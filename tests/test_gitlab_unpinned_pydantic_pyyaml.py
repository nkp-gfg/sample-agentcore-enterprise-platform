"""Substituted Pydantic and PyYAML releases must not run in GitLab CI.

The shell job installs both projects with no version and no hash, then
``scripts/check-deploy-config.sh`` imports ``infra_utils.platform_config``.
The pytest, control-library, and cdk-synth jobs install one or both without
hashes and import them too. These tests publish a release the ambient index
serves in place of those projects. They fail while that release is installed
or its code runs where the job token is visible, and they pass when the job
refuses the release before unpacking it.

Untested on purpose:
- ``.github/workflows/shell-checks.yml`` installs ranged Pydantic and PyYAML
  and then runs the same shell checks. ``.gitlab-ci.yml`` says those GitHub
  workflows never ran.
- ``scripts/deploy.sh`` ``setup_venv`` installs ``requirements.txt`` for an
  operator, outside this CI job.
- Other unpinned GitLab packages (ruff, checkov, pytest, boto3, colorama,
  aws-cdk-lib, constructs, botocore, requests). The control-library job needs
  some checkov distribution so its install can finish; the one served here is
  inert and is not the assertion.
"""

from __future__ import annotations

import base64
import hashlib
import io
import os
import re
import shutil
import subprocess
import sys
import threading
import urllib.error
import urllib.request
import zipfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

if os.environ.get("GITLAB_JOB_UNDER_TEST") == "1":
    pytest.skip("nested GitLab job under test", allow_module_level=True)

REPO = Path(__file__).resolve().parents[1]
CI_FILE = REPO / ".gitlab-ci.yml"
# CPython 3.13.18, the interpreter in public.ecr.aws/docker/library/python:3.13-slim,
# bundles this pip in Lib/ensurepip.
IMAGE_PIP = "26.2.2"
TOKEN_PLACEHOLDER = "placeholder-not-a-real-token"
PREFERRED = {"pydantic": "2.99.0", "pyyaml": "6.99.0"}
HOSTILE = ("pydantic", "pyyaml")

# pip 26.2.2 vendors the specifier matcher used to pick a release inside the
# job's requested range. Loaded from the wheel, not from memory of the API.
_PIP_WHEEL = Path(f"/tmp/pip-wheel-cache/pip-{IMAGE_PIP}-py3-none-any.whl")


def _specifier_set():
    if not _PIP_WHEEL.is_file():
        _PIP_WHEEL.parent.mkdir(parents=True, exist_ok=True)
        subprocess.check_call(
            [
                sys.executable,
                "-m",
                "pip",
                "download",
                "-d",
                str(_PIP_WHEEL.parent),
                f"pip=={IMAGE_PIP}",
                "--disable-pip-version-check",
            ],
            env=_pypi_env(),
        )
        downloaded = next(_PIP_WHEEL.parent.glob(f"pip-{IMAGE_PIP}-*.whl"))
        if downloaded != _PIP_WHEEL:
            downloaded.replace(_PIP_WHEEL)
    if str(_PIP_WHEEL) not in sys.path:
        sys.path.insert(0, str(_PIP_WHEEL))
    from pip._vendor.packaging.specifiers import SpecifierSet

    return SpecifierSet


def _pypi_env() -> dict[str, str]:
    env = os.environ.copy()
    for key in ("PIP_INDEX_URL", "PIP_TRUSTED_HOST", "PIP_EXTRA_INDEX_URL"):
        env.pop(key, None)
    env["PIP_DISABLE_PIP_VERSION_CHECK"] = "1"
    return env


def _record_hash(data: bytes) -> str:
    digest = hashlib.sha256(data).digest()
    return "sha256=" + base64.urlsafe_b64encode(digest).decode().rstrip("=")


def _build_wheel(
    dest: Path,
    dist_name: str,
    version: str,
    import_name: str | None,
    hostile: bool,
) -> Path:
    """Build a PEP 427 wheel. Hostile wheels record execution and nothing else."""
    info = f"{dist_name}-{version}.dist-info"
    files: dict[str, bytes] = {
        f"{info}/METADATA": (
            "Metadata-Version: 2.1\n"
            f"Name: {dist_name}\n"
            f"Version: {version}\n"
        ).encode(),
        f"{info}/WHEEL": (
            "Wheel-Version: 1.0\n"
            "Generator: gitlab-supply-chain-test\n"
            "Root-Is-Purelib: true\n"
            "Tag: py3-none-any\n"
        ).encode(),
    }
    if import_name:
        if hostile:
            files[f"{import_name}/__init__.py"] = (
                "import os\n"
                "p = os.environ.get('SUPPLY_CHAIN_MARKER')\n"
                "if p:\n"
                "    present = bool(os.environ.get('CI_JOB_TOKEN'))\n"
                f"    open(p, 'a', encoding='utf-8').write('import {import_name} ci_job_token_present=%s\\n' % present)\n"
            ).encode()
            # site.py executes lines that start with "import " when the
            # interpreter starts, which is how the job runs Python.
            files[f"supply_chain_{dist_name}.pth"] = (
                "import os; p=os.environ.get('SUPPLY_CHAIN_MARKER');"
                " p and open(p,'a',encoding='utf-8').write("
                f"'pth {dist_name} ci_job_token_present=%s\\n' % bool(os.environ.get('CI_JOB_TOKEN')))\n"
            ).encode()
        else:
            files[f"{import_name}/__init__.py"] = b""
    record = []
    for path, data in files.items():
        record.append(f"{path},{_record_hash(data)},{len(data)}")
    record.append(f"{info}/RECORD,,")
    files[f"{info}/RECORD"] = ("\n".join(record) + "\n").encode()
    payload = io.BytesIO()
    with zipfile.ZipFile(payload, "w") as archive:
        for path, data in files.items():
            archive.writestr(path, data)
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(payload.getvalue())
    return dest


class _Index(ThreadingHTTPServer):
    allow_reuse_address = True

    def __init__(self, wheels: dict[str, Path]):
        self.by_name = wheels
        self.by_file = {path.name: path for path in wheels.values()}
        self.seen: set[str] = set()
        self._lock = threading.Lock()
        super().__init__(("127.0.0.1", 0), self._handler())

    def _handler(self):
        index = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, fmt: str, *args) -> None:
                return

            def do_HEAD(self) -> None:  # noqa: N802
                self._serve(head=True)

            def do_GET(self) -> None:  # noqa: N802
                self._serve(head=False)

            def _serve(self, head: bool) -> None:
                path = self.path.split("?", 1)[0]
                if path.startswith("/wheels/"):
                    wheel = index.by_file.get(path.rsplit("/", 1)[-1])
                    if wheel is None:
                        self.send_error(404)
                        return
                    body = wheel.read_bytes()
                    ctype = "application/octet-stream"
                elif path.startswith("/simple/"):
                    parts = [part for part in path.split("/") if part]
                    if len(parts) < 2:
                        self.send_error(404)
                        return
                    project = re.sub(r"[-_.]+", "-", parts[1]).lower()
                    with index._lock:
                        index.seen.add(project)
                    wheel = index.by_name.get(project)
                    if wheel is not None:
                        href = f"http://127.0.0.1:{index.server_address[1]}/wheels/{wheel.name}"
                        body = (
                            "<!DOCTYPE html><html><body>"
                            f'<a href="{href}">{wheel.name}</a>'
                            "</body></html>"
                        ).encode()
                        ctype = "text/html; charset=utf-8"
                    else:
                        body, ctype = _proxy_simple(parts[1], self.headers.get("Accept"))
                else:
                    self.send_error(404)
                    return
                self.send_response(200)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                if not head:
                    self.wfile.write(body)

        return Handler


def _proxy_simple(project: str, accept: str | None) -> tuple[bytes, str]:
    request = urllib.request.Request(
        f"https://pypi.org/simple/{project}/",
        headers={
            "Accept": accept or "application/vnd.pypi.simple.v1+json, text/html",
            "User-Agent": "gitlab-supply-chain-test",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            raw = response.headers.get("Content-Type", "text/html")
            return response.read(), raw.split(";")[0]
    except urllib.error.HTTPError as exc:
        return exc.read(), "text/plain"


def _job_body(text: str, job: str) -> list[str] | None:
    lines = text.splitlines()
    start = None
    for i, line in enumerate(lines):
        if re.match(rf"^{re.escape(job)}:\s*(#.*)?$", line):
            start = i + 1
            break
    if start is None:
        return None
    body = []
    for line in lines[start:]:
        if line and not line[0].isspace() and not line.startswith("#"):
            break
        body.append(line)
    return body


def _sequence(body: list[str], key: str) -> list[str]:
    start = None
    for i, line in enumerate(body):
        if re.match(rf"^  {re.escape(key)}:\s*(#.*)?$", line):
            start = i + 1
            break
    if start is None:
        return []
    items: list[str] = []
    i = start
    while i < len(body):
        line = body[i]
        if (
            line.startswith("  ")
            and not line.startswith("   ")
            and line.strip()
            and not line.lstrip().startswith("#")
            and not line.startswith("  -")
        ):
            break
        if not line.strip() or line.lstrip().startswith("#"):
            i += 1
            continue
        matched = re.match(r"^    - (.*)$", line)
        if not matched:
            break
        first = matched.group(1)
        i += 1
        if first in {"|", "|-", "|+", ">", ">-", ">+"}:
            block: list[str] = []
            while i < len(body) and (body[i].startswith("      ") or body[i].strip() == ""):
                block.append("" if body[i].strip() == "" else body[i][6:])
                i += 1
            while block and block[-1] == "":
                block.pop()
            text = "\n".join(block)
            if first.startswith(">"):
                text = re.sub(r"\s*\n\s*", " ", text).strip()
            items.append(text)
        else:
            parts = [first]
            while i < len(body) and re.match(r"^      \S", body[i]):
                parts.append(body[i].strip())
                i += 1
            items.append(re.sub(r"\s+", " ", " ".join(parts)).strip())
    return items


def job_commands(job: str) -> list[str]:
    body = _job_body(CI_FILE.read_text(), job)
    if body is None:
        return []
    return _sequence(body, "before_script") + _sequence(body, "script")


def _specs_in(text: str) -> dict[str, str]:
    found: dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith("-"):
            continue
        matched = re.match(
            r"(?i)^(pydantic|pyyaml)(?:\[[^\]]*\])?\s*([^;\s].*?)?\s*$",
            line,
        )
        if not matched:
            continue
        name = "pyyaml" if matched.group(1).lower() == "pyyaml" else "pydantic"
        found[name] = (matched.group(2) or "").strip()
    return found


def specs_for(commands: list[str]) -> dict[str, str]:
    found: dict[str, str] = {}
    for command in commands:
        for path in re.findall(r"(?:-r|--requirement)(?:\s+|=)(\S+)", command):
            req = REPO / path.strip("\"'")
            if req.is_file():
                found.update(_specs_in(req.read_text()))
        for matched in re.finditer(
            r"(?i)(?<![A-Za-z0-9_.-])(pydantic|pyyaml)(?:\[[^\]]*\])?([<>=!~][^,\s\"']*)?",
            command,
        ):
            name = "pyyaml" if matched.group(1).lower() == "pyyaml" else "pydantic"
            spec = matched.group(2) or ""
            if name not in found or spec:
                found[name] = spec or found.get(name, "")
    return found


def _choose_version(spec: str, preferred: str) -> str:
    specifier_set = _specifier_set()
    parsed = specifier_set(spec or "")
    if parsed.contains(preferred, prereleases=True):
        return preferred
    for item in parsed:
        if item.operator in {"==", "==="}:
            return item.version
    return preferred


def _commands_select(commands: list[str], project: str) -> bool:
    if project in specs_for(commands):
        return True
    for command in commands:
        if re.search(r"\bpip3?\s+install\b", command) and re.search(
            rf"(?i)(?<![A-Za-z0-9_.-]){project}(?![A-Za-z0-9_.-])",
            command,
        ):
            return True
    return False


def _assert_refused(
    marker: Path,
    roots: list[Path],
    index: _Index,
    projects: tuple[str, ...],
    commands: list[str],
) -> None:
    text = marker.read_text() if marker.is_file() else ""
    sentinels = []
    for root in roots:
        if root.is_dir():
            sentinels.extend(root.rglob("supply_chain_*.pth"))
    problems = []
    if text.strip():
        problems.append("substituted package code ran:\n" + text)
    if sentinels:
        problems.append(
            "substituted wheels were installed:\n"
            + "\n".join(str(path) for path in sentinels)
        )
    # A hash mismatch aborts the install before every project is requested.
    # That is a refusal. Skipping the ambient index entirely is not.
    selected = [project for project in projects if _commands_select(commands, project)]
    if selected and not any(project in index.seen for project in selected):
        problems.append(
            "the job still installs "
            + ", ".join(selected)
            + " but did not resolve them from the ambient index, so a "
            "substituted file was not hash-checked"
        )
    if problems:
        pytest.fail(
            "\n".join(problems)
            + "\nInstall Pydantic and PyYAML from a lockfile with hashes and "
            "fail the job before their code can run."
        )


def _stub_dir(path: Path) -> None:
    path.mkdir()
    apt = path / "apt-get"
    apt.write_text("#!/bin/sh\nexit 0\n")
    apt.chmod(0o755)


def _base_path() -> str:
    kept = []
    for entry in os.environ.get("PATH", "").split(":"):
        if not entry or "/tmp/" in entry:
            continue
        kept.append(entry)
    return ":".join(kept)


def _image_venv(path: Path) -> Path:
    subprocess.check_call([sys.executable, "-m", "venv", str(path)], env=_pypi_env())
    subprocess.check_call(
        [str(path / "bin" / "pip"), "install", "-q", f"pip=={IMAGE_PIP}"],
        env=_pypi_env(),
    )
    return path


def _run(commands: list[str], env: dict[str, str], cwd: Path) -> None:
    script = "set -eo pipefail\n" + "\n".join(commands) + "\n"
    subprocess.run(
        ["bash", "-c", script],
        cwd=cwd,
        env=env,
        timeout=600,
        check=False,
    )


def _prepare(tmp: Path, commands: list[str], projects: tuple[str, ...]) -> tuple[_Index, Path, list[Path]]:
    specs = specs_for(commands)
    wheel_dir = tmp / "wheels"
    wheels: dict[str, Path] = {}
    for project in projects:
        version = _choose_version(specs.get(project, ""), PREFERRED[project])
        import_name = "yaml" if project == "pyyaml" else project
        wheels[project] = _build_wheel(
            wheel_dir / f"{project}-{version}-py3-none-any.whl",
            project,
            version,
            import_name,
            hostile=True,
        )
    # Present so `pip install pyyaml checkov` can resolve. Not an assertion.
    wheels["checkov"] = _build_wheel(
        wheel_dir / "checkov-0.0.0-py3-none-any.whl",
        "checkov",
        "0.0.0",
        "checkov",
        hostile=False,
    )
    index = _Index(wheels)
    thread = threading.Thread(target=index.serve_forever, daemon=True)
    thread.start()
    return index, tmp / "marker", [tmp, REPO]


@pytest.fixture()
def supply_chain(tmp_path: Path):
    yield tmp_path
    shutil.rmtree(REPO / ".venv", ignore_errors=True)
    shutil.rmtree(REPO / ".cache", ignore_errors=True)


def _exercise(tmp: Path, job: str, projects: tuple[str, ...], image_python: bool) -> None:
    commands = job_commands(job)
    if not commands:
        return
    index, marker, roots = _prepare(tmp, commands, projects)
    stub = tmp / "stub"
    _stub_dir(stub)
    env = _pypi_env()
    env.update(
        {
            "PATH": _base_path(),
            "PIP_INDEX_URL": f"http://127.0.0.1:{index.server_address[1]}/simple",
            "PIP_TRUSTED_HOST": "127.0.0.1",
            "CI_JOB_TOKEN": TOKEN_PLACEHOLDER,
            "CI_PROJECT_DIR": str(REPO),
            "CI_PIPELINE_SOURCE": "merge_request_event",
            "CI_COMMIT_BRANCH": "main",
            "SUPPLY_CHAIN_MARKER": str(marker),
            "GITLAB_JOB_UNDER_TEST": "1",
            "PYTHONNOUSERSITE": "1",
            "PIP_CACHE_DIR": str(tmp / "pip-cache"),
        }
    )
    if image_python:
        venv = _image_venv(tmp / "image")
        env["PATH"] = f"{venv / 'bin'}:{stub}:{env['PATH']}"
        roots.append(venv)
    else:
        env["PATH"] = f"{stub}:{env['PATH']}"
    try:
        _run(commands, env, REPO)
        _assert_refused(marker, roots, index, projects, commands)
    finally:
        index.shutdown()
        index.server_close()


def test_shell_job_refuses_substituted_pydantic_and_pyyaml(supply_chain: Path) -> None:
    _exercise(supply_chain, "shell", HOSTILE, image_python=True)


def test_pytest_job_refuses_substituted_pyyaml(supply_chain: Path) -> None:
    _exercise(supply_chain, "pytest", ("pyyaml",), image_python=True)


def test_control_library_job_refuses_substituted_pyyaml(supply_chain: Path) -> None:
    _exercise(supply_chain, "control-library", ("pyyaml",), image_python=True)


def test_cdk_synth_job_refuses_substituted_pydantic_and_pyyaml(supply_chain: Path) -> None:
    _exercise(supply_chain, "cdk-synth", HOSTILE, image_python=False)
