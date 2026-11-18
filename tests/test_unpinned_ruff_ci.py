"""The Python lint CI jobs must not run a ruff release the job did not pin.

The jobs install ruff from the package index and then execute it. These tests
publish a release the index would serve for an unpinned ``pip install ruff``
(and for any exact version the job names) and run the job's own commands.
They fail while that release's code runs, and they pass once the commands
refuse the release before executing it.
"""

from __future__ import annotations

import base64
import hashlib
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import textwrap
import threading
import zipfile
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
NEW_RELEASE = "99.0.0"
BASH = ["bash", "--noprofile", "--norc", "-eo", "pipefail", "-c"]


class _WorkflowLoader(yaml.SafeLoader):
    """Load workflow YAML without turning the key ``on`` into a boolean."""


def _workflow_bool(loader: yaml.SafeLoader, node: yaml.Node):
    value = loader.construct_scalar(node)
    if value in ("true", "True"):
        return True
    if value in ("false", "False"):
        return False
    return value


_WorkflowLoader.add_constructor("tag:yaml.org,2002:bool", _workflow_bool)


def _load_yaml(path: Path):
    with path.open(encoding="utf-8") as handle:
        return yaml.load(handle, Loader=_WorkflowLoader)


def _requirement_texts(script: str, root: Path) -> list[str]:
    texts = [script]
    pattern = re.compile(
        r"(?:--requirement|--constraint|-r|-c)(?:=|\s+)([^\s]+)"
    )
    for match in pattern.finditer(script):
        candidate = Path(match.group(1))
        if not candidate.is_absolute():
            candidate = root / candidate
        if candidate.is_file():
            texts.append(candidate.read_text(encoding="utf-8"))
    return texts


def _pinned_ruff_versions(scripts: list[str], root: Path) -> set[str]:
    versions: set[str] = set()
    pin = re.compile(
        r"""(?ix)(?:^|[\s'\"])ruff(?:\[[^\]]*\])?\s*==\s*([0-9][^,\s'\"\\]*)"""
    )
    for script in scripts:
        for text in _requirement_texts(script, root):
            versions.update(match.group(1) for match in pin.finditer(text))
    return versions


def _step_runs_for_python_change(condition: object) -> bool:
    """True when a GitHub Actions ``if`` can be true after a Python file change.

    ``tj-actions/changed-files`` sets ``any_changed`` from the filtered ACMR
    list. A constant false condition never reaches the install.
    """
    if condition is None:
        return True
    text = str(condition).strip()
    if text.lower() == "false":
        return False
    return True


def _github_ruff_scripts(path: Path) -> list[str]:
    document = _load_yaml(path)
    trigger = document.get("on")
    if not _triggers_on_main(trigger):
        return []
    scripts: list[str] = []
    for job in (document.get("jobs") or {}).values():
        for step in job.get("steps") or []:
            script = step.get("run")
            if not isinstance(script, str) or not _mentions_ruff_execution(script):
                continue
            if _step_runs_for_python_change(step.get("if")):
                scripts.append(script)
    return scripts


def _triggers_on_main(trigger: object) -> bool:
    if trigger in ("push", "pull_request"):
        return True
    if isinstance(trigger, list):
        return any(item in ("push", "pull_request") for item in trigger)
    if not isinstance(trigger, dict):
        return False
    for event in ("push", "pull_request"):
        if event not in trigger:
            continue
        spec = trigger[event]
        if not isinstance(spec, dict):
            return True
        branches = spec.get("branches")
        if not branches or "main" in branches:
            return True
    return False


def _mentions_ruff_execution(script: str) -> bool:
    installs = re.search(r"(?m)^\s*.*\bpip\b.*\bruff\b", script) is not None
    invokes = re.search(r"(?m)^\s*ruff\b", script) is not None
    return installs or invokes


def _gitlab_ruff_scripts(path: Path) -> list[str]:
    document = _load_yaml(path)
    rules = (document.get("workflow") or {}).get("rules") or []
    runs_for_mr_or_main = any(
        isinstance(rule, dict)
        and (
            "merge_request_event" in str(rule.get("if", ""))
            or 'CI_COMMIT_BRANCH == "main"' in str(rule.get("if", ""))
            or "CI_COMMIT_BRANCH == 'main'" in str(rule.get("if", ""))
        )
        for rule in rules
    )
    if rules and not runs_for_mr_or_main:
        return []
    job = document.get("ruff")
    if not isinstance(job, dict):
        return []
    scripts: list[str] = []
    before = job.get("before_script") or []
    if isinstance(before, str):
        before = [before]
    for line in before:
        if _mentions_ruff_execution(str(line)):
            scripts.append(str(line))
    body = job.get("script")
    if isinstance(body, list):
        scripts.extend(str(item) for item in body if _mentions_ruff_execution(str(item)))
    elif isinstance(body, str) and _mentions_ruff_execution(body):
        scripts.append(body)
    return scripts


def _payload(version: str, marker: Path, phase: str) -> str:
    return textwrap.dedent(
        f"""\
        import os

        def _record(phase):
            marker = {str(marker)!r}
            readme = os.path.join(os.getcwd(), "README.md")
            line = ""
            if os.path.isfile(readme):
                with open(readme, encoding="utf-8", errors="replace") as handle:
                    line = handle.readline().strip()
            with open(marker, "a", encoding="utf-8") as handle:
                handle.write(phase + "\\n")
                if line:
                    handle.write("readme:" + line + "\\n")

        _record({phase!r})

        def main():
            _record({phase + "-main"!r})
            return 0
        """
    )


def _record_line(path: str, data: bytes) -> str:
    digest = hashlib.sha256(data).digest()
    encoded = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return f"{path},sha256={encoded},{len(data)}"


def _write_wheel(directory: Path, version: str, marker: Path) -> None:
    payload = _payload(version, marker, "wheel-import").encode()
    metadata = (
        "Metadata-Version: 2.1\n"
        "Name: ruff\n"
        f"Version: {version}\n"
    ).encode()
    wheel_meta = (
        "Wheel-Version: 1.0\n"
        "Generator: ruff-ci-test\n"
        "Root-Is-Purelib: true\n"
        "Tag: py3-none-any\n"
    ).encode()
    entry_points = b"[console_scripts]\nruff = ruff:main\n"
    info = f"ruff-{version}.dist-info"
    files = {
        "ruff/__init__.py": payload,
        f"{info}/METADATA": metadata,
        f"{info}/WHEEL": wheel_meta,
        f"{info}/entry_points.txt": entry_points,
    }
    record_lines = [_record_line(name, data) for name, data in sorted(files.items())]
    record_lines.append(f"{info}/RECORD,,")
    files[f"{info}/RECORD"] = ("\n".join(record_lines) + "\n").encode()
    filename = directory / f"ruff-{version}-py3-none-any.whl"
    with zipfile.ZipFile(filename, "w") as archive:
        for name, data in files.items():
            archive.writestr(name, data)


def _write_sdist(directory: Path, version: str, marker: Path) -> None:
    root_name = f"ruff-{version}"
    pyproject = textwrap.dedent(
        f"""\
        [build-system]
        requires = []
        build-backend = "backend"
        backend-path = ["."]

        [project]
        name = "ruff"
        version = "{version}"
        """
    ).encode()
    backend = _payload(version, marker, "sdist-backend").encode()
    backend += textwrap.dedent(
        f"""\

        def get_requires_for_build_wheel(config_settings=None):
            return []

        def prepare_metadata_for_build_wheel(metadata_directory, config_settings=None):
            import pathlib
            dist = pathlib.Path(metadata_directory) / "ruff-{version}.dist-info"
            dist.mkdir(parents=True, exist_ok=True)
            (dist / "METADATA").write_text(
                "Metadata-Version: 2.1\\nName: ruff\\nVersion: {version}\\n",
                encoding="utf-8",
            )
            (dist / "WHEEL").write_text(
                "Wheel-Version: 1.0\\nGenerator: ruff-ci-test\\n"
                "Root-Is-Purelib: true\\nTag: py3-none-any\\n",
                encoding="utf-8",
            )
            return dist.name

        def build_wheel(wheel_directory, config_settings=None, metadata_directory=None):
            import base64
            import hashlib
            import pathlib
            import zipfile

            info = "ruff-{version}.dist-info"
            payload = pathlib.Path(__file__).with_name("ruff_pkg.py").read_bytes()
            metadata = (
                "Metadata-Version: 2.1\\nName: ruff\\nVersion: {version}\\n"
            ).encode()
            wheel_meta = (
                "Wheel-Version: 1.0\\nGenerator: ruff-ci-test\\n"
                "Root-Is-Purelib: true\\nTag: py3-none-any\\n"
            ).encode()
            entry_points = b"[console_scripts]\\nruff = ruff:main\\n"
            members = {{
                "ruff/__init__.py": payload,
                info + "/METADATA": metadata,
                info + "/WHEEL": wheel_meta,
                info + "/entry_points.txt": entry_points,
            }}
            lines = []
            for name, data in sorted(members.items()):
                digest = hashlib.sha256(data).digest()
                encoded = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
                lines.append(f"{{name}},sha256={{encoded}},{{len(data)}}")
            lines.append(info + "/RECORD,,")
            members[info + "/RECORD"] = ("\\n".join(lines) + "\\n").encode()
            filename = "ruff-{version}-py3-none-any.whl"
            target = pathlib.Path(wheel_directory) / filename
            with zipfile.ZipFile(target, "w") as archive:
                for name, data in members.items():
                    archive.writestr(name, data)
            return filename
        """
    ).encode()
    package_source = _payload(version, marker, "sdist-import")
    filename = directory / f"{root_name}.tar.gz"
    with tarfile.open(filename, "w:gz") as archive:
        for name, data in (
            (f"{root_name}/pyproject.toml", pyproject),
            (f"{root_name}/backend.py", backend),
            (f"{root_name}/ruff_pkg.py", package_source.encode()),
        ):
            info = tarfile.TarInfo(name)
            info.size = len(data)
            archive.addfile(info, fileobj=_Bytes(data))


class _Bytes:
    def __init__(self, data: bytes) -> None:
        import io

        self._buffer = io.BytesIO(data)

    def read(self, size: int = -1) -> bytes:
        return self._buffer.read(size)


def _index_page(names: list[str]) -> str:
    links = "\n".join(f'<a href="/packages/{name}">{name}</a>' for name in names)
    return (
        "<!DOCTYPE html><html><body>\n"
        f"{links}\n"
        "</body></html>\n"
    )


class _QuietHandler(SimpleHTTPRequestHandler):
    def log_message(self, format: str, *args) -> None:
        return


def _serve(directory: Path) -> tuple[ThreadingHTTPServer, str]:
    handler = partial(_QuietHandler, directory=str(directory))
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address
    return server, f"http://{host}:{port}/simple"


def _run_scripts(scripts: list[str], root: Path, index_url: str) -> subprocess.CompletedProcess[str]:
    venv = root / ".ruff-ci-venv"
    if venv.exists():
        shutil.rmtree(venv)
    subprocess.run(
        [sys.executable, "-m", "venv", str(venv)],
        check=True,
        cwd=root,
    )
    env = os.environ.copy()
    for key in (
        "PIP_INDEX_URL",
        "PIP_EXTRA_INDEX_URL",
        "PIP_TRUSTED_HOST",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "http_proxy",
        "https_proxy",
        "ALL_PROXY",
        "all_proxy",
    ):
        env.pop(key, None)
    env["PATH"] = str(venv / "bin") + os.pathsep + env.get("PATH", "")
    env["PIP_INDEX_URL"] = index_url
    env["PIP_CONFIG_FILE"] = os.devnull
    env["PIP_NO_CACHE_DIR"] = "1"
    env["PIP_DISABLE_PIP_VERSION_CHECK"] = "1"
    env["PYTHONNOUSERSITE"] = "1"
    env["ALL_CHANGED_FILES"] = "README.md"
    script = "\n".join(scripts)
    return subprocess.run(
        [*BASH, script],
        cwd=root,
        env=env,
        text=True,
        capture_output=True,
        timeout=120,
        check=False,
    )


def attacker_ruff_output(scripts: list[str], artifact: str) -> tuple[str, str]:
    """Run ``scripts`` against an index that serves attacker-built ruff files.

    Returns the marker text written by that code, and the combined command
    output. An empty marker means the commands did not execute the release.
    """
    if not scripts:
        return "", ""
    work = Path(tempfile.mkdtemp(prefix=f"ruff-ci-{artifact}-"))
    packages = work / "packages"
    simple = work / "simple" / "ruff"
    packages.mkdir(parents=True)
    simple.mkdir(parents=True)
    marker = work / "executed.txt"
    versions = _pinned_ruff_versions(scripts, REPO_ROOT) | {NEW_RELEASE}
    names: list[str] = []
    for version in sorted(versions):
        if artifact == "wheel":
            _write_wheel(packages, version, marker)
            names.append(f"ruff-{version}-py3-none-any.whl")
        else:
            _write_sdist(packages, version, marker)
            names.append(f"ruff-{version}.tar.gz")
    (simple / "index.html").write_text(_index_page(names), encoding="utf-8")
    server, index_url = _serve(work)
    completed = None
    try:
        completed = _run_scripts(scripts, REPO_ROOT, index_url)
        text = marker.read_text(encoding="utf-8") if marker.is_file() else ""
        output = ""
        if completed is not None:
            output = (completed.stdout or "") + (completed.stderr or "")
        return text, output
    finally:
        server.shutdown()
        shutil.rmtree(work, ignore_errors=True)
        venv = REPO_ROOT / ".ruff-ci-venv"
        if venv.exists():
            shutil.rmtree(venv, ignore_errors=True)


def _assert_not_executed(scripts: list[str], artifact: str) -> None:
    marker, output = attacker_ruff_output(scripts, artifact)
    rendered = "\n---\n".join(scripts)
    assert marker == "", (
        "The CI commands executed a ruff release from the package index.\n"
        f"artifact: {artifact}\n"
        f"commands:\n{rendered}\n"
        f"release wrote:\n{marker}\n"
        f"command output:\n{output[-4000:]}"
    )


def test_github_python_lint_does_not_execute_indexed_ruff_wheel():
    scripts = _github_ruff_scripts(REPO_ROOT / ".github/workflows/python-lint.yml")
    _assert_not_executed(scripts, "wheel")


def test_github_python_lint_does_not_execute_indexed_ruff_sdist():
    scripts = _github_ruff_scripts(REPO_ROOT / ".github/workflows/python-lint.yml")
    _assert_not_executed(scripts, "sdist")


def test_gitlab_ruff_job_does_not_execute_indexed_ruff_wheel():
    scripts = _gitlab_ruff_scripts(REPO_ROOT / ".gitlab-ci.yml")
    _assert_not_executed(scripts, "wheel")


def test_gitlab_ruff_job_does_not_execute_indexed_ruff_sdist():
    scripts = _gitlab_ruff_scripts(REPO_ROOT / ".gitlab-ci.yml")
    _assert_not_executed(scripts, "sdist")
