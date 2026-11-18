"""Substituted PyYAML and Pydantic releases must not run in CI.

The shell-checks workflow and the other CI jobs that share its install
command fetch PyYAML and Pydantic from the index with a version range and no
hashes, then import them. These tests publish an in-range release on a local
index, reproduce the checkout credential file the job leaves on disk, and run
the install command and the later steps taken from the CI config that is
checked in.

They fail while that command accepts the substituted release or runs it.
They pass when every such command installs only hash-pinned artifacts and
fails closed, without running the substitute, when the index artifact differs.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import shutil
import subprocess
import tarfile
import textwrap
import zipfile
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
PLACEHOLDER_TOKEN = "placeholder-not-a-secret"
PYYAML_VERSION = "9.9.9"
PYDANTIC_VERSION = "2.99.0"

# Import packages the checked-in requirements.txt and CI commands request
# besides the two projects under test. Versions satisfy the ranges in
# requirements.txt at the commit these tests were written against.
STUBS = {
    "aws-cdk-lib": ("2.265.0", {"aws_cdk/__init__.py": ""}),
    "constructs": ("10.8.1", {"constructs/__init__.py": ""}),
    "boto3": ("1.43.72", {"boto3/__init__.py": ""}),
    "botocore": ("1.43.72", {"botocore/__init__.py": ""}),
    "requests": ("2.34.2", {"requests/__init__.py": ""}),
    "colorama": ("0.4.6", {"colorama/__init__.py": ""}),
    "pytest": ("9.1.1", {"pytest/__init__.py": "", "pytest/__main__.py": ""}),
    "checkov": ("3.2.495", {"checkov/__init__.py": ""}),
}

PAYLOAD = r'''
import base64
import json
import os
import re

def note(phase, project):
    path = os.environ.get("CI_SUPPLY_MARKER")
    if not path:
        return
    present = False
    workspace = os.environ.get("GITHUB_WORKSPACE", "")
    config_path = os.path.join(workspace, ".git", "config")
    try:
        config_text = open(config_path, encoding="utf-8").read()
    except OSError:
        config_text = ""
    for cred_path in re.findall(r"\S*git-credentials-[0-9a-fA-F-]+\.config", config_text):
        try:
            body = open(cred_path, encoding="utf-8").read()
        except OSError:
            continue
        match = re.search(r"AUTHORIZATION: basic (\S+)", body)
        if not match:
            continue
        try:
            decoded = base64.b64decode(match.group(1)).decode("utf-8", "replace")
        except Exception:
            continue
        user, _, secret = decoded.partition(":")
        if user == "x-access-token" and secret != "":
            present = True
            break
    record = {
        "phase": phase,
        "project": project,
        "step": os.environ.get("CI_SUPPLY_STEP", ""),
        "credential_present": present,
    }
    with open(path, "a", encoding="utf-8") as handle:
        handle.write(json.dumps(record) + "\n")
'''


def _sha256_record(data: bytes) -> str:
    digest = hashlib.sha256(data).digest()
    return "sha256=" + base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")


def _dist_file_name(dist_name: str) -> str:
    """Wheel and sdist file names use underscores (PEP 427)."""
    return re.sub(r"[-_.]+", "_", dist_name).lower()


def _index_name(dist_name: str) -> str:
    """Simple-index directories use hyphens (PEP 503)."""
    return re.sub(r"[-_.]+", "-", dist_name).lower()


def _write_wheel(dest_dir: Path, dist_name: str, version: str, files: dict[str, str]) -> Path:
    wheel_name = f"{_dist_file_name(dist_name)}-{version}-py3-none-any.whl"
    info = f"{_dist_file_name(dist_name)}-{version}.dist-info"
    payload = {
        f"{info}/METADATA": (
            "Metadata-Version: 2.1\n"
            f"Name: {dist_name}\n"
            f"Version: {version}\n"
        ),
        f"{info}/WHEEL": (
            "Wheel-Version: 1.0\n"
            "Generator: ci-supply-fixture\n"
            "Root-Is-Purelib: true\n"
            "Tag: py3-none-any\n"
        ),
    }
    payload.update(files)
    records = []
    for name, text in payload.items():
        raw = text.encode("utf-8")
        records.append((name, _sha256_record(raw), str(len(raw)), raw))
    records.append((f"{info}/RECORD", "", "", None))
    path = dest_dir / wheel_name
    with zipfile.ZipFile(path, "w") as archive:
        lines = []
        for name, digest, size, raw in records:
            lines.append(f"{name},{digest},{size}")
            if raw is not None:
                archive.writestr(name, raw)
        archive.writestr(f"{info}/RECORD", "\n".join(lines) + "\n")
    return path


def _project_files(dist_name: str, import_name: str, version: str) -> dict[str, str]:
    init = PAYLOAD + f"\nnote('import', {import_name!r})\n"
    return {f"{import_name}/__init__.py": init}


def _write_sdist(dest_dir: Path, dist_name: str, import_name: str, version: str) -> Path:
    root = f"{_dist_file_name(dist_name)}-{version}"
    pyproject = textwrap.dedent(
        f"""\
        [build-system]
        requires = []
        build-backend = "_supply_backend"
        backend-path = ["."]

        [project]
        name = "{dist_name}"
        version = "{version}"
        """
    )
    backend = PAYLOAD + textwrap.dedent(
        f"""\
        import base64
        import hashlib
        import os
        import zipfile

        DIST = {dist_name!r}
        VERSION = {version!r}
        IMPORT = {import_name!r}

        def _record(data):
            digest = hashlib.sha256(data).digest()
            return "sha256=" + base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")

        def _wheel_bytes():
            info = DIST.lower().replace("-", "_") + "-" + VERSION + ".dist-info"
            init = {PAYLOAD!r} + "\\nnote('import', %r)\\n" % IMPORT
            files = {{
                IMPORT + "/__init__.py": init.encode(),
                info + "/METADATA": (
                    "Metadata-Version: 2.1\\nName: " + DIST + "\\nVersion: " + VERSION + "\\n"
                ).encode(),
                info + "/WHEEL": (
                    "Wheel-Version: 1.0\\nGenerator: ci-supply-fixture\\n"
                    "Root-Is-Purelib: true\\nTag: py3-none-any\\n"
                ).encode(),
            }}
            record_lines = []
            chunks = []
            for name, raw in files.items():
                record_lines.append(name + "," + _record(raw) + "," + str(len(raw)))
                chunks.append((name, raw))
            record_name = info + "/RECORD"
            record_lines.append(record_name + ",,")
            chunks.append((record_name, ("\\n".join(record_lines) + "\\n").encode()))
            return chunks

        def prepare_metadata_for_build_wheel(metadata_directory, config_settings=None):
            note("build", DIST.lower())
            info = DIST.lower().replace("-", "_") + "-" + VERSION + ".dist-info"
            target = os.path.join(metadata_directory, info)
            os.makedirs(target, exist_ok=True)
            with open(os.path.join(target, "METADATA"), "w", encoding="utf-8") as handle:
                handle.write("Metadata-Version: 2.1\\nName: " + DIST + "\\nVersion: " + VERSION + "\\n")
            with open(os.path.join(target, "WHEEL"), "w", encoding="utf-8") as handle:
                handle.write(
                    "Wheel-Version: 1.0\\nGenerator: ci-supply-fixture\\n"
                    "Root-Is-Purelib: true\\nTag: py3-none-any\\n"
                )
            return info

        def build_wheel(wheel_directory, config_settings=None, metadata_directory=None):
            note("build", DIST.lower())
            filename = DIST.lower().replace("-", "_") + "-" + VERSION + "-py3-none-any.whl"
            path = os.path.join(wheel_directory, filename)
            with zipfile.ZipFile(path, "w") as archive:
                for name, raw in _wheel_bytes():
                    archive.writestr(name, raw)
            return filename
        """
    )
    tar_path = dest_dir / f"{root}.tar.gz"
    with tarfile.open(tar_path, "w:gz") as archive:
        def add(name: str, text: str) -> None:
            data = text.encode("utf-8")
            info = tarfile.TarInfo(name=f"{root}/{name}")
            info.size = len(data)
            import io
            archive.addfile(info, io.BytesIO(data))

        add("pyproject.toml", pyproject)
        add("_supply_backend.py", backend)
    return tar_path


def _index(root: Path, kind: str) -> str:
    simple = root / "simple"
    files = root / "files"
    files.mkdir(parents=True)
    artifacts: list[tuple[str, Path]] = []
    for dist, (version, modules) in STUBS.items():
        artifacts.append((dist, _write_wheel(files, dist, version, modules)))
    projects = (
        ("PyYAML", "yaml", PYYAML_VERSION),
        ("pydantic", "pydantic", PYDANTIC_VERSION),
    )
    for dist, import_name, version in projects:
        if kind == "wheel":
            path = _write_wheel(files, dist, version, _project_files(dist, import_name, version))
        elif kind == "sdist":
            path = _write_sdist(files, dist, import_name, version)
        else:
            raise AssertionError(kind)
        artifacts.append((dist, path))
    for dist, path in artifacts:
        page = simple / _index_name(dist)
        page.mkdir(parents=True)
        href = Path(os.path.relpath(path, page)).as_posix()
        (page / "index.html").write_text(
            "<!DOCTYPE html><html><body>"
            f'<a href="{href}">{path.name}</a>'
            "</body></html>\n",
            encoding="utf-8",
        )
    return simple.as_uri() + "/"


def _credential_workspace(root: Path) -> dict[str, str]:
    """Lay out the credential file actions/checkout writes for the job token."""
    workspace = root / "workspace"
    runner_temp = root / "runner-temp"
    workspace.mkdir()
    runner_temp.mkdir()
    subprocess.run(["git", "init", "-q", str(workspace)], check=True)
    git_dir = (workspace / ".git").as_posix()
    cred = runner_temp / "git-credentials-aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee.config"
    basic = base64.b64encode(f"x-access-token:{PLACEHOLDER_TOKEN}".encode()).decode("ascii")
    subprocess.run(
        [
            "git",
            "config",
            "--file",
            str(cred),
            f"http.https://github.com/.extraheader",
            f"AUTHORIZATION: basic {basic}",
        ],
        check=True,
    )
    subprocess.run(
        [
            "git",
            "-C",
            str(workspace),
            "config",
            f"includeIf.gitdir:{git_dir}.path",
            str(cred),
        ],
        check=True,
    )
    return {
        "GITHUB_WORKSPACE": str(workspace),
        "RUNNER_TEMP": str(runner_temp),
    }


def _github_jobs(text: str) -> list[tuple[str, str]]:
    lines = text.splitlines()
    try:
        start = lines.index("jobs:") + 1
    except ValueError:
        return []
    jobs: list[tuple[str, str]] = []
    name: str | None = None
    body: list[str] = []
    for line in lines[start:]:
        if re.match(r"^  [^ \n].*:\s*$", line):
            if name is not None:
                jobs.append((name, "\n".join(body)))
            name = line.strip()[:-1]
            body = []
        elif name is not None:
            body.append(line)
    if name is not None:
        jobs.append((name, "\n".join(body)))
    return jobs


def _run_script(lines: list[str], index: int) -> tuple[str, int]:
    line = lines[index]
    inline = re.match(r"^        run:\s*(.*)$", line)
    if not inline:
        return "", index
    rest = inline.group(1).strip()
    index += 1
    if rest in {"|", ">", "|-", ">-"}:
        block: list[str] = []
        while index < len(lines):
            current = lines[index]
            if current.startswith("          "):
                block.append(current[10:])
                index += 1
                continue
            if current.strip() == "":
                nxt = lines[index + 1] if index + 1 < len(lines) else ""
                if nxt.startswith("          ") or nxt.strip() == "":
                    block.append("")
                    index += 1
                    continue
            break
        return "\n".join(block).strip("\n"), index
    return rest, index


def _github_steps(job_body: str) -> list[tuple[str, str]]:
    lines = job_body.splitlines()
    steps: list[tuple[str, str]] = []
    name = ""
    index = 0
    while index < len(lines):
        line = lines[index]
        step = re.match(r"^      - (.*)$", line)
        if step:
            name = ""
            remainder = step.group(1)
            named = re.match(r"name:\s*(.*)$", remainder)
            if named:
                name = named.group(1).strip().strip("'\"")
            index += 1
            continue
        named = re.match(r"^        name:\s*(.*)$", line)
        if named:
            name = named.group(1).strip().strip("'\"")
            index += 1
            continue
        if re.match(r"^        run:", line):
            script, index = _run_script(lines, index)
            steps.append((name, script))
            continue
        index += 1
    return steps


def _gitlab_items(text: str) -> list[tuple[str, list[str]]]:
    jobs: list[tuple[str, list[str]]] = []
    name: str | None = None
    mode: str | None = None
    items: list[str] = []
    lines = text.splitlines()
    index = 0
    while index < len(lines):
        line = lines[index]
        if line and not line.startswith(" ") and not line.startswith("#") and line.endswith(":"):
            key = line[:-1]
            if name is not None:
                jobs.append((name, items))
            if key in {"stages", "workflow", "variables", "default"} or key.startswith("."):
                name = None
                items = []
            else:
                name = key
                items = []
            mode = None
            index += 1
            continue
        if name is None:
            index += 1
            continue
        if line.startswith("  before_script:"):
            mode = "before"
            index += 1
            continue
        if line.startswith("  script:"):
            mode = "script"
            index += 1
            continue
        if re.match(r"^  [A-Za-z0-9_.-]+:\s*$", line):
            mode = None
            index += 1
            continue
        item = re.match(r"^    - (.*)$", line)
        if mode and item:
            body = item.group(1)
            index += 1
            folded: list[str] = []
            while index < len(lines) and lines[index].startswith("      ") and body not in {"|", ">", "|-", ">-"}:
                folded.append(lines[index].strip())
                index += 1
            if folded:
                body = " ".join([body, *folded])
            if body in {"|", ">", "|-", ">-"}:
                block: list[str] = []
                while index < len(lines):
                    current = lines[index]
                    if current.startswith("      "):
                        block.append(current[6:])
                        index += 1
                        continue
                    if current.strip() == "":
                        nxt = lines[index + 1] if index + 1 < len(lines) else ""
                        if nxt.startswith("      "):
                            block.append("")
                            index += 1
                            continue
                    break
                items.append("\n".join(block).strip("\n"))
            else:
                items.append(body.strip())
            continue
        index += 1
    if name is not None:
        jobs.append((name, items))
    return jobs


# Jobs whose install step fetches PyYAML and/or Pydantic and whose later
# steps import them. The install command is re-read from the file, so a
# lockfile fix is what the test runs. Matching is on `pip install`, which
# also covers `python -m pip install`.
TARGET_JOBS = (
    (".github/workflows/contract-parity.yml", "contract-parity"),
    (".github/workflows/control-library.yml", "validate-control-library"),
    (".github/workflows/secret-boundary.yml", "secret-boundary"),
    (".github/workflows/shell-checks.yml", "shell-checks"),
    (".gitlab-ci.yml", "shell"),
    (".gitlab-ci.yml", "control-library"),
    (".gitlab-ci.yml", "pytest"),
    (".gitlab-ci.yml", "cdk-synth"),
)


def _is_pip_install(script: str) -> bool:
    lowered = script.lower()
    return "pip install" in lowered or "pip3 install" in lowered


def _job_scripts(rel: str, job: str) -> tuple[list[str], list[str]]:
    path = REPO / rel
    if rel.endswith(".gitlab-ci.yml"):
        items = dict(_gitlab_items(path.read_text(encoding="utf-8"))).get(job)
        if items is None:
            return [], []
        indexes = [i for i, script in enumerate(items) if _is_pip_install(script)]
        if not indexes:
            return [], items
        first = indexes[0]
        installs = [items[i] for i in indexes]
        followups = [script for script in items[first + 1 :] if script not in installs]
        return installs, followups
    jobs = dict(_github_jobs(path.read_text(encoding="utf-8")))
    body = jobs.get(job)
    if body is None:
        return [], []
    steps = _github_steps(body)
    indexes = [i for i, (_, script) in enumerate(steps) if _is_pip_install(script)]
    if not indexes:
        return [], [script for _, script in steps]
    first = indexes[0]
    installs = [steps[i][1] for i in indexes]
    followups = [script for _, script in steps[first + 1 :] if script not in installs]
    return installs, followups


def _operations() -> list[dict[str, object]]:
    found: list[dict[str, object]] = []
    for rel, job in TARGET_JOBS:
        installs, followups = _job_scripts(rel, job)
        found.append(
            {
                "id": f"{Path(rel).name}:{job}",
                "installs": installs,
                "followups": followups,
            }
        )
    return found


OPERATIONS = _operations()


def _tool_stub(directory: Path) -> None:
    directory.mkdir()
    for name in ("npm", "npx"):
        path = directory / name
        path.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        path.chmod(0o755)


def _run(cmd: str, env: dict[str, str], step: str, timeout: int) -> subprocess.CompletedProcess[str]:
    env = dict(env)
    env["CI_SUPPLY_STEP"] = step
    script = env["CI_SUPPLY_WORKDIR"] + "/step.sh"
    Path(script).write_text(cmd + "\n", encoding="utf-8")
    return subprocess.run(
        ["bash", "--noprofile", "--norc", "-e", "-o", "pipefail", script],
        cwd=str(REPO),
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=timeout,
        check=False,
    )


def _marker_events(path: Path) -> list[dict[str, object]]:
    if not path.is_file():
        return []
    events = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            events.append(json.loads(line))
    return events


@pytest.fixture(scope="module", params=["sdist", "wheel"])
def release_index(request: pytest.FixtureRequest, tmp_path_factory: pytest.TempPathFactory) -> str:
    root = tmp_path_factory.mktemp(f"index-{request.param}")
    return _index(root, request.param)


def test_operations_cover_the_shell_checks_install() -> None:
    ids = [str(item["id"]) for item in OPERATIONS]
    assert "shell-checks.yml:shell-checks" in ids
    shell = next(item for item in OPERATIONS if item["id"] == "shell-checks.yml:shell-checks")
    assert shell["installs"], "shell-checks has no pip install step"
    followups = "\n".join(str(item) for item in shell["followups"])
    assert "scripts/check-deploy-config.sh" in followups
    assert "scripts/check-workshop-flow.sh" in followups


@pytest.mark.parametrize("operation", OPERATIONS, ids=lambda item: str(item["id"]))
def test_substituted_release_does_not_run(operation: dict[str, object], release_index: str, tmp_path: Path) -> None:
    marker = tmp_path / "marker.jsonl"
    venv = tmp_path / "venv"
    subprocess.run(["python3", "-m", "venv", "--clear", str(venv)], check=True)
    tools = tmp_path / "tools"
    _tool_stub(tools)
    env = os.environ.copy()
    env.update(_credential_workspace(tmp_path))
    env.update(
        {
            "PATH": f"{tools}{os.pathsep}{venv / 'bin'}{os.pathsep}{env.get('PATH', '')}",
            "VIRTUAL_ENV": str(venv),
            "PIP_INDEX_URL": release_index,
            "PIP_EXTRA_INDEX_URL": "",
            "PIP_NO_CACHE_DIR": "1",
            "PIP_DISABLE_PIP_VERSION_CHECK": "1",
            "PIP_NO_INPUT": "1",
            "PYTHONNOUSERSITE": "1",
            "CI_SUPPLY_MARKER": str(marker),
            "CI_SUPPLY_WORKDIR": str(tmp_path),
        }
    )
    env.pop("PIP_CONSTRAINT", None)
    env.pop("PIP_REQUIRE_HASHES", None)
    outputs: list[str] = []
    install_rc = 0
    try:
        for number, script in enumerate(operation["installs"]):
            completed = _run(str(script), env, f"install-{number}", timeout=180)
            outputs.append(f"--- install {number} exit {completed.returncode} ---\n{completed.stdout}")
            if completed.returncode != 0:
                install_rc = completed.returncode
                break
        else:
            install_rc = 0
        if install_rc == 0:
            for number, script in enumerate(operation["followups"]):
                completed = _run(str(script), env, f"followup-{number}", timeout=90)
                outputs.append(
                    f"--- followup {number} exit {completed.returncode} ---\n{completed.stdout[-4000:]}"
                )
    finally:
        shutil.rmtree(REPO / ".venv", ignore_errors=True)
        for name in ("cdk.context.json", "cdk.context.json.check-contract-bak"):
            leftover = REPO / name
            if leftover.exists():
                leftover.unlink()
        shutil.rmtree(REPO / "cdk.out", ignore_errors=True)

    events = _marker_events(marker)
    problems: list[str] = []
    if not operation["installs"]:
        problems.append(
            "no pip install step remains; install PyYAML and Pydantic from a "
            "lockfile with pinned versions and hashes"
        )
    if events:
        problems.append(
            "substituted release executed (a side effect before a later refusal still counts):\n"
            + json.dumps(events, indent=2)
        )
    if install_rc == 0:
        problems.append(
            "install exited 0 for an index artifact that is not a hash-pinned lockfile entry; "
            "the job has to fail closed instead of accepting it"
        )
    assert not problems, "\n".join(problems) + "\n" + "\n".join(outputs)[-6000:]
