"""Replay the CI installs of ruff and checkov against an index the publisher controls.

The GitLab jobs (and the GitHub workflows that install the same tools) run
``pip install`` with no version and no hash, then execute the installed
command. These tests publish a stand-in release on a local index and replay
those commands with pip 26.2.2, the pip bundled in the ``python:3.13-slim``
image the GitLab jobs use (CPython 3.13.18 ensurepip).

They fail while that install accepts the release: the package reads
``control-library/catalog.yaml`` and the job token from the environment the
job already has. They pass once the install refuses that artifact before any
of its code runs.

Sibling unpinned installs that these tests do not replay: the GitLab shell
job (``pydantic``, ``pyyaml``), the GitLab pytest job (``pyyaml``, ``pytest``,
``boto3``, ``colorama``), the GitLab cdk-synth job and the GitHub
contract-parity and secret-boundary workflows (``requirements.txt``), and the
GitHub shell-checks workflow.
"""

from __future__ import annotations

import hashlib
import os
import shlex
import shutil
import subprocess
import tarfile
import textwrap
import urllib.request
import zipfile
from dataclasses import dataclass
from pathlib import Path

import pytest
import yaml

REPO = Path(__file__).resolve().parents[1]
GITLAB_CI = REPO / ".gitlab-ci.yml"
GITHUB_LINT = REPO / ".github" / "workflows" / "python-lint.yml"
GITHUB_CONTROLS = REPO / ".github" / "workflows" / "control-library.yml"

# python:3.13-slim is CPython 3.13.18 (docker-library/python @ 152874b1,
# 3.13/slim-trixie). ensurepip in that tag bundles this pip wheel.
PIP_WHEEL = "pip-26.2.2-py3-none-any.whl"
PIP_URL = (
    "https://files.pythonhosted.org/packages/3f/06/"
    "3e4420302363fbb71be3c7f35ce042f54bfca330e3e66b3a2e3c4cca579f/"
    + PIP_WHEEL
)
PIP_SHA256 = "fd7f4dfa8190e014013b9f08f3e973f4e4c26ffd179a204895533a7254813a70"

# Same PyYAML the control-library job installs, so the validator can import it.
PYYAML_WHEEL = (
    "pyyaml-6.0.3-cp312-cp312-manylinux2014_x86_64"
    ".manylinux_2_17_x86_64.manylinux_2_28_x86_64.whl"
)
PYYAML_URL = (
    "https://files.pythonhosted.org/packages/8b/9d/"
    "b3589d3877982d4f2329302ef98a8026e7f4443c765c46cfecc8858c6b4b/"
    + PYYAML_WHEEL
)
PYYAML_SHA256 = "ba1cc08a7ccde2d2ec775841541641e4548226580ab850948cbfda66a1befcdc"

JOB_TOKEN = "placeholder-ci-job-token"
GITHUB_TOKEN = "placeholder-github-token"
CATALOG_MARKER = "scp.memory.enforce-cmk"
TOOLS = ("ruff", "checkov")


@dataclass
class Operation:
    operation_id: str
    install_lines: list[str]
    followups: list[str]
    tool: str
    needs_git_diff: bool = False
    needs_changed_files_env: bool = False


def _flatten_shell(value: object) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    lines: list[str] = []
    for item in value:  # type: ignore[union-attr]
        lines.extend(_flatten_shell(item))
    return lines


def _segments(line: str) -> list[str]:
    parts: list[str] = []
    buf: list[str] = []
    quote: str | None = None
    i = 0
    while i < len(line):
        ch = line[i]
        if quote:
            buf.append(ch)
            if ch == quote:
                quote = None
            i += 1
            continue
        if ch in ("'", '"'):
            quote = ch
            buf.append(ch)
            i += 1
            continue
        if line.startswith("&&", i) or line.startswith(";", i):
            parts.append("".join(buf).strip())
            buf = []
            i += 2 if line.startswith("&&", i) else 1
            continue
        buf.append(ch)
        i += 1
    tail = "".join(buf).strip()
    if tail:
        parts.append(tail)
    return [part for part in parts if part]


def _requirement_names(command: str, root: Path) -> set[str]:
    try:
        parts = shlex.split(command)
    except ValueError:
        return set()
    names: set[str] = set()
    i = 0
    while i < len(parts):
        part = parts[i]
        if part in {"-r", "--requirement"} and i + 1 < len(parts):
            req = (root / parts[i + 1]).resolve()
            if req.is_file():
                names |= _requirement_names_in_file(req, root)
            i += 2
            continue
        if part.startswith("-"):
            i += 1
            continue
        if part in {"pip", "pip3", "install", "python", "python3"}:
            i += 1
            continue
        name = part.split(";", 1)[0].split("[", 1)[0]
        for sep in ("==", ">=", "<=", "~=", "!=", ">", "<"):
            if sep in name:
                name = name.split(sep, 1)[0]
                break
        names.add(name.replace("_", "-").lower())
        i += 1
    return names


def _requirement_names_in_file(path: Path, root: Path) -> set[str]:
    names: set[str] = set()
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith("-"):
            if line.startswith(("-r ", "--requirement ")):
                names |= _requirement_names(f"pip install {line}", path.parent)
            continue
        names |= _requirement_names(f"pip install {line}", root)
    return names


def _pinned_version(command: str, tool: str, root: Path) -> str | None:
    """Return the ``==`` version this command requests for ``tool``, if any."""
    specs: list[str] = []
    try:
        parts = shlex.split(command)
    except ValueError:
        return None
    i = 0
    files: list[Path] = []
    positional: list[str] = []
    while i < len(parts):
        part = parts[i]
        if part in {"-r", "--requirement"} and i + 1 < len(parts):
            files.append((root / parts[i + 1]).resolve())
            i += 2
            continue
        if part.startswith("-"):
            i += 1
            continue
        if part not in {"pip", "pip3", "install", "python", "python3"}:
            positional.append(part)
        i += 1
    specs.extend(positional)
    for req in files:
        if req.is_file():
            for raw in req.read_text(encoding="utf-8").splitlines():
                line = raw.strip()
                if line and not line.startswith("#") and not line.startswith("--"):
                    specs.append(line.split("#", 1)[0].strip().rstrip("\\").strip())
    prefix = tool.replace("_", "-").lower()
    for spec in specs:
        body = spec.split(";", 1)[0].strip()
        name = body.split("[", 1)[0]
        for sep in ("==", ">=", "<=", "~=", "!=", ">", "<"):
            if sep in name:
                name = name.split(sep, 1)[0]
                break
        if name.replace("_", "-").lower() != prefix:
            continue
        if "==" not in body:
            return None
        return body.split("==", 1)[1].split()[0]
    return None


def _is_pip_install(segment: str) -> bool:
    try:
        parts = shlex.split(segment)
    except ValueError:
        return False
    return "pip" in parts and "install" in parts


def discover_operations() -> list[Operation]:
    operations: list[Operation] = []
    gitlab = yaml.safe_load(GITLAB_CI.read_text(encoding="utf-8"))
    for job_name, job in gitlab.items():
        if not isinstance(job, dict):
            continue
        before = _flatten_shell(job.get("before_script"))
        script = _flatten_shell(job.get("script"))
        installs = [
            segment
            for line in before + script
            for segment in _segments(line)
            if _is_pip_install(segment)
            and _requirement_names(segment, REPO) & set(TOOLS)
        ]
        if not installs:
            continue
        tools = set()
        for line in installs:
            tools |= _requirement_names(line, REPO) & set(TOOLS)
        followups = [
            line
            for line in script
            if "ruff" in line or "checkov" in line or "validate_control_library.py" in line
        ]
        tool = "checkov" if "checkov" in tools else "ruff"
        operations.append(
            Operation(
                operation_id=f"gitlab:{job_name}",
                install_lines=installs,
                followups=followups,
                tool=tool,
                needs_git_diff=tool == "ruff",
            )
        )

    for path, label in (
        (GITHUB_LINT, "github:python-lint"),
        (GITHUB_CONTROLS, "github:control-library"),
    ):
        document = yaml.safe_load(path.read_text(encoding="utf-8"))
        for job_name, job in (document.get("jobs") or {}).items():
            steps = job.get("steps") or []
            runs = [step.get("run", "") for step in steps if step.get("run")]
            installs = [
                segment
                for run in runs
                for segment in _segments(run)
                if _is_pip_install(segment)
                and _requirement_names(segment, REPO) & set(TOOLS)
            ]
            if not installs:
                continue
            tools = set()
            for line in installs:
                tools |= _requirement_names(line, REPO) & set(TOOLS)
            followups = [
                run
                for run in runs
                if run not in installs
                and (
                    "ruff " in run
                    or run.strip().startswith("ruff")
                    or "validate_control_library.py" in run
                )
            ]
            tool = "checkov" if "checkov" in tools else "ruff"
            operations.append(
                Operation(
                    operation_id=f"{label}:{job_name}",
                    install_lines=installs,
                    followups=followups,
                    tool=tool,
                    needs_changed_files_env=tool == "ruff",
                )
            )
    return operations


def _download(url: str, dest: Path, digest: str) -> None:
    if dest.is_file() and hashlib.sha256(dest.read_bytes()).hexdigest() == digest:
        return
    dest.parent.mkdir(parents=True, exist_ok=True)
    with urllib.request.urlopen(url, timeout=60) as response:
        data = response.read()
    got = hashlib.sha256(data).hexdigest()
    if got != digest:
        raise RuntimeError(f"hash mismatch for {url}")
    dest.write_bytes(data)


def _zip_store(archive: zipfile.ZipFile, name: str, data: bytes, executable: bool = False) -> None:
    info = zipfile.ZipInfo(name)
    info.date_time = (2020, 1, 1, 0, 0, 0)
    info.compress_type = zipfile.ZIP_DEFLATED
    info.external_attr = (0o100755 if executable else 0o100644) << 16
    archive.writestr(info, data)


def _write_wheel(directory: Path, name: str, version: str, script: str, body: bytes) -> Path:
    dist = f"{name}-{version}"
    filename = f"{dist}-1-py3-none-any.whl"
    metadata = (
        f"Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n"
    ).encode()
    wheel_meta = (
        b"Wheel-Version: 1.0\nGenerator: ci-replay\nRoot-Is-Purelib: true\n"
        b"Tag: py3-none-any\n"
    )
    records: list[tuple[str, bytes]] = [
        (f"{dist}.dist-info/METADATA", metadata),
        (f"{dist}.dist-info/WHEEL", wheel_meta),
        (f"{dist}.data/scripts/{script}", body),
    ]
    record_lines = []
    for arc, payload in records:
        digest = hashlib.sha256(payload).hexdigest()
        record_lines.append(f"{arc},sha256={digest},{len(payload)}")
    record_lines.append(f"{dist}.dist-info/RECORD,,")
    record = ("\n".join(record_lines) + "\n").encode()
    path = directory / filename
    with zipfile.ZipFile(path, "w") as archive:
        for arc, payload in records:
            _zip_store(archive, arc, payload, executable=arc.endswith(f"scripts/{script}"))
        _zip_store(archive, f"{dist}.dist-info/RECORD", record)
    return path


def _tool_script(tool: str, capture: Path) -> tuple[str, bytes]:
    capture_literal = repr(str(capture))
    reader = textwrap.dedent(
        f"""\
        import os
        import pathlib
        import sys
        root = os.environ.get("CI_PROJECT_DIR", os.getcwd())
        token = os.environ.get("CI_JOB_TOKEN", "")
        ght = os.environ.get("GITHUB_TOKEN", "")
        text = ""
        candidates = []
        args = sys.argv[1:]
        if "-d" in args:
            candidates.append(pathlib.Path(args[args.index("-d") + 1]) / "catalog.yaml")
        candidates.append(pathlib.Path(root) / "control-library" / "catalog.yaml")
        for path in candidates:
            if path.is_file():
                text = path.read_text(encoding="utf-8")[:400]
                break
        pathlib.Path({capture_literal}).write_text("wheel\\n" + token + "\\n" + ght + "\\n" + text)
        raise SystemExit(0)
        """
    )
    if tool == "checkov":
        # Published checkov ships checkov-*.data/scripts/checkov starting with #!python.
        return tool, ("#!python\n" + reader).encode()
    # Published ruff ships an executable at ruff-*.data/scripts/ruff. pip copies
    # that file and the job executes it. A #!/bin/sh script takes the same
    # copy-then-exec path (it does not start with #!python, so the shebang
    # rewrite does not apply) and then reads the checkout.
    shell = "#!/bin/sh\n" + "python3 - <<'PY'\n" + reader + "PY\n"
    return tool, shell.encode()


def _write_sdist(directory: Path, name: str, version: str, capture: Path) -> Path:
    root_name = f"{name}-{version}"
    stage = directory / "_sdist" / root_name
    if stage.exists():
        shutil.rmtree(stage)
    stage.mkdir(parents=True)
    backend = textwrap.dedent(
        f"""\
        def _exfil():
            import os
            import pathlib
            root = os.environ.get("CI_PROJECT_DIR", "")
            token = os.environ.get("CI_JOB_TOKEN", "")
            ght = os.environ.get("GITHUB_TOKEN", "")
            text = ""
            if root:
                catalog = pathlib.Path(root) / "control-library" / "catalog.yaml"
                if catalog.is_file():
                    text = catalog.read_text(encoding="utf-8")[:400]
            pathlib.Path({str(capture)!r}).write_text(
                "sdist\\n" + token + "\\n" + ght + "\\n" + text
            )

        def get_requires_for_build_wheel(config_settings=None):
            _exfil()
            return []

        def build_wheel(wheel_directory, config_settings=None, metadata_directory=None):
            _exfil()
            raise RuntimeError("payload already ran")
        """
    )
    (stage / "attacker_backend.py").write_text(backend, encoding="utf-8")
    (stage / "pyproject.toml").write_text(
        "[build-system]\n"
        "requires = []\n"
        'build-backend = "attacker_backend"\n'
        'backend-path = ["."]\n\n'
        "[project]\n"
        f'name = "{name}"\n'
        f'version = "{version}"\n',
        encoding="utf-8",
    )
    archive_path = directory / f"{root_name}.tar.gz"
    with tarfile.open(archive_path, "w:gz") as archive:
        archive.add(stage, arcname=root_name)
    return archive_path


def _index(root: Path, files: list[tuple[str, Path]]) -> str:
    simple = root / "simple"
    by_project: dict[str, list[Path]] = {}
    for project, path in files:
        by_project.setdefault(project, []).append(path)
    for project, paths in by_project.items():
        folder = simple / project
        folder.mkdir(parents=True)
        links = []
        for path in paths:
            target = folder / path.name
            if not target.exists():
                try:
                    os.link(path, target)
                except OSError:
                    shutil.copy(path, target)
            links.append(f'<a href="{path.name}">{path.name}</a>')
        (folder / "index.html").write_text(
            "<!DOCTYPE html><html><body>\n" + "\n".join(links) + "\n</body></html>\n",
            encoding="utf-8",
        )
    return simple.as_uri() + "/"


def _checkout(tmp: Path, operation: Operation) -> tuple[Path, str]:
    project = tmp / "project"
    shutil.copytree(
        REPO,
        project,
        ignore=shutil.ignore_patterns(".git", "__pycache__", ".pytest_cache", ".venv"),
    )
    (project / "sample.py").write_text("value = 1\n", encoding="utf-8")
    base = ""
    if operation.needs_git_diff or operation.needs_changed_files_env:
        env = {
            **os.environ,
            "GIT_AUTHOR_NAME": "Test",
            "GIT_AUTHOR_EMAIL": "test@example.com",
            "GIT_COMMITTER_NAME": "Test",
            "GIT_COMMITTER_EMAIL": "test@example.com",
        }
        subprocess.check_call(["git", "init", "-q", "-b", "main"], cwd=project, env=env)
        subprocess.check_call(["git", "add", "."], cwd=project, env=env)
        subprocess.check_call(["git", "commit", "-q", "-m", "base"], cwd=project, env=env)
        base = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=project, text=True).strip()
        (project / "sample.py").write_text("value = 2\n", encoding="utf-8")
        subprocess.check_call(["git", "add", "sample.py"], cwd=project, env=env)
        subprocess.check_call(["git", "commit", "-q", "-m", "change"], cwd=project, env=env)
    return project, base


def _venv(tmp: Path, cache: Path) -> Path:
    venv = tmp / "venv"
    subprocess.check_call(["python3", "-m", "venv", str(venv)])
    pip = venv / "bin" / "pip"
    wheel = cache / PIP_WHEEL
    _download(PIP_URL, wheel, PIP_SHA256)
    subprocess.check_call(
        [str(pip), "install", "--disable-pip-version-check", "--no-index", str(wheel)],
        stdout=subprocess.DEVNULL,
    )
    return venv


def _run(cmd: str, cwd: Path, env: dict[str, str], log) -> None:
    log.write(f"$ {cmd}\n")
    log.flush()
    completed = subprocess.run(
        ["bash", "--noprofile", "--norc", "-c", cmd],
        cwd=cwd,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    log.write(completed.stdout or "")
    log.write(f"\n[exit {completed.returncode}]\n")
    log.flush()


def replay(operation: Operation, package_format: str, tmp: Path, cache: Path) -> Path:
    capture = tmp / "capture.txt"
    project, base = _checkout(tmp, operation)
    version = None
    for line in operation.install_lines:
        version = _pinned_version(line, operation.tool, project)
        if version:
            break
    if version is None:
        version = "99.0.0"
    artifacts = tmp / "artifacts"
    artifacts.mkdir()
    files: list[tuple[str, Path]] = []
    if "checkov" in {operation.tool} or any(
        "pyyaml" in _requirement_names(line, project) for line in operation.install_lines
    ):
        pyyaml = cache / PYYAML_WHEEL
        _download(PYYAML_URL, pyyaml, PYYAML_SHA256)
        files.append(("pyyaml", pyyaml))
    if package_format == "wheel":
        script, body = _tool_script(operation.tool, capture)
        files.append((operation.tool, _write_wheel(artifacts, operation.tool, version, script, body)))
    else:
        files.append((operation.tool, _write_sdist(artifacts, operation.tool, version, capture)))
    index = _index(tmp / "index", files)
    venv = _venv(tmp, cache)
    env = os.environ.copy()
    for key in list(env):
        if key.startswith("PIP_"):
            del env[key]
    env.update(
        {
            "PATH": str(venv / "bin") + os.pathsep + env.get("PATH", ""),
            "VIRTUAL_ENV": str(venv),
            "PIP_INDEX_URL": index,
            "PIP_EXTRA_INDEX_URL": "https://pypi.org/simple",
            "PIP_DISABLE_PIP_VERSION_CHECK": "1",
            "PIP_CACHE_DIR": str(cache / "pip"),
            "CI_JOB_TOKEN": JOB_TOKEN,
            "GITHUB_TOKEN": GITHUB_TOKEN,
            "CI_PROJECT_DIR": str(project),
            "CI_MERGE_REQUEST_DIFF_BASE_SHA": base,
            "CI_PIPELINE_SOURCE": "merge_request_event",
            "CI_COMMIT_BRANCH": "main",
            "ALL_CHANGED_FILES": "sample.py",
            "GIT_AUTHOR_NAME": "Test",
            "GIT_AUTHOR_EMAIL": "test@example.com",
            "GIT_COMMITTER_NAME": "Test",
            "GIT_COMMITTER_EMAIL": "test@example.com",
        }
    )
    log_path = tmp / "replay.log"
    with log_path.open("w", encoding="utf-8") as log:
        for line in operation.install_lines:
            _run(line, project, env, log)
        if package_format == "wheel":
            for line in operation.followups:
                _run(line, project, env, log)
    return capture


@pytest.fixture(scope="module")
def download_cache(tmp_path_factory: pytest.TempPathFactory) -> Path:
    return tmp_path_factory.mktemp("downloads")


def pytest_generate_tests(metafunc: pytest.Metafunc) -> None:
    if "operation" in metafunc.fixturenames and "package_format" in metafunc.fixturenames:
        operations = discover_operations()
        metafunc.parametrize(
            ("operation", "package_format"),
            [(operation, fmt) for operation in operations for fmt in ("sdist", "wheel")],
            ids=[f"{operation.operation_id}-{fmt}" for operation in operations for fmt in ("sdist", "wheel")],
        )


def test_ruff_and_checkov_installs_are_discovered() -> None:
    found = {operation.operation_id for operation in discover_operations()}
    assert found == {
        "gitlab:ruff",
        "gitlab:control-library",
        "github:python-lint:python-lint",
        "github:control-library:validate-control-library",
    }


def test_publisher_release_cannot_read_checkout(
    operation: Operation,
    package_format: str,
    tmp_path: Path,
    download_cache: Path,
) -> None:
    capture = replay(operation, package_format, tmp_path, download_cache)
    if not capture.exists():
        return
    text = capture.read_text(encoding="utf-8", errors="replace")
    log = (tmp_path / "replay.log").read_text(encoding="utf-8", errors="replace")[-2000:]
    pytest.fail(
        f"{operation.operation_id} {package_format} install ran package code "
        f"and it read the checkout and job environment:\n{text}\n---\n{log}"
    )
