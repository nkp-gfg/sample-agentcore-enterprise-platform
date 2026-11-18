"""Supply-chain spec for the ASH GitHub Actions install.

The monthly full-repository scan and the pull-request scan both install
Automated Security Helper with pip from a git revision. These tests execute
that install the way pip resolves a revision, against a local stand-in of the
upstream repository whose tag can be moved. They fail while a moved tag's
build backend runs inside the job and can read the checkout credential and
the checked-out source. They pass when both workflows install from an
immutable commit or from a checksum-verified artifact, and when checkout does
not leave the job token on disk.

Run:
    python3 -m pytest tests/test_ash_workflow_supply_chain.py -q
"""

from __future__ import annotations

import base64
import os
import re
import shutil
import subprocess
import textwrap
import uuid
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
FULL_SCAN = REPO_ROOT / ".github" / "workflows" / "ash-full-repository-scan.yml"
PR_SCAN = REPO_ROOT / ".github" / "workflows" / "ash-security-scan.yml"
ASH_WORKFLOWS = (FULL_SCAN, PR_SCAN)

ASH_GIT_URL = "https://github.com/awslabs/automated-security-helper.git"
GIT_REQUIREMENT = re.compile(
    r"git\+https://github\.com/awslabs/automated-security-helper\.git@(?P<rev>[A-Za-z0-9_./-]+)"
)
SHA40 = re.compile(r"^[0-9a-fA-F]{40}$")
SHA256_HEX = re.compile(r"\b([0-9a-fA-F]{64})\b")
# Obvious placeholder. This is not a credential.
JOB_TOKEN_PLACEHOLDER = "PLACEHOLDER_JOB_TOKEN"
SOURCE_SENTINEL_NAME = "SOURCE_SENTINEL.txt"
SOURCE_SENTINEL_TEXT = "workspace-source-sentinel"


def _load_workflow(path: Path) -> dict:
    document = yaml.safe_load(path.read_text())
    assert isinstance(document, dict)
    return document


def _checkout_steps(workflow: dict) -> list[dict]:
    steps: list[dict] = []
    for job in (workflow.get("jobs") or {}).values():
        for step in job.get("steps") or []:
            uses = str(step.get("uses") or "")
            if uses.startswith("actions/checkout@"):
                steps.append(step)
    return steps


def _run_scripts(workflow: dict) -> list[str]:
    scripts: list[str] = []
    for job in (workflow.get("jobs") or {}).values():
        for step in job.get("steps") or []:
            run = step.get("run")
            if isinstance(run, str):
                scripts.append(run)
    return scripts


def _ash_git_revisions(workflow_text: str) -> list[str]:
    return [match.group("rev") for match in GIT_REQUIREMENT.finditer(workflow_text)]


def _mutable_revisions(revisions: list[str]) -> list[str]:
    return [revision for revision in revisions if not SHA40.fullmatch(revision)]


def _checksum_guarded_local_install(scripts: list[str]) -> bool:
    """A release-artifact install is guarded only when a digest is checked first.

    The check has to be a literal digest compared before pip runs, and the pip
    install that follows has to be a local file. Re-resolving a git tag after
    the check does not count: the tag can move between the check and the use.
    """

    for script in scripts:
        if "automated-security-helper" not in script and "pip install" not in script:
            continue
        digest = SHA256_HEX.search(script)
        if digest is None or "sha256sum -c" not in script:
            continue
        if not re.search(r"(?m)^set -e\b", script):
            continue
        checksum_at = script.index("sha256sum -c")
        pip_at = script.find("pip install", checksum_at)
        if pip_at < 0:
            continue
        pip_line = script[pip_at:].splitlines()[0]
        if "git+" in pip_line or pip_line.strip().startswith("pip install http"):
            continue
        if "|| true" in script[checksum_at:pip_at]:
            continue
        return True
    return False


def _git(repo: Path, *args: str) -> str:
    completed = subprocess.run(
        ["git", *args],
        cwd=repo,
        check=True,
        capture_output=True,
        text=True,
    )
    return completed.stdout.strip()


def _write_backend(repo: Path, *, malicious: bool, marker: Path) -> None:
    marker_literal = str(marker)
    if malicious:
        body = textwrap.dedent(
            f"""\
            import base64
            import os
            import subprocess
            from pathlib import Path

            MARKER = Path({marker_literal!r})

            def _job_token_available(workspace: Path) -> bool:
                completed = subprocess.run(
                    ["git", "config", "--local", "--get-regexp", r"includeIf\\..*\\.path"],
                    cwd=workspace,
                    capture_output=True,
                    text=True,
                )
                if completed.returncode != 0:
                    return False
                for line in completed.stdout.splitlines():
                    parts = line.split(None, 1)
                    if len(parts) != 2:
                        continue
                    credential_file = Path(parts[1])
                    if not credential_file.is_file():
                        continue
                    body = credential_file.read_text()
                    marker = "AUTHORIZATION: basic "
                    start = body.find(marker)
                    if start < 0:
                        continue
                    encoded = body[start + len(marker):].splitlines()[0].strip()
                    decoded = base64.b64decode(encoded).decode()
                    if decoded.startswith("x-access-token:"):
                        return True
                return False

            def _record() -> None:
                workspace = Path(os.environ["GITHUB_WORKSPACE"])
                source_read = (workspace / {SOURCE_SENTINEL_NAME!r}).read_text() == {SOURCE_SENTINEL_TEXT!r}
                token_read = _job_token_available(workspace)
                MARKER.write_text(
                    "executed\\n"
                    f"source_read={{int(source_read)}}\\n"
                    f"token_read={{int(token_read)}}\\n"
                )

            def get_requires_for_build_wheel(config_settings=None):
                _record()
                return []

            def build_wheel(wheel_directory, config_settings=None, metadata_directory=None):
                _record()
                return _write_wheel(wheel_directory)
            """
        )
    else:
        body = textwrap.dedent(
            """\
            def get_requires_for_build_wheel(config_settings=None):
                return []

            def build_wheel(wheel_directory, config_settings=None, metadata_directory=None):
                return _write_wheel(wheel_directory)
            """
        )
    wheel_writer = textwrap.dedent(
        """\
        def _write_wheel(wheel_directory):
            import base64
            import hashlib
            import os
            import zipfile

            name = "automated_security_helper-3.2.2-py3-none-any.whl"
            dist = "automated_security_helper-3.2.2.dist-info"
            files = {
                f"{dist}/METADATA": (
                    "Metadata-Version: 2.1\\n"
                    "Name: automated-security-helper\\n"
                    "Version: 3.2.2\\n"
                ).encode(),
                f"{dist}/WHEEL": (
                    "Wheel-Version: 1.0\\n"
                    "Generator: backend\\n"
                    "Root-Is-Purelib: true\\n"
                    "Tag: py3-none-any\\n"
                ).encode(),
                f"{dist}/entry_points.txt": (
                    "[console_scripts]\\n"
                    "ash = ash_entry:main\\n"
                ).encode(),
                "ash_entry.py": b"def main():\\n    raise SystemExit(0)\\n",
            }
            record = []
            for arcname, data in files.items():
                digest = hashlib.sha256(data).digest()
                encoded = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
                record.append(f"{arcname},sha256={encoded},{len(data)}\\n")
            record.append(f"{dist}/RECORD,,\\n")
            files[f"{dist}/RECORD"] = "".join(record).encode()
            path = os.path.join(wheel_directory, name)
            with zipfile.ZipFile(path, "w") as archive:
                for arcname, data in files.items():
                    archive.writestr(arcname, data)
            return name
        """
    )
    (repo / "backend.py").write_text(body + "\n" + wheel_writer)
    (repo / "pyproject.toml").write_text(
        textwrap.dedent(
            """\
            [build-system]
            requires = []
            build-backend = "backend"
            backend-path = ["."]

            [project]
            name = "automated-security-helper"
            version = "3.2.2"
            """
        )
    )


def _commit(repo: Path, message: str) -> str:
    _git(repo, "add", "backend.py", "pyproject.toml")
    _git(
        repo,
        "-c",
        "user.email=ash-test@example.invalid",
        "-c",
        "user.name=ASH Test",
        "commit",
        "-m",
        message,
    )
    return _git(repo, "rev-parse", "HEAD")


def _upstream(tmp: Path, marker: Path) -> tuple[Path, str]:
    repo = tmp / "upstream"
    repo.mkdir(parents=True)
    _git(repo, "init", "-b", "main")
    _write_backend(repo, malicious=False, marker=marker)
    good_sha = _commit(repo, "benign package")
    _git(repo, "tag", "v3.2.2")
    _write_backend(repo, malicious=True, marker=marker)
    _commit(repo, "moved tag package")
    _git(repo, "tag", "-f", "v3.2.2")
    moved = _git(repo, "rev-parse", "v3.2.2^{}")
    assert moved != good_sha
    return repo, good_sha


def _persist_checkout_credential(workspace: Path, runner_temp: Path) -> None:
    """Write the credential the way actions/checkout leaves it when persisting."""

    runner_temp.mkdir(parents=True, exist_ok=True)
    credential_path = runner_temp / f"git-credentials-{uuid.uuid4()}.config"
    basic = base64.b64encode(
        f"x-access-token:{JOB_TOKEN_PLACEHOLDER}".encode()
    ).decode()
    subprocess.run(
        [
            "git",
            "config",
            "--file",
            str(credential_path),
            "http.https://github.com/.extraheader",
            f"AUTHORIZATION: basic {basic}",
        ],
        check=True,
    )
    git_dir = (workspace / ".git").as_posix()
    subprocess.run(
        [
            "git",
            "config",
            "--local",
            f"includeIf.gitdir:{git_dir}.path",
            str(credential_path),
        ],
        cwd=workspace,
        check=True,
    )


def _workspace(tmp: Path, *, persist_credentials: bool) -> Path:
    workspace = tmp / "workspace"
    workspace.mkdir(parents=True)
    _git(workspace, "init", "-b", "main")
    (workspace / SOURCE_SENTINEL_NAME).write_text(SOURCE_SENTINEL_TEXT)
    _git(workspace, "add", SOURCE_SENTINEL_NAME)
    _git(
        workspace,
        "-c",
        "user.email=ash-test@example.invalid",
        "-c",
        "user.name=ASH Test",
        "commit",
        "-m",
        "checkout",
    )
    if persist_credentials:
        _persist_checkout_credential(workspace, tmp / "runner-temp")
    return workspace


def _pip_install(requirement: str, workspace: Path, target: Path) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["GITHUB_WORKSPACE"] = str(workspace)
    env["PIP_DISABLE_PIP_VERSION_CHECK"] = "1"
    return subprocess.run(
        [
            "pip3",
            "install",
            "--target",
            str(target),
            "--no-cache-dir",
            requirement,
        ],
        cwd=workspace,
        env=env,
        capture_output=True,
        text=True,
    )


def _marker_shows_exposure(marker: Path) -> bool:
    if not marker.is_file():
        return False
    text = marker.read_text()
    return "executed" in text and "source_read=1" in text and "token_read=1" in text


def _install_requirement_for_workflow(
    workflow_text: str,
    upstream: Path,
    good_sha: str,
) -> str | None:
    """Return the pip requirement the workflow will execute, or None if guarded.

    A full commit hash is installed as that immutable object. The local benign
    commit stands in for the pinned hash: pip checks out the named object and
    does not look the tag up again. A tag or branch name is installed as that
    name, which git resolves at install time.
    """

    revisions = _ash_git_revisions(workflow_text)
    if not revisions:
        return None
    mutable = _mutable_revisions(revisions)
    if mutable:
        return f"git+file://{upstream.resolve()}@{mutable[0]}"
    return f"git+file://{upstream.resolve()}@{good_sha}"


def _workflow_persists_credentials(workflow: dict) -> bool:
    steps = _checkout_steps(workflow)
    if not steps:
        return True
    for step in steps:
        value = (step.get("with") or {}).get("persist-credentials", True)
        if value is True or str(value).strip().lower() == "true":
            return True
    return False


@pytest.mark.parametrize("workflow_path", ASH_WORKFLOWS, ids=["full-scan", "pull-request"])
def test_moved_tag_cannot_execute_during_ash_install(workflow_path: Path, tmp_path: Path):
    workflow_text = workflow_path.read_text()
    workflow = _load_workflow(workflow_path)
    scripts = _run_scripts(workflow)
    marker = tmp_path / "exploit-marker.txt"
    upstream, good_sha = _upstream(tmp_path, marker)
    workspace = _workspace(
        tmp_path,
        persist_credentials=_workflow_persists_credentials(workflow),
    )

    # The tag name itself is exploitable. This stays true after the workflow
    # is pinned; it checks that the harness still exercises pip.
    control_marker = tmp_path / "control-marker.txt"
    control_upstream, _ = _upstream(tmp_path / "control", control_marker)
    control_workspace = _workspace(tmp_path / "control-ws", persist_credentials=True)
    control = _pip_install(
        f"git+file://{control_upstream.resolve()}@v3.2.2",
        control_workspace,
        tmp_path / "control-target",
    )
    assert _marker_shows_exposure(control_marker), (
        "pip did not execute the moved tag's build backend.\n"
        f"exit={control.returncode}\n"
        f"stdout={control.stdout[-2000:]}\n"
        f"stderr={control.stderr[-2000:]}"
    )

    if _checksum_guarded_local_install(scripts) and not _mutable_revisions(
        _ash_git_revisions(workflow_text)
    ):
        _assert_replaced_artifact_fails_checksum(scripts)
        assert not marker.exists()
        return

    requirement = _install_requirement_for_workflow(workflow_text, upstream, good_sha)
    assert requirement is not None, workflow_text
    completed = _pip_install(requirement, workspace, tmp_path / "target")
    assert not _marker_shows_exposure(marker), (
        "Installing the workflow's ASH requirement executed the moved tag. "
        "The build backend read the checked-out source and the checkout credential "
        f"for {workflow_path.relative_to(REPO_ROOT)}.\n"
        f"requirement={requirement}\n"
        f"pip_exit={completed.returncode}\n"
        f"marker={marker.read_text() if marker.exists() else 'absent'}"
    )


@pytest.mark.parametrize("workflow_path", ASH_WORKFLOWS, ids=["full-scan", "pull-request"])
def test_checkout_does_not_keep_the_job_token(workflow_path: Path):
    workflow = _load_workflow(workflow_path)
    steps = _checkout_steps(workflow)
    assert steps, f"{workflow_path} has no actions/checkout step"
    for step in steps:
        value = (step.get("with") or {}).get("persist-credentials")
        assert str(value).strip().lower() == "false", (
            f"{workflow_path.relative_to(REPO_ROOT)} checkout persists the job token"
        )


def _assert_replaced_artifact_fails_checksum(scripts: list[str]) -> None:
    """Run sha256sum -c the way the workflow step does, against a replaced file.

    pip is not started unless that check succeeds. A moved or substituted
    artifact must fail the digest comparison first.
    """

    script = next(item for item in scripts if "sha256sum -c" in item and "pip install" in item)
    digest = SHA256_HEX.search(script)
    assert digest is not None
    target = Path("/tmp") / f"ash-replaced-{uuid.uuid4().hex}"
    target.write_bytes(b"replaced-artifact")
    try:
        check = subprocess.run(
            ["sha256sum", "-c", "-"],
            input=f"{digest.group(1)}  {target}\n",
            text=True,
            capture_output=True,
        )
    finally:
        target.unlink(missing_ok=True)
    assert check.returncode != 0


def test_full_scan_install_is_immutable_or_checksum_guarded():
    workflow_text = FULL_SCAN.read_text()
    scripts = _run_scripts(_load_workflow(FULL_SCAN))
    revisions = _ash_git_revisions(workflow_text)
    if _checksum_guarded_local_install(scripts) and not _mutable_revisions(revisions):
        _assert_replaced_artifact_fails_checksum(scripts)
        return
    assert revisions and not _mutable_revisions(revisions), (
        "ash-full-repository-scan.yml installs ASH from a movable git ref "
        f"{_mutable_revisions(revisions) or revisions}"
    )
