"""The monthly ASH workflow must not run movable third-party refs with issue write.

A tag is resolved when the job runs. These tests move that tag after the
reviewed commit is recorded, then execute the commit the ref resolves to.
The action path follows actions/runner v2.338.2: a full 40-character SHA is
the object id, any other ref is a tag, and an action input whose default is
the github.token expression is passed to the action process as INPUT_<NAME>.
The install path follows pip 24.0: the revision after @ in a git+ URL is
looked up as refs/tags/<rev>, and setup.py is executed from that commit.
"""

from __future__ import annotations

import base64
import os
import re
import subprocess
import textwrap
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_PATH = REPO_ROOT / ".github" / "workflows" / "ash-full-repository-scan.yml"
FULL_SHA = re.compile(r"^[0-9a-fA-F]{40}$")
TOKEN_EXPRESSIONS = {
    "${{ github.token }}",
    "${{github.token}}",
    "${{ secrets.GITHUB_TOKEN }}",
    "${{secrets.GITHUB_TOKEN}}",
}
# Placeholder only. The real job token is supplied by the Actions service.
JOB_TOKEN = "JOB_TOKEN_PLACEHOLDER"
SCAN_ACTION_REPOS = (
    "actions/checkout",
    "actions/setup-python",
    "actions/upload-artifact",
)


def _load_workflow():
    document = yaml.safe_load(WORKFLOW_PATH.read_text())
    # PyYAML 1.1 parses the unquoted key "on" as boolean true.
    if True in document and "on" not in document:
        document["on"] = document.pop(True)
    return document


def _git(repo: Path, *args: str) -> str:
    completed = subprocess.run(
        ["git", *args],
        cwd=repo,
        check=True,
        capture_output=True,
        text=True,
    )
    return completed.stdout.strip()


def _init_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir(parents=True)
    _git(repo, "init", "-q")
    _git(repo, "config", "user.email", "tests@example.com")
    _git(repo, "config", "user.name", "tests")
    return repo


def _commit_tree(repo: Path, files: dict[str, str], message: str) -> str:
    for name, contents in files.items():
        path = repo / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(contents)
        _git(repo, "add", name)
    _git(repo, "commit", "-q", "-m", message)
    return _git(repo, "rev-parse", "HEAD")


def _normalize_permissions(value) -> dict[str, str]:
    """Apply the workflow-syntax rule for one permissions block.

    Specifying any permission sets every permission that is absent to none.
    write-all grants every permission, including issues.
    """
    if value is None:
        return {}
    if value == "write-all":
        return {"issues": "write", "contents": "write"}
    if value == "read-all":
        return {"issues": "read", "contents": "read"}
    if not isinstance(value, dict):
        raise AssertionError(f"unsupported permissions value: {value!r}")
    return {str(key): str(access) for key, access in value.items()}


def _job_permissions(workflow: dict, job: dict) -> dict[str, str]:
    """Job permissions replace the workflow block when the job sets its own."""
    if "permissions" in job:
        return _normalize_permissions(job.get("permissions"))
    if "permissions" in workflow:
        return _normalize_permissions(workflow.get("permissions"))
    return {}


def _issues_write(permissions: dict[str, str]) -> bool:
    return permissions.get("issues") == "write"


def _uses_steps(job: dict) -> list[dict]:
    steps = []
    for step in job.get("steps") or []:
        uses = step.get("uses")
        if isinstance(uses, str) and "@" in uses and not uses.startswith("./"):
            steps.append(step)
    return steps


def _split_uses(uses: str) -> tuple[str, str]:
    owner_repo, ref = uses.rsplit("@", 1)
    return owner_repo, ref


def _evaluate_token_expression(value: str) -> str:
    if value.strip() in TOKEN_EXPRESSIONS:
        return JOB_TOKEN
    return value


def _action_environment(action_yaml: str, workflow_inputs: dict) -> dict[str, str]:
    """Evaluate action inputs the way ActionRunner merges defaults.

    Workflow `with` values win. A missing input uses the action.yml default.
    The github.token expression evaluates to the job token, then the input is
    exported as INPUT_<NAME>, matching Handler.AddInputsToEnvironment.
    """
    action = yaml.safe_load(action_yaml) or {}
    supplied = {
        str(key): _evaluate_token_expression(str(value))
        for key, value in (workflow_inputs or {}).items()
    }
    merged = dict(supplied)
    for name, meta in (action.get("inputs") or {}).items():
        if name in merged:
            continue
        default = ""
        if isinstance(meta, dict) and "default" in meta:
            default = _evaluate_token_expression(str(meta.get("default") or ""))
        merged[name] = default
    environment = {}
    for name, value in merged.items():
        environment[f"INPUT_{name.replace(' ', '_').upper()}"] = value
    return environment


def _create_issue(token: str, permissions: dict[str, str], title: str) -> dict | None:
    """Stand-in for POST /repos/{owner}/{repo}/issues.

    The workflow grants issues: write and calls this endpoint with the job
    token. Unspecified permissions are none, so the call is refused unless
    issues is write.
    """
    if token != JOB_TOKEN or not _issues_write(permissions):
        return None
    return {"title": title, "token": token}


def _benign_action() -> dict[str, str]:
    return {
        "action.yml": textwrap.dedent(
            """\
            name: Reviewed
            runs:
              using: node20
              main: main.py
            """
        ),
        "main.py": "raise SystemExit(0)\n",
    }


def _malicious_action() -> dict[str, str]:
    return {
        "action.yml": textwrap.dedent(
            """\
            name: Moved tag
            inputs:
              token:
                default: ${{ github.token }}
            runs:
              using: node20
              main: main.py
            """
        ),
        "main.py": textwrap.dedent(
            """\
            import os
            from pathlib import Path
            Path(os.environ["ATTACK_RESULT"]).write_text(os.environ.get("INPUT_TOKEN", ""))
            """
        ),
    }


def _run_action_commit(
    repo: Path,
    commit: str,
    workflow_inputs: dict,
    permissions: dict[str, str],
    result_path: Path,
) -> dict | None:
    _git(repo, "checkout", "-q", "--detach", commit)
    environment = _action_environment(
        (repo / "action.yml").read_text(),
        workflow_inputs,
    )
    env = os.environ.copy()
    env.update(environment)
    env["ATTACK_RESULT"] = str(result_path)
    subprocess.run(
        ["python3", "main.py"],
        cwd=repo,
        check=True,
        env=env,
    )
    recovered = result_path.read_text() if result_path.exists() else ""
    return _create_issue(recovered, permissions, "opened by moved action tag")


def _resolve_after_move(tmp_path: Path, ref: str, workflow_inputs: dict, permissions):
    """Move the ref the workflow named, then run the commit that resolves."""
    repo = _init_repo(tmp_path)
    benign = _commit_tree(repo, _benign_action(), "reviewed action")
    malicious = _commit_tree(repo, _malicious_action(), "moved tag")
    result_path = tmp_path / "attack-result.txt"

    if FULL_SHA.fullmatch(ref):
        # A full SHA names the reviewed object. Retargeting a tag leaves it.
        _git(repo, "tag", "-f", "moved-tag", benign)
        _git(repo, "tag", "-f", "moved-tag", malicious)
        executed = _git(repo, "rev-parse", f"{benign}^{{commit}}")
        reviewed = benign
    else:
        _git(repo, "tag", "-f", ref, benign)
        reviewed = _git(repo, "rev-parse", f"refs/tags/{ref}^{{commit}}")
        _git(repo, "tag", "-f", ref, malicious)
        show_ref = _git(repo, "show-ref", ref)
        executed = ""
        for line in show_ref.splitlines():
            sha, name = line.split()
            if name == f"refs/tags/{ref}":
                executed = _git(repo, "rev-parse", f"{sha}^{{commit}}")
        if not executed:
            raise AssertionError(f"tag {ref} did not resolve")

    issue = _run_action_commit(
        repo, executed, workflow_inputs, permissions, result_path
    )
    return reviewed, executed, issue


def _workflow_cases():
    workflow = _load_workflow()
    cases = []
    for job_name, job in (workflow.get("jobs") or {}).items():
        permissions = _job_permissions(workflow, job)
        for step in _uses_steps(job):
            owner_repo, ref = _split_uses(step["uses"])
            cases.append(
                pytest.param(
                    ref,
                    step.get("with") or {},
                    permissions,
                    id=f"{job_name}-{owner_repo}",
                )
            )
    return cases


@pytest.mark.parametrize(
    ("ref", "workflow_inputs", "permissions"),
    _workflow_cases(),
)
def test_moved_action_tag_cannot_open_an_issue(
    tmp_path: Path, ref: str, workflow_inputs: dict, permissions: dict
):
    reviewed, executed, issue = _resolve_after_move(
        tmp_path, ref, workflow_inputs, permissions
    )
    assert executed == reviewed and issue is None, (
        f"{WORKFLOW_PATH.name} ref {ref!r} resolved to {executed} after the tag "
        f"moved away from reviewed commit {reviewed}. The action at that commit "
        f"received the job token and opened an issue ({issue}) with "
        f"permissions {permissions}. Pin the action to a full commit SHA."
    )


def _git_install_revision(workflow: dict) -> str | None:
    for job in (workflow.get("jobs") or {}).values():
        for step in job.get("steps") or []:
            script = step.get("run")
            if not isinstance(script, str) or "git+" not in script:
                continue
            for token in script.split():
                if token.startswith("git+") and "@" in token:
                    path = token.split("://", 1)[-1]
                    _base, revision = path.rsplit("@", 1)
                    return revision.split("#", 1)[0]
    return None


def _write_checkout_credentials(workspace: Path, runner_temp: Path, token: str) -> None:
    """Write the credential file checkout persists when persist-credentials is true.

    actions/checkout at 3d3c42e5 stores base64("x-access-token:<token>") in a
    config file under RUNNER_TEMP and points the worktree git config at it.
    The post step deletes that file only after later steps have run.
    """
    runner_temp.mkdir(parents=True, exist_ok=True)
    credential_file = runner_temp / "git-credentials.config"
    basic = base64.b64encode(f"x-access-token:{token}".encode()).decode()
    credential_file.write_text(
        '[http "https://github.com"]\n'
        f"\textraheader = AUTHORIZATION: basic {basic}\n"
    )
    _git(workspace, "init", "-q")
    git_dir = (workspace / ".git").resolve().as_posix()
    _git(
        workspace,
        "config",
        f"includeIf.gitdir:{git_dir}.path",
        str(credential_file),
    )


def _pip_resolve(repo: Path, revision: str) -> str:
    """Resolve a git+ URL revision the way pip 24.0 Git.get_revision_sha does."""
    if FULL_SHA.fullmatch(revision):
        return _git(repo, "rev-parse", f"{revision}^{{commit}}")
    show_ref = _git(repo, "show-ref", revision)
    for line in show_ref.splitlines():
        sha, name = line.split()
        if name == f"refs/tags/{revision}":
            return _git(repo, "rev-parse", f"{sha}^{{commit}}")
    raise AssertionError(f"pip did not resolve {revision}")


def test_moved_git_install_tag_cannot_open_an_issue(tmp_path: Path):
    workflow = _load_workflow()
    revision = _git_install_revision(workflow)
    assert revision, "expected a git+ install in the monthly scan"

    permissions = {}
    for job in (workflow.get("jobs") or {}).values():
        for step in job.get("steps") or []:
            script = step.get("run")
            if isinstance(script, str) and "git+" in script:
                permissions = _job_permissions(workflow, job)

    checkout_pins_credentials = True
    for job in (workflow.get("jobs") or {}).values():
        for step in job.get("steps") or []:
            uses = step.get("uses")
            if isinstance(uses, str) and uses.startswith("actions/checkout@"):
                supplied = step.get("with") or {}
                if str(supplied.get("persist-credentials", "true")).lower() == "false":
                    checkout_pins_credentials = False

    package = _init_repo(tmp_path / "package-src")
    benign = _commit_tree(
        package,
        {"setup.py": "print('reviewed package')\n"},
        "reviewed package",
    )
    malicious_setup = textwrap.dedent(
        """\
        import base64
        import os
        from pathlib import Path

        workspace = Path(os.environ["GITHUB_WORKSPACE"])
        config = (workspace / ".git" / "config").read_text()
        credential_path = ""
        for line in config.splitlines():
            stripped = line.strip()
            if stripped.startswith("path = "):
                credential_path = stripped.split("=", 1)[1].strip()
        text = Path(credential_path).read_text()
        encoded = text.split("AUTHORIZATION: basic ", 1)[1].split()[0]
        decoded = base64.b64decode(encoded).decode()
        token = decoded.split("x-access-token:", 1)[1]
        Path(os.environ["ATTACK_RESULT"]).write_text(token)
        """
    )
    malicious = _commit_tree(
        package,
        {"setup.py": malicious_setup},
        "moved package tag",
    )

    workspace = tmp_path / "workspace"
    workspace.mkdir()
    if checkout_pins_credentials:
        _write_checkout_credentials(workspace, tmp_path / "runner-temp", JOB_TOKEN)

    if FULL_SHA.fullmatch(revision):
        _git(package, "tag", "-f", "moved-tag", benign)
        _git(package, "tag", "-f", "moved-tag", malicious)
        executed = _pip_resolve(package, benign)
        reviewed = benign
    else:
        _git(package, "tag", "-f", revision, benign)
        reviewed = _git(package, "rev-parse", f"refs/tags/{revision}^{{commit}}")
        _git(package, "tag", "-f", revision, malicious)
        executed = _pip_resolve(package, revision)

    _git(package, "checkout", "-q", "--detach", executed)
    result_path = tmp_path / "install-result.txt"
    env = os.environ.copy()
    env["ATTACK_RESULT"] = str(result_path)
    env["GITHUB_WORKSPACE"] = str(workspace)
    # pip's setuptools shim execs setup.py from the resolved checkout.
    subprocess.run(["python3", "setup.py"], cwd=package, check=True, env=env)
    recovered = result_path.read_text() if result_path.exists() else ""
    issue = _create_issue(recovered, permissions, "opened by moved install tag")

    assert executed == reviewed and issue is None, (
        f"git install revision {revision!r} resolved to {executed} after the tag "
        f"moved away from reviewed commit {reviewed}. setup.py read the token "
        f"checkout persisted and opened an issue ({issue}) with permissions "
        f"{permissions}. Pin the git install to a full commit SHA."
    )


def test_scan_steps_do_not_receive_issues_write():
    workflow = _load_workflow()
    offenders = []
    for job_name, job in (workflow.get("jobs") or {}).items():
        permissions = _job_permissions(workflow, job)
        if not _issues_write(permissions):
            continue
        for step in job.get("steps") or []:
            uses = step.get("uses")
            script = step.get("run")
            shares_bug = False
            if isinstance(uses, str):
                owner_repo, _ref = _split_uses(uses) if "@" in uses else (uses, "")
                if owner_repo in SCAN_ACTION_REPOS:
                    shares_bug = True
            if isinstance(script, str) and "git+" in script:
                shares_bug = True
            if shares_bug:
                offenders.append(f"{job_name}: {uses or 'run'}")
    assert offenders == [], (
        "issues: write is granted to the whole job, so these steps receive the "
        f"token the monthly report uses to open issues: {offenders}. "
        "Move issue creation into a job that does not run checkout, "
        "setup-python, upload-artifact, or the git install."
    )
