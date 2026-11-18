"""Control-library jobs must keep the same validation result when an action tag moves.

The hosted runner (actions/runner v2.338.2) asks GitHub to resolve each
``uses`` ref on every job, downloads that commit, and runs it before the
validation commands. A full commit id stays on that object. A tag is the
tag's current commit, so moving the tag changes which action runs and can
change the validation result. These tests fail until every ``uses`` in
``.github/workflows/control-library.yml`` is a full commit SHA.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_PATH = REPO_ROOT / ".github" / "workflows" / "control-library.yml"
FULL_COMMIT = __import__("re").compile(r"^[0-9a-fA-F]{40}$")
# Stand-in for the job's contents:read token. Not a credential.
JOB_TOKEN = "placeholder-job-token"
POLICY_REL = Path("control-library/scp/gateway/deny-no-auth.json")
TERRAFORM_REL = Path("control-library/terraform/org-guardrails/main.tf")

# Same floating refs this workflow uses today. The fixture repos are named
# after the actions so a pin in the workflow no longer selects these tags.
ACTION_TAGS = {
    "actions/checkout": "v7",
    "actions/setup-python": "v7",
    "hashicorp/setup-terraform": "v4",
}


def _git(repo: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(repo), *args],
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def _commit_file(repo: Path, relative: str, text: str) -> None:
    path = repo / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    _git(repo, "add", relative)


def _action_manifest() -> str:
    # The downloaded action.yml is what the runner evaluates. A replacement
    # commit can default an input to the job token.
    return (
        "name: fixture\n"
        "inputs:\n"
        "  token:\n"
        "    default: ${{ github.token }}\n"
        "runs:\n"
        "  using: composite\n"
        "  steps:\n"
        "    - shell: bash\n"
        '      run: python3 "$GITHUB_ACTION_PATH/main.py"\n'
    )


def _write_commit(repo: Path, main_py: str, message: str) -> str:
    _commit_file(repo, "action.yml", _action_manifest())
    _commit_file(repo, "main.py", main_py)
    _git(repo, "commit", "-m", message)
    return _git(repo, "rev-parse", "HEAD")


def _init_action_repo(path: Path) -> None:
    path.mkdir(parents=True)
    _git(path, "init", "-q")
    _git(path, "config", "user.email", "action-fixture@example.com")
    _git(path, "config", "user.name", "action-fixture")


def _proof_reader(role: str) -> str:
    return f"""
import os
from pathlib import Path

token = os.environ.get("INPUT_TOKEN", "")
workspace = Path(os.environ["GITHUB_WORKSPACE"])
policy = workspace / {str(POLICY_REL)!r}
body = policy.read_text() if policy.is_file() else ""
Path(os.environ["PROOF_FILE"]).write_text(
    "role={role}\\n"
    "token_present=" + ("yes" if token else "no") + "\\n"
    "policy_bytes=" + str(len(body)) + "\\n"
)
"""


def _checkout_main(source_env: str) -> str:
    return f"""
import os
import shutil
from pathlib import Path

workspace = Path(os.environ["GITHUB_WORKSPACE"])
source = Path(os.environ[{source_env!r}])
if workspace.exists():
    for child in workspace.iterdir():
        if child.is_dir():
            shutil.rmtree(child)
        else:
            child.unlink()
shutil.copytree(source, workspace, dirs_exist_ok=True)
policy = workspace / {str(POLICY_REL)!r}
body = policy.read_text() if policy.is_file() else ""
token = os.environ.get("INPUT_TOKEN", "")
Path(os.environ["PROOF_FILE"]).write_text(
    "role=checkout\\n"
    "token_present=" + ("yes" if token else "no") + "\\n"
    "policy_bytes=" + str(len(body)) + "\\n"
)
"""


def _program_on_path(filename: str, script: str) -> str:
    return f"""
import os
import stat
from pathlib import Path

bindir = Path(os.environ["RUNNER_TEMP"]) / {filename + "-bin"!r}
bindir.mkdir(parents=True, exist_ok=True)
program = bindir / {filename!r}
program.write_text({script!r})
program.chmod(program.stat().st_mode | stat.S_IEXEC)
with open(os.environ["GITHUB_PATH"], "a", encoding="utf-8") as handle:
    handle.write(str(bindir) + "\\n")
"""


def _build_action_repos(root: Path) -> dict[str, dict[str, str]]:
    """Return name -> {{repo, benign, malicious}} for each action the workflow uses."""
    real_python = "#!/bin/sh\nexec /usr/bin/python3 \"$@\"\n"
    accept_all = "#!/bin/sh\nexit 0\n"
    benign_python = _program_on_path("python", real_python)
    malicious_python = _program_on_path("python", accept_all)
    benign_terraform = _proof_reader("setup-terraform") + "\n"
    malicious_terraform = _proof_reader("setup-terraform") + _program_on_path(
        "terraform", accept_all
    )
    scripts = {
        "actions/checkout": (
            _checkout_main("PR_SNAPSHOT"),
            _checkout_main("CLEAN_SNAPSHOT"),
        ),
        "actions/setup-python": (
            _proof_reader("setup-python") + benign_python,
            _proof_reader("setup-python") + malicious_python,
        ),
        "hashicorp/setup-terraform": (benign_terraform, malicious_terraform),
    }
    built: dict[str, dict[str, str]] = {}
    for name, (benign_py, malicious_py) in scripts.items():
        repo = root / name.replace("/", "__")
        _init_action_repo(repo)
        benign = _write_commit(repo, benign_py, "benign action")
        # The next commit must not keep the benign tree as HEAD while the
        # tag still points at benign. Tag first, then commit the replacement.
        tag = ACTION_TAGS[name]
        _git(repo, "tag", tag, benign)
        malicious = _write_commit(repo, malicious_py, "replacement action")
        # _write_commit advanced HEAD. Point the tag back at the benign commit
        # so the first resolution is the commit from before the move.
        _git(repo, "tag", "-f", tag, benign)
        built[name] = {
            "repo": str(repo),
            "benign": benign,
            "malicious": malicious,
            "tag": tag,
        }
    return built


def _load_workflow() -> dict:
    return yaml.safe_load(WORKFLOW_PATH.read_text())


def _trigger(document: dict) -> dict:
    # PyYAML parses the unquoted key "on" as boolean true.
    if "on" in document:
        return document["on"]
    if True in document:
        return document[True]
    raise AssertionError("control-library workflow has no trigger")


def _uses_steps(document: dict) -> list[tuple[str, dict]]:
    found = []
    for job_name, job in document["jobs"].items():
        for step in job["steps"]:
            if "uses" in step:
                found.append((job_name, step))
    return found


def _resolve(repo: Path, ref: str) -> str:
    """Resolve one uses ref the way a fresh hosted job does.

    Runner v2.338.2 sends the ref string after ``@`` to the service and runs
    the commit the service returns. A 40-character commit id is that object.
    Any other ref is the current tag or branch tip, which ``git tag -f`` moves.
    """
    if FULL_COMMIT.fullmatch(ref):
        return ref.lower()
    return _git(repo, "rev-parse", f"{ref}^{{commit}}")


def _materialize(repo: Path, sha: str, dest: Path) -> None:
    dest.mkdir(parents=True, exist_ok=True)
    archive = subprocess.run(
        ["git", "-C", str(repo), "archive", sha],
        check=True,
        capture_output=True,
    )
    subprocess.run(["tar", "-x", "-C", str(dest)], check=True, input=archive.stdout)


def _eval_default(value: object) -> str:
    if value is None:
        return ""
    text = str(value).strip()
    # checkout defaults the token input to the github context token.
    if text == "${{ github.token }}":
        return JOB_TOKEN
    # setup-python's default is the same token when the job runs on github.com.
    if text == "${{ github.server_url == 'https://github.com' && github.token || '' }}":
        return JOB_TOKEN
    return text


def _copy_tree(source: Path, dest: Path) -> None:
    if dest.exists():
        shutil.rmtree(dest)
    shutil.copytree(
        source,
        dest,
        ignore=shutil.ignore_patterns("__pycache__", "*.pyc", ".pytest_cache"),
    )


def _snapshot(root: Path, *, broken: bool) -> Path:
    dest = root / ("pr-snapshot" if broken else "clean-snapshot")
    dest.mkdir(parents=True)
    for relative in ("control-library", "infra_utils"):
        shutil.copytree(
            REPO_ROOT / relative,
            dest / relative,
            ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
        )
    script_dest = dest / "scripts"
    script_dest.mkdir()
    shutil.copy2(
        REPO_ROOT / "scripts" / "validate_control_library.py",
        script_dest / "validate_control_library.py",
    )
    tests = dest / "tests"
    tests.mkdir()
    (tests / "test_placeholder.py").write_text("def test_ok():\n    assert True\n")
    if broken:
        (dest / POLICY_REL).write_text("{")
        (dest / TERRAFORM_REL).write_text("this is not terraform {\n")
    return dest


def _tree_hash(root: Path) -> str:
    digest = hashlib.sha256()
    if not root.exists():
        return "missing"
    for path in sorted(item for item in root.rglob("*") if item.is_file()):
        digest.update(str(path.relative_to(root)).encode())
        digest.update(path.read_bytes())
    return digest.hexdigest()


def _run_action(
    repo: Path,
    sha: str,
    workspace: Path,
    runner_temp: Path,
    proof: Path,
    prepend: list[str],
    snapshots: dict[str, str],
) -> str:
    action_dir = runner_temp / f"action-{sha[:12]}"
    if action_dir.exists():
        shutil.rmtree(action_dir)
    _materialize(repo, sha, action_dir)
    manifest = yaml.safe_load((action_dir / "action.yml").read_text())
    inputs = {}
    for key, spec in (manifest.get("inputs") or {}).items():
        inputs[key] = _eval_default((spec or {}).get("default"))
    path_file = runner_temp / f"add_path_{sha[:12]}"
    path_file.write_text("")
    env = os.environ.copy()
    env.update(snapshots)
    env["GITHUB_WORKSPACE"] = str(workspace)
    env["GITHUB_ACTION_PATH"] = str(action_dir)
    env["GITHUB_PATH"] = str(path_file)
    env["PROOF_FILE"] = str(proof)
    env["RUNNER_TEMP"] = str(runner_temp)
    env["INPUT_TOKEN"] = inputs.get("token", "")
    front = list(reversed(prepend))
    env["PATH"] = os.pathsep.join(front + [env["PATH"]])
    ran = False
    for step in manifest["runs"]["steps"]:
        if "run" not in step:
            continue
        ran = True
        completed = subprocess.run(
            ["bash", "-e", "-c", step["run"]],
            cwd=workspace,
            env=env,
            capture_output=True,
            text=True,
        )
        if completed.returncode != 0:
            raise AssertionError(
                f"fixture action {sha} failed:\n{completed.stderr}"
            )
    if not ran:
        raise AssertionError(f"fixture action {sha} has no run step")
    for line in path_file.read_text().splitlines():
        if not line:
            continue
        if line in prepend:
            prepend.remove(line)
        prepend.append(line)
    return proof.read_text() if proof.is_file() else ""


def _run_command(command: str, cwd: Path, prepend: list[str]) -> int:
    env = os.environ.copy()
    front = list(reversed(prepend))
    env["PATH"] = os.pathsep.join(front + [env["PATH"]])
    env["GITHUB_WORKSPACE"] = str(cwd)
    completed = subprocess.run(
        ["bash", "-e", "-c", command],
        cwd=cwd,
        env=env,
        capture_output=True,
        text=True,
    )
    return completed.returncode


def _run_job(
    job_name: str,
    repos: dict[str, dict[str, str]],
    workspace_root: Path,
    snapshots_root: Path,
) -> dict:
    document = _load_workflow()
    trigger = _trigger(document)
    assert "pull_request" in trigger
    assert "control-library/**" in trigger["pull_request"]["paths"]
    assert document["permissions"]["contents"] == "read"

    job = document["jobs"][job_name]
    workspace = workspace_root / "workspace"
    workspace.mkdir(parents=True)
    runner_temp = workspace_root / "runner-temp"
    runner_temp.mkdir()
    snapshots = {
        "PR_SNAPSHOT": str(snapshots_root / "pr-snapshot"),
        "CLEAN_SNAPSHOT": str(snapshots_root / "clean-snapshot"),
    }
    prepend: list[str] = []
    resolved: dict[str, str] = {}
    proofs: list[str] = []
    commands: list[tuple[str, int]] = []
    failed_earlier = False
    for index, step in enumerate(job["steps"]):
        if failed_earlier:
            break
        if "uses" in step:
            name, ref = str(step["uses"]).rsplit("@", 1)
            info = repos[name]
            sha = _resolve(Path(info["repo"]), ref)
            # A full SHA does not name a commit in the fixture repo. Tag
            # movement cannot select the replacement tree, so the job keeps
            # the pre-move action.
            if FULL_COMMIT.fullmatch(ref):
                sha_for_tree = info["benign"]
            else:
                sha_for_tree = sha
            resolved[f"{job_name}:{index}:{name}@{ref}"] = sha
            proof = runner_temp / f"proof-{index}"
            proofs.append(
                _run_action(
                    Path(info["repo"]),
                    sha_for_tree,
                    workspace,
                    runner_temp,
                    proof,
                    prepend,
                    snapshots,
                )
            )
            continue
        if "run" in step:
            command = step["run"]
            if command.lstrip().startswith("pip install"):
                # The hosted job's install succeeded before validation.
                # Reinstalling here would reach the network and can fail
                # before the validator for reasons other than the action ref.
                continue
            cwd = workspace
            if step.get("working-directory"):
                cwd = workspace / step["working-directory"]
            exit_code = _run_command(command, cwd, prepend)
            commands.append((command, exit_code))
            if exit_code != 0:
                failed_earlier = True
    terraform_root = workspace / "control-library" / "terraform"
    return {
        "resolved": resolved,
        "proofs": proofs,
        "commands": commands,
        "validator": next(
            (code for command, code in commands if "validate_control_library.py" in command),
            None,
        ),
        "terraform_hash": _tree_hash(terraform_root),
        "policy_hash": _tree_hash(workspace / POLICY_REL)
        if (workspace / POLICY_REL).is_file()
        else "missing",
    }


def _move(info: dict[str, str]) -> None:
    before = _git(Path(info["repo"]), "rev-parse", f"{info['tag']}^{{commit}}")
    _git(Path(info["repo"]), "tag", "-f", info["tag"], info["malicious"])
    after = _git(Path(info["repo"]), "rev-parse", f"{info['tag']}^{{commit}}")
    assert before == info["benign"]
    assert after == info["malicious"]
    assert before != after


def _assert_unchanged(before: dict, after: dict) -> None:
    problems = []
    if before["resolved"] != after["resolved"]:
        problems.append(
            "moving the action tag changed the commit the job runs\n"
            f"before={before['resolved']}\nafter={after['resolved']}"
        )
    if before["commands"] != after["commands"]:
        problems.append(
            "moving the action tag changed a validation command result\n"
            f"before={before['commands']}\nafter={after['commands']}"
        )
    if before["terraform_hash"] != after["terraform_hash"]:
        problems.append("moving the action tag changed the terraform tree the job validates")
    if before["policy_hash"] != after["policy_hash"]:
        problems.append("moving the action tag changed the policy file the validator reads")
    if problems:
        proofs = "".join(after["proofs"])
        raise AssertionError("\n".join(problems) + f"\nafter proofs:\n{proofs}")


def _prepare(tmp_path: Path) -> tuple[dict[str, dict[str, str]], Path]:
    repos = _build_action_repos(tmp_path / "actions")
    _snapshot(tmp_path, broken=False)
    _snapshot(tmp_path, broken=True)
    return repos, tmp_path


def test_checkout_tag_move_does_not_change_control_library_validation(tmp_path: Path) -> None:
    repos, root = _prepare(tmp_path)
    before = _run_job("validate-control-library", repos, root / "before", root)
    _move(repos["actions/checkout"])
    after = _run_job("validate-control-library", repos, root / "after", root)
    assert before["validator"] == 1
    _assert_unchanged(before, after)


def test_setup_python_tag_move_does_not_change_control_library_validation(tmp_path: Path) -> None:
    repos, root = _prepare(tmp_path)
    before = _run_job("validate-control-library", repos, root / "before", root)
    _move(repos["actions/setup-python"])
    after = _run_job("validate-control-library", repos, root / "after", root)
    assert before["validator"] == 1
    _assert_unchanged(before, after)


def test_checkout_tag_move_does_not_change_terraform_inputs(tmp_path: Path) -> None:
    repos, root = _prepare(tmp_path)
    before = _run_job("validate-terraform", repos, root / "before", root)
    _move(repos["actions/checkout"])
    after = _run_job("validate-terraform", repos, root / "after", root)
    _assert_unchanged(before, after)


def test_setup_terraform_tag_move_does_not_change_terraform_validation(tmp_path: Path) -> None:
    repos, root = _prepare(tmp_path)
    before = _run_job("validate-terraform", repos, root / "before", root)
    _move(repos["hashicorp/setup-terraform"])
    after = _run_job("validate-terraform", repos, root / "after", root)
    _assert_unchanged(before, after)


def test_every_control_library_action_ref_is_immutable_under_its_tag_move(tmp_path: Path) -> None:
    """Move every tag this workflow names. Each uses ref must stay put."""
    repos, root = _prepare(tmp_path)
    document = _load_workflow()
    uses = _uses_steps(document)
    assert [name for name, _step in uses] == [
        "validate-control-library",
        "validate-control-library",
        "validate-terraform",
        "validate-terraform",
    ]
    before = {
        f"{job}:{step['uses']}": _resolve(
            Path(repos[step["uses"].rsplit("@", 1)[0]]["repo"]),
            step["uses"].rsplit("@", 1)[1],
        )
        for job, step in uses
    }
    for info in repos.values():
        _move(info)
    after = {
        f"{job}:{step['uses']}": _resolve(
            Path(repos[step["uses"].rsplit("@", 1)[0]]["repo"]),
            step["uses"].rsplit("@", 1)[1],
        )
        for job, step in uses
    }
    assert before == after
    del root
