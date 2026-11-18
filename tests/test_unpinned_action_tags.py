"""Movable action tags must not be what a job executes.

actions/runner v2.338.2 (d1eb12d4b115c301201de27d667284e1a80f2ab5) keeps the
text after ``@`` as ``RepositoryPathReference.Ref`` and sends that string to
the service when the job prepares actions. A full commit SHA stays on that
object. A tag is resolved to whatever commit it points at then, which is the
commit whose archive is unpacked and run, with ``github.token`` available to
an input default the downloaded ``action.yml`` declares.

These tests fail while a workflow names a tag. They pass once every ``uses``
is a 40-character commit SHA.

Run:

    python -m pytest tests/test_unpinned_action_tags.py -q
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parents[1]
WORKFLOWS = REPO / ".github" / "workflows"
# Stand-in for system.github.token. Not a credential.
JOB_TOKEN = "JOB_TOKEN_PLACEHOLDER"
CANARY = "REPOSITORY_CONTENTS_CANARY"
FULL_SHA = re.compile(r"^[0-9a-f]{40}$")
CONTRACT_WORKFLOW = WORKFLOWS / "contract-parity.yml"
CONTRACT_SCRIPT = REPO / "scripts" / "check-contract.sh"

# actions/runner src/Sdk/DTPipelines/.../PipelineTemplateConverter.cs splits
# uses on '@' and stores the second segment as the ref.
_USES_SPLIT = "@"


@dataclass(frozen=True)
class ActionUse:
    workflow: Path
    job_id: str
    index: int
    name: str
    ref: str
    inputs: dict


@dataclass(frozen=True)
class JobResult:
    executed: str
    effect: str
    script: bytes


def _git(repo: Path, *args: str) -> str:
    env = os.environ.copy()
    env["GIT_AUTHOR_NAME"] = "pin-test"
    env["GIT_AUTHOR_EMAIL"] = "pin-test@example.com"
    env["GIT_COMMITTER_NAME"] = "pin-test"
    env["GIT_COMMITTER_EMAIL"] = "pin-test@example.com"
    completed = subprocess.run(
        ["git", *args],
        cwd=repo,
        check=True,
        capture_output=True,
        text=True,
        env=env,
    )
    return completed.stdout.strip()


def _trigger_map(document: dict) -> dict:
    # PyYAML 6 treats the bare key "on" as boolean true (YAML 1.1).
    block = document.get("on", document.get(True, {}))
    return block if isinstance(block, dict) else {}


def _action_uses(document: dict, workflow: Path) -> list[ActionUse]:
    found: list[ActionUse] = []
    jobs = document.get("jobs") or {}
    for job_id, job in jobs.items():
        if not isinstance(job, dict):
            continue
        for index, step in enumerate(job.get("steps") or []):
            if not isinstance(step, dict):
                continue
            uses = step.get("uses")
            if not isinstance(uses, str):
                continue
            if uses.startswith("docker://") or uses.startswith("./") or uses.startswith(".\\"):
                continue
            segments = uses.split(_USES_SPLIT)
            path_segments = [part for part in segments[0].replace("\\", "/").split("/") if part]
            git_ref = segments[1] if len(segments) == 2 else ""
            if len(segments) != 2 or len(path_segments) < 2 or not git_ref:
                raise AssertionError(f"unparsed uses {uses!r} in {workflow}")
            inputs = step.get("with") or {}
            if not isinstance(inputs, dict):
                inputs = {}
            found.append(
                ActionUse(
                    workflow=workflow,
                    job_id=str(job_id),
                    index=index,
                    name=f"{path_segments[0]}/{path_segments[1]}",
                    ref=git_ref,
                    inputs={str(key): value for key, value in inputs.items()},
                )
            )
    return found


def _load_workflow(path: Path) -> tuple[dict, list[ActionUse]]:
    document = yaml.safe_load(path.read_text())
    return document, _action_uses(document, path)


def _write_action(repo: Path, kind: str) -> None:
    if kind == "benign":
        manifest = (
            "name: reviewed\n"
            "description: reviewed action snapshot\n"
            "runs:\n"
            "  using: node24\n"
            "  main: index.js\n"
        )
        script = (
            "const fs = require('fs');\n"
            "const path = require('path');\n"
            "const ws = process.env.GITHUB_WORKSPACE;\n"
            "fs.appendFileSync(path.join(ws, 'actions-executed.txt'), 'benign\\n');\n"
        )
    else:
        # The downloaded manifest is what the runner evaluates. A workflow
        # that does not pass `token` still receives github.token when the
        # manifest default is that expression.
        manifest = (
            "name: moved-tag\n"
            "description: tag moved after the workflow was written\n"
            "inputs:\n"
            "  token:\n"
            "    description: job token\n"
            "    default: ${{ github.token }}\n"
            "runs:\n"
            "  using: node24\n"
            "  main: index.js\n"
        )
        script = (
            "const fs = require('fs');\n"
            "const path = require('path');\n"
            "const ws = process.env.GITHUB_WORKSPACE;\n"
            "const token = process.env.INPUT_TOKEN || '';\n"
            "const canaryPath = path.join(ws, 'repository-canary.txt');\n"
            "const canary = fs.existsSync(canaryPath) ? fs.readFileSync(canaryPath, 'utf8') : '';\n"
            "fs.writeFileSync(path.join(ws, 'supply-chain-effect.txt'), token + '\\n' + canary);\n"
            "const script = path.join(ws, 'scripts', 'check-contract.sh');\n"
            "fs.mkdirSync(path.dirname(script), { recursive: true });\n"
            "fs.writeFileSync(script, '#!/bin/bash\\nexit 0\\n');\n"
            "fs.appendFileSync(path.join(ws, 'actions-executed.txt'), 'malicious\\n');\n"
        )
    (repo / "action.yml").write_text(manifest)
    (repo / "index.js").write_text(script)
    (repo / "payload-kind").write_text(kind + "\n")


def _build_moved_tag_repo(ref: str) -> tuple[Path, str]:
    """Return the repo and the commit the job will execute.

    The publisher tags a reviewed commit, then the tag is force-moved.
    ``git tag -f`` is the move GitHub documents for major-version tags.
    Resolution uses ``git rev-parse <ref>^{commit}``, which is the ref
    the runner sends as ``ActionReference.Ref`` / ``Version``.
    """
    repo = Path(tempfile.mkdtemp(prefix="action-repo-"))
    _git(repo, "init", "-b", "main")
    _write_action(repo, "benign")
    _git(repo, "add", ".")
    _git(repo, "commit", "-m", "reviewed snapshot")
    benign = _git(repo, "rev-parse", "HEAD")
    tag = ref if not FULL_SHA.fullmatch(ref) else "movable"
    _git(repo, "tag", tag)
    _write_action(repo, "malicious")
    _git(repo, "add", ".")
    _git(repo, "commit", "-m", "moved tag")
    _git(repo, "tag", "-f", tag)
    moved = _git(repo, "rev-parse", f"{tag}^{{commit}}")
    if moved == benign:
        raise AssertionError("tag move did not change the commit")
    if FULL_SHA.fullmatch(ref):
        # A full object id does not follow the tag. rev-parse of that
        # commit is still the reviewed snapshot after tag -f.
        pinned = _git(repo, "rev-parse", "--verify", f"{benign}^{{commit}}")
        if pinned != benign:
            raise AssertionError("commit object id changed when the tag moved")
        return repo, benign
    resolved = _git(repo, "rev-parse", "--verify", f"{ref}^{{commit}}")
    return repo, resolved


def _materialize(repo: Path, sha: str, dest: Path) -> None:
    """Unpack the resolved commit the way ActionManager unwraps one archive directory."""
    staging = dest.parent / f"{dest.name}-staging"
    wrapper = staging / "unwrapped"
    wrapper.mkdir(parents=True)
    archive = subprocess.check_output(["git", "archive", "--format=tar", sha], cwd=repo)
    subprocess.run(["tar", "-x", "-C", str(wrapper)], input=archive, check=True)
    children = list(staging.iterdir())
    if len(children) != 1:
        raise AssertionError(f"archive produced {len(children)} directories")
    dest.mkdir(parents=True, exist_ok=True)
    for child in children[0].iterdir():
        target = dest / child.name
        if child.is_dir():
            shutil.copytree(child, target)
        else:
            shutil.copy2(child, target)


def _evaluate_default(value: object) -> str:
    """Evaluate an action.yml input default against the job's github context.

    ContextValueNode reads ExpressionValues['github']; Index.HandleObject
    then reads 'token'. ExecutionContext copies system.github.token into
    that field before steps run.
    """
    if not isinstance(value, str):
        return "" if value is None else str(value)
    if value.strip() == "${{ github.token }}":
        return JOB_TOKEN
    return value


def _run_action(action_dir: Path, workspace: Path, workflow_inputs: dict) -> None:
    manifest = yaml.safe_load((action_dir / "action.yml").read_text())
    inputs = {str(key): "" if value is None else str(value) for key, value in workflow_inputs.items()}
    for name, spec in (manifest.get("inputs") or {}).items():
        if name in inputs or not isinstance(spec, dict) or "default" not in spec:
            continue
        inputs[name] = _evaluate_default(spec["default"])
    env = os.environ.copy()
    # GitHubContext allowlist exports workspace as GITHUB_WORKSPACE.
    env["GITHUB_WORKSPACE"] = str(workspace)
    for key, value in inputs.items():
        env[f"INPUT_{key.replace(' ', '_').upper()}"] = value
    main = manifest["runs"]["main"]
    subprocess.run(
        ["node", str(action_dir / main)],
        cwd=workspace,
        check=True,
        env=env,
    )


def _workspace() -> Path:
    workspace = Path(tempfile.mkdtemp(prefix="job-workspace-"))
    script_dir = workspace / "scripts"
    script_dir.mkdir()
    shutil.copy2(CONTRACT_SCRIPT, script_dir / "check-contract.sh")
    (workspace / "repository-canary.txt").write_text(CANARY)
    return workspace


def _execute(use: ActionUse, workspace: Path) -> None:
    repo, sha = _build_moved_tag_repo(use.ref)
    try:
        action_dir = Path(tempfile.mkdtemp(prefix="action-dir-"))
        try:
            _materialize(repo, sha, action_dir)
            kind = (action_dir / "payload-kind").read_text().strip()
            if FULL_SHA.fullmatch(use.ref) and kind != "benign":
                raise AssertionError("SHA pin checked out the moved tag")
            if not FULL_SHA.fullmatch(use.ref) and kind != "malicious":
                raise AssertionError("tag ref did not resolve to the moved commit")
            _run_action(action_dir, workspace, use.inputs)
        finally:
            shutil.rmtree(action_dir, ignore_errors=True)
    finally:
        shutil.rmtree(repo, ignore_errors=True)


def _result(workspace: Path) -> JobResult:
    executed_path = workspace / "actions-executed.txt"
    effect_path = workspace / "supply-chain-effect.txt"
    script_path = workspace / "scripts" / "check-contract.sh"
    return JobResult(
        executed=executed_path.read_text() if executed_path.exists() else "",
        effect=effect_path.read_text() if effect_path.exists() else "",
        script=script_path.read_bytes(),
    )


def _assert_reviewed_execution(result: JobResult, original_script: bytes) -> None:
    assert result.executed.strip() == "benign", result.executed
    assert JOB_TOKEN not in result.effect
    assert CANARY not in result.effect
    assert result.script == original_script


def test_contract_parity_is_reachable_from_pull_request_and_main_push():
    document, _uses = _load_workflow(CONTRACT_WORKFLOW)
    triggers = _trigger_map(document)
    assert "main" in (triggers.get("push") or {}).get("branches", [])
    assert "main" in (triggers.get("pull_request") or {}).get("branches", [])
    permissions = document.get("permissions") or {}
    assert permissions.get("contents") == "read"


def test_contract_parity_job_runs_actions_before_the_parity_script():
    document, uses = _load_workflow(CONTRACT_WORKFLOW)
    job_uses = [item for item in uses if item.job_id == "contract-parity"]
    assert [item.name for item in job_uses] == [
        "actions/checkout",
        "actions/setup-python",
        "actions/setup-node",
    ]
    steps = document["jobs"]["contract-parity"]["steps"]
    runs = [step.get("run") for step in steps if isinstance(step, dict) and "run" in step]
    assert any("scripts/check-contract.sh" in (command or "") for command in runs)
    parity_at = next(
        index
        for index, step in enumerate(steps)
        if isinstance(step, dict) and "run" in step and "scripts/check-contract.sh" in step["run"]
    )
    assert all(item.index < parity_at for item in job_uses)


def test_moved_tags_do_not_run_contract_parity_or_read_the_job_token():
    _document, uses = _load_workflow(CONTRACT_WORKFLOW)
    job_uses = [item for item in uses if item.job_id == "contract-parity"]
    original = CONTRACT_SCRIPT.read_bytes()
    workspace = _workspace()
    try:
        for use in job_uses:
            _execute(use, workspace)
        _assert_reviewed_execution(_result(workspace), original)
    finally:
        shutil.rmtree(workspace, ignore_errors=True)


def test_each_contract_parity_action_ignores_its_own_moved_tag(name: str = ""):
    _document, uses = _load_workflow(CONTRACT_WORKFLOW)
    job_uses = [item for item in uses if item.job_id == "contract-parity"]
    selected = [item for item in job_uses if item.name == name] if name else job_uses
    assert selected, name
    original = CONTRACT_SCRIPT.read_bytes()
    for use in selected:
        workspace = _workspace()
        try:
            _execute(use, workspace)
            _assert_reviewed_execution(_result(workspace), original)
        finally:
            shutil.rmtree(workspace, ignore_errors=True)


def test_moved_checkout_tag_does_not_run_during_contract_parity():
    test_each_contract_parity_action_ignores_its_own_moved_tag("actions/checkout")


def test_moved_setup_python_tag_does_not_run_during_contract_parity():
    test_each_contract_parity_action_ignores_its_own_moved_tag("actions/setup-python")


def test_moved_setup_node_tag_does_not_run_during_contract_parity():
    test_each_contract_parity_action_ignores_its_own_moved_tag("actions/setup-node")


def _every_action_use() -> list[ActionUse]:
    found: list[ActionUse] = []
    for path in sorted(WORKFLOWS.glob("*.yml")):
        _document, uses = _load_workflow(path)
        found.extend(uses)
    return found


def test_every_workflow_action_use_ignores_a_moved_tag():
    original = CONTRACT_SCRIPT.read_bytes()
    uses = _every_action_use()
    assert uses, "no action uses found"
    moved = []
    for use in uses:
        workspace = _workspace()
        try:
            _execute(use, workspace)
            result = _result(workspace)
            if (
                result.executed.strip() != "benign"
                or JOB_TOKEN in result.effect
                or CANARY in result.effect
                or result.script != original
            ):
                moved.append(f"{use.workflow.name}:{use.job_id} {use.name}@{use.ref}")
        finally:
            shutil.rmtree(workspace, ignore_errors=True)
    assert moved == []
