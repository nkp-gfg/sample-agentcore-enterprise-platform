"""Action refs in workflows must not follow a moved tag.

The control-library Terraform job checks out with ``actions/checkout@v7`` and
installs Terraform with ``hashicorp/setup-terraform@v4``. The runner resolves
that ref when the job starts and executes the action at the commit the ref
points at. A tag can be moved, so the next run executes the new commit and
the following ``terraform`` steps use the binary that commit placed on
``PATH``. A full 40-character commit SHA does not follow a tag move.

These tests fail while any workflow action uses a movable ref. They pass
once every ``uses`` ref is a full commit SHA.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tarfile
from dataclasses import dataclass, field
from io import BytesIO
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = REPO_ROOT / ".github" / "workflows"
NODE = shutil.which("node")
JOB_TOKEN_PLACEHOLDER = "JOB_TOKEN_PLACEHOLDER"
SHA_REF = re.compile(r"^[0-9a-f]{40}$")
TOKEN_EXPRESSIONS = {"github.token", "secrets.GITHUB_TOKEN"}
TERRAFORM_COMMAND = re.compile(r"(?:^|[;&|]\s*)terraform\b", re.MULTILINE)


@dataclass
class ActionRepo:
    path: Path
    benign_sha: str
    attacker_sha: str
    pinned_trees: dict[str, dict[str, str]] = field(default_factory=dict)
    tags: set[str] = field(default_factory=set)


@dataclass(frozen=True)
class StepOutcome:
    action: str
    ref: str
    resolved: str
    identity: str
    token: str


def _git(repo: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", *args],
        cwd=repo,
        check=check,
        capture_output=True,
        text=True,
    )


def _init_repo(path: Path) -> None:
    path.mkdir(parents=True)
    _git(path, "init", "-q")
    _git(path, "config", "user.email", "actions-test@example.com")
    _git(path, "config", "user.name", "actions-test")
    _git(path, "config", "commit.gpgsign", "false")


def _action_files(identity: str) -> dict[str, str]:
    # Node action, same shape as hashicorp/setup-terraform@v4 (runs.using node24,
    # main dist/index.js). The script records the job token handed to it as an
    # input and installs a terraform executable, then appends that directory to
    # GITHUB_PATH the way @actions/core addPath does.
    script = """\
const fs = require('fs');
const os = require('os');
const path = require('path');
const id = %s;
const toolDir = process.env.TOOL_DIR;
fs.mkdirSync(toolDir, {recursive: true});
const log = process.env.TERRAFORM_LOG;
const body = "#!/bin/sh\\nprintf '%%s %%s\\\\n' "
  + JSON.stringify(id) + ' "$*" >> ' + JSON.stringify(log) + "\\nexit 0\\n";
const terraform = path.join(toolDir, 'terraform');
fs.writeFileSync(terraform, body);
fs.chmodSync(terraform, 0o755);
fs.appendFileSync(process.env.GITHUB_PATH, toolDir + os.EOL);
fs.writeFileSync(process.env.ACTION_EVIDENCE, JSON.stringify({
  id: id,
  token: process.env.INPUT_TOKEN || ""
}));
""" % json.dumps(identity)
    manifest = """\
name: stand-in
inputs:
  token:
    description: Job token from github.token
    default: ${{ github.token }}
runs:
  using: node24
  main: dist/index.js
"""
    return {"action.yml": manifest, "dist/index.js": script}


def _commit(repo: Path, files: dict[str, str], message: str) -> str:
    for relative, content in files.items():
        destination = repo / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(content)
    _git(repo, "add", ".")
    _git(repo, "commit", "-q", "-m", message)
    return _git(repo, "rev-parse", "HEAD").stdout.strip()


def _new_action_repo(path: Path) -> ActionRepo:
    _init_repo(path)
    benign = _commit(path, _action_files("reviewed-action"), "reviewed action")
    attacker = _commit(path, _action_files("replaced-action"), "replaced action")
    return ActionRepo(path=path, benign_sha=benign, attacker_sha=attacker)


def parse_uses(value: str) -> tuple[str, str, str]:
    """Split ``uses`` the way the runner's pipeline converter does.

    actions/runner v2.338.2
    src/Sdk/DTPipelines/Pipelines/ObjectTemplating/PipelineTemplateConverter.cs
    splits on ``@`` and then on ``/`` (lines 629-653).
    """
    if value.startswith("docker://"):
        raise AssertionError(f"container action is outside this model: {value}")
    if value.startswith("./") or value.startswith(".\\"):
        raise AssertionError(f"local action is outside this model: {value}")
    segments = value.split("@")
    path_segments = [part for part in re.split(r"[/\\]", segments[0]) if part]
    git_ref = segments[1] if len(segments) == 2 else ""
    if (
        len(segments) != 2
        or len(path_segments) < 2
        or not path_segments[0]
        or not path_segments[1]
        or not git_ref
    ):
        raise AssertionError(f"Expected {{org}}/{{repo}}[/path]@ref. Actual {value!r}")
    name = f"{path_segments[0]}/{path_segments[1]}"
    directory = "/".join(path_segments[2:])
    return name, git_ref, directory


def _eval_expressions(value: str, token: str) -> str:
    def replace(match: re.Match[str]) -> str:
        expression = match.group(1).strip()
        if expression in TOKEN_EXPRESSIONS:
            return token
        return match.group(0)

    return re.sub(r"\$\{\{\s*([^}]+?)\s*\}\}", replace, value)


def _resolve(repo: ActionRepo, ref: str) -> str:
    """Resolve a uses ref.

    A 40-hex commit id is the commit. Anything else is a tag, read from
    ``refs/tags/<ref>`` at call time. Moving that tag changes the result.
    The hosted job log for control-library prints
    ``Download action repository 'hashicorp/setup-terraform@v4' (SHA:...)``,
    which is the runner reporting the commit the service resolved for the
    tag (actions/runner v2.338.2 ActionManager.cs lines 1211-1212).
    """
    if SHA_REF.fullmatch(ref):
        if ref not in repo.pinned_trees:
            raise AssertionError(f"pinned ref {ref} has no immutable tree")
        return ref
    resolved = _git(repo.path, "rev-parse", f"refs/tags/{ref}^{{commit}}")
    return resolved.stdout.strip()


def _materialize(repo: ActionRepo, ref: str, destination: Path) -> str:
    resolved = _resolve(repo, ref)
    destination.mkdir(parents=True)
    if SHA_REF.fullmatch(ref):
        for relative, content in repo.pinned_trees[ref].items():
            target = destination / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content)
        return resolved
    archive = subprocess.check_output(["git", "archive", resolved], cwd=repo.path)
    with tarfile.open(fileobj=BytesIO(archive), mode="r:") as tar:
        tar.extractall(destination, filter="data")
    return resolved


def _input_env(action_dir: Path, step: dict, token: str) -> dict[str, str]:
    """Merge action.yml defaults with the step ``with`` block.

    Runner v2.338.2 ActionRunner.cs lines 206-218 fills missing inputs from
    the action manifest. EvaluateDefaultInput (ActionManifestManager.cs
    lines 273-291) evaluates ``${{ github.token }}`` against the github
    context. ExecutionContext.cs lines 1025-1030 copies
    ``system.github.token`` into that context. Handler.cs lines 182-186
    publishes each input as ``INPUT_<NAME>``.
    """
    manifest = yaml.safe_load((action_dir / "action.yml").read_text()) or {}
    runs = manifest.get("runs") or {}
    using = str(runs.get("using", ""))
    if using.lower() not in {"node12", "node16", "node20", "node24"}:
        raise AssertionError(f"stand-in action must be a node action, got {using!r}")
    main = runs.get("main")
    if main != "dist/index.js":
        raise AssertionError(f"stand-in main must be dist/index.js, got {main!r}")
    inputs: dict[str, str] = {}
    for name, spec in (manifest.get("inputs") or {}).items():
        default = ""
        if isinstance(spec, dict) and spec.get("default") is not None:
            default = str(spec["default"])
        inputs[name] = _eval_expressions(default, token)
    for name, raw in (step.get("with") or {}).items():
        inputs[str(name)] = _eval_expressions("" if raw is None else str(raw), token)
    environment = {}
    for name, value in inputs.items():
        environment[f"INPUT_{name.replace(' ', '_').upper()}"] = value
    return environment


def _consume_path_file(path_file: Path, prepend: list[str]) -> None:
    """Apply GITHUB_PATH the way AddPathFileCommand does.

    actions/runner v2.338.2 FileCommandManager.cs lines 134-154 appends each
    non-empty line, dropping any earlier copy of that line. ScriptHandler.cs
    line 184 then prepends that list in reverse order.
    """
    if not path_file.exists():
        return
    for line in path_file.read_text(encoding="utf-8").splitlines():
        if line == "":
            continue
        while line in prepend:
            prepend.remove(line)
        prepend.append(line)
    path_file.write_text("")


def _run_node_action(
    action_dir: Path,
    step: dict,
    tool_dir: Path,
    path_file: Path,
    evidence_path: Path,
    terraform_log: Path,
    token: str,
) -> dict:
    if NODE is None:
        raise AssertionError("node is required to execute the action entrypoint")
    path_file.write_text("")
    environment = os.environ.copy()
    environment.pop("GITHUB_TOKEN", None)
    environment.update(_input_env(action_dir, step, token))
    environment.update(
        {
            "GITHUB_PATH": str(path_file),
            "TOOL_DIR": str(tool_dir),
            "TERRAFORM_LOG": str(terraform_log),
            "ACTION_EVIDENCE": str(evidence_path),
        }
    )
    completed = subprocess.run(
        [NODE, str(action_dir / "dist" / "index.js")],
        cwd=action_dir,
        check=False,
        capture_output=True,
        text=True,
        env=environment,
    )
    if completed.returncode != 0:
        raise AssertionError(
            "action entrypoint failed\n"
            f"stdout: {completed.stdout}\nstderr: {completed.stderr}"
        )
    return json.loads(evidence_path.read_text())


def _run_terraform_steps(steps: list, prepend: list[str], terraform_log: Path) -> None:
    path_value = os.pathsep.join([*reversed(prepend), os.environ.get("PATH", "")])
    environment = os.environ.copy()
    environment["PATH"] = path_value
    environment["TERRAFORM_LOG"] = str(terraform_log)
    environment.pop("GITHUB_TOKEN", None)
    for step in steps:
        if not isinstance(step, dict) or "run" not in step:
            continue
        script = step["run"]
        if not isinstance(script, str) or not TERRAFORM_COMMAND.search(script):
            continue
        completed = subprocess.run(
            ["bash", "-c", script],
            check=False,
            capture_output=True,
            text=True,
            env=environment,
        )
        if completed.returncode != 0:
            raise AssertionError(
                "terraform step failed\n"
                f"script: {script}\nstdout: {completed.stdout}\nstderr: {completed.stderr}"
            )


def _prepare(repo: ActionRepo, ref: str) -> None:
    if SHA_REF.fullmatch(ref):
        repo.pinned_trees.setdefault(ref, _action_files("reviewed-action"))
        return
    if ref in repo.tags:
        return
    _git(repo.path, "tag", "-f", ref, repo.benign_sha)
    repo.tags.add(ref)


def _move_tags(repo: ActionRepo) -> None:
    for ref in repo.tags:
        _git(repo.path, "tag", "-f", ref, repo.attacker_sha)


def execute_job(repo_for: dict[str, ActionRepo], job: dict, work: Path, token: str) -> tuple[list[StepOutcome], str]:
    steps = job.get("steps") or []
    prepend: list[str] = []
    outcomes: list[StepOutcome] = []
    work.mkdir(parents=True, exist_ok=True)
    terraform_log = work / "terraform.log"
    terraform_log.write_text("")
    for index, step in enumerate(steps):
        if not isinstance(step, dict) or "uses" not in step:
            continue
        name, ref, _directory = parse_uses(str(step["uses"]))
        repo = repo_for[name]
        action_dir = work / f"action-{index}"
        tool_dir = work / f"tool-{index}"
        evidence_path = work / f"evidence-{index}.json"
        path_file = work / f"github-path-{index}"
        resolved = _materialize(repo, ref, action_dir)
        evidence = _run_node_action(
            action_dir,
            step,
            tool_dir,
            path_file,
            evidence_path,
            terraform_log,
            token,
        )
        _consume_path_file(path_file, prepend)
        outcomes.append(
            StepOutcome(
                action=name,
                ref=ref,
                resolved=resolved,
                identity=evidence["id"],
                token=evidence["token"],
            )
        )
    _run_terraform_steps(steps, prepend, terraform_log)
    return outcomes, terraform_log.read_text()


def _jobs(document: dict) -> list[tuple[str, dict]]:
    jobs = []
    for name, job in (document.get("jobs") or {}).items():
        if isinstance(job, dict) and "steps" in job:
            jobs.append((name, job))
        elif isinstance(job, dict) and "uses" in job:
            raise AssertionError(f"job-level uses is not covered: {name}: {job['uses']}")
    return jobs


def _load_workflows() -> list[tuple[Path, dict]]:
    loaded = []
    for path in sorted(WORKFLOWS.glob("*.yml")):
        loaded.append((path, yaml.safe_load(path.read_text()) or {}))
    return loaded


def _repos_for(workflows: list[tuple[Path, dict]], root: Path) -> dict[str, ActionRepo]:
    repos: dict[str, ActionRepo] = {}
    for _path, document in workflows:
        for _name, job in _jobs(document):
            for step in job.get("steps") or []:
                if not isinstance(step, dict) or "uses" not in step:
                    continue
                action, ref, _directory = parse_uses(str(step["uses"]))
                repo = repos.get(action)
                if repo is None:
                    repo = _new_action_repo(root / action.replace("/", "__"))
                    repos[action] = repo
                _prepare(repo, ref)
    return repos


def _run_all(workflows, repos, root: Path, label: str) -> dict[tuple[str, str], tuple[list[StepOutcome], str]]:
    results = {}
    for path, document in workflows:
        for job_name, job in _jobs(document):
            outcome = execute_job(
                repos,
                job,
                root / label / path.stem / job_name,
                JOB_TOKEN_PLACEHOLDER,
            )
            results[(str(path.relative_to(REPO_ROOT)), job_name)] = outcome
    return results


def test_full_commit_sha_does_not_follow_a_moved_tag(tmp_path: Path):
    repo = _new_action_repo(tmp_path / "action")
    pinned = repo.benign_sha
    _prepare(repo, pinned)
    _prepare(repo, "v4")
    before, before_log = execute_job(
        {"local/action": repo},
        {
            "steps": [
                {"uses": f"local/action@{pinned}"},
                {"uses": "local/action@v4"},
                {"run": "terraform init -backend=false -input=false\nterraform validate\n"},
            ]
        },
        tmp_path / "before",
        JOB_TOKEN_PLACEHOLDER,
    )
    _move_tags(repo)
    after_pin, after_pin_log = execute_job(
        {"local/action": repo},
        {
            "steps": [
                {"uses": f"local/action@{pinned}"},
                {"run": "terraform validate\n"},
            ]
        },
        tmp_path / "after-pin",
        JOB_TOKEN_PLACEHOLDER,
    )
    after_tag, after_tag_log = execute_job(
        {"local/action": repo},
        {
            "steps": [
                {"uses": "local/action@v4"},
                {"run": "terraform init -backend=false -input=false\n"},
            ]
        },
        tmp_path / "after-tag",
        JOB_TOKEN_PLACEHOLDER,
    )

    assert before[0].resolved == pinned
    assert before[0].identity == "reviewed-action"
    assert before[0].token == JOB_TOKEN_PLACEHOLDER
    assert after_pin[0].resolved == pinned
    assert after_pin[0].identity == "reviewed-action"
    assert after_pin_log == "reviewed-action validate\n"
    assert before_log.startswith("reviewed-action init -backend=false -input=false\n")
    assert after_tag[0].resolved == repo.attacker_sha
    assert after_tag[0].identity == "replaced-action"
    assert after_tag[0].token == JOB_TOKEN_PLACEHOLDER
    assert after_tag_log == "replaced-action init -backend=false -input=false\n"


def test_workflow_action_refs_do_not_follow_moved_tags(tmp_path: Path):
    workflows = _load_workflows()
    repos = _repos_for(workflows, tmp_path / "repos")
    before = _run_all(workflows, repos, tmp_path, "before")
    for repo in repos.values():
        _move_tags(repo)
    after = _run_all(workflows, repos, tmp_path, "after")

    drifts = []
    for key in before:
        before_steps, before_log = before[key]
        after_steps, after_log = after[key]
        if before_steps != after_steps or before_log != after_log:
            drifts.append(
                f"{key[0]} job {key[1]}:\n"
                f"  before: {before_steps} terraform={before_log!r}\n"
                f"  after:  {after_steps} terraform={after_log!r}"
            )
    assert drifts == [], (
        "A moved action tag changed the commit the workflow runs or the "
        "terraform binary its later steps execute:\n" + "\n".join(drifts)
    )


def test_control_library_terraform_job_keeps_the_reviewed_terraform_binary(tmp_path: Path):
    workflow_path = WORKFLOWS / "control-library.yml"
    document = yaml.safe_load(workflow_path.read_text())
    job = document["jobs"]["validate-terraform"]
    uses = [str(step["uses"]) for step in job["steps"] if isinstance(step, dict) and "uses" in step]
    assert any(item.startswith("actions/checkout@") for item in uses)

    repos = _repos_for([(workflow_path, document)], tmp_path / "repos")
    before = _run_all([(workflow_path, document)], repos, tmp_path, "before")
    for repo in repos.values():
        _move_tags(repo)
    after = _run_all([(workflow_path, document)], repos, tmp_path, "after")
    key = (".github/workflows/control-library.yml", "validate-terraform")
    before_steps, before_log = before[key]
    after_steps, after_log = after[key]

    setup = [step for step in before_steps if step.action == "hashicorp/setup-terraform"]
    if setup:
        assert before_log == (
            "reviewed-action fmt -check -recursive control-library/terraform/\n"
            "reviewed-action init -backend=false -input=false\n"
            "reviewed-action validate\n"
        )
        assert setup[0].token == JOB_TOKEN_PLACEHOLDER
    reviewed_token = setup[0].token if setup else JOB_TOKEN_PLACEHOLDER
    assert before_steps == after_steps, (
        "Moving the setup-terraform or checkout tag changed the action commit. "
        f"The reviewed action saw token {reviewed_token!r}. "
        f"After the move the job ran {after_steps} and terraform log {after_log!r}."
    )
    assert before_log == after_log, (
        "Moving the setup-terraform tag changed the terraform binary used by "
        f"fmt, init, and validate.\nreviewed:\n{before_log}\nreplaced:\n{after_log}"
    )
