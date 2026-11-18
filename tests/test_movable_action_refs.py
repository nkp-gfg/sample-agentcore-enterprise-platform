"""A moved action tag must not run in a workflow job or use that job's token.

actions/runner v2.338.2 (d1eb12d4b115c301201de27d667284e1a80f2ab5) treats the
text after `@` as the git ref it downloads:

- WorkflowTemplateConverter.cs splits `uses` on `@` and requires `{org}/{repo}[/path]@ref`.
- ActionManager.GetDownloadInfoAsync sends that ref, unchanged, to the resolver.
- The runner's download URL is `tarball/{ref}` (ActionManagerL0.GetLinkToActionArchive).
  GitHub's public tarball route for a tag redirects to `refs/tags/<tag>`, so the
  bytes are whatever the tag points at when the job downloads it.
- ExecutionContext stores the job token on `github.token`. ActionRunner evaluates
  an action input's default when the workflow did not set that input, and
  Handler.AddInputsToEnvironment exports it as `INPUT_<NAME>`. `token` is not on
  GitHubContext's environment allowlist, so the process does not get `GITHUB_TOKEN`
  unless the action asks for `github.token`.

These tests build that sequence with git and node. They fail while a workflow
`uses` a movable ref, and they pass once every external `uses` is a full commit
SHA: downloading that object id does not follow a tag that moves afterward.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = REPO_ROOT / ".github" / "workflows"
SOURCE_FILE = REPO_ROOT / "scripts" / "check-deploy-config.sh"
JOB_TOKEN = "placeholder-job-token"
FULL_SHA = re.compile(r"^[0-9a-f]{40}$")
GITHUB_TOKEN_EXPR = re.compile(r"^\$\{\{\s*github\.token\s*\}\}$")

NODE_MAIN_MOVED = """\
const fs = require("fs");
const { spawnSync } = require("child_process");
fs.writeFileSync(process.env.MOVED_MARKER, "moved\\n");
const token = process.env.INPUT_TOKEN || "";
spawnSync(process.env.PYTHON_BIN, [process.env.CONTENTS_API, token], { stdio: "inherit" });
"""

NODE_MAIN_BENIGN = """\
process.stdout.write("benign\\n");
"""

ACTION_YML_MOVED = """\
name: moved-tag
description: stands in for an action whose tag was moved
inputs:
  token:
    description: job token
    default: ${{ github.token }}
runs:
  using: node24
  main: main.js
"""

ACTION_YML_BENIGN = """\
name: pinned-commit
description: stands in for the commit a full SHA names
runs:
  using: node24
  main: main.js
"""

CONTENTS_API = r'''
import json
import os
import pathlib
import sys

token = sys.argv[1] if len(sys.argv) > 1 else ""
expected = os.environ["EXPECTED_JOB_TOKEN"]
permissions = json.loads(os.environ["JOB_TOKEN_PERMISSIONS"])
effects_path = pathlib.Path(os.environ["EFFECTS_PATH"])
if token == "" or token != expected:
    effects_path.write_text("[]")
    sys.exit(2)
effects = []
for name, level in permissions.items():
    if level not in ("read", "write"):
        continue
    effects.append(f"{name}:{level}")
    if name == "contents":
        source = pathlib.Path(os.environ["SOURCE_FILE"]).read_bytes()
        pathlib.Path(os.environ["SINK_PATH"]).write_bytes(source)
effects_path.write_text(json.dumps(effects))
'''


def _git(repo: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            "git",
            "-C",
            str(repo),
            "-c",
            "user.name=Action Pin Test",
            "-c",
            "user.email=pin-test@example.com",
            "-c",
            "commit.gpgsign=false",
            *args,
        ],
        check=check,
        capture_output=True,
        text=True,
    )


def _rev_parse(repo: Path, ref: str) -> str:
    result = _git(repo, "rev-parse", "--verify", f"{ref}^{{commit}}")
    return result.stdout.strip()


def _init_action_repo(path: Path) -> None:
    path.mkdir(parents=True)
    _git(path, "init", "-b", "placeholder")
    _git(path, "config", "core.autocrlf", "false")


def _commit_action(repo: Path, action_yml: str, main_js: str, message: str) -> str:
    (repo / "action.yml").write_text(action_yml)
    (repo / "main.js").write_text(main_js)
    _git(repo, "add", "action.yml", "main.js")
    _git(repo, "commit", "-m", message)
    return _rev_parse(repo, "HEAD")


def _extract(repo: Path, sha: str, dest: Path) -> None:
    dest.mkdir(parents=True)
    archive = subprocess.run(
        ["git", "-C", str(repo), "archive", sha],
        check=True,
        capture_output=True,
    )
    subprocess.run(["tar", "-x", "-C", str(dest)], check=True, input=archive.stdout)


def _evaluate(value: object, job_token: str) -> str:
    text = value if isinstance(value, str) else ("" if value is None else str(value))
    if GITHUB_TOKEN_EXPR.match(text.strip()):
        return job_token
    return text


def _load_runs(action_dir: Path) -> tuple[str, dict]:
    manifest = yaml.safe_load((action_dir / "action.yml").read_text())
    runs = manifest["runs"]
    using = str(runs["using"])
    if using not in {"node12", "node16", "node20", "node24"}:
        raise AssertionError(f"unsupported action runtime {using}")
    main = str(runs["main"])
    inputs = manifest.get("inputs") or {}
    return main, inputs


def _run_resolved_action(
    action_dir: Path,
    workflow_with: dict,
    permissions: dict,
    work: Path,
) -> dict:
    """Run the commit the ref resolved to, the way ActionRunner runs a node action."""
    main, manifest_inputs = _load_runs(action_dir)
    inputs: dict[str, str] = {}
    for key, value in (workflow_with or {}).items():
        inputs[str(key)] = _evaluate(value, JOB_TOKEN)
    for key, meta in manifest_inputs.items():
        if key in inputs:
            continue
        default = meta.get("default", "") if isinstance(meta, dict) else ""
        inputs[str(key)] = _evaluate(default, JOB_TOKEN)

    marker = work / "moved-marker"
    sink = work / "copied-source"
    effects_path = work / "effects.json"
    api_path = work / "contents_api.py"
    api_path.write_text(CONTENTS_API)
    env = os.environ.copy()
    env.pop("GITHUB_TOKEN", None)
    env.pop("INPUT_TOKEN", None)
    for key, value in inputs.items():
        env[f"INPUT_{key.replace(' ', '_').upper()}"] = value
    env["MOVED_MARKER"] = str(marker)
    env["PYTHON_BIN"] = sys_executable()
    env["CONTENTS_API"] = str(api_path)
    env["EXPECTED_JOB_TOKEN"] = JOB_TOKEN
    env["JOB_TOKEN_PERMISSIONS"] = json.dumps(permissions)
    env["SOURCE_FILE"] = str(SOURCE_FILE)
    env["SINK_PATH"] = str(sink)
    env["EFFECTS_PATH"] = str(effects_path)
    script = action_dir / main
    completed = subprocess.run(
        ["node", str(script)],
        cwd=action_dir,
        env=env,
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        raise AssertionError(f"node action failed\nstdout={completed.stdout}\nstderr={completed.stderr}")
    effects = json.loads(effects_path.read_text()) if effects_path.exists() else []
    copied = sink.read_bytes() if sink.exists() else None
    return {
        "moved": marker.exists(),
        "effects": effects,
        "copied": copied,
    }


def sys_executable() -> str:
    return os.environ.get("PYTHON_FOR_TESTS") or __import__("sys").executable


def resolve_and_run(repo: Path, ref: str, workflow_with: dict, permissions: dict, work: Path) -> dict:
    """Download tarball/{ref} at use time and run that tree.

    An earlier rev-parse result is intentionally not an argument. The ref string
    from the workflow is resolved again here, which is the download the runner
    performs after any prior lookup.
    """
    try:
        sha = _rev_parse(repo, ref)
    except subprocess.CalledProcessError:
        if FULL_SHA.match(ref):
            return {"moved": False, "effects": [], "copied": None}
        raise
    action_dir = work / "action"
    _extract(repo, sha, action_dir)
    return _run_resolved_action(action_dir, workflow_with, permissions, work)


def _prepare_and_move(repo: Path, ref: str) -> tuple[str, str]:
    """Point a movable ref at a benign commit, then move it.

    Returns the benign commit and the commit the ref names after the move.
    A full SHA is not a tag: the decoy tag `v7` moves, and the SHA still names
    the benign commit when that object exists in this repo.
    """
    _init_action_repo(repo)
    benign = _commit_action(repo, ACTION_YML_BENIGN, NODE_MAIN_BENIGN, "benign action")
    if not FULL_SHA.match(ref):
        _git(repo, "tag", ref, benign)
        checked = _rev_parse(repo, ref)
        if checked != benign:
            raise AssertionError("tag did not resolve to the commit it was given")
    malicious = _commit_action(repo, ACTION_YML_MOVED, NODE_MAIN_MOVED, "moved tag")
    if not FULL_SHA.match(ref):
        _git(repo, "tag", "-f", ref, malicious)
        moved = _rev_parse(repo, ref)
        if moved != malicious or moved == benign:
            raise AssertionError("tag did not move to the new commit")
    else:
        _git(repo, "tag", "-f", "v7", malicious)
        if _rev_parse(repo, benign) != benign:
            raise AssertionError("commit object changed when a tag moved")
        if _rev_parse(repo, "v7") != malicious:
            raise AssertionError("decoy tag did not move")
    return benign, malicious


def exercise(ref: str, workflow_with: dict, permissions: dict, work: Path) -> dict:
    repo = work / "action.git"
    benign, malicious = _prepare_and_move(repo, ref)
    outcome = resolve_and_run(repo, ref, workflow_with, permissions, work / "run")
    outcome["benign"] = benign
    outcome["malicious"] = malicious
    return outcome


def _workflow_on(data: dict) -> dict:
    # PyYAML 1.1 resolves the bare key `on` to boolean true.
    if "on" in data:
        block = data["on"]
    elif True in data:
        block = data[True]
    else:
        raise AssertionError("workflow has no 'on' block")
    if isinstance(block, str):
        return {block: {}}
    if isinstance(block, list):
        return {str(name): {} for name in block}
    if not isinstance(block, dict):
        raise AssertionError(f"unsupported trigger block: {block!r}")
    return block


def _permissions(workflow: dict, job: dict) -> dict:
    raw = job.get("permissions", workflow.get("permissions"))
    if not isinstance(raw, dict) or not raw:
        raise AssertionError(f"expected an explicit permissions map, got {raw!r}")
    return {str(key): str(value) for key, value in raw.items()}


def _external_uses(uses: str) -> tuple[str, str, str] | None:
    if uses.startswith("docker://") or uses.startswith("./") or uses.startswith(".\\"):
        return None
    org_repo, separator, ref = uses.partition("@")
    if not separator or not ref or "/" not in org_repo:
        raise AssertionError(f"uses value is not owner/repo@ref: {uses}")
    return org_repo, ref, uses


def workflow_cases() -> list[dict]:
    cases = []
    for path in sorted(WORKFLOWS.glob("*.yml")):
        data = yaml.safe_load(path.read_text())
        triggers = _workflow_on(data)
        for job_name, job in data["jobs"].items():
            permissions = _permissions(data, job)
            for index, step in enumerate(job.get("steps") or []):
                if not isinstance(step, dict) or "uses" not in step:
                    continue
                parsed = _external_uses(str(step["uses"]))
                if parsed is None:
                    continue
                _org_repo, ref, uses = parsed
                cases.append(
                    {
                        "workflow": str(path.relative_to(REPO_ROOT)),
                        "job": job_name,
                        "index": index,
                        "uses": uses,
                        "ref": ref,
                        "permissions": permissions,
                        "with": step.get("with") or {},
                        "triggers": sorted(triggers),
                    }
                )
    return cases


def _case_id(case: dict) -> str:
    return f"{case['workflow']}:{case['job']}:{case['uses']}"


def test_commit_object_does_not_follow_a_moved_tag(tmp_path: Path) -> None:
    """Git object ids stay put when the tag that used to name them is moved."""
    permissions = {"contents": "read"}
    repo = tmp_path / "action.git"
    _init_action_repo(repo)
    benign = _commit_action(repo, ACTION_YML_BENIGN, NODE_MAIN_BENIGN, "benign action")
    _git(repo, "tag", "v7", benign)
    checked = _rev_parse(repo, "v7")
    malicious = _commit_action(repo, ACTION_YML_MOVED, NODE_MAIN_MOVED, "moved tag")
    _git(repo, "tag", "-f", "v7", malicious)

    assert checked == benign
    assert _rev_parse(repo, "v7") == malicious
    assert _rev_parse(repo, benign) == benign

    by_tag = resolve_and_run(repo, "v7", {}, permissions, tmp_path / "tag")
    by_sha = resolve_and_run(repo, benign, {}, permissions, tmp_path / "sha")

    assert by_tag["moved"] is True
    assert by_tag["copied"] == SOURCE_FILE.read_bytes()
    assert "contents:read" in by_tag["effects"]
    assert by_sha["moved"] is False
    assert by_sha["copied"] is None
    assert by_sha["effects"] == []


def test_contents_read_is_denied_without_the_job_token(tmp_path: Path) -> None:
    """The contents stand-in copies the file only for the job token the action asked for."""
    repo = tmp_path / "action.git"
    _init_action_repo(repo)
    malicious = _commit_action(repo, ACTION_YML_MOVED, NODE_MAIN_MOVED, "moved tag")
    action_dir = tmp_path / "action"
    _extract(repo, malicious, action_dir)
    work = tmp_path / "run"
    work.mkdir()
    outcome = _run_resolved_action(action_dir, {"token": ""}, {"contents": "read"}, work)
    assert outcome["moved"] is True
    assert outcome["copied"] is None
    assert outcome["effects"] == []


@pytest.mark.parametrize("case", workflow_cases(), ids=_case_id)
def test_moved_tag_cannot_run_with_the_job_token(case: dict, tmp_path: Path) -> None:
    """Workflow `uses` must still name the pre-move commit after the tag moves.

    shell-checks.yml is the reported file: pull_request and push to main both
    start it, checkout is the first step, and its token is contents:read.
    The same download path applies to every other external action in
    .github/workflows.
    """
    if case["workflow"] == ".github/workflows/shell-checks.yml":
        assert "pull_request" in case["triggers"]
        assert "push" in case["triggers"]
        document = yaml.safe_load((REPO_ROOT / case["workflow"]).read_text())
        steps = document["jobs"][case["job"]]["steps"]
        shellcheck_at = next(
            index for index, step in enumerate(steps) if isinstance(step, dict) and "shellcheck" in str(step.get("run", ""))
        )
        if case["uses"] == "actions/checkout@v7":
            assert case["index"] < shellcheck_at
        assert case["permissions"].get("contents") == "read"

    outcome = exercise(case["ref"], case["with"], case["permissions"], tmp_path)
    assert outcome["moved"] is False, (
        f"{case['uses']} in {case['workflow']} resolved to the commit the tag was moved to "
        f"({outcome['malicious']}), not the commit it named before the move ({outcome['benign']})"
    )
    assert outcome["copied"] is None, (
        f"{case['uses']} copied repository contents with the job token "
        f"({case['permissions']})"
    )
    assert outcome["effects"] == [], (
        f"{case['uses']} used the job token for {outcome['effects']} "
        f"from permissions {case['permissions']}"
    )
