"""Moved action tags must not run with a token that can change pull request comments.

The ASH comment workflow and the monthly full-repository scan both run
``actions/github-script`` at the floating ``v9`` tag. The comment job is
``workflow_run`` on the default branch and grants ``pull-requests: write``.
The scan job grants ``issues: write``. ``label.yml`` does the same with
``actions/labeler@v7`` on ``pull_request_target``. Other unpinned actions in
those write-capable jobs (``actions/checkout@v7``, ``actions/setup-python@v7``,
``actions/upload-artifact@v7``) are included because the runner evaluates
input defaults from the downloaded action file, and that file can read
``github.token``.

These tests fail while a non-SHA ref is what a reaching event executes.
Pinning each of those ``uses`` values to a full 40-character commit SHA makes
a later tag move resolve to a different object, so the tests pass.

Not covered, because those jobs set ``contents: read`` and leave
``issues`` and ``pull-requests`` at no access, which cannot create, update,
or delete issue comments: the unpinned actions in ``ash-security-scan.yml``,
``contract-parity.yml``, ``control-library.yml`` (including
``hashicorp/setup-terraform@v4``), ``python-lint.yml``, and
``shell-checks.yml``. ``docs-integrity.yml`` and ``secret-boundary.yml``
already pin their actions.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = REPO_ROOT / ".github" / "workflows"

# Stand-in for the job's GITHUB_TOKEN. Not a real credential.
JOB_TOKEN = "placeholder-job-token"
BASE_REPOSITORY = "nkp-gfg/sample-agentcore-enterprise-platform"

# PermissionLevel.NoAccess is the zero value. A permissions mapping only
# sets the keys it lists.
PERMISSION_KEYS = (
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

FULL_SHA = re.compile(r"^[0-9a-f]{40}$")
TOKEN_EXPR = re.compile(
    r"\$\{\{\s*(?:secrets\.GITHUB_TOKEN|github\.token)\s*\}\}"
)
STATUS_FN = ("success(", "failure(", "cancelled(", "always(")

# Events whose GITHUB_TOKEN write permissions are forced to read for a pull
# request from a fork. pull_request_target is the documented exception.
# workflow_run is not in this set: it runs on the default branch and keeps
# the write permissions declared in the workflow.
FORK_READ_ONLY_EVENTS = {"pull_request", "pull_request_review", "pull_request_review_comment"}


def _workflow_on(doc: dict):
    if True in doc:
        return doc[True]
    return doc["on"]


def _load_workflows() -> list[tuple[Path, dict]]:
    loaded = []
    for path in sorted(WORKFLOWS.glob("*.yml")):
        loaded.append((path, yaml.safe_load(path.read_text())))
    return loaded


def _apply_permission_block(spec) -> dict[str, str]:
    if spec is None:
        return {key: "none" for key in PERMISSION_KEYS}
    if spec == "read-all":
        return {key: "read" for key in PERMISSION_KEYS}
    if spec == "write-all":
        return {key: "write" for key in PERMISSION_KEYS}
    granted = {key: "none" for key in PERMISSION_KEYS}
    for key, level in spec.items():
        granted[key] = level
    return granted


def job_permissions(doc: dict, job: dict) -> dict[str, str]:
    """Workflow permissions are copied onto a job that does not set its own."""
    if job.get("permissions") is not None:
        return _apply_permission_block(job.get("permissions"))
    if doc.get("permissions") is not None:
        return _apply_permission_block(doc.get("permissions"))
    # No permissions key: the hosted default can be permissive, but every
    # workflow in this repository sets an explicit block.
    return {key: "none" for key in PERMISSION_KEYS}


def effective_permissions(granted: dict[str, str], event_name: str, from_fork: bool) -> dict[str, str]:
    effective = dict(granted)
    if from_fork and event_name in FORK_READ_ONLY_EVENTS:
        for key, level in effective.items():
            if level == "write":
                effective[key] = "read"
    return effective


def can_mutate_issue_comments(perms: dict[str, str]) -> bool:
    """Create, update, and delete issue comments, which are also PR comments."""
    return perms.get("issues") == "write" or perms.get("pull-requests") == "write"


def _wrap_if(condition) -> str:
    """Match WorkflowTemplateConverter.ConvertToIfCondition for these workflows."""
    if condition is None or str(condition).strip() == "":
        return "success()"
    text = str(condition).strip()
    wrapped = re.fullmatch(r"\$\{\{(.*)\}\}", text, flags=re.S)
    if wrapped:
        text = wrapped.group(1).strip()
    if any(name in text for name in STATUS_FN):
        return text
    return f"success() && ({text})"


def _lookup(context: dict, path: str):
    current = context
    for part in path.split("."):
        if not isinstance(current, dict) or part not in current:
            return ""
        current = current[part]
    return current


def _eval_if(expression: str, context: dict):
    parser = _IfParser(expression, context)
    value = parser.parse_and()
    parser.skip()
    if parser.i != len(parser.text):
        raise AssertionError(f"unparsed if-expression tail: {parser.text[parser.i:]!r}")
    return value


class _IfParser:
    def __init__(self, text: str, context: dict):
        self.text = text
        self.context = context
        self.i = 0

    def skip(self) -> None:
        while self.i < len(self.text) and self.text[self.i].isspace():
            self.i += 1

    def parse_and(self):
        value = self.parse_cmp()
        while True:
            self.skip()
            if self.text.startswith("&&", self.i):
                self.i += 2
                rhs = self.parse_cmp()
                value = bool(value) and bool(rhs)
            else:
                return value

    def parse_cmp(self):
        value = self.parse_unary()
        self.skip()
        if self.text.startswith("==", self.i):
            self.i += 2
            return value == self.parse_unary()
        return value

    def parse_unary(self):
        self.skip()
        if self.text.startswith("(", self.i):
            self.i += 1
            value = self.parse_and()
            self.skip()
            if not self.text.startswith(")", self.i):
                raise AssertionError(f"missing ')' in {self.text!r}")
            self.i += 1
            return value
        for name, result in (
            ("success()", bool(self.context.get("success"))),
            ("always()", True),
            ("failure()", not bool(self.context.get("success"))),
            ("cancelled()", False),
        ):
            if self.text.startswith(name, self.i):
                self.i += len(name)
                return result
        if self.text.startswith(("'", '"'), self.i):
            quote = self.text[self.i]
            end = self.text.index(quote, self.i + 1)
            value = self.text[self.i + 1 : end]
            self.i = end + 1
            return value
        match = re.match(r"[A-Za-z_][A-Za-z0-9_.\-]*", self.text[self.i :])
        if not match:
            raise AssertionError(f"cannot parse if-expression at {self.text[self.i:]!r}")
        self.i += len(match.group(0))
        return _lookup(self.context, match.group(0))


def _split_uses(uses: str) -> tuple[str, str]:
    """Split owner/repo[/path]@ref the way the workflow parser does."""
    segments = uses.split("@")
    if len(segments) != 2 or not segments[0] or not segments[1]:
        raise AssertionError(f"unexpected uses value: {uses}")
    return segments[0], segments[1]


def _glob_match(pattern: str, path: str) -> bool:
    regex = []
    index = 0
    while index < len(pattern):
        if pattern.startswith("**/", index):
            regex.append("(?:.*/)?")
            index += 3
        elif pattern.startswith("**", index):
            regex.append(".*")
            index += 2
        elif pattern[index] == "*":
            regex.append("[^/]*")
            index += 1
        elif pattern[index] == "?":
            regex.append("[^/]")
            index += 1
        else:
            regex.append(re.escape(pattern[index]))
            index += 1
    return re.fullmatch("".join(regex), path) is not None


def _changed_files_match(scan_doc: dict, relative_path: str) -> bool:
    for job in scan_doc["jobs"].values():
        for step in job["steps"]:
            files = (step.get("with") or {}).get("files")
            if not files:
                continue
            patterns = [line.strip() for line in str(files).splitlines() if line.strip()]
            return any(_glob_match(pattern, relative_path) for pattern in patterns)
    raise AssertionError("ASH scan workflow does not declare a changed-files filter")


def _run_bash(script: str, env: dict[str, str], cwd: Path) -> None:
    subprocess.run(
        ["bash", "-c", script],
        cwd=cwd,
        env=env,
        check=True,
        text=True,
    )


def _read_output(path: Path) -> dict[str, str]:
    outputs = {}
    if not path.exists():
        return outputs
    for line in path.read_text().splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        outputs[key] = value
    return outputs


def _prepare_comment_artifact(comment_doc: dict, scan_doc: dict) -> dict[str, str]:
    """Run the scan's artifact script and the comment job's pr-info script.

    A pull request that touches a Python file satisfies the scan's changed-file
    filter, so the scan writes pr_number.txt and the comment job's shell step
    publishes it as a step output. The github-script step's ``if`` reads that
    output.
    """
    changed = "agent-code/strands-agent/agent.py"
    if not _changed_files_match(scan_doc, changed):
        return {}

    artifact = Path("/tmp/ash-artifacts")
    results = Path("/tmp/ash-results")
    shutil.rmtree(artifact, ignore_errors=True)
    shutil.rmtree(results, ignore_errors=True)
    try:
        prepare = _find_run(scan_doc, "Prepare artifacts")
        env = os.environ.copy()
        env.update(
            {
                "PR_NUMBER": "17",
                "PR_SHA": "0123456789abcdef0123456789abcdef01234567",
            }
        )
        _run_bash(prepare, env, REPO_ROOT)
        results.mkdir(parents=True)
        for child in artifact.iterdir():
            target = results / child.name
            if child.is_dir():
                shutil.copytree(child, target)
            else:
                shutil.copy2(child, target)

        info_script = _find_run(comment_doc, "Get PR information")
        output_file = results / "github_output.txt"
        env = os.environ.copy()
        env["GITHUB_OUTPUT"] = str(output_file)
        _run_bash(info_script, env, REPO_ROOT)
        return _read_output(output_file)
    finally:
        shutil.rmtree(artifact, ignore_errors=True)
        shutil.rmtree(results, ignore_errors=True)


def _prepare_findings_output(scan_doc: dict) -> dict[str, str]:
    script = _find_run(scan_doc, "Generate scan summary")
    work = Path("/tmp/ash-findings-summary")
    shutil.rmtree(work, ignore_errors=True)
    work.mkdir()
    try:
        (work / "ash-output.log").write_text(
            "ASH Scan Results Summary\nActionable findings detected!\nsource-dir: .\n"
        )
        output_file = work / "github_output.txt"
        env = os.environ.copy()
        env.update(
            {
                "GITHUB_OUTPUT": str(output_file),
                "EVENT_NAME": "schedule",
                "COMMIT_SHA": "0123456789abcdef0123456789abcdef01234567",
                "ACTOR": "scheduler",
            }
        )
        _run_bash(script, env, work)
        return _read_output(output_file)
    finally:
        shutil.rmtree(work, ignore_errors=True)


def _find_run(doc: dict, step_name: str) -> str:
    for job in doc["jobs"].values():
        for step in job["steps"]:
            if step.get("name") == step_name:
                return step["run"]
    raise AssertionError(f"missing run step {step_name}")


def _candidate_events(doc: dict) -> list[dict]:
    trigger = _workflow_on(doc)
    events = []
    if isinstance(trigger, list):
        items = [(name, None) for name in trigger]
    else:
        items = list(trigger.items())
    for name, spec in items:
        if name == "push":
            branches = (spec or {}).get("branches") or ["main"]
            for branch in branches:
                events.append(
                    {"name": "push", "branch": branch, "from_fork": False}
                )
        elif name == "pull_request":
            events.append({"name": "pull_request", "from_fork": True})
        elif name == "pull_request_target":
            events.append({"name": "pull_request_target", "from_fork": True})
        elif name == "schedule":
            events.append({"name": "schedule", "from_fork": False})
        elif name == "workflow_dispatch":
            events.append({"name": "workflow_dispatch", "from_fork": False})
        elif name == "workflow_run":
            spec = spec or {}
            types = spec.get("types") or ["completed"]
            workflows = spec.get("workflows") or []
            for activity in types:
                for workflow_name in workflows:
                    events.append(
                        {
                            "name": "workflow_run",
                            "activity": activity,
                            "workflow": workflow_name,
                            "workflow_run_event": "pull_request",
                            "from_fork": False,
                        }
                    )
    return events


def _context(event: dict, outputs: dict[str, dict[str, str]], success: bool) -> dict:
    return {
        "success": success,
        "github": {
            "event_name": event["name"],
            "event": {
                "workflow_run": {
                    "event": event.get("workflow_run_event", ""),
                    "conclusion": "success",
                }
            },
        },
        "steps": {
            step_id: {"outputs": step_outputs}
            for step_id, step_outputs in outputs.items()
        },
    }


def _condition_holds(condition, event: dict, outputs: dict, success: bool = True) -> bool:
    return bool(_eval_if(_wrap_if(condition), _context(event, outputs, success)))


def _outputs_for(path: Path, doc: dict, workflows: dict[str, dict]) -> dict[str, dict[str, str]]:
    outputs: dict[str, dict[str, str]] = {}
    if path.name == "ash-security-comment.yml":
        pr_info = _prepare_comment_artifact(doc, workflows["ash-security-scan.yml"])
        outputs["pr-info"] = pr_info
    if path.name == "ash-full-repository-scan.yml":
        summary = _prepare_findings_output(doc)
        outputs["scan-summary"] = summary
    return outputs


def _parse_uses_steps(path: Path, doc: dict) -> list[dict]:
    found = []
    for job_name, job in doc["jobs"].items():
        for index, step in enumerate(job["steps"]):
            uses = step.get("uses")
            if not uses or uses.startswith("./") or uses.startswith("docker://"):
                continue
            owner_repo, ref = _split_uses(uses)
            found.append(
                {
                    "file": path.name,
                    "job": job_name,
                    "index": index,
                    "name": step.get("name") or uses,
                    "uses": uses,
                    "owner_repo": owner_repo,
                    "ref": ref,
                    "pinned": FULL_SHA.fullmatch(ref) is not None,
                    "with": step.get("with") or {},
                    "if": step.get("if"),
                    "job_if": job.get("if"),
                }
            )
    return found


class _CommentApi:
    """Issue-comment endpoints, allowed only for issues:write or pull-requests:write."""

    def __init__(self, perms: dict[str, str]):
        self.perms = perms
        self.comments = {
            100: {"id": 100, "issue_number": 4, "body": "existing review note"}
        }
        self.next_id = 101
        self.mutations: list[str] = []
        self._lock = threading.Lock()

    def handle(self, method: str, path: str, token: str, body: dict | None) -> tuple[int, dict]:
        if token != JOB_TOKEN:
            return 401, {"message": "bad credentials"}
        owner_repo = f"/{BASE_REPOSITORY}/"
        prefix = f"/repos{owner_repo}"
        if not path.startswith(prefix):
            return 404, {"message": "not found"}
        if not can_mutate_issue_comments(self.perms):
            return 403, {"message": "resource not accessible by integration"}
        relative = path[len(prefix) :]
        created = re.fullmatch(r"issues/(\d+)/comments", relative)
        existing = re.fullmatch(r"issues/comments/(\d+)", relative)
        with self._lock:
            if method == "POST" and created:
                comment_id = self.next_id
                self.next_id += 1
                self.comments[comment_id] = {
                    "id": comment_id,
                    "issue_number": int(created.group(1)),
                    "body": (body or {}).get("body", ""),
                }
                self.mutations.append(f"create issue {created.group(1)} comment {comment_id}")
                return 201, self.comments[comment_id]
            if method == "PATCH" and existing:
                comment_id = int(existing.group(1))
                if comment_id not in self.comments:
                    return 404, {"message": "not found"}
                self.comments[comment_id]["body"] = (body or {}).get("body", "")
                self.mutations.append(f"update comment {comment_id}")
                return 200, self.comments[comment_id]
            if method == "DELETE" and existing:
                comment_id = int(existing.group(1))
                if comment_id not in self.comments:
                    return 404, {"message": "not found"}
                del self.comments[comment_id]
                self.mutations.append(f"delete comment {comment_id}")
                return 204, {}
        return 404, {"message": "not found"}


def _serve(api: _CommentApi) -> tuple[ThreadingHTTPServer, str]:
    class Handler(BaseHTTPRequestHandler):
        def _read_body(self) -> dict | None:
            length = int(self.headers.get("Content-Length") or "0")
            if length == 0:
                return None
            raw = self.rfile.read(length)
            return json.loads(raw.decode())

        def _dispatch(self, method: str) -> None:
            header = self.headers.get("Authorization") or ""
            token = header[7:] if header.startswith("Bearer ") else ""
            status, payload = api.handle(method, urlparse(self.path).path, token, self._read_body())
            data = json.dumps(payload).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_POST(self) -> None:
            self._dispatch("POST")

        def do_PATCH(self) -> None:
            self._dispatch("PATCH")

        def do_DELETE(self) -> None:
            self._dispatch("DELETE")

        def log_message(self, fmt: str, *args) -> None:
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address
    return server, f"http://{host}:{port}"


def _git(repo: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(repo), *args],
        check=True,
        text=True,
        capture_output=True,
    )
    return result.stdout.strip()


def _init_action_repo(root: Path) -> Path:
    repo = root / "action.git"
    repo.mkdir()
    subprocess.run(["git", "init", "-b", "main", str(repo)], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(repo), "config", "user.email", "actions-test@example.com"], check=True)
    subprocess.run(["git", "-C", str(repo), "config", "user.name", "actions-test"], check=True)
    return repo


ATTACKER_ACTION_YML = """name: Moved tag
inputs:
  token:
    description: token
    default: ${{ github.token }}
  github-token:
    description: token
    default: ${{ github.token }}
  repo-token:
    description: token
    default: ${{ github.token }}
runs:
  using: node24
  main: dist/index.js
"""

ATTACKER_MAIN = r"""
const http = require('http');

function request(method, pathname, token, body) {
  const payload = body ? Buffer.from(JSON.stringify(body)) : null;
  const base = new URL(process.env.GITHUB_API_URL);
  return new Promise((resolve) => {
    const req = http.request(
      {
        hostname: base.hostname,
        port: base.port,
        path: pathname,
        method,
        headers: Object.assign(
          {
            Authorization: 'Bearer ' + token,
            Accept: 'application/vnd.github+json',
            'Content-Type': 'application/json',
          },
          payload ? { 'Content-Length': payload.length } : {}
        ),
      },
      (res) => {
        res.resume();
        res.on('end', () => resolve(res.statusCode));
      }
    );
    req.on('error', () => resolve(0));
    if (payload) req.write(payload);
    req.end();
  });
}

async function main() {
  const repo = process.env.GITHUB_REPOSITORY;
  // These are the input names the runner publishes from github-token,
  // repo-token, and an action.yml default of ${{ github.token }}.
  const tokens = ['INPUT_TOKEN', 'INPUT_GITHUB-TOKEN', 'INPUT_REPO-TOKEN']
    .map((key) => process.env[key])
    .filter((value) => value);
  for (const token of tokens) {
    try {
      await request('POST', `/repos/${repo}/issues/4/comments`, token, {
        body: 'comment from moved tag',
      });
      await request('PATCH', `/repos/${repo}/issues/comments/100`, token, {
        body: 'comment rewritten by moved tag',
      });
      await request('DELETE', `/repos/${repo}/issues/comments/100`, token, null);
    } catch (err) {
      // Keep going so one rejected header cannot hide a later token.
    }
  }
}

main();
"""


def _commit_tree(repo: Path, files: dict[str, str], message: str) -> str:
    for name, contents in files.items():
        path = repo / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(contents)
    subprocess.run(["git", "-C", str(repo), "add", "."], check=True, capture_output=True)
    subprocess.run(
        ["git", "-C", str(repo), "commit", "-m", message],
        check=True,
        capture_output=True,
    )
    return _git(repo, "rev-parse", "HEAD")


def _resolve_ref(repo: Path, ref: str) -> str:
    """Resolve the ref the runner sends to ResolveActionsDownloadInfo.

    A full commit SHA is the object id. Any other ref is the current tag or
    branch, which ``git rev-parse ref^{commit}`` follows after a tag move.
    """
    if FULL_SHA.fullmatch(ref):
        return ref
    return _git(repo, "rev-parse", "--verify", f"{ref}^{{commit}}")


def _input_name(key: str) -> str:
    """Handler.AddInputsToEnvironment replaces spaces, then uppercases."""
    return "INPUT_" + key.replace(" ", "_").upper()


def _evaluated_inputs(action_dir: Path, workflow_with: dict) -> dict[str, str]:
    manifest = yaml.safe_load((action_dir / "action.yml").read_text())
    runs = manifest["runs"]
    if not str(runs.get("using", "")).startswith("node"):
        raise AssertionError(f"attacker action is not a node action: {runs}")
    provided = {}
    for key, value in workflow_with.items():
        provided[str(key)] = TOKEN_EXPR.sub(JOB_TOKEN, str(value))
    for key, spec in (manifest.get("inputs") or {}).items():
        if key in provided or not isinstance(spec, dict):
            continue
        default = spec.get("default")
        if default is not None:
            provided[key] = TOKEN_EXPR.sub(JOB_TOKEN, str(default))
    return provided


def _execute_resolved_action(
    repo: Path,
    resolved: str,
    workflow_with: dict,
    api_url: str,
) -> bool:
    """Spawn node on runs.main the way NodeScriptActionHandler does.

    Returns True when the resolved object is in this action repo and node
    was started. A full SHA that is not the moved tag is not in the repo.
    """
    try:
        _git(repo, "cat-file", "-e", f"{resolved}^{{commit}}")
    except subprocess.CalledProcessError:
        return False
    destination = repo.parent / "extracted"
    shutil.rmtree(destination, ignore_errors=True)
    destination.mkdir()
    archive = subprocess.run(
        ["git", "-C", str(repo), "archive", resolved],
        check=True,
        capture_output=True,
    )
    subprocess.run(["tar", "-x", "-C", str(destination)], input=archive.stdout, check=True)
    inputs = _evaluated_inputs(destination, workflow_with)
    manifest = yaml.safe_load((destination / "action.yml").read_text())
    main = destination / manifest["runs"]["main"]
    env = {
        "PATH": os.environ.get("PATH", ""),
        "GITHUB_API_URL": api_url,
        "GITHUB_REPOSITORY": BASE_REPOSITORY,
    }
    for key, value in inputs.items():
        env[_input_name(key)] = value
    subprocess.run(
        ["node", str(main)],
        cwd=destination,
        env=env,
        check=False,
        capture_output=True,
        text=True,
    )
    return True


def _move_tag_and_run(ref: str, workflow_with: dict, perms: dict[str, str]) -> dict:
    root = Path("/tmp/moved-action-tag")
    shutil.rmtree(root, ignore_errors=True)
    root.mkdir()
    server = None
    try:
        repo = _init_action_repo(root)
        legitimate = _commit_tree(
            repo,
            {
                "action.yml": "name: Legitimate\nruns:\n  using: node24\n  main: dist/index.js\n",
                "dist/index.js": "process.exit(0);\n",
            },
            "legitimate action",
        )
        # A full SHA is an object id, so the movable ref is a separate tag.
        movable = ref if FULL_SHA.fullmatch(ref) is None else "v9"
        _git(repo, "tag", "-a", movable, "-m", movable, legitimate)
        attacker = _commit_tree(
            repo,
            {"action.yml": ATTACKER_ACTION_YML, "dist/index.js": ATTACKER_MAIN},
            "moved tag payload",
        )
        # Force-update the tag ref. The previous commit object stays addressable.
        _git(repo, "tag", "-f", movable, attacker)
        moved = _git(repo, "rev-parse", "--verify", f"{movable}^{{commit}}")
        if moved != attacker:
            raise AssertionError("git tag -f did not move the tag")
        if _git(repo, "rev-parse", "--verify", f"{legitimate}^{{commit}}") != legitimate:
            raise AssertionError("moving the tag rewrote the previous commit")

        resolved = _resolve_ref(repo, ref)
        api = _CommentApi(perms)
        server, api_url = _serve(api)
        executed = _execute_resolved_action(repo, resolved, workflow_with, api_url)
        return {
            "resolved": resolved,
            "attacker": attacker,
            "executed_resolved_tree": executed,
            "mutations": list(api.mutations),
        }
    finally:
        if server is not None:
            server.shutdown()
            server.server_close()
        shutil.rmtree(root, ignore_errors=True)


def _reaching_action_steps() -> list[dict]:
    loaded = {path.name: doc for path, doc in _load_workflows()}
    reached = []
    for path, doc in _load_workflows():
        outputs = None
        for step in _parse_uses_steps(path, doc):
            for event in _candidate_events(doc):
                granted = job_permissions(doc, doc["jobs"][step["job"]])
                perms = effective_permissions(granted, event["name"], event["from_fork"])
                if not can_mutate_issue_comments(perms):
                    continue
                if outputs is None:
                    outputs = _outputs_for(path, doc, loaded)
                if not _condition_holds(step["job_if"], event, outputs):
                    continue
                if not _condition_holds(step["if"], event, outputs):
                    continue
                step = dict(step)
                step["event"] = event["name"]
                step["permissions"] = perms
                reached.append(step)
                break
    return reached


def test_moved_action_tags_cannot_mutate_pull_request_comments():
    """Every action a write-capable job actually runs.

    The attacker moves that action's tag, the reaching event downloads the
    new commit, and the entrypoint uses the job token. Create, update, and
    delete are aimed at pull request 4, not the triggering pull request 17.
    A full commit SHA does not follow the moved tag.
    """
    steps = _reaching_action_steps()
    assert steps, "expected the write-capable workflows to run at least one action"
    failures = []
    for step in steps:
        outcome = _move_tag_and_run(step["ref"], step["with"], step["permissions"])
        ran_attacker = (
            outcome["executed_resolved_tree"] and outcome["resolved"] == outcome["attacker"]
        )
        if ran_attacker or outcome["mutations"]:
            failures.append(
                f"{step['file']} job {step['job']} step {step['name']!r} "
                f"uses {step['uses']} on {step['event']} with {step['permissions']['issues']} "
                f"issues and {step['permissions']['pull-requests']} pull-requests; "
                f"resolved {outcome['resolved']} attacker {outcome['attacker']}; "
                f"mutations {outcome['mutations']}"
            )
    assert not failures, "moved tag ran with comment write:\n" + "\n".join(failures)


def test_ash_comment_job_runs_moved_github_script_against_another_pull_request():
    """The finding's path: scan artifact, workflow_run, then github-script@v9."""
    loaded = {path.name: doc for path, doc in _load_workflows()}
    doc = loaded["ash-security-comment.yml"]
    steps = _reaching_action_steps()
    comment_steps = [
        step
        for step in steps
        if step["file"] == "ash-security-comment.yml" and "github-script" in step["uses"]
    ]
    assert len(comment_steps) == 1, comment_steps
    step = comment_steps[0]
    assert step["event"] == "workflow_run"
    assert step["permissions"]["pull-requests"] == "write"
    assert step["permissions"]["contents"] == "none"
    pr_info = _prepare_comment_artifact(doc, loaded["ash-security-scan.yml"])
    assert pr_info.get("pr_number") == "17"

    outcome = _move_tag_and_run(step["ref"], step["with"], step["permissions"])
    ran_attacker = outcome["executed_resolved_tree"] and outcome["resolved"] == outcome["attacker"]
    assert not ran_attacker and not outcome["mutations"], (
        "workflow_run comment job executed the moved v9 tag and changed comments "
        f"on a pull request other than {pr_info['pr_number']}: {outcome['mutations']}"
    )
