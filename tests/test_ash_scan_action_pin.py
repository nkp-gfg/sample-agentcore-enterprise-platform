"""The monthly ASH scan must not run a movable action with issues access.

The workflow at .github/workflows/ash-full-repository-scan.yml grants the job
``issues: write`` and runs ``actions/github-script@v9`` when a scheduled scan
records findings. The same job also runs other actions at movable tags. These
tests drive that path the way actions/runner v2.338.2 does: resolve the ref
when the job prepares, execute the action entrypoint that ref points at, and
pass the job token through the action inputs. They fail while a moved tag can
create or edit an issue, or can run its own file before that call. They pass
once every step that still runs with ``issues: write`` is pinned to a full
commit SHA.

The pull-request comment workflow uses the same movable tag with
``pull-requests: write`` and no ``issues`` permission. Issue creation on that
workflow is covered. Running that action's code for a pull-request comment is
not the outcome these tests require to fail.
"""

from __future__ import annotations

import os
import re
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
SCAN_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "ash-full-repository-scan.yml"
COMMENT_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "ash-security-comment.yml"

# Obvious placeholder. Not a credential.
JOB_TOKEN = "placeholder-job-token"
OWNER = "example-owner"
REPO = "example-repo"

FULL_SHA = re.compile(r"^[0-9a-fA-F]{40}$")
STATUS_FUNCTIONS = ("always", "cancelled", "failure", "success")


def _workflow_map(path: Path) -> dict:
    loaded = yaml.safe_load(path.read_text())
    # PyYAML 1.1 treats the bare key "on" as boolean true.
    if True in loaded and "on" not in loaded:
        loaded["on"] = loaded.pop(True)
    return loaded


def _is_falsy(value) -> bool:
    # EvaluationResult.IsFalsy in actions/runner DTExpressions2.
    if value is None:
        return True
    if isinstance(value, bool):
        return not value
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return value == 0 or value != value
    if isinstance(value, str):
        return value == ""
    return False


def _equal(left, right) -> bool:
    # EvaluationResult.AbstractEqual: strings compare ordinal-ignore-case.
    if isinstance(left, str) and isinstance(right, str):
        return left.casefold() == right.casefold()
    return left == right


class _Parser:
    def __init__(self, text: str):
        token = r"&&|\|\||==|!=|[()]|'(?:[^'\\]|\\.)*'|\"(?:[^\"\\]|\\.)*\"|[A-Za-z_][A-Za-z0-9_.-]*"
        self.tokens = [tok for tok in re.findall(token, text) if not tok.isspace()]
        self.index = 0

    def peek(self):
        if self.index >= len(self.tokens):
            return None
        return self.tokens[self.index]

    def take(self):
        current = self.peek()
        if current is None:
            raise AssertionError("expression ended early")
        self.index += 1
        return current

    def parse(self):
        value = self._or()
        if self.peek() is not None:
            raise AssertionError(f"unparsed expression tail: {self.tokens[self.index:]}")
        return value

    def _or(self):
        left = self._and()
        rights = []
        while self.peek() == "||":
            self.take()
            rights.append(self._and())

        def evaluate(context):
            result = left(context)
            for right in rights:
                if not _is_falsy(result):
                    right(context)
                    continue
                result = right(context)
            return result

        return evaluate

    def _and(self):
        left = self._cmp()
        rights = []
        while self.peek() == "&&":
            self.take()
            rights.append(self._cmp())

        def evaluate(context):
            # And.EvaluateCore returns the first falsy operand's value.
            result = left(context)
            for right in rights:
                if _is_falsy(result):
                    right(context)
                    return result
                result = right(context)
            return result

        return evaluate

    def _cmp(self):
        left = self._primary()
        ops = []
        while self.peek() in {"==", "!="}:
            ops.append((self.take(), self._primary()))

        def evaluate(context):
            result = left(context)
            for op, right_fn in ops:
                right = right_fn(context)
                equal = _equal(result, right)
                result = equal if op == "==" else not equal
            return result

        return evaluate

    def _primary(self):
        token = self.take()
        if token == "(":
            inner = self._or()
            if self.take() != ")":
                raise AssertionError("missing closing parenthesis")
            return inner
        if token[0] in {"'", '"'}:
            literal = token[1:-1]
            return lambda _context: literal
        if self.peek() == "(":
            self.take()
            if self.take() != ")":
                raise AssertionError(f"only zero-argument functions are used, got {token}")
            name = token.casefold()

            def call(context, name=name):
                if name == "success":
                    return context["job_status"] == "success"
                if name == "always":
                    return True
                raise AssertionError(f"unexpected function {name}")

            return call
        path = token.split(".")

        def lookup(context, path=path):
            current = context
            for part in path:
                if not isinstance(current, dict) or part not in current:
                    return None
                current = current[part]
            return current

        return lookup


def _final_if(condition: str | None) -> str:
    # WorkflowTemplateConverter.ConvertToIfCondition wraps conditions that
    # do not already name a status function.
    if condition is None or not str(condition).strip():
        return "success()"
    lowered = condition.casefold()
    if any(re.search(rf"\b{name}\s*\(", lowered) for name in STATUS_FUNCTIONS):
        return condition
    return f"success() && ({condition})"


def _condition_passes(condition: str | None, context: dict) -> bool:
    expression = _final_if(condition)
    value = _Parser(expression).parse()(context)
    return not _is_falsy(value)


def _permissions(workflow: dict, job: dict) -> dict[str, str]:
    # A job with no permissions block receives the workflow block. Keys that
    # are absent stay NoAccess, the zero value of PermissionLevel.
    block = job.get("permissions")
    if block is None:
        block = workflow.get("permissions") or {}
    levels = {}
    for key, value in block.items():
        if value not in {"none", "read", "write"}:
            raise AssertionError(f"unexpected permission level {key}={value}")
        levels[key] = "none" if value == "none" else value
    return levels


def _split_uses(uses: str) -> tuple[str, str]:
    name, ref = uses.rsplit("@", 1)
    return name, ref.strip()


class ActionMirror:
    """Git repos standing in for action repositories. Tags move with update-ref."""

    def __init__(self, root: Path):
        self.root = root
        self.root.mkdir(parents=True, exist_ok=True)
        self._repos: dict[str, Path] = {}

    def repo(self, name: str) -> Path:
        if name not in self._repos:
            path = self.root / name
            path.mkdir(parents=True, exist_ok=True)
            self._git(path, ["init", "-q"])
            self._git(path, ["config", "user.email", "test@example.com"])
            self._git(path, ["config", "user.name", "Action Mirror"])
            self._repos[name] = path
        return self._repos[name]

    def commit_files(self, name: str, files: dict[str, str], message: str) -> str:
        path = self.repo(name)
        for relative, contents in files.items():
            destination = path / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_text(contents)
            self._git(path, ["add", relative])
        self._git(path, ["commit", "-q", "-m", message])
        return self._git(path, ["rev-parse", "HEAD"]).strip()

    def point_tag(self, name: str, tag: str, commit: str) -> None:
        # A tag ref is not a commit id. Updating it is the move the next job sees.
        self._git(self.repo(name), ["update-ref", f"refs/tags/{tag}", commit])

    def resolve(self, name: str, ref: str) -> str | None:
        if FULL_SHA.fullmatch(ref):
            kind = self._git(
                self.repo(name),
                ["cat-file", "-t", ref],
                check=False,
            )
            if kind.strip() != "commit":
                return None
            return ref.lower()
        resolved = self._git(
            self.repo(name),
            ["rev-parse", "--verify", f"{ref}^{{commit}}"],
            check=False,
        )
        if not resolved:
            return None
        return resolved.strip()

    def show_file(self, name: str, commit: str, relative: str) -> str | None:
        shown = self._git(
            self.repo(name),
            ["show", f"{commit}:{relative}"],
            check=False,
        )
        return shown if shown != "" else None

    def _git(self, path: Path, args: list[str], check: bool = True) -> str:
        result = subprocess.run(
            ["git", *args],
            cwd=path,
            check=False,
            capture_output=True,
            text=True,
        )
        if check and result.returncode != 0:
            raise AssertionError(result.stderr)
        if result.returncode != 0:
            return ""
        return result.stdout


BENIGN_ACTION = {
    "action.yml": "name: Benign\nruns:\n  using: node24\n  main: dist/index.js\n",
    "dist/index.js": "process.exit(0);\n",
}

# The moved tag's entrypoint is the code the runner executes. It records that
# it ran, then calls the issues create and update routes with the token the
# runner placed in the action inputs. The header shape is withAuthorizationPrefix
# from @octokit/auth-token 6.0.0.
MALICIOUS_ACTION = {
    "action.yml": """
name: Moved tag
inputs:
  github-token:
    description: Job token
    default: ${{ github.token }}
  token:
    description: Checkout-style token input
    default: ${{ github.token }}
runs:
  using: node24
  main: dist/index.js
""",
    "dist/index.js": r"""
const fs = require('fs');
const http = require('http');

fs.writeFileSync('moved-tag-ran', 'ran');

const token = (process.env['INPUT_GITHUB-TOKEN'] || process.env['INPUT_TOKEN'] || '').trim();
const api = new URL(process.env.GITHUB_API_URL);
const owner = process.env.GITHUB_REPOSITORY_OWNER;
const repository = process.env.GITHUB_REPOSITORY;
const repo = repository.slice(owner.length + 1);

function authorization(value) {
  if (value.split('.').length === 3) {
    return 'bearer ' + value;
  }
  return 'token ' + value;
}

function call(method, path, body) {
  const data = JSON.stringify(body);
  const headers = {
    'content-type': 'application/json',
    'content-length': Buffer.byteLength(data),
    accept: 'application/vnd.github+json',
  };
  if (token) {
    headers.authorization = authorization(token);
  }
  return new Promise((resolve, reject) => {
    const req = http.request({
      protocol: api.protocol,
      hostname: api.hostname,
      port: api.port,
      path,
      method,
      headers,
    }, (res) => {
      res.resume();
      res.on('end', () => resolve(res.statusCode));
    });
    req.on('error', reject);
    req.write(data);
    req.end();
  });
}

call('POST', `/repos/${owner}/${repo}/issues`, {title: 'moved-tag', body: 'created'})
  .then(() => call('PATCH', `/repos/${owner}/${repo}/issues/1`, {title: 'edited', body: 'changed'}))
  .catch(() => {});
""",
}


class IssueApi:
    """POST/PATCH issues routes from @octokit/plugin-rest-endpoint-methods 17.0.0.

    A job token may change an issue only when that token's issues permission is
    write and the path is the repository the token was issued for.
    """

    def __init__(self):
        self.tokens: dict[str, dict] = {}
        self.issues: dict[tuple[str, str], dict[int, dict]] = {}
        self.attempts: list[dict] = []
        self._lock = threading.Lock()
        self._server = ThreadingHTTPServer(("127.0.0.1", 0), self._handler(self))
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    @property
    def base_url(self) -> str:
        host, port = self._server.server_address[:2]
        return f"http://{host}:{port}"

    def issue(self, token: str, permissions: dict[str, str]) -> None:
        self.tokens[token] = {
            "owner": OWNER,
            "repo": REPO,
            "permissions": permissions,
        }

    def close(self) -> None:
        self._server.shutdown()
        self._thread.join(timeout=5)
        self._server.server_close()

    def changed(self) -> bool:
        return any(self.issues.values())

    @staticmethod
    def _handler(api: "IssueApi"):
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, fmt, *args):
                return

            def do_POST(self):
                self._handle("POST")

            def do_PATCH(self):
                self._handle("PATCH")

            def _handle(self, method: str):
                length = int(self.headers.get("content-length", "0"))
                raw = self.rfile.read(length) if length else b""
                parsed = urlparse(self.path)
                match = re.fullmatch(
                    r"/repos/([^/]+)/([^/]+)/issues(?:/(\d+))?",
                    parsed.path,
                )
                status = 404
                mutated = False
                with api._lock:
                    api.attempts.append(
                        {
                            "method": method,
                            "path": parsed.path,
                            "authorization": self.headers.get("authorization"),
                        }
                    )
                    if match and (
                        (method == "POST" and match.group(3) is None)
                        or (method == "PATCH" and match.group(3) is not None)
                    ):
                        status, mutated = api._authorize_and_apply(
                            method,
                            match.group(1),
                            match.group(2),
                            match.group(3),
                            self.headers.get("authorization"),
                            raw,
                        )
                self.send_response(status)
                self.send_header("content-type", "application/json")
                self.end_headers()
                if mutated:
                    self.wfile.write(b'{"ok":true}')
                else:
                    self.wfile.write(b'{"message":"refused"}')

        return Handler

    def _authorize_and_apply(
        self,
        method: str,
        owner: str,
        repo: str,
        number: str | None,
        authorization: str | None,
        raw: bytes,
    ) -> tuple[int, bool]:
        token = None
        if authorization:
            kind, _, value = authorization.partition(" ")
            if kind in {"token", "bearer"} and value:
                token = value
        record = self.tokens.get(token or "")
        if record is None:
            return 401, False
        if record["owner"] != owner or record["repo"] != repo:
            return 403, False
        if record["permissions"].get("issues") != "write":
            return 403, False
        import json

        body = json.loads(raw.decode() or "{}")
        key = (owner, repo)
        bucket = self.issues.setdefault(key, {})
        if method == "POST":
            issue_number = max(bucket, default=0) + 1
            bucket[issue_number] = {
                "title": body.get("title"),
                "body": body.get("body"),
            }
            return 201, True
        issue_number = int(number)
        current = bucket.setdefault(issue_number, {"title": None, "body": None})
        current.update({k: v for k, v in body.items() if k in {"title", "body"}})
        return 200, True


def _evaluate_template(value: str, token: str) -> str:
    # ActionManifestManager.EvaluateDefaultInput and step input evaluation.
    # Only the token expressions this workflow and the moved action use.

    def replace(match: re.Match) -> str:
        expression = match.group(1).strip()
        if expression in {"github.token", "secrets.GITHUB_TOKEN"}:
            return token
        # Other step inputs (artifact name, paths) are not the token.
        return "evaluated"

    return re.sub(r"\$\{\{\s*([^}]+?)\s*\}\}", replace, value)


def _input_environment(inputs: dict[str, str]) -> dict[str, str]:
    # Handler.AddInputsToEnvironment. Hyphens stay; spaces become underscores.
    environment = {}
    for key, value in inputs.items():
        environment[f"INPUT_{key.replace(' ', '_').upper()}"] = value or ""
    return environment


def _context_environment(github: dict) -> dict[str, str]:
    # GitHubContext allowlist. "token" is not exported, so GITHUB_TOKEN is absent.
    allow = {
        "action",
        "api_url",
        "event_name",
        "repository",
        "repository_owner",
        "workspace",
    }
    environment = {}
    for key, value in github.items():
        if key in allow and isinstance(value, str):
            environment[f"GITHUB_{key.upper()}"] = value
    return environment


def _load_action(mirror: ActionMirror, name: str, commit: str) -> dict | None:
    text = mirror.show_file(name, commit, "action.yml")
    if text is None:
        return None
    return yaml.safe_load(text)


def _materialize(mirror: ActionMirror, name: str, commit: str, directory: Path) -> None:
    archive = subprocess.run(
        ["git", "archive", commit],
        cwd=mirror.repo(name),
        check=True,
        capture_output=True,
    )
    directory.mkdir(parents=True, exist_ok=True)
    subprocess.run(["tar", "-x"], cwd=directory, input=archive.stdout, check=True)


def _run_node_action(directory: Path, environment: dict[str, str]) -> None:
    manifest = yaml.safe_load((directory / "action.yml").read_text())
    using = manifest["runs"]["using"]
    if not str(using).startswith("node"):
        raise AssertionError(f"unexpected action runtime {using}")
    main = directory / manifest["runs"]["main"]
    subprocess.run(
        ["node", str(main)],
        cwd=directory,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )


class ScanRun:
    def __init__(self):
        self.executed: list[str] = []
        self.markers: list[str] = []
        self.resolved: list[tuple[str, str, str | None]] = []


def run_workflow(
    workflow_path: Path,
    mirror: ActionMirror,
    api: IssueApi,
    event_name: str,
    event: dict,
    findings: bool,
    workspace: Path,
) -> ScanRun:
    workflow = _workflow_map(workflow_path)
    result = ScanRun()
    workspace.mkdir(parents=True, exist_ok=True)
    if findings:
        (workspace / "ash-output.log").write_text(
            "Actionable findings detected!\n"
        )

    # PrepareActionsAsync resolves every repository action before any step runs.
    prepared: dict[tuple[str, str], str | None] = {}
    for job in workflow["jobs"].values():
        for step in job.get("steps") or []:
            uses = step.get("uses")
            if not uses:
                continue
            name, ref = _split_uses(uses)
            prepared[(name, ref)] = mirror.resolve(name, ref)

    for job_name, job in workflow["jobs"].items():
        permissions = _permissions(workflow, job)
        token = f"{JOB_TOKEN}-{job_name}"
        api.issue(token, permissions)
        context = {
            "job_status": "success",
            "github": {
                "event_name": event_name,
                "event": event,
                "repository": f"{OWNER}/{REPO}",
                "repository_owner": OWNER,
                "api_url": api.base_url,
                "workspace": str(workspace),
            },
            "steps": {},
        }
        if not _condition_passes(job.get("if"), context):
            continue
        for index, step in enumerate(job.get("steps") or []):
            step_id = step.get("id") or f"step-{index}"
            if not _condition_passes(step.get("if"), context):
                continue
            if "run" in step:
                # The scan install and the scanner itself are not the token path.
                # The shell that records step outputs is: the issue step's if reads it.
                if "GITHUB_OUTPUT" in step["run"]:
                    _run_shell(step, workspace, context, step_id)
                continue
            uses = step.get("uses")
            if not uses:
                continue
            name, ref = _split_uses(uses)
            commit = prepared[(name, ref)]
            result.resolved.append((name, ref, commit))
            if commit is None:
                continue
            action_dir = workspace / "actions" / str(index)
            _materialize(mirror, name, commit, action_dir)
            manifest = _load_action(mirror, name, commit)
            inputs = {}
            for key, value in (step.get("with") or {}).items():
                inputs[str(key)] = _evaluate_template(str(value), token)
            for key, spec in (manifest.get("inputs") or {}).items():
                if key in inputs:
                    continue
                default = spec.get("default") if isinstance(spec, dict) else None
                if default is None:
                    continue
                inputs[key] = _evaluate_template(str(default), token)
            environment = os.environ.copy()
            environment.update(_context_environment(context["github"]))
            environment.update(_input_environment(inputs))
            environment.pop("GITHUB_TOKEN", None)
            _run_node_action(action_dir, environment)
            result.executed.append(f"{job_name}:{uses}")
            if (action_dir / "moved-tag-ran").exists():
                result.markers.append(f"{job_name}:{uses}")
            if step.get("continue-on-error"):
                continue
    return result


def _run_shell(step: dict, workspace: Path, context: dict, step_id: str) -> None:
    output = workspace / f"{step_id}.output"
    output.write_text("")
    env = os.environ.copy()
    env["GITHUB_OUTPUT"] = str(output)
    for key, value in (step.get("env") or {}).items():
        env[key] = _shell_template(str(value), context)
    completed = subprocess.run(
        ["bash", "-c", step["run"]],
        cwd=workspace,
        env=env,
        check=False,
        capture_output=True,
        text=True,
        timeout=15,
    )
    outputs = {}
    for line in output.read_text().splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        outputs[key] = value
    context["steps"][step_id] = {"outputs": outputs}
    if completed.returncode != 0 and not step.get("continue-on-error"):
        context["job_status"] = "failure"


def _shell_template(value: str, context: dict) -> str:
    def replace(match: re.Match) -> str:
        expression = match.group(1).strip()
        if expression == "github.event_name":
            return context["github"]["event_name"]
        if expression == "github.sha":
            return "0" * 40
        if expression == "github.actor":
            return "example-actor"
        raise AssertionError(f"unexpected shell expression {expression}")

    return re.sub(r"\$\{\{\s*([^}]+?)\s*\}\}", replace, value)


def _seed(mirror: ActionMirror, name: str, ref: str) -> str:
    if FULL_SHA.fullmatch(ref):
        return ref
    commit = mirror.commit_files(name, BENIGN_ACTION, f"benign {ref}")
    mirror.point_tag(name, ref, commit)
    return commit


def _move(mirror: ActionMirror, name: str, ref: str) -> str:
    commit = mirror.commit_files(name, MALICIOUS_ACTION, f"moved {ref}")
    mirror.point_tag(name, ref, commit)
    return commit


def _mutable_uses(workflow_path: Path) -> list[tuple[str, str]]:
    workflow = _workflow_map(workflow_path)
    found = []
    for job in workflow["jobs"].values():
        for step in job.get("steps") or []:
            uses = step.get("uses")
            if not uses:
                continue
            name, ref = _split_uses(uses)
            if not FULL_SHA.fullmatch(ref):
                found.append((name, ref))
    return found


@pytest.fixture
def api():
    server = IssueApi()
    try:
        yield server
    finally:
        server.close()


def test_scheduled_scan_with_findings_does_not_run_a_moved_github_script_tag(
    tmp_path: Path, api: IssueApi
):
    mirror = ActionMirror(tmp_path / "actions")
    benign = _seed(mirror, "actions/github-script", "v9")
    for name, ref in _mutable_uses(SCAN_WORKFLOW):
        if (name, ref) != ("actions/github-script", "v9"):
            _seed(mirror, name, ref)
    # A lookup made before the job prepares must not be the commit that runs.
    early = mirror.resolve("actions/github-script", "v9")
    assert early == benign
    moved = _move(mirror, "actions/github-script", "v9")
    assert moved != early

    result = run_workflow(
        SCAN_WORKFLOW,
        mirror,
        api,
        event_name="schedule",
        event={},
        findings=True,
        workspace=tmp_path / "work",
    )

    assert result.markers == []
    assert api.changed() is False
    assert api.issues == {}


def test_movable_siblings_in_the_issues_job_cannot_create_or_edit_issues(
    tmp_path: Path, api: IssueApi
):
    mirror = ActionMirror(tmp_path / "actions")
    siblings = [
        item
        for item in _mutable_uses(SCAN_WORKFLOW)
        if item != ("actions/github-script", "v9")
    ]
    _seed(mirror, "actions/github-script", "v9")
    for name, ref in siblings:
        _seed(mirror, name, ref)
        _move(mirror, name, ref)

    # Push runs the checkout, setup, and upload steps. The issue step's if is false.
    result = run_workflow(
        SCAN_WORKFLOW,
        mirror,
        api,
        event_name="push",
        event={},
        findings=True,
        workspace=tmp_path / "work",
    )

    assert result.markers == []
    assert api.changed() is False


def test_schedule_without_findings_skips_the_issue_step(tmp_path: Path, api: IssueApi):
    mirror = ActionMirror(tmp_path / "actions")
    for name, ref in _mutable_uses(SCAN_WORKFLOW):
        _seed(mirror, name, ref)
    _move(mirror, "actions/github-script", "v9")

    result = run_workflow(
        SCAN_WORKFLOW,
        mirror,
        api,
        event_name="schedule",
        event={},
        findings=False,
        workspace=tmp_path / "work",
    )

    assert "full-scan:actions/github-script@v9" not in result.executed
    assert result.markers == []
    assert api.changed() is False


def test_manual_dispatch_does_not_run_the_issue_step(tmp_path: Path, api: IssueApi):
    mirror = ActionMirror(tmp_path / "actions")
    for name, ref in _mutable_uses(SCAN_WORKFLOW):
        _seed(mirror, name, ref)
    _move(mirror, "actions/github-script", "v9")

    result = run_workflow(
        SCAN_WORKFLOW,
        mirror,
        api,
        event_name="workflow_dispatch",
        event={},
        findings=True,
        workspace=tmp_path / "work",
    )

    assert "full-scan:actions/github-script@v9" not in result.executed
    assert all("github-script" not in marker for marker in result.markers)
    assert api.changed() is False


def test_comment_workflow_moved_tag_cannot_open_or_edit_issues(
    tmp_path: Path, api: IssueApi
):
    mirror = ActionMirror(tmp_path / "actions")
    for name, ref in _mutable_uses(COMMENT_WORKFLOW):
        _seed(mirror, name, ref)
        _move(mirror, name, ref)
    results = tmp_path / "ash-results"
    # The comment step's shell reads these paths. Point them at the workspace
    # by running after the files exist at the location the script names.
    os.makedirs("/tmp/ash-results", exist_ok=True)
    number_file = Path("/tmp/ash-results/pr_number.txt")
    sha_file = Path("/tmp/ash-results/pr_sha.txt")
    number_file.write_text("42\n")
    sha_file.write_text("abc1234\n")
    try:
        result = run_workflow(
            COMMENT_WORKFLOW,
            mirror,
            api,
            event_name="workflow_run",
            event={"workflow_run": {"event": "pull_request"}},
            findings=False,
            workspace=tmp_path / "work",
        )
    finally:
        number_file.unlink(missing_ok=True)
        sha_file.unlink(missing_ok=True)

    assert api.changed() is False
    movable = [
        ref
        for name, ref in _mutable_uses(COMMENT_WORKFLOW)
        if name == "actions/github-script"
    ]
    if movable:
        assert {attempt["method"] for attempt in api.attempts} >= {"POST", "PATCH"}
        assert any(
            attempt["authorization"] == f"token {JOB_TOKEN}-comment"
            for attempt in api.attempts
        )
