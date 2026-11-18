"""Spec for movable GitHub Action tags in this repository's workflows.

The runner parses ``uses: org/repo@ref`` by splitting on ``@`` and sends that
ref, unchanged, to the service that returns the tarball for the current
target of the ref (actions/runner v2.338.2,
``PipelineTemplateConverter.cs`` around the ``uses.Value.Split('@')`` parse,
and ``ActionManager.GetDownloadInfoAsync``). A 40-character commit id is the
commit; a tag is whatever commit the tag points at when the job resolves it.
The service result is what gets extracted and run. These tests re-resolve the
ref at execution time, after the tag has moved, so a check that only records
the tag's previous commit does not hide the commit that actually runs.

Action input defaults are evaluated with the ``github`` context, which
includes ``token`` (``action_yaml.json`` definition ``input-default-context``,
``ActionRunner`` merging defaults, ``ExecutionContext`` assigning
``github.token`` from ``system.github.token``). ``token`` is not copied into
the process environment (``GitHubContext`` allowlist). The composite step's
``env`` block is, and that block reads ``inputs.token``.

``permissions.contents: read`` is the job token's contents grant. The local
contents endpoint implements ``GET /repos/{owner}/{repo}/contents/{path}``
with ``Authorization: Bearer`` and returns the documented ``content`` string.
The moved tag's action reads that body before the ruff step runs.
"""

from __future__ import annotations

import base64
import json
import os
import re
import shutil
import subprocess
import textwrap
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = REPO_ROOT / ".github" / "workflows"
JOB_TOKEN = "JOB_TOKEN_PLACEHOLDER"
SOURCE_PATH = "pkg/sample.py"
SOURCE_TEXT = "REVIEW_SOURCE_SENTINEL = 'source-under-lint'\n"
REPOSITORY = "nkp-gfg/sample-agentcore-enterprise-platform"
FULL_SHA = re.compile(r"^[0-9a-f]{40}$")
# Status letters from tj-actions/changed-files ChangeTypeEnum at
# 9426d40962ed5378910ee2e21d5f8c6fcbf2dd96.
ACMR = ("A", "C", "M", "R")


def _git(repo: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", "-C", str(repo), "-c", "user.name=action-test", "-c", "user.email=action-test@example.com", *args],
        check=check,
        capture_output=True,
        text=True,
    )


def _parse_uses(uses: str) -> dict[str, str] | None:
    """Match PipelineTemplateConverter's repository-uses parse."""
    if uses.startswith("docker://") or uses.startswith("./") or uses.startswith(".\\"):
        return None
    segments = uses.split("@")
    path_segments = [part for part in re.split(r"[/\\]", segments[0]) if part]
    git_ref = segments[1] if len(segments) == 2 else ""
    if len(segments) != 2 or len(path_segments) < 2 or not path_segments[0] or not path_segments[1] or not git_ref:
        raise AssertionError(f"Expected org/repo[/path]@ref, got {uses!r}")
    return {
        "name": f"{path_segments[0]}/{path_segments[1]}",
        "path": "/".join(path_segments[2:]),
        "ref": git_ref,
    }


def _workflow_files() -> list[Path]:
    return sorted(WORKFLOWS.glob("*.yml"))


def _load_workflow(path: Path) -> dict:
    # PyYAML's default resolver treats the workflow key "on" as a boolean.
    class Loader(yaml.SafeLoader):
        pass

    Loader.yaml_implicit_resolvers = {
        key: [(tag, pattern) for tag, pattern in values if tag != "tag:yaml.org,2002:bool"]
        for key, values in yaml.SafeLoader.yaml_implicit_resolvers.items()
    }
    loaded = yaml.load(path.read_text(), Loader=Loader)
    if not isinstance(loaded, dict):
        raise AssertionError(f"{path} did not parse as a workflow mapping")
    return loaded


def _job_permissions(workflow: dict, job: dict) -> dict[str, str]:
    # A job-level permissions map replaces the workflow map for that job.
    permissions = job.get("permissions", workflow.get("permissions")) or {}
    return {str(key): str(value) for key, value in permissions.items()}


def _steps(job: dict) -> list[dict]:
    return list(job.get("steps") or [])


def _condition_text(step: dict) -> str:
    raw = step.get("if")
    if raw is None:
        return "success()"
    text = str(raw).strip()
    if text.startswith("${{") and text.endswith("}}"):
        text = text[3:-2].strip()
    if not any(name + "(" in text for name in ("always", "success", "failure", "cancelled")):
        return f"success() && ({text})"
    return text


def _condition_true(expression: str, outputs: dict[str, dict[str, str]], event_name: str) -> bool:
    expression = expression.strip()
    if expression in {"success()", "always()"}:
        return True
    if expression.startswith("success() &&"):
        return _condition_true(expression[len("success() &&") :].strip().strip("()"), outputs, event_name)
    if "&&" in expression:
        return all(_condition_true(part, outputs, event_name) for part in expression.split("&&"))
    if "||" in expression:
        return any(_condition_true(part, outputs, event_name) for part in expression.split("||"))
    compared = re.fullmatch(
        r"steps\.([A-Za-z0-9_-]+)\.outputs\.([A-Za-z0-9_-]+)\s*==\s*'([^']*)'",
        expression,
    )
    if compared:
        step_id, name, expected = compared.groups()
        return outputs.get(step_id, {}).get(name) == expected
    event = re.fullmatch(r"github\.event_name\s*==\s*'([^']*)'", expression)
    if event:
        return event_name == event.group(1)
    present = re.fullmatch(r"steps\.([A-Za-z0-9_-]+)\.outputs\.([A-Za-z0-9_-]+)", expression)
    if present:
        step_id, name = present.groups()
        return bool(outputs.get(step_id, {}).get(name))
    return True


def _evaluate(value: str, contexts: dict) -> str:
    def replace(match: re.Match[str]) -> str:
        cursor = contexts
        for part in match.group(1).strip().split("."):
            if not isinstance(cursor, dict) or part not in cursor:
                raise KeyError(match.group(1))
            cursor = cursor[part]
        return str(cursor)

    return re.sub(r"\$\{\{\s*([^}]+?)\s*\}\}", replace, value)


class _ContentsAPI(BaseHTTPRequestHandler):
    """Stand-in for GET /repos/{owner}/{repo}/contents/{path}."""

    repository_text = SOURCE_TEXT
    permissions: dict[str, str] = {"contents": "read"}
    seen_bearer: list[bool]

    def log_message(self, fmt: str, *args) -> None:
        return

    def do_GET(self) -> None:  # noqa: N802
        expected = f"/repos/{REPOSITORY}/contents/{SOURCE_PATH}"
        if self.path.split("?", 1)[0] != expected:
            self.send_error(404)
            return
        authorization = self.headers.get("Authorization", "")
        token_ok = authorization == f"Bearer {JOB_TOKEN}"
        self.seen_bearer.append(token_ok)
        if not token_ok or self.permissions.get("contents") != "read":
            self.send_error(403)
            return
        encoded = base64.b64encode(self.repository_text.encode()).decode()
        body = json.dumps(
            {
                "type": "file",
                "encoding": "base64",
                "size": len(self.repository_text.encode()),
                "name": Path(SOURCE_PATH).name,
                "path": SOURCE_PATH,
                "content": encoded,
            }
        ).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@pytest.fixture(scope="module")
def contents_api() -> str:
    _ContentsAPI.seen_bearer = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), _ContentsAPI)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()


def _micromatch(paths: list[str], patterns: list[str]) -> list[str]:
    """Call micromatch 4 with the options getFilteredChangedFiles passes."""
    if not patterns:
        return list(paths)
    install = Path("/tmp/mm/node_modules/micromatch")
    if not install.exists():
        subprocess.run(
            ["npm", "install", "--prefix", "/tmp/mm", "micromatch@4.0.8", "--silent"],
            check=True,
            capture_output=True,
            text=True,
        )
    script = (
        "const m=require('micromatch');"
        "const paths=JSON.parse(process.argv[1]);"
        "const patterns=JSON.parse(process.argv[2]);"
        "process.stdout.write(JSON.stringify(m(paths, patterns, {dot:true, windows:false, noext:true})));"
    )
    completed = subprocess.run(
        ["node", "-e", script, json.dumps(paths), json.dumps(patterns)],
        check=True,
        capture_output=True,
        text=True,
        env={**os.environ, "NODE_PATH": "/tmp/mm/node_modules"},
    )
    return json.loads(completed.stdout)


def _any_changed(repo: Path, base: str, head: str, files_input: str) -> str:
    """Reproduce changed-files any_changed for a pull_request three-dot diff.

    previous SHA is pull_request.base.sha, diff is ``...``, and any_changed is
    the string form of whether the ACMR paths that survive the ``files``
    micromatch are non-empty. Deleted paths are not part of that set.
    """
    diff = _git(
        repo,
        "diff",
        "--name-status",
        "--ignore-submodules=all",
        "--diff-filter=ACDMRTUX",
        f"{base}...{head}",
    )
    buckets: dict[str, list[str]] = {letter: [] for letter in "ACDMRTUX"}
    for line in diff.stdout.splitlines():
        if not line.strip():
            continue
        change_type, *paths = line.split("\t")
        if change_type.startswith("R"):
            buckets["R"].append(paths[-1])
        else:
            buckets.setdefault(change_type, []).append(paths[0])
    patterns = [item for item in files_input.split("\n") if item]
    filtered: list[str] = []
    for letter in ACMR:
        filtered.extend(_micromatch(buckets.get(letter, []), patterns))
    joined = " ".join(dict.fromkeys(path for path in filtered if path))
    value = joined.strip() != "" and len(joined) > 0
    return str(value).lower()


def _init_action_repo(tmp: Path) -> tuple[Path, str, str]:
    repo = tmp / "action"
    repo.mkdir(parents=True)
    _git(repo, "init", "-q", "-b", "main")
    (repo / "action.yml").write_text(
        "name: pinned\nruns:\n  using: composite\n  steps:\n    - shell: bash\n      run: echo pinned-action\n"
    )
    _git(repo, "add", "action.yml")
    _git(repo, "commit", "-q", "-m", "good")
    good_sha = _git(repo, "rev-parse", "HEAD").stdout.strip()

    read_source = textwrap.dedent(
        """\
        import base64, json, os, urllib.request
        token = os.environ["TOKEN"]
        url = (
            os.environ["GITHUB_API_URL"].rstrip("/")
            + "/repos/"
            + os.environ["GITHUB_REPOSITORY"]
            + "/contents/"""
        + SOURCE_PATH
        + """"
        )
        request = urllib.request.Request(
            url,
            headers={
                "Authorization": "Bearer " + token,
                "Accept": "application/vnd.github.object+json",
            },
        )
        with urllib.request.urlopen(request) as response:
            body = json.loads(response.read().decode())
        print(base64.b64decode(body["content"]).decode(), end="")
        """
    )
    (repo / "action.yml").write_text(
        textwrap.dedent(
            """\
            name: moved
            inputs:
              token:
                description: job token
                default: ${{ github.token }}
            runs:
              using: composite
              steps:
                - shell: bash
                  env:
                    TOKEN: ${{ inputs.token }}
                  run: python3 "$GITHUB_ACTION_PATH/read_source.py"
            """
        )
    )
    (repo / "read_source.py").write_text(read_source)
    _git(repo, "add", "action.yml", "read_source.py")
    _git(repo, "commit", "-q", "-m", "evil")
    evil_sha = _git(repo, "rev-parse", "HEAD").stdout.strip()
    assert good_sha != evil_sha
    return repo, good_sha, evil_sha


def _set_tags(repo: Path, sha: str, names: set[str]) -> None:
    for name in sorted(names):
        _git(repo, "tag", "-f", name, sha)


def _resolve(repo: Path, ref: str) -> str:
    """Resolve a uses ref the way a tag move can change and a commit id cannot."""
    if FULL_SHA.fullmatch(ref):
        return ref
    resolved = _git(repo, "rev-parse", "--verify", f"refs/tags/{ref}^{{commit}}")
    return resolved.stdout.strip()


def _run_action(
    repo: Path,
    sha: str,
    evil_sha: str,
    api: str,
    workflow_with: dict | None,
) -> str:
    if sha != evil_sha:
        return ""
    destination = repo.parent / f"extract-{sha[:8]}"
    if destination.exists():
        shutil.rmtree(destination)
    destination.mkdir()
    archive = subprocess.run(
        ["git", "-C", str(repo), "archive", sha],
        check=True,
        capture_output=True,
    )
    subprocess.run(["tar", "-x", "-C", str(destination)], input=archive.stdout, check=True)
    manifest = yaml.safe_load((destination / "action.yml").read_text())
    contexts = {
        "github": {"token": JOB_TOKEN},
        "secrets": {"GITHUB_TOKEN": JOB_TOKEN},
        "inputs": {},
    }
    provided = {str(key): str(value) for key, value in (workflow_with or {}).items()}
    inputs: dict[str, str] = {}
    for name, spec in (manifest.get("inputs") or {}).items():
        if name in provided:
            inputs[name] = _evaluate(provided[name], contexts)
        else:
            default = "" if not isinstance(spec, dict) else str(spec.get("default") or "")
            inputs[name] = _evaluate(default, contexts) if default else ""
    contexts["inputs"] = inputs
    stdout: list[str] = []
    for step in manifest["runs"]["steps"]:
        if "run" not in step:
            continue
        env = os.environ.copy()
        env["GITHUB_API_URL"] = api
        env["GITHUB_REPOSITORY"] = REPOSITORY
        env["GITHUB_ACTION_PATH"] = str(destination)
        for key, value in inputs.items():
            env[f"INPUT_{key.replace(' ', '_').upper()}"] = value
        for key, value in (step.get("env") or {}).items():
            env[str(key)] = _evaluate(str(value), contexts)
        script = destination / "step.sh"
        script.write_text(str(step["run"]))
        completed = subprocess.run(
            ["bash", str(script)],
            cwd=destination,
            env=env,
            capture_output=True,
            text=True,
        )
        stdout.append(completed.stdout)
        if completed.returncode != 0:
            stdout.append(completed.stderr)
    return "".join(stdout)


def _use_after_tag_move(
    repo: Path,
    ref: str,
    good_sha: str,
    evil_sha: str,
    tag_names: set[str],
    api: str,
    workflow_with: dict | None,
) -> tuple[str, str, str]:
    """Look up the ref, move every tag, then look it up again and run that tree."""
    movable = {ref} if not FULL_SHA.fullmatch(ref) else set()
    _set_tags(repo, good_sha, tag_names | movable)
    checked = _resolve(repo, ref)
    _set_tags(repo, evil_sha, tag_names | movable)
    used = _resolve(repo, ref)
    output = _run_action(repo, used, evil_sha, api, workflow_with)
    return checked, used, output


def _product_repo(tmp: Path) -> tuple[Path, str, str]:
    repo = tmp / "product"
    repo.mkdir(parents=True)
    _git(repo, "init", "-q", "-b", "main")
    (repo / "README").write_text("base\n")
    _git(repo, "add", "README")
    _git(repo, "commit", "-q", "-m", "base")
    base = _git(repo, "rev-parse", "HEAD").stdout.strip()
    _git(repo, "checkout", "-q", "-b", "pr")
    package = repo / "pkg"
    package.mkdir()
    (package / "sample.py").write_text(SOURCE_TEXT)
    _git(repo, "add", "pkg/sample.py")
    _git(repo, "commit", "-q", "-m", "change python")
    _git(repo, "checkout", "-q", "main")
    _git(repo, "merge", "--no-ff", "-q", "-m", "merge pr", "pr")
    head = _git(repo, "rev-parse", "HEAD").stdout.strip()
    return repo, base, head


def test_sha_pin_does_not_execute_tag_after_it_moves(tmp_path: Path, contents_api: str) -> None:
    repo, good_sha, evil_sha = _init_action_repo(tmp_path)
    before = len(_ContentsAPI.seen_bearer)
    checked, used, output = _use_after_tag_move(
        repo,
        good_sha,
        good_sha,
        evil_sha,
        {"v7"},
        contents_api,
        None,
    )
    assert checked == good_sha
    assert used == good_sha
    assert _resolve(repo, "v7") == evil_sha
    assert SOURCE_TEXT not in output
    assert _ContentsAPI.seen_bearer[before:] == []


def test_python_lint_moved_tag_cannot_read_source_before_ruff(tmp_path: Path, contents_api: str) -> None:
    workflow_path = WORKFLOWS / "python-lint.yml"
    workflow = _load_workflow(workflow_path)
    assert "pull_request" in workflow["on"]
    assert "main" in workflow["on"]["pull_request"]["branches"]
    job = workflow["jobs"]["python-lint"]
    permissions = _job_permissions(workflow, job)
    _ContentsAPI.permissions = permissions
    _ContentsAPI.seen_bearer = []

    steps = _steps(job)
    names = [step.get("name") or step.get("uses") for step in steps]
    checkout_at = next(i for i, step in enumerate(steps) if str(step.get("uses", "")).startswith("actions/checkout@"))
    setup_at = next(i for i, step in enumerate(steps) if str(step.get("uses", "")).startswith("actions/setup-python@"))
    ruff_at = next(i for i, step in enumerate(steps) if "ruff check" in str(step.get("run", "")))
    assert checkout_at < ruff_at
    assert setup_at < ruff_at
    assert names[checkout_at] == "Checkout code"

    product, base, head = _product_repo(tmp_path / "py")
    changed = next(step for step in steps if step.get("id") == "changed-files")
    files_input = str(changed["with"]["files"])
    any_changed = _any_changed(product, base, head, files_input)
    assert any_changed == "true"
    outputs = {"changed-files": {"any_changed": any_changed}}

    action_repo, good_sha, evil_sha = _init_action_repo(tmp_path / "actions")
    tag_names = {"v7"}
    leaks: list[str] = []
    ruff_started = False
    for index, step in enumerate(steps):
        if index == ruff_at:
            ruff_started = True
            break
        uses = step.get("uses")
        if not uses:
            continue
        if not _condition_true(_condition_text(step), outputs, "pull_request"):
            continue
        parsed = _parse_uses(str(uses))
        assert parsed is not None
        _checked, used, output = _use_after_tag_move(
            action_repo,
            parsed["ref"],
            good_sha,
            evil_sha,
            tag_names,
            contents_api,
            step.get("with"),
        )
        if SOURCE_TEXT in output or used == evil_sha:
            read = "read the repository" if SOURCE_TEXT in output else "ran the moved tag"
            leaks.append(
                f"{workflow_path.name}:{parsed['name']}@{parsed['ref']} {read} as {used} before ruff"
            )
    assert ruff_started
    assert leaks == []


def test_non_python_change_still_checks_out_with_a_stable_ref(tmp_path: Path, contents_api: str) -> None:
    workflow = _load_workflow(WORKFLOWS / "python-lint.yml")
    job = workflow["jobs"]["python-lint"]
    _ContentsAPI.permissions = _job_permissions(workflow, job)
    product = tmp_path / "product"
    product.mkdir()
    _git(product, "init", "-q", "-b", "main")
    (product / "README").write_text("base\n")
    _git(product, "add", "README")
    _git(product, "commit", "-q", "-m", "base")
    base = _git(product, "rev-parse", "HEAD").stdout.strip()
    _git(product, "checkout", "-q", "-b", "pr")
    (product / "README").write_text("docs only\n")
    _git(product, "add", "README")
    _git(product, "commit", "-q", "-m", "docs")
    _git(product, "checkout", "-q", "main")
    _git(product, "merge", "--no-ff", "-q", "-m", "merge docs", "pr")
    head = _git(product, "rev-parse", "HEAD").stdout.strip()
    changed = next(step for step in job["steps"] if step.get("id") == "changed-files")
    any_changed = _any_changed(product, base, head, str(changed["with"]["files"]))
    assert any_changed == "false"
    outputs = {"changed-files": {"any_changed": any_changed}}
    action_repo, good_sha, evil_sha = _init_action_repo(tmp_path / "actions")
    leaks: list[str] = []
    for step in job["steps"]:
        uses = step.get("uses")
        if not uses or not _condition_true(_condition_text(step), outputs, "pull_request"):
            continue
        parsed = _parse_uses(str(uses))
        assert parsed is not None
        _checked, used, output = _use_after_tag_move(
            action_repo,
            parsed["ref"],
            good_sha,
            evil_sha,
            {"v7"},
            contents_api,
            step.get("with"),
        )
        if used == evil_sha or SOURCE_TEXT in output:
            leaks.append(f"{parsed['name']}@{parsed['ref']}")
    assert leaks == []


def test_every_workflow_use_stays_on_its_commit_when_tags_move(tmp_path: Path, contents_api: str) -> None:
    action_repo, good_sha, evil_sha = _init_action_repo(tmp_path)
    leaks: list[str] = []
    seen = 0
    for path in _workflow_files():
        workflow = _load_workflow(path)
        for job_name, job in (workflow.get("jobs") or {}).items():
            if not isinstance(job, dict):
                continue
            _ContentsAPI.permissions = _job_permissions(workflow, job)
            for step in _steps(job):
                uses = step.get("uses")
                if not uses:
                    continue
                parsed = _parse_uses(str(uses))
                if parsed is None:
                    continue
                seen += 1
                tag_names = {parsed["ref"]} if not FULL_SHA.fullmatch(parsed["ref"]) else set()
                _checked, used, output = _use_after_tag_move(
                    action_repo,
                    parsed["ref"],
                    good_sha,
                    evil_sha,
                    tag_names or {"unused"},
                    contents_api,
                    step.get("with"),
                )
                if used == evil_sha or SOURCE_TEXT in output:
                    leaks.append(f"{path.name} job {job_name} {parsed['name']}@{parsed['ref']}")
    assert seen > 0
    assert leaks == []
