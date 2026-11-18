"""Movable action tags in the ASH scan workflow.

GitHub's hosted runner (actions/runner v2.338.2) does not execute the text of a
`uses:` line. It sends the ref to the resolve API, downloads the tarball for
the returned commit, unwraps it, and runs that commit's action.yml. A full
40-character commit SHA names a git object. A tag does not: `git update-ref`
changes which commit `rev-parse <tag>^{commit}` returns, and the tarball for
that tag changes with it.

These tests fail while a workflow step names a tag. They pass when every
`uses:` ref is a full commit SHA, because moving a tag then no longer changes
the commit whose action.yml runs.
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import re
import shutil
import subprocess
import textwrap
import zipfile
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = REPO_ROOT / ".github" / "workflows"
FULL_SHA = re.compile(r"^[0-9a-f]{40}$")
# Obvious placeholder. This is not a credential.
JOB_TOKEN = "placeholder-github-token"
REPOSITORY_FILE = "repository-file.txt"
REPOSITORY_BODY = "repository-contents"
HONEST_COMMENT = "## Security Scan Results\n\nhonest-scan\n"
ATTACK_COMMENT = "PWNED\n"
HONEST_PR = "17"
ATTACK_PR = "999"

ALLOWLISTED_GITHUB_ENV = ("workspace", "action_path")


def _git(repo: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env.update(
        {
            "GIT_AUTHOR_NAME": "action-ref-test",
            "GIT_AUTHOR_EMAIL": "action-ref-test@example.com",
            "GIT_COMMITTER_NAME": "action-ref-test",
            "GIT_COMMITTER_EMAIL": "action-ref-test@example.com",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": "/dev/null",
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
    """Resolve a ref the way a git-backed action download resolves it."""
    return _git(repo, "rev-parse", "--verify", f"{ref}^{{commit}}").stdout.strip()


def _init_action_repo(root: Path) -> Path:
    repo = root / "action"
    repo.mkdir()
    _git(repo, "init", "-b", "main")
    return repo


def _commit_action(repo: Path, entry: str, token_env: bool) -> str:
    env_block = "      env:\n        TOKEN: ${{ github.token }}\n" if token_env else ""
    manifest = (
        "name: fixture\n"
        "description: fixture action used to observe which commit runs\n"
        "inputs:\n"
        "  token:\n"
        "    default: ${{ github.token }}\n"
        "  name:\n"
        "    default: ''\n"
        "  path:\n"
        "    default: ''\n"
        "runs:\n"
        "  using: composite\n"
        "  steps:\n"
        "    - shell: bash\n"
        f"{env_block}"
        '      run: bash "$GITHUB_ACTION_PATH/entry.sh"\n'
    )
    (repo / "action.yml").write_text(manifest)
    (repo / "entry.sh").write_text(entry)
    _git(repo, "add", "action.yml", "entry.sh")
    _git(repo, "commit", "-m", "action commit")
    return _rev_parse(repo, "HEAD")


def _honest_entry() -> str:
    return textwrap.dedent(
        """\
        #!/bin/bash
        set -euo pipefail
        printf '%s\\n' honest > "$STEP_PROOF"
        if [ -n "${PUBLISH_HELPER:-}" ]; then
          python3 "$PUBLISH_HELPER" publish --store "$ARTIFACT_STORE" --name "$INPUT_NAME" --path "$INPUT_PATH"
        fi
        """
    )


def _malicious_entry() -> str:
    return textwrap.dedent(
        """\
        #!/bin/bash
        set -euo pipefail
        printf '%s\\n' moved > "$STEP_PROOF"
        if [ -n "${GITHUB_WORKSPACE:-}" ] && [ -f "$GITHUB_WORKSPACE/repository-file.txt" ]; then
          cat "$GITHUB_WORKSPACE/repository-file.txt" > "$STEP_PROOF.read"
        fi
        if [ -n "${TOKEN:-}" ]; then
          printf '%s' "$TOKEN" > "$STEP_PROOF.token"
        fi
        if [ -n "${PUBLISH_HELPER:-}" ]; then
          evil="$(mktemp -d)"
          printf '%s\\n' "999" > "$evil/pr_number.txt"
          printf '%s\\n' "deadbeefdeadbeef" > "$evil/pr_sha.txt"
          printf '%s\\n' "PWNED" > "$evil/pr_comment.md"
          python3 "$PUBLISH_HELPER" publish --store "$ARTIFACT_STORE" --name "$INPUT_NAME" --path "$evil"
        fi
        """
    )


def _move_tag(repo: Path, tag: str, sha: str) -> None:
    _git(repo, "update-ref", f"refs/tags/{tag}", sha)


def build_moved_tag_repo(root: Path, tag: str = "v7") -> tuple[Path, str, str]:
    """Commit an honest action, tag it, then move that tag onto a second commit."""
    repo = _init_action_repo(root)
    honest = _commit_action(repo, _honest_entry(), token_env=False)
    _move_tag(repo, tag, honest)
    malicious = _commit_action(repo, _malicious_entry(), token_env=True)
    _move_tag(repo, tag, malicious)
    assert _rev_parse(repo, tag) == malicious
    assert _rev_parse(repo, honest) == honest
    assert honest != malicious
    return repo, honest, malicious


def extract_action(repo: Path, sha: str, dest: Path) -> Path:
    """Unpack one commit the way ActionManager downloads an action tarball.

    The runner downloads the archive for ResolvedSha, requires exactly one
    top-level directory, and loads action.yml from the unwrapped directory.
    """
    staging = dest / "staging"
    staging.mkdir(parents=True)
    archive = dest / "action.tar"
    _git(repo, "archive", "--format=tar", f"--prefix=action-{sha[:12]}/", "-o", str(archive), sha)
    subprocess.run(["tar", "-xf", str(archive), "-C", str(staging)], check=True)
    directories = [path for path in staging.iterdir() if path.is_dir()]
    assert len(directories) == 1, directories
    return directories[0]


def _eval_expr(value: str, github: dict[str, str], inputs: dict[str, str]) -> str:
    def replace(match: re.Match[str]) -> str:
        expression = match.group(1).strip()
        if expression.startswith("github."):
            return github[expression.split(".", 1)[1]]
        if expression.startswith("inputs."):
            return inputs[expression.split(".", 1)[1]]
        raise AssertionError(f"expression not handled by this harness: {expression}")

    return re.sub(r"\$\{\{\s*(.*?)\s*\}\}", replace, value)


def _step_inputs(manifest: dict, step_with: dict | None, github: dict[str, str]) -> dict[str, str]:
    """User `with` values win. Missing inputs take the action.yml default.

    Defaults are evaluated against the job's github context, including token.
    """
    resolved: dict[str, str] = {}
    for name, spec in (manifest.get("inputs") or {}).items():
        default = "" if not isinstance(spec, dict) else spec.get("default", "")
        if isinstance(default, bool):
            default = "true" if default else "false"
        resolved[name] = _eval_expr(str(default), github, resolved)
    for key, value in (step_with or {}).items():
        resolved[str(key)] = _eval_expr(str(value), github, resolved)
    return resolved


def run_extracted_action(
    action_dir: Path,
    *,
    workspace: Path,
    proof: Path,
    step_with: dict | None = None,
    extra_env: dict[str, str] | None = None,
) -> None:
    manifest = yaml.safe_load((action_dir / "action.yml").read_text())
    runs = manifest["runs"]
    assert runs["using"] == "composite"
    github = {
        "token": JOB_TOKEN,
        "workspace": str(workspace),
        "action_path": str(action_dir),
    }
    inputs = _step_inputs(manifest, step_with, github)
    for step in runs["steps"]:
        env = os.environ.copy()
        for secret_name in ("GITHUB_TOKEN", "GH_TOKEN", "ACTIONS_RUNTIME_TOKEN"):
            env.pop(secret_name, None)
        for key in ALLOWLISTED_GITHUB_ENV:
            env[f"GITHUB_{key.upper()}"] = github[key]
        env["STEP_PROOF"] = str(proof)
        for key, value in inputs.items():
            env[f"INPUT_{key.replace(' ', '_').upper()}"] = value
        if extra_env:
            env.update(extra_env)
        for key, value in (step.get("env") or {}).items():
            env[str(key)] = _eval_expr(str(value), github, inputs)
        script = _eval_expr(str(step["run"]), github, inputs)
        completed = subprocess.run(
            ["bash", "-euo", "pipefail", "-c", script],
            check=False,
            capture_output=True,
            text=True,
            env=env,
            cwd=str(workspace),
        )
        assert completed.returncode == 0, completed.stderr


def commit_selected_by(workflow_ref: str, repo: Path, honest: str, malicious: str, tag: str) -> str:
    """Return the commit the runner would execute for this uses ref.

    A 40-hex ref is the commit object. Moving `tag` does not change
    `rev-parse <sha>^{commit}`. Any other ref is the tag, which now points at
    the second commit.
    """
    if FULL_SHA.fullmatch(workflow_ref):
        assert _rev_parse(repo, honest) == honest
        assert _rev_parse(repo, tag) == malicious
        return honest
    resolved = _rev_parse(repo, workflow_ref)
    assert resolved == malicious
    return resolved


def _workflow_uses() -> list[tuple[str, int, str]]:
    found: list[tuple[str, int, str]] = []
    for path in sorted(WORKFLOWS.glob("*.yml")):
        relative = path.relative_to(REPO_ROOT).as_posix()
        for number, line in enumerate(path.read_text().splitlines(), 1):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            match = re.search(r"uses:\s*([^#\s]+)", line)
            if match:
                found.append((relative, number, match.group(1)))
    return found


def _split_uses(uses: str) -> tuple[str, str]:
    name, ref = uses.rsplit("@", 1)
    return name, ref


def _load_workflow(name: str) -> dict:
    loaded = yaml.safe_load((WORKFLOWS / name).read_text())
    # PyYAML 1.1 parses the workflow key `on` as boolean true.
    if True in loaded and "on" not in loaded:
        loaded["on"] = loaded.pop(True)
    return loaded


def _jobs(workflow: dict) -> list[dict]:
    return list((workflow.get("jobs") or {}).values())


def _steps(workflow: dict) -> list[dict]:
    steps: list[dict] = []
    for job in _jobs(workflow):
        steps.extend(job.get("steps") or [])
    return steps


def _find_step(workflow: dict, action: str) -> dict | None:
    prefix = f"{action}@"
    for step in _steps(workflow):
        uses = str(step.get("uses") or "")
        if uses.startswith(prefix):
            return step
    return None


def _condition_holds(expression, any_changed: bool) -> bool:
    if expression is None:
        return True
    text = str(expression).strip()
    text = text.replace(
        "steps.changed-files.outputs.any_changed",
        "'true'" if any_changed else "'false'",
    )
    text = text.replace("always()", "True")
    text = text.replace("&&", " and ").replace("||", " or ")
    if not re.fullmatch(r"[A-Za-z0-9_'\"=() \t.!-]+", text):
        raise AssertionError(f"unrecognized step if: {expression}")
    return bool(eval(text, {"__builtins__": {}}, {}))  # noqa: S307


def _run_workflow_step(step: dict, workspace: Path, proof: Path, extra_env: dict[str, str] | None = None) -> None:
    uses = str(step["uses"])
    _name, ref = _split_uses(uses)
    tag = ref if not FULL_SHA.fullmatch(ref) else "v7"
    with __import__("tempfile").TemporaryDirectory() as tmp:
        root = Path(tmp)
        repo, honest, malicious = build_moved_tag_repo(root, tag=tag)
        selected = commit_selected_by(ref, repo, honest, malicious, tag)
        action_dir = extract_action(repo, selected, root / "extracted")
        run_extracted_action(
            action_dir,
            workspace=workspace,
            proof=proof,
            step_with=step.get("with"),
            extra_env=extra_env,
        )


def publish_artifact(store: Path, name: str, source: Path) -> str:
    """Zip the files the action chose and record the digest of that zip.

    upload-artifact sends the files it selected under the artifact name and
    the service stores that blob. download-artifact later compares the
    downloaded blob to the digest stored on that artifact record.
    """
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        files = sorted(path for path in source.rglob("*") if path.is_file())
        for path in files:
            archive.write(path, path.relative_to(source).as_posix())
    blob = buffer.getvalue()
    digest = "sha256:" + hashlib.sha256(blob).hexdigest()
    store.mkdir(parents=True, exist_ok=True)
    (store / f"{name}.json").write_text(json.dumps({"name": name, "blob": blob.hex(), "digest": digest}))
    return digest


def download_artifact(store: Path, name: str, dest: Path) -> str:
    """Extract a stored artifact only when its bytes match the recorded digest."""
    record = json.loads((store / f"{name}.json").read_text())
    blob = bytes.fromhex(record["blob"])
    actual = "sha256:" + hashlib.sha256(blob).hexdigest()
    if actual != record["digest"]:
        raise RuntimeError(f"digest mismatch for {name}")
    dest.mkdir(parents=True, exist_ok=True)
    for child in dest.iterdir():
        if child.is_file():
            child.unlink()
        else:
            shutil.rmtree(child)
    with zipfile.ZipFile(io.BytesIO(blob)) as archive:
        archive.extractall(dest)
    return actual


def _comment_script() -> str:
    workflow = _load_workflow("ash-security-comment.yml")
    for step in _steps(workflow):
        script = ((step.get("with") or {}).get("script"))
        if script:
            return str(script)
    raise AssertionError("comment workflow has no github-script body")


def _post_comment(result_dir: Path) -> list[dict]:
    """Run the comment workflow's script the way github-script wraps it.

    callAsyncFunction builds an AsyncFunction whose parameters are the
    injected names and whose body is the workflow script.
    """
    script_path = result_dir / "script.js"
    wrapper_path = result_dir / "wrapper.js"
    output_path = result_dir / "posted.json"
    script_path.write_text(_comment_script())
    wrapper_path.write_text(
        textwrap.dedent(
            """\
            const fs = require("fs");
            const AsyncFunction = Object.getPrototypeOf(async () => null).constructor;
            const posted = [];
            const github = {
              rest: {
                issues: {
                  listComments: async () => ({ data: [] }),
                  deleteComment: async () => {},
                  updateComment: async (params) => { posted.push(params); },
                  createComment: async (params) => { posted.push(params); },
                },
              },
            };
            const context = { repo: { owner: "example-owner", repo: "example-repo" } };
            const source = fs.readFileSync(process.env.SCRIPT_PATH, "utf8");
            const fn = new AsyncFunction("github", "context", "require", source);
            fn(github, context, require).then(() => {
              fs.writeFileSync(process.env.COMMENT_RESULT, JSON.stringify(posted));
            }).catch((error) => {
              console.error(error);
              process.exit(1);
            });
            """
        )
    )
    completed = subprocess.run(
        ["node", str(wrapper_path)],
        check=False,
        capture_output=True,
        text=True,
        env={
            **os.environ,
            "SCRIPT_PATH": str(script_path),
            "COMMENT_RESULT": str(output_path),
        },
    )
    assert completed.returncode == 0, completed.stderr
    return json.loads(output_path.read_text())


@pytest.mark.parametrize(
    ("relative", "line", "uses"),
    _workflow_uses(),
    ids=[f"{relative}:{line}:{uses}" for relative, line, uses in _workflow_uses()],
)
def test_action_ref_does_not_follow_a_moved_tag(relative: str, line: int, uses: str, tmp_path: Path) -> None:
    """Every workflow `uses` stays on the commit it had before a tag move."""
    _name, ref = _split_uses(uses)
    tag = ref if not FULL_SHA.fullmatch(ref) else "v7"
    _repo, honest, malicious = build_moved_tag_repo(tmp_path, tag=tag)
    selected = commit_selected_by(ref, _repo, honest, malicious, tag)
    action_dir = extract_action(_repo, selected, tmp_path / "extracted")
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    proof = tmp_path / "proof"
    run_extracted_action(action_dir, workspace=workspace, proof=proof)
    marker = proof.read_text().strip()
    assert marker == "honest", (
        f"{relative}:{line} uses {uses}. Moving tag {tag} selected the replacement "
        f"action ({marker}) instead of the commit that was current when the ref was written."
    )


def test_checkout_on_a_pull_request_does_not_run_a_moved_tag(tmp_path: Path) -> None:
    """checkout has no `if`, so a pull request runs it before any changed-file check."""
    workflow = _load_workflow("ash-security-scan.yml")
    assert workflow["on"]["pull_request"]["branches"] == ["main"]
    assert workflow["permissions"]["contents"] == "read"
    step = _find_step(workflow, "actions/checkout")
    assert step is not None
    assert _condition_holds(step.get("if"), any_changed=False)
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    proof = tmp_path / "proof"
    _run_workflow_step(step, workspace, proof)
    assert proof.read_text().strip() == "honest"
    assert not proof.with_suffix(".token").exists()


def test_setup_python_does_not_read_the_workspace_when_its_tag_moves(tmp_path: Path) -> None:
    """A pull request that changes a watched file reaches setup-python."""
    workflow = _load_workflow("ash-security-scan.yml")
    step = _find_step(workflow, "actions/setup-python")
    assert step is not None
    assert _condition_holds(step.get("if"), any_changed=True)
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / REPOSITORY_FILE).write_text(REPOSITORY_BODY)
    proof = tmp_path / "proof"
    _run_workflow_step(step, workspace, proof)
    assert proof.read_text().strip() == "honest"
    assert not proof.with_suffix(".read").exists()
    assert not proof.with_suffix(".token").exists()


def test_moved_upload_tag_cannot_change_the_comment_workflow(tmp_path: Path) -> None:
    """The comment job posts the artifact named by the scan's upload step."""
    scan = _load_workflow("ash-security-scan.yml")
    comment = _load_workflow("ash-security-comment.yml")
    upload = _find_step(scan, "actions/upload-artifact")
    download = _find_step(comment, "actions/download-artifact")
    assert upload is not None and download is not None
    assert _condition_holds(upload.get("if"), any_changed=True)
    assert comment["on"]["workflow_run"]["workflows"] == ["ASH Security Scan"]
    assert comment["permissions"]["pull-requests"] == "write"
    upload_name = str(upload["with"]["name"])
    download_name = str(download["with"]["name"])
    assert upload_name == download_name == "ash-security-results"

    artifacts = tmp_path / "ash-artifacts"
    artifacts.mkdir()
    (artifacts / "pr_number.txt").write_text(HONEST_PR + "\n")
    (artifacts / "pr_sha.txt").write_text("abcdef1234567890\n")
    (artifacts / "pr_comment.md").write_text(HONEST_COMMENT)

    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / REPOSITORY_FILE).write_text(REPOSITORY_BODY)
    proof = tmp_path / "proof"
    store = tmp_path / "artifact-store"
    _run_workflow_step(
        upload,
        workspace,
        proof,
        extra_env={
            "PUBLISH_HELPER": str(Path(__file__).resolve()),
            "ARTIFACT_STORE": str(store),
            "INPUT_PATH": str(artifacts),
        },
    )

    # The comment script reads this path literally. The download step writes it there.
    downloaded = Path(str(download["with"]["path"]))
    assert downloaded.as_posix() == "/tmp/ash-results"
    if downloaded.exists():
        shutil.rmtree(downloaded)
    try:
        digest = download_artifact(store, download_name, downloaded)
        record = json.loads((store / f"{download_name}.json").read_text())
        assert digest == record["digest"]
        posted = _post_comment(tmp_path)
        assert posted, "comment script did not post"
        comment_body = posted[0]["body"]
        assert posted[0]["issue_number"] == int(HONEST_PR)
        assert "honest-scan" in comment_body
        assert "PWNED" not in comment_body
        assert ATTACK_PR not in comment_body
    finally:
        if downloaded.exists():
            shutil.rmtree(downloaded)


def main(argv: list[str]) -> None:
    if len(argv) >= 2 and argv[1] == "publish":
        import argparse

        parser = argparse.ArgumentParser()
        parser.add_argument("publish")
        parser.add_argument("--store", required=True)
        parser.add_argument("--name", required=True)
        parser.add_argument("--path", required=True)
        args = parser.parse_args(argv[1:])
        publish_artifact(Path(args.store), args.name, Path(args.path))
        return
    raise SystemExit("usage: test_movable_action_tags.py publish --store DIR --name NAME --path DIR")


if __name__ == "__main__":
    import sys

    main(sys.argv)
