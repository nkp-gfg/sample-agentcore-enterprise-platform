"""Symlink and size limits for the documentation integrity checker.

The Documentation Integrity workflow checks out a pull request and runs
``python scripts/check_docs.py``. These tests are the contract for that
checker. They fail while a Markdown path, ``docs/_sidebar.md``, or
``docs/index.html`` is read through a symbolic link or past
``MAX_DOCUMENT_BYTES``.

A passing fix must:

- refuse a documentation tree that contains a symbolic link instead of
  following it
- still refuse when the path is a regular file at ``lstat`` time and a
  symbolic link at ``open`` time (``O_NOFOLLOW`` or an equivalent that
  does not look the path up again)
- stop after ``MAX_DOCUMENT_BYTES`` (1 MiB) on every document read below
- report the failure and return. ``main`` must return non-zero. Each
  check function must return a non-empty list of errors, or raise
  ``OSError`` with ``errno.ELOOP``

``MemoryError``, a timeout, or an error that quotes the sentinel
``followed-symlink-must-not-be-read`` means the symlink target was read.

Not covered here, and why:

- ``scripts/check_repository_structure.py`` lists files with
  ``Path.is_file`` before ``read_text``. A symlink to ``/dev/zero`` is
  not a regular file, so that read is not reached for this payload.
- ``scripts/gen_platform_reference.py`` reads fixed generator inputs.
  The pull-request workflow does not run it.
"""

from __future__ import annotations

import errno
import os
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
MARKER = "followed-symlink-must-not-be-read"
MAX_DOCUMENT_BYTES = 1024 * 1024
ADDRESS_SPACE_LIMIT = 256 * 1024 * 1024
RUN_TIMEOUT_SECONDS = 8

REQUIRED_SIDEBAR_LINKS = (
    "home.md",
    "MIGRATION_RUNBOOK.md",
    "PLATFORM_YAML.md?id=migration",
)
REQUIRED_INDEX_SNIPPETS = (
    '"/.*/_sidebar.md": "/_sidebar.md",',
    'const docsBasePath = window.location.pathname.replace(/[^/]*$/, "");',
    "basePath: docsBasePath,",
)


def _run_worker(
    mode: str, repo: Path | None = None
) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["CHECK_DOCS_MODE"] = mode
    if repo is not None:
        env["CHECK_DOCS_REPO"] = str(repo)
    try:
        return subprocess.run(
            [sys.executable, str(Path(__file__).resolve()), mode],
            check=False,
            capture_output=True,
            text=True,
            timeout=RUN_TIMEOUT_SECONDS,
            env=env,
            cwd=REPO,
        )
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout or ""
        stderr = exc.stderr or ""
        if isinstance(stdout, bytes):
            stdout = stdout.decode(errors="replace")
        if isinstance(stderr, bytes):
            stderr = stderr.decode(errors="replace")
        pytest.fail(
            f"{mode} did not finish within {RUN_TIMEOUT_SECONDS}s\n"
            f"stdout:\n{stdout}\nstderr:\n{stderr}"
        )


def _assert_rejected(mode: str, repo: Path | None = None) -> None:
    completed = _run_worker(mode, repo)
    assert completed.returncode == 0, (
        f"{mode} exited {completed.returncode}\n"
        f"stdout:\n{completed.stdout}\nstderr:\n{completed.stderr}"
    )


def _sidebar_text() -> str:
    return "".join(f"[{link}]({link})\n" for link in REQUIRED_SIDEBAR_LINKS)


def _index_text() -> str:
    return (
        "<!doctype html>\n<script>\n"
        + "\n".join(REQUIRED_INDEX_SNIPPETS)
        + "\n</script>\n"
    )


def _write_valid_tree(root: Path) -> Path:
    """A documentation tree the checker accepts, apart from cases under test."""

    docs = root / "docs"
    docs.mkdir(parents=True, exist_ok=True)
    for name in ("home.md", "MIGRATION_RUNBOOK.md", "PLATFORM_YAML.md", "ok.md"):
        (docs / name).write_text(f"# {name}\n", encoding="utf-8")
    (docs / "_sidebar.md").write_text(_sidebar_text(), encoding="utf-8")
    (docs / "_404.md").write_text("# missing\n", encoding="utf-8")
    (docs / "index.html").write_text(_index_text(), encoding="utf-8")
    (docs / "sub").mkdir(exist_ok=True)
    return docs


def _markdown_marker(root: Path) -> Path:
    """Content that shows up in checker errors only when the target is parsed."""

    target = root / "marker-target.md"
    target.write_text(
        f"[leaked]({MARKER})\n[leaked]({MARKER})\n",
        encoding="utf-8",
    )
    return target


def _html_marker(root: Path) -> Path:
    target = root / "marker-target.html"
    target.write_text(
        f'<script src="{MARKER}.js"></script>\n',
        encoding="utf-8",
    )
    return target


def _oversized(payload: str) -> str:
    if len(payload.encode("utf-8")) > MAX_DOCUMENT_BYTES:
        raise RuntimeError("payload already exceeds the document limit")
    extra = MAX_DOCUMENT_BYTES + 1 - len(payload.encode("utf-8"))
    return payload + ("a" * extra)


def test_ordinary_markdown_file_is_accepted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    docs = _write_valid_tree(tmp_path)
    (docs / "sub" / "note.md").write_text("[home](../home.md)\n", encoding="utf-8")
    monkeypatch.syspath_prepend(str(REPO))
    from scripts import check_docs

    monkeypatch.setattr(check_docs, "REPO_ROOT", tmp_path)
    monkeypatch.setattr(check_docs, "DOCS_ROOT", docs)
    errors, _count, links = check_docs.check_markdown_links()
    assert errors == []
    assert links >= 1


def test_markdown_symlink_is_rejected_without_reading_its_target() -> None:
    _assert_rejected("markdown-symlink")


def test_markdown_symlink_swapped_in_before_open_is_rejected() -> None:
    _assert_rejected("markdown-race")


def test_markdown_symlink_to_dev_zero_is_rejected() -> None:
    _assert_rejected("markdown-zero")


def test_sidebar_symlink_is_rejected_without_reading_its_target() -> None:
    _assert_rejected("sidebar-symlink")


def test_sidebar_symlink_swapped_in_before_open_is_rejected() -> None:
    _assert_rejected("sidebar-race")


def test_sidebar_symlink_to_dev_zero_is_rejected() -> None:
    _assert_rejected("sidebar-zero")


def test_index_symlink_is_rejected_without_reading_its_target() -> None:
    _assert_rejected("index-symlink")


def test_index_symlink_swapped_in_before_open_is_rejected() -> None:
    _assert_rejected("index-race")


def test_index_symlink_to_dev_zero_is_rejected() -> None:
    _assert_rejected("index-zero")


def test_markdown_read_stops_at_one_mebibyte() -> None:
    _assert_rejected("byte-markdown")


def test_sidebar_read_stops_at_one_mebibyte() -> None:
    _assert_rejected("byte-sidebar")


def test_index_read_stops_at_one_mebibyte() -> None:
    _assert_rejected("byte-index")


def test_main_rejects_markdown_symlink_to_dev_zero() -> None:
    _assert_rejected("main-zero")


def test_git_checkout_preserves_markdown_symlink_and_checker_rejects_it(
    tmp_path: Path,
) -> None:
    origin = tmp_path / "origin"
    docs = _write_valid_tree(origin)
    os.symlink("/dev/zero", docs / "sub" / "evil.md")
    commit_env = os.environ.copy()
    commit_env.update(
        {
            "GIT_AUTHOR_NAME": "Docs Test",
            "GIT_AUTHOR_EMAIL": "docs-test@example.com",
            "GIT_COMMITTER_NAME": "Docs Test",
            "GIT_COMMITTER_EMAIL": "docs-test@example.com",
        }
    )
    subprocess.run(["git", "init", "-b", "main", str(origin)], check=True, cwd=origin)
    subprocess.run(["git", "add", "docs"], check=True, cwd=origin)
    subprocess.run(
        ["git", "commit", "-m", "add docs symlink"],
        check=True,
        cwd=origin,
        env=commit_env,
    )
    cloned = tmp_path / "clone"
    subprocess.run(["git", "clone", str(origin), str(cloned)], check=True)
    evil = cloned / "docs" / "sub" / "evil.md"
    assert evil.is_symlink()
    assert os.readlink(evil) == "/dev/zero"
    _assert_rejected("main-existing", cloned)


def _install_swap_on_open(victim: Path, link_target: Path) -> None:
    """Replace ``victim`` with a symlink when the checker opens that path.

    The hook runs from Python's ``open`` audit, which is before the
    ``open`` syscall. A check that only ``lstat``s the path, then opens
    it again, follows ``link_target``. An open that uses ``O_NOFOLLOW``
    fails with ``ELOOP`` and never reads ``link_target``.
    """

    victim_name = victim.name
    swapped = False

    def hook(event: str, args: tuple[object, ...]) -> None:
        nonlocal swapped
        if event != "open" or swapped or not args:
            return
        raw = args[0]
        if isinstance(raw, int) or raw is None:
            return
        if isinstance(raw, bytes):
            raw = os.fsdecode(raw)
        if not isinstance(raw, str):
            return
        if os.path.basename(raw) != victim_name:
            return
        swapped = True
        os.unlink(victim)
        os.symlink(link_target, victim)

    sys.addaudithook(hook)


def _call(check: str) -> int:
    from scripts import check_docs

    repo = (
        Path(os.environ["CHECK_DOCS_REPO"])
        if os.environ.get("CHECK_DOCS_REPO")
        else None
    )
    if repo is None:
        raise RuntimeError("CHECK_DOCS_REPO is not set")
    check_docs.REPO_ROOT = repo
    check_docs.DOCS_ROOT = repo / "docs"
    functions = {
        "markdown": check_docs.check_markdown_links,
        "sidebar": check_docs.check_sidebar,
        "index": check_docs.check_site_assets,
        "main": check_docs.main,
    }
    try:
        result = functions[check]()
    except MemoryError:
        print("followed symlink until memory was exhausted", file=sys.stderr)
        return 2
    except OSError as exc:
        if MARKER in str(exc):
            print(f"followed symlink: {exc}", file=sys.stderr)
            return 4
        if exc.errno == errno.ELOOP:
            print("rejected symlink at open", file=sys.stderr)
            return 0
        print(f"unexpected OSError: {exc}", file=sys.stderr)
        return 5
    if check == "main":
        if result == 0:
            print("main accepted the tree", file=sys.stderr)
            return 3
        print(f"main rejected the tree with status {result}", file=sys.stderr)
        return 0
    errors = result[0] if isinstance(result, tuple) else result
    rendered = "\n".join(errors)
    if MARKER in rendered:
        print(rendered, file=sys.stderr)
        return 4
    if not errors:
        print("checker accepted the tree", file=sys.stderr)
        return 3
    print(rendered, file=sys.stderr)
    return 0


def _prepare(mode: str, root: Path) -> str:
    docs = _write_valid_tree(root)
    markdown_marker = _markdown_marker(root)
    html_marker = _html_marker(root)
    if mode == "markdown-symlink":
        os.symlink(markdown_marker, docs / "sub" / "evil.md")
        return "markdown"
    if mode == "markdown-race":
        victim = docs / "sub" / "evil.md"
        victim.write_text("# notes\n", encoding="utf-8")
        _install_swap_on_open(victim, markdown_marker)
        return "markdown"
    if mode == "markdown-zero":
        os.symlink("/dev/zero", docs / "sub" / "evil.md")
        return "markdown"
    if mode == "sidebar-symlink":
        sidebar = docs / "_sidebar.md"
        sidebar.unlink()
        os.symlink(markdown_marker, sidebar)
        return "sidebar"
    if mode == "sidebar-race":
        _install_swap_on_open(docs / "_sidebar.md", markdown_marker)
        return "sidebar"
    if mode == "sidebar-zero":
        sidebar = docs / "_sidebar.md"
        sidebar.unlink()
        os.symlink("/dev/zero", sidebar)
        return "sidebar"
    if mode == "index-symlink":
        index = docs / "index.html"
        index.unlink()
        os.symlink(html_marker, index)
        return "index"
    if mode == "index-race":
        _install_swap_on_open(docs / "index.html", html_marker)
        return "index"
    if mode == "index-zero":
        index = docs / "index.html"
        index.unlink()
        os.symlink("/dev/zero", index)
        return "index"
    if mode == "byte-markdown":
        (docs / "sub" / "big.md").write_text(
            _oversized("# notes\n"),
            encoding="utf-8",
        )
        return "markdown"
    if mode == "byte-sidebar":
        (docs / "_sidebar.md").write_text(_oversized(_sidebar_text()), encoding="utf-8")
        return "sidebar"
    if mode == "byte-index":
        (docs / "index.html").write_text(_oversized(_index_text()), encoding="utf-8")
        return "index"
    if mode == "main-zero":
        os.symlink("/dev/zero", docs / "sub" / "evil.md")
        return "main"
    if mode == "main-existing":
        return "main"
    raise SystemExit(f"unknown mode {mode}")


def _worker(mode: str) -> int:
    import resource

    resource.setrlimit(resource.RLIMIT_AS, (ADDRESS_SPACE_LIMIT, ADDRESS_SPACE_LIMIT))
    if mode == "main-existing":
        return _call("main")
    root = Path(os.environ["CHECK_DOCS_REPO"])
    check = _prepare(mode, root)
    return _call(check)


def _worker_main() -> int:
    mode = sys.argv[1]
    if "CHECK_DOCS_REPO" not in os.environ:
        import tempfile

        workspace = tempfile.mkdtemp(prefix="check-docs-symlink-")
        os.environ["CHECK_DOCS_REPO"] = workspace
    sys.path.insert(0, str(REPO))
    return _worker(mode)


if __name__ == "__main__":
    raise SystemExit(_worker_main())


# Keep the workflow command visible next to the contract. This string is not
# executed; the tests above call the same main the workflow runs.
WORKFLOW_COMMAND = textwrap.dedent(
    """
    python scripts/check_docs.py
    """
).strip()
