"""Migration build context must stay inside the repository.

RuntimeStack packages ``build_context`` as a CDK directory asset. These tests
fail while an absolute path, a parent-segment path, or a symlink can make that
asset include a file from outside the repository. They pass once construction
fails closed before any outside file is read or staged.

``aws-cdk`` CLI 2.1148.1 (the unpinned ``npm install -g aws-cdk`` in
``scripts/deploy.sh``) zips a directory asset by walking it with
``followSymbolicLinks: true`` and reading every file
(``package/lib/index.js`` ``writeZipFile`` and ``packageFile``). The payload
check below does that same walk, so a staged symlink to an outside file still
fails.
"""

from __future__ import annotations

import builtins
import os
import runpy
import shutil
from pathlib import Path
from unittest.mock import patch

import aws_cdk as cdk
import pytest

from stacks.runtime_stack import RuntimeStack

REPO = Path(__file__).resolve().parents[1]
ENV = cdk.Environment(account="111111111111", region="us-east-1")
MARKER = "outside-marker-value"
SIMULATION = "migration/simulation/existing-ec2-agent"


def _outside_tree(tmp_path: Path) -> Path:
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "marker.txt").write_text(MARKER + "\n", encoding="utf-8")
    (outside / "Dockerfile").write_text("FROM scratch\n", encoding="utf-8")
    return outside


def _synthesize(
    outdir: Path, build_context: str, dockerfile: str = "Dockerfile"
) -> None:
    app = cdk.App(outdir=str(outdir))
    RuntimeStack(
        app,
        "MigrationRuntime",
        project_name="proj",
        environment="dev",
        component_name="orchestrator",
        source_dir="agent-code",
        build_context=build_context,
        build_dockerfile=dockerfile,
        adapter_dir="migration/adapter",
        migration_port="8000",
        migration_invoke_path="/run",
        env=ENV,
    )
    app.synth()


def _zip_payload(root: Path) -> bytes:
    """Bytes a toolkit publish would put in the context zip.

    Mirrors ``writeZipFile`` in aws-cdk 2.1148.1: every file under the staged
    directory, including the target of a symbolic link.
    """
    if not root.exists():
        return b""
    chunks: list[bytes] = []
    for dirpath, _dirnames, filenames in os.walk(root, followlinks=True):
        for name in filenames:
            path = Path(dirpath) / name
            try:
                chunks.append(path.read_bytes())
            except OSError:
                continue
    return b"\0".join(chunks)


def _opened_under(opened: list[str], root: Path) -> list[str]:
    root = root.resolve()
    hits: list[str] = []
    for raw in opened:
        try:
            resolved = Path(raw).resolve()
        except OSError:
            continue
        if resolved == root or root in resolved.parents:
            hits.append(str(resolved))
    return hits


def _expect_refused(
    tmp_path: Path,
    build_context: str,
    *,
    dockerfile: str = "Dockerfile",
    outside: Path | None = None,
) -> None:
    outdir = tmp_path / "assembly"
    opened: list[str] = []
    real_open = builtins.open

    def tracking_open(file, *args, **kwargs):
        if isinstance(file, (str, os.PathLike)):
            opened.append(os.fspath(file))
        return real_open(file, *args, **kwargs)

    # Any refusal is correct; the fix chooses the exception type.
    with patch("builtins.open", tracking_open), pytest.raises(Exception):  # noqa: B017
        _synthesize(outdir, build_context, dockerfile)

    assert MARKER.encode() not in _zip_payload(outdir)
    if outside is not None:
        assert _opened_under(opened, outside) == []


def test_absolute_migration_context_is_not_packaged(tmp_path: Path) -> None:
    outside = _outside_tree(tmp_path)
    _expect_refused(tmp_path, str(outside), outside=outside)


def test_parent_segment_migration_context_is_not_packaged(tmp_path: Path) -> None:
    outside = _outside_tree(tmp_path)
    relative = os.path.relpath(outside, REPO)
    assert ".." in relative
    _expect_refused(tmp_path, relative, outside=outside)


def test_context_directory_symlink_is_not_packaged(tmp_path: Path) -> None:
    outside = _outside_tree(tmp_path)
    link = REPO / f".containment-context-{tmp_path.name}"
    link.symlink_to(outside, target_is_directory=True)
    try:
        relative = os.path.relpath(link, REPO)
        assert ".." not in Path(relative).parts
        assert not Path(relative).is_absolute()
        _expect_refused(tmp_path, relative, outside=outside)
    finally:
        link.unlink(missing_ok=True)


def test_symlink_inside_context_is_not_packaged(tmp_path: Path) -> None:
    outside = _outside_tree(tmp_path)
    context = REPO / f".containment-tree-{tmp_path.name}"
    context.mkdir()
    try:
        (context / "Dockerfile").write_text("FROM scratch\n", encoding="utf-8")
        target = os.path.relpath(outside / "marker.txt", context)
        assert ".." in target
        (context / "marker.txt").symlink_to(target)
        relative = os.path.relpath(context, REPO)
        _expect_refused(tmp_path, relative, outside=outside)
    finally:
        if context.exists():
            for child in context.iterdir():
                child.unlink()
            context.rmdir()


def test_dockerfile_outside_context_is_rejected(tmp_path: Path) -> None:
    outside = _outside_tree(tmp_path)
    dockerfile = os.path.relpath(outside / "Dockerfile", REPO / SIMULATION)
    assert ".." in dockerfile
    _expect_refused(
        tmp_path,
        SIMULATION,
        dockerfile=dockerfile,
        outside=outside,
    )


def test_absolute_dockerfile_is_rejected(tmp_path: Path) -> None:
    outside = _outside_tree(tmp_path)
    _expect_refused(
        tmp_path,
        SIMULATION,
        dockerfile=str(outside / "Dockerfile"),
        outside=outside,
    )


def test_in_repo_context_still_synthesizes(tmp_path: Path) -> None:
    outdir = tmp_path / "assembly"
    _synthesize(outdir, SIMULATION)
    assert MARKER.encode() not in _zip_payload(outdir)
    assert (REPO / SIMULATION / "Dockerfile").is_file()


def test_internal_symlink_still_synthesizes(tmp_path: Path) -> None:
    context = REPO / f".containment-internal-{tmp_path.name}"
    context.mkdir()
    try:
        (context / "Dockerfile").write_text("FROM scratch\n", encoding="utf-8")
        (context / "alias.Dockerfile").symlink_to("Dockerfile")
        outdir = tmp_path / "assembly"
        _synthesize(outdir, os.path.relpath(context, REPO))
        assert MARKER.encode() not in _zip_payload(outdir)
    finally:
        if context.exists():
            for child in context.iterdir():
                child.unlink()
            context.rmdir()


def _run_app() -> tuple[bool, bytes, list[str]]:
    opened: list[str] = []
    real_open = builtins.open

    def tracking_open(file, *args, **kwargs):
        if isinstance(file, (str, os.PathLike)):
            opened.append(os.fspath(file))
        return real_open(file, *args, **kwargs)

    before = set(Path("/tmp").glob("cdk.out*"))
    raised = False
    payload = b""
    previous = os.getcwd()
    os.chdir(REPO)
    try:
        with patch("builtins.open", tracking_open):
            try:
                module = runpy.run_path(str(REPO / "app.py"))
            except Exception:  # noqa: BLE001 - any failed synth is a refusal
                raised = True
            else:
                payload = _zip_payload(Path(module["app"].outdir))
        for assembly in set(Path("/tmp").glob("cdk.out*")) - before:
            payload += _zip_payload(assembly)
    finally:
        os.chdir(previous)
        for assembly in set(Path("/tmp").glob("cdk.out*")) - before:
            shutil.rmtree(assembly, ignore_errors=True)
    return raised, payload, opened


def _assert_app_refused(outside: Path) -> None:
    raised, payload, opened = _run_app()
    assert raised
    assert MARKER.encode() not in payload
    assert _opened_under(opened, outside) == []


def test_app_env_context_is_not_packaged(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    outside = _outside_tree(tmp_path)
    monkeypatch.setenv("CDK_DEFAULT_ACCOUNT", "111111111111")
    monkeypatch.setenv("CDK_DEFAULT_REGION", "us-east-1")
    monkeypatch.setenv("PLATFORM_CONFIG", str(tmp_path / "absent.yaml"))
    monkeypatch.setenv("MIGRATION_ENABLED", "true")
    monkeypatch.setenv("MIGRATION_BUILD_CONTEXT", str(outside))
    monkeypatch.setenv("MIGRATION_BUILD_DOCKERFILE", "Dockerfile")
    monkeypatch.setenv("MIGRATION_PORT", "8000")
    monkeypatch.setenv("MIGRATION_INVOKE_PATH", "/run")
    monkeypatch.setenv("MIGRATION_TARGET_RUNTIME", "agentcore")
    monkeypatch.setenv("MIGRATION_TARGET_MODE", "adapter")
    _assert_app_refused(outside)


def test_app_yaml_context_is_not_packaged(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    outside = _outside_tree(tmp_path)
    manifest = tmp_path / "platform.yaml"
    manifest.write_text(
        "\n".join(
            [
                "project: proj",
                "environment: dev",
                "migration:",
                "  source:",
                "    platform: ec2",
                "    build:",
                f"      context: {outside}",
                "      dockerfile: Dockerfile",
                "    port: 8000",
                "    invoke_path: /run",
                "  target:",
                "    runtime: agentcore",
                "    mode: adapter",
                "",
            ]
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("CDK_DEFAULT_ACCOUNT", "111111111111")
    monkeypatch.setenv("CDK_DEFAULT_REGION", "us-east-1")
    monkeypatch.setenv("PLATFORM_CONFIG", str(manifest))
    monkeypatch.delenv("MIGRATION_BUILD_CONTEXT", raising=False)
    monkeypatch.delenv("MIGRATION_ENABLED", raising=False)
    _assert_app_refused(outside)
