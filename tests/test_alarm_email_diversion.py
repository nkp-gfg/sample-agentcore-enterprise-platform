"""Production alarm mail must follow the validated manifest inbox.

The deploy path exports observability.alarm_email and then synthesizes with
``build_context_args``. These tests fail while a CDK context value or
``ALARM_EMAIL`` can replace that inbox, and pass once synthesis subscribes
the manifest address and refuses a different one.

Workshop mode is not covered: it does not require a monitored inbox.
"""

from __future__ import annotations

import itertools
import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

from infra_utils.platform_config import load_platform_config

REPO = Path(__file__).resolve().parents[1]
MANIFEST_EMAIL = "ops@corpmail.io"
CONTEXT_EMAIL = "alerts@diverted.invalid"
ENV_EMAIL = "pages@diverted.invalid"
ACCOUNT = "111111111111"
REGION = "us-east-1"


def _cdk_executable() -> str:
    found = shutil.which("cdk")
    if not found:
        pytest.fail("cdk is not on PATH; install aws-cdk CLI 2.1149.0 or newer")
    return found


def _production_manifest(path: Path, email: str) -> None:
    raw = yaml.safe_load((REPO / "presets" / "production.yaml").read_text())
    raw["deployment"]["platform_account"] = ACCOUNT
    raw["identity"]["tenant_id"] = "11111111-2222-3333-4444-555555555555"
    raw["identity"]["client_id"] = "app-client-id"
    raw["security"]["org_id"] = "o-1a2b3c4d5e"
    raw["observability"]["alarm_email"] = email
    path.write_text(yaml.safe_dump(raw))
    loaded = load_platform_config(path)
    assert loaded.deployment.mode == "production"
    assert loaded.observability.alarm_email == email


def _az_context() -> dict[str, list[str]]:
    # Same seed check-contract.sh uses so the VPC can synthesize without AWS.
    return {
        f"availability-zones:account={ACCOUNT}:region={REGION}": [
            f"{REGION}a",
            f"{REGION}b",
        ]
    }


def _write_context_cache(extra: dict | None = None) -> None:
    data = _az_context()
    if extra:
        data.update(extra)
    (REPO / "cdk.context.json").write_text(json.dumps(data) + "\n")


def _base_env(manifest: Path, home: Path, **overrides: str) -> dict[str, str]:
    home.mkdir(parents=True, exist_ok=True)
    env = {
        "PATH": os.environ["PATH"],
        "HOME": str(home),
        "PROJECT_DIR": str(REPO),
        "PLATFORM_CONFIG": str(manifest),
        "CDK_DEFAULT_ACCOUNT": ACCOUNT,
        "CDK_DEFAULT_REGION": REGION,
        "JSII_SILENCE_WARNING_UNTESTED_NODE_VERSION": "1",
        "PYTHONDONTWRITEBYTECODE": "1",
    }
    env.update(overrides)
    return env


def _deploy_context(env: dict[str, str]) -> tuple[dict[str, str], list[str]]:
    """Run deploy.sh's export and context builder, then return the child env."""
    script = r"""
set -euo pipefail
log_info() { :; }
log_warn() { :; }
log_error() { printf '%s\n' "$*" >&2; }
eval "$(sed -n '/^PLATFORM_CONFIG=/p; /^apply_platform_config()/,/^}/p; /^build_context_args()/,/^}/p' "$PROJECT_DIR/scripts/deploy.sh")"
apply_platform_config
build_context_args
printf '%s\n' "${CONTEXT_ARGS[@]}" > "$CONTEXT_ARGS_FILE"
env > "$ENV_FILE"
"""
    args_file = Path(env["HOME"]) / "context-args.txt"
    env_file = Path(env["HOME"]) / "child.env"
    child = dict(env)
    child["CONTEXT_ARGS_FILE"] = str(args_file)
    child["ENV_FILE"] = str(env_file)
    subprocess.run(
        ["bash", "-c", script],
        cwd=REPO,
        env=child,
        check=True,
        text=True,
    )
    args = [line for line in args_file.read_text().splitlines() if line != ""]
    exported: dict[str, str] = {}
    for line in env_file.read_text().splitlines():
        key, sep, value = line.partition("=")
        if sep:
            exported[key] = value
    return exported, args


def _email_endpoints(outdir: Path) -> set[str]:
    found: set[str] = set()
    if not outdir.exists():
        return found
    for path in outdir.rglob("*.json"):
        try:
            data = json.loads(path.read_text())
        except json.JSONDecodeError:
            continue
        resources = data.get("Resources") if isinstance(data, dict) else None
        if not isinstance(resources, dict):
            continue
        for resource in resources.values():
            if not isinstance(resource, dict):
                continue
            if resource.get("Type") != "AWS::SNS::Subscription":
                continue
            props = resource.get("Properties") or {}
            if props.get("Protocol") == "email":
                endpoint = props.get("Endpoint")
                if isinstance(endpoint, str):
                    found.add(endpoint)
    return found


def _synth(
    env: dict[str, str], args: list[str], outdir: Path
) -> subprocess.CompletedProcess[str]:
    if outdir.exists():
        shutil.rmtree(outdir)
    return subprocess.run(
        [
            _cdk_executable(),
            "synth",
            "--quiet",
            "--output",
            str(outdir),
            *args,
        ],
        cwd=REPO,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )


def _assert_rejected_inbox_absent(
    proc: subprocess.CompletedProcess[str], outdir: Path, rejected: str
) -> None:
    endpoints = _email_endpoints(outdir)
    assert rejected not in endpoints, (
        f"synthesis subscribed {rejected!r} (exit {proc.returncode})\n"
        f"{proc.stderr[-2000:]}"
    )
    if proc.returncode == 0:
        assert endpoints == {MANIFEST_EMAIL}
    else:
        # A refusal may still write the manifest subscription. It must not
        # write any other inbox.
        assert endpoints <= {MANIFEST_EMAIL}


@pytest.fixture
def manifest(tmp_path: Path) -> Path:
    path = tmp_path / "platform.yaml"
    _production_manifest(path, MANIFEST_EMAIL)
    return path


def test_build_context_args_pins_manifest_alarm_email(
    manifest: Path, tmp_path: Path
) -> None:
    _env, args = _deploy_context(_base_env(manifest, tmp_path / "home"))
    paired = list(itertools.pairwise(args))
    assert ("-c", f"alarm_email={MANIFEST_EMAIL}") in paired, args


@pytest.mark.parametrize(
    "source",
    ["cdk.json", "cdk.context.json", "user"],
)
def test_deploy_synth_keeps_manifest_inbox(
    source: str, manifest: Path, tmp_path: Path
) -> None:
    home = tmp_path / "home"
    home.mkdir()
    outdir = tmp_path / "cdk.out"
    cdk_json = REPO / "cdk.json"
    context_file = REPO / "cdk.context.json"
    original_cdk = cdk_json.read_text()
    original_context = context_file.read_text() if context_file.exists() else None
    try:
        if source == "cdk.json":
            data = json.loads(original_cdk)
            data.setdefault("context", {})["alarm_email"] = CONTEXT_EMAIL
            cdk_json.write_text(json.dumps(data, indent=2) + "\n")
            _write_context_cache()
        elif source == "cdk.context.json":
            # Flat map: the CLI loads this file as the context bag itself.
            _write_context_cache({"alarm_email": CONTEXT_EMAIL})
        else:
            _write_context_cache()
            (home / ".cdk.json").write_text(
                json.dumps({"context": {"alarm_email": CONTEXT_EMAIL}}) + "\n"
            )
        exported, args = _deploy_context(_base_env(manifest, home))
        assert exported.get("ALARM_EMAIL") == MANIFEST_EMAIL
        proc = _synth(exported, args, outdir)
        _assert_rejected_inbox_absent(proc, outdir, CONTEXT_EMAIL)
    finally:
        cdk_json.write_text(original_cdk)
        if original_context is None:
            context_file.unlink(missing_ok=True)
        else:
            context_file.write_text(original_context)


def _with_az_cache(fn):
    context_file = REPO / "cdk.context.json"
    original = context_file.read_text() if context_file.exists() else None
    _write_context_cache()
    try:
        return fn()
    finally:
        if original is None:
            context_file.unlink(missing_ok=True)
        else:
            context_file.write_text(original)


def test_visible_context_mismatch_fails_closed(manifest: Path, tmp_path: Path) -> None:
    def run() -> None:
        home = tmp_path / "home"
        exported, args = _deploy_context(_base_env(manifest, home))
        proc = _synth(
            exported,
            [*args, "-c", f"alarm_email={CONTEXT_EMAIL}"],
            tmp_path / "cdk.out",
        )
        assert proc.returncode != 0, proc.stderr[-2000:]
        _assert_rejected_inbox_absent(proc, tmp_path / "cdk.out", CONTEXT_EMAIL)

    _with_az_cache(run)


def test_environment_mismatch_fails_closed(manifest: Path, tmp_path: Path) -> None:
    def run() -> None:
        home = tmp_path / "home"
        exported, args = _deploy_context(
            _base_env(manifest, home, ALARM_EMAIL=ENV_EMAIL)
        )
        assert exported.get("ALARM_EMAIL") == ENV_EMAIL
        proc = _synth(exported, args, tmp_path / "cdk.out")
        assert proc.returncode != 0, proc.stderr[-2000:]
        _assert_rejected_inbox_absent(proc, tmp_path / "cdk.out", ENV_EMAIL)

    _with_az_cache(run)


def test_matching_manifest_inbox_is_subscribed(manifest: Path, tmp_path: Path) -> None:
    def run() -> None:
        home = tmp_path / "home"
        exported, args = _deploy_context(_base_env(manifest, home))
        proc = _synth(exported, args, tmp_path / "cdk.out")
        assert proc.returncode == 0, proc.stderr[-2000:]
        assert _email_endpoints(tmp_path / "cdk.out") == {MANIFEST_EMAIL}

    _with_az_cache(run)
