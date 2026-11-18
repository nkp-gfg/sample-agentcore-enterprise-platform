"""Newlines in platform.yaml must not become shell assignments during deploy.

`deploy.sh` loads the manifest by running `platform_config --export` and
evaluating every KEY=value line. These tests drive that function, then start
the same `npx` and `bash -c` programs the deploy script starts afterwards.
They fail while a newline in an exported string can set another variable.
"""

from __future__ import annotations

import os
import shlex
import subprocess
from pathlib import Path

import pytest
import yaml

REPO = Path(__file__).resolve().parents[1]

# deploy.sh sets these from the manifest. A second line in an exported value
# must not be able to introduce either name.
_NODE_OPTIONS = "NODE_OPTIONS"
_BASH_ENV = "BASH_ENV"

_DRIVER = r"""
unset NODE_OPTIONS BASH_ENV LD_PRELOAD MODEL_ID IDP_CLIENT_ID IDP_ISSUER_URL
set -euo pipefail
log_info() { :; }
log_warn() { :; }
log_error() { echo "$*" >&2; }
eval "$(sed -n '/^apply_platform_config()/,/^}/p' "$REPO/scripts/deploy.sh")"
export PLATFORM_CONFIG="$MANIFEST"
export PROJECT_DIR="$REPO"
trap 'rc=$?
{
  printf "status=%s\n" "$rc"
  printf "node_options=%s\n" "${NODE_OPTIONS-}"
  printf "bash_env=%s\n" "${BASH_ENV-}"
  printf "model_id=%s\n" "${MODEL_ID-}"
} > "$REPORT"
# Same program name deploy.sh uses for cdk. --version stays on this machine.
npx --version >/dev/null
# run_verify starts module checks with bash -c after the manifest is applied.
bash -c "exit 0"
' EXIT
apply_platform_config
"""


def _migration(**source: object) -> dict:
    body = {
        "platform": "other",
        "port": 8080,
        "invoke_path": "/invocations",
        "health_path": "/healthz",
    }
    body.update(source)
    return {
        "project": "agentcore-workshop",
        "environment": "dev",
        "region": "us-east-1",
        "migration": {
            "source": body,
            "target": {"runtime": "agentcore", "mode": "adapter"},
        },
    }


def _with_build(**extra: object) -> dict:
    return _migration(
        build={"context": "./customer-build", "dockerfile": "Dockerfile"},
        **extra,
    )


def _manifests(node_assignment: str, bash_assignment: str) -> dict[str, dict]:
    """Every exported string that is not already constrained to one line."""
    return {
        "agents.model_id": {
            "agents": {"model_id": "anthropic.claude-sonnet-4-6\n" + node_assignment}
        },
        "agents.model_id bash": {
            "agents": {"model_id": "anthropic.claude-sonnet-4-6\n" + bash_assignment}
        },
        "identity.client_id": {
            "identity": {
                "client_id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee\n" + node_assignment
            }
        },
        "identity.issuer_url": {
            "identity": {
                "issuer_url": "https://login.microsoftonline.com/common\n"
                + node_assignment
            }
        },
        "migration.source.env": _with_build(
            env={"APP_CONFIG": "level=info\n" + node_assignment}
        ),
        "migration.source.env bash": _with_build(
            env={"APP_CONFIG": "level=info\n" + bash_assignment}
        ),
        "migration.source.image": _migration(
            image="public.ecr.aws/demo/agent:1\n" + node_assignment
        ),
        "migration.source.build.context": _migration(
            build={
                "context": "./customer-build\n" + node_assignment,
                "dockerfile": "Dockerfile",
            }
        ),
        "migration.source.build.dockerfile": _migration(
            build={
                "context": "./customer-build",
                "dockerfile": "Dockerfile\n" + node_assignment,
            }
        ),
        "migration.source.registry_secret_name": _with_build(
            registry_secret_name="agentcore/registry\n" + node_assignment
        ),
        "migration.source.invoke_path": _with_build(
            invoke_path="/invocations\n" + node_assignment
        ),
        "migration.source.health_path": _with_build(
            health_path="/healthz\n" + node_assignment
        ),
    }


def _run(tmp_path: Path, manifest: dict) -> dict[str, str]:
    manifest_path = tmp_path / "platform.yaml"
    manifest_path.write_text(yaml.safe_dump(manifest), encoding="utf-8")
    node_marker = tmp_path / "node-loaded"
    bash_marker = tmp_path / "bash-loaded"
    payload_js = tmp_path / "payload.js"
    payload_sh = tmp_path / "payload.sh"
    report_path = tmp_path / "report"
    payload_js.write_text(
        "require('fs').writeFileSync(%s, 'loaded');\n" % repr(str(node_marker)),
        encoding="utf-8",
    )
    payload_sh.write_text(
        "#!/bin/bash\ntouch %s\n" % shlex.quote(str(bash_marker)),
        encoding="utf-8",
    )
    payload_sh.chmod(0o755)

    env = {
        "PATH": os.environ.get("PATH", ""),
        "HOME": os.environ.get("HOME", ""),
        "LANG": os.environ.get("LANG", "C.UTF-8"),
        "TMPDIR": str(tmp_path),
        "REPO": str(REPO),
        "MANIFEST": str(manifest_path),
        "REPORT": str(report_path),
    }
    completed = subprocess.run(
        ["bash", "-c", _DRIVER],
        cwd=REPO,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )
    assert report_path.is_file(), (
        "apply_platform_config ended without a report\n"
        f"stdout:\n{completed.stdout}\nstderr:\n{completed.stderr}"
    )
    parsed: dict[str, str] = {}
    for line in report_path.read_text(encoding="utf-8").splitlines():
        key, _, value = line.partition("=")
        parsed[key] = value
    parsed["node_marker"] = "yes" if node_marker.exists() else ""
    parsed["bash_marker"] = "yes" if bash_marker.exists() else ""
    return parsed


def _assert_not_injected(result: dict[str, str]) -> None:
    assert result["node_marker"] == ""
    assert result["bash_marker"] == ""
    assert result["node_options"] == ""
    assert result["bash_env"] == ""
    assert result["status"] != "0"


def test_benign_model_id_is_applied_and_does_not_run_a_payload(tmp_path: Path) -> None:
    result = _run(
        tmp_path,
        {"agents": {"model_id": "anthropic.claude-sonnet-4-6"}},
    )
    assert result["status"] == "0"
    assert result["model_id"] == "anthropic.claude-sonnet-4-6"
    assert result["node_options"] == ""
    assert result["bash_env"] == ""
    assert result["node_marker"] == ""
    assert result["bash_marker"] == ""


@pytest.mark.parametrize(
    "field",
    [
        "agents.model_id",
        "agents.model_id bash",
        "identity.client_id",
        "identity.issuer_url",
        "migration.source.env",
        "migration.source.env bash",
        "migration.source.image",
        "migration.source.build.context",
        "migration.source.build.dockerfile",
        "migration.source.registry_secret_name",
        "migration.source.invoke_path",
        "migration.source.health_path",
    ],
)
def test_newline_in_exported_string_is_rejected_before_npx_or_bash(
    tmp_path: Path, field: str
) -> None:
    node_assignment = f"{_NODE_OPTIONS}=--require {tmp_path / 'payload.js'}"
    bash_assignment = f"{_BASH_ENV}={tmp_path / 'payload.sh'}"
    manifest = _manifests(node_assignment, bash_assignment)[field]
    result = _run(tmp_path, manifest)
    _assert_not_injected(result)


def test_carriage_return_in_model_id_is_rejected(tmp_path: Path) -> None:
    result = _run(
        tmp_path,
        {"agents": {"model_id": "anthropic.claude-sonnet-4-6\r"}},
    )
    _assert_not_injected(result)
