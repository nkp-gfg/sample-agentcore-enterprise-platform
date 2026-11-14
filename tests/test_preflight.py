from __future__ import annotations

import sys
from collections.abc import Sequence
from pathlib import Path

from scripts.preflight import (
    CommandResult,
    CommandRunner,
    Preflight,
    _assert_read_only_aws_calls,
)

ACCOUNT = "111122223333"


class FakeRunner:
    def __init__(
        self, overrides: dict[tuple[str, ...], CommandResult] | None = None
    ) -> None:
        self.calls: list[tuple[str, ...]] = []
        self.overrides = overrides or {}

    def run(self, args: Sequence[str]) -> CommandResult:
        call = tuple(args)
        self.calls.append(call)
        for prefix, result in self.overrides.items():
            if call[: len(prefix)] == prefix:
                return result
        defaults = {
            ("node", "--version"): CommandResult(0, "v20.19.0"),
            ("npm", "--version"): CommandResult(0, "10.8.2"),
            ("aws", "--version"): CommandResult(0, "aws-cli/2.31.0"),
            ("bash", "--version"): CommandResult(0, "GNU bash, version 5.2.37"),
            ("npx", "--no-install", "cdk"): CommandResult(0, "2.1024.0"),
            (
                "aws",
                "sts",
                "get-caller-identity",
            ): CommandResult(
                0,
                f"{ACCOUNT}\tarn:aws:sts::{ACCOUNT}:assumed-role/EbaOperator/session",
            ),
            ("aws", "configure", "get"): CommandResult(0, "us-east-1"),
            ("aws", "secretsmanager", "get-secret-value"): CommandResult(0, "32"),
            ("aws", "bedrock", "get-inference-profile"): CommandResult(
                0, f"arn:aws:bedrock:us-east-1:{ACCOUNT}:inference-profile/test"
            ),
        }
        for prefix, result in defaults.items():
            if call[: len(prefix)] == prefix:
                return result
        return CommandResult(1, stderr=f"unexpected test command: {call}")


def _which(command: str) -> str | None:
    return None if command == "docker" else f"/test/bin/{command}"


def _manifest(tmp_path: Path, *, account: str = ACCOUNT) -> Path:
    path = tmp_path / "platform.yaml"
    path.write_text(
        f"""
project: preflight-test
environment: dev
region: us-east-1
deployment:
  platform_account: "{account}"
identity:
  idp: entra_id
  tenant_id: "697a5720-ec4f-42dc-9713-d01182b20533"
  client_id: "bec79924-165d-42b5-8ae7-f9f57fc6dbaa"
  client_secret_name: agentcore/test-idp
agents:
  model_id: us.anthropic.claude-sonnet-4-6
""",
        encoding="utf-8",
    )
    return path


def _preflight(path: Path, runner: FakeRunner, repo_root: Path) -> Preflight:
    return Preflight(
        path,
        runner=runner,
        which=_which,
        python_version=(3, 13, 7),
        repo_root=repo_root,
    )


def test_preflight_passes_with_read_only_calls(tmp_path: Path, capsys) -> None:
    runner = FakeRunner()

    result = _preflight(_manifest(tmp_path), runner, tmp_path).run()

    output = capsys.readouterr().out
    assert result == 0
    assert f"matches pinned account {ACCOUNT}" in output
    assert "agentcore/test-idp is readable and non-empty" in output
    assert "is discoverable from us-east-1" in output
    assert "No AWS resources were changed." in output
    _assert_read_only_aws_calls(runner.calls)


def test_preflight_fails_on_missing_secret_without_printing_a_value(
    tmp_path: Path, capsys
) -> None:
    runner = FakeRunner(
        {
            (
                "aws",
                "secretsmanager",
                "get-secret-value",
            ): CommandResult(254, stderr="ResourceNotFoundException")
        }
    )

    result = _preflight(_manifest(tmp_path), runner, tmp_path).run()

    output = capsys.readouterr().out
    assert result == 1
    assert "agentcore/test-idp does not exist" in output
    assert "create or repair it before build" in output
    assert "secret-string" not in output.lower()
    _assert_read_only_aws_calls(runner.calls)


def test_preflight_stops_account_scoped_reads_on_account_mismatch(
    tmp_path: Path, capsys
) -> None:
    runner = FakeRunner()

    result = _preflight(
        _manifest(tmp_path, account="999988887777"), runner, tmp_path
    ).run()

    output = capsys.readouterr().out
    assert result == 1
    assert f"credentials resolve to {ACCOUNT}" in output
    assert "platform.yaml pins 999988887777" in output
    assert not any(call[:2] == ("aws", "secretsmanager") for call in runner.calls)
    assert not any(call[:2] == ("aws", "bedrock") for call in runner.calls)
    _assert_read_only_aws_calls(runner.calls)


def test_preflight_fails_when_migration_build_context_is_missing(
    tmp_path: Path, capsys
) -> None:
    manifest = tmp_path / "migration.yaml"
    manifest.write_text(
        f"""
project: migration-test
environment: eba
region: us-east-1
deployment:
  platform_account: "{ACCOUNT}"
migration:
  source:
    platform: ec2
    build:
      context: ./customer-agent
      dockerfile: Dockerfile
    port: 8000
    invoke_path: /run
  target:
    runtime: agentcore
    mode: adapter
""",
        encoding="utf-8",
    )
    runner = FakeRunner()

    result = _preflight(manifest, runner, tmp_path).run()

    output = capsys.readouterr().out
    assert result == 1
    assert "build context does not exist" in output
    assert "migrated container owns its model configuration" in output
    _assert_read_only_aws_calls(runner.calls)


def test_read_only_guard_rejects_mutating_aws_call() -> None:
    calls = [("aws", "secretsmanager", "create-secret", "--name", "example")]

    try:
        _assert_read_only_aws_calls(calls)
    except AssertionError as exc:
        assert "unapproved AWS call" in str(exc)
    else:
        raise AssertionError("read-only guard accepted create-secret")


def test_command_runner_blocks_unapproved_aws_call_before_execution() -> None:
    result = CommandRunner().run(("aws", "cloudformation", "deploy"))

    assert result.returncode == 1
    assert result.stderr == "blocked non-read-only AWS command"


def test_preflight_validates_hr_part2_footprint_and_god_agent_default_model(
    tmp_path: Path, capsys
) -> None:
    repo_root = Path(__file__).resolve().parents[1]
    manifest = tmp_path / "part2.yaml"
    manifest.write_text(
        f"""
project: agentcore-production
environment: prod
region: us-east-1
deployment:
  platform_account: "{ACCOUNT}"
identity:
  idp: cognito
  mode: brokered
agents:
  pattern: god-agent
security:
  networking: true
  cloudtrail_alerting: true
  egress_filter: true
  require_guardrails: true
  cedar:
    enabled: true
    mode: ENFORCE
use_cases:
  hr-data:
    seed: true
  hr-identity: {{}}
  hr-tools: {{}}
""",
        encoding="utf-8",
    )
    runner = FakeRunner(
        {
            ("aws", "bedrock", "get-foundation-model"): CommandResult(
                0,
                "arn:aws:bedrock:us-east-1::foundation-model/openai.gpt-oss-120b-1:0",
            )
        }
    )

    result = _preflight(manifest, runner, repo_root).run()

    output = capsys.readouterr().out
    assert result == 0, output
    assert (
        "[PASS] HR Part 2: hr-data, hr-identity, hr-tools, pattern=god-agent ready"
        in output
    )
    assert "openai.gpt-oss-120b-1:0 is discoverable" in output
    _assert_read_only_aws_calls(runner.calls)


def test_preflight_catches_hr_tools_missing_egress_filter_or_cedar(
    tmp_path: Path, capsys
) -> None:
    repo_root = Path(__file__).resolve().parents[1]
    manifest = tmp_path / "part2-bad.yaml"
    manifest.write_text(
        f"""
project: agentcore-workshop
environment: dev
region: us-east-1
deployment:
  platform_account: "{ACCOUNT}"
security:
  networking: true
  cloudtrail_alerting: true
  egress_filter: false
  cedar:
    enabled: false
use_cases:
  hr-data: {{}}
  hr-identity: {{}}
  hr-tools: {{}}
""",
        encoding="utf-8",
    )
    runner = FakeRunner(
        {
            ("aws", "bedrock", "get-inference-profile"): CommandResult(
                0, f"arn:aws:bedrock:us-east-1:{ACCOUNT}:inference-profile/test"
            ),
            ("aws", "bedrock", "get-foundation-model"): CommandResult(
                0, "arn:aws:bedrock:us-east-1::foundation-model/test"
            ),
        }
    )

    result = _preflight(manifest, runner, repo_root).run()

    output = capsys.readouterr().out
    assert result == 1
    assert "requires security.egress_filter: true" in output
    assert "requires security.cedar.enabled: true and mode: ENFORCE" in output
    _assert_read_only_aws_calls(runner.calls)


def test_command_runner_strips_exported_prefix_env_var(monkeypatch) -> None:
    monkeypatch.setenv("PREFIX", "agentcore-production-prod")

    result = CommandRunner().run(
        (sys.executable, "-c", "import os; print(os.environ.get('PREFIX', 'UNSET'))")
    )

    assert result.returncode == 0
    assert result.stdout == "UNSET"


def test_preflight_explains_when_cdk_on_path_but_missing_from_node_prefix(
    tmp_path: Path, capsys
) -> None:
    runner = FakeRunner(
        {("npx", "--no-install", "cdk"): CommandResult(1, stderr="missing")}
    )

    result = _preflight(_manifest(tmp_path), runner, tmp_path).run()

    output = capsys.readouterr().out
    assert result == 1
    assert "cdk is on PATH, but `npx --no-install cdk` could not resolve" in output
    assert "npm install -g aws-cdk" in output


def test_command_runner_blocks_secretsmanager_mutations_and_deploy_uses_stdin() -> None:
    for verb in ("put-secret-value", "create-secret"):
        result = CommandRunner().run(("aws", "secretsmanager", verb))
        assert result.returncode == 1
        assert result.stderr == "blocked non-read-only AWS command"

    deploy_sh = (
        Path(__file__).resolve().parents[1] / "scripts" / "deploy.sh"
    ).read_text(encoding="utf-8")
    assert '--secret-string "$value"' not in deploy_sh
    assert "--secret-string file:///dev/stdin" in deploy_sh
