"""Legacy agent-to-agent default must not expose a machine-credential runtime.

These tests fail while the vulnerability is present. They describe the
deployment the product actually synthesizes:

* With no platform manifest, no ``enable_a2a`` context, and no ``ENABLE_A2A``
  environment variable, ``scripts/deploy.sh`` omits the flag and ``app.py``
  falls through to its legacy default of on.
* That synthesis creates the code-agent and research-agent runtimes with
  protocol ``A2A`` and no JWT authorizer. AgentCore then authorizes callers
  with IAM ``bedrock-agentcore:InvokeAgentRuntime`` only.
* Every runtime role is granted that action on ``*``. The research runtime's
  environment names the platform machine credential provider, and the research
  agent requests a machine token for gateway tools.

A fix has to do three things. Leave ``ENABLE_A2A`` unset and the deploy script
must still pass ``enable_a2a=false``. Synthesize with neither context nor the
environment variable and no agent-to-agent runtime may appear. When a preset
or flag explicitly turns agent-to-agent on, each of those runtimes needs a
resource policy that denies ``InvokeAgentRuntime`` to every principal other
than the orchestrator runtime role. Identity policies on the runtime roles are
not that control: an explicit deny on the runtime is what stops a different
principal who already has ``InvokeAgentRuntime``.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

REPO = Path(__file__).resolve().parents[1]
A2A_STACK_SUFFIXES = ("runtime-code-agent", "runtime-research-agent")
INVOKE_ACTION = "bedrock-agentcore:InvokeAgentRuntime"
ORCHESTRATOR_ROLE_SUFFIX = "-orchestrator-runtime-role"
ACCOUNT = "111111111111"
REGION = "us-east-1"


def _run(cmd: list[str], *, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        cmd,
        cwd=REPO,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )


def deploy_context_args(extra: dict[str, str] | None = None) -> list[str]:
    """Run the real ``build_context_args`` from scripts/deploy.sh."""
    env = os.environ.copy()
    for key in (
        "ENABLE_A2A",
        "ENABLE_NETWORKING",
        "ENABLE_SECURITY",
        "PLATFORM_CONFIG",
        "PROJECT_NAME",
        "ENVIRONMENT",
        "AGENT_PATTERN",
    ):
        env.pop(key, None)
    env.update(extra or {})
    script = r"""
set -euo pipefail
eval "$(sed -n '/^build_context_args()/,/^}/p' scripts/deploy.sh)"
PROJECT_NAME="${PROJECT_NAME:-agentcore-workshop}"
ENVIRONMENT="${ENVIRONMENT:-dev}"
AGENT_PATTERN="${AGENT_PATTERN:-orchestrator}"
build_context_args
printf '%s\n' "${CONTEXT_ARGS[@]}"
"""
    result = _run(["bash", "-c", script], env=env)
    assert result.returncode == 0, result.stderr
    return [line for line in result.stdout.splitlines() if line]


def _pairs(args: list[str]) -> dict[str, str]:
    pairs: dict[str, str] = {}
    index = 0
    while index < len(args):
        if args[index] == "-c" and index + 1 < len(args) and "=" in args[index + 1]:
            key, value = args[index + 1].split("=", 1)
            pairs[key] = value
            index += 2
            continue
        index += 1
    return pairs


def synth_app(
    outdir: Path,
    *,
    context: dict[str, str] | None = None,
    env_updates: dict[str, str] | None = None,
) -> dict[str, dict[str, Any]]:
    """Synthesize app.py the way CDK loads it, and return stack templates."""
    env = os.environ.copy()
    for key in ("ENABLE_A2A", "PLATFORM_CONFIG", "CDK_CONTEXT_JSON", "CDK_OUTDIR"):
        env.pop(key, None)
    env["CDK_OUTDIR"] = str(outdir)
    env["CDK_DEFAULT_ACCOUNT"] = ACCOUNT
    env["CDK_DEFAULT_REGION"] = REGION
    # A missing file is the attack path: app.py must not invent a manifest.
    env["PLATFORM_CONFIG"] = str(outdir / "platform.yaml")
    if context is not None:
        env["CDK_CONTEXT_JSON"] = json.dumps(context)
    env.update(env_updates or {})
    result = _run([sys.executable, str(REPO / "app.py")], env=env)
    assert result.returncode == 0, result.stderr or result.stdout
    templates: dict[str, dict[str, Any]] = {}
    for path in outdir.glob("*.template.json"):
        templates[path.name] = json.loads(path.read_text())
    assert templates, "app.py produced no templates"
    return templates


def _resources(template: dict[str, Any], resource_type: str) -> list[tuple[str, dict[str, Any]]]:
    return [
        (logical_id, resource)
        for logical_id, resource in template.get("Resources", {}).items()
        if resource.get("Type") == resource_type
    ]


def a2a_runtimes(
    templates: dict[str, dict[str, Any]],
) -> list[tuple[str, str, dict[str, Any]]]:
    found = []
    for name, template in templates.items():
        for logical_id, resource in _resources(template, "AWS::BedrockAgentCore::Runtime"):
            if resource["Properties"].get("ProtocolConfiguration") == "A2A":
                found.append((name, logical_id, resource["Properties"]))
    return found


def _role_name(resource: dict[str, Any]) -> str | None:
    name = resource.get("Properties", {}).get("RoleName")
    return name if isinstance(name, str) else None


def _orchestrator_role(template: dict[str, Any]) -> tuple[str, dict[str, Any]] | None:
    for logical_id, resource in _resources(template, "AWS::IAM::Role"):
        name = _role_name(resource)
        if name and name.endswith(ORCHESTRATOR_ROLE_SUFFIX):
            return logical_id, resource
    return None


def _is_orchestrator_arn(
    node: Any,
    home: dict[str, Any],
    templates: dict[str, dict[str, Any]],
) -> bool:
    """True when a template node is the orchestrator runtime role ARN."""
    if isinstance(node, str):
        return node.endswith(ORCHESTRATOR_ROLE_SUFFIX) or (
            f":role/{node.split(':role/')[-1]}" in node
            and node.split(":role/")[-1].endswith(ORCHESTRATOR_ROLE_SUFFIX)
        )
    if isinstance(node, list):
        return bool(node) and all(_is_orchestrator_arn(item, home, templates) for item in node)
    if not isinstance(node, dict):
        return False
    if "Fn::GetAtt" in node:
        target = node["Fn::GetAtt"]
        if (
            isinstance(target, list)
            and len(target) == 2
            and target[1] == "Arn"
            and isinstance(target[0], str)
        ):
            resource = home.get("Resources", {}).get(target[0])
            name = _role_name(resource) if isinstance(resource, dict) else None
            return bool(name and name.endswith(ORCHESTRATOR_ROLE_SUFFIX))
        return False
    if "Ref" in node and isinstance(node["Ref"], str):
        resource = home.get("Resources", {}).get(node["Ref"])
        name = _role_name(resource) if isinstance(resource, dict) else None
        return bool(name and name.endswith(ORCHESTRATOR_ROLE_SUFFIX))
    if "Fn::ImportValue" in node and isinstance(node["Fn::ImportValue"], str):
        export_name = node["Fn::ImportValue"]
        for template in templates.values():
            for output in template.get("Outputs", {}).values():
                export = output.get("Export", {})
                if isinstance(export, dict) and export.get("Name") == export_name:
                    return _is_orchestrator_arn(output.get("Value"), template, templates)
        return False
    if "Fn::Sub" in node:
        body = node["Fn::Sub"]
        if isinstance(body, str):
            return body.endswith(ORCHESTRATOR_ROLE_SUFFIX)
        if isinstance(body, list) and body:
            return _is_orchestrator_arn(body[-1], home, templates) or (
                isinstance(body[0], str) and ORCHESTRATOR_ROLE_SUFFIX in body[0]
            )
    return False


def _placeholder(node: Any, tokens: dict[str, Any]) -> str:
    key = f"__TOKEN_{len(tokens)}__"
    tokens[key] = node
    return f'"{key}"'


def _flatten(node: Any, tokens: dict[str, Any]) -> str:
    if isinstance(node, str):
        return node
    if isinstance(node, dict) and set(node) == {"Fn::Join"}:
        separator, parts = node["Fn::Join"]
        chunks = []
        for part in parts:
            if isinstance(part, str):
                chunks.append(part)
            else:
                chunks.append(_placeholder(part, tokens))
        return separator.join(chunks)
    if isinstance(node, dict) and set(node) == {"Fn::Sub"}:
        body = node["Fn::Sub"]
        if isinstance(body, str):
            return body
        if isinstance(body, list) and len(body) == 2 and isinstance(body[0], str):
            text = body[0]
            mapping = body[1] if isinstance(body[1], dict) else {}
            for name, value in mapping.items():
                text = text.replace("${" + name + "}", _placeholder(value, tokens).strip('"'))
            return text
    return _placeholder(node, tokens)


def _policy_document(policy: Any) -> tuple[dict[str, Any], dict[str, Any]]:
    tokens: dict[str, Any] = {}
    if isinstance(policy, dict) and "Statement" in policy:
        return policy, tokens
    flat = _flatten(policy, tokens)
    return json.loads(flat), tokens


def _resolve(value: Any, tokens: dict[str, Any]) -> Any:
    if isinstance(value, str) and value in tokens:
        return tokens[value]
    if isinstance(value, list):
        return [_resolve(item, tokens) for item in value]
    if isinstance(value, dict):
        return {key: _resolve(item, tokens) for key, item in value.items()}
    return value


def _actions(statement: dict[str, Any]) -> set[str]:
    action = statement.get("Action", [])
    if isinstance(action, str):
        return {action}
    if isinstance(action, list):
        return {item for item in action if isinstance(item, str)}
    return set()


def _targets_runtime(policy_resource: dict[str, Any], runtime_logical_id: str) -> bool:
    arn = policy_resource.get("Properties", {}).get("ResourceArn")
    return arn == {"Fn::GetAtt": [runtime_logical_id, "AgentRuntimeArn"]}


def _denies_everyone_but_orchestrator(
    statement: dict[str, Any],
    home: dict[str, Any],
    templates: dict[str, dict[str, Any]],
) -> bool:
    if statement.get("Effect") != "Deny" or INVOKE_ACTION not in _actions(statement):
        return False
    principal = statement.get("Principal", {})
    not_principal = statement.get("NotPrincipal", {})
    if isinstance(not_principal, dict) and _is_orchestrator_arn(
        not_principal.get("AWS"), home, templates
    ):
        return True
    condition = statement.get("Condition", {})
    if not isinstance(condition, dict):
        return False
    arn_not_equals = condition.get("ArnNotEquals", {})
    if not isinstance(arn_not_equals, dict):
        return False
    excluded = arn_not_equals.get("aws:PrincipalArn")
    principal_aws = principal.get("AWS") if isinstance(principal, dict) else None
    everyone = principal_aws in ("*", ["*"])
    return everyone and _is_orchestrator_arn(excluded, home, templates)


def runtime_denies_non_orchestrator(
    template_name: str,
    runtime_logical_id: str,
    templates: dict[str, dict[str, Any]],
) -> bool:
    home = templates[template_name]
    for _, resource in _resources(home, "AWS::BedrockAgentCore::ResourcePolicy"):
        if not _targets_runtime(resource, runtime_logical_id):
            continue
        try:
            document, tokens = _policy_document(resource["Properties"].get("Policy"))
        except (json.JSONDecodeError, TypeError, ValueError):
            continue
        document = _resolve(document, tokens)
        statements = document.get("Statement", [])
        if isinstance(statements, dict):
            statements = [statements]
        if any(
            isinstance(statement, dict)
            and _denies_everyone_but_orchestrator(statement, home, templates)
            for statement in statements
        ):
            return True
    return False


def test_deploy_script_passes_a2a_off_when_the_variable_is_unset() -> None:
    pairs = _pairs(deploy_context_args())
    assert pairs.get("enable_a2a") == "false"


def test_deploy_script_keeps_an_explicit_a2a_opt_in() -> None:
    assert _pairs(deploy_context_args({"ENABLE_A2A": "true"})).get("enable_a2a") == "true"
    assert _pairs(deploy_context_args({"ENABLE_A2A": "false"})).get("enable_a2a") == "false"


def test_presets_keep_agent_to_agent_opt_in() -> None:
    sys.path.insert(0, str(REPO))
    from infra_utils.platform_config import load_platform_config, to_env

    greenfield = to_env(load_platform_config(REPO / "presets" / "greenfield.yaml"))
    multi_agent = to_env(load_platform_config(REPO / "presets" / "multi-agent.yaml"))
    platform_team = to_env(load_platform_config(REPO / "presets" / "platform-team.yaml"))
    assert greenfield["ENABLE_A2A"] == "false"
    assert multi_agent["ENABLE_A2A"] == "true"
    assert platform_team["ENABLE_A2A"] == "true"


def test_unset_flags_do_not_synthesize_agent_to_agent_runtimes(tmp_path: Path) -> None:
    templates = synth_app(tmp_path / "unset")
    names = " ".join(templates)
    for suffix in A2A_STACK_SUFFIXES:
        assert suffix not in names
    assert a2a_runtimes(templates) == []


def test_explicit_off_context_does_not_synthesize_agent_to_agent_runtimes(
    tmp_path: Path,
) -> None:
    templates = synth_app(tmp_path / "off", context={"enable_a2a": "false"})
    assert a2a_runtimes(templates) == []


def test_explicit_a2a_runtimes_reject_principals_other_than_the_orchestrator(
    tmp_path: Path,
) -> None:
    """Opt-in agent-to-agent deploys still have to close the same invoke path.

    The research runtime is the one that receives the platform machine
    credential provider name. The code runtime shares the authorizer-less A2A
    protocol, so a principal who can invoke it still runs Bedrock as that
    runtime. Both need the same resource-policy deny.
    """
    context = dict(_pairs(deploy_context_args({"ENABLE_A2A": "true"})))
    templates = synth_app(tmp_path / "on", context=context)
    runtimes = a2a_runtimes(templates)
    assert {name for name, _, _ in runtimes} == {
        "agentcore-workshop-dev-runtime-code-agent.template.json",
        "agentcore-workshop-dev-runtime-research-agent.template.json",
    }
    orchestrator = templates["agentcore-workshop-dev-runtime-orchestrator.template.json"]
    assert _orchestrator_role(orchestrator) is not None
    orch_runtime = _resources(orchestrator, "AWS::BedrockAgentCore::Runtime")[0][1]
    assert "AuthorizerConfiguration" in orch_runtime["Properties"]

    research = templates["agentcore-workshop-dev-runtime-research-agent.template.json"]
    identity = templates["agentcore-workshop-dev-identity.template.json"]
    provider_names = [
        resource["Properties"].get("Name")
        for _, resource in _resources(
            identity, "AWS::BedrockAgentCore::OAuth2CredentialProvider"
        )
    ]
    for template_name, logical_id, props in runtimes:
        assert "AuthorizerConfiguration" not in props
        assert runtime_denies_non_orchestrator(template_name, logical_id, templates), (
            f"{template_name} {logical_id} is protocol A2A with no JWT authorizer "
            "and no resource policy denying InvokeAgentRuntime to principals "
            "other than the orchestrator runtime role"
        )
        credential = props.get("EnvironmentVariables", {}).get(
            "GATEWAY_CREDENTIAL_PROVIDER_NAME"
        )
        if template_name.endswith("runtime-research-agent.template.json") and credential:
            assert credential in provider_names
            assert credential == "agentcore-workshop-dev-gateway-m2m"


def test_resource_policy_checker_rejects_a_policy_on_the_wrong_runtime() -> None:
    """The deny has to name the runtime it protects, not a sibling resource."""
    orchestrator_role = {
        "Type": "AWS::IAM::Role",
        "Properties": {"RoleName": "agentcore-workshop-dev-orchestrator-runtime-role"},
    }
    runtime = {
        "Type": "AWS::BedrockAgentCore::Runtime",
        "Properties": {"ProtocolConfiguration": "A2A"},
    }
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "DenyOtherPrincipals",
                "Effect": "Deny",
                "Principal": {"AWS": "*"},
                "Action": INVOKE_ACTION,
                "Resource": "*",
                "Condition": {
                    "ArnNotEquals": {
                        "aws:PrincipalArn": {"Fn::GetAtt": ["OrchestratorRole", "Arn"]}
                    }
                },
            }
        ],
    }
    home = {
        "Resources": {
            "OrchestratorRole": orchestrator_role,
            "Runtime": runtime,
            "OtherRuntime": runtime,
            "Policy": {
                "Type": "AWS::BedrockAgentCore::ResourcePolicy",
                "Properties": {
                    "ResourceArn": {"Fn::GetAtt": ["OtherRuntime", "AgentRuntimeArn"]},
                    "Policy": policy,
                },
            },
        }
    }
    templates = {"home.template.json": home}
    assert runtime_denies_non_orchestrator("home.template.json", "OtherRuntime", templates)
    assert not runtime_denies_non_orchestrator("home.template.json", "Runtime", templates)


def test_resource_policy_checker_accepts_a_joined_orchestrator_deny() -> None:
    role_arn = {"Fn::ImportValue": "agentcore-workshop-dev-orchestrator-role-arn"}
    document = {
        "Fn::Join": [
            "",
            [
                '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Principal":{"AWS":"*"},"Action":"',
                INVOKE_ACTION,
                '","Resource":"*","Condition":{"ArnNotEquals":{"aws:PrincipalArn":',
                role_arn,
                "}}}]}",
            ],
        ]
    }
    home = {
        "Resources": {
            "Runtime": {
                "Type": "AWS::BedrockAgentCore::Runtime",
                "Properties": {"ProtocolConfiguration": "A2A"},
            },
            "Policy": {
                "Type": "AWS::BedrockAgentCore::ResourcePolicy",
                "Properties": {
                    "ResourceArn": {"Fn::GetAtt": ["Runtime", "AgentRuntimeArn"]},
                    "Policy": document,
                },
            },
        }
    }
    orchestrator = {
        "Resources": {
            "RuntimeRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "RoleName": "agentcore-workshop-dev-orchestrator-runtime-role"
                },
            }
        },
        "Outputs": {
            "RoleArn": {
                "Value": {"Fn::GetAtt": ["RuntimeRole", "Arn"]},
                "Export": {"Name": "agentcore-workshop-dev-orchestrator-role-arn"},
            }
        },
    }
    templates = {
        "home.template.json": home,
        "orchestrator.template.json": orchestrator,
    }
    assert runtime_denies_non_orchestrator("home.template.json", "Runtime", templates)


def test_resource_policy_checker_rejects_a_deny_that_does_not_spare_the_orchestrator() -> None:
    home = {
        "Resources": {
            "Runtime": {
                "Type": "AWS::BedrockAgentCore::Runtime",
                "Properties": {"ProtocolConfiguration": "A2A"},
            },
            "Policy": {
                "Type": "AWS::BedrockAgentCore::ResourcePolicy",
                "Properties": {
                    "ResourceArn": {"Fn::GetAtt": ["Runtime", "AgentRuntimeArn"]},
                    "Policy": json.dumps(
                        {
                            "Version": "2012-10-17",
                            "Statement": [
                                {
                                    "Effect": "Deny",
                                    "Principal": {"AWS": "*"},
                                    "Action": INVOKE_ACTION,
                                    "Resource": "*",
                                }
                            ],
                        }
                    ),
                },
            },
        }
    }
    templates = {"home.template.json": home}
    assert not runtime_denies_non_orchestrator("home.template.json", "Runtime", templates)


@pytest.mark.parametrize(
    "statement",
    [
        {"Effect": "Allow", "Principal": "*", "Action": INVOKE_ACTION},
        {"Effect": "Deny", "Principal": {"AWS": "*"}, "Action": "s3:GetObject"},
    ],
)
def test_resource_policy_checker_ignores_statements_that_do_not_deny_invoke(
    statement: dict[str, Any],
) -> None:
    home: dict[str, Any] = {"Resources": {}}
    assert not _denies_everyone_but_orchestrator(statement, home, {})
