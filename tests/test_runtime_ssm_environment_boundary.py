"""A runtime role may read only its own environment's discovery parameters.

Two environments that share a project name (dev and prod) each publish
discovery parameters under /<project>/<environment>/. The runtime execution
role is what code inside that runtime — including a migrated customer
process, which is started with the runtime environment — uses to call
ssm:GetParameter and ssm:GetParameters. Those actions must not authorize
another environment's parameters, another region, or another account.

The IAM wildcard match below is the rule in "IAM JSON policy elements:
Resource" and "Action": `*` is any combination of characters (including
`/`), and `?` is one character. Action names are case-insensitive. An
explicit Deny overrides Allow; otherwise one matching Allow is enough for
a same-account request with no resource-based policy and no permissions
boundary. Parameter ARNs use the Systems Manager resource type
`parameter/${ParameterNameWithoutLeadingSlash}`.
"""

from __future__ import annotations

import importlib
import inspect
import json
import re
import sys
import types
from typing import Any

import aws_cdk as cdk
import pytest
from aws_cdk.assertions import Template

from infra_utils.agentcore_role import AgentCoreRole
from infra_utils.policy_loader import load_control
from stacks.auth_stack import AuthStack
from stacks.gateway_stack import GatewayStack
from stacks.identity_stack import IdentityStack
from stacks.runtime_stack import RuntimeStack

ACCOUNT = "111111111111"
OTHER_ACCOUNT = "222222222222"
REGION = "us-east-1"
OTHER_REGION = "eu-west-1"
PROJECT = "agentcore-workshop"
ENV = cdk.Environment(account=ACCOUNT, region=REGION)

# Names the attack reads. The auth stack also publishes the rest of the
# /auth/* interface; those are collected from the synthesized template.
ATTACK_SUFFIXES = (
    "auth/m2m-client-id",
    "auth/m2m-client-secret-name",
    "gateway/url",
)

SSM_ACTIONS = ("ssm:GetParameter", "ssm:GetParameters")


def _wildcard_match(pattern: str, value: str, *, ignore_case: bool = False) -> bool:
    """Match `pattern` against `value` using IAM `*` and `?` wildcards."""
    regex_parts: list[str] = []
    for char in pattern:
        if char == "*":
            regex_parts.append(".*")
        elif char == "?":
            regex_parts.append(".")
        else:
            regex_parts.append(re.escape(char))
    flags = re.IGNORECASE if ignore_case else 0
    return re.fullmatch("".join(regex_parts), value, flags) is not None


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _resolve(node: Any, *, region: str, account: str, partition: str = "aws") -> Any:
    """Resolve the CloudFormation intrinsics CDK uses for IAM resource ARNs."""
    if isinstance(node, list):
        return [
            _resolve(item, region=region, account=account, partition=partition)
            for item in node
        ]
    if not isinstance(node, dict) or len(node) != 1:
        return node

    if "Ref" in node:
        ref = node["Ref"]
        if ref == "AWS::Partition":
            return partition
        if ref == "AWS::Region":
            return region
        if ref == "AWS::AccountId":
            return account
        return node

    if "Fn::Join" in node:
        separator, parts = node["Fn::Join"]
        resolved_parts = [
            _resolve(part, region=region, account=account, partition=partition)
            for part in parts
        ]
        if any(isinstance(part, (dict, list)) for part in resolved_parts):
            return {"Fn::Join": [separator, resolved_parts]}
        return separator.join(str(part) for part in resolved_parts)

    if "Fn::Sub" in node:
        body = node["Fn::Sub"]
        if isinstance(body, str):
            template, mapping = body, {}
        else:
            template, mapping = body
        resolved_mapping = {
            key: _resolve(value, region=region, account=account, partition=partition)
            for key, value in mapping.items()
        }

        def replace(match: re.Match[str]) -> str:
            key = match.group(1)
            if key in resolved_mapping and isinstance(resolved_mapping[key], str):
                return resolved_mapping[key]
            pseudo = {
                "AWS::Partition": partition,
                "AWS::Region": region,
                "AWS::AccountId": account,
            }
            return pseudo.get(key, match.group(0))

        return re.sub(r"\$\{([^}]+)\}", replace, template)

    return node


def _must_string(value: Any, what: str) -> str:
    if not isinstance(value, str):
        raise AssertionError(f"could not resolve {what} to a string: {value!r}")
    return value


def _statement_matches(statement: dict[str, Any], action: str, resource_arn: str) -> bool:
    if "NotAction" in statement:
        blocked = any(
            _wildcard_match(str(pattern), action, ignore_case=True)
            for pattern in _as_list(statement["NotAction"])
        )
        if blocked:
            return False
    elif "Action" in statement:
        allowed = any(
            _wildcard_match(str(pattern), action, ignore_case=True)
            for pattern in _as_list(statement["Action"])
        )
        if not allowed:
            return False
    else:
        return False

    if "NotResource" in statement:
        patterns = [
            _must_string(item, "NotResource")
            for item in _as_list(statement["NotResource"])
        ]
        if any(_wildcard_match(pattern, resource_arn) for pattern in patterns):
            return False
    if "Resource" in statement:
        patterns = [
            _must_string(item, "Resource") for item in _as_list(statement["Resource"])
        ]
        if not any(_wildcard_match(pattern, resource_arn) for pattern in patterns):
            return False
    elif "NotResource" not in statement:
        return False

    # A Condition this harness does not interpret must not hide a resource
    # that still matches. The scoping fix is the resource ARN itself.
    return True


def identity_allows(
    statements: list[dict[str, Any]], action: str, resource_arn: str
) -> bool:
    """Same-account identity-policy result: Deny wins, else any Allow."""
    allowed = False
    for statement in statements:
        effect = statement.get("Effect", "Allow")
        if not _statement_matches(statement, action, resource_arn):
            continue
        if effect == "Deny":
            return False
        if effect == "Allow":
            allowed = True
    return allowed


def parameter_arn(name: str, *, region: str, account: str, partition: str = "aws") -> str:
    """SSM parameter ARN. `name` is the stored name, including its leading slash."""
    if not name.startswith("/"):
        raise AssertionError(f"parameter name {name!r} has no leading slash")
    without_leading_slash = name[1:]
    return (
        f"arn:{partition}:ssm:{region}:{account}:parameter/{without_leading_slash}"
    )


def _resources(template: dict[str, Any], resource_type: str) -> dict[str, dict[str, Any]]:
    return {
        logical_id: resource
        for logical_id, resource in template["Resources"].items()
        if resource["Type"] == resource_type
    }


def _runtime_role_ids(template: dict[str, Any]) -> list[str]:
    role_ids = []
    for resource in _resources(template, "AWS::BedrockAgentCore::Runtime").values():
        role_arn = resource["Properties"]["RoleArn"]
        target, attribute = role_arn["Fn::GetAtt"]
        assert attribute == "Arn"
        role_ids.append(target)
    if not role_ids:
        raise AssertionError("synthesized runtime has no execution role")
    return role_ids


def _statements_for_role(template: dict[str, Any], role_id: str) -> list[dict[str, Any]]:
    role = template["Resources"][role_id]
    assert role["Type"] == "AWS::IAM::Role"
    properties = role["Properties"]
    if properties.get("ManagedPolicyArns"):
        raise AssertionError(
            "runtime role attaches a managed policy this test cannot evaluate"
        )
    if properties.get("PermissionsBoundary"):
        raise AssertionError(
            "runtime role has a permissions boundary this test cannot evaluate"
        )

    statements: list[dict[str, Any]] = []
    for inline in _as_list(properties.get("Policies")):
        document = inline["PolicyDocument"]
        statements.extend(_as_list(document["Statement"]))
    for policy in _resources(template, "AWS::IAM::Policy").values():
        attached = any(
            item == {"Ref": role_id} for item in _as_list(policy["Properties"].get("Roles"))
        )
        if not attached:
            continue
        statements.extend(_as_list(policy["Properties"]["PolicyDocument"]["Statement"]))
    return [
        _resolve_statement(statement) for statement in statements if isinstance(statement, dict)
    ]


def _resolve_statement(statement: dict[str, Any]) -> dict[str, Any]:
    resolved = dict(statement)
    for key in ("Resource", "NotResource"):
        if key in resolved:
            resolved[key] = _resolve(resolved[key], region=REGION, account=ACCOUNT)
    return resolved


def runtime_statements(template: dict[str, Any]) -> list[dict[str, Any]]:
    statements: list[dict[str, Any]] = []
    for role_id in _runtime_role_ids(template):
        trust = template["Resources"][role_id]["Properties"]["AssumeRolePolicyDocument"]
        principals = [
            statement.get("Principal", {}).get("Service")
            for statement in _as_list(trust["Statement"])
            if statement.get("Effect", "Allow") == "Allow"
            and statement.get("Action") in ("sts:AssumeRole", ["sts:AssumeRole"])
        ]
        assert "bedrock-agentcore.amazonaws.com" in principals, principals
        statements.extend(_statements_for_role(template, role_id))
    return statements


def _synth_runtime(
    environment: str,
    component_name: str,
    *,
    migration: bool = False,
) -> dict[str, Any]:
    app = cdk.App()
    kwargs: dict[str, Any] = {}
    if migration:
        kwargs.update(
            build_context="migration/simulation/existing-ec2-agent",
            build_dockerfile="Dockerfile",
            adapter_dir="migration/adapter",
            migration_port="8000",
            migration_invoke_path="/invocations",
        )
    stack = RuntimeStack(
        app,
        f"runtime-{environment}-{component_name}",
        project_name=PROJECT,
        environment=environment,
        component_name=component_name,
        source_dir="agent-code",
        runtime_type="orchestrator" if component_name == "orchestrator" else "a2a_agent",
        env=ENV,
        **kwargs,
    )
    return Template.from_stack(stack).to_json()


def _synth_auth(environment: str, *, direct: bool = False) -> dict[str, Any]:
    app = cdk.App()
    extra: dict[str, Any] = {}
    if direct:
        extra = {
            "idp_type": "entra_id",
            "idp_mode": "direct",
            "idp_config": {
                "tenant_id": "22222222-3333-4444-5555-666666666666",
                "client_id": "placeholder-client-id",
                "client_secret_name": "placeholder-machine-secret-name",
            },
        }
    stack = AuthStack(
        app,
        f"auth-{environment}-{'direct' if direct else 'brokered'}",
        project_name=PROJECT,
        environment=environment,
        env=ENV,
        **extra,
    )
    return Template.from_stack(stack).to_json()


def _environment_templates(environment: str) -> dict[str, dict[str, Any]]:
    """One synthesis: auth, the identity stack that consumes it, and gateway."""
    app = cdk.App()
    auth = AuthStack(
        app,
        "auth",
        project_name=PROJECT,
        environment=environment,
        env=ENV,
    )
    identity = IdentityStack(
        app,
        "identity",
        project_name=PROJECT,
        environment=environment,
        gateway_m2m_client_id=auth.m2m_client_id,
        gateway_m2m_client_secret_name=auth.m2m_client_secret_name,
        cognito_discovery_url=auth.discovery_url,
        env=ENV,
    )
    GatewayStack(
        app,
        "gateway",
        project_name=PROJECT,
        environment=environment,
        cognito_issuer_url=f"https://cognito-idp.{REGION}.amazonaws.com/{REGION}_Example",
        cognito_allowed_clients=["placeholder-client-id"],
        env=ENV,
    )
    assembly = app.synth()
    return {
        "auth": assembly.get_stack_by_name("auth").template,
        "identity": assembly.get_stack_by_name("identity").template,
        "gateway": assembly.get_stack_by_name("gateway").template,
    }


def _parameter_names(template: dict[str, Any]) -> dict[str, dict[str, Any]]:
    names = {}
    for resource in _resources(template, "AWS::SSM::Parameter").values():
        name = resource["Properties"]["Name"]
        assert isinstance(name, str), name
        names[name] = resource["Properties"]
    return names


@pytest.fixture(scope="module")
def dev_runtime_templates() -> dict[str, dict[str, Any]]:
    return {
        "orchestrator": _synth_runtime("dev", "orchestrator"),
        "code-agent": _synth_runtime("dev", "code-agent"),
        "research-agent": _synth_runtime("dev", "research-agent"),
        "migration-orchestrator": _synth_runtime(
            "dev", "orchestrator", migration=True
        ),
    }


@pytest.fixture(scope="module")
def published() -> dict[str, Any]:
    dev = _environment_templates("dev")
    prod = _environment_templates("prod")
    return {
        "dev_auth": dev["auth"],
        "prod_auth": prod["auth"],
        "prod_auth_direct": _synth_auth("prod", direct=True),
        "dev_gateway": dev["gateway"],
        "prod_gateway": prod["gateway"],
        "prod_identity": prod["identity"],
        "dev_identity": dev["identity"],
    }


def _names_ending(parameters: dict[str, dict[str, Any]], suffix: str) -> str:
    matches = [name for name in parameters if name.endswith("/" + suffix)]
    assert len(matches) == 1, (suffix, sorted(parameters))
    return matches[0]


def test_iam_wildcard_matches_documented_slash_expansion() -> None:
    """The matcher follows the Resource element examples that `*` crosses `/`."""
    pattern = "arn:aws:s3:::amzn-s3-demo-bucket/*/test/*"
    matches = [
        "arn:aws:s3:::amzn-s3-demo-bucket/1/test/object.jpg",
        "arn:aws:s3:::amzn-s3-demo-bucket/1/2/test/object.jpg",
        "arn:aws:s3:::amzn-s3-demo-bucket/1/2/test/3/object.jpg",
        "arn:aws:s3:::amzn-s3-demo-bucket/1/2/3/test/4/object.jpg",
        "arn:aws:s3:::amzn-s3-demo-bucket/1///test///object.jpg",
        "arn:aws:s3:::amzn-s3-demo-bucket/1/test/.jpg",
        "arn:aws:s3:::amzn-s3-demo-bucket//test/object.jpg",
        "arn:aws:s3:::amzn-s3-demo-bucket/1/test/",
    ]
    for arn in matches:
        assert _wildcard_match(pattern, arn), arn
    assert not _wildcard_match(
        pattern, "arn:aws:s3:::amzn-s3-demo-bucket/1/2/test.jpg"
    )
    assert _wildcard_match("s3:*", "S3:GetObject", ignore_case=True)


def test_cloudformation_arn_join_resolves_before_matching() -> None:
    resolved = _resolve(
        {
            "Fn::Join": [
                "",
                [
                    "arn:",
                    {"Ref": "AWS::Partition"},
                    ":ssm:",
                    {"Ref": "AWS::Region"},
                    ":",
                    {"Ref": "AWS::AccountId"},
                    ":parameter/agentcore-workshop/dev/*",
                ],
            ]
        },
        region=REGION,
        account=ACCOUNT,
    )
    assert resolved == (
        f"arn:aws:ssm:{REGION}:{ACCOUNT}:parameter/agentcore-workshop/dev/*"
    )


def test_published_parameters_carry_client_identifiers_and_secret_name(
    published: dict[str, Any],
) -> None:
    auth = published["prod_auth"]
    parameters = _parameter_names(auth)
    clients = _resources(auth, "AWS::Cognito::UserPoolClient")
    pools = _resources(auth, "AWS::Cognito::UserPool")
    secrets = _resources(auth, "AWS::SecretsManager::Secret")
    assert pools and clients and secrets

    def referenced_client(suffix: str) -> dict[str, Any]:
        name = _names_ending(parameters, suffix)
        value = parameters[name]["Value"]
        assert isinstance(value, dict) and "Ref" in value, value
        return clients[value["Ref"]]["Properties"]

    m2m = referenced_client("auth/m2m-client-id")
    app_client = referenced_client("auth/app-client-id")
    web = referenced_client("auth/web-client-id")
    assert m2m["ClientName"].endswith("-m2m-client-v2")
    assert app_client["ClientName"].endswith("-app-client")
    assert web["ClientName"].endswith("-web-client")
    assert "client_credentials" in json.dumps(m2m["AllowedOAuthFlows"]) or (
        "client_credentials" in json.dumps(m2m)
    )

    pool_name = _names_ending(parameters, "auth/user-pool-id")
    pool_value = parameters[pool_name]["Value"]
    assert pool_value["Ref"] in pools

    secret_name = _names_ending(parameters, "auth/m2m-client-secret-name")
    secret_dump = json.dumps(parameters[secret_name]["Value"])
    assert any(logical_id in secret_dump for logical_id in secrets)
    # The parameter publishes the secret's name. The generated secret value
    # stays on the user-pool client and is not copied into this parameter.
    assert "UserPoolClient.ClientSecret" not in secret_dump
    assert "SecretString" not in secret_dump

    gateway = _parameter_names(published["prod_gateway"])
    gateway_value = gateway[_names_ending(gateway, "gateway/url")]["Value"]
    assert gateway_value["Fn::GetAtt"][1] == "GatewayUrl"

    identity = _parameter_names(published["prod_identity"])
    provider = identity[
        _names_ending(identity, "identity/gateway-credential-provider-name")
    ]
    assert isinstance(provider["Value"], str) and provider["Value"]


def _foreign_arns(published: dict[str, Any]) -> list[str]:
    names = []
    names.extend(_parameter_names(published["prod_auth"]))
    names.extend(_parameter_names(published["prod_auth_direct"]))
    names.extend(_parameter_names(published["prod_gateway"]))
    names.extend(_parameter_names(published["prod_identity"]))
    assert any(name.endswith("/" + suffix) for suffix in ATTACK_SUFFIXES for name in names)
    return [parameter_arn(name, region=REGION, account=ACCOUNT) for name in names]


def _own_arns(published: dict[str, Any]) -> list[str]:
    names = []
    names.extend(_parameter_names(published["dev_auth"]))
    names.extend(_parameter_names(published["dev_gateway"]))
    names.extend(_parameter_names(published["dev_identity"]))
    return [parameter_arn(name, region=REGION, account=ACCOUNT) for name in names]


def _assert_role_boundary(
    statements: list[dict[str, Any]], published: dict[str, Any], label: str
) -> None:
    for action in SSM_ACTIONS:
        for arn in _foreign_arns(published):
            assert not identity_allows(statements, action, arn), (
                f"{label} allows {action} on {arn}"
            )
        for arn in _own_arns(published):
            assert identity_allows(statements, action, arn), (
                f"{label} must still allow {action} on its own parameter {arn}"
            )
        own_name = f"/{PROJECT}/dev/auth/m2m-client-id"
        other_region = parameter_arn(own_name, region=OTHER_REGION, account=ACCOUNT)
        other_account = parameter_arn(own_name, region=REGION, account=OTHER_ACCOUNT)
        sibling = parameter_arn(
            f"/{PROJECT}/devops/auth/m2m-client-id", region=REGION, account=ACCOUNT
        )
        other_project = parameter_arn(
            "/other-project/dev/auth/m2m-client-id", region=REGION, account=ACCOUNT
        )
        for arn in (other_region, other_account, sibling, other_project):
            assert not identity_allows(statements, action, arn), (
                f"{label} allows {action} on {arn}"
            )


@pytest.mark.parametrize(
    "component",
    ["orchestrator", "code-agent", "research-agent", "migration-orchestrator"],
)
def test_dev_runtime_role_cannot_read_another_environments_parameters(
    component: str,
    dev_runtime_templates: dict[str, dict[str, Any]],
    published: dict[str, Any],
) -> None:
    template = dev_runtime_templates[component]
    runtime = next(iter(_resources(template, "AWS::BedrockAgentCore::Runtime").values()))
    env = runtime["Properties"]["EnvironmentVariables"]
    assert env["PROJECT_NAME"] == PROJECT
    assert env["ENVIRONMENT"] == "dev"
    # The runtime resource does not carry a session policy that could narrow
    # the execution role. The role's identity policy is the permission.
    assert "Policy" not in runtime["Properties"]
    _assert_role_boundary(runtime_statements(template), published, component)


def test_unused_agentcore_role_construct_has_the_same_boundary(
    published: dict[str, Any],
) -> None:
    signature = inspect.signature(AgentCoreRole.__init__)
    app = cdk.App()
    stack = cdk.Stack(app, "reference-role", env=ENV)
    kwargs: dict[str, Any] = {
        "project_name": PROJECT,
        "component_name": "orchestrator",
    }
    if "environment" in signature.parameters:
        kwargs["environment"] = "dev"
    AgentCoreRole(stack, "Role", **kwargs)
    template = Template.from_stack(stack).to_json()
    role_ids = [
        logical_id
        for logical_id, resource in template["Resources"].items()
        if resource["Type"] == "AWS::IAM::Role"
    ]
    assert len(role_ids) == 1
    _assert_role_boundary(
        _statements_for_role(template, role_ids[0]),
        published,
        "AgentCoreRole",
    )


def test_control_library_reference_policy_has_the_same_boundary(
    published: dict[str, Any],
) -> None:
    rendered = load_control(
        "iam.runtime-execution-least-privilege",
        {
            "region": REGION,
            "account_id": ACCOUNT,
            "project": PROJECT,
            "environment": "dev",
        },
    )
    _assert_role_boundary(
        [_resolve_statement(statement) for statement in rendered["Statement"]],
        published,
        "iam.runtime-execution-least-privilege",
    )


def _load_adapter():
    """Import the adapter. The SDK import is not on the env-copy path."""
    try:
        return importlib.import_module("migration.adapter.adapter")
    except ModuleNotFoundError as exc:
        if exc.name != "bedrock_agentcore":
            raise
    package = types.ModuleType("bedrock_agentcore")
    runtime = types.ModuleType("bedrock_agentcore.runtime")

    class BedrockAgentCoreApp:
        def entrypoint(self, function):
            return function

        def run(self):
            return None

    runtime.BedrockAgentCoreApp = BedrockAgentCoreApp
    package.runtime = runtime
    sys.modules["bedrock_agentcore"] = package
    sys.modules["bedrock_agentcore.runtime"] = runtime
    return importlib.import_module("migration.adapter.adapter")


def test_migrated_child_is_started_with_the_runtime_credential_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    adapter = _load_adapter()
    captured: dict[str, Any] = {}

    class _Process:
        def __init__(self) -> None:
            self.stderr = iter(())
            self.returncode = None

        def poll(self) -> None:
            return None

    def popen(cmd: list[str], **kwargs: Any) -> _Process:
        captured["cmd"] = cmd
        captured["kwargs"] = kwargs
        return _Process()

    monkeypatch.setattr(adapter.subprocess, "Popen", popen)
    parent = {
        "PATH": "/usr/bin",
        "PROJECT_NAME": PROJECT,
        "ENVIRONMENT": "dev",
        "AWS_ACCESS_KEY_ID": "placeholder-access-key",
        "AWS_SECRET_ACCESS_KEY": "placeholder-secret-key",
        "AWS_SESSION_TOKEN": "placeholder-session-token",
        "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI": "/placeholder/credentials",
    }
    child_env = adapter.build_child_env(dict(parent), {})
    child = adapter.Child(["/usr/bin/placeholder-agent"], child_env)
    child.start()

    assert captured["kwargs"]["env"]["AWS_ACCESS_KEY_ID"] == "placeholder-access-key"
    assert captured["kwargs"]["env"]["AWS_SECRET_ACCESS_KEY"] == "placeholder-secret-key"
    assert captured["kwargs"]["env"]["AWS_SESSION_TOKEN"] == "placeholder-session-token"
    assert (
        captured["kwargs"]["env"]["AWS_CONTAINER_CREDENTIALS_RELATIVE_URI"]
        == "/placeholder/credentials"
    )
    assert captured["kwargs"]["env"]["ENVIRONMENT"] == "dev"
    assert "preexec_fn" not in captured["kwargs"]
    assert captured["kwargs"].get("start_new_session") is not True
