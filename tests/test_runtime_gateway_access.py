"""A runtime execution role must not read or call every gateway in the account.

The orchestrator, the code and research agents, and a migration runtime each
receive the role built in ``stacks/runtime_stack.py``. These tests synthesize
that stack, follow the role attached to ``AWS::BedrockAgentCore::Runtime``, and
evaluate the identity policy the way IAM does for a same-account call made with
that role's credentials.

They fail while ``ListGateways``, ``GetGateway``, and ``InvokeGateway`` are
allowed on every gateway. They pass once ``ListGateways`` is absent and
``GetGateway`` and ``InvokeGateway`` do not apply to a gateway this deployment
did not create.

Actions left on the same unscoped statement, and not asserted here, are
``InvokeAgentRuntime``, ``CreateEvent``, ``GetEvent``, ``ListEvents``,
``DeleteEvent``, ``ListSessions``, ``RetrieveMemoryRecords``,
``StartBrowserSession``, ``StopBrowserSession``,
``ConnectBrowserAutomationStream``, ``GetResourceOauth2Token``,
``CreateWorkloadIdentity``, ``GetWorkloadAccessToken``,
``GetWorkloadAccessTokenForJWT``, and ``GetWorkloadAccessTokenForUserId``.
The gateway service role's separate ``InvokeGateway`` grant (web search) is a
different principal and is not this role.
"""

from __future__ import annotations

import re
from functools import lru_cache
from typing import Any

import aws_cdk as cdk
import botocore.session
import pytest
from aws_cdk.assertions import Template

from stacks.runtime_stack import RuntimeStack

ACCOUNT = "111111111111"
REGION = "us-east-1"
ENV = cdk.Environment(account=ACCOUNT, region=REGION)
FOREIGN_GATEWAY = (
    f"arn:aws:bedrock-agentcore:{REGION}:{ACCOUNT}:gateway/otherteamgw-0123456789"
)
OTHER_REGION_GATEWAY = (
    "arn:aws:bedrock-agentcore:us-west-2:"
    f"{ACCOUNT}:gateway/otherteamgw-0123456789"
)
THIS_DEPLOYMENT_GATEWAY = (
    f"arn:aws:bedrock-agentcore:{REGION}:{ACCOUNT}:gateway/thisdeploy-0123456789"
)

# ListGateways has no resource type in the service authorization reference, so
# the request resource is "*" and a statement names every resource to allow it.
LIST_RESOURCE = "*"

PSEUDO = {
    "AWS::Partition": "aws",
    "AWS::Region": REGION,
    "AWS::AccountId": ACCOUNT,
    "AWS::URLSuffix": "amazonaws.com",
}

# Operators whose documented result is true when the key is absent.
_NEGATED = {
    "StringNotEquals",
    "StringNotEqualsIgnoreCase",
    "StringNotLike",
    "ArnNotEquals",
    "ArnNotLike",
}


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _glob(pattern: str, text: str) -> bool:
    """'*' is any sequence and '?' is one character, including ':'."""
    parts = []
    for char in pattern:
        if char == "*":
            parts.append(".*")
        elif char == "?":
            parts.append(".")
        else:
            parts.append(re.escape(char))
    return re.fullmatch("".join(parts), text) is not None


def arn_match(pattern: str, value: str) -> bool:
    """Match an IAM Resource ARN pattern.

    Wildcards apply inside colon-separated segments. A '*' that ends a segment
    may also consume later segments.
    """
    if pattern == "*":
        return True
    return _segments(pattern.split(":"), value.split(":"))


def _segments(pattern: list[str], value: list[str]) -> bool:
    if not pattern:
        return not value
    head = pattern[0]
    if head.endswith("*"):
        for take in range(1, len(value) + 1):
            chunk = ":".join(value[:take])
            if _glob(head, chunk) and _segments(pattern[1:], value[take:]):
                return True
        return False
    if not value or not _glob(head, value[0]):
        return False
    return _segments(pattern[1:], value[1:])


def action_match(pattern: str, action: str) -> bool:
    return _glob(pattern.casefold(), action.casefold())


def _substitute(pattern: str, context: dict[str, list[str]]) -> str:
    def repl(match: re.Match[str]) -> str:
        values = context.get(match.group(1))
        if values and len(values) == 1:
            return values[0]
        return match.group(0)

    return re.sub(r"\$\{([^}]+)\}", repl, pattern)


def _concretize(node: Any, context: dict[str, list[str]]) -> str | None | bool:
    """Return a string, False for a specific template resource, or True when
    the node is an intrinsic this evaluator cannot prove is a single resource.
    """
    if isinstance(node, str):
        return _substitute(node, context)
    if not isinstance(node, dict) or len(node) != 1:
        return True
    key, body = next(iter(node.items()))
    if key == "Ref":
        if body in PSEUDO:
            return PSEUDO[body]
        return False
    if key == "Fn::GetAtt" or key == "Fn::ImportValue":
        return False
    if key == "Fn::Join":
        delimiter, parts = body
        rendered = [_concretize(part, context) for part in parts]
        if any(part is False for part in rendered):
            return False
        if any(part is True or not isinstance(part, str) for part in rendered):
            return True
        return delimiter.join(rendered)
    if key == "Fn::Sub":
        if isinstance(body, str):
            template, mapping = body, {}
        else:
            template, mapping = body
        resolved_map = {}
        for name, raw in mapping.items():
            value = _concretize(raw, context)
            if value is False:
                return False
            if not isinstance(value, str):
                return True
            resolved_map[name] = [value]
        combined = {**context, **resolved_map}

        def repl(match: re.Match[str]) -> str:
            name = match.group(1)
            if name in PSEUDO and name not in mapping:
                return PSEUDO[name]
            values = combined.get(name)
            if values and len(values) == 1:
                return values[0]
            return match.group(0)

        rendered = re.sub(r"\$\{([^}]+)\}", repl, template)
        if "${" in rendered:
            return False
        return rendered
    return True


def resource_matches(node: Any, request_resource: str, context: dict[str, list[str]]) -> bool:
    concrete = _concretize(node, context)
    if concrete is False:
        return False
    if concrete is True or not isinstance(concrete, str):
        # An unrecognized resource element is not evidence that the foreign
        # gateway was excluded.
        return True
    return arn_match(concrete, request_resource)


def _values(node: Any, context: dict[str, list[str]]) -> list[str] | None:
    rendered = []
    for item in _as_list(node):
        concrete = _concretize(item, context)
        if not isinstance(concrete, str):
            return None
        rendered.append(concrete)
    return rendered


_KNOWN = {
    "StringEquals",
    "StringNotEquals",
    "StringEqualsIgnoreCase",
    "StringNotEqualsIgnoreCase",
    "StringLike",
    "StringNotLike",
    "ArnEquals",
    "ArnLike",
    "ArnNotEquals",
    "ArnNotLike",
    "Bool",
}


def _positive_match(operator: str, policy_value: str, request_value: str) -> bool:
    """Positive match for one pair. Negation is applied by the caller."""
    ignore_case = "IgnoreCase" in operator
    left, right = (policy_value, request_value)
    if ignore_case or operator == "Bool":
        left, right = left.casefold(), right.casefold()
    if operator.startswith("String") and "Like" not in operator or operator == "Bool":
        return left == right
    if "Like" in operator and operator.startswith("String"):
        return _glob(left, right)
    if operator.startswith("Arn"):
        return arn_match(left, right)
    return True


def _operator_matches(
    operator: str,
    policy_values: list[str],
    request_values: list[str] | None,
) -> bool:
    """Evaluate one condition operator.

    Several policy values for one key are a logical OR of the operator, except
    the ForAllValues and ForAnyValue qualifiers, which use the set rules.
    An operator this function does not implement returns True, so an unread
    restriction cannot make a still-broad allow look denied.
    """
    if operator == "Null":
        expects_absent = policy_values[0].casefold() == "true"
        return expects_absent == (request_values is None)

    qualifier = None
    base = operator
    if base.startswith("ForAllValues:"):
        qualifier, base = "all", base.split(":", 1)[1]
    elif base.startswith("ForAnyValue:"):
        qualifier, base = "any", base.split(":", 1)[1]
    if_exists = base.endswith("IfExists")
    if if_exists:
        base = base[: -len("IfExists")]
    negated = base in _NEGATED
    if base not in _KNOWN:
        return True

    if request_values is None:
        if if_exists or qualifier == "all":
            return True
        if negated:
            return True
        return False

    def matches_value(request_value: str) -> bool:
        hits = [
            _positive_match(base, policy_value, request_value)
            for policy_value in policy_values
        ]
        return (not any(hits)) if negated else any(hits)

    if qualifier == "all":
        return all(matches_value(request_value) for request_value in request_values)
    return any(matches_value(request_value) for request_value in request_values)


def condition_matches(condition: dict[str, Any] | None, context: dict[str, list[str]]) -> bool:
    if not condition:
        return True
    for operator, keys in condition.items():
        for key, raw_values in keys.items():
            policy_values = _values(raw_values, context)
            if policy_values is None:
                return True
            if not _operator_matches(operator, policy_values, context.get(key)):
                return False
    return True


def statement_applies(
    statement: dict[str, Any],
    action: str,
    resource: str,
    context: dict[str, list[str]],
) -> bool:
    actions = _as_list(statement.get("Action"))
    not_actions = _as_list(statement.get("NotAction"))
    if actions and not any(
        isinstance(item, str) and action_match(item, action) for item in actions
    ):
        if any(not isinstance(item, str) for item in actions):
            pass
        else:
            return False
    if not actions and not not_actions:
        return False
    if not_actions and any(
        isinstance(item, str) and action_match(item, action) for item in not_actions
    ):
        return False
    if "Resource" in statement:
        matched = any(
            resource_matches(item, resource, context)
            for item in _as_list(statement["Resource"])
        )
    elif "NotResource" in statement:
        matched = not any(
            resource_matches(item, resource, context)
            for item in _as_list(statement["NotResource"])
        )
    else:
        matched = False
    if not matched:
        return False
    return condition_matches(statement.get("Condition"), context)


def identity_decision(
    statements: list[dict[str, Any]],
    action: str,
    resource: str,
    context: dict[str, list[str]],
) -> str:
    """Identity-policy decision. Implicit deny, and an explicit deny wins."""
    applicable = [
        statement
        for statement in statements
        if statement_applies(statement, action, resource, context)
    ]
    if any(statement.get("Effect") == "Deny" for statement in applicable):
        return "Deny"
    if any(statement.get("Effect", "Allow") == "Allow" for statement in applicable):
        return "Allow"
    return "Deny"


def _resources(template: dict[str, Any], resource_type: str) -> dict[str, dict[str, Any]]:
    return {
        logical_id: resource
        for logical_id, resource in template["Resources"].items()
        if resource["Type"] == resource_type
    }


def runtime_role_statements(
    template: dict[str, Any],
) -> tuple[list[dict[str, Any]], dict[str, list[str]]]:
    runtimes = _resources(template, "AWS::BedrockAgentCore::Runtime")
    assert len(runtimes) == 1
    role_arn = next(iter(runtimes.values()))["Properties"]["RoleArn"]
    assert role_arn.get("Fn::GetAtt"), role_arn
    role_id, attribute = role_arn["Fn::GetAtt"]
    assert attribute == "Arn"
    role = template["Resources"][role_id]
    assert role["Type"] == "AWS::IAM::Role"
    properties = role["Properties"]
    assert "PermissionsBoundary" not in properties
    assert not properties.get("ManagedPolicyArns")
    assert properties["AssumeRolePolicyDocument"]["Statement"] == [
        {
            "Action": "sts:AssumeRole",
            "Effect": "Allow",
            "Principal": {"Service": "bedrock-agentcore.amazonaws.com"},
        }
    ]
    role_name = properties["RoleName"]
    assert isinstance(role_name, str)
    context = {
        "aws:PrincipalAccount": [ACCOUNT],
        "aws:PrincipalArn": [f"arn:aws:iam::{ACCOUNT}:role/{role_name}"],
        "aws:PrincipalType": ["AssumedRole"],
        "aws:ResourceAccount": [ACCOUNT],
        "aws:SecureTransport": ["true"],
        "aws:ViaAWSService": ["false"],
    }
    for tag in properties.get("Tags") or []:
        context[f"aws:PrincipalTag/{tag['Key']}"] = [tag["Value"]]

    statements: list[dict[str, Any]] = []
    for policy in _resources(template, "AWS::IAM::Policy").values():
        attached = policy["Properties"].get("Roles") or []
        if {"Ref": role_id} not in attached:
            continue
        document = policy["Properties"]["PolicyDocument"]
        statements.extend(_as_list(document["Statement"]))
    for inline in properties.get("Policies") or []:
        statements.extend(_as_list(inline["PolicyDocument"]["Statement"]))
    assert statements, "runtime role has no identity policy"
    return statements, context


@lru_cache
def synthesized(kind: str) -> dict[str, Any]:
    app = cdk.App()
    common = {
        "project_name": "acme",
        "environment": "dev",
        "source_dir": "agent-code",
        "env": ENV,
    }
    if kind == "orchestrator":
        stack = RuntimeStack(
            app,
            "Runtime",
            component_name="orchestrator",
            runtime_type="orchestrator",
            dockerfile_pattern="orchestrator",
            **common,
        )
    elif kind == "code-agent":
        stack = RuntimeStack(
            app,
            "Runtime",
            component_name="code-agent",
            runtime_type="a2a_agent",
            dockerfile_pattern="code-agent",
            **common,
        )
    elif kind == "research-agent":
        stack = RuntimeStack(
            app,
            "Runtime",
            component_name="research-agent",
            runtime_type="a2a_agent",
            dockerfile_pattern="research-agent",
            **common,
        )
    elif kind == "migration-orchestrator":
        stack = RuntimeStack(
            app,
            "Runtime",
            component_name="orchestrator",
            runtime_type="orchestrator",
            build_context="migration/simulation/existing-ec2-agent",
            build_dockerfile="Dockerfile",
            adapter_dir="migration/adapter",
            migration_port="8000",
            migration_invoke_path="/run",
            migration_health_path="/healthz",
            migration_secret_names=["API_TOKEN"],
            **common,
        )
    else:
        raise AssertionError(kind)
    template = Template.from_stack(stack).to_json()
    assert "AWS::BedrockAgentCore::Gateway" not in {
        resource["Type"] for resource in template["Resources"].values()
    }
    return template


def _context_for(resource: str, base: dict[str, list[str]]) -> dict[str, list[str]]:
    context = dict(base)
    if resource == LIST_RESOURCE:
        context["aws:RequestedRegion"] = [REGION]
    else:
        context["aws:RequestedRegion"] = [resource.split(":")[3]]
    return context


@pytest.mark.parametrize(
    ("policy_resource", "action", "request_resource", "expected"),
    [
        ("*", "bedrock-agentcore:GetGateway", FOREIGN_GATEWAY, "Allow"),
        (
            f"arn:aws:bedrock-agentcore:{REGION}:{ACCOUNT}:gateway/*",
            "bedrock-agentcore:GetGateway",
            FOREIGN_GATEWAY,
            "Allow",
        ),
        (
            f"arn:aws:bedrock-agentcore:*:*:gateway/*",
            "bedrock-agentcore:InvokeGateway",
            OTHER_REGION_GATEWAY,
            "Allow",
        ),
        (THIS_DEPLOYMENT_GATEWAY, "bedrock-agentcore:GetGateway", FOREIGN_GATEWAY, "Deny"),
        (THIS_DEPLOYMENT_GATEWAY, "bedrock-agentcore:GetGateway", THIS_DEPLOYMENT_GATEWAY, "Allow"),
        ("*", "bedrock-agentcore:ListGateways", LIST_RESOURCE, "Allow"),
        (THIS_DEPLOYMENT_GATEWAY, "bedrock-agentcore:ListGateways", LIST_RESOURCE, "Deny"),
    ],
)
def test_evaluator_follows_iam_resource_and_action_wildcards(
    policy_resource: str, action: str, request_resource: str, expected: str
) -> None:
    statements = [
        {"Effect": "Allow", "Action": action, "Resource": policy_resource}
    ]
    context = _context_for(
        request_resource,
        {"aws:ResourceAccount": [ACCOUNT], "aws:PrincipalAccount": [ACCOUNT]},
    )
    assert identity_decision(statements, action, request_resource, context) == expected


def test_explicit_deny_overrides_an_allow_on_the_same_gateway() -> None:
    statements = [
        {"Effect": "Allow", "Action": "bedrock-agentcore:GetGateway", "Resource": "*"},
        {"Effect": "Deny", "Action": "bedrock-agentcore:GetGateway", "Resource": "*"},
    ]
    assert (
        identity_decision(statements, "bedrock-agentcore:GetGateway", FOREIGN_GATEWAY, {})
        == "Deny"
    )


def test_missing_key_and_negated_or_forall_conditions_do_not_hide_an_allow() -> None:
    """A condition that is true when the foreign gateway lacks the key is not a fix."""
    absent_not_equals = {
        "Effect": "Allow",
        "Action": "bedrock-agentcore:GetGateway",
        "Resource": "*",
        "Condition": {"StringNotEquals": {"aws:ResourceTag/team": "acme"}},
    }
    for_all_missing = {
        "Effect": "Allow",
        "Action": "bedrock-agentcore:GetGateway",
        "Resource": "*",
        "Condition": {"ForAllValues:StringEquals": {"aws:ResourceTag/team": "acme"}},
    }
    absent_equals = {
        "Effect": "Allow",
        "Action": "bedrock-agentcore:GetGateway",
        "Resource": "*",
        "Condition": {"StringEquals": {"aws:ResourceTag/team": "acme"}},
    }
    assert identity_decision([absent_not_equals], "bedrock-agentcore:GetGateway", FOREIGN_GATEWAY, {}) == "Allow"
    assert identity_decision([for_all_missing], "bedrock-agentcore:GetGateway", FOREIGN_GATEWAY, {}) == "Allow"
    assert identity_decision([absent_equals], "bedrock-agentcore:GetGateway", FOREIGN_GATEWAY, {}) == "Deny"


def test_get_gateway_returns_authorizer_role_key_protocol_and_interceptors() -> None:
    model = botocore.session.Session().get_service_model("bedrock-agentcore-control")
    members = set(model.operation_model("GetGateway").output_shape.members)
    assert {
        "authorizerConfiguration",
        "authorizerType",
        "roleArn",
        "kmsKeyArn",
        "protocolConfiguration",
        "protocolType",
        "interceptorConfigurations",
    } <= members
    summary = model.shape_for("GatewaySummary").members
    assert {"gatewayId", "authorizerType", "protocolType"} <= set(summary)
    listed = set(model.operation_model("ListGateways").output_shape.members)
    assert "items" in listed
    assert model.metadata["signingName"] == "bedrock-agentcore"


ROLES = ("orchestrator", "code-agent", "research-agent", "migration-orchestrator")
CALLS = (
    ("bedrock-agentcore:ListGateways", LIST_RESOURCE),
    ("bedrock-agentcore:GetGateway", FOREIGN_GATEWAY),
    ("bedrock-agentcore:GetGateway", OTHER_REGION_GATEWAY),
    ("bedrock-agentcore:InvokeGateway", FOREIGN_GATEWAY),
    ("bedrock-agentcore:InvokeGateway", OTHER_REGION_GATEWAY),
)


@pytest.mark.parametrize("kind", ROLES)
@pytest.mark.parametrize(("action", "resource"), CALLS)
def test_runtime_role_cannot_read_or_invoke_another_teams_gateway(
    kind: str, action: str, resource: str
) -> None:
    template = synthesized(kind)
    statements, base = runtime_role_statements(template)
    context = _context_for(resource, base)
    decision = identity_decision(statements, action, resource, context)
    assert decision == "Deny", (
        f"{kind} execution role {decision}s {action} on {resource}. "
        "ListGateways must be removed. GetGateway and InvokeGateway must be "
        "limited to the gateway this runtime is meant to call, not every "
        "gateway in the account."
    )
