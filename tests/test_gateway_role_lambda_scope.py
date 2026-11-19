"""The gateway role may invoke only the Lambda functions this stack registers.

AgentCore assumes the gateway execution role for a target whose credential
provider is GATEWAY_IAM_ROLE, then calls lambda:InvokeFunction. The Lambda
event is the tool arguments. In the same account an identity-policy allow is
enough; the function's resource policy is not required.

stacks/gateway_stack.py grants that action on
arn:aws:lambda:region:account:function:{prefix}-tool-*. The stack only creates
{prefix}-tool-{tool_name} for each tool_configs entry (app.py ships
sample-tool). These tests synthesize that stack and apply IAM resource
matching to the role the gateway actually uses. They fail while a name this
stack did not register is still authorized.
"""

from __future__ import annotations

import ast
import re
import tempfile
from pathlib import Path
from typing import Any

import aws_cdk as cdk
import pytest
from aws_cdk.assertions import Template

from stacks.gateway_stack import GatewayStack

REPO = Path(__file__).resolve().parents[1]
ACCOUNT = "111111111111"
REGION = "us-east-1"
ENV = cdk.Environment(account=ACCOUNT, region=REGION)
PARTITION = "aws"
INVOKE = "lambda:InvokeFunction"

ISSUER = "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_example"


def _app_tool_configs() -> dict[str, Any]:
    """The tool_configs literal app.py passes into GatewayStack."""
    tree = ast.parse((REPO / "app.py").read_text())
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if not isinstance(func, ast.Name) or func.id != "GatewayStack":
            continue
        for keyword in node.keywords:
            if keyword.arg == "tool_configs":
                return ast.literal_eval(keyword.value)
    raise AssertionError("app.py does not pass tool_configs to GatewayStack")


def _segment_regex(segment: str) -> str:
    """IAM wildcards inside one ARN segment: ``*`` any length, ``?`` one character."""
    parts: list[str] = []
    for char in segment:
        if char == "*":
            parts.append(".*")
        elif char == "?":
            parts.append(".")
        else:
            parts.append(re.escape(char))
    return "".join(parts)


def arn_matches(pattern: str, arn: str) -> bool:
    """Match an IAM Resource ARN pattern.

    Wildcards apply inside colon-separated segments. If ``*`` is the last
    character of the last segment, it also matches further segments, so a
    pattern that ends in ``name*`` matches ``name-other`` and ``name:1``.
    A pattern with no such star does not match a longer name or a qualifier.
    """
    pattern_segments = pattern.split(":")
    arn_segments = arn.split(":")
    if pattern_segments and pattern_segments[-1].endswith("*"):
        head = len(pattern_segments) - 1
        if len(arn_segments) < head:
            return False
        pairs = zip(pattern_segments[:-1], arn_segments[:head], strict=True)
        if not all(re.fullmatch(_segment_regex(left), right) for left, right in pairs):
            return False
        tail = ":".join(arn_segments[head:])
        return re.fullmatch(_segment_regex(pattern_segments[-1]), tail) is not None
    if len(pattern_segments) != len(arn_segments):
        return False
    return all(
        re.fullmatch(_segment_regex(left), right)
        for left, right in zip(pattern_segments, arn_segments, strict=True)
    )


def _action_matches(pattern: str, action: str) -> bool:
    """Action names are case-insensitive. ``*`` and ``?`` match the whole string."""
    return arn_matches(pattern.casefold(), action.casefold())


def _statement_actions_match(statement: dict[str, Any], action: str) -> bool:
    actions = statement.get("Action")
    not_actions = statement.get("NotAction")
    if actions is None and not_actions is None:
        return False
    if actions is not None:
        patterns = actions if isinstance(actions, list) else [actions]
        if not any(_action_matches(pattern, action) for pattern in patterns):
            return False
    if not_actions is not None:
        patterns = not_actions if isinstance(not_actions, list) else [not_actions]
        if any(_action_matches(pattern, action) for pattern in patterns):
            return False
    return True


def _values(node: Any) -> list[Any]:
    if node is None:
        return []
    if isinstance(node, list):
        return node
    return [node]


class _Unresolved(Exception):
    """A CloudFormation intrinsic this evaluator does not know how to expand."""


def _resolve(node: Any, resources: dict[str, Any]) -> str:
    if isinstance(node, str):
        return node
    if not isinstance(node, dict) or len(node) != 1:
        raise _Unresolved(node)
    key, value = next(iter(node.items()))
    if key == "Ref":
        refs = {
            "AWS::AccountId": ACCOUNT,
            "AWS::Region": REGION,
            "AWS::Partition": PARTITION,
        }
        if value not in refs:
            raise _Unresolved(node)
        return refs[value]
    if key == "Fn::Join":
        separator, parts = value
        return separator.join(_resolve(part, resources) for part in parts)
    if key == "Fn::Sub":
        if isinstance(value, list):
            template, mapping = value
        else:
            template, mapping = value, {}
        resolved_map = {
            name: _resolve(mapped, resources) for name, mapped in mapping.items()
        }

        def replace(match: re.Match[str]) -> str:
            name = match.group(1)
            if name in resolved_map:
                return resolved_map[name]
            pseudo = {
                "AWS::AccountId": ACCOUNT,
                "AWS::Region": REGION,
                "AWS::Partition": PARTITION,
            }
            if name in pseudo:
                return pseudo[name]
            if "." in name:
                logical_id, attribute = name.split(".", 1)
                return _get_att(logical_id, attribute, resources)
            raise _Unresolved(node)

        return re.sub(r"\$\{([^}]+)\}", replace, template)
    if key == "Fn::GetAtt":
        if isinstance(value, str):
            logical_id, attribute = value.split(".", 1)
        else:
            logical_id, attribute = value
        return _get_att(logical_id, attribute, resources)
    raise _Unresolved(node)


def _get_att(logical_id: str, attribute: str, resources: dict[str, Any]) -> str:
    resource = resources[logical_id]
    if resource["Type"] == "AWS::Lambda::Function" and attribute == "Arn":
        function_name = _resolve(resource["Properties"]["FunctionName"], resources)
        return f"arn:{PARTITION}:lambda:{REGION}:{ACCOUNT}:function:{function_name}"
    raise _Unresolved({"Fn::GetAtt": [logical_id, attribute]})


def _patterns(node: Any, resources: dict[str, Any]) -> list[str]:
    return [_resolve(item, resources) for item in _values(node)]


def _resources_match(
    statement: dict[str, Any], arn: str, resources: dict[str, Any]
) -> bool:
    if "Resource" in statement:
        patterns = _patterns(statement["Resource"], resources)
        if not any(arn_matches(pattern, arn) for pattern in patterns):
            return False
    elif "NotResource" not in statement:
        return False
    if "NotResource" in statement:
        patterns = _patterns(statement["NotResource"], resources)
        if any(arn_matches(pattern, arn) for pattern in patterns):
            return False
    return True


def _condition_holds(condition: dict[str, Any] | None, resource_arn: str) -> bool:
    """Missing keys and unknown operators do not satisfy the statement.

    The simulated request is the gateway role calling lambda:InvokeFunction
    on ``resource_arn`` in this account and region. A condition that does not
    distinguish that ARN from any other therefore cannot authorize one and
    refuse the other.
    """
    if not condition:
        return True
    request = {
        "aws:RequestedRegion": REGION,
        "aws:PrincipalAccount": ACCOUNT,
        "aws:ResourceAccount": ACCOUNT,
        "lambda:FunctionArn": resource_arn,
    }
    for operator, comparisons in condition.items():
        base = operator.split(":", 1)[-1]
        if base not in {
            "StringEquals",
            "StringNotEquals",
            "StringLike",
            "StringNotLike",
            "ArnEquals",
            "ArnNotEquals",
            "ArnLike",
            "ArnNotLike",
        }:
            return False
        negate = "Not" in base
        like = base.endswith("Like")
        for key, expected in comparisons.items():
            if key not in request:
                return False
            actual = request[key]
            expected_values = expected if isinstance(expected, list) else [expected]
            if like:
                matched = any(
                    _action_matches(str(candidate), actual)
                    for candidate in expected_values
                )
            else:
                matched = any(str(candidate) == actual for candidate in expected_values)
            if negate:
                matched = not matched
            if not matched:
                return False
    return True


def _statements_allow(
    statements: list[dict[str, Any]],
    arn: str,
    resources: dict[str, Any],
) -> bool:
    allowed = False
    for statement in statements:
        if not _statement_actions_match(statement, INVOKE):
            continue
        if not _resources_match(statement, arn, resources):
            continue
        if not _condition_holds(statement.get("Condition"), arn):
            continue
        effect = statement.get("Effect", "Allow")
        if effect == "Deny":
            return False
        if effect == "Allow":
            allowed = True
    return allowed


def _role_statements(
    template: dict[str, Any], role_logical_id: str
) -> list[dict[str, Any]]:
    resources = template["Resources"]
    role = resources[role_logical_id]
    collected: list[dict[str, Any]] = []
    for inline in _values(role["Properties"].get("Policies")):
        document = inline["PolicyDocument"]
        collected.extend(_values(document["Statement"]))
    for resource in resources.values():
        if resource["Type"] != "AWS::IAM::Policy":
            continue
        attached = False
        for role_ref in _values(resource["Properties"].get("Roles")):
            if role_ref == {"Ref": role_logical_id}:
                attached = True
            get_att = role_ref.get("Fn::GetAtt") if isinstance(role_ref, dict) else None
            if get_att in ([role_logical_id, "Arn"], f"{role_logical_id}.Arn"):
                attached = True
        if not attached:
            continue
        document = resource["Properties"]["PolicyDocument"]
        collected.extend(_values(document["Statement"]))
    if role["Properties"].get("PermissionsBoundary") or role["Properties"].get(
        "ManagedPolicyArns"
    ):
        raise AssertionError(
            "gateway role gained a managed policy or permissions boundary; "
            "evaluate that document before treating the inline policy as the "
            f"whole permission: {role['Properties']}"
        )
    return collected


def _gateway_role_id(template: dict[str, Any]) -> str:
    gateways = [
        resource
        for resource in template["Resources"].values()
        if resource["Type"] == "AWS::BedrockAgentCore::Gateway"
    ]
    assert len(gateways) == 1
    role_arn = gateways[0]["Properties"]["RoleArn"]
    get_att = role_arn["Fn::GetAtt"]
    if isinstance(get_att, str):
        return get_att.split(".", 1)[0]
    return get_att[0]


def _registered_lambda_arns(template: dict[str, Any]) -> list[str]:
    """Lambda ARNs of targets the stack registers with the gateway role."""
    found: list[str] = []
    for resource in template["Resources"].values():
        if resource["Type"] != "AWS::BedrockAgentCore::GatewayTarget":
            continue
        properties = resource["Properties"]
        providers = properties.get("CredentialProviderConfigurations") or []
        types = {provider.get("CredentialProviderType") for provider in providers}
        lambda_arn = (
            properties.get("TargetConfiguration", {})
            .get("Mcp", {})
            .get("Lambda", {})
            .get("LambdaArn")
        )
        if lambda_arn is None:
            continue
        assert types == {"GATEWAY_IAM_ROLE"}, types
        found.append(_resolve(lambda_arn, template["Resources"]))
    return found


def _function_arn(function_name: str) -> str:
    return f"arn:{PARTITION}:lambda:{REGION}:{ACCOUNT}:function:{function_name}"


def _prefix(template: dict[str, Any]) -> str:
    gateways = [
        resource
        for resource in template["Resources"].values()
        if resource["Type"] == "AWS::BedrockAgentCore::Gateway"
    ]
    name = gateways[0]["Properties"]["Name"]
    assert isinstance(name, str) and name.endswith("-gateway"), name
    return name[: -len("-gateway")]


def synthesize(**kwargs: Any) -> dict[str, Any]:
    with tempfile.TemporaryDirectory() as outdir:
        app = cdk.App(outdir=outdir)
        GatewayStack(
            app,
            "GatewayUnderTest",
            project_name=kwargs.pop("project_name", "agentcore-workshop"),
            environment=kwargs.pop("environment", "dev"),
            cognito_issuer_url=ISSUER,
            cognito_allowed_clients=["client"],
            env=ENV,
            **kwargs,
        )
        assembly = app.synth()
        stack = next(stack for stack in assembly.stacks if stack.stack_name)
        return Template.from_json(stack.template).to_json()


def _allows(template: dict[str, Any], function_name: str) -> bool:
    role_id = _gateway_role_id(template)
    statements = _role_statements(template, role_id)
    return _statements_allow(
        statements, _function_arn(function_name), template["Resources"]
    )


def _assert_only_registered_functions(template: dict[str, Any]) -> None:
    registered = _registered_lambda_arns(template)
    prefix = _prefix(template)
    for arn in registered:
        name = arn.rsplit(":", 1)[-1]
        assert _allows(template, name), (
            f"{name} is a Lambda target this stack registers, and the gateway "
            "role must still be able to invoke it"
        )
        extended = f"{name}-extra"
        assert not _allows(template, extended), (
            f"the gateway role can invoke {extended}, a different function "
            f"whose name merely continues {name}. Resource patterns that end "
            "in a wildcard still match it."
        )
    capture = f"{prefix}-tool-capture"
    assert capture not in {arn.rsplit(":", 1)[-1] for arn in registered}
    assert not _allows(template, capture), (
        f"the gateway role can invoke {capture}, which this stack does not "
        "create. A principal who can create that function and register it as "
        "a Lambda gateway target receives later tool arguments."
    )
    assert not _allows(template, "unrelated-function")


def test_arn_wildcards_follow_iam_segment_rules() -> None:
    """Examples from the IAM Resource element: ``*`` matches inside a segment.

    The documented S3 pattern matches keys with extra path pieces, and does
    not match keys that lack the literal ``/test/`` separator. A trailing
    ``*`` is the last character of its segment, so it also matches past the
    next colon; an exact function ARN does not.
    """
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
    rejects = [
        "arn:aws:s3:::amzn-s3-demo-bucket/1-test/object.jpg",
        "arn:aws:s3:::amzn-s3-demo-bucket/test/object.jpg",
        "arn:aws:s3:::amzn-s3-demo-bucket/1/2/test.jpg",
    ]
    for arn in matches:
        assert arn_matches(pattern, arn), arn
    for arn in rejects:
        assert not arn_matches(pattern, arn), arn

    exact = "arn:aws:lambda:us-east-1:111111111111:function:my-function"
    starred = exact + "*"
    assert arn_matches(starred, exact)
    assert arn_matches(starred, exact + "-extra")
    assert arn_matches(starred, exact + ":1")
    assert arn_matches(exact, exact)
    assert not arn_matches(exact, exact + "-extra")
    assert not arn_matches(exact, exact + ":1")


def test_shipped_tool_config_rejects_an_unregistered_function() -> None:
    """app.py's gateway, including web search (on in the default region)."""
    template = synthesize(
        tool_configs=_app_tool_configs(),
        enable_web_search=True,
    )
    registered = _registered_lambda_arns(template)
    assert [arn.rsplit(":", 1)[-1] for arn in registered] == [
        "agentcore-workshop-dev-tool-sample-tool"
    ]
    _assert_only_registered_functions(template)


@pytest.mark.parametrize(
    "kwargs",
    [
        {"tool_configs": _app_tool_configs()},
        {
            "tool_configs": _app_tool_configs(),
            "enable_web_search": True,
            "enable_cedar": True,
            "cedar_mode": "ENFORCE",
            "enable_egress_filter": True,
            "kms_key_arn": "arn:aws:kms:us-east-1:111111111111:key/example",
        },
        {
            "project_name": "prodtest",
            "environment": "prod",
            "tool_configs": {
                "sample-tool": {
                    "source_dir": "tools/sample_tool",
                    "env_vars": {},
                    "tool_schema": [],
                },
                "other-tool": {
                    "source_dir": "tools/sample_tool",
                    "env_vars": {},
                    "tool_schema": [],
                },
            },
        },
    ],
    ids=["sample-tool", "flags-on", "two-tools"],
)
def test_registered_targets_are_the_only_invocable_functions(
    kwargs: dict[str, Any],
) -> None:
    template = synthesize(**kwargs)
    registered_names = {
        arn.rsplit(":", 1)[-1] for arn in _registered_lambda_arns(template)
    }
    assert registered_names == {
        f"{_prefix(template)}-tool-{tool_name}" for tool_name in kwargs["tool_configs"]
    }
    _assert_only_registered_functions(template)


def test_role_without_tools_cannot_invoke_a_prefixed_function() -> None:
    """The invoke grant is installed even when tool_configs is empty."""
    template = synthesize()
    assert _registered_lambda_arns(template) == []
    capture = f"{_prefix(template)}-tool-capture"
    assert not _allows(template, capture), (
        f"with no Lambda targets, the gateway role can still invoke {capture}"
    )


def test_other_account_function_is_not_invocable() -> None:
    template = synthesize(tool_configs=_app_tool_configs())
    role_id = _gateway_role_id(template)
    statements = _role_statements(template, role_id)
    foreign = (
        "arn:aws:lambda:us-east-1:222222222222:function:"
        "agentcore-workshop-dev-tool-capture"
    )
    assert not _statements_allow(statements, foreign, template["Resources"])
