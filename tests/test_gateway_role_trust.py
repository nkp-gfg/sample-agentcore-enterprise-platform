"""The gateway execution role must be assumable only by this gateway.

GatewayStack passes the role to the gateway (RoleArn) and registers Lambda
targets with GATEWAY_IAM_ROLE. The service then assumes the role and calls
lambda:InvokeFunction. These tests synthesize that stack and evaluate the
trust policy and identity policy the template installs.

IAM rules the evaluator follows, from the IAM User Guide:

- A missing Condition matches. A missing context key makes a condition false,
  except IfExists and the Null operator.
- Operators and keys in one Condition are AND. Multiple values of one key are
  OR. Negated operators with multiple values are NOR.
- An explicit Deny overrides Allow. Allow statements are a union.
- StringEquals is case-sensitive. ArnLike and ArnEquals compare colon segments
  case-sensitively; a * that ends a segment may cross later colons, and * inside
  a segment also matches '/'.
"""

from __future__ import annotations

import re
from typing import Any

import aws_cdk as cdk
from aws_cdk.assertions import Template

from stacks.gateway_stack import GatewayStack

ACCOUNT = "111111111111"
OTHER_ACCOUNT = "999999999999"
REGION = "us-east-1"
PROJECT = "prodtest"
ENVIRONMENT = "prod"
PREFIX = f"{PROJECT}-{ENVIRONMENT}"
ISSUER = "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_example"
ENV = cdk.Environment(account=ACCOUNT, region=REGION)

# Fits the control-plane gateway id pattern and is not this stack's gateway.
OTHER_GATEWAY_ID = "notthisgateway-aaaaaaaaaa"


def synthesize(tool_names: list[str], **flags: Any) -> dict[str, Any]:
    tool_configs = {
        name: {
            "source_dir": "tools/sample_tool",
            "env_vars": {},
            "tool_schema": [],
        }
        for name in tool_names
    }
    app = cdk.App()
    stack = GatewayStack(
        app,
        "GatewayUnderTest",
        project_name=PROJECT,
        environment=ENVIRONMENT,
        cognito_issuer_url=ISSUER,
        cognito_allowed_clients=["client"],
        tool_configs=tool_configs or None,
        env=ENV,
        **flags,
    )
    return Template.from_stack(stack).to_json()


def _resources(template: dict[str, Any], resource_type: str) -> list[tuple[str, dict]]:
    return [
        (logical_id, resource)
        for logical_id, resource in template["Resources"].items()
        if resource["Type"] == resource_type
    ]


def _statements(document: dict[str, Any]) -> list[dict[str, Any]]:
    statement = document.get("Statement", [])
    if isinstance(statement, dict):
        return [statement]
    return list(statement)


def _gateway(template: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    found = _resources(template, "AWS::BedrockAgentCore::Gateway")
    assert len(found) == 1, found
    return found[0]


def _role_logical_id(template: dict[str, Any]) -> tuple[str, str]:
    """Return (gateway logical id, execution role logical id) from RoleArn."""
    gateway_id, gateway = _gateway(template)
    role_arn = gateway["Properties"]["RoleArn"]
    if isinstance(role_arn, dict) and list(role_arn) == ["Fn::GetAtt"]:
        logical_id, attribute = role_arn["Fn::GetAtt"]
        assert attribute == "Arn", role_arn
        return gateway_id, logical_id
    if isinstance(role_arn, str):
        role_name = role_arn.rsplit("/", 1)[-1]
        for logical_id, resource in _resources(template, "AWS::IAM::Role"):
            if resource["Properties"].get("RoleName") == role_name:
                return gateway_id, logical_id
    raise AssertionError(f"Gateway RoleArn does not select an IAM role: {role_arn}")


def _execution_role(template: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    _gateway_id, role_id = _role_logical_id(template)
    resource = template["Resources"][role_id]
    assert resource["Type"] == "AWS::IAM::Role", resource
    return role_id, resource


def trust_statements(template: dict[str, Any]) -> list[dict[str, Any]]:
    _role_id, role = _execution_role(template)
    return _statements(role["Properties"]["AssumeRolePolicyDocument"])


def identity_statements(template: dict[str, Any]) -> list[dict[str, Any]]:
    role_id, role = _execution_role(template)
    found = []
    for policy in role["Properties"].get("Policies") or []:
        found.extend(_statements(policy["PolicyDocument"]))
    for _logical_id, resource in _resources(template, "AWS::IAM::Policy"):
        roles = resource["Properties"].get("Roles") or []
        if any(isinstance(ref, dict) and ref.get("Ref") == role_id for ref in roles):
            found.extend(_statements(resource["Properties"]["PolicyDocument"]))
    return found


def tool_function_arns(template: dict[str, Any]) -> dict[str, str]:
    """Map each tool Lambda's logical id to the ARN its explicit name deploys as."""
    found = {}
    for logical_id, resource in _resources(template, "AWS::Lambda::Function"):
        name = resource["Properties"].get("FunctionName")
        if isinstance(name, str) and name.startswith(f"{PREFIX}-tool-"):
            found[logical_id] = f"arn:aws:lambda:{REGION}:{ACCOUNT}:function:{name}"
    return found


def _resolve(node: Any) -> Any:
    if isinstance(node, (str, int, float, bool)) or node is None:
        return node
    if isinstance(node, list):
        return [_resolve(item) for item in node]
    if not isinstance(node, dict) or len(node) != 1:
        return ("unresolved", repr(node))
    key, value = next(iter(node.items()))
    if key == "Ref":
        return {"AWS::AccountId": ACCOUNT, "AWS::Region": REGION, "AWS::Partition": "aws"}.get(
            value, ("ref", value)
        )
    if key == "Fn::GetAtt":
        logical_id, attribute = value if isinstance(value, list) else value.split(".", 1)
        return ("getatt", logical_id, attribute)
    if key == "Fn::Join":
        separator, parts = value
        resolved = [_resolve(part) for part in parts]
        if all(isinstance(part, str) for part in resolved):
            return separator.join(resolved)
        return ("join", separator, tuple(resolved))
    if key == "Fn::Sub":
        return _resolve_sub(value)
    return ("unresolved", key, repr(value))


def _resolve_sub(value: Any) -> Any:
    if isinstance(value, str):
        template, mapping = value, {}
    else:
        template, mapping = value
    resolved_map = {key: _resolve(item) for key, item in mapping.items()}

    def replace(match: re.Match[str]) -> str:
        name = match.group(1)
        if name in resolved_map and isinstance(resolved_map[name], str):
            return resolved_map[name]
        builtin = {"AWS::AccountId": ACCOUNT, "AWS::Region": REGION, "AWS::Partition": "aws"}
        if name in builtin:
            return builtin[name]
        return match.group(0)

    replaced = re.sub(r"\$\{([^}]+)\}", replace, template)
    if "${" not in replaced:
        return replaced
    return ("sub", replaced)


def _as_text(value: Any, functions: dict[str, str]) -> Any:
    if (
        isinstance(value, tuple)
        and len(value) == 3
        and value[0] == "getatt"
        and value[2] == "Arn"
        and value[1] in functions
    ):
        return functions[value[1]]
    return value


def _segment_match(pattern: str, text: str) -> bool:
    regex = []
    for char in pattern:
        if char == "*":
            regex.append(".*")
        elif char == "?":
            regex.append(".")
        else:
            regex.append(re.escape(char))
    return re.fullmatch("".join(regex), text) is not None


def arn_matches(pattern: str, arn: str) -> bool:
    """Resource and ArnLike matching for one pattern and one ARN."""
    if pattern == "*":
        return True
    pattern_segments = pattern.split(":")
    arn_segments = arn.split(":")
    return _segments_match(pattern_segments, arn_segments)


def _segments_match(pattern_segments: list[str], arn_segments: list[str]) -> bool:
    if not pattern_segments:
        return not arn_segments
    if not arn_segments:
        return False
    pattern = pattern_segments[0]
    if pattern.endswith("*"):
        if len(pattern_segments) == 1:
            return _segment_match(pattern, ":".join(arn_segments))
        for take in range(1, len(arn_segments) + 1):
            if _segment_match(pattern, ":".join(arn_segments[:take])) and _segments_match(
                pattern_segments[1:], arn_segments[take:]
            ):
                return True
        return False
    if not _segment_match(pattern, arn_segments[0]):
        return False
    return _segments_match(pattern_segments[1:], arn_segments[1:])


def _wildcard_match(pattern: str, text: str) -> bool:
    return _segment_match(pattern, text)


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _operator_name(operator: str) -> tuple[str, bool]:
    if operator.endswith("IfExists"):
        return operator[: -len("IfExists")], True
    return operator, False


def _condition_matches(condition: dict[str, Any] | None, context: dict[str, Any]) -> bool:
    if not condition:
        return True
    context = {key.lower(): value for key, value in context.items()}
    for operator, keys in condition.items():
        name, if_exists = _operator_name(operator)
        negated = name in {"StringNotEquals", "StringNotLike", "ArnNotEquals", "ArnNotLike"}
        for key, raw_policy_values in keys.items():
            present = key.lower() in context
            if not present:
                if if_exists or name == "Null":
                    continue
                if negated:
                    continue
                return False
            request_value = context[key.lower()]
            policy_values = [_resolve(item) for item in _as_list(raw_policy_values)]
            if name == "Null":
                expects_missing = str(policy_values[0]).lower() == "true"
                if expects_missing == present:
                    return False
                continue
            comparisons = [
                _value_matches(name, policy_value, request_value) for policy_value in policy_values
            ]
            if negated:
                if any(comparisons):
                    return False
            elif not any(comparisons):
                return False
    return True


def _value_matches(operator: str, policy_value: Any, request_value: Any) -> bool:
    if isinstance(policy_value, tuple) or isinstance(request_value, tuple):
        return policy_value == request_value
    policy_text = str(policy_value)
    request_text = str(request_value)
    if operator in {"StringEquals", "ArnEquals"}:
        return policy_text == request_text
    if operator == "StringEqualsIgnoreCase":
        return policy_text.lower() == request_text.lower()
    if operator == "StringLike":
        return _wildcard_match(policy_text, request_text)
    if operator in {"ArnLike"}:
        return arn_matches(policy_text, request_text)
    if operator in {"StringNotEquals", "ArnNotEquals"}:
        return policy_text == request_text
    if operator in {"StringNotLike", "ArnNotLike"}:
        matcher = _wildcard_match if operator == "StringNotLike" else arn_matches
        return matcher(policy_text, request_text)
    # An operator this evaluator does not model must not look like a restriction.
    return True


def _principal_matches(statement: dict[str, Any]) -> bool:
    principal = statement.get("Principal")
    if principal is None:
        return True
    if principal == "*":
        return True
    services = _as_list((principal or {}).get("Service"))
    return any(
        service == "*" or service == "bedrock-agentcore.amazonaws.com" for service in services
    )


def _action_matches(statement: dict[str, Any], action: str) -> bool:
    patterns = [str(item).lower() for item in _as_list(statement.get("Action"))]
    if not patterns:
        return False
    return any(_wildcard_match(pattern, action.lower()) for pattern in patterns)


def _resource_matches(
    statement: dict[str, Any],
    resource: Any,
    functions: dict[str, str],
    *,
    trust: bool,
) -> bool:
    patterns = [_as_text(_resolve(item), functions) for item in _as_list(statement.get("Resource"))]
    not_patterns = [
        _as_text(_resolve(item), functions) for item in _as_list(statement.get("NotResource"))
    ]
    if not patterns and not not_patterns:
        return trust
    resource_text = _as_text(resource, functions)
    if patterns and not any(_resource_pattern_matches(pattern, resource_text) for pattern in patterns):
        return False
    if any(_resource_pattern_matches(pattern, resource_text) for pattern in not_patterns):
        return False
    return True


def _resource_pattern_matches(pattern: Any, resource: Any) -> bool:
    if isinstance(pattern, tuple) or isinstance(resource, tuple):
        return pattern == resource
    return arn_matches(str(pattern), str(resource))


def _statement_matches(
    statement: dict[str, Any],
    *,
    action: str,
    resource: Any,
    context: dict[str, Any],
    functions: dict[str, str],
    trust: bool,
) -> bool:
    if not _principal_matches(statement):
        return False
    if not _action_matches(statement, action):
        return False
    if not _resource_matches(statement, resource, functions, trust=trust):
        return False
    return _condition_matches(statement.get("Condition"), context)


def is_allowed(
    statements: list[dict[str, Any]],
    *,
    action: str,
    resource: Any = None,
    context: dict[str, Any] | None = None,
    functions: dict[str, str] | None = None,
    trust: bool = False,
) -> bool:
    functions = functions or {}
    context = context or {}
    matched = [
        statement
        for statement in statements
        if _statement_matches(
            statement,
            action=action,
            resource=resource,
            context=context,
            functions=functions,
            trust=trust,
        )
    ]
    if any(statement.get("Effect", "Allow") == "Deny" for statement in matched):
        return False
    return any(statement.get("Effect", "Allow") == "Allow" for statement in matched)


def _gateway_arn_token(gateway_id: str) -> tuple[str, str, str]:
    return ("getatt", gateway_id, "GatewayArn")


def _other_gateway_arn(account: str) -> str:
    return f"arn:aws:bedrock-agentcore:{REGION}:{account}:gateway/{OTHER_GATEWAY_ID}"


def _assume_context(*, account: str, source_arn: Any) -> dict[str, Any]:
    return {"aws:SourceAccount": account, "aws:SourceArn": source_arn}


def test_only_this_gateway_can_assume_the_execution_role() -> None:
    template = synthesize(["sample-tool"])
    gateway_id, role_id = _role_logical_id(template)
    role = template["Resources"][role_id]
    statements = trust_statements(template)
    assert role["Properties"]["RoleName"] == f"{PREFIX}-gateway-role"

    own_gateway = _assume_context(account=ACCOUNT, source_arn=_gateway_arn_token(gateway_id))
    other_gateway_here = _assume_context(
        account=ACCOUNT, source_arn=_other_gateway_arn(ACCOUNT)
    )
    other_account = _assume_context(
        account=OTHER_ACCOUNT, source_arn=_other_gateway_arn(OTHER_ACCOUNT)
    )
    own_arn_other_account = _assume_context(
        account=OTHER_ACCOUNT, source_arn=_gateway_arn_token(gateway_id)
    )

    assert is_allowed(
        statements,
        action="sts:AssumeRole",
        context=own_gateway,
        trust=True,
    ), "the stack gateway must still be able to assume its execution role"
    assert not is_allowed(
        statements,
        action="sts:AssumeRole",
        context=other_gateway_here,
        trust=True,
    ), "another gateway in this account must not assume the execution role"
    assert not is_allowed(
        statements,
        action="sts:AssumeRole",
        context=other_account,
        trust=True,
    ), "a gateway in another account must not assume the execution role"
    assert not is_allowed(
        statements,
        action="sts:AssumeRole",
        context=own_arn_other_account,
        trust=True,
    ), "aws:SourceAccount must be this account even when SourceArn is this gateway"


def _lambda_targets(template: dict[str, Any]) -> list[dict[str, Any]]:
    targets = []
    for _logical_id, resource in _resources(template, "AWS::BedrockAgentCore::GatewayTarget"):
        configuration = resource["Properties"]["TargetConfiguration"]["Mcp"]
        if "Lambda" in configuration:
            targets.append(resource)
    return targets


def test_execution_role_invokes_only_the_tool_functions_this_stack_creates() -> None:
    template = synthesize(["sample-tool", "calendar"])
    functions = tool_function_arns(template)
    assert set(functions) and len(functions) == 2, functions
    statements = identity_statements(template)

    tool_roles = set()
    for logical_id in functions:
        role = template["Resources"][logical_id]["Properties"]["Role"]
        assert list(role) == ["Fn::GetAtt"] and role["Fn::GetAtt"][1] == "Arn"
        tool_roles.add(role["Fn::GetAtt"][0])
    assert len(tool_roles) == 1, tool_roles
    tool_role = template["Resources"][tool_roles.pop()]
    assert tool_role["Properties"]["AssumeRolePolicyDocument"]["Statement"][0]["Principal"] == {
        "Service": "lambda.amazonaws.com"
    }

    targets = _lambda_targets(template)
    assert len(targets) == 2
    for target in targets:
        providers = target["Properties"]["CredentialProviderConfigurations"]
        assert providers == [{"CredentialProviderType": "GATEWAY_IAM_ROLE"}]
        lambda_arn = target["Properties"]["TargetConfiguration"]["Mcp"]["Lambda"]["LambdaArn"]
        assert _as_text(_resolve(lambda_arn), functions) in functions.values()

    for arn in functions.values():
        assert is_allowed(
            statements,
            action="lambda:InvokeFunction",
            resource=arn,
            functions=functions,
        ), arn

    undeclared = f"arn:aws:lambda:{REGION}:{ACCOUNT}:function:{PREFIX}-tool-not-deployed"
    suffix = f"arn:aws:lambda:{REGION}:{ACCOUNT}:function:{PREFIX}-tool-sample-tool-extra"
    other_account = f"arn:aws:lambda:{REGION}:{OTHER_ACCOUNT}:function:{PREFIX}-tool-sample-tool"
    assert not is_allowed(
        statements,
        action="lambda:InvokeFunction",
        resource=undeclared,
        functions=functions,
    ), undeclared
    assert not is_allowed(
        statements,
        action="lambda:InvokeFunction",
        resource=suffix,
        functions=functions,
    ), suffix
    assert not is_allowed(
        statements,
        action="lambda:InvokeFunction",
        resource=other_account,
        functions=functions,
    ), other_account


def test_execution_role_without_tools_cannot_invoke_the_tool_prefix() -> None:
    template = synthesize([])
    assert tool_function_arns(template) == {}
    statements = identity_statements(template)
    undeclared = f"arn:aws:lambda:{REGION}:{ACCOUNT}:function:{PREFIX}-tool-not-deployed"
    assert not is_allowed(
        statements,
        action="lambda:InvokeFunction",
        resource=undeclared,
    ), undeclared


def test_web_search_does_not_add_a_broader_lambda_invoke() -> None:
    template = synthesize(["sample-tool"], enable_web_search=True)
    functions = tool_function_arns(template)
    statements = identity_statements(template)
    sample = next(iter(functions.values()))
    undeclared = f"arn:aws:lambda:{REGION}:{ACCOUNT}:function:{PREFIX}-tool-not-deployed"
    assert is_allowed(
        statements,
        action="lambda:InvokeFunction",
        resource=sample,
        functions=functions,
    )
    assert not is_allowed(
        statements,
        action="lambda:InvokeFunction",
        resource=undeclared,
        functions=functions,
    ), undeclared
