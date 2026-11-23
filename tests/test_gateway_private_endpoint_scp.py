"""Gateway private-endpoint SCP must block public egress, not only a missing type.

The consolidated org guardrail is built in
``control-library/terraform/org-guardrails/gateway.tf`` by reading every
``control-library/scp/gateway/*.json`` document, substituting the scalar
sentinels, and flattening the statements. These tests render that document
the same way and evaluate it with IAM condition rules.

A member-account administrator is allowed ``bedrock-agentcore:CreateGatewayTarget``
and ``bedrock-agentcore:UpdateGatewayTarget`` by an identity policy.
``FullAWSAccess`` is the SCP allow that Organizations attaches beside a
deny-list guardrail. The guardrail must still explicit-deny a target whose
private-endpoint type is one of the two real union members when the subnets
are not the organization's no-internet-route subnet. The MCP and passthrough
endpoint strings are caller-supplied URLs and are not IAM condition keys, so
the URL itself cannot be what the decision turns on.

``subnet-approved1`` is the subnet id these tests treat as having no internet
route. A fix has to allow a target that uses only that subnet and deny every
other subnet id, including ids that do not appear in the policy text.

``SynchronizeGatewayTargets`` is not covered. Its request carries target ids
only, not a private endpoint, subnet list, or endpoint URL.
"""

from __future__ import annotations

import gzip
import json
import re
from pathlib import Path

import botocore
import pytest

REPO = Path(__file__).resolve().parents[1]
MODULE = REPO / "control-library" / "terraform" / "org-guardrails"

# Subnet id the organization has classified as having no route to the internet.
APPROVED_SUBNET = "subnet-approved1"

PUBLIC_MCP_ENDPOINT = "https://tools.example.com/mcp"
PRIVATE_DNS_MCP_ENDPOINT = "https://mcp.internal.example.com/mcp"
PUBLIC_PASSTHROUGH_ENDPOINT = "https://tools.example.com/v1"

TARGET_ACTIONS = (
    "bedrock-agentcore:CreateGatewayTarget",
    "bedrock-agentcore:UpdateGatewayTarget",
)

# Organizations attaches this allow next to any deny-list SCP. It allows every
# action; it does not grant permissions by itself, and an explicit deny wins.
FULL_AWS_ACCESS = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
}

MEMBER_ADMIN_IDENTITY = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": list(TARGET_ACTIONS),
            "Resource": "*",
        }
    ],
}

_NEGATED_BASES = {"StringNotEquals", "StringNotLike"}
_POSITIVE_BASES = {"StringEquals", "StringLike"}


def _brace_block(text: str, open_index: int) -> str:
    depth = 0
    for index in range(open_index, len(text)):
        char = text[index]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return text[open_index + 1 : index]
    raise AssertionError("unbalanced brace in terraform file")


def _variable_defaults(variables_tf: str) -> dict[str, str]:
    defaults: dict[str, str] = {}
    for match in re.finditer(r'variable\s+"([^"]+)"\s*\{', variables_tf):
        body = _brace_block(variables_tf, match.end() - 1)
        found = re.search(r'default\s*=\s*"((?:\\.|[^"\\])*)"', body)
        if found:
            defaults[match.group(1)] = found.group(1)
    return defaults


def render_consolidated_gateway_scp(module: Path = MODULE) -> dict:
    """Replay gateway.tf: file() + replace() + keys() order + flatten statements."""
    gateway_tf = (module / "gateway.tf").read_text()
    defaults = _variable_defaults((module / "variables.tf").read_text())
    library = (module / defaults["control_library_path"]).resolve()
    rendered: dict[str, str] = {}
    entry = re.compile(
        r'"([^"]+)"\s*=\s*(replace\(\s*)?file\("\$\{local\.gw_dir\}/([^"]+)"\)'
        r'(?:\s*,\s*"([^"]*)"\s*,\s*var\.([A-Za-z0-9_]+)\s*\))?',
        re.S,
    )
    for key, is_replace, relative, sentinel, variable in entry.findall(gateway_tf):
        document = (library / "scp" / "gateway" / relative).read_text()
        if is_replace:
            document = document.replace(sentinel, defaults[variable])
        rendered[key] = document
    if "targets-require-private-endpoint" not in rendered:
        raise AssertionError("gateway.tf did not load the private-endpoint SCP")
    statements = []
    for key in sorted(rendered):
        statements.extend(json.loads(rendered[key])["Statement"])
    return {"Version": "2012-10-17", "Statement": statements}


def _service_model() -> dict:
    root = Path(botocore.__file__).resolve().parent / "data" / "bedrock-agentcore-control"
    versions = sorted(path for path in root.iterdir() if path.is_dir())
    with gzip.open(versions[-1] / "service-2.json.gz", "rt") as handle:
        return json.load(handle)


def _shape(model: dict, name: str) -> dict:
    return model["shapes"][name]


def _matches_pattern(model: dict, shape_name: str, value: str) -> bool:
    pattern = _shape(model, shape_name).get("pattern")
    if pattern is None:
        return True
    return re.fullmatch(pattern, value) is not None


def _request_values(context: dict, key: str) -> list[str] | None:
    if key not in context or context[key] is None:
        return None
    value = context[key]
    if value == "" or value == []:
        return None
    if isinstance(value, list):
        return [str(item) for item in value]
    return [str(value)]


def _policy_values(value) -> list[str]:
    if isinstance(value, list):
        return [str(item) for item in value]
    return [str(value)]


def _like(text: str, pattern: str) -> bool:
    regex = "^" + "".join(
        ".*" if char == "*" else "." if char == "?" else re.escape(char) for char in pattern
    ) + "$"
    return re.fullmatch(regex, text) is not None


def _one_value(base: str, request_value: str, policy_values: list[str]) -> bool:
    if base == "StringEquals":
        return request_value in policy_values
    if base == "StringNotEquals":
        return request_value not in policy_values
    if base == "StringLike":
        return any(_like(request_value, pattern) for pattern in policy_values)
    if base == "StringNotLike":
        return all(not _like(request_value, pattern) for pattern in policy_values)
    raise AssertionError(f"unsupported condition operator {base}")


def _operator_matches(operator: str, policy_value, request_values: list[str] | None) -> bool:
    if operator == "Null":
        expected = _policy_values(policy_value)[0].lower()
        absent = request_values is None
        if expected == "true":
            return absent
        if expected == "false":
            return not absent
        raise AssertionError(f"Null expected true or false, got {expected}")

    working = operator
    if_exists = working.endswith("IfExists")
    if if_exists:
        working = working[: -len("IfExists")]
    set_operator = None
    if working.startswith("ForAnyValue:"):
        set_operator = "any"
        working = working.split(":", 1)[1]
    elif working.startswith("ForAllValues:"):
        set_operator = "all"
        working = working.split(":", 1)[1]
    if working not in _POSITIVE_BASES | _NEGATED_BASES:
        raise AssertionError(f"unsupported condition operator {operator}")

    if request_values is None:
        if set_operator == "any":
            return False
        if if_exists:
            return True
        if set_operator == "all":
            return True
        return working in _NEGATED_BASES

    policy_values = _policy_values(policy_value)
    results = [_one_value(working, item, policy_values) for item in request_values]
    if set_operator == "all":
        return all(results) if results else True
    # ForAnyValue, and a single-valued operator applied to each request value:
    # at least one request value has to satisfy the base operator. A negated
    # base with no set qualifier still follows that "any value" reading when
    # the key is present, which denies a mixed subnet list under StringNotEquals.
    return any(results)


def _condition_matches(condition: dict | None, context: dict) -> bool:
    if not condition:
        return True
    for operator, keys in condition.items():
        for key, policy_value in keys.items():
            if not _operator_matches(operator, policy_value, _request_values(context, key)):
                return False
    return True


def _action_matches(statement_action, requested: str) -> bool:
    actions = statement_action if isinstance(statement_action, list) else [statement_action]
    for action in actions:
        if action == "*" or action == requested:
            return True
        if action.endswith("*") and requested.startswith(action[:-1]):
            return True
    return False


def _resource_matches(statement_resource, requested: str = "*") -> bool:
    resources = (
        statement_resource if isinstance(statement_resource, list) else [statement_resource]
    )
    return any(resource == "*" or resource == requested for resource in resources)


def _statement_matches(statement: dict, action: str, context: dict) -> bool:
    return (
        _action_matches(statement["Action"], action)
        and _resource_matches(statement.get("Resource", "*"))
        and _condition_matches(statement.get("Condition"), context)
    )


def explicit_effect(policy: dict, effect: str, action: str, context: dict) -> str | None:
    for statement in policy["Statement"]:
        if statement.get("Effect") == effect and _statement_matches(statement, action, context):
            return statement.get("Sid", effect)
    return None


def member_admin_decision(scp: dict, action: str, context: dict) -> str:
    """SCP explicit deny, else FullAWSAccess allow intersected with the identity allow."""
    denied_by = explicit_effect(scp, "Deny", action, context)
    if denied_by:
        return "denied"
    scp_allows = explicit_effect(FULL_AWS_ACCESS, "Allow", action, context) is not None
    identity_allows = explicit_effect(MEMBER_ADMIN_IDENTITY, "Allow", action, context) is not None
    if scp_allows and identity_allows:
        return "allowed"
    return "denied"


def authorization_context(body: dict) -> dict:
    """Condition keys AgentCore publishes for a gateway-target request.

    The endpoint URL is not one of those keys. ``bedrock-agentcore:subnets`` is
    published from the managed VPC subnet list. A self-managed Lattice request
    has no subnet list in the API, so the key is absent unless the caller
    context includes one.
    """
    context: dict = {}
    private_endpoint = body.get("privateEndpoint") or {}
    present = [
        name
        for name in ("managedVpcResource", "selfManagedLatticeResource")
        if private_endpoint.get(name) is not None
    ]
    if len(present) == 1:
        context["bedrock-agentcore:PrivateEndpointType"] = present[0]
        if present[0] == "managedVpcResource":
            managed = private_endpoint["managedVpcResource"]
            if managed.get("subnetIds"):
                context["bedrock-agentcore:subnets"] = list(managed["subnetIds"])
            if managed.get("securityGroupIds"):
                context["bedrock-agentcore:securityGroups"] = list(managed["securityGroupIds"])
    target = body.get("targetConfiguration") or {}
    for family, key in (
        ("mcp", "bedrock-agentcore:McpTargetConfigurationType"),
        ("http", "bedrock-agentcore:HttpTargetConfigurationType"),
        ("inference", "bedrock-agentcore:InferenceTargetConfigurationType"),
    ):
        members = [name for name, value in (target.get(family) or {}).items() if value is not None]
        if len(members) == 1:
            context[key] = members[0]
    credentials = body.get("credentialProviderConfigurations") or []
    if credentials:
        context["bedrock-agentcore:CredentialProviderType"] = credentials[0][
            "credentialProviderType"
        ]
    return context


def _credentials() -> list[dict]:
    return [{"credentialProviderType": "GATEWAY_IAM_ROLE"}]


def managed_vpc_body(endpoint_family: dict, subnet_ids: list[str]) -> dict:
    return {
        "gatewayIdentifier": "gateway-0123456789",
        "name": "public-egress-target",
        "targetConfiguration": endpoint_family,
        "credentialProviderConfigurations": _credentials(),
        "privateEndpoint": {
            "managedVpcResource": {
                "vpcIdentifier": "vpc-0123456789abcdef0",
                "subnetIds": subnet_ids,
                "endpointIpAddressType": "IPV4",
            }
        },
    }


def lattice_body(endpoint_family: dict) -> dict:
    return {
        "gatewayIdentifier": "gateway-0123456789",
        "name": "public-egress-target",
        "targetConfiguration": endpoint_family,
        "credentialProviderConfigurations": _credentials(),
        "privateEndpoint": {
            "selfManagedLatticeResource": {
                "resourceConfigurationIdentifier": "rcfg-0123456789abcdef0",
            }
        },
    }


def mcp_server(endpoint: str) -> dict:
    return {"mcp": {"mcpServer": {"endpoint": endpoint}}}


def http_passthrough(endpoint: str) -> dict:
    # PassthroughProtocolType is MCP, A2A, INFERENCE, or CUSTOM. MCP keeps the
    # public endpoint on a value the control-plane API accepts.
    return {"http": {"passthrough": {"endpoint": endpoint, "protocolType": "MCP"}}}


def lambda_target() -> dict:
    return {
        "mcp": {
            "lambda": {
                "lambdaArn": "arn:aws:lambda:us-east-1:111122223333:function:tool",
                "toolSchema": {
                    "inlinePayload": [
                        {
                            "name": "text_analysis_tool",
                            "description": "Inspect text.",
                            "inputSchema": {"type": "object"},
                        }
                    ]
                },
            }
        }
    }


def unlisted_subnet(policy_text: str) -> str:
    for number in range(1, 1000):
        candidate = f"subnet-natroute{number:02d}"
        if candidate not in policy_text and candidate != APPROVED_SUBNET:
            return candidate
    raise AssertionError("could not find a subnet id absent from the policy")


@pytest.fixture(scope="module")
def scp() -> dict:
    return render_consolidated_gateway_scp()


@pytest.fixture(scope="module")
def service_model() -> dict:
    return _service_model()


def test_evaluator_follows_published_condition_rules():
    """Pin the stand-in to the IAM condition rules the gateway statements use."""
    assert _operator_matches("Null", "true", None) is True
    assert _operator_matches("Null", "true", ["managedVpcResource"]) is False
    assert _operator_matches("Null", "false", ["managedVpcResource"]) is True
    assert _operator_matches("Null", "false", None) is False

    assert _operator_matches("StringEquals", ["lambda", "mcpServer"], ["mcpServer"]) is True
    assert _operator_matches("StringEquals", ["lambda", "mcpServer"], ["apiGateway"]) is False
    assert _operator_matches("StringEquals", ["lambda", "mcpServer"], None) is False
    assert _operator_matches("StringNotEquals", ["lambda", "mcpServer"], ["mcpServer"]) is False
    assert _operator_matches("StringNotEquals", ["lambda", "mcpServer"], ["apiGateway"]) is True
    assert _operator_matches("StringNotEquals", ["lambda", "mcpServer"], None) is True

    approved = [APPROVED_SUBNET]
    assert _operator_matches("ForAnyValue:StringEquals", approved, None) is False
    assert _operator_matches("ForAllValues:StringEquals", approved, None) is True
    assert _operator_matches("ForAnyValue:StringNotEquals", approved, None) is False
    assert (
        _operator_matches("ForAnyValue:StringNotEquals", approved, [APPROVED_SUBNET, "subnet-other01"])
        is True
    )
    assert _operator_matches("ForAnyValue:StringNotEquals", approved, [APPROVED_SUBNET]) is False
    assert (
        _condition_matches(
            {
                "ForAllValues:StringEquals": {"bedrock-agentcore:subnets": approved},
                "Null": {"bedrock-agentcore:subnets": "false"},
            },
            {},
        )
        is False
    )

    deny_missing = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "DenyMissing",
                "Effect": "Deny",
                "Action": "bedrock-agentcore:CreateGatewayTarget",
                "Resource": "*",
                "Condition": {"Null": {"bedrock-agentcore:PrivateEndpointType": "true"}},
            }
        ],
    }
    assert (
        member_admin_decision(deny_missing, "bedrock-agentcore:CreateGatewayTarget", {})
        == "denied"
    )
    assert (
        member_admin_decision(
            deny_missing,
            "bedrock-agentcore:CreateGatewayTarget",
            {"bedrock-agentcore:PrivateEndpointType": "managedVpcResource"},
        )
        == "allowed"
    )


def test_caller_supplied_endpoints_match_the_control_plane_schema(service_model):
    assert _matches_pattern(
        service_model, "McpServerTargetConfigurationEndpointString", PUBLIC_MCP_ENDPOINT
    )
    assert _matches_pattern(
        service_model, "McpServerTargetConfigurationEndpointString", PRIVATE_DNS_MCP_ENDPOINT
    )
    assert _matches_pattern(service_model, "PassthroughEndpoint", PUBLIC_PASSTHROUGH_ENDPOINT)
    assert _matches_pattern(service_model, "SubnetId", APPROVED_SUBNET)
    credential_type = _shape(service_model, "CredentialProviderType")
    assert "GATEWAY_IAM_ROLE" in credential_type["enum"]
    assert "MCP" in _shape(service_model, "PassthroughProtocolType")["enum"]
    managed = _shape(service_model, "ManagedVpcResource")
    assert "subnetIds" in managed["members"]
    assert "routingDomain" in managed["members"]
    lattice = _shape(service_model, "SelfManagedLatticeResource")["members"]
    assert "resourceConfigurationIdentifier" in lattice
    assert "subnetIds" not in lattice


def test_endpoint_url_is_not_copied_into_the_authorization_context():
    body = managed_vpc_body(mcp_server(PUBLIC_MCP_ENDPOINT), [APPROVED_SUBNET])
    context = authorization_context(body)
    flat = json.dumps(context)
    assert "tools.example.com" not in flat
    assert "https://" not in flat
    assert context["bedrock-agentcore:PrivateEndpointType"] == "managedVpcResource"
    assert context["bedrock-agentcore:subnets"] == [APPROVED_SUBNET]
    assert context["bedrock-agentcore:McpTargetConfigurationType"] == "mcpServer"


@pytest.mark.parametrize("action", TARGET_ACTIONS)
def test_missing_private_endpoint_type_stays_denied(scp, action):
    body = {
        "gatewayIdentifier": "gateway-0123456789",
        "targetConfiguration": mcp_server(PUBLIC_MCP_ENDPOINT),
        "credentialProviderConfigurations": _credentials(),
    }
    decision = member_admin_decision(scp, action, authorization_context(body))
    assert decision == "denied", decision


@pytest.mark.parametrize("action", TARGET_ACTIONS)
def test_non_private_endpoint_type_value_is_denied(scp, action):
    context = authorization_context(
        managed_vpc_body(mcp_server(PUBLIC_MCP_ENDPOINT), [APPROVED_SUBNET])
    )
    context["bedrock-agentcore:PrivateEndpointType"] = "publicInternet"
    decision = member_admin_decision(scp, action, context)
    assert decision == "denied", decision


@pytest.mark.parametrize("action", TARGET_ACTIONS)
def test_public_mcp_endpoint_on_an_unlisted_subnet_is_denied(scp, action):
    subnet_id = unlisted_subnet(json.dumps(scp))
    body = managed_vpc_body(mcp_server(PUBLIC_MCP_ENDPOINT), [subnet_id])
    decision = member_admin_decision(scp, action, authorization_context(body))
    assert decision == "denied", (subnet_id, decision)


@pytest.mark.parametrize("action", TARGET_ACTIONS)
def test_private_dns_name_on_an_unlisted_subnet_is_denied(scp, action):
    subnet_id = unlisted_subnet(json.dumps(scp))
    body = managed_vpc_body(mcp_server(PRIVATE_DNS_MCP_ENDPOINT), [subnet_id])
    decision = member_admin_decision(scp, action, authorization_context(body))
    assert decision == "denied", decision


@pytest.mark.parametrize("action", TARGET_ACTIONS)
def test_mixed_approved_and_unlisted_subnets_are_denied(scp, action):
    subnet_id = unlisted_subnet(json.dumps(scp))
    body = managed_vpc_body(
        mcp_server(PUBLIC_MCP_ENDPOINT), [APPROVED_SUBNET, subnet_id]
    )
    decision = member_admin_decision(scp, action, authorization_context(body))
    assert decision == "denied", decision


@pytest.mark.parametrize("action", TARGET_ACTIONS)
def test_public_passthrough_endpoint_on_an_unlisted_subnet_is_denied(scp, action):
    subnet_id = unlisted_subnet(json.dumps(scp))
    body = managed_vpc_body(http_passthrough(PUBLIC_PASSTHROUGH_ENDPOINT), [subnet_id])
    context = authorization_context(body)
    assert "bedrock-agentcore:McpTargetConfigurationType" not in context
    assert context["bedrock-agentcore:HttpTargetConfigurationType"] == "passthrough"
    decision = member_admin_decision(scp, action, context)
    assert decision == "denied", decision


@pytest.mark.parametrize("action", TARGET_ACTIONS)
def test_lambda_target_on_an_unlisted_subnet_is_denied(scp, action):
    subnet_id = unlisted_subnet(json.dumps(scp))
    body = managed_vpc_body(lambda_target(), [subnet_id])
    decision = member_admin_decision(scp, action, authorization_context(body))
    assert decision == "denied", decision


@pytest.mark.parametrize("action", TARGET_ACTIONS)
def test_self_managed_lattice_without_approved_subnets_is_denied(scp, action):
    body = lattice_body(mcp_server(PUBLIC_MCP_ENDPOINT))
    context = authorization_context(body)
    assert context["bedrock-agentcore:PrivateEndpointType"] == "selfManagedLatticeResource"
    assert "bedrock-agentcore:subnets" not in context
    assert "tools.example.com" not in json.dumps(context)
    decision = member_admin_decision(scp, action, context)
    assert decision == "denied", decision


@pytest.mark.parametrize("action", TARGET_ACTIONS)
def test_approved_subnet_allows_public_url_for_mcp_http_and_lambda(scp, action):
    cases = [
        managed_vpc_body(mcp_server(PUBLIC_MCP_ENDPOINT), [APPROVED_SUBNET]),
        managed_vpc_body(http_passthrough(PUBLIC_PASSTHROUGH_ENDPOINT), [APPROVED_SUBNET]),
        managed_vpc_body(lambda_target(), [APPROVED_SUBNET]),
        lattice_body(mcp_server(PUBLIC_MCP_ENDPOINT)),
    ]
    # Lattice has no subnet field. The allow case supplies the approved subnet
    # in the same context key the managed VPC path publishes.
    contexts = [authorization_context(body) for body in cases]
    contexts[-1]["bedrock-agentcore:subnets"] = [APPROVED_SUBNET]
    for context in contexts:
        decision = member_admin_decision(scp, action, context)
        assert decision == "allowed", (action, context, decision)


def test_same_public_url_changes_decision_only_with_the_subnet(scp):
    action = "bedrock-agentcore:CreateGatewayTarget"
    allowed = member_admin_decision(
        scp,
        action,
        authorization_context(
            managed_vpc_body(mcp_server(PUBLIC_MCP_ENDPOINT), [APPROVED_SUBNET])
        ),
    )
    denied = member_admin_decision(
        scp,
        action,
        authorization_context(
            managed_vpc_body(
                mcp_server(PUBLIC_MCP_ENDPOINT),
                [unlisted_subnet(json.dumps(scp))],
            )
        ),
    )
    assert allowed == "allowed", allowed
    assert denied == "denied", denied
