"""Gateway protocol SCP must fail closed when ProtocolType is omitted.

The consolidated gateway SCP (and the standalone restrict-protocol control it is
merged from) is supposed to force CreateGateway and UpdateGateway onto the
allowed protocol. These tests evaluate that document the way IAM evaluates a
deny statement: every operator in a Condition block is AND, Null "false"
matches only when the key is present, and a negated operator such as
StringNotEquals matches when its key is absent.

They fail while an omitted ProtocolType is not an explicit deny. CreateGateway
does not require protocolType, and the only enumerated value is MCP, so the
omitted field is the request that leaves the gateway off the MCP-only mode.
UpdateGateway replaces the whole configuration and resets every optional field
that is left out, so an update that omits protocolType shares the hole.

Run:

    python -m pytest tests/test_gateway_protocol_scp.py -q
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from infra_utils.policy_loader import load_control

ROOT = Path(__file__).resolve().parents[1]
GUARDRAILS = ROOT / "control-library" / "terraform" / "org-guardrails"
CREATE = "bedrock-agentcore:CreateGateway"
UPDATE = "bedrock-agentcore:UpdateGateway"
PROTOCOL_KEY = "bedrock-agentcore:ProtocolType"

# Negated matching operators. If the key is absent, a positive operator does
# not match and a negated operator does. Null and ...IfExists are separate.
_NEGATED_OPERATORS = {
    "StringNotEquals",
    "StringNotEqualsIgnoreCase",
    "StringNotLike",
    "ArnNotEquals",
    "ArnNotLike",
    "NumericNotEquals",
    "DateNotEquals",
    "NotIpAddress",
}


def _terraform_string_default(variable: str) -> str:
    """Return a string variable's default from the org-guardrails module."""
    source = (GUARDRAILS / "variables.tf").read_text()
    match = re.search(
        rf'variable "{re.escape(variable)}" \{{(.*?)\n\}}',
        source,
        re.S,
    )
    if not match:
        raise AssertionError(f"variable {variable} not found in variables.tf")
    default = re.search(r'default\s+=\s+"([^"]*)"', match.group(1))
    if not default:
        raise AssertionError(f"variable {variable} has no string default")
    return default.group(1)


def render_consolidated_gateway_scp(
    *,
    allowed_protocol: str | None = None,
    kms_key_arn_pattern: str | None = None,
    discovery_url_pattern: str | None = None,
) -> dict:
    """Reproduce gateway.tf's local.gateway_scp_consolidated value.

    The module reads each control file, replaces the scalar sentinels with
    replace() (not templatefile()), and flattens Statement arrays in
    lexicographic key order. enable_gateway_scps only gates whether that
    document is published; it does not change the document.
    """
    if allowed_protocol is None:
        allowed_protocol = _terraform_string_default("allowed_gateway_protocol")
    if kms_key_arn_pattern is None:
        kms_key_arn_pattern = _terraform_string_default("gateway_kms_key_arn_pattern")
    if discovery_url_pattern is None:
        discovery_url_pattern = _terraform_string_default(
            "approved_discovery_url_pattern"
        )

    # gw_dir = "${path.module}/${var.control_library_path}/scp/gateway"
    # control_library_path defaults to "../.." from this module.
    library = (GUARDRAILS / _terraform_string_default("control_library_path")).resolve()
    gw_dir = library / "scp" / "gateway"
    rendered = {
        "require-cmk": (gw_dir / "require-cmk.json")
        .read_text()
        .replace("<<kms_key_arn_pattern>>", kms_key_arn_pattern),
        "deny-no-auth": (gw_dir / "deny-no-auth.json").read_text(),
        "require-policy-engine": (gw_dir / "require-policy-engine.json").read_text(),
        "enforce-approved-idp": (gw_dir / "enforce-approved-idp.json")
        .read_text()
        .replace("<<approved_discovery_url_pattern>>", discovery_url_pattern),
        "restrict-protocol": (gw_dir / "restrict-protocol.json")
        .read_text()
        .replace("<<allowed_protocol>>", allowed_protocol),
        "targets-require-private-endpoint": (
            gw_dir / "targets-require-private-endpoint.json"
        ).read_text(),
        "targets-restrict-credential-provider": (
            gw_dir / "targets-restrict-credential-provider.json"
        ).read_text(),
        "targets-restrict-type": (gw_dir / "targets-restrict-type.json").read_text(),
    }
    statements = []
    for name in sorted(rendered):
        decoded = json.loads(rendered[name])
        statement = decoded["Statement"]
        if isinstance(statement, dict):
            statements.append(statement)
        else:
            statements.extend(statement)
    document = {"Version": "2012-10-17", "Statement": statements}
    assert "<<" not in json.dumps(document)
    return document


def _like(value: str, pattern: str) -> bool:
    """IAM StringLike: case-sensitive, '*' and '?' wildcards, whole string."""
    escaped = re.escape(pattern).replace(r"\*", ".*").replace(r"\?", ".")
    return re.fullmatch(escaped, value) is not None


def _policy_values(value) -> list:
    if isinstance(value, list):
        return value
    return [value]


def _request_values(context: dict, key: str) -> list[str] | None:
    """None means the key is absent. A present value is a single string or a list."""
    if key not in context or context[key] is None:
        return None
    value = context[key]
    if isinstance(value, list):
        return [str(item) for item in value]
    return [str(value)]


def _operator_matches(operator: str, key: str, policy_value, context: dict) -> bool:
    if operator == "Null":
        # "true" matches a missing key. "false" matches a key that is present.
        expect_absent = str(_policy_values(policy_value)[0]).lower() == "true"
        return (_request_values(context, key) is None) == expect_absent

    if operator.endswith("IfExists"):
        if _request_values(context, key) is None:
            return True
        operator = operator[: -len("IfExists")]

    present = _request_values(context, key)
    if present is None:
        return operator in _NEGATED_OPERATORS

    expected = [str(item) for item in _policy_values(policy_value)]
    if operator == "StringEquals":
        return any(left == right for left in present for right in expected)
    if operator == "StringNotEquals":
        # NOR across the policy values: true only when none of them match.
        return all(left != right for left in present for right in expected)
    if operator == "StringLike":
        return any(_like(left, right) for left in present for right in expected)
    if operator == "StringNotLike":
        return all(not _like(left, right) for left in present for right in expected)
    raise AssertionError(f"operator {operator} is not used by the gateway SCPs")


def _condition_matches(condition: dict | None, context: dict) -> bool:
    """Every operator and every key inside it must match (logical AND)."""
    if not condition:
        return True
    for operator, comparisons in condition.items():
        for key, policy_value in comparisons.items():
            if not _operator_matches(operator, key, policy_value, context):
                return False
    return True


def _pattern_matches(value: str, pattern: str) -> bool:
    return _like(value, pattern)


def _element_matches(element, value: str) -> bool:
    patterns = element if isinstance(element, list) else [element]
    return any(_pattern_matches(value, pattern) for pattern in patterns)


def matching_deny_sids(policy: dict, action: str, context: dict, resource: str = "*") -> list[str]:
    """Sids of Deny statements that match this request.

    A deny-list SCP attached beside FullAWSAccess denies the request exactly
    when one of these statements matches. No match means this SCP allows it.
    """
    matched = []
    for index, statement in enumerate(policy["Statement"]):
        if statement.get("Effect") != "Deny":
            continue
        if not _element_matches(statement["Action"], action):
            continue
        if "Resource" in statement and not _element_matches(statement["Resource"], resource):
            continue
        if _condition_matches(statement.get("Condition"), context):
            matched.append(statement.get("Sid", f"statement-{index}"))
    return matched


def _hardened_gateway_context(**overrides) -> dict:
    """A Create/UpdateGateway context that satisfies every guardrail except protocol.

    The caller is a member-account administrator who sets the CMK, a non-NONE
    authorizer, an approved discovery URL, and a policy engine in ENFORCE, and
    then leaves protocolType off the request. Absent keys are omitted from the
    context rather than sent as empty strings.
    """
    context = {
        "bedrock-agentcore:KmsKeyArn": (
            "arn:aws:kms:us-east-1:111122223333:key/11111111-2222-3333-4444-555555555555"
        ),
        "bedrock-agentcore:GatewayAuthorizerType": "CUSTOM_JWT",
        "bedrock-agentcore:DiscoveryUrl": (
            "https://login.example.com/.well-known/openid-configuration"
        ),
        "bedrock-agentcore:PolicyEngineArn": (
            "arn:aws:bedrock-agentcore:us-east-1:111122223333:policy-engine/engine"
        ),
        "bedrock-agentcore:PolicyEngineMode": "ENFORCE",
    }
    for key, value in overrides.items():
        if value is None:
            context.pop(key, None)
        else:
            context[key] = value
    return context


def test_evaluator_denies_when_negated_key_is_absent():
    """The policy-engine statement is the fail-closed shape this control lacks.

    StringNotEquals with no Null guard matches a missing PolicyEngineMode, so
    the same consolidated document already denies that omission. This pins the
    evaluator to that rule before the protocol assertions use it.
    """
    policy = render_consolidated_gateway_scp()
    context = _hardened_gateway_context(**{
        PROTOCOL_KEY: "MCP",
        "bedrock-agentcore:PolicyEngineMode": None,
    })
    assert "DenyGatewayPolicyEngineNotEnforced" in matching_deny_sids(
        policy, CREATE, context
    )


def test_evaluator_null_false_does_not_match_a_missing_key():
    """Null false AND anything else cannot match when the key was not sent."""
    condition = {
        "StringNotEquals": {PROTOCOL_KEY: "MCP"},
        "Null": {PROTOCOL_KEY: "false"},
    }
    assert _operator_matches("Null", PROTOCOL_KEY, "false", {}) is False
    assert _operator_matches("StringNotEquals", PROTOCOL_KEY, "MCP", {}) is True
    assert _condition_matches(condition, {}) is False
    assert _condition_matches(condition, {PROTOCOL_KEY: "HTTP"}) is True
    assert _condition_matches(condition, {PROTOCOL_KEY: "MCP"}) is False


def test_merge_keeps_restrict_protocol_statement():
    merged = render_consolidated_gateway_scp()
    standalone = load_control("scp.gateway.restrict-protocol")["Statement"][0]
    found = [
        statement
        for statement in merged["Statement"]
        if statement.get("Sid") == "DenyNonApprovedGatewayProtocol"
    ]
    assert found == [standalone]
    assert _terraform_string_default("allowed_gateway_protocol") == "MCP"


def test_explicit_mcp_gateway_is_not_denied():
    documents = (
        render_consolidated_gateway_scp(),
        load_control("scp.gateway.restrict-protocol"),
    )
    context = _hardened_gateway_context(**{PROTOCOL_KEY: "MCP"})
    for document in documents:
        for action in (CREATE, UPDATE):
            assert matching_deny_sids(document, action, context) == []


def test_explicit_non_mcp_protocol_is_denied():
    documents = (
        render_consolidated_gateway_scp(),
        load_control("scp.gateway.restrict-protocol"),
    )
    for protocol in ("HTTP", "mcp", "A2A"):
        context = _hardened_gateway_context(**{PROTOCOL_KEY: protocol})
        for document in documents:
            for action in (CREATE, UPDATE):
                denied = matching_deny_sids(document, action, context)
                assert denied, f"{action} protocol {protocol!r} was not denied"


def test_create_gateway_without_protocol_type_is_denied():
    """CreateGateway that omits protocolType must be an explicit SCP deny.

    botocore's CreateGatewayRequest does not require protocolType and does not
    default it. The published control-plane guide states that setting MCP
    restricts the gateway to MCP targets, and omitting the field allows both
    MCP and HTTP targets. The request below supplies every other key the
    consolidated guardrail demands.
    """
    policy = render_consolidated_gateway_scp()
    standalone = load_control("scp.gateway.restrict-protocol")
    context = _hardened_gateway_context()
    assert PROTOCOL_KEY not in context
    for document in (policy, standalone):
        denied = matching_deny_sids(document, CREATE, context)
        assert denied, (
            "CreateGateway with no ProtocolType key was not denied. "
            f"Matching deny sids: {denied or 'none'}."
        )


def test_update_gateway_without_protocol_type_is_denied():
    """UpdateGateway resets omitted optional fields, including protocolType.

    The same Null guard that lets a create omit the protocol also lets an
    update omit it. The control-plane model documents UpdateGateway as
    replacing the whole configuration and resetting omitted optional fields,
    and protocolType is optional there too.
    """
    policy = render_consolidated_gateway_scp()
    standalone = load_control("scp.gateway.restrict-protocol")
    context = _hardened_gateway_context()
    assert PROTOCOL_KEY not in context
    for document in (policy, standalone):
        denied = matching_deny_sids(document, UPDATE, context)
        assert denied, (
            "UpdateGateway with no ProtocolType key was not denied. "
            f"Matching deny sids: {denied or 'none'}."
        )


def test_empty_protocol_type_is_denied():
    """A present empty protocol is not the allowed value and must be denied."""
    policy = render_consolidated_gateway_scp()
    context = _hardened_gateway_context(**{PROTOCOL_KEY: ""})
    for action in (CREATE, UPDATE):
        assert matching_deny_sids(policy, action, context)


def test_allowed_protocol_parameter_is_the_only_present_value_let_through():
    """<<allowed_protocol>> is the value a present ProtocolType must equal."""
    allowed = "HTTP"
    documents = (
        render_consolidated_gateway_scp(allowed_protocol=allowed),
        load_control(
            "scp.gateway.restrict-protocol", {"allowed_protocol": allowed}
        ),
    )
    chosen = _hardened_gateway_context(**{PROTOCOL_KEY: allowed})
    other = _hardened_gateway_context(**{PROTOCOL_KEY: "MCP"})
    for document in documents:
        for action in (CREATE, UPDATE):
            assert matching_deny_sids(document, action, chosen) == []
            assert matching_deny_sids(document, action, other)


def test_custom_allowed_protocol_still_denies_omission():
    """Changing the allowed value does not permit a request that omits the key."""
    allowed = "HTTP"
    documents = (
        render_consolidated_gateway_scp(allowed_protocol=allowed),
        load_control(
            "scp.gateway.restrict-protocol", {"allowed_protocol": allowed}
        ),
    )
    omitted = _hardened_gateway_context()
    assert PROTOCOL_KEY not in omitted
    for document in documents:
        for action in (CREATE, UPDATE):
            assert matching_deny_sids(document, action, omitted)
