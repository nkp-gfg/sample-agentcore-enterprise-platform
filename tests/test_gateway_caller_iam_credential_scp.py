"""Gateway credential SCP must deny caller IAM credential forwarding.

The consolidated gateway SCP is built the way
``control-library/terraform/org-guardrails/gateway.tf`` builds it: read each
library file, ``replace()`` sentinels with the module's default variable
values, and flatten ``Statement`` arrays in lexicographic ``keys()`` order.

Authorization is not executed against AWS here. ``scp_decision`` is the
stand-in for that evaluation. It follows the IAM condition rules used by the
statements in this policy:

- Several condition operators on one statement are a logical AND, and several
  values of one key are a logical OR. A negated operator with several values
  is a logical NOR.
- ``StringEquals`` is case-sensitive. If the key is absent, a matching
  operator is false and a negated operator (``StringNotEquals``,
  ``StringNotLike``) is true. ``Null`` and ``...IfExists`` are the exceptions:
  ``Null`` "true" matches an absent key and "false" matches a present key;
  ``...IfExists`` is true when the key is absent.
- ``StringLike`` / ``StringNotLike`` treat ``*`` and ``?`` as wildcards.
- One matching ``Deny`` is an explicit deny. If no deny matches, the result is
  Allow because this module attaches the gateway SCP on top of FullAWSAccess
  (``variables.tf``) and a member-account administrator identity policy allows
  the action.

These tests fail while ``CALLER_IAM_CREDENTIALS`` is omitted from the deny.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from infra_utils.policy_loader import load_control

REPO = Path(__file__).resolve().parents[1]
MODULE = REPO / "control-library" / "terraform" / "org-guardrails"
CREDENTIAL_CONTROL = "scp.gateway.targets-restrict-credential-provider"
CREDENTIAL_SID = "DenyDisallowedTargetCredentialProviders"
CALLER_IAM = "CALLER_IAM_CREDENTIALS"
TARGET_ACTIONS = (
    "bedrock-agentcore:CreateGatewayTarget",
    "bedrock-agentcore:UpdateGatewayTarget",
)
GATEWAY_ACTIONS = (
    "bedrock-agentcore:CreateGateway",
    "bedrock-agentcore:UpdateGateway",
)

_REPLACE_ENTRY = re.compile(
    r'"([^"]+)"\s*=\s*replace\(\s*'
    r'file\("\$\{local\.gw_dir\}/([^"]+)"\)\s*,\s*'
    r'"(<<[^"]+>>)"\s*,\s*var\.([A-Za-z0-9_]+)\s*\)',
    re.DOTALL,
)
_FILE_ENTRY = re.compile(
    r'"([^"]+)"\s*=\s*file\("\$\{local\.gw_dir\}/([^"]+)"\)',
)


def _string_default(variables_tf: str, name: str) -> str:
    match = re.search(
        rf'variable "{re.escape(name)}"\s*\{{.*?default\s*=\s*"([^"]*)"',
        variables_tf,
        re.DOTALL,
    )
    if match is None:
        raise AssertionError(f"variable {name} has no string default")
    return match.group(1)


def _wildcard_match(pattern: str, value: str) -> bool:
    """Case-sensitive IAM ``*`` / ``?`` match used by ``StringLike``."""
    i = j = 0
    star_i = star_j = -1
    while j < len(value):
        if i < len(pattern) and (pattern[i] == "?" or pattern[i] == value[j]):
            i += 1
            j += 1
        elif i < len(pattern) and pattern[i] == "*":
            star_i = i
            star_j = j
            i += 1
        elif star_i != -1:
            star_j += 1
            i = star_i + 1
            j = star_j
        else:
            return False
    while i < len(pattern) and pattern[i] == "*":
        i += 1
    return i == len(pattern)


def _as_strings(value: object) -> list[str]:
    if isinstance(value, list):
        return [str(item) for item in value]
    return [str(value)]


def _condition_matches(condition: dict, context: dict) -> bool:
    return all(
        _operator_matches(operator, key_map, context)
        for operator, key_map in condition.items()
    )


def _operator_matches(operator: str, key_map: dict, context: dict) -> bool:
    if_exists = operator.endswith("IfExists")
    if if_exists:
        operator = operator[: -len("IfExists")]
    quantifier = None
    if operator.startswith("ForAnyValue:"):
        quantifier = "any"
        operator = operator.split(":", 1)[1]
    elif operator.startswith("ForAllValues:"):
        quantifier = "all"
        operator = operator.split(":", 1)[1]
    return all(
        _key_matches(
            operator, quantifier, if_exists, policy_value, context.get(key, _ABSENT)
        )
        for key, policy_value in key_map.items()
    )


class _Absent:
    pass


_ABSENT = _Absent()


def _key_matches(operator, quantifier, if_exists, policy_value, request_value) -> bool:
    absent = isinstance(request_value, _Absent) or request_value is None
    if absent:
        if if_exists:
            return True
        if operator == "Null":
            return _null_matches(True, policy_value)
        if operator in {"StringNotEquals", "StringNotLike"}:
            return True
        if operator in {"StringEquals", "StringLike"}:
            return False
        raise NotImplementedError(operator)
    if operator == "Null":
        return _null_matches(False, policy_value)
    policy_values = _as_strings(policy_value)
    request_values = _as_strings(request_value)
    matches = _value_matches(operator, policy_values, request_values, quantifier)
    return matches


def _null_matches(absent: bool, policy_value: object) -> bool:
    expected = policy_value
    if isinstance(expected, list):
        if len(expected) != 1:
            raise NotImplementedError("Null with multiple policy values")
        expected = expected[0]
    if isinstance(expected, bool):
        want_absent = expected
    elif expected == "true":
        want_absent = True
    elif expected == "false":
        want_absent = False
    else:
        raise AssertionError(f"unexpected Null policy value {expected!r}")
    return absent is want_absent


def _value_matches(operator, policy_values, request_values, quantifier) -> bool:
    def one(request: str) -> bool:
        if operator == "StringEquals":
            return request in policy_values
        if operator == "StringNotEquals":
            return request not in policy_values
        if operator == "StringLike":
            return any(_wildcard_match(pattern, request) for pattern in policy_values)
        if operator == "StringNotLike":
            return all(
                not _wildcard_match(pattern, request) for pattern in policy_values
            )
        raise NotImplementedError(operator)

    if quantifier == "all":
        # ForAllValues is true when the request set is empty.
        return all(one(request) for request in request_values)
    if quantifier == "any":
        return any(one(request) for request in request_values)
    # No set operator: one request value, OR across policy values. Negated
    # operators are NOR, which ``one`` already expresses for a single value.
    if len(request_values) != 1:
        raise NotImplementedError(
            f"{operator} without a set operator received {request_values!r}"
        )
    return one(request_values[0])


def scp_decision(policy: dict, action: str, context: dict, resource: str = "*") -> str:
    """Return Deny when a statement in ``policy`` explicitly denies the request.

    Allow means no statement in this SCP denies it. With FullAWSAccess attached
    beside this policy, that request is permitted to a principal whose identity
    policy allows the action.
    """
    statements = policy["Statement"]
    if isinstance(statements, dict):
        statements = [statements]
    for statement in statements:
        if statement.get("Effect") != "Deny":
            raise NotImplementedError("only Deny statements are implemented")
        actions = statement["Action"]
        if isinstance(actions, str):
            actions = [actions]
        if any("*" in item or "?" in item for item in actions):
            raise NotImplementedError(f"wildcard action {actions!r}")
        if action not in actions:
            continue
        resources = statement.get("Resource", "*")
        if isinstance(resources, str):
            resources = [resources]
        if resource not in resources and "*" not in resources:
            continue
        condition = statement.get("Condition")
        if condition is None or _condition_matches(condition, context):
            return "Deny"
    return "Allow"


def consolidated_gateway_scp() -> dict:
    """Reproduce ``local.gateway_scp_consolidated`` from the org-guardrails module."""
    gateway_tf = (MODULE / "gateway.tf").read_text()
    variables_tf = (MODULE / "variables.tf").read_text()
    if (
        'gw_dir = "${path.module}/${var.control_library_path}/scp/gateway"'
        not in gateway_tf
    ):
        raise AssertionError(
            "gateway.tf no longer reads scp/gateway from control_library_path"
        )
    rendered_body = re.search(
        r"gateway_scp_rendered = \{(.*?)\n  \}",
        gateway_tf,
        re.DOTALL,
    )
    if rendered_body is None:
        raise AssertionError("gateway_scp_rendered map not found")
    body = rendered_body.group(1)
    entries: dict[str, tuple[str, tuple[str, str] | None]] = {}
    for name, filename, sentinel, variable in _REPLACE_ENTRY.findall(body):
        entries[name] = (filename, (sentinel, variable))
    leftover = _REPLACE_ENTRY.sub("", body)
    for name, filename in _FILE_ENTRY.findall(leftover):
        entries[name] = (filename, None)
    library = (MODULE / _string_default(variables_tf, "control_library_path")).resolve()
    gateway_dir = library / "scp" / "gateway"
    on_disk = sorted(path.name for path in gateway_dir.glob("*.json"))
    if sorted(filename for filename, _replacement in entries.values()) != on_disk:
        raise AssertionError(
            f"gateway.tf map {sorted(entries)} does not cover {on_disk}"
        )
    rendered: dict[str, dict] = {}
    for name in sorted(entries):
        filename, replacement = entries[name]
        text = (gateway_dir / filename).read_text()
        if replacement is not None:
            sentinel, variable = replacement
            text = text.replace(sentinel, _string_default(variables_tf, variable))
        rendered[name] = json.loads(text)
    statements = []
    for name in sorted(rendered):
        document_statements = rendered[name]["Statement"]
        if not isinstance(document_statements, list):
            raise TypeError(f"{name} Statement is not a list")
        statements.extend(document_statements)
    return {"Version": "2012-10-17", "Statement": statements}


def _fill_wildcards(pattern: str) -> str:
    return pattern.replace("*", "sample").replace("?", "x")


def _target_context(credential_type: str, shape: str) -> dict:
    context = {
        "bedrock-agentcore:CredentialProviderType": credential_type,
        "bedrock-agentcore:PrivateEndpointType": "managedVpcResource",
    }
    if shape == "http-runtime":
        context["bedrock-agentcore:HttpTargetConfigurationType"] = "agentcoreRuntime"
    elif shape == "lambda":
        context["bedrock-agentcore:McpTargetConfigurationType"] = "lambda"
        context["bedrock-agentcore:PrivateEndpointType"] = "selfManagedLatticeResource"
    else:
        raise AssertionError(shape)
    return context


def _gateway_context(
    authorizer: str,
    *,
    discovery_url: str | None,
    mode: str = "ENFORCE",
    kms: str | None = "present",
) -> dict:
    variables_tf = (MODULE / "variables.tf").read_text()
    context = {
        "bedrock-agentcore:GatewayAuthorizerType": authorizer,
        "bedrock-agentcore:PolicyEngineArn": (
            "arn:aws:bedrock-agentcore:us-east-1:111122223333:policy-engine/example"
        ),
        "bedrock-agentcore:PolicyEngineMode": mode,
        "bedrock-agentcore:ProtocolType": _string_default(
            variables_tf, "allowed_gateway_protocol"
        ),
    }
    if kms == "present":
        context["bedrock-agentcore:KmsKeyArn"] = _fill_wildcards(
            _string_default(variables_tf, "gateway_kms_key_arn_pattern")
        )
    if discovery_url is not None:
        context["bedrock-agentcore:DiscoveryUrl"] = discovery_url
    return context


# ── Stand-in checked against the IAM rules it implements ──


def test_string_equals_is_and_of_keys_and_or_of_values():
    condition = {
        "StringEquals": {
            "aws:PrincipalTag/department": ["finance", "hr", "legal"],
            "aws:PrincipalTag/role": ["audit", "security"],
        }
    }
    assert _condition_matches(
        condition,
        {"aws:PrincipalTag/department": "legal", "aws:PrincipalTag/role": "audit"},
    )
    assert _condition_matches(
        condition,
        {"aws:PrincipalTag/department": "finance", "aws:PrincipalTag/role": "security"},
    )
    assert not _condition_matches(
        condition,
        {"aws:PrincipalTag/department": "hr", "aws:PrincipalTag/role": "payroll"},
    )
    assert not _condition_matches(
        condition,
        {"aws:PrincipalTag/department": "hr"},
    )
    assert not _condition_matches(condition, {})


def test_negated_operator_is_nor_and_true_when_key_is_absent():
    condition = {"StringNotEquals": {"aws:RequestedRegion": ["us-east-1", "eu-west-1"]}}
    assert not _condition_matches(condition, {"aws:RequestedRegion": "us-east-1"})
    assert _condition_matches(condition, {"aws:RequestedRegion": "ap-northeast-1"})
    assert _condition_matches(condition, {})


def test_null_and_if_exists_follow_key_presence():
    assert _condition_matches({"Null": {"example:Key": "true"}}, {})
    assert not _condition_matches(
        {"Null": {"example:Key": "true"}},
        {"example:Key": "value"},
    )
    assert _condition_matches(
        {"Null": {"example:Key": "false"}},
        {"example:Key": "value"},
    )
    assert not _condition_matches({"Null": {"example:Key": "false"}}, {})
    assert _condition_matches({"StringEqualsIfExists": {"example:Key": "keep"}}, {})
    assert not _condition_matches(
        {"StringEqualsIfExists": {"example:Key": "keep"}},
        {"example:Key": "drop"},
    )
    assert _condition_matches(
        {"StringEqualsIfExists": {"example:Key": "keep"}},
        {"example:Key": "keep"},
    )


def test_string_not_like_uses_wildcards_and_denies_only_on_a_miss():
    pattern = "arn:aws:kms:*:*:key/*"
    assert _wildcard_match(pattern, _fill_wildcards(pattern))
    assert not _wildcard_match(pattern, "arn:aws:kms:sample:sample:alias/sample")
    condition = {"StringNotLike": {"bedrock-agentcore:KmsKeyArn": pattern}}
    assert not _condition_matches(
        condition,
        {"bedrock-agentcore:KmsKeyArn": _fill_wildcards(pattern)},
    )
    assert _condition_matches(
        condition,
        {"bedrock-agentcore:KmsKeyArn": "arn:aws:kms:sample:sample:alias/sample"},
    )


# ── The guardrail ──


def test_consolidated_document_contains_the_library_credential_statement():
    library = load_control(CREDENTIAL_CONTROL)
    consolidated = consolidated_gateway_scp()
    matches = [
        statement
        for statement in consolidated["Statement"]
        if statement.get("Sid") == CREDENTIAL_SID
    ]
    assert matches == library["Statement"]
    assert [statement["Sid"] for statement in matches] == [CREDENTIAL_SID]


@pytest.mark.parametrize("action", TARGET_ACTIONS)
@pytest.mark.parametrize("shape", ["http-runtime", "lambda"])
def test_caller_iam_credentials_are_denied_for_each_target_action(action, shape):
    """A private HTTP runtime or Lambda target using caller IAM credentials is denied.

    The same request with the gateway IAM role, an API key, or JWT passthrough
    shows the decision changes only with the credential type. API key and JWT
    passthrough stay denied. The gateway IAM role stays allowed.
    """
    policy = consolidated_gateway_scp()
    assert (
        scp_decision(policy, action, _target_context("GATEWAY_IAM_ROLE", shape))
        == "Allow"
    )
    assert scp_decision(policy, action, _target_context("API_KEY", shape)) == "Deny"
    assert (
        scp_decision(policy, action, _target_context("JWT_PASSTHROUGH", shape))
        == "Deny"
    )
    decision = scp_decision(policy, action, _target_context(CALLER_IAM, shape))
    assert decision == "Deny", (
        f"{action} for a {shape} target with {CALLER_IAM} was {decision}"
    )


@pytest.mark.parametrize("action", TARGET_ACTIONS)
def test_individual_credential_control_denies_caller_iam_credentials(action):
    """The catalog control, attached on its own, denies the same credential type."""
    policy = load_control(CREDENTIAL_CONTROL)
    context = {"bedrock-agentcore:CredentialProviderType": CALLER_IAM}
    assert (
        scp_decision(
            policy,
            action,
            {"bedrock-agentcore:CredentialProviderType": "API_KEY"},
        )
        == "Deny"
    )
    assert (
        scp_decision(
            policy,
            action,
            {"bedrock-agentcore:CredentialProviderType": "JWT_PASSTHROUGH"},
        )
        == "Deny"
    )
    assert scp_decision(policy, action, context) == "Deny"


@pytest.mark.parametrize("action", GATEWAY_ACTIONS)
@pytest.mark.parametrize("authorizer", ["AWS_IAM", "AUTHENTICATE_ONLY"])
def test_authorizers_that_can_forward_caller_iam_are_not_denied(action, authorizer):
    """Those authorizers are the ones caller IAM credentials can be attached to.

    The consolidated SCP does not deny creating or updating them when the CMK
    and enforced policy engine required by the sibling statements are present
    and the discovery URL is absent.
    """
    policy = consolidated_gateway_scp()
    assert (
        scp_decision(policy, action, _gateway_context(authorizer, discovery_url=None))
        == "Allow"
    )


@pytest.mark.parametrize("action", GATEWAY_ACTIONS)
def test_sibling_gateway_denies_still_match(action):
    policy = consolidated_gateway_scp()
    variables_tf = (MODULE / "variables.tf").read_text()
    approved = _fill_wildcards(
        _string_default(variables_tf, "approved_discovery_url_pattern")
    )
    assert (
        scp_decision(policy, action, _gateway_context("NONE", discovery_url=None))
        == "Deny"
    )
    assert (
        scp_decision(
            policy,
            action,
            _gateway_context("AWS_IAM", discovery_url=None, kms=None),
        )
        == "Deny"
    )
    assert (
        scp_decision(
            policy,
            action,
            _gateway_context("AWS_IAM", discovery_url=None, mode="LOG_ONLY"),
        )
        == "Deny"
    )
    assert (
        scp_decision(
            policy,
            action,
            _gateway_context("CUSTOM_JWT", discovery_url=approved),
        )
        == "Allow"
    )
    assert (
        scp_decision(
            policy,
            action,
            _gateway_context("CUSTOM_JWT", discovery_url="http://sample"),
        )
        == "Deny"
    )
