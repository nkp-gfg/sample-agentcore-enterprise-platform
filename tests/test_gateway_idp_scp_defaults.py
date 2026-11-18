"""Default gateway and memory SCP patterns must not approve an attacker's IdP or KMS key.

The org-guardrails module injects ``approved_discovery_url_pattern``,
``gateway_kms_key_arn_pattern``, and ``kms_key_arn_pattern`` into the SCP
documents it attaches. With no operator-supplied value, those variables (and the
matching catalog defaults used by ``policy_loader``) are broad enough that the
StringNotLike denies do not match an HTTPS discovery URL the caller chooses or
a customer-managed key in another account.

These tests render that unsubstituted policy and evaluate it the way IAM
evaluates an SCP deny: every condition operator in a statement is AND, a single
negated operator with several values is NOR, ``*`` and ``?`` are case-sensitive
wildcards, a missing key makes ``StringNotLike`` true, and ``Null`` is only a
presence test. An explicit deny is the SCP refusing the call. No matching deny
means the SCP allows it (FullAWSAccess plus an identity policy that already
permits the action).

A render that refuses to produce a policy until the operator passes a pattern
is fail-closed and satisfies the tests. UpdateMemory is not covered: the memory
SCP does not name that action, and the service authorization reference does not
list ``bedrock-agentcore:KmsKeyArn`` on it.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

from infra_utils.policy_loader import load_control

REPO = Path(__file__).resolve().parents[1]
MODULE = REPO / "control-library" / "terraform" / "org-guardrails"
VARIABLES = MODULE / "variables.tf"
GATEWAY_DIR = REPO / "control-library" / "scp" / "gateway"
MEMORY_SCP = REPO / "control-library" / "scp" / "memory" / "enforce-cmk.json"

# CreateGateway accepts this shape (CustomJWTAuthorizerConfiguration.discoveryUrl).
ATTACKER_DISCOVERY_URL = "https://attacker.example/.well-known/openid-configuration"
OTHER_ATTACKER_DISCOVERY_URL = "https://evil.invalid/.well-known/openid-configuration"
NON_HTTPS_DISCOVERY_URL = "http://attacker.example/.well-known/openid-configuration"
ORG_DISCOVERY_URL = "https://login.example.com/tenant/.well-known/openid-configuration"

# CreateGateway kmsKeyArn / CreateMemory encryptionKeyArn. Account 999988887777 is not the org.
FOREIGN_KEY_ARN = (
    "arn:aws:kms:us-east-1:999988887777:key/11111111-2222-3333-4444-555555555555"
)
ORG_KEY_ARN = (
    "arn:aws:kms:us-east-1:111122223333:key/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
)
ORG_KEY_PATTERN = "arn:aws:kms:*:111122223333:key/*"
ORG_DISCOVERY_PATTERN = "https://login.example.com/tenant/*"

GATEWAY_ACTIONS = (
    "bedrock-agentcore:CreateGateway",
    "bedrock-agentcore:UpdateGateway",
)


class PatternsRequired(Exception):
    """The module will not emit a policy until the operator supplies a pattern."""


# ── IAM SCP evaluation (operators used by these documents) ──


def _as_list(value):
    if isinstance(value, list):
        return value
    return [value]


def _string_like(pattern: str, value: str) -> bool:
    """Case-sensitive StringLike: ``*`` is any run of characters, ``?`` is one."""
    parts: list[str] = []
    for char in pattern:
        if char == "*":
            parts.append(".*")
        elif char == "?":
            parts.append(".")
        else:
            parts.append(re.escape(char))
    return re.fullmatch("".join(parts), value) is not None


def _request_values(context: dict, key: str):
    for present, value in context.items():
        if present.lower() == key.lower():
            if value is None:
                return None
            return [str(item) for item in _as_list(value)]
    return None


def _operator_matches(operator: str, policy_value, request_values) -> bool:
    policies = [str(item) for item in _as_list(policy_value)]
    if operator == "Null":
        wants_absent = policies[0] == "true"
        return (request_values is None) if wants_absent else (request_values is not None)
    if request_values is None:
        # A missing key does not match, so a negated operator is true.
        return operator in {"StringNotEquals", "StringNotLike"}

    def one(candidate: str) -> bool:
        matches = []
        for expected in policies:
            if operator in {"StringEquals", "StringNotEquals"}:
                matches.append(candidate == expected)
            elif operator in {"StringLike", "StringNotLike"}:
                matches.append(_string_like(expected, candidate))
            else:
                raise AssertionError(f"unsupported condition operator {operator}")
        any_match = any(matches)
        if operator in {"StringNotEquals", "StringNotLike"}:
            return not any_match
        return any_match

    return all(one(candidate) for candidate in request_values)


def _condition_matches(condition: dict | None, context: dict) -> bool:
    if not condition:
        return True
    for operator, keys in condition.items():
        for key, policy_value in keys.items():
            if not _operator_matches(operator, policy_value, _request_values(context, key)):
                return False
    return True


def _action_matches(statement_action, request_action: str) -> bool:
    for action in _as_list(statement_action):
        if action == "*" or action.lower() == request_action.lower():
            return True
    return False


def explicit_deny(policy: dict, action: str, context: dict) -> bool:
    """True when an SCP statement explicitly denies this action and context."""
    for statement in policy["Statement"]:
        if statement.get("Effect") != "Deny":
            continue
        if not _action_matches(statement.get("Action"), action):
            continue
        resources = _as_list(statement.get("Resource", "*"))
        if not any(resource == "*" for resource in resources):
            continue
        if _condition_matches(statement.get("Condition"), context):
            return True
    return False


def gateway_context(
    *,
    discovery_url: str | None,
    kms_key_arn: str | None,
    authorizer_type: str = "CUSTOM_JWT",
    policy_engine_arn: str | None = (
        "arn:aws:bedrock-agentcore:us-east-1:111122223333:policy-engine/member-engine"
    ),
    policy_engine_mode: str | None = "ENFORCE",
    protocol_type: str | None = "MCP",
) -> dict:
    """Condition keys CreateGateway and UpdateGateway populate from the request.

    The gateway condition-key page lists DiscoveryUrl, KmsKeyArn, PolicyEngineArn,
    PolicyEngineMode, ProtocolType, and GatewayAuthorizerType for both actions.
    The service authorization reference maps DiscoveryUrl to
    authorizerConfiguration.customJWTAuthorizer.discoveryUrl, KmsKeyArn to the
    KMS key ARN in the request, the policy-engine keys to
    policyEngineConfiguration, ProtocolType to protocolType, and
    GatewayAuthorizerType to authorizerType. A None argument omits the key, which
    is what IAM does when the API field is absent.
    """
    context = {}
    if authorizer_type is not None:
        context["bedrock-agentcore:GatewayAuthorizerType"] = authorizer_type
    if discovery_url is not None:
        context["bedrock-agentcore:DiscoveryUrl"] = discovery_url
    if kms_key_arn is not None:
        context["bedrock-agentcore:KmsKeyArn"] = kms_key_arn
    if policy_engine_arn is not None:
        context["bedrock-agentcore:PolicyEngineArn"] = policy_engine_arn
    if policy_engine_mode is not None:
        context["bedrock-agentcore:PolicyEngineMode"] = policy_engine_mode
    if protocol_type is not None:
        context["bedrock-agentcore:ProtocolType"] = protocol_type
    return context


def memory_context(encryption_key_arn: str | None) -> dict:
    """CreateMemory exposes encryptionKeyArn as bedrock-agentcore:KmsKeyArn."""
    if encryption_key_arn is None:
        return {}
    return {"bedrock-agentcore:KmsKeyArn": encryption_key_arn}


# ── rendering the policies the module actually attaches ──


def _hcl_default(variable_name: str) -> str | None:
    text = VARIABLES.read_text()
    match = re.search(
        rf'variable "{re.escape(variable_name)}"\s*\{{(.*?)\n\}}',
        text,
        re.S,
    )
    if not match:
        raise AssertionError(f"{variable_name} is not declared in variables.tf")
    default = re.search(r'^\s*default\s*=\s*"([^"]*)"', match.group(1), re.M)
    if not default:
        return None
    return default.group(1)


def _require(variable_name: str) -> str:
    value = _hcl_default(variable_name)
    if value is None:
        raise PatternsRequired(variable_name)
    return value


def render_module_gateway_scp() -> dict:
    """Replay gateway.tf: replace() each sentinel, then merge statements in key order."""
    discovery = _require("approved_discovery_url_pattern")
    gateway_kms = _require("gateway_kms_key_arn_pattern")
    protocol = _require("allowed_gateway_protocol")
    rendered = {
        "require-cmk": (GATEWAY_DIR / "require-cmk.json")
        .read_text()
        .replace("<<kms_key_arn_pattern>>", gateway_kms),
        "deny-no-auth": (GATEWAY_DIR / "deny-no-auth.json").read_text(),
        "require-policy-engine": (GATEWAY_DIR / "require-policy-engine.json").read_text(),
        "enforce-approved-idp": (GATEWAY_DIR / "enforce-approved-idp.json")
        .read_text()
        .replace("<<approved_discovery_url_pattern>>", discovery),
        "restrict-protocol": (GATEWAY_DIR / "restrict-protocol.json")
        .read_text()
        .replace("<<allowed_protocol>>", protocol),
        "targets-require-private-endpoint": (
            GATEWAY_DIR / "targets-require-private-endpoint.json"
        ).read_text(),
        "targets-restrict-credential-provider": (
            GATEWAY_DIR / "targets-restrict-credential-provider.json"
        ).read_text(),
        "targets-restrict-type": (GATEWAY_DIR / "targets-restrict-type.json").read_text(),
    }
    statements = []
    for name in sorted(rendered):
        statements.extend(json.loads(rendered[name])["Statement"])
    return {"Version": "2012-10-17", "Statement": statements}


def render_module_memory_scp() -> dict:
    pattern = _require("kms_key_arn_pattern")
    return json.loads(MEMORY_SCP.read_text().replace("<<kms_key_arn_pattern>>", pattern))


def _terraform_console(expression: str) -> str:
    if shutil.which("terraform") is None:
        pytest.skip("terraform is not on PATH")
    if not (MODULE / ".terraform").is_dir():
        subprocess.run(
            ["terraform", "init", "-backend=false", "-input=false", "-no-color"],
            cwd=MODULE,
            check=True,
            capture_output=True,
            text=True,
        )
    completed = subprocess.run(
        ["terraform", "console", "-no-color"],
        cwd=MODULE,
        input=expression + "\n",
        capture_output=True,
        text=True,
        check=False,
    )
    output = (completed.stdout or "") + (completed.stderr or "")
    if completed.returncode != 0:
        if any(
            name in output
            for name in (
                "approved_discovery_url_pattern",
                "gateway_kms_key_arn_pattern",
                "kms_key_arn_pattern",
            )
        ):
            raise PatternsRequired(output)
        raise AssertionError(output)
    text = completed.stdout.strip()
    # console prints a one-line string as JSON and a multiline string as <<EOT.
    if text.startswith("<<EOT\n") and text.endswith("\nEOT"):
        return text[len("<<EOT\n") : -len("\nEOT")]
    return json.loads(text)


def _load_catalog_control(control_id: str, params: dict | None = None) -> dict:
    try:
        return load_control(control_id, params)
    except ValueError as exc:
        if "missing required params" in str(exc):
            raise PatternsRequired(str(exc)) from exc
        raise


def _assert_denied(policy: dict, action: str, context: dict) -> None:
    assert explicit_deny(policy, action, context), (
        f"{action} is not explicitly denied. Context keys: {sorted(context)}"
    )


# ── evaluator matches the IAM rules these policies depend on ──


def test_string_like_is_case_sensitive_and_star_crosses_delimiters():
    assert _string_like("https://*", ATTACKER_DISCOVERY_URL)
    assert _string_like("https://*", "https://attacker.example")
    assert not _string_like("https://*", NON_HTTPS_DISCOVERY_URL)
    assert not _string_like("https://*", "HTTPS://attacker.example/.well-known/openid-configuration")
    assert _string_like("arn:aws:kms:*:*:key/*", FOREIGN_KEY_ARN)
    assert not _string_like("arn:aws:kms:*:111122223333:key/*", FOREIGN_KEY_ARN)
    assert _string_like("arn:aws:kms:*:111122223333:key/*", ORG_KEY_ARN)


def test_missing_key_makes_string_not_like_true_and_null_false_checks_presence():
    absent: dict = {}
    assert _operator_matches("StringNotLike", "https://*", _request_values(absent, "bedrock-agentcore:DiscoveryUrl"))
    assert not _operator_matches("Null", "false", _request_values(absent, "bedrock-agentcore:DiscoveryUrl"))
    present = {"bedrock-agentcore:DiscoveryUrl": ATTACKER_DISCOVERY_URL}
    assert not _operator_matches(
        "StringNotLike", "https://*", _request_values(present, "bedrock-agentcore:DiscoveryUrl")
    )
    assert _operator_matches("Null", "false", _request_values(present, "bedrock-agentcore:DiscoveryUrl"))
    assert not _condition_matches(
        {
            "StringNotLike": {"bedrock-agentcore:DiscoveryUrl": "https://*"},
            "Null": {"bedrock-agentcore:DiscoveryUrl": "false"},
        },
        present,
    )


def test_terraform_console_matches_the_module_replay():
    """gateway.tf's replace() and statement merge are what the module attaches."""
    try:
        replay = render_module_gateway_scp()
    except PatternsRequired:
        with pytest.raises(PatternsRequired):
            _terraform_console("local.gateway_scp_consolidated")
        return
    rendered = json.loads(_terraform_console("local.gateway_scp_consolidated"))
    assert rendered == replay
    memory = json.loads(_terraform_console("local.cmk_scp_rendered"))
    assert memory == render_module_memory_scp()


# ── the unsubstituted policies must deny the attacker's values ──


@pytest.mark.parametrize("action", GATEWAY_ACTIONS)
@pytest.mark.parametrize(
    "discovery_url",
    [ATTACKER_DISCOVERY_URL, OTHER_ATTACKER_DISCOVERY_URL],
)
def test_default_gateway_scp_denies_attacker_https_issuer(action, discovery_url):
    try:
        policy = render_module_gateway_scp()
    except PatternsRequired:
        return
    _assert_denied(
        policy,
        action,
        gateway_context(discovery_url=discovery_url, kms_key_arn=ORG_KEY_ARN),
    )


@pytest.mark.parametrize("action", GATEWAY_ACTIONS)
def test_default_gateway_scp_denies_foreign_kms_key(action):
    try:
        policy = render_module_gateway_scp()
    except PatternsRequired:
        return
    _assert_denied(
        policy,
        action,
        gateway_context(discovery_url=ORG_DISCOVERY_URL, kms_key_arn=FOREIGN_KEY_ARN),
    )


@pytest.mark.parametrize("action", GATEWAY_ACTIONS)
def test_catalog_idp_default_denies_attacker_discovery_url(action):
    try:
        policy = _load_catalog_control("scp.gateway.enforce-approved-idp")
    except PatternsRequired:
        return
    _assert_denied(
        policy,
        action,
        {"bedrock-agentcore:DiscoveryUrl": ATTACKER_DISCOVERY_URL},
    )


@pytest.mark.parametrize("action", GATEWAY_ACTIONS)
def test_catalog_gateway_kms_default_denies_foreign_key(action):
    try:
        policy = _load_catalog_control("scp.gateway.require-cmk")
    except PatternsRequired:
        return
    _assert_denied(
        policy,
        action,
        {"bedrock-agentcore:KmsKeyArn": FOREIGN_KEY_ARN},
    )


def test_catalog_and_module_memory_defaults_deny_foreign_key():
    context = memory_context(FOREIGN_KEY_ARN)
    try:
        catalog = _load_catalog_control("scp.memory.enforce-cmk")
    except PatternsRequired:
        catalog = None
    else:
        _assert_denied(catalog, "bedrock-agentcore:CreateMemory", context)
    try:
        module = render_module_memory_scp()
    except PatternsRequired:
        module = None
    else:
        _assert_denied(module, "bedrock-agentcore:CreateMemory", context)
    assert catalog is None or module is None or explicit_deny(catalog, "bedrock-agentcore:CreateMemory", context)


def test_request_that_meets_every_other_gateway_control_is_still_denied():
    """The other merged statements do not name the IdP host or the KMS account.

    A caller who sets authorizerType CUSTOM_JWT, protocolType MCP, and their own
    policy engine in ENFORCE satisfies deny-no-auth, restrict-protocol, and
    require-policy-engine. The remaining denies are the IdP and KMS patterns.
    """
    try:
        policy = render_module_gateway_scp()
    except PatternsRequired:
        return
    for action in GATEWAY_ACTIONS:
        _assert_denied(
            policy,
            action,
            gateway_context(
                discovery_url=ATTACKER_DISCOVERY_URL,
                kms_key_arn=FOREIGN_KEY_ARN,
            ),
        )


# ── controls that already hold, and must keep holding after the defaults change ──


@pytest.mark.parametrize("action", GATEWAY_ACTIONS)
def test_default_or_pinned_scp_denies_a_non_https_discovery_url(action):
    context = gateway_context(
        discovery_url=NON_HTTPS_DISCOVERY_URL,
        kms_key_arn=ORG_KEY_ARN,
    )
    try:
        policy = render_module_gateway_scp()
    except PatternsRequired:
        policy = _load_catalog_control(
            "scp.gateway.enforce-approved-idp",
            {"approved_discovery_url_pattern": ORG_DISCOVERY_PATTERN},
        )
        context = {"bedrock-agentcore:DiscoveryUrl": NON_HTTPS_DISCOVERY_URL}
    _assert_denied(policy, action, context)


@pytest.mark.parametrize("action", GATEWAY_ACTIONS)
def test_omitted_gateway_kms_key_is_denied_and_iam_auth_omits_discovery_url(action):
    try:
        policy = render_module_gateway_scp()
    except PatternsRequired:
        policy = None
    if policy is not None:
        _assert_denied(
            policy,
            action,
            gateway_context(discovery_url=ORG_DISCOVERY_URL, kms_key_arn=None),
        )
        iam_auth = gateway_context(
            discovery_url=None,
            kms_key_arn=ORG_KEY_ARN,
            authorizer_type="AWS_IAM",
        )
        assert not explicit_deny(policy, action, iam_auth), (
            f"{action} denied a gateway that omitted DiscoveryUrl"
        )
        return
    kms = _load_catalog_control(
        "scp.gateway.require-cmk",
        {"kms_key_arn_pattern": ORG_KEY_PATTERN},
    )
    _assert_denied(kms, action, {})
    idp = _load_catalog_control(
        "scp.gateway.enforce-approved-idp",
        {"approved_discovery_url_pattern": ORG_DISCOVERY_PATTERN},
    )
    assert not explicit_deny(idp, action, {}), (
        f"{action} denied a request that omitted DiscoveryUrl"
    )


def test_omitted_memory_kms_key_is_denied():
    try:
        policy = _load_catalog_control("scp.memory.enforce-cmk")
    except PatternsRequired:
        policy = _load_catalog_control(
            "scp.memory.enforce-cmk",
            {"kms_key_arn_pattern": ORG_KEY_PATTERN},
        )
    _assert_denied(policy, "bedrock-agentcore:CreateMemory", memory_context(None))


@pytest.mark.parametrize("action", GATEWAY_ACTIONS)
def test_pinned_patterns_deny_attacker_and_allow_the_org_values(action):
    idp = _load_catalog_control(
        "scp.gateway.enforce-approved-idp",
        {"approved_discovery_url_pattern": ORG_DISCOVERY_PATTERN},
    )
    _assert_denied(idp, action, {"bedrock-agentcore:DiscoveryUrl": ATTACKER_DISCOVERY_URL})
    assert not explicit_deny(
        idp, action, {"bedrock-agentcore:DiscoveryUrl": ORG_DISCOVERY_URL}
    )
    kms = _load_catalog_control(
        "scp.gateway.require-cmk",
        {"kms_key_arn_pattern": ORG_KEY_PATTERN},
    )
    _assert_denied(kms, action, {"bedrock-agentcore:KmsKeyArn": FOREIGN_KEY_ARN})
    assert not explicit_deny(kms, action, {"bedrock-agentcore:KmsKeyArn": ORG_KEY_ARN})
    _assert_denied(kms, action, {})


def test_pinned_memory_pattern_denies_foreign_key_and_omitted_key():
    policy = _load_catalog_control(
        "scp.memory.enforce-cmk",
        {"kms_key_arn_pattern": ORG_KEY_PATTERN},
    )
    _assert_denied(policy, "bedrock-agentcore:CreateMemory", memory_context(FOREIGN_KEY_ARN))
    _assert_denied(policy, "bedrock-agentcore:CreateMemory", memory_context(None))
    assert not explicit_deny(
        policy, "bedrock-agentcore:CreateMemory", memory_context(ORG_KEY_ARN)
    )
