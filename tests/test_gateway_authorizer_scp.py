"""The attached gateway SCP must deny authorizers that do not authorize callers.

``control-library/terraform/org-guardrails/gateway.tf`` merges every file under
``control-library/scp/gateway/`` into the single document published as
``aws_organizations_policy.gateway.content``. These tests render that local
with Terraform and evaluate it the way IAM evaluates an SCP deny layered on
``FullAWSAccess``:

* Operators in one ``Condition`` are AND, and values of one key are OR, except
  a negated operator, whose values are NOR (IAM User Guide, "Conditions with
  multiple context keys or values").
* ``StringEquals`` is case-sensitive. ``StringLike`` / ``StringNotLike`` use
  ``*`` and ``?`` wildcards. A missing key makes a positive operator false and
  a negated operator such as ``StringNotLike`` or ``StringNotEquals`` true.
  ``Null`` is the exception and tests presence (IAM User Guide, "IAM JSON
  policy elements: Condition operators").
* A matching ``Deny`` in the SCP blocks the action even for an account
  administrator (Organizations User Guide, "SCP effects on permissions").
  ``FullAWSAccess`` allows the action when no deny matches.

``bedrock-agentcore:GatewayAuthorizerType`` is the authorizer configured on
``CreateGateway`` and ``UpdateGateway``. ``AUTHENTICATE_ONLY`` is a valid
authorizer type: the gateway checks the caller's SigV4 signature and forwards
the request without an IAM authorization decision. A target that uses
``GATEWAY_IAM_ROLE`` is then called with the gateway service role.

The requests below satisfy every other statement in the merged document (CMK
pattern, policy engine in ``ENFORCE``, approved protocol, no unapproved
discovery URL, private endpoint, and a gateway-role target). They differ only
by authorizer type.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
MODULE = REPO / "control-library" / "terraform" / "org-guardrails"
GATEWAY_TF = MODULE / "gateway.tf"

CREATE_GATEWAY = "bedrock-agentcore:CreateGateway"
UPDATE_GATEWAY = "bedrock-agentcore:UpdateGateway"
CREATE_TARGET = "bedrock-agentcore:CreateGatewayTarget"
UPDATE_TARGET = "bedrock-agentcore:UpdateGatewayTarget"

AUTHORIZER = "bedrock-agentcore:GatewayAuthorizerType"
KMS_KEY = "bedrock-agentcore:KmsKeyArn"
POLICY_ENGINE_ARN = "bedrock-agentcore:PolicyEngineArn"
POLICY_ENGINE_MODE = "bedrock-agentcore:PolicyEngineMode"
PROTOCOL = "bedrock-agentcore:ProtocolType"
DISCOVERY_URL = "bedrock-agentcore:DiscoveryUrl"
CREDENTIAL_PROVIDER = "bedrock-agentcore:CredentialProviderType"
PRIVATE_ENDPOINT = "bedrock-agentcore:PrivateEndpointType"
MCP_TARGET_TYPE = "bedrock-agentcore:McpTargetConfigurationType"

# Shipped defaults in variables.tf. The CMK and discovery patterns are the
# sentinels gateway.tf injects before the documents are merged.
APPROVED_CMK = "arn:aws:kms:us-east-1:123456789012:key/11111111-2222-3333-4444-555555555555"
POLICY_ENGINE = "arn:aws:bedrock-agentcore:us-east-1:123456789012:policy-engine/member-engine"
APPROVED_DISCOVERY = "https://idp.example.com/.well-known/openid-configuration"

OTHER_GATEWAY_DENIES = {
    "DenyGatewayWithoutCMK",
    "DenyGatewayWithNonApprovedCMK",
    "DenyGatewayWithoutPolicyEngine",
    "DenyGatewayPolicyEngineNotEnforced",
    "DenyGatewayWithUnapprovedDiscoveryUrl",
    "DenyNonApprovedGatewayProtocol",
}


def _string_like(value: str, pattern: str) -> bool:
    """Case-sensitive ``*`` / ``?`` match of the whole string."""
    parts: list[str] = []
    for char in pattern:
        if char == "*":
            parts.append(".*")
        elif char == "?":
            parts.append(".")
        else:
            parts.append(re.escape(char))
    return re.fullmatch("".join(parts), value) is not None


def _values(raw: object) -> list[str]:
    if isinstance(raw, list):
        return [str(item) for item in raw]
    return [str(raw)]


def _operator_matches(operator: str, policy_values: list[str], request_values: list[str] | None) -> bool:
    negated = "Not" in operator
    if request_values is None:
        # Missing key: positive operators do not match; negated operators do.
        # Null is handled by the caller.
        return negated

    def one(policy_value: str, request_value: str) -> bool:
        if operator in ("StringEquals", "StringNotEquals"):
            return request_value == policy_value
        if operator in ("StringLike", "StringNotLike"):
            return _string_like(request_value, policy_value)
        raise AssertionError(f"operator {operator} is not used by the gateway SCP")

    # Positive operators OR their values. Negated operators NOR them: true
    # only when every policy value fails to match.
    matched = any(
        one(policy_value, request_value)
        for policy_value in policy_values
        for request_value in request_values
    )
    return not matched if negated else matched


def _condition_matches(condition: dict, context: dict[str, str]) -> bool:
    for operator, keys in condition.items():
        if operator == "Null":
            for key, expected in keys.items():
                present = key in context and context[key] is not None
                wants_absent = str(expected).lower() == "true"
                if wants_absent == present:
                    return False
            continue
        for key, raw_values in keys.items():
            request_values = [context[key]] if key in context else None
            if not _operator_matches(operator, _values(raw_values), request_values):
                return False
    return True


def _statement_denies(statement: dict, action: str, context: dict[str, str]) -> bool:
    if statement.get("Effect") != "Deny":
        return False
    actions = statement["Action"]
    if isinstance(actions, str):
        actions = [actions]
    if action not in actions:
        return False
    resources = statement.get("Resource", "*")
    if isinstance(resources, str):
        resources = [resources]
    if "*" not in resources:
        return False
    condition = statement.get("Condition")
    return condition is None or _condition_matches(condition, context)


def deny_sids(policy: dict, action: str, context: dict[str, str]) -> list[str]:
    """Sids of SCP deny statements that match this request context."""
    return [
        statement["Sid"]
        for statement in policy["Statement"]
        if _statement_denies(statement, action, context)
    ]


def _render_consolidated_scp() -> dict:
    terraform = shutil.which("terraform")
    if terraform is None:
        pytest.fail("terraform is not on PATH; the SCP under test is rendered by gateway.tf")
    init = subprocess.run(
        [terraform, f"-chdir={MODULE}", "init", "-backend=false", "-input=false"],
        check=False,
        capture_output=True,
        text=True,
    )
    if init.returncode != 0:
        pytest.fail(f"terraform init failed:\n{init.stdout}\n{init.stderr}")
    console = subprocess.run(
        [
            terraform,
            f"-chdir={MODULE}",
            "console",
            "-var",
            'target_ids=["123456789012"]',
        ],
        input="local.gateway_scp_consolidated\n",
        check=False,
        capture_output=True,
        text=True,
    )
    if console.returncode != 0:
        pytest.fail(f"terraform console failed:\n{console.stdout}\n{console.stderr}")
    rendered = json.loads(console.stdout.strip().splitlines()[-1])
    return json.loads(rendered)


@pytest.fixture(scope="module")
def gateway_scp() -> dict:
    source = GATEWAY_TF.read_text()
    assert 'content     = local.gateway_scp_consolidated' in source
    policy = _render_consolidated_scp()
    assert policy["Version"] == "2012-10-17"
    assert any(statement["Sid"] == "DenyNoAuthGateway" for statement in policy["Statement"])
    return policy


def _gateway_request(authorizer: str, *, discovery_url: str | None = None, mode: str = "ENFORCE") -> dict[str, str]:
    context = {
        AUTHORIZER: authorizer,
        KMS_KEY: APPROVED_CMK,
        POLICY_ENGINE_ARN: POLICY_ENGINE,
        POLICY_ENGINE_MODE: mode,
        PROTOCOL: "MCP",
    }
    if discovery_url is not None:
        context[DISCOVERY_URL] = discovery_url
    return context


def _target_request(credential_provider: str, *, mcp_type: str = "lambda") -> dict[str, str]:
    return {
        CREDENTIAL_PROVIDER: credential_provider,
        PRIVATE_ENDPOINT: "managedVpcResource",
        MCP_TARGET_TYPE: mcp_type,
    }


@pytest.mark.parametrize("action", [CREATE_GATEWAY, UPDATE_GATEWAY])
def test_authenticate_only_is_denied_when_every_other_guardrail_is_met(gateway_scp, action):
    """AUTHENTICATE_ONLY must be denied by the authorizer statement itself.

    The request carries an approved CMK, a policy engine in ENFORCE, and the
    MCP protocol, and it omits DiscoveryUrl. Those are the inputs the sibling
    denies look at. The only difference from the allowed AWS_IAM request is
    the authorizer type.
    """
    authenticate_only = deny_sids(
        gateway_scp, action, _gateway_request("AUTHENTICATE_ONLY")
    )
    aws_iam = deny_sids(gateway_scp, action, _gateway_request("AWS_IAM"))
    custom_jwt = deny_sids(
        gateway_scp,
        action,
        _gateway_request("CUSTOM_JWT", discovery_url=APPROVED_DISCOVERY),
    )

    assert not aws_iam, f"{action} with AWS_IAM was denied by {aws_iam}"
    assert not custom_jwt, f"{action} with CUSTOM_JWT was denied by {custom_jwt}"
    assert authenticate_only, (
        f"{action} with AUTHENTICATE_ONLY was not denied. "
        "The gateway checks SigV4 and forwards the call with no IAM authorization."
    )
    assert not (set(authenticate_only) & OTHER_GATEWAY_DENIES), (
        f"{action} with AUTHENTICATE_ONLY was denied by another guardrail "
        f"{authenticate_only}, not by the authorizer condition"
    )


@pytest.mark.parametrize("action", [CREATE_GATEWAY, UPDATE_GATEWAY])
def test_none_authorizer_stays_denied(gateway_scp, action):
    denied = deny_sids(gateway_scp, action, _gateway_request("NONE"))
    assert "DenyNoAuthGateway" in denied


@pytest.mark.parametrize("action", [CREATE_GATEWAY, UPDATE_GATEWAY])
def test_log_only_policy_engine_is_still_denied(gateway_scp, action):
    denied = deny_sids(
        gateway_scp, action, _gateway_request("AWS_IAM", mode="LOG_ONLY")
    )
    assert "DenyGatewayPolicyEngineNotEnforced" in denied


@pytest.mark.parametrize("action", [CREATE_TARGET, UPDATE_TARGET])
def test_gateway_iam_role_target_is_not_denied(gateway_scp, action):
    """A target invoked with the gateway service role is outside the authorizer deny.

    The credential-provider statement denies API_KEY and JWT_PASSTHROUGH only,
    so GATEWAY_IAM_ROLE on a private lambda target is allowed.
    """
    allowed = deny_sids(
        gateway_scp, action, _target_request("GATEWAY_IAM_ROLE")
    )
    blocked = deny_sids(gateway_scp, action, _target_request("API_KEY"))
    assert not allowed, f"{action} with GATEWAY_IAM_ROLE was denied by {allowed}"
    assert "DenyDisallowedTargetCredentialProviders" in blocked


def test_string_like_matches_the_shipped_kms_pattern():
    pattern = "arn:aws:kms:*:*:key/*"
    assert _string_like(APPROVED_CMK, pattern)
    assert not _string_like("arn:aws:kms:us-east-1:123456789012:alias/other", pattern)
    assert _operator_matches("StringEquals", ["NONE", "AUTHENTICATE_ONLY"], ["AUTHENTICATE_ONLY"])
    assert not _operator_matches("StringEquals", ["NONE"], ["AUTHENTICATE_ONLY"])
    assert not _operator_matches("StringNotEquals", ["ENFORCE"], ["ENFORCE"])
    assert _operator_matches("StringNotEquals", ["lambda", "mcpServer"], ["apiGateway"])
    assert _operator_matches("StringNotLike", ["https://*"], None)
    assert not _operator_matches("StringEquals", ["NONE"], None)
