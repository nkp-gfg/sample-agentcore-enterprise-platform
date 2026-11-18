"""Gateway CMK guardrail must not approve a KMS key from an arbitrary account.

The org-guardrails module attaches one consolidated SCP when enable_gateway_scps
is true. That document is built by substituting gateway_kms_key_arn_pattern into
DenyGatewayWithNonApprovedCMK. These tests render that document with Terraform
and evaluate it with the IAM StringLike / StringNotLike / StringEquals /
StringNotEquals / Null rules. They fail while a wildcard account segment still
lets CreateGateway and UpdateGateway encrypt under a key the organization does
not own.

CreateMemory is not covered. scp.memory.enforce-cmk documents its default as
"any CMK" rather than an organization-owned key.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

from infra_utils.policy_loader import load_control

REPO = Path(__file__).resolve().parents[1]
MODULE = REPO / "control-library" / "terraform" / "org-guardrails"

# CreateGateway and UpdateGateway both accept this shape, including any
# 12-digit account. Published request pattern from the AgentCore control
# plane API reference for kmsKeyArn.
KMS_KEY_ARN_PATTERN = (
    r"arn:aws(|-cn|-us-gov):kms:[a-zA-Z0-9-]*:[0-9]{12}:key/[a-zA-Z0-9-]{36}"
)

ORG_ACCOUNT = "111122223333"
EXTERNAL_ACCOUNT = "999999999999"
KEY_ID = "12345678-1234-1234-1234-123456789012"
PINNED_PATTERN = f"arn:aws:kms:*:{ORG_ACCOUNT}:key/*"

GATEWAY_ACTIONS = (
    "bedrock-agentcore:CreateGateway",
    "bedrock-agentcore:UpdateGateway",
)

# Patterns whose account segment is a wildcard. Each is paired with a key ARN
# that the pattern matches and that belongs to an account other than ORG_ACCOUNT.
WILDCARD_ACCOUNT_CASES = (
    ("arn:aws:kms:*:*:key/*", EXTERNAL_ACCOUNT),
    ("arn:aws:kms:us-east-1:*:key/*", EXTERNAL_ACCOUNT),
    ("arn:aws:kms:*:????????????:key/*", EXTERNAL_ACCOUNT),
    ("arn:aws:kms:*:11112222333*:key/*", "111122223339"),
)


def _key_arn(account: str, region: str = "us-east-1") -> str:
    return f"arn:aws:kms:{region}:{account}:key/{KEY_ID}"


def _compliant_context(kms_key_arn: str | None) -> dict[str, str]:
    """A Create/UpdateGateway request that satisfies every gateway guardrail
    except the account that owns the CMK.
    """
    context = {
        "bedrock-agentcore:GatewayAuthorizerType": "CUSTOM_JWT",
        "bedrock-agentcore:PolicyEngineArn": (
            f"arn:aws:bedrock-agentcore:us-east-1:{ORG_ACCOUNT}:policy-engine/pe-1"
        ),
        "bedrock-agentcore:PolicyEngineMode": "ENFORCE",
        "bedrock-agentcore:DiscoveryUrl": (
            "https://idp.example/.well-known/openid-configuration"
        ),
        "bedrock-agentcore:ProtocolType": "MCP",
    }
    if kms_key_arn is not None:
        context["bedrock-agentcore:KmsKeyArn"] = kms_key_arn
    return context


def wildcard_match(pattern: str, name: str) -> bool:
    """IAM StringLike match.

    Same walk as github.com/minio/pkg v3.11.0 wildcard/match.go Match and
    deepMatchRune (simple=false): '*' is any byte sequence, including ':' and
    '/', and '?' is one byte. Results are memoized; the walk is unchanged.
    """
    if pattern == "":
        return name == pattern
    if pattern == "*":
        return True

    memo: dict[tuple[int, int], bool] = {}

    def deep(start_s: int, start_p: int) -> bool:
        key = (start_s, start_p)
        cached = memo.get(key)
        if cached is not None:
            return cached
        si, pi = start_s, start_p
        while pi < len(pattern):
            char = pattern[pi]
            if char == "?":
                if si >= len(name):
                    memo[key] = False
                    return False
            elif char == "*":
                result = (
                    pi == len(pattern) - 1
                    or deep(si, pi + 1)
                    or (si < len(name) and deep(si + 1, pi))
                )
                memo[key] = result
                return result
            elif si >= len(name) or name[si] != char:
                memo[key] = False
                return False
            si += 1
            pi += 1
        result = si == len(name) and pi == len(pattern)
        memo[key] = result
        return result

    return deep(0, 0)


def _as_list(value):
    if isinstance(value, list):
        return value
    return [value]


def _request_values(context: dict[str, str], key: str) -> list[str]:
    if key not in context:
        return []
    return [context[key]]


def _parse_bool(value: str) -> bool:
    # strconv.ParseBool accepted strings, used by minio nullFunc for "true"/"false".
    normalized = value.strip().lower()
    if normalized in {"1", "t", "true"}:
        return True
    if normalized in {"0", "f", "false"}:
        return False
    raise ValueError(f"Null condition value is not a bool: {value}")


def _string_equals(policy_values, request_values: list[str]) -> bool:
    # stringFunc.eval: true when the request set intersects the policy set.
    # An empty request set (missing key) does not intersect.
    expected = set(_as_list(policy_values))
    return any(value in expected for value in request_values)


def _string_like(policy_values, request_values: list[str]) -> bool:
    # stringLikeFunc.eval with no ForAllValues/ForAnyValue qualifier.
    patterns = [str(value) for value in _as_list(policy_values)]
    for value in request_values:
        if any(wildcard_match(pattern, value) for pattern in patterns):
            return True
    return False


def _operator_matches(operator: str, policy_value, request_values: list[str]) -> bool:
    # Negated operators flip the positive result, including when the key is
    # absent: stringLikeFunc.evaluate / stringFunc.evaluate (negate) and
    # nullFunc.evaluate. github.com/minio/pkg v3.11.0.
    if operator == "StringEquals":
        return _string_equals(policy_value, request_values)
    if operator == "StringNotEquals":
        return not _string_equals(policy_value, request_values)
    if operator == "StringLike":
        return _string_like(policy_value, request_values)
    if operator == "StringNotLike":
        return not _string_like(policy_value, request_values)
    if operator == "Null":
        want_absent = _parse_bool(str(_as_list(policy_value)[0]))
        absent = len(request_values) == 0
        return absent if want_absent else not absent
    raise AssertionError(f"operator {operator} is not used by the gateway SCP")


def _condition_matches(condition: dict | None, context: dict[str, str]) -> bool:
    # Functions.Evaluate: every operator and every key is AND.
    if not condition:
        return True
    for operator, keys in condition.items():
        for key, policy_value in keys.items():
            if not _operator_matches(
                operator, policy_value, _request_values(context, key)
            ):
                return False
    return True


def _resource_matches(resource, request_resource: str) -> bool:
    return any(
        wildcard_match(str(pattern), request_resource) for pattern in _as_list(resource)
    )


def _action_matches(action, request_action: str) -> bool:
    return request_action in {str(candidate) for candidate in _as_list(action)}


def explicit_denies(policy: dict, action: str, context: dict[str, str]) -> list[str]:
    """Sids of Deny statements that match this request.

    FullAWSAccess allows every action. An SCP set allows the call only when no
    Deny statement matches (AWS Organizations, "How SCPs work with Deny").
    """
    request_resource = (
        f"arn:aws:bedrock-agentcore:us-east-1:{ORG_ACCOUNT}:gateway/gw-0123456789"
    )
    hits = []
    for statement in policy["Statement"]:
        if statement.get("Effect") != "Deny":
            continue
        if not _action_matches(statement["Action"], action):
            continue
        if not _resource_matches(statement["Resource"], request_resource):
            continue
        if _condition_matches(statement.get("Condition"), context):
            hits.append(statement.get("Sid", ""))
    return hits


def _ensure_terraform() -> str:
    found = shutil.which("terraform")
    if found:
        return found
    bundled = Path("/tmp/tfbin/terraform")
    if bundled.is_file():
        return str(bundled)
    cache = Path("/tmp/terraform-1.9.8")
    binary = cache / "terraform"
    if not binary.is_file():
        cache.mkdir(parents=True, exist_ok=True)
        archive = cache / "terraform.zip"
        subprocess.run(
            [
                "curl",
                "-fsSL",
                "-o",
                str(archive),
                "https://releases.hashicorp.com/terraform/1.9.8/terraform_1.9.8_linux_amd64.zip",
            ],
            check=True,
        )
        subprocess.run(["unzip", "-o", str(archive), "-d", str(cache)], check=True)
    return str(binary)


@pytest.fixture(scope="module")
def terraform_env():
    binary = _ensure_terraform()
    env = os.environ.copy()
    env.setdefault("AWS_ACCESS_KEY_ID", "testing")
    env.setdefault("AWS_SECRET_ACCESS_KEY", "testing")
    env.setdefault("AWS_DEFAULT_REGION", "us-east-1")
    subprocess.run(
        [binary, "init", "-backend=false", "-input=false"],
        cwd=MODULE,
        env=env,
        check=True,
        capture_output=True,
        text=True,
    )
    return binary, env


def render_gateway_scp(terraform_env, pattern: str | None):
    """Return (policy, rejected).

    rejected is true when Terraform refuses the pattern (variable validation or
    an equivalent error) instead of rendering a document. Provider and
    credential failures are test errors, not rejections.
    """
    binary, env = terraform_env
    command = [
        binary,
        "console",
        "-var",
        'target_ids=["ou-abcd-1234wxyz"]',
        "-var",
        "enable_gateway_scps=true",
    ]
    if pattern is not None:
        command.extend(["-var", f"gateway_kms_key_arn_pattern={pattern}"])
    completed = subprocess.run(
        command,
        input="local.gateway_scp_consolidated\n",
        cwd=MODULE,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    output = completed.stdout + completed.stderr
    if completed.returncode != 0:
        if (
            "InvalidClientTokenId" in output
            or "No configuration for provider" in output
        ):
            pytest.fail(f"terraform console failed before rendering the SCP:\n{output}")
        return None, True
    rendered = json.loads(completed.stdout.strip())
    if isinstance(rendered, str):
        rendered = json.loads(rendered)
    return rendered, False


def _assert_external_key_denied(policy: dict, account: str) -> None:
    arn = _key_arn(account)
    assert re.fullmatch(KMS_KEY_ARN_PATTERN, arn), arn
    context = _compliant_context(arn)
    for action in GATEWAY_ACTIONS:
        denies = explicit_denies(policy, action, context)
        assert denies, (
            f"{action} with KMS key {arn} is allowed by the consolidated "
            f"gateway SCP. Deny statements did not match."
        )


@pytest.mark.parametrize("action", GATEWAY_ACTIONS)
def test_default_consolidated_scp_denies_external_account_key(terraform_env, action):
    policy, rejected = render_gateway_scp(terraform_env, pattern=None)
    if rejected:
        return
    arn = _key_arn(EXTERNAL_ACCOUNT)
    assert re.fullmatch(KMS_KEY_ARN_PATTERN, arn)
    denies = explicit_denies(policy, action, _compliant_context(arn))
    assert denies, (
        f"{action} with an external-account CMK is allowed when "
        "gateway_kms_key_arn_pattern is left at its default"
    )


@pytest.mark.parametrize(("pattern", "account"), WILDCARD_ACCOUNT_CASES)
def test_wildcard_account_pattern_cannot_approve_foreign_key(
    terraform_env, pattern, account
):
    policy, rejected = render_gateway_scp(terraform_env, pattern=pattern)
    if rejected:
        return
    _assert_external_key_denied(policy, account)


@pytest.mark.parametrize("action", GATEWAY_ACTIONS)
def test_pinned_account_pattern_allows_that_account_and_denies_others(
    terraform_env, action
):
    policy, rejected = render_gateway_scp(terraform_env, pattern=PINNED_PATTERN)
    assert not rejected, "an account-pinned key pattern must still render"
    owned = _key_arn(ORG_ACCOUNT, region="eu-west-1")
    foreign = _key_arn(EXTERNAL_ACCOUNT)
    assert explicit_denies(policy, action, _compliant_context(owned)) == []
    assert explicit_denies(policy, action, _compliant_context(foreign))
    assert explicit_denies(policy, action, _compliant_context(None))


@pytest.mark.parametrize("action", GATEWAY_ACTIONS)
def test_missing_kms_key_is_denied_for_gateway_writes(terraform_env, action):
    policy, rejected = render_gateway_scp(terraform_env, pattern=PINNED_PATTERN)
    assert not rejected
    assert explicit_denies(policy, action, _compliant_context(None))


def test_catalog_default_denies_external_account_key():
    try:
        policy = load_control("scp.gateway.require-cmk")
    except ValueError:
        return
    _assert_external_key_denied(policy, EXTERNAL_ACCOUNT)


@pytest.mark.parametrize(("pattern", "account"), WILDCARD_ACCOUNT_CASES)
def test_catalog_wildcard_account_pattern_cannot_approve_foreign_key(pattern, account):
    try:
        policy = load_control(
            "scp.gateway.require-cmk", {"kms_key_arn_pattern": pattern}
        )
    except ValueError:
        return
    _assert_external_key_denied(policy, account)


@pytest.mark.parametrize("action", GATEWAY_ACTIONS)
def test_catalog_pinned_account_pattern_allows_that_account_and_denies_others(action):
    policy = load_control(
        "scp.gateway.require-cmk", {"kms_key_arn_pattern": PINNED_PATTERN}
    )
    owned = _key_arn(ORG_ACCOUNT)
    foreign = _key_arn(EXTERNAL_ACCOUNT)
    assert explicit_denies(policy, action, _compliant_context(owned)) == []
    assert explicit_denies(policy, action, _compliant_context(foreign))
    assert explicit_denies(policy, action, _compliant_context(None))
