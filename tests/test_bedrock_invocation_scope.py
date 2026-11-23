"""Runtime roles must not invoke Bedrock models outside the allow-list.

The deploy path is: a workshop preset (or any manifest that leaves
``agents.allowed_models`` empty) is loaded by ``load_platform_config``,
flattened by ``to_env``, and read in ``app.py`` as ``allowed_models``. That
list is passed to every ``RuntimeStack``, which calls
``RuntimeStack._attach_runtime_permissions``. An empty list builds the
``BedrockModels`` statement with ``foundation-model/*`` and
``inference-profile/*``.

These tests are the spec for closing that grant. They fail while the
wildcard fallback, the trailing foundation-model ``*``, or an
inference-profile ARN with account ``*`` is still what synthesis emits.
A validator that only rejects an empty list in production mode, or only
when the check runs and not when this function builds the statement, does
not satisfy them: the statement is synthesized directly from the list.

IAM resource matching implemented here follows the IAM User Guide section
"Using wildcards in resource ARNs": ``*`` and ``?`` apply inside a
colon-delimited segment, and a ``*`` that is the last character of a
segment may consume later segments, including the colons between them.
``Converse`` is authorized by ``bedrock:InvokeModel`` and ``ConverseStream``
by ``bedrock:InvokeModelWithResponseStream`` (Bedrock API reference for
those two operations). The ``Null`` condition operator matches when the
key is absent (IAM User Guide, "Condition operator to check existence of
condition keys").
"""

from __future__ import annotations

import re
import tempfile
from functools import lru_cache
from pathlib import Path

import aws_cdk as cdk
import pytest
from aws_cdk import aws_bedrock as bedrock
from aws_cdk import aws_iam as iam
from pydantic import ValidationError

from infra_utils.platform_config import (
    PlatformConfig,
    load_platform_config,
    to_env,
)
from stacks.runtime_stack import RuntimeStack

REPO = Path(__file__).resolve().parents[1]
PRESETS = REPO / "presets"
ACCOUNT = "111111111111"
OTHER_ACCOUNT = "222222222222"
REGION = "us-east-1"
APPROVED = "us.anthropic.claude-sonnet-4-6"
APPROVED_FOUNDATION = "anthropic.claude-sonnet-4-6"
PLAIN_MODEL = "anthropic.claude-opus-4-6-v1"

# app.py passes this same list to the orchestrator, code-agent, and
# research-agent RuntimeStack constructions. One statement builder covers
# all three roles.
INFERENCE_ACTIONS = (
    "bedrock:InvokeModel",
    "bedrock:InvokeModelWithResponseStream",
    "bedrock:Converse",
    "bedrock:ConverseStream",
)

WORKSHOP_PRESETS = (
    "greenfield.yaml",
    "distributed.yaml",
    "federated.yaml",
    "platform-team.yaml",
    "multi-agent.yaml",
    "migration.yaml",
)
SCOPED_PRESETS = (
    "production.yaml",
    "security-focused.yaml",
)

FOREIGN_FOUNDATION = (
    f"arn:aws:bedrock:us-west-2::foundation-model/amazon.titan-text-express-v1"
)
FOREIGN_PROFILE = (
    "arn:aws:bedrock:us-east-1:"
    f"{ACCOUNT}:inference-profile/us.amazon.nova-premier-v1:0"
)
OTHER_ACCOUNT_PROFILE = (
    "arn:aws:bedrock:eu-west-1:"
    f"{OTHER_ACCOUNT}:inference-profile/eu.amazon.nova-lite-v1:0"
)
APPLICATION_PROFILE = (
    f"arn:aws:bedrock:{REGION}:{ACCOUNT}:application-inference-profile/other-team"
)
APPROVED_FOUNDATION_ARN = (
    f"arn:aws:bedrock:{REGION}::foundation-model/{APPROVED_FOUNDATION}"
)
LONGER_FOUNDATION_ARN = (
    f"arn:aws:bedrock:{REGION}::foundation-model/{APPROVED_FOUNDATION}-other"
)
VERSIONED_FOUNDATION_ARN = (
    f"arn:aws:bedrock:{REGION}::foundation-model/{APPROVED_FOUNDATION}-v1:0"
)
APPROVED_PROFILE_ARN = (
    f"arn:aws:bedrock:{REGION}:{ACCOUNT}:inference-profile/{APPROVED}"
)
APPROVED_PROFILE_OTHER_REGION = (
    f"arn:aws:bedrock:eu-west-1:{ACCOUNT}:inference-profile/{APPROVED}"
)
APPROVED_PROFILE_OTHER_ACCOUNT = (
    f"arn:aws:bedrock:eu-west-1:{OTHER_ACCOUNT}:inference-profile/{APPROVED}"
)
PLAIN_EXACT_ARN = f"arn:aws:bedrock:{REGION}::foundation-model/{PLAIN_MODEL}"
PLAIN_LONGER_ARN = (
    f"arn:aws:bedrock:{REGION}::foundation-model/{PLAIN_MODEL}-extra"
)
PLAIN_VERSION_ARN = f"arn:aws:bedrock:{REGION}::foundation-model/{PLAIN_MODEL}:0"


def _glob(pattern: str, text: str) -> bool:
    parts: list[str] = []
    for char in pattern:
        if char == "*":
            parts.append(".*")
        elif char == "?":
            parts.append(".")
        else:
            parts.append(re.escape(char))
    return re.fullmatch("".join(parts), text) is not None


def arn_matches(pattern: str, arn: str) -> bool:
    """Return whether an IAM ``Resource`` pattern matches ``arn``."""
    if pattern == "*":
        return True
    pattern_segments = pattern.split(":")
    arn_segments = arn.split(":")

    def rec(pattern_index: int, arn_index: int) -> bool:
        if pattern_index == len(pattern_segments):
            return arn_index == len(arn_segments)
        segment = pattern_segments[pattern_index]
        if segment.endswith("*"):
            if arn_index >= len(arn_segments):
                return False
            if _glob(segment, arn_segments[arn_index]) and rec(
                pattern_index + 1, arn_index + 1
            ):
                return True
            for end in range(arn_index + 2, len(arn_segments) + 1):
                joined = ":".join(arn_segments[arn_index:end])
                if _glob(segment, joined) and rec(pattern_index + 1, end):
                    return True
            return False
        if arn_index >= len(arn_segments) or not _glob(segment, arn_segments[arn_index]):
            return False
        return rec(pattern_index + 1, arn_index + 1)

    return rec(0, 0)


def _resolve(node: object, account: str, region: str) -> str:
    if isinstance(node, str):
        return node
    if isinstance(node, dict) and "Fn::Join" in node:
        separator, parts = node["Fn::Join"]
        return separator.join(_resolve(part, account, region) for part in parts)
    if isinstance(node, dict) and "Ref" in node:
        ref = node["Ref"]
        if ref == "AWS::AccountId":
            return account
        if ref == "AWS::Region":
            return region
        if ref == "AWS::Partition":
            return "aws"
    if isinstance(node, dict) and "Fn::GetAtt" in node:
        # ApplyBaselineGuardrail points at the guardrail resource, not a model.
        target = node["Fn::GetAtt"]
        name = target[0] if isinstance(target, list) else target
        return f"arn:aws:bedrock:{region}:{account}:guardrail/{name}"
    raise AssertionError(f"unresolved IAM resource value: {node!r}")


def _as_list(value: object) -> list:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _condition_matches(condition: dict | None, context: dict[str, str]) -> bool:
    if not condition:
        return True
    for operator, keys in condition.items():
        if operator != "Null":
            raise AssertionError(
                f"Bedrock statement uses {operator}, which this test does not "
                "evaluate; extend the condition check before trusting the result"
            )
        for key, expected in keys.items():
            absent = key not in context or context[key] is None
            wants_absent = str(expected).lower() == "true"
            if absent != wants_absent:
                return False
    return True


def _statement_matches(
    statement: dict, action: str, resource: str, context: dict[str, str]
) -> bool:
    if "NotAction" in statement or "NotResource" in statement:
        raise AssertionError(f"unsupported statement shape: {statement}")
    if not any(arn_matches(item, action) for item in _as_list(statement.get("Action"))):
        return False
    if not _condition_matches(statement.get("Condition"), context):
        return False
    return any(
        arn_matches(item, resource) for item in _as_list(statement.get("Resource"))
    )


def decision(
    statements: list[dict],
    action: str,
    resource: str,
    context: dict[str, str] | None = None,
) -> str:
    """IAM decision for one action and resource: allow, deny, or implicit deny."""
    context = context or {}
    allowed = False
    for statement in statements:
        if not _statement_matches(statement, action, resource, context):
            continue
        effect = statement.get("Effect", "Allow")
        if effect == "Deny":
            return "deny"
        if effect == "Allow":
            allowed = True
    return "allow" if allowed else "implicit deny"


def _synthesize(
    allowed_models: list[str] | None,
    *,
    guardrail: bool = False,
) -> list[dict]:
    key = tuple(allowed_models) if allowed_models is not None else None
    return _synthesize_cached(key, guardrail)


@lru_cache(maxsize=None)
def _synthesize_cached(
    allowed_models: tuple[str, ...] | None,
    guardrail: bool,
) -> list[dict]:
    models = None if allowed_models is None else list(allowed_models)
    app = cdk.App(outdir=tempfile.mkdtemp(prefix="bedrock-scope-"))
    stack = cdk.Stack(
        app,
        "ScopeProbe",
        env=cdk.Environment(account=ACCOUNT, region=REGION),
    )
    role = iam.Role(
        stack,
        "RuntimeRole",
        assumed_by=iam.ServicePrincipal("bedrock-agentcore.amazonaws.com"),
        role_name="scope-probe-runtime-role",
    )
    guardrail_resource = None
    if guardrail:
        guardrail_resource = bedrock.CfnGuardrail(
            stack,
            "BaselineGuardrail",
            name="scope-probe-guardrail",
            description="probe",
            blocked_input_messaging="blocked",
            blocked_outputs_messaging="blocked",
        )
    RuntimeStack._attach_runtime_permissions(
        role,
        f"arn:aws:ecr:{REGION}:{ACCOUNT}:repository/example",
        project_name="agentcore-workshop",
        allowed_models=models,
        guardrail=guardrail_resource,
    )
    template = app.synth().get_stack_by_name("ScopeProbe").template
    statements: list[dict] = []
    for resource in template["Resources"].values():
        if resource["Type"] != "AWS::IAM::Policy":
            continue
        document = resource["Properties"]["PolicyDocument"]
        for statement in _as_list(document["Statement"]):
            resolved = dict(statement)
            resolved["Resource"] = [
                _resolve(item, ACCOUNT, REGION)
                for item in _as_list(statement.get("Resource"))
            ]
            statements.append(resolved)
    return statements


def authorizes(
    allowed_models: list[str] | None,
    action: str,
    resource: str,
    *,
    context: dict[str, str] | None = None,
    guardrail: bool = False,
) -> bool:
    """Whether the synthesized runtime role allows ``action`` on ``resource``.

    Raising on an empty allow-list is a closed grant: there is no role
    statement that permits the call. A non-empty list must synthesize.
    """
    try:
        statements = _synthesize(allowed_models, guardrail=guardrail)
    except Exception:
        if allowed_models:
            raise
        return False
    return decision(statements, action, resource, context) == "allow"


def allowed_models_as_app_reads_them(preset: Path) -> list[str]:
    """Same resolution as ``app.py``: ``to_env`` then the comma split.

    ``cfg`` checks context, then the process environment, then this map,
    then ``""``. The test supplies no context and no ``ALLOWED_MODELS``
    override, which is how ``deploy.sh`` runs a preset on its own.
    """
    env = to_env(load_platform_config(preset))
    raw = env.get("ALLOWED_MODELS", "")
    return [item.strip() for item in raw.split(",") if item.strip()]


# ── matcher, pinned to the IAM User Guide examples ──


S3_PATTERN = "arn:aws:s3:::amzn-s3-demo-bucket/*/test/*"
S3_MATCHES = (
    "arn:aws:s3:::amzn-s3-demo-bucket/1/test/object.jpg",
    "arn:aws:s3:::amzn-s3-demo-bucket/1/2/test/object.jpg",
    "arn:aws:s3:::amzn-s3-demo-bucket/1/2/test/3/object.jpg",
    "arn:aws:s3:::amzn-s3-demo-bucket/1/2/3/test/4/object.jpg",
    "arn:aws:s3:::amzn-s3-demo-bucket/1///test///object.jpg",
    "arn:aws:s3:::amzn-s3-demo-bucket/1/test/.jpg",
    "arn:aws:s3:::amzn-s3-demo-bucket//test/object.jpg",
    "arn:aws:s3:::amzn-s3-demo-bucket/1/test/",
)
S3_MISSES = (
    "arn:aws:s3:::amzn-s3-demo-bucket/1-test/object.jpg",
    "arn:aws:s3:::amzn-s3-demo-bucket/test/object.jpg",
    "arn:aws:s3:::amzn-s3-demo-bucket/1/2/test.jpg",
)


@pytest.mark.parametrize("arn", S3_MATCHES)
def test_iam_wildcard_matches_documented_s3_examples(arn: str):
    assert arn_matches(S3_PATTERN, arn)


@pytest.mark.parametrize("arn", S3_MISSES)
def test_iam_wildcard_rejects_documented_s3_non_matches(arn: str):
    assert not arn_matches(S3_PATTERN, arn)


def test_trailing_star_crosses_a_colon_only_when_it_ends_the_segment():
    """A model id such as ``...-v1:0`` adds a colon segment. The guide says
    a trailing ``*`` expands across that boundary; a ``*`` earlier in the
    segment does not, by itself, retarget a different resource type."""
    assert arn_matches(
        "arn:aws:bedrock:*::foundation-model/anthropic.claude-sonnet-4-6*",
        VERSIONED_FOUNDATION_ARN,
    )
    assert not arn_matches(
        "arn:aws:bedrock:*:*:inference-profile/*",
        APPLICATION_PROFILE,
    )


# ── empty allow-list: the workshop deploy path ──


@pytest.mark.parametrize("action", INFERENCE_ACTIONS)
@pytest.mark.parametrize("models", [None, []], ids=["omitted", "empty"])
def test_empty_allowlist_does_not_authorize_another_foundation_model(action, models):
    assert not authorizes(models, action, FOREIGN_FOUNDATION)


@pytest.mark.parametrize("action", INFERENCE_ACTIONS)
@pytest.mark.parametrize("models", [None, []], ids=["omitted", "empty"])
def test_empty_allowlist_does_not_authorize_another_system_inference_profile(
    action, models
):
    assert not authorizes(models, action, FOREIGN_PROFILE)
    assert not authorizes(models, action, OTHER_ACCOUNT_PROFILE)


@pytest.mark.parametrize("action", INFERENCE_ACTIONS)
def test_empty_allowlist_does_not_authorize_an_application_inference_profile(action):
    """Teams create application inference profiles. Their ARN resource type
    is ``application-inference-profile``, and the runtime role must not
    gain it by widening ``inference-profile/*`` into ``*``."""
    assert not authorizes([], action, APPLICATION_PROFILE)


@pytest.mark.parametrize("preset", WORKSHOP_PRESETS)
@pytest.mark.parametrize("action", ("bedrock:InvokeModel", "bedrock:ConverseStream"))
def test_workshop_preset_role_cannot_invoke_an_unapproved_model(preset, action):
    models = allowed_models_as_app_reads_them(PRESETS / preset)
    assert models == []
    assert not authorizes(models, action, FOREIGN_FOUNDATION)
    assert not authorizes(models, action, FOREIGN_PROFILE)


def test_workshop_mode_requires_a_nonempty_model_allowlist():
    """Production mode already rejects an empty list. Workshop mode is the
    path the presets use, and it must reject one too. Rejecting only inside
    ``_production_controls_are_complete`` leaves this default in place."""
    with pytest.raises(ValidationError) as excinfo:
        PlatformConfig()
    locations = [error["loc"] for error in excinfo.value.errors()]
    assert any("allowed_models" in location for location in locations), locations


# ── non-empty allow-list: exact model id, this account ──


@pytest.mark.parametrize("action", INFERENCE_ACTIONS)
def test_allowlist_still_permits_the_approved_model_and_profile(action):
    assert authorizes([APPROVED], action, APPROVED_FOUNDATION_ARN)
    assert authorizes([APPROVED], action, APPROVED_PROFILE_ARN)
    assert authorizes([APPROVED], action, APPROVED_PROFILE_OTHER_REGION)


@pytest.mark.parametrize("action", INFERENCE_ACTIONS)
def test_allowlist_foundation_model_arn_stops_at_the_approved_id(action):
    assert not authorizes([APPROVED], action, LONGER_FOUNDATION_ARN)
    assert not authorizes([APPROVED], action, VERSIONED_FOUNDATION_ARN)
    assert not authorizes([APPROVED], action, FOREIGN_FOUNDATION)


@pytest.mark.parametrize("action", INFERENCE_ACTIONS)
def test_allowlist_inference_profile_arn_uses_this_account(action):
    assert not authorizes([APPROVED], action, APPROVED_PROFILE_OTHER_ACCOUNT)
    assert not authorizes([APPROVED], action, FOREIGN_PROFILE)


@pytest.mark.parametrize("action", INFERENCE_ACTIONS)
def test_plain_model_id_is_not_given_a_trailing_wildcard(action):
    assert authorizes([PLAIN_MODEL], action, PLAIN_EXACT_ARN)
    assert not authorizes([PLAIN_MODEL], action, PLAIN_LONGER_ARN)
    assert not authorizes([PLAIN_MODEL], action, PLAIN_VERSION_ARN)


@pytest.mark.parametrize("preset", SCOPED_PRESETS)
def test_scoped_presets_do_not_authorize_a_longer_model_or_another_account(preset):
    models = allowed_models_as_app_reads_them(PRESETS / preset)
    assert models == [APPROVED]
    assert not authorizes(models, "bedrock:InvokeModel", LONGER_FOUNDATION_ARN)
    assert not authorizes(
        models, "bedrock:InvokeModelWithResponseStream", VERSIONED_FOUNDATION_ARN
    )
    assert not authorizes(models, "bedrock:Converse", APPROVED_PROFILE_OTHER_ACCOUNT)
    assert not authorizes(models, "bedrock:ConverseStream", FOREIGN_FOUNDATION)
    assert authorizes(models, "bedrock:InvokeModel", APPROVED_FOUNDATION_ARN)
    assert authorizes(
        models, "bedrock:InvokeModelWithResponseStream", APPROVED_PROFILE_ARN
    )


def test_guardrail_deny_does_not_substitute_for_the_model_allowlist():
    """``DenyUngovernedInference`` applies only when ``bedrock:GuardrailIdentifier``
    is absent. A call that carries a guardrail id is not denied, so the
    allow-list is still what limits the model."""
    present = {"bedrock:GuardrailIdentifier": "scope-probe-guardrail"}
    assert not authorizes(
        [],
        "bedrock:InvokeModel",
        FOREIGN_FOUNDATION,
        context=present,
        guardrail=True,
    )
    assert not authorizes(
        [APPROVED],
        "bedrock:ConverseStream",
        LONGER_FOUNDATION_ARN,
        context=present,
        guardrail=True,
    )
    assert authorizes(
        [APPROVED],
        "bedrock:InvokeModel",
        APPROVED_FOUNDATION_ARN,
        context=present,
        guardrail=True,
    )
