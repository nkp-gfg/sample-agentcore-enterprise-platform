"""Gateway role must not be able to invoke every gateway in the account.

The web-search path in ``stacks/gateway_stack.py`` is what app.py deploys for
the default region and for the workshop presets. These tests synthesize that
stack and evaluate the role's identity policy and trust policy.

They fail while the synthesized role still grants
``bedrock-agentcore:InvokeGateway`` on ``gateway/*`` or still trusts
``bedrock-agentcore.amazonaws.com`` with no source restriction. A fix passes
them when all of the following hold:

- With web search on, the only InvokeGateway resource is this gateway's ARN
  (the ``GatewayArn`` output). InvokeWebSearch stays on the service-owned
  ``aws:tool/web-search.v1`` ARN.
- The trust policy allows the service to assume the role only for this
  account and for a source ARN that matches this gateway's name, and it
  refuses a different gateway, a different account, and a request that omits
  the source keys. The source ARN has to be a string (a ``GetAtt`` of the
  gateway from the role trust is a CloudFormation cycle), scoped so it does
  not also match other gateways.

The runtime role in ``stacks/runtime_stack.py`` (``AgentCoreAccess``) also
grants ``bedrock-agentcore:InvokeGateway`` on ``*`` and uses the same
unrestricted service trust. That statement is not produced by the web-search
path and is not covered here.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import aws_cdk as cdk
import pytest
from aws_cdk.assertions import Template

from infra_utils.platform_config import load_platform_config, to_env
from stacks.gateway_stack import GatewayStack

ROOT = Path(__file__).resolve().parents[1]
APP_PY = ROOT / "app.py"
PRESETS = sorted((ROOT / "presets").glob("*.yaml"))
ACCOUNT = "111111111111"
OTHER_ACCOUNT = "222222222222"
FOREIGN_GATEWAY_SUFFIX = "0123456789"
THIS_GATEWAY_SUFFIX = "0123456789"


def _app_source_slices() -> tuple[str, str, str]:
    """Return the app.py fragments that decide the region and the flag."""
    source = APP_PY.read_text()
    cfg_start = source.index("def cfg(")
    cfg_end = source.index("# ── Configuration")
    region_start = source.index("region = (")
    region_end = source.index("account = os.environ.get")
    flag_start = source.index("WEB_SEARCH_REGIONS = ")
    flag_end = source.index("idp_type = ")
    return (
        source[cfg_start:cfg_end],
        source[region_start:region_end],
        source[flag_start:flag_end],
    )


def app_enable_web_search(
    *,
    context: dict[str, str] | None = None,
    environ: dict[str, str] | None = None,
    yaml_env: dict[str, str] | None = None,
) -> tuple[str, bool]:
    """Run app.py's own region and web-search expressions.

    ``cfg``, the region fallback, and ``enable_web_search`` are exec'd from
    the slices above so a change to those lines is what this function runs.
    """
    context = context or {}
    environ = environ or {}
    yaml_env = yaml_env or {}

    class _Node:
        def try_get_context(self, key: str) -> str:
            return context.get(key, "")

    class _Environ(dict):
        def get(self, key: str, default: str = "") -> str:
            return super().get(key, default)

    namespace = {
        "app": SimpleNamespace(node=_Node()),
        "os": SimpleNamespace(environ=_Environ(environ)),
        "_yaml_env": yaml_env,
    }
    cfg_src, region_src, flag_src = _app_source_slices()
    exec(cfg_src, namespace)  # noqa: S102 - the fragment under test
    exec(region_src, namespace)  # noqa: S102
    exec(flag_src, namespace)  # noqa: S102
    return namespace["region"], namespace["enable_web_search"]


def _glob(pattern: str, text: str) -> bool:
    """``*`` and ``?`` against one string. ``*`` matches any characters.

    This is the within-segment rule from the IAM User Guide, "IAM JSON
    policy elements: Resource": wildcards match any combination of characters
    inside a colon-delimited segment, including ``/``.
    """
    plen, tlen = len(pattern), len(text)
    ok = [[False] * (tlen + 1) for _ in range(plen + 1)]
    ok[0][0] = True
    for i in range(1, plen + 1):
        if pattern[i - 1] == "*":
            ok[i][0] = ok[i - 1][0]
        else:
            break
    for i in range(1, plen + 1):
        for j in range(1, tlen + 1):
            mark = pattern[i - 1]
            if mark == "*":
                ok[i][j] = ok[i - 1][j] or ok[i][j - 1]
            elif mark == "?" or mark == text[j - 1]:
                ok[i][j] = ok[i - 1][j - 1]
    return ok[plen][tlen]


def iam_arn_match(pattern: str, arn: str) -> bool:
    """Match an IAM resource or ArnLike pattern.

    Segments are colon-delimited. A ``*`` that is the last character of a
    segment may also consume later segments, which is the "expand beyond the
    colon boundaries" rule in the same Resource element page. ArnEquals and
    ArnLike use the same six-component wildcard rules (IAM User Guide,
    "IAM JSON policy elements: Condition operators").
    """
    return _segments(pattern.split(":"), arn.split(":"))


def _segments(pattern: list[str], value: list[str]) -> bool:
    if not pattern:
        return not value
    head, rest = pattern[0], pattern[1:]
    if head.endswith("*"):
        if value and _glob(head, value[0]) and _segments(rest, value[1:]):
            return True
        if not rest:
            return _glob(head, ":".join(value))
        for take in range(1, len(value) + 1):
            if _glob(head, ":".join(value[:take])) and _segments(rest, value[take:]):
                return True
        return False
    if not value:
        return False
    return _glob(head, value[0]) and _segments(rest, value[1:])


def _as_list(value):
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _resolve(value, *, account: str, region: str):
    """Resolve partition, account, and region tokens. Leave GetAtt as-is."""
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        return [_resolve(item, account=account, region=region) for item in value]
    if not isinstance(value, dict):
        return value
    if set(value) == {"Ref"}:
        return {
            "AWS::AccountId": account,
            "AWS::Region": region,
            "AWS::Partition": "aws",
        }.get(value["Ref"], value)
    if set(value) == {"Fn::Join"}:
        delim, parts = value["Fn::Join"]
        resolved = [_resolve(part, account=account, region=region) for part in parts]
        if all(isinstance(part, str) for part in resolved):
            return delim.join(resolved)
        return value
    if set(value) == {"Fn::Sub"} and isinstance(value["Fn::Sub"], str):
        text = (
            value["Fn::Sub"]
            .replace("${AWS::Partition}", "aws")
            .replace("${AWS::Region}", region)
            .replace("${AWS::AccountId}", account)
        )
        if "${" in text:
            return value
        return text
    if set(value) == {"Fn::GetAtt"}:
        return value
    return {
        key: _resolve(item, account=account, region=region)
        for key, item in value.items()
    }


def _covers(pattern, target) -> bool:
    if pattern == target:
        return True
    if isinstance(pattern, str) and isinstance(target, str):
        return iam_arn_match(pattern, target)
    return False


def _condition_matches(condition: dict, context: dict) -> bool:
    """AND across operators and keys. A missing key does not match.

    StringEquals is exact. ArnLike and ArnEquals are the same wildcard match.
    ``IfExists`` is true when the key is absent (IAM condition operators).
    A list of policy values matches if any value matches.
    """
    if not condition:
        return True
    for operator, keys in condition.items():
        if_exists = operator.endswith("IfExists")
        base = operator[: -len("IfExists")] if if_exists else operator
        for key, expected in keys.items():
            if key not in context:
                if if_exists:
                    continue
                return False
            actual = context[key]
            values = _as_list(expected)
            if base == "StringEquals":
                matched = any(actual == item for item in values)
            elif base in {"ArnLike", "ArnEquals", "StringLike"}:
                matched = any(
                    isinstance(actual, str)
                    and isinstance(item, str)
                    and (
                        iam_arn_match(item, actual)
                        if base != "StringLike"
                        else _glob(item, actual)
                    )
                    for item in values
                )
            else:
                return False
            if not matched:
                return False
    return True


def _synth_gateway(
    *,
    region: str,
    project_name: str,
    environment: str,
    enable_web_search: bool,
    enable_egress_filter: bool = False,
    enable_cedar: bool = False,
    kms_key_arn: str = "",
) -> dict:
    app = cdk.App()
    stack = GatewayStack(
        app,
        "gw",
        project_name=project_name,
        environment=environment,
        cognito_issuer_url=f"https://cognito-idp.{region}.amazonaws.com/{region}_example",
        cognito_allowed_clients=["client"],
        enable_web_search=enable_web_search,
        enable_egress_filter=enable_egress_filter,
        enable_cedar=enable_cedar,
        kms_key_arn=kms_key_arn,
        env=cdk.Environment(account=ACCOUNT, region=region),
    )
    return Template.from_stack(stack).to_json()


def _gateway(template: dict) -> tuple[dict, str, str]:
    gateways = [
        resource
        for resource in template["Resources"].values()
        if resource["Type"] == "AWS::BedrockAgentCore::Gateway"
    ]
    assert len(gateways) == 1
    props = gateways[0]["Properties"]
    role_arn = props["RoleArn"]
    assert list(role_arn) == ["Fn::GetAtt"]
    role_logical, _attr = role_arn["Fn::GetAtt"]
    return props, role_logical, template["Outputs"]["GatewayArn"]["Value"]


def _role_policies(template: dict, role_logical: str) -> list[dict]:
    documents = []
    for resource in template["Resources"].values():
        if resource["Type"] != "AWS::IAM::Policy":
            continue
        roles = resource["Properties"].get("Roles", [])
        if {"Ref": role_logical} not in roles:
            continue
        documents.append(resource["Properties"]["PolicyDocument"])
    role = template["Resources"][role_logical]
    for inline in _as_list(role["Properties"].get("Policies")):
        documents.append(inline["PolicyDocument"])
    return documents


def _statements(template: dict, role_logical: str) -> list[dict]:
    found = []
    for document in _role_policies(template, role_logical):
        found.extend(_as_list(document["Statement"]))
    return found


def _trust_statements(template: dict, role_logical: str) -> list[dict]:
    document = template["Resources"][role_logical]["Properties"][
        "AssumeRolePolicyDocument"
    ]
    return _as_list(document["Statement"])


def _invoke_patterns(statements: list[dict], *, account: str, region: str) -> list:
    patterns = []
    for statement in statements:
        if statement.get("Effect", "Allow") != "Allow":
            continue
        actions = _as_list(statement.get("Action"))
        if "bedrock-agentcore:InvokeGateway" not in actions:
            continue
        assert "NotResource" not in statement
        for resource in _as_list(statement.get("Resource")):
            patterns.append(_resolve(resource, account=account, region=region))
    return patterns


def _assume_allowed(statements: list[dict], context: dict) -> bool:
    for statement in statements:
        if statement.get("Effect", "Allow") != "Allow":
            continue
        actions = _as_list(statement.get("Action"))
        if "sts:AssumeRole" not in actions:
            continue
        services = _as_list(statement.get("Principal", {}).get("Service"))
        if "bedrock-agentcore.amazonaws.com" not in services:
            continue
        if _condition_matches(statement.get("Condition") or {}, context):
            return True
    return False


def _gateway_arn(region: str, account: str, gateway_id: str) -> str:
    return f"arn:aws:bedrock-agentcore:{region}:{account}:gateway/{gateway_id}"


def _assert_role_is_scoped(template: dict, *, web_search: bool) -> None:
    props, role_logical, gateway_arn = _gateway(template)
    name = props["Name"]
    account = ACCOUNT
    stack_region = _stack_region(template, role_logical)
    statements = [
        _resolve_statement(statement, account=account, region=stack_region)
        for statement in _statements(template, role_logical)
    ]
    patterns = _invoke_patterns(statements, account=account, region=stack_region)
    this_id = f"{name}-{THIS_GATEWAY_SUFFIX}"
    foreign_ids = (
        f"other-gateway-{FOREIGN_GATEWAY_SUFFIX}",
        f"{name}x-{FOREIGN_GATEWAY_SUFFIX}",
        f"x{name}-{FOREIGN_GATEWAY_SUFFIX}",
    )
    foreign_arns = [
        _gateway_arn(stack_region, account, gateway_id) for gateway_id in foreign_ids
    ]

    if web_search:
        assert patterns == [gateway_arn], patterns
        assert not any(
            _covers(pattern, foreign)
            for pattern in patterns
            for foreign in foreign_arns
        )
        search = _action_resources(statements, "bedrock-agentcore:InvokeWebSearch")
        assert search == [
            f"arn:aws:bedrock-agentcore:{stack_region}:aws:tool/web-search.v1"
        ], search
        other_tool = f"arn:aws:bedrock-agentcore:{stack_region}:aws:tool/web-search.v2"
        assert not any(_covers(pattern, other_tool) for pattern in search)
    else:
        assert patterns == [], patterns

    trust = [
        _resolve_statement(statement, account=account, region=stack_region)
        for statement in _trust_statements(template, role_logical)
    ]
    own_source = _gateway_arn(stack_region, account, this_id)
    assert _assume_allowed(
        trust,
        {"aws:SourceAccount": account, "aws:SourceArn": own_source},
    ), trust
    for foreign in foreign_arns:
        assert not _assume_allowed(
            trust,
            {"aws:SourceAccount": account, "aws:SourceArn": foreign},
        ), (foreign, trust)
    assert not _assume_allowed(
        trust,
        {
            "aws:SourceAccount": OTHER_ACCOUNT,
            "aws:SourceArn": own_source,
        },
    ), trust
    assert not _assume_allowed(trust, {}), trust


def _stack_region(template: dict, role_logical: str) -> str:
    for statement in _statements(template, role_logical):
        for resource in _as_list(statement.get("Resource")):
            if isinstance(resource, str) and resource.startswith("arn:aws:lambda:"):
                return resource.split(":")[3]
            if isinstance(resource, str) and ":bedrock-agentcore:" in resource:
                return resource.split(":")[3]
    raise AssertionError("stack region not found on the gateway role")


def _resolve_statement(statement: dict, *, account: str, region: str) -> dict:
    resolved = dict(statement)
    if "Resource" in statement:
        resolved["Resource"] = _resolve(
            statement["Resource"], account=account, region=region
        )
    if "Condition" in statement:
        resolved["Condition"] = _resolve(
            statement["Condition"], account=account, region=region
        )
    return resolved


def _action_resources(statements: list[dict], action: str) -> list:
    found = []
    for statement in statements:
        if statement.get("Effect", "Allow") != "Allow":
            continue
        if action not in _as_list(statement.get("Action")):
            continue
        found.extend(_as_list(statement.get("Resource")))
    return found


def test_iam_wildcard_follows_the_resource_element_examples():
    """Pin the matcher to the examples in the IAM Resource element page."""
    bucket = "arn:aws:s3:::amzn-s3-demo-bucket"
    pattern = f"{bucket}/*/test/*"
    assert iam_arn_match(pattern, f"{bucket}/1/test/object.jpg")
    assert iam_arn_match(pattern, f"{bucket}/1/2/test/object.jpg")
    assert iam_arn_match(pattern, f"{bucket}/1/2/test/3/object.jpg")
    assert iam_arn_match(pattern, f"{bucket}/1///test///object.jpg")
    assert not iam_arn_match(pattern, f"{bucket}/1-test/object.jpg")
    assert not iam_arn_match(pattern, f"{bucket}/test/object.jpg")
    assert not iam_arn_match(pattern, f"{bucket}/1/2/test.jpg")
    assert iam_arn_match(
        "arn:aws:iam::111111111111:user/accounting/*",
        "arn:aws:iam::111111111111:user/accounting/alice",
    )
    assert not iam_arn_match(
        "arn:aws:bedrock-agentcore:us-east-1:111111111111:gateway/*",
        "arn:aws:bedrock-agentcore:eu-west-1:111111111111:gateway/other-gateway-0123456789",
    )


def test_app_wires_the_computed_flag_into_the_gateway_stack():
    source = APP_PY.read_text()
    assert "enable_web_search=enable_web_search" in source


@pytest.mark.parametrize("region", ["us-east-1", "eu-west-1", "ap-northeast-1"])
def test_default_region_without_a_manifest_scopes_the_gateway_role(region: str):
    resolved, enabled = app_enable_web_search(
        context={"region": region} if region != "us-east-1" else {},
        environ={"CDK_DEFAULT_REGION": region},
    )
    assert resolved == region
    assert enabled is True
    template = _synth_gateway(
        region=region,
        project_name="agentcore-workshop",
        environment="dev",
        enable_web_search=enabled,
    )
    _assert_role_is_scoped(template, web_search=True)


def test_region_outside_the_launch_set_leaves_invoke_gateway_off():
    resolved, enabled = app_enable_web_search(
        environ={"CDK_DEFAULT_REGION": "eu-central-1"},
    )
    assert resolved == "eu-central-1"
    assert enabled is False
    template = _synth_gateway(
        region=resolved,
        project_name="agentcore-workshop",
        environment="dev",
        enable_web_search=enabled,
    )
    _assert_role_is_scoped(template, web_search=False)


def test_explicit_enable_outside_the_launch_regions_is_scoped_too():
    resolved, enabled = app_enable_web_search(
        context={"enable_web_search": "true", "region": "eu-central-1"},
    )
    assert resolved == "eu-central-1"
    assert enabled is True
    template = _synth_gateway(
        region=resolved,
        project_name="agentcore-workshop",
        environment="dev",
        enable_web_search=enabled,
    )
    _assert_role_is_scoped(template, web_search=True)


def test_explicit_disable_in_the_default_region_removes_the_grant():
    resolved, enabled = app_enable_web_search(
        context={"enable_web_search": "false"},
        environ={"CDK_DEFAULT_REGION": "us-east-1"},
    )
    assert resolved == "us-east-1"
    assert enabled is False
    template = _synth_gateway(
        region=resolved,
        project_name="agentcore-workshop",
        environment="dev",
        enable_web_search=enabled,
    )
    _assert_role_is_scoped(template, web_search=False)


@pytest.mark.parametrize("preset", PRESETS, ids=lambda path: path.stem)
def test_workshop_preset_gateway_role_matches_resolved_web_search(preset: Path):
    config = load_platform_config(preset)
    yaml_env = to_env(config)
    resolved, enabled = app_enable_web_search(yaml_env=yaml_env)
    assert resolved == config.region
    assert enabled is config.web_search_enabled
    template = _synth_gateway(
        region=resolved,
        project_name=config.project,
        environment=config.environment,
        enable_web_search=enabled,
    )
    _assert_role_is_scoped(template, web_search=enabled)


def test_optional_gateway_controls_do_not_widen_invoke_gateway():
    """Egress, Cedar, and a CMK still run the same web-search grant."""
    resolved, enabled = app_enable_web_search(
        environ={"CDK_DEFAULT_REGION": "us-east-1"},
    )
    assert enabled is True
    template = _synth_gateway(
        region=resolved,
        project_name="agentcore-workshop",
        environment="dev",
        enable_web_search=enabled,
        enable_egress_filter=True,
        enable_cedar=True,
        kms_key_arn=(
            "arn:aws:kms:us-east-1:111111111111:key/"
            "00000000-0000-0000-0000-000000000001"
        ),
    )
    _assert_role_is_scoped(template, web_search=True)
