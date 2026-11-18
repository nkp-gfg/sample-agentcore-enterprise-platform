"""Runtime roles may write only their own AgentCore log group.

AgentCore names each runtime's application log group
``/aws/bedrock-agentcore/runtimes/<agent_id>-<endpoint_name>`` and writes
stdout to the ``runtime-logs`` stream in that group (CloudWatch log group
ARN, and ``:log-stream:<name>`` for stream actions). The default endpoint
name used by this platform is ``DEFAULT``.

These tests synthesize the roles the app actually deploys and evaluate the
identity policy against those ARNs. They fail while one role's log statement
also matches another runtime's group, another region, or another account.

The matcher implements the resource-ARN wildcard rules in
"IAM JSON policy elements: Resource": ``*`` and ``?`` apply inside a
colon-separated segment, and a ``*`` that is the last character of a segment
may consume later segments. ``logs:PutResourcePolicy`` has an empty resource
type in the CloudWatch Logs service-authorization reference, so a statement
grants it only when ``Resource`` is ``*``.
"""

from __future__ import annotations

import re
from typing import Any

import aws_cdk as cdk
from aws_cdk.assertions import Template

from infra_utils.agentcore_role import AgentCoreRole
from infra_utils.policy_loader import load_catalog, load_control
from stacks.runtime_stack import RuntimeStack

ACCOUNT = "111111111111"
OTHER_ACCOUNT = "222222222222"
REGION = "us-east-1"
OTHER_REGION = "eu-west-1"
PARTITION = "aws"
PROJECT = "agentcore-workshop"
ENV_NAME = "dev"

# Opaque ids. They deliberately do not start with a component name, so a
# policy scoped to a component string does not collide with them by accident.
OWN_RUNTIME_ID = "agt9f3c1aorch"
OTHER_RUNTIME_ID = "agt9f3c1aresearch"
ENDPOINT = "DEFAULT"
STDOUT_STREAM = "runtime-logs"
PLANTED_STREAM = "forged-incident"

# Resource types column is empty: the action is granted only with Resource "*".
# https://docs.aws.amazon.com/service-authorization/latest/reference/list_amazoncloudwatchlogs.html
ACTIONS_REQUIRING_STAR = frozenset({"logs:putresourcepolicy"})

LOG_WRITE_ACTIONS = (
    "logs:CreateLogGroup",
    "logs:CreateLogStream",
    "logs:PutLogEvents",
)


def _log_group_name(runtime_id: str, endpoint: str = ENDPOINT) -> str:
    return f"/aws/bedrock-agentcore/runtimes/{runtime_id}-{endpoint}"


def _group_arn(
    runtime_id: str,
    *,
    region: str = REGION,
    account: str = ACCOUNT,
    partition: str = PARTITION,
) -> str:
    return (
        f"arn:{partition}:logs:{region}:{account}:log-group:"
        f"{_log_group_name(runtime_id)}"
    )


def _stream_arn(
    runtime_id: str,
    stream: str,
    *,
    region: str = REGION,
    account: str = ACCOUNT,
    partition: str = PARTITION,
) -> str:
    return f"{_group_arn(runtime_id, region=region, account=account, partition=partition)}:log-stream:{stream}"


def _segment_matches(pattern: str, text: str) -> bool:
    """Match one ARN segment. A final ``*`` may contain colons; earlier ones may not."""
    parts: list[str] = []
    for index, char in enumerate(pattern):
        if char == "*":
            parts.append(".*" if index == len(pattern) - 1 else "[^:]*")
        elif char == "?":
            parts.append("[^:]")
        else:
            parts.append(re.escape(char))
    return re.fullmatch("".join(parts), text) is not None


def _match_segments(patterns: list[str], parts: list[str]) -> bool:
    if not patterns:
        return not parts
    pattern, rest = patterns[0], patterns[1:]
    if not parts:
        return False
    if pattern.endswith("*"):
        for count in range(1, len(parts) + 1):
            chunk = ":".join(parts[:count])
            if _segment_matches(pattern, chunk) and _match_segments(rest, parts[count:]):
                return True
        return False
    return _segment_matches(pattern, parts[0]) and _match_segments(rest, parts[1:])


def arn_matches(pattern: str, arn: str) -> bool:
    """Return whether an IAM ``Resource`` pattern matches ``arn``."""
    if pattern == "*":
        return True
    return _match_segments(pattern.split(":"), arn.split(":"))


def _action_matches(pattern: str, action: str) -> bool:
    """IAM action wildcards. ``*`` matches any character, including ``:``."""
    regex = "".join(".*" if char == "*" else "." if char == "?" else re.escape(char) for char in pattern)
    return re.fullmatch(regex, action, flags=re.IGNORECASE) is not None


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _resolve(node: Any, env: dict[str, str]) -> str:
    """Resolve the CloudFormation intrinsics CDK emits inside IAM resource ARNs."""
    if isinstance(node, str):
        return node
    if isinstance(node, (int, float)):
        return str(node)
    if not isinstance(node, dict) or len(node) != 1:
        raise AssertionError(f"unsupported IAM resource node: {node!r}")
    key, value = next(iter(node.items()))
    if key == "Ref":
        if value not in env:
            raise AssertionError(f"unresolved Ref {value}")
        return env[value]
    if key == "Fn::GetAtt":
        logical, attribute = value
        token = f"{logical}.{attribute}"
        if token not in env:
            raise AssertionError(f"unresolved GetAtt {token}")
        return env[token]
    if key == "Fn::Join":
        separator, pieces = value
        return separator.join(_resolve(piece, env) for piece in pieces)
    if key == "Fn::Sub":
        if isinstance(value, str):
            template, variables = value, {}
        else:
            template, variables = value
        resolved_vars = {name: _resolve(raw, env) for name, raw in variables.items()}

        def replace(match: re.Match) -> str:
            name = match.group(1)
            if name in resolved_vars:
                return resolved_vars[name]
            if name in env:
                return env[name]
            raise AssertionError(f"unresolved Sub variable {name}")

        return re.sub(r"\$\{([^}]+)\}", replace, template)
    if key == "Fn::Select":
        index, options = value
        return _resolve(options[index], env)
    raise AssertionError(f"unsupported intrinsic {key}")


def _statement_applies(statement: dict[str, Any], action: str, arn: str, env: dict[str, str]) -> bool:
    actions = [str(item) for item in _as_list(statement.get("Action"))]
    not_actions = [str(item) for item in _as_list(statement.get("NotAction"))]
    if actions:
        action_ok = any(_action_matches(pattern, action) for pattern in actions)
    else:
        action_ok = bool(not_actions)
    if any(_action_matches(pattern, action) for pattern in not_actions):
        return False
    if not action_ok:
        return False

    if action.lower() in ACTIONS_REQUIRING_STAR:
        resources = [_resolve(item, env) for item in _as_list(statement.get("Resource"))]
        return any(resource == "*" for resource in resources)

    resources = [_resolve(item, env) for item in _as_list(statement.get("Resource"))]
    not_resources = [_resolve(item, env) for item in _as_list(statement.get("NotResource"))]
    if resources:
        resource_ok = any(arn_matches(pattern, arn) for pattern in resources)
    else:
        resource_ok = bool(not_resources)
    if any(arn_matches(pattern, arn) for pattern in not_resources):
        return False
    return resource_ok


def is_authorized(statements: list[dict[str, Any]], action: str, arn: str, env: dict[str, str]) -> bool:
    """Identity-policy result. An explicit Deny overrides Allow. Conditions are
    not treated as a substitute for the resource ARN: a statement whose
    resource matches is authorized for that object."""
    allowed = False
    for statement in statements:
        if not _statement_applies(statement, action, arn, env):
            continue
        if statement.get("Effect", "Allow") == "Deny":
            return False
        allowed = True
    return allowed


def _resources(template: dict[str, Any], resource_type: str) -> list[tuple[str, dict[str, Any]]]:
    return [
        (logical_id, resource)
        for logical_id, resource in template["Resources"].items()
        if resource["Type"] == resource_type
    ]


def _runtime_binding(template: dict[str, Any]) -> tuple[str, str]:
    """Return the runtime logical id and the role logical id it assumes."""
    runtimes = _resources(template, "AWS::BedrockAgentCore::Runtime")
    assert len(runtimes) == 1, runtimes
    runtime_id, runtime = runtimes[0]
    role_arn = runtime["Properties"]["RoleArn"]
    assert list(role_arn) == ["Fn::GetAtt"], role_arn
    role_logical, attribute = role_arn["Fn::GetAtt"]
    assert attribute == "Arn"
    return runtime_id, role_logical


def _role_statements(template: dict[str, Any], role_logical: str) -> list[dict[str, Any]]:
    statements: list[dict[str, Any]] = []
    role = template["Resources"][role_logical]["Properties"]
    for policy in role.get("Policies") or []:
        statements.extend(_as_list(policy["PolicyDocument"]["Statement"]))
    attached: set[str] = set()
    for entry in role.get("ManagedPolicyArns") or []:
        if isinstance(entry, dict) and "Ref" in entry:
            attached.add(entry["Ref"])
        elif isinstance(entry, dict) and "Fn::GetAtt" in entry:
            attached.add(entry["Fn::GetAtt"][0])
    for logical_id, resource in template["Resources"].items():
        if resource["Type"] == "AWS::IAM::Policy":
            roles = resource["Properties"].get("Roles") or []
            names = []
            for item in roles:
                if isinstance(item, dict) and "Ref" in item:
                    names.append(item["Ref"])
                elif isinstance(item, dict) and "Fn::GetAtt" in item:
                    names.append(item["Fn::GetAtt"][0])
            if role_logical in names:
                statements.extend(_as_list(resource["Properties"]["PolicyDocument"]["Statement"]))
        elif resource["Type"] == "AWS::IAM::ManagedPolicy" and logical_id in attached:
            statements.extend(_as_list(resource["Properties"]["PolicyDocument"]["Statement"]))
    return [dict(statement) for statement in statements]


def _resolution_env(template: dict[str, Any], runtime_logical: str, runtime_id: str) -> dict[str, str]:
    return {
        "AWS::Partition": PARTITION,
        "AWS::Region": REGION,
        "AWS::AccountId": ACCOUNT,
        f"{runtime_logical}.AgentRuntimeId": runtime_id,
        f"{runtime_logical}.RuntimeId": runtime_id,
    }


def _synth_runtime(component_name: str, *, migration: bool = False) -> dict[str, Any]:
    app = cdk.App()
    kwargs: dict[str, Any] = {
        "project_name": PROJECT,
        "environment": ENV_NAME,
        "component_name": component_name,
        "source_dir": "agent-code",
        "env": cdk.Environment(account=ACCOUNT, region=REGION),
    }
    if migration:
        kwargs.update(
            runtime_type="orchestrator",
            build_context="migration/simulation/existing-ec2-agent",
            build_dockerfile="Dockerfile",
            adapter_dir="migration/adapter",
        )
    else:
        kwargs.update(
            dockerfile_pattern=component_name if component_name != "orchestrator" else "orchestrator",
            runtime_type="orchestrator" if component_name == "orchestrator" else "a2a_agent",
        )
    stack = RuntimeStack(app, f"Runtime{component_name}", **kwargs)
    return Template.from_stack(stack).to_json()


def _runtime_policy(template: dict[str, Any], runtime_id: str) -> tuple[list[dict[str, Any]], dict[str, str]]:
    runtime_logical, role_logical = _runtime_binding(template)
    return (
        _role_statements(template, role_logical),
        _resolution_env(template, runtime_logical, runtime_id),
    )


def test_iam_arn_matcher_follows_documented_wildcard_rules():
    """Examples copied from the IAM and CloudWatch Logs identity-policy docs.

    S3 wildcards stay inside one colon segment. A trailing segment ``*`` matches
    a log-stream ARN (``:log-stream:name``) and does not match the bare log-group
    ARN. ``arn:aws:logs:*:*:*`` matches every logs resource shape.
    """
    bucket = "arn:aws:s3:::amzn-s3-demo-bucket/*/test/*"
    assert arn_matches(bucket, "arn:aws:s3:::amzn-s3-demo-bucket/1/test/object.jpg")
    assert arn_matches(bucket, "arn:aws:s3:::amzn-s3-demo-bucket/1/2/test/3/object.jpg")
    assert arn_matches(bucket, "arn:aws:s3:::amzn-s3-demo-bucket//test/object.jpg")
    assert not arn_matches(bucket, "arn:aws:s3:::amzn-s3-demo-bucket/1-test/object.jpg")
    assert not arn_matches(bucket, "arn:aws:s3:::amzn-s3-demo-bucket/test/object.jpg")
    assert not arn_matches(bucket, "arn:aws:s3:::amzn-s3-demo-bucket/1/2/test.jpg")

    stream_pattern = "arn:aws:logs:us-west-2:123456789012:log-group:SampleLogGroupName:*"
    stream = (
        "arn:aws:logs:us-west-2:123456789012:log-group:SampleLogGroupName"
        ":log-stream:MyStream"
    )
    group = "arn:aws:logs:us-west-2:123456789012:log-group:SampleLogGroupName"
    assert arn_matches(stream_pattern, stream)
    assert not arn_matches(stream_pattern, group)

    any_logs = "arn:aws:logs:*:*:*"
    assert arn_matches(any_logs, group)
    assert arn_matches(any_logs, stream)

    runtime_pattern = "arn:aws:logs:*:*:log-group:/aws/bedrock-agentcore/runtimes/*"
    own_stream = _stream_arn(OWN_RUNTIME_ID, STDOUT_STREAM)
    other_stream = _stream_arn(OTHER_RUNTIME_ID, PLANTED_STREAM)
    other_group = _group_arn(OTHER_RUNTIME_ID)
    assert arn_matches(runtime_pattern, own_stream)
    assert arn_matches(runtime_pattern, other_stream)
    assert arn_matches(runtime_pattern, other_group)
    assert arn_matches(runtime_pattern, _stream_arn(OTHER_RUNTIME_ID, STDOUT_STREAM, region=OTHER_REGION))
    assert arn_matches(runtime_pattern, _stream_arn(OTHER_RUNTIME_ID, STDOUT_STREAM, account=OTHER_ACCOUNT))
    assert not arn_matches(
        runtime_pattern,
        f"arn:aws:logs:{REGION}:{ACCOUNT}:log-group:/aws/bedrock-agentcore/{PROJECT}-{ENV_NAME}/orchestrator",
    )


def _assert_log_writes_confined(statements: list[dict[str, Any]], env: dict[str, str], owner: str) -> None:
    """``owner`` may write its own default log group and no other runtime's."""
    leaks = []
    foreign_targets = {
        "logs:CreateLogGroup": _group_arn(OTHER_RUNTIME_ID),
        "logs:CreateLogStream": _stream_arn(OTHER_RUNTIME_ID, PLANTED_STREAM),
        "logs:PutLogEvents": _stream_arn(OTHER_RUNTIME_ID, PLANTED_STREAM),
    }
    for action, arn in foreign_targets.items():
        if is_authorized(statements, action, arn, env):
            leaks.append(f"{owner} allows {action} on {arn}")
    for action in ("logs:CreateLogStream", "logs:PutLogEvents"):
        cross_region = _stream_arn(OWN_RUNTIME_ID, STDOUT_STREAM, region=OTHER_REGION)
        cross_account = _stream_arn(OWN_RUNTIME_ID, STDOUT_STREAM, account=OTHER_ACCOUNT)
        if is_authorized(statements, action, cross_region, env):
            leaks.append(f"{owner} allows {action} on {cross_region}")
        if is_authorized(statements, action, cross_account, env):
            leaks.append(f"{owner} allows {action} on {cross_account}")
    if is_authorized(statements, "logs:PutResourcePolicy", _group_arn(OTHER_RUNTIME_ID), env):
        leaks.append(f"{owner} allows logs:PutResourcePolicy on another runtime log group")
    if is_authorized(statements, "logs:PutResourcePolicy", "*", env):
        leaks.append(f"{owner} allows logs:PutResourcePolicy on *")
    assert not leaks, "log permissions reach another runtime, region, or account:\n" + "\n".join(leaks)

    own_targets = {
        "logs:CreateLogGroup": _group_arn(OWN_RUNTIME_ID),
        "logs:CreateLogStream": _stream_arn(OWN_RUNTIME_ID, STDOUT_STREAM),
        "logs:PutLogEvents": _stream_arn(OWN_RUNTIME_ID, STDOUT_STREAM),
        "logs:PutLogEvents#planted": _stream_arn(OWN_RUNTIME_ID, PLANTED_STREAM),
    }
    # The planted name is still this runtime's stream; the action is PutLogEvents.
    own_targets["logs:CreateLogStream#planted"] = _stream_arn(OWN_RUNTIME_ID, PLANTED_STREAM)
    missing = []
    for key, arn in own_targets.items():
        action = key.split("#", 1)[0]
        if not is_authorized(statements, action, arn, env):
            missing.append(f"{owner} denies {action} on its own log resource {arn}")
    assert not missing, "the runtime can no longer write its own log group:\n" + "\n".join(missing)


def test_each_deployed_runtime_role_writes_only_its_own_log_group():
    """Orchestrator, research-agent, and a migration runtime each get their own role.

    The role under test is the one ``AWS::BedrockAgentCore::Runtime`` assumes,
    which is the role a process inside that runtime's microVM receives.
    """
    cases = {
        "orchestrator": _synth_runtime("orchestrator"),
        "research-agent": _synth_runtime("research-agent"),
        "migration-orchestrator": _synth_runtime("orchestrator", migration=True),
    }
    role_names = set()
    for component, template in cases.items():
        _runtime_logical, role_logical = _runtime_binding(template)
        role_name = template["Resources"][role_logical]["Properties"]["RoleName"]
        assert component.split("-")[0] in role_name or "orchestrator" in role_name
        role_names.add(role_name)
        statements, env = _runtime_policy(template, OWN_RUNTIME_ID)
        _assert_log_writes_confined(statements, env, role_name)
    assert len(role_names) == 2


def test_reusable_agentcore_role_cannot_write_every_runtime_log_group():
    """``AgentCoreRole`` grants the same three log actions on the shared wildcard."""
    app = cdk.App()
    stack = cdk.Stack(app, "RoleProbe", env=cdk.Environment(account=ACCOUNT, region=REGION))
    AgentCoreRole(stack, "Role", project_name=PROJECT, component_name="orchestrator")
    template = Template.from_stack(stack).to_json()
    roles = _resources(template, "AWS::IAM::Role")
    assert len(roles) == 1
    statements = _role_statements(template, roles[0][0])
    env = _resolution_env(template, "Runtime", OWN_RUNTIME_ID)
    for action, arn in (
        ("logs:CreateLogGroup", _group_arn(OTHER_RUNTIME_ID)),
        ("logs:CreateLogStream", _stream_arn(OTHER_RUNTIME_ID, PLANTED_STREAM)),
        ("logs:PutLogEvents", _stream_arn(OTHER_RUNTIME_ID, STDOUT_STREAM)),
        ("logs:PutLogEvents", _stream_arn(OWN_RUNTIME_ID, STDOUT_STREAM, region=OTHER_REGION)),
        ("logs:PutLogEvents", _stream_arn(OWN_RUNTIME_ID, STDOUT_STREAM, account=OTHER_ACCOUNT)),
    ):
        assert not is_authorized(statements, action, arn, env), f"AgentCoreRole allows {action} on {arn}"


def test_reference_runtime_policy_cannot_write_every_runtime_log_group():
    """The control-library reference is rendered with its catalog parameters.

    Extra required parameters are filled so a runtime-specific token can name
    one group. ``runtimes/*`` still matches every runtime in the account.
    """
    catalog = load_catalog()
    entry = next(
        item for item in catalog["controls"] if item["id"] == "iam.runtime-execution-least-privilege"
    )
    params: dict[str, str] = {
        "region": REGION,
        "account_id": ACCOUNT,
        "project": PROJECT,
    }
    for name, spec in (entry.get("params") or {}).items():
        if name in params or "default" in (spec or {}):
            continue
        if (spec or {}).get("required"):
            params[name] = OWN_RUNTIME_ID if "runtime" in name or "log" in name else "scoped-value"
    document = load_control("iam.runtime-execution-least-privilege", params)
    statements = [dict(statement) for statement in document["Statement"]]
    env = {"AWS::Partition": PARTITION, "AWS::Region": REGION, "AWS::AccountId": ACCOUNT}
    for action in LOG_WRITE_ACTIONS:
        arn = (
            _group_arn(OTHER_RUNTIME_ID)
            if action == "logs:CreateLogGroup"
            else _stream_arn(OTHER_RUNTIME_ID, PLANTED_STREAM)
        )
        assert not is_authorized(statements, action, arn, env), (
            f"reference policy allows {action} on another runtime ({arn})"
        )
