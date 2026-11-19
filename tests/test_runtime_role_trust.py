"""Runtime and gateway roles may be assumed only for their own resource.

The stacks create an execution role and pass it to CreateAgentRuntime /
CreateGateway as roleArn. AgentCore assumes that role. These tests synthesize
that template and evaluate the assume-role policy the service would present:

* aws:SourceAccount is the account that owns the calling resource
* aws:SourceArn is that resource's ARN

CloudFormation documents the runtime Ref value as
``arn:aws:bedrock-agentcore:region:account:runtime/<name>-<10 chars>``
(AWS::BedrockAgentCore::Runtime). The gateway identifier has the same
``<name>-<10 chars>`` shape (AWS::BedrockAgentCore::Gateway), and the control
plane ARN pattern places that identifier under ``gateway/``.

A trust policy with no conditions, or with a wildcard that also matches a
runtime or gateway the caller just created, fails. The same tests pass once
each role is limited to its own resource in this account.

They fail on purpose until that trust policy is fixed.
"""

from __future__ import annotations

import gzip
import json
import re
from pathlib import Path

import aws_cdk as cdk
import botocore
from aws_cdk.assertions import Template

from stacks.gateway_stack import GatewayStack
from stacks.runtime_stack import RuntimeStack

ACCOUNT = "111111111111"
OTHER_ACCOUNT = "222222222222"
REGION = "us-east-1"
OTHER_REGION = "eu-west-1"
PARTITION = "aws"
# Ten-character suffix from the CloudFormation runtime Ref example
# (MyRuntime-a1b2c3d4e5). The control-plane ARN patterns require exactly this
# length; the caller does not choose it.
SUFFIX = "a1b2c3d4e5"
SERVICE = "bedrock-agentcore.amazonaws.com"
ENV = cdk.Environment(account=ACCOUNT, region=REGION)

# Components app.py actually deploys, plus a second project so a condition
# hardcoded to one name cannot pass.
RUNTIME_CASES = (
    ("workshop", "dev", "orchestrator", "orchestrator"),
    ("workshop", "dev", "code-agent", "a2a_agent"),
    ("workshop", "dev", "research-agent", "a2a_agent"),
    ("otherproj", "prod", "orchestrator", "orchestrator"),
)


def _role_arn_pattern() -> str:
    """RoleArn pattern from the botocore model this environment installed.

    requirements.txt allows botocore>=1.43.72. CreateAgentRuntime and
    CreateGateway both use the RoleArn shape.
    """
    root = Path(botocore.__file__).resolve().parent / "data" / "bedrock-agentcore-control"
    version = sorted(path.name for path in root.iterdir() if path.is_dir())[-1]
    with gzip.open(root / version / "service-2.json.gz", "rt") as handle:
        model = json.load(handle)
    return model["shapes"]["RoleArn"]["pattern"]


def _runtime_arn(region: str, account: str, name: str, suffix: str = SUFFIX) -> str:
    return f"arn:{PARTITION}:bedrock-agentcore:{region}:{account}:runtime/{name}-{suffix}"


def _gateway_arn(region: str, account: str, name: str, suffix: str = SUFFIX) -> str:
    return f"arn:{PARTITION}:bedrock-agentcore:{region}:{account}:gateway/{name}-{suffix}"


def _as_list(value):
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _wild_match(pattern: str, value: str) -> bool:
    """IAM ``*`` / ``?`` match against one string. ``*`` crosses every character."""
    if not isinstance(pattern, str) or not isinstance(value, str):
        return False
    regex = []
    for char in pattern:
        if char == "*":
            regex.append(".*")
        elif char == "?":
            regex.append(".")
        else:
            regex.append(re.escape(char))
    return re.fullmatch("".join(regex), value) is not None


def _arn_parts(arn: str) -> list[str] | None:
    parts = arn.split(":", 5)
    if len(parts) != 6 or parts[0] != "arn":
        return None
    return parts


def _arn_like(pattern: str, value: str) -> bool:
    """ArnLike / ArnEquals: each of the six colon-delimited components, separately.

    A wildcard does not cross a colon. Documented in IAM condition operators.
    """
    pattern_parts = _arn_parts(pattern)
    value_parts = _arn_parts(value)
    if pattern_parts is None or value_parts is None:
        return False
    return all(_wild_match(left, right) for left, right in zip(pattern_parts, value_parts))


def _resolve(node, refs: dict, atts: dict):
    if isinstance(node, list):
        return [_resolve(item, refs, atts) for item in node]
    if not isinstance(node, dict):
        return node
    if set(node) == {"Ref"}:
        return refs.get(node["Ref"], node)
    if set(node) == {"Fn::GetAtt"}:
        attr = node["Fn::GetAtt"]
        if isinstance(attr, str):
            logical, _, name = attr.partition(".")
        else:
            logical, name = attr
        return atts.get((logical, name), node)
    if set(node) == {"Fn::Join"}:
        delim, parts = node["Fn::Join"]
        resolved = _resolve(parts, refs, atts)
        if not isinstance(resolved, list) or not all(isinstance(part, str) for part in resolved):
            return node
        return delim.join(resolved)
    if set(node) == {"Fn::Sub"}:
        spec = node["Fn::Sub"]
        if isinstance(spec, str):
            template, mapping = spec, {}
        else:
            template, mapping = spec
            mapping = _resolve(mapping, refs, atts)
        if not isinstance(mapping, dict):
            return node

        def replace(match: re.Match) -> str:
            key = match.group(1)
            mapped = mapping.get(key)
            if isinstance(mapped, str):
                return mapped
            if key in refs and isinstance(refs[key], str):
                return refs[key]
            if "." in key:
                logical, name = key.split(".", 1)
                found = atts.get((logical, name))
                if isinstance(found, str):
                    return found
            return match.group(0)

        return re.sub(r"\$\{([^}]+)\}", replace, template)
    return {key: _resolve(value, refs, atts) for key, value in node.items()}


def _condition_matches(condition: dict | None, request: dict) -> bool:
    """Every operator matches (AND). A missing key makes a positive operator false.

    ``...IfExists`` is true when the key is absent. Negated operators are true
    when the key is absent. Both are the IAM condition-operator rules.
    """
    if not condition:
        return True
    request_keys = {
        "aws:SourceAccount": request.get("source_account"),
        "aws:SourceArn": request.get("source_arn"),
    }
    for operator, comparisons in condition.items():
        if not isinstance(comparisons, dict):
            return False
        if_exists = operator.endswith("IfExists")
        base = operator[: -len("IfExists")] if if_exists else operator
        negated = False
        for prefix in ("ForAllValues:", "ForAnyValue:"):
            if base.startswith(prefix):
                base = base[len(prefix) :]
                break
        if base.startswith("StringNot") or base.startswith("ArnNot"):
            negated = True
            base = base.replace("Not", "", 1)
        for key, policy_value in comparisons.items():
            actual = request_keys.get(key, None)
            # Keys this harness does not model are absent.
            if key not in request_keys:
                actual = None
            if actual is None:
                if if_exists:
                    continue
                if negated:
                    continue
                return False
            values = [item for item in _as_list(policy_value) if isinstance(item, str)]
            if base in ("StringEquals", "StringEqualsIgnoreCase"):
                matched = any(
                    actual == item
                    if base == "StringEquals"
                    else actual.lower() == item.lower()
                    for item in values
                )
            elif base == "StringLike":
                matched = any(_wild_match(item, actual) for item in values)
            elif base in ("ArnLike", "ArnEquals"):
                matched = any(_arn_like(item, actual) for item in values)
            elif base == "Null":
                # Reached only when the key is present. "true" matches absence.
                matched = str(_as_list(policy_value)[0]).lower() == "false"
            else:
                return False
            if negated:
                matched = not matched
            if not matched:
                return False
    return True


def _principal_matches(statement: dict) -> bool:
    principal = statement.get("Principal")
    if principal == "*":
        return True
    if not isinstance(principal, dict):
        return False
    services = _as_list(principal.get("Service"))
    if SERVICE in services:
        return True
    return "*" in _as_list(principal.get("AWS"))


def _action_matches(statement: dict, action: str) -> bool:
    actions = [item for item in _as_list(statement.get("Action")) if isinstance(item, str)]
    not_actions = [item for item in _as_list(statement.get("NotAction")) if isinstance(item, str)]
    if not actions and not not_actions:
        return False
    if actions and not any(_wild_match(item, action) for item in actions):
        return False
    if any(_wild_match(item, action) for item in not_actions):
        return False
    return True


def _resource_matches(statement: dict, resource: str) -> bool:
    resources = [item for item in _as_list(statement.get("Resource")) if isinstance(item, str)]
    not_resources = [
        item for item in _as_list(statement.get("NotResource")) if isinstance(item, str)
    ]
    if resources and not any(_wild_match(item, resource) for item in resources):
        return False
    if any(_wild_match(item, resource) for item in not_resources):
        return False
    if not resources and not not_resources:
        return False
    return True


def _statements(policy: dict) -> list[dict]:
    statement = policy.get("Statement", [])
    if isinstance(statement, dict):
        return [statement]
    return list(statement)


def assume_allowed(policy: dict, request: dict) -> bool:
    """Whether this role trust policy allows the service AssumeRole request.

    An explicit Deny overrides Allow. No matching Allow is an implicit deny.
    """
    allowed = False
    denied = False
    for statement in _statements(policy):
        if not _principal_matches(statement):
            continue
        if not _action_matches(statement, "sts:AssumeRole"):
            continue
        if not _condition_matches(statement.get("Condition"), request):
            continue
        if statement.get("Effect", "Allow") == "Deny":
            denied = True
        else:
            allowed = True
    return allowed and not denied


def identity_allows(statements: list[dict], action: str, resource: str) -> bool:
    allowed = False
    denied = False
    for statement in statements:
        if statement.get("Condition"):
            continue
        if not _action_matches(statement, action):
            continue
        if not _resource_matches(statement, resource):
            continue
        if statement.get("Effect", "Allow") == "Deny":
            denied = True
        else:
            allowed = True
    return allowed and not denied


def _bindings(logical_id: str, ref_value: str, attributes: dict[str, str]) -> tuple[dict, dict]:
    refs = {
        "AWS::AccountId": ACCOUNT,
        "AWS::Partition": PARTITION,
        "AWS::Region": REGION,
        logical_id: ref_value,
    }
    atts = {(logical_id, name): value for name, value in attributes.items()}
    return refs, atts


def _resources(template: dict, resource_type: str) -> list[tuple[str, dict]]:
    return [
        (logical_id, resource)
        for logical_id, resource in template["Resources"].items()
        if resource["Type"] == resource_type
    ]


def _role_logical_id(role_arn) -> str:
    assert isinstance(role_arn, dict) and list(role_arn) == ["Fn::GetAtt"], role_arn
    logical_id, attribute = role_arn["Fn::GetAtt"]
    assert attribute == "Arn", role_arn
    return logical_id


def _assume_policy(template: dict, role_logical_id: str, refs: dict, atts: dict) -> dict:
    role = template["Resources"][role_logical_id]
    assert role["Type"] == "AWS::IAM::Role"
    return _resolve(role["Properties"]["AssumeRolePolicyDocument"], refs, atts)


def _attached_statements(template: dict, role_logical_id: str, refs: dict, atts: dict) -> list[dict]:
    found = []
    for _logical_id, resource in _resources(template, "AWS::IAM::Policy"):
        roles = resource["Properties"].get("Roles", [])
        if not any(isinstance(item, dict) and item.get("Ref") == role_logical_id for item in roles):
            continue
        document = _resolve(resource["Properties"]["PolicyDocument"], refs, atts)
        found.extend(_statements(document))
    return found


def _assert_restricted(policy: dict, legitimate: dict, denied: list[tuple[str, dict]]) -> None:
    assert assume_allowed(policy, legitimate), (
        "the resource this stack creates must still be able to assume its role. "
        f"Trust policy denied that request: {json.dumps(policy)}"
    )
    opened = [label for label, request in denied if assume_allowed(policy, request)]
    assert not opened, (
        "bedrock-agentcore.amazonaws.com was allowed to assume the role for a "
        f"resource other than the one this stack creates: {opened}. "
        f"Trust policy: {json.dumps(policy)}"
    )


def _denied_requests(
    arn_for,
    name: str,
    *,
    other_name: str,
    hyphen_suffix: bool = False,
) -> list[tuple[str, dict]]:
    own = arn_for(REGION, ACCOUNT, name)
    denied = [
        (
            "another account's resource with the same name",
            {
                "source_account": OTHER_ACCOUNT,
                "source_arn": arn_for(REGION, OTHER_ACCOUNT, name),
            },
        ),
        (
            "a resource created with a different name in this account",
            {
                "source_account": ACCOUNT,
                "source_arn": arn_for(REGION, ACCOUNT, other_name),
            },
        ),
        (
            "a resource whose name only extends this one",
            {
                "source_account": ACCOUNT,
                "source_arn": arn_for(REGION, ACCOUNT, f"{name}_other"),
            },
        ),
        (
            "the same name in another region",
            {
                "source_account": ACCOUNT,
                "source_arn": arn_for(OTHER_REGION, ACCOUNT, name),
            },
        ),
        (
            "the service principal with no source account or source ARN",
            {"source_account": None, "source_arn": None},
        ),
        (
            "the right source ARN but another account in aws:SourceAccount",
            {"source_account": OTHER_ACCOUNT, "source_arn": own},
        ),
        (
            "the right source account but no source ARN",
            {"source_account": ACCOUNT, "source_arn": None},
        ),
    ]
    if hyphen_suffix:
        # Gateway names may contain hyphens, so ``<name>-*`` also matches a
        # gateway the caller names ``<name>-evil``. Runtime names cannot
        # contain a hyphen; the generated id is the only hyphen in that ARN.
        denied.append(
            (
                "a resource whose name adds a hyphenated suffix",
                {
                    "source_account": ACCOUNT,
                    "source_arn": arn_for(REGION, ACCOUNT, f"{name}-evil"),
                },
            )
        )
    return denied


def _synth_runtime(project: str, environment: str, component: str, runtime_type: str) -> dict:
    app = cdk.App()
    stack = RuntimeStack(
        app,
        "Runtime",
        project_name=project,
        environment=environment,
        component_name=component,
        source_dir="agent-code",
        dockerfile_pattern=component,
        runtime_type=runtime_type,
        env=ENV,
    )
    return Template.from_stack(stack).to_json()


def test_create_agent_runtime_accepts_a_role_arn_from_any_account() -> None:
    """The control-plane RoleArn pattern is not limited to the caller's account."""
    pattern = _role_arn_pattern()
    victim = f"arn:{PARTITION}:iam::{ACCOUNT}:role/workshop-dev-orchestrator-runtime-role"
    foreign = f"arn:{PARTITION}:iam::{OTHER_ACCOUNT}:role/workshop-dev-orchestrator-runtime-role"
    assert re.fullmatch(pattern, victim), pattern
    assert re.fullmatch(pattern, foreign), pattern


def test_restricted_trust_policy_allows_only_the_named_runtime() -> None:
    """The evaluator used below accepts a policy that names one runtime."""
    name = "workshop_dev_orchestrator"
    own = _runtime_arn(REGION, ACCOUNT, name)
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": SERVICE},
                "Action": "sts:AssumeRole",
                "Condition": {
                    "StringEquals": {"aws:SourceAccount": ACCOUNT},
                    "ArnLike": {
                        "aws:SourceArn": (
                            f"arn:{PARTITION}:bedrock-agentcore:{REGION}:{ACCOUNT}:"
                            f"runtime/{name}-*"
                        )
                    },
                },
            }
        ],
    }
    legitimate = {"source_account": ACCOUNT, "source_arn": own}
    _assert_restricted(
        policy,
        legitimate,
        _denied_requests(_runtime_arn, name, other_name="AttackerRuntime"),
    )

    gateway_name = "workshop-dev-gateway"
    gateway_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": SERVICE},
                "Action": "sts:AssumeRole",
                "Condition": {
                    "StringEquals": {"aws:SourceAccount": ACCOUNT},
                    "ArnLike": {
                        "aws:SourceArn": (
                            f"arn:{PARTITION}:bedrock-agentcore:{REGION}:{ACCOUNT}:"
                            f"gateway/{gateway_name}-??????????"
                        )
                    },
                },
            }
        ],
    }
    _assert_restricted(
        gateway_policy,
        {
            "source_account": ACCOUNT,
            "source_arn": _gateway_arn(REGION, ACCOUNT, gateway_name),
        },
        _denied_requests(
            _gateway_arn,
            gateway_name,
            other_name="attacker-gateway",
            hyphen_suffix=True,
        ),
    )


def test_runtime_execution_role_trusts_only_its_own_runtime() -> None:
    pattern = _role_arn_pattern()
    for project, environment, component, runtime_type in RUNTIME_CASES:
        template = _synth_runtime(project, environment, component, runtime_type)
        runtimes = _resources(template, "AWS::BedrockAgentCore::Runtime")
        assert len(runtimes) == 1, component
        runtime_logical_id, runtime = runtimes[0]
        runtime_name = runtime["Properties"]["AgentRuntimeName"]
        assert runtime_name == f"{project}_{environment}_{component}".replace("-", "_")
        role_logical_id = _role_logical_id(runtime["Properties"]["RoleArn"])
        role = template["Resources"][role_logical_id]
        role_name = role["Properties"]["RoleName"]
        assert role_name == f"{project}-{environment}-{component}-runtime-role"

        role_arn = f"arn:{PARTITION}:iam::{ACCOUNT}:role/{role_name}"
        assert re.fullmatch(pattern, role_arn), role_arn
        assert re.fullmatch(
            pattern, f"arn:{PARTITION}:iam::{OTHER_ACCOUNT}:role/{role_name}"
        )

        own = _runtime_arn(REGION, ACCOUNT, runtime_name)
        refs, atts = _bindings(
            runtime_logical_id,
            own,
            {"AgentRuntimeArn": own, "AgentRuntimeId": f"{runtime_name}-{SUFFIX}"},
        )
        policy = _assume_policy(template, role_logical_id, refs, atts)
        statements = _attached_statements(template, role_logical_id, refs, atts)
        secret = (
            f"arn:{PARTITION}:secretsmanager:{REGION}:{ACCOUNT}:secret:"
            "bedrock-agentcore-identity!default/oauth2/provider-AbCdEf"
        )
        memory = (
            f"arn:{PARTITION}:bedrock-agentcore:{REGION}:{ACCOUNT}:memory/"
            f"ExampleMemory-{SUFFIX}"
        )
        workload = (
            f"arn:{PARTITION}:bedrock-agentcore:{REGION}:{ACCOUNT}:"
            "workload-identity-directory/default"
        )
        assert identity_allows(statements, "secretsmanager:GetSecretValue", secret), component
        assert identity_allows(
            statements, "bedrock-agentcore:GetWorkloadAccessTokenForUserId", workload
        ), component
        for action in (
            "bedrock-agentcore:CreateEvent",
            "bedrock-agentcore:GetEvent",
            "bedrock-agentcore:ListEvents",
            "bedrock-agentcore:DeleteEvent",
        ):
            assert identity_allows(statements, action, memory), (component, action)

        _assert_restricted(
            policy,
            {"source_account": ACCOUNT, "source_arn": own},
            _denied_requests(_runtime_arn, runtime_name, other_name="AttackerRuntime"),
        )


def test_gateway_execution_role_trusts_only_its_own_gateway() -> None:
    app = cdk.App()
    stack = GatewayStack(
        app,
        "Gateway",
        project_name="workshop",
        environment="dev",
        cognito_issuer_url="https://cognito-idp.us-east-1.amazonaws.com/us-east-1_example",
        cognito_allowed_clients=["client"],
        env=ENV,
    )
    template = Template.from_stack(stack).to_json()
    gateways = _resources(template, "AWS::BedrockAgentCore::Gateway")
    assert len(gateways) == 1
    gateway_logical_id, gateway = gateways[0]
    gateway_name = gateway["Properties"]["Name"]
    assert gateway_name == "workshop-dev-gateway"
    role_logical_id = _role_logical_id(gateway["Properties"]["RoleArn"])
    role_name = template["Resources"][role_logical_id]["Properties"]["RoleName"]
    assert role_name == "workshop-dev-gateway-role"

    identifier = f"{gateway_name}-{SUFFIX}"
    own = _gateway_arn(REGION, ACCOUNT, gateway_name)
    refs, atts = _bindings(
        gateway_logical_id,
        identifier,
        {"GatewayArn": own, "GatewayIdentifier": identifier},
    )
    policy = _assume_policy(template, role_logical_id, refs, atts)
    _assert_restricted(
        policy,
        {"source_account": ACCOUNT, "source_arn": own},
        _denied_requests(
            _gateway_arn,
            gateway_name,
            other_name="attacker-gateway",
            hyphen_suffix=True,
        ),
    )
