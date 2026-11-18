"""Runtime roles must not read or delete every AgentCore memory in the account.

The default app (``app.py``) gives the orchestrator, code-agent, and research-agent
runtimes one execution role each. ``RuntimeStack._attach_runtime_permissions``
puts CreateEvent, GetEvent, ListEvents, DeleteEvent, ListSessions, and
RetrieveMemoryRecords on that role. Those actions authorize against a memory
ARN (``arn:${Partition}:bedrock-agentcore:${Region}:${Account}:memory/${MemoryId}``).
A resource of ``*`` therefore matches every memory in the account.

These tests synthesize that app and evaluate the role policy that
``AWS::BedrockAgentCore::Runtime`` actually references. They fail while any of
those actions is allowed on a memory other than this deployment's memory, and
they pass once each runtime role is limited to that memory. The orchestrator
is the runtime that receives ``MEMORY_ID``; it must keep all six actions on
its own memory. The code and research roles must lose access to every other
memory (drop the actions, or scope them to the same memory).

Run:

    pip install -r requirements.txt
    pytest tests/test_runtime_memory_data_plane_scope.py -q
"""

import json
import os
import re

os.environ["CDK_DEFAULT_ACCOUNT"] = "111122223333"
os.environ["CDK_DEFAULT_REGION"] = "us-east-1"
# Defaults in app.py, not whatever platform.yaml happens to be in the worktree.
os.environ["PLATFORM_CONFIG"] = "/tmp/no-such-platform.yaml"

import app  # noqa: E402

ACCOUNT = "111122223333"
REGION = "us-east-1"
PARTITION = "aws"
# Distinct ids so a prefix wildcard on one cannot match the other.
OWN_MEMORY_ID = "mem-this-deployment"
FOREIGN_MEMORY_ID = "mem-other-deployment"

# Every bedrock-agentcore action whose resource type is memory* in the
# service authorization reference. The runtime policy grants a subset.
MEMORY_RESOURCE_ACTIONS = frozenset(
    {
        "bedrock-agentcore:BatchCreateMemoryRecords",
        "bedrock-agentcore:BatchDeleteMemoryRecords",
        "bedrock-agentcore:BatchUpdateMemoryRecords",
        "bedrock-agentcore:CreateEvent",
        "bedrock-agentcore:DeleteEvent",
        "bedrock-agentcore:DeleteMemory",
        "bedrock-agentcore:DeleteMemoryRecord",
        "bedrock-agentcore:GetEvent",
        "bedrock-agentcore:GetMemory",
        "bedrock-agentcore:GetMemoryRecord",
        "bedrock-agentcore:IngestData",
        "bedrock-agentcore:ListActors",
        "bedrock-agentcore:ListEvents",
        "bedrock-agentcore:ListMemoryExtractionJobs",
        "bedrock-agentcore:ListMemoryRecords",
        "bedrock-agentcore:ListSessions",
        "bedrock-agentcore:RetrieveMemoryRecords",
        "bedrock-agentcore:StartMemoryExtractionJob",
        "bedrock-agentcore:UpdateMemory",
        "bedrock-agentcore:UpdateMemoryRecordExpirySpecification",
    }
)

# Request fields the caller of these APIs chooses (memoryId is the resource,
# not a condition key). A condition on one of these does not stop a caller
# who can set it to the value the policy requires.
ATTACKER_CONDITION_KEYS = frozenset(
    {
        "bedrock-agentcore:actorId",
        "bedrock-agentcore:sessionId",
        "bedrock-agentcore:namespace",
        "bedrock-agentcore:namespacePath",
        "bedrock-agentcore:strategyId",
        "bedrock-agentcore:sourceNamespace",
    }
)

RUNTIME_COMPONENTS = ("orchestrator", "code-agent", "research-agent")


def memory_arn(memory_id: str, region: str = REGION) -> str:
    return (
        f"arn:{PARTITION}:bedrock-agentcore:{region}:{ACCOUNT}:memory/{memory_id}"
    )


OWN_MEMORY_ARN = memory_arn(OWN_MEMORY_ID)
FOREIGN_MEMORY_ARN = memory_arn(FOREIGN_MEMORY_ID)


def _assembly():
    return app.app.synth()


def _stack(suffix: str):
    return next(
        stack
        for stack in _assembly().stacks
        if stack.stack_name.endswith(suffix)
    )


def _memory_exports():
    """Map cross-stack export names to this deployment's memory id or ARN."""
    exports = {}
    for output in _stack("-memory").template.get("Outputs", {}).values():
        value = output.get("Value")
        export = (output.get("Export") or {}).get("Name")
        if not export or not isinstance(value, dict) or "Fn::GetAtt" not in value:
            continue
        target = value["Fn::GetAtt"]
        if target == ["Memory", "MemoryArn"]:
            exports[export] = OWN_MEMORY_ARN
        elif target == ["Memory", "MemoryId"]:
            exports[export] = OWN_MEMORY_ID
    return exports


class _Resolver:
    """Substitute the memory id/ARN tokens and pseudo-parameters a synth emits."""

    def __init__(self):
        self.exports = _memory_exports()

    def resolve(self, node):
        if isinstance(node, str):
            return node
        if isinstance(node, list):
            return "".join(self.resolve(part) for part in node)
        if not isinstance(node, dict):
            return str(node)
        if set(node) == {"Ref"}:
            ref = node["Ref"]
            return {
                "AWS::Partition": PARTITION,
                "AWS::Region": REGION,
                "AWS::AccountId": ACCOUNT,
            }.get(ref, f"${{{ref}}}")
        if set(node) == {"Fn::ImportValue"}:
            name = self.resolve(node["Fn::ImportValue"])
            if name not in self.exports:
                raise AssertionError(f"unresolved memory export {name}")
            return self.exports[name]
        if set(node) == {"Fn::GetAtt"}:
            target = node["Fn::GetAtt"]
            if target == ["Memory", "MemoryArn"]:
                return OWN_MEMORY_ARN
            if target == ["Memory", "MemoryId"]:
                return OWN_MEMORY_ID
            return f"${{GetAtt:{target[0]}.{target[1]}}}"
        if set(node) == {"Fn::Join"}:
            separator, parts = node["Fn::Join"]
            return separator.join(self.resolve(part) for part in parts)
        if set(node) == {"Fn::Sub"}:
            return self._sub(node["Fn::Sub"])
        raise AssertionError(f"unsupported policy intrinsic {json.dumps(node)}")

    def _sub(self, spec):
        if isinstance(spec, str):
            template, variables = spec, {}
        else:
            template, variables = spec
        variables = {key: self.resolve(value) for key, value in variables.items()}

        def replace(match):
            key = match.group(1)
            if key in variables:
                return variables[key]
            if key in ("AWS::Partition", "AWS::Region", "AWS::AccountId"):
                return {"AWS::Partition": PARTITION, "AWS::Region": REGION, "AWS::AccountId": ACCOUNT}[key]
            raise AssertionError(f"unsupported Fn::Sub variable {key}")

        return re.sub(r"\$\{([^}]+)\}", replace, template)


def wildcard_match(pattern: str, value: str) -> bool:
    """IAM ``*`` / ``?`` match. ``*`` matches any characters, including colons.

    The Resource element treats ``*`` as any combination of characters, and a
    ``*`` at the end of an ARN segment may cross colon boundaries. Matching
    ``*`` across colons is the broader reading, so a too-wide pattern still
    matches a foreign memory. An exact ARN matches only itself.
    """
    regex = []
    for char in pattern:
        if char == "*":
            regex.append(".*")
        elif char == "?":
            regex.append(".")
        else:
            regex.append(re.escape(char))
    return re.fullmatch("".join(regex), value) is not None


def _as_list(value):
    if value is None:
        return None
    if isinstance(value, list):
        return value
    return [value]


def _condition_holds(condition: dict, context: dict) -> bool:
    """True when the runtime role's request can satisfy ``condition``.

    Keys the API caller sets (actor id, session id, namespace) are filled
    from the policy when it names a single required value. Every other key
    is compared to ``context`` and fails closed on an operator this harness
    does not implement.
    """
    context = dict(context)
    for operator, pairs in condition.items():
        base = operator.split(":")[-1]
        qualifier = operator[: -len(base) - 1] if operator != base else ""
        if qualifier not in ("", "ForAnyValue", "ForAllValues"):
            return False
        for key, expected in pairs.items():
            expected_values = expected if isinstance(expected, list) else [expected]
            if key.startswith("bedrock-agentcore:namespaceVariable/"):
                attacker_controlled = True
            else:
                attacker_controlled = key in ATTACKER_CONDITION_KEYS
            if attacker_controlled and base in ("StringEquals", "ArnEquals") and qualifier != "ForAllValues":
                if key in context and context[key] not in expected_values:
                    return False
                context[key] = expected_values[0]
            elif attacker_controlled and base in ("StringLike", "ArnLike") and len(expected_values) == 1:
                context.setdefault(key, expected_values[0].replace("*", "").replace("?", "x") or "x")
            elif not attacker_controlled:
                actual = context.get(key)
                if not _operator_matches(base, qualifier, actual, expected_values):
                    return False
            elif not _operator_matches(base, qualifier, context.get(key, "attacker-chosen"), expected_values):
                # Attacker may omit the key or set it. Try both.
                if not _operator_matches(base, qualifier, None, expected_values):
                    return False
    return True


def _operator_matches(base, qualifier, actual, expected_values) -> bool:
    if base == "Null":
        wants_absent = expected_values == ["true"]
        return (actual is None) == wants_absent
    if base == "Bool":
        return str(actual).lower() in {value.lower() for value in expected_values}
    if actual is None:
        return False
    actual_values = actual if isinstance(actual, list) else [actual]
    if base in ("StringEquals", "ArnEquals"):
        ok = any(item in expected_values for item in actual_values)
    elif base in ("StringNotEquals", "ArnNotEquals"):
        ok = all(item not in expected_values for item in actual_values)
    elif base in ("StringLike", "ArnLike"):
        ok = any(
            wildcard_match(pattern, item)
            for item in actual_values
            for pattern in expected_values
        )
    elif base in ("StringNotLike", "ArnNotLike"):
        ok = all(
            not wildcard_match(pattern, item)
            for item in actual_values
            for pattern in expected_values
        )
    else:
        return False
    if qualifier == "ForAllValues":
        return ok
    return ok


def _element_matches(stmt, present_key, absent_key, value, resolver) -> bool:
    present = _as_list(stmt.get(present_key))
    absent = _as_list(stmt.get(absent_key))
    if present is None and absent is None:
        return False
    if present is not None and not any(
        wildcard_match(resolver.resolve(item), value) for item in present
    ):
        return False
    if absent is not None and any(
        wildcard_match(resolver.resolve(item), value) for item in absent
    ):
        return False
    return True


def statement_matches(stmt, action: str, resource_arn: str, context: dict, resolver) -> bool:
    if stmt.get("Effect") not in (None, "Allow", "Deny"):
        return False
    condition = stmt.get("Condition") or {}
    if condition and not _condition_holds(condition, context):
        return False
    if not _element_matches(stmt, "Action", "NotAction", action, resolver):
        return False
    return _element_matches(stmt, "Resource", "NotResource", resource_arn, resolver)


def request_allowed(statements, action: str, resource_arn: str, context: dict, resolver) -> bool:
    """Identity-policy result: an explicit Deny overrides Allow. No match is deny."""
    allowed = False
    for stmt in statements:
        if not statement_matches(stmt, action, resource_arn, context, resolver):
            continue
        if stmt.get("Effect", "Allow") == "Deny":
            return False
        allowed = True
    return allowed


def _runtime_role(template):
    runtime = next(
        resource
        for resource in template["Resources"].values()
        if resource["Type"] == "AWS::BedrockAgentCore::Runtime"
    )
    role_arn = runtime["Properties"]["RoleArn"]
    assert role_arn["Fn::GetAtt"][1] == "Arn"
    logical_id = role_arn["Fn::GetAtt"][0]
    role = template["Resources"][logical_id]
    assert role["Type"] == "AWS::IAM::Role"
    return logical_id, role


def _statements_for_role(template, logical_id):
    role = template["Resources"][logical_id]
    statements = []
    for inline in role["Properties"].get("Policies") or []:
        document = inline["PolicyDocument"]
        statements.extend(_as_list(document["Statement"]))
    for resource in template["Resources"].values():
        if resource["Type"] != "AWS::IAM::Policy":
            continue
        roles = resource["Properties"].get("Roles") or []
        attached = any(
            item == logical_id or item == {"Ref": logical_id} for item in roles
        )
        if not attached:
            continue
        statements.extend(_as_list(resource["Properties"]["PolicyDocument"]["Statement"]))
    return statements


def _role_context(role):
    role_name = role["Properties"]["RoleName"]
    assert isinstance(role_name, str)
    return {
        "aws:PrincipalAccount": ACCOUNT,
        "aws:PrincipalArn": f"arn:{PARTITION}:iam::{ACCOUNT}:role/{role_name}",
    }


def _component_policy(component: str):
    template = _stack(f"-runtime-{component}").template
    logical_id, role = _runtime_role(template)
    assert role["Properties"].get("PermissionsBoundary") is None
    trust = role["Properties"]["AssumeRolePolicyDocument"]["Statement"]
    assert any(
        stmt.get("Principal", {}).get("Service") == "bedrock-agentcore.amazonaws.com"
        for stmt in trust
    )
    return _statements_for_role(template, logical_id), _role_context(role)


def _granted_memory_actions(statements, resolver, context) -> set[str]:
    granted = set()
    for stmt in statements:
        if stmt.get("Effect") == "Deny":
            continue
        for action in MEMORY_RESOURCE_ACTIONS:
            if statement_matches(stmt, action, FOREIGN_MEMORY_ARN, context, resolver) or statement_matches(
                stmt, action, OWN_MEMORY_ARN, context, resolver
            ):
                granted.add(action)
        for action in _as_list(stmt.get("Action")) or []:
            resolved = resolver.resolve(action)
            if resolved in ("*", "bedrock-agentcore:*"):
                granted.add(resolved)
    return granted


def test_wildcard_resource_matches_every_memory_and_an_exact_arn_does_not():
    """The evaluator used below distinguishes the bug from the fix."""
    statements = [
        {
            "Effect": "Allow",
            "Action": "bedrock-agentcore:DeleteEvent",
            "Resource": "*",
        }
    ]
    context = {"aws:PrincipalAccount": ACCOUNT}
    resolver = _Resolver()
    assert request_allowed(statements, "bedrock-agentcore:DeleteEvent", FOREIGN_MEMORY_ARN, context, resolver)
    assert request_allowed(statements, "bedrock-agentcore:DeleteEvent", OWN_MEMORY_ARN, context, resolver)

    scoped = [
        {
            "Effect": "Allow",
            "Action": list(MEMORY_RESOURCE_ACTIONS),
            "Resource": OWN_MEMORY_ARN,
        }
    ]
    assert not request_allowed(
        scoped, "bedrock-agentcore:DeleteEvent", FOREIGN_MEMORY_ARN, context, resolver
    )
    assert request_allowed(
        scoped, "bedrock-agentcore:ListEvents", OWN_MEMORY_ARN, context, resolver
    )
    assert not request_allowed(
        scoped, "bedrock-agentcore:GetEvent", memory_arn(FOREIGN_MEMORY_ID, region="eu-west-1"), context, resolver
    )

    starred_memory = [
        {
            "Effect": "Allow",
            "Action": "bedrock-agentcore:RetrieveMemoryRecords",
            "Resource": f"arn:{PARTITION}:bedrock-agentcore:*:*:memory/*",
        }
    ]
    assert request_allowed(
        starred_memory,
        "bedrock-agentcore:RetrieveMemoryRecords",
        FOREIGN_MEMORY_ARN,
        context,
        resolver,
    )

    # A broad allow plus a deny of every other memory is the same outcome.
    denied = [
        {
            "Effect": "Allow",
            "Action": "bedrock-agentcore:DeleteEvent",
            "Resource": "*",
        },
        {
            "Effect": "Deny",
            "Action": "bedrock-agentcore:DeleteEvent",
            "NotResource": OWN_MEMORY_ARN,
        },
    ]
    assert not request_allowed(
        denied, "bedrock-agentcore:DeleteEvent", FOREIGN_MEMORY_ARN, context, resolver
    )
    assert request_allowed(
        denied, "bedrock-agentcore:DeleteEvent", OWN_MEMORY_ARN, context, resolver
    )

    # The caller chooses actorId, so a condition on it does not pin the memory.
    actor_only = [
        {
            "Effect": "Allow",
            "Action": "bedrock-agentcore:ListEvents",
            "Resource": "*",
            "Condition": {"StringEquals": {"bedrock-agentcore:actorId": "caller-sub"}},
        }
    ]
    assert request_allowed(
        actor_only, "bedrock-agentcore:ListEvents", FOREIGN_MEMORY_ARN, context, resolver
    )


def test_default_memory_has_no_resource_policy_or_permission_boundary():
    """Same-account access is the identity policy: nothing else in the default app denies it."""
    memory = _stack("-memory").template
    resource_policies = [
        logical
        for logical, resource in memory["Resources"].items()
        if resource["Type"] == "AWS::BedrockAgentCore::ResourcePolicy"
    ]
    assert resource_policies == []
    for component in RUNTIME_COMPONENTS:
        _statements, context = _component_policy(component)
        assert context["aws:PrincipalArn"].endswith(f"-{component}-runtime-role")


def test_runtime_roles_cannot_use_another_memory():
    """Each runtime role must deny the memory data plane on any other memory."""
    resolver = _Resolver()
    offenders = []
    for component in RUNTIME_COMPONENTS:
        statements, context = _component_policy(component)
        granted = _granted_memory_actions(statements, resolver, context)
        unexpected = granted - MEMORY_RESOURCE_ACTIONS
        assert not unexpected, (
            f"{component} grants a memory-wide action the scope check does not name: {unexpected}"
        )
        for action in sorted(granted):
            foreign_arns = [
                FOREIGN_MEMORY_ARN,
                memory_arn(FOREIGN_MEMORY_ID, region="eu-west-1"),
            ]
            for foreign in foreign_arns:
                if request_allowed(statements, action, foreign, context, resolver):
                    offenders.append(f"{component} {action} on {foreign}")
    assert not offenders, (
        "these runtime roles can call the memory data plane on a memory that is "
        f"not this deployment's memory: {offenders}"
    )


def test_orchestrator_keeps_memory_data_plane_on_its_own_memory():
    """Scoping must not drop the actions the orchestrator memory integration uses."""
    resolver = _Resolver()
    statements, context = _component_policy("orchestrator")
    required = [
        "bedrock-agentcore:CreateEvent",
        "bedrock-agentcore:GetEvent",
        "bedrock-agentcore:ListEvents",
        "bedrock-agentcore:DeleteEvent",
        "bedrock-agentcore:ListSessions",
        "bedrock-agentcore:RetrieveMemoryRecords",
    ]
    missing = [
        action
        for action in required
        if not request_allowed(statements, action, OWN_MEMORY_ARN, context, resolver)
    ]
    assert not missing, (
        "orchestrator runtime role must still allow these actions on this "
        f"deployment's memory ARN: {missing}"
    )
