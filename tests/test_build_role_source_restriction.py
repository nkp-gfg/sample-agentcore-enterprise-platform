"""The image-build role must be assumable only by its own CodeBuild project.

RuntimeStack builds each agent image with a CodeBuild project, then points the
AgentCore runtime at the tag that build pushes. These tests synthesize that
stack and apply the IAM condition rules to the role trust policy the template
actually contains. A second project in the same account must not be able to
assume the role that can push that repository or read the migration registry
secret. The repository must refuse tag overwrites, and the runtime must record
the digest the build trigger publishes rather than the movable tag.

The pattern-mode cases cover every RuntimeStack constructed from app.py
(orchestrator, code-agent, and research-agent). Those stacks call the same
constructor without a migration source. The migration cases cover the other
branch, which also grants the build role the registry secret.
"""

from __future__ import annotations

import json
import re
import tempfile
from typing import Any

import aws_cdk as cdk
import pytest
from aws_cdk.assertions import Template

from stacks.runtime_stack import RuntimeStack

ENV = cdk.Environment(account="111111111111", region="us-east-1")
ACCOUNT = "111111111111"
REGION = "us-east-1"
PARTITION = "aws"
OTHER_ACCOUNT = "222222222222"
REGISTRY_SECRET_NAME = "migration/registry-login"
REGISTRY_SECRET_SUFFIX = "AbCdEf"


def _template(mode: str) -> dict[str, Any]:
    app = cdk.App(outdir=tempfile.mkdtemp(prefix="build-role-restriction-"))
    kwargs: dict[str, Any] = {}
    if mode == "migration":
        kwargs = {
            "build_context": "migration/simulation/existing-ec2-agent",
            "build_dockerfile": "Dockerfile",
            "adapter_dir": "migration/adapter",
            "registry_secret_name": REGISTRY_SECRET_NAME,
        }
    elif mode != "pattern":
        raise AssertionError(f"unknown mode {mode}")
    stack = RuntimeStack(
        app,
        "RuntimeUnderTest",
        project_name="proj",
        environment="dev",
        component_name="orchestrator",
        source_dir="agent-code",
        runtime_type="orchestrator",
        env=ENV,
        **kwargs,
    )
    return Template.from_stack(stack).to_json()


def _resources(template: dict[str, Any], resource_type: str) -> dict[str, dict[str, Any]]:
    return {
        logical_id: resource
        for logical_id, resource in template["Resources"].items()
        if resource["Type"] == resource_type
    }


def _one(template: dict[str, Any], resource_type: str) -> tuple[str, dict[str, Any]]:
    found = _resources(template, resource_type)
    assert len(found) == 1, f"expected one {resource_type}, found {list(found)}"
    return next(iter(found.items()))


def _resolve_context(template: dict[str, Any]) -> dict[str, Any]:
    return {
        "account": ACCOUNT,
        "region": REGION,
        "partition": PARTITION,
        "resources": template["Resources"],
    }


def _resolve(node: Any, ctx: dict[str, Any]) -> Any:
    if isinstance(node, list):
        return [_resolve(item, ctx) for item in node]
    if not isinstance(node, dict):
        return node
    if set(node) == {"Ref"}:
        return _resolve_ref(node["Ref"], ctx)
    if set(node) == {"Fn::GetAtt"}:
        return _resolve_getatt(node["Fn::GetAtt"], ctx)
    if set(node) == {"Fn::Join"}:
        separator, parts = node["Fn::Join"]
        resolved = [_resolve(part, ctx) for part in parts]
        if not all(isinstance(part, str) for part in resolved):
            return {"Fn::Join": [_resolve(separator, ctx), resolved]}
        return _resolve(separator, ctx).join(resolved)
    if set(node) == {"Fn::Sub"}:
        return _resolve_sub(node["Fn::Sub"], ctx)
    if set(node) == {"Fn::Select"}:
        index, collection = node["Fn::Select"]
        resolved = _resolve(collection, ctx)
        if isinstance(resolved, list):
            return resolved[index]
        return {"Fn::Select": [index, resolved]}
    if set(node) == {"Fn::Split"}:
        delimiter, source = node["Fn::Split"]
        resolved = _resolve(source, ctx)
        if isinstance(resolved, str):
            return resolved.split(_resolve(delimiter, ctx))
        return {"Fn::Split": [_resolve(delimiter, ctx), resolved]}
    return {key: _resolve(value, ctx) for key, value in node.items()}


def _resolve_ref(name: str, ctx: dict[str, Any]) -> Any:
    pseudos = {
        "AWS::AccountId": ctx["account"],
        "AWS::Region": ctx["region"],
        "AWS::Partition": ctx["partition"],
        "AWS::URLSuffix": "amazonaws.com",
    }
    if name in pseudos:
        return pseudos[name]
    resource = ctx["resources"].get(name)
    if resource is None:
        return {"Ref": name}
    if resource["Type"] == "AWS::ECR::Repository":
        return resource["Properties"]["RepositoryName"]
    if resource["Type"] == "AWS::CodeBuild::Project":
        return resource["Properties"]["Name"]
    return {"Ref": name}


def _resolve_getatt(pair: Any, ctx: dict[str, Any]) -> Any:
    if isinstance(pair, str):
        logical_id, attribute = pair.split(".", 1)
    else:
        logical_id, attribute = pair
    resource = ctx["resources"][logical_id]
    if resource["Type"] == "AWS::CodeBuild::Project" and attribute == "Arn":
        return _project_arn(resource["Properties"]["Name"], ctx["account"])
    if resource["Type"] == "AWS::ECR::Repository" and attribute == "Arn":
        name = resource["Properties"]["RepositoryName"]
        return (
            f"arn:{ctx['partition']}:ecr:{ctx['region']}:{ctx['account']}:"
            f"repository/{name}"
        )
    return {"Fn::GetAtt": [logical_id, attribute]}


def _resolve_sub(value: Any, ctx: dict[str, Any]) -> Any:
    if isinstance(value, list):
        template, mapping = value
        resolved_mapping = {
            key: _resolve(item, ctx) for key, item in mapping.items()
        }
    else:
        template, resolved_mapping = value, {}

    def replace(match: re.Match[str]) -> str:
        name = match.group(1)
        if name in resolved_mapping and isinstance(resolved_mapping[name], str):
            return resolved_mapping[name]
        resolved = _resolve_ref(name, ctx)
        if isinstance(resolved, str):
            return resolved
        raise AssertionError(f"unresolved Fn::Sub variable {name}")

    return re.sub(r"\$\{([^}]+)\}", replace, template)


def _project_arn(project_name: str, account: str) -> str:
    return (
        f"arn:{PARTITION}:codebuild:{REGION}:{account}:project/{project_name}"
    )


def _repository_arn(template: dict[str, Any]) -> str:
    repository = _one(template, "AWS::ECR::Repository")[1]
    name = repository["Properties"]["RepositoryName"]
    return f"arn:{PARTITION}:ecr:{REGION}:{ACCOUNT}:repository/{name}"


def _role_logical_id(service_role: Any) -> str:
    if isinstance(service_role, dict) and "Fn::GetAtt" in service_role:
        return service_role["Fn::GetAtt"][0]
    if isinstance(service_role, dict) and "Ref" in service_role:
        return service_role["Ref"]
    raise AssertionError(f"cannot identify service role from {service_role!r}")


def _statements_for_role(
    template: dict[str, Any], role_logical_id: str
) -> list[dict[str, Any]]:
    statements: list[dict[str, Any]] = []
    for resource in template["Resources"].values():
        if resource["Type"] != "AWS::IAM::Policy":
            continue
        roles = resource["Properties"].get("Roles", [])
        attached = any(
            isinstance(role, dict) and role.get("Ref") == role_logical_id
            for role in roles
        )
        if not attached:
            continue
        document = resource["Properties"]["PolicyDocument"]
        if isinstance(document, str):
            document = json.loads(document)
        found = document["Statement"]
        statements.extend(found if isinstance(found, list) else [found])
    return statements


def _trust_statements(template: dict[str, Any], role_logical_id: str) -> list[dict[str, Any]]:
    document = template["Resources"][role_logical_id]["Properties"][
        "AssumeRolePolicyDocument"
    ]
    if isinstance(document, str):
        document = json.loads(document)
    found = document["Statement"]
    return found if isinstance(found, list) else [found]


def _build_trigger_id(template: dict[str, Any], project_logical_id: str) -> str:
    matches = []
    for logical_id, resource in _resources(
        template, "AWS::CloudFormation::CustomResource"
    ).items():
        properties = resource["Properties"]
        project_name = properties.get("ProjectName")
        if project_name == {"Ref": project_logical_id}:
            matches.append(logical_id)
    assert len(matches) == 1, f"expected one build trigger, found {matches}"
    return matches[0]


def _walk(node: Any) -> list[Any]:
    found = [node]
    if isinstance(node, dict):
        for value in node.values():
            found.extend(_walk(value))
    elif isinstance(node, list):
        for value in node:
            found.extend(_walk(value))
    return found


def _literal_text(node: Any) -> str:
    if isinstance(node, str):
        return node
    if isinstance(node, list):
        return "".join(_literal_text(item) for item in node)
    if isinstance(node, dict) and set(node) == {"Fn::Join"}:
        separator, parts = node["Fn::Join"]
        return _literal_text(separator).join(_literal_text(part) for part in parts)
    if isinstance(node, dict) and set(node) == {"Fn::Sub"}:
        template = node["Fn::Sub"]
        template = template[0] if isinstance(template, list) else template
        return re.sub(r"\$\{[^}]+\}", "", template)
    if isinstance(node, dict):
        return "".join(_literal_text(value) for value in node.values())
    return ""


def _glob_match(pattern: str, value: str) -> bool:
    expression = re.escape(pattern).replace(r"\*", ".*").replace(r"\?", ".")
    return re.fullmatch(expression, value) is not None


def _arn_match(pattern: str, value: str) -> bool:
    pattern_parts = pattern.split(":")
    value_parts = value.split(":")
    if len(pattern_parts) != len(value_parts):
        return False
    return all(
        _glob_match(pattern_part, value_part)
        for pattern_part, value_part in zip(pattern_parts, value_parts)
    )


def _as_list(value: Any) -> list[Any]:
    if isinstance(value, list):
        return value
    return [value]


def _context_value(context: dict[str, str], key: str) -> tuple[bool, str | None]:
    for name, value in context.items():
        if name.lower() == key.lower():
            return True, value
    return False, None


def _positive_match(operator: str, pattern: str, value: str) -> bool:
    if operator in ("StringEquals", "StringEqualsIgnoreCase"):
        if operator == "StringEqualsIgnoreCase":
            return pattern.casefold() == value.casefold()
        return pattern == value
    if operator == "StringLike":
        return _glob_match(pattern, value)
    if operator in ("ArnEquals", "ArnLike"):
        return _arn_match(pattern, value)
    raise AssertionError(f"unsupported condition operator {operator}")


def _one_key_matches(operator: str, expected: Any, present: bool, actual: str | None) -> bool:
    base = operator
    if base.endswith("IfExists"):
        if not present:
            return True
        base = base[: -len("IfExists")]
    qualifier = None
    for prefix in ("ForAllValues:", "ForAnyValue:"):
        if base.startswith(prefix):
            qualifier = prefix[:-1]
            base = base[len(prefix) :]
            break
    if base == "Null":
        expects_missing = str(expected).lower() == "true"
        return expects_missing == (not present)
    if not present or actual is None:
        # A missing key makes a positive operator false and a negated operator true.
        return base in ("StringNotEquals", "StringNotEqualsIgnoreCase", "StringNotLike", "ArnNotEquals", "ArnNotLike")
    patterns = [str(item) for item in _as_list(expected)]
    negated = base in (
        "StringNotEquals",
        "StringNotEqualsIgnoreCase",
        "StringNotLike",
        "ArnNotEquals",
        "ArnNotLike",
    )
    positive = {
        "StringNotEquals": "StringEquals",
        "StringNotEqualsIgnoreCase": "StringEqualsIgnoreCase",
        "StringNotLike": "StringLike",
        "ArnNotEquals": "ArnEquals",
        "ArnNotLike": "ArnLike",
    }.get(base, base)
    matched = any(_positive_match(positive, pattern, actual) for pattern in patterns)
    if qualifier == "ForAllValues":
        # One request value must match a policy value; an empty set is not used here.
        matched = matched
    if negated:
        # Multiple policy values on a negated operator are NOR.
        return not matched
    return matched


def _condition_matches(condition: dict[str, Any] | None, context: dict[str, str]) -> bool:
    if not condition:
        return True
    for operator, keys in condition.items():
        for key, expected in keys.items():
            present, actual = _context_value(context, key)
            if not _one_key_matches(operator, expected, present, actual):
                return False
    return True


def _action_matches(action: str, requested: str) -> bool:
    if action == "*":
        return True
    if action.endswith("*"):
        return requested.startswith(action[:-1])
    return action == requested


def _statement_actions_match(statement: dict[str, Any], requested: str) -> bool:
    actions = statement.get("Action")
    not_actions = statement.get("NotAction")
    if actions is not None:
        allowed = any(
            _action_matches(action, requested) for action in _as_list(actions)
        )
        if not allowed:
            return False
    if not_actions is not None and any(
        _action_matches(action, requested) for action in _as_list(not_actions)
    ):
        return False
    return actions is not None or not_actions is not None


def _resource_matches(statement: dict[str, Any], resource_arn: str | None) -> bool:
    if resource_arn is None:
        return "Resource" not in statement and "NotResource" not in statement
    resources = statement.get("Resource")
    not_resources = statement.get("NotResource")
    if resources is not None:
        patterns = [item for item in _as_list(resources) if isinstance(item, str)]
        if not any(_glob_match(pattern, resource_arn) for pattern in patterns):
            return False
    if not_resources is not None:
        patterns = [item for item in _as_list(not_resources) if isinstance(item, str)]
        if any(_glob_match(pattern, resource_arn) for pattern in patterns):
            return False
    return True


def _principal_matches(statement: dict[str, Any], service: str) -> bool:
    principal = statement.get("Principal")
    if principal == "*":
        return True
    if not isinstance(principal, dict):
        return False
    services = _as_list(principal.get("Service", []))
    return service in services


def _effect(statement: dict[str, Any]) -> str:
    return statement.get("Effect", "Deny")


def _decision(
    statements: list[dict[str, Any]],
    *,
    action: str,
    context: dict[str, str],
    service: str | None = None,
    resource_arn: str | None = None,
) -> str:
    """Return allow or deny for one policy document.

    Explicit deny wins, then explicit allow, otherwise implicit deny. Condition
    operators are AND across keys and OR across values; a missing key makes a
    positive match false.
    """
    applicable: list[dict[str, Any]] = []
    for statement in statements:
        if service is not None and not _principal_matches(statement, service):
            continue
        if not _statement_actions_match(statement, action):
            continue
        if not _resource_matches(statement, resource_arn):
            continue
        if not _condition_matches(statement.get("Condition"), context):
            continue
        applicable.append(statement)
    if any(_effect(statement) == "Deny" for statement in applicable):
        return "deny"
    if any(_effect(statement) == "Allow" for statement in applicable):
        return "allow"
    return "deny"


def _assume(
    template: dict[str, Any],
    role_logical_id: str,
    *,
    source_arn: str,
    source_account: str,
) -> str:
    statements = _resolve(_trust_statements(template, role_logical_id), _resolve_context(template))
    return _decision(
        statements,
        action="sts:AssumeRole",
        service="codebuild.amazonaws.com",
        context={
            "aws:SourceArn": source_arn,
            "aws:SourceAccount": source_account,
        },
    )


def _identity_decision(
    template: dict[str, Any],
    role_logical_id: str,
    action: str,
    resource_arn: str,
) -> str:
    statements = _resolve(
        _statements_for_role(template, role_logical_id), _resolve_context(template)
    )
    return _decision(statements, action=action, resource_arn=resource_arn, context={})


def _image_build(template: dict[str, Any]) -> dict[str, Any]:
    project_logical_id, project = _one(template, "AWS::CodeBuild::Project")
    role_logical_id = _role_logical_id(project["Properties"]["ServiceRole"])
    project_name = project["Properties"]["Name"]
    return {
        "project_logical_id": project_logical_id,
        "project_name": project_name,
        "project_arn": _project_arn(project_name, ACCOUNT),
        "role_logical_id": role_logical_id,
        "repository_arn": _repository_arn(template),
        "trigger_logical_id": _build_trigger_id(template, project_logical_id),
    }


def _runtime_image_nodes(template: dict[str, Any]) -> tuple[Any, Any]:
    _, runtime = _one(template, "AWS::BedrockAgentCore::Runtime")
    container_uri = runtime["Properties"]["AgentRuntimeArtifact"]["ContainerConfiguration"][
        "ContainerUri"
    ]
    image_uri = template["Outputs"]["ImageUri"]["Value"]
    return container_uri, image_uri


def _assert_digest_pinned(template: dict[str, Any], build: dict[str, Any]) -> None:
    source_hash = template["Outputs"]["SourceHash"]["Value"]
    assert isinstance(source_hash, str) and source_hash
    for label, node in zip(
        ("runtime container URI", "ImageUri output"),
        _runtime_image_nodes(template),
        strict=True,
    ):
        references = [
            item
            for item in _walk(node)
            if item == {"Fn::GetAtt": [build["trigger_logical_id"], "ImageDigest"]}
        ]
        literals = _literal_text(node)
        assert references, (
            f"{label} must be the digest published by the build trigger "
            f"({build['trigger_logical_id']} ImageDigest), not a tag chosen "
            f"when the stack is synthesized: {node}"
        )
        assert "@" in literals, (
            f"{label} must use the digest separator '@' before ImageDigest, "
            f"got literals {literals!r}"
        )
        assert source_hash not in literals, (
            f"{label} still embeds the movable source-hash tag {source_hash}"
        )


@pytest.mark.parametrize("mode", ["pattern", "migration"])
def test_foreign_codebuild_project_cannot_assume_the_image_build_role(mode: str) -> None:
    template = _template(mode)
    build = _image_build(template)

    # The evaluator distinguishes an exact project ARN from a wildcard. A trust
    # policy that allows every project in the account still fails this test.
    own = _project_arn(build["project_name"], ACCOUNT)
    same_account_other = _project_arn("attacker-build", ACCOUNT)
    same_account_suffix = _project_arn(f"{build['project_name']}-attacker", ACCOUNT)
    other_account = _project_arn(build["project_name"], OTHER_ACCOUNT)
    sample_trust = [
        {
            "Effect": "Allow",
            "Principal": {"Service": "codebuild.amazonaws.com"},
            "Action": "sts:AssumeRole",
            "Condition": {
                "StringEquals": {"aws:SourceArn": own, "aws:SourceAccount": ACCOUNT}
            },
        }
    ]
    sample_context = {"aws:SourceArn": same_account_other, "aws:SourceAccount": ACCOUNT}
    assert _decision(
        sample_trust,
        action="sts:AssumeRole",
        service="codebuild.amazonaws.com",
        context=sample_context,
    ) == "deny"
    wildcard_trust = [
        {
            "Effect": "Allow",
            "Principal": {"Service": "codebuild.amazonaws.com"},
            "Action": "sts:AssumeRole",
            "Condition": {
                "ArnLike": {
                    "aws:SourceArn": _project_arn("*", ACCOUNT),
                }
            },
        }
    ]
    assert _decision(
        wildcard_trust,
        action="sts:AssumeRole",
        service="codebuild.amazonaws.com",
        context=sample_context,
    ) == "allow"

    assert _identity_decision(
        template, build["role_logical_id"], "ecr:PutImage", build["repository_arn"]
    ) == "allow", "the project service role must be able to push its own repository"
    other_repository = (
        f"arn:{PARTITION}:ecr:{REGION}:{ACCOUNT}:repository/some-other-repository"
    )
    assert _identity_decision(
        template, build["role_logical_id"], "ecr:PutImage", other_repository
    ) == "deny", "push permission must be the runtime repository, not another repository"

    if mode == "migration":
        secret_arn = (
            f"arn:{PARTITION}:secretsmanager:{REGION}:{ACCOUNT}:secret:"
            f"{REGISTRY_SECRET_NAME}-{REGISTRY_SECRET_SUFFIX}"
        )
        unrelated_secret = (
            f"arn:{PARTITION}:secretsmanager:{REGION}:{ACCOUNT}:secret:"
            f"unrelated-{REGISTRY_SECRET_SUFFIX}"
        )
        assert _identity_decision(
            template,
            build["role_logical_id"],
            "secretsmanager:GetSecretValue",
            secret_arn,
        ) == "allow"
        assert _identity_decision(
            template,
            build["role_logical_id"],
            "secretsmanager:GetSecretValue",
            unrelated_secret,
        ) == "deny"
        _, project = _one(template, "AWS::CodeBuild::Project")
        buildspec = json.loads(project["Properties"]["Source"]["BuildSpec"])
        commands = [
            command
            for phase in buildspec["phases"].values()
            for command in phase["commands"]
        ]
        assert any(
            "secretsmanager get-secret-value" in command
            and "REGISTRY_SECRET_NAME" in command
            for command in commands
        )
        _, trigger = next(
            item
            for item in _resources(
                template, "AWS::CloudFormation::CustomResource"
            ).items()
            if item[0] == build["trigger_logical_id"]
        )
        overrides = trigger["Properties"]["EnvironmentOverrides"]
        registry_override = next(
            item for item in overrides if item["name"] == "REGISTRY_SECRET_NAME"
        )
        assert registry_override["value"] == REGISTRY_SECRET_NAME

    assert _assume(
        template,
        build["role_logical_id"],
        source_arn=build["project_arn"],
        source_account=ACCOUNT,
    ) == "allow", "the stack's own CodeBuild project must still be able to assume its role"

    for label, source_arn, source_account in (
        ("another project in this account", same_account_other, ACCOUNT),
        ("a project name that extends the real name", same_account_suffix, ACCOUNT),
        ("the same project name in another account", other_account, OTHER_ACCOUNT),
    ):
        decision = _assume(
            template,
            build["role_logical_id"],
            source_arn=source_arn,
            source_account=source_account,
        )
        assert decision == "deny", (
            f"{label} ({source_arn}) can assume {build['role_logical_id']}, "
            "the role that can push the runtime repository"
        )


@pytest.mark.parametrize("mode", ["pattern", "migration"])
def test_agent_image_repository_tags_are_immutable(mode: str) -> None:
    template = _template(mode)
    _, repository = _one(template, "AWS::ECR::Repository")
    properties = repository["Properties"]
    assert properties.get("ImageTagMutability") == "IMMUTABLE", (
        "ImageTagMutability is "
        f"{properties.get('ImageTagMutability')!r}; omitting it leaves the "
        "repository MUTABLE, so the tag the runtime records can be replaced"
    )
    assert not properties.get("ImageTagMutabilityExclusionFilters"), (
        "exclusion filters would make selected tags writable again"
    )


@pytest.mark.parametrize("mode", ["pattern", "migration"])
def test_runtime_records_the_build_digest_not_the_source_hash_tag(mode: str) -> None:
    template = _template(mode)
    _assert_digest_pinned(template, _image_build(template))
