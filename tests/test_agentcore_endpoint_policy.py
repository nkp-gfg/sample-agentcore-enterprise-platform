"""The AgentCore interface endpoint must not deploy on the AWS default policy.

The platform-team preset turns networking on and leaves security.org_id empty.
app.py then builds NetworkingStack with VPC endpoints enabled. The stack always
creates the AgentCore gateway interface endpoint, and it attaches
control-library/vpce/agentcore-in-org.json only when an organization id is
set. With the id unset, synthesis omits PolicyDocument.

AWS attaches its default endpoint policy when that property is omitted. The
default is full access: every principal, every action. These tests synthesize
the product path and evaluate that effective policy. They fail while the
endpoint is published without the organization policy, including when a later
error is raised after the endpoint is already in the template. They pass when
synthesis refuses to create the AgentCore endpoint unless an organization id
is set, and when that id's organization policy is the policy on the endpoint.

Bedrock Runtime, ECR, ECR Docker, CloudWatch Logs, Secrets Manager, and the S3
gateway endpoint are created in the same method and never receive this
organization policy. They are not this control and are not asserted here.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import aws_cdk as cdk
import pytest
from aws_cdk.assertions import Template

from infra_utils.policy_loader import load_control
from stacks.networking_stack import NetworkingStack

REPO = Path(__file__).resolve().parents[1]
ACCOUNT_ENV = cdk.Environment(account="111111111111", region="us-east-1")
ORG_ID = "o-abc123def456"
OTHER_ORG = "o-outsiderorg1"

# AWS PrivateLink, "Default endpoint policy": if no policy is attached, AWS
# attaches this document. AgentCore's interface-endpoint guide states the same
# default for this service: full access through the endpoint.
AWS_DEFAULT_ENDPOINT_POLICY: dict[str, Any] = {
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": "*",
            "Action": "*",
            "Resource": "*",
        }
    ]
}

FOREIGN_SIGV4 = {"aws:PrincipalOrgID": OTHER_ORG}
SAME_ORG_SIGV4 = {"aws:PrincipalOrgID": ORG_ID}
OAUTH_CALLER: dict[str, str] = {}


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _principal_matches(principal: Any) -> bool:
    if principal == "*" or principal == {"AWS": "*"}:
        return True
    if isinstance(principal, dict) and principal.get("AWS") == "*":
        return True
    return False


def _action_matches(action: Any, requested: str) -> bool:
    for item in _as_list(action):
        if item == "*" or item == requested:
            return True
        if isinstance(item, str) and item.endswith("*") and requested.startswith(item[:-1]):
            return True
    return False


def _resource_matches(resource: Any) -> bool:
    return any(item == "*" for item in _as_list(resource))


def _string_not_equals(policy_value: Any, request_values: list[str] | None) -> bool:
    """StringNotEquals, including a missing key.

    A missing key makes a negated operator such as StringNotEquals true.
    A present key matches when it is not equal to the policy value.
    """
    expected = _as_list(policy_value)
    if request_values is None:
        return True
    return all(value not in expected for value in request_values)


def _null_matches(policy_value: Any, request_values: list[str] | None) -> bool:
    """Null true matches an absent key. Null false matches a present key."""
    wants_absent = str(policy_value).lower() == "true"
    is_absent = request_values is None
    return wants_absent == is_absent


def _condition_matches(condition: dict[str, Any] | None, context: dict[str, str]) -> bool:
    if not condition:
        return True
    for operator, keys in condition.items():
        for key, policy_value in keys.items():
            present = key in context
            request_values = [context[key]] if present else None
            if operator == "StringNotEquals":
                matched = _string_not_equals(policy_value, request_values)
            elif operator == "Null":
                matched = _null_matches(policy_value, request_values)
            else:
                raise AssertionError(f"unexpected condition operator {operator}")
            if not matched:
                return False
    return True


def _statement_matches(statement: dict[str, Any], action: str, context: dict[str, str]) -> bool:
    return (
        _principal_matches(statement.get("Principal"))
        and _action_matches(statement.get("Action"), action)
        and _resource_matches(statement.get("Resource"))
        and _condition_matches(statement.get("Condition"), context)
    )


def endpoint_policy_allows(policy: dict[str, Any], action: str, context: dict[str, str]) -> bool:
    """Decide one request against an endpoint policy alone.

    An explicit deny overrides an allow. Otherwise a matching allow allows the
    request. With neither, the request stays at the default implicit deny.
    The caller's identity policy is not applied: the finding is that the
    endpoint itself adds no organization or action restriction.
    """
    statements = _as_list(policy.get("Statement"))
    if any(
        statement.get("Effect") == "Deny" and _statement_matches(statement, action, context)
        for statement in statements
    ):
        return False
    return any(
        statement.get("Effect") == "Allow" and _statement_matches(statement, action, context)
        for statement in statements
    )


def _policy_document(properties: dict[str, Any]) -> dict[str, Any]:
    document = properties.get("PolicyDocument")
    if document is None:
        return AWS_DEFAULT_ENDPOINT_POLICY
    if isinstance(document, str):
        document = json.loads(document)
    return document


def _resources(template: dict[str, Any], resource_type: str) -> list[dict[str, Any]]:
    return [
        resource
        for resource in template.get("Resources", {}).values()
        if resource.get("Type") == resource_type
    ]


def agentcore_endpoints(template: dict[str, Any]) -> list[dict[str, Any]]:
    found = []
    for resource in _resources(template, "AWS::EC2::VPCEndpoint"):
        service = json.dumps(resource.get("Properties", {}).get("ServiceName"))
        if "bedrock-agentcore.gateway" in service:
            found.append(resource)
    return found


def _templates_for(app: cdk.App) -> list[dict[str, Any]]:
    templates = []
    for child in app.node.children:
        if not isinstance(child, cdk.Stack):
            continue
        templates.append(Template.from_stack(child).to_json())
    return templates


def synthesize_networking(**overrides: Any) -> tuple[list[dict[str, Any]], str | None]:
    """Build NetworkingStack the way app.py does, even if construction raises.

    An exception after the endpoint is added still leaves that endpoint in the
    stack, so the templates are returned alongside the error.
    """
    app = cdk.App()
    error = None
    kwargs: dict[str, Any] = {
        "project_name": "agentcore-workshop",
        "environment": "dev",
        "enable_vpc_endpoints": True,
        "env": ACCOUNT_ENV,
    }
    kwargs.update(overrides)
    try:
        NetworkingStack(app, "agentcore-workshop-dev-networking", **kwargs)
    except Exception as exc:  # noqa: BLE001 — the refusal itself is the assertion
        error = f"{type(exc).__name__}: {exc}"
    return _templates_for(app), error


def synthesize_app(env: dict[str, str]) -> tuple[list[dict[str, Any]], str | None]:
    """Run app.py and return every stack template that was constructed.

    app.py builds stacks at import. A later stack can raise after the
    networking stack already holds the AgentCore endpoint. The child process
    still emits that template.
    """
    script = r"""
import json, os, sys
root = os.environ["REPO_ROOT"]
os.chdir(root)
sys.path.insert(0, root)
error = None
app = None
try:
    import importlib.util
    loader = importlib.util.spec_from_file_location(
        "agentcore_app", os.path.join(root, "app.py")
    )
    module = importlib.util.module_from_spec(loader)
    sys.modules["agentcore_app"] = module
    loader.loader.exec_module(module)
    app = module.app
except Exception as exc:
    error = f"{type(exc).__name__}: {exc}"
    module = sys.modules.get("agentcore_app")
    app = getattr(module, "app", None) if module is not None else None
templates = []
if app is not None:
    import aws_cdk as cdk
    from aws_cdk.assertions import Template
    for child in app.node.children:
        if isinstance(child, cdk.Stack):
            templates.append(Template.from_stack(child).to_json())
json.dump({"templates": templates, "error": error}, sys.stdout)
"""
    child_env = os.environ.copy()
    for key in (
        "ORG_ID",
        "ENABLE_NETWORKING",
        "ENABLE_RESOURCE_POLICIES",
        "ENABLE_SECURITY",
        "PLATFORM_CONFIG",
        "CDK_DEFAULT_ACCOUNT",
        "CDK_DEFAULT_REGION",
    ):
        child_env.pop(key, None)
    child_env.update(env)
    child_env["REPO_ROOT"] = str(REPO)
    child_env["PLATFORM_ALLOW_PLACEHOLDERS"] = "1"
    child_env["CDK_DEFAULT_ACCOUNT"] = "111111111111"
    child_env["CDK_DEFAULT_REGION"] = "us-east-1"
    completed = subprocess.run(
        [sys.executable, "-c", script],
        cwd=REPO,
        env=child_env,
        text=True,
        capture_output=True,
        check=False,
    )
    if completed.returncode != 0:
        raise AssertionError(
            "app.py synthesis helper failed\n"
            f"stdout:\n{completed.stdout}\nstderr:\n{completed.stderr}"
        )
    payload = json.loads(completed.stdout)
    return payload["templates"], payload["error"]


def _all_agentcore(templates: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [endpoint for template in templates for endpoint in agentcore_endpoints(template)]


def _assert_no_default_agentcore_endpoint(templates: list[dict[str, Any]]) -> None:
    endpoints = _all_agentcore(templates)
    for endpoint in endpoints:
        properties = endpoint["Properties"]
        policy = _policy_document(properties)
        allowed = {
            action: endpoint_policy_allows(policy, action, FOREIGN_SIGV4)
            for action in (
                "bedrock-agentcore:InvokeGateway",
                "bedrock-agentcore:CreateGateway",
            )
        }
        assert not any(allowed.values()), (
            "AgentCore endpoint allows a SigV4 caller from another organization. "
            f"PrivateDnsEnabled={properties.get('PrivateDnsEnabled')!r} "
            f"PolicyDocument={json.dumps(properties.get('PolicyDocument'))} "
            f"effective={json.dumps(policy)} decisions={allowed}"
        )
    assert endpoints == [], (
        "The AgentCore interface endpoint must not be created unless an "
        "organization id is set and the organization endpoint policy is attached. "
        f"Found {len(endpoints)} bedrock-agentcore.gateway endpoint(s)."
    )


def _assert_org_policy_attached(templates: list[dict[str, Any]], org_id: str) -> None:
    endpoints = _all_agentcore(templates)
    assert len(endpoints) == 1, endpoints
    properties = endpoints[0]["Properties"]
    assert properties.get("PrivateDnsEnabled") is True
    assert properties.get("VpcEndpointType") == "Interface"
    expected = load_control("vpce.agentcore-in-org", {"org_id": org_id})
    actual = _policy_document(properties)
    assert actual == expected
    assert endpoint_policy_allows(actual, "bedrock-agentcore:InvokeGateway", {"aws:PrincipalOrgID": org_id})
    assert not endpoint_policy_allows(
        actual, "bedrock-agentcore:CreateGateway", {"aws:PrincipalOrgID": org_id}
    )
    assert not endpoint_policy_allows(actual, "bedrock-agentcore:InvokeGateway", FOREIGN_SIGV4)
    assert not endpoint_policy_allows(actual, "bedrock-agentcore:CreateGateway", FOREIGN_SIGV4)
    assert endpoint_policy_allows(actual, "bedrock-agentcore:InvokeGateway", OAUTH_CALLER)
    assert not endpoint_policy_allows(actual, "bedrock-agentcore:CreateGateway", OAUTH_CALLER)
    assert org_id in json.dumps(actual)
    assert OTHER_ORG not in json.dumps(actual)


def test_platform_team_preset_does_not_publish_a_default_agentcore_endpoint() -> None:
    templates, error = synthesize_app(
        {"PLATFORM_CONFIG": str(REPO / "presets" / "platform-team.yaml")}
    )
    assert error is None, error
    _assert_no_default_agentcore_endpoint(templates)


def test_enable_networking_without_org_id_does_not_publish_a_default_endpoint() -> None:
    templates, error = synthesize_app({"ENABLE_NETWORKING": "true"})
    assert error is None or "org" in error.lower()
    _assert_no_default_agentcore_endpoint(templates)


def test_security_focused_preset_does_not_leave_the_endpoint_behind() -> None:
    """Resource policies fail later when org_id is empty. The endpoint must
    already be absent; a refusal that runs after the endpoint is added fails."""
    templates, error = synthesize_app(
        {"PLATFORM_CONFIG": str(REPO / "presets" / "security-focused.yaml")}
    )
    assert error is not None
    _assert_no_default_agentcore_endpoint(templates)


@pytest.mark.parametrize("org_id", ["", None])
def test_networking_stack_refuses_the_endpoint_without_an_org_id(org_id: str | None) -> None:
    templates, _error = synthesize_networking(org_id=org_id)
    _assert_no_default_agentcore_endpoint(templates)


def test_networking_stack_default_org_id_refuses_the_endpoint() -> None:
    templates, _error = synthesize_networking()
    _assert_no_default_agentcore_endpoint(templates)


def test_org_id_attaches_that_organizations_policy_to_the_agentcore_endpoint() -> None:
    templates, error = synthesize_networking(org_id=ORG_ID)
    assert error is None, error
    _assert_org_policy_attached(templates, ORG_ID)


def test_app_with_org_id_attaches_that_organizations_policy() -> None:
    templates, error = synthesize_app(
        {
            "PLATFORM_CONFIG": str(REPO / "presets" / "platform-team.yaml"),
            "ORG_ID": ORG_ID,
        }
    )
    assert error is None, error
    _assert_org_policy_attached(templates, ORG_ID)


def test_a_different_org_id_is_the_one_written_into_the_policy() -> None:
    other = "o-zzzzzzzzzz"
    templates, error = synthesize_networking(org_id=other)
    assert error is None, error
    _assert_org_policy_attached(templates, other)
    rendered = json.dumps(_policy_document(_all_agentcore(templates)[0]["Properties"]))
    assert ORG_ID not in rendered
