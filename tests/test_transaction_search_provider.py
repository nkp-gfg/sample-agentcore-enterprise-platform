"""The Transaction Search provider must not run caller-supplied AWS API calls.

A normal deploy leaves an AwsCustomResource Lambda in the account. Its role
can change the account-wide X-Ray trace destination, write a CloudWatch Logs
resource policy, and start Application Signals. The CDK provider handler reads
the service, action, and parameters from the invoke event. These tests invoke
that deployed handler with those calls and require it to ignore them.

They fail while that passthrough is what the stack deploys.
"""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from typing import Any

import aws_cdk as cdk
import pytest

from stacks.observability_stack import ObservabilityStack

REPO = Path(__file__).resolve().parents[1]
HARNESS = Path(__file__).resolve().parent / "transaction_search_provider_harness.cjs"
SDK_PACKAGES = (
    "@aws-sdk/client-cloudwatch-logs@3.1173.0",
    "@aws-sdk/client-xray@3.1173.0",
    "@aws-sdk/client-iam@3.1173.0",
    "@aws-sdk/client-application-signals@3.1173.0",
    "@aws-sdk/client-cloudtrail@3.1173.0",
)
ENV = cdk.Environment(account="111111111111", region="us-east-1")
ATTACKER_POLICY = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": "111122223333"},
                "Action": "logs:PutLogEvents",
                "Resource": "*",
            }
        ],
    }
)

# Every SDK call the provider role allows, other than the one destination
# update the feature needs. cloudtrail:CreateServiceLinkedChannel is on the
# role but is not in this list: @aws-sdk/client-cloudtrail@3.1173.0 has no
# CreateServiceLinkedChannel command, so this handler never reaches that API.
ATTACKS: list[dict[str, Any]] = [
    {
        "name": "logs-put-resource-policy",
        "call": {
            "service": "CloudWatchLogs",
            "action": "putResourcePolicy",
            "parameters": {
                "policyName": "attacker-policy",
                "policyDocument": ATTACKER_POLICY,
            },
            "physicalResourceId": {"id": "attacker-chosen"},
        },
    },
    {
        "name": "logs-describe-resource-policies",
        "call": {
            "service": "CloudWatchLogs",
            "action": "describeResourcePolicies",
            "parameters": {},
            "physicalResourceId": {"id": "attacker-chosen"},
        },
    },
    {
        "name": "logs-create-log-group",
        "call": {
            "service": "CloudWatchLogs",
            "action": "createLogGroup",
            "parameters": {"logGroupName": "aws/spans"},
            "physicalResourceId": {"id": "attacker-chosen"},
        },
    },
    {
        "name": "logs-create-log-stream",
        "call": {
            "service": "CloudWatchLogs",
            "action": "createLogStream",
            "parameters": {
                "logGroupName": "aws/spans",
                "logStreamName": "attacker",
            },
            "physicalResourceId": {"id": "attacker-chosen"},
        },
    },
    {
        "name": "logs-put-retention-policy",
        "call": {
            "service": "CloudWatchLogs",
            "action": "putRetentionPolicy",
            "parameters": {"logGroupName": "aws/spans", "retentionInDays": 1},
            "physicalResourceId": {"id": "attacker-chosen"},
        },
    },
    {
        "name": "xray-retarget-destination",
        "call": {
            "service": "XRay",
            "action": "updateTraceSegmentDestination",
            "parameters": {"Destination": "XRay"},
            "physicalResourceId": {"id": "attacker-chosen"},
        },
    },
    {
        "name": "xray-get-destination",
        "call": {
            "service": "XRay",
            "action": "getTraceSegmentDestination",
            "parameters": {},
            "physicalResourceId": {"id": "attacker-chosen"},
        },
    },
    {
        "name": "xray-update-indexing-rule",
        "call": {
            "service": "XRay",
            "action": "updateIndexingRule",
            "parameters": {
                "Name": "Default",
                "Rule": {"Probabilistic": {"DesiredSamplingPercentage": 0}},
            },
            "physicalResourceId": {"id": "attacker-chosen"},
        },
    },
    {
        "name": "xray-get-indexing-rules",
        "call": {
            "service": "XRay",
            "action": "getIndexingRules",
            "parameters": {},
            "physicalResourceId": {"id": "attacker-chosen"},
        },
    },
    {
        "name": "application-signals-start-discovery",
        "call": {
            "service": "ApplicationSignals",
            "action": "startDiscovery",
            "parameters": {},
            "physicalResourceId": {"id": "attacker-chosen"},
        },
    },
    {
        "name": "iam-create-service-linked-role",
        "call": {
            "service": "IAM",
            "action": "createServiceLinkedRole",
            "parameters": {
                "AWSServiceName": "application-signals.cloudwatch.amazonaws.com",
                "Description": "attacker",
            },
            "physicalResourceId": {"id": "attacker-chosen"},
        },
    },
    {
        "name": "iam-get-role",
        "call": {
            "service": "IAM",
            "action": "getRole",
            "parameters": {
                "RoleName": "AWSServiceRoleForCloudWatchApplicationSignals"
            },
            "physicalResourceId": {"id": "attacker-chosen"},
        },
    },
]

REQUEST_TYPES = ("Create", "Update", "Delete")
HARDCODED_DESTINATION = json.dumps({"Destination": "CloudWatchLogs"})


def _synth(tmp: Path, *, enable_transaction_search: bool) -> dict[str, Any]:
    app = cdk.App(outdir=str(tmp))
    ObservabilityStack(
        app,
        "obs",
        project_name="plat",
        environment="dev",
        enable_transaction_search=enable_transaction_search,
        env=ENV,
    )
    app.synth()
    return json.loads((tmp / "obs.template.json").read_text())


def _provider(template: dict[str, Any]) -> tuple[str, dict[str, Any]] | None:
    resources = template.get("Resources") or {}
    custom = [
        resource
        for resource in resources.values()
        if resource["Type"] == "Custom::AWS"
    ]
    if not custom:
        return None
    token = custom[0]["Properties"]["ServiceToken"]
    function_id = token["Fn::GetAtt"][0]
    return function_id, resources[function_id]


def _handler_source(outdir: Path, function: dict[str, Any]) -> Path:
    code = function["Properties"]["Code"]
    if "ZipFile" in code:
        path = outdir / "inline-provider.js"
        path.write_text(code["ZipFile"])
        return path
    key = code["S3Key"]
    asset = key[: -len(".zip")] if key.endswith(".zip") else key
    return outdir / f"asset.{asset}" / "index.js"


def _statements(node: Any) -> list[dict[str, Any]]:
    found: list[dict[str, Any]] = []
    if isinstance(node, dict):
        effect = node.get("Effect")
        action = node.get("Action")
        if effect in ("Allow", "Deny") and action is not None:
            found.append(node)
        for value in node.values():
            found.extend(_statements(value))
    elif isinstance(node, list):
        for value in node:
            found.extend(_statements(value))
    elif isinstance(node, str) and "Effect" in node and "Action" in node:
        try:
            found.extend(_statements(json.loads(node)))
        except json.JSONDecodeError:
            pass
    return found


def _actions(statement: dict[str, Any]) -> set[str]:
    action = statement["Action"]
    return set(action) if isinstance(action, list) else {action}


@pytest.fixture(scope="module")
def sdk_node_modules(tmp_path_factory: pytest.TempPathFactory) -> Path:
    vendor = tmp_path_factory.mktemp("aws-sdk")
    subprocess.run(
        ["npm", "install", "--silent", "--no-fund", "--no-audit", *SDK_PACKAGES],
        cwd=vendor,
        check=True,
    )
    return vendor / "node_modules"


@pytest.fixture(scope="module")
def default_provider(tmp_path_factory: pytest.TempPathFactory) -> dict[str, Any]:
    outdir = tmp_path_factory.mktemp("synth")
    template = _synth(outdir, enable_transaction_search=True)
    located = _provider(template)
    if located is None:
        return {"template": template, "function": None, "handler": None}
    function_id, function = located
    return {
        "template": template,
        "function_id": function_id,
        "function": function,
        "handler": _handler_source(outdir, function),
        "outdir": outdir,
    }


@pytest.fixture(scope="module")
def provider_results(
    default_provider: dict[str, Any], sdk_node_modules: Path
) -> dict[str, dict[str, Any]]:
    handler = default_provider["handler"]
    if handler is None:
        return {}
    cases = [
        {
            "name": f"{attack['name']}:{request_type}",
            "requestType": request_type,
            "call": attack["call"],
        }
        for attack in ATTACKS
        for request_type in REQUEST_TYPES
    ]
    env = os.environ.copy()
    env.update(
        {
            "NODE_PATH": str(sdk_node_modules),
            "AWS_ACCESS_KEY_ID": "TESTKEY",
            "AWS_SECRET_ACCESS_KEY": "TESTSECRET",
            "AWS_REGION": "us-east-1",
            "AWS_EC2_METADATA_DISABLED": "true",
            "AWS_SDK_JS_SUPPRESS_MAINTENANCE_MODE_MESSAGE": "1",
        }
    )
    completed = subprocess.run(
        ["node", str(HARNESS), str(handler)],
        input=json.dumps(cases),
        text=True,
        capture_output=True,
        env=env,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    parsed = json.loads(completed.stdout)
    return {item["name"]: item for item in parsed}


def _is_hardcoded_destination(call: dict[str, str]) -> bool:
    path = call.get("path") or ""
    target = call.get("target") or ""
    body = call.get("body") or ""
    names_destination = path.endswith(
        "/UpdateTraceSegmentDestination"
    ) or target.endswith(".UpdateTraceSegmentDestination")
    return names_destination and body == HARDCODED_DESTINATION


def test_disabling_transaction_search_does_not_create_the_provider(
    tmp_path: Path,
) -> None:
    template = _synth(tmp_path, enable_transaction_search=False)
    assert _provider(template) is None


@pytest.mark.parametrize("attack", ATTACKS, ids=lambda attack: attack["name"])
@pytest.mark.parametrize("request_type", REQUEST_TYPES)
def test_provider_ignores_caller_supplied_api_calls(
    default_provider: dict[str, Any],
    provider_results: dict[str, dict[str, Any]],
    attack: dict[str, Any],
    request_type: str,
) -> None:
    if default_provider["handler"] is None:
        return
    result = provider_results[f"{attack['name']}:{request_type}"]
    unexpected = [
        call for call in result["calls"] if not _is_hardcoded_destination(call)
    ]
    assert unexpected == [], result


def test_provider_role_can_only_update_the_trace_destination(
    default_provider: dict[str, Any],
) -> None:
    function = default_provider["function"]
    if function is None:
        return
    template = default_provider["template"]
    role_id = function["Properties"]["Role"]["Fn::GetAtt"][0]
    role_name = template["Resources"][role_id]["Properties"].get("RoleName")
    allowed: set[str] = set()
    for resource in template["Resources"].values():
        if resource["Type"] != "AWS::IAM::Policy":
            continue
        roles = resource["Properties"].get("Roles", [])
        attaches = any(
            role == {"Ref": role_id} or role == role_name for role in roles
        )
        if not attaches:
            continue
        for statement in _statements(resource["Properties"]["PolicyDocument"]):
            if statement["Effect"] == "Allow":
                allowed.update(_actions(statement))
    assert allowed == {"xray:UpdateTraceSegmentDestination"}


def test_only_cloudformation_for_this_stack_can_invoke_the_provider(
    default_provider: dict[str, Any],
) -> None:
    if default_provider["function"] is None:
        return
    denies = [
        statement
        for statement in _statements(default_provider["template"])
        if statement["Effect"] == "Deny"
        and (
            "lambda:InvokeFunction" in _actions(statement)
            or "*" in _actions(statement)
        )
    ]
    rendered = json.dumps(denies)
    assert denies, "provider function has no resource-based invoke deny"
    assert "cloudformation.amazonaws.com" in rendered
    assert "aws:cloudformation:stack" in rendered or "StackId" in rendered
