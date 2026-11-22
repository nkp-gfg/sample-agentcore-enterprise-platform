"""Log delivery verification must follow the resources this deployment published.

`scripts/check_observability.py` is the observability step of `scripts/verify.py`
and of module 9 in `scripts/deploy.sh`. It lists CloudWatch Logs delivery
sources and deliveries through the botocore paginators
(`deliverySources`, `deliveries`, `deliveryDestinations` in
botocore's logs paginators). A source counts only when all of the following
hold:

- Its `resourceArns` contain an AgentCore ARN this deployment published.
- That source has a delivery.
- The delivery's destination `destinationResourceArn` is the log group
  `ObservabilityStack` creates for that resource:
  `/aws/bedrock-agentcore/{project}-{environment}/{resource}` with the
  CloudFormation log group Arn suffix `:*`.
- Sources that do not carry a published ARN are ignored, including names
  that only share the `{project}-{environment}` prefix.

Published ARNs, from the stacks that write them:

- gateway: `DescribeStacks` output `GatewayArn` on `{prefix}-gateway`
  (`stacks/gateway_stack.py`). There is no gateway ARN in SSM.
- memory: SSM `/{project}/{environment}/memory/memory-arn` and output
  `MemoryArn` on `{prefix}-memory`.
- runtimes: SSM `/{project}/{environment}/runtimes/{component}/arn` and output
  `RuntimeArn` on `{prefix}-runtime-{component}`. The monitored resource key
  and log group name are `runtime-{component}` (`app.py`). Orchestrator
  generations use the source name suffix `-g{N}` (`observability_stack.py`);
  the log group name does not. Identity is the published ARN.

The Logs client below is a real boto3 client. Responses are validated against
the botocore 1.44.9 logs/ssm/cloudformation/xray models and paged with the
real paginator (`nextToken`, one item at a time), which is the behavior
`_all_paginated` was written for.
"""

from __future__ import annotations

import json
import sys
from datetime import UTC, datetime
from pathlib import Path

import boto3
import pytest
from botocore.awsrequest import AWSResponse
from botocore.validate import validate_parameters

# Saved before tests replace boto3.client. check_observability binds the same
# module object, so patching its client attribute patches this name too.
_BOTO3_CLIENT = boto3.client

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "scripts"))

REGION = "us-east-1"
ACCOUNT = "111122223333"
PROJECT = "agentcore-workshop"
ENVIRONMENT = "dev"
PREFIX = f"{PROJECT}-{ENVIRONMENT}"

GATEWAY_ARN = f"arn:aws:bedrock-agentcore:{REGION}:{ACCOUNT}:gateway/gw-platform"
MEMORY_ARN = f"arn:aws:bedrock-agentcore:{REGION}:{ACCOUNT}:memory/mem-platform"
RUNTIME_ARN = (
    f"arn:aws:bedrock-agentcore:{REGION}:{ACCOUNT}:runtime/{PREFIX}-orchestrator"
)
UNRELATED_ARN = f"arn:aws:lambda:{REGION}:{ACCOUNT}:function:unrelated"


def log_group_name(resource: str) -> str:
    return f"/aws/bedrock-agentcore/{PREFIX}/{resource}"


def log_group_arn(resource: str) -> str:
    # AWS::Logs::LogGroup Arn, which CDK's logGroupArn attribute returns and
    # ObservabilityStack stores as DeliveryDestination.DestinationResourceArn.
    return f"arn:aws:logs:{REGION}:{ACCOUNT}:log-group:{log_group_name(resource)}:*"


def _named(kind: str, name: str) -> str:
    assert 1 <= len(name) <= 60, name
    return f"arn:aws:logs:{REGION}:{ACCOUNT}:{kind}:{name}"


def source(name: str, resource_arn: str) -> dict:
    return {
        "name": name,
        "arn": _named("delivery-source", name),
        "resourceArns": [resource_arn],
        "logType": "APPLICATION_LOGS",
        "service": "bedrock-agentcore",
    }


def destination(resource: str, target_group: str) -> dict:
    name = f"{PREFIX}-{resource}-cw-dest"
    return {
        "name": name,
        "arn": _named("delivery-destination", name),
        "deliveryDestinationType": "CWL",
        "deliveryDestinationConfiguration": {
            "destinationResourceArn": log_group_arn(target_group),
        },
    }


def delivery(source_name: str, destination_arn: str, delivery_id: str) -> dict:
    return {
        "id": delivery_id,
        "arn": _named("delivery", delivery_id),
        "deliverySourceName": source_name,
        "deliveryDestinationArn": destination_arn,
        "deliveryDestinationType": "CWL",
    }


def connected(
    resource: str,
    resource_arn: str,
    delivery_id: str,
    *,
    source_name=None,
    target_group=None,
):
    """One platform source, the destination ObservabilityStack creates, and the delivery between them."""
    source_name = source_name or f"{PREFIX}-{resource}-app-logs"
    dest = destination(resource, target_group or resource)
    return (
        source(source_name, resource_arn),
        delivery(source_name, dest["arn"], delivery_id),
        dest,
    )


class Deployment:
    def __init__(self):
        self.sources: list[dict] = []
        self.deliveries: list[dict] = []
        self.destinations: list[dict] = []

    def add(self, source_item, delivery_item=None, destination_item=None):
        self.sources.append(source_item)
        if delivery_item is not None:
            self.deliveries.append(delivery_item)
        if destination_item is not None:
            self.destinations.append(destination_item)
        return self


def platform_connections() -> list[tuple]:
    """Gateway, memory, and the generation-2 orchestrator source, each aimed at its own log group."""
    return [
        connected("gateway", GATEWAY_ARN, "dgw"),
        connected("memory", MEMORY_ARN, "dmem"),
        connected(
            "runtime-orchestrator",
            RUNTIME_ARN,
            "drt",
            source_name=f"{PREFIX}-runtime-orchestrator-app-logs-g2",
        ),
    ]


def _page(items: list, params: dict, member: str) -> dict:
    start = int(params.get("nextToken") or 0)
    limit = int(params.get("limit") or 1)
    body = {member: items[start : start + limit]}
    nxt = start + limit
    if nxt < len(items):
        body["nextToken"] = str(nxt)
    return body


def _matching_path(path: str, name: str, recursive: bool) -> bool:
    prefix = path.rstrip("/")
    if not name.startswith(prefix + "/"):
        return False
    return recursive or "/" not in name[len(prefix) + 1 :]


def _parameters() -> list[dict]:
    return [
        {
            "Name": f"/{PROJECT}/{ENVIRONMENT}/memory/memory-arn",
            "Type": "String",
            "Value": MEMORY_ARN,
        },
        {
            "Name": f"/{PROJECT}/{ENVIRONMENT}/runtimes/orchestrator/arn",
            "Type": "String",
            "Value": RUNTIME_ARN,
        },
    ]


def _stacks() -> list[dict]:
    created = datetime(2026, 8, 11, tzinfo=UTC)

    def stack(name: str, outputs: list[dict]) -> dict:
        return {
            "StackName": name,
            "CreationTime": created,
            "StackStatus": "CREATE_COMPLETE",
            "Outputs": outputs,
        }

    return [
        stack(
            f"{PREFIX}-gateway",
            [
                {"OutputKey": "GatewayArn", "OutputValue": GATEWAY_ARN},
                {
                    "OutputKey": "GatewayId",
                    "OutputValue": "gw-platform",
                },
            ],
        ),
        stack(
            f"{PREFIX}-memory",
            [
                {
                    "OutputKey": "MemoryArn",
                    "OutputValue": MEMORY_ARN,
                    "ExportName": f"{PREFIX}-memory-arn",
                }
            ],
        ),
        stack(
            f"{PREFIX}-runtime-orchestrator",
            [
                {
                    "OutputKey": "RuntimeArn",
                    "OutputValue": RUNTIME_ARN,
                    "ExportName": f"{PREFIX}-orchestrator-runtime-arn",
                }
            ],
        ),
        stack(
            f"{PREFIX}-observability",
            [
                {
                    "OutputKey": "MonitoredResources",
                    "OutputValue": "gateway,memory,runtime-orchestrator",
                }
            ],
        ),
    ]


def _span_policy() -> dict:
    document = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "xray.amazonaws.com"},
                "Action": "logs:PutLogEvents",
                "Resource": [
                    f"arn:aws:logs:{REGION}:{ACCOUNT}:log-group:aws/spans:*",
                    f"arn:aws:logs:{REGION}:{ACCOUNT}:log-group:/aws/application-signals/data:*",
                ],
            }
        ],
    }
    return {
        "policyName": f"{PREFIX}-transaction-search-xray",
        "policyDocument": json.dumps(document),
    }


def _error(code: str, message: str, status: int = 400):
    return (
        AWSResponse(None, status, {}, None),
        {
            "Error": {"Code": code, "Message": message},
            "ResponseMetadata": {"HTTPStatusCode": status},
        },
    )


def _logs_response(deployment: Deployment, operation: str, params: dict):
    if operation == "DescribeDeliverySources":
        items = list(deployment.sources)
        wanted = params.get("resourceArns")
        if wanted:
            items = [
                item
                for item in items
                if set(wanted) & set(item.get("resourceArns") or [])
            ]
        return _page(items, params, "deliverySources")
    if operation == "GetDeliverySource":
        for item in deployment.sources:
            if item["name"] == params.get("name"):
                return {"deliverySource": item}
        return _error("ResourceNotFoundException", "unknown delivery source")
    if operation == "DescribeDeliveries":
        items = list(deployment.deliveries)
        wanted = params.get("deliverySourceNames")
        if wanted:
            items = [item for item in items if item["deliverySourceName"] in wanted]
        return _page(items, params, "deliveries")
    if operation == "DescribeDeliveryDestinations":
        items = list(deployment.destinations)
        wanted = params.get("names")
        if wanted:
            items = [item for item in items if item["name"] in wanted]
        return _page(items, params, "deliveryDestinations")
    if operation == "GetDeliveryDestination":
        for item in deployment.destinations:
            if item["name"] == params.get("name"):
                return {"deliveryDestination": item}
        return _error("ResourceNotFoundException", "unknown delivery destination")
    if operation == "DescribeResourcePolicies":
        return {"resourcePolicies": [_span_policy()]}
    return None


def _ssm_response(operation: str, params: dict):
    parameters = _parameters()
    if operation == "GetParametersByPath":
        path = params["Path"]
        recursive = bool(params.get("Recursive"))
        matched = [
            item for item in parameters if _matching_path(path, item["Name"], recursive)
        ]
        return {"Parameters": matched}
    if operation == "GetParameter":
        for item in parameters:
            if item["Name"] == params.get("Name"):
                return {"Parameter": item}
        return _error("ParameterNotFound", "unknown parameter")
    if operation == "GetParameters":
        names = params.get("Names") or []
        found = [item for item in parameters if item["Name"] in names]
        missing = [
            name for name in names if name not in {item["Name"] for item in found}
        ]
        return {"Parameters": found, "InvalidParameters": missing}
    return None


def _cloudformation_response(operation: str, params: dict):
    stacks = _stacks()
    if operation == "DescribeStacks":
        name = params.get("StackName")
        if name is not None:
            stacks = [item for item in stacks if item["StackName"] == name]
            if not stacks:
                return _error("ValidationError", f"Stack with id {name} does not exist")
        return {"Stacks": stacks}
    return None


def _dispatch(deployment: Deployment, service: str, operation: str, params: dict):
    if service == "logs":
        response = _logs_response(deployment, operation, params)
    elif service == "ssm":
        response = _ssm_response(operation, params)
    elif service == "cloudformation":
        response = _cloudformation_response(operation, params)
    elif service == "xray" and operation == "GetTraceSegmentDestination":
        response = {"Destination": "CloudWatchLogs", "Status": "ACTIVE"}
    else:
        response = None
    if response is None:
        raise AssertionError(f"no response for {service}.{operation} {params}")
    return response


def _client(deployment: Deployment, service_name: str, region_name: str = REGION):
    """Real boto3 client whose HTTP call is replaced with a model-validated page."""
    client = _BOTO3_CLIENT(service_name, region_name=region_name)
    latest: dict = {}

    def capture(params, **kwargs):
        latest["params"] = params

    def respond(model, **kwargs):
        result = _dispatch(
            deployment,
            client.meta.service_model.service_name,
            model.name,
            latest.get("params") or {},
        )
        if isinstance(result, tuple):
            return result
        if model.output_shape is not None:
            validate_parameters(result, model.output_shape)
        return (AWSResponse(None, 200, {}, None), result)

    def clear_account(builtins, **kwargs):
        if "AWS::Auth::AccountId" in builtins:
            builtins["AWS::Auth::AccountId"] = None

    client.meta.events.register("before-parameter-build.*.*", capture)
    client.meta.events.register("before-call.*.*", respond)
    client.meta.events.register("before-endpoint-resolution.*", clear_account)
    return client


def _prove_publication_is_readable(deployment: Deployment) -> None:
    """The stand-in must actually serve the ARNs the stacks publish."""
    ssm = _client(deployment, "ssm")
    found = {
        item["Name"]: item["Value"]
        for item in ssm.get_parameters_by_path(
            Path=f"/{PROJECT}/{ENVIRONMENT}", Recursive=True
        )["Parameters"]
    }
    assert found[f"/{PROJECT}/{ENVIRONMENT}/memory/memory-arn"] == MEMORY_ARN
    assert found[f"/{PROJECT}/{ENVIRONMENT}/runtimes/orchestrator/arn"] == RUNTIME_ARN
    one = ssm.get_parameter(Name=f"/{PROJECT}/{ENVIRONMENT}/memory/memory-arn")
    assert one["Parameter"]["Value"] == MEMORY_ARN

    cfn = _client(deployment, "cloudformation")
    outputs = {
        item["OutputKey"]: item["OutputValue"]
        for item in cfn.describe_stacks(StackName=f"{PREFIX}-gateway")["Stacks"][0][
            "Outputs"
        ]
    }
    assert outputs["GatewayArn"] == GATEWAY_ARN
    monitored = {
        item["OutputKey"]: item["OutputValue"]
        for item in cfn.describe_stacks(StackName=f"{PREFIX}-observability")["Stacks"][
            0
        ]["Outputs"]
    }
    assert monitored["MonitoredResources"] == "gateway,memory,runtime-orchestrator"


@pytest.fixture
def deployment(monkeypatch):
    monkeypatch.setenv("PROJECT_NAME", PROJECT)
    monkeypatch.setenv("ENVIRONMENT", ENVIRONMENT)
    monkeypatch.setenv("AWS_REGION", REGION)
    monkeypatch.delenv("AWS_DEFAULT_REGION", raising=False)
    import importlib

    import check_observability

    check_observability = importlib.reload(check_observability)
    state = Deployment()
    monkeypatch.setattr(
        check_observability.boto3,
        "client",
        lambda service_name, *args, **kwargs: _client(
            state, service_name, kwargs.get("region_name", REGION)
        ),
    )
    _prove_publication_is_readable(state)
    return state, check_observability


def _reject(fn, capsys):
    try:
        fn()
    except SystemExit as exc:
        assert exc.code == 1
        rejected = True
    else:
        rejected = False
    captured = capsys.readouterr()
    assert rejected, f"check reported success:\n{captured.out}"
    assert "PASS:" not in captured.out
    assert "OK: logs and traces are being accepted" not in captured.out
    assert "FAIL:" in captured.err


def _accept(fn, capsys):
    try:
        fn()
    except SystemExit as exc:
        captured = capsys.readouterr()
        pytest.fail(
            f"check rejected a complete delivery set ({exc.code}):\n"
            f"{captured.err}{captured.out}"
        )
    captured = capsys.readouterr()
    assert captured.err == ""
    assert "PASS: 3 vended log deliveries active" in captured.out


def test_prefixed_decoy_delivery_is_not_vended_platform_logs(deployment, capsys):
    """The attack: delete the platform sources and leave one connected source that only shares the name prefix."""
    state, check_observability = deployment
    decoy = destination("unrelated", "unrelated")
    decoy["deliveryDestinationConfiguration"]["destinationResourceArn"] = (
        f"arn:aws:logs:{REGION}:{ACCOUNT}:log-group:/aws/unrelated/decoy:*"
    )
    state.add(
        source(f"{PREFIX}-unrelated", UNRELATED_ARN),
        delivery(f"{PREFIX}-unrelated", decoy["arn"], "ddecoy"),
        decoy,
    )
    state.add(
        source("other-workshop-dev-gateway-app-logs", UNRELATED_ARN),
        delivery("other-workshop-dev-gateway-app-logs", decoy["arn"], "dother"),
    )
    _reject(check_observability.check_log_deliveries, capsys)


def test_reused_platform_source_name_with_a_different_resource_arn_is_rejected(
    deployment, capsys
):
    """A source named like the gateway still does not count when its resource ARN is not the published gateway."""
    state, check_observability = deployment
    gateway_source, gateway_delivery, gateway_dest = connected(
        "gateway", UNRELATED_ARN, "dgw"
    )
    state.add(gateway_source, gateway_delivery, gateway_dest)
    memory = connected("memory", MEMORY_ARN, "dmem")
    runtime = connected(
        "runtime-orchestrator",
        RUNTIME_ARN,
        "drt",
        source_name=f"{PREFIX}-runtime-orchestrator-app-logs-g2",
    )
    state.add(*memory)
    state.add(*runtime)
    _reject(check_observability.check_log_deliveries, capsys)


def test_delivery_into_a_different_log_group_is_rejected(deployment, capsys):
    """Gateway, memory, and runtime ARNs are bound, but the gateway delivery lands in the memory log group."""
    state, check_observability = deployment
    state.add(*connected("gateway", GATEWAY_ARN, "dgw", target_group="memory"))
    state.add(*connected("memory", MEMORY_ARN, "dmem"))
    state.add(
        *connected(
            "runtime-orchestrator",
            RUNTIME_ARN,
            "drt",
            source_name=f"{PREFIX}-runtime-orchestrator-app-logs-g2",
        )
    )
    _reject(check_observability.check_log_deliveries, capsys)


def test_missing_published_runtime_is_rejected_when_other_deliveries_exist(
    deployment, capsys
):
    state, check_observability = deployment
    state.add(*connected("gateway", GATEWAY_ARN, "dgw"))
    state.add(*connected("memory", MEMORY_ARN, "dmem"))
    _reject(check_observability.check_log_deliveries, capsys)


def test_published_resources_pass_and_unrelated_prefixed_sources_are_ignored(
    deployment, capsys
):
    """Required deliveries may sit on later Logs pages. An unconnected prefixed source does not fail the check."""
    state, check_observability = deployment
    state.add(source(f"{PREFIX}-unrelated", UNRELATED_ARN))
    state.add(source("other-workshop-dev-gateway-app-logs", UNRELATED_ARN))
    for item in platform_connections():
        state.add(*item)
    _accept(check_observability.check_log_deliveries, capsys)


def test_observability_script_does_not_report_logs_accepted_for_a_prefixed_decoy(
    deployment, capsys
):
    """main() is what verify and deploy.sh execute. Trace checks are healthy; only log delivery is forged."""
    state, check_observability = deployment
    decoy = destination("unrelated", "unrelated")
    decoy["deliveryDestinationConfiguration"]["destinationResourceArn"] = (
        f"arn:aws:logs:{REGION}:{ACCOUNT}:log-group:/aws/unrelated/decoy:*"
    )
    state.add(
        source(f"{PREFIX}-unrelated", UNRELATED_ARN),
        delivery(f"{PREFIX}-unrelated", decoy["arn"], "ddecoy"),
        decoy,
    )
    _reject(check_observability.main, capsys)
