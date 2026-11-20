"""Security-alert delivery for AgentCore control-plane changes.

The production, security-focused, and platform-team presets set
``security.traceability``. ``app.py`` turns that into ``enable_traceability``
on ``ObservabilityStack`` and, because traceability requires it, deploys
``SecurityStack`` with a logging trail. The EventBridge rule must publish a
CloudTrail management event to the security-alerts topic when the call
changes where a gateway sends tool traffic, which image or endpoint a
runtime serves, which OAuth client the token vault stores, which workload
identity that vault is bound to, or a policy mutation in the same family the
rule already alerts on.

These tests fail while those event names are absent from the rule. They pass
once the synthesized pattern matches the events and the rule still publishes
to the security-alerts topic.

Left untested, on purpose: memory create/update (``DeleteMemory`` is already
alerted, and memory writes are not the data-flow change this rule is missing),
API-key and payment credential-provider writes, token-vault CMK rotation,
and the browser, code-interpreter, harness, dataset, evaluator, registry,
consent, capacity, configuration, payment, and gateway rate-limit or rule
writes. ``InvokeGateway`` is covered only as a data event that must stay
quiet.
"""

from __future__ import annotations

import gzip
import json
from pathlib import Path
from typing import Any

import aws_cdk as cdk
import botocore
import pytest
import yaml
from aws_cdk.assertions import Template

from infra_utils.platform_config import load_platform_config, to_env
from stacks.observability_stack import ObservabilityStack
from stacks.security_stack import SecurityStack

REPO = Path(__file__).resolve().parents[1]
PRESETS = ("production.yaml", "security-focused.yaml", "platform-team.yaml")
ENV = cdk.Environment(account="111111111111", region="us-east-1")

# botocore 1.44.7 (the install of botocore>=1.43.72) names the control plane
# ``bedrock-agentcore-control`` and signs it as ``bedrock-agentcore``.
# CloudTrail records that service as bedrock-agentcore.amazonaws.com: the
# management-event example on
# https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/understanding-gateway-cloudtrail-log-entries.html
# uses eventSource "bedrock-agentcore.amazonaws.com" and eventName "CreateGateway".
EVENT_SOURCE = "bedrock-agentcore.amazonaws.com"

# EventBridge delivers that record with detail-type "AWS API Call via CloudTrail"
# and source "aws." plus the eventSource minus ".amazonaws.com". The worked
# example on
# https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-service-event-cloudtrail.html
# maps eventSource "ec2.amazonaws.com" to source "aws.ec2".
DETAIL_TYPE = "AWS API Call via CloudTrail"

# Write management events match a rule whose State is ENABLED. Read-only
# management events match only ENABLED_WITH_ALL_CLOUDTRAIL_MANAGEMENT_EVENTS.
# Same page as the envelope example.
WRITE_RULE_STATES = {
    "ENABLED",
    "ENABLED_WITH_ALL_CLOUDTRAIL_MANAGEMENT_EVENTS",
}

IMAGE = "111111111111.dkr.ecr.us-east-1.amazonaws.com/agent:swapped"
MCP_ENDPOINT = "https://tools.example.invalid/mcp"
OAUTH_CLIENT_ID = "placeholder-oauth-client-id"

# Request fields are the input members of each operation in
# botocore/data/bedrock-agentcore-control/2023-06-05/service-2.json.gz.
# The rule filters on eventName; the parameters are the change the event
# describes, and a match must not depend on stripping them.
CONTROL_PLANE_CHANGES: dict[str, dict[str, Any]] = {
    "CreateGatewayTarget": {
        "gatewayIdentifier": "gateway-under-test",
        "name": "external-tools",
        "targetConfiguration": {
            "mcp": {"mcpServer": {"endpoint": MCP_ENDPOINT}},
        },
    },
    "UpdateGatewayTarget": {
        "gatewayIdentifier": "gateway-under-test",
        "targetId": "target-under-test",
        "name": "external-tools",
        "targetConfiguration": {
            "mcp": {"mcpServer": {"endpoint": MCP_ENDPOINT}},
        },
    },
    "DeleteGatewayTarget": {
        "gatewayIdentifier": "gateway-under-test",
        "targetId": "target-under-test",
    },
    "SynchronizeGatewayTargets": {
        "gatewayIdentifier": "gateway-under-test",
    },
    "CreateAgentRuntime": {
        "agentRuntimeName": "orchestrator",
        "agentRuntimeArtifact": {
            "containerConfiguration": {"containerUri": IMAGE},
        },
    },
    "UpdateAgentRuntime": {
        "agentRuntimeId": "runtime-under-test",
        "agentRuntimeArtifact": {
            "containerConfiguration": {"containerUri": IMAGE},
        },
    },
    "DeleteAgentRuntime": {"agentRuntimeId": "runtime-under-test"},
    "CreateAgentRuntimeEndpoint": {
        "agentRuntimeId": "runtime-under-test",
        "name": "DEFAULT",
        "agentRuntimeVersion": "2",
    },
    "UpdateAgentRuntimeEndpoint": {
        "agentRuntimeId": "runtime-under-test",
        "endpointName": "DEFAULT",
        "agentRuntimeVersion": "2",
    },
    "DeleteAgentRuntimeEndpoint": {
        "agentRuntimeId": "runtime-under-test",
        "endpointName": "DEFAULT",
    },
    "CreateOauth2CredentialProvider": {
        "name": "gateway-m2m",
        "credentialProviderVendor": "CustomOauth2",
        "oauth2ProviderConfigInput": {
            "customOauth2ProviderConfig": {"clientId": OAUTH_CLIENT_ID},
        },
    },
    "UpdateOauth2CredentialProvider": {
        "name": "gateway-m2m",
        "credentialProviderVendor": "CustomOauth2",
        "oauth2ProviderConfigInput": {
            "customOauth2ProviderConfig": {"clientId": OAUTH_CLIENT_ID},
        },
    },
    "DeleteOauth2CredentialProvider": {"name": "gateway-m2m"},
    "CreateWorkloadIdentity": {"name": "workload-under-test"},
    "UpdateWorkloadIdentity": {
        "name": "workload-under-test",
        "allowedResourceOauth2ReturnUrls": ["https://callback.example.invalid/return"],
    },
    "DeleteWorkloadIdentity": {"name": "workload-under-test"},
    "UpdatePolicy": {
        "policyEngineId": "engine-under-test",
        "policyId": "policy-under-test",
        "definition": {
            "cedar": {"statement": "permit(principal, action, resource);"},
        },
    },
    "CreatePolicyEngine": {"name": "engine-under-test"},
    "DeletePolicyEngine": {"policyEngineId": "engine-under-test"},
}


def _service_model() -> dict[str, Any]:
    data_dir = Path(botocore.__file__).resolve().parent / "data"
    path = data_dir / "bedrock-agentcore-control" / "2023-06-05" / "service-2.json.gz"
    with gzip.open(path) as handle:
        return json.load(handle)


def test_required_operations_are_signed_control_plane_writes() -> None:
    """The names above are the control-plane operations, not invented strings."""
    model = _service_model()
    assert model["metadata"]["signingName"] == "bedrock-agentcore"
    shapes = model["shapes"]
    for name, parameters in CONTROL_PLANE_CHANGES.items():
        operation = model["operations"][name]
        assert operation["http"]["method"].upper() != "GET"
        members = shapes[operation["input"]["shape"]]["members"]
        missing = sorted(set(parameters) - set(members))
        assert not missing, f"{name} parameters not in the API: {missing}"


def _eventbridge_source(event_source: str) -> str:
    suffix = ".amazonaws.com"
    if not event_source.endswith(suffix):
        raise AssertionError(f"unexpected CloudTrail eventSource {event_source}")
    return "aws." + event_source[: -len(suffix)]


def test_eventbridge_source_follows_the_cloudtrail_delivery_example() -> None:
    assert _eventbridge_source("ec2.amazonaws.com") == "aws.ec2"
    assert _eventbridge_source(EVENT_SOURCE) == "aws.bedrock-agentcore"


def _management_event(
    event_name: str,
    request_parameters: dict[str, Any],
    *,
    read_only: bool = False,
    management: bool = True,
) -> dict[str, Any]:
    """CloudTrail record wrapped the way EventBridge delivers it.

    Field names and the management-event flags come from the CreateGateway
    example (readOnly false, managementEvent true, eventCategory Management,
    eventType AwsApiCall, eventSource bedrock-agentcore.amazonaws.com).
    """
    return {
        "detail-type": DETAIL_TYPE,
        "source": _eventbridge_source(EVENT_SOURCE),
        "detail": {
            "eventSource": EVENT_SOURCE,
            "eventName": event_name,
            "awsRegion": "us-east-1",
            "readOnly": read_only,
            "eventType": "AwsApiCall",
            "managementEvent": management,
            "eventCategory": "Management" if management else "Data",
            "requestParameters": request_parameters,
        },
    }


def _pattern_matches(pattern: Any, event: Any) -> bool:
    """EventBridge content filter for the pattern this stack synthesizes.

    From the comparison table at
    https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-event-patterns-content-based-filtering.html
    an object matches when every field matches (And), and a list of strings
    matches when the event value equals any entry (Or / Equals). Fields the
    pattern does not mention are ignored. aws-cdk-lib 2.277.0
    ``aws_events.EventPattern`` (installed package, class docstring) states
    the same nesting, exact, and ignore-unmentioned rules. Operator objects
    such as ``prefix`` are rejected: this rule does not use them, and
    silently treating one as a value would hide a non-match.
    """
    if isinstance(pattern, dict):
        if not isinstance(event, dict):
            return False
        return all(
            key in event and _pattern_matches(sub, event[key])
            for key, sub in pattern.items()
        )
    if isinstance(pattern, list):
        return any(_equals(item, event) for item in pattern)
    raise AssertionError(f"unsupported pattern node {pattern!r}")


def _equals(expected: Any, actual: Any) -> bool:
    if isinstance(expected, dict):
        raise TypeError(f"unsupported pattern operator {expected!r}")
    return expected == actual


def _resources(template: dict[str, Any], resource_type: str) -> list[dict[str, Any]]:
    return [
        resource
        for resource in template["Resources"].values()
        if resource["Type"] == resource_type
    ]


def _logical_ids(template: dict[str, Any], resource_type: str) -> list[str]:
    return [
        logical_id
        for logical_id, resource in template["Resources"].items()
        if resource["Type"] == resource_type
    ]


def _ref_id(value: Any) -> str | None:
    if isinstance(value, dict) and set(value) == {"Ref"}:
        return value["Ref"]
    if isinstance(value, dict) and "Fn::GetAtt" in value:
        getatt = value["Fn::GetAtt"]
        if isinstance(getatt, list) and getatt:
            return str(getatt[0])
        if isinstance(getatt, str) and "." in getatt:
            return getatt.split(".", 1)[0]
    return None


def _trail_records_write_management_events(template: dict[str, Any]) -> bool:
    """A logging trail with no restricting selector records these writes.

    AWS::CloudTrail::Trail documents that a trail created without specific
    event selectors logs all read and write management events and no data
    events. PutEventSelectors rejects an empty selector list ("Specify a
    valid number of event selectors (1 to 5)"), so the empty EventSelectors
    array aws-cdk-lib 2.277.0 writes (cloudtrail.ts passes the still-empty
    array when ``managementEvents`` is unset) does not install a filter.
    """
    trails = _resources(template, "AWS::CloudTrail::Trail")
    if len(trails) != 1:
        return False
    props = trails[0]["Properties"]
    if props.get("IsLogging") is not True:
        return False
    if props.get("AdvancedEventSelectors"):
        return False
    selectors = props.get("EventSelectors") or []
    if not selectors:
        return True
    for selector in selectors:
        if selector.get("IncludeManagementEvents") is False:
            continue
        if selector.get("ReadWriteType", "All") not in {"All", "WriteOnly"}:
            continue
        excluded = selector.get("ExcludeManagementEventSources") or []
        if EVENT_SOURCE in excluded:
            continue
        return True
    return False


def _events_may_publish(template: dict[str, Any], topic_id: str) -> bool:
    for resource in _resources(template, "AWS::SNS::TopicPolicy"):
        topics = resource["Properties"].get("Topics", [])
        if not any(_ref_id(topic) == topic_id for topic in topics):
            continue
        for statement in resource["Properties"]["PolicyDocument"]["Statement"]:
            if statement.get("Effect") != "Allow":
                continue
            action = statement.get("Action")
            actions = [action] if isinstance(action, str) else list(action or [])
            if "sns:Publish" not in actions:
                continue
            principal = statement.get("Principal", {})
            service = principal.get("Service") if isinstance(principal, dict) else None
            services = [service] if isinstance(service, str) else list(service or [])
            if "events.amazonaws.com" not in services:
                continue
            resource_arn = statement.get("Resource")
            if resource_arn == "*" or _ref_id(resource_arn) == topic_id:
                return True
    return False


def _security_alerts_receives(
    observability: dict[str, Any],
    security: dict[str, Any],
    event: dict[str, Any],
) -> bool:
    if not _trail_records_write_management_events(security):
        return False
    rules = _resources(observability, "AWS::Events::Rule")
    if len(rules) != 1:
        return False
    props = rules[0]["Properties"]
    state = props.get("State", "ENABLED")
    if state not in WRITE_RULE_STATES:
        return False
    detail = event["detail"]
    # ENABLED does not deliver read-only management events. See WRITE_RULE_STATES.
    if (
        state == "ENABLED"
        and detail.get("managementEvent") is True
        and detail.get("readOnly") is True
    ):
        return False
    if not detail.get("managementEvent") and detail.get("eventCategory") == "Data":
        # The trail above does not select data events, so EventBridge is not
        # sent this record. The pattern is still applied below only for
        # management events that the trail records.
        return False
    if props.get("EventBusName") not in (None, "default"):
        # CloudTrail events are delivered to the default bus only.
        return False
    if not _pattern_matches(props["EventPattern"], event):
        return False
    topic_ids = [
        logical_id
        for logical_id in _logical_ids(observability, "AWS::SNS::Topic")
        if observability["Resources"][logical_id]["Properties"].get("DisplayName")
        == "AgentCore security alerts"
    ]
    if len(topic_ids) != 1:
        return False
    topic_id = topic_ids[0]
    targets = props.get("Targets") or []
    if not any(_ref_id(target.get("Arn")) == topic_id for target in targets):
        return False
    return _events_may_publish(observability, topic_id)


def _preset_flags(preset_name: str) -> dict[str, Any]:
    """Same precedence as ``app.py`` ``cfg`` with no context and no env override.

    ``cfg`` is context, then ``os.environ``, then ``to_env(platform.yaml)``,
    then the legacy default. Traceability's legacy default is ``"false"``.
    """
    path = REPO / "presets" / preset_name
    raw = yaml.safe_load(path.read_text())
    assert raw["security"]["traceability"] is True
    assert raw["security"]["cloudtrail_alerting"] is True
    config = load_platform_config(path)
    yaml_env = to_env(config)
    context = ""
    environ = ""
    enable_traceability = (
        context or environ or yaml_env.get("ENABLE_TRACEABILITY", "") or "false"
    ) == "true"
    enable_security = (
        context or environ or yaml_env.get("ENABLE_SECURITY", "") or "false"
    ) == "true"
    return {
        "project": config.project,
        "environment": config.environment,
        "enable_traceability": enable_traceability,
        "enable_security": enable_security,
        "enable_transaction_search": (
            yaml_env.get("ENABLE_TRANSACTION_SEARCH", "true") == "true"
        ),
        "enable_alarms": yaml_env.get("ENABLE_ALARMS", "false") == "true",
        "alarm_email": yaml_env.get("ALARM_EMAIL", ""),
        "log_retention_days": int(yaml_env.get("LOG_RETENTION_DAYS", "30")),
        "retain_data": config.deployment.mode == "production",
    }


def _synth(preset_name: str) -> tuple[dict[str, Any], dict[str, Any]]:
    flags = _preset_flags(preset_name)
    assert flags["enable_traceability"] is True
    assert flags["enable_security"] is True
    app = cdk.App()
    observability = ObservabilityStack(
        app,
        "Observability",
        project_name=flags["project"],
        environment=flags["environment"],
        enable_traceability=flags["enable_traceability"],
        enable_transaction_search=flags["enable_transaction_search"],
        enable_alarms=flags["enable_alarms"],
        alarm_email=flags["alarm_email"],
        log_retention_days=flags["log_retention_days"],
        retain_data=flags["retain_data"],
        env=ENV,
    )
    security_app = cdk.App()
    security = SecurityStack(
        security_app,
        "Security",
        project_name=flags["project"],
        environment=flags["environment"],
        enable_cloudtrail=True,
        retain_data=flags["retain_data"],
        env=ENV,
    )
    return (
        Template.from_stack(observability).to_json(),
        Template.from_stack(security).to_json(),
    )


@pytest.fixture(scope="module", params=PRESETS)
def deployed(
    request: pytest.FixtureRequest,
) -> tuple[str, dict[str, Any], dict[str, Any]]:
    preset = request.param
    observability, security = _synth(preset)
    return preset, observability, security


def test_create_gateway_management_event_reaches_security_alerts(
    deployed: tuple[str, dict[str, Any], dict[str, Any]],
) -> None:
    """The event name the rule already lists is delivered. Locks the harness."""
    _preset, observability, security = deployed
    event = _management_event(
        "CreateGateway",
        {"name": "gateway-under-test", "protocolType": "MCP"},
    )
    assert _security_alerts_receives(observability, security, event)


@pytest.mark.parametrize("operation", sorted(CONTROL_PLANE_CHANGES))
def test_control_plane_change_reaches_security_alerts(
    deployed: tuple[str, dict[str, Any], dict[str, Any]],
    operation: str,
) -> None:
    preset, observability, security = deployed
    event = _management_event(operation, CONTROL_PLANE_CHANGES[operation])
    assert _security_alerts_receives(observability, security, event), (
        f"{preset}: {operation} changed "
        f"{event['detail']['requestParameters']} and the security-alerts "
        "topic was not published"
    )


def test_invoke_gateway_data_event_stays_off_the_security_alerts_topic(
    deployed: tuple[str, dict[str, Any], dict[str, Any]],
) -> None:
    """Data-plane gateway calls are not management events and must stay quiet."""
    _preset, observability, security = deployed
    event = _management_event(
        "InvokeGateway",
        {"body": {"method": "tools/call"}},
        management=False,
    )
    assert not _security_alerts_receives(observability, security, event)


def test_other_service_write_stays_off_the_security_alerts_topic(
    deployed: tuple[str, dict[str, Any], dict[str, Any]],
) -> None:
    _preset, observability, security = deployed
    event = _management_event("CreateBucket", {"bucketName": "unrelated"})
    event = {
        **event,
        "source": _eventbridge_source("s3.amazonaws.com"),
        "detail": {**event["detail"], "eventSource": "s3.amazonaws.com"},
    }
    assert not _security_alerts_receives(observability, security, event)
