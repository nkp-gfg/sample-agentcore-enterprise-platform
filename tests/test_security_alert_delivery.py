"""Security-alert delivery for sensitive AgentCore control-plane calls.

Production turns on ``security.traceability`` and requires
``observability.alarm_email``. The observability stack publishes the matched
CloudTrail events to an SNS topic. These tests require that topic to deliver
to the configured operator address, and they require synthesis to fail when
traceability is on and no address is configured.

They fail while the security topic is created without a subscription.
"""

from __future__ import annotations

import os
import subprocess
import sys
import textwrap
from pathlib import Path
from typing import Any

import aws_cdk as cdk
import pytest
import yaml

REPO = Path(__file__).resolve().parents[1]
ENV = cdk.Environment(account="111111111111", region="us-east-1")
OPERATOR = "ops@corp.internal"

# Every event name the traceability rule matches. Each one is published to the
# same topic, so each one is unsubscribed together.
SENSITIVE_OPERATIONS = [
    "CreateGateway",
    "UpdateGateway",
    "DeleteGateway",
    "DeleteMemory",
    "PutResourcePolicy",
    "DeleteResourcePolicy",
    "CreatePolicy",
    "DeletePolicy",
    "UpdatePolicyEngine",
]


def _resources(template: dict[str, Any], resource_type: str) -> dict[str, dict[str, Any]]:
    return {
        logical_id: resource
        for logical_id, resource in template["Resources"].items()
        if resource["Type"] == resource_type
    }


def _topic_logical_id(topic_arn: Any) -> str | None:
    if not isinstance(topic_arn, dict):
        return None
    if isinstance(topic_arn.get("Ref"), str):
        return topic_arn["Ref"]
    getatt = topic_arn.get("Fn::GetAtt")
    if isinstance(getatt, list) and getatt and isinstance(getatt[0], str):
        return getatt[0]
    if isinstance(getatt, str) and getatt:
        return getatt.split(".", 1)[0]
    return None


def _email_topics(template: dict[str, Any], email: str) -> set[str]:
    subscribed: set[str] = set()
    for resource in _resources(template, "AWS::SNS::Subscription").values():
        props = resource["Properties"]
        if props.get("Protocol") != "email" or props.get("Endpoint") != email:
            continue
        topic = _topic_logical_id(props.get("TopicArn"))
        if topic:
            subscribed.add(topic)
    return subscribed


def _rule_matches(props: dict[str, Any], operation: str) -> bool:
    if props.get("State") != "ENABLED":
        return False
    pattern = props.get("EventPattern") or {}
    if pattern.get("source") != ["aws.bedrock-agentcore"]:
        return False
    if pattern.get("detail-type") != ["AWS API Call via CloudTrail"]:
        return False
    names = (pattern.get("detail") or {}).get("eventName")
    return isinstance(names, list) and operation in names


def _assert_operation_reaches_operator(
    template: dict[str, Any], operation: str, email: str
) -> None:
    """The rule that matches ``operation`` must publish to a topic that
    actually subscribes the configured operator address."""
    subscribed = _email_topics(template, email)
    matching_rules = [
        (logical_id, resource["Properties"])
        for logical_id, resource in _resources(template, "AWS::Events::Rule").items()
        if _rule_matches(resource["Properties"], operation)
    ]
    assert matching_rules, (
        f"{operation} is not on an enabled CloudTrail rule for "
        "aws.bedrock-agentcore"
    )
    delivered = False
    for _logical_id, props in matching_rules:
        for target in props.get("Targets") or []:
            topic = _topic_logical_id(target.get("Arn"))
            if topic and topic in subscribed:
                delivered = True
    assert delivered, (
        f"{operation} is published to an SNS topic with no email subscription "
        f"for {email}"
    )


def _synth_stack(**kwargs: Any) -> dict[str, Any]:
    app = cdk.App()
    from stacks.observability_stack import ObservabilityStack

    stack = ObservabilityStack(
        app,
        "SecurityAlertObservability",
        project_name="agentcore-production",
        environment="prod",
        enable_transaction_search=False,
        log_retention_days=90,
        env=ENV,
        **kwargs,
    )
    return cdk.assertions.Template.from_stack(stack).to_json()


def _production_manifest(alarm_email: str) -> str:
    """Same control flags as presets/production.yaml, with sentinels replaced
    so synthesis is the real production gate rather than the placeholder bypass.
    """
    return textwrap.dedent(
        f"""\
        project: agentcore-production
        environment: prod
        region: us-east-1
        deployment:
          mode: production
          strategy: centralized
          platform_account: "111111111111"
        identity:
          idp: entra_id
          mode: brokered
          tenant_id: 3f2b1c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5d
          client_id: prod-client
          client_secret_name: agentcore/idp-client-secret
        agents:
          pattern: strands-agent
          model_id: us.anthropic.claude-sonnet-4-6
          allowed_models:
            - us.anthropic.claude-sonnet-4-6
          memory:
            event_expiry_days: 30
        gateway:
          web_search: "off"
          tools: [sample-tool]
        security:
          networking: true
          cloudtrail_alerting: true
          resource_policies: true
          egress_filter: true
          require_guardrails: true
          cedar:
            enabled: true
            mode: ENFORCE
          traceability: true
          org_id: o-abcd12345678
        observability:
          transaction_search: true
          alarms: true
          alarm_email: {alarm_email}
          log_retention_days: 90
        """
    )


def _workshop_manifest(*, traceability: bool, alarm_email: str, alarms: bool) -> str:
    email_line = f'alarm_email: "{alarm_email}"' if alarm_email else 'alarm_email: ""'
    return textwrap.dedent(
        f"""\
        project: agentcore-workshop
        environment: dev
        region: us-east-1
        deployment:
          mode: workshop
          strategy: centralized
        security:
          cloudtrail_alerting: true
          traceability: {"true" if traceability else "false"}
        observability:
          transaction_search: false
          alarms: {"true" if alarms else "false"}
          {email_line}
        """
    )


def _synth_app(manifest: str, tmp_path: Path) -> subprocess.CompletedProcess[str]:
    manifest_path = tmp_path / "platform.yaml"
    manifest_path.write_text(manifest)
    out = tmp_path / "cdk.out"
    env = os.environ.copy()
    env.update(
        {
            "PLATFORM_CONFIG": str(manifest_path),
            "CDK_DEFAULT_ACCOUNT": "111111111111",
            "CDK_DEFAULT_REGION": "us-east-1",
            "JSII_SILENCE_WARNING_UNTESTED_NODE_VERSION": "1",
        }
    )
    env.pop("PLATFORM_ALLOW_PLACEHOLDERS", None)
    # app.py builds its own App. Seed the AZ context the networking VPC lookup
    # asks for so synthesis does not call AWS.
    code = """
import os
import aws_cdk as cdk
outdir = os.environ["CDK_OUTDIR"]
_App = cdk.App
def App(*args, **kwargs):
    context = dict(kwargs.get("context") or {})
    context.setdefault(
        "availability-zones:account=111111111111:region=us-east-1",
        ["us-east-1a", "us-east-1b"],
    )
    kwargs["context"] = context
    kwargs["outdir"] = outdir
    return _App(*args, **kwargs)
cdk.App = App
import app as entry
assembly = entry.app.synth()
print(assembly.directory)
"""
    env["CDK_OUTDIR"] = str(out)
    return subprocess.run(
        [sys.executable, "-c", code],
        cwd=REPO,
        env=env | {"PYTHONPATH": str(REPO)},
        input=None,
        capture_output=True,
        text=True,
        check=False,
    )


def _observability_template(assembly_dir: Path) -> dict[str, Any]:
    templates = list(assembly_dir.glob("*.template.json"))
    assert templates, f"no templates in {assembly_dir}"
    observability = []
    for path in templates:
        document = yaml.safe_load(path.read_text())
        if not isinstance(document, dict):
            continue
        description = str(document.get("Description") or "")
        resources = document.get("Resources") or {}
        names = [
            resource.get("Properties", {}).get("TopicName", "")
            for resource in resources.values()
            if resource.get("Type") == "AWS::SNS::Topic"
        ]
        if any(str(name).endswith("-agentcore-security-alerts") for name in names):
            observability.append(document)
        elif "observability" in description.lower():
            observability.append(document)
    assert len(observability) == 1, "expected one observability template"
    return observability[0]


def _security_template(assembly_dir: Path) -> dict[str, Any]:
    for path in assembly_dir.glob("*.template.json"):
        document = yaml.safe_load(path.read_text())
        resources = (document or {}).get("Resources") or {}
        if any(resource.get("Type") == "AWS::CloudTrail::Trail" for resource in resources.values()):
            return document
    raise AssertionError("production synthesis did not include a CloudTrail trail")


@pytest.fixture(scope="module")
def production_assembly(tmp_path_factory: pytest.TempPathFactory) -> Path:
    work = tmp_path_factory.mktemp("production-alerts")
    result = _synth_app(_production_manifest(OPERATOR), work)
    assert result.returncode == 0, result.stderr[-2000:]
    directory = Path(result.stdout.strip().splitlines()[-1])
    assert directory.is_dir(), result.stdout
    return directory


@pytest.fixture(scope="module")
def production_observability(production_assembly: Path) -> dict[str, Any]:
    return _observability_template(production_assembly)


def test_production_trail_records_management_events(production_assembly: Path) -> None:
    """The alert rule only matches CloudTrail management events. The production
    security stack must actually record them, or the rule never sees the call.
    """
    template = _security_template(production_assembly)
    trails = _resources(template, "AWS::CloudTrail::Trail")
    assert len(trails) == 1
    props = next(iter(trails.values()))["Properties"]
    assert props["IsLogging"] is True
    selectors = props.get("EventSelectors") or []
    assert selectors == [] or any(
        selector.get("IncludeManagementEvents", True) and selector.get("ReadWriteType", "All") == "All"
        for selector in selectors
    )
    assert not props.get("AdvancedEventSelectors")


@pytest.mark.parametrize("operation", SENSITIVE_OPERATIONS)
def test_production_sensitive_api_notifies_operator(
    production_observability: dict[str, Any], operation: str
) -> None:
    _assert_operation_reaches_operator(production_observability, operation, OPERATOR)


def test_traceability_without_alarms_still_notifies_operator() -> None:
    """``alarm_email`` is the notification target even when the operational
    alarm topic is not created. Traceability must not depend on ``alarms``.
    """
    template = _synth_stack(
        enable_traceability=True,
        enable_alarms=False,
        alarm_email=OPERATOR,
    )
    for operation in SENSITIVE_OPERATIONS:
        _assert_operation_reaches_operator(template, operation, OPERATOR)


def test_traceability_without_notification_target_fails_synthesis() -> None:
    from stacks.observability_stack import ObservabilityStack

    app = cdk.App()
    with pytest.raises(Exception) as exc:
        ObservabilityStack(
            app,
            "TraceabilityWithoutTarget",
            project_name="agentcore-workshop",
            environment="dev",
            enable_traceability=True,
            enable_transaction_search=False,
            enable_alarms=True,
            alarm_email="",
            env=ENV,
        )
    message = str(exc.value).lower()
    assert "traceability" in message
    assert "alarm_email" in message or "notification" in message


def test_app_refuses_traceability_without_notification_target(tmp_path: Path) -> None:
    result = _synth_app(
        _workshop_manifest(traceability=True, alarm_email="", alarms=False),
        tmp_path,
    )
    assert result.returncode != 0, (
        "synthesis succeeded with traceability on and no notification target"
    )
    message = (result.stderr + result.stdout).lower()
    assert "traceability" in message
    assert "alarm_email" in message or "notification" in message
