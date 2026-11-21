"""Audit coverage for the CloudTrail the security stack treats as the record.

The security-focused preset, the platform-team preset, and any other
non-production config with security.cloudtrail_alerting enabled deploy that
trail with workshop retention. Retention may stay disposable. Region scope
and log-file validation may not: a management event in another region has to
land in this trail, and a later edit of a delivered log file has to be
detectable.

Traceability alerting is a separate control. CloudTrail delivers an API event
to the event bus in the region where the call happened, so an EventBridge
rule in the deployment stack does not see any other region. These tests
require the sensitive AgentCore event names to be filtered on the log group
of a multi-region trail, which is the delivery path that receives every
enabled region.

They fail until that behavior is synthesized.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import textwrap
from pathlib import Path
from typing import Any

import aws_cdk as cdk
import pytest
import yaml
from aws_cdk.assertions import Template

from stacks.security_stack import SecurityStack

REPO = Path(__file__).resolve().parents[1]
ACCOUNT = "111111111111"
# Same shape the deploy script asks for when resource policies are on.
# Not an account credential.
ORG_ID = "o-abc123def456"
ENV = cdk.Environment(account=ACCOUNT, region="us-east-1")

# Event names the observability stack alerts on. Gateway writes are in this
# list. Memory creates/updates and OAuth credential-provider writes are not;
# those are covered only by the trail-scope assertions below, because a
# default trail selector records every management event. This file does not
# invent eventName strings for the credential-provider APIs.
SENSITIVE_EVENT_NAMES = (
    "CreateGateway",
    "UpdateGateway",
    "DeleteGateway",
    "DeleteMemory",
    "PutResourcePolicy",
    "DeleteResourcePolicy",
    "CreatePolicy",
    "DeletePolicy",
    "UpdatePolicyEngine",
)

SYNTH_SCRIPT = textwrap.dedent(
    """
    import json
    import importlib.util
    import aws_cdk as cdk
    from aws_cdk.assertions import Template

    spec = importlib.util.spec_from_file_location("platform_app", "app.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    synthesized = []
    for child in module.app.node.children:
        if isinstance(child, cdk.Stack):
            synthesized.append(
                {
                    "id": child.node.id,
                    "region": child.region,
                    "template": Template.from_stack(child).to_json(),
                }
            )
    print(json.dumps(synthesized))
    """
)


def resources(template: dict[str, Any], resource_type: str) -> list[dict[str, Any]]:
    return [
        resource
        for resource in template["Resources"].values()
        if resource["Type"] == resource_type
    ]


def stack_by_suffix(synthesized: list[dict[str, Any]], suffix: str) -> dict[str, Any]:
    matches = [stack for stack in synthesized if stack["id"].endswith(suffix)]
    assert len(matches) == 1, [stack["id"] for stack in synthesized]
    return matches[0]


def trail_properties(template: dict[str, Any]) -> dict[str, Any]:
    trails = resources(template, "AWS::CloudTrail::Trail")
    assert len(trails) == 1
    return trails[0]["Properties"]


def assert_management_events_not_narrowed(properties: dict[str, Any]) -> None:
    """Empty selectors are the CDK default: every management event.

    aws-cdk-lib 2.278.0 records that default in
    package/aws-cloudtrail/README.md ("By default, a Trail logs all
    management events") and passes an empty eventSelectors array unless
    managementEvents is set. CloudFormation describes the same default for
    a trail created without specific event selectors.
    """
    selectors = properties.get("EventSelectors") or []
    advanced = properties.get("AdvancedEventSelectors") or []
    if not selectors and not advanced:
        return
    if selectors:
        assert any(
            selector.get("IncludeManagementEvents", True) is True
            and selector.get("ReadWriteType", "All") in ("All", "WriteOnly")
            for selector in selectors
        )
    if advanced:
        encoded = json.dumps(advanced)
        assert "Management" in encoded


def assert_audit_trail(template: dict[str, Any], *, disposable: bool) -> None:
    properties = trail_properties(template)
    # L1 defaults are false for both properties. An omitted value is still
    # a single-region trail with validation off.
    assert properties["IsMultiRegionTrail"] is True
    assert properties["EnableLogFileValidation"] is True
    assert properties["IsLogging"] is True
    assert_management_events_not_narrowed(properties)

    bucket = resources(template, "AWS::S3::Bucket")[0]
    if disposable:
        assert bucket["DeletionPolicy"] == "Delete"
        assert bucket["UpdateReplacePolicy"] == "Delete"
        assert "VersioningConfiguration" not in bucket["Properties"]
        assert resources(template, "Custom::S3AutoDeleteObjects")
    else:
        assert bucket["DeletionPolicy"] == "Retain"
        assert not resources(template, "Custom::S3AutoDeleteObjects")


def synthesize(
    extra_env: dict[str, str], config_path: Path | None
) -> list[dict[str, Any]]:
    env = os.environ.copy()
    for name in (
        "PLATFORM_CONFIG",
        "CDK_DEFAULT_REGION",
        "CDK_DEFAULT_ACCOUNT",
        "AWS_REGION",
        "AWS_DEFAULT_REGION",
        "DEPLOYMENT_MODE",
        "ENABLE_SECURITY",
        "ENABLE_TRACEABILITY",
        "ORG_ID",
    ):
        env.pop(name, None)
    env["CDK_DEFAULT_ACCOUNT"] = ACCOUNT
    env["PLATFORM_ALLOW_PLACEHOLDERS"] = "1"
    env.update(extra_env)
    if config_path is not None:
        env["PLATFORM_CONFIG"] = str(config_path)
    completed = subprocess.run(
        [sys.executable, "-c", SYNTH_SCRIPT],
        cwd=REPO,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )
    if completed.returncode != 0:
        raise AssertionError(completed.stderr or completed.stdout)
    return json.loads(completed.stdout)


def _logical_ids(value: Any) -> set[str]:
    found: set[str] = set()
    if isinstance(value, dict):
        ref = value.get("Ref")
        if isinstance(ref, str):
            found.add(ref)
        attribute = value.get("Fn::GetAtt")
        if isinstance(attribute, list) and attribute and isinstance(attribute[0], str):
            found.add(attribute[0])
        for child in value.values():
            found.update(_logical_ids(child))
    elif isinstance(value, list):
        for child in value:
            found.update(_logical_ids(child))
    return found


def centralized_sensitive_alerts(synthesized: list[dict[str, Any]]) -> bool:
    """True when a multi-region trail's CloudWatch Logs group is filtered.

    CDK renders that link as GetAtt on the trail's CloudWatchLogsLogGroupArn
    and Ref on the metric filter's LogGroupName, both naming the log group.
    A multi-region trail writes every enabled region's events to that one
    group. An EventBridge rule does not: the event is delivered to the bus
    in the region of the API call, and a rule in this stack stays there.
    """
    for stack in synthesized:
        resources_by_type: dict[str, list[dict[str, Any]]] = {}
        for resource in stack["template"]["Resources"].values():
            resources_by_type.setdefault(resource["Type"], []).append(resource)
        for trail in resources_by_type.get("AWS::CloudTrail::Trail", []):
            properties = trail["Properties"]
            if properties.get("IsMultiRegionTrail") is not True:
                continue
            trail_group = _logical_ids(properties.get("CloudWatchLogsLogGroupArn"))
            if not trail_group:
                continue
            for filter_type in (
                "AWS::Logs::MetricFilter",
                "AWS::Logs::SubscriptionFilter",
            ):
                for log_filter in resources_by_type.get(filter_type, []):
                    filter_props = log_filter["Properties"]
                    if not trail_group & _logical_ids(filter_props.get("LogGroupName")):
                        continue
                    pattern = str(filter_props.get("FilterPattern", ""))
                    if all(
                        event_name in pattern for event_name in SENSITIVE_EVENT_NAMES
                    ):
                        return True
    return False


def test_workshop_retention_does_not_narrow_the_trail() -> None:
    app = cdk.App()
    template = Template.from_stack(
        SecurityStack(
            app,
            "WorkshopSecurity",
            project_name="agentcore-workshop",
            environment="dev",
            enable_cloudtrail=True,
            retain_data=False,
            env=ENV,
        )
    ).to_json()
    assert_audit_trail(template, disposable=True)


def test_security_focused_preset_trail_covers_every_region() -> None:
    synthesized = synthesize(
        {"ORG_ID": ORG_ID}, REPO / "presets" / "security-focused.yaml"
    )
    security = stack_by_suffix(synthesized, "-security")
    assert security["region"] == "us-east-1"
    assert_audit_trail(security["template"], disposable=True)
    mode = trail_properties(security["template"])["Tags"]
    assert {"Key": "DeploymentMode", "Value": "workshop"} in mode


def test_platform_team_preset_trail_covers_every_region() -> None:
    synthesized = synthesize({}, REPO / "presets" / "platform-team.yaml")
    security = stack_by_suffix(synthesized, "-security")
    assert security["region"] == "us-east-1"
    assert_audit_trail(security["template"], disposable=True)


def test_cloudtrail_alerting_manifest_outside_the_home_preset_region(
    tmp_path: Path,
) -> None:
    manifest = tmp_path / "platform.yaml"
    manifest.write_text(
        yaml.safe_dump(
            {
                "project": "agentcore-workshop",
                "environment": "dev",
                "region": "eu-west-1",
                "deployment": {"mode": "workshop"},
                "security": {"cloudtrail_alerting": True},
            }
        )
    )
    synthesized = synthesize({}, manifest)
    security = stack_by_suffix(synthesized, "-security")
    assert security["region"] == "eu-west-1"
    assert_audit_trail(security["template"], disposable=True)


def test_enable_security_without_production_mode_covers_every_region() -> None:
    synthesized = synthesize(
        {"ENABLE_SECURITY": "true", "CDK_DEFAULT_REGION": "us-west-2"},
        None,
    )
    security = stack_by_suffix(synthesized, "-security")
    assert security["region"] == "us-west-2"
    assert_audit_trail(security["template"], disposable=True)


def test_production_preset_keeps_retention_and_full_trail_coverage() -> None:
    synthesized = synthesize({}, REPO / "presets" / "production.yaml")
    security = stack_by_suffix(synthesized, "-security")
    assert_audit_trail(security["template"], disposable=False)


@pytest.mark.parametrize(
    ("preset", "extra_env"),
    [
        ("security-focused.yaml", {"ORG_ID": ORG_ID}),
        ("platform-team.yaml", {}),
        ("production.yaml", {}),
    ],
)
def test_traceability_alerts_cover_sensitive_calls_in_every_region(
    preset: str, extra_env: dict[str, str]
) -> None:
    synthesized = synthesize(extra_env, REPO / "presets" / preset)
    observability = stack_by_suffix(synthesized, "-observability")
    rules = resources(observability["template"], "AWS::Events::Rule")
    assert rules, preset
    pattern = rules[0]["Properties"]["EventPattern"]
    assert set(SENSITIVE_EVENT_NAMES) <= set(pattern["detail"]["eventName"])
    # The rule resource exists only in the deployment stack. Coverage of any
    # other region has to come from the multi-region trail's log group.
    assert centralized_sensitive_alerts(synthesized), (
        f"{preset}: sensitive AgentCore events are only matched in "
        f"{observability['region']}"
    )
