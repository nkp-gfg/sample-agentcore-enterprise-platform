"""Platform alarm verification must require the alarms the observability stack creates.

`scripts/check_alarms.py` is what `deploy.sh verify` runs when
`observability.alarms` is on. These tests drive `check_alarms.main` through
the same DescribeAlarms pagination the script uses. The stand-in applies the
prefix and alarm-type rules from the CloudWatch service model shipped with
botocore 1.43.127 (boto3 1.43.72): `AlarmNamePrefix` returns names that start
with the prefix, and omitting `AlarmTypes` returns only metric alarms.

A listing is one DescribeAlarms sequence: the first request has no
`NextToken`, and later pages keep the same snapshot. DescribeAlarms may
return a partial page, so the stand-in pages one alarm at a time unless
`MaxRecords` is set. The check must follow `NextToken` and must decide from
that single listing. A second listing is a fresh read and must not be
treated as the set that was just validated.

The expected set is the one `stacks/observability_stack.py` creates for the
footprint `PlatformConfig.expected_stacks` selects:

- runtime `{prefix}-{runtime}-system-errors|throttles|latency-p99` on
  `AWS/Bedrock-AgentCore` (`SystemErrors`/`Throttles` Sum, `Latency` p99)
  with dimensions `Operation=InvokeAgentRuntime`, `Name={runtime}::DEFAULT`,
  and a non-empty `Resource`
- gateway alarms on the same namespace (`InvokeGateway`, `Protocol=MCP`,
  non-empty `Resource`) when the gateway stack is in the footprint
- memory `CreateEvent` and `ListEvents` system-error and throttle alarms
  when the memory stack is in the footprint
- `bedrock-invocation-throttles` and `bedrock-invocation-server-errors` on
  `AWS/Bedrock` with no dimensions
- `AlarmActions` and `OKActions` each contain
  `arn:aws:sns:{region}:{account}:{prefix}-platform-alarms`
  (CDK v2.265.0 `SnsAction` stores the topic ARN; SNS topic ARNs put the
  topic name in the resource component)

Dimension order is not significant. `OK` and `INSUFFICIENT_DATA` are healthy.
`ALARM` is not. Extra names that start with the prefix are not healthy.
Exact `Resource` values, thresholds, periods, comparison operators, and
treat-missing-data are not part of this contract.
"""

from __future__ import annotations

import copy
import os
import sys
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path

import pytest
import yaml

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "scripts"))

os.environ.setdefault("AWS_REGION", "us-east-1")
os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")
os.environ.setdefault("AWS_EC2_METADATA_DISABLED", "true")

import check_alarms

from infra_utils.platform_config import PlatformConfig, load_platform_config

ACCOUNT = "111111111111"
WORKLOAD_ACCOUNT = "222222222222"
REGION = "us-east-1"
PROJECT = "alarmcheck"
ENVIRONMENT = "dev"
PREFIX = f"{PROJECT}-{ENVIRONMENT}-"
AGENTCORE_NAMESPACE = "AWS/Bedrock-AgentCore"
BEDROCK_NAMESPACE = "AWS/Bedrock"
PAGE_SIZE = 1


@dataclass(frozen=True)
class Footprint:
    name: str
    a2a: bool = False
    generation: int = 1
    strategy: str = "centralized"
    account: str = ACCOUNT
    platform_account: str = ""
    workload_accounts: tuple[str, ...] = ()


FOOTPRINTS = [
    Footprint("centralized"),
    Footprint("a2a", a2a=True),
    Footprint("generation-2", generation=2),
    Footprint(
        "federated-platform",
        strategy="federated",
        account=ACCOUNT,
        platform_account=ACCOUNT,
        workload_accounts=(WORKLOAD_ACCOUNT,),
    ),
    Footprint(
        "federated-workload",
        strategy="federated",
        account=WORKLOAD_ACCOUNT,
        platform_account=ACCOUNT,
        workload_accounts=(WORKLOAD_ACCOUNT,),
    ),
]


def topic_arn(account: str) -> str:
    return f"arn:aws:sns:{REGION}:{account}:{PREFIX}platform-alarms"


def _dims(*pairs: tuple[str, str]) -> list[dict[str, str]]:
    # CloudWatch does not promise dimension order. Reverse the stack's
    # insertion order so a comparison that requires that order fails.
    return [{"Name": name, "Value": value} for name, value in reversed(pairs)]


def _alarm(
    name: str,
    *,
    namespace: str,
    metric: str,
    state: str,
    actions: list[str],
    dimensions: list[dict[str, str]],
    statistic: str | None = "Sum",
    extended_statistic: str | None = None,
) -> dict:
    record = {
        "AlarmName": name,
        "StateValue": state,
        "Namespace": namespace,
        "MetricName": metric,
        "AlarmActions": list(actions),
        "OKActions": list(actions),
        "Dimensions": [dict(item) for item in dimensions],
    }
    if extended_statistic:
        record["ExtendedStatistic"] = extended_statistic
    elif statistic:
        record["Statistic"] = statistic
    return record


def runtime_metric_name(config: PlatformConfig, component: str) -> str:
    rt_name = f"{config.project}_{config.environment}_{component}".replace("-", "_")
    if (
        component == "orchestrator"
        and config.agents.orchestrator_runtime_generation > 1
    ):
        rt_name = f"{rt_name}_g{config.agents.orchestrator_runtime_generation}"
    return f"{rt_name}::DEFAULT"


def monitored_keys(config: PlatformConfig, account: str) -> list[str]:
    prefix = f"{config.project}-{config.environment}-"
    suffixes = {name.removeprefix(prefix) for name in config.expected_stacks(account)}
    keys: list[str] = []
    for key in (
        "runtime-orchestrator",
        "runtime-code-agent",
        "runtime-research-agent",
        "gateway",
        "memory",
    ):
        if key in suffixes:
            keys.append(key)
    return keys


def expected_alarms(
    config: PlatformConfig,
    account: str,
    *,
    resource: str = "arn:aws:bedrock-agentcore:us-east-1:111111111111:runtime/live",
    state_for: Mapping[str, str] | None = None,
) -> list[dict]:
    """Metric alarms ObservabilityStack creates for this config and account."""
    actions = [topic_arn(account)]
    alarms: list[dict] = []

    def add(
        name: str,
        namespace: str,
        metric: str,
        dimensions: list[dict],
        *,
        p99: bool = False,
    ) -> None:
        state = "INSUFFICIENT_DATA" if state_for is None else state_for.get(name, "OK")
        alarms.append(
            _alarm(
                f"{PREFIX}{name}",
                namespace=namespace,
                metric=metric,
                state=state,
                actions=actions,
                dimensions=dimensions,
                statistic=None if p99 else "Sum",
                extended_statistic="p99" if p99 else None,
            )
        )

    for key in monitored_keys(config, account):
        if key.startswith("runtime-"):
            component = key.removeprefix("runtime-")
            dimensions = _dims(
                ("Resource", resource),
                ("Operation", "InvokeAgentRuntime"),
                ("Name", runtime_metric_name(config, component)),
            )
            add(f"{key}-system-errors", AGENTCORE_NAMESPACE, "SystemErrors", dimensions)
            add(f"{key}-throttles", AGENTCORE_NAMESPACE, "Throttles", dimensions)
            add(
                f"{key}-latency-p99",
                AGENTCORE_NAMESPACE,
                "Latency",
                dimensions,
                p99=True,
            )
        elif key == "gateway":
            dimensions = _dims(
                ("Resource", resource),
                ("Operation", "InvokeGateway"),
                ("Protocol", "MCP"),
            )
            add(
                "gateway-system-errors", AGENTCORE_NAMESPACE, "SystemErrors", dimensions
            )
            add("gateway-throttles", AGENTCORE_NAMESPACE, "Throttles", dimensions)
            add(
                "gateway-latency-p99",
                AGENTCORE_NAMESPACE,
                "Latency",
                dimensions,
                p99=True,
            )
        elif key == "memory":
            for operation in ("CreateEvent", "ListEvents"):
                dimensions = _dims(("Resource", resource), ("Operation", operation))
                slug = operation.lower()
                add(
                    f"memory-{slug}-system-errors",
                    AGENTCORE_NAMESPACE,
                    "SystemErrors",
                    dimensions,
                )
                add(
                    f"memory-{slug}-throttles",
                    AGENTCORE_NAMESPACE,
                    "Throttles",
                    dimensions,
                )

    add("bedrock-invocation-throttles", BEDROCK_NAMESPACE, "InvocationThrottles", [])
    add(
        "bedrock-invocation-server-errors",
        BEDROCK_NAMESPACE,
        "InvocationServerErrors",
        [],
    )
    return alarms


def decoy_alarm() -> dict:
    """One inert metric alarm whose name starts with the platform prefix."""
    return _alarm(
        f"{PREFIX}inert",
        namespace="AWS/CloudWatch",
        metric="CPUUtilization",
        state="OK",
        actions=[],
        dimensions=_dims(("InstanceId", "i-00000000000000000")),
        statistic="Average",
    )


def unrelated_alarm() -> dict:
    """An ALARM whose name does not start with the platform prefix."""
    return _alarm(
        f"{PROJECT}-development-unrelated",
        namespace="AWS/EC2",
        metric="CPUUtilization",
        state="ALARM",
        actions=[],
        dimensions=[],
        statistic="Average",
    )


class CloudWatch:
    """DescribeAlarms pagination stand-in built from botocore 1.43.127.

    `Paginator.paginate` forwards `AlarmNamePrefix` and `PageIterator`
    follows `NextToken` until the token is absent. The service model returns
    only metric alarms when `AlarmTypes` is omitted, and only names that
    start with `AlarmNamePrefix`.
    """

    def __init__(
        self,
        snapshots: Iterable[Iterable[dict]],
        composites: Iterable[dict] = (),
        page_size: int = PAGE_SIZE,
    ):
        self.snapshots = [list(copy.deepcopy(list(page))) for page in snapshots]
        self.composites = list(copy.deepcopy(list(composites)))
        self.page_size = page_size
        self.listings = 0
        self.requests: list[dict] = []
        self._listing_snapshot: list[dict] = []

    def get_paginator(self, operation_name: str):
        if operation_name != "describe_alarms":
            raise ValueError(operation_name)
        return _AlarmPaginator(self)

    def describe_alarms(self, **kwargs):
        if kwargs.get("NextToken"):
            start = int(kwargs["NextToken"])
            snapshot = self._listing_snapshot
        else:
            self.listings += 1
            index = min(self.listings - 1, len(self.snapshots) - 1)
            snapshot = self.snapshots[index] if self.snapshots else []
            self._listing_snapshot = snapshot
            start = 0
        self.requests.append(dict(kwargs))
        matched = _matching_metric_alarms(snapshot, kwargs)
        size = int(kwargs.get("MaxRecords") or self.page_size)
        page = matched[start : start + size]
        response: dict = {"MetricAlarms": page}
        alarm_types = kwargs.get("AlarmTypes")
        if (
            alarm_types
            and "CompositeAlarm" in alarm_types
            and not kwargs.get("NextToken")
        ):
            response["CompositeAlarms"] = [
                copy.deepcopy(alarm)
                for alarm in self.composites
                if _name_matches(alarm["AlarmName"], kwargs)
            ]
        next_start = start + size
        if next_start < len(matched):
            response["NextToken"] = str(next_start)
        return response


class _AlarmPaginator:
    def __init__(self, cloudwatch: CloudWatch):
        self._cloudwatch = cloudwatch

    def paginate(self, **kwargs):
        token = None
        while True:
            call = dict(kwargs)
            if token:
                call["NextToken"] = token
            page = self._cloudwatch.describe_alarms(**call)
            yield page
            token = page.get("NextToken")
            if not token:
                break


class Sts:
    def __init__(self, account: str):
        self.account = account

    def get_caller_identity(self) -> dict[str, str]:
        return {
            "UserId": "TESTUSER",
            "Account": self.account,
            "Arn": f"arn:aws:iam::{self.account}:user/alarm-verify",
        }


def _name_matches(name: str, kwargs: dict) -> bool:
    prefix = kwargs.get("AlarmNamePrefix")
    if prefix and not name.startswith(prefix):
        return False
    names = kwargs.get("AlarmNames")
    return names is None or name in names


def _matching_metric_alarms(snapshot: list[dict], kwargs: dict) -> list[dict]:
    alarm_types = kwargs.get("AlarmTypes")
    if alarm_types is not None and "MetricAlarm" not in alarm_types:
        return []
    return [
        copy.deepcopy(alarm)
        for alarm in snapshot
        if _name_matches(alarm["AlarmName"], kwargs)
    ]


def write_config(directory: Path, footprint: Footprint) -> PlatformConfig:
    deployment: dict = {"strategy": footprint.strategy}
    if footprint.platform_account:
        deployment["platform_account"] = footprint.platform_account
    if footprint.workload_accounts:
        deployment["workload_accounts"] = list(footprint.workload_accounts)
    document = {
        "project": PROJECT,
        "environment": ENVIRONMENT,
        "region": REGION,
        "deployment": deployment,
        "agents": {
            "a2a": footprint.a2a,
            "orchestrator_runtime_generation": footprint.generation,
        },
        "observability": {"alarms": True},
    }
    path = directory / "platform.yaml"
    path.write_text(yaml.safe_dump(document))
    return load_platform_config(path)


def prepare(
    monkeypatch: pytest.MonkeyPatch, directory: Path, footprint: Footprint
) -> PlatformConfig:
    config = write_config(directory, footprint)
    monkeypatch.setenv("PROJECT_NAME", PROJECT)
    monkeypatch.setenv("ENVIRONMENT", ENVIRONMENT)
    monkeypatch.setenv("AWS_REGION", REGION)
    monkeypatch.setenv("AWS_DEFAULT_REGION", REGION)
    monkeypatch.setenv("ENABLE_ALARMS", "true")
    monkeypatch.setenv("ENABLE_A2A", "true" if footprint.a2a else "false")
    monkeypatch.setenv("ORCHESTRATOR_RUNTIME_GENERATION", str(footprint.generation))
    monkeypatch.setenv("DEPLOYMENT_STRATEGY", footprint.strategy)
    monkeypatch.setenv("PLATFORM_CONFIG", str(directory / "platform.yaml"))
    if footprint.platform_account:
        monkeypatch.setenv("PLATFORM_ACCOUNT", footprint.platform_account)
    else:
        monkeypatch.delenv("PLATFORM_ACCOUNT", raising=False)
    return config


def install(
    monkeypatch: pytest.MonkeyPatch,
    snapshots: list[list[dict]],
    *,
    account: str,
    composites: Iterable[dict] = (),
    page_size: int = PAGE_SIZE,
) -> CloudWatch:
    cloudwatch = CloudWatch(snapshots, composites, page_size)

    def client(service: str, *_args, **kwargs):
        if service == "cloudwatch":
            if kwargs.get("region_name") not in (None, REGION):
                return CloudWatch([[]], page_size=page_size)
            return cloudwatch
        if service == "sts":
            return Sts(account)
        raise AssertionError(service)

    monkeypatch.setattr(check_alarms.boto3, "client", client)
    return cloudwatch


def invoke() -> int:
    try:
        check_alarms.main()
    except SystemExit as exc:
        if exc.code in (None, 0):
            return 0
        return exc.code if isinstance(exc.code, int) else 1
    return 0


def assert_rejected(code: int, output: str) -> None:
    assert code != 0, output
    assert "none firing" not in output


def assert_accepted(code: int, output: str) -> None:
    assert code == 0, output


def _output(capsys: pytest.CaptureFixture[str]) -> str:
    captured = capsys.readouterr()
    return captured.out + captured.err


@pytest.mark.parametrize("footprint", FOOTPRINTS, ids=lambda footprint: footprint.name)
def test_prefixed_inert_alarm_does_not_satisfy_the_platform_set(
    footprint, tmp_path, monkeypatch, capsys
):
    prepare(monkeypatch, tmp_path, footprint)
    install(
        monkeypatch,
        [[decoy_alarm(), unrelated_alarm()]],
        account=footprint.account,
    )

    assert_rejected(invoke(), _output(capsys))


@pytest.mark.parametrize("footprint", FOOTPRINTS, ids=lambda footprint: footprint.name)
def test_exact_platform_alarm_set_is_healthy(footprint, tmp_path, monkeypatch, capsys):
    config = prepare(monkeypatch, tmp_path, footprint)
    resource = f"arn:aws:bedrock-agentcore:{REGION}:{footprint.account}:runtime/{footprint.name}"
    live = expected_alarms(config, footprint.account, resource=resource)
    # Both healthy states must pass, including a quiet error metric.
    live[0]["StateValue"] = "OK"
    install(
        monkeypatch,
        [[*live, unrelated_alarm()]],
        account=footprint.account,
    )

    assert_accepted(invoke(), _output(capsys))


def test_extra_prefixed_alarm_is_rejected(tmp_path, monkeypatch, capsys):
    footprint = FOOTPRINTS[0]
    config = prepare(monkeypatch, tmp_path, footprint)
    install(
        monkeypatch,
        [[*expected_alarms(config, footprint.account), decoy_alarm()]],
        account=footprint.account,
    )

    assert_rejected(invoke(), _output(capsys))


def test_missing_platform_alarm_is_rejected_while_others_remain(
    tmp_path, monkeypatch, capsys
):
    footprint = FOOTPRINTS[0]
    config = prepare(monkeypatch, tmp_path, footprint)
    live = expected_alarms(config, footprint.account)
    removed = live.pop()
    assert removed["AlarmName"].endswith("bedrock-invocation-server-errors")
    install(monkeypatch, [live], account=footprint.account)

    assert_rejected(invoke(), _output(capsys))


def test_wrong_namespace_is_rejected(tmp_path, monkeypatch, capsys):
    def mutate(alarm: dict) -> None:
        if alarm["MetricName"] == "SystemErrors":
            alarm["Namespace"] = "AWS/EC2"

    _reject_mutated(tmp_path, monkeypatch, capsys, mutate)


def test_wrong_metric_name_is_rejected(tmp_path, monkeypatch, capsys):
    def mutate(alarm: dict) -> None:
        if alarm["MetricName"] == "SystemErrors":
            alarm["MetricName"] = "CPUUtilization"

    _reject_mutated(tmp_path, monkeypatch, capsys, mutate)


def test_sum_alarm_with_the_wrong_statistic_is_rejected(tmp_path, monkeypatch, capsys):
    def mutate(alarm: dict) -> None:
        if alarm["MetricName"] == "SystemErrors":
            alarm["Statistic"] = "Average"

    _reject_mutated(tmp_path, monkeypatch, capsys, mutate)


def test_latency_alarm_must_use_p99(tmp_path, monkeypatch, capsys):
    def mutate(alarm: dict) -> None:
        if alarm["MetricName"] == "Latency":
            alarm.pop("ExtendedStatistic", None)
            alarm["Statistic"] = "Average"

    _reject_mutated(tmp_path, monkeypatch, capsys, mutate)


def test_runtime_name_dimension_must_match_generation(tmp_path, monkeypatch, capsys):
    footprint = next(item for item in FOOTPRINTS if item.name == "generation-2")
    config = prepare(monkeypatch, tmp_path, footprint)
    live = expected_alarms(config, footprint.account)
    stale = runtime_metric_name(
        PlatformConfig.model_validate(
            {
                "project": PROJECT,
                "environment": ENVIRONMENT,
                "agents": {"orchestrator_runtime_generation": 1},
            }
        ),
        "orchestrator",
    )
    assert stale != runtime_metric_name(config, "orchestrator")
    for alarm in live:
        for dimension in alarm["Dimensions"]:
            if dimension["Name"] == "Name":
                dimension["Value"] = stale
    install(monkeypatch, [live], account=footprint.account)

    assert_rejected(invoke(), _output(capsys))


def test_gateway_protocol_dimension_must_match(tmp_path, monkeypatch, capsys):
    def mutate(alarm: dict) -> None:
        for dimension in alarm["Dimensions"]:
            if dimension["Name"] == "Protocol":
                dimension["Value"] = "HTTP"

    _reject_mutated(tmp_path, monkeypatch, capsys, mutate)


def test_empty_resource_dimension_is_rejected(tmp_path, monkeypatch, capsys):
    def mutate(alarm: dict) -> None:
        for dimension in alarm["Dimensions"]:
            if dimension["Name"] == "Resource":
                dimension["Value"] = ""

    _reject_mutated(tmp_path, monkeypatch, capsys, mutate)


def test_bedrock_alarm_rejects_extra_dimensions(tmp_path, monkeypatch, capsys):
    def mutate(alarm: dict) -> None:
        if alarm["Namespace"] == BEDROCK_NAMESPACE:
            alarm["Dimensions"] = _dims(("ModelId", "unused"))

    _reject_mutated(tmp_path, monkeypatch, capsys, mutate)


def test_alarm_action_must_target_the_platform_topic(tmp_path, monkeypatch, capsys):
    def mutate(alarm: dict) -> None:
        alarm["AlarmActions"] = [topic_arn(ACCOUNT).replace("platform-alarms", "other")]

    _reject_mutated(tmp_path, monkeypatch, capsys, mutate)


def test_ok_action_must_target_the_platform_topic(tmp_path, monkeypatch, capsys):
    def mutate(alarm: dict) -> None:
        alarm["OKActions"] = []

    _reject_mutated(tmp_path, monkeypatch, capsys, mutate)


def test_topic_in_another_account_is_rejected(tmp_path, monkeypatch, capsys):
    def mutate(alarm: dict) -> None:
        foreign = topic_arn(WORKLOAD_ACCOUNT)
        alarm["AlarmActions"] = [foreign]
        alarm["OKActions"] = [foreign]

    _reject_mutated(tmp_path, monkeypatch, capsys, mutate)


def test_firing_platform_alarm_is_rejected(tmp_path, monkeypatch, capsys):
    footprint = FOOTPRINTS[0]
    config = prepare(monkeypatch, tmp_path, footprint)
    live = expected_alarms(config, footprint.account)
    live[-1]["StateValue"] = "ALARM"
    install(monkeypatch, [live], account=footprint.account)

    assert_rejected(invoke(), _output(capsys))


def test_firing_alarm_on_a_later_page_is_rejected(tmp_path, monkeypatch, capsys):
    footprint = FOOTPRINTS[0]
    config = prepare(monkeypatch, tmp_path, footprint)
    live = expected_alarms(config, footprint.account)
    firing = live.pop(0)
    firing["StateValue"] = "ALARM"
    live.append(firing)
    install(monkeypatch, [live], account=footprint.account, page_size=1)

    assert_rejected(invoke(), _output(capsys))


def test_no_prefixed_metric_alarms_are_rejected(tmp_path, monkeypatch, capsys):
    prepare(monkeypatch, tmp_path, FOOTPRINTS[0])
    install(monkeypatch, [[unrelated_alarm()]], account=ACCOUNT)

    assert_rejected(invoke(), _output(capsys))


def test_prefixed_composite_alarm_does_not_count(tmp_path, monkeypatch, capsys):
    prepare(monkeypatch, tmp_path, FOOTPRINTS[0])
    install(
        monkeypatch,
        [[]],
        account=ACCOUNT,
        composites=[
            {
                "AlarmName": f"{PREFIX}composite",
                "StateValue": "OK",
            }
        ],
    )

    assert_rejected(invoke(), _output(capsys))


def test_second_listing_cannot_replace_the_validated_set(tmp_path, monkeypatch, capsys):
    footprint = FOOTPRINTS[0]
    config = prepare(monkeypatch, tmp_path, footprint)
    good = [*expected_alarms(config, footprint.account), unrelated_alarm()]
    cloudwatch = install(
        monkeypatch,
        [good, [decoy_alarm(), unrelated_alarm()]],
        account=footprint.account,
    )

    code = invoke()
    output = _output(capsys)
    if cloudwatch.listings == 1:
        assert_accepted(code, output)
    else:
        assert_rejected(code, output)


def _reject_mutated(tmp_path, monkeypatch, capsys, mutate) -> None:
    footprint = FOOTPRINTS[0]
    config = prepare(monkeypatch, tmp_path, footprint)
    live = expected_alarms(config, footprint.account)
    for alarm in live:
        mutate(alarm)
    install(monkeypatch, [live], account=footprint.account)
    assert_rejected(invoke(), _output(capsys))
