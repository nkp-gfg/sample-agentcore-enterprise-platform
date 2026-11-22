"""The network check must not treat the SSM subnet list as the deployment.

``scripts/check_network.py`` loads ``networking/private-subnet-ids``, describes
only those ids, and then requires each runtime to contain that list. It never
asks whether the list is the networking stack's private subnets, and it never
rejects a runtime subnet that is outside the list. A value that drops one id
therefore makes both checks succeed.

The authoritative private subnets in these tests are the ``PrivateSubnetIds``
output of ``{project}-{environment}-networking`` and the subnets in that
stack's VPC tagged ``aws-cdk:subnet-type=Private``. Both describe the same
set. Every read of the SSM parameter returns the caller's value, including a
second read, so looking the parameter up again between the zone check and the
placement check does not change the result.

The stand-in returns the parsed shapes those APIs document for botocore
1.43.72 (the minimum ``requirements.txt`` allows): SSM ``Parameter.Value`` is
the stored string, EC2 ``DescribeSubnets`` filters are ANDed, and
``GetAgentRuntime`` returns ``networkConfiguration.networkModeConfig.subnets``.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(REPO / "scripts"))

import check_network
import utils

PROJECT = "agentcore-workshop"
ENVIRONMENT = "dev"
PREFIX = f"/{PROJECT}/{ENVIRONMENT}"
STACK_NAME = f"{PROJECT}-{ENVIRONMENT}-networking"
VPC_ID = "vpc-11111111"
RUNTIME_ID = "orch-1"
RUNTIME_ARN = f"arn:aws:bedrock-agentcore:us-east-1:111122223333:runtime/{RUNTIME_ID}"

GOOD = "subnet-11111111"
OTHER_GOOD = "subnet-33333333"
UNSUPPORTED = "subnet-22222222"
PUBLIC = "subnet-44444444"
EXTRA = "subnet-55555555"

SUPPORTED_AZ = "use1-az1"
OTHER_SUPPORTED_AZ = "use1-az2"
UNSUPPORTED_AZ = "use1-az3"


def _subnet(
    subnet_id: str,
    zone_id: str,
    *,
    vpc_id: str = VPC_ID,
    subnet_type: str,
) -> dict:
    return {
        "SubnetId": subnet_id,
        "VpcId": vpc_id,
        "AvailabilityZoneId": zone_id,
        "AvailabilityZone": "us-east-1a",
        "MapPublicIpOnLaunch": subnet_type == "Public",
        "State": "available",
        "Tags": [
            {"Key": "aws-cdk:subnet-type", "Value": subnet_type},
            {"Key": "aws-cdk:subnet-name", "Value": subnet_type},
        ],
    }


class _Paginator:
    def __init__(self, parameters: list[dict]):
        self._parameters = parameters

    def paginate(self, Path: str, Recursive: bool = False):
        prefix = Path if Path.endswith("/") else f"{Path}/"
        matched = [item for item in self._parameters if item["Name"].startswith(prefix)]
        yield {"Parameters": matched}


class _Ssm:
    def __init__(self, world: Deployment):
        self._world = world

    def get_parameter(self, Name: str, **_kwargs):
        self._world.parameter_reads.append(Name)
        try:
            value = self._world.parameters[Name]
        except KeyError as exc:
            raise AssertionError(f"unexpected parameter {Name}") from exc
        return {"Parameter": {"Name": Name, "Type": "String", "Value": value}}

    def get_paginator(self, name: str):
        assert name == "get_parameters_by_path"
        listed = [
            {"Name": key, "Type": "String", "Value": value}
            for key, value in self._world.parameters.items()
        ]
        return _Paginator(listed)


class _Ec2:
    def __init__(self, world: Deployment):
        self._world = world

    def describe_subnets(self, SubnetIds=None, Filters=None, **_kwargs):
        # DescribeSubnets joins filters with AND. Multiple values of one
        # filter are OR. Tag filters use the tag:<key> name.
        subnets = list(self._world.subnets)
        if SubnetIds is not None:
            wanted = set(SubnetIds)
            subnets = [item for item in subnets if item["SubnetId"] in wanted]
            missing = wanted - {item["SubnetId"] for item in subnets}
            if missing:
                raise AssertionError(f"unknown subnet ids {sorted(missing)}")
        for filt in Filters or []:
            name = filt["Name"]
            values = set(filt.get("Values") or [])
            kept = []
            for subnet in subnets:
                tags = {tag["Key"]: tag["Value"] for tag in subnet.get("Tags", [])}
                if name == "vpc-id":
                    ok = subnet["VpcId"] in values
                elif name == "subnet-id":
                    ok = subnet["SubnetId"] in values
                elif name in ("availability-zone-id", "availabilityZoneId"):
                    ok = subnet["AvailabilityZoneId"] in values
                elif name.startswith("tag:"):
                    ok = tags.get(name[len("tag:") :]) in values
                elif name == "tag-key":
                    ok = bool(set(tags) & values)
                else:
                    raise AssertionError(f"unsupported subnet filter {name}")
                if ok:
                    kept.append(subnet)
            subnets = kept
        return {"Subnets": subnets}


class _CloudFormation:
    def __init__(self, world: Deployment):
        self._world = world

    def describe_stacks(self, StackName: str | None = None, **_kwargs):
        stack = {
            "StackName": STACK_NAME,
            "StackStatus": "CREATE_COMPLETE",
            "Outputs": [
                {"OutputKey": "VpcId", "OutputValue": VPC_ID},
                {
                    "OutputKey": "PrivateSubnetIds",
                    "OutputValue": ",".join(self._world.authoritative_private_ids),
                },
                {
                    "OutputKey": "RuntimeSecurityGroupId",
                    "OutputValue": "sg-11111111",
                },
            ],
        }
        if StackName not in (None, STACK_NAME):
            raise AssertionError(f"unexpected stack {StackName}")
        return {"Stacks": [stack]}


class _Control:
    def __init__(self, world: Deployment):
        self._world = world

    def get_agent_runtime(self, agentRuntimeId: str, **_kwargs):
        assert agentRuntimeId == RUNTIME_ID
        return {
            "agentRuntimeId": RUNTIME_ID,
            "networkConfiguration": {
                "networkMode": "VPC",
                "networkModeConfig": {
                    "subnets": list(self._world.runtime_subnet_ids),
                    "securityGroups": ["sg-11111111"],
                },
            },
        }


class Deployment:
    def __init__(
        self,
        *,
        parameter_private_ids: list[str],
        authoritative_private_ids: list[str],
        runtime_subnet_ids: list[str],
        subnets: list[dict],
    ):
        self.parameter_reads: list[str] = []
        self.authoritative_private_ids = list(authoritative_private_ids)
        self.runtime_subnet_ids = list(runtime_subnet_ids)
        self.subnets = list(subnets)
        self.parameters = {
            f"{PREFIX}/networking/private-subnet-ids": ",".join(parameter_private_ids),
            f"{PREFIX}/networking/vpc-id": VPC_ID,
            f"{PREFIX}/networking/runtime-security-group-id": "sg-11111111",
            f"{PREFIX}/runtimes/orchestrator/arn": RUNTIME_ARN,
        }

    def client(self, service: str, **_kwargs):
        if service == "ssm":
            return _Ssm(self)
        if service == "ec2":
            return _Ec2(self)
        if service == "cloudformation":
            return _CloudFormation(self)
        if service == "bedrock-agentcore-control":
            return _Control(self)
        raise AssertionError(f"unexpected AWS client {service}")


def _private(subnet_id: str, zone_id: str) -> dict:
    return _subnet(subnet_id, zone_id, subnet_type="Private")


def _install(monkeypatch: pytest.MonkeyPatch, world: Deployment) -> None:
    monkeypatch.setenv("AWS_REGION", "us-east-1")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
    monkeypatch.setenv("PROJECT_NAME", PROJECT)
    monkeypatch.setenv("ENVIRONMENT", ENVIRONMENT)
    # An empty allow-list skips the migration probe, which is a different check.
    monkeypatch.setenv("MIGRATION_PRIVATE_DEPENDENCIES", "")
    monkeypatch.setattr(check_network, "REGION", "us-east-1")
    monkeypatch.setattr(sys, "argv", ["check_network.py"])
    monkeypatch.setattr(check_network.boto3, "client", world.client)
    monkeypatch.setattr(utils.boto3, "client", world.client)


def _assert_rejected(monkeypatch: pytest.MonkeyPatch, world: Deployment) -> None:
    _install(monkeypatch, world)
    with pytest.raises(SystemExit) as caught:
        check_network.main()
    assert caught.value.code not in (0, None)


def _assert_accepted(monkeypatch: pytest.MonkeyPatch, world: Deployment) -> None:
    _install(monkeypatch, world)
    try:
        check_network.main()
    except SystemExit as exc:
        assert exc.code in (0, None)


def test_trimmed_parameter_hides_unsupported_subnet_the_runtime_does_not_use(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The attack: drop the unsupported subnet from SSM and leave the runtime
    on the remaining id. The stack output and the VPC still contain it."""
    world = Deployment(
        parameter_private_ids=[GOOD],
        authoritative_private_ids=[GOOD, UNSUPPORTED],
        runtime_subnet_ids=[GOOD],
        subnets=[
            _private(GOOD, SUPPORTED_AZ),
            _private(UNSUPPORTED, UNSUPPORTED_AZ),
            _subnet(PUBLIC, SUPPORTED_AZ, subnet_type="Public"),
        ],
    )
    _assert_rejected(monkeypatch, world)


def test_trimmed_parameter_hides_unsupported_subnet_still_attached_to_runtime(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    world = Deployment(
        parameter_private_ids=[GOOD],
        authoritative_private_ids=[GOOD, UNSUPPORTED],
        runtime_subnet_ids=[GOOD, UNSUPPORTED],
        subnets=[
            _private(GOOD, SUPPORTED_AZ),
            _private(UNSUPPORTED, UNSUPPORTED_AZ),
            _subnet(PUBLIC, SUPPORTED_AZ, subnet_type="Public"),
        ],
    )
    _assert_rejected(monkeypatch, world)


def test_parameter_that_omits_a_supported_stack_subnet_is_rejected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    world = Deployment(
        parameter_private_ids=[GOOD],
        authoritative_private_ids=[GOOD, OTHER_GOOD],
        runtime_subnet_ids=[GOOD],
        subnets=[
            _private(GOOD, SUPPORTED_AZ),
            _private(OTHER_GOOD, OTHER_SUPPORTED_AZ),
            _subnet(PUBLIC, SUPPORTED_AZ, subnet_type="Public"),
        ],
    )
    _assert_rejected(monkeypatch, world)


def test_runtime_subnet_outside_the_stack_set_is_rejected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """SSM matches the stack, but the runtime keeps another subnet. The
    placement check has to reject that subnet, not only ids missing from the
    runtime."""
    world = Deployment(
        parameter_private_ids=[GOOD],
        authoritative_private_ids=[GOOD],
        runtime_subnet_ids=[GOOD, EXTRA],
        subnets=[
            _private(GOOD, SUPPORTED_AZ),
            _subnet(
                EXTRA, UNSUPPORTED_AZ, vpc_id="vpc-99999999", subnet_type="Private"
            ),
            _subnet(PUBLIC, SUPPORTED_AZ, subnet_type="Public"),
        ],
    )
    _assert_rejected(monkeypatch, world)


def test_matching_supported_layout_is_accepted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    world = Deployment(
        parameter_private_ids=[GOOD, OTHER_GOOD],
        authoritative_private_ids=[GOOD, OTHER_GOOD],
        runtime_subnet_ids=[OTHER_GOOD, GOOD],
        subnets=[
            _private(GOOD, SUPPORTED_AZ),
            _private(OTHER_GOOD, OTHER_SUPPORTED_AZ),
            _subnet(PUBLIC, SUPPORTED_AZ, subnet_type="Public"),
        ],
    )
    _assert_accepted(monkeypatch, world)


def test_parameter_that_still_lists_the_unsupported_subnet_is_rejected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    world = Deployment(
        parameter_private_ids=[GOOD, UNSUPPORTED],
        authoritative_private_ids=[GOOD, UNSUPPORTED],
        runtime_subnet_ids=[GOOD, UNSUPPORTED],
        subnets=[
            _private(GOOD, SUPPORTED_AZ),
            _private(UNSUPPORTED, UNSUPPORTED_AZ),
            _subnet(PUBLIC, SUPPORTED_AZ, subnet_type="Public"),
        ],
    )
    _assert_rejected(monkeypatch, world)
