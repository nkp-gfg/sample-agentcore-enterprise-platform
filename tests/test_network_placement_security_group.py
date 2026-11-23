"""The VPC placement check must reject a runtime that left the published group.

`scripts/check_network.py` is the check `scripts/verify.py` and module C of
`scripts/deploy.sh` run when networking is enabled. It loads the private
subnet ids from SSM and the live runtime from GetAgentRuntime. The
networking stack also publishes `networking/runtime-security-group-id`, and
GetAgentRuntime returns that attachment as
`networkConfiguration.networkModeConfig.securityGroups` (botocore
bedrock-agentcore-control shape VpcConfig). These tests drive `main()` with
responses parsed by botocore's own response parsers. They fail while the
check ignores the security group.
"""

from __future__ import annotations

import importlib
import json
import sys
from pathlib import Path

import boto3
import botocore.session
import pytest
from botocore.exceptions import ClientError
from botocore.parsers import ResponseParserFactory

REPO = Path(__file__).resolve().parents[1]
SCRIPTS = REPO / "scripts"
PREFIX = "/agentcore-workshop/dev"
SUBNET_A = "subnet-0123456789abcdef0"
SUBNET_B = "subnet-0fedcba9876543210"
SUBNETS = f"{SUBNET_A},{SUBNET_B}"
ZONE_BY_SUBNET = {
    SUBNET_A: "use1-az1",
    SUBNET_B: "use1-az2",
}
PUBLISHED_PARAMETER = f"{PREFIX}/networking/runtime-security-group-id"

sys.path.insert(0, str(SCRIPTS))


def _parser(service: str):
    model = botocore.session.get_session().get_service_model(service)
    parser = ResponseParserFactory().create_parser(model.resolved_protocol)
    return model, parser


def _parse(service: str, operation: str, body: bytes, headers: dict | None = None):
    model, parser = _parser(service)
    parsed = parser.parse(
        {
            "body": body,
            "headers": headers or {},
            "status_code": 200,
        },
        model.operation_model(operation).output_shape,
    )
    return parsed


class _Ssm:
    """SSM reads, parsed with the json parser for service model ssm."""

    def __init__(self, parameters: dict[str, str], real_client):
        self.parameters = parameters
        self.parameter_calls: list[str] = []
        self.path_calls: list[dict] = []
        # The placement check's client factory replaces boto3.client. The
        # paginator still has to be the real botocore paginator, so it is
        # built from the client function captured before that replacement.
        real = real_client("ssm", region_name="us-east-1")
        self._paginator = real.get_paginator("get_parameters_by_path")
        self._paginator._method = self.get_parameters_by_path

    def get_parameter(self, Name: str, **kwargs):
        self.parameter_calls.append(Name)
        try:
            value = self.parameters[Name]
        except KeyError:
            raise ClientError(
                {"Error": {"Code": "ParameterNotFound", "Message": "missing"}},
                "GetParameter",
            ) from None
        return _parse(
            "ssm",
            "GetParameter",
            json.dumps(
                {"Parameter": {"Name": Name, "Type": "String", "Value": value}}
            ).encode(),
            {"content-type": "application/x-amz-json-1.1"},
        )

    def get_parameters_by_path(self, Path: str, Recursive: bool = False, **kwargs):
        self.path_calls.append({"Path": Path, "Recursive": Recursive, **kwargs})
        token = kwargs.get("NextToken")
        matched = [
            {"Name": name, "Type": "String", "Value": value}
            for name, value in sorted(self.parameters.items())
            if name.startswith(Path.rstrip("/") + "/")
        ]
        # One parameter per page so the real paginator has to follow NextToken.
        pages: list[list[dict]] = [[item] for item in matched] or [[]]
        index = 0 if not token else int(token)
        body: dict = {"Parameters": pages[index]}
        if index + 1 < len(pages):
            body["NextToken"] = str(index + 1)
        return _parse(
            "ssm",
            "GetParametersByPath",
            json.dumps(body).encode(),
            {"content-type": "application/x-amz-json-1.1"},
        )

    def get_paginator(self, operation: str):
        if operation != "get_parameters_by_path":
            raise AssertionError(operation)
        return self._paginator


class _Ec2:
    """DescribeSubnets responses parsed with the ec2 query parser."""

    def __init__(self):
        self.calls: list[list[str]] = []

    def describe_subnets(self, SubnetIds: list[str], **kwargs):
        self.calls.append(list(SubnetIds))
        items = []
        for subnet_id in SubnetIds:
            items.append(
                "<item>"
                f"<subnetId>{subnet_id}</subnetId>"
                f"<availabilityZoneId>{ZONE_BY_SUBNET[subnet_id]}</availabilityZoneId>"
                "</item>"
            )
        xml = (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<DescribeSubnetsResponse xmlns="http://ec2.amazonaws.com/doc/2016-11-15/">'
            "<requestId>req-placement</requestId>"
            f"<subnetSet>{''.join(items)}</subnetSet>"
            "</DescribeSubnetsResponse>"
        )
        return _parse("ec2", "DescribeSubnets", xml.encode())


class _Control:
    """GetAgentRuntime responses parsed with the rest-json parser."""

    def __init__(self, networks: dict[str, dict]):
        self.networks = networks
        self.calls: list[str] = []

    def get_agent_runtime(self, agentRuntimeId: str, **kwargs):
        self.calls.append(agentRuntimeId)
        network = self.networks[agentRuntimeId]
        body = {
            "agentRuntimeArn": (
                "arn:aws:bedrock-agentcore:us-east-1:123456789012:"
                f"runtime/{agentRuntimeId}"
            ),
            "agentRuntimeName": "orchestrator",
            "agentRuntimeId": agentRuntimeId,
            "agentRuntimeVersion": "1",
            "createdAt": "2026-01-01T00:00:00Z",
            "lastUpdatedAt": "2026-01-01T00:00:00Z",
            "roleArn": "arn:aws:iam::123456789012:role/runtime",
            "status": "READY",
            "lifecycleConfiguration": {},
            "networkConfiguration": network,
        }
        return _parse(
            "bedrock-agentcore-control",
            "GetAgentRuntime",
            json.dumps(body).encode(),
            {"content-type": "application/json"},
        )


def _runtime_id(component: str) -> str:
    # AgentRuntimeId allows a single hyphen before a 10-character suffix.
    compact = component.replace("-", "")
    return f"{compact}-abcDEF1234"


def _arn(component: str) -> str:
    return (
        "arn:aws:bedrock-agentcore:us-east-1:123456789012:"
        f"runtime/{_runtime_id(component)}"
    )


def _vpc_network(security_groups: list[str] | None, subnets: list[str] | None = None):
    config: dict = {"subnets": subnets or [SUBNET_B, SUBNET_A]}
    if security_groups is not None:
        config["securityGroups"] = security_groups
    return {"networkMode": "VPC", "networkModeConfig": config}


class _Placement:
    def __init__(self, check_network, ssm: _Ssm, ec2: _Ec2, control: _Control):
        self.check_network = check_network
        self.ssm = ssm
        self.ec2 = ec2
        self.control = control

    def run(self, *argv: str):
        sys.argv = ["check_network.py", *argv]
        self.check_network.main()


@pytest.fixture
def placement(monkeypatch):
    monkeypatch.setenv("AWS_REGION", "us-east-1")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
    monkeypatch.setenv("PROJECT_NAME", "agentcore-workshop")
    monkeypatch.setenv("ENVIRONMENT", "dev")
    monkeypatch.setenv("MIGRATION_PRIVATE_DEPENDENCIES", "")
    import check_network

    importlib.reload(check_network)
    assert check_network.REGION == "us-east-1"

    holder: dict[str, _Placement] = {}
    real_client = boto3.client

    def client(service: str, **kwargs):
        current = holder["current"]
        if service == "ssm":
            return current.ssm
        if service == "ec2":
            return current.ec2
        if service == "bedrock-agentcore-control":
            return current.control
        raise AssertionError(service)

    monkeypatch.setattr(boto3, "client", client)

    def build(
        networks: dict[str, dict],
        *,
        published: str | None = "sg-0123456789abcdef0",
        include_published: bool = True,
    ) -> _Placement:
        parameters = {
            f"{PREFIX}/networking/private-subnet-ids": SUBNETS,
        }
        if include_published:
            parameters[PUBLISHED_PARAMETER] = "" if published is None else published
        for component in networks:
            parameters[f"{PREFIX}/runtimes/{component}/id"] = _runtime_id(component)
            parameters[f"{PREFIX}/runtimes/{component}/arn"] = _arn(component)
        built = _Placement(
            check_network,
            _Ssm(parameters, real_client),
            _Ec2(),
            _Control(
                {
                    _runtime_id(component): network
                    for component, network in networks.items()
                }
            ),
        )
        holder["current"] = built
        return built

    return build


def _loaded_published_group(case: _Placement) -> bool:
    if PUBLISHED_PARAMETER in case.ssm.parameter_calls:
        return True
    parent, _, _leaf = PUBLISHED_PARAMETER.rpartition("/")
    for call in case.ssm.path_calls:
        path = call["Path"].rstrip("/")
        if call.get("Recursive") and PUBLISHED_PARAMETER.startswith(path + "/"):
            return True
        if not call.get("Recursive") and path == parent:
            return True
    return False


def _reject(placement_case: _Placement, capsys):
    with pytest.raises(SystemExit) as raised:
        placement_case.run()
    assert raised.value.code == 1
    captured = capsys.readouterr()
    assert "OK: network placement matches the deployment's claim" not in captured.out
    assert "no runtimes found" not in captured.err
    assert "not in the expected subnets" not in captured.err
    assert "networkMode is" not in captured.err
    assert "PASS: private subnets are in supported AZs" in captured.out
    return captured


def test_vpc_check_rejects_a_runtime_that_replaced_the_published_group(
    placement, capsys
):
    published = "sg-0123456789abcdef0"
    replacement = "sg-0fedcba9876543210"
    case = placement(
        {"orchestrator": _vpc_network([replacement])},
        published=published,
    )
    captured = _reject(case, capsys)
    assert "PASS: orchestrator is in the VPC" not in captured.out
    assert "orchestrator" in captured.err
    assert "security" in captured.err.lower()
    assert replacement in captured.err
    assert case.control.calls == [_runtime_id("orchestrator")]


def test_vpc_check_rejects_a_runtime_that_keeps_the_published_group_and_adds_another(
    placement, capsys
):
    published = "sg-aaaabbbbccccdddd1"
    extra = "sg-1111222233334444a"
    case = placement(
        {"orchestrator": _vpc_network([extra, published])},
        published=published,
    )
    captured = _reject(case, capsys)
    assert "orchestrator" in captured.err
    assert "security" in captured.err.lower()
    assert extra in captured.err


def test_vpc_check_rejects_a_runtime_whose_security_group_list_is_empty(
    placement, capsys
):
    case = placement(
        {"orchestrator": _vpc_network([])},
        published="sg-abcdef0123456789a",
    )
    captured = _reject(case, capsys)
    assert "PASS: orchestrator is in the VPC" not in captured.out
    assert "security" in captured.err.lower()


def test_vpc_check_rejects_a_runtime_response_that_omits_security_groups(
    placement, capsys
):
    case = placement(
        {"orchestrator": _vpc_network(None)},
        published="sg-0123456789abcdeff",
    )
    captured = _reject(case, capsys)
    assert "PASS: orchestrator is in the VPC" not in captured.out
    assert "security" in captured.err.lower()


def test_vpc_check_rejects_when_a_later_runtime_uses_a_different_group(
    placement, capsys
):
    published = "sg-01234567012345670"
    wider = "sg-fedcba98fedcba980"
    case = placement(
        {
            "orchestrator": _vpc_network([published]),
            "research-agent": _vpc_network([wider]),
        },
        published=published,
    )
    captured = _reject(case, capsys)
    assert "research-agent" in captured.err
    assert wider in captured.err
    assert "PASS: research-agent is in the VPC" not in captured.out
    assert case.control.calls == [
        _runtime_id("orchestrator"),
        _runtime_id("research-agent"),
    ]


def test_vpc_check_rejects_when_the_published_security_group_parameter_is_missing(
    placement, capsys
):
    case = placement(
        {"orchestrator": _vpc_network(["sg-0123456789abcdef0"])},
        include_published=False,
    )
    captured = _reject(case, capsys)
    assert "PASS: orchestrator is in the VPC" not in captured.out
    assert "runtime-security-group-id" in captured.out + captured.err


def test_vpc_check_rejects_when_the_published_security_group_parameter_is_empty(
    placement, capsys
):
    case = placement(
        {"orchestrator": _vpc_network(["sg-0123456789abcdef0"])},
        published=None,
    )
    captured = _reject(case, capsys)
    assert "PASS: orchestrator is in the VPC" not in captured.out
    assert "security" in captured.err.lower()


def test_vpc_check_accepts_a_runtime_using_only_the_published_security_group(
    placement, capsys
):
    published = "sg-00112233445566778"
    case = placement(
        {"orchestrator": _vpc_network([published])},
        published=published,
    )
    case.run()
    captured = capsys.readouterr()
    assert "PASS: orchestrator is in the VPC (2 subnets)" in captured.out
    assert "OK: network placement matches the deployment's claim" in captured.out
    assert case.ec2.calls == [[SUBNET_A, SUBNET_B]]
    assert case.control.calls == [_runtime_id("orchestrator")]
    assert case.ssm.path_calls[0]["Path"] == f"{PREFIX}/runtimes"
    assert case.ssm.path_calls[0]["Recursive"] is True
    assert _loaded_published_group(case)


def test_vpc_check_treats_the_live_security_groups_as_a_set(placement, capsys):
    published = "sg-abcdefabcdefabcde"
    case = placement(
        {"orchestrator": _vpc_network([published, published])},
        published=published,
    )
    case.run()
    captured = capsys.readouterr()
    assert "PASS: orchestrator is in the VPC (2 subnets)" in captured.out
    assert "OK: network placement matches the deployment's claim" in captured.out


def test_public_check_does_not_apply_the_vpc_security_group(placement, capsys):
    case = placement(
        {"orchestrator": {"networkMode": "PUBLIC"}},
        published="sg-0123456789abcdef0",
    )
    case.run("--expect-public")
    captured = capsys.readouterr()
    assert "PASS: orchestrator is PUBLIC" in captured.out
    assert "OK: network placement matches the deployment's claim" in captured.out
    assert case.ec2.calls == []


def test_vpc_check_still_rejects_a_runtime_missing_a_private_subnet(placement, capsys):
    published = "sg-0123456789abcdef0"
    case = placement(
        {"orchestrator": _vpc_network([published], subnets=[SUBNET_A])},
        published=published,
    )
    with pytest.raises(SystemExit) as raised:
        case.run()
    assert raised.value.code == 1
    captured = capsys.readouterr()
    assert SUBNET_B in captured.err
    assert "OK: network placement matches the deployment's claim" not in captured.out
