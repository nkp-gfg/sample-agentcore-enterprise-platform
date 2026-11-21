"""The network placement check must judge the runtimes this deployment created.

``scripts/check_network.py`` is the check ``scripts/deploy.sh`` (module C) and
``scripts/verify.py`` run to decide that agents are in the private VPC. It
lists runtime ARNs from Systems Manager and calls GetAgentRuntime on the last
path segment. These tests substitute that stored ARN with a different runtime
that is already in the deployment's subnets and is in the mode the operator
asked for. The deployment's own runtime, recorded on the CloudFormation
outputs of this deployment, is in the other mode.

The stand-in is the boto3 client pinned by ``requirements.txt`` (botocore
1.43.72). Each call runs that client's serializer and response parser. The
service data those parsers accept is the service model shipped in that
botocore:

- SSM ``GetParametersByPath`` returns ``Parameters[].Name`` and ``Value``
  unchanged (``botocore/data/ssm/2014-11-06/service-2.json.gz``).
- ``GetAgentRuntime`` sends only ``agentRuntimeId``, in the URI
  ``/runtimes/{agentRuntimeId}/`` (``botocore/data/bedrock-agentcore-control/
  2023-06-05/service-2.json.gz``). ``botocore/serialize.py`` copies a string
  onto that URI. The response ``networkConfiguration.networkMode`` is
  ``PUBLIC`` or ``VPC``.
- CloudFormation ``DescribeStacks`` returns ``Outputs[].OutputKey`` and
  ``OutputValue`` for the stack name in the request
  (``botocore/data/cloudformation/2010-05-15``).

Every Systems Manager read returns the substituted parameters, including a
later read of the same path. Re-reading Parameter Store cannot authorize the
substitute. The authoritative runtime ids and ARNs are the ``RuntimeArn`` and
``RuntimeId`` outputs on ``{project}-{environment}-runtime-{component}``.
The authoritative subnet ids are the ``PrivateSubnetIds`` output on
``{project}-{environment}-networking``.

A passing check is a failure of these tests while a substituted runtime can
still satisfy the placement claim.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from urllib.parse import unquote
from xml.sax.saxutils import escape

import boto3
import pytest
from botocore.awsrequest import AWSResponse
from botocore.parsers import create_parser

_BOTO3_CLIENT = boto3.client

REPO = Path(__file__).resolve().parents[1]
SCRIPTS = REPO / "scripts"

PROJECT = "agentcore-workshop"
ENVIRONMENT = "dev"
PREFIX = f"{PROJECT}-{ENVIRONMENT}"
REGION = "us-east-1"
ACCOUNT = "123456789012"
OTHER_REGION = "eu-west-1"
OTHER_ACCOUNT = "210987654321"

ORCHESTRATOR_ID = "orchestratorRt-abcdefghij"
CODE_AGENT_ID = "codeAgentRt-zzzzzzzzzz"
DECOY_ID = "decoyRuntime-klmnopqrst"
PUBLIC_DECOY_ID = "publicDecoy-abcdefghij"

SUBNET_A = "subnet-0aa11bb2"
SUBNET_B = "subnet-0cc33dd4"
SUBNETS = (SUBNET_A, SUBNET_B)
SECURITY_GROUP = "sg-0123456789abcdef0"

CREATED = "2026-01-01T00:00:00Z"


def runtime_arn(
    runtime_id: str, *, region: str = REGION, account: str = ACCOUNT
) -> str:
    return f"arn:aws:bedrock-agentcore:{region}:{account}:runtime/{runtime_id}"


def _xml(tag: str, children: str) -> str:
    return f"<{tag}>{children}</{tag}>"


def _output_xml(output: dict[str, str]) -> str:
    body = (
        f"<OutputKey>{escape(output['OutputKey'])}</OutputKey>"
        f"<OutputValue>{escape(output['OutputValue'])}</OutputValue>"
    )
    export_name = output.get("ExportName")
    if export_name:
        body += f"<ExportName>{escape(export_name)}</ExportName>"
    return _xml("member", body)


def _stack_xml(name: str, outputs: list[dict[str, str]]) -> str:
    rendered = "".join(_output_xml(output) for output in outputs)
    return _xml(
        "member",
        "<StackName>" + escape(name) + "</StackName>"
        "<CreationTime>" + CREATED + "</CreationTime>"
        "<StackStatus>CREATE_COMPLETE</StackStatus>"
        "<Outputs>" + rendered + "</Outputs>",
    )


class PlacementPlane:
    """Live AWS, replaced by botocore's own serializer and parser.

    Runtime network modes are keyed by the runtime id in the serialized
    GetAgentRuntime URI, which is the id in the caller's account and region.
    An ARN's account and region are not an input to that API.
    """

    def __init__(
        self,
        *,
        parameters: dict[str, str],
        stacks: dict[str, list[dict[str, str]]],
        networks: dict[str, dict],
    ) -> None:
        self.parameters = dict(parameters)
        self.stacks = dict(stacks)
        self.networks = dict(networks)
        self.runtime_ids: list[str] = []
        self.operations: list[str] = []
        self._clients: dict[str, object] = {}

    def client(self, service: str, region_name: str | None = None, **_kwargs):
        existing = self._clients.get(service)
        if existing is not None:
            return existing
        client = _BOTO3_CLIENT(service, region_name=region_name or REGION)
        service_id = client.meta.service_model.service_id.hyphenize()

        def handler(model, params, context, **kwargs):
            del context, kwargs
            self.operations.append(f"{service}.{model.name}")
            return self._dispatch(client, model, params)

        client.meta.events.register(f"before-call.{service_id}.*", handler)
        self._clients[service] = client
        return client

    def _dispatch(self, client, model, params):
        name = model.name
        if name == "GetParameter":
            return self._get_parameter(client, model, params)
        if name == "GetParametersByPath":
            return self._get_parameters_by_path(client, model, params)
        if name == "DescribeSubnets":
            return self._describe_subnets(client, model, params)
        if name == "GetAgentRuntime":
            return self._get_agent_runtime(client, model, params)
        if name == "DescribeStacks":
            return self._describe_stacks(client, model, params)
        if name == "ListStacks":
            return self._list_stacks(client, model, params)
        if name == "ListExports":
            return self._list_exports(client, model, params)
        raise AssertionError(
            f"unexpected AWS call {client.meta.service_model.service_name}.{name}"
        )

    def _parse(self, client, model, body: bytes, headers: dict | None = None):
        parser = create_parser(client.meta.service_model.metadata["protocol"])
        parsed = parser.parse(
            {"body": body, "headers": headers or {}, "status_code": 200},
            model.output_shape,
        )
        return AWSResponse(None, 200, {}, None), parsed

    def _error(self, status: int, code: str, message: str):
        return AWSResponse(None, status, {}, None), {
            "Error": {"Code": code, "Message": message},
            "ResponseMetadata": {"HTTPStatusCode": status},
        }

    def _json_body(self, params) -> dict:
        body = params.get("body") or b"{}"
        if isinstance(body, bytes):
            return json.loads(body.decode() or "{}")
        return dict(body)

    def _get_parameter(self, client, model, params):
        name = self._json_body(params)["Name"]
        if name not in self.parameters:
            return self._error(400, "ParameterNotFound", f"Parameter {name} not found")
        body = {
            "Parameter": {
                "Name": name,
                "Type": "String",
                "Value": self.parameters[name],
            }
        }
        return self._parse(client, model, json.dumps(body).encode())

    def _get_parameters_by_path(self, client, model, params):
        request = self._json_body(params)
        path = request["Path"].rstrip("/")
        matched = [
            {
                "Name": name,
                "Type": "String",
                "Value": value,
            }
            for name, value in sorted(self.parameters.items())
            if name.startswith(path + "/")
        ]
        # One page. A repeated call returns this same substituted set.
        body = {"Parameters": matched}
        return self._parse(
            client,
            model,
            json.dumps(body).encode(),
            {"content-type": "application/x-amz-json-1.1"},
        )

    def _describe_subnets(self, client, model, params):
        body = params.get("body") or {}
        subnet_ids = [
            value for key, value in sorted(body.items()) if key.startswith("SubnetId.")
        ]
        items = []
        for subnet_id in subnet_ids:
            zone_id = {SUBNET_A: "use1-az1", SUBNET_B: "use1-az2"}.get(subnet_id)
            if zone_id is None:
                return self._error(400, "InvalidSubnetID.NotFound", subnet_id)
            items.append(
                "<item>"
                f"<subnetId>{escape(subnet_id)}</subnetId>"
                f"<availabilityZoneId>{zone_id}</availabilityZoneId>"
                "</item>"
            )
        xml = (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<DescribeSubnetsResponse xmlns="http://ec2.amazonaws.com/doc/2016-11-15/">'
            f"<subnetSet>{''.join(items)}</subnetSet>"
            "</DescribeSubnetsResponse>"
        ).encode()
        return self._parse(client, model, xml)

    def _get_agent_runtime(self, client, model, params):
        segments = [unquote(part) for part in params["url_path"].split("/") if part]
        runtime_id = segments[-1]
        self.runtime_ids.append(runtime_id)
        network = self.networks.get(runtime_id)
        if network is None:
            return self._error(404, "ResourceNotFoundException", runtime_id)
        body = {
            "agentRuntimeArn": runtime_arn(runtime_id),
            "agentRuntimeName": "placedRuntime",
            "agentRuntimeId": runtime_id,
            "agentRuntimeVersion": "1",
            "createdAt": CREATED,
            "lastUpdatedAt": CREATED,
            "roleArn": f"arn:aws:iam::{ACCOUNT}:role/placement",
            "status": "READY",
            "lifecycleConfiguration": {},
            "networkConfiguration": network,
        }
        return self._parse(client, model, json.dumps(body).encode())

    def _selected_stacks(self, params) -> list[str]:
        body = params.get("body") or {}
        requested = body.get("StackName")
        if not requested:
            return list(self.stacks)
        if requested not in self.stacks:
            return []
        return [requested]

    def _describe_stacks(self, client, model, params):
        names = self._selected_stacks(params)
        if params.get("body", {}).get("StackName") and not names:
            requested = params["body"]["StackName"]
            return self._error(
                400,
                "ValidationError",
                f"Stack with id {requested} does not exist",
            )
        members = "".join(_stack_xml(name, self.stacks[name]) for name in names)
        xml = (
            '<?xml version="1.0"?>'
            '<DescribeStacksResponse xmlns="http://cloudformation.amazonaws.com/doc/2010-05-15/">'
            "<DescribeStacksResult><Stacks>"
            + members
            + "</Stacks></DescribeStacksResult>"
            "</DescribeStacksResponse>"
        ).encode()
        return self._parse(client, model, xml)

    def _list_stacks(self, client, model, params):
        del params
        members = []
        for name in self.stacks:
            members.append(
                "<member>"
                f"<StackName>{escape(name)}</StackName>"
                f"<CreationTime>{CREATED}</CreationTime>"
                "<StackStatus>CREATE_COMPLETE</StackStatus>"
                "</member>"
            )
        xml = (
            '<?xml version="1.0"?>'
            '<ListStacksResponse xmlns="http://cloudformation.amazonaws.com/doc/2010-05-15/">'
            "<ListStacksResult><StackSummaries>"
            + "".join(members)
            + "</StackSummaries></ListStacksResult>"
            "</ListStacksResponse>"
        ).encode()
        return self._parse(client, model, xml)

    def _list_exports(self, client, model, params):
        del params
        members = []
        for name, outputs in self.stacks.items():
            for output in outputs:
                export_name = output.get("ExportName")
                if not export_name:
                    continue
                members.append(
                    "<member>"
                    f"<ExportingStackId>{escape(name)}</ExportingStackId>"
                    f"<Name>{escape(export_name)}</Name>"
                    f"<Value>{escape(output['OutputValue'])}</Value>"
                    "</member>"
                )
        xml = (
            '<?xml version="1.0"?>'
            '<ListExportsResponse xmlns="http://cloudformation.amazonaws.com/doc/2010-05-15/">'
            "<ListExportsResult><Exports>"
            + "".join(members)
            + "</Exports></ListExportsResult>"
            "</ListExportsResponse>"
        ).encode()
        return self._parse(client, model, xml)


def _ssm_prefix() -> str:
    return f"/{PROJECT}/{ENVIRONMENT}"


def _runtime_parameter(component: str, kind: str) -> str:
    return f"{_ssm_prefix()}/runtimes/{component}/{kind}"


def _runtime_stack(component: str) -> str:
    return f"{PREFIX}-runtime-{component}"


def _runtime_export(component: str) -> str:
    return f"{PREFIX}-{component}-runtime-arn"


def _vpc_network() -> dict:
    return {
        "networkMode": "VPC",
        "networkModeConfig": {
            "securityGroups": [SECURITY_GROUP],
            "subnets": list(SUBNETS),
        },
    }


def _public_network() -> dict:
    return {"networkMode": "PUBLIC"}


def _networking_stack() -> tuple[str, list[dict[str, str]]]:
    return (
        f"{PREFIX}-networking",
        [
            {
                "OutputKey": "PrivateSubnetIds",
                "OutputValue": ",".join(SUBNETS),
            },
            {
                "OutputKey": "VpcId",
                "OutputValue": "vpc-0123456789abcdef0",
            },
            {
                "OutputKey": "RuntimeSecurityGroupId",
                "OutputValue": SECURITY_GROUP,
            },
        ],
    )


def _runtime_outputs(component: str, runtime_id: str) -> list[dict[str, str]]:
    return [
        {
            "OutputKey": "RuntimeArn",
            "OutputValue": runtime_arn(runtime_id),
            "ExportName": _runtime_export(component),
        },
        {"OutputKey": "RuntimeId", "OutputValue": runtime_id},
    ]


def _deployment_parameters(*components: str) -> dict[str, str]:
    parameters = {
        f"{_ssm_prefix()}/networking/private-subnet-ids": ",".join(SUBNETS),
    }
    for component in components:
        parameters[_runtime_parameter(component, "arn")] = runtime_arn(
            ORCHESTRATOR_ID if component == "orchestrator" else CODE_AGENT_ID
        )
        parameters[_runtime_parameter(component, "id")] = (
            ORCHESTRATOR_ID if component == "orchestrator" else CODE_AGENT_ID
        )
    return parameters


@pytest.fixture
def checker(monkeypatch):
    monkeypatch.setenv("AWS_REGION", REGION)
    monkeypatch.setenv("AWS_DEFAULT_REGION", REGION)
    monkeypatch.setenv("PROJECT_NAME", PROJECT)
    monkeypatch.setenv("ENVIRONMENT", ENVIRONMENT)
    monkeypatch.setenv("MIGRATION_PRIVATE_DEPENDENCIES", "")
    monkeypatch.setenv("AWS_EC2_METADATA_DISABLED", "true")
    sys.path.insert(0, str(SCRIPTS))
    import check_network

    monkeypatch.setattr(check_network, "REGION", REGION)
    return check_network


def _install(monkeypatch, plane: PlacementPlane) -> PlacementPlane:
    monkeypatch.setattr(boto3, "client", plane.client)
    return plane


def _run(checker, monkeypatch, argv: list[str]) -> tuple[int | None, str]:
    monkeypatch.setattr(sys, "argv", argv)
    try:
        checker.main()
    except SystemExit as exc:
        code = exc.code
        if code is None:
            code = 0
    else:
        code = 0
    return code, ""


def _output(capsys) -> str:
    captured = capsys.readouterr()
    return captured.out + captured.err


def _assert_rejected(
    checker, monkeypatch, capsys, argv: list[str], forbidden: tuple[str, ...]
) -> str:
    code, _ = _run(checker, monkeypatch, argv)
    text = _output(capsys)
    assert code not in (0, None), text
    assert "OK: network placement matches the deployment's claim" not in text
    for line in forbidden:
        assert line not in text, text
    return text


def test_substituted_runtime_arn_does_not_pass_vpc_placement(
    checker, monkeypatch, capsys
) -> None:
    """Overwrite the orchestrator ARN and id with a runtime in another account.

    The substitute is in VPC mode in this deployment's subnets. The runtime
    this deployment created is PUBLIC. Both Parameter Store reads return the
    substitute.
    """
    parameters = _deployment_parameters("orchestrator")
    parameters[_runtime_parameter("orchestrator", "arn")] = runtime_arn(
        DECOY_ID, region=OTHER_REGION, account=OTHER_ACCOUNT
    )
    parameters[_runtime_parameter("orchestrator", "id")] = DECOY_ID
    networking_name, networking_outputs = _networking_stack()
    _install(
        monkeypatch,
        PlacementPlane(
            parameters=parameters,
            stacks={
                _runtime_stack("orchestrator"): _runtime_outputs(
                    "orchestrator", ORCHESTRATOR_ID
                ),
                networking_name: networking_outputs,
            },
            networks={
                ORCHESTRATOR_ID: _public_network(),
                DECOY_ID: _vpc_network(),
            },
        ),
    )

    _assert_rejected(
        checker,
        monkeypatch,
        capsys,
        ["check_network.py"],
        ("PASS: orchestrator is in the VPC",),
    )


def test_deleted_runtime_parameter_leaves_only_a_decoy(
    checker, monkeypatch, capsys
) -> None:
    """The deployment parameter is gone. Only a decoy ARN remains under the prefix."""
    parameters = {
        f"{_ssm_prefix()}/networking/private-subnet-ids": ",".join(SUBNETS),
        f"{_ssm_prefix()}/runtimes/planted/arn": runtime_arn(
            DECOY_ID, region=OTHER_REGION, account=OTHER_ACCOUNT
        ),
    }
    networking_name, networking_outputs = _networking_stack()
    _install(
        monkeypatch,
        PlacementPlane(
            parameters=parameters,
            stacks={
                _runtime_stack("orchestrator"): _runtime_outputs(
                    "orchestrator", ORCHESTRATOR_ID
                ),
                networking_name: networking_outputs,
            },
            networks={
                ORCHESTRATOR_ID: _public_network(),
                DECOY_ID: _vpc_network(),
            },
        ),
    )

    _assert_rejected(
        checker,
        monkeypatch,
        capsys,
        ["check_network.py"],
        ("PASS: planted is in the VPC", "PASS: orchestrator is in the VPC"),
    )


def test_one_substituted_component_does_not_pass(checker, monkeypatch, capsys) -> None:
    """code-agent matches this deployment and is in the VPC. orchestrator does not."""
    parameters = _deployment_parameters("orchestrator", "code-agent")
    parameters[_runtime_parameter("orchestrator", "arn")] = runtime_arn(DECOY_ID)
    parameters[_runtime_parameter("orchestrator", "id")] = DECOY_ID
    networking_name, networking_outputs = _networking_stack()
    _install(
        monkeypatch,
        PlacementPlane(
            parameters=parameters,
            stacks={
                _runtime_stack("orchestrator"): _runtime_outputs(
                    "orchestrator", ORCHESTRATOR_ID
                ),
                _runtime_stack("code-agent"): _runtime_outputs(
                    "code-agent", CODE_AGENT_ID
                ),
                networking_name: networking_outputs,
            },
            networks={
                ORCHESTRATOR_ID: _public_network(),
                CODE_AGENT_ID: _vpc_network(),
                DECOY_ID: _vpc_network(),
            },
        ),
    )

    _assert_rejected(
        checker,
        monkeypatch,
        capsys,
        ["check_network.py"],
        ("PASS: orchestrator is in the VPC",),
    )


def test_substituted_runtime_does_not_pass_expect_public(
    checker, monkeypatch, capsys
) -> None:
    """``--expect-public`` shares the lookup. A public substitute must not pass it."""
    parameters = _deployment_parameters("orchestrator")
    parameters[_runtime_parameter("orchestrator", "arn")] = runtime_arn(
        PUBLIC_DECOY_ID, region=OTHER_REGION, account=OTHER_ACCOUNT
    )
    parameters[_runtime_parameter("orchestrator", "id")] = PUBLIC_DECOY_ID
    networking_name, networking_outputs = _networking_stack()
    _install(
        monkeypatch,
        PlacementPlane(
            parameters=parameters,
            stacks={
                _runtime_stack("orchestrator"): _runtime_outputs(
                    "orchestrator", ORCHESTRATOR_ID
                ),
                networking_name: networking_outputs,
            },
            networks={
                ORCHESTRATOR_ID: _vpc_network(),
                PUBLIC_DECOY_ID: _public_network(),
            },
        ),
    )

    _assert_rejected(
        checker,
        monkeypatch,
        capsys,
        ["check_network.py", "--expect-public"],
        ("PASS: orchestrator is PUBLIC",),
    )


def test_deployment_runtime_in_the_recorded_subnets_passes(
    checker, monkeypatch, capsys
) -> None:
    """The stored ARN is the runtime this deployment created, and that runtime is in the VPC."""
    networking_name, networking_outputs = _networking_stack()
    plane = _install(
        monkeypatch,
        PlacementPlane(
            parameters=_deployment_parameters("orchestrator"),
            stacks={
                _runtime_stack("orchestrator"): _runtime_outputs(
                    "orchestrator", ORCHESTRATOR_ID
                ),
                networking_name: networking_outputs,
            },
            networks={ORCHESTRATOR_ID: _vpc_network()},
        ),
    )

    code, _ = _run(checker, monkeypatch, ["check_network.py"])
    text = _output(capsys)
    assert code == 0, text
    assert "PASS: orchestrator is in the VPC" in text
    assert "OK: network placement matches the deployment's claim" in text
    assert plane.runtime_ids
    assert set(plane.runtime_ids) == {ORCHESTRATOR_ID}


def test_expect_public_passes_for_the_deployment_runtime(
    checker, monkeypatch, capsys
) -> None:
    networking_name, networking_outputs = _networking_stack()
    plane = _install(
        monkeypatch,
        PlacementPlane(
            parameters=_deployment_parameters("orchestrator"),
            stacks={
                _runtime_stack("orchestrator"): _runtime_outputs(
                    "orchestrator", ORCHESTRATOR_ID
                ),
                networking_name: networking_outputs,
            },
            networks={ORCHESTRATOR_ID: _public_network()},
        ),
    )

    code, _ = _run(checker, monkeypatch, ["check_network.py", "--expect-public"])
    text = _output(capsys)
    assert code == 0, text
    assert "PASS: orchestrator is PUBLIC" in text
    assert set(plane.runtime_ids) == {ORCHESTRATOR_ID}
