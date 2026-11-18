"""Runtime execution roles must not drive another workload's browser session.

The orchestrator, and the code and research agents, each get an AgentCore
runtime whose RoleArn is the role built in stacks/runtime_stack.py. That role
is what code inside the runtime calls AWS with. These tests synthesize that
role, then drive the browser client shipped in bedrock-agentcore 1.21.0
(browser_client.py) at a browser and a session this runtime did not create.

They fail while StartBrowserSession, StopBrowserSession, or
ConnectBrowserAutomationStream is authorized for that foreign browser. Control
plane browser administration (CreateBrowser, DeleteBrowser, GetBrowser,
ListBrowsers) is not granted on this role and is not part of this check.
"""

from __future__ import annotations

import gzip
import json
import re
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import Any

import aws_cdk as cdk
import boto3
import pytest
from aws_cdk.assertions import Template
from botocore.credentials import Credentials

from stacks.runtime_stack import RuntimeStack

ACCOUNT = "111111111111"
REGION = "us-east-1"
ENV = cdk.Environment(account=ACCOUNT, region=REGION)
# System browser id BrowserClient.start uses when the caller does not pass one.
# bedrock-agentcore 1.21.0 tools/browser_client.py DEFAULT_IDENTIFIER.
SYSTEM_BROWSER_ID = "aws.browser.v1"
# A custom browser this stack does not create. Two ids so a deny that names
# only the first one still leaves the second authorized.
FOREIGN_BROWSER_IDS = ("other-workload-browser", "second-workload-browser")
# BrowserSessionId pattern from botocore's bedrock-agentcore service model.
# These are not sessions this runtime started.
FOREIGN_SESSION_IDS = (
    "otherworkloadsession000000000000000",
    "secondworkloadsession00000000000000",
)
SDK_VERSION = "1.21.0"
# IAM actions for browser sessions. The three the role grants today, plus the
# other data-plane session actions in the same service model, plus the stream
# actions that are IAM permissions rather than service-model operations.
# CreateBrowser / DeleteBrowser / GetBrowser / ListBrowsers are control-plane
# administration and are intentionally not in this list.
SESSION_ACTIONS = (
    "bedrock-agentcore:StartBrowserSession",
    "bedrock-agentcore:StopBrowserSession",
    "bedrock-agentcore:GetBrowserSession",
    "bedrock-agentcore:ListBrowserSessions",
    "bedrock-agentcore:UpdateBrowserStream",
    "bedrock-agentcore:InvokeBrowser",
    "bedrock-agentcore:SaveBrowserSessionProfile",
    "bedrock-agentcore:ConnectBrowserAutomationStream",
    "bedrock-agentcore:ConnectBrowserLiveViewStream",
)

# Resource types from the service authorization reference for Amazon Bedrock
# AgentCore: browser uses account "aws"; browser-custom uses the caller account.
# ConnectBrowserAutomationStream has no resource type there, so IAM evaluates
# it against resource "*".


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _arn_match(pattern: str, value: str) -> bool:
    """IAM Resource matching: * and ? , and a trailing * may cross ':'."""

    def rec(pattern_rest: str, value_rest: str) -> bool:
        if pattern_rest == "":
            return value_rest == ""
        head, tail = pattern_rest[0], pattern_rest[1:]
        if head == "*":
            crosses_colon = tail == "" or tail[0] == ":"
            limit = len(value_rest)
            for consumed in range(limit + 1):
                if (
                    not crosses_colon
                    and consumed < limit
                    and value_rest[consumed] == ":"
                ):
                    break
                if rec(tail, value_rest[consumed:]):
                    return True
            return False
        if head == "?":
            if value_rest == "" or value_rest[0] == ":":
                return False
            return rec(tail, value_rest[1:])
        if value_rest == "" or head != value_rest[0]:
            return False
        return rec(tail, value_rest[1:])

    if "${" in pattern:
        # A policy variable can expand to the resource under test.
        return True
    return rec(pattern, value)


def _action_match(pattern: str, action: str) -> bool:
    pattern_rest = pattern.casefold()
    action_rest = action.casefold()
    if pattern_rest == "*":
        return True

    def rec(pat: str, text: str) -> bool:
        if pat == "":
            return text == ""
        head, tail = pat[0], pat[1:]
        if head == "*":
            return any(rec(tail, text[i:]) for i in range(len(text) + 1))
        if head == "?":
            return text != "" and rec(tail, text[1:])
        if text == "" or head != text[0]:
            return False
        return rec(tail, text[1:])

    return rec(pattern_rest, action_rest)


def _resource_matches(statement: dict[str, Any], resource: str) -> bool:
    if "Resource" in statement:
        patterns = _as_list(statement["Resource"])
        for pattern in patterns:
            if not isinstance(pattern, str) or _arn_match(pattern, resource):
                return True
        return False
    if "NotResource" in statement:
        patterns = _as_list(statement["NotResource"])
        for pattern in patterns:
            if not isinstance(pattern, str):
                return True
        return not any(_arn_match(pattern, resource) for pattern in patterns)
    return True


def _action_matches(statement: dict[str, Any], action: str) -> bool:
    if "Action" in statement:
        return any(
            isinstance(pattern, str) and _action_match(pattern, action)
            for pattern in _as_list(statement["Action"])
        ) or any(
            not isinstance(pattern, str) for pattern in _as_list(statement["Action"])
        )
    if "NotAction" in statement:
        patterns = _as_list(statement["NotAction"])
        if any(not isinstance(pattern, str) for pattern in patterns):
            return True
        return not any(
            _action_match(pattern, action)
            for pattern in patterns
            if isinstance(pattern, str)
        )
    return False


def _condition_holds(condition: dict[str, Any] | None, context: dict[str, str]) -> bool:
    """True when every condition operator matches. Unknown operators match,
    so an Allow we cannot prove is narrower still counts as an Allow."""
    if not condition:
        return True
    for operator, comparisons in condition.items():
        name = operator.split(":")[-1] if ":" in operator else operator
        # IfExists only changes missing-key behavior; the base name is after it.
        if_exists = name.endswith("IfExists")
        if if_exists:
            name = name[: -len("IfExists")]
        for key, expected in comparisons.items():
            expected_values = [str(item) for item in _as_list(expected)]
            present = key in context
            if not present:
                if name == "Null":
                    wants_null = expected_values == ["true"]
                    if not wants_null:
                        return False
                    continue
                if if_exists:
                    continue
                return False
            actual = context[key]
            if name == "Null":
                wants_null = expected_values == ["true"]
                if wants_null:
                    return False
                continue
            if name in ("StringEquals", "ArnEquals"):
                if actual not in expected_values:
                    return False
                continue
            if name in ("StringLike", "ArnLike"):
                if not any(_arn_match(item, actual) for item in expected_values):
                    return False
                continue
            # Unimplemented operator: do not treat it as a restriction.
            continue
    return True


def identity_allows(
    statements: list[dict[str, Any]],
    action: str,
    resource: str,
    context: dict[str, str] | None = None,
) -> bool:
    """Identity-policy evaluation: explicit deny overrides allow, else implicit deny."""
    request_context = {
        "aws:RequestedRegion": REGION,
        "aws:PrincipalAccount": ACCOUNT,
    }
    if context:
        request_context.update(context)
    allowed = False
    for statement in statements:
        if not _action_matches(statement, action):
            continue
        if not _resource_matches(statement, resource):
            continue
        if not _condition_holds(statement.get("Condition"), request_context):
            continue
        effect = str(statement.get("Effect", "Allow")).lower()
        if effect == "deny":
            return False
        if effect == "allow":
            allowed = True
    return allowed


def _service_model() -> dict[str, Any]:
    import botocore

    path = (
        Path(botocore.__file__).parent
        / "data"
        / "bedrock-agentcore"
        / "2024-02-28"
        / "service-2.json.gz"
    )
    with gzip.open(path, "rt", encoding="utf-8") as handle:
        return json.load(handle)


def _session_id_pattern() -> re.Pattern[str]:
    shapes = _service_model()["shapes"]
    return re.compile(shapes["BrowserSessionId"]["pattern"])


def browser_arn(browser_id: str, *, system: bool) -> str:
    if system:
        return f"arn:aws:bedrock-agentcore:{REGION}:aws:browser/{browser_id}"
    return f"arn:aws:bedrock-agentcore:{REGION}:{ACCOUNT}:browser-custom/{browser_id}"


def _statements_for_runtime_role(template: dict[str, Any]) -> list[dict[str, Any]]:
    runtimes = [
        resource
        for resource in template["Resources"].values()
        if resource["Type"] == "AWS::BedrockAgentCore::Runtime"
    ]
    assert len(runtimes) == 1
    role_arn = runtimes[0]["Properties"]["RoleArn"]
    logical_id, attribute = role_arn["Fn::GetAtt"]
    assert attribute == "Arn"
    role = template["Resources"][logical_id]
    assert role["Type"] == "AWS::IAM::Role"
    assert "PermissionsBoundary" not in role["Properties"]
    trust = role["Properties"]["AssumeRolePolicyDocument"]["Statement"]
    assert trust[0]["Principal"] == {"Service": "bedrock-agentcore.amazonaws.com"}

    statements: list[dict[str, Any]] = []
    for inline in role["Properties"].get("Policies", []):
        body = inline["PolicyDocument"]["Statement"]
        statements.extend(body if isinstance(body, list) else [body])
    for resource in template["Resources"].values():
        if resource["Type"] != "AWS::IAM::Policy":
            continue
        attached = resource["Properties"].get("Roles", [])
        if {"Ref": logical_id} not in attached:
            continue
        body = resource["Properties"]["PolicyDocument"]["Statement"]
        statements.extend(body if isinstance(body, list) else [body])
    assert statements, "runtime role has no identity policy"
    return statements


def _synthesize(component_name: str, runtime_type: str, **extra: Any) -> dict[str, Any]:
    app = cdk.App()
    stack = RuntimeStack(
        app,
        f"runtime-{component_name}",
        project_name="proj",
        environment="dev",
        component_name=component_name,
        source_dir="agent-code",
        runtime_type=runtime_type,
        env=ENV,
        **extra,
    )
    return Template.from_stack(stack).to_json()


RUNTIME_CASES = (
    ("orchestrator", "orchestrator", {}),
    ("code-agent", "a2a_agent", {"dockerfile_pattern": "code-agent"}),
    ("research-agent", "a2a_agent", {"dockerfile_pattern": "research-agent"}),
    (
        "orchestrator",
        "orchestrator",
        {
            "build_context": "migration/simulation/existing-ec2-agent",
            "build_dockerfile": "Dockerfile",
            "adapter_dir": "migration/adapter",
            "migration_port": "8000",
            "migration_invoke_path": "/invocations",
        },
    ),
)


@pytest.fixture(scope="module")
def runtime_policies() -> list[list[dict[str, Any]]]:
    return [
        _statements_for_runtime_role(_synthesize(name, runtime_type, **extra))
        for name, runtime_type, extra in RUNTIME_CASES
    ]


def test_wildcard_allows_and_missing_action_denies() -> None:
    """The evaluator agrees with an allow on * and with an implicit deny."""
    allow_all = [
        {
            "Effect": "Allow",
            "Action": "bedrock-agentcore:StartBrowserSession",
            "Resource": "*",
        }
    ]
    assert identity_allows(
        allow_all,
        "bedrock-agentcore:StartBrowserSession",
        browser_arn(SYSTEM_BROWSER_ID, system=True),
    )
    deny_overrides = allow_all + [
        {
            "Effect": "Deny",
            "Action": "bedrock-agentcore:StartBrowserSession",
            "Resource": "*",
        }
    ]
    assert not identity_allows(
        deny_overrides,
        "bedrock-agentcore:StartBrowserSession",
        browser_arn(SYSTEM_BROWSER_ID, system=True),
    )
    scoped = [
        {
            "Effect": "Allow",
            "Action": "bedrock-agentcore:StartBrowserSession",
            "Resource": browser_arn("some-other-browser", system=False),
        }
    ]
    assert not identity_allows(
        scoped,
        "bedrock-agentcore:StartBrowserSession",
        browser_arn(FOREIGN_BROWSER_IDS[0], system=False),
    )
    assert not identity_allows(
        [],
        "bedrock-agentcore:ConnectBrowserAutomationStream",
        "*",
    )


def test_browser_api_selects_the_browser_in_the_uri_and_the_session_in_the_query() -> (
    None
):
    """StopBrowserSession does not put the session id in the IAM resource."""
    model = _service_model()
    stop = model["operations"]["StopBrowserSession"]
    shape = model["shapes"][stop["input"]["shape"]]
    assert shape["required"] == ["browserIdentifier", "sessionId"]
    assert shape["members"]["browserIdentifier"]["location"] == "uri"
    assert shape["members"]["sessionId"]["location"] == "querystring"
    start = model["operations"]["StartBrowserSession"]
    start_shape = model["shapes"][start["input"]["shape"]]
    assert start_shape["members"]["browserIdentifier"]["location"] == "uri"
    assert "sessionId" not in start_shape["members"]
    pattern = _session_id_pattern()
    assert all(pattern.fullmatch(session_id) for session_id in FOREIGN_SESSION_IDS)


class _RecordingPlane:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, Any]]] = []

    def start_browser_session(self, **kwargs: Any) -> dict[str, str]:
        self.calls.append(("start_browser_session", kwargs))
        return {
            "browserIdentifier": kwargs["browserIdentifier"],
            "sessionId": "startedbythisclient0000000000000000",
        }

    def stop_browser_session(self, **kwargs: Any) -> dict[str, str]:
        self.calls.append(("stop_browser_session", kwargs))
        return {}


def _client_for(plane: _RecordingPlane, monkeypatch: pytest.MonkeyPatch) -> Any:
    try:
        installed = version("bedrock-agentcore")
    except PackageNotFoundError:
        installed = None
    if installed != SDK_VERSION:
        pytest.fail(
            f"bedrock-agentcore {SDK_VERSION} is required, found {installed}. "
            f"Install it with: pip install bedrock-agentcore=={SDK_VERSION}"
        )
    from bedrock_agentcore.tools.browser_client import BrowserClient

    def client(service_name: str, **_kwargs: Any) -> Any:
        if service_name == "bedrock-agentcore":
            return plane
        if service_name == "bedrock-agentcore-control":
            return object()
        raise AssertionError(service_name)

    monkeypatch.setattr(boto3, "client", client)
    placeholder = Credentials(
        "placeholder-access-key",
        "placeholder-secret-key",
        "placeholder-session-token",
    )

    class _Session:
        def get_credentials(self) -> Credentials:
            return placeholder

    monkeypatch.setattr(boto3, "Session", lambda: _Session())
    return BrowserClient(REGION)


def test_runtime_role_denies_browser_sessions_it_did_not_create(
    runtime_policies: list[list[dict[str, Any]]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A caller that did not create the session can still start, stop, and attach.

    The assertions are the secure state, so this test fails until those three
    actions are no longer authorized for a browser this stack did not create.
    """
    pattern = _session_id_pattern()
    plane = _RecordingPlane()
    client = _client_for(plane, monkeypatch)

    started: list[str] = []
    for browser_id in (SYSTEM_BROWSER_ID, *FOREIGN_BROWSER_IDS):
        started.append(client.start(identifier=browser_id))
    assert [call[1]["browserIdentifier"] for call in plane.calls] == [
        SYSTEM_BROWSER_ID,
        *FOREIGN_BROWSER_IDS,
    ]

    stopped: list[tuple[str, str]] = []
    for browser_id, session_id in (
        (SYSTEM_BROWSER_ID, FOREIGN_SESSION_IDS[0]),
        (FOREIGN_BROWSER_IDS[0], FOREIGN_SESSION_IDS[0]),
        (FOREIGN_BROWSER_IDS[1], FOREIGN_SESSION_IDS[1]),
    ):
        assert pattern.fullmatch(session_id)
        client.identifier = browser_id
        client.session_id = session_id
        client.stop()
        stopped.append((browser_id, session_id))
    stop_calls = [call for call in plane.calls if call[0] == "stop_browser_session"]
    assert [
        (call[1]["browserIdentifier"], call[1]["sessionId"]) for call in stop_calls
    ] == stopped

    attached: list[tuple[str, str, str]] = []
    for browser_id, session_id in (
        (SYSTEM_BROWSER_ID, FOREIGN_SESSION_IDS[0]),
        (FOREIGN_BROWSER_IDS[1], FOREIGN_SESSION_IDS[1]),
    ):
        client.identifier = browser_id
        client.session_id = session_id
        url, _headers = client.generate_ws_headers()
        assert url.endswith(
            f"/browser-streams/{browser_id}/sessions/{session_id}/automation"
        )
        attached.append((browser_id, session_id, url))

    violations: list[str] = []
    for statements in runtime_policies:
        for browser_id, system in (
            (SYSTEM_BROWSER_ID, True),
            (FOREIGN_BROWSER_IDS[0], False),
            (FOREIGN_BROWSER_IDS[1], False),
        ):
            resource = browser_arn(browser_id, system=system)
            for action in SESSION_ACTIONS:
                if identity_allows(statements, action, resource):
                    violations.append(f"{action} on {resource}")
        for action in (
            "bedrock-agentcore:ConnectBrowserAutomationStream",
            "bedrock-agentcore:ConnectBrowserLiveViewStream",
        ):
            # No resource type: the authorization request resource is "*".
            if identity_allows(statements, action, "*"):
                violations.append(f"{action} on *")
    assert not violations, (
        "runtime execution role authorizes browser sessions it did not create: "
        + "; ".join(violations)
    )
    # Keep the exercised calls live so a rewrite that drops them still fails.
    assert started and stopped and attached
