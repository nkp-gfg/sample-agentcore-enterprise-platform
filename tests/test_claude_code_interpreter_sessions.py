"""Session lifecycle for the Claude code-interpreter tools.

A signed-in turn may run execute_code, execute_command, write_files, and
read_files, and the model is allowed to pass an empty code_int_session_id.
Those calls have to share one aws.codeinterpreter.v1 session, and that
session has to be stopped before the turn returns. A later turn has to
stop the earlier session before it starts another.

These tests fail while each empty id starts a session and nothing stops it.
"""

import asyncio
import importlib
import json
import os
import sys
import types
from datetime import datetime, timezone
from pathlib import Path

import boto3
import mcp.types as mcp_types
import pytest
from botocore.exceptions import ClientError

REPO = Path(__file__).resolve().parents[1]
AGENT_CODE = REPO / "agent-code"
PATTERNS = ("claude-sdk-agent", "claude-sdk-multi-agent")

BURST = (
    (
        "execute_code",
        {"code": "print(1)", "language": "python", "code_int_session_id": ""},
    ),
    (
        "execute_command",
        {"command": "echo one", "code_int_session_id": ""},
    ),
    (
        "write_files",
        {
            "files_to_create": [{"path": "a.txt", "text": "a"}],
            "code_int_session_id": "",
        },
    ),
    (
        "read_files",
        {"paths": ["a.txt"], "code_int_session_id": ""},
    ),
    (
        "execute_code",
        {"code": "print(2)", "language": "python", "code_int_session_id": ""},
    ),
)

_ORIGINAL_BOTO_CLIENT = boto3.client
_INSTALLED = []


class _Status:
    def __init__(self, status_code):
        self.status_code = status_code


class InterpreterTransport:
    """Real bedrock-agentcore client, stopped before the HTTP call.

    Parameter building still runs, including the idempotency token botocore
    adds to StartCodeInterpreterSession. The handler returns the documented
    response fields the agent reads (sessionId, stream).
    """

    def __init__(self):
        self.calls = []
        self.fail_invokes = False
        self._next_session = 0

    def install(self):
        transport = self

        def client(service_name, *args, **kwargs):
            if service_name != "bedrock-agentcore":
                return _ORIGINAL_BOTO_CLIENT(service_name, *args, **kwargs)
            region = kwargs.get("region_name") or "us-east-1"
            created = _ORIGINAL_BOTO_CLIENT(
                "bedrock-agentcore", region_name=region
            )
            created.meta.events.register(
                "before-call.bedrock-agentcore", transport._before_call
            )
            return created

        boto3.client = client
        _INSTALLED.append(self)

    def _before_call(self, model, params, **kwargs):
        body = params.get("body") or b""
        if isinstance(body, bytes):
            parsed_body = json.loads(body.decode()) if body else {}
        else:
            parsed_body = body
        entry = {
            "operation": model.name,
            "url": params.get("url") or "",
            "body": parsed_body,
            "headers": dict(params.get("headers") or {}),
            "query": dict(params.get("query_string") or {}),
        }
        self.calls.append(entry)
        if entry["operation"] == "StartCodeInterpreterSession":
            self._next_session += 1
            session_id = f"ci-session-{self._next_session:04d}"
            entry["sessionId"] = session_id
            return _Status(200), {
                "codeInterpreterIdentifier": "aws.codeinterpreter.v1",
                "sessionId": session_id,
                "createdAt": datetime.now(timezone.utc),
            }
        if entry["operation"] == "InvokeCodeInterpreter":
            if self.fail_invokes:
                return _Status(409), {
                    "Error": {
                        "Code": "ConflictException",
                        "Message": "interpreter invoke failed",
                    }
                }
            return _Status(200), {
                "stream": [{"result": {"stdout": "ok"}}],
            }
        if entry["operation"] == "StopCodeInterpreterSession":
            return _Status(200), {
                "codeInterpreterIdentifier": "aws.codeinterpreter.v1",
                "sessionId": entry["query"].get("sessionId", ""),
                "lastUpdatedAt": datetime.now(timezone.utc),
            }
        raise AssertionError(f"unexpected operation {entry['operation']}")


def _request_blob(call):
    return json.dumps(
        {
            "url": call["url"],
            "body": call["body"],
            "headers": call["headers"],
            "query": call["query"],
        },
        default=str,
    )


def _started(calls):
    return [
        call["sessionId"]
        for call in calls
        if call["operation"] == "StartCodeInterpreterSession"
    ]


def _stopped(calls, known_ids):
    stopped = []
    for call in calls:
        if call["operation"] != "StopCodeInterpreterSession":
            continue
        blob = _request_blob(call)
        matches = [session_id for session_id in known_ids if session_id in blob]
        assert matches, f"stop did not name a session this turn started: {blob}"
        assert len(matches) == 1, blob
        stopped.append(matches[0])
    return stopped


def _live(calls):
    known = _started(calls)
    live = list(known)
    for session_id in _stopped(calls, known):
        live.remove(session_id)
    return live


def _install_runtime_stub():
    runtime = types.ModuleType("bedrock_agentcore.runtime")

    class RequestContext:
        def __init__(self, request_headers=None, session_id=None, request=None):
            self.request_headers = request_headers
            self.session_id = session_id
            self.request = request

    class BedrockAgentCoreApp:
        def entrypoint(self, func):
            # bedrock_agentcore.runtime.app.BedrockAgentCoreApp.entrypoint
            # stores the function and returns it unchanged.
            self.handlers = {"main": func}
            return func

        def run(self, *args, **kwargs):
            raise RuntimeError("the test drives the entrypoint directly")

    runtime.RequestContext = RequestContext
    runtime.BedrockAgentCoreApp = BedrockAgentCoreApp

    identity_auth = types.ModuleType("bedrock_agentcore.identity.auth")

    def requires_access_token(*args, **kwargs):
        def decorator(func):
            return func

        return decorator

    identity_auth.requires_access_token = requires_access_token
    identity = types.ModuleType("bedrock_agentcore.identity")
    identity.auth = identity_auth
    package = types.ModuleType("bedrock_agentcore")
    package.runtime = runtime
    package.identity = identity
    sys.modules["bedrock_agentcore"] = package
    sys.modules["bedrock_agentcore.runtime"] = runtime
    sys.modules["bedrock_agentcore.identity"] = identity
    sys.modules["bedrock_agentcore.identity.auth"] = identity_auth


def _load_pattern(pattern, transport):
    agent_dir = AGENT_CODE / pattern
    for name in list(sys.modules):
        if name == "agent" or name == "code_int_mcp" or name.startswith("code_int_mcp."):
            del sys.modules[name]
        if pattern == "claude-sdk-multi-agent" and (
            name == "agents" or name.startswith("agents.")
        ):
            del sys.modules[name]
    sys.path.insert(0, str(AGENT_CODE))
    sys.path.insert(0, str(agent_dir))
    transport.install()
    agent_mod = importlib.import_module("agent")
    server_mod = importlib.import_module("code_int_mcp.server")
    return agent_mod, server_mod


async def _call_tool(server, name, arguments):
    # mcp.server.lowlevel.server.Server.call_tool validates the arguments,
    # then calls the SDK handler, which awaits the tool with that same dict.
    instance = server["instance"]
    handler = instance.request_handlers[mcp_types.CallToolRequest]
    request = mcp_types.CallToolRequest(
        params=mcp_types.CallToolRequestParams(name=name, arguments=arguments)
    )
    result = await handler(request)
    inner = result.root
    if getattr(inner, "isError", False):
        text = ""
        content = getattr(inner, "content", None) or []
        if content:
            text = getattr(content[0], "text", "")
        raise AssertionError(f"{name} was rejected before it ran: {text}")
    return result


def _assert_one_session(calls, tool_count):
    starts = [
        call
        for call in calls
        if call["operation"] == "StartCodeInterpreterSession"
    ]
    invokes = [
        call for call in calls if call["operation"] == "InvokeCodeInterpreter"
    ]
    assert len(starts) == 1, (
        "one turn started "
        f"{len(starts)} code-interpreter sessions: "
        + ", ".join(call["url"] for call in starts)
    )
    start = starts[0]
    assert "/code-interpreters/aws.codeinterpreter.v1/sessions/start" in start["url"]
    session_id = start["sessionId"]
    assert len(invokes) == tool_count, (
        f"{tool_count} tool calls produced {len(invokes)} interpreter invokes"
    )
    for invoke in invokes:
        assert session_id in _request_blob(invoke), (
            f"invoke used a session other than the one this turn started: "
            f"{_request_blob(invoke)}"
        )
        assert "aws.codeinterpreter.v1" in invoke["url"]
    assert _live(calls) == [], (
        "the session was still running when the turn returned: "
        f"{_live(calls)}"
    )
    stops = [
        call
        for call in calls
        if call["operation"] == "StopCodeInterpreterSession"
    ]
    assert len(stops) >= 1
    assert any(session_id in _request_blob(call) for call in stops), (
        f"stop did not target the session this turn started ({session_id})"
    )
    assert all(
        "/code-interpreters/aws.codeinterpreter.v1/sessions/stop" in call["url"]
        for call in stops
    )


async def _run_turn(agent_mod, server_mod, prompt, runtime_session_id, tool_calls):
    seen = {}
    snapshots = []

    class ModelTurn:
        def __init__(self, options):
            seen["options"] = options

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

        async def query(self, user_prompt):
            seen["prompt"] = user_prompt

        async def receive_response(self):
            options = seen["options"]
            assert options.mcp_servers["codeint"] is server_mod.code_int_mcp_server
            for tool_name in (
                "mcp__codeint__execute_code",
                "mcp__codeint__execute_command",
                "mcp__codeint__write_files",
                "mcp__codeint__read_files",
            ):
                assert tool_name in options.allowed_tools
            assert "code_int_session_id" in options.system_prompt
            server = options.mcp_servers["codeint"]
            for name, arguments in tool_calls:
                await _call_tool(server, name, arguments)
                snapshots.append(_live(transport_for(agent_mod).calls))
            if False:
                yield None

    agent_mod.ClaudeSDKClient = ModelTurn
    agent_mod.extract_user_id_from_context = lambda context: "user-1"
    payload = {
        "prompt": prompt,
        "runtimeSessionId": runtime_session_id,
        "code_int_session_id": "",
    }
    context = types.SimpleNamespace(
        request_headers={"Authorization": "Bearer signed-in-user"}
    )
    async for _event in agent_mod.main(payload, context):
        pass
    assert seen["prompt"] == prompt
    return snapshots


def transport_for(agent_mod):
    return agent_mod._test_transport


@pytest.fixture(params=PATTERNS)
def pattern(request):
    os.environ["AWS_EC2_METADATA_DISABLED"] = "true"
    os.environ.pop("PROJECT_NAME", None)
    os.environ.pop("ENVIRONMENT", None)
    os.environ.pop("GATEWAY_URL", None)
    saved_path = list(sys.path)
    _install_runtime_stub()
    transport = InterpreterTransport()
    agent_mod, server_mod = _load_pattern(request.param, transport)
    agent_mod._test_transport = transport
    yield request.param, agent_mod, server_mod, transport
    boto3.client = _ORIGINAL_BOTO_CLIENT
    sys.path[:] = saved_path


def test_one_turn_with_empty_session_ids_uses_one_session_and_stops_it(pattern):
    name, agent_mod, server_mod, transport = pattern
    prompt = (
        "Run code many times, each time in a fresh interpreter, "
        "and pass an empty code_int_session_id on every call."
    )

    snapshots = asyncio.run(
        _run_turn(agent_mod, server_mod, prompt, f"{name}-turn-1", BURST)
    )

    assert snapshots, "the turn never called the interpreter tools"
    assert all(len(live) <= 1 for live in snapshots), (
        f"{name} held more than one interpreter session during the turn: "
        f"{snapshots}"
    )
    _assert_one_session(transport.calls, len(BURST))


def test_failed_invokes_do_not_start_another_session(pattern):
    name, agent_mod, server_mod, transport = pattern
    transport.fail_invokes = True
    calls = (
        (
            "execute_code",
            {"code": "print(1)", "language": "python", "code_int_session_id": ""},
        ),
        (
            "execute_command",
            {"command": "echo again", "code_int_session_id": ""},
        ),
        (
            "execute_code",
            {"code": "print(2)", "language": "python", "code_int_session_id": ""},
        ),
    )
    prompt = "Run each of these in a new interpreter with an empty session id."

    snapshots = asyncio.run(
        _run_turn(agent_mod, server_mod, prompt, f"{name}-failures", calls)
    )

    assert all(len(live) <= 1 for live in snapshots), snapshots
    # The invoke raises ClientError inside the client. That must not leak
    # the session that was already started, and it must not start another.
    assert any(
        call["operation"] == "InvokeCodeInterpreter" for call in transport.calls
    )
    _assert_one_session(transport.calls, len(calls))


def test_next_turn_does_not_leave_the_previous_session_running(pattern):
    name, agent_mod, server_mod, transport = pattern
    prompt = "Execute this in a fresh interpreter with an empty code_int_session_id."
    one_call = (
        (
            "execute_code",
            {"code": "print(1)", "language": "python", "code_int_session_id": ""},
        ),
    )

    asyncio.run(_run_turn(agent_mod, server_mod, prompt, f"{name}-a", one_call))
    first_live = _live(transport.calls)
    assert first_live == [], (
        f"{name} left a session running after the first turn: {first_live}"
    )
    first_started = _started(transport.calls)

    asyncio.run(_run_turn(agent_mod, server_mod, prompt, f"{name}-b", one_call))
    assert _live(transport.calls) == []
    started = _started(transport.calls)
    assert len(started) == 2, started
    assert started[0] == first_started[0]
    second_turn_invokes = [
        call
        for call in transport.calls
        if call["operation"] == "InvokeCodeInterpreter"
        and started[0] not in _request_blob(call)
    ]
    assert second_turn_invokes, "the second turn did not invoke its own session"
    assert all(started[1] in _request_blob(call) for call in second_turn_invokes)
