"""Code Interpreter sandboxes must follow the verified caller, not the model.

execute_code, execute_command, write_files, and read_files take
code_int_session_id from the model and pass it to InvokeCodeInterpreter.
These tests fail while that value selects the sandbox. They pass when the
sandbox is chosen on the server from the verified JWT subject and the
runtime session id, and a session id supplied by the model is ignored.

The stand-in for the AWS API keys files only by session id. That is the
request shape in botocore's bedrock-agentcore service model: InvokeCodeInterpreter
has no user member, and sessionId is sent as the
x-amzn-code-interpreter-session-id header. Both callers share one client,
the same way both users share the runtime role.

Fix contract, which these tests call when it exists and which agent.main
must call itself:

    code_int_mcp.server.client.bind_caller(user_id, runtime_session_id)

user_id is the subject extract_user_id_from_context returned. runtime_session_id
is payload["runtimeSessionId"]. Bind before the model invokes tools. The same
pair shares one sandbox. A different subject or a different runtime session
does not. A model-supplied code_int_session_id never selects the sandbox, even
when this process created that session for someone else.
"""

import asyncio
import importlib
import json
import os
import re
import sys
from pathlib import Path

import boto3
import pytest
from botocore.exceptions import ClientError
from claude_agent_sdk._internal.query import Query

REPO = Path(__file__).resolve().parents[1]
AGENT_CODE = REPO / "agent-code"
PATTERNS = ("claude-sdk-agent", "claude-sdk-multi-agent")

SESSION_ID = re.compile(r"[0-9a-zA-Z]{1,40}\Z")
VICTIM_MARKER = "victim-work-marker"
ATTACKER_MARKER = "attacker-sandbox-marker"
OTHER_SESSION = "otherSession0123456789abcd"


def _assert_session_id(value: str) -> str:
    assert SESSION_ID.fullmatch(value), value
    return value


class SessionKeyedInterpreter:
    """bedrock-agentcore stand-in built from the service model.

    Sandbox bytes live under the session id carried by the serialized
    x-amzn-code-interpreter-session-id header. The request has no caller
    identity, so two users of one client share a session whenever they
    present the same id.
    """

    def __init__(self):
        self._aws = boto3.client(
            "bedrock-agentcore",
            region_name="us-east-1",
            aws_access_key_id="testing",
            aws_secret_access_key="testing",
        )
        self.sessions: dict[str, dict[str, str]] = {}
        self.invokes: list[dict] = []
        self._next = 0

    def _request(self, operation: str, parameters: dict) -> dict:
        model = self._aws.meta.service_model.operation_model(operation)
        return self._aws._serializer.serialize_to_request(parameters, model)

    def start_code_interpreter_session(self, **kwargs):
        request = self._request("StartCodeInterpreterSession", kwargs)
        assert request["method"] == "PUT"
        assert request["url_path"] == (
            "/code-interpreters/aws.codeinterpreter.v1/sessions/start"
        )
        self._next += 1
        session_id = _assert_session_id(f"srv{self._next:022d}")
        self.sessions[session_id] = {}
        return {
            "codeInterpreterIdentifier": kwargs.get("codeInterpreterIdentifier"),
            "sessionId": session_id,
            "createdAt": "2026-01-01T00:00:00Z",
        }

    def invoke_code_interpreter(self, **kwargs):
        request = self._request("InvokeCodeInterpreter", kwargs)
        header = request["headers"]["x-amzn-code-interpreter-session-id"]
        assert header == kwargs["sessionId"]
        assert request["method"] == "POST"
        assert request["url_path"] == (
            "/code-interpreters/aws.codeinterpreter.v1/tools/invoke"
        )
        assert header not in request["url_path"]
        body = json.loads(request["body"])
        self.invokes.append(
            {
                "sessionId": header,
                "name": body["name"],
                "arguments": body.get("arguments") or {},
            }
        )
        session = self.sessions.get(header)
        if session is None:
            raise ClientError(
                {
                    "Error": {
                        "Code": "ResourceNotFoundException",
                        "Message": "session is not active",
                    }
                },
                "InvokeCodeInterpreter",
            )
        result = _apply(session, body["name"], body.get("arguments") or {})
        return {"stream": [{"result": result}], "sessionId": header}


def _apply(session: dict[str, str], name: str, arguments: dict) -> dict:
    """Session filesystem for the four tool names the agents send.

    writeFiles stores each content block's text at its path. readFiles
    returns those bytes. executeCode and executeCommand keep the submitted
    source in the session so a later readFiles of that path returns it.
    Nothing in the request identifies an end user.
    """
    if name == "writeFiles":
        for block in arguments.get("content") or []:
            session[block["path"]] = block.get("text") or ""
        return {"content": [{"type": "text", "text": "wrote"}], "isError": False}
    if name == "readFiles":
        text = "\n".join(session.get(path, "") for path in arguments.get("paths") or [])
        return {"content": [{"type": "text", "text": text}], "isError": False}
    if name == "executeCode":
        session["submitted-code"] = arguments.get("code") or ""
        return {
            "content": [{"type": "text", "text": arguments.get("code") or ""}],
            "isError": False,
        }
    if name == "executeCommand":
        session["submitted-command"] = arguments.get("command") or ""
        return {
            "content": [{"type": "text", "text": arguments.get("command") or ""}],
            "isError": False,
        }
    raise AssertionError(f"unexpected tool name {name}")


class _SdkBridge:
    def __init__(self, instance):
        self.sdk_mcp_servers = {"codeint": instance}


def _install_interpreter(server) -> SessionKeyedInterpreter:
    interpreter = SessionKeyedInterpreter()
    server.client.ci_client = interpreter
    clear = getattr(server.client, "clear_caller", None)
    if callable(clear):
        clear()
    return interpreter


def publish_caller(server, user_id: str, runtime_session_id: str) -> None:
    """Publish the caller the entrypoint already verified.

    No-op until the fix adds bind_caller. Tests that need isolation still
    fail without it, because the model-supplied session id is what is invoked.
    """
    bind = getattr(server.client, "bind_caller", None)
    if callable(bind):
        bind(user_id, runtime_session_id)


def load_pattern(pattern: str):
    root = AGENT_CODE / pattern
    for name in list(sys.modules):
        if name == "agent" or name.startswith("code_int_mcp") or name.startswith("agents"):
            del sys.modules[name]
    for entry in (str(AGENT_CODE), str(root)):
        if entry in sys.path:
            sys.path.remove(entry)
        sys.path.insert(0, entry)
    os.environ["AWS_REGION"] = "us-east-1"
    os.environ.pop("GATEWAY_URL", None)
    os.environ.pop("PROJECT_NAME", None)
    os.environ.pop("DOCKER_CONTAINER", None)
    server = importlib.import_module("code_int_mcp.server")
    agent = importlib.import_module("agent")
    return server, agent


async def mcp_tools_call(server, name: str, arguments: dict) -> dict:
    """The CLI's tools/call message, routed by the SDK the agents ship."""
    instance = server.code_int_mcp_server["instance"]
    bridge = _SdkBridge(instance)
    listed = await Query._handle_sdk_mcp_request(
        bridge,
        "codeint",
        {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}},
    )
    assert "error" not in listed, listed
    response = await Query._handle_sdk_mcp_request(
        bridge,
        "codeint",
        {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {"name": name, "arguments": arguments},
        },
    )
    assert "error" not in response, response
    assert response["result"].get("isError") is not True, response
    return json.loads(response["result"]["content"][0]["text"])


def _run(coro):
    return asyncio.run(coro)


async def _open_attacker_session(server, interpreter):
    publish_caller(server, "attacker-sub", "rt-attacker")
    opened = await mcp_tools_call(
        server,
        "execute_code",
        {
            "code": "print('ready')",
            "language": "python",
            "code_int_session_id": "",
        },
    )
    session_id = _assert_session_id(opened["code_int_session_id"])
    assert session_id in interpreter.sessions
    return session_id


@pytest.mark.parametrize("pattern", PATTERNS)
@pytest.mark.parametrize(
    "operation",
    ["execute_code", "execute_command", "write_files", "read_files"],
)
def test_model_session_id_cannot_join_another_callers_sandbox(pattern, operation):
    """A session id the model was given must not select another user's sandbox."""
    server, _agent = load_pattern(pattern)
    interpreter = _install_interpreter(server)

    async def body():
        attacker_session = await _open_attacker_session(server, interpreter)
        seeded = await mcp_tools_call(
            server,
            "write_files",
            {
                "files_to_create": [
                    {"path": "attacker.txt", "text": ATTACKER_MARKER}
                ],
                "code_int_session_id": attacker_session,
            },
        )
        assert seeded["success"] is True

        publish_caller(server, "victim-sub", "rt-victim")
        before = len(interpreter.invokes)
        attacker_files = dict(interpreter.sessions[attacker_session])
        if operation == "execute_code":
            victim = await mcp_tools_call(
                server,
                "execute_code",
                {
                    "code": VICTIM_MARKER,
                    "language": "python",
                    "code_int_session_id": attacker_session,
                },
            )
        elif operation == "execute_command":
            victim = await mcp_tools_call(
                server,
                "execute_command",
                {
                    "command": VICTIM_MARKER,
                    "code_int_session_id": attacker_session,
                },
            )
        elif operation == "write_files":
            victim = await mcp_tools_call(
                server,
                "write_files",
                {
                    "files_to_create": [
                        {"path": "secret.txt", "text": VICTIM_MARKER}
                    ],
                    "code_int_session_id": attacker_session,
                },
            )
        else:
            victim = await mcp_tools_call(
                server,
                "read_files",
                {
                    "paths": ["attacker.txt"],
                    "code_int_session_id": attacker_session,
                },
            )

        victim_invokes = interpreter.invokes[before:]
        assert victim_invokes, "the victim turn never reached the interpreter"
        assert all(call["sessionId"] != attacker_session for call in victim_invokes), (
            "InvokeCodeInterpreter used the session id supplied by the model: "
            f"{[call['sessionId'] for call in victim_invokes]}"
        )
        assert interpreter.sessions[attacker_session] == attacker_files, (
            "the victim turn changed files in the attacker's sandbox"
        )
        assert VICTIM_MARKER not in json.dumps(interpreter.sessions[attacker_session])

        publish_caller(server, "attacker-sub", "rt-attacker")
        read_back = await mcp_tools_call(
            server,
            "read_files",
            {
                "paths": ["secret.txt", "submitted-code", "submitted-command"],
                "code_int_session_id": attacker_session,
            },
        )
        assert VICTIM_MARKER not in read_back["output"]
        if operation == "read_files":
            assert ATTACKER_MARKER not in victim["output"]
        return victim

    _run(body())


@pytest.mark.parametrize("pattern", PATTERNS)
def test_string_encoded_files_cannot_select_the_session(pattern):
    """write_files and read_files also accept a JSON string. Same rule."""
    server, _agent = load_pattern(pattern)
    interpreter = _install_interpreter(server)

    async def body():
        attacker_session = await _open_attacker_session(server, interpreter)
        publish_caller(server, "victim-sub", "rt-victim")
        before = len(interpreter.invokes)
        written = await server.write_files.handler(
            {
                "files_to_create": json.dumps(
                    [{"path": "secret.txt", "text": VICTIM_MARKER}]
                ),
                "code_int_session_id": attacker_session,
            }
        )
        assert written.get("is_error") is not True
        victim_invokes = interpreter.invokes[before:]
        assert victim_invokes
        assert all(call["sessionId"] != attacker_session for call in victim_invokes)
        read = await server.read_files.handler(
            {
                "paths": json.dumps(["secret.txt"]),
                "code_int_session_id": OTHER_SESSION,
            }
        )
        text = read["content"][0]["text"]
        assert VICTIM_MARKER in text
        assert all(
            call["sessionId"] != attacker_session
            for call in interpreter.invokes[before:]
        )
        assert VICTIM_MARKER not in json.dumps(interpreter.sessions[attacker_session])

    _run(body())


@pytest.mark.parametrize("pattern", PATTERNS)
def test_same_caller_keeps_one_sandbox_despite_model_session_ids(pattern):
    server, _agent = load_pattern(pattern)
    interpreter = _install_interpreter(server)

    async def body():
        publish_caller(server, "victim-sub", "rt-victim")
        await mcp_tools_call(
            server,
            "write_files",
            {
                "files_to_create": [{"path": "secret.txt", "text": VICTIM_MARKER}],
                "code_int_session_id": OTHER_SESSION,
            },
        )
        read = await mcp_tools_call(
            server,
            "read_files",
            {
                "paths": ["secret.txt"],
                "code_int_session_id": "secondModelSession0123456789",
            },
        )
        assert VICTIM_MARKER in read["output"]
        used = {call["sessionId"] for call in interpreter.invokes}
        assert OTHER_SESSION not in used
        assert "secondModelSession0123456789" not in used
        assert len(used) == 1

    _run(body())


@pytest.mark.parametrize("pattern", PATTERNS)
def test_subject_and_runtime_session_both_bound_the_sandbox(pattern):
    server, _agent = load_pattern(pattern)
    _install_interpreter(server)

    async def body():
        publish_caller(server, "victim-sub", "rt-one")
        written = await mcp_tools_call(
            server,
            "write_files",
            {
                "files_to_create": [{"path": "secret.txt", "text": VICTIM_MARKER}],
                "code_int_session_id": "",
            },
        )
        returned = _assert_session_id(written["code_int_session_id"])

        publish_caller(server, "victim-sub", "rt-two")
        other_runtime = await mcp_tools_call(
            server,
            "read_files",
            {"paths": ["secret.txt"], "code_int_session_id": returned},
        )
        assert VICTIM_MARKER not in other_runtime["output"]

        publish_caller(server, "other-sub", "rt-one")
        other_user = await mcp_tools_call(
            server,
            "read_files",
            {"paths": ["secret.txt"], "code_int_session_id": returned},
        )
        assert VICTIM_MARKER not in other_user["output"]

        publish_caller(server, "victim-sub", "rt-one")
        same = await mcp_tools_call(
            server,
            "read_files",
            {"paths": ["secret.txt"], "code_int_session_id": OTHER_SESSION},
        )
        assert VICTIM_MARKER in same["output"]

    _run(body())


class ScriptedModel:
    """Stand-in for the model. It copies tool calls out of the prompt text.

    The real Claude model is not run. This only checks that a prompt which
    names a session id reaches the tools unchanged, which is what main does
    with payload["prompt"].
    """

    results: list[dict] = []

    def __init__(self, options):
        self.options = options
        self.prompt = None

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def query(self, prompt):
        self.prompt = prompt

    async def receive_response(self):
        spec = json.loads(self.prompt)
        instance = self.options.mcp_servers["codeint"]["instance"]
        bridge = _SdkBridge(instance)
        for call in spec["tool_calls"]:
            response = await Query._handle_sdk_mcp_request(
                bridge,
                "codeint",
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "tools/call",
                    "params": {
                        "name": call["name"],
                        "arguments": call["arguments"],
                    },
                },
            )
            assert "error" not in response, response
            ScriptedModel.results.append(
                json.loads(response["result"]["content"][0]["text"])
            )
        if False:
            yield None


@pytest.mark.parametrize("pattern", PATTERNS)
def test_entrypoint_binds_the_verified_subject_before_tools_run(pattern):
    """main must bind the subject it just verified. The test does not."""
    server, agent = load_pattern(pattern)
    interpreter = _install_interpreter(server)
    agent.ClaudeSDKClient = ScriptedModel
    from bedrock_agentcore.runtime import RequestContext

    subjects = []

    def verified_subject(context):
        assert context.request_headers["Authorization"].startswith("Bearer ")
        subjects.append(context)
        return subjects_by_call[len(subjects) - 1]

    agent.extract_user_id_from_context = verified_subject
    subjects_by_call = ["attacker-sub", "victim-sub", "attacker-sub"]

    async def turn(user_index: int, runtime_session_id: str, tool_calls: list[dict]):
        ScriptedModel.results = []
        context = RequestContext(
            request_headers={"Authorization": "Bearer placeholder"}
        )
        events = []
        async for event in agent.main(
            {
                "prompt": json.dumps({"tool_calls": tool_calls}),
                "runtimeSessionId": runtime_session_id,
            },
            context,
        ):
            events.append(event)
        assert ScriptedModel.results, events
        return ScriptedModel.results

    async def body():
        opened = await turn(
            0,
            "rt-attacker",
            [
                {
                    "name": "execute_code",
                    "arguments": {
                        "code": "print('ready')",
                        "language": "python",
                        "code_int_session_id": "",
                    },
                }
            ],
        )
        attacker_session = _assert_session_id(opened[0]["code_int_session_id"])
        before = len(interpreter.invokes)
        victim = await turn(
            1,
            "rt-victim",
            [
                {
                    "name": "write_files",
                    "arguments": {
                        "files_to_create": [
                            {"path": "secret.txt", "text": VICTIM_MARKER}
                        ],
                        "code_int_session_id": attacker_session,
                    },
                },
                {
                    "name": "read_files",
                    "arguments": {
                        "paths": ["secret.txt"],
                        "code_int_session_id": OTHER_SESSION,
                    },
                },
            ],
        )
        victim_invokes = interpreter.invokes[before : before + 2]
        assert len(victim_invokes) >= 2
        assert all(call["sessionId"] != attacker_session for call in victim_invokes)
        assert {call["sessionId"] for call in victim_invokes} != {OTHER_SESSION}
        assert len({call["sessionId"] for call in victim_invokes}) == 1
        assert VICTIM_MARKER in victim[1]["output"]
        assert VICTIM_MARKER not in json.dumps(
            interpreter.sessions[attacker_session]
        )

        read_back = await turn(
            2,
            "rt-attacker",
            [
                {
                    "name": "read_files",
                    "arguments": {
                        "paths": ["secret.txt"],
                        "code_int_session_id": attacker_session,
                    },
                }
            ],
        )
        assert VICTIM_MARKER not in read_back[0]["output"]

    _run(body())
