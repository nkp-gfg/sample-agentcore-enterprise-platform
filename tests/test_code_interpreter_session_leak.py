"""Code-interpreter sessions must not outlive the agent request that started them.

A signed-in caller invokes a Strands, LangGraph, or AG-UI entrypoint and asks
it to run Python. The entrypoint registers ``execute_python_securely``. The
first call starts an AgentCore code-interpreter session through
``bedrock-agentcore`` 1.21.0 ``CodeInterpreter.start`` (no arguments), which
calls ``StartCodeInterpreterSession`` on ``aws.codeinterpreter.v1`` with
``sessionTimeoutSeconds`` 900. The service keeps that session until
``StopCodeInterpreterSession`` or the timeout. These tests drive the real
entrypoint, wrapper, and SDK client, and stand in only for the model tool
dispatch and the AWS data plane.

They fail while a finished request leaves its session READY. Stopping a
different session id does not count: the data-plane stand-in only terminates
the session whose id and interpreter identifier were passed to stop.

Not covered here: ``agent-code/claude-sdk-agent`` and
``agent-code/claude-sdk-multi-agent``. Their ``CodeInterpreterClient`` also
calls ``start_code_interpreter_session`` with a 900 second timeout and never
calls ``stop_code_interpreter_session``. Driving those entrypoints needs the
Claude Agent SDK subprocess, so they are left untested.
"""

from __future__ import annotations

import asyncio
import importlib.util
import inspect
import json
import os
import re
import sys
import types
import urllib.request
from pathlib import Path

import pytest
from botocore.exceptions import ClientError
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm

import jwt

REPO = Path(__file__).resolve().parents[1]
AGENT_CODE = REPO / "agent-code"

# Read at shared.auth import. Set before the first agent module loads.
ISSUER = "https://idp.example.test/issuer"
CLIENT_ID = "client-app"
os.environ["COGNITO_ISSUER_URL"] = ISSUER
os.environ["COGNITO_ALLOWED_CLIENTS"] = CLIENT_ID
os.environ["AWS_DEFAULT_REGION"] = "us-east-1"
os.environ["AWS_REGION"] = "us-east-1"
os.environ["MEMORY_ID"] = "mem-test"
os.environ.pop("GATEWAY_CREDENTIAL_PROVIDER_NAME", None)
os.environ.pop("GATEWAY_URL", None)

# Documented account quota is 1000 concurrent active code-interpreter
# sessions. Tests scale that same rule down so a handful of leaked sessions
# fill it. The error is the one StartCodeInterpreterSession documents for
# exceeding a service quota.
ACCOUNT_SESSION_QUOTA = 1000
MARKER = "CODE_INTERPRETER_OK"
FAILURE_CODE = "SIMULATE_INTERPRETER_FAILURE"
PYTHON_FENCE = re.compile(r"```python\n(.*?)```", re.DOTALL)

AGENT_NAMES = (
    "strands-agent",
    "langgraph-agent",
    "agui-strands-agent",
    "agui-langgraph-agent",
)


class _Response:
    def __init__(self, payload: bytes):
        self._payload = payload

    def read(self, *args, **kwargs):
        return self._payload

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


class _Event:
    def __init__(self, payload: dict):
        self.payload = payload

    def model_dump(self, **kwargs):
        return self.payload


class CodeInterpreterPlane:
    """In-process stand-in for the bedrock-agentcore data plane.

    ``CodeInterpreter.start`` / ``stop`` / ``invoke`` in bedrock-agentcore
    1.21.0 are thin wrappers over ``start_code_interpreter_session``,
    ``stop_code_interpreter_session``, and ``invoke_code_interpreter``. The
    class has no destructor and no context-manager exit of its own; only
    ``code_session`` calls ``stop``. This plane therefore keeps a session
    READY until stop is called with that session's id and interpreter id.
    Discarding the boto client does not change the session. A start past
    ``capacity`` raises ``ServiceQuotaExceededException`` and does not
    create a session.
    """

    def __init__(self):
        self.capacity = ACCOUNT_SESSION_QUOTA
        self.sessions: dict[str, dict] = {}
        self.starts: list[dict] = []
        self.stops: list[dict] = []
        self.invokes: list[dict] = []

    def reset(self, capacity: int = ACCOUNT_SESSION_QUOTA):
        self.capacity = capacity
        self.sessions.clear()
        self.starts.clear()
        self.stops.clear()
        self.invokes.clear()

    def ready(self) -> list[dict]:
        return [dict(session) for session in self.sessions.values() if session["status"] == "READY"]

    def start_code_interpreter_session(self, **kwargs):
        if len(self.ready()) >= self.capacity:
            raise ClientError(
                {
                    "Error": {
                        "Code": "ServiceQuotaExceededException",
                        "Message": "Concurrent active sessions per account exceeded",
                    }
                },
                "StartCodeInterpreterSession",
            )
        identifier = kwargs["codeInterpreterIdentifier"]
        session_id = f"sess{len(self.sessions):032d}"
        record = {
            "sessionId": session_id,
            "codeInterpreterIdentifier": identifier,
            "name": kwargs.get("name"),
            "sessionTimeoutSeconds": kwargs.get("sessionTimeoutSeconds", 900),
            "status": "READY",
        }
        self.sessions[session_id] = record
        self.starts.append(dict(record))
        return {
            "sessionId": session_id,
            "codeInterpreterIdentifier": identifier,
            "createdAt": "2026-01-01T00:00:00Z",
        }

    def stop_code_interpreter_session(self, **kwargs):
        session_id = kwargs["sessionId"]
        identifier = kwargs["codeInterpreterIdentifier"]
        self.stops.append(
            {"sessionId": session_id, "codeInterpreterIdentifier": identifier}
        )
        session = self.sessions.get(session_id)
        if (
            session is None
            or session["codeInterpreterIdentifier"] != identifier
            or session["status"] != "READY"
        ):
            raise ClientError(
                {
                    "Error": {
                        "Code": "ResourceNotFoundException",
                        "Message": "Session is not an active session of this interpreter",
                    }
                },
                "StopCodeInterpreterSession",
            )
        session["status"] = "TERMINATED"
        return {}

    def invoke_code_interpreter(self, **kwargs):
        session_id = kwargs["sessionId"]
        identifier = kwargs["codeInterpreterIdentifier"]
        session = self.sessions.get(session_id)
        if (
            session is None
            or session["status"] != "READY"
            or session["codeInterpreterIdentifier"] != identifier
        ):
            raise ClientError(
                {
                    "Error": {
                        "Code": "ResourceNotFoundException",
                        "Message": "Session is not active",
                    }
                },
                "InvokeCodeInterpreter",
            )
        arguments = kwargs.get("arguments") or {}
        self.invokes.append(
            {
                "sessionId": session_id,
                "codeInterpreterIdentifier": identifier,
                "name": kwargs.get("name"),
                "code": arguments.get("code"),
            }
        )
        if arguments.get("code") == FAILURE_CODE:
            raise ClientError(
                {
                    "Error": {
                        "Code": "InternalServerException",
                        "Message": "interpreter failed",
                    }
                },
                "InvokeCodeInterpreter",
            )
        return {"stream": [{"result": {"stdout": MARKER}}]}


PLANE = CodeInterpreterPlane()


class _Client:
    def __init__(self, service_name: str, plane: CodeInterpreterPlane):
        self.service_name = service_name
        self.plane = plane

    def __getattr__(self, name: str):
        def method(**kwargs):
            handler = getattr(self.plane, name, None)
            if handler is None:
                raise AssertionError(f"unexpected {self.service_name}.{name}({kwargs})")
            return handler(**kwargs)

        return method


_ORIGINAL_SESSION_CLIENT = None
_ORIGINAL_URLOPEN = None
_SIGNING_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_PUBLIC_JWK = json.loads(RSAAlgorithm.to_jwk(_SIGNING_KEY.public_key()))
_PUBLIC_JWK.update({"kid": "test-key", "use": "sig", "alg": "RS256"})


def _install_standins():
    global _ORIGINAL_SESSION_CLIENT, _ORIGINAL_URLOPEN
    import boto3.session

    if _ORIGINAL_SESSION_CLIENT is None:
        _ORIGINAL_SESSION_CLIENT = boto3.session.Session.client

        def client(self, service_name, *args, **kwargs):
            if service_name in ("bedrock-agentcore", "bedrock-agentcore-control"):
                return _Client(service_name, PLANE)
            return _ORIGINAL_SESSION_CLIENT(self, service_name, *args, **kwargs)

        boto3.session.Session.client = client

    if _ORIGINAL_URLOPEN is None:
        _ORIGINAL_URLOPEN = urllib.request.urlopen

        def urlopen(url, *args, **kwargs):
            target = url.full_url if isinstance(url, urllib.request.Request) else str(url)
            if target.startswith(ISSUER):
                if target.endswith("openid-configuration"):
                    body = json.dumps({"jwks_uri": f"{ISSUER}/jwks"}).encode()
                elif target.endswith("/jwks"):
                    body = json.dumps({"keys": [_PUBLIC_JWK]}).encode()
                else:
                    raise AssertionError(f"unexpected issuer URL {target}")
                return _Response(body)
            return _ORIGINAL_URLOPEN(url, *args, **kwargs)

        urllib.request.urlopen = urlopen


def _restore_standins():
    global _ORIGINAL_SESSION_CLIENT, _ORIGINAL_URLOPEN
    if _ORIGINAL_SESSION_CLIENT is not None:
        import boto3.session

        boto3.session.Session.client = _ORIGINAL_SESSION_CLIENT
        _ORIGINAL_SESSION_CLIENT = None
    if _ORIGINAL_URLOPEN is not None:
        urllib.request.urlopen = _ORIGINAL_URLOPEN
        _ORIGINAL_URLOPEN = None


@pytest.fixture(scope="module", autouse=True)
def aws_and_idp_standins():
    _install_standins()
    yield
    _restore_standins()


@pytest.fixture(autouse=True)
def clean_plane():
    PLANE.reset()
    yield
    PLANE.reset()


def _token(subject: str) -> str:
    return jwt.encode(
        {
            "sub": subject,
            "iss": ISSUER,
            "aud": CLIENT_ID,
            "token_use": "id",
            "exp": 2_000_000_000,
        },
        _SIGNING_KEY,
        algorithm="RS256",
        headers={"kid": "test-key"},
    )


def _context(subject: str):
    from bedrock_agentcore.runtime import RequestContext

    return RequestContext(
        request_headers={"Authorization": f"Bearer {_token(subject)}"}
    )


def _stub_module(name: str, **attrs):
    module = sys.modules.get(name)
    if module is None:
        module = types.ModuleType(name)
        module.__package__ = name
        module.__path__ = []
        sys.modules[name] = module
        if "." in name:
            parent_name, child = name.rsplit(".", 1)
            parent = sys.modules.get(parent_name)
            if parent is not None and not hasattr(parent, child):
                setattr(parent, child, module)
    for key, value in attrs.items():
        setattr(module, key, value)
    return module


def _tool(fn=None, **kwargs):
    def wrap(func):
        func.name = func.__name__
        return func

    if fn is None:
        return wrap
    return wrap(fn)


class _Agent:
    def __init__(self, *args, tools=None, **kwargs):
        self.tools = list(tools or [])

    async def stream_async(self, prompt):
        for result in _dispatch(self.tools, prompt):
            yield {"tool_result": result}
        if "RAISE_AFTER_TOOL" in prompt:
            raise RuntimeError("agent failed after code execution")
        yield {"data": "done"}


class _Graph:
    def __init__(self, tools):
        self.tools = list(tools or [])

    async def astream(self, inputs, config=None, stream_mode=None):
        messages = inputs.get("messages") or []
        prompt = messages[-1][1] if messages else ""
        for result in _dispatch(self.tools, prompt):
            yield (_Event({"tool_result": result}), {})
        if "RAISE_AFTER_TOOL" in prompt:
            raise RuntimeError("agent failed after code execution")
        yield (_Event({"data": "done"}), {})


def _create_agent(*args, tools=None, **kwargs):
    return _Graph(tools)


class _BedrockModel:
    def __init__(self, *args, **kwargs):
        pass


class _ChatBedrock:
    def __init__(self, *args, **kwargs):
        pass


class _MemorySaver:
    def __init__(self, *args, **kwargs):
        pass


class _SessionManager:
    def __init__(self, *args, **kwargs):
        pass


class _RunAgentInput:
    def __init__(self, thread_id: str, prompt: str):
        self.thread_id = thread_id
        self.prompt = prompt

    @classmethod
    def model_validate(cls, payload):
        parts = []
        for message in payload.get("messages") or []:
            if message.get("role") != "user":
                continue
            content = message.get("content", "")
            if isinstance(content, list):
                content = "".join(
                    part.get("text", "") if isinstance(part, dict) else str(part)
                    for part in content
                )
            parts.append(content)
        thread_id = payload.get("threadId") or payload.get("thread_id") or "default"
        return cls(thread_id, "\n".join(parts))


class _RunErrorEvent:
    def __init__(self, message: str, code: str):
        self.message = message
        self.code = code

    def model_dump(self, **kwargs):
        return {"type": "RUN_ERROR", "message": self.message, "code": self.code}


class _StrandsAguiAgent:
    def __init__(self, agent, name, description):
        self._agents_by_thread = {}
        self.agent = agent

    async def run(self, input_data):
        thread_id = input_data.thread_id or "default"
        agent = self._agents_by_thread[thread_id]
        async for event in agent.stream_async(input_data.prompt):
            yield _Event(event)


class _LangGraphAguiAgent:
    def __init__(self, *, name, description, graph, config):
        self.graph = graph

    async def run(self, input_data):
        async for event in self.graph.astream(
            {"messages": [("user", input_data.prompt)]}
        ):
            yield event[0]


class _Middleware:
    def __init__(self, *args, **kwargs):
        pass


def _install_framework_stubs():
    _stub_module("strands", Agent=_Agent, tool=_tool)
    _stub_module("strands.models", BedrockModel=_BedrockModel)
    _stub_module("strands.tools")
    _stub_module("strands.tools.mcp", MCPClient=object)
    _stub_module("mcp")
    _stub_module("mcp.client")
    _stub_module("mcp.client.streamable_http", streamablehttp_client=lambda **kwargs: None)
    _stub_module("langchain")
    _stub_module("langchain.agents", create_agent=_create_agent)
    _stub_module("langchain_aws", ChatBedrock=_ChatBedrock)
    _stub_module("langchain_core")
    _stub_module("langchain_core.tools", tool=_tool)
    _stub_module("langchain_mcp_adapters")
    _stub_module("langchain_mcp_adapters.client", MultiServerMCPClient=object)
    _stub_module("langgraph_checkpoint_aws", AgentCoreMemorySaver=_MemorySaver)
    _stub_module("ag_ui")
    _stub_module("ag_ui.core", RunAgentInput=_RunAgentInput, RunErrorEvent=_RunErrorEvent)
    _stub_module("ag_ui_strands", StrandsAgent=_StrandsAguiAgent)
    _stub_module("copilotkit", CopilotKitMiddleware=_Middleware, LangGraphAGUIAgent=_LangGraphAguiAgent)

    # The AG-UI Strands module imports the memory session manager at import
    # time. The real module imports strands' session types, which this harness
    # does not run. The session manager is not on the code-interpreter path;
    # it only has to construct so the entrypoint can reach the tool.
    import bedrock_agentcore.memory.integrations as integrations

    package_name = "bedrock_agentcore.memory.integrations.strands"
    if package_name not in sys.modules:
        package = _stub_module(package_name)
        integrations.strands = package
        config = _stub_module(f"{package_name}.config")
        # The real config module is pydantic-only, but importing the package
        # runs strands session types. The entrypoint only needs an object it
        # can pass into the session manager, which is not on the interpreter path.
        config.AgentCoreMemoryConfig = lambda **kwargs: types.SimpleNamespace(**kwargs)
        session_mod = _stub_module(f"{package_name}.session_manager")
        session_mod.AgentCoreMemorySessionManager = _SessionManager


_LOADED: dict[str, types.ModuleType] = {}


def _purge_agent_modules():
    for name in list(sys.modules):
        if name == "tools" or name.startswith("tools.") or name == "agent_under_test":
            del sys.modules[name]


def load_agent(agent_name: str):
    if agent_name in _LOADED:
        return _LOADED[agent_name]
    _install_framework_stubs()
    _purge_agent_modules()
    agent_dir = AGENT_CODE / agent_name
    added = []
    for path in (str(AGENT_CODE), str(agent_dir)):
        if path not in sys.path:
            sys.path.insert(0, path)
            added.append(path)
    try:
        spec = importlib.util.spec_from_file_location(
            "agent_under_test", agent_dir / "agent.py"
        )
        module = importlib.util.module_from_spec(spec)
        sys.modules["agent_under_test"] = module
        spec.loader.exec_module(module)
    finally:
        for path in added:
            if sys.path and sys.path[0] == path:
                sys.path.pop(0)
            elif path in sys.path:
                sys.path.remove(path)
    _LOADED[agent_name] = module
    _purge_agent_modules()
    sys.modules.pop("agent_under_test", None)
    return module


def _find_tool(tools):
    for tool in tools:
        name = getattr(tool, "name", None) or getattr(tool, "__name__", "")
        if name == "execute_python_securely":
            return tool
    raise AssertionError(
        "entrypoint did not register execute_python_securely; "
        f"tools={tools!r}"
    )


def _call_tool(tool, code: str):
    invoke = getattr(tool, "invoke", None)
    if invoke is not None and not inspect.isfunction(tool) and not inspect.ismethod(tool):
        return invoke({"code": code})
    return tool(code=code)


def _dispatch(tools, prompt: str) -> list[str]:
    """Stand in for the model selecting the registered code-interpreter tool.

    The entrypoint passes the caller-supplied text to the agent. This harness
    does what the framework does after the model emits a tool call: it calls
    the ``execute_python_securely`` object the entrypoint registered, with the
    Python from the caller's message as ``code``.
    """
    codes = [block.strip("\n") for block in PYTHON_FENCE.findall(prompt)]
    if not codes:
        return []
    tool = _find_tool(tools)
    return [_call_tool(tool, code) for code in codes]


def _prompt(*codes: str, raise_after: bool = False) -> str:
    body = "\n".join(f"```python\n{code}\n```" for code in codes)
    if raise_after:
        body += "\nRAISE_AFTER_TOOL"
    return body


def _payload(agent_name: str, prompt: str) -> dict:
    if agent_name.startswith("agui-"):
        return {
            "threadId": "thread-1",
            "runId": "run-1",
            "messages": [{"id": "m1", "role": "user", "content": prompt}],
        }
    return {"prompt": prompt, "runtimeSessionId": "runtime-session-1"}


def run_turn(agent_name: str, prompt: str, subject: str) -> list:
    module = load_agent(agent_name)
    context = _context(subject)

    async def collect():
        events = []
        async for event in module.invocations(_payload(agent_name, prompt), context):
            events.append(event)
        return events

    return asyncio.run(collect())


def _assert_every_started_session_was_stopped():
    assert PLANE.starts, "no code-interpreter session was started; the tool path did not run"
    assert PLANE.invokes, "executeCode was never invoked"
    ready = PLANE.ready()
    assert not ready, (
        "code-interpreter sessions were still READY after the request finished: "
        f"{ready}. stops={PLANE.stops}"
    )
    for started in PLANE.starts:
        matches = [
            stop
            for stop in PLANE.stops
            if stop["sessionId"] == started["sessionId"]
            and stop["codeInterpreterIdentifier"] == started["codeInterpreterIdentifier"]
        ]
        assert matches, (
            "StopCodeInterpreterSession was not called for the session that "
            f"StartCodeInterpreterSession created: {started}. stops={PLANE.stops}"
        )


@pytest.mark.parametrize("agent_name", AGENT_NAMES)
def test_finished_request_stops_the_session_it_started(agent_name):
    events = run_turn(agent_name, _prompt(f"print('{MARKER}')"), "user-attacker")
    blob = json.dumps(events)
    assert MARKER in blob
    assert any(call["code"] == f"print('{MARKER}')" for call in PLANE.invokes)
    assert any(call["name"] == "executeCode" for call in PLANE.invokes)
    _assert_every_started_session_was_stopped()


@pytest.mark.parametrize("agent_name", AGENT_NAMES)
def test_two_tool_calls_in_one_request_leave_no_session(agent_name):
    first = "print('one')"
    second = "print('two')"
    run_turn(agent_name, _prompt(first, second), "user-attacker")
    assert [call["code"] for call in PLANE.invokes] == [first, second]
    _assert_every_started_session_was_stopped()


@pytest.mark.parametrize("agent_name", AGENT_NAMES)
def test_session_is_stopped_when_the_turn_fails_after_the_tool(agent_name):
    events = run_turn(
        agent_name,
        _prompt(f"print('{MARKER}')", raise_after=True),
        "user-attacker",
    )
    blob = json.dumps(events)
    assert "agent failed after code execution" in blob
    _assert_every_started_session_was_stopped()


@pytest.mark.parametrize("agent_name", AGENT_NAMES)
def test_session_is_stopped_when_execute_code_fails(agent_name):
    events = run_turn(agent_name, _prompt(FAILURE_CODE), "user-attacker")
    blob = json.dumps(events)
    assert "Code execution failed" in blob
    _assert_every_started_session_was_stopped()


@pytest.mark.parametrize("agent_name", AGENT_NAMES)
def test_repeated_requests_do_not_fill_the_account_session_quota(agent_name):
    # Same rule as the account-wide concurrent active session quota, scaled
    # to two so the leaked sessions from two finished requests are enough.
    PLANE.capacity = 2
    run_turn(agent_name, _prompt("print('first')"), "user-attacker")
    run_turn(agent_name, _prompt("print('second')"), "user-attacker")
    events = run_turn(agent_name, _prompt(f"print('{MARKER}')"), "user-other")
    assert any(call["code"] == f"print('{MARKER}')" for call in PLANE.invokes), (
        "another caller's executeCode did not run; finished requests still "
        f"hold the account session quota. ready={PLANE.ready()} events={events}"
    )
    _assert_every_started_session_was_stopped()


def test_stop_for_a_different_session_does_not_free_the_one_that_was_started():
    started = PLANE.start_code_interpreter_session(
        codeInterpreterIdentifier="aws.codeinterpreter.v1",
        name="held",
        sessionTimeoutSeconds=900,
    )
    with pytest.raises(ClientError):
        PLANE.stop_code_interpreter_session(
            codeInterpreterIdentifier="aws.codeinterpreter.v1",
            sessionId="not-the-started-session",
        )
    assert PLANE.ready()[0]["sessionId"] == started["sessionId"]
    PLANE.stop_code_interpreter_session(
        codeInterpreterIdentifier=started["codeInterpreterIdentifier"],
        sessionId=started["sessionId"],
    )
    assert PLANE.ready() == []
