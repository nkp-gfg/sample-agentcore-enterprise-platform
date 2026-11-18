"""Code interpreter failures must not return the AWS error text to the caller.

These tests drive the runtime entrypoints and the Claude interpreter tools. The
AWS data-plane call is stubbed with botocore's Stubber, so the exception is the
ClientError the service client raises. The model is scripted only far enough to
request the interpreter tool; it never repeats the service error.

They fail while the tool result or the caller-visible stream still contains the
operation name, the error code, or the service message. The fixed failure text
the tools must return is ``Code execution failed``.
"""

from __future__ import annotations

import asyncio
import importlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import boto3
import pytest
from botocore.stub import Stubber
from starlette.testclient import TestClient

REPO = Path(__file__).resolve().parents[1]
AGENT_CODE = REPO / "agent-code"

FIXED_FAILURE = "Code execution failed"
DENIED_ACTION = "bedrock-agentcore:InvokeCodeInterpreter"
DENIED_RESOURCE = (
    "arn:aws:bedrock-agentcore:us-east-1:000000000000:code-interpreter/example"
)
SERVICE_MESSAGE = (
    "User: arn:aws:sts::000000000000:assumed-role/runtime-role/session "
    f"is not authorized to perform: {DENIED_ACTION} on resource: {DENIED_RESOURCE}"
)

_AGENT_MODULES = ("agent", "tools", "shared", "code_int_mcp")


@pytest.fixture(autouse=True)
def _restore_import_state():
    path = sys.path.copy()
    yield
    sys.path[:] = path
    for name in list(sys.modules):
        if name in _AGENT_MODULES or name.startswith(tuple(f"{module}." for module in _AGENT_MODULES)):
            del sys.modules[name]


def _service_message(error_code: str) -> str:
    return f"{error_code} detail: {SERVICE_MESSAGE}"


def _leak_markers(error_code: str) -> tuple[str, ...]:
    return (
        SERVICE_MESSAGE,
        DENIED_ACTION,
        DENIED_RESOURCE,
        error_code,
        "An error occurred (",
        "InvokeCodeInterpreter",
        "StartCodeInterpreterSession",
        "is not authorized to perform",
    )


def _assert_caller_safe(body: str, error_code: str) -> None:
    assert FIXED_FAILURE in body
    for marker in _leak_markers(error_code):
        assert marker not in body, marker


def _purge_agent_modules() -> None:
    for name in list(sys.modules):
        if name in _AGENT_MODULES or name.startswith(tuple(f"{m}." for m in _AGENT_MODULES)):
            del sys.modules[name]


def _load_agent(agent_dirname: str):
    _purge_agent_modules()
    agent_dir = str(AGENT_CODE / agent_dirname)
    shared_root = str(AGENT_CODE)
    for path in (agent_dir, shared_root):
        if path in sys.path:
            sys.path.remove(path)
    sys.path.insert(0, shared_root)
    sys.path.insert(0, agent_dir)
    return importlib.import_module("agent")


def _stubbed_interpreter_client(error_code: str, *, fail_session: bool = False):
    client = boto3.client("bedrock-agentcore", region_name="us-east-1")
    stubber = Stubber(client)
    message = _service_message(error_code)
    if fail_session:
        stubber.add_client_error(
            "start_code_interpreter_session",
            service_error_code=error_code,
            service_message=message,
            http_status_code=403,
        )
    else:
        stubber.add_response(
            "start_code_interpreter_session",
            {
                "codeInterpreterIdentifier": "aws.codeinterpreter.v1",
                "sessionId": "session-1",
                "createdAt": datetime.now(timezone.utc),
            },
        )
        stubber.add_client_error(
            "invoke_code_interpreter",
            service_error_code=error_code,
            service_message=message,
            http_status_code=403,
        )
    stubber.activate()
    return client


class _InterpreterClientPatch:
    """Send CodeInterpreter's data-plane calls to one stubbed client."""

    def __init__(self, client):
        self._client = client
        self._original = boto3.Session.client

    def __enter__(self):
        stubbed = self._client
        original = self._original

        def client(session, service_name, *args, **kwargs):
            if service_name == "bedrock-agentcore":
                return stubbed
            return original(session, service_name, *args, **kwargs)

        boto3.Session.client = client
        return stubbed

    def __exit__(self, *exc):
        boto3.Session.client = self._original
        return False


def _scripted_strands_model():
    from strands.models.bedrock import BedrockModel

    original = BedrockModel.stream
    calls = {"n": 0}

    async def stream(
        self,
        messages,
        tool_specs=None,
        system_prompt=None,
        *,
        tool_choice=None,
        system_prompt_content=None,
        **kwargs,
    ):
        calls["n"] += 1
        if calls["n"] == 1:
            yield {"messageStart": {"role": "assistant"}}
            yield {
                "contentBlockStart": {
                    "start": {
                        "toolUse": {
                            "name": "execute_python_securely",
                            "toolUseId": "tool-1",
                        }
                    }
                }
            }
            yield {
                "contentBlockDelta": {
                    "delta": {"toolUse": {"input": json.dumps({"code": "print(1)"})}}
                }
            }
            yield {"contentBlockStop": {}}
            yield {"messageStop": {"stopReason": "tool_use"}}
            return
        yield {"messageStart": {"role": "assistant"}}
        yield {"contentBlockStart": {"start": {}}}
        yield {"contentBlockDelta": {"delta": {"text": "done"}}}
        yield {"contentBlockStop": {}}
        yield {"messageStop": {"stopReason": "end_turn"}}

    BedrockModel.stream = stream
    return BedrockModel, original


def _scripted_langgraph_model():
    from langchain_core.language_models.chat_models import BaseChatModel
    from langchain_core.messages import AIMessage
    from langchain_core.outputs import ChatGeneration, ChatResult

    class Scripted(BaseChatModel):
        step: int = 0

        def bind_tools(self, tools, **kwargs):
            return self

        @property
        def _llm_type(self) -> str:
            return "scripted-code-interpreter"

        def _generate(self, messages, stop=None, run_manager=None, **kwargs):
            self.step += 1
            if self.step == 1:
                message = AIMessage(
                    content="",
                    tool_calls=[
                        {
                            "name": "execute_python_securely",
                            "args": {"code": "print(1)"},
                            "id": "call-1",
                            "type": "tool_call",
                        }
                    ],
                )
            else:
                message = AIMessage(content="done")
            return ChatResult(generations=[ChatGeneration(message=message)])

    return Scripted()


def _post(app, payload: dict) -> str:
    with TestClient(app) as client:
        response = client.post(
            "/invocations",
            json=payload,
            headers={"Authorization": "Bearer placeholder"},
        )
    assert response.status_code == 200, response.text[:500]
    return response.text


def _signed_in(agent_module) -> None:
    agent_module.extract_user_id_from_context = lambda context: "user-1"


@pytest.mark.parametrize("error_code", ["AccessDeniedException", "ValidationException"])
def test_strands_invocation_hides_interpreter_service_error(error_code: str):
    agent_module = _load_agent("strands-agent")
    _signed_in(agent_module)
    model_cls, original_stream = _scripted_strands_model()
    try:
        with _InterpreterClientPatch(_stubbed_interpreter_client(error_code)):
            body = _post(
                agent_module.app,
                {"prompt": "Run print(1) in the code interpreter.", "runtimeSessionId": "sess-1"},
            )
    finally:
        model_cls.stream = original_stream
    assert "execute_python_securely" in body
    _assert_caller_safe(body, error_code)


@pytest.mark.parametrize("error_code", ["AccessDeniedException", "ValidationException"])
def test_langgraph_invocation_hides_interpreter_service_error(error_code: str):
    from langgraph.checkpoint.memory import MemorySaver

    agent_module = _load_agent("langgraph-agent")
    _signed_in(agent_module)
    agent_module._build_model = _scripted_langgraph_model
    agent_module._create_checkpointer = lambda: MemorySaver()
    with _InterpreterClientPatch(_stubbed_interpreter_client(error_code)):
        body = _post(
            agent_module.app,
            {"prompt": "Run print(1) in the code interpreter.", "runtimeSessionId": "sess-1"},
        )
    assert "execute_python_securely" in body
    _assert_caller_safe(body, error_code)


@pytest.mark.parametrize("error_code", ["AccessDeniedException", "ValidationException"])
def test_agui_strands_invocation_hides_interpreter_service_error(
    error_code: str, tmp_path: Path
):
    from strands.session.file_session_manager import FileSessionManager

    agent_module = _load_agent("agui-strands-agent")
    _signed_in(agent_module)
    storage = tmp_path / "sessions"
    agent_module._create_session_manager = lambda user_id, session_id: FileSessionManager(
        session_id=session_id, storage_dir=str(storage)
    )
    model_cls, original_stream = _scripted_strands_model()
    try:
        with _InterpreterClientPatch(_stubbed_interpreter_client(error_code)):
            body = _post(
                agent_module.app,
                {
                    "threadId": f"thread-{error_code}",
                    "runId": "run-1",
                    "messages": [
                        {"id": "m1", "role": "user", "content": "Run print(1) in the code interpreter."}
                    ],
                },
            )
    finally:
        model_cls.stream = original_stream
    assert "TOOL_CALL_RESULT" in body
    _assert_caller_safe(body, error_code)


@pytest.mark.parametrize("error_code", ["AccessDeniedException", "ValidationException"])
def test_agui_langgraph_invocation_hides_interpreter_service_error(error_code: str):
    from langgraph.checkpoint.memory import MemorySaver

    agent_module = _load_agent("agui-langgraph-agent")
    _signed_in(agent_module)
    agent_module._build_model = _scripted_langgraph_model
    agent_module._create_checkpointer = lambda: MemorySaver()
    with _InterpreterClientPatch(_stubbed_interpreter_client(error_code)):
        body = _post(
            agent_module.app,
            {
                "threadId": f"thread-{error_code}",
                "runId": "run-1",
                "messages": [
                    {"id": "m1", "role": "user", "content": "Run print(1) in the code interpreter."}
                ],
            },
        )
    assert "TOOL_CALL_RESULT" in body
    _assert_caller_safe(body, error_code)


def _load_code_interpreter(agent_dirname: str):
    _purge_agent_modules()
    agent_dir = str(AGENT_CODE / agent_dirname)
    if agent_dir in sys.path:
        sys.path.remove(agent_dir)
    sys.path.insert(0, agent_dir)
    return importlib.import_module("code_int_mcp.server")


def _claude_result_text(result: dict) -> str:
    content = result["content"]
    assert content and content[0]["type"] == "text"
    return content[0]["text"]


def _assert_claude_failure(text: str, error_code: str) -> None:
    parsed = json.loads(text)
    assert parsed["success"] is False
    assert parsed["error"] == FIXED_FAILURE
    _assert_caller_safe(text, error_code)


@pytest.mark.parametrize(
    "agent_dirname",
    ["claude-sdk-agent", "claude-sdk-multi-agent"],
)
@pytest.mark.parametrize("error_code", ["AccessDeniedException", "ValidationException"])
@pytest.mark.parametrize(
    ("tool_name", "arguments"),
    [
        (
            "execute_code",
            {"code": "print(1)", "language": "python", "code_int_session_id": ""},
        ),
        ("execute_command", {"command": "ls", "code_int_session_id": ""}),
        (
            "write_files",
            {
                "files_to_create": [{"path": "a.txt", "text": "hi"}],
                "code_int_session_id": "",
            },
        ),
        ("read_files", {"paths": ["a.txt"], "code_int_session_id": ""}),
    ],
)
def test_claude_interpreter_tools_hide_service_error(
    agent_dirname: str, error_code: str, tool_name: str, arguments: dict
):
    server = _load_code_interpreter(agent_dirname)
    server.client.ci_client = _stubbed_interpreter_client(error_code)
    tool = getattr(server, tool_name)
    result = asyncio.run(tool.handler(arguments))
    _assert_claude_failure(_claude_result_text(result), error_code)


@pytest.mark.parametrize(
    "agent_dirname",
    ["claude-sdk-agent", "claude-sdk-multi-agent"],
)
def test_claude_interpreter_session_start_hides_service_error(agent_dirname: str):
    server = _load_code_interpreter(agent_dirname)
    server.client.ci_client = _stubbed_interpreter_client(
        "AccessDeniedException", fail_session=True
    )
    result = asyncio.run(
        server.execute_code.handler(
            {"code": "print(1)", "language": "python", "code_int_session_id": ""}
        )
    )
    _assert_claude_failure(_claude_result_text(result), "AccessDeniedException")
