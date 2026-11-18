"""Assistant replies must not be copied into the runtime logger.

The Claude single-agent and multi-agent entrypoints are what
``@app.entrypoint`` registers and what the container runs
(``opentelemetry-instrument python -m agent``). A caller supplies ``prompt``
on the invocation payload. The entrypoint forwards that prompt to
``ClaudeSDKClient.query`` and then logs every assistant ``TextBlock`` at INFO
before yielding it on the response stream.

These tests drive that entrypoint. The model subprocess is replaced by a
client that feeds CLI JSON through ``parse_message`` — the same parser
``ClaudeSDKClient.receive_messages`` uses — and then runs the real
entrypoint loop. They fail while the full assistant text is still passed to
the logger, including text the reply repeats from the caller or from a code
interpreter tool result. They pass once that text is no longer logged at any
level. The response stream is still required to carry the reply.

Not covered here: the ``stderr=`` callback on ``ClaudeAgentOptions`` logs each
Claude CLI stderr line verbatim. This suite does not run the CLI, so it does
not show whether those lines contain conversation content.
"""

from __future__ import annotations

import asyncio
import importlib.util
import io
import json
import logging
import sys
import uuid
from pathlib import Path
from typing import ClassVar

import pytest

pytest.importorskip("claude_agent_sdk")
pytest.importorskip("bedrock_agentcore")

from claude_agent_sdk import ProcessError, ResultMessage
from claude_agent_sdk._internal.message_parser import parse_message

REPO = Path(__file__).resolve().parents[1]
AGENT_CODE = REPO / "agent-code"

# Markers are unique per test. None of them may appear in a log record or in
# the INFO stream basicConfig writes (StreamHandler to stderr, level INFO).
REPLY = "reply"
TOOL_OUTPUT = "tool-output"
TOOL_INPUT = "tool-input"
THINKING = "thinking"
PROMPT_ONLY = "prompt-only"


def _marker(kind: str) -> str:
    return f"MARKER-{kind}-{uuid.uuid4().hex}"


def _load_entrypoint(pattern: str):
    """Import one pattern's agent.py as the registered runtime entrypoint.

    Each pattern directory has its own ``code_int_mcp`` package, so a previous
    pattern's copy is dropped before this one is loaded. ``shared`` is the
    same tree for both.
    """
    pattern_dir = AGENT_CODE / pattern
    for name in list(sys.modules):
        if (
            name == "claude_entrypoint_under_test"
            or name == "code_int_mcp"
            or name.startswith(("code_int_mcp.", "agents", "agents."))
        ):
            del sys.modules[name]
    for path in (str(AGENT_CODE), str(pattern_dir)):
        if path in sys.path:
            sys.path.remove(path)
        sys.path.insert(0, path)
    spec = importlib.util.spec_from_file_location(
        "claude_entrypoint_under_test",
        pattern_dir / "agent.py",
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules["claude_entrypoint_under_test"] = module
    spec.loader.exec_module(module)
    assert module.app.handlers["main"] is module.main
    return module


class _ScriptedClaudeSDKClient:
    """Transport stand-in whose messages are parsed by the real SDK parser.

    ``ClaudeSDKClient.receive_messages`` does ``parse_message`` on each CLI
    dict and ``receive_response`` stops after ``ResultMessage``. This client
    does those two steps and nothing else, so the entrypoint sees the same
    objects the SDK would hand it.
    """

    pending: ClassVar[list] = []
    constructed: ClassVar[list] = []

    def __init__(self, options=None):
        self.options = options
        self.prompt = None
        _ScriptedClaudeSDKClient.constructed.append(self)

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def query(self, prompt, session_id="default"):
        self.prompt = prompt

    async def receive_response(self):
        item = _ScriptedClaudeSDKClient.pending.pop(0)
        if isinstance(item, BaseException):
            raise item
        for raw in item:
            message = parse_message(raw)
            if message is None:
                continue
            yield message
            if isinstance(message, ResultMessage):
                return


def _assistant(blocks: list[dict], *, parent_tool_use_id: str | None = None) -> dict:
    message = {
        "type": "assistant",
        "session_id": "claude-session",
        "message": {
            "role": "assistant",
            "model": "claude-test",
            "id": "msg-1",
            "stop_reason": "end_turn",
            "content": blocks,
        },
    }
    if parent_tool_use_id is not None:
        message["parent_tool_use_id"] = parent_tool_use_id
    return message


def _conversation(
    markers: dict[str, str], *, parent_tool_use_id: str | None = None
) -> list[dict]:
    """CLI JSON for one turn: thinking, tool use, tool result, then the reply.

    The reply text repeats the caller's secret and the code-interpreter
    output. ``prompt-only`` stays in the invocation payload and is not part
    of any message the parser returns.
    """
    tool_result_body = json.dumps(
        {
            "code_int_session_id": "ci-session-1",
            "output": markers[TOOL_OUTPUT],
        }
    )
    reply = (
        f"Code interpreter output {markers[TOOL_OUTPUT]}. "
        f"Repeating the caller text {markers[REPLY]}."
    )
    return [
        {
            "type": "system",
            "subtype": "init",
            "session_id": "claude-session",
            "data": {"session_id": "claude-session"},
        },
        _assistant(
            [
                {
                    "type": "thinking",
                    "thinking": markers[THINKING],
                    "signature": "sig",
                },
                {
                    "type": "tool_use",
                    "id": "toolu_1",
                    "name": "mcp__codeint__execute_code",
                    "input": {
                        "code": f"print({markers[TOOL_INPUT]!r})",
                        "language": "python",
                        "code_int_session_id": "",
                    },
                },
            ]
        ),
        {
            "type": "user",
            "message": {
                "role": "user",
                "content": [
                    {
                        "type": "tool_result",
                        "tool_use_id": "toolu_1",
                        "content": [{"type": "text", "text": tool_result_body}],
                    }
                ],
            },
        },
        _assistant(
            [{"type": "text", "text": reply}],
            parent_tool_use_id=parent_tool_use_id,
        ),
        {
            "type": "result",
            "subtype": "success",
            "duration_ms": 1,
            "duration_api_ms": 1,
            "is_error": False,
            "num_turns": 1,
            "session_id": "claude-session",
        },
    ]


def _payload(markers: dict[str, str], session_id: str) -> dict:
    body = {
        "prompt": (
            f"Repeat {markers[REPLY]} back to me. "
            f"Leave {markers[PROMPT_ONLY]} out of the answer."
        ),
        "runtimeSessionId": session_id,
    }
    # Same JSON decode the runtime does before it calls the entrypoint.
    return json.loads(json.dumps(body))


async def _collect(agent, payload):
    context = object()
    events = []
    async for event in agent.main(payload, context):
        events.append(event)
    return events


def _run(agent, payload, scripts, *, prior_session: str | None = None):
    _ScriptedClaudeSDKClient.pending = list(scripts)
    _ScriptedClaudeSDKClient.constructed = []
    agent._session_map.clear()
    if prior_session is not None:
        agent._session_map[payload["runtimeSessionId"]] = prior_session
    agent.ClaudeSDKClient = _ScriptedClaudeSDKClient
    agent.extract_user_id_from_context = lambda context: "user-1"

    # Observe every level. basicConfig in the entrypoint sets the root logger
    # to INFO and attaches a StreamHandler; a second handler here records the
    # same records, and the StringIO handler is the INFO stderr stream.
    root = logging.getLogger()
    previous_level = root.level
    root.setLevel(logging.DEBUG)
    records: list[logging.LogRecord] = []

    class _Collect(logging.Handler):
        def emit(self, record):
            records.append(record)

    collect = _Collect(level=logging.DEBUG)
    info_stream = io.StringIO()
    info_handler = logging.StreamHandler(info_stream)
    info_handler.setLevel(logging.INFO)
    info_handler.setFormatter(logging.Formatter(logging.BASIC_FORMAT))
    root.addHandler(collect)
    root.addHandler(info_handler)
    try:
        events = asyncio.run(_collect(agent, payload))
    finally:
        root.removeHandler(collect)
        root.removeHandler(info_handler)
        root.setLevel(previous_level)
    logged = "\n".join(record.getMessage() for record in records)
    logged += "\n" + info_stream.getvalue()
    return events, logged


def _assert_reply_is_returned_and_not_logged(events, logged, markers, reply_fragment):
    returned = [event.get("data") for event in events if isinstance(event, dict)]
    assert any(reply_fragment in (item or "") for item in returned), (
        "entrypoint did not yield the assistant text, so the log assertion "
        "would not be exercising the response path"
    )
    leaked = [kind for kind, marker in markers.items() if marker in logged]
    assert leaked == [], (
        f"runtime logger received conversation content (kinds: {', '.join(leaked)})"
    )


@pytest.fixture(autouse=True)
def _no_gateway(monkeypatch):
    """Keep gateway resolution on the in-process miss path (no SSM or token call)."""
    for name in (
        "GATEWAY_URL",
        "PROJECT_NAME",
        "ENVIRONMENT",
        "GATEWAY_CREDENTIAL_PROVIDER_NAME",
    ):
        monkeypatch.delenv(name, raising=False)


@pytest.mark.parametrize(
    "pattern",
    ["claude-sdk-agent", "claude-sdk-multi-agent"],
)
def test_entrypoint_does_not_log_assistant_text(pattern):
    agent = _load_entrypoint(pattern)
    markers = {
        kind: _marker(kind)
        for kind in (REPLY, TOOL_OUTPUT, TOOL_INPUT, THINKING, PROMPT_ONLY)
    }
    parent = "task-tool-use" if pattern == "claude-sdk-multi-agent" else None
    events, logged = _run(
        agent,
        _payload(markers, f"session-{pattern}"),
        [_conversation(markers, parent_tool_use_id=parent)],
    )
    reply = markers[REPLY]
    _assert_reply_is_returned_and_not_logged(events, logged, markers, reply)
    assert _ScriptedClaudeSDKClient.constructed[0].prompt is not None
    assert markers[PROMPT_ONLY] in _ScriptedClaudeSDKClient.constructed[0].prompt
    assert markers[PROMPT_ONLY] not in "".join(
        event.get("data", "") for event in events if isinstance(event, dict)
    )


@pytest.mark.parametrize(
    "pattern",
    ["claude-sdk-agent", "claude-sdk-multi-agent"],
)
def test_resume_retry_does_not_log_assistant_text(pattern):
    """A failed resume starts a fresh session through the same logger."""
    agent = _load_entrypoint(pattern)
    markers = {
        kind: _marker(kind)
        for kind in (REPLY, TOOL_OUTPUT, TOOL_INPUT, THINKING, PROMPT_ONLY)
    }
    session_id = f"resume-{pattern}"
    events, logged = _run(
        agent,
        _payload(markers, session_id),
        [
            ProcessError("resume failed"),
            _conversation(markers),
        ],
        prior_session="prior-claude-session",
    )
    _assert_reply_is_returned_and_not_logged(events, logged, markers, markers[REPLY])
    assert len(_ScriptedClaudeSDKClient.constructed) == 2
    assert (
        _ScriptedClaudeSDKClient.constructed[0].options.resume == "prior-claude-session"
    )
    assert _ScriptedClaudeSDKClient.constructed[1].options.resume is None
