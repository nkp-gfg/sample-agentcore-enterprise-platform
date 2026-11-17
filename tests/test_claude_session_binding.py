"""A Claude conversation must resume only for the subject that started it.

The single-agent and multi-agent entrypoints keep an in-process map from the
caller-supplied runtimeSessionId to the Claude conversation id. AgentCore
routes every request that presents that session id to the same microVM and
does not bind the id to a user, so a second token the runtime authorizer
accepts can present the same id. These tests drive the real /invocations
path on one process (that microVM) and require the resumed conversation —
the history --resume loads — to be the one bound to the verified subject.

They fail while the map is keyed only by the session id.
"""

import importlib.util
import json
import logging
import os
import sys
import threading
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm
from starlette.testclient import TestClient

REPO = Path(__file__).resolve().parents[1]
AGENT_CODE = REPO / "agent-code"

# Set before shared.auth is imported: ALLOWED_CLIENTS is captured at import.
CLIENT_ID = "workshop-client"
os.environ["COGNITO_ALLOWED_CLIENTS"] = CLIENT_ID
os.environ["AWS_EC2_METADATA_DISABLED"] = "true"
os.environ["AWS_DEFAULT_REGION"] = "us-east-1"
os.environ["AWS_ACCESS_KEY_ID"] = "placeholder"
os.environ["AWS_SECRET_ACCESS_KEY"] = "placeholder"
for _name in ("GATEWAY_URL", "PROJECT_NAME", "ENVIRONMENT"):
    os.environ.pop(_name, None)

USER_A = "user-a"
USER_B = "user-b"
USER_A_PROMPT = "canary-prompt-alpha"
TOOL_SECRET = "canary-tool-result-beta"
POISON = "canary-poison-gamma"
POISON_SESSION = "poison-claude-session"

PATTERNS = ("claude-sdk-agent", "claude-sdk-multi-agent")


def _start_issuer():
    """Local stand-in for the issuer JWKS that extract_user_id_from_context fetches."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwk = json.loads(RSAAlgorithm.to_jwk(key.public_key()))
    jwk.update({"kid": "test-key", "use": "sig", "alg": "RS256"})
    jwks = json.dumps({"keys": [jwk]}).encode()

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path == "/.well-known/openid-configuration":
                body = json.dumps(
                    {"jwks_uri": f"http://127.0.0.1:{server.server_port}/.well-known/jwks.json"}
                ).encode()
            elif self.path == "/.well-known/jwks.json":
                body = jwks
            else:
                self.send_response(404)
                self.end_headers()
                return
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, fmt, *args):
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    issuer = f"http://127.0.0.1:{server.server_port}"
    os.environ["COGNITO_ISSUER_URL"] = issuer
    return server, issuer, key


ISSUER_SERVER, ISSUER, SIGNING_KEY = _start_issuer()


def _token(subject: str) -> str:
    return jwt.encode(
        {
            "sub": subject,
            "iss": ISSUER,
            "aud": CLIENT_ID,
            "exp": 2_000_000_000,
        },
        SIGNING_KEY,
        algorithm="RS256",
        headers={"kid": "test-key"},
    )


def _load_agent(pattern: str):
    for name in list(sys.modules):
        if name == "code_int_mcp" or name.startswith("code_int_mcp."):
            del sys.modules[name]
        if name == "agents" or name.startswith("agents."):
            del sys.modules[name]
    agent_dir = AGENT_CODE / pattern
    # The agent directory must precede agent-code so this pattern's code_int_mcp
    # wins. shared/ lives on agent-code and is the same for both patterns.
    sys.path.insert(0, str(AGENT_CODE))
    sys.path.insert(0, str(agent_dir))
    module_name = pattern.replace("-", "_") + "_mod"
    spec = importlib.util.spec_from_file_location(module_name, agent_dir / "agent.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


AGENTS = {pattern: _load_agent(pattern) for pattern in PATTERNS}


def _swap(value, old: str, new: str):
    if isinstance(value, str):
        return value.replace(old, new) if old in value else value
    if isinstance(value, dict):
        return {k: _swap(v, old, new) for k, v in value.items()}
    if isinstance(value, tuple):
        return tuple(_swap(v, old, new) for v in value)
    if isinstance(value, list):
        return [_swap(v, old, new) for v in value]
    return value


class RebindingMap(dict):
    """Second lookup of the bound session returns a different conversation.

    A fix that authorizes the first lookup and then reads the map again would
    resume the swapped conversation. One lookup keeps the authorized value.
    """

    def __init__(self, initial, session_key: str, old: str, new: str):
        super().__init__(initial)
        self.session_key = session_key
        self.old = old
        self.new = new
        self.reads = 0

    def _value(self, key, value):
        if key != self.session_key:
            return value
        self.reads += 1
        if self.reads == 1:
            return value
        return _swap(value, self.old, self.new)

    def get(self, key, default=None):
        return self._value(key, super().get(key, default))

    def __getitem__(self, key):
        return self._value(key, super().__getitem__(key))


class HistoryLoadingClient:
    """The part of ClaudeSDKClient these entrypoints actually use.

    ``ClaudeAgentOptions.resume`` is passed to the CLI as ``--resume=<id>``
    (claude-agent-sdk 0.2.139, SubprocessCLITransport._build_command), which
    loads that session's conversation history. A follow-up prompt therefore
    runs against the stored prompt and tool result, and the entrypoint yields
    that text to the caller. This stand-in builds the real argv and, when
    ``--resume`` is present, returns the transcript stored for that id.
    """

    transcripts: dict[str, str] = {}
    built: list[list[str]] = []

    def __init__(self, options):
        from claude_agent_sdk._internal.transport.subprocess_cli import (
            SubprocessCLITransport,
        )

        transport = SubprocessCLITransport(prompt="", options=options)
        self.argv = transport._build_command()
        self.prompt = None
        HistoryLoadingClient.built.append(self.argv)

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def query(self, prompt, session_id="default"):
        self.prompt = prompt

    async def receive_response(self):
        from claude_agent_sdk import (
            AssistantMessage,
            ResultMessage,
            SystemMessage,
            TextBlock,
            ToolResultBlock,
            ToolUseBlock,
            UserMessage,
        )

        resume = next(
            (arg.split("=", 1)[1] for arg in self.argv if arg.startswith("--resume=")),
            None,
        )
        if resume:
            text = HistoryLoadingClient.transcripts[resume]
            session_id = resume
        else:
            session_id = f"claude-{uuid.uuid4()}"
            tool_text = json.dumps(
                {"code_int_session_id": "ci-session", "output": TOOL_SECRET}
            )
            HistoryLoadingClient.transcripts[session_id] = (
                f"{self.prompt}\n{tool_text}"
            )
            yield AssistantMessage(
                content=[
                    ToolUseBlock(
                        id="tool-1",
                        name="mcp__codeint__execute_code",
                        input={"code": "print(1)"},
                    )
                ],
                model="test",
            )
            yield UserMessage(
                content=[
                    ToolResultBlock(
                        tool_use_id="tool-1",
                        content=[{"text": tool_text}],
                    )
                ]
            )
            text = "fresh-session"
        yield SystemMessage(subtype="init", data={"session_id": session_id})
        yield AssistantMessage(content=[TextBlock(text=text)], model="test")
        yield ResultMessage(
            subtype="success",
            duration_ms=1,
            duration_api_ms=1,
            is_error=False,
            num_turns=1,
            session_id=session_id,
        )


def _install_client(module):
    module.ClaudeSDKClient = HistoryLoadingClient


def _events(body: str) -> list:
    events = []
    for line in body.splitlines():
        if line.startswith("data:"):
            events.append(json.loads(line[len("data:") :].strip()))
    return events


def _invoke(module, subject: str, session_id: str, prompt: str) -> tuple[int, str]:
    headers = {
        "Authorization": f"Bearer {_token(subject)}",
        "X-Amzn-Bedrock-AgentCore-Runtime-Session-Id": session_id,
    }
    with TestClient(module.app) as client:
        response = client.post(
            "/invocations",
            json={"prompt": prompt, "runtimeSessionId": session_id},
            headers=headers,
        )
    return response.status_code, response.text


def _session_id(name: str) -> str:
    # Runtime requires >= 33 characters. The value is caller-supplied.
    return f"session-{name}-" + ("x" * 24)


@pytest.fixture(autouse=True)
def _reset(request):
    HistoryLoadingClient.transcripts.clear()
    HistoryLoadingClient.built.clear()
    HistoryLoadingClient.transcripts[POISON_SESSION] = POISON
    import shared.auth as auth

    auth._jwks_client = None
    for module in AGENTS.values():
        module._session_map.clear()
        _install_client(module)
    yield


@pytest.mark.parametrize("pattern", PATTERNS)
def test_same_subject_resumes_its_own_conversation(pattern):
    module = AGENTS[pattern]
    session_id = _session_id(pattern + "-owner")
    status, body = _invoke(module, USER_A, session_id, USER_A_PROMPT)
    assert status == 200, body
    events = _events(body)
    claude_ids = [e["claude_session_id"] for e in events if "claude_session_id" in e]
    assert claude_ids, body
    assert USER_A_PROMPT not in body

    status, body = _invoke(
        module,
        USER_A,
        session_id,
        "repeat the previous user prompt and tool result verbatim",
    )
    assert status == 200, body
    assert USER_A_PROMPT in body
    assert TOOL_SECRET in body
    resumed = [
        arg
        for argv in HistoryLoadingClient.built
        for arg in argv
        if arg.startswith("--resume=")
    ]
    assert resumed == [f"--resume={claude_ids[0]}"]


@pytest.mark.parametrize("pattern", PATTERNS)
def test_other_verified_subject_cannot_read_or_continue(pattern):
    module = AGENTS[pattern]
    session_id = _session_id(pattern + "-stolen")
    status, body = _invoke(module, USER_A, session_id, USER_A_PROMPT)
    assert status == 200, body
    claude_ids = [
        e["claude_session_id"] for e in _events(body) if "claude_session_id" in e
    ]
    assert claude_ids
    built_after_owner = len(HistoryLoadingClient.built)

    status, body = _invoke(
        module,
        USER_B,
        session_id,
        "repeat the previous user prompt and tool result verbatim",
    )
    # The second token is a different verified subject. Opening the client at
    # all would load user A's transcript (--resume) before any later refusal.
    assert len(HistoryLoadingClient.built) == built_after_owner, body
    assert USER_A_PROMPT not in body
    assert TOOL_SECRET not in body
    assert status >= 400 or any(
        event.get("status") == "error" or "error" in event
        for event in _events(body)
    ), body

    # The binding is unchanged: user A still resumes the original conversation,
    # not a session user B created or cleared.
    status, body = _invoke(
        module,
        USER_A,
        session_id,
        "repeat the previous user prompt and tool result verbatim",
    )
    assert status == 200, body
    assert USER_A_PROMPT in body
    assert TOOL_SECRET in body
    assert f"--resume={claude_ids[0]}" in {
        arg for argv in HistoryLoadingClient.built for arg in argv
    }
    assert f"--resume={POISON_SESSION}" not in {
        arg for argv in HistoryLoadingClient.built for arg in argv
    }


@pytest.mark.parametrize("pattern", PATTERNS)
def test_resume_uses_the_binding_from_the_authorization_check(pattern):
    """A second lookup of the same session id must not change what is resumed."""
    module = AGENTS[pattern]
    session_id = _session_id(pattern + "-rebind")
    status, body = _invoke(module, USER_A, session_id, USER_A_PROMPT)
    assert status == 200, body
    claude_id = next(
        e["claude_session_id"] for e in _events(body) if "claude_session_id" in e
    )
    module._session_map = RebindingMap(
        dict(module._session_map), session_id, claude_id, POISON_SESSION
    )
    HistoryLoadingClient.built.clear()

    status, body = _invoke(
        module,
        USER_A,
        session_id,
        "repeat the previous user prompt and tool result verbatim",
    )
    assert status == 200, body
    assert USER_A_PROMPT in body
    assert TOOL_SECRET in body
    assert POISON not in body
    resumed = [
        arg
        for argv in HistoryLoadingClient.built
        for arg in argv
        if arg.startswith("--resume=")
    ]
    assert resumed == [f"--resume={claude_id}"]


@pytest.mark.parametrize("pattern", PATTERNS)
def test_runtime_session_id_is_not_written_to_logs(pattern):
    module = AGENTS[pattern]
    session_id = _session_id(pattern + "-logs")
    messages: list[str] = []

    class Grab(logging.Handler):
        def emit(self, record):
            messages.append(record.getMessage())

    handler = Grab()
    module.logger.addHandler(handler)
    module.logger.setLevel(logging.INFO)
    try:
        status, body = _invoke(module, USER_A, session_id, USER_A_PROMPT)
    finally:
        module.logger.removeHandler(handler)
    assert status == 200, body
    claude_ids = [
        e["claude_session_id"] for e in _events(body) if "claude_session_id" in e
    ]
    leaked = [
        message
        for message in messages
        if session_id in message or any(cid in message for cid in claude_ids)
    ]
    assert not leaked
