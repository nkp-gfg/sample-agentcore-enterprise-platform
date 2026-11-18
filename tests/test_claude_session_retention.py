"""Session-retention behavior of the Claude agent entrypoints.

These tests drive the real entrypoint (`main`) that
`BedrockAgentCoreApp._handle_invocation` calls with the JSON body unchanged.
The Claude CLI is replaced by a transport that speaks the SDK control
protocol and returns one result message; `claude_agent_sdk` still parses
that message into a `ResultMessage` and the agent stores
`payload["runtimeSessionId"]` from it.

The assertions describe the bound the process must enforce. They fail while
every successful turn is retained with no cap, no session-id check, and no
binding to the verified token subject.
"""

from __future__ import annotations

import asyncio
import importlib.util
import json
import os
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm
from starlette.datastructures import Headers

REPO = Path(__file__).resolve().parents[1]
AGENT_CODE = REPO / "agent-code"

# Process-wide cap the entrypoints must enforce. Any smaller cap also passes.
MAX_RETAINED_SESSIONS = 64
SESSION_ID_MIN = 33
SESSION_ID_MAX = 128

_PRIVATE = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_PUBLIC_JWK = json.loads(RSAAlgorithm.to_jwk(_PRIVATE.public_key()))
_PUBLIC_JWK.update({"kid": "test-key", "use": "sig", "alg": "RS256"})


class _JwksHandler(BaseHTTPRequestHandler):
    issuer = ""

    def do_GET(self):
        if self.path.startswith("/.well-known/openid-configuration"):
            body = json.dumps({"jwks_uri": f"{self.issuer}/jwks"}).encode()
        elif self.path.startswith("/jwks"):
            body = json.dumps({"keys": [_PUBLIC_JWK]}).encode()
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


def _start_issuer() -> str:
    server = ThreadingHTTPServer(("127.0.0.1", 0), _JwksHandler)
    issuer = f"http://127.0.0.1:{server.server_address[1]}"
    _JwksHandler.issuer = issuer
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return issuer


ISSUER = _start_issuer()
os.environ["COGNITO_ISSUER_URL"] = ISSUER
os.environ["COGNITO_ALLOWED_CLIENTS"] = "client-allowed"
os.environ.pop("GATEWAY_URL", None)
os.environ.pop("PROJECT_NAME", None)
os.environ["AWS_EC2_METADATA_DISABLED"] = "true"
os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")
os.environ.setdefault("AWS_ACCESS_KEY_ID", "test")
os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "test")


def _token(subject: str) -> str:
    return jwt.encode(
        {
            "sub": subject,
            "iss": ISSUER,
            "aud": "client-allowed",
            "client_id": "client-allowed",
            "token_use": "access",
            "exp": int(time.time()) + 3600,
        },
        _PRIVATE,
        algorithm="RS256",
        headers={"kid": "test-key"},
    )


def _load_agent(directory: str, module_name: str):
    """Import one agent tree the way its container does: that pattern's
    directory on sys.path ahead of the shared package."""
    for name in list(sys.modules):
        if name == "code_int_mcp" or name.startswith("code_int_mcp."):
            del sys.modules[name]
        if name == "agents" or name.startswith("agents."):
            del sys.modules[name]
    agent_dir = str(AGENT_CODE / directory)
    sys.path.insert(0, str(AGENT_CODE))
    sys.path.insert(0, agent_dir)
    spec = importlib.util.spec_from_file_location(
        module_name, AGENT_CODE / directory / "agent.py"
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    # Drop the pattern directory so the next pattern does not shadow shared.
    sys.path.remove(agent_dir)
    return module


class _ScriptedTransport:
    """Minimal stand-in for the Claude CLI stdout stream.

    Built from claude-agent-sdk 0.2.139:
    - Query._send_control_request writes a control_request and waits for
      control_response (query.py).
    - client.query writes a user message (client.py).
    - message_parser.parse_message turns a type=result object into
      ResultMessage, which receive_response yields and then returns.
    """

    def __init__(self, claude_session_id: str, seen: list):
        self._claude_session_id = claude_session_id
        self._seen = seen
        self._queue: asyncio.Queue = asyncio.Queue()
        self._ready = False
        self._closed = False

    async def connect(self) -> None:
        self._ready = True

    def is_ready(self) -> bool:
        return self._ready

    async def write(self, data: str) -> None:
        message = json.loads(data)
        self._seen.append(message)
        if message.get("type") == "control_request":
            await self._queue.put(
                {
                    "type": "control_response",
                    "response": {
                        "subtype": "success",
                        "request_id": message["request_id"],
                        "response": {},
                    },
                }
            )
        elif message.get("type") == "user":
            await self._queue.put(
                {
                    "type": "result",
                    "subtype": "success",
                    "duration_ms": 1,
                    "duration_api_ms": 1,
                    "is_error": False,
                    "num_turns": 1,
                    "session_id": self._claude_session_id,
                    "stop_reason": "end_turn",
                }
            )

    async def read_messages(self):
        while not self._closed:
            yield await self._queue.get()

    async def end_input(self) -> None:
        return None

    async def close(self) -> None:
        self._closed = True
        self._ready = False
        await self._queue.put({"type": "end"})


def _install_client(module):
    """Route ClaudeSDKClient through the real SDK with a scripted transport."""
    real = module.ClaudeSDKClient
    state = {"n": 0, "resumes": [], "constructed": 0}

    class _Client(real):
        def __init__(self, options=None, transport=None):
            state["constructed"] += 1
            state["n"] += 1
            state["resumes"].append(getattr(options, "resume", None))
            super().__init__(
                options=options,
                transport=_ScriptedTransport(f"claude-{state['n']}", []),
            )

    module.ClaudeSDKClient = _Client
    return state


def _context(module, token: str):
    return module.RequestContext(request_headers={"Authorization": f"Bearer {token}"})


async def _turn(module, token: str, session_id: str, prompt: str = "hi"):
    events = []
    async for event in module.main(
        {"prompt": prompt, "runtimeSessionId": session_id},
        _context(module, token),
    ):
        events.append(event)
    return events


def _session_id(index: int) -> str:
    return f"sess{index:036d}"


@pytest.fixture()
def single_agent():
    module = _load_agent("claude-sdk-agent", "claude_single_agent_under_test")
    state = _install_client(module)
    return module, state


@pytest.fixture()
def multi_agent():
    module = _load_agent("claude-sdk-multi-agent", "claude_multi_agent_under_test")
    state = _install_client(module)
    return module, state


def test_single_agent_drops_sessions_past_the_cap(single_agent):
    """One caller opening a new session id per turn must not retain them all."""
    module, state = single_agent
    token = _token("user-a")
    before = state["constructed"]

    async def _run():
        for index in range(MAX_RETAINED_SESSIONS + 1):
            await _turn(module, token, _session_id(index))
        # The earliest id has to have been evicted: resuming it must not
        # hand the model the claude id stored on its first turn.
        state["resumes"].clear()
        await _turn(module, token, _session_id(0))

    asyncio.run(_run())

    assert state["constructed"] > before
    assert state["resumes"][-1] != "claude-1"


def test_single_agent_rejects_session_id_before_model_call(single_agent):
    """A session id outside the fixed length and charset is not stored and
    does not start a model call."""
    module, state = single_agent
    token = _token("user-a")
    rejected = [
        "short",
        "a" * (SESSION_ID_MIN - 1),
        "a" * (SESSION_ID_MAX + 1),
        ("a" * (SESSION_ID_MIN - 1)) + "!",
        "A" * 100_000,
        "session id with spaces and punctuation!!!",
    ]

    async def _run():
        for session_id in rejected:
            constructed = state["constructed"]
            events = await _turn(module, token, session_id)
            assert state["constructed"] == constructed, session_id
            assert any(
                isinstance(event, dict) and event.get("status") == "error"
                for event in events
            ), session_id

    asyncio.run(_run())


def test_single_agent_sessions_are_bound_to_the_verified_subject(single_agent):
    """The same caller-supplied session id for two subjects must not resume
    the other subject's Claude conversation."""
    module, state = single_agent

    async def _run():
        await _turn(module, _token("user-a"), _session_id(7))
        state["resumes"].clear()
        await _turn(module, _token("user-b"), _session_id(7))

    asyncio.run(_run())
    assert state["resumes"][-1] is None


def test_multi_agent_drops_sessions_past_the_cap(multi_agent):
    module, state = multi_agent
    token = _token("user-a")

    async def _run():
        for index in range(MAX_RETAINED_SESSIONS + 1):
            await _turn(module, token, _session_id(1000 + index))
        state["resumes"].clear()
        await _turn(module, token, _session_id(1000))

    asyncio.run(_run())
    assert state["resumes"][-1] != "claude-1"


def test_multi_agent_rejects_session_id_before_model_call(multi_agent):
    module, state = multi_agent
    token = _token("user-a")

    async def _run():
        constructed = state["constructed"]
        events = await _turn(module, token, "A" * 100_000)
        assert state["constructed"] == constructed
        assert any(
            isinstance(event, dict) and event.get("status") == "error"
            for event in events
        )

    asyncio.run(_run())


def test_multi_agent_sessions_are_bound_to_the_verified_subject(multi_agent):
    module, state = multi_agent

    async def _run():
        await _turn(module, _token("user-a"), _session_id(8))
        state["resumes"].clear()
        await _turn(module, _token("user-b"), _session_id(8))

    asyncio.run(_run())
    assert state["resumes"][-1] is None


def test_http_invocation_delivers_body_session_id_to_the_same_map(single_agent):
    """POST /invocations passes the JSON body through to the entrypoint.
    A second call with the same body session id resumes the stored claude id,
    which is only possible if the first call retained it in-process."""
    module, state = single_agent
    token = _token("user-http")
    session_id = _session_id(42)

    class _Request:
        def __init__(self, payload):
            self.headers = Headers({"authorization": f"Bearer {token}"})
            self._payload = payload

        async def json(self):
            return self._payload

    async def _invoke(prompt: str):
        response = await module.app._handle_invocation(
            _Request({"prompt": prompt, "runtimeSessionId": session_id})
        )
        iterator = response.body_iterator
        if hasattr(iterator, "__aiter__"):
            async for _chunk in iterator:
                pass
        else:
            for _chunk in iterator:
                pass

    async def _run():
        await _invoke("first")
        state["resumes"].clear()
        await _invoke("second")

    asyncio.run(_run())
    # Vulnerable behavior: the second invocation of the same process resumes
    # the claude id from the first. A cap does not remove a single live
    # session, so this stays true after a fix. It pins the HTTP path.
    assert state["resumes"][-1] == f"claude-{state['n'] - 1}"
