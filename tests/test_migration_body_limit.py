"""Body-size contract for the migration adapter and the sample server it fronts.

The deployed migration preset builds migration/simulation/existing-ec2-agent and
forwards every AgentCore invocation to POST /run. A caller who can invoke that
runtime supplies the JSON body. These tests are the cap that body must meet:

* 1 MiB (1048576 bytes) is the largest Content-Length and the largest serialized
  invocation the two processes may accept.
* A larger or negative Content-Length is rejected with HTTP 413 before the
  server reads the socket, and the prompt is not passed to the agent.
* The adapter rejects the same oversized payload with ``{"status": "error",
  "code": 413}`` and does not open the child POST. A body at the limit is
  still forwarded, and a small prompt is still passed to the agent.

The tests fail while the server reads ``Content-Length`` with no maximum and
the adapter posts the invocation with no maximum.
"""

import importlib.util
import json
import socket
import sys
import threading
import types
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
MAX_BODY_BYTES = 1024 * 1024
REJECT_TIMEOUT_SECONDS = 2.0

# ── import the sample server and the adapter under test ──
_server_spec = importlib.util.spec_from_file_location(
    "migration_sample_server",
    REPO / "migration/simulation/existing-ec2-agent/server.py",
)
server = importlib.util.module_from_spec(_server_spec)
_server_spec.loader.exec_module(server)

try:
    import bedrock_agentcore.runtime  # noqa: F401
except ImportError:

    class _FakeApp:
        def entrypoint(self, fn):
            return fn

        def run(self, *args, **kwargs):
            raise RuntimeError("app.run() must not be reached in unit tests")

    _fake_runtime = types.ModuleType("bedrock_agentcore.runtime")
    _fake_runtime.BedrockAgentCoreApp = _FakeApp
    _fake_pkg = types.ModuleType("bedrock_agentcore")
    _fake_pkg.runtime = _fake_runtime
    sys.modules["bedrock_agentcore"] = _fake_pkg
    sys.modules["bedrock_agentcore.runtime"] = _fake_runtime

if "migration_adapter" in sys.modules:
    adapter = sys.modules["migration_adapter"]
else:
    _adapter_spec = importlib.util.spec_from_file_location(
        "migration_adapter", REPO / "migration/adapter/adapter.py"
    )
    adapter = importlib.util.module_from_spec(_adapter_spec)
    sys.modules["migration_adapter"] = adapter
    _adapter_spec.loader.exec_module(adapter)


class RecordingAgent:
    """Stand-in for the Strands agent. Records every prompt the server passes on."""

    def __init__(self):
        self.prompts = []
        self._lock = threading.Lock()

    def __call__(self, prompt):
        with self._lock:
            self.prompts.append(prompt)
        return "ok"


def _prompt_body(prompt: str) -> bytes:
    body = json.dumps({"prompt": prompt}).encode()
    return body


def _body_of_size(size: int) -> bytes:
    prefix = b'{"prompt":"'
    suffix = b'"}'
    pad = size - len(prefix) - len(suffix)
    assert pad > 0
    body = prefix + (b"A" * pad) + suffix
    assert len(body) == size
    return body


def _payload_of_serialized_size(size: int) -> dict:
    overhead = len(json.dumps({"prompt": ""}).encode())
    payload = {"prompt": "A" * (size - overhead)}
    raw = json.dumps(payload).encode()
    assert len(raw) == size, len(raw)
    return payload


def _request_head(content_length, *, include_length=True) -> bytes:
    lines = [
        "POST /run HTTP/1.1",
        "Host: 127.0.0.1",
        "Content-Type: application/json",
    ]
    if include_length:
        lines.append(f"Content-Length: {content_length}")
    lines.extend(["Connection: close", "", ""])
    return "\r\n".join(lines).encode()


def _status_code(raw: bytes) -> int:
    line = raw.split(b"\r\n", 1)[0]
    return int(line.split()[1])


def _http_exchange(port: int, head: bytes, body: bytes = b"", timeout: float = REJECT_TIMEOUT_SECONDS) -> bytes:
    """Send one request and return whatever the server writes before it goes quiet.

    The write side stays open when ``body`` is empty, so a handler that tries to
    read a declared body blocks instead of seeing EOF.
    """
    sock = socket.create_connection(("127.0.0.1", port), timeout=timeout)
    sock.settimeout(timeout)
    try:
        sock.sendall(head)
        if body:
            sock.sendall(body)
        chunks = []
        while True:
            try:
                block = sock.recv(65536)
            except TimeoutError:
                break
            if not block:
                break
            chunks.append(block)
        return b"".join(chunks)
    finally:
        sock.close()


@pytest.fixture
def sample_server():
    agent = RecordingAgent()
    server._agent = agent
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.Handler)
    # Join request threads on close so a handler unblocked by the client
    # cannot run get_agent() after the next test has replaced _agent.
    httpd.daemon_threads = False
    httpd.block_on_close = True
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield httpd.server_address[1], agent
    finally:
        httpd.shutdown()
        httpd.server_close()
        server._agent = None


class _RecordingChild(BaseHTTPRequestHandler):
    """Accepts any body and records how many POST bytes arrived."""

    def do_GET(self):
        if self.path == "/healthz":
            self._reply(200, b'{"status":"ok"}')
        else:
            self._reply(404, b"{}")

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        payload = self.rfile.read(length if length > 0 else 0)
        self.server.posts.append(len(payload))
        self._reply(200, b'{"answer":"ok"}')

    def _reply(self, code, body):
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        return


@pytest.fixture
def child_server():
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), _RecordingChild)
    httpd.posts = []
    httpd.daemon_threads = False
    httpd.block_on_close = True
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield httpd
    finally:
        httpd.shutdown()
        httpd.server_close()


def _assert_rejected_before_read(port: int, content_length) -> None:
    raw = _http_exchange(port, _request_head(content_length))
    assert raw, (
        "server blocked reading the socket instead of rejecting "
        f"Content-Length {content_length}"
    )
    assert _status_code(raw) == 413, raw.split(b"\r\n", 1)[0]


def test_server_rejects_oversized_content_length_before_reading(sample_server):
    port, agent = sample_server
    _assert_rejected_before_read(port, MAX_BODY_BYTES + 1)
    assert agent.prompts == []


def test_server_rejects_negative_content_length_before_reading(sample_server):
    port, agent = sample_server
    _assert_rejected_before_read(port, -1)
    assert agent.prompts == []


def test_server_does_not_pass_oversized_body_to_the_model(sample_server):
    port, agent = sample_server
    body = _body_of_size(MAX_BODY_BYTES + 1)
    raw = _http_exchange(port, _request_head(len(body)), body)
    if agent.prompts:
        pytest.fail(
            f"model was invoked {len(agent.prompts)} time(s); "
            f"first prompt is {len(agent.prompts[0])} bytes"
        )
    assert raw, "server did not answer the oversized POST"
    assert _status_code(raw) == 413, raw.split(b"\r\n", 1)[0]


def test_server_concurrent_oversized_bodies_do_not_reach_the_model(sample_server):
    port, agent = sample_server
    body = _body_of_size(MAX_BODY_BYTES + 1)
    statuses = []
    errors = []

    def one_request():
        try:
            raw = _http_exchange(port, _request_head(len(body)), body)
            statuses.append(_status_code(raw) if raw else 0)
        except Exception as exc:  # noqa: BLE001 — collect worker failures
            errors.append(exc)

    threads = [threading.Thread(target=one_request) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=10)
    assert not errors
    assert statuses == [413, 413]
    if agent.prompts:
        pytest.fail(
            f"model was invoked {len(agent.prompts)} time(s); "
            f"first prompt is {len(agent.prompts[0])} bytes"
        )


def test_server_accepts_a_body_at_the_limit_and_passes_the_prompt(sample_server):
    port, agent = sample_server
    body = _body_of_size(MAX_BODY_BYTES)
    raw = _http_exchange(port, _request_head(len(body)), body, timeout=5)
    assert _status_code(raw) == 200, raw.split(b"\r\n", 1)[0]
    assert len(agent.prompts) == 1
    assert agent.prompts[0] == "A" * (MAX_BODY_BYTES - len(b'{"prompt":""}'))


def test_server_accepts_a_small_prompt(sample_server):
    port, agent = sample_server
    body = _prompt_body("hello")
    raw = _http_exchange(port, _request_head(len(body)), body)
    assert _status_code(raw) == 200
    assert agent.prompts == ["hello"]


def test_server_without_content_length_does_not_read_a_trailing_body(sample_server):
    port, agent = sample_server
    trailing = _body_of_size(MAX_BODY_BYTES + 1)
    raw = _http_exchange(port, _request_head(None, include_length=False), trailing)
    assert raw, "server did not answer a POST with no Content-Length"
    status = _status_code(raw)
    if status == 200:
        assert agent.prompts == [""]
    else:
        assert status == 413
        assert agent.prompts == []
    assert not any(len(prompt) > MAX_BODY_BYTES for prompt in agent.prompts)


def _assert_not_forwarded(result, child):
    assert result.get("status") == "error" and result.get("code") == 413, result
    assert child.posts == [], (
        f"child received {len(child.posts)} POST(s); "
        f"first body is {child.posts[0] if child.posts else 0} bytes"
    )


def test_adapter_forward_rejects_an_oversized_payload_before_posting(child_server):
    payload = _payload_of_serialized_size(MAX_BODY_BYTES + 1)
    result = adapter.forward(
        payload, f"http://127.0.0.1:{child_server.server_address[1]}/run"
    )
    _assert_not_forwarded(result, child_server)


def test_adapter_forward_rejects_an_oversized_non_prompt_field(child_server):
    payload = {"prompt": "hi", "blob": "B" * (MAX_BODY_BYTES + 1)}
    assert len(json.dumps(payload).encode()) > MAX_BODY_BYTES
    result = adapter.forward(
        payload, f"http://127.0.0.1:{child_server.server_address[1]}/run"
    )
    _assert_not_forwarded(result, child_server)


def test_adapter_forward_sends_a_payload_at_the_limit(child_server):
    payload = _payload_of_serialized_size(MAX_BODY_BYTES)
    result = adapter.forward(
        payload, f"http://127.0.0.1:{child_server.server_address[1]}/run"
    )
    assert result == {"answer": "ok"}
    assert child_server.posts == [MAX_BODY_BYTES]


def test_adapter_invoke_rejects_an_oversized_payload_before_posting(child_server, monkeypatch):
    port = child_server.server_address[1]

    class Alive:
        def alive(self):
            return True

    monkeypatch.setattr(adapter, "_child", Alive())
    monkeypatch.setenv("MIGRATION_PORT", str(port))
    monkeypatch.setenv("MIGRATION_INVOKE_PATH", "/run")
    monkeypatch.setenv("MIGRATION_HEALTH_PATH", "/healthz")
    result = adapter.invoke(_payload_of_serialized_size(MAX_BODY_BYTES + 1))
    _assert_not_forwarded(result, child_server)


def test_runtime_entrypoint_rejects_an_oversized_invocation(child_server, monkeypatch):
    """POST /invocations on the real BedrockAgentCoreApp, when the SDK is installed.

    The adapter image installs bedrock-agentcore>=1.21.0 and does not set a
    Starlette body limit. This drives that entrypoint rather than calling
    invoke() directly. It skips only when the SDK was stubbed out.
    """
    if not hasattr(adapter.app, "router"):
        pytest.skip("bedrock_agentcore is not installed; the app object is a stub")
    pytest.importorskip("httpx")
    from starlette.testclient import TestClient

    port = child_server.server_address[1]

    class Alive:
        def alive(self):
            return True

    monkeypatch.setattr(adapter, "_child", Alive())
    monkeypatch.setenv("MIGRATION_PORT", str(port))
    monkeypatch.setenv("MIGRATION_INVOKE_PATH", "/run")
    monkeypatch.setenv("MIGRATION_HEALTH_PATH", "/healthz")
    payload = _payload_of_serialized_size(MAX_BODY_BYTES + 1)
    with TestClient(adapter.app) as client:
        response = client.post("/invocations", json=payload)
    assert response.status_code == 200
    _assert_not_forwarded(response.json(), child_server)
