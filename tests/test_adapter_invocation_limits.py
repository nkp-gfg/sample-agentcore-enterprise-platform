"""Invocation-forward limits for the migration adapter.

The migrated runtime's entrypoint is ``adapter.invoke``. It forwards the
caller's payload to the customer process with ``adapter.forward``. These tests
run that path against a local child HTTP server (the same shape of stub the
existing adapter tests use). They fail while ``urlopen`` has no deadline and
while success bodies, error bodies, and event streams are read without a byte
cap or a total duration cap.

Contract the forward must meet, measured from the call:

- ``MAX_FORWARD_SECONDS`` (5s) is a total deadline. A child that accepts the
  POST and then keeps the connection open — by sending nothing, or by
  dribbling bytes so a per-read socket timeout never fires — must produce a
  structured error ``{"status": "error", "code": 504, "error": <non-empty str>}``
  and close the child connection before that deadline.
- ``MAX_RESPONSE_BYTES`` (256 KiB) is a cap on bytes read from the child. It
  applies to a 2xx body (``resp.read``), a non-2xx body (``HTTPError.read``),
  and a ``text/event-stream`` body (``_stream_events``). Crossing it returns
  the same 504 object and closes the child connection. The child must not be
  able to deliver the rest of the body into the adapter.
- ``MAX_STREAM_SECONDS`` is the same 5s total deadline applied while an event
  stream stays open under the byte cap.

A small JSON reply, a small non-2xx body, and a short event stream still pass
through unchanged. Health probes are not part of this contract; they already
pass a timeout.
"""

import importlib.util
import inspect
import json
import socket
import sys
import threading
import time
import types
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]

# ── limits the invocation forward must enforce ──
MAX_FORWARD_SECONDS = 5.0
MAX_STREAM_SECONDS = 5.0
MAX_RESPONSE_BYTES = 256 * 1024
# A deadline implemented at the cap still has to be observed before this.
OBSERVE_SECONDS = MAX_FORWARD_SECONDS + 3.0
# One extra small write may land in the kernel after the adapter stops.
BYTES_SLACK = 64 * 1024
CHUNK = 32 * 1024
OVERSIZED_BODY = 2 * 1024 * 1024

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

_spec = importlib.util.spec_from_file_location(
    "migration_adapter_limits", REPO / "migration/adapter" / "adapter.py"
)
adapter = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(adapter)


def _is_504(value) -> bool:
    return (
        isinstance(value, dict)
        and value.get("status") == "error"
        and value.get("code") == 504
        and isinstance(value.get("error"), str)
        and bool(value["error"])
    )


def _consume(value):
    """Return a dict, or the list of items a forward() generator yielded.

    Stops early when a 504 object appears so a capped stream does not have to
    be drained by the test. Closes the generator either way, which is what the
    runtime does when it finishes the response.
    """
    if not inspect.isgenerator(value):
        return value
    items = []
    try:
        for item in value:
            items.append(item)
            if _is_504(item):
                break
    finally:
        value.close()
    return items


def _call(fn, seconds: float):
    """Run fn on a daemon thread and wait at most ``seconds``.

    The vulnerable forward blocks inside ``urlopen`` / ``read`` past any short
    deadline, so the thread is still alive when this returns. A fixed forward
    has already published a 504 object.
    """
    box: dict = {}

    def target():
        try:
            box["value"] = _consume(fn())
        except BaseException as exc:  # noqa: BLE001 — the assertion reports it
            box["error"] = exc

    thread = threading.Thread(target=target, daemon=True)
    thread.start()
    thread.join(seconds)
    return thread, box


def _assert_504(thread: threading.Thread, box: dict) -> None:
    assert not thread.is_alive(), (
        "invocation forward was still blocked after "
        f"{OBSERVE_SECONDS:.0f}s; the child connection has no deadline"
    )
    assert "error" not in box, box.get("error")
    value = box["value"]
    if isinstance(value, list):
        assert value, "event stream ended without a 504 error"
        value = value[-1]
    assert _is_504(value), value


class _Child(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _read_request(self) -> None:
        length = int(self.headers.get("Content-Length", "0") or "0")
        raw = self.rfile.read(length) if length else b""
        if raw:
            self.server.payloads.append(json.loads(raw.decode()))

    def _shrink_socket(self) -> None:
        # Keep the kernel from absorbing the rest of an oversized body after
        # the adapter stops reading. write() then blocks until the adapter
        # reads, and fails once the adapter closes the connection.
        self.connection.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 8 * 1024)

    def _write_all(self, payload: bytes) -> None:
        sent = 0
        view = memoryview(payload)
        try:
            while sent < len(payload):
                chunk = view[sent : sent + CHUNK]
                self.wfile.write(chunk)
                self.wfile.flush()
                sent += len(chunk)
                if sent < len(payload):
                    time.sleep(0.01)
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError, TimeoutError):
            pass
        finally:
            self.server.bytes_sent += sent

    def do_GET(self):
        if self.path == "/healthz":
            body = b'{"status":"ok"}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        self.send_error(404)

    def do_POST(self):
        self._shrink_socket()
        self._read_request()
        mode = self.server.mode
        if mode == "hang":
            # Accept the caller's payload and hold the connection open.
            self.server.accepted.set()
            self.server.release.wait(60)
            return
        if mode == "trickle":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Connection", "close")
            self.end_headers()
            self.server.accepted.set()
            # One byte well inside a 5s per-read socket timeout, forever.
            for _ in range(60):
                if self.server.release.is_set():
                    break
                try:
                    self.wfile.write(b"x")
                    self.wfile.flush()
                    self.server.bytes_sent += 1
                except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError, TimeoutError):
                    break
                time.sleep(0.5)
            return
        if mode == "large":
            body = b"y" * OVERSIZED_BODY
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self._write_all(body)
            return
        if mode == "large-error":
            body = b"z" * OVERSIZED_BODY
            self.send_response(500)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self._write_all(body)
            return
        if mode == "large-sse":
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Connection", "close")
            self.end_headers()
            line = b"data: " + (b"e" * 1024) + b"\n\n"
            repeats = (OVERSIZED_BODY // len(line)) + 1
            self._write_all(line * repeats)
            return
        if mode == "slow-sse":
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Connection", "close")
            self.end_headers()
            self.server.accepted.set()
            for i in range(40):
                if self.server.release.is_set():
                    break
                line = f"data: {json.dumps({'n': i})}\n\n".encode()
                try:
                    self.wfile.write(line)
                    self.wfile.flush()
                    self.server.bytes_sent += len(line)
                except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError, TimeoutError):
                    break
                time.sleep(0.5)
            return
        if mode == "small-json":
            body = json.dumps({"answer": "ok"}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if mode == "small-error":
            body = b"child exploded"
            self.send_response(500)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if mode == "small-sse":
            body = b'data: {"delta": "a"}\n\ndata: raw-text\n\n'
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        self.send_error(404)

    def log_message(self, *args):
        pass


class _Server(ThreadingHTTPServer):
    def __init__(self, mode: str):
        super().__init__(("127.0.0.1", 0), _Child)
        self.mode = mode
        self.bytes_sent = 0
        self.payloads: list = []
        self.accepted = threading.Event()
        self.release = threading.Event()
        self.daemon_threads = True


@contextmanager
def _child_server(mode: str):
    server = _Server(mode)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.release.set()
        server.shutdown()
        server.server_close()


def _url(server: _Server, path: str) -> str:
    return f"http://127.0.0.1:{server.server_address[1]}{path}"


def _bind_invoke(monkeypatch, server: _Server) -> None:
    class Alive:
        def alive(self):
            return True

    monkeypatch.setattr(adapter, "_child", Alive())
    monkeypatch.setenv("MIGRATION_PORT", str(server.server_address[1]))
    monkeypatch.setenv("MIGRATION_HEALTH_PATH", "/healthz")
    monkeypatch.setenv("MIGRATION_INVOKE_PATH", "/invoke")


def _assert_bounded_read(server: _Server) -> None:
    ceiling = MAX_RESPONSE_BYTES + BYTES_SLACK
    assert server.bytes_sent <= ceiling, (
        f"child delivered {server.bytes_sent} bytes into the adapter; "
        f"the cap is {MAX_RESPONSE_BYTES} bytes"
    )


@pytest.fixture(autouse=True)
def _no_global_socket_timeout():
    """A process-wide default timeout would hide the missing urlopen deadline."""
    assert socket.getdefaulttimeout() is None


def test_forward_silent_child_returns_504_within_deadline():
    payload = {"prompt": "hold-open"}
    with _child_server("hang") as server:
        thread, box = _call(lambda: adapter.forward(payload, _url(server, "/invoke")), OBSERVE_SECONDS)
        assert server.accepted.wait(2), "child never saw the invocation"
        assert server.payloads == [payload]
        try:
            _assert_504(thread, box)
        finally:
            server.release.set()


def test_invoke_silent_child_returns_504_within_deadline(monkeypatch):
    payload = {"prompt": "hold-open"}
    with _child_server("hang") as server:
        _bind_invoke(monkeypatch, server)
        thread, box = _call(lambda: adapter.invoke(payload), OBSERVE_SECONDS)
        assert server.accepted.wait(2), "entrypoint never forwarded the payload"
        assert server.payloads == [payload]
        try:
            _assert_504(thread, box)
        finally:
            server.release.set()


def test_forward_trickle_cannot_hold_the_worker_past_the_deadline():
    """Bytes arriving faster than a per-read timeout must still hit a total deadline."""
    with _child_server("trickle") as server:
        thread, box = _call(
            lambda: adapter.forward({"prompt": "dribble"}, _url(server, "/invoke")),
            OBSERVE_SECONDS,
        )
        assert server.accepted.wait(2)
        try:
            _assert_504(thread, box)
        finally:
            server.release.set()


def test_invoke_trickle_cannot_hold_the_worker_past_the_deadline(monkeypatch):
    with _child_server("trickle") as server:
        _bind_invoke(monkeypatch, server)
        thread, box = _call(lambda: adapter.invoke({"prompt": "dribble"}), OBSERVE_SECONDS)
        assert server.accepted.wait(2)
        try:
            _assert_504(thread, box)
        finally:
            server.release.set()


def test_forward_large_success_body_is_capped_and_closed():
    with _child_server("large") as server:
        thread, box = _call(
            lambda: adapter.forward({"prompt": "big"}, _url(server, "/invoke")),
            OBSERVE_SECONDS,
        )
        _assert_504(thread, box)
        _assert_bounded_read(server)


def test_invoke_large_success_body_is_capped_and_closed(monkeypatch):
    with _child_server("large") as server:
        _bind_invoke(monkeypatch, server)
        thread, box = _call(lambda: adapter.invoke({"prompt": "big"}), OBSERVE_SECONDS)
        _assert_504(thread, box)
        _assert_bounded_read(server)


def test_forward_large_error_body_is_capped_and_closed():
    with _child_server("large-error") as server:
        thread, box = _call(
            lambda: adapter.forward({"prompt": "big-error"}, _url(server, "/invoke")),
            OBSERVE_SECONDS,
        )
        _assert_504(thread, box)
        _assert_bounded_read(server)


def test_forward_event_stream_stops_at_byte_cap_and_closes():
    with _child_server("large-sse") as server:
        thread, box = _call(
            lambda: adapter.forward({"prompt": "stream"}, _url(server, "/invoke")),
            OBSERVE_SECONDS,
        )
        _assert_504(thread, box)
        _assert_bounded_read(server)


def test_invoke_event_stream_stops_at_byte_cap_and_closes(monkeypatch):
    with _child_server("large-sse") as server:
        _bind_invoke(monkeypatch, server)
        thread, box = _call(lambda: adapter.invoke({"prompt": "stream"}), OBSERVE_SECONDS)
        _assert_504(thread, box)
        _assert_bounded_read(server)


def test_forward_event_stream_stops_at_duration_cap_and_closes():
    with _child_server("slow-sse") as server:
        thread, box = _call(
            lambda: adapter.forward({"prompt": "slow-stream"}, _url(server, "/invoke")),
            OBSERVE_SECONDS,
        )
        assert server.accepted.wait(2)
        try:
            _assert_504(thread, box)
            # Under the byte cap: the failure mode here is duration, not size.
            assert server.bytes_sent < MAX_RESPONSE_BYTES
        finally:
            server.release.set()


def test_invoke_event_stream_stops_at_duration_cap_and_closes(monkeypatch):
    with _child_server("slow-sse") as server:
        _bind_invoke(monkeypatch, server)
        thread, box = _call(lambda: adapter.invoke({"prompt": "slow-stream"}), OBSERVE_SECONDS)
        assert server.accepted.wait(2)
        try:
            _assert_504(thread, box)
            assert server.bytes_sent < MAX_RESPONSE_BYTES
        finally:
            server.release.set()


def test_small_json_text_error_and_sse_still_pass_through():
    with _child_server("small-json") as server:
        assert adapter.forward({"prompt": "hi"}, _url(server, "/invoke")) == {"answer": "ok"}
    with _child_server("small-error") as server:
        result = adapter.forward({"prompt": "hi"}, _url(server, "/invoke"))
        assert result["status"] == "error"
        assert result["code"] == 500
        assert "child exploded" in result["error"]
    with _child_server("small-sse") as server:
        assert list(adapter.forward({"prompt": "hi"}, _url(server, "/invoke"))) == [
            {"delta": "a"},
            "raw-text",
        ]
