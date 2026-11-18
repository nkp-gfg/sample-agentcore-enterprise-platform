"""Caller-visible errors from the migration preset must not carry internal text.

The migration preset builds migration/simulation/existing-ec2-agent and the
adapter forwards POST /invocations to that server's /run. These tests drive
that path. They fail while the server returns exception text and while the
adapter repeats a child error body, and they pass once both return a fixed
message and the server logs the exception instead.

Run:
    python3 -m venv /tmp/migration-error-tests
    /tmp/migration-error-tests/bin/pip install -r requirements.txt 'strands-agents==1.65.0'
    /tmp/migration-error-tests/bin/python -m pytest tests/test_migration_error_disclosure.py -q
"""

import importlib.util
import json
import logging
import sys
import threading
import types
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
CUSTOMER_DIR = REPO / "migration/simulation/existing-ec2-agent"

# Obvious non-secret placeholders. Botocore will not sign a local request
# without some static credentials, and these values are not real keys.
_PLACEHOLDER_ACCESS_KEY = "testing"
_PLACEHOLDER_SECRET_KEY = "testing"

# Text shaped like the Bedrock AccessDeniedException message documented by AWS.
# The sentinel is unique to this file so a response that merely says "error"
# cannot hide a partial copy of the service message.
SERVICE_ERROR = (
    "You don't have access to the model with the specified model ID. "
    "User: arn:aws:sts::000000000000:assumed-role/migration-runtime "
    "is not authorized to perform: bedrock:InvokeModel on resource: "
    "arn:aws:bedrock:us-east-1::foundation-model/unavailable.model "
    "because no identity-based policy allows the bedrock:InvokeModel action. "
    "model-call-failure-detail"
)
SERVICE_NEEDLES = (
    "model-call-failure-detail",
    "assumed-role/migration-runtime",
    "bedrock:InvokeModel",
    "000000000000",
    "unavailable.model",
    "AccessDeniedException",
)


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


try:
    import bedrock_agentcore.runtime  # noqa: F401
except ImportError:

    class _FakeApp:
        def entrypoint(self, fn):
            return fn

        def run(self, *args, **kwargs):
            raise RuntimeError("app.run() must not be reached in unit tests")

    _runtime = types.ModuleType("bedrock_agentcore.runtime")
    _runtime.BedrockAgentCoreApp = _FakeApp
    _pkg = types.ModuleType("bedrock_agentcore")
    _pkg.runtime = _runtime
    sys.modules["bedrock_agentcore"] = _pkg
    sys.modules["bedrock_agentcore.runtime"] = _runtime

customer = _load("migration_customer_server", CUSTOMER_DIR / "server.py")
adapter = _load("migration_adapter_disclosure", REPO / "migration/adapter/adapter.py")


class _BedrockErrorHandler(BaseHTTPRequestHandler):
    """Stand-in for the Bedrock Runtime HTTP error, parsed by real botocore."""

    calls = 0

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        self.rfile.read(length)
        type(self).calls += 1
        payload = json.dumps({"message": SERVICE_ERROR}).encode()
        self.send_response(403)
        self.send_header("Content-Type", "application/json")
        self.send_header("x-amzn-errortype", "AccessDeniedException")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, fmt, *args):
        return


class _RecordingHandler(logging.Handler):
    def __init__(self):
        super().__init__()
        self.lines: list[str] = []

    def emit(self, record):
        self.lines.append(self.format(record))
        if record.exc_info:
            self.lines.append(
                self.formatter.formatException(record.exc_info)
                if self.formatter
                else ""
            )


@pytest.fixture
def error_logs():
    handler = _RecordingHandler()
    handler.setFormatter(logging.Formatter("%(message)s"))
    root = logging.getLogger()
    root.addHandler(handler)
    try:
        yield handler.lines
    finally:
        root.removeHandler(handler)


@pytest.fixture
def bedrock_endpoint(monkeypatch):
    _BedrockErrorHandler.calls = 0
    server = ThreadingHTTPServer(("127.0.0.1", 0), _BedrockErrorHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    endpoint = f"http://127.0.0.1:{server.server_address[1]}"
    monkeypatch.setenv("AWS_ENDPOINT_URL_BEDROCK_RUNTIME", endpoint)
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", _PLACEHOLDER_ACCESS_KEY)
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", _PLACEHOLDER_SECRET_KEY)
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
    monkeypatch.setenv("AWS_EC2_METADATA_DISABLED", "true")
    monkeypatch.setenv("AWS_MAX_ATTEMPTS", "1")
    monkeypatch.delenv("AWS_SESSION_TOKEN", raising=False)
    monkeypatch.delenv("AWS_PROFILE", raising=False)
    monkeypatch.delenv("HTTP_PROXY", raising=False)
    monkeypatch.delenv("HTTPS_PROXY", raising=False)
    monkeypatch.delenv("http_proxy", raising=False)
    monkeypatch.delenv("https_proxy", raising=False)
    try:
        yield endpoint
    finally:
        server.shutdown()
        customer._agent = None


@pytest.fixture
def customer_http():
    server = ThreadingHTTPServer(("127.0.0.1", 0), customer.Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_address[1]}"
    try:
        yield base
    finally:
        server.shutdown()
        customer._agent = None


def _exchange(url: str, data: bytes, content_type: str = "application/json"):
    request = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": content_type},
    )
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            return response.status, response.read().decode()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode()


def _assert_hidden(visible: str, needles: tuple[str, ...]):
    leaked = [needle for needle in needles if needle in visible]
    assert not leaked, f"response disclosed internal details: {leaked}"


def _assert_logged(capsys, records: list[str], needle: str):
    captured = capsys.readouterr()
    blob = "\n".join([captured.out, captured.err, *records])
    assert needle in blob, "exception detail was not logged server-side"


def test_model_failure_is_not_returned_to_the_caller(
    bedrock_endpoint, customer_http, monkeypatch, capsys, error_logs
):
    monkeypatch.setenv("MODEL_ID", "unavailable.model")
    customer._agent = None
    status, body = _exchange(
        f"{customer_http}/run",
        json.dumps({"prompt": "hello"}).encode(),
    )
    assert _BedrockErrorHandler.calls >= 1, (
        "model call never reached the runtime client"
    )
    assert status == 500
    _assert_hidden(body, SERVICE_NEEDLES)
    _assert_logged(capsys, error_logs, "model-call-failure-detail")


def test_default_agent_model_failure_is_not_returned(
    bedrock_endpoint, customer_http, monkeypatch, capsys, error_logs
):
    monkeypatch.delenv("MODEL_ID", raising=False)
    if str(CUSTOMER_DIR) not in sys.path:
        sys.path.insert(0, str(CUSTOMER_DIR))
    customer._agent = None
    status, body = _exchange(
        f"{customer_http}/run",
        json.dumps({"prompt": "hello"}).encode(),
    )
    assert _BedrockErrorHandler.calls >= 1, "default agent never called the model"
    assert status == 500
    _assert_hidden(body, SERVICE_NEEDLES + ("anthropic.claude-sonnet-4-20250514",))
    _assert_logged(capsys, error_logs, "model-call-failure-detail")


def test_blank_prompt_does_not_return_the_validation_exception(
    bedrock_endpoint, customer_http, monkeypatch, capsys, error_logs
):
    monkeypatch.setenv("MODEL_ID", "unavailable.model")
    customer._agent = None
    try:
        customer.get_agent()("")
    except Exception as exc:  # noqa: BLE001 — capture the text the handler must hide
        detail = f"{type(exc).__name__}: {exc}"
    else:
        pytest.fail("blank prompt did not fail the agent call")
    customer._agent = None
    status, body = _exchange(
        f"{customer_http}/run",
        json.dumps({"prompt": ""}).encode(),
    )
    assert status == 500
    _assert_hidden(body, (detail, "ValueError", "Input prompt is blank"))
    _assert_logged(capsys, error_logs, "Input prompt is blank")


def test_malformed_json_does_not_return_the_parser_exception(
    customer_http, capsys, error_logs
):
    status, body = _exchange(f"{customer_http}/run", b"{")
    assert status == 500
    _assert_hidden(body, ("JSONDecodeError", "Expecting property name"))
    _assert_logged(capsys, error_logs, "JSONDecodeError")


class _ChildErrorHandler(BaseHTTPRequestHandler):
    def _reply(self, code: int, body: bytes, content_type: str):
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/healthz":
            self._reply(200, b'{"status":"ok"}', "application/json")
        else:
            self._reply(404, b"missing", "text/plain")

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        self.rfile.read(length)
        if self.path == "/text":
            self._reply(500, b"child-text-failure-detail", "text/plain")
        elif self.path == "/denied":
            self._reply(
                400,
                json.dumps({"error": "child-json-failure-detail"}).encode(),
                "application/json",
            )
        else:
            self._reply(
                500,
                json.dumps({"error": SERVICE_ERROR}).encode(),
                "application/json",
            )

    def log_message(self, fmt, *args):
        return


@pytest.fixture
def child_error_server():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _ChildErrorHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_address[1]}"
    try:
        yield base
    finally:
        server.shutdown()


@pytest.mark.parametrize(
    ("path", "needle"),
    [
        ("/run", "model-call-failure-detail"),
        ("/text", "child-text-failure-detail"),
        ("/denied", "child-json-failure-detail"),
    ],
)
def test_adapter_forward_hides_child_error_body(child_error_server, path, needle):
    result = adapter.forward({"prompt": "hello"}, f"{child_error_server}{path}")
    assert result["status"] == "error"
    assert result["code"] >= 400
    _assert_hidden(json.dumps(result), (needle, SERVICE_ERROR))


class _Alive:
    def alive(self):
        return True


def test_adapter_invoke_hides_child_error_body(child_error_server, monkeypatch):
    previous = adapter._child
    port = child_error_server.rsplit(":", 1)[1]
    monkeypatch.setenv("MIGRATION_PORT", port)
    monkeypatch.setenv("MIGRATION_INVOKE_PATH", "/run")
    monkeypatch.setenv("MIGRATION_HEALTH_PATH", "/healthz")
    adapter._child = _Alive()
    try:
        result = adapter.invoke({"prompt": "hello"})
    finally:
        adapter._child = previous
    assert result["status"] == "error"
    _assert_hidden(
        json.dumps(result), ("model-call-failure-detail", "AccessDeniedException")
    )


def test_adapter_invoke_of_the_customer_server_hides_the_model_error(
    bedrock_endpoint, monkeypatch
):
    customer._agent = None
    monkeypatch.setenv("MODEL_ID", "unavailable.model")
    port_holder = ThreadingHTTPServer(("127.0.0.1", 0), customer.Handler)
    port = port_holder.server_address[1]
    port_holder.server_close()
    env = {
        "PORT": str(port),
        "MODEL_ID": "unavailable.model",
        "AWS_ENDPOINT_URL_BEDROCK_RUNTIME": bedrock_endpoint,
        "AWS_ACCESS_KEY_ID": _PLACEHOLDER_ACCESS_KEY,
        "AWS_SECRET_ACCESS_KEY": _PLACEHOLDER_SECRET_KEY,
        "AWS_DEFAULT_REGION": "us-east-1",
        "AWS_EC2_METADATA_DISABLED": "true",
        "AWS_MAX_ATTEMPTS": "1",
        "PATH": "/usr/bin:/bin",
    }
    child = adapter.Child([sys.executable, str(CUSTOMER_DIR / "server.py")], env)
    previous = adapter._child
    child.start()
    adapter._child = child
    monkeypatch.setenv("MIGRATION_PORT", str(port))
    monkeypatch.setenv("MIGRATION_INVOKE_PATH", "/run")
    monkeypatch.setenv("MIGRATION_HEALTH_PATH", "/healthz")
    try:
        adapter.wait_for_child(
            f"http://127.0.0.1:{port}/healthz",
            timeout=30,
            child=child,
        )
        result = adapter.invoke({"prompt": "hello"})
    finally:
        adapter._child = previous
        if child.proc is not None and child.proc.poll() is None:
            child.proc.kill()
            child.proc.wait(timeout=5)
        customer._agent = None
    assert _BedrockErrorHandler.calls >= 1
    assert result["status"] == "error"
    _assert_hidden(json.dumps(result), SERVICE_NEEDLES)


def test_health_probe_failure_hides_the_probe_exception(monkeypatch):
    previous = adapter._child
    child = adapter.Child(["sleep", "60"], {})
    child.start()
    adapter._child = child
    monkeypatch.setenv("MIGRATION_PORT", "1")
    monkeypatch.setenv("MIGRATION_INVOKE_PATH", "/run")
    monkeypatch.setenv("MIGRATION_HEALTH_PATH", "/healthz")
    try:
        result = adapter.invoke({"prompt": "hello"})
    finally:
        adapter._child = previous
        if child.proc is not None and child.proc.poll() is None:
            child.proc.kill()
            child.proc.wait(timeout=5)
    assert result["status"] == "error"
    assert result["code"] == 503
    visible = json.dumps(result)
    _assert_hidden(
        visible,
        ("URLError", "Connection refused", "Errno", "http://127.0.0.1:1/healthz"),
    )
