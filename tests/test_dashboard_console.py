"""Security and behavior tests for the local EBA Console."""

from __future__ import annotations

import json
import sys
import threading
import time
from datetime import UTC, datetime, timedelta
from email.message import Message
from http.client import HTTPConnection
from io import BytesIO
from pathlib import Path
from types import SimpleNamespace

import pytest

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from dashboard import server

CONSOLE_JS = (REPO / "dashboard" / "public" / "console.js").read_text()
APP_JS = (REPO / "dashboard" / "public" / "app.js").read_text()
INDEX_HTML = (REPO / "dashboard" / "public" / "index.html").read_text()
TEST_SESSION_TOKEN = server.SESSION_TOKEN  # pragma: allowlist secret
TEST_CSRF_TOKEN = server.CSRF_TOKEN  # pragma: allowlist secret


def _status(
    *,
    component: str = "orchestrator",
    state: str = "deployed",
    age_seconds: int = 0,
) -> dict:
    suffix = server.COMPONENTS[component]
    return {
        "available": True,
        "timestamp": (datetime.now(UTC) - timedelta(seconds=age_seconds)).isoformat(),
        "account": "111111111111",
        "region": "eu-west-1",
        "project": "project",
        "environment": "dev",
        "stacks": {
            f"project-dev-{suffix}": {
                "state": state,
                "outputs": {
                    "RuntimeArn": (
                        "arn:aws:bedrock-agentcore:eu-west-1:111111111111:runtime/test"
                    ),
                    "RuntimeId": "runtime-id",
                },
            }
        },
    }


def test_status_must_be_fresh_and_successful(tmp_path):
    path = tmp_path / "status.json"
    path.write_text(json.dumps(_status(age_seconds=server.MAX_STATUS_AGE_SECONDS + 1)))
    with pytest.raises(server.RequestRejected, match="stale"):
        server.load_status(path)

    path.write_text(json.dumps({"available": False}))
    with pytest.raises(server.RequestRejected, match="did not succeed"):
        server.load_status(path)


def test_invocation_accepts_only_deployed_allowlisted_components():
    component, prompt, session, runtime_arn = server.validate_invocation(
        {
            "component": "orchestrator",
            "prompt": "  synthetic question  ",
            "sessionId": "session-" + ("a" * 32),
            # Browser-supplied routing fields are ignored.
            "runtimeArn": "arn:attacker:selected",
            "protocol": "attacker-selected",
        },
        _status(),
    )
    assert (component, prompt, session) == (
        "orchestrator",
        "synthetic question",
        "session-" + ("a" * 32),
    )
    assert runtime_arn == (
        "arn:aws:bedrock-agentcore:eu-west-1:111111111111:runtime/test"
    )

    with pytest.raises(server.RequestRejected, match="Unknown"):
        server.validate_invocation(
            {
                "component": "arbitrary-runtime",
                "prompt": "hello",
                "sessionId": "session-" + ("a" * 32),
            },
            _status(),
        )
    with pytest.raises(server.RequestRejected, match="not deployed"):
        server.validate_invocation(
            {
                "component": "orchestrator",
                "prompt": "hello",
                "sessionId": "session-" + ("a" * 32),
            },
            _status(state="failed"),
        )
    with pytest.raises(server.RequestRejected, match="internal"):
        server.validate_invocation(
            {
                "component": "code-agent",
                "prompt": "hello",
                "sessionId": "session-" + ("a" * 32),
            },
            _status(component="code-agent"),
        )


def test_invocation_rejects_oversized_prompt_and_unsafe_session():
    with pytest.raises(server.RequestRejected, match="at most"):
        server.validate_invocation(
            {
                "component": "orchestrator",
                "prompt": "x" * (server.MAX_PROMPT_CHARS + 1),
                "sessionId": "session-" + ("a" * 32),
            },
            _status(),
        )
    with pytest.raises(server.RequestRejected, match="Session ID"):
        server.validate_invocation(
            {
                "component": "orchestrator",
                "prompt": "hello",
                "sessionId": ("a" * 40) + "\n",
            },
            _status(),
        )


@pytest.mark.parametrize(
    ("component", "pattern", "migration", "expected"),
    [
        ("orchestrator", "orchestrator", None, "http"),
        ("orchestrator", "agui-strands-agent", None, "ag-ui"),
        ("orchestrator", "god-agent", None, "ag-ui"),
        ("orchestrator", "agui-strands-agent", object(), "http"),
    ],
)
def test_protocol_is_derived_from_trusted_config(
    monkeypatch,
    component,
    pattern,
    migration,
    expected,
):
    monkeypatch.delenv("AGENT_PATTERN", raising=False)
    monkeypatch.setattr(
        server,
        "load_config",
        lambda: SimpleNamespace(
            agents=SimpleNamespace(pattern=pattern),
            migration=migration,
        ),
    )
    assert server.protocol_for(component) == expected


class _STS:
    def __init__(self, account):
        self.account = account

    def get_caller_identity(self):
        return {"Account": self.account}


def test_operator_identity_and_runtime_must_match_monitor():
    status = _status()
    arn = status["stacks"]["project-dev-runtime-orchestrator"]["outputs"]["RuntimeArn"]

    assert (
        server.validate_operator_identity(
            status,
            arn,
            client_factory=lambda service, region_name: _STS("111111111111"),
            context_factory=lambda: SimpleNamespace(
                project="project",
                environment="dev",
                region="eu-west-1",
            ),
        )
        == "eu-west-1"
    )
    with pytest.raises(server.RequestRejected, match="profile does not match"):
        server.validate_operator_identity(
            status,
            arn,
            client_factory=lambda service, region_name: _STS("222222222222"),
            context_factory=lambda: SimpleNamespace(
                project="project",
                environment="dev",
                region="eu-west-1",
            ),
        )
    with pytest.raises(server.RequestRejected, match="runtime ARN"):
        server.validate_operator_identity(
            status,
            arn.replace("eu-west-1", "us-east-1"),
            client_factory=lambda service, region_name: _STS("111111111111"),
            context_factory=lambda: SimpleNamespace(
                project="project",
                environment="dev",
                region="eu-west-1",
            ),
        )
    with pytest.raises(server.RequestRejected, match="configuration"):
        server.validate_operator_identity(
            status,
            arn,
            client_factory=lambda service, region_name: _STS("111111111111"),
            context_factory=lambda: SimpleNamespace(
                project="another-project",
                environment="dev",
                region="eu-west-1",
            ),
        )


def test_console_invokes_the_exact_monitored_arn(monkeypatch):
    monkeypatch.setattr(
        server,
        "load_config",
        lambda: SimpleNamespace(
            agents=SimpleNamespace(pattern="orchestrator"),
            migration=None,
        ),
    )
    calls = []
    fake = SimpleNamespace(
        invoke_agent=lambda prompt, session, **kwargs: (
            calls.append((prompt, session, kwargs)) or '{"response":"ok"}'
        )
    )
    arn = "arn:aws:bedrock-agentcore:eu-west-1:111111111111:runtime/exact"
    protocol, _ = server.invoke_component(
        "orchestrator",
        "hello",
        "session-" + ("a" * 32),
        arn,
        "eu-west-1",
        invoke_module=fake,
    )
    assert protocol == "http"
    assert calls[0][2] == {
        "runtime_arn": arn,
        "region": "eu-west-1",
        "max_response_bytes": server.MAX_INVOKE_RESPONSE_BYTES,
    }


def test_runtime_response_exposes_text_and_metadata_only_trace():
    body = (
        'data: {"type":"TOOL_CALL_START","toolCallName":"search",'
        '"toolCallId":"1","args":"must-not-appear"}\n'
        'data: {"type":"TEXT_MESSAGE_CONTENT","delta":"Hello "}\n'
        'data: {"type":"TEXT_MESSAGE_CONTENT","delta":"world"}'
    )
    output, trace = server.parse_runtime_response(body)
    assert output == "Hello world"
    assert trace == [{"kind": "tool", "label": "search"}]
    assert "must-not-appear" not in json.dumps(trace)


def test_agent_text_wrappers_are_normalized():
    assert server.parse_runtime_response("AGENT TEXT: 'hello'") == ("hello", [])
    assert server.parse_runtime_response("AGENT TEXT: hello") == ("hello", [])


def test_unknown_payload_and_tool_result_never_render_raw_canary():
    canary = "SECRET-CANARY-MUST-NOT-RENDER"
    body = json.dumps(
        {
            "message": {
                "role": "user",
                "content": [{"toolResult": {"content": [{"text": canary}]}}],
            }
        }
    )
    output, trace = server.parse_runtime_response(body)
    assert output == "The runtime returned no displayable assistant text."
    assert canary not in output
    assert canary not in json.dumps(trace)


def test_runtime_reader_rejects_oversized_response():
    response = BytesIO(b"x" * 9)
    with pytest.raises(
        server.runtime_invoke.RuntimeVerificationError, match="exceeded"
    ):
        server.runtime_invoke._read_bounded(response, limit=8)


@pytest.fixture
def console_handler(monkeypatch):
    monkeypatch.setattr(server, "load_status", _status)
    monkeypatch.setattr(
        server,
        "validate_operator_identity",
        lambda status, runtime_arn: "eu-west-1",
    )
    monkeypatch.setattr(
        server,
        "invoke_component",
        lambda component, prompt, session, runtime_arn, region: (
            "http",
            json.dumps({"response": f"reply to {prompt}"}),
        ),
    )

    def request(method: str, path: str, body: bytes = b"", headers=None):
        port = 8888
        handler = server.EbaConsoleHandler.__new__(server.EbaConsoleHandler)
        handler.directory = str(server.PUBLIC)
        handler.path = path
        handler.command = method
        handler.request_version = "HTTP/1.1"
        handler.requestline = f"{method} {path} HTTP/1.1"
        handler.server = SimpleNamespace(
            server_port=port,
            session_token=TEST_SESSION_TOKEN,
            csrf_token=TEST_CSRF_TOKEN,
        )
        handler.client_address = ("127.0.0.1", 12345)
        handler.rfile = BytesIO(body)
        handler.wfile = BytesIO()
        handler.headers = Message()
        all_headers = {
            "Host": f"127.0.0.1:{port}",
            **(headers or {}),
        }
        if body and "Content-Length" not in all_headers:
            all_headers["Content-Length"] = str(len(body))
        for key, value in all_headers.items():
            handler.headers[key] = value
        getattr(handler, f"do_{method}")()
        raw_headers, response_body = handler.wfile.getvalue().split(b"\r\n\r\n", 1)
        lines = raw_headers.decode().splitlines()
        status = int(lines[0].split()[1])
        response_headers = {}
        for line in lines[1:]:
            if ":" in line:
                key, value = line.split(":", 1)
                response_headers[key] = value.strip()
        return status, response_headers, response_body

    return request


def _assert_security_headers(headers: dict[str, str]) -> None:
    assert headers["X-Frame-Options"] == "DENY"
    assert headers["X-Content-Type-Options"] == "nosniff"
    assert headers["Referrer-Policy"] == "no-referrer"
    assert headers["Permissions-Policy"] == "camera=(), microphone=(), geolocation=()"
    assert headers["Cross-Origin-Opener-Policy"] == "same-origin"
    assert headers["Cross-Origin-Resource-Policy"] == "same-origin"
    assert "Python/" not in headers["Server"]
    csp = headers["Content-Security-Policy"]
    assert "frame-ancestors 'none'" in csp
    assert "script-src 'self';" in csp
    assert "style-src 'self';" in csp
    assert "object-src 'none';" in csp
    assert "worker-src 'none';" in csp
    assert "'unsafe-inline'" not in csp


def test_health_endpoint_is_local_minimal_and_hardened(console_handler):
    status, headers, body = console_handler("GET", "/api/health")
    assert status == 200
    assert json.loads(body) == {"status": "ok"}
    _assert_security_headers(headers)
    assert headers["Cache-Control"] == "no-store"

    for bad_host in (
        "attacker.example",
        "127.0.0.1",
        "localhost",
        "127.0.0.1:8889",
        "127.0.0.1:80",
    ):
        status, err_headers, _ = console_handler(
            "GET",
            "/api/health",
            headers={"Host": bad_host},
        )
        assert status == 403, bad_host
        assert err_headers["Cache-Control"] == "no-store"

    assert server._is_same_origin("http://127.0.0.1:8888", "127.0.0.1:8888", 8888)
    assert not server._is_same_origin(
        "http://localhost:8888",
        "127.0.0.1:8888",
        8888,
    )
    assert not server._is_same_origin(
        "https://127.0.0.1:8888",
        "127.0.0.1:8888",
        8888,
    )
    assert not server._is_same_origin(
        "http://127.0.0.1",
        "127.0.0.1:80",
        80,
    )


def test_session_endpoint_requires_bearer_session_token(console_handler):
    status, headers, _ = console_handler("GET", "/api/session")
    assert status == 401
    assert headers["Cache-Control"] == "no-store"

    status, _, _ = console_handler(
        "GET",
        "/api/session",
        headers={"Authorization": "Bearer wrong-token"},
    )
    assert status == 401

    status, headers, body = console_handler(
        "GET",
        "/api/session",
        headers={"Authorization": f"Bearer {TEST_SESSION_TOKEN}"},
    )
    assert status == 200
    assert headers["Cache-Control"] == "no-store"
    _assert_security_headers(headers)
    session = json.loads(body)
    assert session == {
        "interactive": True,
        "localOnly": True,
        "maxPromptChars": server.MAX_PROMPT_CHARS,
        "csrfToken": TEST_CSRF_TOKEN,
    }


def test_status_json_requires_session_token_for_get_and_head(
    tmp_path, monkeypatch, console_handler
):
    public_dir = tmp_path / "public"
    public_dir.mkdir()
    (public_dir / "index.html").write_text("<html></html>", encoding="utf-8")
    (public_dir / "status.json").write_text('{"available": true}', encoding="utf-8")
    monkeypatch.setattr(server, "PUBLIC", public_dir)

    for method in ("GET", "HEAD"):
        status, headers, body = console_handler(method, "/status.json?t=123")
        assert status == 401
        assert headers["Cache-Control"] == "no-store"
        if method == "HEAD":
            assert body == b""

    srv = server.make_server(
        port=0,
        session_token=TEST_SESSION_TOKEN,
        csrf_token=TEST_CSRF_TOKEN,
    )
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    try:
        for _ in range(50):
            if srv.server_port:
                break
            time.sleep(0.01)
        port = srv.server_port
        for method in ("GET", "HEAD"):
            conn = HTTPConnection("127.0.0.1", port, timeout=5)
            try:
                conn.request(
                    method,
                    "/status.json?t=123",
                    headers={
                        "Host": f"127.0.0.1:{port}",
                        "Authorization": f"Bearer {TEST_SESSION_TOKEN}",
                    },
                )
                resp = conn.getresponse()
                resp_body = resp.read()
                resp_headers = {k.lower(): v for k, v in resp.getheaders()}
            finally:
                conn.close()
            assert resp.status == 200
            assert resp_headers["cache-control"] == "no-store"
            if method == "HEAD":
                assert resp_body == b""
            else:
                assert json.loads(resp_body) == {"available": True}
    finally:
        srv.shutdown()
        srv.server_close()
        thread.join(timeout=2)


def test_static_asset_allowlist_mime_map_and_symlink_guard(
    tmp_path, monkeypatch, console_handler
):
    assert "/app.js" in server.STATIC_ASSETS
    assert server.EbaConsoleHandler.extensions_map[".js"].startswith(
        "application/javascript"
    )
    assert server.EbaConsoleHandler.extensions_map[".svg"] == "image/svg+xml"

    status, _, body = console_handler("GET", "/../server.py")
    assert status == 404
    assert "not found" in json.loads(body)["error"].lower()

    status, _, _ = console_handler("GET", "/secret.txt")
    assert status == 404

    public_dir = tmp_path / "public"
    public_dir.mkdir()
    outside = tmp_path / "outside.js"
    outside.write_text("console.log('leak');", encoding="utf-8")
    (public_dir / "app.js").symlink_to(outside)
    monkeypatch.setattr(server, "PUBLIC", public_dir)

    for method in ("GET", "HEAD"):
        status, _, body = console_handler(method, "/app.js")
        assert status == 404
        if method == "HEAD":
            assert body == b""


def test_http_verbs_and_head_enforce_loopback_and_json_405(console_handler):
    for method in ("OPTIONS", "PUT", "DELETE", "PATCH", "TRACE"):
        bad_status, _, _ = console_handler(
            method,
            "/",
            headers={"Host": "attacker.example"},
        )
        assert bad_status == 403

        status, headers, body = console_handler(method, "/api/invoke")
        assert status == 405
        assert headers["Cache-Control"] == "no-store"
        assert "not supported" in json.loads(body)["error"]

    status, _, body = console_handler(
        "HEAD",
        "/api/health",
        headers={"Host": "attacker.example"},
    )
    assert status == 403
    assert body == b""

    status, headers, body = console_handler("HEAD", "/api/health")
    assert status == 200
    assert headers["Cache-Control"] == "no-store"
    assert body == b""


def test_post_requires_session_token_same_origin_csrf_and_json(console_handler):
    payload = json.dumps(
        {
            "component": "orchestrator",
            "prompt": "synthetic question",
            "sessionId": "session-" + ("a" * 32),
        }
    ).encode()
    # Missing session bearer token -> 401
    status, headers, _ = console_handler(
        "POST",
        "/api/invoke",
        body=payload,
        headers={
            "Content-Type": "application/json",
            "Origin": "http://127.0.0.1:8888",
            "X-EBA-CSRF": TEST_CSRF_TOKEN,
        },
    )
    assert status == 401
    assert headers["Cache-Control"] == "no-store"

    # Cross-origin Origin -> 403 even with valid session + CSRF tokens
    status, _, _ = console_handler(
        "POST",
        "/api/invoke",
        body=payload,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {TEST_SESSION_TOKEN}",
            "Origin": "https://attacker.example",
            "X-EBA-CSRF": TEST_CSRF_TOKEN,
        },
    )
    assert status == 403

    # All three valid (+ query string normalization) -> 200
    status, headers, body = console_handler(
        "POST",
        "/api/invoke?trace=1",
        body=payload,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {TEST_SESSION_TOKEN}",
            "Origin": "http://127.0.0.1:8888",
            "X-EBA-CSRF": TEST_CSRF_TOKEN,
        },
    )
    response = json.loads(body)
    assert status == 200
    assert headers["Cache-Control"] == "no-store"
    assert response["output"] == "reply to synthetic question"
    assert response["component"] == "orchestrator"
    assert "raw" not in response


def test_invocation_gate_runs_before_load_status_and_sts(console_handler, monkeypatch):
    calls: list[str] = []

    def fail_if_called_status():
        calls.append("load_status")
        return _status()

    def fail_if_called_sts(*_args, **_kwargs):
        calls.append("validate_operator_identity")
        return "[REDACTED]"

    monkeypatch.setattr(server, "load_status", fail_if_called_status)
    monkeypatch.setattr(server, "validate_operator_identity", fail_if_called_sts)
    monkeypatch.setattr(
        server,
        "INVOCATION_GATE",
        SimpleNamespace(acquire=lambda: False, release=lambda: None),
    )

    payload = json.dumps(
        {
            "component": "orchestrator",
            "prompt": "synthetic question",
            "sessionId": "session-" + ("a" * 32),
        }
    ).encode()
    status, headers, body = console_handler(
        "POST",
        "/api/invoke",
        body=payload,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {TEST_SESSION_TOKEN}",
            "Origin": "http://127.0.0.1:8888",
            "X-EBA-CSRF": TEST_CSRF_TOKEN,
        },
    )
    assert status == 429
    assert headers["Cache-Control"] == "no-store"
    assert "busy" in json.loads(body)["error"].lower()
    assert calls == []


def test_no_cloud_mutation_endpoint_is_exposed(console_handler):
    payload = b"{}"
    for path in ("/api/create", "/api/delete", "/api/agents"):
        status, _, _ = console_handler(
            "POST",
            path,
            body=payload,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {TEST_SESSION_TOKEN}",
                "Origin": "http://127.0.0.1:8888",
                "X-EBA-CSRF": TEST_CSRF_TOKEN,
            },
        )
        assert status == 404


def test_post_rejects_missing_csrf_token(console_handler):
    payload = json.dumps(
        {
            "component": "orchestrator",
            "prompt": "synthetic question",
            "sessionId": "session-" + ("a" * 32),
        }
    ).encode()
    status, _, body = console_handler(
        "POST",
        "/api/invoke",
        body=payload,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {TEST_SESSION_TOKEN}",
            "Origin": "http://127.0.0.1:8888",
        },
    )
    assert status == 403
    assert "token" in json.loads(body)["error"]


def test_helper_system_exit_becomes_stable_browser_error(
    console_handler,
    monkeypatch,
):
    monkeypatch.setattr(
        server,
        "invoke_component",
        lambda *args, **kwargs: (_ for _ in ()).throw(SystemExit(1)),
    )
    payload = json.dumps(
        {
            "component": "orchestrator",
            "prompt": "synthetic question",
            "sessionId": "session-" + ("a" * 32),
        }
    ).encode()
    status, _, body = console_handler(
        "POST",
        "/api/invoke",
        body=payload,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {TEST_SESSION_TOKEN}",
            "Origin": "http://127.0.0.1:8888",
            "X-EBA-CSRF": TEST_CSRF_TOKEN,
        },
    )
    assert status == 502
    assert json.loads(body)["error"].startswith("Agent invocation could not")


def test_server_socket_timeout_daemon_threads_and_startup_output(monkeypatch, capsys):
    srv = server.make_server(
        port=0,
        session_token=TEST_SESSION_TOKEN,
        csrf_token=TEST_CSRF_TOKEN,
    )
    try:
        assert srv.daemon_threads is True
        assert srv.block_on_close is False
    finally:
        srv.server_close()

    assert server.EbaConsoleHandler.timeout == 15

    recorded: list[float] = []

    class FakeSocket:
        def settimeout(self, value: float) -> None:
            recorded.append(value)

        def makefile(self, *_args, **_kwargs):
            return BytesIO()

    fake_handler = server.EbaConsoleHandler.__new__(server.EbaConsoleHandler)
    fake_handler.request = FakeSocket()
    fake_handler.client_address = ("127.0.0.1", 12345)
    fake_handler.server = SimpleNamespace(server_port=8888)
    fake_handler.disable_nagle_algorithm = False
    fake_handler.setup()
    assert recorded
    assert set(recorded) == {15}

    class FakeServer:
        def __init__(self):
            self.session_token = TEST_SESSION_TOKEN

        def serve_forever(self):
            raise KeyboardInterrupt()

        def server_close(self):
            pass

    monkeypatch.setattr(server, "make_server", lambda **_kwargs: FakeServer())
    monkeypatch.setattr(sys, "argv", ["server.py", "--port", "8888"])
    server.main()
    out = capsys.readouterr().out
    assert f"http://127.0.0.1:8888/#token={TEST_SESSION_TOKEN}" in out
    assert TEST_SESSION_TOKEN in out


def test_ui_preserves_the_demo_style_without_unsafe_response_rendering():
    assert 'class="sidebar"' in INDEX_HTML
    assert 'id="tab-agents"' in INDEX_HTML
    assert 'id="tab-playground"' in INDEX_HTML
    assert 'id="authGate"' in INDEX_HTML
    assert 'id="authGateForm"' in INDEX_HTML
    assert "Use synthetic or customer-approved data only" in INDEX_HTML
    assert "createElement" in CONSOLE_JS
    assert ".textContent =" in CONSOLE_JS
    assert "innerHTML" not in CONSOLE_JS
    assert "innerHTML" not in APP_JS
    assert "innerHTML" not in INDEX_HTML
    assert "localStorage" not in APP_JS
    assert "sessionStorage" not in APP_JS
    assert "localStorage" not in CONSOLE_JS
    assert "sessionStorage" not in CONSOLE_JS
    assert (
        "history.replaceState(null, '', window.location.pathname + window.location.search)"
        in APP_JS
    )
    assert "/api/session" in CONSOLE_JS
    assert "Authorization: `Bearer ${state.sessionToken}`" in CONSOLE_JS
    assert "navigator.clipboard" not in CONSOLE_JS
    assert "create agent" not in CONSOLE_JS.lower()
    assert "delete agent" not in CONSOLE_JS.lower()
    assert "Math.random" not in CONSOLE_JS
    assert "getRandomValues" in CONSOLE_JS
    assert '"X-EBA-CSRF"' in CONSOLE_JS
    assert "agent.customerFacing" in CONSOLE_JS
