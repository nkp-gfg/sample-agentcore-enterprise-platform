"""Boundary tests for the loopback-only hr-web server.

Three guarantees this file pins:

1. The server refuses a request whose ``Host`` header is not a loopback
   authority, even though the socket is already bound to ``127.0.0.1``.
2. The server exposes no create / update / delete routes: every write verb
   on every path answers ``4xx``, and the response is a safe JSON envelope.
3. ``GET /config.json`` returns exactly the six non-secret fields built
   from the four whitelisted SSM parameters plus the pinned A2UI protocol
   version. A secret value sitting at an unrelated SSM path, or an extra
   field in the SSM-sourced payload, is never written to the browser.

SSM is mocked. The server reads nothing from AWS.
"""

from __future__ import annotations

import json
import sys
import threading
import time
from http import HTTPStatus
from http.client import HTTPConnection
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
HR_WEB = REPO / "hr-web"

sys.path.insert(0, str(HR_WEB))

import server  # type: ignore[import-not-found]

VALID_RUNTIME_ARN = (
    "arn:aws:bedrock-agentcore:eu-west-1:111111111111:runtime/orchestrator-abc"
)
VALID_ISSUER = "https://cognito-idp.eu-west-1.amazonaws.com/eu-west-1_pool"
VALID_GATEWAY = "https://gw.example.com/mcp"
VALID_WEB_CLIENT_ID = "1a2b3c4d5e"
SECRET_CANARY = "SECRET-DO-NOT-LEAK-" + ("x" * 20)  # pragma: allowlist secret


def _stub_bearer_header() -> str:
    import base64

    hdr = base64.urlsafe_b64encode(b'{"alg":"none"}').rstrip(b"=").decode()
    body = base64.urlsafe_b64encode(b'{"sub":"u1"}').rstrip(b"=").decode()
    return f"Bearer {hdr}.{body}.sig"


def _public_config() -> server.PublicConfig:
    return server.PublicConfig(
        runtime_arn=VALID_RUNTIME_ARN,
        region="eu-west-1",
        web_client_id=VALID_WEB_CLIENT_ID,
        issuer_url=VALID_ISSUER,
        gateway_url=VALID_GATEWAY,
        a2ui_protocol_version=server.A2UI_PROTOCOL_VERSION,
    )


@pytest.fixture
def running_server():
    """Start the hr-web server on 127.0.0.1:0 and tear it down cleanly."""
    srv = server.make_server(_public_config(), host="127.0.0.1", port=0)
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    # Wait for the socket to be listening.
    for _ in range(50):
        if srv.server_port:
            break
        time.sleep(0.01)
    try:
        yield srv
    finally:
        srv.shutdown()
        srv.server_close()
        thread.join(timeout=2)


def _request(
    server_port: int,
    method: str,
    path: str,
    *,
    host_header: str | None = None,
    body: bytes | None = None,
    extra_headers: dict[str, str] | None = None,
) -> tuple[int, dict[str, str], bytes]:
    """Low-level HTTP request so we can set an arbitrary ``Host`` header."""
    conn = HTTPConnection("127.0.0.1", server_port, timeout=5)
    headers = dict(extra_headers or {})
    headers.setdefault("Host", host_header or f"127.0.0.1:{server_port}")
    try:
        conn.request(method, path, body=body, headers=headers)
        response = conn.getresponse()
        return (
            response.status,
            {k.lower(): v for k, v in response.getheaders()},
            response.read(),
        )
    finally:
        conn.close()


# ---------------------------------------------------------------- 1. Loopback


def test_make_server_refuses_non_loopback_host():
    # The server-boot path does not trust an operator who flips the bind
    # address: binding anything other than loopback is a configuration bug
    # we flag at boot, not a runtime check we hope succeeds.
    with pytest.raises(server.ConfigError, match="loopback"):
        server.make_server(_public_config(), host="0.0.0.0", port=0)  # nosec B104 — tests non-loopback rejection


def test_rejects_non_loopback_host_header(running_server):
    status, _, body = _request(
        running_server.server_port,
        "GET",
        "/config.json",
        host_header="attacker.example",
    )
    assert status == HTTPStatus.FORBIDDEN
    assert "loopback" in json.loads(body)["error"].lower()


def test_rejects_non_loopback_host_header_on_root(running_server):
    status, _, _ = _request(
        running_server.server_port,
        "GET",
        "/",
        host_header="rebound.local",
    )
    assert status == HTTPStatus.FORBIDDEN


def test_accepts_loopback_host_header(running_server):
    from urllib.parse import urlsplit

    status, headers, _ = _request(
        running_server.server_port,
        "GET",
        "/",
    )
    assert status == HTTPStatus.OK
    assert headers.get("x-frame-options") == "DENY"
    csp = headers.get("content-security-policy", "")
    assert "frame-ancestors 'none'" in csp
    assert "style-src 'self'" in csp
    assert "'unsafe-inline'" not in csp
    # W3C CSP forbids mid-hostname wildcards like `https://cognito-idp.*.amazonaws.com`
    # (which Chrome/Safari reject, blocking OIDC discovery on Sign in).
    assert ".*." not in csp
    issuer_origin = f"https://{urlsplit(VALID_ISSUER).netloc}"
    cfg = _public_config()
    assert issuer_origin in csp
    assert f"https://*.auth.{cfg.region}.amazoncognito.com" in csp
    assert "https://*.amazoncognito.com" not in csp
    assert "https://login.microsoftonline.com" not in csp


# ---------------------------------------------------- 2. No mutation surface


@pytest.mark.parametrize("method", ["POST", "PUT", "DELETE", "PATCH"])
@pytest.mark.parametrize(
    "path",
    [
        "/",
        "/config.json",
        "/api/anything",
        "/create",
        "/update",
        "/delete",
        "/leave",
        "/approve",
    ],
)
def test_no_create_update_delete_route_is_exposed(running_server, method, path):
    status, _, body = _request(
        running_server.server_port,
        method,
        path,
        body=b"{}",
        extra_headers={"Content-Type": "application/json"},
    )
    # Every write verb on every path answers 4xx, and the response is a
    # safe JSON envelope: the server is read-only by construction.
    assert status in {
        HTTPStatus.METHOD_NOT_ALLOWED,
        HTTPStatus.NOT_FOUND,
        HTTPStatus.FORBIDDEN,
        HTTPStatus.BAD_REQUEST,
    }
    envelope = json.loads(body)
    assert "error" in envelope
    # No path ever responds with a success code to a mutation.
    assert status < 200 or status >= 400


def test_invented_api_path_on_get_is_404(running_server):
    status, _, _ = _request(running_server.server_port, "GET", "/api/anything")
    assert status == HTTPStatus.NOT_FOUND


# ---------------------------------------------------- 3. /config.json shape


def test_config_endpoint_returns_only_whitelisted_fields(running_server):
    status, headers, body = _request(
        running_server.server_port,
        "GET",
        "/config.json",
    )
    assert status == HTTPStatus.OK
    assert headers.get("cache-control") == "no-store"
    assert headers.get("content-type", "").startswith("application/json")
    payload = json.loads(body)
    assert set(payload) == {
        "runtime_arn",
        "region",
        "web_client_id",
        "issuer_url",
        "gateway_url",
        "a2ui_protocol_version",
    }
    assert payload["runtime_arn"] == VALID_RUNTIME_ARN
    assert payload["region"] == "eu-west-1"
    assert payload["issuer_url"] == VALID_ISSUER
    assert payload["gateway_url"] == VALID_GATEWAY
    assert payload["web_client_id"] == VALID_WEB_CLIENT_ID
    # The A2UI protocol version is a pinned compile-time constant, not an SSM
    # value. The browser refuses any inbound message whose ``version`` field
    # disagrees, which is how a stale catalog in the agent surfaces as a
    # single failed render instead of a silent shape mismatch.
    assert payload["a2ui_protocol_version"] == server.A2UI_PROTOCOL_VERSION
    # Every value is a URL or a public identifier. None of them look like
    # an access key, a password, or a client secret.
    serialized = json.dumps(payload)
    assert "secret" not in serialized.lower()
    assert "password" not in serialized.lower()
    assert "AKIA" not in serialized
    assert "ASIA" not in serialized


def test_config_endpoint_never_leaks_an_unrelated_ssm_secret():
    """A secret under an unrelated SSM path has no path into /config.json.

    Even if the SSM reader is coerced to return a value with a canary string,
    the server reads only the four whitelisted leaves, and its serializer
    is gated on PUBLIC_CONFIG_FIELDS. An extra ``secret`` field from a
    confused reader cannot reach the browser.
    """

    def hostile_reader(name: str) -> str:
        values = {
            "/proj/dev/runtimes/orchestrator/arn": VALID_RUNTIME_ARN,
            "/proj/dev/auth/web-client-id": VALID_WEB_CLIENT_ID,
            "/proj/dev/auth/issuer-url": VALID_ISSUER,
            "/proj/dev/gateway/url": VALID_GATEWAY,
        }
        if name in values:
            return values[name]
        # The reader is only called for the four whitelisted leaves; any
        # other path is a bug and should NOT produce a value that reaches
        # the config.
        raise AssertionError(
            f"hr-web asked SSM for a non-whitelisted path: {name}. "
            f"If this ever surfaces a {SECRET_CANARY!r} value, the "
            "server lost its read-only contract."
        )

    config = server.load_config(
        project="proj",
        environment="dev",
        ssm_reader=hostile_reader,
    )
    # Even if someone later adds a free-form field to PublicConfig, the
    # browser can only ever receive the PUBLIC_CONFIG_FIELDS names.
    assert set(config.as_public_dict()) == server.PUBLIC_CONFIG_FIELDS
    # Including the pinned A2UI version, which is a compile-time constant,
    # not something that could have been coerced to a secret by the reader.
    assert (
        config.as_public_dict()["a2ui_protocol_version"] == server.A2UI_PROTOCOL_VERSION
    )
    serialized = json.dumps(config.as_public_dict())
    assert SECRET_CANARY not in serialized


def test_load_config_requires_every_parameter_to_be_present():
    def missing_reader(name: str) -> str:
        if name.endswith("/gateway/url"):
            return ""  # empty value simulates a parameter that was deleted
        return "x"

    with pytest.raises(server.ConfigError, match="gateway/url"):
        server.load_config(
            project="proj",
            environment="dev",
            ssm_reader=missing_reader,
        )


def test_load_config_rejects_a_malformed_runtime_arn():
    def bad_arn(name: str) -> str:
        if name.endswith("/runtimes/orchestrator/arn"):
            return "not-an-arn"
        if name.endswith("/auth/web-client-id"):
            return VALID_WEB_CLIENT_ID
        if name.endswith("/auth/issuer-url"):
            return VALID_ISSUER
        if name.endswith("/gateway/url"):
            return VALID_GATEWAY
        raise AssertionError(name)

    with pytest.raises(server.ConfigError, match="AgentCore ARN"):
        server.load_config(
            project="proj",
            environment="dev",
            ssm_reader=bad_arn,
        )


def test_public_config_dataclass_cannot_hold_unknown_fields():
    """Adding a field without reviewing PUBLIC_CONFIG_FIELDS is a build error.

    The server serializes only PUBLIC_CONFIG_FIELDS. If someone tacks an
    extra dataclass field on in the future, this test fails and forces a
    review of whether that new field is safe to send to the browser.
    """
    from dataclasses import fields

    assert {f.name for f in fields(server.PublicConfig)} == server.PUBLIC_CONFIG_FIELDS


def test_a2ui_protocol_version_is_a_bare_semver_string():
    """The pinned A2UI protocol version is a short public string, never a URL.

    A version pin that ever carries a scheme, a credential or a host is
    almost certainly a configuration mistake: the A2UI v1.0 wire spec names
    its version as ``"1.0"``, not as a URL.
    """
    value = server.A2UI_PROTOCOL_VERSION
    assert isinstance(value, str)
    assert value.strip() == value and value
    assert "://" not in value
    assert "@" not in value
    assert "/" not in value
    assert "secret" not in value.lower()


def test_invocations_rejects_unauthenticated_and_cross_origin_requests(running_server):
    """POST /invocations requires loopback Host, loopback Origin, Bearer token, and valid session id."""
    # Missing Bearer token -> 401
    status, _, body = _request(
        running_server.server_port,
        "POST",
        "/invocations",
        body=b"{}",
        extra_headers={"Content-Type": "application/json"},
    )
    assert status == HTTPStatus.UNAUTHORIZED
    assert "bearer" in json.loads(body)["error"].lower()

    # Cross-origin Origin header -> 403
    status, _, body = _request(
        running_server.server_port,
        "POST",
        "/invocations",
        body=b"{}",
        extra_headers={
            "Content-Type": "application/json",
            "Origin": "https://evil.example",
            "Authorization": _stub_bearer_header(),
            "X-Amzn-Bedrock-AgentCore-Runtime-Session-Id": "session-" + ("a" * 32),
        },
    )
    assert status == HTTPStatus.FORBIDDEN

    # Short session id -> 400
    status, _, body = _request(
        running_server.server_port,
        "POST",
        "/invocations",
        body=b"{}",
        extra_headers={
            "Content-Type": "application/json",
            "Authorization": _stub_bearer_header(),
            "X-Amzn-Bedrock-AgentCore-Runtime-Session-Id": "short",
        },
    )
    assert status == HTTPStatus.BAD_REQUEST


def test_default_boto3_ssm_reader_queries_single_prefixed_paths(monkeypatch):
    """Regression: default boto3 reader must not double-prefix `/{project}/{env}`."""
    seen_names: list[str] = []

    class FakeSsmClient:
        def get_parameter(self, *, Name: str) -> dict:
            seen_names.append(Name)
            assert "//" not in Name, f"Double slash in SSM parameter path: {Name}"
            mapping = {
                "/agentcore-production/prod/runtimes/orchestrator/arn": VALID_RUNTIME_ARN,
                "/agentcore-production/prod/auth/web-client-id": VALID_WEB_CLIENT_ID,
                "/agentcore-production/prod/auth/issuer-url": VALID_ISSUER,
                "/agentcore-production/prod/gateway/url": VALID_GATEWAY,
            }
            return {"Parameter": {"Value": mapping[Name]}}

    import boto3

    monkeypatch.setattr(boto3, "client", lambda *_a, **_kw: FakeSsmClient())
    cfg = server.load_config(
        project="agentcore-production",
        environment="prod",
        region="eu-west-1",
    )
    assert cfg.region == "eu-west-1"
    assert seen_names == [
        "/agentcore-production/prod/runtimes/orchestrator/arn",
        "/agentcore-production/prod/auth/web-client-id",
        "/agentcore-production/prod/auth/issuer-url",
        "/agentcore-production/prod/gateway/url",
    ]


# ------------------------------------ 4. Static enterprise & SVG asset checks


def test_serves_enterprise_catalog_asset_with_security_headers(running_server):
    """Static /enterprise-catalog.js is served locally with hardening headers."""
    status, headers, body = _request(
        running_server.server_port,
        "GET",
        "/enterprise-catalog.js",
    )
    assert status == HTTPStatus.OK
    assert "javascript" in headers.get("content-type", "").lower()
    assert headers.get("x-content-type-options") == "nosniff"
    assert headers.get("x-frame-options") == "DENY"
    csp = headers.get("content-security-policy", "")
    assert "script-src 'self'" in csp

    text = body.decode("utf-8")
    for expected in (
        "window.EnterpriseCatalog",
        "Object.freeze",
        "APP_TITLE",
        "APP_SUBTITLE",
        "BOTS",
        "MARKETPLACE_AGENTS",
        "PROMPTS",
        "GUIDE_SECTIONS",
    ):
        assert expected in text

    lowered = text.lower()
    for forbidden in ("akia", "asia", "client_secret", "https://", "http://"):
        assert forbidden not in lowered

    # Non-loopback Host header and mutation verbs are refused on static assets too.
    bad_status, _, _ = _request(
        running_server.server_port,
        "GET",
        "/enterprise-catalog.js",
        host_header="attacker.example",
    )
    assert bad_status == HTTPStatus.FORBIDDEN

    for method in ("POST", "PUT", "DELETE", "PATCH"):
        m_status, _, m_body = _request(
            running_server.server_port,
            method,
            "/enterprise-catalog.js",
            body=b"{}",
        )
        assert m_status == HTTPStatus.METHOD_NOT_ALLOWED
        assert "error" in json.loads(m_body)


def test_enterprise_catalog_pins_god_agent_graph_and_tool_names():
    """enterprise-catalog.js matches the deployed god-agent graph and tool map."""
    catalog_path = HR_WEB / "public" / "enterprise-catalog.js"
    assert catalog_path.is_file()
    text = catalog_path.read_text(encoding="utf-8")

    expected_bot_ids = (
        "god-bot",
        "hr-operations",
        "leave-balance",
        "leave-eligibility",
        "leave-submit",
        "hr-payroll",
        "compensation",
        "direct-reports",
        "finance-payroll",
        "allowance",
        "review-node",
        "code-agent",
        "research-agent",
        "platform-gateway",
    )
    for bot_id in expected_bot_ids:
        assert f'"{bot_id}"' in text

    expected_tools = (
        "hr-ops___get_leave_balance",
        "hr-ops___check_leave_eligibility",
        "hr-ops___submit_leave_request",
        "hr-payroll___get_employee_compensation",
        "hr-payroll___list_direct_reports",
        "hr-finance___get_allowance",
        "hr-ops___record_leave_decision",
    )
    for tool_name in expected_tools:
        assert f'"{tool_name}"' in text

    for category in (
        "Leave",
        "Allowances",
        "Team & Compensation",
        "Approvals",
        "Security & Guardrails",
        "Platform",
    ):
        assert f'"{category}"' in text


def test_serves_favicon_svg_asset_with_security_headers(running_server):
    """Static /favicon.svg is a safe inline-free SVG served only to loopback."""
    status, headers, body = _request(
        running_server.server_port,
        "GET",
        "/favicon.svg",
    )
    assert status == HTTPStatus.OK
    assert headers.get("content-type", "").startswith("image/svg+xml")
    assert headers.get("x-content-type-options") == "nosniff"
    assert headers.get("x-frame-options") == "DENY"
    csp = headers.get("content-security-policy", "")
    assert "img-src 'self' data:" in csp

    svg = body.decode("utf-8")
    assert "<svg" in svg
    assert 'xmlns="http://www.w3.org/2000/svg"' in svg
    assert "</svg>" in svg
    assert "<script" not in svg.lower()

    bad_status, _, _ = _request(
        running_server.server_port,
        "GET",
        "/favicon.svg",
        host_header="attacker.example",
    )
    assert bad_status == HTTPStatus.FORBIDDEN

    for method in ("POST", "PUT", "DELETE", "PATCH"):
        m_status, _, m_body = _request(
            running_server.server_port,
            method,
            "/favicon.svg",
            body=b"<svg/>",
        )
        assert m_status == HTTPStatus.METHOD_NOT_ALLOWED
        assert "error" in json.loads(m_body)


# ------------------------------------ 5. Hardening & streaming regressions


def test_host_header_requires_explicit_matching_port(running_server):
    """Host headers omitting the port or naming a different port are rejected."""
    for bad_host in (
        "127.0.0.1",
        "localhost",
        f"127.0.0.1:{running_server.server_port + 1}",
        "127.0.0.1:80",
    ):
        status, _, body = _request(
            running_server.server_port,
            "GET",
            "/config.json",
            host_header=bad_host,
        )
        assert status == HTTPStatus.FORBIDDEN, bad_host
        assert "loopback" in json.loads(body)["error"].lower()


def test_invocations_requires_exact_same_origin_when_origin_present(running_server):
    """Origin must match Host (scheme=http, same loopback host and port)."""
    port = running_server.server_port
    base_headers = {
        "Content-Type": "application/json",
        "Authorization": _stub_bearer_header(),
        "X-Amzn-Bedrock-AgentCore-Runtime-Session-Id": "session-" + ("a" * 32),
    }

    # Cross-alias loopback (localhost vs 127.0.0.1) is refused.
    status, _, _ = _request(
        port,
        "POST",
        "/invocations",
        body=b"{}",
        host_header=f"127.0.0.1:{port}",
        extra_headers={**base_headers, "Origin": f"http://localhost:{port}"},
    )
    assert status == HTTPStatus.FORBIDDEN

    # Wrong scheme (https vs http) is refused.
    status, _, _ = _request(
        port,
        "POST",
        "/invocations",
        body=b"{}",
        host_header=f"127.0.0.1:{port}",
        extra_headers={**base_headers, "Origin": f"https://127.0.0.1:{port}"},
    )
    assert status == HTTPStatus.FORBIDDEN


def test_invocations_streams_sse_incrementally_via_read1(running_server, monkeypatch):
    """_forward_invocations uses read1() so small SSE chunks flush immediately."""
    first_chunk_sent = threading.Event()
    release_second_chunk = threading.Event()

    class FakeUpstreamResponse:
        def __init__(self):
            self.headers = {"Content-Type": "text/event-stream"}
            self._step = 0

        def __enter__(self):
            return self

        def __exit__(self, *_a):
            return False

        def read1(self, _n: int) -> bytes:
            if self._step == 0:
                self._step = 1
                first_chunk_sent.set()
                return b'data: {"type":"RUN_STARTED"}\n\n'
            if self._step == 1:
                assert release_second_chunk.wait(timeout=3)
                self._step = 2
                return b'data: {"type":"RUN_FINISHED"}\n\n'
            return b""

        def read(self, _n: int) -> bytes:
            raise AssertionError("read1 should be preferred over buffered read()")

    monkeypatch.setattr(server, "urlopen", lambda *_a, **_kw: FakeUpstreamResponse())

    port = running_server.server_port
    conn = HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        conn.request(
            "POST",
            "/invocations",
            body=b'{"threadId":"t1"}',
            headers={
                "Host": f"127.0.0.1:{port}",
                "Origin": f"http://127.0.0.1:{port}",
                "Content-Type": "application/json",
                "Authorization": _stub_bearer_header(),
                "X-Amzn-Bedrock-AgentCore-Runtime-Session-Id": "session-" + ("a" * 32),
            },
        )
        resp = conn.getresponse()
        assert resp.status == HTTPStatus.OK
        assert first_chunk_sent.wait(timeout=2)
        chunk1 = resp.read1(4096)
        assert b"RUN_STARTED" in chunk1
        release_second_chunk.set()
        rest = resp.read()
        assert b"RUN_FINISHED" in rest
    finally:
        release_second_chunk.set()
        conn.close()


def test_main_accepts_region_cli_flag(monkeypatch):
    """--region is parsed and forwarded to load_config()."""
    captured: dict[str, object] = {}

    def fake_load_config(
        *, project=None, environment=None, region=None, ssm_reader=None
    ):
        captured["project"] = project
        captured["environment"] = environment
        captured["region"] = region
        return _public_config()

    class FakeServer:
        def serve_forever(self):
            raise KeyboardInterrupt()

        def server_close(self):
            captured["closed"] = True

    monkeypatch.setattr(server, "load_config", fake_load_config)
    monkeypatch.setattr(server, "make_server", lambda *_a, **_kw: FakeServer())
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "server.py",
            "--project",
            "agentcore-production",
            "--environment",
            "prod",
            "--region",
            "ap-southeast-1",
            "--port",
            "8899",
        ],
    )
    server.main()
    assert captured == {
        "project": "agentcore-production",
        "environment": "prod",
        "region": "ap-southeast-1",
        "closed": True,
    }


def test_app_js_client_security_invariants():
    """app.js keeps tokens/history out of persistent storage, drops inline styles, and enforces OIDC nonce/iss/aud."""
    app_text = (HR_WEB / "public" / "app.js").read_text(encoding="utf-8")
    assert "localStorage.setItem" not in app_text
    assert "window.HrWeb" not in app_text
    assert "injectFallbackStyles" not in app_text
    assert "historyByUser" in app_text
    assert "sessionStorage.setItem(key" not in app_text
    assert "revocation_endpoint" in app_text
    assert "nonce: oidcNonce" in app_text
    assert "ID token nonce mismatch" in app_text
    assert "ID token issuer mismatch" in app_text
    assert "ID token audience mismatch" in app_text
    for dangerous_sink in (
        ".innerHTML",
        ".outerHTML",
        "insertAdjacentHTML",
        "document.write",
    ):
        assert dangerous_sink not in app_text


def test_csp_connect_src_scopes_to_direct_entra_issuer():
    """Direct Entra issuer gets login.microsoftonline.com without Cognito wildcards."""
    entra_cfg = server.PublicConfig(
        runtime_arn=VALID_RUNTIME_ARN,
        region=_public_config().region,
        web_client_id=VALID_WEB_CLIENT_ID,
        issuer_url="https://login.microsoftonline.com/tenant-123/v2.0",
        gateway_url=VALID_GATEWAY,
        a2ui_protocol_version=server.A2UI_PROTOCOL_VERSION,
    )
    srv = server.make_server(entra_cfg, host="127.0.0.1", port=0)
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    for _ in range(50):
        if srv.server_port:
            break
        time.sleep(0.01)
    try:
        status, headers, _ = _request(srv.server_port, "GET", "/")
        assert status == HTTPStatus.OK
        csp = headers.get("content-security-policy", "")
        assert "https://login.microsoftonline.com" in csp
        assert "amazoncognito.com" not in csp
    finally:
        srv.shutdown()
        srv.server_close()
        thread.join(timeout=2)


def test_invocations_validates_content_type_and_json_object(running_server):
    """POST /invocations requires Content-Type: application/json and a JSON object body."""
    port = running_server.server_port
    auth_headers = {
        "Authorization": _stub_bearer_header(),
        "X-Amzn-Bedrock-AgentCore-Runtime-Session-Id": "session-" + ("a" * 32),
    }

    # Wrong Content-Type -> 415
    status, _, body = _request(
        port,
        "POST",
        "/invocations",
        body=b"{}",
        extra_headers={**auth_headers, "Content-Type": "text/plain"},
    )
    assert status == HTTPStatus.UNSUPPORTED_MEDIA_TYPE
    assert "application/json" in json.loads(body)["error"]

    # Invalid JSON -> 400
    status, _, body = _request(
        port,
        "POST",
        "/invocations",
        body=b"{not-json",
        extra_headers={**auth_headers, "Content-Type": "application/json"},
    )
    assert status == HTTPStatus.BAD_REQUEST
    assert "valid json" in json.loads(body)["error"].lower()

    # Non-object JSON -> 400
    status, _, body = _request(
        port,
        "POST",
        "/invocations",
        body=b'["array"]',
        extra_headers={**auth_headers, "Content-Type": "application/json"},
    )
    assert status == HTTPStatus.BAD_REQUEST
    assert "json object" in json.loads(body)["error"].lower()


def test_invocation_gate_rate_limit_and_concurrency(monkeypatch):
    """InvocationGate bounds concurrent streams and per-minute rate with 429."""
    gate = server.InvocationGate(concurrent=1, per_minute=2)
    srv = server.make_server(
        _public_config(), host="127.0.0.1", port=0, invocation_gate=gate
    )
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    for _ in range(50):
        if srv.server_port:
            break
        time.sleep(0.01)

    entered = threading.Event()
    release = threading.Event()

    class BlockingUpstream:
        def __init__(self):
            self.headers = {"Content-Type": "text/event-stream"}

        def __enter__(self):
            entered.set()
            assert release.wait(timeout=3)
            return self

        def __exit__(self, *_a):
            return False

        def read1(self, _n: int) -> bytes:
            return b""

    monkeypatch.setattr(server, "urlopen", lambda *_a, **_kw: BlockingUpstream())
    req_headers = {
        "Content-Type": "application/json",
        "Authorization": _stub_bearer_header(),
        "X-Amzn-Bedrock-AgentCore-Runtime-Session-Id": "session-" + ("a" * 32),
    }

    first_result: list[int] = []

    def _run_first():
        st, _, _ = _request(
            srv.server_port,
            "POST",
            "/invocations",
            body=b'{"threadId":"t1"}',
            extra_headers=req_headers,
        )
        first_result.append(st)

    try:
        t1 = threading.Thread(target=_run_first, daemon=True)
        t1.start()
        assert entered.wait(timeout=2)

        # Second concurrent request hits concurrency limit -> 429.
        st2, _, body2 = _request(
            srv.server_port,
            "POST",
            "/invocations",
            body=b'{"threadId":"t2"}',
            extra_headers=req_headers,
        )
        assert st2 == HTTPStatus.TOO_MANY_REQUESTS
        assert "too many" in json.loads(body2)["error"].lower()

        release.set()
        t1.join(timeout=3)
        assert first_result == [HTTPStatus.OK]

        # Second sequential request succeeds (per_minute=2).
        st3, _, _ = _request(
            srv.server_port,
            "POST",
            "/invocations",
            body=b'{"threadId":"t3"}',
            extra_headers=req_headers,
        )
        assert st3 == HTTPStatus.OK

        # Third request in same minute hits per_minute=2 -> 429.
        st4, _, _ = _request(
            srv.server_port,
            "POST",
            "/invocations",
            body=b'{"threadId":"t4"}',
            extra_headers=req_headers,
        )
        assert st4 == HTTPStatus.TOO_MANY_REQUESTS
    finally:
        release.set()
        srv.shutdown()
        srv.server_close()
        thread.join(timeout=2)


def test_urlopen_blocks_http_redirects():
    """server.urlopen disables 3xx redirects so Bearer tokens never leave origin."""
    from http.server import BaseHTTPRequestHandler, HTTPServer
    from urllib.error import HTTPError
    from urllib.request import Request

    saw_target = False

    class RedirectHandler(BaseHTTPRequestHandler):
        def do_POST(self):
            nonlocal saw_target
            if self.path == "/redirect":
                self.send_response(302)
                self.send_header("Location", "/secret-target")
                self.end_headers()
            else:
                saw_target = True
                self.send_response(200)
                self.end_headers()

        def log_message(self, *_a):
            pass

    target_srv = HTTPServer(("127.0.0.1", 0), RedirectHandler)
    t = threading.Thread(target=target_srv.serve_forever, daemon=True)
    t.start()
    try:
        req = Request(
            f"http://127.0.0.1:{target_srv.server_port}/redirect",
            data=b"{}",
            headers={"Authorization": "Bearer secret-token"},
            method="POST",
        )
        with pytest.raises(HTTPError) as exc_info:
            server.urlopen(req, timeout=2)
        assert exc_info.value.code == 302
        assert saw_target is False
    finally:
        target_srv.shutdown()
        target_srv.server_close()
        t.join(timeout=2)


def test_invocations_hides_raw_urlerror_reason(running_server, monkeypatch):
    """URLError returns generic 502 error without exposing internal exc.reason."""
    from urllib.error import URLError

    def fail_urlopen(*_a, **_kw):
        raise URLError("SENSITIVE_INTERNAL_DNS_ERROR")

    monkeypatch.setattr(server, "urlopen", fail_urlopen)
    status, _, body = _request(
        running_server.server_port,
        "POST",
        "/invocations",
        body=b"{}",
        extra_headers={
            "Content-Type": "application/json",
            "Authorization": _stub_bearer_header(),
            "X-Amzn-Bedrock-AgentCore-Runtime-Session-Id": "session-" + ("a" * 32),
        },
    )
    assert status == HTTPStatus.BAD_GATEWAY
    payload = json.loads(body)
    assert payload == {"error": "Could not reach AgentCore runtime."}
    assert "SENSITIVE_INTERNAL_DNS_ERROR" not in body.decode("utf-8")


def test_hr_adapter_and_primitives_days_and_multi_review_surfaces():
    """Verify EmployeeConfirmForm days fallback and keyed manager_review surfaces in Node."""
    import shutil
    import subprocess

    node = shutil.which("node")
    if not node:
        pytest.skip("node not installed")

    adapter_path = str(HR_WEB / "public" / "hr-tool-adapter.js")
    primitives_path = str(HR_WEB / "public" / "hr-primitives.js")
    script = r"""
const fs = require("fs");
const vm = require("vm");

function makeNode(tag) {
  const node = {
    tagName: tag.toUpperCase(),
    className: "",
    textContent: "",
    children: [],
    dataset: {},
    attributes: {},
    hidden: false,
    classList: { add(c) { node.className = (node.className + " " + c).trim(); } },
    setAttribute(k, v) { node.attributes[k] = String(v); },
    addEventListener() {},
    append(...items) {
      for (const it of items) {
        if (it && typeof it === "object") node.children.push(it);
      }
    },
    focus() {},
  };
  return node;
}

const windowObj = {};
const sandbox = {
  window: windowObj,
  document: { createElement: makeNode },
  console,
};
vm.createContext(sandbox);
vm.runInContext(fs.readFileSync(process.argv[1], "utf8"), sandbox);
vm.runInContext(fs.readFileSync(process.argv[2], "utf8"), sandbox);

const adapter = sandbox.window.HrToolAdapter;
const catalog = sandbox.window.HrCatalog;

// 1. Top-level days preserved when arguments lacks days; empty string falls back to deriveDays.
const msgsTopDays = adapter.fromInterrupt({
  kind: "employee_confirm",
  days: 4,
  arguments: {
    leave_type: "annual",
    start_date: "2026-12-01",
    end_date: "2026-12-04",
    reason: "Trip",
  },
});
const topProps = msgsTopDays[1].createSurface.components[0];
if (topProps.days !== 4) throw new Error("Expected top-level days 4, got " + topProps.days);

const cardFromBlank = catalog.components.EmployeeConfirmForm(
  { leaveType: "annual", startDate: "2026-12-01", endDate: "2026-12-03", days: "", reason: "Trip" },
  { emitAction() {} },
);
const dlText = JSON.stringify(cardFromBlank);
if (!dlText.includes('"Days"') || !dlText.includes('"3"')) {
  throw new Error("Expected derived Days 3 when days is empty string: " + dlText);
}

// 2. Concurrent manager_review interrupts get distinct surfaces keyed by request_id.
const rev1 = adapter.fromInterrupt({
  kind: "manager_review",
  request_id: "lr-111",
  employee_id: "E1",
  leave_type: "annual",
  start_date: "2026-12-01",
  end_date: "2026-12-03",
  days: 3,
  reason: "A",
});
const rev2 = adapter.fromInterrupt({
  kind: "manager_review",
  request_id: "lr-222",
  employee_id: "E2",
  leave_type: "sick",
  start_date: "2026-12-05",
  end_date: "2026-12-05",
  days: 1,
  reason: "B",
});
const s1 = rev1[1].createSurface.surfaceId;
const s2 = rev2[1].createSurface.surfaceId;
if (s1 === s2 || s1 !== "surface-manager-review-lr-111" || s2 !== "surface-manager-review-lr-222") {
  throw new Error(`Expected distinct keyed surfaces, got ${s1} and ${s2}`);
}

const del1 = adapter.clearSurfacesFor("manager_review", "lr-111");
if (del1[0].deleteSurface.surfaceId !== "surface-manager-review-lr-111") {
  throw new Error("Unexpected delete surfaceId: " + JSON.stringify(del1));
}
"""
    res = subprocess.run(
        [node, "-e", script, adapter_path, primitives_path],
        capture_output=True,
        text=True,
        check=False,
    )
    assert res.returncode == 0, res.stderr or res.stdout
