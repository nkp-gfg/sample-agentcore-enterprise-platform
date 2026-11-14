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
SECRET_CANARY = "SECRET-DO-NOT-LEAK-" + ("x" * 20)


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
        server.make_server(_public_config(), host="0.0.0.0", port=0)


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
    status, headers, _ = _request(
        running_server.server_port,
        "GET",
        "/",
    )
    assert status == HTTPStatus.OK
    assert headers.get("x-frame-options") == "DENY"
    csp = headers.get("content-security-policy", "")
    assert "frame-ancestors 'none'" in csp
    # W3C CSP forbids mid-hostname wildcards like `https://cognito-idp.*.amazonaws.com`
    # (which Chrome/Safari reject, blocking OIDC discovery on Sign in).
    assert ".*." not in csp
    assert "https://cognito-idp.eu-west-1.amazonaws.com" in csp
    assert "https://bedrock-agentcore.eu-west-1.amazonaws.com" in csp
    assert "https://*.amazoncognito.com" in csp
    assert "https://login.microsoftonline.com" in csp


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
            "Authorization": "Bearer eyJhbGciOiJub25lIn0.eyJzdWIiOiJ1MSJ9.sig",
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
            "Authorization": "Bearer eyJhbGciOiJub25lIn0.eyJzdWIiOiJ1MSJ9.sig",
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

