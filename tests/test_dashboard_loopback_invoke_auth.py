"""Loopback clients must not be able to invoke a deployed runtime.

The console binds to 127.0.0.1 and treats a process-wide token as the
credential for POST /api/invoke. These tests act as a second TCP client.
They may use only headers they set themselves and values the server has
already written into an HTTP response. They must not be able to make the
process call AWS or return assistant text.

The tests fail while GET /api/health (or any other unauthenticated
response) still discloses a value the invoke handler will accept.
"""

from __future__ import annotations

import json
import os
import threading
import urllib.parse
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from http.client import HTTPConnection
from http.server import ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace

import pytest
from botocore.exceptions import ClientError

REPO = Path(__file__).resolve().parents[1]
import sys

sys.path.insert(0, str(REPO))

from dashboard import server

ACCOUNT = "111111111111"
REGION = "eu-west-1"
PROJECT = "project"
ENVIRONMENT = "dev"
RUNTIME_ARN = (
    f"arn:aws:bedrock-agentcore:{REGION}:{ACCOUNT}:runtime/orchestrator-under-test"
)
GATEWAY_URL = "https://gateway.example.invalid/mcp"
APP_CLIENT_ID = "placeholder-app-client-id"
M2M_CLIENT_ID = "placeholder-m2m-client-id"
ASSISTANT_MARKER = "loopback-invoke-marker"
ATTACKER_PROMPT = "synthetic loopback prompt"
SESSION_ID = "session-" + ("b" * 32)
# Chosen by the caller. It is not read from the server.
ATTACKER_CHOSEN_HEADER = "attacker-supplied-value"

# Deployment identifiers the finding says a loopback reader learns from
# status.json. None of these are credentials; they are fixture labels.
SENSITIVE_FACTS = (ACCOUNT, RUNTIME_ARN, GATEWAY_URL, APP_CLIENT_ID, M2M_CLIENT_ID)


class _AwsClient:
    """Stand-in for the boto3 clients this request path actually calls.

    Built from dashboard/server.py validate_operator_identity and from
    scripts/utils.py auth_mode, get_ssm_param, _optional_ssm_param, and
    get_m2m_token. Successful responses let that code keep going. The
    recorded calls are the operator-credential use the attacker must
    not be able to cause.
    """

    def __init__(self, service: str, region_name: str | None, calls: list[tuple]):
        self.service = service
        self.region_name = region_name
        self._calls = calls

    def get_caller_identity(self) -> dict[str, str]:
        self._calls.append((self.service, "get_caller_identity", self.region_name))
        return {"Account": ACCOUNT}

    def get_parameter(self, *, Name: str) -> dict:
        self._calls.append((self.service, "get_parameter", Name))
        if Name.endswith("/auth/m2m-client-secret-name"):
            raise ClientError(
                {"Error": {"Code": "ParameterNotFound", "Message": "missing"}},
                "GetParameter",
            )
        values = {
            f"/{PROJECT}/{ENVIRONMENT}/auth/mode": "brokered",
            f"/{PROJECT}/{ENVIRONMENT}/auth/user-pool-id": "placeholder-user-pool-id",
            f"/{PROJECT}/{ENVIRONMENT}/auth/m2m-client-id": M2M_CLIENT_ID,
        }
        try:
            value = values[Name]
        except KeyError as exc:
            raise ClientError(
                {"Error": {"Code": "ParameterNotFound", "Message": "missing"}},
                "GetParameter",
            ) from exc
        return {"Parameter": {"Value": value}}

    def describe_user_pool_client(self, *, UserPoolId: str, ClientId: str) -> dict:
        self._calls.append(
            (self.service, "describe_user_pool_client", UserPoolId, ClientId)
        )
        return {
            "UserPoolClient": {
                "ClientSecret": "placeholder-client-secret",
            }
        }


class _HttpBody:
    def __init__(self, payload: bytes):
        self._payload = payload
        self._offset = 0

    def read(self, amount: int = -1) -> bytes:
        if amount is None or amount < 0:
            amount = len(self._payload) - self._offset
        chunk = self._payload[self._offset : self._offset + amount]
        self._offset += len(chunk)
        return chunk


def _status_document() -> dict:
    now = datetime.now(UTC) - timedelta(seconds=1)
    suffix = server.COMPONENTS["orchestrator"]
    return {
        "available": True,
        "timestamp": now.isoformat(),
        "account": ACCOUNT,
        "region": REGION,
        "project": PROJECT,
        "environment": ENVIRONMENT,
        "stacks": {
            f"{PROJECT}-{ENVIRONMENT}-{suffix}": {
                "state": "deployed",
                "outputs": {
                    "RuntimeArn": RUNTIME_ARN,
                    "RuntimeId": "runtime-id",
                },
            }
        },
        "ssm_parameters": {
            "gateway/url": GATEWAY_URL,
            "auth/app-client-id": APP_CLIENT_ID,
            "auth/m2m-client-id": M2M_CLIENT_ID,
        },
    }


@pytest.fixture
def console(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> Iterator[SimpleNamespace]:
    public = tmp_path / "public"
    public.mkdir()
    status_path = public / "status.json"
    status_path.write_text(json.dumps(_status_document()), encoding="utf-8")
    os.chmod(status_path, 0o600)

    monkeypatch.setattr(server, "PUBLIC", public)
    monkeypatch.setattr(server, "STATUS_FILE", status_path)
    monkeypatch.setattr(server, "INVOCATION_GATE", server.InvocationGate())
    monkeypatch.setenv("AWS_REGION", REGION)
    monkeypatch.setenv("AWS_DEFAULT_REGION", REGION)
    monkeypatch.setenv("PROJECT_NAME", PROJECT)
    monkeypatch.setenv("ENVIRONMENT", ENVIRONMENT)
    monkeypatch.delenv("AGENT_PATTERN", raising=False)
    monkeypatch.delenv("PLATFORM_CONFIG", raising=False)

    aws_calls: list[tuple] = []
    outbound: list[dict] = []

    def client_factory(service: str, region_name: str | None = None, **_kwargs):
        return _AwsClient(service, region_name, aws_calls)

    real_validate = server.validate_operator_identity

    def validate_with_local_credentials(status, runtime_arn, **kwargs):
        kwargs.setdefault("client_factory", client_factory)
        return real_validate(status, runtime_arn, **kwargs)

    monkeypatch.setattr(
        server, "validate_operator_identity", validate_with_local_credentials
    )
    monkeypatch.setattr("boto3.client", client_factory)

    def urlopen(req, timeout=None, **_kwargs):
        url = getattr(req, "full_url", str(req))
        raw = getattr(req, "data", None) or b""
        if not isinstance(raw, bytes):
            raw = bytes(raw)
        has_authorization = any(
            name.lower() == "authorization" for name, _value in req.header_items()
        )
        outbound.append(
            {
                "url": url,
                "body": raw,
                "has_authorization": has_authorization,
            }
        )
        if "/invocations?" in url:
            payload = json.dumps({"response": ASSISTANT_MARKER}).encode()
        elif url.endswith("/oauth2/token"):
            payload = json.dumps({"access_token": "placeholder-access-token"}).encode()
        else:
            raise AssertionError(
                f"unexpected outbound URL shape: {url.split('?', 1)[0]}"
            )
        return _HttpBody(payload)

    monkeypatch.setattr(server.runtime_invoke.urllib.request, "urlopen", urlopen)

    httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.EbaConsoleHandler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    port = httpd.server_address[1]
    try:
        yield SimpleNamespace(
            port=port,
            aws_calls=aws_calls,
            outbound=outbound,
        )
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=5)


def _exchange(
    port: int,
    method: str,
    path: str,
    *,
    body: bytes | None = None,
    extra_headers: dict[str, str] | None = None,
) -> tuple[int, dict[str, str], bytes]:
    """One TCP connection to the console, as another local process would open."""
    headers = {
        "Host": f"127.0.0.1:{port}",
        "Accept": "application/json",
    }
    if extra_headers:
        headers.update(extra_headers)
    connection = HTTPConnection("127.0.0.1", port, timeout=10)
    try:
        connection.request(method, path, body=body, headers=headers)
        response = connection.getresponse()
        payload = response.read()
        response_headers = {key: value for key, value in response.getheaders()}
        return response.status, response_headers, payload
    finally:
        connection.close()


def _strings(value: object, label: str, found: list[tuple[str, str]]) -> None:
    if isinstance(value, str):
        if value and len(value) <= 512:
            found.append((label, value))
        return
    if isinstance(value, dict):
        for key, item in value.items():
            _strings(item, f"{label}.{key}", found)
        return
    if isinstance(value, list):
        for index, item in enumerate(value):
            _strings(item, f"{label}[{index}]", found)


def _served_values(port: int) -> list[tuple[str, str]]:
    """Every string a loopback client can learn without a prior secret.

    Includes response headers, so a token moved into Set-Cookie or another
    header is still treated as served by this process.
    """
    found: list[tuple[str, str]] = []
    paths = (
        "/api/health",
        "/api/health?t=1",
        "/status.json",
        "/status.json?t=1",
        "/",
        "/index.html",
        "/console.js",
    )
    for path in paths:
        status, headers, body = _exchange(port, "GET", path)
        for key, value in headers.items():
            _strings(value, f"GET {path} header {key}", found)
        text = body.decode("utf-8", errors="replace")
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError:
            _strings(text, f"GET {path} body status={status}", found)
        else:
            _strings(parsed, f"GET {path} status={status}", found)
    unique: list[tuple[str, str]] = []
    seen: set[str] = set()
    for label, value in found:
        if value in seen:
            continue
        seen.add(value)
        unique.append((label, value))
    return unique


def _invoke(
    port: int,
    header_value: str | None,
) -> tuple[int, bytes]:
    payload = json.dumps(
        {
            "component": "orchestrator",
            "prompt": ATTACKER_PROMPT,
            "sessionId": SESSION_ID,
        }
    ).encode()
    headers = {
        "Content-Type": "application/json",
        "Origin": f"http://127.0.0.1:{port}",
    }
    if header_value is not None:
        headers["X-EBA-CSRF"] = header_value
    status, _response_headers, body = _exchange(
        port,
        "POST",
        "/api/invoke",
        body=payload,
        extra_headers=headers,
    )
    return status, body


def _assert_invoke_refused(console: SimpleNamespace, port: int) -> None:
    attempts: list[tuple[str, str | None]] = [
        ("no X-EBA-CSRF header", None),
        ("an X-EBA-CSRF value chosen by the client", ATTACKER_CHOSEN_HEADER),
    ]
    attempts.extend(_served_values(port))
    for label, value in attempts:
        before_aws = len(console.aws_calls)
        before_outbound = len(console.outbound)
        status, body = _invoke(port, value)
        caused_aws = len(console.aws_calls) > before_aws
        new_outbound = console.outbound[before_outbound:]
        runtime_posts = [
            item for item in new_outbound if "/invocations?" in item["url"]
        ]
        prompt_reached_runtime = any(
            ATTACKER_PROMPT.encode() in item["body"] for item in runtime_posts
        )
        returned_assistant = ASSISTANT_MARKER.encode() in body
        if prompt_reached_runtime or returned_assistant or caused_aws or new_outbound:
            preview = []
            for item in runtime_posts:
                preview.append(
                    {
                        "host": item["url"].split("/", 3)[2],
                        "monitored_arn": urllib.parse.quote(RUNTIME_ARN, safe="")
                        in item["url"],
                        "invocations": "/invocations?" in item["url"],
                        "prompt_in_body": ATTACKER_PROMPT.encode() in item["body"],
                        "session_in_body": SESSION_ID.encode() in item["body"],
                        "shape": (
                            "ag-ui"
                            if b'"messages"' in item["body"]
                            else "http"
                            if b'"prompt"' in item["body"]
                            else "other"
                        ),
                        "authorized": item["has_authorization"],
                    }
                )
            raise AssertionError(
                f"{label} authorized POST /api/invoke (HTTP {status}). "
                f"aws_calls={console.aws_calls[before_aws:]!r} "
                f"runtime={preview!r} assistant_returned={returned_assistant}"
            )


@pytest.mark.parametrize(
    "agent_pattern",
    ["orchestrator", "agui-strands-agent"],
)
def test_loopback_client_cannot_invoke_with_served_material(
    console: SimpleNamespace,
    monkeypatch: pytest.MonkeyPatch,
    agent_pattern: str,
) -> None:
    """POST /api/invoke for both protocols the console derives after auth.

    ``orchestrator`` reaches scripts/invoke.py invoke_agent. Patterns that
    start with ``agui-`` reach invoke_agui. Both are behind the same POST
    handler, and neither may run for a client that only knows served data.
    """
    if agent_pattern == "orchestrator":
        monkeypatch.delenv("AGENT_PATTERN", raising=False)
    else:
        monkeypatch.setenv("AGENT_PATTERN", agent_pattern)
    _assert_invoke_refused(console, console.port)


def test_loopback_client_cannot_read_status_identifiers(
    console: SimpleNamespace,
) -> None:
    """status.json is mode 0600, but the console reads and serves it.

    A loopback client that has not presented a secret from outside this
    process must not receive the account id, runtime ARN, gateway URL, or
    client ids, including by replaying a value the server itself returned.
    """
    leaked = _served_values(console.port)
    pages = [
        ("GET", path, None)
        for path in (
            "/api/health",
            "/api/health?t=1",
            "/status.json",
            "/status.json?t=1",
            "/",
            "/index.html",
        )
    ]
    for label, value in leaked:
        pages.append(("GET", "/status.json", value))
        pages.append(("GET", "/api/health", value))

    for method, path, header in pages:
        extra = {"X-EBA-CSRF": header} if header is not None else None
        status, headers, body = _exchange(
            console.port,
            method,
            path,
            extra_headers=extra,
        )
        visible = (
            body.decode("utf-8", errors="replace")
            + "\n"
            + "\n".join(f"{key}: {value}" for key, value in headers.items())
        )
        disclosed = [fact for fact in SENSITIVE_FACTS if fact in visible]
        assert not disclosed, (
            f"{method} {path} (HTTP {status}) disclosed deployment "
            f"identifiers to an unauthenticated loopback client: "
            + ", ".join(disclosed)
        )
