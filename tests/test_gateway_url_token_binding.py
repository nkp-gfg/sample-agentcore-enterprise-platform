"""Machine token must not follow an unchecked gateway URL.

The gateway test script, its MCP helper, the invoke script's tool listing,
and the hello-platform verifier all read a URL from SSM and POST it with the
platform machine access token. These tests are the contract for that path:

- Send the token only to an https URL whose host is
  ``{gateway-id}.gateway.bedrock-agentcore.{region}.amazonaws.com``, where
  ``{region}`` is what ``resolve_region()`` returns when the request is made
  and ``{gateway-id}`` is a single DNS label.
- Do not open a connection to any other host, scheme, or userinfo form.
- Do not follow redirects. A 302 from an allowed host must not contact the
  Location target.
- Read the parameter once. A later read of the same parameter must not
  retarget the request, including when the second value is also an allowed
  gateway host.

They fail while the scripts still attach the token to whatever string SSM
returns. The stand-in SSM client is botocore's Stubber (the service model
returns Parameter.Value unchanged). The HTTP clients are the real
``requests`` and ``urllib`` stacks; only DNS is pinned to the local listeners
so the test does not leave the machine.

Not covered here, and not the same operator path:

- The agent runtime MCP clients under ``agent-code/*/tools/gateway.py`` and
  ``agent-code/claude-sdk-*/agent.py``. Those prefer the ``GATEWAY_URL``
  environment value injected at deploy and only then fall back to SSM. The
  token fetch and the HTTP send sit in libraries this environment does not
  install.
- ``use-cases/_template/verify.py`` is a scaffold with an unsubstituted name.
  The deployed copy of that pattern is hello-platform, which is covered, and
  it calls ``mcp_request``.
- ``invoke.py`` agent and A2A calls build
  ``https://bedrock-agentcore.{region}.amazonaws.com/...`` from a runtime ARN.
  The host is not the gateway parameter.
"""

from __future__ import annotations

import importlib.util
import json
import os
import socket
import ssl
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import boto3
import pytest
from botocore.stub import Stubber

_ORIGINAL_BOTO3_CLIENT = boto3.client

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "scripts"))

# Placeholders so boto3 can build a client without the instance metadata
# service. They are not credentials for any account.
os.environ.setdefault("AWS_ACCESS_KEY_ID", "placeholder-access-key")
os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "placeholder-secret-key")
os.environ.setdefault("AWS_EC2_METADATA_DISABLED", "true")
os.environ.setdefault("AWS_REGION", "us-east-1")
os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")
os.environ.setdefault("PROJECT_NAME", "agentcore-workshop")
os.environ.setdefault("ENVIRONMENT", "dev")
for _proxy in (
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
    "http_proxy",
    "https_proxy",
    "all_proxy",
):
    os.environ.pop(_proxy, None)

import invoke  # noqa: E402
import test_gateway  # noqa: E402
import utils  # noqa: E402

FIXTURE_MACHINE_TOKEN = "fixture-machine-access-token"
PROJECT = "agentcore-workshop"
ENV = "dev"
GATEWAY_PARAMETER = f"/{PROJECT}/{ENV}/gateway/url"
SEEN_PARAMETER = f"/{PROJECT}/{ENV}/use-cases/hello-platform/gateway-seen"
REGION = "us-east-1"
OTHER_REGION = "eu-west-1"
GATEWAY_HOST = f"gw-one.gateway.bedrock-agentcore.{REGION}.amazonaws.com"
OTHER_GATEWAY_HOST = f"gw-two.gateway.bedrock-agentcore.{REGION}.amazonaws.com"
EU_GATEWAY_HOST = f"gw-eu.gateway.bedrock-agentcore.{OTHER_REGION}.amazonaws.com"
ATTACKER_HOST = "attacker.example"
GATEWAY_URL = f"https://{GATEWAY_HOST}/mcp"
OTHER_GATEWAY_URL = f"https://{OTHER_GATEWAY_HOST}/mcp"
EU_GATEWAY_URL = f"https://{EU_GATEWAY_HOST}/mcp"
ATTACKER_URL = f"https://{ATTACKER_HOST}/mcp"


def _host_of(header: str) -> str:
    host = header.strip()
    if host.startswith("["):
        return host
    return host.split(":")[0].lower()


class _RecordingServer(ThreadingHTTPServer):
    allow_reuse_address = True
    records: list[dict]
    mode: str

    def __init__(self, address, handler):
        self.records = []
        self.mode = "mcp"
        self._lock = threading.Lock()
        super().__init__(address, handler)

    def record(self, item: dict) -> None:
        with self._lock:
            self.records.append(item)

    def snapshot(self) -> list[dict]:
        with self._lock:
            return list(self.records)

    def clear(self) -> None:
        with self._lock:
            self.records.clear()


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        return

    def do_GET(self):
        self._handle()

    def do_POST(self):
        self._handle()

    def _handle(self):
        length = int(self.headers.get("Content-Length", "0") or "0")
        body = self.rfile.read(length) if length else b""
        host = _host_of(self.headers.get("Host", ""))
        self.server.record(
            {
                "host": host,
                "path": self.path,
                "authorization": self.headers.get("Authorization"),
                "body": body,
            }
        )
        if self.server.mode == "redirect" and host == GATEWAY_HOST:
            self._reply(302, b"", location=f"https://{ATTACKER_HOST}/steal")
            return
        payload = {}
        if body:
            try:
                payload = json.loads(body)
            except json.JSONDecodeError:
                payload = {}
        method = payload.get("method")
        if method == "tools/call":
            response = {"jsonrpc": "2.0", "id": method, "result": {"ok": True}}
        else:
            response = {
                "jsonrpc": "2.0",
                "id": method or "tools/list",
                "result": {"tools": [{"name": "sample-tool___text_analysis_tool"}]},
            }
        encoded = json.dumps(response).encode()
        self._reply(200, encoded)

    def _reply(self, status: int, body: bytes, location: str | None = None) -> None:
        self.send_response(status)
        if location:
            self.send_header("Location", location)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)


def _make_certificate(directory: Path) -> tuple[Path, Path]:
    names = (
        GATEWAY_HOST,
        OTHER_GATEWAY_HOST,
        EU_GATEWAY_HOST,
        ATTACKER_HOST,
        # Hosts the untrusted cases use, so a real TLS handshake completes and
        # the Authorization header is observable if the client sends it.
        f"{GATEWAY_HOST}.{ATTACKER_HOST}",
        f"gw-one.gateway.bedrock-agentcore.{OTHER_REGION}.amazonaws.com",
    )
    cert = directory / "cert.pem"
    key = directory / "key.pem"
    san = ",".join(f"DNS:{name}" for name in names)
    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            str(key),
            "-out",
            str(cert),
            "-days",
            "2",
            "-subj",
            "/CN=gateway-url-token-binding-test",
            "-addext",
            f"subjectAltName={san}",
        ],
        check=True,
        capture_output=True,
    )
    return cert, key


def _serve_https(cert: Path, key: Path) -> _RecordingServer:
    server = _RecordingServer(("127.0.0.1", 443), _Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


def _serve_http() -> _RecordingServer:
    server = _RecordingServer(("127.0.0.1", 80), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


@pytest.fixture(scope="module")
def listeners(tmp_path_factory):
    cert, key = _make_certificate(tmp_path_factory.mktemp("certs"))
    https = _serve_https(cert, key)
    http = _serve_http()
    os.environ["REQUESTS_CA_BUNDLE"] = str(cert)
    os.environ["SSL_CERT_FILE"] = str(cert)
    import urllib.request

    urllib.request._opener = None  # rebuilt with SSL_CERT_FILE on next urlopen
    real_getaddrinfo = socket.getaddrinfo

    def pinned_getaddrinfo(host, port, *args, **kwargs):
        try:
            port_num = int(port)
        except (TypeError, ValueError):
            return real_getaddrinfo(host, port, *args, **kwargs)
        return [
            (
                socket.AF_INET,
                socket.SOCK_STREAM,
                socket.IPPROTO_TCP,
                "",
                ("127.0.0.1", port_num),
            )
        ]

    socket.getaddrinfo = pinned_getaddrinfo
    try:
        yield https, http
    finally:
        socket.getaddrinfo = real_getaddrinfo
        https.shutdown()
        http.shutdown()


@pytest.fixture
def traffic(listeners):
    https, http = listeners
    https.clear()
    http.clear()
    https.mode = "mcp"
    http.mode = "mcp"
    return https, http


def _queue_parameter(monkeypatch, name: str, values: list[str]) -> None:
    client = _ORIGINAL_BOTO3_CLIENT("ssm", region_name=REGION)
    stubber = Stubber(client)
    queued = list(values) + [values[-1]] * 8
    for value in queued:
        stubber.add_response(
            "get_parameter",
            {"Parameter": {"Name": name, "Type": "String", "Value": value}},
            {"Name": name},
        )
    stubber.activate()

    def client_factory(*args, **kwargs):
        if args and args[0] != "ssm":
            raise AssertionError(f"unexpected AWS client {args[0]}")
        return client

    monkeypatch.setattr(boto3, "client", client_factory)
    monkeypatch.setattr(utils, "get_m2m_token", lambda *args, **kwargs: FIXTURE_MACHINE_TOKEN)
    monkeypatch.setattr(
        test_gateway, "get_m2m_token", lambda *args, **kwargs: FIXTURE_MACHINE_TOKEN
    )
    monkeypatch.setattr(
        invoke, "get_m2m_token", lambda *args, **kwargs: FIXTURE_MACHINE_TOKEN
    )


def _attempt(fn) -> BaseException | None:
    try:
        fn()
    except BaseException as exc:  # noqa: BLE001 — refusal may exit or raise
        return exc
    return None


def _records(traffic) -> list[dict]:
    https, http = traffic
    return https.snapshot() + http.snapshot()


def _assert_silent(traffic) -> None:
    seen = _records(traffic)
    assert seen == [], f"untrusted gateway URL was contacted: {seen}"


def _run_test_gateway_main(monkeypatch) -> None:
    monkeypatch.setattr(
        sys,
        "argv",
        ["test_gateway.py", "--project", PROJECT, "--env", ENV],
    )
    test_gateway.main()


def _run_invoke_tools(monkeypatch) -> None:
    monkeypatch.setattr(sys, "argv", ["invoke.py", "--tools"])
    invoke.main()


def _hello_platform():
    path = REPO / "use-cases" / "hello-platform" / "verify.py"
    spec = importlib.util.spec_from_file_location("hello_platform_verify", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


UNTRUSTED_URLS = [
    ATTACKER_URL,
    f"http://{GATEWAY_HOST}/mcp",
    f"https://{GATEWAY_HOST}.{ATTACKER_HOST}/mcp",
    f"https://{ATTACKER_HOST}/mcp?next={GATEWAY_HOST}",
    f"https://gw-one.gateway.bedrock-agentcore.{OTHER_REGION}.amazonaws.com/mcp",
    "http://127.0.0.1/mcp",
]


@pytest.mark.parametrize("url", UNTRUSTED_URLS)
def test_test_gateway_does_not_send_machine_token_to_untrusted_url(
    monkeypatch, traffic, url
):
    _queue_parameter(monkeypatch, GATEWAY_PARAMETER, [url])
    _attempt(lambda: _run_test_gateway_main(monkeypatch))
    _assert_silent(traffic)


@pytest.mark.parametrize("url", UNTRUSTED_URLS)
def test_mcp_request_does_not_send_machine_token_to_untrusted_url(
    monkeypatch, traffic, url
):
    _queue_parameter(monkeypatch, GATEWAY_PARAMETER, [url])
    _attempt(
        lambda: test_gateway.mcp_request(url, FIXTURE_MACHINE_TOKEN, "tools/list")
    )
    _assert_silent(traffic)


@pytest.mark.parametrize("url", UNTRUSTED_URLS)
def test_invoke_tool_listing_does_not_send_machine_token_to_untrusted_url(
    monkeypatch, traffic, url
):
    _queue_parameter(monkeypatch, GATEWAY_PARAMETER, [url])
    _attempt(lambda: _run_invoke_tools(monkeypatch))
    _assert_silent(traffic)


@pytest.mark.parametrize(
    "caller",
    ["main", "mcp_request"],
)
def test_userinfo_url_does_not_deliver_the_machine_token(monkeypatch, traffic, caller):
    """requests parses userinfo@host as the host after '@'. urllib keeps the
    '@' in the host and never completes TLS to that name, so this case is
    asserted on the requests callers only."""
    url = f"https://{GATEWAY_HOST}@{ATTACKER_HOST}/mcp"
    _queue_parameter(monkeypatch, GATEWAY_PARAMETER, [url])
    if caller == "main":
        _attempt(lambda: _run_test_gateway_main(monkeypatch))
    else:
        _attempt(
            lambda: test_gateway.mcp_request(url, FIXTURE_MACHINE_TOKEN, "tools/list")
        )
    _assert_silent(traffic)


def test_hello_platform_verifier_does_not_send_machine_token_to_untrusted_url(
    monkeypatch, traffic
):
    _queue_parameter(
        monkeypatch,
        SEEN_PARAMETER,
        [f"hello: {ATTACKER_URL}"],
    )
    hello = _hello_platform()
    _attempt(hello.main)
    _assert_silent(traffic)


def test_allowed_gateway_host_still_receives_the_machine_token(monkeypatch, traffic):
    _queue_parameter(monkeypatch, GATEWAY_PARAMETER, [GATEWAY_URL])
    exc = _attempt(lambda: _run_test_gateway_main(monkeypatch))
    assert exc is None, exc
    seen = _records(traffic)
    assert seen, "the published gateway host was not called"
    assert {item["host"] for item in seen} == {GATEWAY_HOST}
    assert {item["authorization"] for item in seen} == {
        f"Bearer {FIXTURE_MACHINE_TOKEN}"
    }
    methods = []
    for item in seen:
        methods.append(json.loads(item["body"])["method"])
    assert methods == ["tools/list", "tools/call"]


def test_invoke_tool_listing_sends_token_only_to_allowed_host(monkeypatch, traffic):
    _queue_parameter(monkeypatch, GATEWAY_PARAMETER, [GATEWAY_URL])
    result = invoke.list_tools()
    seen = _records(traffic)
    assert {item["host"] for item in seen} == {GATEWAY_HOST}
    assert seen[0]["authorization"] == f"Bearer {FIXTURE_MACHINE_TOKEN}"
    assert "sample-tool___text_analysis_tool" in result


def test_allowed_host_follows_the_region_in_effect(monkeypatch, traffic):
    monkeypatch.setenv("AWS_REGION", OTHER_REGION)
    monkeypatch.setenv("AWS_DEFAULT_REGION", OTHER_REGION)
    _queue_parameter(monkeypatch, GATEWAY_PARAMETER, [EU_GATEWAY_URL])
    exc = _attempt(lambda: _run_test_gateway_main(monkeypatch))
    assert exc is None, exc
    seen = _records(traffic)
    assert {item["host"] for item in seen} == {EU_GATEWAY_HOST}
    assert {item["authorization"] for item in seen} == {
        f"Bearer {FIXTURE_MACHINE_TOKEN}"
    }


def test_redirect_from_allowed_host_is_not_followed(monkeypatch, traffic):
    https, _http = traffic
    https.mode = "redirect"
    _queue_parameter(monkeypatch, GATEWAY_PARAMETER, [GATEWAY_URL])

    _attempt(lambda: test_gateway.mcp_request(GATEWAY_URL, FIXTURE_MACHINE_TOKEN, "tools/list"))
    _attempt(invoke.list_tools)

    seen = _records(traffic)
    assert seen, "the allowed host was not contacted, so the redirect was not exercised"
    assert all(item["host"] == GATEWAY_HOST for item in seen), seen
    assert all(item["path"] != "/steal" for item in seen)


def test_second_ssm_read_cannot_retarget_the_token(monkeypatch, traffic):
    """The first value is an allowed host. Every later read is a different
    allowed host. The request has to stay on the first host."""
    for call in (
        lambda: _run_test_gateway_main(monkeypatch),
        invoke.list_tools,
    ):
        traffic[0].clear()
        traffic[1].clear()
        _queue_parameter(
            monkeypatch,
            GATEWAY_PARAMETER,
            [GATEWAY_URL, OTHER_GATEWAY_URL],
        )
        _attempt(call)
        seen = _records(traffic)
        assert seen, "neither gateway host was contacted"
        assert all(item["host"] == GATEWAY_HOST for item in seen), seen
        assert all(
            item["authorization"] == f"Bearer {FIXTURE_MACHINE_TOKEN}" for item in seen
        )
