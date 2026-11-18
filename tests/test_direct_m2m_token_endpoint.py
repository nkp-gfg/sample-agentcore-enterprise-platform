"""Direct M2M login must not post the IdP client secret to an untrusted token endpoint.

AuthStack direct mode publishes the issuer as
https://login.microsoftonline.com/{tenant}/v2.0 (stacks/auth_stack.py).
scripts/utils.py then loads that issuer's discovery document and posts the
Secrets Manager client secret to whatever token_endpoint the document names.
These tests run that path through urllib against a local TLS listener. They
fail while the secret is still delivered to an endpoint the deployment did
not pin to the Entra host.
"""

from __future__ import annotations

import json
import os
import socket
import ssl
import subprocess
import sys
import threading
from datetime import UTC, datetime
from email.message import Message
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from io import BytesIO
from pathlib import Path
from types import SimpleNamespace

import boto3
import pytest

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(REPO / "scripts"))

os.environ.setdefault("AWS_REGION", "us-east-1")
os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")
os.environ.setdefault("PROJECT_NAME", "agentcore-workshop")
os.environ.setdefault("ENVIRONMENT", "dev")

import check_identity
import invoke
import utils
from dashboard import server as console

# Obvious stand-in for the Secrets Manager string. Not a credential.
PLACEHOLDER_CLIENT_SECRET = "placeholder-client-secret"
PLACEHOLDER_CLIENT_ID = "placeholder-client-id"
PLACEHOLDER_SECRET_NAME = "placeholder-secret-name"
PLACEHOLDER_ACCESS_TOKEN = "placeholder-access-token"
TENANT = "00000000-0000-4000-8000-000000000001"
ENTRA_HOST = "login.microsoftonline.com"
ATTACKER_HOST = "attacker.test"
LOOKALIKE_HOST = "login.microsoftonline.com.attacker.test"
RUNTIME_HOST = "bedrock-agentcore.us-east-1.amazonaws.com"
COGNITO_HOST = "agentcore-workshop-dev-111111111111.auth.us-east-1.amazoncognito.com"
ACCOUNT = "111111111111"
HOSTS_MARKER = "# cursor-direct-m2m-token-endpoint"
HOSTS_PATH = Path("/etc/hosts")

PARAMS: dict[str, str] = {}
WORLD: dict = {"records": [], "document": {}, "https_port": 0, "http_port": 0}


class _AwsStrings:
    """Returns the string shapes botocore's JSON parser leaves unchanged.

    SSM GetParameterResult.Parameter.Value and Secrets Manager
    GetSecretValueResponse.SecretString are both type string
    (botocore 1.44.6 service models). JSONParser._handle_string returns
    that string as stored.
    """

    def get_parameter(self, Name):
        key = Name.split("/", 3)[3]
        if key not in PARAMS:
            raise KeyError(key)
        return {"Parameter": {"Name": Name, "Type": "String", "Value": PARAMS[key]}}

    def get_secret_value(self, SecretId):
        assert SecretId == PARAMS["auth/m2m-client-secret-name"]
        return {"SecretString": PLACEHOLDER_CLIENT_SECRET}

    def get_caller_identity(self):
        return {"Account": ACCOUNT}


def _client(service_name, region_name=None, **kwargs):
    return _AwsStrings()


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        self._respond()

    def do_POST(self):
        self._respond()

    def _respond(self):
        length = int(self.headers.get("Content-Length", "0") or "0")
        body = self.rfile.read(length) if length else b""
        path = self.path.split("?", 1)[0]
        record = {
            "scheme": self.server.scheme,
            "method": self.command,
            "host": self.headers.get("Host", ""),
            "path": path,
            "body": body,
            "header_blob": str(self.headers).encode(),
        }
        WORLD["records"].append(record)
        extra_headers: list[tuple[str, str]] = []
        if self.command == "GET" and path.endswith("/.well-known/openid-configuration"):
            payload = json.dumps(WORLD["document"]).encode()
            status = 200
        elif self.command == "POST" and path.endswith("/token") and WORLD.get("redirect_to"):
            # 308 keeps the method. urllib.request on this interpreter does not
            # resend a POST body; a client that does would deliver the secret.
            payload = b""
            status = 308
            extra_headers.append(("Location", WORLD["redirect_to"]))
        elif self.command == "POST" and path.endswith("/token"):
            payload = json.dumps({"access_token": PLACEHOLDER_ACCESS_TOKEN}).encode()
            status = 200
        elif self.command == "POST":
            payload = b'{"response":"ok"}'
            status = 200
        else:
            payload = b"{}"
            status = 404
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        for key, value in extra_headers:
            self.send_header(key, value)
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, fmt, *args):
        return


class _TlsServer(ThreadingHTTPServer):
    def __init__(self, address, handler, context):
        super().__init__(address, handler)
        self.socket = context.wrap_socket(self.socket, server_side=True)


def _serve(httpd) -> None:
    httpd.serve_forever(poll_interval=0.05)


def _write_cert(directory: Path) -> tuple[Path, Path, Path]:
    ca_key = directory / "ca.key"
    ca_pem = directory / "ca.pem"
    srv_key = directory / "srv.key"
    srv_csr = directory / "srv.csr"
    srv_pem = directory / "srv.pem"
    names = ",".join(
        f"DNS:{host}"
        for host in (ENTRA_HOST, ATTACKER_HOST, LOOKALIKE_HOST, RUNTIME_HOST, COGNITO_HOST)
    )
    subprocess.run(
        [
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-sha256", "-days", "1",
            "-nodes", "-keyout", str(ca_key), "-out", str(ca_pem), "-subj", "/CN=TestCA",
        ],
        check=True,
        capture_output=True,
    )
    subprocess.run(
        [
            "openssl", "req", "-newkey", "rsa:2048", "-sha256", "-nodes",
            "-keyout", str(srv_key), "-out", str(srv_csr), "-subj", f"/CN={ENTRA_HOST}",
            "-addext", f"subjectAltName={names}",
        ],
        check=True,
        capture_output=True,
    )
    subprocess.run(
        [
            "openssl", "x509", "-req", "-in", str(srv_csr), "-CA", str(ca_pem),
            "-CAkey", str(ca_key), "-out", str(srv_pem), "-days", "1", "-sha256",
            "-copy_extensions", "copy",
        ],
        check=True,
        capture_output=True,
    )
    return ca_pem, srv_pem, srv_key


def _install_hosts() -> None:
    names = " ".join((ENTRA_HOST, ATTACKER_HOST, LOOKALIKE_HOST, RUNTIME_HOST, COGNITO_HOST))
    line = f"127.0.0.1 {names} {HOSTS_MARKER}"
    current = HOSTS_PATH.read_text()
    kept = "\n".join(row for row in current.splitlines() if HOSTS_MARKER not in row)
    updated = kept.rstrip() + "\n" + line + "\n"
    subprocess.run(["sudo", "tee", str(HOSTS_PATH)], input=updated, text=True, check=True, capture_output=True)


def _restore_hosts() -> None:
    current = HOSTS_PATH.read_text()
    if HOSTS_MARKER not in current:
        return
    kept = "\n".join(row for row in current.splitlines() if HOSTS_MARKER not in row)
    subprocess.run(
        ["sudo", "tee", str(HOSTS_PATH)],
        input=kept.rstrip() + "\n",
        text=True,
        check=True,
        capture_output=True,
    )


@pytest.fixture(scope="module", autouse=True)
def local_listeners(tmp_path_factory):
    previous_timeout = socket.getdefaulttimeout()
    socket.setdefaulttimeout(5)
    for key in ("http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "all_proxy"):
        os.environ.pop(key, None)
    os.environ["NO_PROXY"] = "*"

    directory = tmp_path_factory.mktemp("m2m-token-endpoint")
    ca_pem, srv_pem, srv_key = _write_cert(directory)
    _install_hosts()

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(srv_pem, srv_key)
    httpsd = _TlsServer(("127.0.0.1", 0), _Handler, context)
    httpsd.scheme = "https"
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    httpd.scheme = "http"
    WORLD["https_port"] = httpsd.server_address[1]
    WORLD["http_port"] = httpd.server_address[1]

    saved_cert = os.environ.get("SSL_CERT_FILE")
    os.environ["SSL_CERT_FILE"] = str(ca_pem)
    import urllib.request

    saved_opener = urllib.request._opener
    urllib.request._opener = None

    threads = [
        threading.Thread(target=_serve, args=(httpsd,), daemon=True),
        threading.Thread(target=_serve, args=(httpd,), daemon=True),
    ]
    for thread in threads:
        thread.start()
    try:
        yield
    finally:
        httpsd.shutdown()
        httpd.shutdown()
        httpsd.server_close()
        httpd.server_close()
        urllib.request._opener = saved_opener
        if saved_cert is None:
            os.environ.pop("SSL_CERT_FILE", None)
        else:
            os.environ["SSL_CERT_FILE"] = saved_cert
        _restore_hosts()
        socket.setdefaulttimeout(previous_timeout)


@pytest.fixture(autouse=True)
def aws_strings(monkeypatch):
    monkeypatch.setattr(boto3, "client", _client)
    monkeypatch.setattr(utils.boto3, "client", _client)


def _https(host: str, path: str) -> str:
    return f"https://{host}:{WORLD['https_port']}{path}"


def _http(host: str, path: str) -> str:
    return f"http://{host}:{WORLD['http_port']}{path}"


def entra_issuer() -> str:
    return _https(ENTRA_HOST, f"/{TENANT}/v2.0")


def entra_token() -> str:
    return _https(ENTRA_HOST, f"/{TENANT}/oauth2/v2.0/token")


def configure(issuer: str, token_endpoint: str, issuer_claim: str | None = None) -> None:
    PARAMS.clear()
    PARAMS.update(
        {
            "auth/mode": "direct",
            "auth/issuer-url": issuer,
            "auth/m2m-client-id": PLACEHOLDER_CLIENT_ID,
            "auth/m2m-scope": "placeholder-scope",
            "auth/m2m-client-secret-name": PLACEHOLDER_SECRET_NAME,
            "auth/app-client-id": PLACEHOLDER_CLIENT_ID,
            "gateway/url": _https(ATTACKER_HOST, "/mcp"),
        }
    )
    WORLD["document"] = {
        "issuer": issuer if issuer_claim is None else issuer_claim,
        "token_endpoint": token_endpoint,
    }
    WORLD["redirect_to"] = None
    WORLD["records"].clear()


def secret_destinations() -> list[tuple[str, str, str, str]]:
    needle = PLACEHOLDER_CLIENT_SECRET.encode()
    found = []
    for record in WORLD["records"]:
        haystack = record["body"] + record["path"].encode() + record["header_blob"]
        if needle in haystack:
            hostname = record["host"].split(":")[0]
            found.append((record["scheme"], record["method"], hostname, record["path"]))
    return found


def request_log() -> list[tuple[str, str, str, str]]:
    return [
        (record["scheme"], record["method"], record["host"], record["path"])
        for record in WORLD["records"]
    ]


def assert_secret_not_posted() -> None:
    delivered = secret_destinations()
    assert delivered == [], (
        "client secret left the process toward "
        f"{delivered}; requests seen: {request_log()}"
    )


def _call(entry) -> None:
    """Run an entry point. Refusal may raise; posting the secret must not."""
    try:
        entry()
    except (Exception, SystemExit):
        return


def _invoke_post() -> str:
    return invoke._post(
        _https(RUNTIME_HOST, "/runtimes/test/invocations?qualifier=DEFAULT"),
        {"prompt": "hello"},
        {},
        region="us-east-1",
    )


def _dashboard_post() -> None:
    status = {
        "available": True,
        "timestamp": datetime.now(UTC).isoformat(),
        "account": ACCOUNT,
        "region": "us-east-1",
        "project": "agentcore-workshop",
        "environment": "dev",
        "stacks": {
            "agentcore-workshop-dev-runtime-orchestrator": {
                "state": "deployed",
                "outputs": {
                    "RuntimeArn": (
                        f"arn:aws:bedrock-agentcore:us-east-1:{ACCOUNT}:runtime/test"
                    )
                },
            }
        },
    }
    payload = json.dumps(
        {
            "component": "orchestrator",
            "prompt": "hello",
            "sessionId": "session-" + ("a" * 32),
        }
    ).encode()
    handler = console.EbaConsoleHandler.__new__(console.EbaConsoleHandler)
    handler.path = "/api/invoke"
    handler.command = "POST"
    handler.request_version = "HTTP/1.1"
    handler.requestline = "POST /api/invoke HTTP/1.1"
    handler.server = SimpleNamespace(server_port=8888)
    handler.client_address = ("127.0.0.1", 12345)
    handler.rfile = BytesIO(payload)
    handler.wfile = BytesIO()
    handler.headers = Message()
    for key, value in {
        "Host": "127.0.0.1:8888",
        "Origin": "http://127.0.0.1:8888",
        "Content-Type": "application/json",
        "Content-Length": str(len(payload)),
        "X-EBA-CSRF": console.CSRF_TOKEN,
    }.items():
        handler.headers[key] = value
    original_status = console.load_status
    original_identity = console.validate_operator_identity

    def _identity(status_doc, runtime_arn, **_kwargs):
        # do_POST binds client_factory to boto3.client at import. Pass the
        # same string client the login path uses so the account check runs
        # without calling AWS.
        return original_identity(
            status_doc,
            runtime_arn,
            client_factory=_client,
        )

    console.load_status = lambda path=None: status
    console.validate_operator_identity = _identity
    try:
        handler.do_POST()
    finally:
        console.load_status = original_status
        console.validate_operator_identity = original_identity


@pytest.mark.parametrize(
    "entry",
    [utils.get_m2m_token, _invoke_post, invoke.list_tools, _dashboard_post, check_identity.main],
)
def test_attacker_issuer_does_not_receive_the_client_secret(entry, monkeypatch):
    """SSM auth/mode=direct and auth/issuer-url name an attacker host.

    Discovery and token_endpoint are both on that host, and the discovery
    issuer claim matches. That is enough, today, for the operator's login
    to post the client secret there.
    """
    monkeypatch.setenv("IDP_MODE", "direct")
    issuer = _https(ATTACKER_HOST, "/idp")
    configure(issuer, _https(ATTACKER_HOST, "/token"))
    _call(entry)
    assert_secret_not_posted()


def test_token_endpoint_on_a_different_host_does_not_receive_the_secret():
    configure(entra_issuer(), _https(ATTACKER_HOST, "/token"))
    _call(utils.get_m2m_token)
    assert_secret_not_posted()


def test_http_token_endpoint_does_not_receive_the_secret():
    configure(entra_issuer(), _http(ATTACKER_HOST, "/token"))
    _call(utils.get_m2m_token)
    assert_secret_not_posted()


def test_lookalike_issuer_host_does_not_receive_the_secret():
    issuer = _https(LOOKALIKE_HOST, f"/{TENANT}/v2.0")
    configure(issuer, _https(LOOKALIKE_HOST, "/token"))
    _call(utils.get_m2m_token)
    assert_secret_not_posted()


def test_mismatched_discovery_issuer_does_not_post_the_secret():
    configure(
        entra_issuer(),
        entra_token(),
        issuer_claim=_https(ATTACKER_HOST, "/idp"),
    )
    _call(utils.get_m2m_token)
    assert_secret_not_posted()


def test_redirect_off_the_token_host_does_not_receive_the_secret():
    """A 308 from an otherwise acceptable token endpoint must not carry the secret.

    urllib.request in this interpreter refuses to resend a POST body on 308.
    The assertion still fails if a later change follows that redirect and
    posts the secret to the Location host.
    """
    configure(entra_issuer(), entra_token())
    WORLD["redirect_to"] = _https(ATTACKER_HOST, "/token")
    _call(utils.get_m2m_token)
    assert any(path.endswith("/token") for _, _, _, path in request_log()), request_log()
    leaked = [item for item in secret_destinations() if item[2] != ENTRA_HOST]
    assert leaked == [], f"client secret followed a redirect to {leaked}"


def test_legitimate_entra_issuer_posts_only_to_its_https_token_endpoint():
    configure(entra_issuer(), entra_token())
    assert utils.get_m2m_token() == PLACEHOLDER_ACCESS_TOKEN
    assert secret_destinations() == [
        ("https", "POST", ENTRA_HOST, f"/{TENANT}/oauth2/v2.0/token")
    ]
