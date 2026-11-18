"""Caller-visible agent errors must be fixed strings, not exception text.

The LangGraph, Strands, and AG-UI entrypoints catch failures and put
``str(exception)`` on the HTTP response. A caller who can invoke the runtime
reads that string. For an AWS client error, botocore copies the service
``message`` field into ``ClientError`` (botocore ``BaseJSONParser._do_error_parse``
and ``ClientError.MSG_TEMPLATE``), and that message is what the entrypoint
returns.

These tests fail while that disclosure is present. After the entrypoints
return a fixed message and log the exception only on the server, they pass.

Authentication failures must come back as exactly ``Unauthorized`` (the
response the Strands entrypoint already uses). Every other entrypoint
failure must come back as exactly ``Agent run failed``. The response must
not contain the exception text.

Run (dependencies are the agent requirements, not the CI pytest job):

    python -m pip install -r agent-code/langgraph-agent/requirements.txt \\
        -r agent-code/strands-agent/requirements.txt \\
        -r agent-code/agui-langgraph-agent/requirements.txt \\
        -r agent-code/agui-strands-agent/requirements.txt \\
        -r agent-code/orchestrator/requirements.txt \\
        pytest httpx cryptography
    python -m pytest tests/test_entrypoint_error_disclosure.py -q
"""

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
AGENT_CODE = REPO / "agent-code"

# Documentation-style identifiers. They are the service error text a denied
# AWS call puts in the ``message`` field, not a credential.
ACCOUNT_ID = "111122223333"
ROLE_ARN = "arn:aws:sts::111122223333:assumed-role/AgentCoreRuntimeRole/session"
RESOURCE_ARN = "arn:aws:bedrock:us-east-1:111122223333:inference-profile/example"
DENIED_MESSAGE = (
    f"User: {ROLE_ARN} is not authorized to perform: bedrock:InvokeModel "
    f"on resource: {RESOURCE_ARN}"
)
AUTH_LEAK = "not one of this deployment's clients"
SAFE_AUTH = "Unauthorized"
SAFE_FAILURE = "Agent run failed"
ALLOWED_CLIENT = "allowed-client"
OTHER_CLIENT = "other-client"

_REQUIRED = (
    "bedrock_agentcore",
    "jwt",
    "cryptography",
    "httpx",
    "starlette",
    "langchain",
    "langgraph",
    "langchain_aws",
    "langgraph_checkpoint_aws",
    "strands",
    "copilotkit",
    "ag_ui",
    "ag_ui_strands",
    "boto3",
)


def _deps_installed() -> bool:
    return all(importlib.util.find_spec(name) is not None for name in _REQUIRED)


pytestmark = pytest.mark.skipif(
    not _deps_installed(),
    reason=(
        "agent runtime dependencies are not installed; "
        "see tests/test_entrypoint_error_disclosure.py"
    ),
)


class _DenialState:
    """Which AWS calls the stand-in service refuses."""

    def __init__(self) -> None:
        self.mode = "deny-all"
        self.lock = threading.Lock()

    def set_mode(self, mode: str) -> None:
        with self.lock:
            self.mode = mode

    def get_mode(self) -> str:
        with self.lock:
            return self.mode


_STATE = _DenialState()
_JWKS: dict = {}
_ISSUER = ""
_PRIVATE_PEM = ""


class _Handler(BaseHTTPRequestHandler):
    """Local stand-in for the OIDC issuer and for the AWS JSON endpoints.

    AWS calls are answered with the rest-json error document botocore parses:
    a 403 body whose ``message`` is copied into ``ClientError``. ListEvents
    can return an empty page so a later model call is the one that fails.
    """

    def do_GET(self) -> None:
        if self.path.split("?", 1)[0].endswith("/.well-known/openid-configuration"):
            body = json.dumps({"jwks_uri": f"{_ISSUER}/.well-known/jwks.json"}).encode()
            self._send(200, body, "application/json")
            return
        if self.path.split("?", 1)[0].endswith("/.well-known/jwks.json"):
            body = json.dumps({"keys": [_JWKS]}).encode()
            self._send(200, body, "application/json")
            return
        self._deny()

    def do_POST(self) -> None:
        path = self.path.split("?", 1)[0]
        length = int(self.headers.get("Content-Length", "0") or "0")
        if length:
            self.rfile.read(length)
        if (
            _STATE.get_mode() == "model-only"
            and "/sessions/" in path
            and "converse" not in path
        ):
            self._send(200, json.dumps({"events": []}).encode(), "application/json")
            return
        self._deny()

    def _deny(self) -> None:
        body = json.dumps(
            {"__type": "AccessDeniedException", "message": DENIED_MESSAGE}
        ).encode()
        self.send_response(403)
        self.send_header("Content-Type", "application/json")
        self.send_header("x-amzn-errortype", "AccessDeniedException")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send(self, status: int, body: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args) -> None:
        return


@pytest.fixture(scope="module")
def services() -> dict[str, str]:
    """Issuer and AWS endpoint on one local server. Nothing leaves the machine."""
    global _ISSUER, _JWKS, _PRIVATE_PEM
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from jwt.algorithms import RSAAlgorithm

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    _PRIVATE_PEM = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    jwk = json.loads(RSAAlgorithm.to_jwk(key.public_key()))
    jwk.update({"kid": "test-key", "use": "sig", "alg": "RS256"})
    _JWKS = jwk

    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    port = server.server_address[1]
    _ISSUER = f"http://127.0.0.1:{port}"
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield {"issuer": _ISSUER, "endpoint": _ISSUER}
    finally:
        server.shutdown()


def _token(services: dict[str, str], *, client_id: str) -> str:
    import time

    import jwt

    now = int(time.time())
    return jwt.encode(
        {
            "iss": services["issuer"],
            "aud": client_id,
            "sub": "user-1",
            "token_use": "access",
            "iat": now,
            "exp": now + 3600,
        },
        _PRIVATE_PEM,
        algorithm="RS256",
        headers={"kid": "test-key"},
    )


def _invoke(services: dict[str, str], case: dict) -> tuple[int, str]:
    env = {
        "PATH": os.environ.get("PATH", ""),
        "HOME": os.environ.get("HOME", ""),
        "LANG": os.environ.get("LANG", "C.UTF-8"),
        "PYTHONUNBUFFERED": "1",
        "COGNITO_ISSUER_URL": services["issuer"],
        "COGNITO_ALLOWED_CLIENTS": ALLOWED_CLIENT,
        "AWS_ACCESS_KEY_ID": "testing",
        "AWS_SECRET_ACCESS_KEY": "testing",
        "AWS_DEFAULT_REGION": "us-east-1",
        "AWS_REGION": "us-east-1",
        "AWS_EC2_METADATA_DISABLED": "true",
        "AWS_ENDPOINT_URL": services["endpoint"],
        "AWS_MAX_ATTEMPTS": "1",
        "AWS_RETRY_MODE": "standard",
        "NO_PROXY": "127.0.0.1,localhost",
        "no_proxy": "127.0.0.1,localhost",
        "HARNESS_CASE": json.dumps(case),
    }
    client_id = case.get("token_client")
    if client_id:
        env["HARNESS_TOKEN"] = _token(services, client_id=client_id)
    if case.get("memory_id"):
        env["MEMORY_ID"] = case["memory_id"]
    _STATE.set_mode(case.get("aws_mode", "deny-all"))
    completed = subprocess.run(
        [sys.executable, str(Path(__file__).resolve()), "--harness"],
        cwd=str(REPO),
        env=env,
        text=True,
        capture_output=True,
        timeout=90,
        check=False,
    )
    for line in reversed(completed.stdout.splitlines()):
        if line.startswith("RESULT "):
            payload = json.loads(line[len("RESULT ") :])
            return payload["status"], payload["body"]
    raise AssertionError(
        "harness produced no RESULT line\n"
        f"exit={completed.returncode}\n"
        f"stdout:\n{completed.stdout}\n"
        f"stderr:\n{completed.stderr}"
    )


def _assert_fixed(
    status: int, body: str, *, kind: str, forbidden: tuple[str, ...]
) -> None:
    expected = SAFE_AUTH if kind == "auth" else SAFE_FAILURE
    assert status == 200, body
    assert expected in body
    for secret in forbidden:
        assert secret not in body, body
    # The fixed string is the whole client-visible error, not a prefix of
    # the exception text. SSE and JSON wrappers may surround it.
    assert "AccessDeniedException" not in body
    assert "ClientError" not in body
    assert "Traceback" not in body


def test_botocore_copies_denied_message_into_client_error(
    services: dict[str, str],
) -> None:
    """The stand-in speaks the error document botocore actually parses.

    This is not the vulnerability. It checks that a 403 from the local
    endpoint becomes a ClientError whose text is the service message, which
    is the string the entrypoints then return.
    """
    import boto3
    from botocore.exceptions import ClientError

    _STATE.set_mode("deny-all")
    client = boto3.client(
        "bedrock-runtime",
        region_name="us-east-1",
        endpoint_url=services["endpoint"],
        aws_access_key_id="testing",
        aws_secret_access_key="testing",
    )
    with pytest.raises(ClientError) as caught:
        client.converse(
            modelId="example-model",
            messages=[{"role": "user", "content": [{"text": "hello"}]}],
        )
    text = str(caught.value)
    assert ACCOUNT_ID in text
    assert ROLE_ARN in text
    assert RESOURCE_ARN in text
    assert "Converse" in text


def test_langgraph_returns_client_check_failure_verbatim(
    services: dict[str, str],
) -> None:
    status, body = _invoke(
        services,
        {
            "agent": "langgraph-agent",
            "kind": "prompt",
            "token_client": OTHER_CLIENT,
        },
    )
    _assert_fixed(status, body, kind="auth", forbidden=(AUTH_LEAK, OTHER_CLIENT))


def test_langgraph_returns_memory_configuration_error_verbatim(
    services: dict[str, str],
) -> None:
    status, body = _invoke(
        services,
        {
            "agent": "langgraph-agent",
            "kind": "prompt",
            "token_client": ALLOWED_CLIENT,
        },
    )
    _assert_fixed(
        status,
        body,
        kind="failure",
        forbidden=("MEMORY_ID environment variable is required",),
    )


def test_langgraph_returns_memory_access_denied_verbatim(
    services: dict[str, str],
) -> None:
    status, body = _invoke(
        services,
        {
            "agent": "langgraph-agent",
            "kind": "prompt",
            "token_client": ALLOWED_CLIENT,
            "memory_id": "example-memory",
            "aws_mode": "deny-all",
        },
    )
    _assert_fixed(
        status,
        body,
        kind="failure",
        forbidden=(ACCOUNT_ID, ROLE_ARN, RESOURCE_ARN, DENIED_MESSAGE),
    )


def test_langgraph_returns_model_access_denied_verbatim(
    services: dict[str, str],
) -> None:
    status, body = _invoke(
        services,
        {
            "agent": "langgraph-agent",
            "kind": "prompt",
            "token_client": ALLOWED_CLIENT,
            "memory_id": "example-memory",
            "aws_mode": "model-only",
        },
    )
    _assert_fixed(
        status,
        body,
        kind="failure",
        forbidden=(ACCOUNT_ID, ROLE_ARN, RESOURCE_ARN, DENIED_MESSAGE),
    )


def test_strands_hides_client_check_failure(services: dict[str, str]) -> None:
    status, body = _invoke(
        services,
        {
            "agent": "strands-agent",
            "kind": "prompt",
            "token_client": OTHER_CLIENT,
        },
    )
    _assert_fixed(status, body, kind="auth", forbidden=(AUTH_LEAK, OTHER_CLIENT))


def test_strands_returns_model_access_denied_verbatim(services: dict[str, str]) -> None:
    status, body = _invoke(
        services,
        {
            "agent": "strands-agent",
            "kind": "prompt",
            "token_client": ALLOWED_CLIENT,
        },
    )
    _assert_fixed(
        status,
        body,
        kind="failure",
        forbidden=(ACCOUNT_ID, ROLE_ARN, RESOURCE_ARN, DENIED_MESSAGE),
    )


def test_agui_langgraph_returns_client_check_failure_verbatim(
    services: dict[str, str],
) -> None:
    status, body = _invoke(
        services,
        {
            "agent": "agui-langgraph-agent",
            "kind": "agui",
            "token_client": OTHER_CLIENT,
        },
    )
    _assert_fixed(status, body, kind="auth", forbidden=(AUTH_LEAK, OTHER_CLIENT))


def test_agui_langgraph_returns_model_access_denied_verbatim(
    services: dict[str, str],
) -> None:
    status, body = _invoke(
        services,
        {
            "agent": "agui-langgraph-agent",
            "kind": "agui",
            "token_client": ALLOWED_CLIENT,
            "memory_id": "example-memory",
            "aws_mode": "model-only",
        },
    )
    _assert_fixed(
        status,
        body,
        kind="failure",
        forbidden=(ACCOUNT_ID, ROLE_ARN, RESOURCE_ARN, DENIED_MESSAGE),
    )


def test_agui_strands_returns_client_check_failure_verbatim(
    services: dict[str, str],
) -> None:
    status, body = _invoke(
        services,
        {
            "agent": "agui-strands-agent",
            "kind": "agui",
            "token_client": OTHER_CLIENT,
        },
    )
    _assert_fixed(status, body, kind="auth", forbidden=(AUTH_LEAK, OTHER_CLIENT))


def test_agui_strands_returns_model_access_denied_verbatim(
    services: dict[str, str],
) -> None:
    status, body = _invoke(
        services,
        {
            "agent": "agui-strands-agent",
            "kind": "agui",
            "token_client": ALLOWED_CLIENT,
            "memory_id": "example-memory",
            "aws_mode": "model-only",
        },
    )
    _assert_fixed(
        status,
        body,
        kind="failure",
        forbidden=(ACCOUNT_ID, ROLE_ARN, RESOURCE_ARN, DENIED_MESSAGE),
    )


def test_orchestrator_returns_model_access_denied_verbatim(
    services: dict[str, str],
) -> None:
    status, body = _invoke(
        services,
        {
            "agent": "orchestrator",
            "kind": "orchestrator",
            "aws_mode": "deny-all",
        },
    )
    _assert_fixed(
        status,
        body,
        kind="failure",
        forbidden=(ACCOUNT_ID, ROLE_ARN, RESOURCE_ARN, DENIED_MESSAGE),
    )


def harness() -> int:
    """Load one agent and POST /invocations. Used in a fresh interpreter."""
    case = json.loads(os.environ["HARNESS_CASE"])
    agent_dir = AGENT_CODE / case["agent"]
    sys.path.insert(0, str(agent_dir))
    sys.path.insert(0, str(AGENT_CODE))

    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "agent_under_test", agent_dir / "agent.py"
    )
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {agent_dir / 'agent.py'}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    from starlette.testclient import TestClient

    token = os.environ.get("HARNESS_TOKEN", "")
    headers = {}
    if token:
        headers["Authorization"] = "Bearer " + token
    kind = case["kind"]
    if kind == "prompt":
        payload = {
            "prompt": "hello",
            "runtimeSessionId": "session-abcdefghijklmnopqrstuvwxyz0123456789",
        }
    elif kind == "agui":
        payload = {
            "threadId": "thread-abcdefghijklmnopqrstuvwxyz",
            "runId": "run-abcdefghijklmnopqrstuvwxyz",
            "messages": [{"id": "m1", "role": "user", "content": "hello"}],
        }
    elif kind == "orchestrator":
        payload = {"prompt": "hello"}
        headers = {}
    else:
        raise RuntimeError(f"unknown kind {kind}")

    with TestClient(module.app, raise_server_exceptions=False) as client:
        response = client.post("/invocations", json=payload, headers=headers)
    print(
        "RESULT " + json.dumps({"status": response.status_code, "body": response.text})
    )
    return 0


if __name__ == "__main__" and "--harness" in sys.argv:
    raise SystemExit(harness())
