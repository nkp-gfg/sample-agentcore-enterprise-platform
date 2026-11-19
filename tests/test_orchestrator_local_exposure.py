"""Local orchestrator must not accept unauthenticated prompts on a published port.

The workshop compose service is the path under test. These tests are the
expected behavior and fail until that path is fixed:

- ``docker/docker-compose.yml`` publishes container port 8080 only on
  ``127.0.0.1``. A short mapping with no host address is published on every
  host interface (Docker Engine treats an empty host IP as ``0.0.0.0`` and,
  when IPv6 is available, ``::``).
- That compose service does not pass ``AWS_ACCESS_KEY_ID``,
  ``AWS_SECRET_ACCESS_KEY``, ``AWS_SESSION_TOKEN``, or ``AWS_SECURITY_TOKEN``
  into the container.
- ``POST /invocations`` reads ``ORCHESTRATOR_LOCAL_SECRET`` from the
  environment and rejects the request with HTTP 403 unless the
  ``X-Orchestrator-Local-Secret`` header matches that value. The comparison
  is for that request only. A missing variable rejects every invocation.
  Rejection happens before a Bedrock client is constructed and before any
  Bedrock request is signed.
- A request that presents the matching header is the one whose prompt is
  sent to Bedrock, and the model text from that call is what the caller
  receives. ``GET /ping`` stays unauthenticated so the compose healthcheck
  can run, and it must not call Bedrock.

Run (versions are what the unpinned orchestrator requirements resolved to
on the commit these tests were written against)::

    python3 -m pip install 'bedrock-agentcore==1.23.1' 'strands-agents==1.56.0' \
        'boto3==1.44.6' 'botocore==1.44.6' pytest pyyaml httpx
    python3 -m pytest tests/test_orchestrator_local_exposure.py -q
"""

from __future__ import annotations

import importlib
import json
import os
import sys
from binascii import crc32
from pathlib import Path
from struct import pack

import pytest
import yaml
from botocore.awsrequest import AWSResponse
from starlette.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

REPO = Path(__file__).resolve().parents[1]
COMPOSE_FILE = REPO / "docker" / "docker-compose.yml"
ORCHESTRATOR_DIR = REPO / "agent-code" / "orchestrator"
SECRET_HEADER = "X-Orchestrator-Local-Secret"
SECRET_ENV = "ORCHESTRATOR_LOCAL_SECRET"
LOCAL_SECRET = "PLACEHOLDER_LOCAL_SECRET"
MODEL_TEXT = "MODEL_TEXT_FROM_STUB"
CREDENTIAL_ENV = (
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "AWS_SECURITY_TOKEN",
)
LOOPBACK_HOST = "127.0.0.1"

# Populated by the boto3 patch. Cleared at the start of each request.
_BEDROCK: dict[str, list] = {"clients": [], "signed": []}


def _encode_headers(headers: dict[str, str]) -> bytes:
    """Encode event-stream headers the way botocore's decoder reads them.

    Name length is one byte and string values are type 7 with a two-byte
    length. See botocore 1.44.6 ``eventstream.py`` ``EventStreamHeaderParser``.
    """
    encoded = b""
    for name, value in headers.items():
        name_bytes = name.encode("utf-8")
        value_bytes = value.encode("utf-8")
        encoded += pack("!B", len(name_bytes)) + name_bytes
        encoded += pack("!B", 7)
        encoded += pack("!H", len(value_bytes)) + value_bytes
    return encoded


def _encode_message(event_type: str, payload: dict) -> bytes:
    """One event-stream message. Prelude and CRC match botocore's parser."""
    headers = _encode_headers(
        {
            ":message-type": "event",
            ":event-type": event_type,
            ":content-type": "application/json",
        }
    )
    body = json.dumps(payload).encode("utf-8")
    total_length = 12 + len(headers) + len(body) + 4
    prelude_without_crc = pack("!II", total_length, len(headers))
    prelude_crc = crc32(prelude_without_crc) & 0xFFFFFFFF
    prelude = prelude_without_crc + pack("!I", prelude_crc)
    message_crc = (
        crc32(pack("!I", prelude_crc) + headers + body, prelude_crc) & 0xFFFFFFFF
    )
    return prelude + headers + body + pack("!I", message_crc)


def _converse_stream_body(text: str) -> bytes:
    """A ConverseStream body the installed botocore parser accepts.

    The shapes are ``ConverseStreamOutput`` and its members in
    ``botocore/data/bedrock-runtime/2023-09-30/service-2.json``.
    """
    events = [
        ("messageStart", {"role": "assistant"}),
        (
            "contentBlockDelta",
            {"delta": {"text": text}, "contentBlockIndex": 0},
        ),
        ("contentBlockStop", {"contentBlockIndex": 0}),
        ("messageStop", {"stopReason": "end_turn"}),
        (
            "metadata",
            {
                "usage": {
                    "inputTokens": 1,
                    "outputTokens": 1,
                    "totalTokens": 2,
                },
                "metrics": {"latencyMs": 1},
            },
        ),
    ]
    return b"".join(_encode_message(name, payload) for name, payload in events)


class _RawStream:
    def __init__(self, data: bytes) -> None:
        self._data = data

    def stream(self, amt: int = 65536, decode_content: object = None):
        yield self._data

    def read(self, amt: int | None = None) -> bytes:
        if amt is None:
            return self._data
        return self._data[:amt]

    def close(self) -> None:
        return None


def _header_text(value: object) -> str:
    if isinstance(value, bytes):
        return value.decode("utf-8")
    return str(value)


def _install_bedrock_capture(monkeypatch: pytest.MonkeyPatch) -> None:
    import boto3

    original = boto3.Session.client

    def client(self, service_name, *args, **kwargs):
        created = original(self, service_name, *args, **kwargs)
        if service_name != "bedrock-runtime":
            return created
        _BEDROCK["clients"].append(service_name)

        def remember_signer(request, request_signer=None, **_kwargs):
            request.context["captured_signer"] = request_signer

        def capture(request, **_kwargs):
            body = request.body
            if hasattr(body, "read"):
                body = body.read()
            signer = request.context.get("captured_signer")
            frozen = signer._credentials.get_frozen_credentials()
            _BEDROCK["signed"].append(
                {
                    "url": request.url,
                    "authorization": _header_text(request.headers.get("Authorization")),
                    "session_token": _header_text(
                        request.headers.get("X-Amz-Security-Token")
                    ),
                    "credential_method": signer._credentials.method,
                    "access_key": frozen.access_key,
                    "secret_present": bool(frozen.secret_key),
                    "body": body.decode("utf-8") if isinstance(body, bytes) else body,
                }
            )
            return AWSResponse(
                request.url,
                200,
                {"Content-Type": "application/vnd.amazon.eventstream"},
                _RawStream(_converse_stream_body(MODEL_TEXT)),
            )

        created.meta.events.register(
            "before-sign.bedrock-runtime.ConverseStream", remember_signer
        )
        created.meta.events.register(
            "before-send.bedrock-runtime.ConverseStream", capture
        )
        return created

    monkeypatch.setattr(boto3.Session, "client", client)


def _load_orchestrator(secret: str | None):
    if secret is None:
        os.environ.pop(SECRET_ENV, None)
    else:
        os.environ[SECRET_ENV] = secret
    sys.path.insert(0, str(ORCHESTRATOR_DIR))
    import agent

    return importlib.reload(agent)


@pytest.fixture
def bedrock_capture(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "PLACEHOLDER_ACCESS_KEY_ID")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "PLACEHOLDER_SECRET_ACCESS_KEY")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "PLACEHOLDER_SESSION_TOKEN")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
    monkeypatch.setenv("AWS_REGION", "us-east-1")
    monkeypatch.delenv("AWS_PROFILE", raising=False)
    monkeypatch.delenv("AWS_ENDPOINT_URL", raising=False)
    monkeypatch.delenv("GUARDRAIL_ID", raising=False)
    monkeypatch.delenv(SECRET_ENV, raising=False)
    empty_config = tmp_path / "empty-aws-config"
    empty_config.write_text("")
    monkeypatch.setenv("AWS_CONFIG_FILE", str(empty_config))
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", str(empty_config))
    _install_bedrock_capture(monkeypatch)
    yield


def _reset_capture() -> None:
    _BEDROCK["clients"].clear()
    _BEDROCK["signed"].clear()


def _post(app, payload: dict, headers: dict[str, str] | None = None):
    _reset_capture()
    with TestClient(app) as http:
        return http.post("/invocations", json=payload, headers=headers or {})


def _prompt_texts(body: str) -> list[str]:
    parsed = json.loads(body)
    texts = []
    for message in parsed.get("messages", []):
        for block in message.get("content", []):
            if "text" in block:
                texts.append(block["text"])
    return texts


def _assert_rejected(response) -> None:
    assert response.status_code == 403
    assert MODEL_TEXT not in response.text
    assert _BEDROCK["clients"] == []
    assert _BEDROCK["signed"] == []


def _assert_signed_with_env_credentials(prompt: str) -> None:
    assert len(_BEDROCK["signed"]) == 1
    signed = _BEDROCK["signed"][0]
    assert _prompt_texts(signed["body"]) == [prompt]
    assert "bedrock-runtime" in signed["url"]
    assert "converse-stream" in signed["url"]
    assert signed["credential_method"] == "env"
    assert signed["access_key"] == os.environ["AWS_ACCESS_KEY_ID"]
    assert signed["session_token"] == os.environ["AWS_SESSION_TOKEN"]
    assert signed["secret_present"] is True
    assert os.environ["AWS_ACCESS_KEY_ID"] in signed["authorization"]


def test_unauthenticated_prompt_is_rejected_before_bedrock(bedrock_capture):
    module = _load_orchestrator(LOCAL_SECRET)
    response = _post(
        module.app,
        {"prompt": "unique-unauthenticated-prompt"},
        {"Host": "127.0.0.1"},
    )
    _assert_rejected(response)


def test_bearer_token_does_not_authorize_an_invocation(bedrock_capture):
    module = _load_orchestrator(LOCAL_SECRET)
    response = _post(
        module.app,
        {"prompt": "unique-bearer-prompt"},
        {
            "Host": "127.0.0.1",
            "Authorization": "Bearer PLACEHOLDER_NOT_THE_LOCAL_SECRET",
        },
    )
    _assert_rejected(response)


def test_wrong_local_secret_is_rejected_before_bedrock(bedrock_capture):
    module = _load_orchestrator(LOCAL_SECRET)
    response = _post(
        module.app,
        {"prompt": "unique-wrong-secret-prompt"},
        {SECRET_HEADER: "PLACEHOLDER_WRONG_SECRET"},
    )
    _assert_rejected(response)


def test_unset_local_secret_rejects_every_invocation(bedrock_capture):
    module = _load_orchestrator(None)
    response = _post(
        module.app,
        {"prompt": "unique-unset-secret-prompt"},
        {SECRET_HEADER: LOCAL_SECRET},
    )
    _assert_rejected(response)


def test_empty_payload_is_rejected_before_bedrock(bedrock_capture):
    module = _load_orchestrator(LOCAL_SECRET)
    response = _post(module.app, {})
    _assert_rejected(response)


def test_secret_authorizes_only_that_requests_prompt(bedrock_capture):
    module = _load_orchestrator(LOCAL_SECRET)
    authorized = _post(
        module.app,
        {"prompt": "prompt-authorized-a"},
        {SECRET_HEADER: LOCAL_SECRET},
    )
    assert authorized.status_code == 200
    assert authorized.json()["response"] == MODEL_TEXT
    _assert_signed_with_env_credentials("prompt-authorized-a")

    rejected = _post(
        module.app,
        {"prompt": "prompt-not-authorized-b"},
    )
    _assert_rejected(rejected)

    second = _post(
        module.app,
        {"prompt": "prompt-authorized-c"},
        {SECRET_HEADER: LOCAL_SECRET},
    )
    assert second.status_code == 200
    assert second.json()["response"] == MODEL_TEXT
    _assert_signed_with_env_credentials("prompt-authorized-c")
    assert "prompt-not-authorized-b" not in _BEDROCK["signed"][0]["body"]
    assert "prompt-authorized-a" not in _prompt_texts(_BEDROCK["signed"][0]["body"])


def test_ping_stays_open_and_does_not_call_bedrock(bedrock_capture):
    module = _load_orchestrator(LOCAL_SECRET)
    _reset_capture()
    with TestClient(module.app) as http:
        response = http.get("/ping")
    assert response.status_code == 200
    assert _BEDROCK["clients"] == []
    assert _BEDROCK["signed"] == []


def test_websocket_does_not_call_bedrock(bedrock_capture):
    module = _load_orchestrator(LOCAL_SECRET)
    _reset_capture()
    with TestClient(module.app) as http:
        try:
            with http.websocket_connect("/ws"):
                pass
        except WebSocketDisconnect:
            # The app has no websocket handler and closes the socket.
            pass
    assert _BEDROCK["clients"] == []
    assert _BEDROCK["signed"] == []


def _split_port_spec(raw: str) -> tuple[str, str, str]:
    """Same field split as go-connections v0.4.0 ``nat.splitParts``."""
    without_proto, _, _protocol = raw.partition("/")
    parts = without_proto.split(":")
    count = len(parts)
    container = parts[-1]
    if count == 1:
        return "", "", container
    if count == 2:
        return "", parts[0], container
    if count == 3:
        return parts[0], parts[1], container
    return ":".join(parts[:-2]), parts[-2], container


def _published_ports(service: dict) -> list[dict[str, str]]:
    bindings = []
    for entry in service.get("ports") or []:
        if isinstance(entry, str):
            host_ip, host_port, container_port = _split_port_spec(entry)
            bindings.append(
                {
                    "host_ip": host_ip,
                    "host_port": host_port,
                    "container_port": container_port,
                    "protocol": entry.partition("/")[2] or "tcp",
                }
            )
            continue
        if not isinstance(entry, dict):
            pytest.fail(f"unsupported port entry: {entry!r}")
        published = entry.get("published", "")
        target = entry.get("target", "")
        bindings.append(
            {
                "host_ip": str(entry.get("host_ip") or ""),
                "host_port": str(published),
                "container_port": str(target),
                "protocol": str(entry.get("protocol") or "tcp"),
            }
        )
    return bindings


def _environment_names(service: dict) -> set[str]:
    names: set[str] = set()
    environment = service.get("environment")
    if isinstance(environment, dict):
        names.update(str(key) for key in environment)
    elif isinstance(environment, list):
        for item in environment:
            if isinstance(item, str):
                names.add(item.split("=", 1)[0])
            elif isinstance(item, dict):
                names.update(str(key) for key in item)
    for secret in service.get("secrets") or []:
        if isinstance(secret, str):
            names.add(secret)
        elif isinstance(secret, dict):
            target = secret.get("target") or secret.get("source") or ""
            names.add(str(target))
    return names


def _compose_services() -> dict:
    document = yaml.safe_load(COMPOSE_FILE.read_text())
    return document.get("services") or {}


def test_compose_publishes_orchestrator_only_on_loopback():
    services = _compose_services()
    orchestrator = services["orchestrator"]
    assert orchestrator.get("network_mode") != "host"
    assert _published_ports(orchestrator) == [
        {
            "host_ip": LOOPBACK_HOST,
            "host_port": "8080",
            "container_port": "8080",
            "protocol": "tcp",
        }
    ]
    for service_name, service in services.items():
        assert service.get("network_mode") != "host", service_name
        for binding in _published_ports(service):
            assert binding["host_ip"] == LOOPBACK_HOST, (service_name, binding)


def test_compose_does_not_inject_aws_credential_environment():
    for service_name, service in _compose_services().items():
        leaked = _environment_names(service) & set(CREDENTIAL_ENV)
        assert leaked == set(), (service_name, leaked)
