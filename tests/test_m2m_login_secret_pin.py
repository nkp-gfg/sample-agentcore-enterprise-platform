"""Machine login must not fetch or send a secret chosen by SSM.

Direct-mode login (scripts/utils.py get_m2m_token) reads auth/issuer-url and
auth/m2m-client-secret-name from SSM, then posts that secret to the token
endpoint named by the issuer's discovery document. Those parameters are not
the deployment's own copy of the id and the host. These tests are the pin:

- The token endpoint host has to be login.microsoftonline.com (the only
  direct-mode identity provider this deployment supports). A lookalike host,
  a userinfo host, or a discovery document that names some other host is
  refused before any secret is fetched and before any request is sent there.
- When the deployment named its secret (IDP_CLIENT_SECRET_NAME, which
  deploy.sh and scripts/verify.py already export), that is the only id
  GetSecretValue may use. A different id, including one returned by a later
  read of the same parameter, is refused before GetSecretValue.
- The same rules apply to every caller of get_m2m_token: invoke, the gateway
  test, identity check, and both use-case verify scripts.

Brokered login is not covered. It builds the token host from the project,
environment, account, and region and does not follow a discovery document, so
it does not post the secret to a host taken from SSM. The AgentCore token
vault and the migration adapter fetch secrets on other paths and are not
covered here either.

These tests fail while the pin is missing.
"""

from __future__ import annotations

import importlib.util
import io
import json
import sys
import urllib.parse
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(REPO / "scripts"))

import utils

TENANT = "11111111-2222-3333-4444-555555555555"
CLIENT = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
DEPLOYMENT_SECRET_NAME = "agentcore/idp-client-secret"
UNPINNED_SECRET_NAME = "connected-service/credential"
SWAPPED_SECRET_NAME = "connected-service/other-credential"
DEPLOYMENT_SECRET = "deployment-secret-placeholder"
UNPINNED_SECRET = "unpinned-secret-placeholder"
SWAPPED_SECRET = "swapped-secret-placeholder"
ENTRA_HOST = "login.microsoftonline.com"
ENTRA_ISSUER = f"https://{ENTRA_HOST}/{TENANT}/v2.0"
ENTRA_TOKEN = f"https://{ENTRA_HOST}/{TENANT}/oauth2/v2.0/token"
ATTACKER_ISSUER = "https://attacker.example/v2.0"
ATTACKER_TOKEN = "https://attacker.example/token"
LOOKALIKE_ISSUER = f"https://{ENTRA_HOST}.attacker.example/{TENANT}/v2.0"
USERINFO_ISSUER = f"https://{ENTRA_HOST}@attacker.example/{TENANT}/v2.0"
PATH_ISSUER = f"https://attacker.example/{ENTRA_HOST}/v2.0"
COLLECTOR_TOKEN = "https://collector.example/token"

SECRETS = {
    DEPLOYMENT_SECRET_NAME: DEPLOYMENT_SECRET,
    UNPINNED_SECRET_NAME: UNPINNED_SECRET,
    SWAPPED_SECRET_NAME: SWAPPED_SECRET,
}


class RecordingAws:
    """SSM and Secrets Manager stand-in.

    Each parameter is a queue. The first read returns the first value; every
    later read returns the next value, then stays on the last one. A check
    that accepts the first value and then reads the parameter again therefore
    acts on a different id than the one it checked.
    """

    def __init__(self, params: dict[str, list[str]], secret_ids: list[str]):
        self.params = {key: list(values) for key, values in params.items()}
        self.secret_ids = secret_ids
        self.reads: list[str] = []

    def get_parameter(self, Name):
        key = Name.split("/", 3)[3]
        self.reads.append(key)
        queue = self.params[key]
        value = queue.pop(0) if len(queue) > 1 else queue[0]
        return {"Parameter": {"Value": value}}

    def get_secret_value(self, SecretId):
        self.secret_ids.append(SecretId)
        return {"SecretString": SECRETS.get(SecretId, "unexpected-secret-placeholder")}


def _host(url: str) -> str | None:
    return urllib.parse.urlparse(url).hostname


def _install(monkeypatch, params, discovery_endpoints):
    secret_ids: list[str] = []
    recorded: list[tuple[str, bytes | None]] = []
    endpoints = list(discovery_endpoints)
    aws = RecordingAws(params, secret_ids)
    monkeypatch.setattr(utils.boto3, "client", lambda *args, **kwargs: aws)

    def fake_urlopen(req, *args, **kwargs):
        if isinstance(req, str):
            url, body = req, None
        else:
            url, body = req.full_url, req.data
        recorded.append((url, body))
        if url.endswith("/.well-known/openid-configuration"):
            endpoint = endpoints.pop(0) if len(endpoints) > 1 else endpoints[0]
            payload = {"token_endpoint": endpoint, "issuer": url}
        else:
            payload = {"access_token": "stub-token"}
        return io.BytesIO(json.dumps(payload).encode())

    monkeypatch.setattr(utils.urllib.request, "urlopen", fake_urlopen)
    return secret_ids, recorded, aws.reads


def _params(**overrides: list[str]) -> dict[str, list[str]]:
    base = {
        "auth/mode": ["direct"],
        "auth/issuer-url": [ENTRA_ISSUER],
        "auth/m2m-client-id": [CLIENT],
        "auth/m2m-scope": [f"{CLIENT}/.default"],
        "auth/m2m-client-secret-name": [DEPLOYMENT_SECRET_NAME],
        "auth/app-client-id": [CLIENT],
        "gateway/url": ["https://gateway.example/mcp"],
        "use-cases/hello-platform/gateway-seen": ["hello: https://gateway.example/mcp"],
        "use-cases/{name}/gateway-seen": ["hello: https://gateway.example/mcp"],
    }
    base.update(overrides)
    return base


def _design_env(monkeypatch, *, secret_name: str | None = DEPLOYMENT_SECRET_NAME):
    monkeypatch.setenv("PROJECT_NAME", "proj")
    monkeypatch.setenv("ENVIRONMENT", "dev")
    monkeypatch.setenv("AWS_REGION", "us-east-1")
    monkeypatch.setenv("IDP_MODE", "direct")
    monkeypatch.setenv("IDP_TYPE", "entra_id")
    monkeypatch.setenv("IDP_TENANT_ID", TENANT)
    monkeypatch.setenv("IDP_CLIENT_ID", CLIENT)
    if secret_name is None:
        monkeypatch.delenv("IDP_CLIENT_SECRET_NAME", raising=False)
    else:
        monkeypatch.setenv("IDP_CLIENT_SECRET_NAME", secret_name)


def _bodies(recorded) -> list[str]:
    return [body.decode() if isinstance(body, bytes) else "" for _, body in recorded]


def _assert_no_off_host(recorded) -> None:
    offenders = [url for url, _ in recorded if _host(url) != ENTRA_HOST]
    assert offenders == []


def _assert_secret_not_sent(recorded, placeholder: str) -> None:
    assert all(placeholder not in body for body in _bodies(recorded))


def _attempt(fn):
    try:
        return fn()
    except SystemExit:
        return None
    except Exception:
        return None


@pytest.mark.parametrize(
    "issuer",
    [ATTACKER_ISSUER, LOOKALIKE_ISSUER, USERINFO_ISSUER, PATH_ISSUER],
)
def test_direct_login_does_not_contact_or_fetch_for_untrusted_issuer(
    monkeypatch, issuer
):
    _design_env(monkeypatch)
    secret_ids, recorded, _reads = _install(
        monkeypatch,
        _params(
            **{
                "auth/issuer-url": [issuer, ATTACKER_ISSUER],
                "auth/m2m-client-secret-name": [
                    UNPINNED_SECRET_NAME,
                    SWAPPED_SECRET_NAME,
                ],
            }
        ),
        [ATTACKER_TOKEN, COLLECTOR_TOKEN],
    )

    _attempt(lambda: utils.get_m2m_token())

    assert secret_ids == []
    _assert_no_off_host(recorded)
    _assert_secret_not_sent(recorded, UNPINNED_SECRET)
    _assert_secret_not_sent(recorded, SWAPPED_SECRET)
    _assert_secret_not_sent(recorded, DEPLOYMENT_SECRET)


def test_untrusted_issuer_is_refused_without_the_design_secret_name(monkeypatch):
    """invoke.py does not require the deploy shell's exported secret name."""
    _design_env(monkeypatch, secret_name=None)
    secret_ids, recorded, _reads = _install(
        monkeypatch,
        _params(
            **{
                "auth/issuer-url": [ATTACKER_ISSUER],
                "auth/m2m-client-secret-name": [DEPLOYMENT_SECRET_NAME],
            }
        ),
        [ATTACKER_TOKEN],
    )

    _attempt(lambda: utils.get_m2m_token())

    assert secret_ids == []
    _assert_no_off_host(recorded)
    _assert_secret_not_sent(recorded, DEPLOYMENT_SECRET)


def test_discovery_token_host_is_pinned_before_the_secret_is_fetched(monkeypatch):
    _design_env(monkeypatch)
    secret_ids, recorded, _reads = _install(
        monkeypatch,
        _params(
            **{
                "auth/issuer-url": [ENTRA_ISSUER, ATTACKER_ISSUER],
                "auth/m2m-client-secret-name": [
                    DEPLOYMENT_SECRET_NAME,
                    UNPINNED_SECRET_NAME,
                ],
            }
        ),
        [ATTACKER_TOKEN, COLLECTOR_TOKEN],
    )

    _attempt(lambda: utils.get_m2m_token())

    assert secret_ids == []
    _assert_no_off_host(recorded)
    _assert_secret_not_sent(recorded, DEPLOYMENT_SECRET)
    _assert_secret_not_sent(recorded, UNPINNED_SECRET)


def test_unpinned_secret_name_is_rejected_before_get_secret_value(monkeypatch):
    _design_env(monkeypatch)
    secret_ids, recorded, _reads = _install(
        monkeypatch,
        _params(
            **{
                "auth/m2m-client-secret-name": [
                    UNPINNED_SECRET_NAME,
                    SWAPPED_SECRET_NAME,
                ],
            }
        ),
        [ENTRA_TOKEN, COLLECTOR_TOKEN],
    )

    _attempt(lambda: utils.get_m2m_token())

    assert secret_ids == []
    _assert_no_off_host(recorded)
    _assert_secret_not_sent(recorded, UNPINNED_SECRET)
    _assert_secret_not_sent(recorded, SWAPPED_SECRET)


def test_repeat_lookup_cannot_swap_the_secret_after_a_matching_read(monkeypatch):
    _design_env(monkeypatch)
    secret_ids, recorded, _reads = _install(
        monkeypatch,
        _params(
            **{
                "auth/issuer-url": [ENTRA_ISSUER, ATTACKER_ISSUER],
                "auth/m2m-client-secret-name": [
                    DEPLOYMENT_SECRET_NAME,
                    UNPINNED_SECRET_NAME,
                ],
            }
        ),
        [COLLECTOR_TOKEN, ATTACKER_TOKEN],
    )

    _attempt(lambda: utils.get_m2m_token())

    # The first discovery document names an off-platform token host, so the
    # secret must not be fetched at all. A later read of the secret id is a
    # different id from the one that matched the deployment name.
    assert secret_ids == []
    _assert_no_off_host(recorded)
    _assert_secret_not_sent(recorded, UNPINNED_SECRET)
    _assert_secret_not_sent(recorded, DEPLOYMENT_SECRET)


def test_ssm_mode_flip_to_direct_still_pins_the_host(monkeypatch):
    _design_env(monkeypatch)
    monkeypatch.setenv("IDP_MODE", "brokered")
    secret_ids, recorded, _reads = _install(
        monkeypatch,
        _params(
            **{
                "auth/mode": ["direct"],
                "auth/issuer-url": [ATTACKER_ISSUER],
                "auth/m2m-client-secret-name": [UNPINNED_SECRET_NAME],
            }
        ),
        [ATTACKER_TOKEN],
    )

    _attempt(lambda: utils.get_m2m_token())

    assert secret_ids == []
    _assert_no_off_host(recorded)
    _assert_secret_not_sent(recorded, UNPINNED_SECRET)
    _assert_secret_not_sent(recorded, DEPLOYMENT_SECRET)


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize(
    "caller",
    ["invoke", "gateway", "identity", "hello", "template"],
)
def test_every_machine_login_caller_keeps_the_pin(monkeypatch, caller):
    _design_env(monkeypatch)
    secret_ids, recorded, _reads = _install(
        monkeypatch,
        _params(
            **{
                "auth/issuer-url": [ATTACKER_ISSUER, ATTACKER_ISSUER],
                "auth/m2m-client-secret-name": [
                    UNPINNED_SECRET_NAME,
                    SWAPPED_SECRET_NAME,
                ],
            }
        ),
        [ATTACKER_TOKEN, COLLECTOR_TOKEN],
    )

    class _Response:
        status_code = 200
        text = ""

        def json(self):
            return {"result": {"tools": [{"name": "sample-tool"}]}}

    import requests

    monkeypatch.setattr(requests, "post", lambda *args, **kwargs: _Response())

    if caller == "invoke":
        import invoke

        _attempt(
            lambda: invoke._post(
                "https://bedrock-agentcore.us-east-1.amazonaws.com/runtimes/x/invocations",
                {"prompt": "hi"},
                {},
            )
        )
        _attempt(invoke.list_tools)
    elif caller == "gateway":
        gateway = _load(REPO / "scripts" / "test_gateway.py", "test_gateway_cli")
        monkeypatch.setattr(sys, "argv", ["test_gateway.py"])
        _attempt(gateway.main)
    elif caller == "identity":
        identity = _load(REPO / "scripts" / "check_identity.py", "check_identity_cli")
        _attempt(identity.main)
    elif caller == "hello":
        hello = _load(
            REPO / "use-cases" / "hello-platform" / "verify.py", "hello_verify_cli"
        )
        _attempt(hello.main)
    else:
        template = _load(
            REPO / "use-cases" / "_template" / "verify.py", "template_verify_cli"
        )
        _attempt(template.main)

    assert "auth/m2m-client-secret-name" in _reads
    assert UNPINNED_SECRET_NAME not in secret_ids
    assert SWAPPED_SECRET_NAME not in secret_ids
    _assert_secret_not_sent(recorded, UNPINNED_SECRET)
    _assert_secret_not_sent(recorded, SWAPPED_SECRET)
    _assert_secret_not_sent(recorded, DEPLOYMENT_SECRET)
    off = [
        url
        for url, _ in recorded
        if _host(url) not in {ENTRA_HOST, "gateway.example", "bedrock-agentcore.us-east-1.amazonaws.com"}
    ]
    assert off == []
