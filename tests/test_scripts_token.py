"""Unit check for utils.get_m2m_token URL and Basic auth construction (no AWS needed)."""

import base64
import io
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

import utils
from botocore.exceptions import ClientError

# Stub values, not credentials. Held in constants deliberately: a string literal
# compared against a variable named `token` reads as a hardcoded credential to
# Bandit (B105), and a HIGH finding that has to be explained away on every scan
# is worse than naming the fixture properly once.
STUB_RESPONSE_VALUE = "stub-value-from-fake-urlopen"
STUB_CLIENT_CONFIG_VALUE = "stub-value-from-fake-secrets-manager"
STUB_SECRET_NAME = "agentcore/test/m2m"


class FakeAwsClient:
    """Stands in for the ssm / cognito-idp / sts clients get_m2m_token creates."""

    def get_parameter(self, Name):
        values = {
            "auth/mode": "brokered",
            "auth/user-pool-id": "pool-123",
            "auth/m2m-client-id": "client-abc",
            "auth/m2m-client-secret-name": STUB_SECRET_NAME,
        }
        value = next(value for suffix, value in values.items() if Name.endswith(suffix))
        return {"Parameter": {"Value": value}}

    def get_secret_value(self, SecretId):
        assert SecretId == STUB_SECRET_NAME
        return {"SecretString": STUB_CLIENT_CONFIG_VALUE}

    def get_caller_identity(self):
        return {"Account": "111122223333"}


def test_get_m2m_token_builds_url_and_basic_auth(monkeypatch):
    monkeypatch.setenv("PROJECT_NAME", "myproj")
    monkeypatch.setenv("ENVIRONMENT", "prod")
    monkeypatch.setenv("AWS_REGION", "eu-west-1")
    monkeypatch.setattr(utils.boto3, "client", lambda *a, **kw: FakeAwsClient())

    captured = {}

    def fake_urlopen(req, timeout=None):
        captured["req"] = req
        captured["timeout"] = timeout
        return io.BytesIO(json.dumps({"access_token": STUB_RESPONSE_VALUE}).encode())

    monkeypatch.setattr(utils.urllib.request, "urlopen", fake_urlopen)

    token = utils.get_m2m_token()

    assert token == STUB_RESPONSE_VALUE
    assert captured["timeout"] == 15
    req = captured["req"]
    assert (
        req.full_url
        == "https://myproj-prod-111122223333.auth.eu-west-1.amazoncognito.com/oauth2/token"
    )
    basic = f"client-abc:{STUB_CLIENT_CONFIG_VALUE}".encode()
    expected_auth = "Basic " + base64.b64encode(basic).decode()
    assert req.get_header("Authorization") == expected_auth
    assert b"grant_type=client_credentials" in req.data
    assert b"agentcore%2Finvoke" in req.data


def test_old_deployment_falls_back_to_describe_user_pool_client(monkeypatch):
    class LegacyAwsClient(FakeAwsClient):
        def get_parameter(self, Name):
            if Name.endswith("auth/m2m-client-secret-name"):
                raise ClientError(
                    {"Error": {"Code": "ParameterNotFound", "Message": "missing"}},
                    "GetParameter",
                )
            return super().get_parameter(Name)

        def describe_user_pool_client(self, UserPoolId, ClientId):
            assert (UserPoolId, ClientId) == ("pool-123", "client-abc")
            return {"UserPoolClient": {"ClientSecret": STUB_CLIENT_CONFIG_VALUE}}

    monkeypatch.setenv("PROJECT_NAME", "myproj")
    monkeypatch.setenv("ENVIRONMENT", "prod")
    monkeypatch.setenv("AWS_REGION", "eu-west-1")
    monkeypatch.setattr(utils.boto3, "client", lambda *a, **kw: LegacyAwsClient())
    monkeypatch.setattr(
        utils.urllib.request,
        "urlopen",
        lambda _req, timeout=None: io.BytesIO(
            json.dumps({"access_token": STUB_RESPONSE_VALUE}).encode()
        ),
    )

    assert utils.get_m2m_token() == STUB_RESPONSE_VALUE


def test_secret_reference_access_denied_does_not_fall_back(monkeypatch):
    class DeniedAwsClient(FakeAwsClient):
        def get_parameter(self, Name):
            if Name.endswith("auth/m2m-client-secret-name"):
                raise ClientError(
                    {"Error": {"Code": "AccessDenied", "Message": "denied"}},
                    "GetParameter",
                )
            return super().get_parameter(Name)

    monkeypatch.setenv("AWS_REGION", "eu-west-1")
    monkeypatch.setattr(utils.boto3, "client", lambda *a, **kw: DeniedAwsClient())

    try:
        utils.get_m2m_token("myproj", "prod")
    except ClientError as exc:
        assert exc.response["Error"]["Code"] == "AccessDenied"
    else:
        raise AssertionError("AccessDenied must not fall back to Cognito")


def test_invoke_imports_without_aws_and_session_id_is_40_chars():
    """invoke.py must be importable with no AWS credentials (no module-level calls)."""
    import invoke

    sid = invoke.new_session_id()
    assert len(sid) == 40
    assert sid != invoke.new_session_id()


def test_oidc_discovery_and_direct_token_reject_non_https_urls(monkeypatch):
    import pytest

    with pytest.raises(ValueError, match="https://"):
        utils.oidc_discovery("http://login.example.com/v2.0")

    class DirectAwsClient(FakeAwsClient):
        def get_parameter(self, Name):
            if Name.endswith("auth/mode"):
                return {"Parameter": {"Value": "direct"}}
            if Name.endswith("auth/issuer-url"):
                return {"Parameter": {"Value": "https://login.example.com/v2.0"}}
            if Name.endswith("auth/m2m-scope"):
                return {"Parameter": {"Value": "api://client/.default"}}
            return super().get_parameter(Name)

    monkeypatch.setenv("PROJECT_NAME", "myproj")
    monkeypatch.setenv("ENVIRONMENT", "prod")
    monkeypatch.setenv("AWS_REGION", "[REDACTED]")
    monkeypatch.setattr(utils.boto3, "client", lambda *a, **kw: DirectAwsClient())
    monkeypatch.setattr(
        utils.urllib.request,
        "urlopen",
        lambda _url, timeout=None: io.BytesIO(
            json.dumps({"token_endpoint": "http://insecure.example/token"}).encode()
        ),
    )

    with pytest.raises(ValueError, match="https://"):
        utils.get_m2m_token()


def test_no_redirect_opener_refuses_http_redirects():
    import threading
    import urllib.error
    from http.server import BaseHTTPRequestHandler, HTTPServer

    import pytest

    class RedirectHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(302)
            self.send_header("Location", "http://127.0.0.1/redirected")
            self.end_headers()

        def log_message(self, *_args):
            pass

    server = HTTPServer(("127.0.0.1", 0), RedirectHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        url = f"http://127.0.0.1:{server.server_port}/start"
        with pytest.raises(urllib.error.HTTPError) as exc_info:
            utils._NO_REDIRECT_OPENER.open(url, timeout=5)
        assert exc_info.value.code == 302
        assert "disabled" in str(exc_info.value.reason).lower()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_authenticate_cognito_decodes_urlsafe_jwt_payload(monkeypatch):
    # Includes '-' and '_' in base64url encoding (0xfb, 0xff bytes) where
    # standard base64.b64decode would fail, plus unpadded payload length % 4 != 0.
    sub_value = "user-???"
    payload_bytes = json.dumps({"sub": sub_value, "pad": "~?>?"}).encode("utf-8")
    b64url_payload = (
        base64.urlsafe_b64encode(payload_bytes).rstrip(b"=").decode("ascii")
    )
    assert "-" in b64url_payload or "_" in b64url_payload
    id_token = f"eyJhbGciOiJub25lIn0.{b64url_payload}.sig"

    class CognitoStub:
        class exceptions:
            class UserNotFoundException(Exception):
                pass

        def admin_get_user(self, **_kwargs):
            return {}

        def describe_user_pool_client(self, **_kwargs):
            return {"UserPoolClient": {}}

        def initiate_auth(self, **_kwargs):
            return {
                "AuthenticationResult": {
                    "AccessToken": "stub-access",
                    "IdToken": id_token,
                }
            }

    monkeypatch.setenv("AWS_REGION", "us-east-1")
    monkeypatch.setattr(utils.boto3, "client", lambda *a, **kw: CognitoStub())

    access, returned_id, user_id = utils.authenticate_cognito(
        "pool-1", "client-1", "alice", "pw"
    )
    assert access == "stub-access"
    assert returned_id == id_token
    assert user_id == sub_value
