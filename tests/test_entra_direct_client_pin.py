"""Direct Entra mode must pin the calling client, not only the audience.

Deployments with identity.mode direct and identity.idp entra_id put the app
client id in the runtime and gateway authorizers as allowedAudience, and copy
that same id into COGNITO_ALLOWED_CLIENTS. Entra v2 access tokens put the API
in aud and the application that requested the token in azp (v1 tokens use
appid). An identity token's aud is that same client id and carries neither
azp nor appid. Audience-only checks therefore accept another application's
access token and the app's own identity token. The subject of that token is
the memory actor id, and only after that check do memory-enabled agents open
gateway tools with the platform machine credential.

These tests are the required behavior. They fail while that gap is present.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "agent-code"))
sys.path.insert(0, str(REPO / "agent-code" / "shared"))

import jwt
from bedrock_agentcore.runtime import RequestContext
from jwt_claims import TokenRejected, validate_claims

TENANT = "11111111-2222-3333-4444-555555555555"
CLIENT = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
OTHER_APP = "bbbbbbbb-cccc-dddd-eeee-ffffffffffff"
ENTRA_ISSUER = f"https://login.microsoftonline.com/{TENANT}/v2.0"
ALLOW = (CLIENT,)


def test_foreign_azp_is_rejected_and_is_not_the_subject():
    """Another app's access token for this API must not act as its subject."""
    claims = _entra_access(azp=OTHER_APP, sub="victim-user")
    with pytest.raises(TokenRejected):
        validate_claims(claims, ENTRA_ISSUER, ALLOW)


def test_foreign_appid_is_rejected():
    """v1 tokens name the caller in appid. A foreign appid is not our client."""
    claims = _entra_access(azp=CLIENT, sub="victim-user")
    claims.pop("azp")
    claims["ver"] = "1.0"
    claims["appid"] = OTHER_APP
    with pytest.raises(TokenRejected):
        validate_claims(claims, ENTRA_ISSUER, ALLOW)


def test_allowed_azp_does_not_excuse_a_foreign_appid():
    """Both caller claims have to be allow-listed when a token carries both."""
    claims = _entra_access(azp=CLIENT, sub="victim-user")
    claims["appid"] = OTHER_APP
    with pytest.raises(TokenRejected):
        validate_claims(claims, ENTRA_ISSUER, ALLOW)


def test_identity_token_with_nonce_is_rejected():
    """An Entra identity token has aud equal to the client id and no azp."""
    claims = _entra_identity(sub="signed-in-user")
    with pytest.raises(TokenRejected):
        validate_claims(claims, ENTRA_ISSUER, ALLOW)


def test_versioned_token_without_caller_claim_is_rejected():
    """Access tokens carry azp or appid. A versioned token with neither is not one."""
    claims = {
        "iss": ENTRA_ISSUER,
        "aud": CLIENT,
        "sub": "signed-in-user",
        "ver": "2.0",
    }
    with pytest.raises(TokenRejected):
        validate_claims(claims, ENTRA_ISSUER, ALLOW)


def test_audience_list_does_not_hide_a_foreign_azp():
    claims = _entra_access(azp=OTHER_APP, sub="victim-user")
    claims["aud"] = [CLIENT]
    with pytest.raises(TokenRejected):
        validate_claims(claims, ENTRA_ISSUER, ALLOW)


def test_matching_azp_still_requires_the_audience():
    """The caller pin is in addition to the audience check."""
    claims = _entra_access(azp=CLIENT, sub="user-subject")
    claims["aud"] = OTHER_APP
    with pytest.raises(TokenRejected):
        validate_claims(claims, ENTRA_ISSUER, ALLOW)


def test_matching_access_token_returns_its_own_subject():
    """The actor is the sub of the token whose caller was allow-listed."""
    claims = _entra_access(azp=CLIENT, sub="user-subject")
    claims["oid"] = "object-id-not-the-subject"
    assert validate_claims(claims, ENTRA_ISSUER, ALLOW) == "user-subject"


def test_cognito_token_without_azp_is_still_accepted():
    """Brokered Cognito tokens have no azp. Pinning azp must not reject them."""
    issuer = "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_example"
    claims = {"iss": issuer, "aud": CLIENT, "sub": "user-1", "token_use": "access"}
    assert validate_claims(claims, issuer, ALLOW) == "user-1"


def test_signed_foreign_azp_token_never_becomes_the_memory_actor(issuer):
    """Header to subject, then memory and gateway. Rejection happens first.

    strands, langgraph, agui-strands, agui-langgraph, claude-sdk-agent, and
    claude-sdk-multi-agent all take this return value as the user id. The
    strands and langgraph patterns pass it to AgentCore Memory as actor_id
    and only then open gateway tools. Those tools call
    @requires_access_token(auth_flow="M2M"), which fetches the platform
    credential and does not use this inbound token.
    """
    token = _sign(_timed(issuer, _entra_access(azp=OTHER_APP, sub="victim-user")))
    context = _context(
        token, _sign(_timed(issuer, _entra_access(azp=CLIENT, sub="other-user")))
    )
    follow_on: list[str] = []

    def invoke():
        # Same order as the memory agents: identity, then actor_id, then tools.
        user_id = _auth().extract_user_id_from_context(context)
        follow_on.append(user_id)
        return user_id

    with pytest.raises(ValueError):
        invoke()
    assert follow_on == []


def test_signed_identity_token_never_becomes_the_memory_actor(issuer):
    token = _sign(_timed(issuer, _entra_identity(sub="signed-in-user")))
    context = _context(token)
    with pytest.raises(ValueError):
        _auth().extract_user_id_from_context(context)


def test_signed_access_token_from_our_client_returns_its_subject(issuer):
    """A second read of the header must not swap in another subject."""
    payload_user = "user-from-the-request-body"
    token = _sign(
        _timed(
            issuer,
            _entra_access(azp=CLIENT, sub="user-subject"),
        )
    )
    swapped = _sign(_timed(issuer, _entra_access(azp=OTHER_APP, sub="victim-user")))
    context = _context(token, swapped)
    user_id = _auth().extract_user_id_from_context(context)
    assert user_id == "user-subject"
    assert user_id != payload_user


def test_direct_mode_authorizers_pin_the_calling_client():
    """Runtime and gateway templates must require azp, not only aud.

    AgentCore matches allowedAudience against aud and allowedClients against
    client_id. Entra tokens have no client_id. The caller pin that the
    service can enforce is a required custom claim: azp equals the app client
    id. app.py's direct-mode branch is what this synthesis runs.
    """
    env = os.environ.copy()
    env.update(
        {
            "CDK_DEFAULT_ACCOUNT": "111111111111",
            "CDK_DEFAULT_REGION": "us-east-1",
            "IDP_MODE": "direct",
            "IDP_TYPE": "entra_id",
            "IDP_TENANT_ID": TENANT,
            "IDP_CLIENT_ID": CLIENT,
            "IDP_CLIENT_SECRET_NAME": "agentcore/idp-client-secret",
            "ENABLE_A2A": "false",
            "PLATFORM_CONFIG": str(REPO / "does-not-exist.yaml"),
        }
    )
    script = r"""
import json
import app
from aws_cdk.assertions import Template

wanted = ("runtime-orchestrator", "-gateway")
found = {}
for child in app.app.node.children:
    name = child.node.id
    if not any(part in name for part in wanted):
        continue
    template = Template.from_stack(child).to_json()
    for resource in template["Resources"].values():
        if resource["Type"] not in {
            "AWS::BedrockAgentCore::Runtime",
            "AWS::BedrockAgentCore::Gateway",
        }:
            continue
        props = resource["Properties"]
        found[resource["Type"]] = {
            "authorizer": props.get("AuthorizerConfiguration"),
            "allowed_clients": (props.get("EnvironmentVariables") or {}).get(
                "COGNITO_ALLOWED_CLIENTS"
            ),
        }
print(json.dumps(found))
"""
    completed = subprocess.run(
        [sys.executable, "-c", script],
        cwd=REPO,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    # app.synth writes a warning to stderr before the JSON line.
    found = json.loads(completed.stdout.strip().splitlines()[-1])
    runtime = found["AWS::BedrockAgentCore::Runtime"]
    gateway = found["AWS::BedrockAgentCore::Gateway"]
    assert runtime["allowed_clients"] == CLIENT
    assert _pins_caller(runtime["authorizer"], CLIENT)
    assert _pins_caller(gateway["authorizer"], CLIENT)


def _pins_caller(authorizer: dict, client: str) -> bool:
    jwt_auth = (authorizer or {}).get("CustomJWTAuthorizer") or {}
    if client not in (jwt_auth.get("AllowedAudience") or []):
        return False
    for claim in jwt_auth.get("CustomClaims") or []:
        if claim.get("InboundTokenClaimName") != "azp":
            continue
        match = claim.get("AuthorizingClaimMatchValue") or {}
        if match.get("ClaimMatchOperator") != "EQUALS":
            continue
        value = (match.get("ClaimMatchValue") or {}).get("MatchValueString")
        if value == client and claim.get("InboundTokenClaimValueType") == "STRING":
            return True
    return False


def _entra_access(azp: str, sub: str) -> dict:
    return {
        "iss": ENTRA_ISSUER,
        "aud": CLIENT,
        "azp": azp,
        "sub": sub,
        "ver": "2.0",
        "scp": "access_as_user",
    }


def _entra_identity(sub: str) -> dict:
    return {
        "iss": ENTRA_ISSUER,
        "aud": CLIENT,
        "sub": sub,
        "ver": "2.0",
        "nonce": "nonce-from-the-authorize-request",
        "tid": TENANT,
    }


def _timed(issuer: str, claims: dict) -> dict:
    now = int(time.time())
    body = dict(claims)
    # Signature test uses a local issuer so JWKS is fetched from this process.
    # The claim rules compare iss to the configured issuer and do not care
    # which host that string names.
    body["iss"] = issuer
    body.update(iat=now, nbf=now, exp=now + 600)
    return body


_PRIVATE_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_PUBLIC_JWK = json.loads(RSAAlgorithm.to_jwk(_PRIVATE_KEY.public_key()))
_PUBLIC_JWK.update({"kid": "test-key", "use": "sig", "alg": "RS256"})


def _sign(claims: dict) -> str:
    return jwt.encode(
        claims, _PRIVATE_KEY, algorithm="RS256", headers={"kid": "test-key"}
    )


class _JwksHandler(BaseHTTPRequestHandler):
    issuer = ""

    def do_GET(self):
        if self.path.rstrip("/").endswith("openid-configuration"):
            body = {"jwks_uri": f"{self.issuer}/keys"}
        elif self.path.split("?", 1)[0] == "/keys":
            body = {"keys": [_PUBLIC_JWK]}
        else:
            self.send_response(404)
            self.end_headers()
            return
        encoded = json.dumps(body).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def log_message(self, fmt: str, *args) -> None:
        return


class _SwappingHeaders(dict):
    """First Authorization read is the token under test. Later reads change it.

    A check that decodes the header once and a later read that decodes it
    again would authorize one token and act as the other.
    """

    def __init__(self, first: str, second: str | None):
        super().__init__(Authorization=first)
        self._second = second
        self._reads = 0

    def _value(self, key):
        if key != "Authorization":
            return super().get(key)
        self._reads += 1
        if self._reads == 1 or self._second is None:
            return super().__getitem__("Authorization")
        return self._second

    def get(self, key, default=None):
        value = self._value(key)
        return default if value is None else value

    def __getitem__(self, key):
        value = self._value(key)
        if value is None:
            raise KeyError(key)
        return value


def _context(token: str, swapped: str | None = None) -> RequestContext:
    context = RequestContext(request_headers={"Authorization": "placeholder"})
    # Assigned after validation so pydantic does not copy this into a plain dict.
    context.request_headers = _SwappingHeaders(
        f"Bearer {token}", None if swapped is None else f"Bearer {swapped}"
    )
    return context


_SERVER: ThreadingHTTPServer | None = None
_AUTH = None


def _issuer() -> str:
    global _SERVER
    if _SERVER is None:
        _SERVER = ThreadingHTTPServer(("127.0.0.1", 0), _JwksHandler)
        _JwksHandler.issuer = f"http://127.0.0.1:{_SERVER.server_port}"
        threading.Thread(target=_SERVER.serve_forever, daemon=True).start()
    return _JwksHandler.issuer


def _auth():
    global _AUTH
    if _AUTH is None:
        os.environ["COGNITO_ISSUER_URL"] = _issuer()
        os.environ["COGNITO_ALLOWED_CLIENTS"] = CLIENT
        import importlib

        from shared import auth

        _AUTH = importlib.reload(auth)
        _AUTH._jwks_client = None
    return _AUTH


@pytest.fixture(scope="module")
def issuer():
    return _issuer()
