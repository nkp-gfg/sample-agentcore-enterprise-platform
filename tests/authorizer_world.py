"""Stand-in for the AgentCore control plane and the gateway MCP endpoint.

The shapes this module returns are the botocore 1.43.72 service model
``bedrock-agentcore-control/2023-06-05`` (the floor pinned in requirements.txt):

* ``GetGateway`` output carries ``authorizerConfiguration.customJWTAuthorizer``
  with ``discoveryUrl``, ``allowedClients``, and ``allowedAudience``.
  ``ListGateways`` items do not carry the authorizer configuration or the URL.
* ``GetAgentRuntime`` output carries the same ``authorizerConfiguration``.
  ``ListAgentRuntimes`` items do not.
* ``UpdateGateway`` accepts that same authorizer structure, so a caller who
  can update the gateway can change the live allow-list without writing SSM.

Token acceptance on the MCP URL follows the control-plane fields the service
model documents, applied to the claims named by the AgentCore gateway inbound
auth guide: ``allowedClients`` against ``client_id``, ``allowedAudience``
against ``aud``. A list that is present is a constraint. The discovery URL is
fetched the same way ``scripts/utils.py`` fetches OpenID configuration, and
the token ``iss`` must equal that document's ``issuer``.
"""

from __future__ import annotations

import base64
import io
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from urllib.error import HTTPError

import boto3

# GatewayIdentifier: ([0-9a-z][-]?){1,100}-[0-9a-z]{10}
LIVE_GATEWAY_ID = "sample-gateway-abcd123456"
DECOY_GATEWAY_ID = "other-gateway-zzzz999999"
# AgentRuntimeId: [a-zA-Z][a-zA-Z0-9_]{0,99}-[a-zA-Z0-9]{10}
ORCHESTRATOR_RUNTIME_ID = "orchestrator-AbCdEf1234"

PROJECT = "agentcore-workshop"
ENV = "dev"
REGION = "us-east-1"
ACCOUNT = "111122223333"
POOL_ID = "us-east-1_AbCdEfGhI"
APP_CLIENT = "designed-app-client"
M2M_CLIENT = "designed-m2m-client"
WEB_CLIENT = "designed-web-client"
ATTACKER_CLIENT = "attacker-added-client"
ATTACKER_AUDIENCE = "attacker-added-audience"
SECRET_NAME = "placeholder/m2m-client-secret"
SECRET_VALUE = "placeholder-client-secret"
BROKERED_ISSUER = f"https://cognito-idp.{REGION}.amazonaws.com/{POOL_ID}"
DIRECT_TENANT = "11111111-2222-3333-4444-555555555555"
DIRECT_ISSUER = f"https://login.microsoftonline.com/{DIRECT_TENANT}/v2.0"
ATTACKER_ISSUER = "https://attacker.example/v2.0"
STATE_ENV = "AUTHORIZER_WORLD_STATE"


def discovery_url(issuer: str) -> str:
    """Same derivation as infra_utils/jwt_authorizer.py custom_jwt_authorizer."""
    return f"{issuer.rstrip('/')}/.well-known/openid-configuration"


def _b64(data: dict) -> str:
    raw = base64.urlsafe_b64encode(json.dumps(data).encode()).rstrip(b"=")
    return raw.decode()


def mint_token(claims: dict) -> str:
    """Unsigned JWT whose payload ``check_identity.claims`` can decode.

    The value is a fixture claim set, not a credential.
    """
    return f"{_b64({'alg': 'none', 'typ': 'JWT'})}.{_b64(claims)}."


def decode_token(token: str) -> dict:
    payload = token.split(".")[1]
    pad = "=" * (-len(payload) % 4)
    return json.loads(base64.urlsafe_b64decode(payload + pad))


class AuthorizerWorld:
    """One deployment's SSM interface plus the live gateway and runtime."""

    def __init__(
        self,
        *,
        mode: str = "brokered",
        gateway_divergence: str | None = None,
        runtime_divergence: str | None = None,
        include_runtime: bool = False,
        open_enforcement: bool = False,
        diverge_for_scripts: tuple[str, ...] = (),
    ) -> None:
        self.mode = mode
        self.gateway_divergence = gateway_divergence
        self.runtime_divergence = runtime_divergence
        self.include_runtime = include_runtime
        # When set, GetGateway/GetAgentRuntime stay on the design authorizer
        # unless the running script's file name is in this tuple. The MCP
        # endpoint uses the same switch, so the gateway script sees the
        # widened allow-list the identity script did not.
        self.diverge_for_scripts = diverge_for_scripts
        self.open_enforcement = open_enforcement
        self.get_gateway_ids: list[str] = []
        self.get_runtime_ids: list[str] = []
        self.http_exchanges: list[dict] = []
        self._installed = False
        self._orig_client = None
        self._orig_urlopen = None
        self._orig_post = None

    @property
    def issuer(self) -> str:
        return DIRECT_ISSUER if self.mode == "direct" else BROKERED_ISSUER

    @property
    def live_gateway_url(self) -> str:
        return (
            f"https://{LIVE_GATEWAY_ID}.gateway.bedrock-agentcore."
            f"{REGION}.amazonaws.com/mcp"
        )

    @property
    def decoy_gateway_url(self) -> str:
        return (
            f"https://{DECOY_GATEWAY_ID}.gateway.bedrock-agentcore."
            f"{REGION}.amazonaws.com/mcp"
        )

    def design_authorizer(self) -> dict:
        """The authorizer app.py passes into the gateway and the orchestrator.

        Brokered: app client and M2M client, no audience. Direct: audience is
        the app client id, no client list.
        """
        jwt = {"discoveryUrl": discovery_url(self.issuer)}
        if self.mode == "direct":
            jwt["allowedAudience"] = [APP_CLIENT]
        else:
            jwt["allowedClients"] = [APP_CLIENT, M2M_CLIENT]
        return {"customJWTAuthorizer": jwt}

    def _divergent(self, kind: str | None) -> dict:
        auth = json.loads(json.dumps(self.design_authorizer()))
        jwt = auth["customJWTAuthorizer"]
        if kind == "client":
            clients = list(jwt.get("allowedClients") or [])
            clients.append(ATTACKER_CLIENT)
            jwt["allowedClients"] = clients
        elif kind == "audience":
            audience = list(jwt.get("allowedAudience") or [])
            audience.append(ATTACKER_AUDIENCE)
            jwt["allowedAudience"] = audience
        elif kind == "discovery":
            jwt["discoveryUrl"] = discovery_url(ATTACKER_ISSUER)
        elif kind == "direct-client":
            # Direct design pins audience only. An added client list is not
            # the design, even when the original audience is still present.
            jwt["allowedClients"] = [ATTACKER_CLIENT]
        elif kind:
            raise ValueError(kind)
        return auth

    def _script_name(self) -> str:
        import sys

        return Path(sys.argv[0]).name if sys.argv else ""

    def _gateway_authorizer(self) -> dict:
        kind = self.gateway_divergence
        if kind and self.diverge_for_scripts:
            if self._script_name() not in self.diverge_for_scripts:
                kind = None
        return self._divergent(kind)

    def _runtime_authorizer(self) -> dict:
        kind = self.runtime_divergence
        if kind and self.diverge_for_scripts:
            if self._script_name() not in self.diverge_for_scripts:
                kind = None
        return self._divergent(kind)

    def ssm_parameters(self) -> dict[str, str]:
        prefix = f"/{PROJECT}/{ENV}"
        params = {
            f"{prefix}/auth/mode": self.mode,
            f"{prefix}/auth/issuer-url": self.issuer,
            f"{prefix}/auth/app-client-id": APP_CLIENT,
            f"{prefix}/auth/web-client-id": WEB_CLIENT,
            f"{prefix}/auth/m2m-client-id": M2M_CLIENT,
            f"{prefix}/auth/m2m-client-secret-name": SECRET_NAME,
            f"{prefix}/auth/m2m-scope": (
                f"{APP_CLIENT}/.default" if self.mode == "direct" else "agentcore/invoke"
            ),
            f"{prefix}/auth/user-pool-id": POOL_ID,
            f"{prefix}/gateway/url": self.live_gateway_url,
            f"{prefix}/use-cases/hello-platform/gateway-seen": (
                f"hello: {self.live_gateway_url}"
            ),
        }
        if self.include_runtime:
            params[f"{prefix}/runtimes/orchestrator/id"] = ORCHESTRATOR_RUNTIME_ID
        return params

    def designed_claims(self) -> dict:
        if self.mode == "direct":
            return {"iss": self.issuer, "aud": APP_CLIENT, "sub": "machine"}
        return {
            "iss": self.issuer,
            "client_id": M2M_CLIENT,
            "sub": "machine",
            "scope": "agentcore/invoke",
        }

    def designed_token(self) -> str:
        return mint_token(self.designed_claims())

    def issuer_for_discovery(self, url: str) -> str:
        if url == discovery_url(ATTACKER_ISSUER):
            return ATTACKER_ISSUER
        if url == discovery_url(self.issuer):
            return self.issuer
        raise AssertionError(f"discovery URL is not one this deployment publishes: {url}")

    def gateway_response(self, gateway_id: str) -> dict:
        self.get_gateway_ids.append(gateway_id)
        if gateway_id == LIVE_GATEWAY_ID:
            url = self.live_gateway_url
            authorizer = self._gateway_authorizer()
            name = "sample-gateway"
        elif gateway_id == DECOY_GATEWAY_ID:
            url = self.decoy_gateway_url
            authorizer = self.design_authorizer()
            name = "other-gateway"
        else:
            raise KeyError(gateway_id)
        now = datetime.now(timezone.utc)
        return {
            "gatewayArn": (
                f"arn:aws:bedrock-agentcore:{REGION}:{ACCOUNT}:gateway/{gateway_id}"
            ),
            "gatewayId": gateway_id,
            "gatewayUrl": url,
            "createdAt": now,
            "updatedAt": now,
            "status": "READY",
            "name": name,
            "roleArn": f"arn:aws:iam::{ACCOUNT}:role/gateway",
            "protocolType": "MCP",
            "authorizerType": "CUSTOM_JWT",
            "authorizerConfiguration": authorizer,
        }

    def runtime_response(self, runtime_id: str) -> dict:
        self.get_runtime_ids.append(runtime_id)
        if runtime_id != ORCHESTRATOR_RUNTIME_ID:
            raise KeyError(runtime_id)
        now = datetime.now(timezone.utc)
        return {
            "agentRuntimeArn": (
                f"arn:aws:bedrock-agentcore:{REGION}:{ACCOUNT}:runtime/{runtime_id}"
            ),
            "agentRuntimeName": "orchestrator",
            "agentRuntimeId": runtime_id,
            "agentRuntimeVersion": "1",
            "createdAt": now,
            "lastUpdatedAt": now,
            "roleArn": f"arn:aws:iam::{ACCOUNT}:role/runtime",
            "status": "READY",
            "lifecycleConfiguration": {},
            "authorizerConfiguration": self._runtime_authorizer(),
        }

    def _client(self, service_name, region_name=None, **kwargs):
        world = self
        if service_name == "ssm":
            return _Ssm(world)
        if service_name == "secretsmanager":
            return _Secrets()
        if service_name == "sts":
            return _Sts()
        if service_name == "cognito-idp":
            return _Cognito()
        if service_name == "bedrock-agentcore-control":
            return _Control(world)
        raise AssertionError(f"unexpected AWS client {service_name}")

    def install(self) -> None:
        import requests
        import urllib.request

        if self._installed:
            return
        self._orig_client = boto3.client
        self._orig_urlopen = urllib.request.urlopen
        self._orig_post = requests.post
        boto3.client = self._client
        urllib.request.urlopen = self._urlopen
        requests.post = self._post
        self._installed = True

    def restore(self) -> None:
        import requests
        import urllib.request

        if not self._installed:
            return
        boto3.client = self._orig_client
        urllib.request.urlopen = self._orig_urlopen
        requests.post = self._orig_post
        self._installed = False

    def _urlopen(self, req, timeout=None, **kwargs):
        url = req if isinstance(req, str) else req.full_url
        if url.endswith("/.well-known/openid-configuration"):
            issuer = self.issuer_for_discovery(url)
            body = {
                "issuer": issuer,
                "token_endpoint": f"{issuer}/oauth2/token",
                "jwks_uri": f"{issuer}/jwks",
            }
            return io.BytesIO(json.dumps(body).encode())
        if url.endswith("/oauth2/token"):
            return io.BytesIO(
                json.dumps({"access_token": self.designed_token()}).encode()
            )
        # Gateway calls made with urllib (invoke.py list_tools) hit the same
        # endpoint the requests stand-in enforces.
        if url.split("?", 1)[0] in {self.live_gateway_url, self.decoy_gateway_url}:
            header = req.headers.get("Authorization") or req.headers.get("authorization")
            token = ""
            if header and header.startswith("Bearer "):
                token = header[len("Bearer ") :]
            status, payload = self._decide(url, token)
            raw = json.dumps(payload).encode()
            if status != 200:
                raise HTTPError(url, status, "unauthorized", hdrs=None, fp=io.BytesIO(raw))
            return io.BytesIO(raw)
        raise AssertionError(f"unexpected URL opened: {url}")

    def _post(self, url, json=None, headers=None, timeout=None, **kwargs):
        token = ""
        header = (headers or {}).get("Authorization", "")
        if header.startswith("Bearer "):
            token = header[len("Bearer ") :]
        status, payload = self._decide(url, token)
        return _Response(status, payload)

    def _decide(self, url: str, token: str) -> tuple[int, dict]:
        gateway_id = LIVE_GATEWAY_ID if url.split("?", 1)[0] == self.live_gateway_url else None
        if url.split("?", 1)[0] == self.decoy_gateway_url:
            gateway_id = DECOY_GATEWAY_ID
        if gateway_id is None:
            raise AssertionError(f"POST is not a gateway this deployment published: {url}")
        authorizer = (
            self._gateway_authorizer()
            if gateway_id == LIVE_GATEWAY_ID
            else self.design_authorizer()
        )
        accepted = self._accepts(token, authorizer)
        claims = {}
        if token:
            try:
                claims = decode_token(token)
            except Exception:  # noqa: BLE001 — a probe may be malformed
                claims = {}
        status = 200 if accepted else 401
        self.http_exchanges.append(
            {
                "url": url,
                "gateway_id": gateway_id,
                "claims": claims,
                "status": status,
                "outside_design": self.outside_design(claims) if claims else False,
            }
        )
        if not accepted:
            return 401, {"message": "unauthorized"}
        return 200, {
            "jsonrpc": "2.0",
            "id": "tools/list",
            "result": {"tools": [{"name": "sample-tool___text_analysis_tool"}]},
        }

    def outside_design(self, claims: dict) -> bool:
        """True when this token is not one the design authorizer names."""
        if self.mode == "direct":
            aud = claims.get("aud")
            if isinstance(aud, list):
                aud = aud[0] if aud else None
            return aud != APP_CLIENT
        return claims.get("client_id") not in {APP_CLIENT, M2M_CLIENT}

    def _accepts(self, token: str, authorizer: dict) -> bool:
        try:
            claims = decode_token(token)
        except Exception:  # noqa: BLE001
            return False
        jwt = authorizer["customJWTAuthorizer"]
        issuer = self.issuer_for_discovery(jwt["discoveryUrl"])
        if self.open_enforcement and not self.diverge_for_scripts:
            # The endpoint used for the call is not enforcing the allow-list
            # GetGateway returned. Any token from the discovery issuer is
            # accepted, including a client the design does not name.
            return claims.get("iss") == issuer
        if claims.get("iss") != issuer:
            return False
        clients = jwt.get("allowedClients")
        audience = jwt.get("allowedAudience")
        if not clients and not audience:
            return False
        if clients and claims.get("client_id") not in clients:
            return False
        if audience:
            aud = claims.get("aud")
            auds = aud if isinstance(aud, list) else [aud]
            if not any(item in audience for item in auds):
                return False
        return True

    def rejected_outside_probe(self) -> bool:
        return any(
            item["outside_design"] and item["status"] != 200
            for item in self.http_exchanges
        )

    def accepted_outside_probe(self) -> bool:
        return any(
            item["outside_design"] and item["status"] == 200
            for item in self.http_exchanges
        )

    def saw_live_gateway(self) -> bool:
        return LIVE_GATEWAY_ID in self.get_gateway_ids


class _Response:
    def __init__(self, status_code: int, payload: dict) -> None:
        self.status_code = status_code
        self._payload = payload
        self.text = json.dumps(payload)

    def json(self) -> dict:
        return self._payload


class _Ssm:
    def __init__(self, world: AuthorizerWorld) -> None:
        self._world = world
        self.exceptions = SimpleNamespace(ParameterNotFound=ParameterNotFound)

    def get_parameter(self, Name, WithDecryption=False):
        try:
            value = self._world.ssm_parameters()[Name]
        except KeyError as exc:
            raise ParameterNotFound(Name) from exc
        return {"Parameter": {"Value": value}}


class ParameterNotFound(Exception):
    pass


class _Secrets:
    def get_secret_value(self, SecretId):
        assert SecretId == SECRET_NAME
        return {"SecretString": SECRET_VALUE}


class _Sts:
    def get_caller_identity(self):
        return {"Account": ACCOUNT}


class _Cognito:
    def describe_user_pool_client(self, UserPoolId, ClientId):
        raise AssertionError("secret name is published; DescribeUserPoolClient is unused")


class _Control:
    def __init__(self, world: AuthorizerWorld) -> None:
        self._world = world

    def get_gateway(self, **kwargs):
        gateway_id = kwargs.get("gatewayIdentifier") or kwargs.get("GatewayIdentifier")
        return self._world.gateway_response(gateway_id)

    def list_gateways(self, **kwargs):
        if kwargs.get("nextToken"):
            return {"items": []}
        now = datetime.now(timezone.utc)
        # Decoy first. A check that reads only the first summary, or only the
        # first GetGateway, is not looking at the gateway SSM gateway/url names.
        items = []
        for gateway_id, name in (
            (DECOY_GATEWAY_ID, "other-gateway"),
            (LIVE_GATEWAY_ID, "sample-gateway"),
        ):
            items.append(
                {
                    "gatewayId": gateway_id,
                    "name": name,
                    "status": "READY",
                    "createdAt": now,
                    "updatedAt": now,
                    "authorizerType": "CUSTOM_JWT",
                    "protocolType": "MCP",
                }
            )
        return {"items": items}

    def list_agent_runtimes(self, **kwargs):
        if kwargs.get("nextToken") or not self._world.include_runtime:
            return {"agentRuntimes": []}
        now = datetime.now(timezone.utc)
        return {
            "agentRuntimes": [
                {
                    "agentRuntimeArn": (
                        f"arn:aws:bedrock-agentcore:{REGION}:{ACCOUNT}:"
                        f"runtime/{ORCHESTRATOR_RUNTIME_ID}"
                    ),
                    "agentRuntimeId": ORCHESTRATOR_RUNTIME_ID,
                    "agentRuntimeVersion": "1",
                    "agentRuntimeName": "orchestrator",
                    "description": "",
                    "lastUpdatedAt": now,
                    "status": "READY",
                }
            ]
        }

    def get_agent_runtime(self, **kwargs):
        runtime_id = kwargs.get("agentRuntimeId") or kwargs.get("AgentRuntimeId")
        return self._world.runtime_response(runtime_id)


def dump(world: AuthorizerWorld, path: Path) -> None:
    path.write_text(
        json.dumps(
            {
                "mode": world.mode,
                "gateway_divergence": world.gateway_divergence,
                "runtime_divergence": world.runtime_divergence,
                "include_runtime": world.include_runtime,
                "open_enforcement": world.open_enforcement,
                "diverge_for_scripts": list(world.diverge_for_scripts),
            }
        )
    )


def load(path: Path) -> AuthorizerWorld:
    data = json.loads(path.read_text())
    return AuthorizerWorld(
        mode=data["mode"],
        gateway_divergence=data["gateway_divergence"],
        runtime_divergence=data["runtime_divergence"],
        include_runtime=data["include_runtime"],
        open_enforcement=data["open_enforcement"],
        diverge_for_scripts=tuple(data["diverge_for_scripts"]),
    )


def install_from_env() -> None:
    path = os.environ.get(STATE_ENV)
    if not path:
        return
    world = load(Path(path))
    world.install()
    # Child process: keep the installed patches for the life of the script.
    _KEEP.append(world)


_KEEP: list[AuthorizerWorld] = []
