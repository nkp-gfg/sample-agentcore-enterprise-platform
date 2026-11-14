#!/usr/bin/env python3
"""Loopback-only server for the local HR assistant UI.

Layer 3 of the HR plan. The facilitator runs this on their laptop. It serves
the static frontend under ``public/`` and one tiny ``GET /config.json``
endpoint that carries non-secret SSM-sourced URLs the browser needs to open
the Cognito hosted UI and to stream AG-UI events from the module 6 runtime.

This server deliberately has:

- no create / update / delete routes,
- no AWS proxy (the browser talks to AgentCore directly),
- no sign-in of its own (identity comes from the Cognito web client flow in
  the browser, through PKCE).

See ``custom-app-plan/phases.md`` § "Layer 3" and ``README.md`` for context.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import re
import sys
from dataclasses import asdict, dataclass
from http import HTTPStatus
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlsplit
from urllib.request import Request, urlopen

HERE = Path(__file__).resolve().parent
PUBLIC = HERE / "public"

REPO = HERE.parent
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

logger = logging.getLogger("hr-web")

LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})
DEFAULT_PORT = 8899

# The four SSM parameter *leaves* this server is allowed to read. Any attempt
# to serialize a value that was not loaded through one of these leaves is a
# bug: a secret in the parameter tree has no path into ``/config.json``.
SSM_PARAMETER_LEAVES = (
    "runtimes/orchestrator/arn",
    "auth/web-client-id",
    "auth/issuer-url",
    "gateway/url",
)

# A defensive second gate: the browser-facing config must only ever carry
# these field names. Adding a new field here is a conscious review step.
PUBLIC_CONFIG_FIELDS = frozenset(
    {
        "runtime_arn",
        "region",
        "web_client_id",
        "issuer_url",
        "gateway_url",
        "a2ui_protocol_version",
    }
)

RUNTIME_ARN_RE = re.compile(
    r"^arn:aws:bedrock-agentcore:([a-z]{2}(?:-[a-z]+)+-\d):\d{12}:runtime/.+$"
)
SESSION_ID_RE = re.compile(r"^[A-Za-z0-9_-]{33,128}$")
XRAY_TRACE_ID_RE = re.compile(r"^1-[0-9a-f]{8}-[0-9a-fA-F-]{24,36}$")
MAX_INVOKE_BODY_BYTES = 256 * 1024

# The A2UI wire protocol version this UI speaks. Pinned so a mismatched
# catalog or renderer is a visible, reviewable change — not a silent upgrade.
# Not an SSM value: it is a compile-time constant that the browser uses to
# refuse messages whose ``version`` field disagrees.
A2UI_PROTOCOL_VERSION = "1.0"


class ConfigError(RuntimeError):
    """A startup problem the facilitator must fix before the UI can work."""


class RequestRejected(ValueError):
    """A safe request error that can be returned to the browser."""

    def __init__(self, status: HTTPStatus, message: str):
        super().__init__(message)
        self.status = status
        self.message = message


@dataclass(frozen=True)
class PublicConfig:
    """Non-secret values the browser needs to talk to Cognito and AgentCore.

    Every field is a URL or an identifier that is already published to AWS
    endpoints the browser will contact. Nothing here is a password, a client
    secret, an IAM access key, or a user token.
    """

    runtime_arn: str
    region: str
    web_client_id: str
    issuer_url: str
    gateway_url: str
    a2ui_protocol_version: str

    def as_public_dict(self) -> dict[str, str]:
        """Serialize only the whitelisted fields, in a stable order."""
        raw = asdict(self)
        return {name: raw[name] for name in sorted(PUBLIC_CONFIG_FIELDS)}


def _project_and_env(
    *,
    project: str | None = None,
    environment: str | None = None,
) -> tuple[str, str]:
    """Resolve the SSM prefix pair from args, env, or ``platform.yaml``."""
    project = project or os.environ.get("PROJECT_NAME")
    environment = environment or os.environ.get("ENVIRONMENT")
    manifest = Path(os.environ.get("PLATFORM_CONFIG") or REPO / "platform.yaml")
    if (not project or not environment) and manifest.exists():
        try:
            from infra_utils.platform_config import load_platform_config
        except Exception as exc:
            raise ConfigError(
                "Could not load platform.yaml to resolve project/environment. "
                "Set PROJECT_NAME and ENVIRONMENT, or run from a repo checkout "
                f"with infra_utils available. ({exc})"
            ) from exc
        config = load_platform_config(manifest)
        project = project or config.project
        environment = environment or config.environment
    if not project or not environment:
        raise ConfigError(
            "Set PROJECT_NAME and ENVIRONMENT, or run from a repo with "
            "platform.yaml and infra_utils importable."
        )
    return project, environment


def _derive_region(runtime_arn: str) -> str:
    match = RUNTIME_ARN_RE.match(runtime_arn)
    if not match:
        raise ConfigError(
            f"Runtime ARN from SSM is not a valid AgentCore ARN: {runtime_arn!r}"
        )
    return match.group(1)


def load_config(
    *,
    project: str | None = None,
    environment: str | None = None,
    region: str | None = None,
    ssm_reader=None,
) -> PublicConfig:
    """Read the four non-secret SSM parameters and build the public config.

    ``ssm_reader`` is a callable ``(name) -> value`` used only in tests. The
    normal path uses boto3's ``ssm:GetParameter`` against the deployment
    region.
    """
    project, environment = _project_and_env(project=project, environment=environment)
    prefix = f"/{project}/{environment}"

    if ssm_reader is None:
        try:
            from scripts.utils import resolve_region
        except Exception as exc:
            raise ConfigError(
                "Could not import scripts/utils for region resolution. Run from "
                f"a checkout with scripts/ importable. ({exc})"
            ) from exc
        resolved_region = region or resolve_region()
        import boto3

        ssm_client = boto3.client("ssm", region_name=resolved_region)

        def _read(full_name: str) -> str:
            return ssm_client.get_parameter(Name=full_name)["Parameter"]["Value"]

        reader = _read
    else:
        reader = ssm_reader

    values: dict[str, str] = {}
    for leaf in SSM_PARAMETER_LEAVES:
        full = f"{prefix}/{leaf}"
        value = reader(full)
        if not isinstance(value, str) or not value:
            raise ConfigError(f"SSM parameter {full} is empty or not a string")
        values[leaf] = value

    runtime_arn = values["runtimes/orchestrator/arn"]
    derived_region = _derive_region(runtime_arn)
    return PublicConfig(
        runtime_arn=runtime_arn,
        region=derived_region,
        web_client_id=values["auth/web-client-id"],
        issuer_url=values["auth/issuer-url"],
        gateway_url=values["gateway/url"],
        a2ui_protocol_version=A2UI_PROTOCOL_VERSION,
    )


def _is_loopback_host(value: str, expected_port: int) -> bool:
    """A browser Host header that names this loopback server by explicit port.

    The socket is already bound to ``127.0.0.1``, so a non-loopback peer
    cannot even reach us; we still check the Host header so a CSRF-shaped
    attempt (a DNS-rebound domain that resolves to 127.0.0.1) is refused.
    """
    if not value:
        return False
    try:
        parsed = urlsplit(f"//{value}")
    except ValueError:
        return False
    return (
        parsed.hostname in LOOPBACK_HOSTS
        and parsed.port == expected_port
        and not parsed.username
        and not parsed.password
        and not parsed.path
        and not parsed.query
        and not parsed.fragment
    )


class HrWebHandler(SimpleHTTPRequestHandler):
    """Static ``public/`` + a single ``GET /config.json`` endpoint."""

    server_version = "AgentCoreHrWeb/1"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(PUBLIC), **kwargs)

    # Every write verb is refused. The server reads SSM once at boot and never
    # changes state afterwards, so GET + HEAD are the full surface.
    def do_POST(self) -> None:
        path_only = self.path.split("?", 1)[0]
        if path_only == "/invocations":
            self._forward_invocations()
            return
        self._reject_mutation("POST")

    def do_PUT(self) -> None:
        self._reject_mutation("PUT")

    def do_DELETE(self) -> None:
        self._reject_mutation("DELETE")

    def do_PATCH(self) -> None:
        self._reject_mutation("PATCH")

    def _forward_invocations(self) -> None:
        """Same-origin loopback SSE passthrough to AgentCore Runtime.

        Forwards ONLY the browser's Cognito Bearer JWT (zero server-side AWS
        credentials) so browser fetch() is never blocked by cross-origin CORS
        preflight on `bedrock-agentcore.<region>.amazonaws.com`.
        """
        try:
            self._require_loopback_host()
            origin = self.headers.get("Origin", "").strip()
            if origin:
                parsed_origin = urlsplit(origin)
                host_header = self.headers.get("Host", "").strip()
                if (
                    parsed_origin.scheme != "http"
                    or parsed_origin.hostname not in LOOPBACK_HOSTS
                    or parsed_origin.port != self.server.server_port
                    or parsed_origin.netloc.lower() != host_header.lower()
                ):
                    raise RequestRejected(
                        HTTPStatus.FORBIDDEN, "Same-origin loopback Origin required."
                    )

            auth_header = self.headers.get("Authorization", "").strip()
            if not auth_header.lower().startswith("bearer ") or len(auth_header) < 16:
                raise RequestRejected(
                    HTTPStatus.UNAUTHORIZED, "Bearer access token required."
                )

            session_id = self.headers.get(
                "X-Amzn-Bedrock-AgentCore-Runtime-Session-Id", ""
            ).strip()
            if not SESSION_ID_RE.match(session_id):
                raise RequestRejected(
                    HTTPStatus.BAD_REQUEST,
                    "Valid X-Amzn-Bedrock-AgentCore-Runtime-Session-Id (33-128 chars) required.",
                )

            try:
                content_length = int(self.headers.get("Content-Length", "0"))
            except ValueError as exc:
                raise RequestRejected(
                    HTTPStatus.BAD_REQUEST, "Invalid Content-Length."
                ) from exc
            if content_length <= 0 or content_length > MAX_INVOKE_BODY_BYTES:
                raise RequestRejected(
                    HTTPStatus.BAD_REQUEST, "Request body out of bounds."
                )
            raw_body = self.rfile.read(content_length)

            config: PublicConfig | None = getattr(self.server, "public_config", None)
            if config is None:
                raise RequestRejected(
                    HTTPStatus.SERVICE_UNAVAILABLE,
                    "Server configuration is not loaded.",
                )

            upstream_url = (
                f"https://bedrock-agentcore.{config.region}.amazonaws.com/runtimes/"
                f"{quote(config.runtime_arn, safe='')}/invocations?qualifier=DEFAULT"
            )
            upstream_headers = {
                "Authorization": auth_header,
                "Content-Type": "application/json",
                "Accept": "text/event-stream",
                "X-Amzn-Bedrock-AgentCore-Runtime-Session-Id": session_id,
            }
            trace_id = self.headers.get("X-Amzn-Trace-Id", "").strip()
            if trace_id and XRAY_TRACE_ID_RE.match(trace_id):
                upstream_headers["X-Amzn-Trace-Id"] = trace_id

            upstream_req = Request(
                upstream_url,
                data=raw_body,
                headers=upstream_headers,
                method="POST",
            )
            try:
                with urlopen(upstream_req, timeout=180) as upstream:  # nosec B310 — https
                    self.send_response(HTTPStatus.OK)
                    self.send_header(
                        "Content-Type",
                        upstream.headers.get("Content-Type", "text/event-stream"),
                    )
                    self.send_header("Cache-Control", "no-store")
                    self.end_headers()
                    read_chunk = getattr(upstream, "read1", upstream.read)
                    while True:
                        chunk = read_chunk(4096)
                        if not chunk:
                            break
                        self.wfile.write(chunk)
                        self.wfile.flush()
            except HTTPError as exc:
                self._send_json(
                    HTTPStatus(exc.code)
                    if exc.code in HTTPStatus._value2member_map_
                    else HTTPStatus.BAD_GATEWAY,
                    {"error": f"Runtime returned HTTP {exc.code}."},
                )
            except URLError as exc:
                self._send_json(
                    HTTPStatus.BAD_GATEWAY,
                    {"error": f"Could not reach AgentCore runtime: {exc.reason}"},
                )
        except RequestRejected as exc:
            self._send_json(exc.status, {"error": exc.message})

    def _reject_mutation(self, method: str) -> None:
        try:
            self._require_loopback_host()
        except RequestRejected as exc:
            self._send_json(exc.status, {"error": exc.message})
            return
        # 405 with no Allow for write verbs: the server has no mutations.
        self._send_json(
            HTTPStatus.METHOD_NOT_ALLOWED,
            {"error": f"{method} is not supported on this server."},
        )

    def _connect_src_origins(self) -> str:
        """Build valid W3C CSP `connect-src` origins for the configured deployment.

        W3C CSP host-source wildcards (`*`) are only valid as the leftmost
        label (`https://*.amazoncognito.com`), NEVER mid-hostname
        (`https://cognito-idp.*.amazonaws.com` is rejected by Chrome/Safari
        and blocks OIDC discovery on Sign in). Derive the exact regional
        origins from `PublicConfig` instead.
        """
        origins: list[str] = ["'self'", "https://*.amazoncognito.com"]
        config: PublicConfig | None = getattr(self.server, "public_config", None)
        if config is not None:
            parsed_issuer = urlsplit(config.issuer_url)
            if parsed_issuer.scheme == "https" and parsed_issuer.netloc:
                issuer_origin = f"https://{parsed_issuer.netloc}"
                if issuer_origin not in origins:
                    origins.append(issuer_origin)
            for regional_host in (
                f"https://cognito-idp.{config.region}.amazonaws.com",
                f"https://bedrock-agentcore.{config.region}.amazonaws.com",
            ):
                if regional_host not in origins:
                    origins.append(regional_host)
        origins.append("https://login.microsoftonline.com")
        return " ".join(origins)

    def end_headers(self) -> None:
        # Hardening headers mirror ``dashboard/server.py`` so a review covers
        # both loopback consoles the same way. ``connect-src`` allows exact
        # regional Cognito/AgentCore origins plus Cognito hosted-UI domains.
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; img-src 'self' data:; "
            "style-src 'self' 'unsafe-inline'; script-src 'self'; "
            f"connect-src {self._connect_src_origins()}; "
            "base-uri 'none'; frame-ancestors 'none'; form-action 'none'",
        )
        if self.path.startswith("/config.json"):
            self.send_header("Cache-Control", "no-store")
        super().end_headers()

    def _require_loopback_host(self) -> None:
        if not _is_loopback_host(
            self.headers.get("Host", ""),
            self.server.server_port,
        ):
            raise RequestRejected(HTTPStatus.FORBIDDEN, "Loopback host required.")

    def _send_json(self, status: HTTPStatus, value: dict) -> None:
        body = json.dumps(value, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        try:
            self._require_loopback_host()
            path_only = self.path.split("?", 1)[0]
            if path_only == "/config.json":
                config = getattr(self.server, "public_config", None)
                if config is None:
                    raise RequestRejected(
                        HTTPStatus.SERVICE_UNAVAILABLE,
                        "Server configuration is not loaded.",
                    )
                self._send_json(HTTPStatus.OK, config.as_public_dict())
                return
            super().do_GET()
        except RequestRejected as exc:
            self._send_json(exc.status, {"error": exc.message})

    def log_message(self, fmt: str, *args) -> None:
        logger.info("%s - %s", self.client_address[0], fmt % args)


class HrWebServer(ThreadingHTTPServer):
    """Threaded HTTP server that carries one frozen ``PublicConfig``."""

    def __init__(
        self,
        server_address: tuple[str, int],
        handler_class,
        public_config: PublicConfig,
    ):
        super().__init__(server_address, handler_class)
        self.public_config = public_config


def make_server(
    public_config: PublicConfig,
    *,
    host: str = "127.0.0.1",
    port: int = DEFAULT_PORT,
) -> HrWebServer:
    """Factory used by ``main`` and by the boundary tests."""
    if host not in LOOPBACK_HOSTS:
        raise ConfigError(
            f"hr-web refuses to bind non-loopback host {host!r}. This is a "
            "facilitator-operated UI; hosting it is out of scope."
        )
    return HrWebServer((host, port), HrWebHandler, public_config)


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the local HR assistant UI")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument(
        "--project",
        default=None,
        help="Project name (default: PROJECT_NAME or platform.yaml)",
    )
    parser.add_argument(
        "--environment",
        default=None,
        help="Environment name (default: ENVIRONMENT or platform.yaml)",
    )
    parser.add_argument(
        "--region",
        default=None,
        help="AWS region for SSM lookup (default: AWS_REGION or platform.yaml)",
    )
    args = parser.parse_args()
    if not 1 <= args.port <= 65535:
        parser.error("--port must be between 1 and 65535")

    logging.basicConfig(level=logging.INFO, format="%(message)s")

    try:
        config = load_config(
            project=args.project,
            environment=args.environment,
            region=args.region,
        )
    except ConfigError as exc:
        print(f"hr-web could not start: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc

    server = make_server(config, port=args.port)
    print(f"hr-web UI: http://127.0.0.1:{args.port}")
    print("Facilitator access only. Press Ctrl+C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
