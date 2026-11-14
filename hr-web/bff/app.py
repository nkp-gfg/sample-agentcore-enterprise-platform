"""FastAPI Backend-for-Frontend (BFF) for hr-web on ECS Fargate.

Security & resilience properties:
  1. Keeps OAuth tokens strictly on the server (DynamoDB-backed); the browser
     receives only an opaque ``HttpOnly; SameSite=Lax`` session cookie plus a
     per-session CSRF token (``X-BFF-CSRF``).
  2. Stores both PKCE login states and user chat transcripts in DynamoDB so
     horizontal scale-out and ECS task restarts never break sign-in or drop
     chat history.
  3. Invokes Amazon Bedrock AgentCore Runtime server-to-server over HTTPS (via
     the VPC interface endpoint when running in VPC private subnets) and streams
     SSE chunks incrementally to the browser with zero buffering.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import time
from collections.abc import AsyncIterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlencode, urlsplit

import boto3
import httpx
import jwt
from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import (
    FileResponse,
    JSONResponse,
    RedirectResponse,
    StreamingResponse,
)

from bff.session_store import DynamoSessionStore

logger = logging.getLogger("hr-web-bff")

HERE = Path(__file__).resolve().parent
PUBLIC_DIR = HERE.parent / "public"
A2UI_PROTOCOL_VERSION = "1.0"
SESSION_COOKIE_NAME = "hr_bff_sid"
SESSION_ID_RE = re.compile(r"^[A-Za-z0-9_-]{33,128}$")
THREAD_ID_RE = re.compile(r"^[A-Za-z0-9_-]{8,128}$")
XRAY_TRACE_ID_RE = re.compile(r"^1-[0-9a-f]{8}-[0-9a-fA-F-]{24,36}$")
REGION_RE = re.compile(r"^[a-z]{2}(?:-[a-z]+)+-\d$")
RUNTIME_ARN_RE = re.compile(
    r"^arn:aws:bedrock-agentcore:([a-z]{2}(?:-[a-z]+)+-\d):\d{12}:runtime/.+$"
)
MAX_INVOKE_BODY_BYTES = 256 * 1024
TOKEN_REFRESH_SKEW_SECONDS = 60

STATIC_ASSETS: dict[str, tuple[str, str]] = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/index.html": ("index.html", "text/html; charset=utf-8"),
    "/styles.css": ("styles.css", "text/css; charset=utf-8"),
    "/a2ui.js": ("a2ui.js", "application/javascript; charset=utf-8"),
    "/hr-primitives.js": ("hr-primitives.js", "application/javascript; charset=utf-8"),
    "/hr-tool-adapter.js": (
        "hr-tool-adapter.js",
        "application/javascript; charset=utf-8",
    ),
    "/enterprise-catalog.js": (
        "enterprise-catalog.js",
        "application/javascript; charset=utf-8",
    ),
    "/app.js": ("app.js", "application/javascript; charset=utf-8"),
    "/hr-catalog.json": ("hr-catalog.json", "application/json; charset=utf-8"),
    "/favicon.svg": ("favicon.svg", "image/svg+xml"),
}


@dataclass(frozen=True)
class BffSettings:
    region: str
    ssm_prefix: str
    oidc_issuer_url: str
    oidc_client_id: str
    oidc_client_secret: str
    oidc_redirect_uri: str
    oidc_logout_uri: str
    oidc_scope: str
    bff_session_table: str
    chat_session_table: str
    exposure: str
    cookie_secure: bool
    session_ttl_hours: int
    runtime_arn_override: str = ""

    @classmethod
    def from_env(cls) -> BffSettings:
        region = (
            os.environ.get("AWS_REGION_NAME")
            or os.environ.get("AWS_REGION")
            or "us-east-1"
        )
        if not REGION_RE.match(region):
            raise RuntimeError(f"Invalid AWS region configured: {region!r}")
        project = os.environ.get("PROJECT_NAME", "")
        env = os.environ.get("ENVIRONMENT", "")
        ssm_prefix = os.environ.get("BFF_SSM_PREFIX") or (
            f"/{project}/{env}" if project and env else ""
        )
        return cls(
            region=region,
            ssm_prefix=ssm_prefix,
            oidc_issuer_url=os.environ.get("OIDC_ISSUER_URL", "").rstrip("/"),
            oidc_client_id=os.environ.get("OIDC_CLIENT_ID", ""),
            oidc_client_secret=os.environ.get("OIDC_CLIENT_SECRET", ""),
            oidc_redirect_uri=os.environ.get("OIDC_REDIRECT_URI", ""),
            oidc_logout_uri=os.environ.get("OIDC_LOGOUT_URI", ""),
            oidc_scope=os.environ.get("OIDC_SCOPE", "openid email profile"),
            bff_session_table=os.environ.get("BFF_SESSION_TABLE", ""),
            chat_session_table=os.environ.get("CHAT_SESSION_TABLE", ""),
            exposure=os.environ.get("FRONTEND_EXPOSURE", "private"),
            cookie_secure=os.environ.get("COOKIE_SECURE", "true").lower() == "true",
            session_ttl_hours=int(os.environ.get("SESSION_TTL_HOURS", "12")),
            runtime_arn_override=os.environ.get("RUNTIME_ARN", ""),
        )


def _pkce_challenge(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def _assert_https_url(url: str, label: str) -> str:
    parsed = urlsplit(url)
    if parsed.scheme != "https" or not parsed.netloc:
        raise HTTPException(status_code=502, detail=f"Invalid {label} URL.")
    return url


def _summarize_tool_result(tool_name: str, result: Any) -> str:
    if not isinstance(result, dict):
        return "Completed"
    if result.get("authorized") is False:
        return f"Denied · {result.get('reason_code') or 'NOT_AUTHORIZED'}"
    bare = tool_name.split("___")[-1] if "___" in tool_name else tool_name
    d = result.get("data") or {}
    if bare == "get_leave_balance":
        return f"Annual {d.get('annual', '—')}d · Sick {d.get('sick', '—')}d"
    if bare == "get_allowance":
        amt = d.get("amount")
        return "No entry" if amt is None else f"{amt} {d.get('currency', '')}".strip()
    if bare == "list_direct_reports":
        cnt = len(d.get("reports") or []) if isinstance(d.get("reports"), list) else 0
        return f"{cnt} direct report{'' if cnt == 1 else 's'}"
    if bare == "check_leave_eligibility":
        return f"Eligible ({d.get('days', '—')}d)" if d.get("eligible") else "Checked"
    if bare == "submit_leave_request":
        rid = d.get("request_id")
        return f"Pending {rid}" if rid else "Submitted"
    if bare == "record_leave_decision":
        return f"Decision: {d.get('status')}" if d.get("status") else "Recorded"
    if bare == "get_employee_compensation":
        sal = d.get("base_salary")
        return (
            f"{sal} {d.get('currency', '')}".strip()
            if sal is not None
            else "Authorized"
        )
    return "Completed"


class _SseTurnCollector:
    """Tee AG-UI SSE chunks to capture the assistant turn for DynamoDB history."""

    def __init__(self) -> None:
        self._buf = ""
        self.root_text = ""
        self.subagent_texts: dict[str, str] = {}
        self.last_subagent_run_id: str | None = None
        self.outstanding: dict[str, str] = {}
        self.traces: list[dict[str, Any]] = []
        self.errors: list[str] = []

    def feed_bytes(self, chunk: bytes) -> None:
        self._buf += chunk.decode("utf-8", errors="replace")
        while "\n" in self._buf:
            line, self._buf = self._buf.split("\n", 1)
            line = line.rstrip("\r")
            if not line.startswith("data:"):
                continue
            raw = line[5:].strip()
            if not raw:
                continue
            try:
                ev = json.loads(raw)
            except json.JSONDecodeError:
                continue
            if isinstance(ev, dict):
                self._handle_event(ev)

    def _handle_event(self, ev: dict[str, Any]) -> None:
        kind = ev.get("type")
        sub_id = (
            ev.get("subagentRunId")
            or ev.get("subagent_run_id")
            or (ev.get("metadata") or {}).get("subagentRunId")
            or (ev.get("metadata") or {}).get("subagent_run_id")
        )
        if kind == "TEXT_MESSAGE_CONTENT":
            delta = str(ev.get("delta") or "")
            if sub_id:
                sid = str(sub_id)
                self.last_subagent_run_id = sid
                self.subagent_texts[sid] = self.subagent_texts.get(sid, "") + delta
            else:
                self.root_text += delta
        elif kind == "TOOL_CALL_START":
            cid = str(ev.get("toolCallId") or "")
            cname = str(ev.get("toolCallName") or "")
            if cid and cname:
                self.outstanding[cid] = cname
        elif kind == "TOOL_CALL_RESULT":
            cid = str(ev.get("toolCallId") or "")
            cname = self.outstanding.pop(cid, None) or str(
                ev.get("toolCallName") or "tool"
            )
            bare = cname.split("___")[-1] if "___" in cname else cname
            if bare == "task":
                return
            raw_content = ev.get("content")
            parsed: Any = raw_content
            if isinstance(raw_content, str):
                try:
                    parsed = json.loads(raw_content)
                except ValueError:
                    parsed = None
            trace_kind = "info"
            tag = ""
            if isinstance(parsed, dict):
                if parsed.get("authorized") is False:
                    trace_kind = "deny"
                elif parsed.get("authorized") is True:
                    trace_kind = "allow"
                if parsed.get("reason_code"):
                    tag = f" · {parsed['reason_code']}"
            summary = _summarize_tool_result(cname, parsed)
            label = (
                f"{bare}{tag} · {summary}" if summary != "Completed" else f"{bare}{tag}"
            )
            self.traces.append(
                {
                    "kind": trace_kind,
                    "label": label,
                    "toolName": cname,
                    "detail": parsed,
                }
            )
        elif kind == "RUN_ERROR":
            msg = str(ev.get("message") or ev.get("code") or "Runtime error.")
            self.errors.append(msg)

    def assistant_message(self) -> dict[str, Any] | None:
        text = self.root_text.strip()
        if not text and self.subagent_texts:
            if (
                self.last_subagent_run_id
                and self.subagent_texts.get(self.last_subagent_run_id, "").strip()
            ):
                text = self.subagent_texts[self.last_subagent_run_id].strip()
            else:
                for cand in reversed(list(self.subagent_texts.values())):
                    if cand.strip():
                        text = cand.strip()
                        break
        if not text and not self.traces and self.errors:
            return {
                "role": "error",
                "text": self.errors[-1],
                "meta": "Runtime error",
                "timestamp": int(time.time() * 1000),
                "traces": [],
                "cards": [],
            }
        if not text and not self.traces:
            return None
        return {
            "role": "assistant",
            "text": text,
            "meta": "HR assistant",
            "timestamp": int(time.time() * 1000),
            "traces": self.traces,
            "cards": [],
        }


class BffRuntime:
    """Holds AWS clients, OIDC discovery cache, and DynamoDB store."""

    def __init__(
        self,
        settings: BffSettings,
        *,
        store: DynamoSessionStore | None = None,
        http_client: httpx.AsyncClient | None = None,
    ) -> None:
        self.settings = settings
        self._store = store
        self._http_client = http_client
        self._discovery: dict[str, Any] | None = None
        self._jwks_client: jwt.PyJWKClient | None = None
        self._runtime_arn_cache: tuple[float, str] | None = None
        self._refresh_locks: dict[str, asyncio.Lock] = {}

    @property
    def store(self) -> DynamoSessionStore:
        if self._store is None:
            ddb = boto3.resource("dynamodb", region_name=self.settings.region)
            self._store = DynamoSessionStore(
                bff_table=ddb.Table(self.settings.bff_session_table),
                chat_table=ddb.Table(self.settings.chat_session_table),
                session_ttl_hours=self.settings.session_ttl_hours,
            )
        return self._store

    def http(self) -> httpx.AsyncClient:
        if self._http_client is None:
            self._http_client = httpx.AsyncClient(
                timeout=httpx.Timeout(connect=10.0, read=180.0, write=30.0, pool=10.0),
                follow_redirects=False,
            )
        return self._http_client

    async def get_discovery(self) -> dict[str, Any]:
        if self._discovery is not None:
            return self._discovery
        issuer = _assert_https_url(self.settings.oidc_issuer_url, "OIDC_ISSUER_URL")
        url = f"{issuer.rstrip('/')}/.well-known/openid-configuration"
        resp = await self.http().get(url, timeout=10.0)
        if resp.status_code != 200:
            raise HTTPException(status_code=502, detail="OIDC discovery failed.")
        doc = resp.json()
        _assert_https_url(
            doc.get("authorization_endpoint", ""), "authorization_endpoint"
        )
        _assert_https_url(doc.get("token_endpoint", ""), "token_endpoint")
        _assert_https_url(doc.get("jwks_uri", ""), "jwks_uri")
        self._discovery = doc
        return doc

    def verify_id_token(
        self, id_token: str, expected_nonce: str, jwks_uri: str, issuer: str
    ) -> dict[str, Any]:
        if self._jwks_client is None:
            self._jwks_client = jwt.PyJWKClient(jwks_uri, cache_keys=True)
        signing_key = self._jwks_client.get_signing_key_from_jwt(id_token)
        claims = jwt.decode(
            id_token,
            signing_key.key,
            algorithms=["RS256", "ES256"],
            audience=self.settings.oidc_client_id,
            issuer=issuer,
            options={"require": ["exp", "iss", "aud", "sub"]},
        )
        if claims.get("nonce") != expected_nonce:
            raise ValueError("ID token nonce mismatch.")
        return claims

    def get_runtime_arn(self) -> str:
        if self.settings.runtime_arn_override:
            return self.settings.runtime_arn_override
        now = time.monotonic()
        if self._runtime_arn_cache and (now - self._runtime_arn_cache[0]) < 60.0:
            return self._runtime_arn_cache[1]
        if not self.settings.ssm_prefix:
            raise HTTPException(
                status_code=503, detail="BFF SSM prefix is not configured."
            )
        ssm = boto3.client("ssm", region_name=self.settings.region)
        name = f"{self.settings.ssm_prefix}/runtimes/orchestrator/arn"
        value = ssm.get_parameter(Name=name)["Parameter"]["Value"]
        if not RUNTIME_ARN_RE.match(value):
            raise HTTPException(
                status_code=503, detail="Configured runtime ARN is invalid."
            )
        self._runtime_arn_cache = (now, value)
        return value

    async def ensure_fresh_session(
        self, session: dict[str, Any]
    ) -> dict[str, Any] | None:
        sid = str(session.get("session_id") or "")
        expires_at = int(session.get("expires_at") or 0)
        if expires_at > int(time.time()) + TOKEN_REFRESH_SKEW_SECONDS:
            return session
        refresh_token = str(session.get("refresh_token") or "")
        if not refresh_token:
            self.store.delete_session(sid)
            return None
        lock = self._refresh_locks.setdefault(sid, asyncio.Lock())
        async with lock:
            latest = self.store.get_session(sid)
            if not latest:
                return None
            if (
                int(latest.get("expires_at") or 0)
                > int(time.time()) + TOKEN_REFRESH_SKEW_SECONDS
            ):
                return latest
            disc = await self.get_discovery()
            token_url = _assert_https_url(disc["token_endpoint"], "token_endpoint")
            form: dict[str, str] = {
                "grant_type": "refresh_token",
                "client_id": self.settings.oidc_client_id,
                "refresh_token": refresh_token,
            }
            if self.settings.oidc_client_secret:
                form["client_secret"] = self.settings.oidc_client_secret
            resp = await self.http().post(token_url, data=form, timeout=10.0)
            if resp.status_code != 200:
                self.store.delete_session(sid)
                return None
            tokens = resp.json()
            access_token = tokens.get("access_token")
            if not access_token:
                self.store.delete_session(sid)
                return None
            new_exp = int(time.time()) + int(tokens.get("expires_in") or 3600)
            new_refresh = tokens.get("refresh_token") or refresh_token
            new_id = tokens.get("id_token") or latest.get("id_token") or ""
            self.store.update_session_tokens(
                sid,
                access_token=access_token,
                id_token=new_id,
                refresh_token=new_refresh,
                expires_at=new_exp,
            )
            updated = dict(latest)
            updated.update(
                {
                    "access_token": access_token,
                    "id_token": new_id,
                    "refresh_token": new_refresh,
                    "expires_at": new_exp,
                }
            )
            return updated


def create_app(
    *,
    settings: BffSettings | None = None,
    runtime: BffRuntime | None = None,
) -> FastAPI:
    cfg = settings or BffSettings.from_env()
    rt = runtime or BffRuntime(cfg)
    app = FastAPI(
        title="AgentCore HR BFF", docs_url=None, redoc_url=None, openapi_url=None
    )

    @app.middleware("http")
    async def security_headers_middleware(request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Permissions-Policy"] = (
            "camera=(), microphone=(), geolocation=()"
        )
        response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
        response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; img-src 'self' data:; "
            "style-src 'self'; script-src 'self'; "
            "connect-src 'self'; object-src 'none'; worker-src 'none'; "
            "base-uri 'none'; frame-ancestors 'none'; form-action 'none'"
        )
        path = request.url.path
        if path in {"/config.json", "/invocations"} or path.startswith(
            ("/api/", "/auth/")
        ):
            response.headers["Cache-Control"] = "no-store"
        return response

    def _require_session(request: Request) -> dict[str, Any]:
        sid = request.cookies.get(SESSION_COOKIE_NAME, "")
        session = rt.store.get_session(sid)
        if not session:
            raise HTTPException(status_code=401, detail="Authentication required.")
        return session

    def _require_csrf(request: Request, session: dict[str, Any]) -> None:
        origin = (request.headers.get("origin") or "").strip()
        if origin and cfg.oidc_redirect_uri:
            expected_origin = f"{urlsplit(cfg.oidc_redirect_uri).scheme}://{urlsplit(cfg.oidc_redirect_uri).netloc}".lower()
            if origin.lower() != expected_origin:
                raise HTTPException(
                    status_code=403, detail="Cross-origin request rejected."
                )
        sent_csrf = (request.headers.get("x-bff-csrf") or "").strip()
        expected_csrf = str(session.get("csrf_token") or "")
        if (
            not sent_csrf
            or not expected_csrf
            or not hmac.compare_digest(sent_csrf, expected_csrf)
        ):
            raise HTTPException(status_code=403, detail="Invalid CSRF token.")

    @app.get("/healthz")
    async def healthz():
        return {"status": "ok"}

    @app.get("/config.json")
    async def config_json():
        return {
            "auth_mode": "bff",
            "a2ui_protocol_version": A2UI_PROTOCOL_VERSION,
            "exposure": cfg.exposure,
        }

    @app.get("/auth/login")
    async def auth_login():
        disc = await rt.get_discovery()
        auth_url = _assert_https_url(
            disc["authorization_endpoint"], "authorization_endpoint"
        )
        verifier = secrets.token_urlsafe(48)
        oauth_state = secrets.token_urlsafe(24)
        nonce = secrets.token_urlsafe(24)
        rt.store.put_pkce_state(oauth_state, verifier=verifier, nonce=nonce)
        query = urlencode(
            {
                "response_type": "code",
                "client_id": cfg.oidc_client_id,
                "redirect_uri": cfg.oidc_redirect_uri,
                "scope": cfg.oidc_scope,
                "state": oauth_state,
                "nonce": nonce,
                "code_challenge": _pkce_challenge(verifier),
                "code_challenge_method": "S256",
            }
        )
        return RedirectResponse(url=f"{auth_url}?{query}", status_code=302)

    @app.get("/auth/callback")
    async def auth_callback(request: Request):
        err = request.query_params.get("error")
        if err:
            return RedirectResponse(url=f"/?error={quote(err)}", status_code=302)
        code = request.query_params.get("code", "")
        returned_state = request.query_params.get("state", "")
        if not code or not returned_state:
            return RedirectResponse(url="/?error=invalid_request", status_code=302)
        pkce = rt.store.pop_pkce_state(returned_state)
        if not pkce:
            return RedirectResponse(url="/?error=invalid_state", status_code=302)
        disc = await rt.get_discovery()
        token_url = _assert_https_url(disc["token_endpoint"], "token_endpoint")
        form: dict[str, str] = {
            "grant_type": "authorization_code",
            "client_id": cfg.oidc_client_id,
            "code": code,
            "redirect_uri": cfg.oidc_redirect_uri,
            "code_verifier": str(pkce["verifier"]),
        }
        if cfg.oidc_client_secret:
            form["client_secret"] = cfg.oidc_client_secret
        resp = await rt.http().post(token_url, data=form, timeout=10.0)
        if resp.status_code != 200:
            logger.warning("OIDC token exchange failed: HTTP %s", resp.status_code)
            return RedirectResponse(
                url="/?error=token_exchange_failed", status_code=302
            )
        tokens = resp.json()
        access_token = tokens.get("access_token")
        id_token = tokens.get("id_token")
        if not access_token or not id_token:
            return RedirectResponse(url="/?error=missing_tokens", status_code=302)
        try:
            claims = rt.verify_id_token(
                id_token,
                str(pkce["nonce"]),
                disc["jwks_uri"],
                disc.get("issuer") or cfg.oidc_issuer_url,
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning("ID token verification failed: %s", exc)
            return RedirectResponse(url="/?error=invalid_token", status_code=302)

        expires_at = int(time.time()) + int(tokens.get("expires_in") or 3600)
        sub = str(claims["sub"])
        user_label = str(
            claims.get("email")
            or claims.get("preferred_username")
            or claims.get("cognito:username")
            or sub
        )
        session = rt.store.create_session(
            sub=sub,
            user_label=user_label,
            access_token=access_token,
            id_token=id_token,
            refresh_token=tokens.get("refresh_token"),
            expires_at=expires_at,
        )
        response = RedirectResponse(url="/", status_code=302)
        response.set_cookie(
            key=SESSION_COOKIE_NAME,
            value=session["session_id"],
            httponly=True,
            secure=cfg.cookie_secure,
            samesite="lax",
            path="/",
            max_age=cfg.session_ttl_hours * 3600,
        )
        return response

    @app.get("/api/auth/me")
    async def auth_me(request: Request, response: Response):
        sid = request.cookies.get(SESSION_COOKIE_NAME, "")
        session = rt.store.get_session(sid)
        if not session:
            return {"authenticated": False}
        fresh = await rt.ensure_fresh_session(session)
        if not fresh:
            response.delete_cookie(SESSION_COOKIE_NAME, path="/")
            return {"authenticated": False}
        return {
            "authenticated": True,
            "userLabel": fresh.get("user_label", "Signed in"),
            "sub": fresh.get("sub", ""),
            "csrfToken": fresh.get("csrf_token", ""),
            "activeThreadId": fresh.get("active_thread_id", ""),
        }

    @app.post("/auth/logout")
    async def auth_logout(request: Request):
        session = _require_session(request)
        _require_csrf(request, session)
        refresh_token = str(session.get("refresh_token") or "")
        rt.store.delete_session(str(session["session_id"]))
        logout_url = ""
        try:
            disc = await rt.get_discovery()
            if refresh_token and disc.get("revocation_endpoint"):
                rev_url = _assert_https_url(
                    disc["revocation_endpoint"], "revocation_endpoint"
                )
                rev_form: dict[str, str] = {
                    "token": refresh_token,
                    "client_id": cfg.oidc_client_id,
                }
                if cfg.oidc_client_secret:
                    rev_form["client_secret"] = cfg.oidc_client_secret
                await rt.http().post(rev_url, data=rev_form, timeout=3.0)
            if disc.get("end_session_endpoint") and cfg.oidc_logout_uri:
                end_url = _assert_https_url(
                    disc["end_session_endpoint"], "end_session_endpoint"
                )
                logout_url = f"{end_url}?" + urlencode(
                    {
                        "client_id": cfg.oidc_client_id,
                        "logout_uri": cfg.oidc_logout_uri,
                    }
                )
        except Exception as exc:  # noqa: BLE001
            logger.debug("Best-effort OIDC logout cleanup failed: %s", exc)
        resp = JSONResponse({"ok": True, "logoutUrl": logout_url})
        resp.delete_cookie(SESSION_COOKIE_NAME, path="/")
        return resp

    @app.get("/api/sessions")
    async def list_sessions(request: Request):
        session = _require_session(request)
        fresh = await rt.ensure_fresh_session(session)
        if not fresh:
            raise HTTPException(status_code=401, detail="Session expired.")
        threads = rt.store.list_chat_threads(str(fresh["sub"]))
        return {"threads": threads, "activeThreadId": fresh.get("active_thread_id", "")}

    @app.get("/api/sessions/{thread_id}")
    async def get_session_detail(thread_id: str, request: Request):
        if not THREAD_ID_RE.match(thread_id):
            raise HTTPException(status_code=400, detail="Invalid thread ID.")
        session = _require_session(request)
        fresh = await rt.ensure_fresh_session(session)
        if not fresh:
            raise HTTPException(status_code=401, detail="Session expired.")
        thread = rt.store.get_chat_thread(str(fresh["sub"]), thread_id)
        if not thread:
            raise HTTPException(status_code=404, detail="Conversation not found.")
        rt.store.set_active_thread(str(fresh["session_id"]), thread_id)
        return thread

    @app.delete("/api/sessions/{thread_id}")
    async def delete_session_thread(thread_id: str, request: Request):
        if not THREAD_ID_RE.match(thread_id):
            raise HTTPException(status_code=400, detail="Invalid thread ID.")
        session = _require_session(request)
        _require_csrf(request, session)
        rt.store.delete_chat_thread(str(session["sub"]), thread_id)
        return {"ok": True}

    @app.delete("/api/sessions")
    async def clear_session_threads(request: Request):
        session = _require_session(request)
        _require_csrf(request, session)
        deleted = rt.store.clear_chat_threads(str(session["sub"]))
        rt.store.set_active_thread(str(session["session_id"]), "")
        return {"ok": True, "deleted": deleted}

    @app.post("/invocations")
    async def invocations(request: Request):
        session = _require_session(request)
        _require_csrf(request, session)
        fresh = await rt.ensure_fresh_session(session)
        if not fresh:
            raise HTTPException(status_code=401, detail="Session expired.")

        session_id_hdr = (
            request.headers.get("x-amzn-bedrock-agentcore-runtime-session-id") or ""
        ).strip()
        if not SESSION_ID_RE.match(session_id_hdr):
            raise HTTPException(
                status_code=400,
                detail="Valid X-Amzn-Bedrock-AgentCore-Runtime-Session-Id (33-128 chars) required.",
            )
        ctype = (
            (request.headers.get("content-type") or "").split(";", 1)[0].strip().lower()
        )
        if ctype != "application/json":
            raise HTTPException(
                status_code=415, detail="Content-Type must be application/json."
            )

        raw_body = await request.body()
        if not raw_body or len(raw_body) > MAX_INVOKE_BODY_BYTES:
            raise HTTPException(status_code=400, detail="Request body out of bounds.")
        try:
            payload = json.loads(raw_body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise HTTPException(
                status_code=400, detail="Request body must be valid JSON."
            ) from exc
        if not isinstance(payload, dict):
            raise HTTPException(
                status_code=400, detail="Request body must be a JSON object."
            )

        runtime_arn = rt.get_runtime_arn()
        region = cfg.region
        upstream_url = (
            f"https://bedrock-agentcore.{region}.amazonaws.com/runtimes/"
            f"{quote(runtime_arn, safe='')}/invocations?qualifier=DEFAULT"
        )
        upstream_headers = {
            "Authorization": f"Bearer {fresh['access_token']}",
            "Content-Type": "application/json",
            "Accept": "text/event-stream",
            "X-Amzn-Bedrock-AgentCore-Runtime-Session-Id": session_id_hdr,
        }
        trace_id = (request.headers.get("x-amzn-trace-id") or "").strip()
        if trace_id and XRAY_TRACE_ID_RE.match(trace_id):
            upstream_headers["X-Amzn-Trace-Id"] = trace_id

        fwd = (
            payload.get("forwardedProps")
            if isinstance(payload.get("forwardedProps"), dict)
            else {}
        )
        is_pending_poll = bool(fwd.get("checkPendingReviews"))
        owner_sub = str(fresh["sub"])
        thread_id = str(payload.get("threadId") or session_id_hdr)
        active_agent_id = str(fwd.get("activeAgentId") or "hr-assistant")
        if not is_pending_poll and THREAD_ID_RE.match(thread_id):
            rt.store.set_active_thread(str(fresh["session_id"]), thread_id)
            user_msgs = [
                {
                    "role": "user",
                    "text": str(m.get("content") or ""),
                    "meta": "You",
                    "timestamp": int(time.time() * 1000),
                    "traces": [],
                    "cards": [],
                }
                for m in (payload.get("messages") or [])
                if isinstance(m, dict)
                and m.get("role") == "user"
                and str(m.get("content") or "").strip()
            ]
            if user_msgs:
                rt.store.append_turn_messages(
                    owner_sub=owner_sub,
                    thread_id=thread_id,
                    new_messages=user_msgs,
                    active_agent_id=active_agent_id,
                )

        collector = _SseTurnCollector()

        async def _stream() -> AsyncIterator[bytes]:
            try:
                async with rt.http().stream(
                    "POST",
                    upstream_url,
                    content=raw_body,
                    headers=upstream_headers,
                ) as upstream:
                    if upstream.status_code != 200:
                        err_event = {
                            "type": "RUN_ERROR",
                            "code": f"RuntimeHttp{upstream.status_code}",
                            "message": f"Runtime returned HTTP {upstream.status_code}.",
                        }
                        chunk = f"data: {json.dumps(err_event)}\n\n".encode()
                        collector.feed_bytes(chunk)
                        yield chunk
                        return
                    async for chunk in upstream.aiter_bytes():
                        if chunk:
                            collector.feed_bytes(chunk)
                            yield chunk
            except httpx.HTTPError as exc:
                logger.warning(
                    "Upstream AgentCore runtime request failed: %s", type(exc).__name__
                )
                err_event = {
                    "type": "RUN_ERROR",
                    "code": "UpstreamError",
                    "message": "Could not reach AgentCore runtime.",
                }
                yield f"data: {json.dumps(err_event)}\n\n".encode()
            finally:
                if not is_pending_poll and THREAD_ID_RE.match(thread_id):
                    assistant_msg = collector.assistant_message()
                    if assistant_msg is not None:
                        try:
                            rt.store.append_turn_messages(
                                owner_sub=owner_sub,
                                thread_id=thread_id,
                                new_messages=[assistant_msg],
                                active_agent_id=active_agent_id,
                            )
                        except Exception:
                            logger.exception(
                                "Failed persisting assistant turn to DynamoDB"
                            )

        return StreamingResponse(_stream(), media_type="text/event-stream")

    @app.get("/{full_path:path}")
    async def serve_static(full_path: str):
        req_path = f"/{full_path}" if full_path else "/"
        entry = STATIC_ASSETS.get(req_path)
        if not entry:
            raise HTTPException(status_code=404, detail="Resource not found.")
        filename, media_type = entry
        public_root = PUBLIC_DIR.resolve()
        target = (public_root / filename).resolve()
        if not target.is_relative_to(public_root) or not target.is_file():
            raise HTTPException(status_code=404, detail="Resource not found.")
        return FileResponse(target, media_type=media_type)

    return app


app = create_app()
