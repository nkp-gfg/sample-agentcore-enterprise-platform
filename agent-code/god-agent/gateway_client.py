"""Per-leaf gateway MCP clients using Cognito `client_credentials` + `aws_client_metadata`.

`docs/hr/tools.md` § Routing maps each leaf to its one gateway tool:

    leave-balance      → hr-ops___get_leave_balance
    leave-eligibility  → hr-ops___check_leave_eligibility
    leave-submit       → hr-ops___submit_leave_request
    compensation       → hr-payroll___get_employee_compensation
    direct-reports     → hr-payroll___list_direct_reports
    allowance          → hr-finance___get_allowance

How identity reaches Cedar and the gateway Lambdas (`docs/hr/modules.md` § H3 claims):
  - AgentCore Token Vault's M2M decorator cannot forward per-user `aws_client_metadata`.
  - Instead, this module performs an OAuth 2.0 `client_credentials` exchange
    against the Cognito User Pool's `/oauth2/token` endpoint (discovered from
    `{issuer_url}/.well-known/openid-configuration`), authenticating with the
    M2M client secret from Secrets Manager and passing:
      `aws_client_metadata = {"verified_user_id": <verified_sub>, "calling_agent": <leaf>}`
  - Cognito invokes the H3 Pre-Token Generation V3_0 Lambda
    (`TokenGeneration_ClientCredentials`), which looks up `verified_user_id`
    in `employees.cognito_sub` and stamps `employee_id`, `user_id`, `role`,
    and `agent_id` onto the issued access token.
  - Cedar (`ENFORCE`) verifies `employee_id` and `agent_id == <leaf>`; the
    gateway REQUEST interceptor promotes `caller_employee_id`, `agent_id`, and
    `session_id` onto the tool arguments.
"""

from __future__ import annotations

import asyncio
import base64
import contextvars
import datetime as _dt
import json
import logging
import time
import urllib.parse
import urllib.request
import uuid
from collections.abc import Awaitable, Callable
from typing import Any

import boto3
from langchain_core.tools import BaseTool, StructuredTool
from langgraph.types import interrupt
from pydantic import BaseModel, Field
from shared.region import runtime_region
from ssm_config import auth_m2m_config, gateway_config

logger = logging.getLogger(__name__)

LEAF_TOOL_MAP: dict[str, str] = {
    "leave-balance": "hr-ops___get_leave_balance",
    "leave-eligibility": "hr-ops___check_leave_eligibility",
    "leave-submit": "hr-ops___submit_leave_request",
    "compensation": "hr-payroll___get_employee_compensation",
    "direct-reports": "hr-payroll___list_direct_reports",
    "allowance": "hr-finance___get_allowance",
}

REVIEW_NODE_CALLING_AGENT = "review-node"
REVIEW_NODE_TOOL = "hr-ops___record_leave_decision"

ALLOWED_CALLING_AGENTS: frozenset[str] = frozenset(LEAF_TOOL_MAP) | {
    REVIEW_NODE_CALLING_AGENT,
}

# Per-turn execution context (never persisted into checkpoints or logs).
_CURRENT_USER_SUB: contextvars.ContextVar[str] = contextvars.ContextVar(
    "god_agent_user_sub", default=""
)
_CURRENT_SESSION_ID: contextvars.ContextVar[str] = contextvars.ContextVar(
    "god_agent_session_id", default=""
)
_TURN_TOOL_EVENTS: contextvars.ContextVar[list[dict[str, Any]] | None] = (
    contextvars.ContextVar("god_agent_turn_tool_events", default=None)
)
_TURN_PENDING_REVIEW: contextvars.ContextVar[dict[str, Any] | None] = (
    contextvars.ContextVar("god_agent_turn_pending_review", default=None)
)

# Process-local caches for OIDC token endpoint and M2M client secret (never user tokens).
_TOKEN_ENDPOINT_CACHE: dict[str, str] = {}
_M2M_SECRET_CACHE: dict[str, tuple[float, str]] = {}
_M2M_SECRET_TTL_SECONDS = 300.0


class UnknownCallingAgent(ValueError):
    """Attempted to mint a token for an unlisted `calling_agent`."""


def _assert_known_calling_agent(calling_agent: str) -> None:
    if calling_agent not in ALLOWED_CALLING_AGENTS:
        raise UnknownCallingAgent(
            f"calling_agent={calling_agent!r} is not one of "
            f"{sorted(ALLOWED_CALLING_AGENTS)}"
        )


def set_turn_context(verified_user_sub: str, session_id: str) -> None:
    _CURRENT_USER_SUB.set(verified_user_sub)
    _CURRENT_SESSION_ID.set(session_id)
    _TURN_TOOL_EVENTS.set([])
    _TURN_PENDING_REVIEW.set(None)


def record_turn_tool_event(tool_name: str, result: Any) -> None:
    buf = _TURN_TOOL_EVENTS.get()
    if buf is not None:
        buf.append(
            {
                "tool_call_id": f"call-{uuid.uuid4().hex[:16]}",
                "tool_name": tool_name,
                "result": result,
            }
        )


def drain_turn_tool_events() -> list[dict[str, Any]]:
    buf = _TURN_TOOL_EVENTS.get()
    if not buf:
        return []
    copied = list(buf)
    buf.clear()
    return copied


def take_turn_pending_review() -> dict[str, Any] | None:
    pending = _TURN_PENDING_REVIEW.get()
    _TURN_PENDING_REVIEW.set(None)
    return pending


def decode_jwt_claims_unverified(token: str) -> dict[str, Any]:
    """Decode claims from a JWT just returned by Cognito over TLS."""
    try:
        _h, payload_b64, _s = token.split(".")
        pad = "=" * (-len(payload_b64) % 4)
        data = json.loads(base64.urlsafe_b64decode(payload_b64 + pad))
        return data if isinstance(data, dict) else {}
    except Exception:  # noqa: BLE001
        return {}


def _discover_token_endpoint(issuer_url: str) -> str:
    cached = _TOKEN_ENDPOINT_CACHE.get(issuer_url)
    if cached:
        return cached
    discovery_url = f"{issuer_url.rstrip('/')}/.well-known/openid-configuration"
    req = urllib.request.Request(discovery_url, headers={"Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=10) as resp:  # nosec B310 — https
        doc = json.loads(resp.read())
    endpoint = str(doc.get("token_endpoint") or "").strip()
    if not endpoint:
        raise RuntimeError(f"OIDC discovery at {discovery_url} missing token_endpoint")
    _TOKEN_ENDPOINT_CACHE[issuer_url] = endpoint
    return endpoint


def _read_m2m_client_secret(secret_name: str) -> str:
    now = time.monotonic()
    cached = _M2M_SECRET_CACHE.get(secret_name)
    if cached and (now - cached[0]) < _M2M_SECRET_TTL_SECONDS:
        return cached[1]
    sm = boto3.client("secretsmanager", region_name=runtime_region())
    secret_str = sm.get_secret_value(SecretId=secret_name)["SecretString"].strip()
    _M2M_SECRET_CACHE[secret_name] = (now, secret_str)
    return secret_str


def _mint_token_sync(verified_user_sub: str, calling_agent: str) -> str:
    _assert_known_calling_agent(calling_agent)
    if not verified_user_sub:
        raise RuntimeError("Cannot mint leaf gateway token without verified_user_sub")
    cfg = auth_m2m_config()
    token_endpoint = _discover_token_endpoint(cfg.issuer_url)
    client_secret = _read_m2m_client_secret(cfg.client_secret_name)

    metadata = json.dumps(
        {"verified_user_id": verified_user_sub, "calling_agent": calling_agent}
    )
    form_fields = {
        "grant_type": "client_credentials",
        "aws_client_metadata": metadata,
    }
    if cfg.scope:
        form_fields["scope"] = cfg.scope
    body = urllib.parse.urlencode(form_fields).encode()
    basic = base64.b64encode(f"{cfg.client_id}:{client_secret}".encode()).decode()
    req = urllib.request.Request(
        token_endpoint,
        data=body,
        headers={
            "Authorization": f"Basic {basic}",
            "Content-Type": "application/x-www-form-urlencoded",
        },
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=15) as resp:  # nosec B310 — https
        payload = json.loads(resp.read())
    token = str(payload.get("access_token") or "")
    if not token:
        raise RuntimeError("Cognito token endpoint returned no access_token")
    return token


async def mint_leaf_gateway_token(verified_user_sub: str, calling_agent: str) -> str:
    """Mint a short-lived Cognito M2M token carrying `verified_user_id` + `calling_agent`."""
    return await asyncio.to_thread(_mint_token_sync, verified_user_sub, calling_agent)


async def resolve_employee_id_for_sub(verified_user_sub: str) -> str:
    """Resolve `employee_id` for `verified_user_sub` via a review-node token exchange."""
    token = await mint_leaf_gateway_token(verified_user_sub, REVIEW_NODE_CALLING_AGENT)
    claims = decode_jwt_claims_unverified(token)
    return str(claims.get("employee_id") or "").strip()


def build_token_fetcher(
    calling_agent: str, *, verified_user_sub: str | None = None
) -> Callable[[], Awaitable[str]]:
    _assert_known_calling_agent(calling_agent)

    async def _fetch() -> str:
        sub = verified_user_sub or _CURRENT_USER_SUB.get()
        return await mint_leaf_gateway_token(sub, calling_agent)

    return _fetch


def _invoke_gateway_mcp_sync(
    token: str, tool_name: str, arguments: dict[str, Any], session_id: str
) -> dict[str, Any]:
    gw = gateway_config()
    rpc_body = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": uuid.uuid4().hex,
            "method": "tools/call",
            "params": {"name": tool_name, "arguments": arguments},
        }
    ).encode()
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
    }
    if session_id:
        headers["runtimeSessionId"] = session_id
    req = urllib.request.Request(gw.url, data=rpc_body, headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=30) as resp:  # nosec B310 — https
        raw_text = resp.read().decode("utf-8", errors="replace").strip()

    # Streamable HTTP MCP may return plain JSON or `data: {...}` SSE lines.
    rpc_payload: dict[str, Any] = {}
    if raw_text.startswith("{"):
        rpc_payload = json.loads(raw_text)
    else:
        for line in raw_text.splitlines():
            if line.startswith("data:"):
                candidate = line[5:].strip()
                if candidate:
                    rpc_payload = json.loads(candidate)

    if "error" in rpc_payload:
        err = rpc_payload["error"]
        msg = err.get("message") if isinstance(err, dict) else str(err)
        logger.warning("Gateway MCP error calling %s: %s", tool_name, msg)
        return {"authorized": False, "reason_code": "NOT_AUTHORIZED"}

    result = rpc_payload.get("result") or {}
    if result.get("isError"):
        return {"authorized": False, "reason_code": "NOT_AUTHORIZED"}
    content = result.get("content") or []
    if (
        content
        and isinstance(content[0], dict)
        and isinstance(content[0].get("text"), str)
    ):
        try:
            parsed = json.loads(content[0]["text"])
            if isinstance(parsed, dict):
                return parsed
        except ValueError:
            pass
    if isinstance(result, dict) and "authorized" in result:
        return result
    return {"authorized": False, "reason_code": "DATA_UNAVAILABLE"}


async def call_gateway_tool(
    calling_agent: str,
    tool_name: str,
    arguments: dict[str, Any],
    *,
    verified_user_sub: str | None = None,
    session_id: str | None = None,
) -> dict[str, Any]:
    sub = verified_user_sub or _CURRENT_USER_SUB.get()
    sid = session_id if session_id is not None else _CURRENT_SESSION_ID.get()
    token = await mint_leaf_gateway_token(sub, calling_agent)
    parsed = await asyncio.to_thread(
        _invoke_gateway_mcp_sync, token, tool_name, arguments, sid
    )
    record_turn_tool_event(tool_name, parsed)
    return parsed


# ── Tool argument schemas (docs/hr/tools.md § Arguments) ───────────────────


class _NoArgs(BaseModel):
    pass


class _CompensationArgs(BaseModel):
    employee_id: str | None = Field(
        default=None,
        description="Optional target employee_id. Omit to read the caller's own compensation.",
    )


class _AllowanceArgs(BaseModel):
    item_type: str = Field(
        default="telephone",
        description="Allowance item type. v1 accepts 'telephone' only.",
    )
    period: str | None = Field(
        default=None,
        description="Optional YYYY-MM period. Defaults to previous UTC month.",
    )


class _LeaveCheckArgs(BaseModel):
    leave_type: str = Field(description="Leave type: 'annual' or 'sick'.")
    start_date: str = Field(description="Inclusive ISO start date YYYY-MM-DD.")
    end_date: str = Field(description="Inclusive ISO end date YYYY-MM-DD.")


class _LeaveSubmitArgs(BaseModel):
    leave_type: str = Field(description="Leave type: 'annual' or 'sick'.")
    start_date: str = Field(description="Inclusive ISO start date YYYY-MM-DD.")
    end_date: str = Field(description="Inclusive ISO end date YYYY-MM-DD.")
    reason: str = Field(default="", description="Plain-text reason for the request.")
    idempotency_key: str | None = Field(
        default=None,
        description="Optional idempotency key; generated deterministically if omitted.",
    )


class _RecordDecisionArgs(BaseModel):
    request_id: str = Field(description="Pending leave request_id.")
    decision: str = Field(description="Decision: 'approve' or 'reject'.")


def _compute_inclusive_days(start_date: str, end_date: str) -> int | str:
    try:
        s = _dt.date.fromisoformat(start_date)
        e = _dt.date.fromisoformat(end_date)
        return (e - s).days + 1
    except ValueError:
        return ""


def build_local_leaf_tool(calling_agent: str) -> BaseTool:
    """Construct the leaf's single gateway tool with lazy per-call token minting."""
    if calling_agent not in LEAF_TOOL_MAP:
        raise UnknownCallingAgent(
            f"{calling_agent!r} is not a leaf — only {sorted(LEAF_TOOL_MAP)} "
            "have a gateway tool."
        )
    tool_name = LEAF_TOOL_MAP[calling_agent]

    if calling_agent == "leave-balance":

        async def _leave_balance() -> dict[str, Any]:
            return await call_gateway_tool(calling_agent, tool_name, {})

        return StructuredTool.from_function(
            coroutine=_leave_balance,
            name=tool_name,
            description="Read the signed-in employee's annual and sick leave balances.",
            args_schema=_NoArgs,
        )

    if calling_agent == "direct-reports":

        async def _direct_reports() -> dict[str, Any]:
            return await call_gateway_tool(calling_agent, tool_name, {})

        return StructuredTool.from_function(
            coroutine=_direct_reports,
            name=tool_name,
            description="List the signed-in manager's active direct reports (one hop).",
            args_schema=_NoArgs,
        )

    if calling_agent == "compensation":

        async def _compensation(employee_id: str | None = None) -> dict[str, Any]:
            args: dict[str, Any] = {}
            if employee_id:
                args["employee_id"] = employee_id
            return await call_gateway_tool(calling_agent, tool_name, args)

        return StructuredTool.from_function(
            coroutine=_compensation,
            name=tool_name,
            description="Read compensation for the caller or one of their direct reports.",
            args_schema=_CompensationArgs,
        )

    if calling_agent == "allowance":

        async def _allowance(
            item_type: str = "telephone", period: str | None = None
        ) -> dict[str, Any]:
            args: dict[str, Any] = {"item_type": item_type}
            if period:
                args["period"] = period
            return await call_gateway_tool(calling_agent, tool_name, args)

        return StructuredTool.from_function(
            coroutine=_allowance,
            name=tool_name,
            description="Read the signed-in employee's allowance for a YYYY-MM period.",
            args_schema=_AllowanceArgs,
        )

    if calling_agent == "leave-eligibility":

        async def _leave_eligibility(
            leave_type: str, start_date: str, end_date: str
        ) -> dict[str, Any]:
            return await call_gateway_tool(
                calling_agent,
                tool_name,
                {
                    "leave_type": leave_type,
                    "start_date": start_date,
                    "end_date": end_date,
                },
            )

        return StructuredTool.from_function(
            coroutine=_leave_eligibility,
            name=tool_name,
            description="Check whether the caller is eligible for leave over an inclusive date range.",
            args_schema=_LeaveCheckArgs,
        )

    # `leave-submit`: pauses on `employee_confirm` BEFORE invoking the gateway!
    async def _leave_submit(
        leave_type: str,
        start_date: str,
        end_date: str,
        reason: str = "",
        idempotency_key: str | None = None,
    ) -> dict[str, Any]:
        sid = _CURRENT_SESSION_ID.get() or "session"
        stable_key = idempotency_key or str(
            uuid.uuid5(
                uuid.NAMESPACE_URL,
                f"{sid}:{leave_type}:{start_date}:{end_date}:{reason}",
            )
        )
        proposed_args = {
            "leave_type": leave_type,
            "start_date": start_date,
            "end_date": end_date,
            "reason": reason,
            "idempotency_key": stable_key,
        }
        confirm_payload = {
            "kind": "employee_confirm",
            "leave_type": leave_type,
            "start_date": start_date,
            "end_date": end_date,
            "days": _compute_inclusive_days(start_date, end_date),
            "reason": reason,
            "arguments": proposed_args,
        }

        raw_resume = interrupt(confirm_payload)
        decision = ""
        edited_args: dict[str, Any] = {}
        if isinstance(raw_resume, str):
            decision = raw_resume.strip().lower()
        elif isinstance(raw_resume, dict):
            if raw_resume.get("__agui_cancelled__"):
                decision = "reject"
            else:
                decision = str(raw_resume.get("decision") or "").strip().lower()
                if isinstance(raw_resume.get("arguments"), dict):
                    edited_args = dict(raw_resume["arguments"])

        if decision == "reject":
            return {"authorized": False, "reason_code": "CANCELLED_BY_EMPLOYEE"}
        if decision not in {"approve", "edit"}:
            return {"authorized": False, "reason_code": "INVALID_DECISION"}

        final_args = dict(proposed_args)
        if edited_args:
            for k in ("leave_type", "start_date", "end_date", "reason"):
                if k in edited_args and edited_args[k] is not None:
                    final_args[k] = edited_args[k]
            if (
                final_args["start_date"] != start_date
                or final_args["end_date"] != end_date
                or final_args["leave_type"] != leave_type
            ):
                final_args["idempotency_key"] = str(
                    uuid.uuid5(
                        uuid.NAMESPACE_URL,
                        f"{sid}:{final_args['leave_type']}:{final_args['start_date']}:{final_args['end_date']}:{final_args['reason']}",
                    )
                )

        result = await call_gateway_tool(calling_agent, tool_name, final_args)
        data = result.get("data") if isinstance(result, dict) else None
        if (
            isinstance(result, dict)
            and result.get("authorized") is True
            and isinstance(data, dict)
            and data.get("status") == "pending"
            and data.get("request_id")
            and data.get("reviewer_employee_id")
        ):
            _TURN_PENDING_REVIEW.set(
                {
                    "kind": "manager_review",
                    "request_id": str(data["request_id"]),
                    "employee_id": str(data.get("employee_id") or ""),
                    "reviewer_employee_id": str(data["reviewer_employee_id"]),
                    "leave_type": str(final_args["leave_type"]),
                    "start_date": str(final_args["start_date"]),
                    "end_date": str(final_args["end_date"]),
                    "days": int(data.get("days") or 1),
                    # Never sent to a model — goes straight to agent_state + card.
                    "reason": str(final_args.get("reason") or ""),
                }
            )
        return result

    return StructuredTool.from_function(
        coroutine=_leave_submit,
        name=tool_name,
        description="Submit a leave request after employee confirmation.",
        args_schema=_LeaveSubmitArgs,
    )


async def fetch_leaf_tool(calling_agent: str) -> BaseTool:
    """Return the single gateway tool bound to `calling_agent`."""
    return build_local_leaf_tool(calling_agent)


async def fetch_review_node_tool(
    *, verified_user_sub: str | None = None
) -> tuple[BaseTool, str]:
    """Return the `record_leave_decision` tool bound to the reviewing manager's token."""
    sub = verified_user_sub or _CURRENT_USER_SUB.get()
    token = await mint_leaf_gateway_token(sub, REVIEW_NODE_CALLING_AGENT)

    async def _record_decision(request_id: str, decision: str) -> dict[str, Any]:
        sid = _CURRENT_SESSION_ID.get()
        parsed = await asyncio.to_thread(
            _invoke_gateway_mcp_sync,
            token,
            REVIEW_NODE_TOOL,
            {"request_id": request_id, "decision": decision},
            sid,
        )
        record_turn_tool_event(REVIEW_NODE_TOOL, parsed)
        return parsed

    tool = StructuredTool.from_function(
        coroutine=_record_decision,
        name=REVIEW_NODE_TOOL,
        description="Record manager approval or rejection on a pending leave request.",
        args_schema=_RecordDecisionArgs,
    )
    return tool, token
