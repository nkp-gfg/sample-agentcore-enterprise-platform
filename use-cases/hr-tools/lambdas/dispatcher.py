"""Lambda entry point for every HR gateway target.

docs/hr/tools.md lists three targets (hr-ops, hr-payroll, hr-finance),
one Lambda each. The gateway sends the full action name on
`context.client_context.custom['bedrockAgentCoreToolName']` as
`"<target>___<tool>"`; the dispatcher reads that, strips the target
prefix, and calls the per-tool handler's `handler(event, context)`.

This module is the file CDK configures as the Lambda handler
(`handler.handler`), bundled into each target Lambda. The per-tool
packages — `get_leave_balance`, `check_leave_eligibility`, etc. —
live next to this file inside the same deployment zip.

Error handling:

- The per-tool handler is expected to always return a dict the gateway
  can send through the interceptor. A raised `HRToolError` from the
  tool is still mapped here (defence in depth); every other exception
  turns into `DATA_UNAVAILABLE` and is logged with a stack trace, so
  the model never sees the error string.
- The business response (`{"authorized": ..., "reason_code": ...,
  "data": ...}`) is wrapped in the AgentCore Lambda target shape
  (`{"content": [{"type": "text", "text": "<json>"}]}`), the same
  shape the sample tool uses, so the gateway's response interceptor
  sees normal tool output and not a JSON-RPC error.
"""

from __future__ import annotations

import importlib
import json
import logging
from typing import Any

from shared import DataUnavailable, HRToolError, build_response, log_decision

logger = logging.getLogger()
logger.setLevel(logging.INFO)

_TOOL_SEPARATOR = "___"


def _extract_tool_name(context: Any) -> str:
    """Pull the tool name out of the AgentCore Lambda target context.

    `context.client_context.custom['bedrockAgentCoreToolName']` is the
    full action name, e.g. `hr-ops___get_leave_balance`. Everything
    before the first `___` is the target; everything after is the tool.
    """
    client = getattr(context, "client_context", None)
    if client is None:
        raise HRToolError("no client_context on invocation")
    custom = getattr(client, "custom", None) or {}
    full = custom.get("bedrockAgentCoreToolName") or ""
    if _TOOL_SEPARATOR not in full:
        raise HRToolError(f"bedrockAgentCoreToolName malformed: {full!r}")
    _target, _, tool_name = full.partition(_TOOL_SEPARATOR)
    return tool_name


def _wrap(response: dict[str, Any]) -> dict[str, Any]:
    """Return the AgentCore Lambda target response shape.

    docs/hr/tools.md § Responses is the business object. The sample
    tool returns `{"content": [...]}`; we keep that wrapper so the
    response interceptor sees a normal tool result rather than a
    JSON-RPC error.
    """
    return {"content": [{"type": "text", "text": json.dumps(response)}]}


def _extract_audit_identity(event: dict) -> tuple[str, str, str]:
    caller_id = (
        event.get("caller_employee_id")
        if isinstance(event, dict) and isinstance(event.get("caller_employee_id"), str)
        else ""
    )
    agent_id = (
        event.get("agent_id")
        if isinstance(event, dict) and isinstance(event.get("agent_id"), str)
        else ""
    )
    session_id = (
        event.get("session_id")
        if isinstance(event, dict) and isinstance(event.get("session_id"), str)
        else ""
    )
    return caller_id.strip() or "unmapped", agent_id, session_id


def handler(event: dict, context: Any) -> dict[str, Any]:
    """Dispatch by tool name. Every failure becomes a normal tool result."""
    try:
        tool_name = _extract_tool_name(context)
    except HRToolError as exc:
        logger.error("dispatch failed: %s", exc)
        return _wrap(build_response(authorized=False, reason_code=exc.reason_code))

    logger.info("dispatching tool=%s", tool_name)

    try:
        module = importlib.import_module(f"{tool_name}.handler")
    except ModuleNotFoundError as exc:
        logger.error("no handler packaged for tool %s: %s", tool_name, exc)
        return _wrap(build_response(authorized=False, reason_code="NOT_AUTHORIZED"))

    try:
        response = module.handler(event, context)
    except HRToolError as exc:
        logger.warning(
            "tool %s raised HRToolError reason_code=%s", tool_name, exc.reason_code
        )
        caller_id, agent_id, session_id = _extract_audit_identity(event)
        log_decision(
            action=tool_name,
            caller_employee_id=caller_id,
            target_employee_id=None,
            allow=False,
            reason_code=exc.reason_code,
            agent_id=agent_id,
            session_id=session_id,
            policy_version="",
            decided_by_layer="tool",
        )
        return _wrap(build_response(authorized=False, reason_code=exc.reason_code))
    except Exception:
        logger.exception("tool %s raised unexpectedly", tool_name)
        caller_id, agent_id, session_id = _extract_audit_identity(event)
        log_decision(
            action=tool_name,
            caller_employee_id=caller_id,
            target_employee_id=None,
            allow=False,
            reason_code=DataUnavailable.reason_code,
            agent_id=agent_id,
            session_id=session_id,
            policy_version="",
            decided_by_layer="tool",
        )
        return _wrap(
            build_response(authorized=False, reason_code=DataUnavailable.reason_code)
        )

    if not isinstance(response, dict) or "authorized" not in response:
        logger.error("tool %s returned bad shape: %r", tool_name, response)
        caller_id, agent_id, session_id = _extract_audit_identity(event)
        log_decision(
            action=tool_name,
            caller_employee_id=caller_id,
            target_employee_id=None,
            allow=False,
            reason_code="DATA_UNAVAILABLE",
            agent_id=agent_id,
            session_id=session_id,
            policy_version="",
            decided_by_layer="tool",
        )
        return _wrap(build_response(authorized=False, reason_code="DATA_UNAVAILABLE"))
    return _wrap(response)
