"""Append one row to `decision_log` as `hr_audit`.

docs/hr/schema.md § decision_log is append-only (hr_audit's grants are
INSERT only, no UPDATE, no DELETE, no SELECT). docs/hr/policy.md § end
locks the row: action, caller, target, allow, reason_code, agent_id,
session_id, trace_id, decided_by_layer (`opa` or `tool`), policy_version.
No amounts. No leave reason. No `full_name`.

The handler writes the same row to the Lambda log as one JSON line so
the SIEM subscription filter picks it up. Keeping the two writes in one
function makes it hard to drop one of them in a refactor.
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any

from .db import connect
from .errors import DataUnavailable

logger = logging.getLogger(__name__)

_INSERT_SQL = """
INSERT INTO decision_log
    (action, caller_employee_id, target_employee_id, allow, reason_code,
     agent_id, session_id, trace_id, decided_by_layer, policy_version)
VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
"""


def _trace_id_from_env() -> str | None:
    # Lambda injects `_X_AMZN_TRACE_ID` when X-Ray is on. Example:
    #   Root=1-abc...;Parent=def...;Sampled=1
    header = os.environ.get("_X_AMZN_TRACE_ID") or ""
    for part in header.split(";"):
        key, sep, value = part.strip().partition("=")
        if sep and key == "Root" and value:
            return value
    return None


def log_decision(
    *,
    action: str,
    caller_employee_id: str,
    target_employee_id: str | None,
    allow: bool,
    reason_code: str,
    agent_id: str,
    session_id: str,
    policy_version: str,
    decided_by_layer: str,
    trace_id: str | None = None,
) -> None:
    """Insert one row AND emit one JSON log line.

    Every field in the row MUST be free of amounts and leave text —
    the contract in docs/hr/policy.md is "no amounts, no leave reason".
    This function never sees those because its signature does not accept
    them. That is the control: passing an amount would be a code change.

    A failure to INSERT is logged but does NOT raise, so a transient
    `hr_audit` outage cannot turn an allow into a `DATA_UNAVAILABLE`.
    docs/hr/acceptance.md § H4 expects one audit row per call, but the
    row is not the decision; the response is. If the row is missing the
    SIEM will see the JSON log line and the operator can reconcile.
    """
    trace_id = trace_id or _trace_id_from_env()
    _emit_json_line(
        action=action,
        caller_employee_id=caller_employee_id,
        target_employee_id=target_employee_id,
        allow=allow,
        reason_code=reason_code,
        agent_id=agent_id,
        session_id=session_id,
        trace_id=trace_id,
        decided_by_layer=decided_by_layer,
        policy_version=policy_version,
    )
    try:
        with connect("hr_audit") as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    _INSERT_SQL,
                    (
                        action,
                        caller_employee_id,
                        target_employee_id,
                        allow,
                        reason_code,
                        agent_id,
                        session_id,
                        trace_id,
                        decided_by_layer,
                        policy_version,
                    ),
                )
            connection.commit()
    except DataUnavailable:
        logger.exception("decision_log INSERT failed (DataUnavailable)")
    except Exception:
        logger.exception("decision_log INSERT failed")


def _emit_json_line(**row: Any) -> None:
    # One JSON object per call is the SIEM subscription filter contract
    # in docs/hr/modules.md § Kill switch and audit export. Keep keys
    # sorted so a log search can rely on field order being stable.
    logger.info(json.dumps(row, sort_keys=True, default=str))
