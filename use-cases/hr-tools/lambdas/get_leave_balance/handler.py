"""get_leave_balance — self only.

docs/hr/tools.md: no arguments; always reads the caller.
docs/hr/policy.md: allowed only when `caller == requested`. The tool
sets `requested_employee_id = caller` before evaluating the policy, as the spec
pins for self-only tools.

The response carries `on_probation` and `probation_end_date` so the
specialist can phrase a refusal without re-fetching. The amount
columns are the leave balances (days), not salary — the "no amounts"
rule in docs/hr/policy.md § end refers to salary and allowance; leave
`remaining_days` is not an amount in that sense.
"""

from __future__ import annotations

import datetime as _dt
import logging

from shared import (
    DataUnavailable,
    build_response,
    connect,
    evaluate_policy,
    get_identity,
    is_service_enabled,
    log_decision,
)

logger = logging.getLogger(__name__)

_ACTION = "get_leave_balance"
_SELECT_EMPLOYEE_SQL = (
    "SELECT status, probation_end_date FROM employees WHERE employee_id = %s"
)
_SELECT_BALANCE_SQL = (
    "SELECT leave_type, remaining_days FROM leave_balances WHERE employee_id = %s"
)


def _on_probation(probation_end: _dt.date | None) -> bool:
    if probation_end is None:
        return False
    today = _dt.datetime.now(_dt.UTC).date()
    return probation_end > today


def handler(event: dict, context) -> dict:
    caller, agent_id, session_id = get_identity(event)

    if not is_service_enabled():
        log_decision(
            action=_ACTION,
            caller_employee_id=caller,
            target_employee_id=caller,
            allow=False,
            reason_code="SERVICE_DISABLED",
            agent_id=agent_id,
            session_id=session_id,
            policy_version="",
            decided_by_layer="tool",
        )
        return build_response(authorized=False, reason_code="SERVICE_DISABLED")

    try:
        with connect("hr_reader") as connection, connection.cursor() as cursor:
            cursor.execute(_SELECT_EMPLOYEE_SQL, (caller,))
            employee_row = cursor.fetchone()
            cursor.execute(_SELECT_BALANCE_SQL, (caller,))
            balance_rows = cursor.fetchall() or []
    except DataUnavailable:
        log_decision(
            action=_ACTION,
            caller_employee_id=caller,
            target_employee_id=caller,
            allow=False,
            reason_code="DATA_UNAVAILABLE",
            agent_id=agent_id,
            session_id=session_id,
            policy_version="",
            decided_by_layer="tool",
        )
        return build_response(authorized=False, reason_code="DATA_UNAVAILABLE")

    decision = evaluate_policy(
        {
            "action": _ACTION,
            "caller_employee_id": caller,
            "requested_employee_id": caller,
            "agent_id": agent_id,
        }
    )
    reason_code = decision["reason_code"]
    log_decision(
        action=_ACTION,
        caller_employee_id=caller,
        target_employee_id=caller,
        allow=decision["allow"],
        reason_code=reason_code,
        agent_id=agent_id,
        session_id=session_id,
        policy_version=decision["policy_version"],
        decided_by_layer="policy",
    )

    if not decision["allow"]:
        return build_response(authorized=False, reason_code=reason_code)

    if employee_row is None:
        return build_response(authorized=False, reason_code="DATA_UNAVAILABLE")

    _status, probation_end = employee_row
    balances: dict[str, float] = {"annual": 0.0, "sick": 0.0}
    for leave_type, remaining in balance_rows:
        if leave_type in balances:
            try:
                balances[leave_type] = float(remaining)
            except (TypeError, ValueError):
                balances[leave_type] = 0.0
    return build_response(
        authorized=True,
        reason_code="ALLOW",
        data={
            "annual": balances["annual"],
            "sick": balances["sick"],
            "on_probation": _on_probation(probation_end),
            "probation_end_date": (
                probation_end.isoformat() if probation_end is not None else None
            ),
        },
    )
