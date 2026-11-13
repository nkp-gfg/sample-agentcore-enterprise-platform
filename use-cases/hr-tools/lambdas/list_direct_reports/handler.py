"""list_direct_reports — reports of the caller, one hop only.

docs/hr/tools.md: no arguments. The query itself is the rule — see
docs/hr/policy.md: `list_direct_reports` is not an OPA decision, the
query is `manager_id = caller` and `status = active`, and the result
lists ids and names only. There is no `requested_employee_id` field
for this tool; the audit row records the caller as both.
"""

from __future__ import annotations

import logging

from shared import (
    DataUnavailable,
    build_response,
    connect,
    get_identity,
    is_service_enabled,
    log_decision,
)

logger = logging.getLogger(__name__)

_ACTION = "list_direct_reports"
_SELECT_SQL = (
    "SELECT employee_id, full_name FROM employees "
    "WHERE manager_id = %s AND status = 'active' "
    "ORDER BY employee_id"
)


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
            cursor.execute(_SELECT_SQL, (caller,))
            rows = cursor.fetchall() or []
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

    reports = [{"employee_id": r[0], "full_name": r[1]} for r in rows]

    # docs/hr/policy.md pins this: not an OPA decision, so decided_by_layer
    # is `tool`. The audit row still carries agent_id and session_id so
    # the SIEM join to the gateway log works the same way.
    log_decision(
        action=_ACTION,
        caller_employee_id=caller,
        target_employee_id=caller,
        allow=True,
        reason_code="ALLOW",
        agent_id=agent_id,
        session_id=session_id,
        policy_version="",
        decided_by_layer="tool",
    )
    return build_response(
        authorized=True, reason_code="ALLOW", data={"reports": reports}
    )
