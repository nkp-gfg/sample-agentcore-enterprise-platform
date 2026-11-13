"""record_leave_decision — reviewer-only.

docs/hr/tools.md § Arguments: `request_id`, `decision` (approve|reject).
The reviewer is the token's `employee_id`, never an argument. The Cedar
permit for this action is bound to `agent_id == "review-node"` which
no leaf agent ever sets, so a model call cannot reach this Lambda.

docs/hr/policy.md § Rules: allowed only when the stored row is
`pending`, `caller_employee_id` equals the requester's current
`manager_id`, and the caller is not the requester. On allow the row
is updated to the chosen status with `decided_by` and `decided_at`;
on deny nothing is written.
"""

from __future__ import annotations

import datetime as _dt
import logging

from shared import (
    DataUnavailable,
    build_response,
    connect,
    get_identity,
    is_service_enabled,
    log_decision,
    opa_evaluate,
)
from shared.errors import HRToolError

logger = logging.getLogger(__name__)

_ACTION = "record_leave_decision"

_SELECT_REQUEST_SQL = (
    "SELECT lr.employee_id, lr.status, e.manager_id "
    "FROM leave_requests lr "
    "LEFT JOIN employees e ON e.employee_id = lr.employee_id "
    "WHERE lr.request_id = %s"
)
# docs/hr/schema.md § leave_requests: UPDATE must only touch
# status, decided_by, and decided_at. The hr_writer role is granted
# UPDATE on exactly those three columns; anything else is a refused
# statement at the RDS layer.
_UPDATE_SQL = (
    "UPDATE leave_requests "
    "SET status = %s, decided_by = %s, decided_at = %s "
    "WHERE request_id = %s AND status = 'pending'"
)


def _normalise_decision(raw) -> str:
    if raw == "approve":
        return "approved"
    if raw == "reject":
        return "rejected"
    raise HRToolError("decision must be 'approve' or 'reject'")


def handler(event: dict, context) -> dict:
    caller, agent_id, session_id = get_identity(event)

    if not is_service_enabled():
        log_decision(
            action=_ACTION,
            caller_employee_id=caller,
            target_employee_id=None,
            allow=False,
            reason_code="SERVICE_DISABLED",
            agent_id=agent_id,
            session_id=session_id,
            policy_version="",
            decided_by_layer="tool",
        )
        return build_response(authorized=False, reason_code="SERVICE_DISABLED")

    request_id = event.get("request_id")
    if not isinstance(request_id, str) or not request_id.strip():
        log_decision(
            action=_ACTION,
            caller_employee_id=caller,
            target_employee_id=None,
            allow=False,
            reason_code="NOT_REVIEWER",
            agent_id=agent_id,
            session_id=session_id,
            policy_version="",
            decided_by_layer="tool",
        )
        return build_response(authorized=False, reason_code="NOT_REVIEWER")

    try:
        new_status = _normalise_decision(event.get("decision"))
    except HRToolError:
        log_decision(
            action=_ACTION,
            caller_employee_id=caller,
            target_employee_id=None,
            allow=False,
            reason_code="NOT_REVIEWER",
            agent_id=agent_id,
            session_id=session_id,
            policy_version="",
            decided_by_layer="tool",
        )
        return build_response(authorized=False, reason_code="NOT_REVIEWER")

    try:
        with connect("hr_writer") as connection:
            with connection.cursor() as cursor:
                cursor.execute(_SELECT_REQUEST_SQL, (request_id,))
                row = cursor.fetchone()
                if row is None:
                    requester = None
                    request_status = "missing"
                    requester_manager = None
                else:
                    requester, request_status, requester_manager = row

                decision = opa_evaluate(
                    {
                        "action": _ACTION,
                        "caller_employee_id": caller,
                        "requested_employee_id": requester,
                        "request_status": request_status,
                        "requester_manager_id": requester_manager,
                        "agent_id": agent_id,
                    }
                )
                reason_code = decision["reason_code"]
                if not decision["allow"]:
                    log_decision(
                        action=_ACTION,
                        caller_employee_id=caller,
                        target_employee_id=requester,
                        allow=False,
                        reason_code=reason_code,
                        agent_id=agent_id,
                        session_id=session_id,
                        policy_version=decision["policy_version"],
                        decided_by_layer="opa",
                    )
                    return build_response(authorized=False, reason_code=reason_code)

                decided_at = _dt.datetime.now(_dt.UTC)
                cursor.execute(
                    _UPDATE_SQL, (new_status, caller, decided_at, request_id)
                )
                affected = getattr(cursor, "rowcount", 0) or 0
            connection.commit()
    except DataUnavailable:
        log_decision(
            action=_ACTION,
            caller_employee_id=caller,
            target_employee_id=None,
            allow=False,
            reason_code="DATA_UNAVAILABLE",
            agent_id=agent_id,
            session_id=session_id,
            policy_version="",
            decided_by_layer="tool",
        )
        return build_response(authorized=False, reason_code="DATA_UNAVAILABLE")
    except Exception:
        logger.exception("record_leave_decision update failed")
        return build_response(authorized=False, reason_code="DATA_UNAVAILABLE")

    if affected != 1:
        # The row was pending at SELECT time and is no longer pending now;
        # a concurrent reviewer won the race. Treat the loser as
        # NOT_REVIEWER so no second decision is recorded.
        log_decision(
            action=_ACTION,
            caller_employee_id=caller,
            target_employee_id=requester,
            allow=False,
            reason_code="NOT_REVIEWER",
            agent_id=agent_id,
            session_id=session_id,
            policy_version=decision["policy_version"],
            decided_by_layer="tool",
        )
        return build_response(authorized=False, reason_code="NOT_REVIEWER")

    log_decision(
        action=_ACTION,
        caller_employee_id=caller,
        target_employee_id=requester,
        allow=True,
        reason_code="ALLOW",
        agent_id=agent_id,
        session_id=session_id,
        policy_version=decision["policy_version"],
        decided_by_layer="opa",
    )
    return build_response(
        authorized=True,
        reason_code="ALLOW",
        data={
            "request_id": request_id,
            "status": new_status,
            "decided_by": caller,
        },
    )
