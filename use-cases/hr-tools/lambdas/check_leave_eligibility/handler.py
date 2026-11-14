"""check_leave_eligibility — pure read, no row created.

docs/hr/tools.md: arguments `leave_type` (annual|sick), `start_date`,
`end_date`. The response is `{eligible, days}` on allow and a reason
code on deny. Everything a submit would do except the INSERT runs
here — probation, invalid range, insufficient balance, overlap — so
the specialist can offer the form only when the eligible check
returned true.
"""

from __future__ import annotations

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
from shared.errors import InvalidLeaveType
from shared.leave import (
    inclusive_days,
    load_leave_context,
    normalise_leave_type,
    parse_iso_date,
)

logger = logging.getLogger(__name__)

_ACTION = "check_leave_eligibility"


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
        leave_type = normalise_leave_type(event.get("leave_type"))
    except InvalidLeaveType as exc:
        log_decision(
            action=_ACTION,
            caller_employee_id=caller,
            target_employee_id=caller,
            allow=False,
            reason_code=exc.reason_code,
            agent_id=agent_id,
            session_id=session_id,
            policy_version="",
            decided_by_layer="tool",
        )
        return build_response(authorized=False, reason_code=exc.reason_code)

    try:
        start_date = parse_iso_date(event.get("start_date"), "start_date")
        end_date = parse_iso_date(event.get("end_date"), "end_date")
    except ValueError:
        # An unparseable date shape is treated as invalid range so the
        # model does not learn which side was wrong. The policy evaluator
        # produces the same reason when end < start.
        log_decision(
            action=_ACTION,
            caller_employee_id=caller,
            target_employee_id=caller,
            allow=False,
            reason_code="INVALID_RANGE",
            agent_id=agent_id,
            session_id=session_id,
            policy_version="",
            decided_by_layer="tool",
        )
        return build_response(authorized=False, reason_code="INVALID_RANGE")

    days = inclusive_days(start_date, end_date)

    try:
        with connect("hr_reader") as connection, connection.cursor() as cursor:
            leave_ctx = load_leave_context(
                cursor,
                caller_employee_id=caller,
                leave_type=leave_type,
                start_date=start_date,
                end_date=end_date,
            )
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
            "start_date": start_date.isoformat(),
            "end_date": end_date.isoformat(),
            "days": days,
            "remaining_days": leave_ctx["remaining_days"],
            "on_probation": leave_ctx["on_probation"],
            "overlaps_existing": leave_ctx["overlaps_existing"],
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

    return build_response(
        authorized=True,
        reason_code="ALLOW",
        data={"eligible": True, "days": days},
    )
