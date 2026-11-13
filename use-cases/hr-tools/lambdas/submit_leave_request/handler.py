"""submit_leave_request — insert exactly one pending row, idempotently.

docs/hr/tools.md: arguments `leave_type`, `start_date`, `end_date`,
`reason`, `idempotency_key`. On allow the response is
`{request_id, status: pending, days}`.

Idempotency (docs/hr/policy.md, docs/hr/acceptance.md § H2):

- Same `(employee_id, idempotency_key)` with the same body → return
  the stored row with `authorized: true`. Do NOT insert again.
- Same key with a different `leave_type`, date range, or `reason` →
  `IDEMPOTENCY_CONFLICT`, insert nothing.
- A denied attempt is NOT stored and does NOT consume the key.

The INSERT runs as `hr_writer`. The OPA eval and the idempotency
check run BEFORE the INSERT so a deny never writes. `reason` is held
in Postgres but is NEVER written to the Lambda log or `decision_log`.
"""

from __future__ import annotations

import logging
import uuid

from shared import (
    DataUnavailable,
    build_response,
    connect,
    get_identity,
    is_service_enabled,
    log_decision,
    opa_evaluate,
)
from shared.errors import HRToolError, IdempotencyConflict, InvalidLeaveType
from shared.leave import (
    inclusive_days,
    load_leave_context,
    normalise_leave_type,
    parse_iso_date,
)

logger = logging.getLogger(__name__)

_ACTION = "submit_leave_request"

_SELECT_IDEMPOTENT_SQL = (
    "SELECT request_id, leave_type, start_date, end_date, reason, status "
    "FROM leave_requests "
    "WHERE employee_id = %s AND idempotency_key = %s"
)
_INSERT_SQL = (
    "INSERT INTO leave_requests "
    "(request_id, employee_id, leave_type, start_date, end_date, reason, "
    " status, idempotency_key) "
    "VALUES (%s, %s, %s, %s, %s, %s, 'pending', %s)"
)


def _audit(
    *,
    caller: str,
    agent_id: str,
    session_id: str,
    allow: bool,
    reason_code: str,
    policy_version: str,
    decided_by_layer: str,
) -> None:
    log_decision(
        action=_ACTION,
        caller_employee_id=caller,
        target_employee_id=caller,
        allow=allow,
        reason_code=reason_code,
        agent_id=agent_id,
        session_id=session_id,
        policy_version=policy_version,
        decided_by_layer=decided_by_layer,
    )


def handler(event: dict, context) -> dict:
    caller, agent_id, session_id = get_identity(event)

    if not is_service_enabled():
        _audit(
            caller=caller,
            agent_id=agent_id,
            session_id=session_id,
            allow=False,
            reason_code="SERVICE_DISABLED",
            policy_version="",
            decided_by_layer="tool",
        )
        return build_response(authorized=False, reason_code="SERVICE_DISABLED")

    try:
        leave_type = normalise_leave_type(event.get("leave_type"))
    except InvalidLeaveType as exc:
        _audit(
            caller=caller,
            agent_id=agent_id,
            session_id=session_id,
            allow=False,
            reason_code=exc.reason_code,
            policy_version="",
            decided_by_layer="tool",
        )
        return build_response(authorized=False, reason_code=exc.reason_code)

    try:
        start_date = parse_iso_date(event.get("start_date"), "start_date")
        end_date = parse_iso_date(event.get("end_date"), "end_date")
    except ValueError:
        _audit(
            caller=caller,
            agent_id=agent_id,
            session_id=session_id,
            allow=False,
            reason_code="INVALID_RANGE",
            policy_version="",
            decided_by_layer="tool",
        )
        return build_response(authorized=False, reason_code="INVALID_RANGE")

    reason_text = event.get("reason") or ""
    if not isinstance(reason_text, str):
        reason_text = ""
    idempotency_key = event.get("idempotency_key") or ""
    if not isinstance(idempotency_key, str) or not idempotency_key.strip():
        # Not a spec reason code; INVALID_RANGE is the closest tool-side
        # match without leaking that we specifically needed a key.
        _audit(
            caller=caller,
            agent_id=agent_id,
            session_id=session_id,
            allow=False,
            reason_code="INVALID_RANGE",
            policy_version="",
            decided_by_layer="tool",
        )
        return build_response(authorized=False, reason_code="INVALID_RANGE")

    days = inclusive_days(start_date, end_date)

    # Step 1: Open a hr_writer connection. The same connection does
    # the idempotency SELECT and the final INSERT inside a single
    # transaction, so a concurrent submit cannot slip a second row in
    # between the two statements.
    try:
        connection_ctx = connect("hr_writer")
    except DataUnavailable:
        _audit(
            caller=caller,
            agent_id=agent_id,
            session_id=session_id,
            allow=False,
            reason_code="DATA_UNAVAILABLE",
            policy_version="",
            decided_by_layer="tool",
        )
        return build_response(authorized=False, reason_code="DATA_UNAVAILABLE")

    try:
        with connection_ctx as connection:
            with connection.cursor() as cursor:
                # Step 2: idempotency lookup. A match with the SAME body
                # returns the stored row with authorized=true. A match
                # with a DIFFERENT body is IDEMPOTENCY_CONFLICT; the
                # row is not touched.
                cursor.execute(_SELECT_IDEMPOTENT_SQL, (caller, idempotency_key))
                existing = cursor.fetchone()
                if existing is not None:
                    (
                        stored_request_id,
                        stored_type,
                        stored_start,
                        stored_end,
                        stored_reason,
                        stored_status,
                    ) = existing
                    if (
                        stored_type == leave_type
                        and stored_start.isoformat() == start_date.isoformat()
                        and stored_end.isoformat() == end_date.isoformat()
                        and (stored_reason or "") == reason_text
                    ):
                        # Same body → return stored row.
                        _audit(
                            caller=caller,
                            agent_id=agent_id,
                            session_id=session_id,
                            allow=True,
                            reason_code="ALLOW",
                            policy_version="",
                            decided_by_layer="tool",
                        )
                        return build_response(
                            authorized=True,
                            reason_code="ALLOW",
                            data={
                                "request_id": stored_request_id,
                                "status": stored_status,
                                "days": inclusive_days(stored_start, stored_end),
                            },
                        )
                    try:
                        raise IdempotencyConflict(
                            "idempotency key reused with different body"
                        )
                    except IdempotencyConflict as exc:
                        _audit(
                            caller=caller,
                            agent_id=agent_id,
                            session_id=session_id,
                            allow=False,
                            reason_code=exc.reason_code,
                            policy_version="",
                            decided_by_layer="tool",
                        )
                        return build_response(
                            authorized=False, reason_code=exc.reason_code
                        )

                # Step 3: build the OPA input exactly like
                # check_leave_eligibility does.
                leave_ctx = load_leave_context(
                    cursor,
                    caller_employee_id=caller,
                    leave_type=leave_type,
                    start_date=start_date,
                    end_date=end_date,
                )

                decision = opa_evaluate(
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
                if not decision["allow"]:
                    _audit(
                        caller=caller,
                        agent_id=agent_id,
                        session_id=session_id,
                        allow=False,
                        reason_code=reason_code,
                        policy_version=decision["policy_version"],
                        decided_by_layer="opa",
                    )
                    # Deny: do NOT insert. Do NOT consume the key.
                    return build_response(authorized=False, reason_code=reason_code)

                # Step 4: insert. request_id is generated here; the model
                # never picks one (docs/hr/schema.md).
                request_id = f"lr-{uuid.uuid4()}"
                try:
                    cursor.execute(
                        _INSERT_SQL,
                        (
                            request_id,
                            caller,
                            leave_type,
                            start_date,
                            end_date,
                            reason_text,
                            idempotency_key,
                        ),
                    )
                except Exception as exc:
                    connection.rollback()
                    logger.exception("submit INSERT failed")
                    raise HRToolError("insert failed") from exc

            connection.commit()
    except HRToolError as exc:
        _audit(
            caller=caller,
            agent_id=agent_id,
            session_id=session_id,
            allow=False,
            reason_code=exc.reason_code,
            policy_version="",
            decided_by_layer="tool",
        )
        return build_response(authorized=False, reason_code=exc.reason_code)
    except Exception:
        logger.exception("submit_leave_request transaction failed")
        _audit(
            caller=caller,
            agent_id=agent_id,
            session_id=session_id,
            allow=False,
            reason_code="DATA_UNAVAILABLE",
            policy_version="",
            decided_by_layer="tool",
        )
        return build_response(authorized=False, reason_code="DATA_UNAVAILABLE")

    _audit(
        caller=caller,
        agent_id=agent_id,
        session_id=session_id,
        allow=True,
        reason_code="ALLOW",
        policy_version=decision["policy_version"],
        decided_by_layer="opa",
    )
    return build_response(
        authorized=True,
        reason_code="ALLOW",
        data={"request_id": request_id, "status": "pending", "days": days},
    )
