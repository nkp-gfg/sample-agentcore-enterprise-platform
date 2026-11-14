"""get_allowance — self-only allowance for the previous calendar month.

docs/hr/tools.md § Arguments: `item_type` (v1 accepts `telephone` only),
optional `period` (default is the previous UTC calendar month). The
allow path returns `{item_type, period, amount, currency}`. A self call
with no row is `authorized: true` with `amount: null` — it is NOT
`NOT_AUTHORIZED`, because that would leak the fact that a row exists
for someone else.

docs/hr/policy.md § Rules: `caller_employee_id == requested_employee_id`.
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
from shared.errors import HRToolError, InvalidItem

logger = logging.getLogger(__name__)

_ACTION = "get_allowance"
_VALID_ITEMS = {"telephone"}
_SELECT_SQL = (
    "SELECT amount, currency FROM payroll_items "
    "WHERE employee_id = %s AND item_type = %s AND period = %s"
)


def _previous_period(today: _dt.date) -> str:
    """Return `YYYY-MM` for the previous calendar month in UTC.

    docs/hr/tools.md: January rolls to December of the previous year.
    On 2026-11-13 the period is `2026-10`.
    """
    if today.month == 1:
        return f"{today.year - 1:04d}-12"
    return f"{today.year:04d}-{today.month - 1:02d}"


def _validate_period(raw) -> str:
    if raw is None:
        return _previous_period(_dt.datetime.now(_dt.UTC).date())
    if not isinstance(raw, str):
        raise InvalidItem("period must be a YYYY-MM string")
    try:
        _dt.datetime.strptime(raw, "%Y-%m")
    except ValueError as exc:
        raise InvalidItem(f"period must be YYYY-MM, got {raw!r}") from exc
    return raw


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

    item_type = event.get("item_type")
    if item_type not in _VALID_ITEMS:
        log_decision(
            action=_ACTION,
            caller_employee_id=caller,
            target_employee_id=caller,
            allow=False,
            reason_code="INVALID_ITEM",
            agent_id=agent_id,
            session_id=session_id,
            policy_version="",
            decided_by_layer="tool",
        )
        return build_response(authorized=False, reason_code="INVALID_ITEM")

    try:
        period = _validate_period(event.get("period"))
    except InvalidItem as exc:
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

    try:
        with connect("hr_reader") as connection, connection.cursor() as cursor:
            cursor.execute(_SELECT_SQL, (caller, item_type, period))
            row = cursor.fetchone()
    except DataUnavailable:
        return build_response(authorized=False, reason_code="DATA_UNAVAILABLE")

    if row is None:
        # Self-call with no row: amount is null, NOT a deny. See
        # docs/hr/tools.md § Responses — "A self call with no row is
        # `authorized` true and `amount` null."
        return build_response(
            authorized=True,
            reason_code="ALLOW",
            data={
                "item_type": item_type,
                "period": period,
                "amount": None,
                "currency": None,
            },
        )

    amount, currency = row
    try:
        amount_number = float(amount)
    except (TypeError, ValueError) as exc:
        raise HRToolError("allowance amount is not numeric") from exc
    return build_response(
        authorized=True,
        reason_code="ALLOW",
        data={
            "item_type": item_type,
            "period": period,
            "amount": amount_number,
            "currency": currency,
        },
    )
