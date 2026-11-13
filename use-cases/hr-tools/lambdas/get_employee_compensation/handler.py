"""get_employee_compensation — self or one-hop direct report.

docs/hr/tools.md § Arguments: optional `employee_id` (defaults to the
caller). docs/hr/policy.md § Rules: allowed when the target is active
and either the caller is the target or `target_manager_id` equals the
caller. One hop only. The tool MUST NOT read `base_salary` before OPA
allows — the row is fetched WITHOUT the amount, OPA decides, and only
then does the allow path select the amount.

docs/hr/schema.md § salaries holds the amount on a separate row keyed
by `employee_id`. The read-before-OPA query reads `employees` only
(status, manager, full_name). The allow path then reads `salaries`.
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
    opa_evaluate,
)
from shared.db import connect as _connect  # noqa: F401 — kept for clarity in the module
from shared.errors import HRToolError

logger = logging.getLogger(__name__)

_ACTION = "get_employee_compensation"
_SELECT_TARGET_SQL = (
    "SELECT status, manager_id, full_name FROM employees WHERE employee_id = %s"
)
_SELECT_SALARY_SQL = "SELECT base_salary, currency FROM salaries WHERE employee_id = %s"


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

    # The tool argument `employee_id` maps to the OPA field
    # `requested_employee_id`. The model MAY omit it; the self-read is
    # the default (docs/hr/tools.md). `caller_employee_id` from the
    # argument is ignored — the interceptor already set it.
    requested = event.get("employee_id") or caller
    if not isinstance(requested, str) or not requested.strip():
        requested = caller

    # Read the current row (no salary column) so OPA has the live
    # `manager_id` — docs/hr/policy.md forbids a stale copy inside OPA.
    try:
        with connect("hr_reader") as connection, connection.cursor() as cursor:
            cursor.execute(_SELECT_TARGET_SQL, (requested,))
            row = cursor.fetchone()
    except DataUnavailable:
        log_decision(
            action=_ACTION,
            caller_employee_id=caller,
            target_employee_id=requested,
            allow=False,
            reason_code="DATA_UNAVAILABLE",
            agent_id=agent_id,
            session_id=session_id,
            policy_version="",
            decided_by_layer="tool",
        )
        return build_response(authorized=False, reason_code="DATA_UNAVAILABLE")

    if row is None:
        target_status, target_manager, _full_name = ("unknown", None, None)
    else:
        target_status, target_manager, _full_name = row

    decision = opa_evaluate(
        {
            "action": _ACTION,
            "caller_employee_id": caller,
            "requested_employee_id": requested,
            "target_status": target_status,
            "target_manager_id": target_manager,
            "agent_id": agent_id,
        }
    )
    reason_code = decision["reason_code"]

    log_decision(
        action=_ACTION,
        caller_employee_id=caller,
        target_employee_id=requested,
        allow=decision["allow"],
        reason_code=reason_code,
        agent_id=agent_id,
        session_id=session_id,
        policy_version=decision["policy_version"],
        decided_by_layer="opa",
    )

    if not decision["allow"]:
        return build_response(authorized=False, reason_code=reason_code)

    # Only after OPA allows do we read the amount. Reading it earlier
    # and discarding it on deny would still leak a figure into memory
    # and, eventually, into a trace.
    try:
        with connect("hr_reader") as connection, connection.cursor() as cursor:
            cursor.execute(_SELECT_SALARY_SQL, (requested,))
            amount_row = cursor.fetchone()
            cursor.execute(_SELECT_TARGET_SQL, (requested,))
            target_row = cursor.fetchone()
    except DataUnavailable:
        return build_response(authorized=False, reason_code="DATA_UNAVAILABLE")

    if amount_row is None or target_row is None:
        # Salary row missing after OPA already allowed on the employee
        # row: treat as data gap, never fall through as an allow with
        # null fields.
        return build_response(authorized=False, reason_code="DATA_UNAVAILABLE")

    base_salary, currency = amount_row
    _status, _manager, full_name = target_row
    try:
        amount_number = float(base_salary)
    except (TypeError, ValueError) as exc:
        raise HRToolError("salary row is not numeric") from exc
    return build_response(
        authorized=True,
        reason_code="ALLOW",
        data={
            "employee_id": requested,
            "full_name": full_name,
            "base_salary": amount_number,
            "currency": currency,
        },
    )
