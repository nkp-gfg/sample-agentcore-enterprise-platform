"""Shared leave-check logic.

`check_leave_eligibility` and `submit_leave_request` take the same
arguments and run the same OPA rule (docs/hr/policy.md § Rules). Both
need: the caller's probation state, the remaining balance for the
requested leave type, and whether another `pending` row of either
type intersects the inclusive range. Keeping the loader here keeps
the two handlers free of SQL drift.
"""

from __future__ import annotations

import datetime as _dt
import logging

from .errors import DataUnavailable, InvalidLeaveType

logger = logging.getLogger(__name__)

VALID_LEAVE_TYPES = {"annual", "sick"}


def normalise_leave_type(raw) -> str:
    """Return the leave type when valid, else raise InvalidLeaveType.

    docs/hr/policy.md reason code `INVALID_LEAVE_TYPE` is tool-layer
    (not Rego). We refuse here so the OPA eval never sees a
    non-conforming value.
    """
    if not isinstance(raw, str) or raw not in VALID_LEAVE_TYPES:
        raise InvalidLeaveType(f"leave_type must be one of {sorted(VALID_LEAVE_TYPES)}")
    return raw


def parse_iso_date(raw, field: str) -> _dt.date:
    """Parse `YYYY-MM-DD` or raise a ValueError with the field name."""
    if not isinstance(raw, str):
        # Deliberately ValueError (not TypeError): the handler catches
        # this one shape and maps it to the INVALID_RANGE reason code.
        raise ValueError(f"{field} must be an ISO date string")  # noqa: TRY004
    try:
        return _dt.date.fromisoformat(raw)
    except ValueError as exc:
        raise ValueError(f"{field} is not a valid ISO date: {raw!r}") from exc


def inclusive_days(start_date: _dt.date, end_date: _dt.date) -> int:
    """docs/hr/policy.md § Input `days` = (end - start) + 1.

    Same-day is 1. An inverted range returns a non-positive number so
    the Rego `INVALID_RANGE` rule catches it instead of shortcutting
    to `INSUFFICIENT_BALANCE`.
    """
    return (end_date - start_date).days + 1


def on_probation(
    probation_end: _dt.date | None, *, today: _dt.date | None = None
) -> bool:
    """docs/hr/schema.md: `probation_end_date` after today is probation.
    The end date itself is NOT probation."""
    if probation_end is None:
        return False
    today = today or _dt.datetime.now(_dt.UTC).date()
    return probation_end > today


_SELECT_PROBATION_SQL = (
    "SELECT probation_end_date FROM employees "
    "WHERE employee_id = %s AND status = 'active'"
)
_SELECT_BALANCE_SQL = (
    "SELECT remaining_days FROM leave_balances "
    "WHERE employee_id = %s AND leave_type = %s"
)
# docs/hr/policy.md § overlaps_existing: ANOTHER pending row for this
# employee intersects the inclusive range, of EITHER leave type.
_SELECT_OVERLAP_SQL = (
    "SELECT 1 FROM leave_requests "
    "WHERE employee_id = %s AND status = 'pending' "
    "AND start_date <= %s AND end_date >= %s "
    "LIMIT 1"
)


def load_leave_context(
    cursor,
    *,
    caller_employee_id: str,
    leave_type: str,
    start_date: _dt.date,
    end_date: _dt.date,
) -> dict:
    """Return the fields docs/hr/policy.md § Input adds for leave actions.

    Raises `DataUnavailable` if the employee row is missing or
    terminated — that is a data gap, not an auth decision, so the
    handler must map it to `DATA_UNAVAILABLE`.
    """
    cursor.execute(_SELECT_PROBATION_SQL, (caller_employee_id,))
    employee_row = cursor.fetchone()
    if employee_row is None:
        raise DataUnavailable("caller has no active employee row")
    probation_end = employee_row[0]

    cursor.execute(_SELECT_BALANCE_SQL, (caller_employee_id, leave_type))
    balance_row = cursor.fetchone()
    remaining = 0.0
    if balance_row is not None:
        try:
            remaining = float(balance_row[0])
        except (TypeError, ValueError):
            remaining = 0.0

    cursor.execute(_SELECT_OVERLAP_SQL, (caller_employee_id, end_date, start_date))
    overlap_row = cursor.fetchone()

    return {
        "on_probation": on_probation(probation_end),
        "remaining_days": remaining,
        "overlaps_existing": overlap_row is not None,
    }
