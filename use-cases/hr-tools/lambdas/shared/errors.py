"""Reason codes the Lambda assigns before authorization policy evaluation.

docs/hr/policy.md § Reason codes lists the first-match order. The policy
evaluator (`shared/authz.py`) owns `ALLOW`, `NOT_AUTHORIZED`,
`PROBATION_PERIOD`, `INVALID_RANGE`, `INSUFFICIENT_BALANCE`, `OVERLAP`, and
`NOT_REVIEWER`. Everything in this file is a pre-policy tool-layer error.

Each exception carries its reason code as a class attribute so the handler
can map a raise straight into `build_response(authorized=False, reason_code=...)`
without a lookup table.
"""


class HRToolError(Exception):
    """Base exception. Default reason is `NOT_AUTHORIZED` so an unexpected
    subclass can never fall open."""

    reason_code: str = "NOT_AUTHORIZED"


class ServiceDisabled(HRToolError):
    reason_code = "SERVICE_DISABLED"


class DataUnavailable(HRToolError):
    reason_code = "DATA_UNAVAILABLE"


class NotMapped(HRToolError):
    reason_code = "NOT_MAPPED"


class InvalidLeaveType(HRToolError):
    reason_code = "INVALID_LEAVE_TYPE"


class InvalidItem(HRToolError):
    reason_code = "INVALID_ITEM"


class IdempotencyConflict(HRToolError):
    reason_code = "IDEMPOTENCY_CONFLICT"
