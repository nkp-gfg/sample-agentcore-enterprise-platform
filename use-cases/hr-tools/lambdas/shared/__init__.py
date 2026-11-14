"""Shared helpers every HR Lambda handler needs.

docs/hr/modules.md § Database roles lists the shared pieces the per-tool
handlers reuse (connect, policy evaluation, decision_log INSERT, response
shape, identity extraction). Keeping them here keeps the per-tool files
focused on building the policy input and mapping the outcome to the response.
"""

from .authz import POLICY_VERSION, evaluate_policy
from .db import connect
from .errors import (
    DataUnavailable,
    HRToolError,
    IdempotencyConflict,
    InvalidItem,
    InvalidLeaveType,
    NotMapped,
    ServiceDisabled,
)
from .identity import get_identity
from .logging_decision import log_decision
from .response import build_response
from .ssm_flag import is_service_enabled

__all__ = [
    "POLICY_VERSION",
    "DataUnavailable",
    "HRToolError",
    "IdempotencyConflict",
    "InvalidItem",
    "InvalidLeaveType",
    "NotMapped",
    "ServiceDisabled",
    "build_response",
    "connect",
    "evaluate_policy",
    "get_identity",
    "is_service_enabled",
    "log_decision",
]
