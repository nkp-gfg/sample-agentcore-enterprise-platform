"""Shared helpers every HR Lambda handler needs.

docs/hr/modules.md § Database roles lists the five pieces the per-tool
handlers reuse (connect, OPA eval, decision_log INSERT, response shape,
identity extraction). Keeping them here also keeps the per-tool files
focused on their one job: build the OPA input, map OPA output to the
response shape, and nothing else.
"""

from .db import connect
from .errors import (
    DataUnavailable,
    HRToolError,
    IdempotencyConflict,
    InvalidItem,
    InvalidLeaveType,
    NotMapped,
    PolicyUnavailable,
    ServiceDisabled,
)
from .identity import get_identity
from .logging_decision import log_decision
from .opa import opa_evaluate
from .response import build_response
from .ssm_flag import is_service_enabled

__all__ = [
    "DataUnavailable",
    "HRToolError",
    "IdempotencyConflict",
    "InvalidItem",
    "InvalidLeaveType",
    "NotMapped",
    "PolicyUnavailable",
    "ServiceDisabled",
    "build_response",
    "connect",
    "get_identity",
    "is_service_enabled",
    "log_decision",
    "opa_evaluate",
]
