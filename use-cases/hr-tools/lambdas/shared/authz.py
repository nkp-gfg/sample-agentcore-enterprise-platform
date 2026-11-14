"""Deterministic in-process HR authorization policy.

Replaces external policy binaries and subprocess evaluation with a pure-Python
rule evaluator that has zero external dependencies, zero file I/O, and zero
subprocess overhead.

Contract (see docs/hr/policy.md):
  - The tool handler builds `document` from gateway-validated JWT claims and
    live PostgreSQL state. Model-supplied arguments never populate
    `caller_employee_id` or `agent_id`.
  - Default decision is deny (`allow=False`, `reason_code="NOT_AUTHORIZED"`).
  - Reason-code precedence follows the exact first-match order in
    docs/hr/policy.md:
      ALLOW -> PROBATION_PERIOD -> INVALID_RANGE -> INSUFFICIENT_BALANCE
      -> OVERLAP -> NOT_REVIEWER -> NOT_AUTHORIZED.
  - Every change to a rule in this file MUST bump `POLICY_VERSION` in the
    same commit so `decision_log` records which rule version ran.
"""

from __future__ import annotations

from typing import Any

POLICY_VERSION = "2026-11-14.1"

_LEAVE_MUTATION_ACTIONS = frozenset(
    {"check_leave_eligibility", "submit_leave_request"}
)


def _non_empty_str(value: Any) -> str | None:
    if isinstance(value, str):
        stripped = value.strip()
        if stripped:
            return stripped
    return None


def _number(value: Any) -> float | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    return None


def evaluate_policy(document: dict[str, Any]) -> dict[str, Any]:
    """Evaluate HR authorization rules and return `{allow, reason_code, policy_version}`."""
    if not isinstance(document, dict):
        return {
            "allow": False,
            "reason_code": "NOT_AUTHORIZED",
            "policy_version": POLICY_VERSION,
        }

    action = _non_empty_str(document.get("action"))
    caller = _non_empty_str(document.get("caller_employee_id"))
    requested = _non_empty_str(document.get("requested_employee_id"))

    if action == "get_employee_compensation":
        target_status = _non_empty_str(document.get("target_status"))
        target_manager = _non_empty_str(document.get("target_manager_id"))
        allowed = bool(
            caller
            and requested
            and target_status == "active"
            and (caller == requested or (target_manager and target_manager == caller))
        )
        return {
            "allow": allowed,
            "reason_code": "ALLOW" if allowed else "NOT_AUTHORIZED",
            "policy_version": POLICY_VERSION,
        }

    if action in {"get_leave_balance", "get_allowance"}:
        allowed = bool(caller and requested and caller == requested)
        return {
            "allow": allowed,
            "reason_code": "ALLOW" if allowed else "NOT_AUTHORIZED",
            "policy_version": POLICY_VERSION,
        }

    if action in _LEAVE_MUTATION_ACTIONS:
        if not caller or not requested or caller != requested:
            return {
                "allow": False,
                "reason_code": "NOT_AUTHORIZED",
                "policy_version": POLICY_VERSION,
            }
        if bool(document.get("on_probation")):
            return {
                "allow": False,
                "reason_code": "PROBATION_PERIOD",
                "policy_version": POLICY_VERSION,
            }
        start_date = _non_empty_str(document.get("start_date"))
        end_date = _non_empty_str(document.get("end_date"))
        if not start_date or not end_date or end_date < start_date:
            return {
                "allow": False,
                "reason_code": "INVALID_RANGE",
                "policy_version": POLICY_VERSION,
            }
        days = _number(document.get("days"))
        remaining = _number(document.get("remaining_days"))
        if days is None or remaining is None or days > remaining:
            return {
                "allow": False,
                "reason_code": "INSUFFICIENT_BALANCE",
                "policy_version": POLICY_VERSION,
            }
        if bool(document.get("overlaps_existing")):
            return {
                "allow": False,
                "reason_code": "OVERLAP",
                "policy_version": POLICY_VERSION,
            }
        return {
            "allow": True,
            "reason_code": "ALLOW",
            "policy_version": POLICY_VERSION,
        }

    if action == "record_leave_decision":
        request_status = _non_empty_str(document.get("request_status"))
        requester_manager = _non_empty_str(document.get("requester_manager_id"))
        allowed = bool(
            caller
            and requested
            and request_status == "pending"
            and requester_manager is not None
            and requester_manager == caller
            and caller != requested
        )
        return {
            "allow": allowed,
            "reason_code": "ALLOW" if allowed else "NOT_REVIEWER",
            "policy_version": POLICY_VERSION,
        }

    return {
        "allow": False,
        "reason_code": "NOT_AUTHORIZED",
        "policy_version": POLICY_VERSION,
    }
