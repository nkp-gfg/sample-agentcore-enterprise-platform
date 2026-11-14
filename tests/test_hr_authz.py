"""H2 acceptance: the deterministic HR authorisation policy (`shared/authz.py`).

The spec is `docs/hr/policy.md` (rules and reason-code order) and
`docs/hr/acceptance.md` ("H2, before any deploy" table). The seed is the
demo in `docs/hr/schema.md`. The test clock is frozen at 2026-11-13.

H2 does not deploy anything. It evaluates the pure-Python `evaluate_policy`
module bundled into every H4 Lambda — zero external binaries or subprocesses.
"""

from __future__ import annotations

import datetime as _dt
import importlib.util
import sys
from pathlib import Path

import pytest

LAMBDAS_DIR = Path(__file__).resolve().parents[1] / "use-cases" / "hr-tools" / "lambdas"
AUTHZ_FILE = LAMBDAS_DIR / "shared" / "authz.py"

CLOCK = _dt.date(2026, 11, 13)


def _load_evaluate_policy():
    assert AUTHZ_FILE.is_file(), f"authz module missing: {AUTHZ_FILE}"
    spec = importlib.util.spec_from_file_location("hr_shared_authz", AUTHZ_FILE)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules["hr_shared_authz"] = mod
    spec.loader.exec_module(mod)
    return mod.evaluate_policy


evaluate_policy = _load_evaluate_policy()


# ---------------------------------------------------------------------------
# Seed, matching docs/hr/schema.md
# ---------------------------------------------------------------------------


def _employee(
    employee_id: str,
    manager_id: str | None,
    status: str = "active",
    probation_end: str = "2020-07-01",
) -> dict:
    return {
        "employee_id": employee_id,
        "manager_id": manager_id,
        "status": status,
        "probation_end_date": probation_end,
    }


SEED: dict[str, dict] = {
    e["employee_id"]: e
    for e in [
        _employee("M1", None),
        _employee("E1", "M1"),
        _employee("E2", "M1"),
        _employee("P1", "M1", probation_end="2027-03-01"),
        _employee("R1", "E1"),
        _employee("R2", "E1"),
        _employee("R3", "E1"),
        _employee("R4", "E1"),
        _employee("X1", "M1", status="terminated"),
    ]
}

LEAVE_BALANCE: dict[tuple[str, str], float] = {
    (eid, kind): days
    for eid in SEED
    for kind, days in (("annual", 14.0), ("sick", 10.0))
}


# ---------------------------------------------------------------------------
# Input builders
# ---------------------------------------------------------------------------


def salary_input(
    caller: str,
    target: str,
    *,
    override_manager_id: str | None | object = ...,
    override_status: str | None = None,
    agent_id: str = "compensation",
) -> dict:
    row = SEED.get(target)
    target_manager = (
        override_manager_id
        if override_manager_id is not ...
        else (row["manager_id"] if row else None)
    )
    target_status = override_status or (row["status"] if row else "unknown")
    return {
        "action": "get_employee_compensation",
        "caller_employee_id": caller,
        "requested_employee_id": target,
        "target_status": target_status,
        "target_manager_id": target_manager,
        "agent_id": agent_id,
    }


def balance_input(caller: str, *, agent_id: str = "leave-balance") -> dict:
    return {
        "action": "get_leave_balance",
        "caller_employee_id": caller,
        "requested_employee_id": caller,
        "agent_id": agent_id,
    }


def allowance_input(caller: str, target: str, *, agent_id: str = "allowance") -> dict:
    return {
        "action": "get_allowance",
        "caller_employee_id": caller,
        "requested_employee_id": target,
        "agent_id": agent_id,
    }


def _probation(employee_id: str) -> bool:
    row = SEED[employee_id]
    return _dt.date.fromisoformat(row["probation_end_date"]) > CLOCK


def _days(start_date: str, end_date: str) -> int:
    start = _dt.date.fromisoformat(start_date)
    end = _dt.date.fromisoformat(end_date)
    return (end - start).days + 1


def leave_input(
    action: str,
    caller: str,
    *,
    leave_type: str = "annual",
    start_date: str = "2026-11-16",
    end_date: str = "2026-11-18",
    remaining_override: float | None = None,
    days_override: int | None = None,
    overlaps_existing: bool = False,
    agent_id: str | None = None,
) -> dict:
    remaining = (
        remaining_override
        if remaining_override is not None
        else LEAVE_BALANCE[(caller, leave_type)]
    )
    days = days_override if days_override is not None else _days(start_date, end_date)
    if agent_id is None:
        agent_id = (
            "leave-eligibility"
            if action == "check_leave_eligibility"
            else "leave-submit"
        )
    return {
        "action": action,
        "caller_employee_id": caller,
        "requested_employee_id": caller,
        "on_probation": _probation(caller),
        "start_date": start_date,
        "end_date": end_date,
        "days": days,
        "remaining_days": remaining,
        "overlaps_existing": overlaps_existing,
        "agent_id": agent_id,
    }


def decision_input(
    caller: str,
    requester: str,
    *,
    request_status: str = "pending",
    requester_manager_id: str | None | object = ...,
    agent_id: str = "review-node",
) -> dict:
    row = SEED.get(requester)
    manager = (
        requester_manager_id
        if requester_manager_id is not ...
        else (row["manager_id"] if row else None)
    )
    return {
        "action": "record_leave_decision",
        "caller_employee_id": caller,
        "requested_employee_id": requester,
        "request_status": request_status,
        "requester_manager_id": manager,
        "agent_id": agent_id,
    }


def _assert_allow(result: dict) -> None:
    assert result["allow"] is True, result
    assert result["reason_code"] == "ALLOW", result
    assert result["policy_version"], result


def _assert_deny(result: dict, code: str) -> None:
    assert result["allow"] is False, result
    assert result["reason_code"] == code, result


# ---------------------------------------------------------------------------
# Salary (get_employee_compensation)
# ---------------------------------------------------------------------------


class TestSalary:
    def test_e1_reads_own_salary_is_allowed(self):
        _assert_allow(evaluate_policy(salary_input("E1", "E1")))

    def test_m1_reads_own_salary_is_allowed(self):
        _assert_allow(evaluate_policy(salary_input("M1", "M1")))

    def test_r1_reads_own_salary_is_allowed(self):
        _assert_allow(evaluate_policy(salary_input("R1", "R1")))

    @pytest.mark.parametrize("report", ["R1", "R2", "R3", "R4"])
    def test_e1_reads_direct_reports(self, report):
        _assert_allow(evaluate_policy(salary_input("E1", report)))

    @pytest.mark.parametrize("target", ["M1", "E2", "X1"])
    def test_e1_cannot_read_manager_peer_or_terminated(self, target):
        _assert_deny(evaluate_policy(salary_input("E1", target)), "NOT_AUTHORIZED")

    def test_m1_reads_direct_report_e1(self):
        _assert_allow(evaluate_policy(salary_input("M1", "E1")))

    def test_m1_cannot_read_skip_level_r1(self):
        _assert_deny(evaluate_policy(salary_input("M1", "R1")), "NOT_AUTHORIZED")

    def test_transfer_moves_salary_access(self):
        under_e2 = {
            "action": "get_employee_compensation",
            "caller_employee_id": "M1",
            "requested_employee_id": "E1",
            "target_status": "active",
            "target_manager_id": "E2",
            "agent_id": "compensation",
        }
        _assert_deny(evaluate_policy(under_e2), "NOT_AUTHORIZED")
        under_e2["caller_employee_id"] = "E2"
        _assert_allow(evaluate_policy(under_e2))

    def test_unknown_id_is_not_authorized(self):
        unknown = {
            "action": "get_employee_compensation",
            "caller_employee_id": "E1",
            "requested_employee_id": "Z9",
            "target_status": "unknown",
            "target_manager_id": None,
            "agent_id": "compensation",
        }
        _assert_deny(evaluate_policy(unknown), "NOT_AUTHORIZED")

    def test_terminated_target_denied_even_when_caller_is_self(self):
        _assert_deny(
            evaluate_policy(salary_input("X1", "X1", override_status="terminated")),
            "NOT_AUTHORIZED",
        )


# ---------------------------------------------------------------------------
# Leave balance & Allowance
# ---------------------------------------------------------------------------


class TestLeaveBalance:
    def test_self_allowed(self):
        _assert_allow(evaluate_policy(balance_input("E1")))

    def test_balance_request_by_different_caller_is_denied(self):
        sneaky = {
            "action": "get_leave_balance",
            "caller_employee_id": "E1",
            "requested_employee_id": "M1",
            "agent_id": "leave-balance",
        }
        _assert_deny(evaluate_policy(sneaky), "NOT_AUTHORIZED")


class TestAllowance:
    def test_self_allowance_allowed(self):
        _assert_allow(evaluate_policy(allowance_input("E1", "E1")))

    def test_e1_cannot_read_m1_allowance(self):
        _assert_deny(
            evaluate_policy(allowance_input("E1", "M1")),
            "NOT_AUTHORIZED",
        )


# ---------------------------------------------------------------------------
# Leave check and submit
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("action", ["check_leave_eligibility", "submit_leave_request"])
class TestLeaveCheckAndSubmit:
    def test_p1_blocked_by_probation(self, action):
        _assert_deny(evaluate_policy(leave_input(action, "P1")), "PROBATION_PERIOD")

    def test_invalid_range(self, action):
        inverted = leave_input(
            action,
            "E1",
            start_date="2026-11-18",
            end_date="2026-11-16",
            days_override=-1,
        )
        _assert_deny(evaluate_policy(inverted), "INVALID_RANGE")

    def test_insufficient_balance(self, action):
        big = leave_input(
            action,
            "E1",
            start_date="2026-11-16",
            end_date="2026-12-25",
        )
        _assert_deny(evaluate_policy(big), "INSUFFICIENT_BALANCE")

    def test_overlap(self, action):
        overlap = leave_input(action, "E1", overlaps_existing=True)
        _assert_deny(evaluate_policy(overlap), "OVERLAP")

    def test_happy_path(self, action):
        _assert_allow(evaluate_policy(leave_input(action, "E1")))

    def test_probation_beats_overlap(self, action):
        pathological = leave_input(action, "P1", overlaps_existing=True)
        _assert_deny(evaluate_policy(pathological), "PROBATION_PERIOD")

    def test_range_beats_balance(self, action):
        pathological = leave_input(
            action,
            "E1",
            start_date="2026-11-18",
            end_date="2026-11-16",
            days_override=100,
        )
        _assert_deny(evaluate_policy(pathological), "INVALID_RANGE")


# ---------------------------------------------------------------------------
# Manager decision (record_leave_decision)
# ---------------------------------------------------------------------------


class TestRecordLeaveDecision:
    def test_direct_manager_approves_pending(self):
        _assert_allow(evaluate_policy(decision_input("M1", "E1")))

    def test_requester_cannot_decide_own_request(self):
        doc = decision_input("E1", "E1", requester_manager_id="E1")
        _assert_deny(evaluate_policy(doc), "NOT_REVIEWER")

    def test_wrong_reviewer_denied(self):
        _assert_deny(
            evaluate_policy(decision_input("E2", "E1")),
            "NOT_REVIEWER",
        )

    def test_skip_level_denied(self):
        _assert_deny(
            evaluate_policy(decision_input("M1", "R1")),
            "NOT_REVIEWER",
        )

    def test_already_approved_denied(self):
        doc = decision_input("M1", "E1", request_status="approved")
        _assert_deny(evaluate_policy(doc), "NOT_REVIEWER")

    def test_already_rejected_denied(self):
        doc = decision_input("M1", "E1", request_status="rejected")
        _assert_deny(evaluate_policy(doc), "NOT_REVIEWER")


# ---------------------------------------------------------------------------
# Policy metadata & defensive edge cases
# ---------------------------------------------------------------------------


class TestPolicyMetadata:
    def test_policy_version_is_non_empty(self):
        result = evaluate_policy(salary_input("E1", "E1"))
        assert isinstance(result["policy_version"], str)
        assert result["policy_version"].strip(), result

    def test_default_deny_on_unknown_action(self):
        novel = {
            "action": "list_all_employees",
            "caller_employee_id": "E1",
            "requested_employee_id": "E1",
            "agent_id": "compensation",
        }
        _assert_deny(evaluate_policy(novel), "NOT_AUTHORIZED")

    def test_malformed_or_missing_fields_fail_closed(self):
        _assert_deny(evaluate_policy({}), "NOT_AUTHORIZED")
        _assert_deny(evaluate_policy({"action": "get_leave_balance"}), "NOT_AUTHORIZED")
        _assert_deny(
            evaluate_policy(
                {
                    "action": "record_leave_decision",
                    "caller_employee_id": "",
                    "requested_employee_id": "",
                    "request_status": "pending",
                    "requester_manager_id": "",
                }
            ),
            "NOT_REVIEWER",
        )
