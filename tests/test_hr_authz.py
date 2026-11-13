"""H2 acceptance: the HR authorisation policy.

The spec is `docs/hr/policy.md` (rules and reason-code order) and
`docs/hr/acceptance.md` ("H2, before any deploy" table). The seed is the
demo in `docs/hr/schema.md`. The test clock is frozen at 2026-11-13.

H2 does not deploy anything. It evaluates `use-cases/hr-tools/policy/authz.rego`
against synthetic inputs with the OPA CLI. Idempotency and the
reason codes the Lambda assigns before evaluation
(`SERVICE_DISABLED`, `POLICY_UNAVAILABLE`, `DATA_UNAVAILABLE`, `NOT_MAPPED`,
`INVALID_LEAVE_TYPE`, `INVALID_ITEM`, `IDEMPOTENCY_CONFLICT`) are covered by
H4's Lambda tests, not here.

When `opa` is not on `$PATH` the suite skips with a clear message. The
Lambda in H4 evaluates the same file with the same CLI contract, so a
green run here is also the Rego-level evidence for H4.
"""

from __future__ import annotations

import datetime as _dt
import json
import shutil
import subprocess
from pathlib import Path

import pytest

POLICY_FILE = (
    Path(__file__).resolve().parents[1]
    / "use-cases"
    / "hr-tools"
    / "policy"
    / "authz.rego"
)

CLOCK = _dt.date(2026, 11, 13)


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
# OPA harness
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def opa_binary() -> str:
    binary = shutil.which("opa")
    if not binary:
        pytest.skip(
            "opa binary not on PATH. Install it from "
            "https://www.openpolicyagent.org/docs/latest/#running-opa "
            "or add it through mise.toml so CI can run these tests."
        )
    return binary


@pytest.fixture(scope="session")
def policy_file() -> Path:
    assert POLICY_FILE.exists(), f"policy file missing: {POLICY_FILE}"
    return POLICY_FILE


def _evaluate(opa: str, policy: Path, document: dict) -> dict:
    """Run `opa eval data.hr.authz.decision` and return the result dict.

    Mirrors the subprocess call H4 will make in-Lambda (a bundled `opa`
    binary or its WASM-compiled equivalent), so the Rego contract stays
    identical between local tests and production.
    """
    completed = subprocess.run(
        [
            opa,
            "eval",
            "--data",
            str(policy),
            "--stdin-input",
            "--format",
            "json",
            "--fail-defined",  # non-zero exit if nothing matched would be unexpected
            "data.hr.authz.decision",
        ],
        input=json.dumps(document),
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode in (0, 1), (
        f"opa eval failed: rc={completed.returncode}\n"
        f"stdout: {completed.stdout}\n"
        f"stderr: {completed.stderr}"
    )
    payload = json.loads(completed.stdout)
    expressions = payload["result"][0]["expressions"]
    return expressions[0]["value"]


# ---------------------------------------------------------------------------
# Input builders
#
# Only build the fields the action actually reads. The spec forbids leaking
# amounts, leave reasons, or full names into Rego input, so none appear here.
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


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


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
    def test_e1_reads_own_salary_is_allowed(self, opa_binary, policy_file):
        result = _evaluate(opa_binary, policy_file, salary_input("E1", "E1"))
        _assert_allow(result)

    def test_m1_reads_own_salary_is_allowed(self, opa_binary, policy_file):
        result = _evaluate(opa_binary, policy_file, salary_input("M1", "M1"))
        _assert_allow(result)

    def test_r1_reads_own_salary_is_allowed(self, opa_binary, policy_file):
        result = _evaluate(opa_binary, policy_file, salary_input("R1", "R1"))
        _assert_allow(result)

    @pytest.mark.parametrize("report", ["R1", "R2", "R3", "R4"])
    def test_e1_reads_direct_reports(self, opa_binary, policy_file, report):
        result = _evaluate(opa_binary, policy_file, salary_input("E1", report))
        _assert_allow(result)

    @pytest.mark.parametrize("target", ["M1", "E2", "X1"])
    def test_e1_cannot_read_manager_peer_or_terminated(
        self, opa_binary, policy_file, target
    ):
        result = _evaluate(opa_binary, policy_file, salary_input("E1", target))
        _assert_deny(result, "NOT_AUTHORIZED")

    def test_m1_reads_direct_report_e1(self, opa_binary, policy_file):
        result = _evaluate(opa_binary, policy_file, salary_input("M1", "E1"))
        _assert_allow(result)

    def test_m1_cannot_read_skip_level_r1(self, opa_binary, policy_file):
        """R1's manager is E1, not M1. Skip-level is denied."""
        result = _evaluate(opa_binary, policy_file, salary_input("M1", "R1"))
        _assert_deny(result, "NOT_AUTHORIZED")

    def test_transfer_moves_salary_access(self, opa_binary, policy_file):
        """E1 transfers under E2. M1 is denied, E2 is allowed.

        The spec guarantees no stale copy of `manager_id`: the Lambda
        reads the current row before building the OPA input, so a
        transfer takes effect on the next call with no policy redeploy.
        We simulate that by passing the updated `target_manager_id`.
        """
        under_e2 = {
            "action": "get_employee_compensation",
            "caller_employee_id": "M1",
            "requested_employee_id": "E1",
            "target_status": "active",
            "target_manager_id": "E2",
            "agent_id": "compensation",
        }
        _assert_deny(_evaluate(opa_binary, policy_file, under_e2), "NOT_AUTHORIZED")
        under_e2["caller_employee_id"] = "E2"
        _assert_allow(_evaluate(opa_binary, policy_file, under_e2))

    def test_unknown_id_is_not_authorized(self, opa_binary, policy_file):
        """An unknown target reaches Rego with `target_status` missing,
        which the spec maps to deny. The reason is the same as a real
        denied person, so a directory probe cannot distinguish them.
        """
        unknown = {
            "action": "get_employee_compensation",
            "caller_employee_id": "E1",
            "requested_employee_id": "Z9",
            "target_status": "unknown",
            "target_manager_id": None,
            "agent_id": "compensation",
        }
        _assert_deny(_evaluate(opa_binary, policy_file, unknown), "NOT_AUTHORIZED")

    def test_terminated_target_denied_even_when_caller_is_self(
        self, opa_binary, policy_file
    ):
        """`target_status == active` is required by both salary rules."""
        result = _evaluate(
            opa_binary,
            policy_file,
            salary_input("X1", "X1", override_status="terminated"),
        )
        _assert_deny(result, "NOT_AUTHORIZED")


# ---------------------------------------------------------------------------
# Leave balance (get_leave_balance)
# ---------------------------------------------------------------------------


class TestLeaveBalance:
    def test_self_allowed(self, opa_binary, policy_file):
        _assert_allow(_evaluate(opa_binary, policy_file, balance_input("E1")))

    def test_balance_request_by_different_caller_is_denied(
        self, opa_binary, policy_file
    ):
        """Defence-in-depth. The tool overwrites `requested_employee_id`
        to the caller for self-only tools before the call, so this case
        cannot arise from a leaf today. The rule still has to deny if
        the Lambda ever regresses."""
        sneaky = {
            "action": "get_leave_balance",
            "caller_employee_id": "E1",
            "requested_employee_id": "M1",
            "agent_id": "leave-balance",
        }
        _assert_deny(_evaluate(opa_binary, policy_file, sneaky), "NOT_AUTHORIZED")


# ---------------------------------------------------------------------------
# Allowance (get_allowance)
# ---------------------------------------------------------------------------


class TestAllowance:
    def test_self_allowance_allowed(self, opa_binary, policy_file):
        _assert_allow(_evaluate(opa_binary, policy_file, allowance_input("E1", "E1")))

    def test_e1_cannot_read_m1_allowance(self, opa_binary, policy_file):
        _assert_deny(
            _evaluate(opa_binary, policy_file, allowance_input("E1", "M1")),
            "NOT_AUTHORIZED",
        )


# ---------------------------------------------------------------------------
# Leave check and submit
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("action", ["check_leave_eligibility", "submit_leave_request"])
class TestLeaveCheckAndSubmit:
    def test_p1_blocked_by_probation(self, opa_binary, policy_file, action):
        result = _evaluate(opa_binary, policy_file, leave_input(action, "P1"))
        _assert_deny(result, "PROBATION_PERIOD")

    def test_invalid_range(self, opa_binary, policy_file, action):
        """End before start is INVALID_RANGE, not INSUFFICIENT_BALANCE,
        regardless of what `days` the Lambda computed."""
        inverted = leave_input(
            action,
            "E1",
            start_date="2026-11-18",
            end_date="2026-11-16",
            days_override=-1,
        )
        _assert_deny(_evaluate(opa_binary, policy_file, inverted), "INVALID_RANGE")

    def test_insufficient_balance(self, opa_binary, policy_file, action):
        """40 days of annual leave against the 14-day seed balance."""
        big = leave_input(
            action,
            "E1",
            start_date="2026-11-16",
            end_date="2026-12-25",
        )
        _assert_deny(_evaluate(opa_binary, policy_file, big), "INSUFFICIENT_BALANCE")

    def test_overlap(self, opa_binary, policy_file, action):
        overlap = leave_input(action, "E1", overlaps_existing=True)
        _assert_deny(_evaluate(opa_binary, policy_file, overlap), "OVERLAP")

    def test_happy_path(self, opa_binary, policy_file, action):
        _assert_allow(_evaluate(opa_binary, policy_file, leave_input(action, "E1")))

    def test_probation_beats_overlap(self, opa_binary, policy_file, action):
        """First-match order: probation is reported before overlap even
        when both would deny."""
        pathological = leave_input(action, "P1", overlaps_existing=True)
        _assert_deny(
            _evaluate(opa_binary, policy_file, pathological), "PROBATION_PERIOD"
        )

    def test_range_beats_balance(self, opa_binary, policy_file, action):
        """First-match order: INVALID_RANGE is reported before
        INSUFFICIENT_BALANCE when both would deny."""
        pathological = leave_input(
            action,
            "E1",
            start_date="2026-11-18",
            end_date="2026-11-16",
            days_override=100,
        )
        _assert_deny(_evaluate(opa_binary, policy_file, pathological), "INVALID_RANGE")


# ---------------------------------------------------------------------------
# Manager decision (record_leave_decision)
# ---------------------------------------------------------------------------


class TestRecordLeaveDecision:
    def test_direct_manager_approves_pending(self, opa_binary, policy_file):
        _assert_allow(_evaluate(opa_binary, policy_file, decision_input("M1", "E1")))

    def test_requester_cannot_decide_own_request(self, opa_binary, policy_file):
        """Self-approval is not permitted even if the caller happens to
        be their own manager in the row. The rule explicitly forbids
        `caller == requester`."""
        doc = decision_input(
            "E1",
            "E1",
            requester_manager_id="E1",  # pathological: self-loop
        )
        _assert_deny(_evaluate(opa_binary, policy_file, doc), "NOT_REVIEWER")

    def test_wrong_reviewer_denied(self, opa_binary, policy_file):
        """E2 is a peer, not the manager of E1."""
        _assert_deny(
            _evaluate(opa_binary, policy_file, decision_input("E2", "E1")),
            "NOT_REVIEWER",
        )

    def test_skip_level_denied(self, opa_binary, policy_file):
        """R1's manager is E1. M1 is skip-level, not direct, so deny."""
        _assert_deny(
            _evaluate(opa_binary, policy_file, decision_input("M1", "R1")),
            "NOT_REVIEWER",
        )

    def test_already_approved_denied(self, opa_binary, policy_file):
        """Second decision on the same row is refused."""
        doc = decision_input("M1", "E1", request_status="approved")
        _assert_deny(_evaluate(opa_binary, policy_file, doc), "NOT_REVIEWER")

    def test_already_rejected_denied(self, opa_binary, policy_file):
        doc = decision_input("M1", "E1", request_status="rejected")
        _assert_deny(_evaluate(opa_binary, policy_file, doc), "NOT_REVIEWER")


# ---------------------------------------------------------------------------
# Policy metadata
# ---------------------------------------------------------------------------


class TestPolicyMetadata:
    def test_policy_version_is_non_empty(self, opa_binary, policy_file):
        """H4 writes `policy_version` to every decision_log row.
        A future rule change must bump this string in the same commit."""
        result = _evaluate(
            opa_binary,
            policy_file,
            salary_input("E1", "E1"),
        )
        assert isinstance(result["policy_version"], str)
        assert result["policy_version"].strip(), result

    def test_default_deny_on_unknown_action(self, opa_binary, policy_file):
        """A new action that the Rego file has not learnt about must
        fall through to deny, not accidentally allow."""
        novel = {
            "action": "list_all_employees",  # does not exist in v1
            "caller_employee_id": "E1",
            "requested_employee_id": "E1",
            "agent_id": "compensation",
        }
        _assert_deny(_evaluate(opa_binary, policy_file, novel), "NOT_AUTHORIZED")
