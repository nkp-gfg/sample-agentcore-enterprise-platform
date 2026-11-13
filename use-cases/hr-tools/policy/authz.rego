# HR authorisation policy.
#
# Package: hr.authz
#
# Contract (see docs/hr/policy.md):
#   - The tool builds `input`. The model never does.
#   - `caller_employee_id` always comes from the gateway-validated token via
#     the request interceptor. The tool overwrites anything the model sent.
#   - For self-only tools the tool sets `requested_employee_id` equal to the
#     caller before evaluation.
#   - Dates are inclusive ISO `YYYY-MM-DD` strings; they compare correctly
#     lexicographically.
#   - The Rego file is evaluated in-process by H2's tests and by each H4
#     Lambda before any amount is read. A failure to evaluate it is mapped to
#     `POLICY_UNAVAILABLE` by the caller, not by this file.
#
# Change control:
#   - Every change to a rule in this file MUST bump `policy_version` in the
#     same commit. H4 writes the version to every `decision_log` row.
#   - The reason-code mapping follows the first-match order in
#     docs/hr/policy.md. Reorder or extend it there in the same commit.

package hr.authz

import rego.v1

policy_version := "2026-11-13.1"

# ----------------------------------------------------------------------------
# allow
# ----------------------------------------------------------------------------

default allow := false

# Salary: self.
allow if {
	input.action == "get_employee_compensation"
	input.target_status == "active"
	input.caller_employee_id == input.requested_employee_id
}

# Salary: one hop, direct manager only.
allow if {
	input.action == "get_employee_compensation"
	input.target_status == "active"
	input.target_manager_id == input.caller_employee_id
}

# Leave balance: self only.
allow if {
	input.action == "get_leave_balance"
	input.caller_employee_id == input.requested_employee_id
}

# Allowance: self only.
allow if {
	input.action == "get_allowance"
	input.caller_employee_id == input.requested_employee_id
}

# Leave check and submit share the same rule set.
allow if {
	input.action == "check_leave_eligibility"
	_leave_rules_pass
}

allow if {
	input.action == "submit_leave_request"
	_leave_rules_pass
}

_leave_rules_pass if {
	input.caller_employee_id == input.requested_employee_id
	not input.on_probation
	input.end_date >= input.start_date
	input.days <= input.remaining_days
	not input.overlaps_existing
}

# Manager decision on a leave request.
# `requested_employee_id` is the requester for this action.
allow if {
	input.action == "record_leave_decision"
	input.request_status == "pending"
	input.requester_manager_id == input.caller_employee_id
	input.caller_employee_id != input.requested_employee_id
}

# ----------------------------------------------------------------------------
# reason_code
#
# First-match ordering from docs/hr/policy.md.
# `SERVICE_DISABLED`, `POLICY_UNAVAILABLE`, `DATA_UNAVAILABLE`, `NOT_MAPPED`,
# `INVALID_LEAVE_TYPE`, `INVALID_ITEM`, and `IDEMPOTENCY_CONFLICT` are decided
# by the Lambda before this file is evaluated.
# ----------------------------------------------------------------------------

default reason_code := "NOT_AUTHORIZED"

reason_code := "ALLOW" if allow

# Leave actions, caller == target. Order matters: probation beats range
# beats balance beats overlap, matching the first-match rule above.
reason_code := "PROBATION_PERIOD" if {
	not allow
	_is_self_leave_action
	input.on_probation
}

reason_code := "INVALID_RANGE" if {
	not allow
	_is_self_leave_action
	not input.on_probation
	input.end_date < input.start_date
}

reason_code := "INSUFFICIENT_BALANCE" if {
	not allow
	_is_self_leave_action
	not input.on_probation
	input.end_date >= input.start_date
	input.days > input.remaining_days
}

reason_code := "OVERLAP" if {
	not allow
	_is_self_leave_action
	not input.on_probation
	input.end_date >= input.start_date
	input.days <= input.remaining_days
	input.overlaps_existing
}

reason_code := "NOT_REVIEWER" if {
	not allow
	input.action == "record_leave_decision"
}

_is_self_leave_action if {
	input.action == "check_leave_eligibility"
	input.caller_employee_id == input.requested_employee_id
}

_is_self_leave_action if {
	input.action == "submit_leave_request"
	input.caller_employee_id == input.requested_employee_id
}

# ----------------------------------------------------------------------------
# decision
#
# The one object the Lambda reads. Keeping `allow` and `reason_code` paired in
# a single evaluation avoids two round-trips and guarantees the mapping is
# applied by Rego itself, not reimplemented in Python.
# ----------------------------------------------------------------------------

decision := {
	"allow": allow,
	"reason_code": reason_code,
	"policy_version": policy_version,
}
