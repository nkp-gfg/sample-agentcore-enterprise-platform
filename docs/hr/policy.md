# HR policy

Module: `use-cases/hr-tools/lambdas/shared/authz.py` (`evaluate_policy`).

H2 and H4 evaluate that deterministic Python module in-process with zero external binaries or subprocesses. The policy module does not store the org chart: the tool reads the current row from Postgres, builds the input below, and evaluates the policy. A stale copy of `manager_id` outside Postgres is forbidden. The same rule is not also written as a `WHERE` clause on the salary query.

Default decision is deny (`allow = False`, `reason_code = "NOT_AUTHORIZED"`).

## Input

The tool builds this object. The model does not.

Dates are `YYYY-MM-DD`. Numeric fields are JSON numbers, not strings. ISO dates compare correctly as strings.

| Field | Type | Actions | Meaning |
|---|---|---|---|
| `action` | string | all | One of the tool names in [Tools](tools.md), except `list_direct_reports` |
| `caller_employee_id` | string | all | From the token. Never from tool arguments |
| `requested_employee_id` | string | all | Who the question is about. The tool argument `employee_id` maps to this field. For self-only tools the tool sets it equal to the caller before evaluation |
| `target_status` | string | salary | `active` or `terminated`. Missing means deny |
| `target_manager_id` | string or null | salary | The requested person's current `manager_id`. JSON `null` when they have none |
| `on_probation` | bool | leave check, submit | `probation_end_date` is after the tool's UTC date. The end date itself is not probation |
| `start_date`, `end_date` | string | leave check, submit | Inclusive ISO dates |
| `days` | number | leave check, submit | `(end_date - start_date) + 1` calendar days. The tool computes it. A same-day request is 1. The model cannot send this |
| `remaining_days` | number | leave check, submit | Balance for that leave type |
| `overlaps_existing` | bool | leave check, submit | True when another `pending` row for this employee intersects the inclusive range, of either leave type |
| `agent_id` | string | all | From the token, through the interceptor. Logged with the decision. Cedar already bound it to the tool |
| `request_status` | string | decision | The stored `status` of `request_id`. Missing means deny |
| `requester_manager_id` | string or null | decision | The requester's current `manager_id` |

Salary input must not contain `base_salary`. Allowance input must not contain `amount`. Leave input must not contain `reason`.

## Rules

Salary is allowed when the target is active and either the caller is the target, or the caller's id equals `target_manager_id`. One hop. A manager sees a direct report. The report does not see the manager. A skip-level manager does not see the report's reports. Terminated and missing targets are not active, so they are denied.

Leave balance and allowance are allowed only when `caller_employee_id` equals `requested_employee_id`.

Leave check and submit are allowed only when all of these hold: the caller is the target, `on_probation` is false, `end_date` is on or after `start_date`, `days` is less than or equal to `remaining_days`, and `overlaps_existing` is false.

`record_leave_decision` is allowed only when `request_status` is `pending`, `caller_employee_id` equals `requester_manager_id`, and the caller is not the requester. `requested_employee_id` is the requester. Anything else is `NOT_REVIEWER`, and the row is not updated.

The module declares `POLICY_VERSION` as a string constant. Every tool writes it to `decision_log`. A change to any rule changes that string in the same commit.

`list_direct_reports` is enforced directly by its SQL query (`manager_id = caller` and `status = active`). It returns ids and names only.

## Reason codes

The tool maps a deny to exactly one code. The first match wins, in this order.

| Code | When |
|---|---|
| `SERVICE_DISABLED` | SSM `use-cases/hr-tools/enabled` is not `true`, or cannot be read. Checked before anything else |
| `DATA_UNAVAILABLE` | Postgres was not read |
| `NOT_MAPPED` | The token has no `employee_id` |
| `INVALID_LEAVE_TYPE` | Leave type is not `annual` or `sick` |
| `INVALID_ITEM` | Allowance type is not `telephone` |
| `IDEMPOTENCY_CONFLICT` | The key exists and `leave_type`, dates, or `reason` differ |
| `NOT_AUTHORIZED` | Salary, allowance, or balance for someone else, including unknown, peer, manager, skip-level, and terminated |
| `PROBATION_PERIOD` | Caller is the target, and they are on probation |
| `INVALID_RANGE` | End date is before the start date |
| `INSUFFICIENT_BALANCE` | Requested days exceed the balance |
| `OVERLAP` | A pending request already covers those dates |
| `NOT_REVIEWER` | `record_leave_decision` by anyone other than the requester's current direct manager, or on a row that is not `pending` |

A second submit with the same `employee_id` and `idempotency_key` and the same body returns the stored row with `authorized: true`. It does not insert again and it does not use a deny code. Denies are not stored, so a denied attempt does not consume the key.

`NOT_AUTHORIZED` is one sentence to the user: "You are not allowed to see this." It does not say whether the person exists. The other codes may be specific, because they are about the caller's own request.

Every evaluation appends `decision_log` with the action, the caller, the target, `agent_id`, `session_id`, `trace_id`, `policy_version`, allow or deny, and the reason code. No amounts and no leave text. The same row is written to the Lambda log as one JSON line so the SIEM receives it.
