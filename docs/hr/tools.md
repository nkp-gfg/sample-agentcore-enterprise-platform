# HR tools

Three gateway targets, one Lambda each. Cedar already uses `ENFORCE`, so the permits are deployed with the targets. The action is `AgentCore::Action::"<target>___<tool>"` and the resource is `AgentCore::Gateway::"<gateway-arn>"`. One permit lists the six actions. The principal is any authenticated caller. Row rules stay in [Policy](policy.md). Do not add a `forbid` policy.

A policy deny is a normal tool result with `authorized: false`. It is not a Lambda exception and not a JSON-RPC `isError`. `POLICY_UNAVAILABLE` and `DATA_UNAVAILABLE` are normal results too, so the model cannot fill in a number after a crash.

| Target | Tool | Who Cedar allows to invoke it | Who OPA allows to succeed |
|---|---|---|---|
| `hr-payroll` | `get_employee_compensation` | any signed-in employee | self, or the target's direct manager |
| `hr-payroll` | `list_direct_reports` | any signed-in employee | the query itself is the rule |
| `hr-ops` | `get_leave_balance` | any signed-in employee | self only |
| `hr-ops` | `check_leave_eligibility` | any signed-in employee | self, and the leave rules |
| `hr-ops` | `submit_leave_request` | any signed-in employee | same rules as the check |
| `hr-finance` | `get_allowance` | any signed-in employee | self only |

There is no `approve_leave`, no `list_all_employees`, and no `execute_sql`.

`caller_employee_id` is not in any input schema. If a caller sends it, the Lambda ignores it and uses the `employee_id` claim from [Modules](modules.md). No claim returns `NOT_MAPPED` and does not call OPA. The tool argument `employee_id`, where a tool has one, is only the OPA field `requested_employee_id`.

The gateway role is granted `lambda:InvokeFunction` on these three functions and no others.

## Arguments

`get_employee_compensation`

| Field | Required | Meaning |
|---|---|---|
| `employee_id` | no | Defaults to the caller. Any other id is only a target. It never becomes the caller. |

`list_direct_reports` takes no arguments.

`get_leave_balance` takes no arguments. It always reads the caller.

`check_leave_eligibility` and `submit_leave_request`

| Field | Required |
|---|---|
| `leave_type` | yes, `annual` or `sick` |
| `start_date` | yes, `YYYY-MM-DD` |
| `end_date` | yes, `YYYY-MM-DD` |
| `reason` | submit only |

`submit_leave_request` also takes `idempotency_key`. The web UI sends one key per form submit. The same key and the same body return the existing pending row. The same key with a different `leave_type`, date, or `reason` returns `IDEMPOTENCY_CONFLICT` and does not insert.

`get_allowance`

| Field | Required | Meaning |
|---|---|---|
| `item_type` | yes | v1 accepts `telephone` only |
| `period` | no | Defaults to the previous calendar month in UTC. January rolls to December of the previous year. On `2026-11-13` the period is `2026-10` |

## Responses

Success:

```json
{"authorized": true, "reason_code": "ALLOW", "data": {}}
```

Deny or failure:

```json
{"authorized": false, "reason_code": "NOT_AUTHORIZED"}
```

`data` is omitted when `authorized` is false. Reason codes are the list in [Policy](policy.md).

`data` shapes:

| Tool | `data` |
|---|---|
| `get_employee_compensation` | `employee_id`, `full_name`, `base_salary`, `currency` |
| `list_direct_reports` | `reports`: list of `employee_id`, `full_name` |
| `get_leave_balance` | `annual`, `sick` as remaining days, `on_probation`, `probation_end_date` |
| `check_leave_eligibility` | `eligible` true, `days` |
| `submit_leave_request` | `request_id`, `status` = `pending`, `days` |
| `get_allowance` | `item_type`, `period`, `amount`, `currency`. A self call with no row is `authorized` true and `amount` null. It is not `NOT_AUTHORIZED`. |

The specialist may say "you are not allowed" only from `authorized: false`. It must not invent a figure the tool did not return.

CloudWatch log lines for these functions contain the action, the caller id, the target id, and the reason code. They do not contain `base_salary`, allowance `amount`, or the leave `reason`.

## Guardrail

The egress interceptor scans `tools/call` responses. The default guardrail anonymizes `NAME`, `EMAIL`, `PHONE`, and `ADDRESS`, and blocks `US_SOCIAL_SECURITY_NUMBER`. Tool responses therefore contain `employee_id` and `full_name`, and the demo seed sets those two to the same short id (`E1`, `R1`). They do not contain email, phone, address, or a government id. Salary numbers are not in that PII list, so an allowed amount reaches the model. Do not widen the guardrail to mask numbers as part of this work.

## Leave form

`show_leave_form` is a UI tool on the leave-eligibility leaf. It is not a gateway target and Cedar does not see it. That leaf emits it only after `check_leave_eligibility` returns `eligible: true` for the same values. Fields: `leave_type`, `start_date`, `end_date`, `reason`. The employee confirmation card then proposes `submit_leave_request` with those fields plus a new `idempotency_key`. The gateway check runs only after the employee approves the card. The manager review is a later pause, specified in [human review](../../custom-app-plan/human-review.md).

## Routing

The god agent does not receive the gateway tools. Each leaf receives only the tool named for it. The nesting is in [god-agent.md](../../custom-app-plan/god-agent.md).

| Department agent | Leaf | Gateway tool |
|---|---|---|
| `hr-operations` | `leave-balance` | `hr-ops___get_leave_balance` |
| `hr-operations` | `leave-eligibility` | `hr-ops___check_leave_eligibility` |
| `hr-operations` | `leave-submit` | `hr-ops___submit_leave_request` |
| `hr-payroll` | `compensation` | `hr-payroll___get_employee_compensation` |
| `hr-payroll` | `direct-reports` | `hr-payroll___list_direct_reports` |
| `finance-payroll` | `allowance` | `hr-finance___get_allowance` |

A question about a person by name is resolved with `list_direct_reports` plus the caller's own id. Zero matches in that set are `NOT_AUTHORIZED`. Two matches ask which person. The model is not given a company directory.
