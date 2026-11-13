# Review: employee HR assistant

Reviewed `plan1.md` and `plan2.md` together. This file is the planning baseline. When this file and [`docs/hr/`](../docs/hr/README.md) disagree about a column, a tool field, or an error code, `docs/hr/` wins. When they disagree about who may see a salary, probation, or pending leave, this file wins.

## Verdict

The goal is achievable on the platform that is already deployed, plus the FAST frontend and its identity-propagation pattern. Do not rebuild auth, the gateway, Cedar, the guardrail, memory, or the VPC.

Three things are actually new:

1. Tools that enforce who the signed-in employee is, including the salary reporting line and the probation rule.
2. One god agent that routes to department agents, and those agents route to a leaf per tool.
3. A web UI that signs in with Entra and renders cards and one leave form.

The model never decides who can see a salary or whether probation blocks leave. Those checks live in the tool and the database. A prompt that says "ignore your rules" still gets "you are not allowed," because the tool does not read an employee id from the model.

## Locked decisions

| Topic | Decision |
|---|---|
| Sign-in | Keep Entra through the existing Cognito web client. The browser sends the Cognito access token. The prompt does not carry an employee id. |
| Identity in tools | Port the FAST pre-token Lambda and `aws_client_metadata` so the gateway token carries `employee_id` and `role`. The Token Vault decorator cannot pass that metadata. |
| Source of truth for people | The HR database, not the prompt and not an Entra group, owns `employee_id` and `manager_id`. Entra only proves who signed in. |
| Salary scope for v1 | Self, plus **direct reports only** (one hop on `manager_id`). Not the whole tree. Plan 1's recursive query is the later version if skip-level access is required. |
| Probation | No leave of any type while `probation_end_date` is still in the future. The check runs in both eligibility and submit. |
| Telephone allowance | Owned by the **Finance Payroll** specialist, as in plan 1. v1 reads `payroll_items` in Postgres. The real downstream API replaces the inside of that tool later. Plan 2's placement under HR Payroll is not used. |
| Who receives the request | One god agent. It routes. It is not an HR agent. Department agents and their leaves are in [god-agent.md](god-agent.md). |
| What each layer does | The god agent only routes. A department agent only routes to its leaves. A leaf picks its one tool and phrases the answer. The tool allows or denies. A review card, not the model, resumes a pause. |
| Review for v1 | The employee confirms `submit_leave_request` before it runs. The direct manager then approves or rejects the pending row. Both are interrupts, in the UI and in Postgres. The contract is [human-review.md](human-review.md). A chat message does not approve. |
| Where the code lives | Three use cases, not one and not the core stacks: `hr-data`, `hr-identity`, `hr-tools`. The Rego file lives in `hr-tools`. H5 and H6 are switches on module 6 and the local frontend. |
| Cedar | Production is already `ENFORCE`. Each new tool ships with its permit in the same deploy. Do not turn the engine back to log-only for the whole gateway. Do not add a blanket `forbid`. |
| Model | Stay on `openai.gpt-oss-120b-1:0` until a routing test fails. Cross-region Claude profiles stay blocked by the organization SCP. |
| UI hosting for v1 | FAST frontend on localhost, pointed at the deployed runtime. No CloudFront or Amplify stack until chat and the leave form work. |

## Where the plans differed

| Topic | Plan 1 | Plan 2 | Resolution |
|---|---|---|---|
| Telephone allowance | Finance Payroll agent, downstream API | HR Payroll agent, `get_allowance` | Finance Payroll owns it. v1 uses Postgres `payroll_items`. The API is a later swap inside the same tool. |
| Salary tree | Recursive: self and everyone below | "Reporting chain," unspecified depth | v1 is self and direct reports only. That matches "my four subordinates." |
| First form | A2UI JSON schema | Named UI tool `show_leave_form`, A2UI later | Named React form first. Keep plan 1's field list as that tool's arguments. |
| First picture | Architecture diagram shows three A2A runtimes | Says start as tools in one runtime, and notes nothing calls A2A yet | One runtime first. A2A is work package 7. |
| Role list | employee, manager, hr_admin, payroll_admin | employee, manager, HR admin | Keep four roles. See the open question on who can see every salary. |
| Identity source | Pre-token map from `sub` | Entra group or the HR database | HR database is the map. The pre-token Lambda looks the person up. Entra groups are not required for v1. |

Everything else matches: the security rule, the three access layers, the tool names, reusing FAST for the UI and the pre-token Lambda, and starting with the schema plus the salary check.

## Out of scope until the questions pass

- Splitting specialists into A2A runtimes and forwarding the user JWT inside JSON-RPC metadata.
- A generic A2UI renderer and CopilotKit.
- A real finance or ERP API.
- PostgreSQL row-level security. The Lambda query is the control. RLS is a second net, not the first.
- A hosted production web UI.
- Indirect reports, peer salaries, and "HR can see everyone" unless the open question below is answered yes.

## Work packages

These packages are the earlier breakdown of the same rules. Field names and error codes in [`docs/hr/`](../docs/hr/README.md) replace the names below. Build order is the modules in `phases.md`, not the package numbers. The open questions at the bottom are already decided by their defaults, and the spec pages use those defaults.

### 1. Schema and salary rule

Tables: `employees` (`employee_id`, `cognito_sub`, `email`, `full_name`, `manager_id`, `hire_date`, `probation_end_date`), `salaries`, `leave_balances`, `leave_requests`, `payroll_items`.

Seed: one manager, one employee under that manager, four people under that employee, one employee still on probation.

The tool argument is `employee_id` ([`docs/hr/tools.md`](../docs/hr/tools.md)). Unit tests pass `caller_employee_id` into the policy input themselves. The token wiring is package 3. Allow if the target is the caller or `manager_id` equals the caller. Otherwise return `NOT_AUTHORIZED` and no amount.

Exit: unit tests for own salary allowed, four direct reports allowed, the manager's salary denied, a peer denied, a skip-level report denied.

### 2. Leave and allowance tools

`get_leave_balance`, `check_leave_eligibility`, `submit_leave_request`, `get_allowance(type, month)`.

Probation refuses every leave type on both check and submit. Allowance reads `payroll_items` for the caller only.

Exit: probation employee cannot pass eligibility or submit. A non-probation employee can submit and the balance check uses their id, not an id supplied as a free argument.

### 3. Identity on the gateway token

Pre-token Lambda on the Cognito user pool (`ESSENTIALS`). The HR tool path calls Cognito with `aws_client_metadata.verified_user_id` set from `shared/auth.py`'s verified `sub`. Claims added: `employee_id`, `role`.

The tool or a request interceptor overwrites `caller_employee_id` from those claims. Model arguments for that field are ignored.

Exit: two test users get different `employee_id` claims. A tool call that tries to set `caller_employee_id` to someone else is still scoped to the token.

### 4. Cedar permits

One permit per new tool, action `AgentCore::Action::"<target>___<tool>"`, resource the gateway ARN. Any signed-in caller may invoke the six tools. There is no approve tool, so `role` does not narrow Cedar in v1. The salary and leave row rules are the OPA file in [`docs/hr/policy.md`](../docs/hr/policy.md). They are not a second copy in SQL, and they are not Cedar.

Ship the permits in the same deploy as the targets. Confirm the gateway role can invoke the new Lambdas.

Exit: `tools/list` as an employee does not show `approve_leave`. A salary call for the manager still returns `not_authorized` from the tool, not from the model.

### 5. Supervisor and three specialists, one runtime

The god-agent pattern in [god-agent.md](god-agent.md). The god agent has no gateway tools. Each leaf has one.

Exit, from `scripts/invoke.py` or `scripts/login_chat.py`: leave balance, telephone allowance, probation refusal, manager salary denied, four direct reports allowed. Then the abuse prompt. Read the runtime log. `deploy.sh verify` runs as an administrator and does not prove this.

### 6. Web UI and the leave form

FAST `frontend/` on localhost against the Cognito web client and the orchestrator ARN from SSM. Cards for leave balance, allowance, and team compensation. `show_leave_form` renders date range, leave type, and reason. Submit calls `submit_leave_request` again, which repeats the probation and balance checks.

Exit: an eligible user submits the form and sees a confirmation. A probation user never gets the form, and a hand-built submit still fails.

### 7. Later

A2A runtimes with the signed user JWT in the JSON-RPC metadata. Downstream finance API behind `get_allowance`. A2UI renderer. RLS. Hosted UI.

Exit for the model checkpoint, before package 6 is treated as final: the same five questions on `openai.gpt-oss-120b-1:0`. If routing or the form fails, stop and pick another in-region tool-capable model. Do not switch to an `eu.` or `us.` profile without an SCP exception.

## Open questions

Answer these before the package that needs them. They do not block package 1.

| Question | Default if nobody answers | Blocks |
|---|---|---|
| Can `hr_admin` or `payroll_admin` see every salary, or only the same direct-report rule? | Same direct-report rule for every role in v1. No global salary view. | Package 4, if the answer is yes |
| Is "four subordinates" only direct reports? | Yes. One hop. | Already locked unless you want the tree |
| Is any leave allowed on probation (for example unpaid)? | No leave type is allowed. | Package 2 |
| Is there a real allowance API and its contract, or is Postgres enough for the demo? | Postgres `payroll_items` for v1. | Package 7 |

## Planning start

Implement from [`docs/hr/`](../docs/hr/README.md), in the module order in `phases.md`. Do not add a column, a reason code, or a tool argument that those pages do not name. Start with H1 (`hr-data`) unless you are only writing the OPA tests.
