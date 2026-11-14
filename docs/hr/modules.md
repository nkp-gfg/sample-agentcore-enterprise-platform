# HR modules

HR is not a new workshop number. Modules 3, 4, 5, 6, C, and E stay the shared platform. Layer 1 is three use cases. Layer 2 is an `agent-code` pattern. Layer 3 is the UI. A use case is off until `platform.yaml` names it. Naming one does not turn the others on.

The platform's `requires:` list only checks core stacks. It cannot say "hr-tools needs hr-data". That edge is real anyway: hr-tools reads SSM parameters that only hr-data publishes. Deploy the dependency first. Destroy the dependent first.

## Folders

Do not create these until this spec is accepted. The paths are fixed so two people do not invent two layouts.

```text
use-cases/hr-data/             layer 1  Postgres
  manifest.yaml
  stack.py
  schema.sql
  seed.sql
  verify.py
  walkthrough.md
use-cases/hr-identity/         layer 1  pre-token Lambda
  manifest.yaml
  stack.py
  verify.py
  walkthrough.md
use-cases/hr-tools/            layer 1  Lambdas, Cedar, authz policy
  manifest.yaml
  stack.py
  lambdas/shared/authz.py
  verify.py
  walkthrough.md
agent-code/god-agent/          layer 2  runtime image
  Dockerfile
  requirements.txt
  agent.py
```

The policy tests live in `tests/test_hr_authz.py` and load `use-cases/hr-tools/lambdas/shared/authz.py`. They are layer 1. They are not a stack.

Layer 2 is a pattern next to the other images under `agent-code/`. It does not import `stacks` or `infra_utils`. The shape is [god-agent.md](../../custom-app-plan/god-agent.md).

Layer 3 is the application UI. It is not a use case and not a runtime image. It consumes the runtime the way `dashboard/` consumes a public contract, and it does not import CDK or the agent package. The review cards are [human-review.md](../../custom-app-plan/human-review.md). Build order is [phases.md](../../custom-app-plan/phases.md).

## Manifests

`requires` uses core stack suffixes. `stacks` must start with `uc-`.

| Use case | requires | stacks |
|---|---|---|
| `hr-data` | `networking`, `security` | `uc-hr-data` |
| `hr-identity` | `auth` | `uc-hr-identity` |
| `hr-tools` | `gateway`, `identity` | `uc-hr-tools` |

`requires` cannot name another use case. hr-tools reads the SSM parameters hr-data publishes, and it trusts the `employee_id` claim hr-identity adds. Deploy those two first. Each manifest also needs `owner: hr-platform` and a `summary`. `verify.py` and `walkthrough.md` are required by the use-case check even though they are not keys in the manifest.

`networking` exists only when `security.networking` is on, and `security` exists only when `security.cloudtrail_alerting` is on. Both are on in this production footprint. A config that turns either off cannot enable `hr-data`.

## Enable

Add only the use cases that colleague is building.

```yaml
use_cases:
  hr-data:
    database_name: hr
    retain_data: true
    seed: false
  hr-identity: {}
  hr-tools:
    audit_stream_arn: ""
```

| Key | Use case | Meaning |
|---|---|---|
| `database_name` | hr-data | Database name inside the cluster. Default `hr`. |
| `retain_data` | hr-data | `true` keeps the cluster, the subnet group, and the secret when the stack is deleted. Default `true` when the key is omitted. `false` is only for a disposable account. The use-case `build()` reads this from its own config dict. The platform context does not pass a retain flag. |
| `audit_stream_arn` | hr-tools | Firehose stream that delivers HR audit lines to the SIEM. Empty means no export |
| `seed` | hr-data | `true` loads [the demo seed](schema.md). Default `false`. Never seed a database that holds real employees. |

## Deploy and destroy

```bash
./scripts/deploy.sh deploy --stack agentcore-production-prod-uc-hr-data
python use-cases/hr-data/verify.py
```

`design` without `--profile` only prints the plan. `design --profile` rewrites `platform.yaml` from a preset. Do not run that on this checkout. At the pattern and IdP prompts, keep the values Part 1 already saved.

The same shape works for `uc-hr-identity` and `uc-hr-tools`. `deploy.sh verify` runs each enabled use case's `verify.py` after the platform checks.

Destroy one stack. Dependents first. `destroy --stack` deletes only that stack. The HR stacks do not export to each other, so delete tools, then identity, then data even if CloudFormation would allow another order. If an error names an export still in use, that name is the stack to destroy first.

```bash
./scripts/deploy.sh destroy --stack agentcore-production-prod-uc-hr-tools
./scripts/deploy.sh destroy --stack agentcore-production-prod-uc-hr-identity
./scripts/deploy.sh destroy --stack agentcore-production-prod-uc-hr-data
```

Order when the platform stays up:

1. Stop the local UI.
2. If the god agent was enabled, redeploy module 6 with the previous `agents.pattern`. Do not destroy `runtime-orchestrator`.
3. Destroy `uc-hr-tools`.
4. Destroy `uc-hr-identity`. The user pool stays. The pre-token trigger is removed.
5. Destroy `uc-hr-data`.

With `retain_data: true`, step 5 deletes the stack and leaves the cluster, the secret, and the backups. Salary rows are still there. Dropping them is a later, explicit operation. It is not what `destroy` does.

Do not destroy `auth`, `security`, or `networking` to remove HR.

## H3 claims

The pre-token Lambda runs only for `TokenGeneration_ClientCredentials`. Browser login tokens are left unchanged. The runtime copies the verified Cognito `sub` into `clientMetadata.verified_user_id` when it asks Cognito for the gateway token. That value is the lookup key. The model cannot set it.

The Lambda selects `employee_id` where `cognito_sub` equals that `sub`, `status` is `active`, and the row exists. It then adds these access-token claims:

| Claim | Value in v1 |
|---|---|
| `employee_id` | The business id from that row |
| `user_id` | The same Cognito `sub` |
| `role` | The constant `employee` |
| `agent_id` | `clientMetadata.calling_agent`, only if it is one of `leave-balance`, `leave-eligibility`, `leave-submit`, `compensation`, `direct-reports`, `allowance`, `review-node`. Any other value adds no `agent_id`, and Cedar then denies every HR tool |

There is no `role` column. `hr_admin` and `payroll_admin` are not issued, and `role` does not change what the authorization policy allows. An active row is missing, or the row is terminated: the Lambda adds no `employee_id`. It does not invent a guest employee. The tool then returns `NOT_MAPPED` before evaluating the policy.

The runtime code sets `calling_agent`, one token per leaf. The model cannot set it. In v1 this is asserted by the runtime, not proved by a separate credential. One Cognito app client per leaf, matched in Cedar on `client_id`, is the stronger version when the departments become separate runtimes.

The HR M2M app client issues access tokens valid for 15 minutes. Its client secret is read from Secrets Manager by exact ARN, only by the runtime role, and rotated. It is never in an environment variable, the checkpoint, or a log.

Destroy removes this trigger from the user pool. Module 3 stays.

## Database roles

H1 creates the roles. The master secret is for H1 only. No Lambda and no runtime uses it.

| Role | Database | Grants | Used by |
|---|---|---|---|
| `hr_reader` | `hr` | SELECT on `employees`, `salaries`, `leave_balances`, `leave_requests`, `payroll_items` | the five read tools |
| `hr_writer` | `hr` | INSERT on `leave_requests`. UPDATE of `status`, `decided_by`, `decided_at` on `leave_requests`. SELECT as `hr_reader` | `submit_leave_request`, `record_leave_decision` |
| `hr_audit` | `hr` | INSERT on `decision_log`. No UPDATE, DELETE, or SELECT | every HR Lambda |
| `hr_identity` | `hr` | SELECT of `employee_id`, `cognito_sub`, `status` on `employees` | the H3 pre-token Lambda |
| `agent_checkpoint` | `agent_state` | owner of the checkpoint tables. No access to `hr` | the god agent |

Lambdas connect with RDS IAM authentication. A token is valid for 15 minutes. The `hr-payroll` and `hr-finance` roles have `rds-db:connect` for `hr_reader` and `hr_audit` only. The `hr-ops` role may also connect as `hr_writer`, and the function opens that connection only inside `submit_leave_request` and `record_leave_decision`. Moving those two tools to their own target and function is the stronger split, at the cost of a fourth Lambda.

## Kill switch and audit export

| Parameter | Publisher | Meaning |
|---|---|---|
| `use-cases/hr-tools/enabled` | hr-tools, initial value `true` | Anything other than `true` makes every HR tool return `SERVICE_DISABLED`. An operator changes it with `aws ssm put-parameter --overwrite`. No deploy |

hr-tools adds a CloudWatch Logs subscription filter on its Lambda log groups to a Firehose stream named in `use_cases.hr-tools.audit_stream_arn`. When that key is empty, no filter is created and the SIEM gap is recorded in the risk register. HR log groups keep 365 days.

## SSM interface

Published under `/{project}/{environment}/use-cases/`. No passwords.

| Parameter | Publisher | Consumers |
|---|---|---|
| `use-cases/hr-data/endpoint` | hr-data | hr-tools, operators |
| `use-cases/hr-data/secret-name` | hr-data | hr-tools, hr-identity |
| `use-cases/hr-data/database-name` | hr-data | hr-tools, hr-identity |
| `use-cases/hr-data/checkpoint-database` | hr-data | the god agent |
| `use-cases/hr-identity/function-arn` | hr-identity | operators, detach-on-destroy |
| `use-cases/hr-tools/enabled` | hr-tools | every HR Lambda, operators |

hr-tools and hr-identity read these with `ssm.StringParameter.value_for_string_parameter`. They do not import the hr-data stack.
