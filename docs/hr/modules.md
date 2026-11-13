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
use-cases/hr-tools/            layer 1  Lambdas, Cedar, OPA
  manifest.yaml
  stack.py
  policy/authz.rego
  verify.py
  walkthrough.md
agent-code/god-agent/          layer 2  runtime image
  Dockerfile
  requirements.txt
  agent.py
```

The policy tests live in `tests/test_hr_authz.py` and load `use-cases/hr-tools/policy/authz.rego`. They are layer 1. They are not a stack.

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
  hr-tools: {}
```

| Key | Use case | Meaning |
|---|---|---|
| `database_name` | hr-data | Database name inside the cluster. Default `hr`. |
| `retain_data` | hr-data | `true` keeps the cluster, the subnet group, and the secret when the stack is deleted. Default `true` when the key is omitted. `false` is only for a disposable account. The use-case `build()` reads this from its own config dict. The platform context does not pass a retain flag. |
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

There is no `role` column. `hr_admin` and `payroll_admin` are not issued, and `role` does not change what OPA allows. An active row is missing, or the row is terminated: the Lambda adds no `employee_id`. It does not invent a guest employee. The tool then returns `NOT_MAPPED` and does not call OPA.

Destroy removes this trigger from the user pool. Module 3 stays.

## SSM interface

Published under `/{project}/{environment}/use-cases/`. No passwords.

| Parameter | Publisher | Consumers |
|---|---|---|
| `use-cases/hr-data/endpoint` | hr-data | hr-tools, operators |
| `use-cases/hr-data/secret-name` | hr-data | hr-tools, hr-identity |
| `use-cases/hr-data/database-name` | hr-data | hr-tools, hr-identity |
| `use-cases/hr-data/checkpoint-database` | hr-data | the god agent |
| `use-cases/hr-identity/function-arn` | hr-identity | operators, detach-on-destroy |

hr-tools and hr-identity read these with `ssm.StringParameter.value_for_string_parameter`. They do not import the hr-data stack.
