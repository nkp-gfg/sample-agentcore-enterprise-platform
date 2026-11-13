# hr-identity (H3)

Pre-token-generation Lambda on the existing Cognito user pool. Looks up the
signed-in employee in the `hr-data` Aurora cluster by their Cognito `sub`
and adds the identity claims the HR tool Lambdas (H4) and Cedar need:
`employee_id`, `role`, and (when the runtime asked for a leaf-scoped token)
`agent_id`.

See [`docs/hr/modules.md`](../../docs/hr/modules.md) §§ H3 claims and SSM
interface, [`docs/hr/policy.md`](../../docs/hr/policy.md),
[`docs/hr/acceptance.md`](../../docs/hr/acceptance.md) § H3, and
[`custom-app-plan/phases.md`](../../custom-app-plan/phases.md) § H3 —
and [`docs/hr/README.md`](../../docs/hr/README.md) for the reading order of
the HR spec.

## What it deploys

- One Python 3.13 `lambda.Function` (`<prefix>-uc-hr-identity-pretoken`)
  running in the module C private subnets, attached to the module C runtime
  security group. Connects to the Aurora writer endpoint on 5432 with an
  RDS IAM token signed for the `hr_identity` database role.
- Its `iam.Role` with the minimum policy needed to:
  - call `rds-db:connect` as the `hr_identity` database user on the
    `hr-data` cluster,
  - read the four `use-cases/hr-data/*` SSM parameters (and the
    `use-cases/hr-identity/*` ones it publishes itself),
  - sign and verify requests to the VPC endpoints,
  - write its own CloudWatch Logs.
- One CloudWatch `logs.LogGroup` with 365-day retention, matching the
  HR plan's log retention for every HR component.
- Two `custom_resources.AwsCustomResource` nodes:
  - ATTACH — on CREATE/UPDATE, calls `cognito-idp:UpdateUserPool` with
    `LambdaConfig.PreTokenGenerationConfig.LambdaArn` pointing at this
    Lambda. Grants `lambda:InvokeFunction` from `cognito-idp.amazonaws.com`.
  - DETACH — on DELETE, calls `UpdateUserPool` again with
    `LambdaConfig: {}` so the user pool is clean after
    `destroy --stack`. Module 3's user pool stays.
- One SSM `StringParameter` published under
  `/{project}/{environment}/use-cases/hr-identity/function-arn`. Consumers:
  operators and the detach-on-destroy step.

The Lambda is not wired to the gateway. It never reads any HR table other
than `employees`, and only the `employee_id`, `cognito_sub`, and `status`
columns (the exact grant `hr_identity` has — see `docs/hr/modules.md` §
Database roles).

## Enable

Append to your `platform.yaml` (`hr-data` and `hr-identity` can go side by
side in the same deploy, but `hr-data` must deploy first because this
Lambda reads its SSM parameters at deploy time):

```yaml
use_cases:
  hr-data:
    database_name: hr
    retain_data: true
    seed: false
  hr-identity: {}        # no settings yet
```

`hr-identity` requires the `auth` stack (the Cognito user pool is created
there) and transitively depends on `networking`, `security`, and the
`hr-data` use case. The production preset turns `security.networking` and
`security.cloudtrail_alerting` on. A config that flips either off is
refused by `python -m infra_utils.platform_config platform.yaml` before any
CDK call.

## Deploy

```bash
./scripts/deploy.sh deploy --stack ${PROJECT:-agentcore-production}-${ENV:-prod}-uc-hr-identity
```

The deploy never touches the auth, networking, security, or hr-data
stacks: this one reads every platform input through SSM and takes no CDK
cross-stack dependency on any of them.

## Verify

```bash
python use-cases/hr-identity/verify.py
```

The script reads the published `function-arn` SSM parameter, calls
`lambda:GetFunction` to confirm the Lambda is `Active`, and calls
`cognito-idp:DescribeUserPool` to confirm the pool's
`LambdaConfig.PreTokenGenerationConfig.LambdaArn` points at it. Expected
output on success:

```
OK: hr-identity pretoken <function-arn> is Active and attached to user pool <user-pool-id>
```

The script does not mint a token. End-to-end claims — "two users get two
different `employee_id` claims; a terminated row is `NOT_MAPPED`;
`calling_agent: 'leave-submit'` carries `agent_id: 'leave-submit'`;
`calling_agent: 'admin'` carries no `agent_id`; every token expires 15
minutes after issue" — are proved by H4's `verify.py` from inside the VPC,
through the gateway.

## Remove

Destroy `uc-hr-tools` first, then this stack:

```bash
./scripts/deploy.sh destroy --stack ${PROJECT:-agentcore-production}-${ENV:-prod}-uc-hr-identity
```

The DETACH custom resource runs on DELETE and removes the trigger from
module 3's user pool. The user pool itself, its app clients, and the
secrets stay. See the "Deploy and destroy" section of
[`custom-app-plan/phases.md`](../../custom-app-plan/phases.md).
