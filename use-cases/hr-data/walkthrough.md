# hr-data (H1)

Aurora PostgreSQL Serverless v2 for the HR assistant, in the private subnets
from module C, storage-encrypted with the module E CMK. Creates the `hr`
database with the HR tables + the five database roles, and an empty
`agent_state` database for the god agent's LangGraph checkpointer. Publishes
four SSM parameters and nothing else.

See [`docs/hr/modules.md`](../../docs/hr/modules.md),
[`docs/hr/schema.md`](../../docs/hr/schema.md), and
[`custom-app-plan/phases.md`](../../custom-app-plan/phases.md) for the full
contract, and [`docs/hr/README.md`](../../docs/hr/README.md) for the reading
order of the HR spec.

## What it deploys

- One `rds.CfnDBCluster` + one `rds.CfnDBInstance` (Aurora PostgreSQL
  Serverless v2 using the region's active default engine version,
  `db.serverless`, 0.5–2 ACU, RDS Data API + IAM auth enabled).
- One dedicated DB `ec2.CfnSecurityGroup` with inbound 5432 from the
  module C runtime security group, and one outbound rule added to that
  runtime SG so pods can reach 5432. Neither modifies the networking stack.
- One `rds.CfnDBSubnetGroup` across the two private subnets.
- One `secretsmanager.Secret` holding `{"username": "hr_master", "password": "..."}`,
  CMK-encrypted. Only the provisioner Lambda and operator-level recovery use
  it; H4 Lambdas authenticate with RDS IAM tokens instead.
- One Lambda + CloudFormation custom resource that applies
  [`provisioner/schema.sql`](provisioner/schema.sql) on every deploy
  (idempotent) and, when `seed: true`, applies
  [`provisioner/seed.sql`](provisioner/seed.sql).
- One CloudWatch log group (`/aws/rds/cluster/<prefix>-uc-hr-data/postgresql`)
  with 365-day retention, matching the HR plan's requirement.
- Four SSM parameters under `/{project}/{environment}/use-cases/hr-data/`:
  `endpoint`, `secret-name`, `database-name`, `checkpoint-database`. No
  passwords in SSM.

## Enable

Append to your `platform.yaml`:

```yaml
use_cases:
  hr-data:
    database_name: hr    # default "hr"
    retain_data: true    # default true; false is only for a disposable account
    seed: false          # true loads the demo seed from docs/hr/schema.md
```

The plan requires `security.networking: true` and
`security.cloudtrail_alerting: true` in the same `platform.yaml` — the
`production` preset turns both on. A config that flips either off is refused
by `python -m infra_utils.platform_config platform.yaml` before any CDK call.

## Deploy

```bash
./scripts/deploy.sh deploy --stack ${PROJECT:-agentcore-production}-${ENV:-prod}-uc-hr-data
```

The deploy command never updates a platform stack, because this stack reads
its platform inputs via SSM and takes no CDK dependency on any core stack.

## Verify

```bash
python use-cases/hr-data/verify.py
```

The script checks SSM parameters, cluster `Status == available`,
`StorageEncrypted`, `IAMDatabaseAuthenticationEnabled`,
`HttpEndpointEnabled`, `DeletionProtection`, that the master secret is
CMK-encrypted, and queries RDS Data API over HTTPS (no VPC access needed on
port 5432) to verify all 6 HR tables, all 5 database roles, `agent_state`,
and (when `seed: true`) the 9 seeded employee rows.

Expected output:

```
OK: hr-data cluster <prefix>-uc-hr-data available (hr db 'hr', checkpoint db 'agent_state', 6 tables + 5 roles verified)
```

## Remove

The HR plan guarantees `destroy --stack` keeps the cluster, the secret, and
the backups when `retain_data: true`. Dropping salary rows is a separate,
explicit step, not part of `destroy`.

```bash
# Remove the entry from platform.yaml first
./scripts/deploy.sh destroy --stack ${PROJECT:-agentcore-production}-${ENV:-prod}-uc-hr-data
```

Destroy order across HR stacks (once H3/H4 exist): tools → identity → data.
HR stacks do not import each other through CloudFormation exports, so
CloudFormation may allow a different order — do not take it. See the
"Deploy and destroy" section of
[`custom-app-plan/phases.md`](../../custom-app-plan/phases.md).
