# GFG deployment, part 2

Part 1 is the platform. This file adds the HR assistant on top of it, in three layers (five deploy/test phases, the local A2UI web UI + EBA Console, and a final sign-off checklist). Finish the verify command for a phase before you start the next one. You can also remove one phase and leave the rest running. The order and the reasons are in `custom-app-plan/phases.md`. If this file and that plan disagree about a command, this file is the one you run.

Do not run `./scripts/deploy.sh workshop`. Do not run `./scripts/deploy.sh destroy` without `--stack` or `--team hr`. A bare `destroy` deletes the whole platform. Do not run `./scripts/deploy.sh design --profile`. That rewrites `platform.yaml` from a preset. `design` on its own only prints the plan.

All HR code lives on the `part2-without-opa-godbot-v3` branch:

- `use-cases/hr-data/`
- `use-cases/hr-identity/`
- `use-cases/hr-tools/`
- `agent-code/god-agent/`
- `hr-web/`

Confirm you are on `part2-without-opa-godbot-v3` (`git checkout part2-without-opa-godbot-v3`) before starting.

## Before you start

Part 1, Step 15, passed on this checkout. The virtualenv is active (`.venv/bin/python`). `REGION` is the Region in your notepad.

### Deployer-local prerequisites

- Python 3.13 with `pip` (the repo's `.venv` set up in Part 1), Node.js 20/22/24 with `npm` and global `aws-cdk` (`npm install -g aws-cdk` inside the active Node prefix), AWS CLI v2, and Bash 4+. If you use `mise`, `mise.toml` pins Node 24, Python 3.13, and `.venv` automatically (run `npm install -g aws-cdk` once under that `mise` Node 24 environment so `npx --no-install cdk` resolves).
- Outbound HTTPS to `pypi.org` and `files.pythonhosted.org` so CDK synth can vendor `pg8000==1.31.5`, `scramp==1.4.9`, and `python-dateutil<3.0.0` into `use-cases/hr-identity/layer/python/` and `manylinux2014_aarch64` wheels for `psycopg[binary]` into the H4 Lambda assets (both cached locally after the first synth). Behind a corporate proxy, export `HTTPS_PROXY` before running `deploy.sh`.
- **No external policy binary is required.** Row- and attribute-level HR authorization runs natively in Python (`use-cases/hr-tools/lambdas/shared/authz.py`) with zero external binaries or subprocesses.
- **No Azure Entra portal changes are needed.** Entra still redirects to Cognito's `/oauth2/idpresponse` URL from Part 1; Cognito's own SPA WebClient gets the local `hr-web` `:8899` callback URLs when `$PREFIX-auth` updates.

### Read the stack prefix from `platform.yaml`

Do not export `AWS_REGION` (`platform.yaml` owns the deploy Region). Set `PREFIX` as a shell variable (do not `export` it — `npm` and `npx` treat `process.env.PREFIX` as their global install prefix) and export `SSM` and `REGION` for the CLI commands below:

```bash
eval "$(.venv/bin/python - <<'PY'
from infra_utils.platform_config import load_platform_config
cfg = load_platform_config("platform.yaml")
print(f"unset PREFIX; PREFIX={cfg.project}-{cfg.environment}")
print(f"export SSM=/{cfg.project}/{cfg.environment}")
print(f"export REGION={cfg.region}")
PY
)"
echo "stacks: $PREFIX"
echo "ssm:    $SSM"
echo "region: $REGION"
```

Stack names use the hyphen form, `agentcore-production-prod-uc-hr-data`. SSM names use the slash form, `/agentcore-production/prod/...`. Use what the block above prints.

Add two lines to `gfg-deploy-notes.txt`. Leave them blank until Phase 3:

```text
E1 Cognito sub:
M1 Cognito sub:
```

When an interactive deploy asks for Region, agent pattern, or IdP, press Enter to keep the values from `platform.yaml` (the only phase that changes `agents.pattern` is Phase 5). Because `platform.yaml` already defines every setting authoritatively, you can also prefix `deploy.sh deploy` with `NON_INTERACTIVE=1` (as shown below) to skip interactive prompts completely.

### Same `design` / `doctor` / `verify` commands in Part 2

The three top-level commands from Part 1 automatically expand to cover Part 2 as you add each HR block to `platform.yaml`:

```bash
# 1. Validate platform.yaml and print the stack plan + enabled HR use cases (no AWS mutations)
./scripts/deploy.sh design

# 2. Read-only preflight: checks tools, AWS account/Region, secrets, Bedrock model,
#    and Part 2 prerequisites (networking, KMS, brokered Cognito, egress filter, Cedar ENFORCE)
./scripts/deploy.sh doctor

# 3. Full-footprint health check: runs all 8 Part 1 checks (using --agui for god-agent)
#    PLUS use-cases/hr-data/verify.py, hr-identity/verify.py, and hr-tools/verify.py
./scripts/deploy.sh verify
```

Run `design` and `doctor` after each `platform.yaml` edit below, run the per-phase `verify.py` right after each stack deploy, and run `./scripts/deploy.sh verify` in Phase 7 to prove all 11 checks pass together.

## Phase 1. Database (`hr-data`)

Append `use_cases` with only `hr-data` to the bottom of `platform.yaml` (leave `hr-identity` and `hr-tools` out until their phases):

```yaml
use_cases:
  hr-data:
    database_name: hr
    retain_data: true
    seed: true
```

`seed: true` loads the nine demo employees (`M1`, `E1`, `E2`, `P1`, `R1`–`R4`, `X1`), their salaries, their leave balances, and E1's `2026-10` telephone allowance row (`docs/hr/schema.md` § Demo seed). Use it only on this demo database; the seed refuses to run if any `employee_id` outside the nine-id demo set is already present. `retain_data: true` keeps the cluster, master secret, and backups when you later delete the stack.

Validate, deploy (~8–12 minutes on first create while Aurora Serverless v2 provisions its writer instance), and verify:

```bash
./scripts/deploy.sh design
./scripts/deploy.sh doctor
NON_INTERACTIVE=1 ./scripts/deploy.sh deploy --stack "$PREFIX-uc-hr-data"
.venv/bin/python use-cases/hr-data/verify.py
```

What happens during deploy:

- `ResolvePlatformKeyArn` resolves `alias/$PREFIX-agentcore` to its backing KMS key ARN (`arn:aws:kms:...:key/<uuid>`) so Aurora storage encryption, the master secret in Secrets Manager, and the provisioner's `kms:Decrypt` IAM policy all bind to the real CMK key ARN without modifying `SecurityStack`.
- Aurora PostgreSQL Serverless v2 (`0.5`–`2.0` ACU) starts in the private subnets using the region's supported default Aurora PostgreSQL engine version, with IAM database authentication and RDS Data API (`EnableHttpEndpoint`) enabled.
- The provisioner CustomResource runs over RDS Data API (HTTPS) to ensure both `hr` and `agent_state` databases exist, applies `schema.sql` (`employees`, `salaries`, `leave_balances`, `leave_requests`, `payroll_items`, `decision_log` + roles `hr_reader`, `hr_writer`, `hr_audit`, `hr_identity`), applies `agent_state_schema.sql` (`agent_checkpoint` role with `USAGE, CREATE ON SCHEMA public`), and applies `seed.sql` when `seed: true`.

`verify.py` does not need VPC access on port 5432. It checks the four SSM parameters (`$SSM/use-cases/hr-data/{endpoint,secret-name,database-name,checkpoint-database}`), cluster encryption/IAM-auth/Data-API/deletion-protection flags, master secret CMK encryption, and queries RDS Data API over HTTPS to confirm all 6 tables, all 5 database roles, `agent_state`, and the 9 seeded employees are live (`OK: hr-data cluster ... available (... 6 tables + 5 roles verified)`).

### Remove only the database

Do this only when the tools stack, the identity stack, and the god agent are already gone.

```bash
./scripts/deploy.sh destroy --stack "$PREFIX-uc-hr-data"
```

Then delete the `hr-data` block from `platform.yaml`. With `retain_data: true`, the stack goes away while the Aurora cluster, master secret, and backups stay.

## Phase 2. Policy unit tests

No stack and no AWS calls. Run this before deploying tools:

```bash
.venv/bin/python -m pytest tests/test_hr_authz.py -q
```

Forty-two unit tests exercise `use-cases/hr-tools/lambdas/shared/authz.py` directly in Python across every row of `docs/hr/acceptance.md` § H2, including one-hop direct-report salary rules, live manager transfer, probation/range/balance/overlap precedence, reviewer-only leave decisions, and closed failure on malformed inputs.

## Phase 3. Identity (`hr-identity`)

Update the `use_cases` block in `platform.yaml` to add `hr-identity` (indented two spaces under `use_cases:`):

```yaml
use_cases:
  hr-data:
    database_name: hr
    retain_data: true
    seed: true
  hr-identity: {}
```

Validate, deploy, and verify:

```bash
./scripts/deploy.sh design
./scripts/deploy.sh doctor
NON_INTERACTIVE=1 ./scripts/deploy.sh deploy --stack "$PREFIX-uc-hr-identity"
.venv/bin/python use-cases/hr-identity/verify.py
```

What happens during deploy:

- CDK synth automatically installs `pg8000==1.31.5`, `scramp==1.4.9`, and `python-dateutil<3.0.0` into `use-cases/hr-identity/layer/python/`.
- The pre-token Lambda deploys into the private subnets with `rds-db:connect` scoped to `hr_identity` only.
- `TriggerManagerFunction` performs a safe read-modify-write `DescribeUserPool` → `UpdateUserPool`, preserving `DeletionProtection`, `AdminCreateUserConfig`, `Policies`, and any existing triggers while ensuring `UserPoolTier` is at least `ESSENTIALS` and attaching `PreTokenGenerationConfig` with `LambdaVersion: V3_0` (required for M2M `TokenGeneration_ClientCredentials` + `aws_client_metadata` enrichment as well as federated human sign-ins).

`verify.py` confirms `$SSM/use-cases/hr-identity/function-arn` exists, the Lambda is `Active`, and the user pool's `PreTokenGenerationConfig` points to it at `LambdaVersion=V3_0`.

### Map Cognito users to employees

The demo seed leaves `cognito_sub = NULL` on every row. Sign in at least once as the two Entra users who will test as `E1` (employee / middle manager of `R1`–`R4`) and `M1` (direct manager of `E1`, `E2`, `P1`) using `.venv/bin/python scripts/login_chat.py` from Part 1, then list their Cognito `sub` UUIDs:

```bash
POOL=$(aws ssm get-parameter --region "$REGION" \
  --name "$SSM/auth/user-pool-id" --query Parameter.Value --output text)
aws cognito-idp list-users --region "$REGION" --user-pool-id "$POOL" \
  --query "Users[].{name:Username,email:Attributes[?Name=='email']|[0].Value,sub:Attributes[?Name=='sub']|[0].Value}" \
  --output table
```

> **Note on Entra `email` vs UPN:** In Microsoft Entra ID (especially `*.onmicrosoft.com` tenants), Cognito's `email` attribute reflects the user's **Contact Information → Email (`mail`)** field in Entra rather than their sign-in UPN (`preferred_username`). That display email has zero effect on authorization — `hr-identity` resolves users strictly by the immutable Cognito `sub` UUID (`Attributes[?Name=='sub']`).

Copy the `sub` UUIDs (not `EntraID_...` `Username`) into `gfg-deploy-notes.txt`, then map them onto `E1` and `M1` over RDS Data API (if you only have one Entra user signed in so far, set `E1_SUB` now to unblock Phase 4–5 and leave `M1_SUB=""` until `M1` signs in):

```bash
CLUSTER_ARN=$(aws rds describe-db-clusters --region "$REGION" \
  --db-cluster-identifier "$PREFIX-uc-hr-data" \
  --query 'DBClusters[0].DBClusterArn' --output text)
SECRET_NAME=$(aws ssm get-parameter --region "$REGION" \
  --name "$SSM/use-cases/hr-data/secret-name" --query Parameter.Value --output text)
SECRET_ARN=$(aws secretsmanager describe-secret --region "$REGION" \
  --secret-id "$SECRET_NAME" --query ARN --output text)

E1_SUB="paste-E1-sub-uuid-from-notepad"
M1_SUB="paste-M1-sub-uuid-from-notepad"

for row in "E1:$E1_SUB" "M1:$M1_SUB"; do
  ID="${row%%:*}"; SUB="${row##*:}"
  if [[ -z "$SUB" || "$SUB" == paste-* ]]; then
    echo "Skipping $ID (sub not set yet)"
    continue
  fi
  aws rds-data execute-statement --region "$REGION" \
    --resource-arn "$CLUSTER_ARN" --secret-arn "$SECRET_ARN" --database hr \
    --sql "UPDATE employees SET cognito_sub = :sub WHERE employee_id = :id" \
    --parameters "[{\"name\":\"sub\",\"value\":{\"stringValue\":\"$SUB\"}},{\"name\":\"id\",\"value\":{\"stringValue\":\"$ID\"}}]"
done

# Confirm mapped employee rows:
aws rds-data execute-statement --region "$REGION" \
  --resource-arn "$CLUSTER_ARN" --secret-arn "$SECRET_ARN" --database hr \
  --sql "SELECT employee_id, cognito_sub, manager_id, status FROM employees WHERE cognito_sub IS NOT NULL ORDER BY employee_id"
```

### Remove only identity

```bash
./scripts/deploy.sh destroy --stack "$PREFIX-uc-hr-identity"
```

The `TriggerManagerFunction` Delete handler removes only `PreTokenGenerationConfig`/`PreTokenGeneration` while preserving all other user-pool settings. Remove `hr-identity` from `platform.yaml`.

## Phase 4. Tools (`hr-tools` + Gateway header promotion)

Update `use_cases` in `platform.yaml` to add `hr-tools`:

```yaml
use_cases:
  hr-data:
    database_name: hr
    retain_data: true
    seed: true
  hr-identity: {}
  hr-tools: {}
```

Enabling `hr-tools` turns on `PassRequestHeaders: true` and `HR_IDENTITY_PROMOTION=1` on the platform Gateway's REQUEST interceptor so validated JWT claims (`employee_id`, `agent_id`) are promoted onto HR tool arguments and cannot be spoofed by the model. **Deploy `$PREFIX-gateway` first** (CDK also checks its `$PREFIX-security` and `$PREFIX-auth` dependencies, registering the `:8899` SPA callbacks on `WebClient` while preserving `hr-identity`'s `V3_0` trigger), **then deploy `$PREFIX-uc-hr-tools`:**

```bash
./scripts/deploy.sh design
./scripts/deploy.sh doctor
NON_INTERACTIVE=1 ./scripts/deploy.sh deploy --stack "$PREFIX-gateway"
NON_INTERACTIVE=1 ./scripts/deploy.sh deploy --stack "$PREFIX-uc-hr-tools"
.venv/bin/python use-cases/hr-tools/verify.py
```

What `verify.py` proves:

1. Kill switch `$SSM/use-cases/hr-tools/enabled` is `true`.
2. Gateway REQUEST interceptor has `PassRequestHeaders=true` and `HR_IDENTITY_PROMOTION=1`.
3. All 3 HR Gateway targets (`hr-ops`, `hr-payroll`, `hr-finance`) are `READY`.
4. All 3 Cedar permits (`hr_tools_read_permit`, `hr_tools_submit_permit`, `hr_tools_decision_permit`) are `ACTIVE`.
5. Bare M2M `tools/list` succeeds and exposes no `approve_leave` tool.
6. Because `E1` was mapped in Phase 3, `verify.py` mints a contextual `leave-balance` M2M token via Cognito `/oauth2/token` + `aws_client_metadata` and verifies a live `tools/call` on `hr-ops___get_leave_balance` returns `authorized: true`.

### Remove only the tools

Ensure Phase 5 (`god-agent`) is already switched back first. Then destroy `uc-hr-tools`, remove `hr-tools:` from `platform.yaml`, and redeploy `gateway` so `PassRequestHeaders` returns to `false`:

```bash
./scripts/deploy.sh destroy --stack "$PREFIX-uc-hr-tools"
# remove hr-tools: {} from platform.yaml, then:
./scripts/deploy.sh deploy --stack "$PREFIX-gateway"
```

## Phase 5. God Agent (`agent-code/god-agent/`)

Start this only after Phase 4's `verify.py` exits `0`.

In `platform.yaml`, change `agents.pattern` to `god-agent` (keep `model_id` and `allowed_models` unchanged):

```yaml
agents:
  pattern: god-agent
```

Validate with `design` and `doctor`, then ensure `$PREFIX-auth` is up to date (`http://127.0.0.1:8899/` and `http://localhost:8899/` on the Cognito SPA web client for Phase 6 while leaving `login_chat.py`'s app client untouched) and deploy `$PREFIX-runtime-orchestrator` (CodeBuild builds the `god-agent` container remotely in ~3–5 minutes and updates the runtime in-place to the `AGUI` protocol with `rds-db:connect` for `agent_checkpoint`, M2M secret read for `aws_client_metadata` exchanges, and web-client JWT acceptance):

```bash
./scripts/deploy.sh design
./scripts/deploy.sh doctor
NON_INTERACTIVE=1 ./scripts/deploy.sh deploy --stack "$PREFIX-auth"
NON_INTERACTIVE=1 ./scripts/deploy.sh deploy --stack "$PREFIX-runtime-orchestrator"
NON_INTERACTIVE=1 ./scripts/deploy.sh verify
```

If you run without `NON_INTERACTIVE=1`, press Enter at the prompts to keep `god-agent` (loaded from `platform.yaml`) and Entra. On its first invocation (`deploy.sh verify` runs `invoke.py --agui` automatically), `god-agent` connects to `agent_state` as `agent_checkpoint` via RDS IAM auth and runs `AsyncPostgresSaver.setup()` to create its checkpoint tables.

Test from the terminal as `E1` and as `M1`:

```bash
# Single question (prints the Session ID used)
.venv/bin/python scripts/login_chat.py --prompt "How many leaves do I have?"

# Compound question (routes to both hr-operations and finance-payroll)
.venv/bin/python scripts/login_chat.py --prompt "How many leaves do I have and what was my telephone allowance last month?"

# Submit leave (pauses for employee confirmation on that Session ID)
.venv/bin/python scripts/login_chat.py --prompt "Submit annual leave from 2026-12-01 to 2026-12-03 for a family trip"

# Confirm the employee pause on the printed Session ID (as E1)
.venv/bin/python scripts/login_chat.py --session "<SESSION_ID>" --resume approve

# Approve the pending request as M1 (using the lr-... request_id printed above)
.venv/bin/python scripts/login_chat.py --session "<NEW_OR_SAME_SESSION>" --request-id "<lr-...>" --resume approve
```

Tick every H5 and Red-Team row in `docs/hr/acceptance.md`.

### Remove only the agent

Set `agents.pattern` in `platform.yaml` back to the pattern Part 1 used (for example `strands-agent`), then redeploy `runtime-orchestrator`:

```bash
./scripts/deploy.sh deploy --stack "$PREFIX-runtime-orchestrator"
```

Do not destroy `runtime-orchestrator`.

## Phase 6. Web UI (`hr-web/`) & EBA Console (`dashboard/`)

Start this only after Phase 5 passes in the terminal. There is no CloudFormation stack for the UI.

### Start `hr-web` (`127.0.0.1:8899`)

```bash
.venv/bin/python hr-web/server.py
```

`server.py` binds strictly to `127.0.0.1:8899`. Open `http://127.0.0.1:8899/` in your browser:

1. Click **Sign in** — completes the Cognito + Entra PKCE flow in the browser (tokens live in browser memory only).
2. Ask HR questions — requests stream over same-origin `POST /invocations` (forwarding only your Bearer token to the AgentCore Runtime `AGUI` SSE endpoint, with zero server-side AWS credentials and no cross-origin CORS preflight issues), and tool results render `LeaveBalanceCard`, `AllowanceCard`, `DirectReportsTable`, and `ProbationNotice` dynamically through the A2UI v1.0 catalog (`hr-web/public/hr-catalog.json`).
3. Ask to book leave as `E1` — `EmployeeConfirmForm` appears on the right. Typing `"approve"` in chat does not submit; clicking **Confirm** submits one `pending` request (`submit_leave_request`).
4. Click **Sign out** (clears token, chat, and thread), then click **Sign in** as `M1` — `hr-web` automatically polls pending reviews for `M1` on sign-in (or click **Check reviews**) and renders `ManagerReviewCard` with **Approve** and **Reject** buttons. Clicking **Approve** invokes `record_leave_decision` as `M1` and records the approval.

### Start the EBA Console alongside `hr-web` (`127.0.0.1:8888`)

Because `hr-web` uses port `8899` and the EBA Console uses port `8888`, both can run simultaneously in separate terminals:

```bash
# Terminal A: status poller (updates dashboard/public/status.json every 15s)
.venv/bin/python dashboard/monitor.py

# Terminal B: loopback EBA Console on http://127.0.0.1:8888
.venv/bin/python dashboard/server.py
```

Open `http://127.0.0.1:8888/`: **Overview** shows `11/11` deployed stacks (including `uc-hr-data`, `uc-hr-identity`, `uc-hr-tools`), **Parameters** displays the 6 published HR SSM paths, **Architecture** renders the `HR assistant (Part 2 · god-agent runtime)` X-Ray band and audit edges, and **Playground** invokes `god-agent` over `AG-UI · OAuth`.

### Remove only the UI

Press `Ctrl+C` in the terminal(s) running `hr-web/server.py`, `dashboard/monitor.py`, and `dashboard/server.py`.

## Phase 7. Final Part 2 checklist

Run the full-footprint health check and tick every row after deploying Phases 1–6:

| # | Check | Command / Action | Pass when |
|---|---|---|---|
| 1 | Preflight clean | `./scripts/deploy.sh doctor` | `0 failed`, `[PASS] HR Part 2: hr-data, hr-identity, hr-tools, pattern=god-agent ready` |
| 2 | All 11 stacks green | `aws cloudformation describe-stacks --region "$REGION" --query "Stacks[?starts_with(StackName,'${PREFIX}-')].[StackName,StackStatus]" --output table` | 11 stacks, each `CREATE_COMPLETE` or `UPDATE_COMPLETE` |
| 3 | Full automated verify | `./scripts/deploy.sh verify` | `OK: all 11 checks passed for this footprint` |
| 4 | Runtime log clean | `LG=$(aws logs describe-log-groups --region "$REGION" --log-group-name-prefix "/aws/bedrock-agentcore/runtimes/${PREFIX//-/_}_orchestrator" --query 'logGroups[0].logGroupName' --output text) && aws logs filter-log-events --region "$REGION" --log-group-name "$LG" --start-time $(( ($(date +%s) - 900) * 1000 )) --query 'events[].message' --output text \| grep -E 'AccessDenied\|Agent run failed\|God agent run failed\|Memory init failed\|Rejected\|guardrail_intervened'` | No output (exit code `1` from `grep`) |
| 5 | Audit log free of amounts | `CLUSTER_ARN=$(aws rds describe-db-clusters --region "$REGION" --db-cluster-identifier "$PREFIX-uc-hr-data" --query 'DBClusters[0].DBClusterArn' --output text) && SECRET_NAME=$(aws ssm get-parameter --region "$REGION" --name "$SSM/use-cases/hr-data/secret-name" --query Parameter.Value --output text) && SECRET_ARN=$(aws secretsmanager describe-secret --region "$REGION" --secret-id "$SECRET_NAME" --query ARN --output text) && aws rds-data execute-statement --region "$REGION" --resource-arn "$CLUSTER_ARN" --secret-arn "$SECRET_ARN" --database hr --sql "SELECT action, caller_employee_id, allow, reason_code, decided_by_layer FROM decision_log ORDER BY id DESC LIMIT 10"` | Rows present with `decided_by_layer` in `('policy','tool')`, zero salaries or leave reasons |
| 6 | Salary & probation rules | `login_chat.py` / `hr-web` as `E1` and `M1` (`docs/hr/acceptance.md` § H5) | `E1` sees `R1`–`R4` and not `M1`; `M1` sees `E1`/`E2`/`P1` and not `R1`–`R4` |
| 7 | Two-stage human review | Submit leave in `hr-web` as `E1`, confirm card, sign in as `M1`, approve card (`docs/hr/acceptance.md` § H6) | Typed `"approve"` in chat does nothing; `M1` card button transitions row to `approved` |
| 8 | EBA Console inventory | Open `http://127.0.0.1:8888/` | `11/11` stacks green, HR X-Ray band + 6 HR SSM parameters visible |

## Remove everything from part 2

Leave Part 1 up. Pick either Path A or Path B.

### Path A — explicit per-phase

1. Stop `hr-web/server.py`.
2. Set `agents.pattern` back to Part 1's pattern and run `./scripts/deploy.sh deploy --stack "$PREFIX-runtime-orchestrator"`.
3. `./scripts/deploy.sh destroy --stack "$PREFIX-uc-hr-tools"`
4. `./scripts/deploy.sh destroy --stack "$PREFIX-uc-hr-identity"`
5. `./scripts/deploy.sh destroy --stack "$PREFIX-uc-hr-data"`
6. Remove the `use_cases:` block from `platform.yaml` and run `./scripts/deploy.sh deploy --stack "$PREFIX-gateway"` so `PassRequestHeaders` returns to `false`.

### Path B — one command for the HR stacks

After step 1 and step 2 above (switching `runtime-orchestrator` back to Part 1's pattern):

```bash
./scripts/deploy.sh destroy --team hr
```

Then remove `use_cases:` from `platform.yaml`, run `./scripts/deploy.sh deploy --stack "$PREFIX-gateway"` if you want `PassRequestHeaders` reset immediately, and confirm Part 1 Step 15 (`./scripts/deploy.sh verify` → `OK: all 8 checks passed`).

### Full-footprint destroy (`./scripts/deploy.sh destroy`)

Running bare `./scripts/deploy.sh destroy` tears down **both** Part 2 and Part 1 (`cdk destroy --all --force` plus `sweep_leftovers` for `/aws/lambda/$PREFIX-*` and `/aws/codebuild/$PREFIX-*` log groups). Use it only when decommissioning the entire environment.

### Retain semantics

With `retain_data: true` (the default), none of the destroy paths delete the Aurora cluster, writer instance, master secret, automated backups, or `/aws/rds/cluster/$PREFIX-uc-hr-data/postgresql` log group.

## Turn HR off in an emergency

Stops every HR tool and the `god-agent` entrypoint within 30 seconds with no redeploy:

```bash
aws ssm put-parameter --overwrite --type String \
  --name "$SSM/use-cases/hr-tools/enabled" --value false --region "$REGION"
```

Set back to `true` to resume.

## Rollback and retry

Part 2 is designed so a failed deploy can be fixed and re-run without wedging in `ROLLBACK_FAILED` or colliding with orphaned resources:

1. **`RetainExceptOnCreate` (`RETAIN_ON_UPDATE_OR_DELETE`)**: All retained HR resources (Aurora cluster/instance/subnet-group/secret and the 365-day CloudWatch log groups across `uc-hr-data`, `uc-hr-identity`, and `uc-hr-tools`) use CloudFormation `RetainExceptOnCreate`. If a stack fails during its **very first** create, CloudFormation deletes the partial resources cleanly during rollback instead of leaving fixed-name log groups or DB clusters behind that would block your retry with `ResourceAlreadyExistsException`. Once the stack reaches `CREATE_COMPLETE`, retention is armed for all future updates and `destroy` runs.
2. **Deferred `DeletionProtection` & safe trigger rollback**: `uc-hr-data` enables RDS `DeletionProtection` inside the provisioner CustomResource **only after** `schema.sql`, `agent_state_schema.sql`, and `seed.sql` succeed, and `uc-hr-identity`'s trigger manager skips `UpdateUserPool` on `Delete` if `Create` never attached the trigger — preventing `ROLLBACK_FAILED`.
3. **Automatic `ROLLBACK_COMPLETE` shell cleanup**: If a Part 2 stack fails on its first create and lands in `ROLLBACK_COMPLETE`, `scripts/deploy.sh` prints the failing `StackEvents`, releases the SSM deployment lock (even on `Ctrl+C`), and on your next `./scripts/deploy.sh deploy --stack "$PREFIX-uc-hr-..."` automatically deletes the empty `ROLLBACK_COMPLETE` shell before recreating it (`security` and `auth` are never auto-deleted).
4. **Update failures**: If a stack already reached `CREATE_COMPLETE` and a later code/config update fails, CloudFormation rolls back in place to `UPDATE_ROLLBACK_COMPLETE`. Fix your code and re-run the exact same `./scripts/deploy.sh deploy --stack ...` command.

## When something fails

| What you see | Why | What to do |
|---|---|---|
| `[FAIL] HR Part 2 ...` in `./scripts/deploy.sh doctor` | `platform.yaml` turned off a prerequisite (`networking`, `egress_filter`, `cedar: ENFORCE`, `require_guardrails`, or `brokered` mode) | Restore the missing flag in `platform.yaml` and re-run `doctor` |
| `FAIL: gateway ... has PassRequestHeaders=false` in `hr-tools/verify.py` | `$PREFIX-gateway` was not redeployed after adding `hr-tools` to `platform.yaml` | Run `./scripts/deploy.sh deploy --stack "$PREFIX-gateway"`, then re-run `verify.py` |
| `redirect_uri_mismatch` when clicking Sign in on `http://127.0.0.1:8899/` | `$PREFIX-auth` has not been updated from `part2-without-opa-godbot-v3` yet | Run `./scripts/deploy.sh deploy --stack "$PREFIX-auth"` so `:8899` callbacks are on the web client |
| `Runtime HTTP 401` or `403` in `hr-web` after signing in | `$PREFIX-runtime-orchestrator` has not been updated with `agents.pattern: god-agent` | Set `agents.pattern: god-agent` and run `./scripts/deploy.sh deploy --stack "$PREFIX-runtime-orchestrator"` |
| Sign-in succeeds, but every HR question answers not allowed / `NOT_MAPPED` | That user's Cognito `sub` UUID is not mapped in `employees.cognito_sub` | Run the "Map Cognito users to employees" block in Phase 3 using `Attributes[?Name=='sub']` (not `EntraID_...` `Username`) |
| Seed exits because another employee id exists | The database already holds non-demo rows | Set `seed: false` |
| Every HR answer is `"The HR assistant is paused"` | `$SSM/use-cases/hr-tools/enabled` is not `true` | Set it back to `true` when ready |
| A tool call is denied with no `decision_log` row | Cedar denied the call at the Gateway before the Lambda ran | Check `$SSM/use-cases/hr-identity/function-arn` and `PreTokenGenerationConfig` (`V3_0`) via `.venv/bin/python use-cases/hr-identity/verify.py` |
