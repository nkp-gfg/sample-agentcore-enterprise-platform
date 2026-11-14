# GFG deployment, part 2

Part 1 is the platform. This file adds the HR assistant on top of it, in three layers (five deploy phases plus the local web UI). Finish the verify command for a phase before you start the next one. You can also remove one phase and leave the rest running. The order and the reasons are in `custom-app-plan/phases.md`. If this file and that plan disagree about a command, this file is the one you run. The plan was updated to match these commands.

Do not run `./scripts/deploy.sh workshop`. Do not run `./scripts/deploy.sh destroy` without `--stack`. That deletes the whole platform. Do not run `./scripts/deploy.sh design --profile`. That rewrites `platform.yaml` from a preset. `design` on its own only prints the plan.

All HR code lives on the `with-ui-godbot-v2` branch (the merged bundle of H1 through H3, H4, Layer 2 god-agent, and Layer 3 A2UI web). The folders below exist on that branch:

- `use-cases/hr-data/`
- `use-cases/hr-identity/`
- `use-cases/hr-tools/`
- `agent-code/god-agent/`
- `hr-web/`

If a folder in the step you are on is missing, you are on a branch without that phase. Stop and check out `with-ui-godbot-v2`.

## Before you start

Part 1, Step 15, passed on this checkout. The virtualenv is active. `REGION` is the Region in your notepad.

### Deployer-local prerequisites

The HR Lambda assets are assembled at CDK synth time, not at deploy time, so the deployer machine needs:

- Python 3.13 with `pip`. The repo's `.venv` is already set up by Part 1.
- Outbound HTTPS to `openpolicyagent.org` and `pypi.org` for one-time downloads (cached in `$TMPDIR/hr-tools-opa-cache` and in the H3 layer's `python/` directory). Behind a proxy, export `HTTPS_PROXY` before `cdk deploy`.
- No local `opa` binary is required — `use-cases/hr-tools/stack.py` downloads a pinned linux/arm64 static release with a sha256 check, matching the Lambda runtime architecture.
- No manual `pip install` into `use-cases/hr-identity/layer/python/` — `use-cases/hr-identity/stack.py` installs `pg8000==1.31.5` into it at synth, idempotent.

### Read the stack prefix from `platform.yaml`

```bash
eval "$(python - <<'PY'
from pathlib import Path
import re
text = Path("platform.yaml").read_text()
project = re.search(r"^project:\s*(\S+)", text, re.M).group(1)
environment = re.search(r"^environment:\s*(\S+)", text, re.M).group(1)
print(f"export PREFIX={project}-{environment}")
print(f"export SSM=/{project}/{environment}")
PY
)"
echo "stacks: $PREFIX"
echo "ssm:    $SSM"
```

Stack names use the hyphen form, `agentcore-production-prod-uc-hr-data`. SSM names use the slash form, `/agentcore-production/prod/...`. If the command prints something else, use what it prints. Do not assume.

Add two lines to `gfg-deploy-notes.txt`. Leave them blank until the identity phase.

```text
E1 Cognito sub:
M1 Cognito sub:
```

When a deploy asks which agent pattern to use, press Enter and keep the pattern Part 1 is already running. When it asks about the IdP, keep Entra. The only phase that changes the pattern is the agent phase.

## Phase 1. Database

Enable only the database. Leave the other two use cases out of `platform.yaml` until their phases.

```yaml
use_cases:
  hr-data:
    database_name: hr
    retain_data: true
    seed: true
```

`seed: true` loads the nine demo people, their salaries, their leave balances, and E1's `2026-10` telephone allowance row (`docs/hr/schema.md` § Demo seed). Use it only on this demo database. The seed refuses to run if any `employee_id` outside the nine-id demo set is already there. `retain_data: true` keeps the cluster when you later delete the stack.

```bash
./scripts/deploy.sh deploy --stack "$PREFIX-uc-hr-data"
python use-cases/hr-data/verify.py
```

The provisioner Lambda runs on CREATE and UPDATE and applies three SQL files in order: `schema.sql` in the `hr` database (tables, indexes, four roles: `hr_reader`, `hr_writer`, `hr_audit`, `hr_identity`), then `agent_state_schema.sql` in the `agent_state` database (creates the fifth role, `agent_checkpoint`, with `CREATE` on `public` so the god agent's LangGraph `PostgresSaver.setup()` can create its checkpoint tables there), then `seed.sql` when `seed: true`.

The database is in a private subnet. `verify.py` does not connect to it from your laptop. It checks the stack and these SSM parameters:

- `$SSM/use-cases/hr-data/endpoint`
- `$SSM/use-cases/hr-data/secret-name`
- `$SSM/use-cases/hr-data/database-name`
- `$SSM/use-cases/hr-data/checkpoint-database`

It also calls `rds:DescribeDBClusters` and `secretsmanager:DescribeSecret` to prove the cluster is `available`, `StorageEncrypted`, `IAMDatabaseAuthenticationEnabled`, and `DeletionProtection` are on, and the master secret is CMK-encrypted. A pass here does not prove a salary query. That happens in phase 4, from inside the VPC.

### Remove only the database

Do this only when the tools stack, the identity stack, and the god agent are already gone. If you delete the database first, those stacks are left pointing at nothing.

```bash
./scripts/deploy.sh destroy --stack "$PREFIX-uc-hr-data"
```

Then delete the `hr-data` block from `platform.yaml`.

The stack goes away. The cluster, the secret, and the backups stay, including the salary rows, `decision_log`, and every checkpoint row in `agent_state`. Deleting those is a later, separate operation. `destroy` does not do it.

## Phase 2. Policy tests

No stack. Run this before the tools phase. It does not call AWS.

```bash
pytest tests/test_hr_authz.py
```

The run requires the pinned OPA 1.22.4 binary on `$PATH` (`.gitlab-ci.yml` installs it with a sha256 check; locally, install via `mise install` or follow `use-cases/hr-tools/README.md`). Forty-one cases cover every pure-Rego row in `docs/hr/acceptance.md` § H2, plus first-match-ordering (probation > overlap, range > balance) and default-deny-on-unknown-action.

A failure here is a rule bug. Do not deploy the tools to find it.

There is nothing to destroy.

## Phase 3. Identity

Add `hr-identity` under `use_cases`. Leave `hr-data` as it is. Do not add `hr-tools` yet.

```yaml
  hr-identity: {}
```

```bash
./scripts/deploy.sh deploy --stack "$PREFIX-uc-hr-identity"
python use-cases/hr-identity/verify.py
```

CDK synth runs `pip install pg8000==1.31.5 --target use-cases/hr-identity/layer/python/` automatically if the pinned version is not already there, so no manual pip-install step is required.

`verify.py` is SSM-only on the deployer side. It:

1. reads `$SSM/use-cases/hr-identity/function-arn` and confirms the SSM parameter exists,
2. calls `lambda:GetFunction` and confirms `State: Active`,
3. calls `cognito-idp:DescribeUserPool` and confirms `LambdaConfig.PreTokenGenerationConfig.LambdaArn` matches the Lambda ARN.

End-to-end claims — two users get two different `employee_id` claims, X1 and an unknown `sub` get no `employee_id`, `calling_agent: leave-submit` carries `agent_id: leave-submit` — are proved by H4's `verify.py` and the H5 acceptance set from inside the VPC through the gateway.

### Map Cognito users to employees

The demo seed sets `cognito_sub = NULL` for every row (`docs/hr/schema.md`). A real sign-in by someone whose `sub` is not yet mapped onto an `employees` row returns `NOT_MAPPED` from the pre-token Lambda and the HR tools refuse every call. Map the facilitator and one tester to E1 and M1 once per environment, through the RDS Data API from the deployer's shell. No psql or VPC bastion is required.

Sign in from Part 1's web client as the two humans you want to act as E1 and M1, then record their Cognito `sub` claims:

```bash
POOL=$(aws ssm get-parameter --region "$REGION" \
  --name "$SSM/auth/user-pool-id" --query Parameter.Value --output text)
aws cognito-idp list-users --region "$REGION" --user-pool-id "$POOL" \
  --query "Users[].{name:Username,sub:Attributes[?Name=='sub']|[0].Value}" --output table
```

Paste the two values into the two blank lines in `gfg-deploy-notes.txt`. Then map them onto the seed rows:

```bash
CLUSTER_ARN=$(aws rds describe-db-clusters --region "$REGION" \
  --db-cluster-identifier "$PREFIX-uc-hr-data" \
  --query 'DBClusters[0].DBClusterArn' --output text)
SECRET_NAME=$(aws ssm get-parameter --region "$REGION" \
  --name "$SSM/use-cases/hr-data/secret-name" --query Parameter.Value --output text)
SECRET_ARN=$(aws secretsmanager describe-secret --region "$REGION" \
  --secret-id "$SECRET_NAME" --query ARN --output text)

E1_SUB="paste-from-notepad"
M1_SUB="paste-from-notepad"

for row in "E1:$E1_SUB" "M1:$M1_SUB"; do
  ID="${row%%:*}"; SUB="${row##*:}"
  aws rds-data execute-statement --region "$REGION" \
    --resource-arn "$CLUSTER_ARN" --secret-arn "$SECRET_ARN" --database hr \
    --sql "UPDATE employees SET cognito_sub = :sub WHERE employee_id = :id" \
    --parameters "[{\"name\":\"sub\",\"value\":{\"stringValue\":\"$SUB\"}},{\"name\":\"id\",\"value\":{\"stringValue\":\"$ID\"}}]"
done
```

The master secret here is only for this one-off mapping; H3's Lambda itself uses the `hr_identity` database role with an IAM token, not the secret. The Data API endpoint on the cluster is on (`enable_http_endpoint=True`) so this works from any machine with AWS credentials — no VPC access required.

Sign back in. The pre-token Lambda now returns `employee_id: E1` (or `M1`) and the agent treats the caller as that employee.

### Remove only identity

```bash
./scripts/deploy.sh destroy --stack "$PREFIX-uc-hr-identity"
```

This detaches the pre-token trigger from the user pool (the DETACH custom resource in the stack clears `LambdaConfig` on DELETE). The user pool from Part 1 stays. Remove the `hr-identity` block from `platform.yaml`. The database and its `cognito_sub` mappings stay.

## Phase 4. Tools

Add `hr-tools` under `use_cases`.

```yaml
  hr-tools: {}
```

```bash
./scripts/deploy.sh deploy --stack "$PREFIX-uc-hr-tools"
python use-cases/hr-tools/verify.py
```

CDK synth downloads the pinned linux/arm64 OPA static binary (checked against sha256 `9e9afee01319a5044790e59b1a2ece39a943f9b6059b97bd86c7aab88830d833`) and runs `pip install --platform manylinux2014_aarch64 psycopg[binary]==3.3.9` into the Lambda asset, so no local OPA install is required and no manual pip step is needed for the driver.

Enabling `hr-tools` also flips `pass_request_headers` on the gateway interceptor and sets `HR_IDENTITY_PROMOTION=1` on its Lambda env, so the REQUEST-pass identity-promotion block in `tools/egress_interceptor/handler.py` overwrites `caller_employee_id`, `agent_id`, and `session_id` on every HR tool call. Non-HR deployments keep the previous default-False behaviour.

`verify.py` calls the gateway the way `scripts/test_gateway.py` calls the sample tools. It does not chat with the agent. A pass means `tools/list` returns six leaf tools (`get_employee_compensation`, `list_direct_reports`, `get_leave_balance`, `check_leave_eligibility`, `submit_leave_request`, `get_allowance`) and the SSM kill switch `use-cases/hr-tools/enabled` is `true`. The salary, leave, and allowance acceptance cases (`docs/hr/acceptance.md` § H4 + § H5) hold once a real token from H3 carries the right claims.

Keep the Part 1 agent pattern at the prompt. This phase does not change it.

### Remove only the tools

The agent phase must already be off. If the god agent is still deployed, it will call tools that no longer exist.

```bash
./scripts/deploy.sh destroy --stack "$PREFIX-uc-hr-tools"
```

Remove the `hr-tools` block from `platform.yaml`. The next deploy of the gateway stack drops the `pass_request_headers` flag back to False and removes `HR_IDENTITY_PROMOTION` from the interceptor env automatically; non-HR traffic is unaffected. Identity and the database stay.

## Phase 5. Agent

Start this only after phase 4's verify exits 0.

The code is `agent-code/god-agent/`, next to the other patterns. Change `agents.pattern` in `platform.yaml` to `god-agent`. Leave `model_id` and `allowed_models` as they are. If `god-agent` is not one of the choices the deploy script prints, this checkout is not `with-ui-godbot-v2` (or the merge bundle you are on misses Layer 2). Stop. Do not type the name anyway.

```yaml
agents:
  pattern: god-agent
```

```bash
./scripts/deploy.sh deploy --stack "$PREFIX-runtime-orchestrator"
```

At the pattern prompt, choose `god-agent`. Keep Entra. This redeploys the runtime Part 1 already has. It does not add a stack. The CodeBuild project bakes a new image from `agent-code/god-agent/Dockerfile` (linux/arm64). On its first invocation the agent connects to `agent_state` as `agent_checkpoint` with an RDS IAM token and calls `PostgresSaver.setup()`, which creates the four LangGraph checkpoint tables (`checkpoints`, `checkpoint_blobs`, `checkpoint_writes`, `checkpoint_migrations`). H1's `agent_state_schema.sql` already granted `CREATE ON SCHEMA public` to `agent_checkpoint` for this step to succeed.

One question in the terminal:

```bash
.venv/bin/python scripts/login_chat.py --prompt "How many leaves do I have?"
```

Sign in as the person mapped to E1, then run the same command as the person mapped to M1. `scripts/invoke.py` is a machine token. A green run of it does not prove this phase.

A leave request that should pause comes back on the same `runtimeSessionId`. The next thing you send on that session is the decision, not a new question that says "approve". The questions to tick are the H5 rows in `docs/hr/acceptance.md`.

If the agent sends a leave question to the finance leaf, stop and change the in-Region model. Do not switch to an `eu.` or `us.` profile.

### Remove only the agent

Set `agents.pattern` back to the pattern Part 1 was using, then:

```bash
./scripts/deploy.sh deploy --stack "$PREFIX-runtime-orchestrator"
```

Choose that previous pattern at the prompt. Do not destroy `runtime-orchestrator`. The tools, identity, and database stay. Checkpoint rows in `agent_state` stay until you remove the database cluster.

## Phase 6. Web UI (`hr-web/`)

Start this only after phase 5 passes in the terminal. There is no stack and no `deploy.sh` command. `hr-web/` is a separate local application. It signs in through Part 1's web client and talks to the module 6 runtime over AG-UI SSE; the agent emits A2UI wire messages that the browser renders dynamically from `hr-web/public/hr-catalog.json`.

```bash
python hr-web/server.py
```

`server.py` binds to `127.0.0.1:8899` only. Open `http://127.0.0.1:8899/` in a browser and click Sign in. Review cards (confirm leave, manager review, probation notice) are rendered by the agent — they are not hard-coded in the UI. Typing "approve" in the chat is still a user turn; only the Confirm / Approve buttons post a decision. See `hr-web/README.md` for the full file layout and the A2UI design choice.

### Remove only the UI

Stop the local process. Do not delete a stack. The agent and the infrastructure keep running.

## Remove everything from part 2

Leave Part 1 up. There are two supported paths. Pick one.

### Path A — explicit per-phase (safest, matches the per-phase remove steps above)

Do these in order, and stop when the remaining system is the one you want.

1. Stop the `hr-web` process.
2. Run phase 5's remove step (redeploy the previous pattern).
3. `./scripts/deploy.sh destroy --stack "$PREFIX-uc-hr-tools"`
4. `./scripts/deploy.sh destroy --stack "$PREFIX-uc-hr-identity"`
5. `./scripts/deploy.sh destroy --stack "$PREFIX-uc-hr-data"`

After step 5, delete the `use_cases` block from `platform.yaml`. Then run Part 1, Step 15. You need the original eight stacks, each `CREATE_COMPLETE` or `UPDATE_COMPLETE`.

### Path B — one command, HR only

`scripts/deploy.sh` ships a `hr` team map covering the three HR use-case stacks in reverse-dependency order (tools → identity → data), so a single command tears the HR footprint down and leaves Part 1 untouched:

```bash
./scripts/deploy.sh destroy --team hr
```

You still need to run phase 5's remove step first (flip `agents.pattern` back to the previous pattern and redeploy `runtime-orchestrator`). `--team hr` does not touch the orchestrator; attempting to destroy the HR tools while the god agent is still live would make the running agent call Lambdas that are being removed.

**What `--team hr` does and does not do:**

- Destroys the three `uc-hr-*` CloudFormation stacks concurrently (CDK's `--exclusively` is applied per stack, so no platform stack is touched).
- Runs the H3 DETACH custom resource, which clears `LambdaConfig.PreTokenGenerationConfig` on module 3's Cognito user pool. The user pool itself stays.
- Drops `pass_request_headers` on the gateway and `HR_IDENTITY_PROMOTION=1` on the interceptor env on the next gateway deploy (which `--team hr` does **not** trigger — deploy `gateway` manually if you need the flip to take effect immediately).
- Does **not** run `sweep_leftovers`, so retained log groups stay (see "retain semantics" below). Full-footprint `destroy` is the only path that sweeps them.
- Does **not** touch the Aurora cluster, master secret, or backups when `retain_data: true` (the default). Salary rows survive. Dropping them is a later, explicit step, not part of `destroy`.

### Also: `./scripts/deploy.sh destroy` with no flags

This is the full-footprint destroy. It is correct and HR-aware — HR is in the CDK app graph via `use_cases:`, so `cdk destroy --all --force` tears down the HR stacks alongside the platform ones, and the post-destroy `sweep_leftovers` catches orphan Lambda log groups through its `/aws/lambda/${PREFIX}-` prefix, which covers:

- `/aws/lambda/${PREFIX}-uc-hr-identity-pretoken` — H3 pre-token Lambda.
- `/aws/lambda/${PREFIX}-uc-hr-data-Provisioner*` — the H1 schema-and-seed custom-resource Lambda.
- `/aws/lambda/${PREFIX}-uc-hr-tools-*` — the three H4 tool Lambdas.

Avoid running this unless you really want Part 1 gone too. If you only want to remove HR, use Path A or Path B.

### Retain semantics

`retain_data: true` (the H1 default) applies `RemovalPolicy.RETAIN` to the Aurora cluster, the writer instance, the DB subnet group, the master secret, and the `postgresql` log group under `/aws/rds/cluster/$PREFIX-uc-hr-data/`. None of the three destroy paths above remove those. If you set `retain_data: false` on a disposable account before destroying, CloudFormation deletes them on the stack tear-down and the backups follow. Switching `retain_data` on an already-deployed cluster only changes future stack updates; destroy the stack with the new value in place for the deletion policy to take effect.

Do not destroy `auth`, `security`, or `networking` to remove Part 2.

## Turn HR off in an emergency

This stops every HR tool in about 30 seconds. It does not redeploy anything.

```bash
aws ssm put-parameter --overwrite --type String \
  --name "$SSM/use-cases/hr-tools/enabled" --value false --region "$REGION"
```

The agent then says the assistant is paused (both the H4 Lambdas and the god agent re-read the flag on every invocation with a 30-second cache). Set the value back to `true` to resume. If the tools must be unreachable even to the gateway, remove the HR Cedar permits with the next `hr-tools` deploy. Cedar then denies every HR call.

To go back to the previous agent version without removing the agent, point the `live` runtime endpoint at the previous version. See the release section in `custom-app-plan/phases.md`.

## When something fails

| What you see | Why | What to do |
|---|---|---|
| `use case 'hr-data' ` and a list of known use cases | The folder or `manifest.yaml` is not in this checkout | Stop. The code for that phase is not merged |
| Unknown pattern `god-agent` | `AGENT_PATTERNS` does not list it yet | Stop. Do not put the name in `platform.yaml` |
| `deploy` starts updating `networking` or `gateway` while you named a `uc-` stack | That use case took a CDK dependency on a platform stack | Stop. It must read SSM instead |
| `verify.py` tries to connect to the database from the laptop | H1's check was written against the private endpoint | It should check SSM only. A SQL proof belongs to phase 4 |
| Seed exits because another employee id exists | This database is not the empty demo | Set `seed: false` or use a database that only has the nine demo ids |
| CDK synth fails at `opa download sha256 mismatch` | The pinned OPA release has moved or the network injected a different payload | Stop. Do not blindly update the pin. Verify the OPA release notes, then bump `_OPA_VERSION` and `_OPA_SHA256_ARM64` in `use-cases/hr-tools/stack.py` together with the x86 pin in `.gitlab-ci.yml` |
| CDK synth fails at `No module named psycopg_binary` on manylinux_aarch64 wheel install | Deployer's `pip` cannot see a manylinux_aarch64 wheel for the pinned psycopg | Upgrade pip in the venv (`pip install --upgrade pip`) or run the deploy from an x86_64 machine that still forces `--platform manylinux2014_aarch64` |
| Destroy says an export is in use | Something still imports that stack | Destroy the stack named in the error first |
| Every HR answer is "the assistant is paused" | `$SSM/use-cases/hr-tools/enabled` is not `true` | Set it to `true` only if the person who turned it off agrees |
| A tool call is denied with no `decision_log` row | Cedar denied it before the Lambda. Usually a missing or wrong `agent_id` claim | Check the H3 claim for that leaf. Do not widen the permit |
| Pre-token logs show `permission denied for table employees` | The deploy predates the H1 fix that granted `rds_iam` to `hr_identity` | Redeploy `hr-data`; the provisioner reapplies the GRANT block idempotently |
| God agent's first turn fails with `permission denied to create relation` | `agent_state` schema was applied before the `agent_checkpoint` fix | Redeploy `hr-data`; `agent_state_schema.sql` creates the role and grants `CREATE ON SCHEMA public` |
| H3 sign-in returns `NOT_MAPPED` | `employees.cognito_sub` is NULL for that user | Run the "Map Cognito users to employees" step in phase 3 |
| Part 1 `verify` fails after phase 5 | The runtime pattern changed, so the old code-interpreter check may not apply | Use the phase 5 CLI tests. After you remove the agent, Part 1 Step 15 applies again |
