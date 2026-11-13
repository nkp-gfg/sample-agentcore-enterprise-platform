# GFG deployment, part 2

Part 1 is the platform. This file adds the assistant on top of it, in three layers. Finish the verify command for a phase before you start the next one. You can also remove one phase and leave the rest running. The order and the reasons are in `custom-app-plan/phases.md`. If this file and that plan disagree about a command, this file is the one you run. The plan was updated to match these commands.

Do not run `./scripts/deploy.sh workshop`. Do not run `./scripts/deploy.sh destroy` without `--stack`. That deletes the whole platform. Do not run `./scripts/deploy.sh design --profile`. That rewrites `platform.yaml` from a preset. `design` on its own only prints the plan.

The folders below are not in the tree until their code is merged. If a folder in the step you are on is missing, stop. Do not invent the stack.

## Before you start

Part 1, Step 15, passed on this checkout. The virtualenv is active. `REGION` is the Region in your notepad.

Read the name prefix from `platform.yaml`. It is `{project}-{environment}`.

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

`seed: true` loads the nine demo people. Use it only on this demo database. The seed refuses to run if any other employee id is already there. `retain_data: true` keeps the cluster when you later delete the stack.

```bash
./scripts/deploy.sh deploy --stack "$PREFIX-uc-hr-data"
python use-cases/hr-data/verify.py
```

Set `PREFIX` to the prefix you printed above.

The database is in a private subnet. `verify.py` does not connect to it from your laptop. It checks the stack and these SSM parameters:

- `/{project}/{environment}/use-cases/hr-data/endpoint`
- `/{project}/{environment}/use-cases/hr-data/secret-name`
- `/{project}/{environment}/use-cases/hr-data/database-name`
- `/{project}/{environment}/use-cases/hr-data/checkpoint-database`

The cluster has two databases. `hr` holds the employee tables. `agent_state` is empty until the agent phase. A pass here does not prove a salary query. That happens in phase 4, from inside the VPC.

### Remove only the database

Do this only when the tools stack and the identity stack are already gone. If you delete the database first, those stacks are left pointing at nothing.

```bash
./scripts/deploy.sh destroy --stack "$PREFIX-uc-hr-data"
```

Then delete the `hr-data` block from `platform.yaml`.

The stack goes away. The cluster, the secret, and the backups stay, including the salary rows and `agent_state`. Deleting those rows is a later, separate operation. `destroy` does not do it.

## Phase 2. Policy tests

No stack. Run this before the tools phase. It does not call AWS.

```bash
pytest tests/test_hr_authz.py
```

A failure here is a rule bug. Do not deploy the tools to find it.

There is nothing to destroy.

## Phase 3. Identity

Add `hr-identity` under `use_cases`. Leave `hr-data` as it is. Do not add `hr-tools` yet.

```yaml
  hr-identity: {}
```

```bash
./scripts/deploy.sh deploy --stack "$PREFIX-uc-hr-identity"
```

Sign-in from Part 1 created Cognito users. Copy the `sub` for the person who will be E1, and the `sub` for the person who will be M1, into the notepad. The pool id is in SSM.

```bash
POOL=$(aws ssm get-parameter --region "$REGION" \
  --name "$SSM/auth/user-pool-id" --query Parameter.Value --output text)
aws cognito-idp list-users --region "$REGION" --user-pool-id "$POOL" \
  --query "Users[].{name:Username,sub:Attributes[?Name=='sub']|[0].Value}" --output table
```

On the first deployment that parameter is `/agentcore-production/prod/auth/user-pool-id`. Use `$SSM` from the start of this file. Do not put the hyphenated stack prefix in the path.

Run the verify with the two subs in the environment, not in a file you will commit:

```bash
HR_E1_SUB="paste-from-notepad" HR_M1_SUB="paste-from-notepad" \
  python use-cases/hr-identity/verify.py
```

The script writes those subs onto the E1 and M1 rows from inside the VPC. A pass means a token for E1 carries `employee_id` E1, and a token for M1 carries M1. X1 and an unknown `sub` get no `employee_id`.

### Remove only identity

```bash
./scripts/deploy.sh destroy --stack "$PREFIX-uc-hr-identity"
```

This detaches the pre-token trigger. The user pool from Part 1 stays. Remove the `hr-identity` block from `platform.yaml`. The database stays.

## Phase 4. Tools

Add `hr-tools` under `use_cases`.

```yaml
  hr-tools: {}
```

```bash
./scripts/deploy.sh deploy --stack "$PREFIX-uc-hr-tools"
python use-cases/hr-tools/verify.py
```

This calls the gateway the way `scripts/test_gateway.py` calls the sample tools. It does not chat with the agent. A pass means the salary, leave, and allowance cases in `docs/hr/acceptance.md` hold, a caller id in the arguments is ignored, and a denied call does not log an amount.

Keep the Part 1 agent pattern at the prompt. This phase does not change it.

### Remove only the tools

The agent phase must already be off. If the god agent is still deployed, it will call tools that no longer exist.

```bash
./scripts/deploy.sh destroy --stack "$PREFIX-uc-hr-tools"
```

Remove the `hr-tools` block from `platform.yaml`. Identity and the database stay.

## Phase 5. Agent

Start this only after phase 4's verify exits 0.

The code is `agent-code/god-agent/`, next to the other patterns. Change the existing `agents.pattern` value to `god-agent`. Leave `model_id` and `allowed_models` as they are.

If `god-agent` is not one of the choices the deploy script prints, this checkout does not have that pattern yet. Stop. Do not type the name anyway.

```bash
./scripts/deploy.sh deploy --stack "$PREFIX-runtime-orchestrator"
```

At the pattern prompt, choose `god-agent`. Keep Entra. This redeploys the runtime Part 1 already has. It does not add a stack. The agent creates its checkpoint tables in `agent_state`. It does not create that database.

One question:

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

## Phase 6. Web UI

Start this only after phase 5 passes in the terminal.

There is no stack and no `deploy.sh` command. The UI is a separate application. It signs in with the Part 1 web client and talks to the runtime. It does not import the CDK app or the agent package. How to start it is that application's own README. The cards it must show are in `custom-app-plan/human-review.md`.

### Remove only the UI

Stop the local process. Do not delete a stack. The agent and the infrastructure keep running.

## Remove everything from part 2

Leave Part 1 up. Do these in order, and stop when the remaining system is the one you want.

1. Stop the UI.
2. Run phase 5's remove step.
3. `./scripts/deploy.sh destroy --stack "$PREFIX-uc-hr-tools"`
4. `./scripts/deploy.sh destroy --stack "$PREFIX-uc-hr-identity"`
5. `./scripts/deploy.sh destroy --stack "$PREFIX-uc-hr-data"`

After step 5, delete the `use_cases` block from `platform.yaml`. Then run Part 1, Step 15. You need the original eight stacks, each `CREATE_COMPLETE` or `UPDATE_COMPLETE`.

Do not destroy `auth`, `security`, or `networking` to remove Part 2.

## Turn HR off in an emergency

This stops every HR tool in about 30 seconds. It does not redeploy anything.

```bash
aws ssm put-parameter --overwrite --type String \
  --name "$SSM/use-cases/hr-tools/enabled" --value false --region "$REGION"
```

The agent then says the assistant is paused. Set the value back to `true` to resume. If the tools must be unreachable even to the gateway, remove the HR Cedar permits with the next `hr-tools` deploy. Cedar then denies every HR call.

To go back to the previous agent version without removing the agent, point the `live` runtime endpoint at the previous version. See the release section in `custom-app-plan/phases.md`.

## When something fails

| What you see | Why | What to do |
|---|---|---|
| `use case 'hr-data' ` and a list of known use cases | The folder or `manifest.yaml` is not in this checkout | Stop. The code for that phase is not merged |
| Unknown pattern `god-agent` | `AGENT_PATTERNS` does not list it yet | Stop. Do not put the name in `platform.yaml` |
| `deploy` starts updating `networking` or `gateway` while you named a `uc-` stack | That use case took a CDK dependency on a platform stack | Stop. It must read SSM instead |
| `verify.py` tries to connect to the database from the laptop | H1's check was written against the private endpoint | It should check SSM only. A SQL proof belongs to phase 4 |
| Seed exits because another employee id exists | This database is not the empty demo | Set `seed: false` or use a database that only has the nine demo ids |
| Destroy says an export is in use | Something still imports that stack | Destroy the stack named in the error first |
| Every HR answer is "the assistant is paused" | `use-cases/hr-tools/enabled` is not `true` | Set it to `true` only if the person who turned it off agrees |
| A tool call is denied with no `decision_log` row | Cedar denied it before the Lambda. Usually a missing or wrong `agent_id` claim | Check the H3 claim for that leaf. Do not widen the permit |
| Part 1 `verify` fails after phase 5 | The runtime pattern changed, so the old code-interpreter check may not apply | Use the phase 5 CLI tests. After you remove the agent, Part 1 Step 15 applies again |
