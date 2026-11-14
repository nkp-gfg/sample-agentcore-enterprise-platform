# hr-tools — the HR assistant tool layer (H4)

Phase H4 of the HR plan ([custom-app-plan/phases.md](../../custom-app-plan/phases.md)).
The authoritative spec for everything in this folder is
[`docs/hr/`](../../docs/hr/README.md); the tables there win when any text in
this walkthrough drifts.

What this use case ships:

- Three AgentCore Gateway Lambda targets — `hr-ops`, `hr-payroll`,
  `hr-finance` — each pointing at one Lambda function with its own IAM role.
- Seven per-tool handlers behind those three Lambdas (one `handler.py` per
  tool under `lambdas/<tool>/`). The dispatcher routes by
  `bedrockAgentCoreToolName`, exactly like the sample tool.
- Three Cedar permits ([`docs/hr/tools.md`](../../docs/hr/tools.md)) deployed
  into the gateway's Cedar policy engine. Every permit is bound to the one
  leaf `agent_id` that may call it. The stack **fails the deploy** if any
  permit does not become `ACTIVE`.
- The SSM kill switch `use-cases/hr-tools/enabled` (default `true`). A human
  turns every HR tool off with `aws ssm put-parameter --overwrite` — no
  redeploy, no model call.
- Per-Lambda CloudWatch log groups with 365-day retention, so the SIEM has
  enough history to join a Cedar decision with the tool-policy decision the
  Lambda logged on the same `session_id` and `trace_id`.

What this use case needs from the platform ([`docs/hr/modules.md`](../../docs/hr/modules.md) § SSM interface):

| Parameter | Publisher | Used for |
|---|---|---|
| `gateway/url`, `gateway/arn`, `gateway/policy-engine-id` | `gateway` core stack | Cedar permit creation + the verify loop |
| `identity/gateway-credential-provider-name` | `identity` core stack | the runtime exchange |
| `use-cases/hr-data/endpoint`, `use-cases/hr-data/database-name` | `hr-data` | the Lambda's RDS IAM connect |
| `use-cases/hr-data/secret-name` | `hr-data` | not read by Lambdas — kept for operators |
| `networking/vpc-id`, `networking/private-subnet-ids`, `networking/runtime-security-group-id` | `networking` | VPC placement for the three Lambdas |

Deploy the hr-data stack first (it publishes the first three rows), then
hr-identity (it adds the pre-token claim the gateway now forwards), then
this one. The platform's `requires:` list cannot name another use case; the
edge is real and lives in SSM, so the deploy order is the rule.

## Enable

In `platform.yaml` (the production preset is the base — hr-tools requires
networking, security CloudTrail alerting, Cedar in `ENFORCE`, and the egress
filter, every one of which the production preset turns on):

```yaml
use_cases:
  hr-data: {}
  hr-identity: {}
  hr-tools:
    # Firehose stream that delivers HR audit log lines to the SIEM. Empty
    # means no export — the SIEM gap is then recorded in the risk register,
    # per docs/hr/modules.md. Deploy without it to try the stack; wire the
    # ARN before any real employee data lands in hr-data.
    audit_stream_arn: ""
```

The unknown-key validation is strict ([`infra_utils/platform_config.py`](../../infra_utils/platform_config.py)
`_use_cases_exist`), so a typo errors out at design time and never deploys.

## Deploy

The stack rides the normal `deploy.sh` flow — it appears in `deploy.sh ls`,
in the full-footprint plan, in the deployment contract (`expected_stacks()`),
and in the destroy path:

```bash
./scripts/deploy.sh deploy --stack <project>-<env>-gateway
./scripts/deploy.sh deploy --stack <project>-<env>-uc-hr-tools
```

The deploy fails hard (not soft) when:

- hr-data has not run yet (the hr-data SSM parameters are missing),
- Cedar is not `ENFORCE` on the gateway (the permits cannot land),
- any one of the three Cedar permits fails to become `ACTIVE`.

That last case is the one the gateway spec in [`docs/hr/tools.md`](../../docs/hr/tools.md)
warns about: a permit that fails to create silently denies every call. The
stack creates the permits with explicit CloudFormation dependencies on their
targets so CloudFormation surfaces the failure.

## Verify

```bash
python use-cases/hr-tools/verify.py
# OK: six HR leaf tools listed on the gateway, kill switch is 'true'
```

`deploy.sh verify` runs this automatically when hr-tools is enabled.
`verify.py` makes one real `tools/list` call with the M2M token and checks
two things:

1. The gateway lists the six leaf tools
   (`hr-ops___get_leave_balance`, `hr-ops___check_leave_eligibility`,
   `hr-ops___submit_leave_request`, `hr-payroll___get_employee_compensation`,
   `hr-payroll___list_direct_reports`, `hr-finance___get_allowance`).
   `hr-ops___record_leave_decision` is reviewer-only and is intentionally
   not asserted — it is deployed, but no leaf is given it.
2. SSM `use-cases/hr-tools/enabled` is `true` after the deploy.

The full H4 acceptance table is behavioural (every H2 case through
`tools/call`, Cedar deny for a wrong `agent_id`, the kill switch flipping,
the `decision_log` row shape): it runs against a real deployment, not here.

## Kill switch

The one operator action that turns every HR tool off without a redeploy is
flipping the SSM parameter. Each HR Lambda reads it with a 30 s in-process
cache, so the change propagates within 30 seconds of the write:

```bash
# Turn HR off
aws ssm put-parameter \
  --name /<project>/<env>/use-cases/hr-tools/enabled \
  --value false --overwrite

# Turn HR back on
aws ssm put-parameter \
  --name /<project>/<env>/use-cases/hr-tools/enabled \
  --value true --overwrite
```

Anything other than the literal string `true` returns `SERVICE_DISABLED`
from every HR tool. Deleting the parameter is also `SERVICE_DISABLED`, not
an allow — a missing kill switch never falls open.

The emergency path for a leaking permit is removing the Cedar policy. The
gateway then denies every HR call at the policy engine, before the Lambda is
invoked. That is a stack change; the kill switch above is the no-deploy
equivalent for the Lambda-side layer of the same control.

## Remove

Destroy order ([`docs/hr/modules.md`](../../docs/hr/modules.md) § Deploy and destroy):

```bash
# 1. hr-tools FIRST — it depends on hr-data and hr-identity through SSM
./scripts/deploy.sh destroy --stack <project>-<env>-uc-hr-tools
# 2. then hr-identity, then hr-data (both are separate commands)
```

`destroy --stack` deletes only that stack. The HR stacks do not export to
each other, so CloudFormation may allow a different order; do not take it.
Delete tools, then identity, then data. If an error names an export still
in use, that is the stack to destroy first.

Do not destroy `auth`, `security`, or `networking` to remove HR. Those are
platform-wide.

## What to read next

- [`docs/hr/tools.md`](../../docs/hr/tools.md) — tool names, arguments,
  response shapes, Cedar permits, interceptor rules.
- [`docs/hr/policy.md`](../../docs/hr/policy.md) — the authorization policy
  input document and the reason-code order the Lambdas follow.
- [`docs/hr/acceptance.md`](../../docs/hr/acceptance.md) § H4 — the
  behavioural acceptance table.
- [`custom-app-plan/production-principles.md`](../../custom-app-plan/production-principles.md)
  — the six production rules H4 locks in.
