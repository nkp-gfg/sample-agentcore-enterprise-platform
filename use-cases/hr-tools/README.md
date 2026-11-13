# hr-tools

Phase H4 of the HR plan. The authoritative spec is
[`docs/hr/`](../../docs/hr/README.md); the step-by-step is
[`walkthrough.md`](walkthrough.md). This README is the one-pager.

## Shape

```
use-cases/hr-tools/
  manifest.yaml                   name + owner + requires + stacks (one line each)
  stack.py                        CDK: 3 Lambdas, 3 roles, 3 gateway targets,
                                      3 Cedar permits, the SSM kill switch,
                                      and the 365-day log groups
  verify.py                       one real tools/list on the gateway + kill-switch assert
  walkthrough.md                  enable → deploy → verify → kill switch → remove
  policy/
    authz.rego                    the H2 OPA policy; unchanged by H4
  lambdas/
    shared/                       the five helpers every tool needs
      identity.py                   get_identity(event); raises NotMapped
      ssm_flag.py                   is_service_enabled(); 30 s in-process cache
      db.py                         connect(role); RDS IAM token
      opa.py                        opa_evaluate(input); bundled authz.rego
      logging_decision.py           log_decision(...); INSERT into decision_log as hr_audit
      response.py                   build_response(authorized, reason_code, data=None)
      errors.py                     HRToolError subclasses with reason_code
    dispatcher.py                 the common Lambda entry; routes by bedrockAgentCoreToolName
    get_employee_compensation/handler.py
    list_direct_reports/handler.py
    get_leave_balance/handler.py
    check_leave_eligibility/handler.py
    submit_leave_request/handler.py
    record_leave_decision/handler.py
    get_allowance/handler.py
```

## Kill switch

Every HR Lambda reads SSM `use-cases/hr-tools/enabled` before anything else,
with a 30 s in-process cache. Anything other than the literal string `true`
returns `SERVICE_DISABLED` within 30 seconds, no model call, no OPA call.

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

Deleting the parameter is also `SERVICE_DISABLED`, not an allow — a missing
kill switch never falls open. The SSM parameter is a `String` with the
initial value `true`, published by this stack.

## What crosses the module boundary

- **Consumed from SSM** (never by importing a core stack):
  `gateway/url`, `gateway/arn`, `gateway/policy-engine-id`,
  `identity/gateway-credential-provider-name`,
  `use-cases/hr-data/endpoint`, `use-cases/hr-data/database-name`,
  `use-cases/hr-data/secret-name`,
  `networking/vpc-id`, `networking/private-subnet-ids`,
  `networking/runtime-security-group-id`.
- **Published to SSM** under `use-cases/hr-tools/`:
  `enabled` (the kill switch).
- **Platform code changes H4 ships** (the single thing
  [`custom-app-plan/phases.md`](../../custom-app-plan/phases.md) § H4 asks
  for, nothing else):
  1. `stacks/gateway_stack.py` gets an optional
     `pass_request_headers` flag on the interceptor configuration; it
     defaults to the current `False` behaviour and flips to `True` only
     when hr-tools is enabled.
  2. `tools/egress_interceptor/handler.py` gets an identity-promotion
     block in the REQUEST pass, gated by `HR_IDENTITY_PROMOTION=1`. The
     block reads the gateway-validated JWT claims from the request headers
     and writes `caller_employee_id`, `agent_id`, and `session_id` onto
     the tool arguments, overwriting whatever the model sent.

The identity-promotion block only fires on HR gateway targets, so every
other gateway target in the deployment is unaffected.
