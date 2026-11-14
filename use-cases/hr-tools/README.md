# hr-tools

Phase H4 of the HR plan. The authoritative spec is
[`docs/hr/`](../../docs/hr/README.md); the step-by-step is
[`walkthrough.md`](walkthrough.md). This README is the one-pager.

## Shape

```
use-cases/hr-tools/
  manifest.yaml                   name + owner + requires + stacks
  stack.py                        CDK: 3 Lambdas, 3 roles, 3 gateway targets,
                                      3 Cedar permits, the SSM kill switch,
                                      and the 365-day log groups
  verify.py                       control-plane + Cedar + interceptor + live MCP check
  walkthrough.md                  enable → deploy → verify → kill switch → remove
  lambdas/
    shared/                       the shared helpers every tool needs
      authz.py                      evaluate_policy(input); deterministic Python rules
      identity.py                   get_identity(event); raises NotMapped
      ssm_flag.py                   is_service_enabled(); 30 s in-process cache
      db.py                         connect(role); RDS IAM token
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
returns `SERVICE_DISABLED` within 30 seconds, with no model call and no
database read.

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
kill switch never falls open.

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
- **Platform code changes H4 ships**:
  1. `stacks/gateway_stack.py` gets an optional
     `pass_request_headers` flag on the interceptor configuration; it
     defaults to `False` and flips to `True` only when `hr-tools` is enabled.
  2. `tools/egress_interceptor/handler.py` gets an identity-promotion
     block in the REQUEST pass, gated by `HR_IDENTITY_PROMOTION=1`, reading
     the gateway-validated JWT claims and overwriting `caller_employee_id`,
     `agent_id`, and `session_id` on HR tool arguments.
