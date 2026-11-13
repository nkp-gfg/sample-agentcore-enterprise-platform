# Learnings: deploying the AgentCore platform in production mode (eu-west-1)

This document records what broke during the first production deployment, why it
broke, how it was fixed, and what is likely to break again. The last section lists
the work that is still open.

No real account IDs, tenant IDs, client IDs or secrets are included. Placeholders
such as `<ACCOUNT_ID>` stand in for them.

---

## Final state

- All 8 stacks are deployed in `eu-west-1`.
- `./scripts/deploy.sh verify` reports **8 of 8 checks passed**.
- The model is `openai.gpt-oss-120b-1:0`, which runs directly in eu-west-1 with no
  cross-region routing.
- **Region and model are free choices.** Nothing in the code is tied to
  eu-west-1. A colleague picks any Region where AgentCore runs and any Bedrock
  model with tool use, and writes both into `platform.yaml`
  (`GFG_Deployment.md`, Step 5).
- A person can sign in and chat with `scripts/login_chat.py`
  (`GFG_Deployment.md`, Step 14).
- The work is committed on `n-fe-sandbox-deployment` and not pushed.

---

## How to read each learning

Each learning has four parts:

- **What we saw:** the error or symptom.
- **Why:** the root cause.
- **Fix:** what was changed.
- **Watch for:** how it could come back.

---

## 1. Organization rules (SCP and Control Tower)

### 1.1 The SCP blocks Bedrock in some EU regions

- **What we saw:** the agent failed with `AccessDeniedException ... on
  arn:aws:bedrock:eu-south-1::foundation-model/... with an explicit deny in a
  service control policy`.
- **Why:** the model ID `eu.anthropic.claude-sonnet-4-6` is an EU cross-region
  inference profile. Bedrock sends each call to one of six EU regions: eu-west-1,
  eu-central-1, eu-west-3, eu-north-1, eu-south-1 and eu-south-2. The organization
  SCP, owned by the management account, denies at least eu-south-1 (Milan). Calls
  routed there failed at random.
- **Fix:** switched to a model with no `eu.`, `us.` or `global.` prefix, so it runs
  in eu-west-1 only. The SCP was not changed.
- **Watch for:**
  - Any model ID that starts with `eu.`, `us.`, `apac.` or `global.` routes across
    regions and will hit this SCP again.
  - **No Claude model is available on-demand in eu-west-1.** Using Claude needs
    either a cross-region profile plus an SCP exception from the org admin, or a
    different region.
  - The org admin can exempt profile routing with this condition in the
    region-deny statement:
    `"ArnNotLike": {"bedrock:InferenceProfileArn": "arn:aws:bedrock:*:*:inference-profile/eu.*"}`

### 1.2 Control Tower hooks reject some templates

- **What we saw:** stacks failed to create because of `AWS::ControlTower::Hook`
  with FailureMode FAIL.
- **Why:** the enforced controls (CT.IAM.PR.3/5, CT.EC2.PR.8/9/11 and
  CT.AUTOSCALING.PR.5) reject an IAM statement with `Action: "*"` and any subnet
  with `MapPublicIpOnLaunch: true`.
- **Fix:** the public subnet now uses `map_public_ip_on_launch=False`, and no IAM
  policy uses `Action: "*"`.
- **Watch for:** a new construct or CDK default that brings back a wildcard action
  or public IPs. Check with `cdk synth` before deploying.

---

## 2. CloudFormation behaviour

### 2.1 A failed stack must be deleted before it can be recreated

- **What we saw:** a stack stuck in `ROLLBACK_COMPLETE`, and `cdk deploy` hanging.
- **Why:** CloudFormation can't update a stack whose first create failed.
- **Fix:** kill the CDK process, then run
  `aws cloudformation delete-stack --stack-name <name> --region eu-west-1`, wait
  for the delete to finish, and redeploy.
- **Watch for:** never delete the `security` or `auth` stacks this way. They hold
  the KMS key and the identity setup.

### 2.2 Most fixes apply on redeploy

Code and IAM changes apply through `./scripts/deploy.sh build`. CloudFormation
updates the resource in place. Only a stack in `ROLLBACK_COMPLETE` must be deleted
first.

---

## 3. AgentCore Gateway

### 3.1 Cedar policies must name the gateway, not a bare `resource`

- **What we saw:** gateway creation failed with `wildcard resource detected`.
- **Why:** AgentCore Cedar rejects a bare `resource` for specific tool actions. It
  also checks the actions against the gateway's tool list, so the policy can only
  be created after the targets exist.
- **Fix:**
  - `10-permit-read-tools.cedar` uses
    `resource == AgentCore::Gateway::"<<gateway_arn>>"`.
  - `gateway_arn` is a required parameter in `control-library/catalog.yaml`.
  - The Cedar policy resource depends on every gateway target.
- **Watch for:** any new Cedar file must name the gateway and must be created
  after the targets.

### 3.2 The gateway role needs policy-engine permissions before the gateway exists

- **What we saw:** gateway creation failed three times, with three different
  denials:
  1. `GetPolicyEngine`
  2. `AuthorizeAction` on the policy engine
  3. `AuthorizeAction` on the gateway ARN
- **Why:** during creation, AgentCore checks the policy engine using the gateway
  role. At that point the gateway ARN doesn't exist yet. It looks like
  `gateway/<name>-<10 random characters>`.
- **Fix:** the `GatewayPolicyEngineAccess` policy is created *before* the gateway.
  It grants:
  - `GetPolicyEngine` on the policy engine.
  - `AuthorizeAction` and `PartiallyAuthorizeActions` on the policy engine and on
    `gateway/<gateway-name>-*`.

  The gateway resource depends on that policy.
- **Watch for:** renaming the gateway changes the `<gateway-name>-*` pattern. The
  policy is built from the same name, so keep it that way.

### 3.3 The gateway role must be allowed to invoke the interceptor Lambda

- **What we saw:** every MCP call (`tools/list`) returned
  `500 An internal error occurred`. The interceptor Lambda's log group didn't even
  exist.
- **Why:** the gateway invokes the interceptor with **its own IAM role**. The role
  could only invoke `<prefix>-tool-*`, and the interceptor is named
  `<prefix>-egress-interceptor`. The Lambda resource policy alone isn't enough.
- **Fix:** an `InvokeEgressInterceptor` statement on the gateway role, scoped to
  the interceptor function ARN.
- **Watch for:** any new interceptor or Lambda target needs an explicit invoke
  permission on the gateway role.

### 3.4 The interceptor must return exactly the format AWS documents

- **What we saw:**
  `InterceptorException - Received invalid response from interceptor`.
- **Why:** the old handler had three bugs:
  1. Every event contains `gatewayRequest`. On the response pass,
     `gatewayResponse` is filled in too. The handler only checked for
     `gatewayRequest`, so it treated responses as requests.
  2. It echoed back the whole request (`path`, `httpMethod`, `context: null`) and
     sent every string, including `"jsonrpc": "2.0"`, through the guardrail.
  3. Its "blocked" reply had the wrong shape.
- **Fix:** rewrote `tools/egress_interceptor/handler.py` to follow the documented
  format:
  - A request returns `transformedGatewayRequest: {body}`.
  - A response returns `transformedGatewayResponse: {statusCode, headers, body}`.
  - A block returns a JSON-RPC tool error.
  - Only `tools/call` arguments (outgoing) and results (incoming) are scanned.

  Tests are in `tests/test_egress_interceptor.py`.
- **Watch for:**
  - Response streaming: follow-up events contain only `body`.
  - Each string in the tool data costs one `ApplyGuardrail` call, which adds
    latency and cost.
  - Format reference:
    https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/gateway-interceptors-types.html

---

## 4. AgentCore Memory and KMS

### 4.1 The agent needs KMS permission for an encrypted Memory

- **What we saw:** in the runtime logs, `Memory init failed: AccessDeniedException
  when calling CreateEvent: Unable to perform KMS operations`. Verify's memory test
  still passed, because it runs as an admin user, not as the agent.
- **Why:** Memory is encrypted with the platform customer-managed key. AgentCore
  uses that key with the caller's identity, and the runtime role had no KMS
  permission.
- **Fix:** a `MemoryKmsViaAgentCore` statement on the runtime role:
  - Actions: `kms:Decrypt`, `kms:GenerateDataKey`, `kms:DescribeKey`.
  - Resource: the platform key only.
  - Condition: `kms:ViaService = bedrock-agentcore.eu-west-1.amazonaws.com`.
- **Watch for:** **a passing verify check doesn't prove the agent works.** Always
  read the runtime logs too, because verify runs some checks as an admin.

### 4.2 Encrypted SNS topics need a key policy for CloudWatch and EventBridge

- **What we saw:** alarms and events could not publish to the KMS-encrypted
  topics.
- **Why:** `cloudwatch.amazonaws.com` and `events.amazonaws.com` need
  `kms:Decrypt` and `kms:GenerateDataKey*` on the key.
- **Fix:** a key policy statement for both services, limited by
  `aws:SourceAccount`. The observability stack uses `kms.Key.from_key_arn` so CDK
  doesn't add an extra, unconditioned grant for EventBridge.
- **Watch for:** passing the key object directly to `targets.SnsTopic` brings the
  broad grant back.

### 4.3 Log groups use default encryption, which is a deliberate choice

- A KMS key on CloudWatch Logs only protects stored data. Shipping to a SIEM through
  subscription filters still works, but anyone reading logs through the API or
  console needs `kms:Decrypt`.
- To keep troubleshooting simple, log groups use the default AWS encryption.

---

## 5. Agent code

### 5.1 Region must come from configuration, with no hidden fallbacks

- **What we saw:** several agents defaulted to `us-east-1`.
- **Fix:**
  - `agent-code/shared/region.py` reads `AWS_REGION_NAME` (set by the runtime
    stack from `platform.yaml`), then `AWS_REGION` (set by AgentCore Runtime).
    With neither, it stops with a clear error instead of guessing a region.
  - All agents, every Bedrock model client, and the code-interpreter clients use
    it.
- **Watch for:** new code that calls `boto3.client(...)` without
  `region_name=runtime_region()`.

### 5.2 Tool-loading errors were reported as "Unauthorized"

- **What we saw:** the agent answered `Unauthorized`, and the logs said `Rejected
  unverified caller: Failed to load tool ...`.
- **Why:** Strands raises `ValueError` when an MCP tool fails to load. The same
  `except ValueError` also handled token-verification failures.
- **Fix (every agent pattern):** the token check has its own `try` block and
  returns a plain `Unauthorized`. Tool or model failures are logged as `Agent run
  failed` with the real error.
- **Watch for:** a new agent pattern must copy this split.

### 5.3 The guardrail's prompt-attack filter flags commands like "use tool X to run Y"

- **What we saw:** the model call finished with `guardrail_intervened`, and the
  agent replied "This request was blocked".
- **Why:** the orchestrator guardrail's `PROMPT_ATTACK` filter is at **HIGH**
  strength. Verify's prompt, "Use execute_python_securely to run print(...)",
  looks like an injection attempt.
- **Fix:** the guardrail stays at HIGH. Only the verify prompt changed, to "Using
  Python, print the text CODE_INTERPRETER_OK and share the output."
- **Watch for:** real users who write prompts as commands may also get blocked.
  To test a prompt:
  ```bash
  aws bedrock-runtime apply-guardrail --region eu-west-1 \
    --guardrail-identifier <GUARDRAIL_ID> --guardrail-version DRAFT \
    --source INPUT --content '[{"text":{"text":"<prompt>"}}]'
  ```
  Note: `apply-guardrail` with the system prompt added always intervenes, but in a
  real `Converse` call the system prompt isn't evaluated. To reproduce a real
  failure, test with an actual `converse --guardrail-config ...` call.

---

## 6. Networking

- AgentCore in eu-west-1 needs three interface endpoints:
  - `bedrock-agentcore` (data plane: Memory, Identity, runtime calls)
  - `bedrock-agentcore-control`
  - `bedrock-agentcore.gateway`
- The org endpoint policy (`vpce.agentcore-in-org`) only allows *invoke* actions.
  It must **not** be attached to the data-plane endpoint, or Memory and Identity
  stop working.

---

## 7. Observability

- **What we saw:** verify reported `trace segment destination ... status is
  PENDING`, and the runtime logged `Failed to export span batch code: 400`.
- **Why:** Transaction Search had just been enabled. It takes several minutes to
  become `ACTIVE`, and X-Ray rejects spans until then.
- **Fix:** nothing to change; wait, then check:
  `aws xray get-trace-segment-destination --region eu-west-1`
- **Watch for:** on a brand-new account, run verify again 10 to 15 minutes after
  the first build.

---

## 8. Local tooling

| Problem | What to do |
|---|---|
| jsii `EPERM` error during tests or synth | Prefix the command with `JSII_RUNTIME_PACKAGE_CACHE=disabled` |
| `.venv` not found | Run commands from the repo root and use `.venv/bin/python` |
| `test_platform_reference` fails | Regenerate the docs with `scripts/gen_platform_reference.py` |
| `cdk deploy` hangs after a rollback | Kill it, delete the `ROLLBACK_COMPLETE` stack, deploy again |
| Region drifts to another value | Don't export `AWS_REGION`; the region comes from `platform.yaml` |
| `platform.yaml` overwritten | Don't run `design --profile production` |

---

## 9. Things that can fail in the future

| Risk | What would happen | How to catch it early |
|---|---|---|
| Model changed to an `eu.`, `us.` or `global.` ID | Random `AccessDenied` if the SCP blocks one of the profile's Regions | Check the profile's Regions (`GFG_Deployment.md`, Step 5) or get an SCP exception first |
| Colleague picks a model without tool use | The agent answers but never calls its tools | Run the tool-use check in `GFG_Deployment.md`, Step 5 |
| Colleague picks a Region without AgentCore | `build` fails early | Run the AgentCore check in `GFG_Deployment.md`, Step 5 |
| Port 3000 is busy when running `login_chat.py` | The sign-in redirect cannot be caught | Stop whatever uses port 3000 |
| New gateway target or interceptor added | 500 errors from the gateway | Grant `lambda:InvokeFunction` on the gateway role |
| New Cedar policy file | Gateway creation fails | Name the gateway ARN and depend on the targets |
| Gateway renamed | Policy-engine check fails during creation | Keep the ARN pattern built from the same name |
| AWS changes the interceptor format | `InterceptorException` | Run `tests/test_egress_interceptor.py` and verify after upgrades |
| Users phrase prompts as commands | Guardrail blocks the request | Track guardrail interventions in CloudWatch |
| A new resource encrypted with the platform key | `Unable to perform KMS operations` | Add a `kms:ViaService`-scoped grant for the caller |
| CDK default adds a public IP or `Action: "*"` | Control Tower hook rejects the stack | Check the synth output before deploying |
| Verify passes but the agent fails | Users see errors while verify looks green | Read the runtime logs after every deploy |
| `gpt-oss-120b` quality isn't good enough | Weak answers or bad tool use | Evaluate on real tasks; Claude needs an SCP change |
| Model retired or changed by AWS | Invocation errors | Check `aws bedrock list-foundation-models --region <region>` regularly |

---

## 10. Pending items

### Done

| Item | Where |
|---|---|
| Model and Region are not hard-coded; any model and Region can be chosen | `platform.yaml`, `presets/production.yaml`, `agent-code/shared/region.py` |
| Every Bedrock model client passes the Region explicitly | All `agent-code/*/agent.py` |
| `allowed_model_resources` recognises only real profile prefixes, so `meta.`, `zai.` and similar models get the right IAM ARN | `infra_utils/platform_config.py`, `tests/test_model_allowlist.py` |
| Auth errors separated from tool errors in every agent pattern | All `agent-code/*/agent.py` |
| Gateway waits for its role policy on a fresh deploy | `stacks/gateway_stack.py` |
| Unit tests for the interceptor grant, gateway ordering, and Memory KMS grant | `tests/test_gateway_role.py`, `tests/test_runtime_role_scoping.py` |
| Alert email also subscribed to the security-alerts topic | `stacks/observability_stack.py` |
| Region- and model-neutral deployment guide, sign-in step, and test checklist | `GFG_Deployment.md`, Steps 5, 14, 15 |
| Sign-in and chat as a real user | `scripts/login_chat.py` |
| `stuats.md` (live identifiers) removed from the branch, including its history | git |
| Both SNS subscriptions confirmed | AWS |
| Security doc covers interceptor scope, its IAM grant, and the KMS grants | `docs/SECURITY_CONTROLS.md` |
| Test that the token check stays isolated in every agent pattern | `tests/test_agent_auth_isolation.py` |

### Must do

1. **Push the branch** when you're ready: `git push -u origin n-fe-sandbox-deployment`.
   Before pushing, confirm no live account ID is in history:
   `git log -p origin/main..HEAD | grep -c <ACCOUNT_ID>` must print `0`.
2. **Have a colleague run `GFG_Deployment.md`** end to end, ideally in another
   Region, and tick the Step 15 checklist.

### Should do

3. **Evaluate the chosen model on real tasks.** If Claude is required, use a
   Region where the SCP allows all of its profile's Regions, or ask the admin for
   an inference-profile exception.
4. **Monitor guardrail interventions** for prompt-attack false positives in the
   first weeks.
5. **Pin the model IAM ARN to the deployment Region for in-Region models.**
   `allowed_model_resources` uses `arn:aws:bedrock:*::foundation-model/...`. The
   wildcard is required for cross-Region profiles, but an in-Region model could be
   pinned.
6. **`DEFAULT_MODEL_ID` fallbacks in `agent-code/*/agent.py` are still `eu.`
   Claude profiles.** Production never uses them, because `agents.model_id` is
   required and deploy injects it. Workshop mode outside the EU would. Change them
   only together with `tests/test_model_allowlist.py` and `scripts/preflight.py`,
   which read the literal value.

### Nice to have

7. **Remove the duplicate OpenTelemetry logging warning**: unset
   `OTEL_PYTHON_LOGGING_AUTO_INSTRUMENTATION_ENABLED`, as the warning suggests.
8. **Reduce guardrail calls in the interceptor** by scanning all strings of one
   tool call in a single `ApplyGuardrail` request.
9. **A small web chat page** on `http://localhost:3000`, so testers don't need
   the terminal.
