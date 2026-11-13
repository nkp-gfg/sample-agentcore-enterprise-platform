# Changes To Be Done — Full Context & Engineering Rationale

> **Status:** items 1 to 7 are applied on `n-fe-sandbox-deployment`, with one
> difference: model and Region are now free choices instead of being pinned to
> `eu-west-1` and `openai.gpt-oss-120b-1:0`. Agent `DEFAULT_MODEL_ID` fallbacks
> were left unchanged. Remaining work is tracked in `learning.md`, section 10.

This document is written for anyone reviewing, maintaining, or continuing work on branch `n-fe-sandbox-deployment`. It explains **not just what needs to change, but the exact AWS/CDK/AgentCore reasoning behind each change**, how each issue was discovered against the live `eu-west-1` production deployment, and what breaks if a change is skipped or reverted.

*(Note: All account IDs, Cognito IDs, KMS key IDs, and IAM ARNs in this document use placeholders such as `<ACCOUNT_ID>` so this file contains no sensitive environment identifiers.)*

---

## Background: How We Got Here

When deploying the platform in `production` mode (`deployment.mode: production` in `platform.yaml`) inside an enterprise AWS Organization account in `eu-west-1` with **AWS Control Tower proactive hooks** and **regional Service Control Policies (SCPs)** active:

1. **Initial `./scripts/deploy.sh verify` failed 6 of 8 checks** (`gateway`, `observability`, `networking`, `guardrail enforcement`, `alarms`, `orchestrator invoke`) while passing `identity` and `memory`.
2. **Why those 6 failed initially:** Only the first 5 foundation/service stacks (`networking`, `security`, `auth`, `identity`, `memory`) had deployed. Stack 6 (`gateway`) failed during CloudFormation creation, which blocked stacks 7 (`runtime-orchestrator`) and 8 (`observability`) because of cross-stack dependencies in `app.py`.
3. **Fixes already proven live (in `5a0b71b`):**
   - **Control Tower `CT.EC2.PR.11`:** Set `map_public_ip_on_launch=False` on VPC public subnets (`stacks/networking_stack.py`).
   - **Cedar Gateway Policy & Role Bootstrap:** Replaced bare `resource` wildcard in `10-permit-read-tools.cedar` with `AgentCore::Gateway::"<<gateway_arn>>"`, made `CfnPolicy` wait on `CfnGatewayTarget`s, and pre-created `GatewayPolicyEngineAccess` with a `gateway/<gw_name>-*` ARN pattern so `GenesisPolicyEngineCheck` succeeds during `CreateGateway`.
   - **Gateway Egress Interceptor:** Added `InvokeEgressInterceptor` (`lambda:InvokeFunction`) on the gateway IAM role and rewrote `tools/egress_interceptor/handler.py` to conform to the AgentCore MCP interceptor contract (`transformedGatewayRequest` / `transformedGatewayResponse` scanning only `tools/call`).
   - **CMK-Encrypted Memory & SNS:** Added `MemoryKmsViaAgentCore` (`kms:ViaService = bedrock-agentcore.<region>.amazonaws.com`) to `RuntimeRole`, and granted `cloudwatch.amazonaws.com` + `events.amazonaws.com` KMS publish permissions in `SecurityStack`.
   - **Guardrail Prompt False Positive:** Reworded `CODE_INTERPRETER_PROMPT` in `scripts/verify.py` from imperative `"Use execute_python_securely to run ..."` to plain language so the `HIGH` `PROMPT_ATTACK` Bedrock Guardrail filter does not block the health check.
   - **Org Region-Deny SCP vs. Cross-Region Profiles:** Switched `platform.yaml` from `eu.anthropic.claude-sonnet-4-6` (which Bedrock routes across 6 EU regions, hitting an org SCP explicit deny in `eu-south-1`) to the in-region model `openai.gpt-oss-120b-1:0` served directly in `eu-west-1`.

After those fixes, all **8 CloudFormation stacks** reached `CREATE_COMPLETE` / `UPDATE_COMPLETE` and `./scripts/deploy.sh verify` passed `8/8`.

However, **auditing the live CloudFormation templates, IAM policies, container logs, and config precedence uncovered 7 remaining issues** that can break a fresh deployment in another account, cause silent configuration/region drift, misparse IAM model ARNs, or leak account identifiers into git history. Each one is detailed below with its full reasoning.

---

## 1. Fix Fresh-Deploy IAM Race Condition in `GatewayStack`

**Files:** `stacks/gateway_stack.py` (around lines 249–255), `tests/test_gateway_role.py`

### How We Found It
Inspecting the live deployed CloudFormation template (`aws cloudformation get-template --stack-name agentcore-production-prod-gateway`) showed:
- `Gateway.DependsOn` was `["GatewayPolicyEngineAccess9838B08E"]` **only**.
- `Gateway` had **no `DependsOn`** pointing to `GatewayRoleDefaultPolicyF4BF688C`.

### Detailed Reason (Why This Matters)
In AWS CDK, passing `role_arn=gw_role.role_arn` to an L1 resource (`agentcore.CfnGateway`) emits `{ "Fn::GetAtt": ["GatewayRole...", "Arn"] }`. CloudFormation uses `Fn::GetAtt` to infer a dependency on the `AWS::IAM::Role` resource itself — **not** on the separate `AWS::IAM::Policy` (`GatewayRole/DefaultPolicy`) resource that CDK synthesizes whenever `gw_role.add_to_policy(...)` is called.

In `GatewayStack`, `GatewayRole/DefaultPolicy` holds three critical permissions:
1. KMS CMK permissions (`kms:Decrypt`, `kms:DescribeKey`, `kms:GenerateDataKey`) required when `kms_key_arn` is passed to `CfnGateway`.
2. `InvokeEgressInterceptor` (`lambda:InvokeFunction` on `<prefix>-egress-interceptor`).
3. `lambda:InvokeFunction` on `<prefix>-tool-*`.

Without an explicit dependency, CloudFormation finishes creating `EgressInterceptor` and `GatewayRole`, and then creates **`Gateway` and `GatewayRole/DefaultPolicy` in parallel**. In our deployment `GatewayRole/DefaultPolicy` happened to complete a few seconds before `CreateGateway` checked KMS/role access, so it succeeded by timing luck. On a fresh deploy in another account or CI pipeline, `CreateGateway` can run before `GatewayRole/DefaultPolicy` finishes attaching and fail with `AccessDenied` on KMS or interceptor validation, leaving the stack in `ROLLBACK_COMPLETE`.

Calling `self._gateway.node.add_dependency(gw_role)` in CDK adds a construct-tree dependency on the `iam.Role` construct, which CDK automatically expands into `DependsOn` for **both** `GatewayRole` and `GatewayRole/DefaultPolicy`.

### What to Change
1. In `stacks/gateway_stack.py`:
   ```python
   self._gateway = agentcore.CfnGateway(self, "Gateway", **gateway_props)
   # A Role dependency also covers its DefaultPolicy (KMS, interceptor, and
   # tool invoke). Without it CloudFormation may create the gateway while
   # that policy is still attaching, and a fresh deploy fails.
   self._gateway.node.add_dependency(gw_role)
   if policy_engine_access is not None:
       self._gateway.node.add_dependency(policy_engine_access)
   ```
2. Add AST-based unit tests in `tests/test_gateway_role.py` (parsed from source rather than importing `aws_cdk`, because the lightweight CI unit-test job runs without `aws-cdk-lib` / `jsii`) asserting:
   - `InvokeEgressInterceptor` is scoped strictly to `self._interceptor_fn.function_arn`.
   - `EvaluatePolicyEngine` includes both `policy_engine.attr_policy_engine_arn` and `gateway_arn_pattern` (`f"{gw_name}-*"`).
   - `self._gateway.node.add_dependency(gw_role)` and `self._gateway.node.add_dependency(policy_engine_access)` are both present.
3. Also add a unit test in `tests/test_runtime_role_scoping.py` verifying `MemoryKmsViaAgentCore` on `RuntimeStack` is scoped to `[kms_key_arn]` (no `"*"`) and enforces the `kms:ViaService` condition for `bedrock-agentcore.<region>.amazonaws.com`.

---

## 2. Eliminate `MODEL_ID` Drift Across `workshop.env`, `presets/production.yaml`, and Docs

**Files:** `workshop.env` (local), `presets/production.yaml`, `GFG_Deployment.md`, `docs/PLATFORM_YAML.md`

### Detailed Reason (Why This Matters)
There are three places where the earlier `eu.anthropic.claude-sonnet-4-6` model ID lingered after `platform.yaml` was switched to `openai.gpt-oss-120b-1:0`, and each causes a different failure for the next operator:

1. **Local `workshop.env` (`MODEL_ID=eu.anthropic.claude-sonnet-4-6`):**
   - `scripts/deploy.sh` applies configuration in strict precedence order:
     **explicit environment variables > `platform.yaml` > `workshop.env` > interactive prompts**.
   - During a normal `./scripts/deploy.sh build`, `platform.yaml` loads first and sets `MODEL_ID=openai.gpt-oss-120b-1:0`, so `workshop.env` does not overwrite it.
   - **However**, `workshop.env` looks like a standard `.env` file. If an engineer runs `source workshop.env` (or loads `.env` files automatically in their IDE/shell) before running `deploy.sh` or `verify.py`, `MODEL_ID` becomes an *explicit environment variable*, overriding `platform.yaml` and silently redeploying or testing against `eu.anthropic.claude-sonnet-4-6` — which then fails randomly whenever Bedrock routes a request to `eu-south-1` (blocked by the org SCP).
   - **Fix:** Update `MODEL_ID=openai.gpt-oss-120b-1:0` in local `workshop.env` (or run `./scripts/deploy.sh config --reset`).

2. **`presets/production.yaml` (`model_id` and `allowed_models`):**
   - `presets/production.yaml` is the template another team or colleague starts from when setting up a new production environment (`./scripts/deploy.sh design --profile production`).
   - Leaving `eu.anthropic.claude-sonnet-4-6` in `presets/production.yaml` guarantees that the next team in the same AWS Organization hits the exact same intermittent `AccessDeniedException ... explicit deny in a service control policy` in `eu-south-1` (because `deploy.sh doctor` only checks `bedrock:GetInferenceProfile` metadata in `eu-west-1`, which passes even when destination regions are SCP-blocked!).
   - **Important constraint on `presets/production.yaml` `region`:** Keep `region: us-east-1` in `presets/production.yaml` unless `scripts/check-contract.sh` is also updated, because `scripts/check-contract.sh` pre-seeds offline VPC AZ lookup context using `CDK_DEFAULT_REGION=us-east-1`. `openai.gpt-oss-120b-1:0` is offered on-demand in-region in **both** `us-east-1` and `eu-west-1` (as well as `eu-central-1` and `eu-north-1`), so setting `model_id: openai.gpt-oss-120b-1:0` in `presets/production.yaml` works cleanly for both CI contract-parity checks and EU/US deployments without cross-region SCP issues.

3. **`GFG_Deployment.md` & `docs/PLATFORM_YAML.md`:**
   - Once `presets/production.yaml` uses `openai.gpt-oss-120b-1:0`, remove any stale note in `GFG_Deployment.md` claiming that `presets/production.yaml` still names an `eu.` Claude profile, so the runbook and preset do not contradict each other.
   - Ensure `docs/PLATFORM_YAML.md` matches `python scripts/gen_platform_reference.py --check`.

---

## 3. Pass Explicit `region_name=runtime_region()` to Model Clients & Fail Fast When Region Is Unset

**Files:**
- `agent-code/shared/region.py`
- `agent-code/strands-agent/agent.py`
- `agent-code/agui-strands-agent/agent.py`
- `agent-code/langgraph-agent/agent.py`
- `agent-code/agui-langgraph-agent/agent.py`
- `agent-code/code-agent/agent.py`
- `agent-code/research-agent/agent.py`
- `agent-code/orchestrator/agent.py` & `agent-code/orchestrator/Dockerfile`
- `agent-code/claude-sdk-agent/code_int_mcp/client.py`
- `agent-code/claude-sdk-multi-agent/code_int_mcp/client.py`

### Detailed Reason (Why This Matters)
Previously, there were two subtle region bugs in `agent-code/`:

1. **Model clients (`BedrockModel` and `ChatBedrock`) omitted `region_name`:**
   - Memory (`AgentCoreMemorySessionManager` / `AgentCoreMemorySaver`), SSM (`get_ssm_parameter`), and Code Interpreter (`CodeInterpreterTools`) were updated to call `runtime_region()`, which reads `AWS_REGION_NAME` (injected by `RuntimeStack`).
   - However, `BedrockModel(...)` in Strands agents and `ChatBedrock(...)` in LangGraph agents did **not** pass `region_name=runtime_region()`.
   - Inside AWS AgentCore Runtime, the managed host happens to set `AWS_REGION`, so `boto3` found `eu-west-1`. But if a developer runs the container locally via Docker passing `AWS_REGION_NAME=eu-west-1` (matching `RuntimeStack`'s env var) without `AWS_REGION`, **Strands' `BedrockModel` defaults to `us-west-2`**, sending inference to Oregon (and failing against IAM/SCPs or missing models) while Memory and Code Interpreter talk to `eu-west-1`!
   - Also note: `agent-code/orchestrator/Dockerfile` originally did **not** copy `shared/` into `/app/shared/`. Adding `from shared.region import runtime_region` to `orchestrator/agent.py` without adding `COPY shared/ shared/` to `orchestrator/Dockerfile` would break container startup with `ModuleNotFoundError: No module named 'shared'`. Both must be updated together.

2. **Silent `DEFAULT_REGION = "eu-west-1"` fallback in `agent-code/shared/region.py`:**
   - Having `shared/region.py` hard-code `DEFAULT_REGION = "eu-west-1"` (just like the old code hard-coded `"us-east-1"`) swaps one silent cross-region bug for another if the repo is later deployed to `eu-central-1` or `us-east-1` and an env var is missed during local testing.
   - Instead, `runtime_region()` should check `AWS_REGION_NAME`, then `AWS_REGION`, then `AWS_DEFAULT_REGION`, and **raise a clear `RuntimeError`** if all three are unset. In AWS, `RuntimeStack` always sets `AWS_REGION_NAME` and AgentCore sets `AWS_REGION`, so a deployed container always resolves cleanly, and a misconfigured local container fails immediately instead of silently calling the wrong AWS region.

---

## 4. Isolate JWT Auth `ValueError` Handling Across All Agent Patterns

**Files:**
- `agent-code/langgraph-agent/agent.py`
- `agent-code/agui-strands-agent/agent.py`
- `agent-code/agui-langgraph-agent/agent.py`
- `agent-code/claude-sdk-agent/agent.py`
- `agent-code/claude-sdk-multi-agent/agent.py`

### Detailed Reason (Why This Matters)
`shared/auth.py`'s `extract_user_id_from_context(context)` validates the caller's Bearer JWT (signature against Cognito/IdP JWKS, expiration, issuer, and allowed `client_id`/`aud`) and raises `ValueError` whenever authentication fails. That `user_id` becomes the `actor_id` in AgentCore Memory — it is the tenant isolation boundary for conversation history.

During live debugging of `strands-agent`, we saw a critical ambiguity:
- **Case A (Catching `ValueError` too broadly):** In `strands-agent`, `extract_user_id_from_context(context)` and `_create_agent(...)` originally shared a single `try ... except ValueError:` block that returned `"Unauthorized"`. When Strands failed to load an MCP tool from the Gateway (before `InvokeEgressInterceptor` was fixed), Strands *also* raised `ValueError("Failed to load tool ...")` — causing the agent to falsely return `"Unauthorized"` for a backend Gateway 500 error!
- **Case B (Not catching auth `ValueError` separately at all):**
  - In `langgraph-agent/agent.py`, `extract_user_id_from_context(context)` was inside the generic `except Exception as e:` block, which echoed `str(e)` directly back to the HTTP caller — leaking internal JWT validation details (expected issuer URLs, client IDs, claim mismatch reasons) instead of a generic `"Unauthorized"` message.
  - In `agui-strands-agent`, `agui-langgraph-agent`, `claude-sdk-agent`, and `claude-sdk-multi-agent`, `extract_user_id_from_context(context)` was called **outside** the `try` block altogether, so an unauthenticated/expired token crashed the async generator with an unhandled exception instead of yielding a clean structured error (`{"status": "error", "error": "Unauthorized"}` or AG-UI `RunErrorEvent(message="Unauthorized", code="Unauthorized")`).

### What to Change
Give `extract_user_id_from_context(context)` its own dedicated `try ... except ValueError` block at the top of the entrypoint in all 5 remaining patterns:
- Log the detailed reason server-side (`logger.warning("Rejected unverified caller: %s", e)`) so operators see the exact cause in CloudWatch Logs.
- Return only `"Unauthorized"` (or `RunErrorEvent(message="Unauthorized", code="Unauthorized")` for `agui-*`) to the caller, then `return`.
- Keep agent creation, MCP tool loading, Memory initialization, and model streaming in a **separate** `try ... except Exception` block below it.

---

## 5. Fix Model-ID Prefix Parsing Bug in `allowed_model_resources()`

**Files:** `infra_utils/platform_config.py` (around lines 1819–1845), `tests/test_model_allowlist.py`

### Detailed Reason (Why This Matters)
`RuntimeStack` scopes the runtime IAM role's `BedrockModels` policy statement using `allowed_model_resources(allowed_models)` from `infra_utils/platform_config.py`:
- For a **cross-region inference profile** (such as `eu.anthropic.claude-sonnet-4-6`), Bedrock IAM requires **both** `arn:aws:bedrock:*:*:inference-profile/eu.anthropic.claude-sonnet-4-6` **and** the underlying foundation model `arn:aws:bedrock:*::foundation-model/anthropic.claude-sonnet-4-6*` (with `eu.` stripped).
- For an **in-region foundation model** (such as `openai.gpt-oss-120b-1:0`, `meta.llama3.1-70b-instruct-v1:0`, or `zai.glm-4.7-flash`), Bedrock IAM requires `arn:aws:bedrock:*::foundation-model/<provider>.<model>*` (with the provider prefix intact).

Previously, `allowed_model_resources()` detected geo prefixes using a generic 2-to-4-letter regex:
```python
prefix_match = re.match(r"^[a-z]{2,4}\.", m)
base = m[prefix_match.end() :] if prefix_match else m
if prefix_match and "." in base:
    resources.append(f"arn:aws:bedrock:*:*:inference-profile/{m}")
```

**Why that breaks real models:** Any provider whose namespace is 2–4 letters (`meta.`, `zai.`, `cohere` won't match `{2,4}` but `meta` and `zai` do!) **and** whose model version contains a dot (`llama3.1`, `glm-4.7`) satisfies **both** `^[a-z]{2,4}\.` and `"." in base`!
As a result, `meta.llama3.1-70b-instruct-v1:0` was misparsed as if `meta.` were a geographic region prefix, generating:
- `arn:aws:bedrock:*:*:inference-profile/meta.llama3.1-70b-instruct-v1:0` (non-existent)
- `arn:aws:bedrock:*::foundation-model/llama3.1-70b-instruct-v1:0*` (**missing `meta.`!**)

If an operator configures `meta.llama3.1-70b-instruct-v1:0` or `zai.glm-4.7-flash` in `platform.yaml`, `deploy.sh build` succeeds completely, and then **every single agent invocation fails at runtime with IAM `AccessDeniedException`** because the runtime role has no permission for `foundation-model/meta.llama3.1-...`!

### What to Change
1. Match only actual AWS Bedrock inference-profile geography prefixes (`us`, `us-gov`, `eu`, `apac`, `ca`, `jp`, `au`, `global`):
   ```python
   _GEO_PROFILE_PREFIX_RE = re.compile(r"^(?:us|us-gov|eu|apac|ca|jp|au|global)\.")
   ```
2. Add unit tests in `tests/test_model_allowlist.py` verifying:
   - `meta.llama3.1-70b-instruct-v1:0`, `zai.glm-4.7-flash`, and `openai.gpt-oss-120b-1:0` emit **only** `arn:aws:bedrock:*::foundation-model/<full-model-id>*` with the provider intact.
   - All 8 real geography prefixes (`us`, `eu`, `apac`, `global`, `jp`, `au`, `ca`, `us-gov`) still emit both the `inference-profile/` ARN and the stripped `foundation-model/` ARN.

---

## 6. Subscribe `alarm_email` to the `SecurityAlerts` SNS Topic in `ObservabilityStack`

**File:** `stacks/observability_stack.py` (around lines 578–615)

### Detailed Reason (Why This Matters)
In `platform.yaml`, production mode requires both `observability.alarms: true` (with `observability.alarm_email`) and `security.traceability: true`.
- Under `enable_alarms`, `ObservabilityStack` creates the `PlatformAlarms` SNS topic (`<prefix>-platform-alarms`) and subscribes `alarm_email` to it.
- Under `enable_traceability`, `ObservabilityStack` creates a second SNS topic, `SecurityAlerts` (`<prefix>-agentcore-security-alerts`), plus an EventBridge rule (`SensitiveAgentCoreEvents`) that catches CloudTrail management events for `CreateGateway`, `UpdateGateway`, `DeleteGateway`, `DeleteMemory`, `PutResourcePolicy`, `DeleteResourcePolicy`, `CreatePolicy`, `DeletePolicy`, and `UpdatePolicyEngine`.
- **The gap:** `SecurityAlerts` had **zero subscriptions** attached in CDK! EventBridge diligently routed sensitive security config-change alerts to `SecurityAlerts`, where SNS silently dropped them because nobody was subscribed.

### What to Change
Subscribe `alarm_email` to `self.alerts_topic` when `alarm_email` is provided (note: AWS SNS sends a separate confirmation email for this second topic, so the inbox owner must click confirm on both topics):
```python
if alarm_email:
    # Without a subscriber these control-plane events reach nobody.
    self.alerts_topic.add_subscription(
        subscriptions.EmailSubscription(alarm_email)
    )
```

---

## 8. Verification Commands Before Pushing

Run these checks from the repository root to prove everything is consistent offline and live:

```bash
# 1. Unit tests (run tests/ specifically; scripts/test_memory.py is a live CLI script, not a pytest module)
JSII_RUNTIME_PACKAGE_CACHE=disabled .venv/bin/pytest tests/ -p no:cacheprovider -q

# 2. Repository structure, docs link integrity, and platform.yaml reference parity
.venv/bin/python scripts/check_repository_structure.py
.venv/bin/python scripts/check_docs.py
.venv/bin/python scripts/gen_platform_reference.py --check

# 3. Preset <-> CDK synthesis contract parity across all presets/*.yaml
JSII_RUNTIME_PACKAGE_CACHE=disabled bash scripts/check-contract.sh

# 4. Deploy updated stacks to eu-west-1 and run the 8-check live verification suite
./scripts/deploy.sh build
./scripts/deploy.sh verify
```
