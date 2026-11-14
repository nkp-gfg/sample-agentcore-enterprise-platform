# Amplify & API Gateway Deployment Plan for `sample-agentcore-enterprise-platform`

This document captures how AWS Amplify and Amazon API Gateway work in `fullstack-solution-template-for-agentcore` (FAST), validates whether `sample-agentcore-enterprise-platform` can deploy its `hr-web` frontend to Amplify today, explains how API Gateway fits into this architecture, and specifies every code, infrastructure, script, test, and documentation change required to ship it cleanly.

---

## 1. Executive Summary & Readiness Verdict

**Current verdict:** **Not deployable to Amplify as-is.**

Today, `sample-agentcore-enterprise-platform` has no Amplify CDK stack, no S3 staging bucket, and no frontend deployment script, and `hr-web/public/app.js` relies on the local loopback Python server (`hr-web/server.py`) at runtime for both `/config.json` and `/invocations`.

With the targeted changes in this plan, `hr-web/public/` can be hosted on **AWS Amplify (`WEB` platform, manual S3-zip deployment)** without introducing a Node/Vite build step, while preserving local `127.0.0.1:8899` execution and all existing security controls.

### Live Validation Against This Account & Repo

Verified against the current workspace and deployed `agentcore-production` / `prod` footprint in `eu-west-1` (account `682975283765`):

| Area | Current Status | Finding |
|---|---|---|
| AWS Amplify availability | Ready | Amplify is active in account `682975283765` (`eu-west-1`); `aws-cdk-lib==2.273.0` already ships `aws_cdk.aws_amplify` (`CfnApp`, `CfnBranch`). |
| Static frontend assets | Ready | `hr-web/public/` is framework-free HTML/CSS/JS/JSON/SVG using relative asset URLs and `REDIRECT_URI = ${location.protocol}//${location.host}/`. |
| Deployed AgentCore Runtime auth | Ready | `agentcore_production_prod_orchestrator-rUbd4R4jXH` uses `AGUI` protocol with `CUSTOM_JWT` accepting `WebClient` (`5kg7rneg7c80bcn517o7nbgtje`) and `Authorization` allowlisted. |
| AgentCore Runtime CORS preflight | Ready | Live `OPTIONS` preflight to `bedrock-agentcore.eu-west-1.amazonaws.com` with `Origin: https://main.d1234567890.amplifyapp.com` returns `HTTP/2 200`, `access-control-allow-origin: *`, and allows `authorization, content-type, accept, x-amzn-bedrock-agentcore-runtime-session-id, x-amzn-trace-id`. |
| Cognito + Entra ID federation | Ready | Brokered Entra ID redirects to Cognito `/oauth2/idpresponse`; no Azure Entra app registration change is needed when adding an Amplify callback URL to Cognito `WebClient`. |
| Amplify CDK + deploy pipeline | Missing | No Amplify stack, S3 staging bucket, or `deploy-frontend` script exists in `stacks/`, `app.py`, or `scripts/`. |
| Frontend runtime endpoints | Blocked | `hr-web/public/app.js` fetches `/config.json` (served from SSM by `server.py`) and posts SSE requests to same-origin `/invocations` (`server.py` proxy). |
| Cognito `WebClient` callbacks | Blocked | `stacks/auth_stack.py` only registers `http://127.0.0.1:8899/`, `http://localhost:8899/`, and `http://localhost:3000/...`. |
| `god-agent` FastAPI CORS middleware | Needs update | `agent-code/god-agent/agent.py` hardcodes `allow_origins=["http://127.0.0.1:8899", "http://localhost:8899"]` and omits `X-Amzn-Trace-Id`. |
| HTTP security headers / CSP | Missing on host | `hr-web/server.py` injects CSP, `X-Frame-Options`, and `Cache-Control: no-store`; Amplify needs matching `customHeaders` with `bedrock-agentcore.<region>.amazonaws.com` in `connect-src`. |
| `dashboard/` (EBA Console) | Out of scope | `dashboard/monitor.py` uses local operator IAM credentials (`boto3`) and stays laptop-only. |

---

## 2. How Amplify Deployment Works in `fullstack-solution-template-for-agentcore` (FAST)

In FAST, Amplify hosting is implemented across three coordinated layers:

### 2.1 Predictable Amplify App + Private S3 Staging (`infra-cdk/lib/amplify-hosting-construct.ts`, `infra-terraform/modules/amplify-hosting/main.tf`)

1. Creates an **access-logs S3 bucket** (`BLOCK_ALL`, 90-day expiration) and a **versioned staging S3 bucket** (`BLOCK_ALL`, SSL-only `aws:SecureTransport=false` deny, 30-day artifact expiration) with a bucket policy granting `amplify.amazonaws.com` `s3:GetObject` and `s3:GetObjectVersion`.
2. Creates an **Amplify App** (`Platform.WEB`, manual deployment — no Git OAuth integration) and a **`main` branch** (`PRODUCTION` stage, `enable_auto_build = false`).
3. Derives the **predictable Amplify URL** immediately at construct instantiation time:
   `https://main.${amplifyApp.appId}.amplifyapp.com` (or `https://main.${cfnApp.attrDefaultDomain}`).

### 2.2 Non-Circular Stack Dependency Order (`infra-cdk/lib/fast-main-stack.ts`)

Because Cognito `UserPoolClient` callback URLs and API Gateway CORS origins both depend on the frontend origin, FAST constructs resources in this strict order:

1. **Step 1 — Amplify Hosting:** Create the Amplify app first so `amplifyUrl` is known before Cognito or Backend constructs render.
2. **Step 2 — Cognito (`cognito-construct.ts`):** Pass `["http://localhost:3000", amplifyUrl]` into the public SPA `UserPoolClient` (`generateSecret: false`, Authorization Code + PKCE).
3. **Step 3 — Backend (`backend-construct.ts`):** Pass `amplifyUrl` into the Backend construct for API Gateway CORS (`CORS_ALLOWED_ORIGINS`) and publish `RuntimeArn`, `CognitoUserPoolId`, `CognitoClientId`, `FeedbackApiUrl`, `AmplifyAppId`, `StagingBucketName`, and `AmplifyUrl` as outputs/SSM parameters.

### 2.3 Build, Config Injection, and S3-Zip Deployment (`scripts/deploy-frontend.py`)

FAST does **not** embed environment variables at CDK synth time. Instead, after CDK deploys:

1. `scripts/deploy-frontend.py` reads stack outputs (`AmplifyAppId`, `StagingBucketName`, `AmplifyUrl`, `CognitoClientId`, `CognitoUserPoolId`, `RuntimeArn`, `FeedbackApiUrl`).
2. Writes non-secret runtime metadata to `public/aws-exports.json` (`authority`, `client_id`, `redirect_uri`, `post_logout_redirect_uri`, `agentRuntimeArn`, `awsRegion`, `feedbackApiUrl`, `agentPattern`).
3. Runs `npm run build` (`vite build` -> `frontend/build/`) and copies `aws-exports.json` into `build/`.
4. Zips `build/` into `amplify-deploy.zip`, uploads it to `s3://<StagingBucketName>/amplify-deploy-<ts>.zip`, calls `aws amplify start-deployment --app-id ... --branch-name main --source-url s3://...`, and polls `aws amplify get-job` until `SUCCEED`.

### 2.4 Direct Browser Invocation (`frontend/src/lib/agentcore-client/client.ts`)

Once loaded in the browser:

- `AuthProvider` (`frontend/src/lib/auth.ts`) fetches `/aws-exports.json` and runs OIDC PKCE login against Cognito Hosted UI.
- `AgentCoreClient.invoke()` sends `POST` requests **directly from the browser** to:
  `https://bedrock-agentcore.<region>.amazonaws.com/runtimes/<encodeURIComponent(runtimeArn)>/invocations?qualifier=DEFAULT`
  with `Authorization: Bearer <accessToken>`, `X-Amzn-Trace-Id`, `X-Amzn-Bedrock-AgentCore-Runtime-Session-Id`, and `Content-Type: application/json`, then reads the `text/event-stream` response via `response.body.getReader()`.

---

## 3. How API Gateway Works Here (Lessons from FAST)

Understanding the split between **AgentCore Runtime**, **AgentCore Gateway**, and **Amazon API Gateway** is essential before writing any infrastructure code.

### 3.1 Three Distinct Endpoints — Do Not Mix Them

| Endpoint | Protocol & Auth | Caller | Purpose |
|---|---|---|---|
| **AgentCore Runtime** (`bedrock-agentcore.<region>.amazonaws.com/runtimes/.../invocations`) | `AGUI` SSE (`POST`), `CUSTOM_JWT` (`access_token`) | Browser (`hr-web` / FAST) | Streams God Bot chat, subagent handovers, tool-result A2UI events, `checkPendingReviews`, and interrupt resumes. |
| **AgentCore Gateway** (`*.gateway.bedrock-agentcore.<region>.amazonaws.com/mcp`) | MCP JSON-RPC, M2M JWT (`client_credentials` + `hr-identity` claims) + Cedar `ENFORCE` + Guardrail Interceptor | `god-agent` runtime only (never the browser) | Executes policy-governed HR Lambda tools (`hr-ops`, `hr-payroll`, `hr-finance`) against Aurora `hr`. |
| **Amazon API Gateway** (`<api-id>.execute-api.<region>.amazonaws.com/...`) | Standard short-lived JSON REST (`GET`/`POST`/`DELETE`), Cognito/JWT Authorizer (`id_token` or scoped `access_token`) | Browser (`hr-web` / FAST) | Application persistence & metadata APIs (user feedback, persistent chat session listing/history) backed by DynamoDB or `agent_state`. |

### 3.2 Why Agent Chat & Streaming Do NOT Go Through API Gateway

In FAST, **agent `/invocations` calls bypass API Gateway completely** and hit `https://bedrock-agentcore.<region>.amazonaws.com` directly from the browser:

1. **Streaming & Timeout Limits:** Classic API Gateway REST API buffers responses and enforces a hard **29-second** integration timeout by default. `god-agent` executes Bedrock Converse calls across three agent tiers (`god-bot` -> department -> leaf) plus Gateway MCP Lambdas, which frequently run 10–45+ seconds and rely on incremental SSE chunk streaming (`TEXT_MESSAGE_CONTENT`, `SUBAGENT_STARTED`, `TOOL_CALL_RESULT`).
2. **VPC Compatibility Without a Proxy:** Even though `sample-agentcore-enterprise-platform` runs `god-agent` in `network_mode: VPC` (private subnets), AgentCore's managed data plane fronts the runtime ENIs on `https://bedrock-agentcore.<region>.amazonaws.com` and enforces `CUSTOM_JWT` + edge CORS automatically (`FAST/docs/DEPLOYMENT.md` § "What runs inside vs outside the VPC").
3. **Zero Proxy Hop:** Removing a Lambda/API Gateway proxy keeps the browser-to-runtime path free of extra IAM roles, proxy latency, and chunk buffering.

### 3.3 How FAST Uses API Gateway (`backend-construct.ts` + `lambdas/feedback/index.py` + `docs/SESSION_MANAGEMENT.md`)

In FAST, API Gateway is strictly for **non-streaming REST application APIs**:

1. **Feedback API (`POST /feedback`):**
   - `apigateway.RestApi` (`prod` stage) with `CognitoUserPoolsAuthorizer`, `RequestValidator` (`validateRequestBody: true`), and `defaultCorsPreflightOptions` restricted to `[frontendUrl, "http://localhost:3000"]`.
   - `PythonFunction` (Python 3.13, `ARM_64`, AWS Lambda Powertools `APIGatewayRestResolver` + `CORSConfig` + Pydantic `FeedbackRequest`).
   - Reads `user_id` strictly from `app.current_event.request_context.authorizer["claims"]["sub"]` (never from the JSON body) and writes to a DynamoDB table (`{prefix}-feedback` with `feedbackType-timestamp-index` GSI).
   - **Important token rule:** Browser sends **`id_token`** (`auth.user?.id_token`) to `CognitoUserPoolsAuthorizer`, whereas it sends **`access_token`** to AgentCore Runtime (`feedbackService.ts:43`, `ChatInterface.tsx:224`). That happens because standard `CognitoUserPoolsAuthorizer` without `authorizationScopes` validates `aud == client_id` (present on Cognito `id_token`, absent on Cognito `access_token`, which carries `client_id` instead).

2. **Session Management API (`GET /sessions`, `GET /sessions/{sessionId}`, `DELETE /sessions/{sessionId}` — `FAST/docs/SESSION_MANAGEMENT.md`):**
   - Because `hr-web` stores chat history only in closure memory (`state.historyByUser`, hardened to never persist transcripts in `localStorage`/`sessionStorage`), refreshing the browser tab loses rendered chat transcripts (while the LangGraph checkpointer in Aurora `agent_state` retains graph state).
   - Adding `/sessions` routes on API Gateway lets the frontend list and reload past conversations per verified `sub` without storing sensitive HR chat transcripts in browser web storage.

### 3.4 Recommended API Gateway Design for `sample-agentcore-enterprise-platform`

You have two deployment modes depending on scope:

- **Phase A — Minimal Amplify Deployment (Zero API Gateway):**
  Deploy `AmplifyStack` + `hr-web/public/` + direct `/invocations`. Chat, A2UI cards, `EmployeeConfirmForm`, `ManagerReviewCard`, and `checkPendingReviews` (persisted in `agent_state.hr_pending_reviews`) all work **with zero API Gateway**.
- **Phase B — Full FAST Parity (Add `stacks/api_stack.py`):**
  Add an API Gateway stack for `/feedback` and `/sessions`, adapted for this repo's security and identity rules:

| Design Choice | FAST Implementation | Recommended Adaptation for This Platform |
|---|---|---|
| **API Gateway type & authorizer** | `apigateway.RestApi` + `CognitoUserPoolsAuthorizer` (brokered Cognito only; requires `id_token`). | Prefer **HTTP API (`aws_apigatewayv2.HttpApi`) + `HttpJwtAuthorizer`** (`issuer_url`, `audience = [web_client_id, app_client_id]`) **or** `RestApi` + `CognitoUserPoolsAuthorizer`. `HttpJwtAuthorizer` works in both Cognito `brokered` mode (with `id_token`, which carries `aud`) and Entra `direct` mode (`aud = app_client_id`), and integrates cleanly via SSM `auth/issuer-url` without importing `UserPool` constructs. |
| **Response caching** | FAST sets `cachingEnabled: true` on `RestApi` (`backend-construct.ts:645`). | **Disable caching (`caching_enabled=False`)** on user-scoped `GET /sessions*` endpoints (or key cache explicitly on `Authorization` hash) so User A can never receive User B's cached session list/transcript. |
| **CORS origins** | `${frontendUrl},http://localhost:3000`. | Pin strictly to `${amplifyUrl},http://127.0.0.1:8899,http://localhost:8899` (never `*`). |
| **Session storage backend** | DynamoDB (`{prefix}-Sessions`) + AgentCore Memory. | In `god-agent`, conversation checkpoints and ownership already live in Aurora `agent_state` (`checkpoints`, `hr_thread_owners`, `hr_pending_reviews`). Either: (a) place the `/sessions` Lambda in `Private` subnets (`networking/private-subnet-ids`, `networking/runtime-security-group-id`) with a read-only/scoped `agent_state` role via RDS IAM auth, or (b) add a DynamoDB `{prefix}-sessions` metadata table encrypted with the platform CMK (`retain_data` respected). Keep `hr_thread_owners` (`owner_sub = claims["sub"]`) as the strict row filter. |
| **Feedback storage** | DynamoDB (`{prefix}-feedback`), `AWS_MANAGED` encryption. | DynamoDB `{prefix}-feedback` with `encryption=KMS` (platform CMK when `enable_security` is on), `point_in_time_recovery_specification`, and `RemovalPolicy.RETAIN` when `retain_data=True`. |
| **Production observability & IAM** | 1-week log retention, `DESTROY` removal policy. | Match platform rules: 90/365-day log retention, `RETAIN` when `retain_data=True`, structured API Gateway access logs, throttling, and `RequestValidator`. |
| **SSM interface** | `/<stack>/feedback-api-url`, `/<stack>/sessions-api-url`. | Publish under `/{project}/{environment}/frontend/api-url` (or `/api/feedback-url`, `/api/sessions-url`) per `docs/PLATFORM_INTERFACE.md`. |

---

## 4. Complete Plan of Code Changes Required

Below is every file to create or modify in `sample-agentcore-enterprise-platform`, grouped by layer.

### 4.1 Configuration & Deployment Contract (`infra_utils/platform_config.py`, `app.py`)

1. **Add `FrontendConfig` to `infra_utils/platform_config.py`:**
   - Add a `FrontendConfig(BaseModel)` with `extra = "forbid"`:
     - `amplify: bool = False` (opt-in so all existing presets and `tests/test_contract.py` default footprints remain unchanged)
     - `api: bool = False` (opt-in API Gateway for `/feedback` and `/sessions`; requires `amplify` or explicit enablement)
     - `allowed_origins: list[str] = Field(default_factory=list)` (optional extra origins beyond Amplify + loopback)
   - Add `frontend: FrontendConfig = Field(default_factory=FrontendConfig)` on `PlatformConfig`.
   - Add validator: refuse `frontend.amplify: true` when `identity.mode == "direct"` (unless Entra SPA redirect URIs and direct-mode frontend config are explicitly supported — `hr-web` today reads `auth/web-client-id`, which is brokered-only).
   - Add `ENABLE_AMPLIFY_FRONTEND` / `ENABLE_FRONTEND_API` to `to_env()` and `apply_environment_overrides()`.
   - Update `expected_stacks(self, account: str = "")` to insert:
     - `f"{prefix}-frontend"` (before `auth`, when `self.frontend.amplify` and `role != "workload"`)
     - `f"{prefix}-frontend-api"` (after `auth`/`memory`/`networking`, when `self.frontend.api` and `role != "platform"` or matching `auth` side — in centralized mode both are in the same account).

2. **Wire stacks in `app.py`:**
   - Read `enable_amplify_frontend = cfg("enable_amplify_frontend", "ENABLE_AMPLIFY_FRONTEND", "false") == "true"` and `enable_frontend_api = cfg("enable_frontend_api", "ENABLE_FRONTEND_API", "false") == "true"`.
   - Instantiate `AmplifyStack` (`{prefix}-frontend`) **before** `AuthStack` so `amplify_stack.amplify_url` is available to pass into `AuthStack`.
   - Pass `web_callback_urls` / `web_logout_urls` to `AuthStack`:
     `[f"{amplify_stack.amplify_url}/"]` when `amplify_stack` is enabled.
   - Pass `allowed_cors_origins` (including `amplify_stack.amplify_url`) to `RuntimeStack` (`orchestrator`) if `god-agent` keeps `CORSMiddleware`.
   - Instantiate `FrontendApiStack` (`{prefix}-frontend-api`) when `enable_frontend_api` is true, wiring `auth_stack` / `amplify_stack` / `security_stack` / `networking_stack`.

### 4.2 New Amplify Hosting Stack (`stacks/amplify_stack.py`)

Create `stacks/amplify_stack.py` modeled directly on `FAST/infra-cdk/lib/amplify-hosting-construct.ts`, using `aws_cdk.aws_amplify` (`CfnApp`, `CfnBranch`) already included in `aws-cdk-lib==2.273.0` (no new package dependency):

1. **S3 Access Logs & Staging Buckets:**
   - `StagingBucketAccessLogs`: `BLOCK_ALL`, `enforce_ssl=True`, 90-day lifecycle expiry, `RemovalPolicy.RETAIN` (`auto_delete_objects=False`) when `retain_data=True` (required by `tests/test_production_mode.py` so no `Custom::S3AutoDeleteObjects` is synthesized in production).
   - `StagingBucket`: `versioned=True`, `BLOCK_ALL`, `enforce_ssl=True`, server access logging to `StagingBucketAccessLogs`, 30-day object expiration, KMS or S3-managed encryption, `RemovalPolicy.RETAIN` when `retain_data=True`.
   - Bucket resource policy:
     - Allow `amplify.amazonaws.com` (`s3:GetObject`, `s3:GetObjectVersion`) scoped with `aws:SourceAccount` / `aws:SourceArn` to the Amplify app/account where supported, or bucket objects per FAST (`AmplifyAccess`).
     - Explicit `Deny` on `aws:SecureTransport == false`.

2. **Amplify `CfnApp` & `CfnBranch`:**
   - `aws_amplify.CfnApp`:
     - `name=f"{prefix}-hr-web"`
     - `platform="WEB"`
     - `custom_rules`:
       - Exact static assets pass through; SPA fallback rule only if needed (or `/<*>` -> `/index.html` `404-200`, keeping `/config.json` served directly).
     - `custom_headers`: YAML matching `hr-web/server.py:640-662` security headers:
       - `X-Content-Type-Options: nosniff`
       - `Referrer-Policy: no-referrer`
       - `X-Frame-Options: DENY`
       - `Permissions-Policy: camera=(), microphone=(), geolocation=()`
       - `Cross-Origin-Opener-Policy: same-origin`
       - `Cross-Origin-Resource-Policy: same-origin`
       - `Strict-Transport-Security: max-age=31536000; includeSubDomains`
       - `Content-Security-Policy`:
         ```text
         default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self';
         connect-src 'self' https://cognito-idp.<region>.amazonaws.com https://<cognito_domain_prefix>.auth.<region>.amazoncognito.com https://bedrock-agentcore.<region>.amazonaws.com <api_origin>;
         object-src 'none'; worker-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'
         ```
       - On `/config.json`: `Cache-Control: no-store`.
   - `aws_amplify.CfnBranch`:
     - `app_id=cfn_app.attr_app_id`
     - `branch_name="main"`
     - `stage="PRODUCTION"`
     - `enable_auto_build=False`

3. **Predictable Domain Property & Outputs/SSM:**
   - `self.amplify_url = f"https://main.{cfn_app.attr_default_domain}"` (equivalent to `https://main.{appId}.amplifyapp.com`).
   - Publish SSM parameters under `/{project}/{environment}/frontend/`:
     - `amplify-app-id`
     - `amplify-url`
     - `staging-bucket`
   - Emit CfnOutputs: `AmplifyAppId`, `AmplifyUrl`, `AmplifyConsoleUrl`, `StagingBucketName`.

> **Alternative if you want a `use-cases/` stack instead of a core stack:** You can place this under `use-cases/hr-web-amplify/stack.py` (`requires: [auth, runtime-orchestrator]`), reading `auth/*` from SSM. However, because `use-cases/` run after `auth` and must not modify `auth_stack.py` directly via CDK imports, updating `WebClient` callback URLs in `auth` would require either an `AwsCustomResource` (`cognito:UpdateUserPoolClient`) or setting `frontend.amplify_url` in `platform.yaml`. Placing `AmplifyStack` in `stacks/` before `AuthStack` (matching FAST) avoids that fragility.

### 4.3 Optional API Gateway Stack (`stacks/api_stack.py` + `lambdas/frontend_api/`)

Only needed if implementing Phase B (`/feedback` and/or `/sessions`):

1. **DynamoDB Table(s):**
   - `{prefix}-feedback` (`feedbackId` PK, `feedbackType-timestamp-index` GSI, CMK encryption if `kms_key_arn` provided, PITR enabled, `RemovalPolicy.RETAIN` if `retain_data=True`).
   - Optional `{prefix}-sessions` metadata table (`userId` PK, `sessionId` SK) — or connect `/sessions` Lambda to `agent_state` in Aurora.
2. **Lambda Function (`ARM_64`, Python 3.13):**
   - Uses AWS Lambda Powertools + Pydantic (ported from `FAST/infra-cdk/lambdas/feedback/index.py`).
   - Reads `sub` strictly from verified JWT claims (`authorizer.claims["sub"]` or `authorizer.jwt.claims["sub"]` for HTTP API v2).
   - `CORS_ALLOWED_ORIGINS` set from `amplify_url` + loopback origins (never `*`).
   - If querying `agent_state` in Aurora, attaches to `networking/private-subnet-ids` + `networking/runtime-security-group-id` + `rds-db:connect` (`agent_checkpoint` or a dedicated read-only `agent_state_reader` DB role) + RDS CA bundle (`verify-full`).
3. **API Gateway (`HttpApi` + `HttpJwtAuthorizer` recommended, or `RestApi` + `CognitoUserPoolsAuthorizer`):**
   - Routes: `POST /feedback`, `GET /sessions`, `GET /sessions/{sessionId}`, `DELETE /sessions/{sessionId}`.
   - Throttling, structured JSON access logs, `caching_enabled=False`, strict CORS preflight allowlist (`amplify_url`).
   - Publish SSM parameter `/{project}/{environment}/frontend/api-url`.

### 4.4 Auth Stack (`stacks/auth_stack.py`)

Update `AuthStack.__init__` (`stacks/auth_stack.py:249-289`):

- Add optional `web_callback_urls: list[str] | None = None` and `web_logout_urls: list[str] | None = None` parameters (or merge into `web_callbacks` / `web_logouts`).
- Keep `"http://127.0.0.1:8899/"` and `"http://localhost:8899/"` so local `hr-web/server.py` continues working.
- Append `https://main.<appId>.amplifyapp.com/` (note the **trailing slash**, matching `hr-web/public/app.js:36` `REDIRECT_URI = ${location.protocol}//${location.host}/`).
- Keep `self._web_client` as a public PKCE client (`generate_secret=False`, `supported_providers` restricted to enterprise IdP when federated).

### 4.5 Runtime Stack & `god-agent` CORS (`stacks/runtime_stack.py`, `agent-code/god-agent/agent.py`)

In `agent-code/god-agent/agent.py:260-271`:

- Today:
  ```python
  app.add_middleware(
      CORSMiddleware,
      allow_origins=["http://127.0.0.1:8899", "http://localhost:8899"],
      allow_credentials=False,
      allow_methods=["POST", "OPTIONS"],
      allow_headers=[
          "Authorization",
          "Content-Type",
          "Accept",
          "X-Amzn-Bedrock-AgentCore-Runtime-Session-Id",
      ],
  )
  ```
- **Change:** Either:
  1. **Remove `CORSMiddleware`** (matching `FAST/patterns/agui-langgraph-agent/agent.py` and `agent-code/agui-langgraph-agent/agent.py`, letting the AgentCore Runtime data-plane edge handle CORS), **or**
  2. Configure `allow_origins` dynamically from `CORS_ALLOWED_ORIGINS` env var (injected by `RuntimeStack` with `http://127.0.0.1:8899`, `http://localhost:8899`, and `amplify_url`) and add `"X-Amzn-Trace-Id"` to `allow_headers` (because `hr-web/public/app.js:2459` sends `X-Amzn-Trace-Id`).
- Redeploy `{prefix}-runtime-orchestrator` after updating `agent.py` so the ARM64 CodeBuild container picks up the change.

### 4.6 Frontend Application (`hr-web/public/`)

1. **`hr-web/public/app.js`:**
   - **Direct AgentCore Runtime invocation off loopback (`app.js:2269`):**
     Update `runtimeUrl()` so loopback keeps same-origin `"/invocations"` (passing `hr-web/server.py` local tests and `InvocationGate` proxy) while hosted Amplify calls the regional AgentCore Runtime endpoint directly:
     ```js
     function isLoopbackOrigin() {
       return ["127.0.0.1", "localhost", "::1"].includes(location.hostname);
     }

     function runtimeUrl() {
       if (isLoopbackOrigin()) {
         return "/invocations";
       }
       const encoded = encodeURIComponent(state.config.runtime_arn);
       return `https://bedrock-agentcore.${state.config.region}.amazonaws.com/runtimes/${encoded}/invocations?qualifier=DEFAULT`;
     }
     ```
   - **Optional `config.json` fields (`app.js:54-61`, `app.js:824-840`):**
     Keep existing 6 required keys (`runtime_arn`, `region`, `web_client_id`, `issuer_url`, `gateway_url`, `a2ui_protocol_version`), and treat `feedback_api_url` / `sessions_api_url` (and optional `invoke_mode`) as optional validated `https://` URLs.
   - **Optional API Gateway client calls (Phase B):**
     Use `state.idToken` (for `CognitoUserPoolsAuthorizer` / `HttpJwtAuthorizer` `aud` match) in `Authorization: Bearer ${state.idToken}` when calling `/feedback` or `/sessions`, with silent refresh retry on `401` matching `streamAgent()`.
   - **Token storage invariant:** Keep OIDC tokens strictly in closure memory (`state.accessToken`, `state.idToken`, `state.refreshToken`), never `localStorage`, preserving the OWASP tests in `hr-web/tests/test_server_boundary.py`.

2. **`hr-web/public/index.html` & `hr-web/public/enterprise-catalog.js`:**
   - Replace hardcoded `"127.0.0.1 only"` login caption (`index.html:34`) and `APP_SUBTITLE` (`enterprise-catalog.js:12`) with environment-neutral text (e.g., `"Secured with Amazon Cognito PKCE & Bedrock AgentCore"` / `"Unified Employee AI Workspace"`).
   - **Do NOT add any `http://` or `https://` URL strings inside `enterprise-catalog.js`** — `test_serves_enterprise_catalog_asset_with_security_headers` explicitly asserts none exist in that file.

3. **`.gitignore`:**
   - Add `hr-web/public/config.json` to `.gitignore` so locally generated Amplify config files are never committed.

4. **`hr-web/server.py`:**
   - Keep `server.py` working unchanged for local `127.0.0.1:8899` sessions (its `_handle_read()` intercepts `GET /config.json` directly from SSM before static file lookup).

### 4.7 Deployment & Operational Scripts (`scripts/`)

1. **Create `scripts/deploy_frontend.py` (modeled after `FAST/scripts/deploy-frontend.py`):**
   - Reads `platform.yaml` via `infra_utils.platform_config.load_platform_config` (following repo conventions, unlike FAST's regex parser).
   - Uses `boto3` (`ssm:GetParameter`, `s3:PutObject`, `amplify:StartDeployment`, `amplify:GetJob`) rather than shelling out to `aws`, keeping credentials clean and region explicit:
     - Reads SSM:
       - `/{prefix_slash}/frontend/amplify-app-id`
       - `/{prefix_slash}/frontend/amplify-url`
       - `/{prefix_slash}/frontend/staging-bucket`
       - `/{prefix_slash}/runtimes/orchestrator/arn`
       - `/{prefix_slash}/auth/web-client-id`
       - `/{prefix_slash}/auth/issuer-url`
       - `/{prefix_slash}/gateway/url`
       - Optional: `/{prefix_slash}/frontend/api-url`
   - Validates `runtime_arn` region via the same `RUNTIME_ARN_RE` pattern used in `hr-web/server.py`, and verifies zero secret-looking keys are written.
   - Copies `hr-web/public/` into a clean staging `tempfile.TemporaryDirectory` (excluding any stray dotfiles/backups), writes `config.json` into that staging copy (never mutating `hr-web/public/` unless requested), creates `amplify-deploy.zip`, uploads to `s3://<staging-bucket>/amplify-deploy-<ts>.zip`, calls `amplify.start_deployment(...)`, and polls `amplify.get_job(...)` until `SUCCEED`.
   - **No Node/npm/Vite build needed** because `hr-web/public/` is pure static ES/CSS/HTML.

2. **Integrate with `scripts/deploy.sh` & `scripts/verify.py`:**
   - Add `./scripts/deploy.sh frontend` (or hook into `deploy` / `build` after CDK stacks succeed when `frontend.amplify: true` is enabled in `platform.yaml`).
   - Update `scripts/verify.py`: when `frontend` stack is in `expected_stacks()`, verify `GET <amplify_url>/config.json` returns `200`, contains only the whitelisted non-secret fields, sets `Cache-Control: no-store` and `X-Frame-Options: DENY`, and verify `GET <amplify_url>/` returns `200`.

### 4.8 Tests & Documentation Gates

1. **`tests/test_amplify_stack.py` (new):**
   - Synth assertions:
     - `StagingBucket` has `PublicAccessBlockConfiguration` all `True`, `VersioningConfiguration: Enabled`, `LoggingConfiguration` set, SSL-only bucket policy (`aws:SecureTransport: false`), and **no** `Custom::S3AutoDeleteObjects` when `retain_data=True`.
     - `AWS::Amplify::App` uses `Platform: WEB` and `CustomHeaders` include strict CSP (`connect-src` with `bedrock-agentcore.<region>.amazonaws.com`, `cognito-idp.<region>.amazonaws.com`, `*.auth.<region>.amazoncognito.com`, no `'unsafe-inline'`, no `.*.` mid-hostname wildcards).
     - `AuthStack` `WebClient` includes `https://main.<domain>/` in `CallbackURLs` and `LogoutURLs` alongside `:8899`.
     - If `FrontendApiStack` exists: JWT authorizer enabled, `cachingEnabled` disabled on user-scoped routes, CORS origin pinned (never `*`).
2. **`hr-web/tests/test_server_boundary.py`:**
   - Add a Node VM test verifying `runtimeUrl()` resolves to `"/invocations"` on `127.0.0.1` / `localhost` and to `https://bedrock-agentcore.<region>.amazonaws.com/runtimes/<encoded>/invocations?qualifier=DEFAULT` on `main.<id>.amplifyapp.com`.
3. **Existing Repo Gates (must remain green):**
   - `.venv/bin/python -m pytest tests/ hr-web/tests/ -q`
   - `scripts/check-contract.sh` (verifies `expected_stacks()` matches `app.py` for every preset and fixture; add a fixture under `tests/fixtures/contract/` with `frontend.amplify: true`).
   - `.venv/bin/python scripts/check_repository_structure.py` (do **not** add unregistered top-level directories; place new code inside `stacks/`, `hr-web/`, `scripts/`, `tests/`).
   - `.venv/bin/python scripts/check_docs.py` (if adding docs under `docs/`, link cleanly and pass Docsify integrity checks).
4. **Update Architecture & HR Planning Docs:**
   - Update `custom-app-plan/review.md`, `custom-app-plan/phases.md`, `hr-web/README.md`, `docs/PLATFORM_INTERFACE.md`, and `GFG_Deployment_Part2.md` to document the opt-in Amplify hosting mode alongside the local `127.0.0.1:8899` facilitator mode.

---

## 5. Security & Operational Considerations When Moving From `127.0.0.1` to Amplify

1. **Public URL Exposure:** `https://main.<appId>.amplifyapp.com/` is publicly reachable on the internet (static assets + `config.json` are unauthenticated, which is safe because `config.json` holds only public URLs/IDs — zero secrets — and every AgentCore/API call requires a Cognito JWT federated through Entra ID MFA/Conditional Access). Restricting access further requires AWS WAF + IP allowlisting or Cognito/CloudFront edge protection if mandated by customer policy.
2. **CSP Exactness (`customHeaders` vs `server.py`):** In `hr-web/server.py`, `_discover_cognito_auth_origin()` pins the exact `<domain>.auth.<region>.amazoncognito.com` origin into `connect-src`. Because Cognito domain prefix is deterministic (`{project}-{environment}-{account}`), `AmplifyStack` can compute the exact origin `https://{prefix}-{account}.auth.{region}.amazoncognito.com` at CDK synth time rather than using wildcards.
3. **Browser-to-Runtime `X-Amzn-Trace-Id` & `Accept` Headers:** Confirm after first live deploy that `POST /invocations` succeeds from Chrome/Safari without CORS rejection when `god-agent`'s `CORSMiddleware` is updated or removed.
4. **Session / Refresh Behavior on Amplify:** Unlike localhost reloads when restarting `server.py`, Amplify pages keep tokens in closure memory across the tab's lifetime; clicking **Sign out** clears closure tokens, purges any legacy storage, revokes the Cognito refresh token, and calls Cognito `logout` (`end_session_endpoint`) so switching personas (`E1` -> `M1`) works cleanly.

---

## 6. Execution Sequence (Once Changes Are Implemented)

1. **Pre-deploy local checks:**
   ```bash
   .venv/bin/python -m pytest tests/ hr-web/tests/ -q
   ./scripts/check-contract.sh
   .venv/bin/python scripts/check_repository_structure.py
   ```
2. **Enable in `platform.yaml`:**
   ```yaml
   frontend:
     amplify: true
     api: false   # set true only when deploying Phase B (/feedback, /sessions)
   ```
3. **Validate & deploy infrastructure in dependency order:**
   ```bash
   ./scripts/deploy.sh design
   ./scripts/deploy.sh doctor
   NON_INTERACTIVE=1 ./scripts/deploy.sh deploy --stack "$PREFIX-frontend"
   NON_INTERACTIVE=1 ./scripts/deploy.sh deploy --stack "$PREFIX-auth"
   NON_INTERACTIVE=1 ./scripts/deploy.sh deploy --stack "$PREFIX-runtime-orchestrator"
   # Optional Phase B:
   # NON_INTERACTIVE=1 ./scripts/deploy.sh deploy --stack "$PREFIX-frontend-api"
   ```
4. **Package & deploy `hr-web/public/` + generated `config.json` to Amplify:**
   ```bash
   .venv/bin/python scripts/deploy_frontend.py
   ```
5. **Verify live:**
   - `./scripts/deploy.sh verify` passes including frontend `GET /` and `GET /config.json` (`Cache-Control: no-store`).
   - Open `https://main.<appId>.amplifyapp.com/` -> **Sign in** -> Entra ID SSO -> Cognito PKCE callback succeeds with no `redirect_uri_mismatch`.
   - Ask `"How many annual and sick leave days do I have remaining?"` as `E1` -> `POST https://bedrock-agentcore.<region>.amazonaws.com/.../invocations` streams `200 OK` SSE and renders `LeaveBalanceCard`.
   - Run 2-stage leave approval (`E1` `EmployeeConfirmForm` Confirm -> sign out -> `M1` `ManagerReviewCard` Approve) and verify `decision_log` in Aurora.
