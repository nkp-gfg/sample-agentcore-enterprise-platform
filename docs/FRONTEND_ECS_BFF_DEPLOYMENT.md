# Hosted HR Web UI (WAF + ALB + ECS Fargate BFF + DynamoDB)

Deployment guide and runbook for hosting `hr-web` behind AWS WAFv2, a config-switchable public/private Application Load Balancer, auto-scaling ARM64 ECS Fargate tasks, DynamoDB session/chat persistence, and a VPCE-locked AgentCore Runtime.

---

## 1. Architecture Summary

1. **AWS WAFv2 (`REGIONAL` WebACL) + Switchable Public/Private ALB (`stacks/frontend_stack.py`):**
   - Attached to the ALB in both `exposure: private` (Internal ALB in private subnets) and `exposure: public` (Internet-facing ALB in public subnets).
   - Enforces per-IP rate limiting (`waf_rate_limit`), `AWSManagedRulesAmazonIpReputationList`, `AWSManagedRulesKnownBadInputsRuleSet`, `AWSManagedRulesCommonRuleSet`, and optional `BlockOutsideAllowedCidrs` (`IPSet` + ALB Security Group).
   - `idle_timeout=300s` for long-lived AG-UI SSE streaming; `load_balancer_name` is omitted so flipping `exposure` replaces the ALB scheme cleanly.
2. **Auto-Scaling ARM64 ECS Fargate BFF (`hr-web/Dockerfile`, `hr-web/bff/app.py`):**
   - Built remotely via CodeBuild (`linux/arm64`) → ECR (no local Docker required).
   - `min_healthy_percent=100`, `max_healthy_percent=200`, scaling between `frontend.min_capacity` and `frontend.max_capacity` on CPU (60%), memory (70%), and ALB request count (300/target, 30s scale-out cooldown).
   - Uses confidential `BffClient` (or direct Entra app registration) so OAuth tokens remain server-side; the browser receives only an `HttpOnly; SameSite=Lax` cookie (`hr_bff_sid`) + `X-BFF-CSRF` header.
3. **DynamoDB Sessions & Chat Persistence (`hr-web/bff/session_store.py`):**
   - `BffSessions` (`PAY_PER_REQUEST`, TTL, PITR, optional CMK) stores single-use PKCE state (`pkce#<state>`) and OAuth session tokens (`sid#<session_id>`).
   - `ChatSessions` (`owner_sub` PK, `thread_id` SK, `owner_sub-updated_at-index` GSI) stores chat transcripts and tool/card traces per verified `sub`, so ECS rolling deployments, scaling, or task restarts preserve login and chat history.
4. **Agents Locked to ECS BFF (`control-library/resource-policies/runtime/vpce-only.json`, `stacks/runtime_stack.py`):**
   - `NetworkingStack` publishes `/{project}/{environment}/networking/agentcore-vpce-id`.
   - When `frontend.restrict_runtime_to_bff_vpc: true`, `RuntimeStack` attaches an `AWS::BedrockAgentCore::ResourcePolicy` restricting `InvokeAgentRuntime` to `aws:SourceVpce` and removes `WebClient` from `allowedClients` so browsers cannot invoke agents directly.

---

## 2. `platform.yaml` Configuration

Enable `security.networking: true` and add the `frontend:` block in `platform.yaml` (alongside your existing `project`, `environment`, `region`, `identity`, `agents`, `security`, `observability`, and `use_cases` settings):

```yaml
security:
  networking: true
  # ... keep your existing production / Part 2 settings ...

agents:
  pattern: god-agent

frontend:
  enabled: true
  exposure: private                  # "private" (Internal ALB) or "public" (Internet-facing ALB)
  domain_name: hr.yourcorp.com       # Recommended with ACM cert for HTTPS OAuth callbacks
  certificate_arn: arn:aws:acm:<region>:<account-id>:certificate/<cert-id>
  allowed_cidrs:
    - <your-corp-vpn-or-office-cidr>/24
  waf_rate_limit: 2000               # Requests per IP per 5-minute window
  min_capacity: 2                    # Baseline tasks across AZs
  max_capacity: 10                   # Burst scale ceiling
  cpu: 512                           # 256 | 512 | 1024 | 2048 | 4096
  memory_mib: 1024                   # Must be valid for the chosen CPU
  session_ttl_hours: 12              # DynamoDB BFF session TTL
  restrict_runtime_to_bff_vpc: true  # Lock AgentCore Runtime to VPCE + BFF only
```

### Switching Between Private and Public

To publish an internal deployment to the internet (or pull a public deployment back to private):

1. Change `frontend.exposure` from `private` to `public` (or `public` to `private`) and update `frontend.allowed_cidrs` if needed.
2. Re-run `./scripts/deploy.sh build` (or deploy `${PREFIX}-frontend`).
3. Update your DNS `CNAME` / Alias record for `frontend.domain_name` to point at the replaced ALB DNS name in the `FrontendUrl` stack output.

---

## 3. Manual CLI Deployment Commands

Run from an AWS-authenticated terminal in the repository root:

```bash
export AWS_PROFILE=<your-aws-profile>
export AWS_REGION=<your-region>      # e.g. us-east-1

# 1. Validate manifest and print stack plan (no AWS changes)
./scripts/deploy.sh design

# 2. Run preflight checks (credentials, Bedrock model, secrets, tools)
./scripts/deploy.sh doctor

# 3. Deploy all stacks (CodeBuild builds both god-agent and hr-web-bff ARM64 images)
./scripts/deploy.sh build

# 4. Point your DNS record for frontend.domain_name -> ALB DNS name (from FrontendUrl output)
aws cloudformation describe-stacks \
  --stack-name "${PROJECT_NAME}-${ENVIRONMENT}-frontend" \
  --region "$AWS_REGION" \
  --query "Stacks[0].Outputs" \
  --output table

# 5. Verify the platform footprint
# Note: when restrict_runtime_to_bff_vpc=true, direct runtime invokes from outside
# the VPC are intentionally denied by the AgentCore Runtime resource policy.
./scripts/deploy.sh verify
```

---

## 4. Agent Prompt (For an AWS-Authenticated Terminal)

```text
Verify AWS credentials are active (`aws sts get-caller-identity`) and inspect `docs/FRONTEND_ECS_BFF_DEPLOYMENT.md` in the repository.

Check my existing deployed stacks and `platform.yaml` (or create `platform.yaml` from my target account/region, Entra ID settings, `agents.pattern: god-agent`, `security.networking: true`, and `use_cases: hr-data, hr-identity, hr-tools`), and add the `frontend:` block:
- `enabled: true`
- `exposure: private` (or `public` if I confirm internet-facing)
- `domain_name` and `certificate_arn` (ask me for the ACM certificate ARN, DNS domain, and `allowed_cidrs` if missing)
- `min_capacity: 2`, `max_capacity: 10`, `restrict_runtime_to_bff_vpc: true`

Run `./scripts/deploy.sh design` and `./scripts/deploy.sh doctor` first and show me the plan. Once I confirm, run `./scripts/deploy.sh build`, verify all CloudFormation stacks (including `*-frontend`) and WAF/ALB/ECS/DynamoDB/AgentCore ResourcePolicy outputs, give me the ALB DNS name for my CNAME record, and verify `/healthz`, `/config.json`, Entra/Cognito login, SSE streaming through the ECS BFF, and session persistence across an ECS task restart.
```

---

## 5. Post-Deploy Verification Checklist

- **Health & Config:** `GET https://<domain>/healthz` returns `{"status":"ok"}`; `GET https://<domain>/config.json` returns `{"auth_mode":"bff","a2ui_protocol_version":"1.0","exposure":"..."}` with `Cache-Control: no-store`.
- **Server-Side Auth & Cookies:** Signing in via `/auth/login` → Cognito/Entra → `/auth/callback` sets only the `hr_bff_sid` `HttpOnly` cookie; browser JS holds zero OAuth access/refresh tokens.
- **Direct Agent Access Blocked:** Calling `https://bedrock-agentcore.<region>.amazonaws.com/runtimes/<arn>/invocations` directly from outside the VPC returns `403` / denied by the `AWS::BedrockAgentCore::ResourcePolicy`.
- **Restart & Burst Resilience:** After sending a chat message, run `aws ecs update-service --cluster <cluster> --service <service> --force-new-deployment`, reload the browser tab, and confirm `/api/auth/me` and `/api/sessions` restore the active session and full conversation transcript from DynamoDB without re-authenticating.
