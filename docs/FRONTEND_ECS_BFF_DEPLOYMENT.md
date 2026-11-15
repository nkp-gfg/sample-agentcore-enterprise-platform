# `auth-alb-ecs` Deployment Guide & Runbook

Single-file deployment reference for the **WAF + switchable public/private ALB + auto-scaling ECS Fargate BFF + DynamoDB sessions + VPCE-locked AgentCore Runtime** stack on branch `auth-alb-ecs`.

- **Repository:** `nkp-gfg/sample-agentcore-enterprise-platform`
- **Branch:** `auth-alb-ecs`
- **Pull request:** [PR #15](https://github.com/nkp-gfg/sample-agentcore-enterprise-platform/pull/15) (`auth-alb-ecs` → `part2-without-opa-godbot-v3`), merged as `2afb108c9226ac943d5af03203465004d539eddd`

---

## 1. Architecture Summary

1. **AWS WAFv2 (`REGIONAL` WebACL) + public/private ALB (`stacks/frontend_stack.py`):**
    - Attached to the ALB in both `exposure: private` (internal ALB in private subnets) and `exposure: public` (internet-facing ALB in public subnets).
    - Enforces per-IP rate limiting (`waf_rate_limit`), `AWSManagedRulesAmazonIpReputationList`, `AWSManagedRulesKnownBadInputsRuleSet`, `AWSManagedRulesCommonRuleSet`, and optional `BlockOutsideAllowedCidrs` (`IPSet` + ALB security group). `SizeRestrictions_BODY` in the common rule set is overridden to count so AG-UI chat bodies over 8 KB are not blocked.
    - `idle_timeout=300s` for long-lived AG-UI SSE streaming; `load_balancer_name` is omitted so flipping `exposure` replaces the ALB scheme cleanly.
2. **Auto-scaling ARM64 ECS Fargate BFF (`hr-web/Dockerfile`, `hr-web/bff/app.py`):**
    - Built remotely via CodeBuild (`linux/arm64`) → ECR (no local Docker required).
    - `min_healthy_percent=100`, `max_healthy_percent=200`, scaling between `frontend.min_capacity` and `frontend.max_capacity` on CPU (60%), memory (70%), and ALB request count (300/target). Scale-out cooldown is 30s; scale-in cooldown is 300s.
    - Uses confidential `BffClient` (or the direct Entra app registration) so OAuth tokens remain server-side; the browser receives only an `HttpOnly; SameSite=Lax` cookie (`hr_bff_sid`) plus an `X-BFF-CSRF` header.
3. **DynamoDB sessions and chat persistence (`hr-web/bff/session_store.py`):**
    - `BffSessions` (`{prefix}-bff-sessions`: `PAY_PER_REQUEST`, TTL attribute `ttl`, PITR, customer-managed key when the security stack provides one) stores single-use PKCE state (`pkce#<state>`) and OAuth session tokens (`sid#<session_id>`).
    - `ChatSessions` (`{prefix}-chat-sessions`: `owner_sub` partition key, `thread_id` sort key, `owner_sub-updated_at-index` GSI) stores chat transcripts and tool/card traces per verified `sub`, so ECS rolling deployments, scaling, or task restarts preserve login and chat history.
4. **Agents locked to the ECS BFF (`control-library/resource-policies/runtime/vpce-only.json`, `stacks/runtime_stack.py`):**
    - `NetworkingStack` publishes `/{project}/{environment}/networking/agentcore-vpce-id`.
    - When `frontend.restrict_runtime_to_bff_vpc: true`, `RuntimeStack` attaches an `AWS::BedrockAgentCore::ResourcePolicy` restricting invoke actions to `aws:SourceVpce`. In brokered mode the orchestrator JWT allow-list is the confidential BFF client plus the M2M client, and the public Cognito `WebClient` is not added, so browsers cannot invoke agents directly.

---

## 2. `platform.yaml` Configuration

Enable `security.networking: true` and add the `frontend:` block in `platform.yaml` (alongside your existing `project`, `environment`, `region`, `identity`, `agents`, `security`, `observability`, and `use_cases` settings). `frontend.enabled` is rejected when `deployment.strategy` is `federated`, because the BFF, auth, and runtime must be in the same account.

```yaml
security:
  networking: true
  # ... keep your existing production / Part 2 settings ...

agents:
  pattern: god-agent

frontend:
  enabled: true
  exposure: private                  # "private" (internal ALB) or "public" (internet-facing ALB)
  domain_name: hr.yourcorp.com       # Recommended with an ACM cert for HTTPS OAuth callbacks
  certificate_arn: arn:aws:acm:<region>:<account-id>:certificate/<cert-id>
  allowed_cidrs:
    - <your-corp-vpn-or-office-cidr>/24
  waf_rate_limit: 2000               # Requests per IP per 5-minute window
  min_capacity: 2                    # Baseline tasks across AZs
  max_capacity: 10                   # Burst scale ceiling
  cpu: 512                           # 256 | 512 | 1024 | 2048 | 4096
  memory_mib: 1024                   # Must be a valid Fargate pair for the chosen CPU
  session_ttl_hours: 12              # DynamoDB BFF session TTL
  restrict_runtime_to_bff_vpc: true  # Lock AgentCore Runtime to the VPCE + BFF only
```

`domain_name` requires `certificate_arn`. Without a certificate the ALB listens on HTTP port 80. With a certificate it listens on HTTPS port 443 (`TLS13_RES`) and redirects port 80. Empty `allowed_cidrs` allows the VPC CIDR when `exposure` is `private`, and `0.0.0.0/0` when `exposure` is `public`. The `BlockOutsideAllowedCidrs` WAF rule is created only when `allowed_cidrs` is set.

### Switching between private and public

To publish an internal deployment to the internet (or pull a public deployment back to private):

1. Change `frontend.exposure` from `private` to `public` (or `public` to `private`) and update `frontend.allowed_cidrs` if needed.
2. Re-run `./scripts/deploy.sh build`, or deploy only the frontend stack with `./scripts/deploy.sh deploy --stack "${PREFIX}-frontend"`. `PREFIX` is `{project}-{environment}`.
3. Update the DNS CNAME or alias for `frontend.domain_name` to the replaced ALB DNS name in the `FrontendUrl` stack output.

---

## 3. Manual CLI Deployment Commands

Run from an AWS-authenticated terminal in the repository root:

```bash
git fetch origin auth-alb-ecs
git checkout auth-alb-ecs
git pull origin auth-alb-ecs

export AWS_PROFILE=<your-aws-profile>
export AWS_REGION=<your-region>      # e.g. us-east-1

# 1. Validate the manifest and print the stack plan (no AWS changes)
./scripts/deploy.sh design

# 2. Run preflight checks (credentials, Bedrock model, secrets, tools)
./scripts/deploy.sh doctor

# 3. Deploy all stacks (CodeBuild builds both the god-agent and hr-web-bff ARM64 images)
./scripts/deploy.sh build

# 4. Point DNS for frontend.domain_name at the ALB DNS name (FrontendUrl output)
aws cloudformation describe-stacks \
  --stack-name "${PROJECT_NAME}-${ENVIRONMENT}-frontend" \
  --region "$AWS_REGION" \
  --query "Stacks[0].Outputs" \
  --output table

# 5. Verify the platform footprint
# When restrict_runtime_to_bff_vpc=true, direct runtime invokes from outside
# the VPC are denied by the AgentCore Runtime resource policy.
./scripts/deploy.sh verify
```

`./scripts/deploy.sh build` is the Design → Build → Verify name for `deploy`.

---

## 4. Ready-to-Paste Prompt

```text
Check out branch `auth-alb-ecs` and pull the latest from `origin/auth-alb-ecs`. Verify AWS credentials are active (`aws sts get-caller-identity`).

Check the existing deployed stacks and `platform.yaml` (or create `platform.yaml` for the target account and region, Entra ID settings, `agents.pattern: god-agent`, `security.networking: true`, and `use_cases: hr-data, hr-identity, hr-tools`), and add the `frontend:` block:
- `enabled: true`
- `exposure: private` (or `public` if internet-facing is confirmed)
- `domain_name` and `certificate_arn` (ask for the ACM certificate ARN, DNS domain, and `allowed_cidrs` if they are missing)
- `min_capacity: 2`, `max_capacity: 10`, `restrict_runtime_to_bff_vpc: true`

Run `./scripts/deploy.sh design` and `./scripts/deploy.sh doctor` first and show the plan. After confirmation, run `./scripts/deploy.sh build`, verify the CloudFormation stacks (including `*-frontend`) and the WAF, ALB, ECS, DynamoDB, and AgentCore ResourcePolicy outputs, return the ALB DNS name for the CNAME record, and verify `/healthz`, `/config.json`, Entra or Cognito login, SSE streaming through the ECS BFF, and session persistence across an ECS task restart.
```

---

## 5. Post-Deploy Verification Checklist

- **Health and config:** `GET https://<domain>/healthz` returns `{"status":"ok"}`. `GET https://<domain>/config.json` returns `{"auth_mode":"bff","a2ui_protocol_version":"1.0","exposure":"..."}` with `Cache-Control: no-store`.
- **Server-side auth and cookies:** Signing in via `/auth/login` → Cognito or Entra → `/auth/callback` sets only the `hr_bff_sid` `HttpOnly` cookie. Browser JavaScript holds no OAuth access or refresh tokens.
- **Direct agent access blocked:** Calling `https://bedrock-agentcore.<region>.amazonaws.com/runtimes/<arn>/invocations` from outside the VPC is denied by the `AWS::BedrockAgentCore::ResourcePolicy`.
- **Restart and burst resilience:** After sending a chat message, run `aws ecs update-service --cluster <cluster> --service <service> --force-new-deployment`, reload the browser tab, and confirm `/api/auth/me` and `/api/sessions` restore the active session and the conversation transcript from DynamoDB without signing in again.

Cluster and service names are the `EcsClusterName` and `EcsServiceName` outputs (`{prefix}-frontend` is the cluster name). Session and chat table names are `BffSessionTableName` and `ChatSessionTableName`.
