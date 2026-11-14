# Production principles

The HR plan checked against six production rules for agents. Each row says what the plan already does, what the platform already ships, and the change that closes the gap. The changes reuse platform pieces. None of them adds a new platform module.

Reviewed on 2026-11-13 against branch `n-fe-sandbox-deployment` at `5a2123e`. The fixes are written into the pages named in the last column. If this page and one of those pages disagree, the page wins and this page is out of date.

| # | Principle | Verdict | One-line reason |
|---|---|---|---|
| 1 | A separate identity for each agent, plus the human it acts for | Partly | The human is carried end to end. The ten agents share one runtime workload identity, and nothing tells the gateway which leaf made a call |
| 2 | Least-privilege, scoped, short-lived tool access | Partly | Gateway, Cedar `ENFORCE`, deterministic authorization policy, and the backend check are all there. The Cedar permit is one allow-all for six tools, read and write are not split, the database has one login, and the token lifetime is not set |
| 3 | Guardrails for prompt injection and data leaks | Partly | Input and tool traffic are guarded. The guardrail prompt-attack filter does not read tool results, and the free-text `reason` reaches the manager's thread |
| 4 | Human approval for irreversible actions | Partly | Leave has an employee card and a manager card. Where the manager's decision gets written was not said, and the plan implied the runtime writes Postgres directly, outside the gateway |
| 5 | Full tracing and audit logs into the SIEM | Partly | Spans, vended logs, CloudTrail alerts, and `decision_log` exist. No agent id, no SIEM export, and `decision_log` lives only in Postgres |
| 6 | Evaluations, red-teaming, versioning, kill switch | Gap | One "ignore your instructions" case. No recursion or call limits, no evaluator, no named endpoint for rollback, and turning HR off means a redeploy |

## 1. Identity per agent and per human

| | |
|---|---|
| Plan today | The caller is the token, never the prompt: [review.md](review.md) locked decisions, H3 claims in [modules.md](../docs/hr/modules.md), `caller_employee_id` absent from every schema in [tools.md](../docs/hr/tools.md). The runtime copies the verified `sub` into `clientMetadata.verified_user_id`. |
| Platform today | The runtime JWT authorizer and `extract_user_id_from_context` in `agent-code/shared/auth.py`. AgentCore Runtime creates one workload identity per runtime and mints a workload access token from the user's JWT ([get-workload-access-token](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/get-workload-access-token.html)). The gateway M2M credential provider in `stacks/identity_stack.py`. SCP item 8 in [SECURITY_CONTROLS.md](../docs/SECURITY_CONTROLS.md) denies the unverified-userId token path. |
| Gap | The god agent, three department agents, and six leaves run in one runtime and share its workload identity. The gateway and the Lambdas cannot tell `leave-submit` from `compensation`. The plan says the Lambda "overwrites the caller from the H3 claim", but a gateway Lambda target does not receive the caller's JWT, and the platform interceptor runs with `pass_request_headers=False` (`stacks/gateway_stack.py`). |
| Change | Each leaf asks for its own gateway token and sets `clientMetadata.calling_agent` to its fixed leaf name, from code. The pre-token Lambda copies it into an `agent_id` claim. Cedar binds each tool to its leaf with `principal.getTag("agent_id")`. A request interceptor reads the gateway-validated token and writes `caller_employee_id`, `agent_id`, and `session_id` into the Lambda event, so the Lambda never parses a bearer token itself. The runtime workload identity stays the agent identity of record in v1. One runtime per department is the later version (work package 7). |
| Pages | [modules.md](../docs/hr/modules.md) H3 claims, [tools.md](../docs/hr/tools.md) identity on the call, [god-agent.md](god-agent.md) agent identity |

## 2. Least privilege, scoped, short-lived

| | |
|---|---|
| Plan today | Tools only through AgentCore Gateway. Cedar in `ENFORCE` with a permit per tool. Authorization policy (`shared/authz.py`) evaluated before any amount is read. The Lambda reads the current row, not the model's argument. No `approve_leave`, `list_all_employees`, or `execute_sql`. The gateway role invokes the three HR functions only. Each leaf has one tool. |
| Platform today | Default-deny Cedar from `control-library/cedar/gateway-default/10-permit-read-tools.cedar`, which says not to put write tools in the read permit. Path-scoped SSM in `infra_utils/agentcore_role.py`. The credential-provider reference policy in `control-library/iam/identity-credential-provider-scoped.json`. |
| Gap | [tools.md](../docs/hr/tools.md) has one permit that lets any signed-in caller invoke all six actions, so `submit_leave_request` shares the read permit. The H4 Lambdas and the checkpointer would use the cluster master secret. The Token Vault cannot pass `aws_client_metadata` ([review.md](review.md)), so the runtime holds the M2M client secret, and its token lifetime is not set. |
| Change | Two permits: a read permit for the five read tools and a write permit for `submit_leave_request`, each limited by `agent_id`. A third permit, for `record_leave_decision`, accepts only the review node. Three database roles: `hr_reader` (SELECT on the HR tables), `hr_writer` (INSERT on `leave_requests`, UPDATE of `status`, `decided_by`, `decided_at` only), and `hr_audit` (INSERT on `decision_log` only, no UPDATE or DELETE). The checkpointer gets its own role on `agent_state` and nothing in `hr`. Lambdas use RDS IAM authentication tokens, valid for 15 minutes, instead of a stored password. The HR M2M app client gets a 15-minute access token, and its secret is read from Secrets Manager by exact ARN and rotated. |
| Pages | [tools.md](../docs/hr/tools.md) Cedar permits, [modules.md](../docs/hr/modules.md) database roles and token lifetime, [policy.md](../docs/hr/policy.md) |

## 3. Guardrails and untrusted content

| | |
|---|---|
| Plan today | The model never supplies the caller. Deny text does not reveal whether a person exists. Name search runs only inside the allowed ids. The leaf may refuse only from `authorized: false`. [tools.md](../docs/hr/tools.md) relies on the gateway guardrail to anonymise names. Deep Agents filesystem writes are denied and there is no `execute` tool ([god-agent.md](god-agent.md)). |
| Platform today | `require_guardrails: true` and `egress_filter: true` in the Part 1 `platform.yaml`. IAM denies inference without `bedrock:GuardrailIdentifier` (item 6b). `tools/egress_interceptor/handler.py` runs `ApplyGuardrail` on `tools/call` arguments (INPUT) and results (OUTPUT). `agent-code/agui-langgraph-agent/agent.py` passes `GUARDRAIL_ID` to `ChatBedrock`. |
| Gap | The god-agent page does not say that every one of the ten `ChatBedrock` instances carries the guardrail. Bedrock's prompt-attack filter does not evaluate `toolResult` content ([guardrails-prompt-attack](https://docs.aws.amazon.com/bedrock/latest/userguide/guardrails-prompt-attack.html)). Leave `reason` is employee-written text that the manager review shows, which makes it an indirect injection path into the manager's thread. The guardrail masks. It does not block salary numbers. |
| Change | One model factory builds every agent's model with the guardrail, and a test fails if one does not. `reason` never enters a model message. The review card renders it as plain text from the interrupt payload. Tool results the model reads are structured fields only, and the leaf prompt tells it to treat them as data. The `task` description a parent writes to a child is the user's question plus resolved ids, and nothing from a tool result. Red-team cases cover indirect injection through `reason` and `full_name`. |
| Pages | [god-agent.md](god-agent.md) guardrail and untrusted data, [human-review.md](human-review.md), [tools.md](../docs/hr/tools.md) guardrail, [acceptance.md](../docs/hr/acceptance.md) red team |

## 4. Human approval for irreversible actions

| | |
|---|---|
| Plan today | `submit_leave_request` is in `interrupt_on` with `approve`, `edit`, `reject`, and no `respond`. The manager decision is a second interrupt. A chat line that says "approve" is not a decision. The runtime checks who resumes. Both pauses survive a restart in Postgres ([human-review.md](human-review.md)). Read tools have no card. |
| Platform today | CloudTrail alerting on AgentCore config changes (`traceability: true`, item 7). Cedar and IAM changes happen only through `deploy.sh`. |
| Gap | After the manager approves, "one update sets `status`", but nothing says who runs that update. Run from the runtime, it bypasses the gateway, Cedar, the authorization policy, and `decision_log`, and it needs write credentials on `hr` inside the agent container. |
| Change | A gateway tool, `hr-ops___record_leave_decision`. Runtime code calls it from the review node after the token check, with the manager's own gateway token. No leaf is given it, and its Cedar permit accepts only `agent_id` `review-node`, which no leaf sets, so a model cannot call it. The authorization policy allows it only when the caller is the requester's current `manager_id`, the row is `pending`, and the caller is not the requester. The runtime holds no `hr` credentials. Production and config changes stay with the platform's deploy, CloudTrail, and change process. They are not an agent action. |
| Pages | [human-review.md](human-review.md), [tools.md](../docs/hr/tools.md), [policy.md](../docs/hr/policy.md) |

## 5. Tracing and audit into the SIEM

| | |
|---|---|
| Plan today | `decision_log` has a row per evaluation, with no amounts. The Lambda log line holds action, caller, target, and reason. Amounts and leave reasons are never logged on a deny. |
| Platform today | ADOT (`aws-opentelemetry-distro`) in every image. Transaction Search and the `aws/spans` log group ([TRACING.md](../docs/TRACING.md)). Vended `APPLICATION_LOGS` delivery per runtime, gateway, and memory (`stacks/observability_stack.py`). Retention of 30, 90, 180, or 365 days. Alarms and the dashboard. CloudTrail security alerts. |
| Gap | There is no `agent_id` or session on an audit row. Cedar decisions and tool-policy decisions are in different places. Nothing leaves CloudWatch for a SIEM. `decision_log` is only in Postgres, so a SIEM cannot see it. Full prompts and outputs in spans can contain an allowed salary, which conflicts with "amounts are not logged". |
| Change | `decision_log` gains `agent_id`, `session_id`, `trace_id`, `decided_by_layer` (`policy` or `tool`), and `policy_version`. Cedar denies never reach the Lambda, so they come from Cedar's decision log (`docs/modules/gateway.md`: Cedar evaluates and logs in both modes), and the SIEM joins the two on `session_id` and `trace_id`. The Lambda writes the same row as one JSON log line. The runtime sets OTel baggage `session.id`, `enduser.id` (the `employee_id`), and `gen_ai.agent.name` on every node ([observability-configure](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/observability-configure.html)). A CloudWatch Logs subscription filter on the HR Lambda groups, the runtime and gateway vended groups, and CloudTrail sends them through Data Firehose to the SIEM ([Firehose to Splunk](https://aws.amazon.com/blogs/big-data/deliver-decompressed-amazon-cloudwatch-logs-to-amazon-s3-and-splunk-using-amazon-data-firehose/)). Prompt and output bodies stay in `aws/spans` under the platform KMS key with read access limited. The SIEM receives metadata, decisions, and ids. HR log groups keep 365 days. |
| Pages | [schema.md](../docs/hr/schema.md) decision_log, [modules.md](../docs/hr/modules.md) audit export, [phases.md](phases.md) H4 exit |

## 6. Evaluations, red team, versions, limits, kill switch

| | |
|---|---|
| Plan today | The H2 to H6 acceptance tables, including one "ignore your instructions" row. A routing check that stops on a wrong subagent. Rollback by redeploying the previous pattern. [phases.md](phases.md) points to a nesting limit in god-agent.md that the page did not contain. |
| Platform today | Runtime, gateway, and Bedrock throttle and error alarms ([observability.md](../docs/modules/observability.md)). AgentCore Runtime creates an immutable version on each update. `DEFAULT` follows the latest, and a named endpoint only moves when told to ([runtime versioning](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/agent-runtime-versioning.html)). [KNOWN_LIMITATIONS.md](../docs/KNOWN_LIMITATIONS.md) item 8 states that AI quality evaluation is not included, and [PRODUCTION_READINESS_PLAN.md](../docs/PRODUCTION_READINESS_PLAN.md) gate G3 asks for it. |
| Gap | LangGraph's default recursion limit is 10,007 super-steps ([graph-api](https://docs.langchain.com/oss/python/langgraph/graph-api#recursion-limit)), so a looping router can run up cost before anything stops it. There are no model or tool call limits, no evaluation set, no online evaluator, no red-team suite, and no cost alarm. HR is turned off by redeploying, which takes minutes. |
| Change | Limits: `recursion_limit` 40 on the god agent run and 25 on each compiled department graph. `ModelCallLimitMiddleware(run_limit=4)` and `ToolCallLimitMiddleware(run_limit=2)` on each leaf ([built-in middleware](https://docs.langchain.com/oss/python/langchain/middleware/built-in)). A per-employee turn rate limit in the runtime. An AWS Budgets alarm on Bedrock for the account. Kill switch: SSM `use-cases/hr-tools/enabled`, read by every HR Lambda with a 30-second cache. Anything other than `true` returns `SERVICE_DISABLED`. Emergency path: remove the HR Cedar permits, which makes the gateway deny every HR call. Versions: prod traffic goes through a named runtime endpoint. Rollback is `UpdateAgentRuntimeEndpoint` to the previous version. The policy module (`shared/authz.py`) carries `POLICY_VERSION`. Evaluations: a versioned H5 question set run on demand before promotion, plus AgentCore Evaluations online on 10% of sessions with `Builtin.Correctness`, `Builtin.Helpfulness`, and a tool-selection evaluator, with alarms on the `Bedrock-AgentCore/Evaluations` metrics ([evaluations](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/evaluations.html)). Red team: the R rows in [acceptance.md](../docs/hr/acceptance.md). |
| Pages | [god-agent.md](god-agent.md) limits, [phases.md](phases.md) release and rollback, [policy.md](../docs/hr/policy.md) `SERVICE_DISABLED`, [acceptance.md](../docs/hr/acceptance.md) |

## Open decisions (pending owner sign-off)

None of these is decided. The pages use the default shown until the owner answers.

| Decision | Status | Default written into the pages | What changes if the answer differs |
|---|---|---|---|
| Is `agent_id` from `clientMetadata`, asserted by runtime code, strong enough, or does each leaf need its own Cognito app client so Cedar matches `client_id`? | Open | `clientMetadata` in v1. Separate app clients when departments split into runtimes | Six app clients and six credential providers in `hr-identity` |
| Do full prompt and output bodies go to the SIEM? | Open | No. Bodies stay in `aws/spans` under KMS. The SIEM gets ids, decisions, and reason codes | The SIEM becomes a salary store and needs HR data classification |
| Which SIEM, and is Firehose the transport? | Open | Firehose with a destination named per account | A Security Lake or vendor agent replaces the subscription filter |
| True on-behalf-of token exchange (Entra OBO through AgentCore Identity) instead of a pre-token claim on an M2M token | Open | Pre-token claim in v1. Cognito does not perform token exchange | `hr-identity` changes to an Entra OBO credential provider |
| Platform change: turn on `pass_request_headers` in `stacks/gateway_stack.py` and `tools/egress_interceptor/handler.py` for the identity step | Open | Planned, not built | Without it the HR Lambda cannot see the caller token and the identity step moves elsewhere |
| Platform change: a named `live` runtime endpoint in module 6 (`login_chat.py` and `invoke.py` call `qualifier=DEFAULT` today) | Open | Planned, not built | Rollback stays a redeploy of the previous image |
| Split `hr-ops` read and write tools into a fourth Lambda | Open | One `hr-ops` Lambda, writer connection opened only inside the two write tools | A fourth target and function, stricter IAM split |

## Sources

Checked on 2026-11-13.

- AgentCore workload access tokens: https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/get-workload-access-token.html
- Cedar tags from JWT claims, `client_id` binding: https://aws.amazon.com/blogs/machine-learning/govern-ai-agent-access-with-okta-cross-app-access-and-amazon-bedrock-agentcore-part-2/
- Workload identity per runtime, on-behalf-of exchange: https://aws.amazon.com/blogs/machine-learning/govern-ai-agent-access-with-okta-cross-app-access-and-amazon-bedrock-agentcore-part-1/
- Gateway header propagation and interceptors: https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/gateway-headers.html
- Guardrail prompt-attack filter and tool results: https://docs.aws.amazon.com/bedrock/latest/userguide/guardrails-prompt-attack.html
- AgentCore Observability, session baggage: https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/observability-configure.html
- AgentCore Evaluations: https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/evaluations.html
- Runtime versions and endpoints: https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/agent-runtime-versioning.html
- LangGraph recursion limit: https://docs.langchain.com/oss/python/langgraph/graph-api#recursion-limit
- LangChain call-limit middleware: https://docs.langchain.com/oss/python/langchain/middleware/built-in
- CloudWatch Logs to a SIEM through Firehose: https://aws.amazon.com/blogs/big-data/deliver-decompressed-amazon-cloudwatch-logs-to-amazon-s3-and-splunk-using-amazon-data-firehose/
