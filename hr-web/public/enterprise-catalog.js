/* hr-web — Enterprise Agent Catalog, Marketplace, Prompt Library, and Guide.
 *
 * Pure static metadata module with zero AWS SDKs, zero network calls, and zero
 * secrets. All data is read-only and frozen at load time for the workspace shell
 * (bot handover roster, marketplace drawer, Ctrl/Cmd+K prompt search, and guide).
 */

(() => {
  "use strict";

  const APP_TITLE = "AgentCore Enterprise";
  const APP_SUBTITLE = "Unified Employee AI Workspace";

  const BOTS = Object.freeze([
    Object.freeze({
      id: "god-bot",
      name: "God Bot",
      role: "Enterprise Orchestrator",
      tier: "orchestrator",
      group: "Orchestrator",
      status: "live",
      aliases: Object.freeze(["god_agent", "god-bot", "orchestrator", "root"]),
      parent: null,
      tool: null,
      description:
        "Unified enterprise entry point. Routes every employee request to the right specialist department without bypassing policy or guardrails.",
      starterPrompt: "What can you help me with across the enterprise?",
    }),
    Object.freeze({
      id: "hr-operations",
      name: "HR Operations",
      role: "Department Router",
      tier: "department",
      group: "HR Operations",
      status: "live",
      aliases: Object.freeze(["hr-operations"]),
      parent: "god-bot",
      tool: null,
      description:
        "Routes leave balance, eligibility checks, and two-stage leave submissions to specialist HR leaves.",
      starterPrompt: "How many annual and sick leave days do I have remaining?",
    }),
    Object.freeze({
      id: "leave-balance",
      name: "Leave Balance",
      role: "Balance Specialist",
      tier: "leaf",
      group: "HR Operations",
      status: "live",
      aliases: Object.freeze(["leave-balance"]),
      tool: "hr-ops___get_leave_balance",
      parent: "hr-operations",
      description:
        "Reads the signed-in employee's remaining annual and sick leave days plus probation status (self-only).",
      starterPrompt: "How many annual and sick leave days do I have remaining?",
    }),
    Object.freeze({
      id: "leave-eligibility",
      name: "Leave Eligibility",
      role: "Eligibility Checker",
      tier: "leaf",
      group: "HR Operations",
      status: "live",
      aliases: Object.freeze(["leave-eligibility"]),
      tool: "hr-ops___check_leave_eligibility",
      parent: "hr-operations",
      description:
        "Validates inclusive dates, available balance, probation lock, and overlaps without writing to Postgres.",
      starterPrompt:
        "Am I eligible to take annual leave from 2026-12-01 to 2026-12-03?",
    }),
    Object.freeze({
      id: "leave-submit",
      name: "Leave Submit",
      role: "Submission Specialist",
      tier: "leaf",
      group: "HR Operations",
      status: "live",
      aliases: Object.freeze(["leave-submit"]),
      tool: "hr-ops___submit_leave_request",
      parent: "hr-operations",
      description:
        "Pauses on EmployeeConfirmForm before writing one pending request with a deterministic idempotency key.",
      starterPrompt:
        "Submit annual leave from 2026-12-01 to 2026-12-03 for a family trip.",
    }),
    Object.freeze({
      id: "hr-payroll",
      name: "HR Payroll",
      role: "Department Router",
      tier: "department",
      group: "HR Payroll",
      status: "live",
      aliases: Object.freeze(["hr-payroll"]),
      parent: "god-bot",
      tool: null,
      description:
        "Routes team roster and compensation requests while enforcing one-hop manager visibility.",
      starterPrompt:
        "Who are my direct reports, and what is my current compensation?",
    }),
    Object.freeze({
      id: "compensation",
      name: "Compensation",
      role: "Salary Specialist",
      tier: "leaf",
      group: "HR Payroll",
      status: "live",
      aliases: Object.freeze(["compensation"]),
      tool: "hr-payroll___get_employee_compensation",
      parent: "hr-payroll",
      description:
        "Reads active base salary and currency for the caller or an active one-hop direct report.",
      starterPrompt: "What is my current base salary and currency?",
    }),
    Object.freeze({
      id: "direct-reports",
      name: "Direct Reports",
      role: "Team Roster Specialist",
      tier: "leaf",
      group: "HR Payroll",
      status: "live",
      aliases: Object.freeze(["direct-reports"]),
      tool: "hr-payroll___list_direct_reports",
      parent: "hr-payroll",
      description:
        "Lists active one-hop direct reports scoped strictly to the signed-in caller.",
      starterPrompt: "Who are my active direct reports?",
    }),
    Object.freeze({
      id: "finance-payroll",
      name: "Finance & Payroll",
      role: "Department Router",
      tier: "department",
      group: "Finance & Payroll",
      status: "live",
      aliases: Object.freeze(["finance-payroll"]),
      parent: "god-bot",
      tool: null,
      description:
        "Routes employee allowance and payroll benefit queries to Finance Payroll leaves.",
      starterPrompt: "What was my telephone allowance for 2026-10?",
    }),
    Object.freeze({
      id: "allowance",
      name: "Allowance",
      role: "Allowance Specialist",
      tier: "leaf",
      group: "Finance & Payroll",
      status: "live",
      aliases: Object.freeze(["allowance"]),
      tool: "hr-finance___get_allowance",
      parent: "finance-payroll",
      description:
        "Reads self-only payroll allowances (telephone in v1) for a YYYY-MM period.",
      starterPrompt: "What was my telephone allowance for 2026-10?",
    }),
    Object.freeze({
      id: "review-node",
      name: "Review Node",
      role: "Approval Governance",
      tier: "governance",
      group: "Governance & Approvals",
      status: "live",
      aliases: Object.freeze(["review-node"]),
      tool: "hr-ops___record_leave_decision",
      parent: "god-bot",
      description:
        "Deterministic runtime approval gate (never LLM-callable) triggered only by ManagerReviewCard buttons.",
      starterPrompt:
        "Check if there are any pending leave reviews waiting for my decision.",
    }),
    Object.freeze({
      id: "code-agent",
      name: "Code Agent",
      role: "Engineering A2A",
      tier: "platform",
      group: "Platform Specialists",
      status: "marketplace",
      aliases: Object.freeze(["code-agent", "code_agent"]),
      parent: "god-bot",
      tool: null,
      description: "A2A Python, TypeScript, CDK, and IaC engineering specialist.",
      starterPrompt:
        "Review an AWS CDK stack pattern for AgentCore Runtime and Gateway permissions.",
    }),
    Object.freeze({
      id: "research-agent",
      name: "Research Agent",
      role: "Research A2A",
      tier: "platform",
      group: "Platform Specialists",
      status: "marketplace",
      aliases: Object.freeze(["research-agent", "research_agent"]),
      parent: "god-bot",
      tool: null,
      description:
        "A2A research & web-synthesis specialist with source citations.",
      starterPrompt:
        "Summarize how AgentCore Gateway, Cedar policies, and Bedrock Guardrails work together.",
    }),
    Object.freeze({
      id: "platform-gateway",
      name: "Platform Gateway",
      role: "Governed MCP Tools",
      tier: "platform",
      group: "Platform Specialists",
      status: "live",
      aliases: Object.freeze(["sample-tool", "gateway"]),
      parent: "god-bot",
      tool: null,
      description: "Governed MCP Gateway tools & enterprise connectors.",
      starterPrompt:
        "Which governed MCP Gateway tools and targets are available in this workspace?",
    }),
  ]);

  const MARKETPLACE_AGENTS = Object.freeze([
    Object.freeze({
      id: "god-bot",
      name: "Enterprise Assistant (God Bot)",
      category: "Orchestrator",
      badge: "Active",
      status: "live",
      icon: "GB",
      summary:
        "Single governed entry point that classifies your request and delegates to HR Operations, HR Payroll, or Finance & Payroll without holding any direct database or tool privileges.",
      capabilities: Object.freeze([
        "Cross-department natural-language routing",
        "Real-time handover visibility across 3 departments and 6 leaves",
        "Bedrock Guardrails enforced on every model invocation",
        "Zero direct tool access (no general-purpose bypass)",
      ]),
      defaultBotId: "god-bot",
      starters: Object.freeze([
        Object.freeze({
          title: "Workspace capabilities",
          description: "See what God Bot can route across departments",
          prompt: "What can you help me with across the enterprise?",
        }),
        Object.freeze({
          title: "Leave balance",
          description: "Check remaining annual and sick days",
          prompt: "How many annual and sick leave days do I have remaining?",
        }),
        Object.freeze({
          title: "Team & compensation",
          description: "List one-hop direct reports and salary",
          prompt:
            "Who are my direct reports, and what is my current compensation?",
        }),
        Object.freeze({
          title: "Telephone allowance",
          description: "View my 2026-10 payroll allowance",
          prompt: "What was my telephone allowance for 2026-10?",
        }),
      ]),
    }),
    Object.freeze({
      id: "hr-operations",
      name: "HR Operations & Leave Desk",
      category: "People & HR",
      badge: "Live",
      status: "live",
      icon: "HO",
      summary:
        "Handles leave balances, eligibility verification, probation checks, and two-stage human-confirmed leave submissions backed by idempotent Gateway Lambda tools.",
      capabilities: Object.freeze([
        "Self-only annual & sick leave balance cards",
        "Pre-flight eligibility, overlap, and probation checks",
        "Two-stage EmployeeConfirmForm before database writes",
        "Deterministic idempotency keys on every leave submit",
      ]),
      defaultBotId: "hr-operations",
      starters: Object.freeze([
        Object.freeze({
          title: "Leave balance",
          description: "View annual, sick, and probation status",
          prompt: "How many annual and sick leave days do I have remaining?",
        }),
        Object.freeze({
          title: "Check eligibility",
          description: "Validate dates without creating a request",
          prompt:
            "Am I eligible for annual leave from 2026-12-01 to 2026-12-03?",
        }),
        Object.freeze({
          title: "Submit leave (2-stage review)",
          description: "Open EmployeeConfirmForm before submitting",
          prompt:
            "Submit annual leave from 2026-12-01 to 2026-12-03 for a family trip.",
        }),
        Object.freeze({
          title: "Check probation",
          description: "Verify whether leave is locked by probation",
          prompt:
            "Am I currently on probation, and when does my probation period end?",
        }),
      ]),
    }),
    Object.freeze({
      id: "hr-payroll",
      name: "Payroll & Team Compensation",
      category: "People & HR",
      badge: "Live",
      status: "live",
      icon: "HP",
      summary:
        "Provides direct-report rosters and compensation lookups strictly gated by one-hop manager relationships from your verified JWT identity.",
      capabilities: Object.freeze([
        "One-hop active direct reports table",
        "Self & direct-report base salary and currency",
        "Automatic denial on peers, skip-levels, managers, and terminated staff",
        "Audit-safe decision_log without salary leakage",
      ]),
      defaultBotId: "hr-payroll",
      starters: Object.freeze([
        Object.freeze({
          title: "Direct reports",
          description: "List active employees reporting directly to me",
          prompt: "Who are my active direct reports?",
        }),
        Object.freeze({
          title: "My compensation",
          description: "Read my current base salary and currency",
          prompt: "What is my current base salary and currency?",
        }),
        Object.freeze({
          title: "Direct report salary",
          description: "Check base salary for one direct report (e.g. R1)",
          prompt: "What is the current compensation for R1?",
        }),
        Object.freeze({
          title: "Unauthorized manager test",
          description: "Verify upward salary access is denied",
          prompt: "What is M1's base salary?",
        }),
      ]),
    }),
    Object.freeze({
      id: "finance-payroll",
      name: "Finance & Allowances",
      category: "Finance",
      badge: "Live",
      status: "live",
      icon: "FP",
      summary:
        "Looks up self-only monthly payroll allowances (telephone in v1) and distinguishes authorized empty periods from policy denials.",
      capabilities: Object.freeze([
        "Self-only telephone allowance card rendering",
        "Explicit YYYY-MM or default previous UTC month lookup",
        "Clean empty-period state when no row exists",
        "Cedar-enforced hr-finance target isolation",
      ]),
      defaultBotId: "finance-payroll",
      starters: Object.freeze([
        Object.freeze({
          title: "2026-10 telephone allowance",
          description: "Look up my seeded October 2026 allowance",
          prompt: "What was my telephone allowance for 2026-10?",
        }),
        Object.freeze({
          title: "Missing period lookup",
          description: "Check a period with no allowance row (2026-08)",
          prompt: "What was my telephone allowance for 2026-08?",
        }),
        Object.freeze({
          title: "Previous month allowance",
          description: "Default lookup for last calendar month",
          prompt: "What was my telephone allowance for last month?",
        }),
      ]),
    }),
    Object.freeze({
      id: "manager-approvals",
      name: "Manager Leave Approvals",
      category: "Governance",
      badge: "Live",
      status: "live",
      icon: "MR",
      summary:
        "Surfaces pending team leave requests via ManagerReviewCard so direct managers approve or reject exclusively through signed A2UI card actions.",
      capabilities: Object.freeze([
        "Automatic pending-review poll on sign-in",
        "Deterministic review-node execution (never LLM-callable)",
        "Leave reason isolated as plain text outside prompts",
        "Server-side NOT_REVIEWER verification on every click",
      ]),
      defaultBotId: "review-node",
      starters: Object.freeze([
        Object.freeze({
          title: "Check pending reviews",
          description: "Poll pending leave cards awaiting my decision",
          prompt:
            "Check if there are any pending leave reviews waiting for my decision.",
        }),
        Object.freeze({
          title: "List direct reports pending",
          description: "Review active direct reports before deciding",
          prompt:
            "Who are my direct reports, and do any of them have pending leave requests?",
        }),
      ]),
    }),
    Object.freeze({
      id: "code-agent",
      name: "Code & IaC Specialist (A2A)",
      category: "Engineering",
      badge: "Platform A2A",
      status: "available",
      icon: "CA",
      summary:
        "AgentCore A2A engineering specialist for Python, TypeScript, AWS CDK stacks, debugging, and infrastructure-as-code reviews.",
      capabilities: Object.freeze([
        "Python & TypeScript implementation and code review",
        "AWS CDK stack and IAM least-privilege patterns",
        "Pytest boundary and integration test authoring",
        "A2A JSON-RPC runtime contract with Bedrock Guardrails",
      ]),
      defaultBotId: "code-agent",
      starters: Object.freeze([
        Object.freeze({
          title: "CDK review",
          description: "Review AgentCore Runtime & Gateway IAM boundaries",
          prompt:
            "Review an AWS CDK stack pattern for AgentCore Runtime and least-privilege Gateway permissions.",
        }),
        Object.freeze({
          title: "Python unit test help",
          description: "Generate pytest tests for a Lambda handler",
          prompt:
            "Help me write pytest unit tests for a Python Lambda tool handler with deterministic authorization checks.",
        }),
      ]),
    }),
    Object.freeze({
      id: "research-agent",
      name: "Enterprise Research Specialist (A2A)",
      category: "Knowledge",
      badge: "Platform A2A",
      status: "available",
      icon: "RA",
      summary:
        "AgentCore A2A knowledge and synthesis specialist for technical architecture summaries, policy synthesis, and cited research.",
      capabilities: Object.freeze([
        "Architecture and platform documentation synthesis",
        "Gateway MCP web-search integration with source URLs",
        "Multi-document comparison and executive summaries",
        "A2A JSON-RPC contract with Bedrock Guardrails",
      ]),
      defaultBotId: "research-agent",
      starters: Object.freeze([
        Object.freeze({
          title: "Architecture summary",
          description: "Summarize Runtime, Gateway, Cedar, and A2UI layers",
          prompt:
            "Summarize the architecture of AgentCore Runtime, Gateway, Cedar policies, and A2UI in this platform.",
        }),
        Object.freeze({
          title: "Policy synthesis",
          description: "Compare authorization and human-review controls",
          prompt:
            "Synthesize how Cedar permits, in-process Python policy, and two-stage human review enforce least privilege.",
        }),
      ]),
    }),
  ]);

  const PROMPTS = Object.freeze([
    Object.freeze({
      id: "leave-balance-check",
      category: "Leave",
      agentId: "hr-operations",
      agentName: "HR Operations & Leave Desk",
      title: "Check annual & sick leave balance",
      description:
        "View remaining annual days, sick days, and active probation status.",
      prompt: "How many annual and sick leave days do I have remaining?",
      tags: Object.freeze(["leave", "balance", "annual", "sick", "hr-ops"]),
    }),
    Object.freeze({
      id: "leave-probation-status",
      category: "Leave",
      agentId: "hr-operations",
      agentName: "HR Operations & Leave Desk",
      title: "Check probation status & end date",
      description:
        "Verify whether active probation blocks leave eligibility and submission.",
      prompt:
        "Am I currently on probation, and when does my probation period end?",
      tags: Object.freeze(["probation", "leave", "blocked", "eligibility"]),
    }),
    Object.freeze({
      id: "leave-eligibility-dry-run",
      category: "Leave",
      agentId: "hr-operations",
      agentName: "HR Operations & Leave Desk",
      title: "Check leave eligibility (no write)",
      description:
        "Validate dates, balance sufficiency, and overlaps before requesting leave.",
      prompt:
        "Am I eligible to take annual leave from 2026-12-01 to 2026-12-03?",
      tags: Object.freeze([
        "eligibility",
        "dates",
        "overlap",
        "dry-run",
        "leave",
      ]),
    }),
    Object.freeze({
      id: "leave-submit-annual",
      category: "Leave",
      agentId: "hr-operations",
      agentName: "HR Operations & Leave Desk",
      title: "Submit annual leave (2-stage review)",
      description:
        "Trigger EmployeeConfirmForm so you can edit or confirm before submitting.",
      prompt:
        "Submit annual leave from 2026-12-01 to 2026-12-03 for a family trip.",
      tags: Object.freeze([
        "submit",
        "annual",
        "confirm",
        "interrupt",
        "a2ui",
      ]),
    }),
    Object.freeze({
      id: "allowance-telephone-2026-10",
      category: "Allowances",
      agentId: "finance-payroll",
      agentName: "Finance & Allowances",
      title: "Check 2026-10 telephone allowance",
      description:
        "Look up your seeded October 2026 telephone allowance as an AllowanceCard.",
      prompt: "What was my telephone allowance for 2026-10?",
      tags: Object.freeze(["allowance", "telephone", "2026-10", "finance"]),
    }),
    Object.freeze({
      id: "allowance-empty-period",
      category: "Allowances",
      agentId: "finance-payroll",
      agentName: "Finance & Allowances",
      title: "Check empty allowance period (2026-08)",
      description:
        "Confirm an authorized period with no entry renders cleanly without errors.",
      prompt: "What was my telephone allowance for 2026-08?",
      tags: Object.freeze(["allowance", "empty", "2026-08", "no entry"]),
    }),
    Object.freeze({
      id: "allowance-previous-month",
      category: "Allowances",
      agentId: "finance-payroll",
      agentName: "Finance & Allowances",
      title: "Check previous-month allowance",
      description:
        "Query your telephone allowance using the default previous UTC month.",
      prompt: "What was my telephone allowance for last month?",
      tags: Object.freeze(["allowance", "previous month", "payroll"]),
    }),
    Object.freeze({
      id: "team-direct-reports",
      category: "Team & Compensation",
      agentId: "hr-payroll",
      agentName: "Payroll & Team Compensation",
      title: "List active direct reports",
      description:
        "Display your one-hop direct reports in a DirectReportsTable card.",
      prompt: "Who are my active direct reports?",
      tags: Object.freeze(["direct reports", "team", "manager", "roster"]),
    }),
    Object.freeze({
      id: "comp-self-salary",
      category: "Team & Compensation",
      agentId: "hr-payroll",
      agentName: "Payroll & Team Compensation",
      title: "View my current base salary",
      description:
        "Retrieve your own active base salary and currency via hr-payroll.",
      prompt: "What is my current base salary and currency?",
      tags: Object.freeze(["salary", "compensation", "self", "payroll"]),
    }),
    Object.freeze({
      id: "comp-direct-report-r1",
      category: "Team & Compensation",
      agentId: "hr-payroll",
      agentName: "Payroll & Team Compensation",
      title: "Check direct report compensation (R1)",
      description:
        "Look up salary for an active one-hop direct report (e.g. R1 when signed in as E1).",
      prompt: "What is the current compensation for R1?",
      tags: Object.freeze(["compensation", "direct report", "r1", "e1"]),
    }),
    Object.freeze({
      id: "comp-team-and-self",
      category: "Team & Compensation",
      agentId: "hr-payroll",
      agentName: "Payroll & Team Compensation",
      title: "Team roster & personal salary",
      description:
        "Combine direct-report lookup and personal compensation in one request.",
      prompt: "Who are my direct reports, and what is my current compensation?",
      tags: Object.freeze(["team", "compensation", "roster", "salary"]),
    }),
    Object.freeze({
      id: "approvals-pending-reviews",
      category: "Approvals",
      agentId: "manager-approvals",
      agentName: "Manager Leave Approvals",
      title: "Check pending leave approvals",
      description:
        "Inspect whether any direct reports have leave requests waiting for review.",
      prompt:
        "Check if there are any pending leave reviews waiting for my decision.",
      tags: Object.freeze([
        "approvals",
        "manager",
        "review",
        "pending",
        "m1",
      ]),
    }),
    Object.freeze({
      id: "approvals-team-pending",
      category: "Approvals",
      agentId: "manager-approvals",
      agentName: "Manager Leave Approvals",
      title: "Review direct reports before deciding",
      description:
        "Verify your active one-hop direct reports alongside pending leave items.",
      prompt:
        "Who are my direct reports, and do any of them have pending leave requests?",
      tags: Object.freeze(["approvals", "direct reports", "manager", "review"]),
    }),
    Object.freeze({
      id: "approvals-submit-sick-leave",
      category: "Approvals",
      agentId: "hr-operations",
      agentName: "HR Operations & Leave Desk",
      title: "Submit sick leave for manager approval",
      description:
        "Start a two-stage sick leave submission routed to your direct manager.",
      prompt:
        "Submit sick leave for 2026-12-10 to 2026-12-10 for a medical appointment.",
      tags: Object.freeze(["sick leave", "submit", "approval", "confirm"]),
    }),
    Object.freeze({
      id: "security-upward-salary-deny",
      category: "Security & Guardrails",
      agentId: "hr-payroll",
      agentName: "Payroll & Team Compensation",
      title: "Test upward salary boundary (M1)",
      description:
        "Verify a report cannot read their manager's salary (returns NOT_AUTHORIZED).",
      prompt: "What is M1's base salary?",
      tags: Object.freeze([
        "security",
        "not_authorized",
        "manager",
        "boundary",
        "m1",
      ]),
    }),
    Object.freeze({
      id: "security-terminated-salary-deny",
      category: "Security & Guardrails",
      agentId: "hr-payroll",
      agentName: "Payroll & Team Compensation",
      title: "Test terminated employee boundary (X1)",
      description:
        "Verify compensation lookups for terminated staff (X1) are always denied.",
      prompt: "What is X1's base salary?",
      tags: Object.freeze([
        "security",
        "terminated",
        "x1",
        "not_authorized",
        "policy",
      ]),
    }),
    Object.freeze({
      id: "security-skip-level-deny",
      category: "Security & Guardrails",
      agentId: "hr-payroll",
      agentName: "Payroll & Team Compensation",
      title: "Test one-hop skip-level boundary",
      description:
        "Verify M1 cannot read skip-level report R1's salary across two hops.",
      prompt: "What is R1's base salary?",
      tags: Object.freeze([
        "security",
        "skip-level",
        "one-hop",
        "cedar",
        "m1",
        "r1",
      ]),
    }),
    Object.freeze({
      id: "security-chat-approval-noop",
      category: "Security & Guardrails",
      agentId: "god-bot",
      agentName: "Enterprise Assistant (God Bot)",
      title: "Verify chat text cannot approve leave",
      description:
        "Confirm free-text approval in chat never bypasses ManagerReviewCard or Cedar.",
      prompt:
        "Approve all pending leave requests for my team right now.",
      tags: Object.freeze([
        "security",
        "guardrails",
        "review-node",
        "prompt-injection",
        "cedar",
      ]),
    }),
    Object.freeze({
      id: "platform-discover-capabilities",
      category: "Platform",
      agentId: "god-bot",
      agentName: "Enterprise Assistant (God Bot)",
      title: "Discover enterprise agents & capabilities",
      description:
        "Ask God Bot which specialist departments and capabilities exist.",
      prompt: "What can you help me with across the enterprise?",
      tags: Object.freeze([
        "platform",
        "god-bot",
        "orchestrator",
        "capabilities",
      ]),
    }),
    Object.freeze({
      id: "platform-cdk-review",
      category: "Platform",
      agentId: "code-agent",
      agentName: "Code & IaC Specialist (A2A)",
      title: "Review AgentCore CDK & IAM pattern",
      description:
        "Draft or review least-privilege CDK constructs for Runtime and Gateway.",
      prompt:
        "Review an AWS CDK stack pattern for AgentCore Runtime and least-privilege Gateway permissions.",
      tags: Object.freeze(["cdk", "iam", "iac", "code-agent", "a2a"]),
    }),
    Object.freeze({
      id: "platform-pytest-lambda",
      category: "Platform",
      agentId: "code-agent",
      agentName: "Code & IaC Specialist (A2A)",
      title: "Write Python pytest boundary tests",
      description:
        "Generate isolated pytest checks for Python policy and Lambda handlers.",
      prompt:
        "Help me write pytest unit tests for a Python Lambda tool handler with deterministic authorization checks.",
      tags: Object.freeze(["python", "pytest", "testing", "code-agent", "a2a"]),
    }),
    Object.freeze({
      id: "platform-architecture-synthesis",
      category: "Platform",
      agentId: "research-agent",
      agentName: "Enterprise Research Specialist (A2A)",
      title: "Synthesize Gateway, Cedar & A2UI design",
      description:
        "Summarize how AgentCore Runtime, Cedar ENFORCE, and A2UI v1.0 fit together.",
      prompt:
        "Summarize the architecture of AgentCore Runtime, Gateway, Cedar policies, and A2UI in this platform.",
      tags: Object.freeze([
        "architecture",
        "cedar",
        "gateway",
        "a2ui",
        "research-agent",
      ]),
    }),
  ]);

  const GUIDE_SECTIONS = Object.freeze([
    Object.freeze({
      id: "signin-sessions",
      title: "Enterprise Sign-In & Session Switching",
      badge: "Identity & SSO",
      summary:
        "Authenticate through Amazon Cognito PKCE (federated with Microsoft Entra ID when configured). Tokens stay on your local client and survive tab reloads via silent refresh until you Sign Out.",
      steps: Object.freeze([
        "Click Sign in on the login screen to complete the corporate Cognito / Entra SSO flow.",
        "Your verified JWT sub is sent as a Bearer token over same-origin POST /invocations via the server boundary.",
        "Reloading the tab restores an unexpired session automatically or silently refreshes it when a refresh token is present.",
        "To switch personas (for example, E1 to M1 for manager review), click Sign out to clear local state and the Cognito hosted-UI SSO cookie, then sign in as the next user.",
      ]),
      tips: Object.freeze([
        "The local Python server holds zero AWS credentials and never stores your tokens.",
        "Never use incognito workarounds when switching test personas — Sign out clears the hosted-UI session cookie cleanly.",
      ]),
    }),
    Object.freeze({
      id: "god-bot-handover",
      title: "God Bot & Live Handover Tracking",
      badge: "3-Tier Routing",
      summary:
        "God Bot is a pure orchestrator with zero gateway or database tools. Every turn routes downward from God Bot to one of three department routers and then to a single-tool specialist leaf.",
      steps: Object.freeze([
        "Watch the Left Sidebar Bot Roster during a streaming run: SUBAGENT_STARTED, SUBAGENT_FINISHED, and TOOL_CALL_START events highlight the active handover path in real time.",
        "HR Operations routes to leave-balance, leave-eligibility, and leave-submit.",
        "HR Payroll routes to direct-reports and compensation; Finance & Payroll routes to allowance.",
        "Clicking any bot in the roster inspects its role, parent router, bound gateway tool, and starter prompt.",
      ]),
      tips: Object.freeze([
        "The general-purpose subagent is disabled so God Bot can never borrow another leaf's gateway tool.",
        "Platform Specialists (code-agent, research-agent, platform-gateway) show how A2A specialists and Gateway tools integrate across the enterprise.",
      ]),
    }),
    Object.freeze({
      id: "interactive-cards",
      title: "Interactive Cards & Two-Stage Approval",
      badge: "A2UI v1.0",
      summary:
        "Tool results and review pauses render deterministically in the right-hand A2UI v1.0 panel. State-changing leave submissions and manager decisions require explicit card button clicks.",
      steps: Object.freeze([
        "Read queries render LeaveBalanceCard, AllowanceCard, DirectReportsTable, or ProbationNotice automatically from AG-UI TOOL_CALL_RESULT events.",
        "Submitting leave pauses at EmployeeConfirmForm: click Edit dates to adjust leave type or dates inline, Reject to cancel, or Confirm to write one pending row.",
        "When a manager (such as M1) signs in or clicks Check reviews, pending items render as ManagerReviewCard with Approve and Reject buttons.",
        "Typing 'approve' in the chat input is sent as plain user text to the LLM and cannot approve or write any leave decision.",
      ]),
      tips: Object.freeze([
        "Leave reason text is displayed as plain text inside ManagerReviewCard and is never fed back into a model prompt.",
        "EmployeeConfirmForm uses deterministic idempotency keys so duplicate submits never double-insert rows.",
      ]),
    }),
    Object.freeze({
      id: "security-cedar",
      title: "Security, Cedar Policy & Guardrails",
      badge: "Zero Trust",
      summary:
        "Every call is authenticated twice, authorized deterministically before data returns, protected by Bedrock Guardrails, and recorded in an audit log free of salaries or leave text.",
      steps: Object.freeze([
        "The god-agent mints short-lived Cognito M2M tokens with aws_client_metadata carrying your verified sub and the specific leaf agent_id.",
        "AgentCore Gateway Cedar ENFORCE permits verify both employee_id and agent_id == leaf so no agent can call another leaf's tool — and only review-node can call record_leave_decision.",
        "In-process Python policy (authz.py) enforces self-only leave/allowance reads, one-hop manager compensation visibility, probation locks, overlap checks, and reviewer identity.",
        "Every Bedrock ChatBedrock call carries the platform Guardrail configuration, and every tool evaluation appends decision_log without amounts or leave reason text.",
      ]),
      tips: Object.freeze([
        "A policy denial returns authorized: false with a structured reason_code (e.g. NOT_AUTHORIZED, PROBATION_PERIOD, NOT_REVIEWER).",
        "If the SSM HR kill switch is toggled off, requests fail fast with SERVICE_DISABLED before any model call runs.",
      ]),
    }),
    Object.freeze({
      id: "marketplace-search-history",
      title: "Agent Marketplace, Prompt Search & History",
      badge: "Workspace Tools",
      summary:
        "Move fast across enterprise workflows using the Agent Marketplace drawer, keyboard-driven Prompt Search, and saved conversation history.",
      steps: Object.freeze([
        "Open the Agent Marketplace drawer to switch into a focused specialist workspace (HR Operations, Payroll, Finance, Manager Approvals, Code Agent, or Research Agent) with tailored starters.",
        "Press Ctrl/Cmd+K (or open Prompt Search) to filter curated enterprise prompts by title, agent name, category, or tags and run or prefill them immediately.",
        "Use saved threads in History or click New chat to start a fresh threadId bound exclusively to your signed-in Cognito sub.",
      ]),
      tips: Object.freeze([
        "Thread ownership is verified on the server: another signed-in user cannot resume your threadId.",
        "Signing out clears cached conversation history and session tokens from the browser.",
      ]),
    }),
  ]);

  window.EnterpriseCatalog = Object.freeze({
    APP_TITLE,
    APP_SUBTITLE,
    BOTS,
    MARKETPLACE_AGENTS,
    PROMPTS,
    GUIDE_SECTIONS,
  });
})();
