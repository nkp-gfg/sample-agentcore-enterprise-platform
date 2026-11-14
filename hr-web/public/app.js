/* hr-web — the Layer 3 facilitator UI.
 *
 * Responsibilities, in order:
 *   1. Load /config.json from the local server.
 *   2. Do the Cognito hosted-UI PKCE flow in the browser, with tokens held in
 *      closure-scoped memory only (never persisted to localStorage or exposed
 *      on window). Signing out revokes the refresh token, purges local/session
 *      storage, and ends the Cognito hosted-UI session.
 *   3. Open an AG-UI SSE stream to the module 6 runtime with that Bearer
 *      token, parse attributed subagent & root events, render assistant
 *      Markdown safely, update the live left-sidebar bot handover roster, and
 *      raise the tool-result / review cards via A2UI v1.0.
 *   4. Render every card through A2UI v1.0 (``a2ui.js`` + ``hr-primitives.js``).
 *      This file owns sign-in, AG-UI streaming, the right-side utility drawer
 *      (History, Prompts, Guide, Marketplace), and the "an A2UI action is the
 *      only path to a resume" gate; the rendering is the catalog's.
 *   5. Gate ``submit_leave_request`` behind the EmployeeConfirmForm primitive
 *      and ``record_leave_decision`` behind the ManagerReviewCard primitive.
 *      Typing "approve" in the chat does nothing: only the Button's A2UI
 *      action posts the AG-UI `resume` list (`status: "resolved"`).
 *
 * Nothing in this file talks to AWS SDKs. The browser fetches openid-
 * configuration from the Cognito issuer URL and POSTs the AG-UI RunAgentInput
 * to the runtime directly, with the user's access token.
 */

(() => {
  "use strict";

  if (!window.A2UI || !window.HrCatalog || !window.HrToolAdapter) {
    throw new Error("A2UI, HrCatalog and HrToolAdapter must load before app.js");
  }

  /* ------------------------------------------------------------- constants */

  const REDIRECT_URI = `${location.protocol}//${location.host}/`;
  const SCOPES = ["openid", "email", "profile"];

  const STORAGE_KEYS = Object.freeze({
    verifier: "hr-web.pkce.verifier",
    state: "hr-web.pkce.state",
    nonce: "hr-web.oidc.nonce",
    discovery: "hr-web.oidc.discovery",
    legacySession: "hr-web.oidc.session",
    thread: "hr-web.chat.threadId",
    historyPrefix: "hr-web.history.",
  });

  const PROMPT_MAX = 4000;
  const MAX_RESPONSE_BYTES = 2 * 1024 * 1024;
  const RENEW_SKEW_MS = 60_000;
  const MAX_HISTORY_THREADS = 30;

  const CONFIG_FIELDS = Object.freeze([
    "runtime_arn",
    "region",
    "web_client_id",
    "issuer_url",
    "gateway_url",
    "a2ui_protocol_version",
  ]);

  const DEFAULT_BOTS = Object.freeze([
    {
      id: "god-bot",
      name: "God Bot",
      role: "Root Orchestrator",
      tier: 1,
      group: "orchestrator",
      status: "live",
      aliases: ["god_agent", "god-agent", "orchestrator", "hr-assistant"],
      parent: null,
      tool: "task",
      description: "Top-level router that delegates every question to the right department.",
    },
    {
      id: "hr-operations",
      name: "HR Operations",
      role: "Department Router",
      tier: 2,
      group: "hr",
      status: "live",
      aliases: ["hr_operations"],
      parent: "god-bot",
      tool: "task",
      description: "Routes leave balance, eligibility, and leave submission requests.",
    },
    {
      id: "hr-payroll",
      name: "HR Payroll",
      role: "Department Router",
      tier: 2,
      group: "hr",
      status: "live",
      aliases: ["hr_payroll"],
      parent: "god-bot",
      tool: "task",
      description: "Routes compensation and direct-reports lookups.",
    },
    {
      id: "finance-payroll",
      name: "Finance Payroll",
      role: "Department Router",
      tier: 2,
      group: "finance",
      status: "live",
      aliases: ["finance_payroll"],
      parent: "god-bot",
      tool: "task",
      description: "Routes monthly allowance queries.",
    },
    {
      id: "leave-balance",
      name: "Leave Balance",
      role: "Leaf Specialist",
      tier: 3,
      group: "hr-operations",
      status: "live",
      aliases: ["get_leave_balance"],
      parent: "hr-operations",
      tool: "hr-ops___get_leave_balance",
      description: "Reads annual and sick leave balances and probation status.",
    },
    {
      id: "leave-eligibility",
      name: "Leave Eligibility",
      role: "Leaf Specialist",
      tier: 3,
      group: "hr-operations",
      status: "live",
      aliases: ["check_leave_eligibility"],
      parent: "hr-operations",
      tool: "hr-ops___check_leave_eligibility",
      description: "Checks date-range eligibility against balance and probation rules.",
    },
    {
      id: "leave-submit",
      name: "Leave Submit",
      role: "Leaf Specialist",
      tier: 3,
      group: "hr-operations",
      status: "live",
      aliases: ["submit_leave_request"],
      parent: "hr-operations",
      tool: "hr-ops___submit_leave_request",
      description: "Submits leave requests after employee confirmation interrupt.",
    },
    {
      id: "compensation",
      name: "Compensation",
      role: "Leaf Specialist",
      tier: 3,
      group: "hr-payroll",
      status: "live",
      aliases: ["get_employee_compensation"],
      parent: "hr-payroll",
      tool: "hr-payroll___get_employee_compensation",
      description: "Reads base salary for self or one-hop direct reports.",
    },
    {
      id: "direct-reports",
      name: "Direct Reports",
      role: "Leaf Specialist",
      tier: 3,
      group: "hr-payroll",
      status: "live",
      aliases: ["list_direct_reports"],
      parent: "hr-payroll",
      tool: "hr-payroll___list_direct_reports",
      description: "Lists active one-hop direct reports for the signed-in caller.",
    },
    {
      id: "allowance",
      name: "Allowance",
      role: "Leaf Specialist",
      tier: 3,
      group: "finance-payroll",
      status: "live",
      aliases: ["get_allowance"],
      parent: "finance-payroll",
      tool: "hr-finance___get_allowance",
      description: "Reads self-only monthly telephone allowance records.",
    },
    {
      id: "review-node",
      name: "Manager Review Node",
      role: "Human-in-the-Loop Gate",
      tier: 3,
      group: "hr-operations",
      status: "live",
      aliases: ["record_leave_decision", "manager-review"],
      parent: "hr-operations",
      tool: "hr-ops___record_leave_decision",
      description: "Runtime review gate that records manager approvals or rejections.",
    },
  ]);

  const DEFAULT_STARTERS = Object.freeze([
    {
      title: "Leave balance",
      subtitle: "Check my remaining annual and sick days",
      prompt: "How many annual and sick leave days do I have remaining?",
    },
    {
      title: "Telephone allowance",
      subtitle: "View my 2026-10 payroll allowance",
      prompt: "What was my telephone allowance for 2026-10?",
    },
    {
      title: "Team & compensation",
      subtitle: "List one-hop direct reports & salary",
      prompt: "Who are my direct reports, and what is my current compensation?",
    },
    {
      title: "Request leave (2-stage review)",
      subtitle: "Trigger confirmation & manager review cards",
      prompt: "Submit annual leave from 2026-12-01 to 2026-12-03 for a family trip",
    },
  ]);

  const DEFAULT_MARKETPLACE_AGENTS = Object.freeze([
    {
      id: "hr-assistant",
      name: "HR Assistant",
      category: "Orchestrator",
      badge: "Live",
      status: "live",
      icon: "HR",
      summary: "Unified enterprise assistant routing across HR Operations, Payroll, and Finance.",
      capabilities: ["Leave Balances", "Leave Requests", "Compensation", "Direct Reports", "Allowances"],
      defaultBotId: "god-bot",
      starters: DEFAULT_STARTERS,
    },
  ]);

  const DEFAULT_GUIDE_SECTIONS = Object.freeze([
    {
      id: "getting-started",
      title: "Using the Enterprise Assistant",
      badge: "Basics",
      summary: "Ask natural-language HR, payroll, or finance questions. Every tool call is authorized by Cedar and Postgres row policies.",
      steps: [
        "Pick a starter prompt or press Ctrl/Cmd+K (or / in an empty input) to search the Prompt Library.",
        "Watch the left Bot Roster to see live God Bot delegation across departments and leaves.",
        "Review structured cards rendered in the right A2UI surface column.",
      ],
      tips: ["Typing \"approve\" in chat never submits or approves leave — always use the A2UI card buttons."],
    },
  ]);

  const TOOL_TO_BOT_MAP = Object.freeze({
    get_leave_balance: "leave-balance",
    check_leave_eligibility: "leave-eligibility",
    submit_leave_request: "leave-submit",
    get_employee_compensation: "compensation",
    list_direct_reports: "direct-reports",
    get_allowance: "allowance",
    record_leave_decision: "review-node",
  });

  /* --------------------------------------------------------------- state */

  const state = {
    config: null,
    discovery: null,
    accessToken: null,
    idToken: null,
    refreshToken: null,
    expiresAt: 0,
    renewTimer: null,
    idClaims: null,
    userLabel: "",
    threadId: null,
    runId: null,
    busy: false,
    pendingEmployeeConfirm: null,
    pendingManagerReviews: new Map(),
    sseController: null,
    processor: null,
    outboundErrors: [],
    activeAgentId: "god-bot",
    selectedBotId: null,
    botActivity: {},
    activeHandoverChain: [],
    currentMessages: [],
    drawerOpen: false,
    drawerMode: "history",
    drawerQuery: "",
  };

  let lastAutofilledPrompt = "";

  /* ------------------------------------------------------------- helpers */

  const $ = (id) => document.getElementById(id);
  const el = (tag, cls, text) => {
    const n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text !== undefined && text !== null) n.textContent = text;
    return n;
  };

  function newId(prefix) {
    const c = window.crypto;
    if (!c) throw new Error("Browser cryptography is required.");
    const bytes = new Uint8Array(16);
    c.getRandomValues(bytes);
    return `${prefix}-${Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("")}`;
  }

  function newXrayTraceId() {
    const epochHex = Math.floor(Date.now() / 1000).toString(16).padStart(8, "0");
    if (window.crypto && typeof window.crypto.randomUUID === "function") {
      return `1-${epochHex}-${window.crypto.randomUUID()}`;
    }
    const bytes = new Uint8Array(12);
    window.crypto.getRandomValues(bytes);
    const hex = Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
    return `1-${epochHex}-${hex}`;
  }

  function formatTime(dateObj) {
    try {
      const d = dateObj instanceof Date ? dateObj : new Date(dateObj || Date.now());
      return d.toLocaleTimeString([], {
        hour: "2-digit",
        minute: "2-digit",
      });
    } catch {
      return "";
    }
  }

  function formatRelativeTime(ts) {
    if (!ts) return "";
    const diffSec = Math.max(0, Math.floor((Date.now() - Number(ts)) / 1000));
    if (diffSec < 60) return "just now";
    if (diffSec < 3600) return `${Math.floor(diffSec / 60)}m ago`;
    if (diffSec < 86400) return `${Math.floor(diffSec / 3600)}h ago`;
    try {
      return new Date(Number(ts)).toLocaleDateString([], { month: "short", day: "numeric" });
    } catch {
      return "";
    }
  }

  function truncateText(text, maxLen = 110) {
    const clean = String(text || "").replace(/\s+/g, " ").trim();
    if (clean.length <= maxLen) return clean;
    return `${clean.slice(0, Math.max(1, maxLen - 1)).trimEnd()}…`;
  }

  function stableStringify(val) {
    if (val === null || typeof val !== "object") return JSON.stringify(val);
    if (Array.isArray(val)) return `[${val.map(stableStringify).join(",")}]`;
    const keys = Object.keys(val).sort();
    return `{${keys.map((k) => `${JSON.stringify(k)}:${stableStringify(val[k])}`).join(",")}}`;
  }

  function bareToolName(toolName) {
    const raw = String(toolName || "");
    return raw.includes("___") ? raw.split("___").pop() : raw;
  }

  function b64urlEncode(bytes) {
    const b = typeof bytes === "string" ? new TextEncoder().encode(bytes) : bytes;
    let bin = "";
    for (const v of b) bin += String.fromCharCode(v);
    return btoa(bin).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
  }

  async function sha256(input) {
    const data = new TextEncoder().encode(input);
    const buf = await window.crypto.subtle.digest("SHA-256", data);
    return new Uint8Array(buf);
  }

  function injectFallbackStyles() {
    if (!document.head || $("hrAppDynamicStyles")) return;
    const style = document.createElement("style");
    style.id = "hrAppDynamicStyles";
    style.textContent = `
      :where(.hr-md) { white-space: normal; line-height: 1.5; font-size: 13px; color: inherit; }
      :where(.hr-md > :first-child) { margin-top: 0; }
      :where(.hr-md > :last-child) { margin-bottom: 0; }
      :where(.hr-md p) { margin: 0 0 8px; }
      :where(.hr-md h1, .hr-md h2, .hr-md h3, .hr-md h4, .hr-md h5, .hr-md h6) {
        margin: 10px 0 4px; font-weight: 700; line-height: 1.3; color: var(--ink, #09090b);
      }
      :where(.hr-md h1) { font-size: 15px; }
      :where(.hr-md h2) { font-size: 14px; }
      :where(.hr-md h3, .hr-md h4) { font-size: 13px; }
      :where(.hr-md ul, .hr-md ol) { margin: 4px 0 8px; padding-left: 20px; }
      :where(.hr-md li) { margin: 2px 0; }
      :where(.hr-md code) {
        font-family: var(--mono, monospace); font-size: 12px;
        background: var(--surface-2, #f4f4f5); border: 1px solid var(--line, #e4e4e7);
        border-radius: 4px; padding: 1px 4px;
      }
      :where(.hr-md pre.hr-md-pre) {
        margin: 6px 0 8px; padding: 8px 10px; border-radius: 6px;
        background: var(--surface-2, #f4f4f5); border: 1px solid var(--line, #e4e4e7);
        overflow-x: auto; white-space: pre-wrap; font-family: var(--mono, monospace); font-size: 12px;
      }
      :where(.hr-md pre.hr-md-pre code) { background: transparent; border: 0; padding: 0; }
      :where(.hr-md blockquote.hr-md-quote) {
        margin: 6px 0 8px; padding: 4px 10px;
        border-left: 3px solid var(--line-strong, #d4d4d8); color: var(--ink-2, #3f3f46);
      }
      :where(.hr-md hr.hr-md-hr) { border: 0; border-top: 1px solid var(--line, #e4e4e7); margin: 8px 0; }
      :where(.hr-md-table-wrap) { overflow-x: auto; margin: 6px 0 8px; }
      :where(.hr-md-table) {
        width: 100%; border-collapse: collapse; font-size: 12px;
        border: 1px solid var(--line, #e4e4e7); border-radius: 6px;
      }
      :where(.hr-md-table th, .hr-md-table td) {
        padding: 5px 8px; border-bottom: 1px solid var(--line, #e4e4e7);
        border-right: 1px solid var(--line, #e4e4e7); text-align: left; vertical-align: top;
      }
      :where(.hr-md-table th) { background: var(--surface-2, #f4f4f5); font-weight: 600; }
      :where(.hr-md-table tr:last-child td) { border-bottom: 0; }
      :where(.hr-md-table th:last-child, .hr-md-table td:last-child) { border-right: 0; }

      :where(.hr-bot-item) {
        width: 100%; display: flex; flex-direction: column; gap: 3px;
        padding: 7px 9px; border: 1px solid var(--line, #e4e4e7); border-radius: 6px;
        background: var(--surface, #fff); text-align: left; cursor: pointer;
        transition: border-color .12s ease, background .12s ease;
      }
      :where(.hr-bot-item[data-tier="2"]) { margin-left: 8px; width: calc(100% - 8px); }
      :where(.hr-bot-item[data-tier="3"]) { margin-left: 16px; width: calc(100% - 16px); }
      :where(.hr-bot-item:hover) { border-color: var(--line-strong, #d4d4d8); background: var(--surface-2, #f4f4f5); }
      :where(.hr-bot-item.is-selected) { border-color: var(--accent, #18181b); }
      :where(.hr-bot-item[data-activity="active"]) { border-color: var(--info, #2563eb); background: var(--info-soft, #eff6ff); }
      :where(.hr-bot-item[data-activity="done"]) { border-color: #b7e4c7; }
      :where(.hr-bot-item[data-activity="denied"], .hr-bot-item[data-activity="error"]) { border-color: #f2b4b4; background: var(--err-soft, #fff5f5); }
      :where(.hr-bot-item[data-activity="paused"]) { border-color: #f6d78b; background: var(--warn-soft, #fffce9); }
      :where(.hr-bot-head) { display: flex; align-items: center; gap: 6px; min-width: 0; }
      :where(.hr-bot-dot) { width: 7px; height: 7px; border-radius: 50%; flex: 0 0 7px; background: var(--line-strong, #d4d4d8); }
      :where(.hr-bot-item[data-activity="active"] .hr-bot-dot) { background: var(--info, #2563eb); }
      :where(.hr-bot-item[data-activity="done"] .hr-bot-dot) { background: var(--ok, #00802f); }
      :where(.hr-bot-item[data-activity="denied"] .hr-bot-dot, .hr-bot-item[data-activity="error"] .hr-bot-dot) { background: var(--err, #db0000); }
      :where(.hr-bot-item[data-activity="paused"] .hr-bot-dot) { background: var(--warn, #855900); }
      :where(.hr-bot-name) { font-size: 12px; font-weight: 600; color: var(--ink, #09090b); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
      :where(.hr-bot-status) { margin-left: auto; font-size: 10px; font-weight: 600; padding: 1px 6px; border-radius: 999px; background: var(--surface-2, #f4f4f5); color: var(--ink-3, #71717a); flex-shrink: 0; }
      :where(.hr-bot-item[data-activity="active"] .hr-bot-status) { background: var(--info-soft, #eff6ff); color: var(--info, #2563eb); }
      :where(.hr-bot-item[data-activity="done"] .hr-bot-status) { background: var(--ok-soft, #effff1); color: var(--ok, #00802f); }
      :where(.hr-bot-item[data-activity="denied"] .hr-bot-status, .hr-bot-item[data-activity="error"] .hr-bot-status) { background: var(--err-soft, #fff5f5); color: var(--err, #db0000); }
      :where(.hr-bot-item[data-activity="paused"] .hr-bot-status) { background: var(--warn-soft, #fffce9); color: var(--warn, #855900); }
      :where(.hr-bot-sub) { font-size: 11px; color: var(--ink-3, #71717a); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
      :where(.hr-bot-details) {
        margin-top: 4px; padding-top: 5px; border-top: 1px dashed var(--line, #e4e4e7);
        font-size: 11px; color: var(--ink-2, #3f3f46); display: flex; flex-direction: column; gap: 3px;
      }

      :where(.hr-drawer-toolbar) { display: flex; align-items: center; justify-content: space-between; gap: 8px; margin-bottom: 10px; }
      :where(.hr-drawer-section) { margin-bottom: 14px; }
      :where(.hr-drawer-section-title) { margin: 0 0 6px; font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: .04em; color: var(--ink-3, #71717a); }
      :where(.hr-drawer-card) {
        border: 1px solid var(--line, #e4e4e7); border-radius: 8px; padding: 10px 11px;
        background: var(--surface, #fff); margin-bottom: 8px; display: flex; flex-direction: column; gap: 6px;
      }
      :where(.hr-drawer-card.is-active) { border-color: var(--accent, #18181b); }
      :where(.hr-drawer-card-head) { display: flex; align-items: flex-start; justify-content: space-between; gap: 8px; }
      :where(.hr-drawer-card-title) { margin: 0; font-size: 13px; font-weight: 600; color: var(--ink, #09090b); }
      :where(.hr-drawer-card-meta) { font-size: 11px; color: var(--ink-3, #71717a); }
      :where(.hr-drawer-card-desc) { margin: 0; font-size: 12px; color: var(--ink-2, #3f3f46); line-height: 1.45; }
      :where(.hr-drawer-chips) { display: flex; flex-wrap: wrap; gap: 4px; }
      :where(.hr-drawer-chip) {
        font-size: 10.5px; padding: 1px 6px; border-radius: 4px;
        background: var(--surface-2, #f4f4f5); border: 1px solid var(--line, #e4e4e7); color: var(--ink-2, #3f3f46);
      }
      :where(.hr-drawer-actions) { display: flex; align-items: center; justify-content: flex-end; gap: 6px; margin-top: 2px; }
      :where(.hr-drawer-empty) {
        padding: 20px 12px; text-align: center; color: var(--ink-3, #71717a);
        border: 1px dashed var(--line, #e4e4e7); border-radius: 8px; font-size: 12.5px;
      }
      :where(.hr-guide-steps) { margin: 0; padding-left: 18px; font-size: 12px; color: var(--ink-2, #3f3f46); display: flex; flex-direction: column; gap: 3px; }
      :where(.hr-guide-tips) { margin: 4px 0 0; padding: 7px 9px; border-radius: 6px; background: var(--surface-2, #f4f4f5); font-size: 11.5px; color: var(--ink-2, #3f3f46); }
      :where(.hr-history-btn) {
        all: unset; cursor: pointer; display: flex; flex-direction: column; gap: 3px; flex: 1; min-width: 0;
      }
      :where(.hr-history-btn:focus-visible) { outline: 2px solid var(--accent, #18181b); border-radius: 4px; }
    `;
    document.head.append(style);
  }

  /* ------------------------------------------------------------- catalog */

  function getCatalog() {
    const ec = (window.EnterpriseCatalog && typeof window.EnterpriseCatalog === "object")
      ? window.EnterpriseCatalog
      : {};
    return {
      BOTS: Array.isArray(ec.BOTS) && ec.BOTS.length > 0 ? ec.BOTS : DEFAULT_BOTS,
      MARKETPLACE_AGENTS: Array.isArray(ec.MARKETPLACE_AGENTS) && ec.MARKETPLACE_AGENTS.length > 0
        ? ec.MARKETPLACE_AGENTS
        : DEFAULT_MARKETPLACE_AGENTS,
      PROMPTS: Array.isArray(ec.PROMPTS) ? ec.PROMPTS : [],
      GUIDE_SECTIONS: Array.isArray(ec.GUIDE_SECTIONS) && ec.GUIDE_SECTIONS.length > 0
        ? ec.GUIDE_SECTIONS
        : DEFAULT_GUIDE_SECTIONS,
    };
  }

  function findBot(botId) {
    if (!botId) return null;
    const { BOTS } = getCatalog();
    return BOTS.find((b) => b && b.id === botId) || null;
  }

  function resolveBotId(rawName, descriptionOrTool) {
    const { BOTS } = getCatalog();
    const candidates = [rawName, descriptionOrTool].filter(Boolean).map((v) => String(v).trim());

    for (const raw of candidates) {
      const lower = raw.toLowerCase();
      const bare = bareToolName(raw).toLowerCase();

      if (TOOL_TO_BOT_MAP[bare]) return TOOL_TO_BOT_MAP[bare];

      for (const bot of BOTS) {
        if (!bot || !bot.id) continue;
        if (String(bot.id).toLowerCase() === lower) return bot.id;
        if (bot.name && String(bot.name).toLowerCase() === lower) return bot.id;
        if (bot.tool && (String(bot.tool).toLowerCase() === lower || bareToolName(bot.tool).toLowerCase() === bare)) {
          return bot.id;
        }
        if (Array.isArray(bot.aliases)) {
          for (const alias of bot.aliases) {
            if (String(alias).toLowerCase() === lower || String(alias).toLowerCase() === bare) {
              return bot.id;
            }
          }
        }
      }
    }

    if (descriptionOrTool) {
      const descLower = String(descriptionOrTool).toLowerCase();
      for (const [toolBare, botId] of Object.entries(TOOL_TO_BOT_MAP)) {
        if (descLower.includes(toolBare)) return botId;
      }
      for (const bot of BOTS) {
        if (!bot || !bot.id) continue;
        if (descLower.includes(String(bot.id).toLowerCase())) return bot.id;
        if (Array.isArray(bot.aliases)) {
          for (const alias of bot.aliases) {
            const a = String(alias).toLowerCase();
            if (a.length >= 4 && descLower.includes(a)) return bot.id;
          }
        }
      }
    }

    if (rawName) {
      const slug = String(rawName).trim().toLowerCase().replace(/[^a-z0-9_-]+/g, "-");
      if (slug) return slug;
    }
    return null;
  }

  function displayBotLabel(botId) {
    const bot = findBot(botId);
    if (bot) {
      if (bot.id === "god-bot") return bot.name || "God Bot";
      return bot.id || bot.name;
    }
    return botId === "god-bot" ? "God Bot" : String(botId || "");
  }

  function samplePromptForBot(bot) {
    if (!bot) return "";
    if (bot.starterPrompt) return bot.starterPrompt;
    const { PROMPTS, MARKETPLACE_AGENTS } = getCatalog();
    const idLower = String(bot.id || "").toLowerCase();
    const matchPrompt = PROMPTS.find((p) => {
      if (!p) return false;
      if (p.agentId && String(p.agentId).toLowerCase() === idLower) return true;
      if (bot.parent && p.agentId && String(p.agentId).toLowerCase() === String(bot.parent).toLowerCase()) return true;
      if (Array.isArray(p.tags) && p.tags.some((t) => String(t).toLowerCase() === idLower)) return true;
      return false;
    });
    if (matchPrompt && matchPrompt.prompt) return matchPrompt.prompt;

    const matchAgent = MARKETPLACE_AGENTS.find(
      (a) => a && (a.defaultBotId === bot.id || a.id === bot.id || a.defaultBotId === bot.parent),
    );
    if (matchAgent && Array.isArray(matchAgent.starters) && matchAgent.starters.length > 0) {
      return matchAgent.starters[0].prompt || "";
    }

    const fallbackPrompts = {
      "god-bot": "How many annual and sick leave days do I have remaining?",
      "hr-operations": "How many annual and sick leave days do I have remaining?",
      "leave-balance": "How many annual and sick leave days do I have remaining?",
      "leave-eligibility": "Am I eligible for annual leave from 2026-12-01 to 2026-12-03?",
      "leave-submit": "Submit annual leave from 2026-12-01 to 2026-12-03 for a family trip",
      "hr-payroll": "Who are my direct reports, and what is my current compensation?",
      compensation: "What is my current base salary?",
      "direct-reports": "Who are my direct reports?",
      "finance-payroll": "What was my telephone allowance for 2026-10?",
      allowance: "What was my telephone allowance for 2026-10?",
      "review-node": "",
    };
    return fallbackPrompts[bot.id] || "";
  }

  /* ------------------------------------------------------------- safe markdown */

  function renderInlineMarkdown(text) {
    const frag = document.createDocumentFragment();
    const src = String(text ?? "");
    let i = 0;
    let plain = "";

    const flushPlain = () => {
      if (plain) {
        frag.append(document.createTextNode(plain));
        plain = "";
      }
    };

    while (i < src.length) {
      // 1. Inline code `...`
      if (src[i] === "`") {
        const end = src.indexOf("`", i + 1);
        if (end !== -1 && !src.slice(i + 1, end).includes("\n")) {
          flushPlain();
          const code = document.createElement("code");
          code.textContent = src.slice(i + 1, end);
          frag.append(code);
          i = end + 1;
          continue;
        }
      }

      // 2. Bold + Italic ***...***
      if (src.startsWith("***", i)) {
        const end = src.indexOf("***", i + 3);
        if (end > i + 3 && !src.slice(i + 3, end).includes("\n")) {
          flushPlain();
          const strong = document.createElement("strong");
          const em = document.createElement("em");
          em.append(renderInlineMarkdown(src.slice(i + 3, end)));
          strong.append(em);
          frag.append(strong);
          i = end + 3;
          continue;
        }
      }

      // 3. Bold **...** or __...__
      if (src.startsWith("**", i) || src.startsWith("__", i)) {
        const marker = src.slice(i, i + 2);
        const end = src.indexOf(marker, i + 2);
        if (end > i + 2 && !src.slice(i + 2, end).includes("\n")) {
          flushPlain();
          const strong = document.createElement("strong");
          strong.append(renderInlineMarkdown(src.slice(i + 2, end)));
          frag.append(strong);
          i = end + 2;
          continue;
        }
      }

      // 4. Italic *...* (require non-space after opening * and non-space before closing *)
      if (src[i] === "*" && i + 1 < src.length && !/\s/.test(src[i + 1])) {
        const end = src.indexOf("*", i + 1);
        if (end > i + 1 && !/\s/.test(src[end - 1]) && !src.slice(i + 1, end).includes("\n")) {
          flushPlain();
          const em = document.createElement("em");
          em.append(renderInlineMarkdown(src.slice(i + 1, end)));
          frag.append(em);
          i = end + 1;
          continue;
        }
      }

      // 5. Italic _..._ ONLY on word boundaries (never break snake_case identifiers!)
      if (
        src[i] === "_"
        && (i === 0 || /[\s([{"']/.test(src[i - 1]))
        && i + 1 < src.length
        && !/\s/.test(src[i + 1])
      ) {
        let end = i + 1;
        let found = -1;
        while ((end = src.indexOf("_", end)) !== -1) {
          const slice = src.slice(i + 1, end);
          if (slice.includes("\n")) break;
          const after = end + 1 >= src.length || /[\s.,!?;:)\]}"']/.test(src[end + 1]);
          if (after && !/\s/.test(src[end - 1])) {
            found = end;
            break;
          }
          end += 1;
        }
        if (found > i + 1) {
          flushPlain();
          const em = document.createElement("em");
          em.append(renderInlineMarkdown(src.slice(i + 1, found)));
          frag.append(em);
          i = found + 1;
          continue;
        }
      }

      plain += src[i];
      i += 1;
    }

    flushPlain();
    return frag;
  }

  function splitPipeCells(line) {
    let trimmed = line.trim();
    if (trimmed.startsWith("|")) trimmed = trimmed.slice(1);
    if (trimmed.endsWith("|")) trimmed = trimmed.slice(0, -1);
    return trimmed.split("|").map((c) => c.trim());
  }

  function isTableSeparatorLine(line) {
    if (!line || !line.includes("-")) return false;
    return /^\s*\|?\s*:?-{2,}:?\s*(?:\|\s*:?-{2,}:?\s*)+\|?\s*$/.test(line)
      || /^\s*\|\s*:?-{2,}:?\s*\|\s*$/.test(line);
  }

  function isBlockBoundary(lines, idx) {
    const line = lines[idx];
    if (!line || !line.trim()) return true;
    if (/^\s*```/.test(line)) return true;
    if (/^\s*(#{1,6})\s+/.test(line)) return true;
    if (/^\s*(?:---+|\*\*\*+|___+)\s*$/.test(line)) return true;
    if (/^\s*>\s?/.test(line)) return true;
    if (/^\s*[*-]\s+/.test(line)) return true;
    if (/^\s*\d+[.)]\s+/.test(line)) return true;
    if (idx + 1 < lines.length && line.includes("|") && isTableSeparatorLine(lines[idx + 1])) return true;
    return false;
  }

  function parseListBlock(lines, startIdx) {
    const firstMatch = lines[startIdx].match(/^(\s*)([*-]|\d+[.)])\s+(.*)$/);
    if (!firstMatch) return { node: null, nextIdx: startIdx + 1 };

    const isOrdered = /^\d+/.test(firstMatch[2]);
    const listEl = document.createElement(isOrdered ? "ol" : "ul");
    if (isOrdered) {
      const startNum = Number.parseInt(firstMatch[2], 10);
      if (Number.isFinite(startNum) && startNum !== 1) listEl.start = startNum;
    }

    const baseIndent = firstMatch[1].length;
    let i = startIdx;

    while (i < lines.length) {
      const line = lines[i];
      if (!line.trim()) break;
      const m = line.match(/^(\s*)([*-]|\d+[.)])\s+(.*)$/);
      if (!m) break;
      const indent = m[1].length;
      const itemOrdered = /^\d+/.test(m[2]);

      if (indent < baseIndent) break;
      if (indent > baseIndent) {
        const sub = parseListBlock(lines, i);
        if (sub.node && listEl.lastElementChild) {
          listEl.lastElementChild.append(sub.node);
          i = sub.nextIdx;
          continue;
        }
      }
      if (indent === baseIndent && itemOrdered !== isOrdered) break;

      const li = document.createElement("li");
      li.append(renderInlineMarkdown(m[3]));
      listEl.append(li);
      i += 1;
    }

    return { node: listEl, nextIdx: i };
  }

  function renderMarkdownSafe(text) {
    const root = el("div", "hr-md");
    const normalized = String(text ?? "").replace(/\r\n?/g, "\n");
    if (!normalized.trim()) {
      root.textContent = normalized;
      return root;
    }

    const lines = normalized.split("\n");
    let i = 0;

    while (i < lines.length) {
      const line = lines[i];

      // 1. Blank line
      if (!line.trim()) {
        i += 1;
        continue;
      }

      // 2. Fenced code block ```
      const fenceMatch = line.match(/^\s*```(.*)$/);
      if (fenceMatch) {
        const lang = fenceMatch[1].trim();
        const codeLines = [];
        i += 1;
        while (i < lines.length && !/^\s*```\s*$/.test(lines[i])) {
          codeLines.push(lines[i]);
          i += 1;
        }
        if (i < lines.length && /^\s*```\s*$/.test(lines[i])) i += 1;
        const pre = el("pre", "hr-md-pre");
        const code = document.createElement("code");
        if (lang) code.dataset.lang = lang;
        code.textContent = codeLines.join("\n");
        pre.append(code);
        root.append(pre);
        continue;
      }

      // 3. Heading # .. ######
      const headMatch = line.match(/^\s*(#{1,6})\s+(.+?)\s*#*$/);
      if (headMatch) {
        const level = headMatch[1].length;
        const h = document.createElement(`h${level}`);
        h.append(renderInlineMarkdown(headMatch[2]));
        root.append(h);
        i += 1;
        continue;
      }

      // 4. Horizontal rule
      if (/^\s*(?:---+|\*\*\*+|___+)\s*$/.test(line)) {
        root.append(el("hr", "hr-md-hr"));
        i += 1;
        continue;
      }

      // 5. Pipe table
      if (i + 1 < lines.length && line.includes("|") && isTableSeparatorLine(lines[i + 1])) {
        const headerCells = splitPipeCells(line);
        const sepCells = splitPipeCells(lines[i + 1]);
        const aligns = sepCells.map((s) => {
          if (s.startsWith(":") && s.endsWith(":")) return "center";
          if (s.endsWith(":")) return "right";
          return "left";
        });
        i += 2;

        const wrap = el("div", "hr-md-table-wrap");
        const table = el("table", "hr-md-table");
        const thead = document.createElement("thead");
        const headRow = document.createElement("tr");
        headerCells.forEach((cell, idx) => {
          const th = document.createElement("th");
          if (aligns[idx] && aligns[idx] !== "left") th.style.textAlign = aligns[idx];
          th.append(renderInlineMarkdown(cell));
          headRow.append(th);
        });
        thead.append(headRow);
        table.append(thead);

        const tbody = document.createElement("tbody");
        while (i < lines.length && lines[i].trim() && lines[i].includes("|") && !/^\s*```/.test(lines[i])) {
          const rowCells = splitPipeCells(lines[i]);
          const tr = document.createElement("tr");
          for (let col = 0; col < Math.max(headerCells.length, rowCells.length); col += 1) {
            const td = document.createElement("td");
            if (aligns[col] && aligns[col] !== "left") td.style.textAlign = aligns[col];
            td.append(renderInlineMarkdown(rowCells[col] ?? ""));
            tr.append(td);
          }
          tbody.append(tr);
          i += 1;
        }
        table.append(tbody);
        wrap.append(table);
        root.append(wrap);
        continue;
      }

      // 6. Blockquote
      if (/^\s*>\s?/.test(line)) {
        const quoteLines = [];
        while (i < lines.length && /^\s*>\s?/.test(lines[i])) {
          quoteLines.push(lines[i].replace(/^\s*>\s?/, ""));
          i += 1;
        }
        const bq = el("blockquote", "hr-md-quote");
        quoteLines.forEach((ql, idx) => {
          if (idx > 0) bq.append(document.createElement("br"));
          bq.append(renderInlineMarkdown(ql));
        });
        root.append(bq);
        continue;
      }

      // 7. Bullet or ordered list
      if (/^\s*(?:[*-]|\d+[.)])\s+/.test(line)) {
        const parsed = parseListBlock(lines, i);
        if (parsed.node) root.append(parsed.node);
        i = parsed.nextIdx;
        continue;
      }

      // 8. Paragraph (preserve soft line breaks inside a paragraph block)
      const paraLines = [];
      while (i < lines.length && !isBlockBoundary(lines, i)) {
        paraLines.push(lines[i]);
        i += 1;
      }
      if (paraLines.length === 0) {
        paraLines.push(lines[i]);
        i += 1;
      }
      const p = document.createElement("p");
      paraLines.forEach((pl, idx) => {
        if (idx > 0) p.append(document.createElement("br"));
        p.append(renderInlineMarkdown(pl));
      });
      root.append(p);
    }

    return root;
  }

  /* ------------------------------------------------------------- config */

  async function loadConfig() {
    const res = await fetch("/config.json", { cache: "no-store" });
    if (!res.ok) throw new Error(`config.json HTTP ${res.status}`);
    const data = await res.json();
    for (const key of CONFIG_FIELDS) {
      if (typeof data[key] !== "string" || !data[key]) {
        throw new Error(`config.json is missing ${key}`);
      }
    }
    state.config = Object.freeze({ ...data });
    if (state.config.a2ui_protocol_version !== window.A2UI.PROTOCOL_VERSION) {
      throw new Error(
        `Server pins A2UI ${state.config.a2ui_protocol_version} but this `
        + `renderer speaks ${window.A2UI.PROTOCOL_VERSION}.`,
      );
    }
  }

  async function loadDiscovery() {
    const cached = sessionStorage.getItem(STORAGE_KEYS.discovery);
    if (cached) {
      try {
        const obj = JSON.parse(cached);
        if (obj && obj.authorization_endpoint && obj.token_endpoint) {
          state.discovery = obj;
          return;
        }
      } catch { /* refetch */ }
    }
    const url = `${state.config.issuer_url.replace(/\/$/, "")}/.well-known/openid-configuration`;
    const res = await fetch(url, { cache: "no-store" });
    if (!res.ok) throw new Error(`openid-configuration HTTP ${res.status}`);
    const disc = await res.json();
    if (!disc.authorization_endpoint || !disc.token_endpoint) {
      throw new Error("Identity provider has no hosted-UI endpoints.");
    }
    state.discovery = disc;
    sessionStorage.setItem(STORAGE_KEYS.discovery, JSON.stringify(disc));
  }

  /* ------------------------------------------------------------- PKCE */

  async function beginSignIn() {
    await loadDiscovery();
    const verifier = b64urlEncode(window.crypto.getRandomValues(new Uint8Array(32)));
    const challenge = b64urlEncode(await sha256(verifier));
    const oauthState = b64urlEncode(window.crypto.getRandomValues(new Uint8Array(16)));
    const oidcNonce = b64urlEncode(window.crypto.getRandomValues(new Uint8Array(16)));
    sessionStorage.setItem(STORAGE_KEYS.verifier, verifier);
    sessionStorage.setItem(STORAGE_KEYS.state, oauthState);
    sessionStorage.setItem(STORAGE_KEYS.nonce, oidcNonce);

    const query = new URLSearchParams({
      response_type: "code",
      client_id: state.config.web_client_id,
      redirect_uri: REDIRECT_URI,
      scope: SCOPES.join(" "),
      state: oauthState,
      nonce: oidcNonce,
      code_challenge: challenge,
      code_challenge_method: "S256",
    });
    location.assign(`${state.discovery.authorization_endpoint}?${query.toString()}`);
  }

  function decodeClaims(jwt) {
    if (typeof jwt !== "string") return null;
    const parts = jwt.split(".");
    if (parts.length < 2) return null;
    try {
      const pad = parts[1] + "=".repeat((4 - (parts[1].length % 4)) % 4);
      const bin = atob(pad.replaceAll("-", "+").replaceAll("_", "/"));
      return JSON.parse(bin);
    } catch { return null; }
  }

  function _issuerMatches(actualIss) {
    if (typeof actualIss !== "string" || !actualIss) return false;
    const normActual = actualIss.replace(/\/$/, "");
    const configIss = state.config.issuer_url.replace(/\/$/, "");
    const discIss = state.discovery && typeof state.discovery.issuer === "string"
      ? state.discovery.issuer.replace(/\/$/, "")
      : "";
    return normActual === configIss || (discIss !== "" && normActual === discIss);
  }

  function _audienceMatches(aud, azp, expectedClientId) {
    if (Array.isArray(aud)) {
      if (!aud.includes(expectedClientId)) return false;
      if (aud.length > 1 && azp && azp !== expectedClientId) return false;
      return true;
    }
    return aud === expectedClientId;
  }

  function validateOidcTokens(tokens, expectedNonce, { requireNonce = false } = {}) {
    const accessToken = tokens.access_token || tokens.accessToken;
    if (!accessToken) throw new Error("Token payload missing access_token.");
    const idToken = tokens.id_token || tokens.idToken || null;
    const accessClaims = decodeClaims(accessToken);
    const idClaims = idToken ? decodeClaims(idToken) : null;
    const clientId = state.config.web_client_id;
    const nowSec = Math.floor(Date.now() / 1000);

    if (requireNonce) {
      if (!idToken || !idClaims) {
        throw new Error("Token exchange returned no valid id_token.");
      }
      if (!expectedNonce || typeof idClaims.nonce !== "string" || idClaims.nonce !== expectedNonce) {
        throw new Error("ID token nonce mismatch.");
      }
    }

    if (idClaims) {
      if (!_issuerMatches(idClaims.iss)) {
        throw new Error("ID token issuer mismatch.");
      }
      if (!_audienceMatches(idClaims.aud, idClaims.azp, clientId)) {
        throw new Error("ID token audience mismatch.");
      }
      if (typeof idClaims.exp === "number" && idClaims.exp <= nowSec - 30) {
        throw new Error("ID token is expired.");
      }
    }

    if (accessClaims) {
      if (accessClaims.iss && !_issuerMatches(accessClaims.iss)) {
        throw new Error("Access token issuer mismatch.");
      }
      if (accessClaims.client_id && accessClaims.client_id !== clientId) {
        throw new Error("Access token client_id mismatch.");
      }
      if (typeof accessClaims.exp === "number" && accessClaims.exp <= nowSec - 30) {
        throw new Error("Access token is expired.");
      }
    }

    return { accessToken, idToken, accessClaims, idClaims };
  }

  function ensureTabThreadId() {
    const existing = sessionStorage.getItem(STORAGE_KEYS.thread);
    if (existing && /^[A-Za-z0-9_-]{33,128}$/.test(existing)) {
      return existing;
    }
    const fresh = newId("thread");
    sessionStorage.setItem(STORAGE_KEYS.thread, fresh);
    return fresh;
  }

  function scheduleSilentRenew(expiresAtMs) {
    if (state.renewTimer) {
      clearTimeout(state.renewTimer);
      state.renewTimer = null;
    }
    if (!state.refreshToken || !expiresAtMs) return;
    const delay = Math.max(5_000, expiresAtMs - Date.now() - RENEW_SKEW_MS);
    state.renewTimer = setTimeout(() => {
      refreshEstablishedSession(state.refreshToken).catch(() => {});
    }, delay);
  }

  function applyAuthenticatedTokens(tokens, fallbackRefreshToken, validationOpts = {}) {
    const {
      accessToken,
      idToken,
      accessClaims,
      idClaims,
    } = validateOidcTokens(tokens, validationOpts.expectedNonce || null, {
      requireNonce: Boolean(validationOpts.requireNonce),
    });
    const refreshToken = tokens.refresh_token || tokens.refreshToken || fallbackRefreshToken || null;
    const expiresAt = (accessClaims && typeof accessClaims.exp === "number")
      ? accessClaims.exp * 1000
      : (typeof tokens.expiresAt === "number"
        ? tokens.expiresAt
        : Date.now() + (Number(tokens.expires_in) || 3600) * 1000);

    // Tokens live exclusively in closure memory for the life of the tab.
    state.accessToken = accessToken;
    state.idToken = idToken;
    state.refreshToken = refreshToken;
    state.expiresAt = expiresAt;
    state.idClaims = idClaims || accessClaims;
    state.userLabel = (idClaims && (idClaims.email || idClaims["cognito:username"]))
      || state.userLabel
      || (accessClaims && (accessClaims.username || accessClaims.sub))
      || "Signed in";
    state.threadId = state.threadId || ensureTabThreadId();

    scheduleSilentRenew(expiresAt);
  }

  async function completeSignIn(code, returnedState) {
    const verifier = sessionStorage.getItem(STORAGE_KEYS.verifier);
    const expectedState = sessionStorage.getItem(STORAGE_KEYS.state);
    const expectedNonce = sessionStorage.getItem(STORAGE_KEYS.nonce);
    sessionStorage.removeItem(STORAGE_KEYS.verifier);
    sessionStorage.removeItem(STORAGE_KEYS.state);
    sessionStorage.removeItem(STORAGE_KEYS.nonce);
    if (!verifier || !expectedState || returnedState !== expectedState) {
      throw new Error("Sign-in state mismatch (possible forged redirect).");
    }
    await loadDiscovery();
    const body = new URLSearchParams({
      grant_type: "authorization_code",
      client_id: state.config.web_client_id,
      code,
      redirect_uri: REDIRECT_URI,
      code_verifier: verifier,
    });
    const res = await fetch(state.discovery.token_endpoint, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: body.toString(),
    });
    if (!res.ok) throw new Error(`Token exchange failed (HTTP ${res.status}).`);
    const tokens = await res.json();
    applyAuthenticatedTokens(tokens, null, { expectedNonce, requireNonce: true });
  }

  async function refreshEstablishedSession(refreshToken) {
    if (!refreshToken || !state.config) return false;
    await loadDiscovery();
    const body = new URLSearchParams({
      grant_type: "refresh_token",
      client_id: state.config.web_client_id,
      refresh_token: refreshToken,
    });
    const res = await fetch(state.discovery.token_endpoint, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: body.toString(),
    });
    if (!res.ok) {
      clearStoredSessionOnly();
      return false;
    }
    const tokens = await res.json();
    try {
      applyAuthenticatedTokens(tokens, refreshToken, { requireNonce: false });
      return true;
    } catch {
      clearStoredSessionOnly();
      return false;
    }
  }

  function purgePrefixedKeys(storage, prefixes) {
    try {
      if (!storage) return;
      const toDelete = [];
      for (let i = 0; i < storage.length; i += 1) {
        const k = storage.key(i);
        if (k && prefixes.some((p) => k.startsWith(p))) {
          toDelete.push(k);
        }
      }
      for (const k of toDelete) storage.removeItem(k);
    } catch { /* ignore */ }
  }

  function purgeLegacyPersistentStorage() {
    purgePrefixedKeys(window.localStorage, [
      "hr-web.oidc.",
      "hr-web.pkce.",
      "hr-web.history.",
      "hr-web.chat.",
    ]);
  }

  function clearStoredSessionOnly() {
    if (state.renewTimer) {
      clearTimeout(state.renewTimer);
      state.renewTimer = null;
    }
    purgeLegacyPersistentStorage();
    purgePrefixedKeys(window.sessionStorage, [
      "hr-web.oidc.",
      "hr-web.pkce.",
      STORAGE_KEYS.thread,
    ]);
  }

  function clearLocalState() {
    clearStoredSessionOnly();
    purgePrefixedKeys(window.sessionStorage, [STORAGE_KEYS.historyPrefix]);
    state.accessToken = null;
    state.idToken = null;
    state.refreshToken = null;
    state.expiresAt = 0;
    state.idClaims = null;
    state.userLabel = "";
    state.threadId = null;
    state.pendingEmployeeConfirm = null;
    state.pendingManagerReviews.clear();
    state.currentMessages = [];
    state.botActivity = {};
    state.activeHandoverChain = [];
    state.selectedBotId = null;
    lastAutofilledPrompt = "";
    try { sessionStorage.clear(); } catch { /* ignore */ }
    if (state.sseController) state.sseController.abort();
    if (state.processor) state.processor.clear();
    state.outboundErrors = [];
    closeDrawer();
    renderMessages({ reset: true });
    updateReviewBadge(0);
    renderIdentity();
    renderBotRoster();
    renderHandoverStatus();
    updateControls();
  }

  async function revokeRefreshTokenBestEffort(discovery, clientId, refreshToken) {
    if (!discovery || !discovery.revocation_endpoint || !clientId || !refreshToken) return;
    const controller = typeof AbortController === "function" ? new AbortController() : null;
    const timer = controller ? setTimeout(() => controller.abort(), 1200) : null;
    try {
      const body = new URLSearchParams({
        token: refreshToken,
        client_id: clientId,
      });
      await fetch(discovery.revocation_endpoint, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: body.toString(),
        keepalive: true,
        signal: controller ? controller.signal : undefined,
      });
    } catch {
      /* best-effort revocation; never stall sign-out */
    } finally {
      if (timer) clearTimeout(timer);
    }
  }

  async function signOut() {
    let discovery = state.discovery;
    const clientId = state.config && state.config.web_client_id;
    const refreshToken = state.refreshToken;
    if (!discovery && state.config) {
      try { await loadDiscovery(); discovery = state.discovery; } catch { /* best effort */ }
    }
    clearLocalState();
    await revokeRefreshTokenBestEffort(discovery, clientId, refreshToken);

    // Clear the Cognito hosted-UI session cookie too (mirrors FAST's
    // `signoutRedirect({ extraQueryParams: { client_id, logout_uri } })`) so a
    // second persona (e.g. M1 after E1) can sign in cleanly without incognito.
    if (discovery && discovery.end_session_endpoint && clientId) {
      const logoutQuery = new URLSearchParams({
        client_id: clientId,
        logout_uri: REDIRECT_URI,
      });
      location.assign(`${discovery.end_session_endpoint}?${logoutQuery.toString()}`);
    }
  }

  function startNewChat() {
    if (state.busy || !state.accessToken) return;
    if (state.sseController) state.sseController.abort();
    state.pendingEmployeeConfirm = null;
    state.pendingManagerReviews.clear();
    state.outboundErrors = [];
    state.currentMessages = [];
    state.selectedBotId = null;
    state.activeHandoverChain = [];
    for (const key of Object.keys(state.botActivity)) {
      state.botActivity[key] = { status: "idle", task: "", lastActiveAt: 0, snippet: "" };
    }
    if (state.processor) state.processor.clear();
    state.threadId = newId("thread");
    try { sessionStorage.setItem(STORAGE_KEYS.thread, state.threadId); } catch { /* ignore */ }
    renderMessages({ reset: true });
    renderWelcomeForActiveAgent(null);
    updateReviewBadge(0);
    renderIdentity();
    renderBotRoster();
    renderHandoverStatus();
    updateControls();
    if (state.drawerOpen && state.drawerMode === "history") renderDrawerBody();
    const chatInput = $("chatInput");
    if (chatInput) chatInput.focus();
  }

  /* ------------------------------------------------------------- history */

  function getUserHistoryStorageKey() {
    const accessClaims = state.accessToken ? decodeClaims(state.accessToken) : null;
    const rawSub = (state.idClaims && (state.idClaims.sub || state.idClaims["cognito:username"] || state.idClaims.email))
      || (accessClaims && (accessClaims.sub || accessClaims.username))
      || "default";
    const safeSub = String(rawSub).replace(/[^A-Za-z0-9_.-]/g, "_") || "default";
    return `${STORAGE_KEYS.historyPrefix}${safeSub}`;
  }

  function loadHistoryList() {
    try {
      const raw = sessionStorage.getItem(getUserHistoryStorageKey());
      if (!raw) return [];
      const parsed = JSON.parse(raw);
      return Array.isArray(parsed) ? parsed.filter((x) => x && typeof x === "object" && x.threadId) : [];
    } catch {
      return [];
    }
  }

  function writeHistoryList(items) {
    const key = getUserHistoryStorageKey();
    const capped = items.slice(0, MAX_HISTORY_THREADS);
    try {
      sessionStorage.setItem(key, JSON.stringify(capped));
    } catch {
      // Retry with smaller cap if storage quota is tight.
      try {
        sessionStorage.setItem(key, JSON.stringify(capped.slice(0, 10)));
      } catch { /* ignore */ }
    }
  }

  function deriveThreadTitle(messages) {
    const firstUser = messages.find((m) => m && m.role === "user" && m.text && m.text.trim());
    if (firstUser) return truncateText(firstUser.text, 64);
    const firstAny = messages.find((m) => m && m.text && m.text.trim());
    return firstAny ? truncateText(firstAny.text, 64) : "Conversation";
  }

  function sanitizeHistoryCards(a2uiMessages) {
    if (!Array.isArray(a2uiMessages)) return [];
    return a2uiMessages.filter((msg) => {
      if (!msg || typeof msg !== "object") return false;
      const comp = msg.createSurface && msg.createSurface.components && msg.createSurface.components[0]
        ? msg.createSurface.components[0].component
        : "";
      if (comp === "EmployeeConfirmForm" || comp === "ManagerReviewCard") return false;
      return true;
    });
  }

  function saveCurrentThreadToHistory() {
    if (!state.accessToken || !state.threadId) return;
    const meaningful = state.currentMessages.filter(
      (m) => m && ((m.text && m.text.trim()) || (Array.isArray(m.traces) && m.traces.length > 0) || (Array.isArray(m.cards) && m.cards.length > 0)),
    );
    if (meaningful.length === 0) return;

    const existing = loadHistoryList().filter((item) => item.threadId !== state.threadId);
    const entry = {
      threadId: state.threadId,
      title: deriveThreadTitle(meaningful),
      updatedAt: Date.now(),
      activeAgentId: state.activeAgentId || "hr-assistant",
      messages: meaningful.map((m) => ({
        role: m.role,
        text: m.text || "",
        meta: m.meta || "",
        timestamp: m.timestamp || Date.now(),
        traces: Array.isArray(m.traces) ? m.traces : [],
        cards: Array.isArray(m.cards) ? m.cards : [],
      })),
    };
    existing.unshift(entry);
    writeHistoryList(existing);
    if (state.drawerOpen && state.drawerMode === "history") {
      renderDrawerBody();
    }
  }

  function deleteHistoryThread(threadId) {
    const remaining = loadHistoryList().filter((item) => item.threadId !== threadId);
    writeHistoryList(remaining);
    if (state.drawerOpen && state.drawerMode === "history") {
      renderDrawerBody();
    }
  }

  function clearAllHistory() {
    try {
      sessionStorage.removeItem(getUserHistoryStorageKey());
    } catch { /* ignore */ }
    if (state.drawerOpen && state.drawerMode === "history") {
      renderDrawerBody();
    }
  }

  function loadHistoryThread(threadId) {
    if (state.busy || !state.accessToken) return;
    const item = loadHistoryList().find((x) => x.threadId === threadId);
    if (!item) return;

    if (state.sseController) state.sseController.abort();
    state.pendingEmployeeConfirm = null;
    state.pendingManagerReviews.clear();
    updateReviewBadge(0);
    state.outboundErrors = [];
    if (state.processor) state.processor.clear();

    state.threadId = item.threadId;
    try { sessionStorage.setItem(STORAGE_KEYS.thread, state.threadId); } catch { /* ignore */ }

    if (item.activeAgentId) {
      selectMarketplaceAgent(item.activeAgentId, { resetChat: false, closeAfter: false });
    }

    const restoredMessages = Array.isArray(item.messages) ? item.messages : [];
    state.currentMessages = restoredMessages.map((m) => ({
      role: m.role,
      text: m.text || "",
      meta: m.meta || "",
      timestamp: m.timestamp || Date.now(),
      traces: Array.isArray(m.traces) ? m.traces : [],
      cards: Array.isArray(m.cards) ? m.cards : [],
    }));

    renderMessages({ reset: true });
    for (const msg of state.currentMessages) {
      const node = appendMessage(msg.role, msg.text, msg.meta, {
        recordHistory: false,
        timestamp: msg.timestamp,
      });
      if (Array.isArray(msg.traces)) {
        for (const tr of msg.traces) {
          appendTrace(node, tr.kind || "info", tr.label || "trace", tr.detail);
        }
      }
      if (Array.isArray(msg.cards) && msg.cards.length > 0) {
        applyA2uiMessages(msg.cards);
      }
    }

    updateReviewBadge(0);
    renderIdentity();
    updateControls();
    closeDrawer();
    const chatInput = $("chatInput");
    if (chatInput) chatInput.focus();
  }

  /* ------------------------------------------------------------- bot roster & handover */

  function ensureBotActivityEntry(botId) {
    if (!botId) return null;
    if (!state.botActivity[botId]) {
      state.botActivity[botId] = { status: "idle", task: "", lastActiveAt: 0, snippet: "" };
    }
    return state.botActivity[botId];
  }

  function resetBotActivityForTurn(userText) {
    const { BOTS } = getCatalog();
    for (const bot of BOTS) {
      if (bot && bot.id) {
        state.botActivity[bot.id] = { status: "idle", task: "", lastActiveAt: 0, snippet: "" };
      }
    }
    for (const key of Object.keys(state.botActivity)) {
      if (state.botActivity[key].status !== "idle") {
        state.botActivity[key] = { status: "idle", task: "", lastActiveAt: 0, snippet: "" };
      }
    }
    state.botActivity["god-bot"] = {
      status: "active",
      task: userText ? truncateText(userText, 72) : "Routing request…",
      lastActiveAt: Date.now(),
      snippet: "",
    };
    state.activeHandoverChain = ["god-bot"];
    renderHandoverStatus();
    renderBotRoster();
  }

  function setBotActivity(botId, patch) {
    if (!botId) return;
    const prev = ensureBotActivityEntry(botId);
    state.botActivity[botId] = Object.assign({}, prev, patch, {
      lastActiveAt: patch.lastActiveAt || Date.now(),
    });
    renderBotRoster();
  }

  function pushHandoverStep(botId) {
    if (!botId) return;
    const last = state.activeHandoverChain[state.activeHandoverChain.length - 1];
    if (last !== botId) {
      state.activeHandoverChain.push(botId);
    }
    renderHandoverStatus();
  }

  function finalizeBotsOnFinish(isInterrupt, isError) {
    for (const [botId, info] of Object.entries(state.botActivity)) {
      if (!info) continue;
      if (info.status === "active") {
        info.status = isError ? "error" : isInterrupt ? "paused" : "done";
      }
    }
    const god = ensureBotActivityEntry("god-bot");
    if (god) {
      god.status = isError ? "error" : isInterrupt ? "paused" : "done";
      if (!god.task) {
        god.task = isError ? "Error" : isInterrupt ? "Awaiting action" : "Completed";
      }
      god.lastActiveAt = Date.now();
    }
    renderHandoverStatus();
    renderBotRoster();
  }

  function renderHandoverStatus() {
    const label = $("handoverStatusLabel");
    const pill = $("activeAgentPill");
    const footerHandover = $("footerHandover");
    const godStatus = (state.botActivity["god-bot"] && state.botActivity["god-bot"].status) || "idle";

    if (!state.activeHandoverChain || state.activeHandoverChain.length === 0) {
      if (label) {
        label.textContent = "Idle · Ready";
        label.dataset.state = "idle";
      }
      if (pill) delete pill.dataset.handover;
      if (footerHandover) footerHandover.textContent = "Routing: God Bot → hr-operations · hr-payroll · finance-payroll";
      return;
    }

    const chainText = state.activeHandoverChain.map(displayBotLabel).join(" → ");
    if (label) {
      label.textContent = chainText;
      label.dataset.state = godStatus;
    }
    if (pill) {
      if (godStatus === "active") pill.dataset.handover = "active";
      else delete pill.dataset.handover;
    }
    if (footerHandover) {
      footerHandover.textContent = `Handover: ${chainText}`;
    }
  }

  function activityLabelText(activityStatus, catalogStatus) {
    if (activityStatus === "active") return "Active";
    if (activityStatus === "done") return "Done";
    if (activityStatus === "denied") return "Denied";
    if (activityStatus === "paused") return "Paused";
    if (activityStatus === "error") return "Error";
    if (catalogStatus && catalogStatus !== "live" && catalogStatus !== "active") {
      return String(catalogStatus).toUpperCase();
    }
    return "Idle";
  }

  function renderBotRoster() {
    const list = $("botRosterList");
    if (!list) return;
    const { BOTS } = getCatalog();
    list.replaceChildren();

    const groups = new Map();
    for (const bot of BOTS) {
      if (!bot || !bot.id || bot.id === "god-bot") continue;
      const groupName = bot.group || "Specialists";
      if (!groups.has(groupName)) groups.set(groupName, []);
      groups.get(groupName).push(bot);
    }

    for (const [groupName, bots] of groups.entries()) {
      const groupWrap = el("div", "ew-bot-group");
      groupWrap.append(el("div", "ew-roster-group-title", groupName));

      for (const bot of bots) {
        const activity = state.botActivity[bot.id] || { status: "idle", task: "", snippet: "" };
        const isSelected = state.selectedBotId === bot.id;

        const btn = el("button", "hr-bot-item");
        btn.type = "button";
        btn.dataset.botId = bot.id;
        btn.dataset.activity = activity.status || "idle";
        if (bot.tier != null) btn.dataset.tier = String(bot.tier);
        if (isSelected) {
          btn.classList.add("is-selected");
          btn.setAttribute("aria-current", "true");
        }

        const head = el("div", "hr-bot-head");
        head.append(el("span", "hr-bot-dot"));
        head.append(el("span", "hr-bot-name", bot.name || bot.id));
        head.append(el("span", "hr-bot-status", activityLabelText(activity.status, bot.status)));

        const subText = activity.task
          ? activity.task
          : (bot.role || bot.tool || bot.description || "");
        const sub = el("div", "hr-bot-sub", subText);

        btn.append(head, sub);

        if (isSelected) {
          const details = el("div", "hr-bot-details");
          if (bot.description) details.append(el("span", "", bot.description));
          if (bot.tool) details.append(el("span", "mono", `tool: ${bot.tool}`));
          if (bot.parent) details.append(el("span", "", `parent: ${displayBotLabel(bot.parent)}`));
          if (activity.snippet) details.append(el("span", "", `output: ${truncateText(activity.snippet, 120)}`));
          btn.append(details);
        }

        btn.addEventListener("click", () => {
          onBotRosterSelect(bot.id);
        });
        groupWrap.append(btn);
      }
      list.append(groupWrap);
    }
  }

  function onBotRosterSelect(botId) {
    const bot = findBot(botId);
    if (!bot) return;
    state.selectedBotId = state.selectedBotId === botId ? null : botId;
    renderBotRoster();

    const activeBot = state.selectedBotId ? bot : null;
    if ($("chatMessages") && $("chatMessages").childElementCount === 0) {
      renderWelcomeForActiveAgent(activeBot);
    }

    if (activeBot && !state.busy && state.accessToken) {
      const sample = samplePromptForBot(activeBot);
      const chatInput = $("chatInput");
      if (sample && chatInput && (!chatInput.value.trim() || chatInput.value === lastAutofilledPrompt)) {
        chatInput.value = sample;
        lastAutofilledPrompt = sample;
        const countEl = $("chatCount");
        if (countEl) countEl.textContent = String(sample.length);
        autoResizeInput();
        updateControls();
        chatInput.focus();
      }
    }
  }

  /* ------------------------------------------------------------- marketplace & welcome */

  function getActiveMarketplaceAgent() {
    const { MARKETPLACE_AGENTS } = getCatalog();
    return (
      MARKETPLACE_AGENTS.find((a) => a && a.id === state.activeAgentId)
      || MARKETPLACE_AGENTS[0]
      || DEFAULT_MARKETPLACE_AGENTS[0]
    );
  }

  function renderActiveAgentPill() {
    const pill = $("activeAgentPill");
    if (!pill) return;
    const agent = getActiveMarketplaceAgent();
    if (!agent) {
      pill.textContent = "God Bot · Orchestrator";
      return;
    }
    pill.textContent = agent.id === "god-bot"
      ? "God Bot · Orchestrator"
      : (agent.name || agent.id);
    pill.dataset.agentId = agent.id;
    pill.dataset.status = agent.status || "live";
    pill.title = agent.summary || agent.name || "";
  }

  function renderWelcomeForActiveAgent(focusBot) {
    const agent = getActiveMarketplaceAgent();
    const titleEl = $("welcomeTitle");
    const subEl = $("welcomeSub");
    const startersEl = $("starterPrompts");
    const welcomeEl = $("welcomeState");
    if (!welcomeEl) return;

    // Remove any previous dynamic A2A routing banner inside welcomeState.
    const existingNotice = $("agentRoutingNotice");
    if (existingNotice) existingNotice.remove();

    if (focusBot) {
      if (titleEl) titleEl.textContent = focusBot.name || focusBot.id;
      if (subEl) subEl.textContent = focusBot.description || focusBot.role || "";
    } else if (agent) {
      if (titleEl) {
        titleEl.textContent = agent.id === "hr-assistant" || agent.id === "god-bot"
          ? "Welcome to AgentCore Enterprise"
          : `${agent.name}`;
      }
      if (subEl) {
        subEl.textContent = agent.summary
          || "Ask about leave balances, eligibility, compensation, direct reports, or monthly allowances — or pick a starter prompt below.";
      }
    }

    if (agent && agent.status && agent.status !== "live" && agent.status !== "active" && subEl && subEl.parentNode) {
      const notice = el("div", "hr-banner");
      notice.id = "agentRoutingNotice";
      notice.textContent = `${agent.name} (${agent.badge || agent.status}) runs as a specialist A2A pattern when enabled and routes requests through the active orchestrator in this workspace.`;
      subEl.after(notice);
    }

    if (startersEl) {
      let chips = [];
      if (focusBot) {
        const promptForBot = samplePromptForBot(focusBot);
        const { PROMPTS } = getCatalog();
        const related = PROMPTS.filter(
          (p) => p && (
            p.agentId === focusBot.id
            || p.agentId === focusBot.parent
            || (Array.isArray(p.tags) && p.tags.includes(focusBot.id))
          ),
        ).slice(0, 4);
        if (related.length > 0) {
          chips = related.map((p) => ({
            title: p.title,
            subtitle: p.description || p.category || focusBot.name,
            prompt: p.prompt,
          }));
        } else if (promptForBot) {
          chips = [{
            title: `Ask ${focusBot.name || focusBot.id}`,
            subtitle: focusBot.role || focusBot.tool || "Run focused prompt",
            prompt: promptForBot,
          }];
        }
      }
      if (chips.length === 0 && agent && Array.isArray(agent.starters) && agent.starters.length > 0) {
        chips = agent.starters;
      }
      if (chips.length === 0) {
        chips = DEFAULT_STARTERS;
      }

      startersEl.replaceChildren();
      for (const s of chips) {
        const chip = el("button", "hr-starter-chip");
        chip.type = "button";
        chip.dataset.prompt = s.prompt || "";
        chip.append(el("strong", "", s.title || "Run prompt"));
        chip.append(el("span", "", s.subtitle || s.description || truncateText(s.prompt, 56)));
        startersEl.append(chip);
      }
    }

    renderActiveAgentPill();
    updateControls();
  }

  function selectMarketplaceAgent(agentId, options = {}) {
    const { MARKETPLACE_AGENTS } = getCatalog();
    const found = MARKETPLACE_AGENTS.find((a) => a && a.id === agentId);
    if (!found) return;
    state.activeAgentId = found.id;
    state.selectedBotId = found.defaultBotId || null;

    const shouldReset = options.resetChat !== false;
    const shouldClose = options.closeAfter !== false;

    if (shouldReset && !state.busy && state.accessToken) {
      startNewChat();
    } else {
      renderWelcomeForActiveAgent(null);
      renderBotRoster();
    }

    if (shouldClose) closeDrawer();
    const chatInput = $("chatInput");
    if (chatInput && !state.busy && state.accessToken) chatInput.focus();
  }

  /* ------------------------------------------------------------- right drawer */

  const DRAWER_TITLES = Object.freeze({
    history: "Conversation History",
    prompts: "Prompt Library",
    guide: "User Guide",
    marketplace: "Agent Marketplace",
  });

  const DRAWER_SEARCH_PLACEHOLDERS = Object.freeze({
    history: "Search conversation history…",
    prompts: "Search prompts, tags, or agents…",
    marketplace: "Search enterprise agents & capabilities…",
  });

  function syncDrawerButtons() {
    for (const btn of document.querySelectorAll("[data-drawer]")) {
      const target = btn.dataset.drawer;
      const isActive = state.drawerOpen && state.drawerMode === target;
      btn.classList.toggle("is-active", isActive);
      btn.dataset.active = isActive ? "true" : "false";
      btn.setAttribute("aria-pressed", String(isActive));
      if (!btn.closest("#rightDrawer")) {
        btn.setAttribute("aria-expanded", String(isActive));
      }
    }
  }

  function openDrawer(mode = "history") {
    const valid = Object.prototype.hasOwnProperty.call(DRAWER_TITLES, mode) ? mode : "history";
    const modeChanged = state.drawerMode !== valid;
    state.drawerOpen = true;
    state.drawerMode = valid;
    if (modeChanged) {
      state.drawerQuery = "";
      const searchInput = $("rightDrawerSearch");
      if (searchInput) searchInput.value = "";
    }

    const drawer = $("rightDrawer");
    if (drawer) {
      drawer.hidden = false;
      drawer.dataset.open = "true";
      drawer.dataset.mode = valid;
      drawer.classList.add("is-open");
    }

    const titleEl = $("rightDrawerTitle");
    if (titleEl) titleEl.textContent = DRAWER_TITLES[valid];

    const searchWrap = $("rightDrawerSearchWrap");
    const searchInput = $("rightDrawerSearch");
    if (searchWrap) searchWrap.hidden = valid === "guide";
    if (searchInput) {
      searchInput.placeholder = DRAWER_SEARCH_PLACEHOLDERS[valid] || "Search…";
    }

    syncDrawerButtons();
    renderDrawerBody();
  }

  function closeDrawer() {
    state.drawerOpen = false;
    const drawer = $("rightDrawer");
    if (drawer) {
      drawer.hidden = true;
      delete drawer.dataset.open;
      drawer.classList.remove("is-open");
    }
    syncDrawerButtons();
  }

  function renderDrawerHistory(body, query) {
    const items = loadHistoryList();
    const toolbar = el("div", "hr-drawer-toolbar");
    toolbar.append(el("span", "hr-drawer-card-meta", `${items.length} / ${MAX_HISTORY_THREADS} saved threads`));
    if (items.length > 0) {
      const clearBtn = el("button", "hr-button hr-button--ghost", "Clear history");
      clearBtn.type = "button";
      clearBtn.addEventListener("click", clearAllHistory);
      toolbar.append(clearBtn);
    }
    body.append(toolbar);

    const filtered = items.filter((item) => {
      if (!query) return true;
      const hay = `${item.title || ""} ${item.activeAgentId || ""} ${(item.messages || []).map((m) => m.text).join(" ")}`.toLowerCase();
      return hay.includes(query);
    });

    if (filtered.length === 0) {
      body.append(el("div", "hr-drawer-empty",
        items.length === 0
          ? "No conversations saved yet. Send a message to start a checkpointed thread."
          : "No conversations match your filter."));
      return;
    }

    for (const item of filtered) {
      const card = el("div", "hr-drawer-card");
      if (item.threadId === state.threadId) card.classList.add("is-active");

      const row = el("div", "hr-drawer-card-head");
      const openBtn = el("button", "hr-history-btn");
      openBtn.type = "button";
      openBtn.append(el("span", "hr-drawer-card-title", item.title || "Conversation"));
      const msgCount = Array.isArray(item.messages) ? item.messages.length : 0;
      const agentObj = getCatalog().MARKETPLACE_AGENTS.find((a) => a && a.id === item.activeAgentId);
      const agentLabel = (agentObj && agentObj.name) || item.activeAgentId || "HR Assistant";
      openBtn.append(el("span", "hr-drawer-card-meta",
        `${agentLabel} · ${msgCount} msg${msgCount === 1 ? "" : "s"} · ${formatRelativeTime(item.updatedAt)}`));
      openBtn.addEventListener("click", () => loadHistoryThread(item.threadId));

      const delBtn = el("button", "hr-button hr-button--ghost", "Delete");
      delBtn.type = "button";
      delBtn.addEventListener("click", (e) => {
        e.stopPropagation();
        deleteHistoryThread(item.threadId);
      });

      row.append(openBtn, delBtn);
      card.append(row);
      body.append(card);
    }
  }

  function renderDrawerPrompts(body, query) {
    const { PROMPTS } = getCatalog();
    const filtered = PROMPTS.filter((p) => {
      if (!p) return false;
      if (!query) return true;
      const tags = Array.isArray(p.tags) ? p.tags.join(" ") : "";
      const hay = `${p.title || ""} ${p.description || ""} ${p.prompt || ""} ${p.category || ""} ${p.agentName || ""} ${tags}`.toLowerCase();
      return hay.includes(query);
    });

    if (filtered.length === 0) {
      body.append(el("div", "hr-drawer-empty",
        PROMPTS.length === 0
          ? "No prompt templates are loaded in this environment."
          : "No prompts match your search."));
      return;
    }

    const groups = new Map();
    for (const p of filtered) {
      const cat = p.category || "General";
      if (!groups.has(cat)) groups.set(cat, []);
      groups.get(cat).push(p);
    }

    for (const [category, list] of groups.entries()) {
      const sec = el("section", "hr-drawer-section");
      sec.append(el("h3", "hr-drawer-section-title", category));

      for (const p of list) {
        const card = el("div", "hr-drawer-card");
        const head = el("div", "hr-drawer-card-head");
        head.append(el("h4", "hr-drawer-card-title", p.title || "Prompt"));
        if (p.agentName || p.agentId) {
          head.append(el("span", "hr-card-tag", p.agentName || p.agentId));
        }
        card.append(head);

        if (p.description) {
          card.append(el("p", "hr-drawer-card-desc", p.description));
        }
        if (Array.isArray(p.tags) && p.tags.length > 0) {
          const chips = el("div", "hr-drawer-chips");
          for (const tag of p.tags) chips.append(el("span", "hr-drawer-chip", String(tag)));
          card.append(chips);
        }

        const actions = el("div", "hr-drawer-actions");
        const useBtn = el("button", "hr-button hr-button--outline", "Use");
        useBtn.type = "button";
        useBtn.disabled = !state.accessToken || state.busy;
        useBtn.addEventListener("click", () => {
          const input = $("chatInput");
          if (!input) return;
          input.value = p.prompt || "";
          lastAutofilledPrompt = "";
          const countEl = $("chatCount");
          if (countEl) countEl.textContent = String(input.value.length);
          autoResizeInput();
          updateControls();
          closeDrawer();
          input.focus();
        });

        const runBtn = el("button", "hr-button", "Run");
        runBtn.type = "button";
        runBtn.disabled = !state.accessToken || state.busy;
        runBtn.addEventListener("click", () => {
          if (!p.prompt) return;
          closeDrawer();
          sendMessage(p.prompt);
        });

        actions.append(useBtn, runBtn);
        card.append(actions);
        sec.append(card);
      }
      body.append(sec);
    }
  }

  function renderDrawerGuide(body) {
    const { GUIDE_SECTIONS } = getCatalog();
    for (const sec of GUIDE_SECTIONS) {
      if (!sec) continue;
      const card = el("section", "hr-drawer-card");
      const head = el("div", "hr-drawer-card-head");
      head.append(el("h4", "hr-drawer-card-title", sec.title || "Guide"));
      if (sec.badge) head.append(el("span", "hr-card-tag", sec.badge));
      card.append(head);

      if (sec.summary) card.append(el("p", "hr-drawer-card-desc", sec.summary));

      if (Array.isArray(sec.steps) && sec.steps.length > 0) {
        const ol = el("ol", "hr-guide-steps");
        for (const step of sec.steps) {
          ol.append(el("li", "", String(step)));
        }
        card.append(ol);
      }

      if (Array.isArray(sec.tips) && sec.tips.length > 0) {
        const tipsBox = el("div", "hr-guide-tips");
        tipsBox.textContent = `Tip: ${sec.tips.join(" · ")}`;
        card.append(tipsBox);
      } else if (typeof sec.tips === "string" && sec.tips) {
        const tipsBox = el("div", "hr-guide-tips");
        tipsBox.textContent = `Tip: ${sec.tips}`;
        card.append(tipsBox);
      }

      const actions = el("div", "hr-drawer-actions");
      if (sec.prompt && state.accessToken) {
        const tryBtn = el("button", "hr-button hr-button--outline", "Try example");
        tryBtn.type = "button";
        tryBtn.disabled = state.busy;
        tryBtn.addEventListener("click", () => {
          closeDrawer();
          sendMessage(sec.prompt);
        });
        actions.append(tryBtn);
      }
      if (sec.id === "prompts" || sec.id === "prompt-library" || sec.id === "marketplace-search-history") {
        const browseBtn = el("button", "hr-button hr-button--outline", "Open Prompts");
        browseBtn.type = "button";
        browseBtn.addEventListener("click", () => openDrawer("prompts"));
        actions.append(browseBtn);
      }
      if (sec.id === "marketplace" || sec.id === "agents" || sec.id === "marketplace-search-history") {
        const mktBtn = el("button", "hr-button hr-button--outline", "Open Marketplace");
        mktBtn.type = "button";
        mktBtn.addEventListener("click", () => openDrawer("marketplace"));
        actions.append(mktBtn);
      }
      if (sec.id === "god-bot-handover" && state.accessToken) {
        const tryLeaveBtn = el("button", "hr-button hr-button--outline", "Try handover");
        tryLeaveBtn.type = "button";
        tryLeaveBtn.disabled = state.busy;
        tryLeaveBtn.addEventListener("click", () => {
          closeDrawer();
          sendMessage("How many annual and sick leave days do I have remaining?");
        });
        actions.append(tryLeaveBtn);
      }
      if (actions.childElementCount > 0) card.append(actions);

      body.append(card);
    }
  }

  function renderDrawerMarketplace(body, query) {
    const { MARKETPLACE_AGENTS } = getCatalog();
    const filtered = MARKETPLACE_AGENTS.filter((agent) => {
      if (!agent) return false;
      if (!query) return true;
      const caps = Array.isArray(agent.capabilities) ? agent.capabilities.join(" ") : "";
      const hay = `${agent.name || ""} ${agent.category || ""} ${agent.badge || ""} ${agent.summary || ""} ${caps}`.toLowerCase();
      return hay.includes(query);
    });

    if (filtered.length === 0) {
      body.append(el("div", "hr-drawer-empty", "No agents match your search."));
      return;
    }

    for (const agent of filtered) {
      const card = el("div", "hr-drawer-card");
      const isActive = agent.id === state.activeAgentId;
      if (isActive) card.classList.add("is-active");

      const head = el("div", "hr-drawer-card-head");
      const titleWrap = el("div");
      const titleText = agent.icon ? `${agent.icon} · ${agent.name}` : agent.name;
      titleWrap.append(el("h4", "hr-drawer-card-title", titleText || agent.id));
      if (agent.category) titleWrap.append(el("div", "hr-drawer-card-meta", agent.category));

      const statusVariant = agent.status === "live" || agent.status === "active"
        ? "hr-card-tag--ok"
        : "hr-card-tag--pending";
      const badgeEl = el("span", `hr-card-tag ${statusVariant}`, agent.badge || agent.status || "Live");
      head.append(titleWrap, badgeEl);
      card.append(head);

      if (agent.summary) card.append(el("p", "hr-drawer-card-desc", agent.summary));

      if (Array.isArray(agent.capabilities) && agent.capabilities.length > 0) {
        const chips = el("div", "hr-drawer-chips");
        for (const cap of agent.capabilities) chips.append(el("span", "hr-drawer-chip", String(cap)));
        card.append(chips);
      }

      const actions = el("div", "hr-drawer-actions");
      const startBtn = el(
        "button",
        `hr-button${isActive ? " hr-button--outline" : ""}`,
        isActive ? "Active (New chat)" : "Start with this agent",
      );
      startBtn.type = "button";
      startBtn.disabled = !state.accessToken || state.busy;
      startBtn.addEventListener("click", () => selectMarketplaceAgent(agent.id));
      actions.append(startBtn);
      card.append(actions);

      body.append(card);
    }
  }

  function renderDrawerBody() {
    const body = $("rightDrawerBody");
    if (!body) return;
    body.replaceChildren();
    const query = (state.drawerQuery || "").trim().toLowerCase();

    if (state.drawerMode === "history") {
      renderDrawerHistory(body, query);
    } else if (state.drawerMode === "prompts") {
      renderDrawerPrompts(body, query);
    } else if (state.drawerMode === "guide") {
      renderDrawerGuide(body);
    } else if (state.drawerMode === "marketplace") {
      renderDrawerMarketplace(body, query);
    }
  }

  /* ------------------------------------------------------------- render */

  function showLoginError(message) {
    const errNode = $("loginError");
    if (!errNode) return;
    if (message) {
      errNode.textContent = String(message);
      errNode.hidden = false;
    } else {
      errNode.textContent = "";
      errNode.hidden = true;
    }
  }

  function syncWelcomeVisibility() {
    const welcome = $("welcomeState");
    const chatMessages = $("chatMessages");
    if (!welcome || !chatMessages) return;
    const hasMessages = chatMessages.childElementCount > 0;
    welcome.hidden = !state.accessToken || hasMessages;
  }

  function updateReviewBadge(count) {
    const badge = $("reviewCountBadge");
    if (!badge) return;
    const n = Math.max(0, Number(count) || 0);
    badge.textContent = String(n);
    badge.hidden = n === 0;
  }

  function renderIdentity() {
    const isAuthenticated = Boolean(state.accessToken);
    const loginScreen = $("loginScreen");
    const workspace = $("appWorkspace");
    const label = $("identityState");

    if (isAuthenticated) {
      showLoginError("");
      if (loginScreen) loginScreen.hidden = true;
      if (workspace) workspace.hidden = false;
      if (label) {
        label.textContent = state.userLabel;
        label.dataset.state = "signed-in";
      }
    } else {
      if (workspace) workspace.hidden = true;
      if (loginScreen) loginScreen.hidden = false;
      if (label) {
        label.textContent = "Not signed in";
        label.dataset.state = "unknown";
      }
      const signInBtn = $("signInBtn");
      if (signInBtn) {
        signInBtn.disabled = false;
        signInBtn.textContent = "Sign in";
      }
    }
    const footerSession = $("footerSession");
    if (footerSession) {
      footerSession.textContent = state.threadId
        ? `session · ${state.threadId}`
        : "session · —";
    }
    renderActiveAgentPill();
    syncWelcomeVisibility();
  }

  function updateControls() {
    const ready = Boolean(state.accessToken) && !state.busy;
    const refreshBtn = $("refreshReviewsBtn");
    const newChatBtn = $("newChatBtn");
    const sendBtn = $("chatSend");
    const chatInput = $("chatInput");
    const chatMessages = $("chatMessages");
    const signInBtn = $("signInBtn");
    const signOutBtn = $("signOutBtn");

    if (chatInput) chatInput.disabled = !ready;
    if (sendBtn) {
      sendBtn.disabled = !ready || !(chatInput && chatInput.value.trim());
      sendBtn.textContent = state.busy ? "Thinking…" : "Send";
      sendBtn.dataset.busy = state.busy ? "true" : "false";
    }
    if (signInBtn) signInBtn.disabled = state.busy;
    if (signOutBtn) signOutBtn.disabled = state.busy;
    if (refreshBtn) refreshBtn.disabled = !ready;
    if (newChatBtn) {
      const hasMessages = Boolean(chatMessages && chatMessages.childElementCount > 0);
      newChatBtn.disabled = !ready || !hasMessages;
    }
    for (const chip of document.querySelectorAll(".hr-starter-chip")) {
      chip.disabled = !ready;
    }
  }

  function appendMessage(role, text, meta, options = {}) {
    const message = el("div", `hr-message hr-message--${role}`);
    const avatar = el("div", "hr-avatar", role === "user" ? "You" : role === "error" ? "!" : "HR");
    avatar.setAttribute("aria-hidden", "true");
    const column = el("div");
    const stamp = formatTime(options.timestamp || new Date());
    const baseMeta = meta || (role === "user" ? "You" : "HR assistant");
    column.append(el("div", "hr-message-meta", stamp ? `${baseMeta} · ${stamp}` : baseMeta));

    const bodyNode = el("div", "hr-message-body");
    if (role === "assistant" && !options.plain && text) {
      bodyNode.append(renderMarkdownSafe(text));
    } else {
      bodyNode.textContent = text || "";
    }
    column.append(bodyNode);
    message.append(avatar, column);

    const messages = $("chatMessages");
    if (messages) {
      messages.append(message);
      messages.scrollTop = messages.scrollHeight;
    }
    syncWelcomeVisibility();

    if (options.recordHistory !== false && state.accessToken && !options.ephemeral) {
      state.currentMessages.push({
        role,
        text: text || "",
        meta: baseMeta,
        timestamp: options.timestamp || Date.now(),
        traces: [],
        cards: [],
      });
      saveCurrentThreadToHistory();
    }

    return message;
  }

  function appendTrace(node, kind, label, detailJson) {
    if (!node) return null;
    let trace = node.querySelector(".hr-trace");
    if (!trace) {
      trace = el("ul", "hr-trace");
      const lastCol = node.querySelector("div:last-child");
      if (lastCol) lastCol.append(trace);
    }
    const item = el("li", "hr-trace-item");
    item.dataset.kind = kind;
    const head = el("div", "hr-trace-head");
    head.append(el("span", "hr-trace-dot"), el("span", "hr-trace-label", label));
    item.append(head);
    if (detailJson !== undefined && detailJson !== null) {
      const toggle = el("button", "hr-trace-toggle", "Details");
      toggle.type = "button";
      const pre = el("pre", "hr-trace-detail");
      pre.hidden = true;
      pre.textContent = typeof detailJson === "string"
        ? detailJson
        : JSON.stringify(detailJson, null, 2);
      toggle.addEventListener("click", () => {
        pre.hidden = !pre.hidden;
        toggle.textContent = pre.hidden ? "Details" : "Hide";
      });
      head.append(toggle);
      item.append(pre);
    }
    trace.append(item);
    return item;
  }

  function renderMessages({ reset }) {
    const messages = $("chatMessages");
    if (reset && messages) messages.replaceChildren();
    syncWelcomeVisibility();
  }

  function applyA2uiMessages(messages) {
    if (!state.processor || !Array.isArray(messages) || messages.length === 0) return;
    state.processor.processMessages(messages);
  }

  /* ------------------------------------------------------------- SSE */

  function runtimeUrl() {
    return "/invocations";
  }

  async function pollPendingReviews({ manual = false } = {}) {
    if (state.busy || !state.accessToken || !state.threadId) return;
    state.busy = true;
    updateControls();
    state.runId = newId("run");
    const input = {
      threadId: state.threadId,
      runId: state.runId,
      messages: [],
      state: {},
      tools: [],
      context: [],
      forwardedProps: Object.assign({ checkPendingReviews: true }, rendererMetadata()),
    };
    try {
      await streamAgent(input);
    } catch (err) {
      if (manual && err && err.message !== "Session expired.") {
        appendMessage("error", explainError(err), "Review check failed", { ephemeral: true });
      }
    } finally {
      state.busy = false;
      updateControls();
    }
  }

  async function sendMessage(text) {
    if (state.busy || !state.accessToken) return;
    const message = (text || "").trim();
    if (!message) return;
    appendMessage("user", message);
    const chatInput = $("chatInput");
    const chatCount = $("chatCount");
    if (chatInput) chatInput.value = "";
    if (chatCount) chatCount.textContent = "0";
    lastAutofilledPrompt = "";
    state.busy = true;
    updateControls();
    resetBotActivityForTurn(message);
    state.runId = newId("run");
    const props = Object.assign(
      state.activeAgentId ? { activeAgentId: state.activeAgentId } : {},
      rendererMetadata(),
    );
    const input = {
      threadId: state.threadId,
      runId: state.runId,
      messages: [{ id: newId("msg"), role: "user", content: message }],
      state: {},
      tools: [],
      context: [],
      forwardedProps: props,
    };
    try {
      await streamAgent(input);
    } catch (err) {
      finalizeBotsOnFinish(false, true);
      appendMessage("error", explainError(err), "Transport error");
    } finally {
      state.busy = false;
      updateControls();
    }
  }

  function explainError(err) {
    const msg = err && err.message ? String(err.message) : "Unknown error.";
    if (/401|unauthor/i.test(msg)) return "The runtime rejected the token. Sign in again.";
    if (/network|fetch/i.test(msg)) return "Network error talking to the runtime. Is it deployed?";
    return msg;
  }

  /**
   * The A2UI renderer-side metadata the agent is entitled to see on its next
   * turn: capabilities (which catalogs we draw, which protocol version we
   * speak) and any renderer errors we have not yet shipped.
   */
  function rendererMetadata() {
    const out = {
      a2uiRendererCapabilities: state.processor
        ? state.processor.getRendererCapabilities()
        : null,
    };
    if (state.outboundErrors.length > 0) {
      out.a2uiRendererErrors = state.outboundErrors.splice(0, state.outboundErrors.length);
    }
    return out;
  }

  async function sendResume(resumePayload, interruptId) {
    if (state.busy || !state.accessToken) return false;
    state.busy = true;
    updateControls();
    resetBotActivityForTurn(
      resumePayload && resumePayload.kind === "manager_review"
        ? `Review decision (${resumePayload.decision || "submit"})`
        : `Confirmation (${(resumePayload && resumePayload.decision) || "submit"})`,
    );
    state.runId = newId("run");
    const input = {
      threadId: state.threadId,
      runId: state.runId,
      messages: [],
      state: {},
      tools: [],
      context: [],
      forwardedProps: Object.assign(
        {
          resume: [resumePayload],
          command: { resume: resumePayload },
        },
        rendererMetadata(),
      ),
    };
    if (interruptId) {
      input.resume = [{
        interruptId,
        status: "resolved",
        payload: resumePayload,
      }];
    }
    try {
      const outcome = await streamAgent(input);
      return !(outcome && outcome.sawRunError && !outcome.sawRunFinished);
    } catch (err) {
      finalizeBotsOnFinish(false, true);
      appendMessage("error", explainError(err), "Transport error");
      return false;
    } finally {
      state.busy = false;
      updateControls();
    }
  }

  function getSubagentRunId(event) {
    return (
      event.subagentRunId
      || event.subagent_run_id
      || (event.metadata && (event.metadata.subagentRunId || event.metadata.subagent_run_id))
      || null
    );
  }

  function summarizeToolResult(toolName, result) {
    if (!result || typeof result !== "object") return "Completed";
    if (result.authorized === false) {
      const lbl = window.HrToolAdapter.reasonLabel(result.reason_code);
      return result.reason_code ? `Denied · ${lbl}` : "Denied";
    }
    const bare = bareToolName(toolName);
    const d = result.data || {};
    if (bare === "get_leave_balance") {
      return `Annual ${d.annual ?? "—"}d · Sick ${d.sick ?? "—"}d`;
    }
    if (bare === "get_allowance") {
      return d.amount == null ? "No entry" : `${d.amount} ${d.currency || ""}`.trim();
    }
    if (bare === "list_direct_reports") {
      const count = Array.isArray(d.reports) ? d.reports.length : 0;
      return `${count} direct report${count === 1 ? "" : "s"}`;
    }
    if (bare === "check_leave_eligibility") {
      return d.eligible ? `Eligible (${d.days ?? "—"}d)` : "Checked";
    }
    if (bare === "submit_leave_request") {
      return d.request_id ? `Pending ${d.request_id}` : "Submitted";
    }
    if (bare === "record_leave_decision") {
      return d.status ? `Decision: ${d.status}` : "Recorded";
    }
    if (bare === "get_employee_compensation") {
      return d.base_salary != null ? `${d.base_salary} ${d.currency || ""}`.trim() : "Authorized";
    }
    return "Completed";
  }

  async function streamAgent(input, _retriedAfterRefresh) {
    if (state.sseController) state.sseController.abort();
    state.sseController = new AbortController();
    const res = await fetch(runtimeUrl(), {
      method: "POST",
      signal: state.sseController.signal,
      headers: {
        Authorization: `Bearer ${state.accessToken}`,
        "Content-Type": "application/json",
        Accept: "text/event-stream",
        "X-Amzn-Bedrock-AgentCore-Runtime-Session-Id": state.threadId,
        "X-Amzn-Trace-Id": newXrayTraceId(),
      },
      body: JSON.stringify(input),
    });
    if (res.status === 401 || res.status === 403) {
      let bodyErr = "";
      try {
        const errJson = await res.clone().json();
        bodyErr = String((errJson && errJson.error) || "");
      } catch { /* ignore non-json */ }
      const isTokenRejection = res.status === 401 || /Runtime returned HTTP 403/i.test(bodyErr);
      if (isTokenRejection) {
        if (!_retriedAfterRefresh && state.refreshToken) {
          const refreshed = await refreshEstablishedSession(state.refreshToken);
          if (refreshed) {
            return streamAgent(input, true);
          }
        }
        clearLocalState();
        showLoginError("Your session expired or was rejected. Please sign in again.");
        throw new Error("Session expired.");
      }
    }
    if (!res.ok) throw new Error(`Runtime HTTP ${res.status}`);
    if (!res.body) throw new Error("Runtime returned no body.");

    const reader = res.body.getReader();
    const decoder = new TextDecoder();
    let buffer = "";
    let read = 0;
    const isSilentPoll = Boolean(input.forwardedProps && input.forwardedProps.checkPendingReviews);
    const assistantNode = appendMessage(
      "assistant",
      isSilentPoll ? "" : "Thinking…",
      "HR assistant",
      { recordHistory: false, plain: true },
    );
    if (!isSilentPoll) assistantNode.dataset.thinking = "true";
    const body = assistantNode.querySelector(".hr-message-body");

    const turnCtx = {
      isSilentPoll,
      assistantNode,
      body,
      receivedRootDelta: false,
      rootText: "",
      activeRootMessageId: null,
      subagentTexts: new Map(),
      lastSubagentRunId: null,
      subagentBotMap: new Map(),
      outstanding: new Map(),
      pendingStartTraces: new Map(),
      seenToolResults: new Set(),
      traces: [],
      cards: [],
      sawRunFinished: false,
      sawRunError: false,
      sawInterrupt: false,
    };

    const clearThinkingPlaceholder = () => {
      if (assistantNode.dataset.thinking === "true") {
        delete assistantNode.dataset.thinking;
        if (!turnCtx.receivedRootDelta) body.textContent = "";
      }
    };
    turnCtx.clearThinkingPlaceholder = clearThinkingPlaceholder;

    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      read += value.byteLength;
      if (read > MAX_RESPONSE_BYTES) {
        throw new Error("Runtime response exceeded safety limit.");
      }
      buffer += decoder.decode(value, { stream: true });
      let newlineIndex;
      while ((newlineIndex = buffer.indexOf("\n")) !== -1) {
        const line = buffer.slice(0, newlineIndex).trimEnd();
        buffer = buffer.slice(newlineIndex + 1);
        if (!line.startsWith("data:")) continue;
        let event;
        try {
          event = JSON.parse(line.slice(5).trim());
        } catch { continue; }
        handleEvent(event, turnCtx);
      }
    }

    clearThinkingPlaceholder();

    // Fallback safety: if stream ended with zero root text AND captured subagent text exists,
    // display the last subagent text so the reply is never blank.
    let finalText = turnCtx.rootText;
    if (!finalText.trim() && turnCtx.subagentTexts.size > 0) {
      let fallback = "";
      if (turnCtx.lastSubagentRunId && turnCtx.subagentTexts.has(turnCtx.lastSubagentRunId)) {
        fallback = turnCtx.subagentTexts.get(turnCtx.lastSubagentRunId) || "";
      }
      if (!fallback.trim()) {
        for (const txt of turnCtx.subagentTexts.values()) {
          if (txt && txt.trim()) fallback = txt;
        }
      }
      if (fallback.trim()) {
        finalText = fallback;
        body.replaceChildren(renderMarkdownSafe(finalText));
      }
    }

    if (!turnCtx.sawRunFinished && !turnCtx.sawRunError && !isSilentPoll) {
      finalizeBotsOnFinish(turnCtx.sawInterrupt, false);
    }

    const hasTrace = Boolean(assistantNode.querySelector(".hr-trace"));
    if (!finalText.trim() && !hasTrace && turnCtx.cards.length === 0) {
      assistantNode.remove();
      syncWelcomeVisibility();
    } else if (!isSilentPoll || hasTrace || finalText.trim() || turnCtx.cards.length > 0) {
      state.currentMessages.push({
        role: "assistant",
        text: finalText,
        meta: "HR assistant",
        timestamp: Date.now(),
        traces: turnCtx.traces,
        cards: turnCtx.cards,
      });
      saveCurrentThreadToHistory();
    }

    return {
      sawRunFinished: turnCtx.sawRunFinished,
      sawRunError: turnCtx.sawRunError,
      sawInterrupt: turnCtx.sawInterrupt,
    };
  }

  function handleEvent(event, turnCtx) {
    if (!event || typeof event !== "object") return;
    const kind = event.type;
    const subagentRunId = getSubagentRunId(event);
    const messagesEl = $("chatMessages");

    switch (kind) {
      case "SUBAGENT_STARTED": {
        const sId = event.subagentRunId || event.subagent_run_id || subagentRunId;
        const botId = resolveBotId(event.name, event.description);
        if (sId && botId) {
          turnCtx.subagentBotMap.set(String(sId), botId);
        }
        if (botId) {
          setBotActivity(botId, {
            status: "active",
            task: truncateText(event.description || event.name || "Running…", 80),
          });
          pushHandoverStep(botId);
          if (turnCtx.assistantNode.dataset.thinking === "true" && !turnCtx.receivedRootDelta) {
            turnCtx.body.textContent = `Routing via ${state.activeHandoverChain.map(displayBotLabel).join(" → ")}…`;
          }
        }
        break;
      }
      case "SUBAGENT_FINISHED": {
        const sId = event.subagentRunId || event.subagent_run_id || subagentRunId;
        const botId = sId ? turnCtx.subagentBotMap.get(String(sId)) : null;
        if (botId) {
          const outcomeType = event.outcome && event.outcome.type;
          const prev = state.botActivity[botId] || {};
          const nextStatus = (outcomeType === "suspended" || outcomeType === "interrupt")
            ? "paused"
            : (prev.status === "denied" || prev.status === "error" ? prev.status : "done");
          setBotActivity(botId, {
            status: nextStatus,
            snippet: event.result ? truncateText(String(event.result), 140) : prev.snippet,
          });
        }
        break;
      }
      case "SUBAGENT_ERROR": {
        const sId = event.subagentRunId || event.subagent_run_id || subagentRunId;
        const botId = sId ? turnCtx.subagentBotMap.get(String(sId)) : null;
        if (botId) {
          setBotActivity(botId, {
            status: "error",
            task: truncateText(event.message || "Subagent error", 80),
          });
        }
        break;
      }
      case "TEXT_MESSAGE_START": {
        if (!subagentRunId && event.messageId) {
          if (
            turnCtx.activeRootMessageId
            && turnCtx.activeRootMessageId !== event.messageId
            && turnCtx.rootText.trim()
            && !turnCtx.rootText.endsWith("\n")
          ) {
            turnCtx.rootText += "\n\n";
          }
          turnCtx.activeRootMessageId = event.messageId;
        }
        break;
      }
      case "TEXT_MESSAGE_CONTENT": {
        const delta = typeof event.delta === "string" ? event.delta : "";
        if (!delta) break;
        if (subagentRunId) {
          const key = String(subagentRunId);
          const prevTxt = turnCtx.subagentTexts.get(key) || "";
          const nextTxt = prevTxt + delta;
          turnCtx.subagentTexts.set(key, nextTxt);
          turnCtx.lastSubagentRunId = key;
          const botId = turnCtx.subagentBotMap.get(key);
          if (botId) {
            setBotActivity(botId, { snippet: truncateText(nextTxt, 140) });
          }
          break;
        }
        turnCtx.clearThinkingPlaceholder();
        turnCtx.receivedRootDelta = true;
        turnCtx.rootText += delta;
        turnCtx.body.replaceChildren(renderMarkdownSafe(turnCtx.rootText));
        if (messagesEl) messagesEl.scrollTop = messagesEl.scrollHeight;
        break;
      }
      case "TOOL_CALL_START": {
        turnCtx.clearThinkingPlaceholder();
        const callId = event.toolCallId ? String(event.toolCallId) : "";
        const callName = event.toolCallName ? String(event.toolCallName) : "";
        if (callId && callName) {
          turnCtx.outstanding.set(callId, { name: callName, subagentRunId });
          if (callName === "task") {
            const parentBotId = subagentRunId
              ? (turnCtx.subagentBotMap.get(String(subagentRunId)) || "god-bot")
              : "god-bot";
            const currentParent = state.botActivity[parentBotId];
            if (!currentParent || currentParent.status !== "active") {
              setBotActivity(parentBotId, { status: "active", task: "Delegating task…" });
            }
          } else {
            const leafBotId = resolveBotId(null, callName);
            if (leafBotId) {
              setBotActivity(leafBotId, {
                status: "active",
                task: `Calling ${bareToolName(callName)}…`,
              });
              pushHandoverStep(leafBotId);
            }
          }
          const traceItem = appendTrace(turnCtx.assistantNode, "info", `tool · ${callName}`);
          if (traceItem) turnCtx.pendingStartTraces.set(callId, traceItem);
        }
        break;
      }
      case "TOOL_CALL_RESULT": {
        turnCtx.clearThinkingPlaceholder();
        const id = event.toolCallId ? String(event.toolCallId) : "";
        const tracked = turnCtx.outstanding.get(id);
        const name = (tracked && tracked.name) || event.toolCallName || "tool";
        turnCtx.outstanding.delete(id);

        const result = parseToolResult(event.content);
        const dedupeSerialized = result !== null
          ? stableStringify(result)
          : String(event.content ?? "");
        const dedupeKey = `${bareToolName(name)}\0${dedupeSerialized}`;

        const pendingStartNode = turnCtx.pendingStartTraces.get(id);
        turnCtx.pendingStartTraces.delete(id);

        if (turnCtx.seenToolResults.has(dedupeKey)) {
          if (pendingStartNode && pendingStartNode.parentNode) {
            pendingStartNode.remove();
          }
          break;
        }
        turnCtx.seenToolResults.add(dedupeKey);

        const leafBotId = resolveBotId(null, name);
        if (leafBotId && name !== "task") {
          const denied = result && result.authorized === false;
          const summary = summarizeToolResult(name, result);
          setBotActivity(leafBotId, {
            status: denied ? "denied" : "done",
            task: summary,
            snippet: summary,
          });
          pushHandoverStep(leafBotId);
        }

        const a2uiMessages = window.HrToolAdapter.fromToolResult(name, result);
        applyA2uiMessages(a2uiMessages);
        const persistableCards = sanitizeHistoryCards(a2uiMessages);
        if (persistableCards.length > 0) {
          turnCtx.cards.push(...persistableCards);
        }

        const traceKind = result && result.authorized === false ? "deny"
          : result && result.authorized === true ? "allow" : "info";
        const tag = result && result.reason_code ? ` · ${result.reason_code}` : "";
        const label = `result · ${name}${tag}`;
        appendTrace(turnCtx.assistantNode, traceKind, label, result);
        turnCtx.traces.push({ kind: traceKind, label, detail: result });
        break;
      }
      case "TOOL_CALL_END": break;
      case "RUN_STARTED": break;
      case "RUN_FINISHED": {
        turnCtx.clearThinkingPlaceholder();
        turnCtx.sawRunFinished = true;
        const hasInterrupt = handleRunFinished(event, turnCtx.isSilentPoll);
        turnCtx.sawInterrupt = hasInterrupt;
        if (!turnCtx.isSilentPoll) {
          finalizeBotsOnFinish(hasInterrupt, false);
        } else if (hasInterrupt) {
          setBotActivity("review-node", { status: "paused", task: "Pending manager review" });
          pushHandoverStep("review-node");
        }
        break;
      }
      case "RUN_ERROR": {
        turnCtx.clearThinkingPlaceholder();
        turnCtx.sawRunError = true;
        finalizeBotsOnFinish(false, true);
        const message = event.message || event.code || "Runtime error.";
        appendMessage("error", String(message), "Runtime error");
        break;
      }
      default: break;
    }
  }

  function parseToolResult(content) {
    if (content == null) return null;
    if (typeof content === "object") return content;
    if (typeof content !== "string") return null;
    try { return JSON.parse(content); }
    catch { return null; }
  }

  function _extractInterruptEntries(outcome) {
    if (!outcome || outcome.type !== "interrupt") return [];
    if (Array.isArray(outcome.interrupts) && outcome.interrupts.length > 0) {
      return outcome.interrupts
        .map((item) => {
          if (!item || typeof item !== "object") return null;
          const raw = item.metadata && item.metadata.langgraph && item.metadata.langgraph.raw
            ? item.metadata.langgraph.raw
            : (item.value || item.payload || null);
          if (!raw || typeof raw !== "object") return null;
          return { id: item.id || null, payload: raw };
        })
        .filter(Boolean);
    }
    const fallback = outcome.value || outcome.payload || outcome.data;
    if (fallback && typeof fallback === "object") {
      return [{ id: fallback.id || null, payload: fallback }];
    }
    return [];
  }

  function reviewKeyFor(payload, interruptId) {
    const raw = (payload && payload.request_id) || interruptId || (payload && payload.interrupt_id) || "";
    return String(raw).trim() || newId("rev");
  }

  function handleRunFinished(event, isSilentPoll = false) {
    const entries = _extractInterruptEntries(event && event.outcome);
    if (entries.length === 0) {
      if (isSilentPoll) {
        for (const [key] of [...state.pendingManagerReviews.entries()]) {
          state.pendingManagerReviews.delete(key);
          applyA2uiMessages(window.HrToolAdapter.clearSurfacesFor("manager_review", key));
        }
        applyA2uiMessages(window.HrToolAdapter.clearSurfacesFor("manager_review"));
        updateReviewBadge(0);
      }
      return false;
    }

    const reviewEntries = entries.filter((e) => e.payload && e.payload.kind === "manager_review");
    if (isSilentPoll) {
      const activeKeys = new Set(
        reviewEntries.map((e) => reviewKeyFor(e.payload, e.id)),
      );
      for (const [key] of [...state.pendingManagerReviews.entries()]) {
        if (!activeKeys.has(key)) {
          state.pendingManagerReviews.delete(key);
          applyA2uiMessages(window.HrToolAdapter.clearSurfacesFor("manager_review", key));
        }
      }
    }

    for (const entry of entries) {
      const payload = entry.payload;
      if (payload.kind === "manager_review") {
        const key = reviewKeyFor(payload, entry.id);
        const stored = Object.assign({}, payload, {
          _interruptId: entry.id || null,
          _reviewKey: key,
        });
        state.pendingManagerReviews.set(key, stored);
        applyA2uiMessages(window.HrToolAdapter.fromInterrupt(stored));
      } else if (payload.kind === "employee_confirm") {
        state.pendingEmployeeConfirm = Object.assign({}, payload, {
          _interruptId: entry.id || null,
        });
        const messages = window.HrToolAdapter.fromInterrupt(payload);
        if (messages.length > 0) applyA2uiMessages(messages);
      } else {
        appendMessage("system",
          `Review pause received for ${String(payload.kind || "unknown")}. Use the card to decide.`,
          "Interrupt");
      }
    }
    updateReviewBadge(state.pendingManagerReviews.size);
    return true;
  }

  /* ------------------------------------------------- A2UI action router */

  /**
   * The ONLY path by which a decision leaves the browser. A free-text chat
   * message that says "approve" does not get here: it goes through
   * ``sendMessage`` to the agent as plain user text, which is governed by
   * Cedar and the gateway tool policy — none of which trust the chat.
   */
  function handleRendererMessage(message) {
    if (!message || typeof message !== "object") return;
    if (message.error) {
      state.outboundErrors.push(message);
      return;
    }
    if (!message.action) return;
    const action = message.action;
    const name = action.name;
    const ctx = action.context || {};
    if (name === "employee_confirm_leave") {
      onEmployeeConfirm(ctx);
      return;
    }
    if (name === "employee_reject_leave") {
      onEmployeeReject(ctx);
      return;
    }
    if (name === "employee_edit_leave") {
      onEmployeeEdit(ctx);
      return;
    }
    if (name === "manager_approve_review") {
      onManagerApprove(ctx);
      return;
    }
    if (name === "manager_reject_review") {
      onManagerReject(ctx);
      return;
    }
  }

  function validateDateRange(start, end) {
    if (!start || !end) return "Start and end dates are required.";
    const a = Date.parse(`${start}T00:00:00Z`);
    const b = Date.parse(`${end}T00:00:00Z`);
    if (Number.isNaN(a) || Number.isNaN(b)) return "Dates must be ISO calendar dates.";
    if (b < a) return "End date must be on or after the start date.";
    return null;
  }

  function restoreEmployeeConfirmIfNeeded(savedInterrupt) {
    if (!savedInterrupt || !state.accessToken || state.pendingEmployeeConfirm) return;
    state.pendingEmployeeConfirm = savedInterrupt;
    const messages = window.HrToolAdapter.fromInterrupt(savedInterrupt);
    if (messages.length > 0) applyA2uiMessages(messages);
  }

  async function onEmployeeConfirm(ctx) {
    const interrupt = state.pendingEmployeeConfirm;
    if (!interrupt || interrupt.kind !== "employee_confirm") return;
    const proposed = interrupt.arguments || interrupt.proposed || interrupt;
    const merged = {
      ...proposed,
      start_date: ctx.start_date || proposed.start_date,
      end_date: ctx.end_date || proposed.end_date,
      leave_type: ctx.leave_type || proposed.leave_type,
      reason: ctx.reason != null ? ctx.reason : proposed.reason,
    };
    const idempotencyKey = proposed.idempotency_key || interrupt.idempotency_key;
    if (idempotencyKey) merged.idempotency_key = idempotencyKey;

    const err = validateDateRange(merged.start_date, merged.end_date);
    if (err) {
      appendMessage("error", err, "Invalid range");
      return;
    }
    const interruptId = interrupt._interruptId || null;
    const savedInterrupt = interrupt;
    state.pendingEmployeeConfirm = null;
    applyA2uiMessages(window.HrToolAdapter.clearSurfacesFor("employee_confirm"));
    const ok = await sendResume({
      decision: "approve",
      kind: "employee_confirm",
      arguments: merged,
    }, interruptId);
    if (!ok) {
      restoreEmployeeConfirmIfNeeded(savedInterrupt);
    }
  }

  async function onEmployeeReject(_ctx) {
    const interrupt = state.pendingEmployeeConfirm;
    if (!interrupt || interrupt.kind !== "employee_confirm") return;
    const interruptId = interrupt._interruptId || null;
    const savedInterrupt = interrupt;
    const proposed = interrupt.arguments || interrupt.proposed || interrupt;
    const resumePayload = { decision: "reject", kind: "employee_confirm" };
    const idempotencyKey = proposed.idempotency_key || interrupt.idempotency_key;
    if (idempotencyKey) resumePayload.idempotency_key = idempotencyKey;

    state.pendingEmployeeConfirm = null;
    applyA2uiMessages(window.HrToolAdapter.clearSurfacesFor("employee_confirm"));
    const ok = await sendResume(resumePayload, interruptId);
    if (ok) {
      appendMessage("system", "You declined to submit this request.", "No request");
    } else {
      restoreEmployeeConfirmIfNeeded(savedInterrupt);
    }
  }

  async function onEmployeeEdit(ctx) {
    const interrupt = state.pendingEmployeeConfirm;
    if (!interrupt || interrupt.kind !== "employee_confirm") return;
    const interruptId = interrupt._interruptId || null;
    const savedInterrupt = interrupt;
    const proposed = interrupt.arguments || interrupt.proposed || interrupt;
    const nextStart = String(ctx.start_date || proposed.start_date || "").trim();
    const nextEnd = String(ctx.end_date || proposed.end_date || "").trim();
    const nextType = String(ctx.leave_type || proposed.leave_type || "annual").trim();
    const err = validateDateRange(nextStart, nextEnd);
    if (err) {
      appendMessage("error", err, "Invalid range");
      return;
    }
    const edited = {
      ...proposed,
      leave_type: nextType,
      start_date: nextStart,
      end_date: nextEnd,
      reason: ctx.reason != null ? ctx.reason : proposed.reason,
    };
    const idempotencyKey = proposed.idempotency_key || interrupt.idempotency_key;
    if (idempotencyKey) edited.idempotency_key = idempotencyKey;

    state.pendingEmployeeConfirm = null;
    applyA2uiMessages(window.HrToolAdapter.clearSurfacesFor("employee_confirm"));
    const ok = await sendResume({ decision: "edit", kind: "employee_confirm", arguments: edited }, interruptId);
    if (!ok) {
      restoreEmployeeConfirmIfNeeded(savedInterrupt);
    }
  }

  async function submitManagerReviewDecision(ctx, decision) {
    const requestId = ctx.request_id ? String(ctx.request_id) : "";
    let reviewKey = requestId;
    if (!reviewKey && state.pendingManagerReviews.size === 1) {
      reviewKey = state.pendingManagerReviews.keys().next().value;
    }
    let interrupt = reviewKey ? state.pendingManagerReviews.get(reviewKey) : null;
    if (!interrupt && requestId) {
      for (const [k, item] of state.pendingManagerReviews.entries()) {
        if (item && (item.request_id === requestId || item._interruptId === requestId)) {
          reviewKey = k;
          interrupt = item;
          break;
        }
      }
    }
    if (!interrupt || interrupt.kind !== "manager_review") return;

    const effectiveRequestId = requestId || interrupt.request_id || "";
    const interruptId = interrupt._interruptId || null;
    const effectiveKey = interrupt._reviewKey || reviewKey;
    state.pendingManagerReviews.delete(effectiveKey);
    updateReviewBadge(state.pendingManagerReviews.size);
    applyA2uiMessages(window.HrToolAdapter.clearSurfacesFor("manager_review", effectiveKey));
    // The runtime checks the reviewer's verified token against
    // reviewer_employee_id before recording the decision. A forged
    // resume from the dev console fails with NOT_REVIEWER.
    const ok = await sendResume({
      decision,
      kind: "manager_review",
      request_id: effectiveRequestId,
    }, interruptId);
    if (!ok && state.accessToken && !state.pendingManagerReviews.has(effectiveKey)) {
      state.pendingManagerReviews.set(effectiveKey, interrupt);
      updateReviewBadge(state.pendingManagerReviews.size);
      applyA2uiMessages(window.HrToolAdapter.fromInterrupt(interrupt));
    }
  }

  async function onManagerApprove(ctx) {
    await submitManagerReviewDecision(ctx, "approve");
  }

  async function onManagerReject(ctx) {
    await submitManagerReviewDecision(ctx, "reject");
  }

  /* ------------------------------------------------------------- init */

  async function loadCatalog() {
    const res = await fetch("hr-catalog.json", { cache: "no-store" });
    if (!res.ok) throw new Error(`hr-catalog.json HTTP ${res.status}`);
    const doc = await res.json();
    if (doc.protocolVersion && doc.protocolVersion !== window.A2UI.PROTOCOL_VERSION) {
      throw new Error(
        `hr-catalog.json pins A2UI ${doc.protocolVersion} but this `
        + `renderer speaks ${window.A2UI.PROTOCOL_VERSION}.`,
      );
    }
    return window.HrCatalog.build(doc);
  }

  async function start() {
    purgeLegacyPersistentStorage();
    injectFallbackStyles();
    const { MARKETPLACE_AGENTS } = getCatalog();
    if (MARKETPLACE_AGENTS.length > 0) {
      state.activeAgentId = MARKETPLACE_AGENTS[0].id || "hr-assistant";
    }
    renderBotRoster();
    renderHandoverStatus();
    renderWelcomeForActiveAgent(null);
    updateReviewBadge(0);

    try {
      await loadConfig();
    } catch (err) {
      showLoginError(`hr-web could not load /config.json: ${err.message}`);
      return;
    }
    let catalog;
    try {
      catalog = await loadCatalog();
    } catch (err) {
      showLoginError(`hr-web could not load hr-catalog.json: ${err.message}`);
      return;
    }
    state.processor = new window.A2UI.MessageProcessor({
      catalog,
      root: $("hrSurfaces"),
      protocolVersion: state.config.a2ui_protocol_version,
      onRendererMessage: handleRendererMessage,
    });
    const params = new URLSearchParams(location.search);
    const code = params.get("code");
    const returnedState = params.get("state");
    const authErr = params.get("error_description") || params.get("error");
    if (authErr) {
      history.replaceState(null, "", REDIRECT_URI);
      renderIdentity();
      updateControls();
      showLoginError(`Sign-in failed: ${authErr}`);
      return;
    }
    if (code) {
      const signInBtn = $("signInBtn");
      if (signInBtn) {
        signInBtn.disabled = true;
        signInBtn.textContent = "Signing in…";
      }
      try {
        await completeSignIn(code, returnedState);
        history.replaceState(null, "", REDIRECT_URI);
        renderIdentity();
        renderBotRoster();
        renderWelcomeForActiveAgent(null);
        updateControls();
        if ($("chatInput")) $("chatInput").focus();
        await pollPendingReviews({ manual: false });
        return;
      } catch (err) {
        history.replaceState(null, "", REDIRECT_URI);
        renderIdentity();
        updateControls();
        showLoginError(err.message);
        return;
      }
    }

    // No OAuth callback in URL: tokens are never persisted across restarts,
    // so show the Login screen until the user signs in via PKCE.
    renderIdentity();
    renderBotRoster();
    renderWelcomeForActiveAgent(null);
    updateControls();
  }

  /* ------------------------------------------------------------- wire-up */

  function autoResizeInput() {
    const input = $("chatInput");
    if (!input) return;
    input.style.height = "auto";
    input.style.height = `${Math.min(Math.max(input.scrollHeight, 54), 180)}px`;
  }

  if ($("signInBtn")) {
    $("signInBtn").addEventListener("click", async () => {
      const btn = $("signInBtn");
      const prevText = btn.textContent;
      showLoginError("");
      btn.disabled = true;
      btn.textContent = "Redirecting…";
      try {
        await beginSignIn();
      } catch (err) {
        btn.disabled = false;
        btn.textContent = prevText;
        showLoginError(err.message);
      }
    });
  }
  if ($("signOutBtn")) {
    $("signOutBtn").addEventListener("click", () => { signOut(); });
  }
  if ($("newChatBtn")) {
    $("newChatBtn").addEventListener("click", startNewChat);
  }
  if ($("refreshReviewsBtn")) {
    $("refreshReviewsBtn").addEventListener("click", () => {
      pollPendingReviews({ manual: true });
    });
  }
  if ($("openMarketplaceFromLeft")) {
    $("openMarketplaceFromLeft").addEventListener("click", () => openDrawer("marketplace"));
  }
  if ($("closeRightDrawerBtn")) {
    $("closeRightDrawerBtn").addEventListener("click", closeDrawer);
  }
  if ($("rightDrawerSearch")) {
    $("rightDrawerSearch").addEventListener("input", (e) => {
      state.drawerQuery = e.target.value || "";
      renderDrawerBody();
    });
  }

  // Event delegation for topbar drawer icons AND quick tabs inside #rightDrawer
  document.addEventListener("click", (e) => {
    const trigger = e.target && e.target.closest ? e.target.closest("[data-drawer]") : null;
    if (!trigger) return;
    const mode = trigger.dataset.drawer;
    if (!mode) return;
    const insideDrawer = Boolean(trigger.closest("#rightDrawer"));
    if (!insideDrawer && state.drawerOpen && state.drawerMode === mode) {
      closeDrawer();
    } else {
      openDrawer(mode);
    }
  });

  // Event delegation for starter prompt chips (supports dynamic Marketplace/Bot starters)
  if ($("starterPrompts")) {
    $("starterPrompts").addEventListener("click", (e) => {
      const chip = e.target && e.target.closest ? e.target.closest(".hr-starter-chip") : null;
      if (!chip || chip.disabled) return;
      const promptText = chip.dataset.prompt || "";
      if (promptText) sendMessage(promptText);
    });
  }

  if ($("chatForm")) {
    $("chatForm").addEventListener("submit", (e) => {
      e.preventDefault();
      if ($("chatInput")) sendMessage($("chatInput").value);
      autoResizeInput();
    });
  }
  if ($("chatInput")) {
    $("chatInput").addEventListener("input", (e) => {
      if ($("chatCount")) $("chatCount").textContent = String(e.target.value.length);
      autoResizeInput();
      updateControls();
    });
    $("chatInput").addEventListener("keydown", (e) => {
      if (e.key === "Enter" && !e.shiftKey) {
        e.preventDefault();
        if ($("chatForm")) $("chatForm").requestSubmit();
        return;
      }
      if (
        e.key === "/"
        && !e.ctrlKey
        && !e.metaKey
        && !e.altKey
        && !e.shiftKey
        && e.target.value === ""
      ) {
        e.preventDefault();
        openDrawer("prompts");
        if ($("rightDrawerSearch")) $("rightDrawerSearch").focus();
      }
    });
  }

  document.addEventListener("keydown", (e) => {
    if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") {
      if (!state.accessToken) return;
      e.preventDefault();
      if (state.drawerOpen && state.drawerMode === "prompts") {
        closeDrawer();
      } else {
        openDrawer("prompts");
        if ($("rightDrawerSearch")) $("rightDrawerSearch").focus();
      }
      return;
    }
    if (e.key === "Escape" && state.drawerOpen) {
      closeDrawer();
    }
  });

  start();
})();
