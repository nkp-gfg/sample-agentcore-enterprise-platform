/* hr-web — the Layer 3 facilitator UI.
 *
 * Responsibilities, in order:
 *   1. Load /config.json from the local server.
 *   2. Do the Cognito hosted-UI PKCE flow in the browser, with tokens held in
 *      memory only. Signing out clears them and drops the stored thread.
 *   3. Open an AG-UI SSE stream to the module 6 runtime with that Bearer
 *      token, parse the events, render assistant text, and raise the tool-
 *      result cards documented in docs/hr/tools.md and the review cards
 *      documented in custom-app-plan/human-review.md.
 *   4. Gate `submit_leave_request` behind the employee confirmation card and
 *      `record_leave_decision` behind the manager review card. Typing
 *      "approve" in the chat does nothing: only the card's button posts the
 *      AG-UI `resume` list.
 *
 * Nothing in this file talks to AWS SDKs. The browser fetches openid-
 * configuration from the Cognito issuer URL and POSTs the AG-UI RunAgentInput
 * to the runtime directly, with the user's access token.
 */

(() => {
  "use strict";

  /* ------------------------------------------------------------- constants */

  // The redirect URI must match a callback URL registered on the Cognito
  // web client. The Layer 3 README documents this requirement.
  const REDIRECT_URI = `${location.protocol}//${location.host}/`;
  const SCOPES = ["openid", "email", "profile"];

  const STORAGE_KEYS = Object.freeze({
    verifier: "hr-web.pkce.verifier",
    state: "hr-web.pkce.state",
    discovery: "hr-web.oidc.discovery",
  });

  const PROMPT_MAX = 4000;
  const MAX_RESPONSE_BYTES = 2 * 1024 * 1024;

  /* --------------------------------------------------------------- state */

  const state = {
    config: null,        // PublicConfig from /config.json
    discovery: null,     // openid-configuration fetched once per sign-in
    accessToken: null,   // kept in memory only
    idClaims: null,
    userLabel: "",
    threadId: null,
    runId: null,
    busy: false,
    pendingInterrupt: null,  // the open review payload, or null
    sseController: null,     // AbortController for the current stream
  };

  /* ------------------------------------------------------------- helpers */

  const $ = (id) => document.getElementById(id);
  const el = (tag, cls, text) => {
    const n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text !== undefined) n.textContent = text;
    return n;
  };
  const show = (id) => { $(id).hidden = false; };
  const hide = (id) => { $(id).hidden = true; };

  function newId(prefix) {
    const c = window.crypto;
    if (!c) throw new Error("Browser cryptography is required.");
    const bytes = new Uint8Array(16);
    c.getRandomValues(bytes);
    return `${prefix}-${Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("")}`;
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

  /* ------------------------------------------------------------- config */

  async function loadConfig() {
    const res = await fetch("/config.json", { cache: "no-store" });
    if (!res.ok) throw new Error(`config.json HTTP ${res.status}`);
    const data = await res.json();
    for (const key of ["runtime_arn", "region", "web_client_id", "issuer_url", "gateway_url"]) {
      if (typeof data[key] !== "string" || !data[key]) {
        throw new Error(`config.json is missing ${key}`);
      }
    }
    state.config = Object.freeze({ ...data });
  }

  async function loadDiscovery() {
    // OIDC discovery lets the browser find the Cognito hosted-UI auth and
    // token endpoints without the server shipping the hosted-UI domain.
    const cached = sessionStorage.getItem(STORAGE_KEYS.discovery);
    if (cached) {
      try {
        const obj = JSON.parse(cached);
        if (obj && obj.authorization_endpoint && obj.token_endpoint) {
          state.discovery = obj;
          return;
        }
      } catch { /* fall through and refetch */ }
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
    const nonce = b64urlEncode(window.crypto.getRandomValues(new Uint8Array(16)));
    sessionStorage.setItem(STORAGE_KEYS.verifier, verifier);
    sessionStorage.setItem(STORAGE_KEYS.state, nonce);

    const query = new URLSearchParams({
      response_type: "code",
      client_id: state.config.web_client_id,
      redirect_uri: REDIRECT_URI,
      scope: SCOPES.join(" "),
      state: nonce,
      code_challenge: challenge,
      code_challenge_method: "S256",
    });
    location.assign(`${state.discovery.authorization_endpoint}?${query.toString()}`);
  }

  async function completeSignIn(code, returnedState) {
    const verifier = sessionStorage.getItem(STORAGE_KEYS.verifier);
    const expected = sessionStorage.getItem(STORAGE_KEYS.state);
    sessionStorage.removeItem(STORAGE_KEYS.verifier);
    sessionStorage.removeItem(STORAGE_KEYS.state);
    if (!verifier || !expected || returnedState !== expected) {
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
    if (!res.ok) {
      throw new Error(`Token exchange failed (HTTP ${res.status}).`);
    }
    const tokens = await res.json();
    if (!tokens.access_token) throw new Error("Token exchange returned no access_token.");
    state.accessToken = tokens.access_token;
    state.idClaims = decodeClaims(tokens.id_token || tokens.access_token);
    state.userLabel = (state.idClaims && (state.idClaims.email || state.idClaims["cognito:username"])) || "Signed in";
    // Fresh thread on every sign-in. Signing out and signing in as another
    // person must not reveal the previous thread.
    state.threadId = newId("thread");
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

  function signOut() {
    state.accessToken = null;
    state.idClaims = null;
    state.userLabel = "";
    state.threadId = null;
    state.pendingInterrupt = null;
    sessionStorage.clear();
    if (state.sseController) state.sseController.abort();
    renderCards({ reset: true });
    renderMessages({ reset: true });
    renderIdentity();
    updateControls();
  }

  /* ------------------------------------------------------------- render */

  function renderIdentity() {
    const label = $("identityState");
    if (state.accessToken) {
      label.textContent = state.userLabel;
      label.dataset.state = "signed-in";
      $("signInBtn").hidden = true;
      $("signOutBtn").hidden = false;
      hide("authBanner");
    } else {
      label.textContent = "Not signed in";
      label.dataset.state = "unknown";
      $("signInBtn").hidden = false;
      $("signOutBtn").hidden = true;
      show("authBanner");
    }
    $("footerSession").textContent = state.threadId ? `session · ${state.threadId}` : "session · —";
  }

  function updateControls() {
    const ready = Boolean(state.accessToken) && !state.busy;
    $("chatInput").disabled = !ready;
    $("chatSend").disabled = !ready || !$("chatInput").value.trim();
    $("signInBtn").disabled = state.busy;
    $("signOutBtn").disabled = state.busy;
  }

  function appendMessage(role, text, meta) {
    const message = el("div", `hr-message hr-message--${role}`);
    const avatar = el("div", "hr-avatar", role === "user" ? "You" : role === "error" ? "!" : "HR");
    avatar.setAttribute("aria-hidden", "true");
    const column = el("div");
    column.append(el("div", "hr-message-meta", meta || (role === "user" ? "You" : "HR assistant")));
    column.append(el("div", "hr-message-body", text));
    message.append(avatar, column);
    const messages = $("chatMessages");
    messages.append(message);
    messages.scrollTop = messages.scrollHeight;
    return message;
  }

  function appendTrace(node, kind, label) {
    let trace = node.querySelector(".hr-trace");
    if (!trace) {
      trace = el("ul", "hr-trace");
      node.querySelector("div:last-child").append(trace);
    }
    const item = el("li", "hr-trace-item");
    item.dataset.kind = kind;
    item.append(el("span", "hr-trace-dot"), el("span", "hr-trace-label", label));
    trace.append(item);
  }

  function renderMessages({ reset }) {
    if (reset) $("chatMessages").replaceChildren();
  }

  function renderCards({ reset }) {
    if (reset) {
      for (const id of [
        "leaveBalanceCard",
        "allowanceCard",
        "reportsCard",
        "employeeConfirmCard",
        "managerReviewCard",
        "probationCard",
      ]) hide(id);
    }
  }

  /* ------------------------------------------------------------- SSE */

  function runtimeUrl() {
    const encoded = encodeURIComponent(state.config.runtime_arn);
    return `https://bedrock-agentcore.${state.config.region}.amazonaws.com/runtimes/${encoded}/invocations?qualifier=DEFAULT`;
  }

  async function sendMessage(text) {
    if (state.busy || !state.accessToken) return;
    const message = (text || "").trim();
    if (!message) return;
    appendMessage("user", message);
    $("chatInput").value = "";
    $("chatCount").textContent = "0";
    state.busy = true;
    updateControls();
    state.runId = newId("run");
    const input = {
      threadId: state.threadId,
      runId: state.runId,
      messages: [{ id: newId("msg"), role: "user", content: message }],
      state: {},
      tools: [],
      context: [],
      forwardedProps: {},
    };
    try {
      await streamAgent(input);
    } catch (err) {
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

  async function sendResume(resumePayload) {
    // The AG-UI resume carries the decision. The runtime checks the token
    // before applying Command(resume=...), so a forged resume for somebody
    // else's thread is still NOT_REVIEWER.
    if (state.busy || !state.accessToken) return;
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
      forwardedProps: { resume: [resumePayload] },
    };
    try {
      await streamAgent(input);
    } catch (err) {
      appendMessage("error", explainError(err), "Transport error");
    } finally {
      state.busy = false;
      updateControls();
    }
  }

  async function streamAgent(input) {
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
      },
      body: JSON.stringify(input),
    });
    if (!res.ok) throw new Error(`Runtime HTTP ${res.status}`);
    if (!res.body) throw new Error("Runtime returned no body.");
    const reader = res.body.getReader();
    const decoder = new TextDecoder();
    let buffer = "";
    let read = 0;
    const assistantNode = appendMessage("assistant", "", "HR assistant");
    const body = assistantNode.querySelector(".hr-message-body");
    const outstanding = new Map(); // toolCallId -> toolCallName
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
        handleEvent(event, body, assistantNode, outstanding);
      }
    }
    // Drop assistant placeholder when the model emitted no text and the
    // stream carried only tool events or an interrupt.
    if (!body.textContent.trim()) {
      assistantNode.remove();
    }
  }

  /* ----------------------------------------------- event dispatch */
  // Fallback for later commits: card rendering plugs into these two hooks.
  const toolResultRenderers = {};

  function handleEvent(event, body, assistantNode, outstanding) {
    if (!event || typeof event !== "object") return;
    const kind = event.type;
    switch (kind) {
      case "TEXT_MESSAGE_CONTENT": {
        const delta = typeof event.delta === "string" ? event.delta : "";
        body.textContent += delta;
        break;
      }
      case "TOOL_CALL_START": {
        if (event.toolCallId && event.toolCallName) {
          outstanding.set(String(event.toolCallId), String(event.toolCallName));
          appendTrace(assistantNode, "info", `tool · ${event.toolCallName}`);
        }
        break;
      }
      case "TOOL_CALL_RESULT": {
        const id = event.toolCallId ? String(event.toolCallId) : "";
        const name = outstanding.get(id) || "tool";
        outstanding.delete(id);
        const result = parseToolResult(event.content);
        const renderer = toolResultRenderers[name];
        if (renderer) renderer(result, assistantNode);
        const traceKind = result && result.authorized === false ? "deny"
          : result && result.authorized === true ? "allow" : "info";
        const tag = result && result.reason_code ? ` · ${result.reason_code}` : "";
        appendTrace(assistantNode, traceKind, `result · ${name}${tag}`);
        break;
      }
      case "TOOL_CALL_END": break;
      case "RUN_STARTED": break;
      case "RUN_FINISHED": {
        handleRunFinished(event, assistantNode);
        break;
      }
      case "RUN_ERROR": {
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

  // Placeholder; interrupt handling is added in the cards commit.
  function handleRunFinished(_event, _node) { /* no-op for now */ }

  /* ------------------------------------------------------------- init */

  async function start() {
    try {
      await loadConfig();
    } catch (err) {
      appendMessage("error", `hr-web could not load /config.json: ${err.message}`, "Setup error");
      return;
    }
    const params = new URLSearchParams(location.search);
    const code = params.get("code");
    const returnedState = params.get("state");
    const authErr = params.get("error_description") || params.get("error");
    if (authErr) {
      appendMessage("error", `Sign-in failed: ${authErr}`, "Sign-in error");
      history.replaceState(null, "", REDIRECT_URI);
    } else if (code) {
      try {
        await completeSignIn(code, returnedState);
        history.replaceState(null, "", REDIRECT_URI);
      } catch (err) {
        appendMessage("error", err.message, "Sign-in error");
        history.replaceState(null, "", REDIRECT_URI);
      }
    }
    renderIdentity();
    updateControls();
  }

  /* ------------------------------------------------------------- wire-up */

  $("signInBtn").addEventListener("click", async () => {
    try { await beginSignIn(); }
    catch (err) { appendMessage("error", err.message, "Sign-in error"); }
  });
  $("signOutBtn").addEventListener("click", signOut);
  $("chatForm").addEventListener("submit", (e) => {
    e.preventDefault();
    sendMessage($("chatInput").value);
  });
  $("chatInput").addEventListener("input", (e) => {
    $("chatCount").textContent = String(e.target.value.length);
    updateControls();
  });
  $("chatInput").addEventListener("keydown", (e) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      $("chatForm").requestSubmit();
    }
  });

  // Exported shape for the cards commit and for tests that may load this
  // module. Everything here is pure wiring; secrets are never put on this
  // namespace.
  window.HrWeb = Object.freeze({
    state,
    toolResultRenderers,
    sendMessage,
    sendResume,
  });

  start();
})();
