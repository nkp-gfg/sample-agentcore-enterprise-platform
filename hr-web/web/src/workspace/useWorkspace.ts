import { useEffect, useRef, useState } from "react";
import { toast } from "sonner";
import type { ActionPayload } from "@a2ui/web_core/v1_0";
import {
  clearNonReviewSurfaces,
  clearSurfacesFor,
  fromInterrupt,
  fromToolResult,
  reasonLabel,
  sanitizeHistoryCards,
  SURFACE_IDS,
  type A2uiWireMessage,
} from "@/a2ui/hr-tool-adapter.ts";
import { HrSurfaces } from "@/a2ui/surfaces.ts";
import {
  clearThreads,
  deleteThread as deleteThreadRequest,
  getThread,
  listThreads,
  logout,
  postInvocation,
  readErrorDetail,
  SessionExpiredError,
  fetchMe,
  type InvocationBody,
  type StoredMessage,
  type ThreadSummary,
} from "@/lib/bff.ts";
import {
  ensureThreadId,
  isActiveThreadId,
  newId,
  rememberThreadId,
  replaceThreadId,
} from "@/lib/ids.ts";
import { takeLoginErrorFromLocation } from "@/lib/oauth-error.ts";
import { readSseJson } from "@/lib/sse.ts";

export interface TraceView {
  kind: "info" | "allow" | "deny";
  label: string;
  detail?: unknown;
}

export interface ChatMessage {
  id: string;
  role: "user" | "assistant" | "error" | "system";
  text: string;
  meta: string;
  timestamp: number;
  traces: TraceView[];
  pending: boolean;
}

export type WorkspaceStatus = "loading" | "anonymous" | "ready";

interface Turn {
  rootText: string;
  activeRootId: string | null;
  subagentTexts: Map<string, string>;
  lastSubId: string | null;
  outstanding: Map<string, { name: string; subId: string | null }>;
  seen: Set<string>;
  traces: TraceView[];
  sawFinished: boolean;
  sawError: boolean;
  sawInterrupt: boolean;
  assistantId: string | null;
}

type ResumePayload = Record<string, unknown>;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

function isAbort(error: unknown): boolean {
  return error instanceof Error && error.name === "AbortError";
}

function bareToolName(toolName: string): string {
  return toolName.includes("___") ? toolName.split("___").pop() || toolName : toolName;
}

function stableStringify(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(stableStringify).join(",")}]`;
  const record = value as Record<string, unknown>;
  const keys = Object.keys(record).sort();
  return `{${keys.map((key) => `${JSON.stringify(key)}:${stableStringify(record[key])}`).join(",")}}`;
}

function parseToolResult(content: unknown): unknown {
  if (content == null) return null;
  if (typeof content === "object") return content;
  if (typeof content !== "string") return null;
  try {
    return JSON.parse(content);
  } catch {
    return null;
  }
}

function summarizeToolResult(toolName: string, result: unknown): string {
  if (!isRecord(result)) return "Completed";
  if (result.authorized === false) {
    return result.reason_code ? `Denied · ${reasonLabel(result.reason_code)}` : "Denied";
  }
  const bare = bareToolName(toolName);
  const data = isRecord(result.data) ? result.data : {};
  if (bare === "get_leave_balance") return `Annual ${data.annual ?? "—"}d · Sick ${data.sick ?? "—"}d`;
  if (bare === "get_allowance") {
    return data.amount == null ? "No entry" : `${String(data.amount)} ${String(data.currency || "")}`.trim();
  }
  if (bare === "list_direct_reports") {
    const count = Array.isArray(data.reports) ? data.reports.length : 0;
    return `${count} direct report${count === 1 ? "" : "s"}`;
  }
  if (bare === "check_leave_eligibility") {
    return data.eligible ? `Eligible (${data.days ?? "—"}d)` : "Checked";
  }
  if (bare === "submit_leave_request") {
    return data.request_id ? `Pending ${String(data.request_id)}` : "Submitted";
  }
  if (bare === "record_leave_decision") {
    return data.status ? `Decision: ${String(data.status)}` : "Recorded";
  }
  if (bare === "get_employee_compensation") {
    return data.base_salary != null
      ? `${String(data.base_salary)} ${String(data.currency || "")}`.trim()
      : "Authorized";
  }
  return "Completed";
}

function subagentRunId(event: Record<string, unknown>): string | null {
  const metadata = isRecord(event.metadata) ? event.metadata : null;
  const value = event.subagentRunId
    ?? event.subagent_run_id
    ?? metadata?.subagentRunId
    ?? metadata?.subagent_run_id
    ?? null;
  return value == null || value === "" ? null : String(value);
}

function validateDateRange(start: unknown, end: unknown): string | null {
  if (typeof start !== "string" || typeof end !== "string" || !start || !end) {
    return "Start and end dates are required.";
  }
  const a = Date.parse(`${start}T00:00:00Z`);
  const b = Date.parse(`${end}T00:00:00Z`);
  if (Number.isNaN(a) || Number.isNaN(b)) return "Dates must be ISO calendar dates.";
  if (b < a) return "End date must be on or after the start date.";
  return null;
}

function explainError(error: unknown): string {
  const message = error instanceof Error ? error.message : "Unknown error.";
  if (/401|unauthor/i.test(message)) return "The runtime rejected the token. Sign in again.";
  if (/network|fetch/i.test(message)) return "Network error talking to the runtime. Is it deployed?";
  return message;
}

function chatRole(role: unknown): ChatMessage["role"] {
  if (role === "user" || role === "assistant" || role === "error" || role === "system") return role;
  return "system";
}

function toChatMessages(stored: StoredMessage[]): ChatMessage[] {
  return stored.map((message) => ({
    id: newId("msg"),
    role: chatRole(message.role),
    text: message.text ?? "",
    meta: message.meta || (message.role === "user" ? "You" : "HR assistant"),
    timestamp: typeof message.timestamp === "number" ? message.timestamp : Date.now(),
    traces: Array.isArray(message.traces)
      ? message.traces.map((trace) => ({
        kind: trace.kind === "allow" || trace.kind === "deny" ? trace.kind : "info",
        label: trace.label || "trace",
        detail: trace.detail,
      }))
      : [],
    pending: false,
  }));
}

function surfacesFromHistory(stored: StoredMessage[]): unknown[] {
  for (let index = stored.length - 1; index >= 0; index -= 1) {
    const message = stored[index];
    if (!message) continue;
    const cards = Array.isArray(message.cards) ? sanitizeHistoryCards(message.cards) : [];
    if (cards.length > 0) return cards;
    const reconstructed: unknown[] = [];
    for (const trace of message.traces ?? []) {
      if (trace?.toolName && trace.detail !== undefined) {
        reconstructed.push(...fromToolResult(trace.toolName, trace.detail));
      }
    }
    const safe = sanitizeHistoryCards(reconstructed);
    if (safe.length > 0) return safe;
  }
  return [];
}

function extractInterrupts(outcome: unknown): Array<{ id: string | null; payload: Record<string, unknown> }> {
  if (!isRecord(outcome) || outcome.type !== "interrupt") return [];
  if (Array.isArray(outcome.interrupts) && outcome.interrupts.length > 0) {
    return outcome.interrupts.flatMap((item) => {
      if (!isRecord(item)) return [];
      const metadata = isRecord(item.metadata) ? item.metadata : null;
      const langgraph = metadata && isRecord(metadata.langgraph) ? metadata.langgraph : null;
      const raw = langgraph && isRecord(langgraph.raw)
        ? langgraph.raw
        : isRecord(item.value)
          ? item.value
          : isRecord(item.payload)
            ? item.payload
            : null;
      if (!raw) return [];
      return [{ id: item.id == null ? null : String(item.id), payload: raw }];
    });
  }
  const fallback = isRecord(outcome.value)
    ? outcome.value
    : isRecord(outcome.payload)
      ? outcome.payload
      : isRecord(outcome.data)
        ? outcome.data
        : null;
  if (!fallback) return [];
  return [{ id: fallback.id == null ? null : String(fallback.id), payload: fallback }];
}

export function useWorkspace() {
  const [status, setStatus] = useState<WorkspaceStatus>("loading");
  const [loginError, setLoginError] = useState("");
  const [userLabel, setUserLabel] = useState("");
  const [threadId, setThreadIdState] = useState("");
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [busy, setBusy] = useState(false);
  const [reviewCount, setReviewCount] = useState(0);
  const [threads, setThreads] = useState<ThreadSummary[]>([]);

  const csrfRef = useRef("");
  const threadRef = useRef("");
  const busyRef = useRef(false);
  const activeAgentRef = useRef("hr-assistant");
  const abortRef = useRef<AbortController | null>(null);
  const invocationGen = useRef(0);
  const pendingEmployee = useRef<Record<string, unknown> | null>(null);
  const pendingManagers = useRef(new Map<string, Record<string, unknown>>());
  const actionRef = useRef<(action: ActionPayload) => void>(() => {});
  const surfacesRef = useRef<HrSurfaces | null>(null);
  if (!surfacesRef.current) {
    surfacesRef.current = new HrSurfaces((action) => {
      actionRef.current(action);
    });
  }
  const surfaces = surfacesRef.current;

  function setThread(next: string) {
    threadRef.current = next;
    setThreadIdState(next);
    rememberThreadId(next);
  }

  function setBusyState(next: boolean) {
    busyRef.current = next;
    setBusy(next);
  }

  function syncReviewCount() {
    setReviewCount(pendingManagers.current.size);
  }

  function expire(message = "Your session expired or was rejected. Please sign in again.") {
    abortRef.current?.abort();
    pendingEmployee.current = null;
    pendingManagers.current.clear();
    syncReviewCount();
    setBusyState(false);
    setStatus("anonymous");
    setLoginError(message);
  }

  function appendMessage(
    role: ChatMessage["role"],
    text: string,
    meta: string,
  ) {
    const id = newId("msg");
    setMessages((current) => [
      ...current,
      { id, role, text, meta, timestamp: Date.now(), traces: [], pending: false },
    ]);
    return id;
  }

  function patchMessage(id: string, patch: (message: ChatMessage) => ChatMessage) {
    setMessages((current) => current.map((message) => (message.id === id ? patch(message) : message)));
  }

  function removeMessage(id: string) {
    setMessages((current) => current.filter((message) => message.id !== id));
  }

  function rendererMetadata(): Record<string, unknown> {
    const current = surfacesRef.current;
    const metadata: Record<string, unknown> = {
      a2uiRendererCapabilities: current && !current.disposed ? current.capabilities() : null,
    };
    const errors = current?.takeErrors() ?? [];
    if (errors.length > 0) metadata.a2uiRendererErrors = errors;
    return metadata;
  }

  function clearPreviousTurnSurfaces(options: {
    preserveEmployeeConfirm?: boolean;
    preserveManagerReviews?: boolean;
  }) {
    const current = surfacesRef.current;
    if (!current || current.disposed) return;
    const preserveEmployeeConfirm = options.preserveEmployeeConfirm ?? false;
    const preserveManagerReviews = options.preserveManagerReviews ?? true;
    const keepEmployee = Boolean(preserveEmployeeConfirm && pendingEmployee.current);
    const activeManagerIds = new Set<string>();
    if (preserveManagerReviews) {
      for (const key of pendingManagers.current.keys()) {
        activeManagerIds.add(SURFACE_IDS.managerReviewFor(key));
      }
    }
    const toDelete: string[] = [];
    for (const id of current.ids()) {
      if (id === SURFACE_IDS.employeeConfirm && keepEmployee) continue;
      if (activeManagerIds.has(id)) continue;
      toDelete.push(id);
    }
    if (toDelete.length > 0) {
      current.apply(clearNonReviewSurfaces(toDelete, {
        preserveEmployeeConfirm: keepEmployee,
        preserveManagerReviews: false,
      }));
    }
  }

  function applyMessages(wire: readonly A2uiWireMessage[]) {
    surfacesRef.current?.apply(wire);
  }

  function handleRunFinished(event: Record<string, unknown>, silent: boolean): boolean {
    const entries = extractInterrupts(event.outcome);
    if (entries.length === 0) {
      if (silent) {
        for (const key of [...pendingManagers.current.keys()]) {
          pendingManagers.current.delete(key);
          applyMessages(clearSurfacesFor("manager_review", key));
        }
        applyMessages(clearSurfacesFor("manager_review"));
        syncReviewCount();
      }
      return false;
    }

    const reviewEntries = entries.filter((entry) => entry.payload.kind === "manager_review");
    if (silent) {
      const activeKeys = new Set(reviewEntries.map((entry) => reviewKey(entry.payload, entry.id)));
      for (const key of [...pendingManagers.current.keys()]) {
        if (!activeKeys.has(key)) {
          pendingManagers.current.delete(key);
          applyMessages(clearSurfacesFor("manager_review", key));
        }
      }
    }

    for (const entry of entries) {
      const payload = entry.payload;
      if (payload.kind === "manager_review") {
        const key = reviewKey(payload, entry.id);
        const stored = {
          ...payload,
          _interruptId: entry.id,
          _reviewKey: key,
        };
        pendingManagers.current.set(key, stored);
        applyMessages(fromInterrupt(stored));
      } else if (payload.kind === "employee_confirm") {
        pendingEmployee.current = { ...payload, _interruptId: entry.id };
        const wire = fromInterrupt(payload);
        if (wire.length > 0) applyMessages(wire);
      } else {
        appendMessage(
          "system",
          `Review pause received for ${String(payload.kind || "unknown")}. Use the card to decide.`,
          "Interrupt",
        );
      }
    }
    syncReviewCount();
    return true;
  }

  function reviewKey(payload: Record<string, unknown>, interruptId: string | null): string {
    const raw = payload.request_id || interruptId || payload.interrupt_id || "";
    const text = String(raw).trim();
    return text || newId("rev");
  }

  async function runInvocation(
    input: InvocationBody,
    mode: "chat" | "resume" | "poll",
    signal?: AbortSignal,
  ): Promise<{ sawRunError: boolean; sawRunFinished: boolean }> {
    const controller = new AbortController();
    abortRef.current = controller;
    const onAbort = () => controller.abort();
    signal?.addEventListener("abort", onAbort);
    const generation = ++invocationGen.current;
    const silent = mode === "poll";
    const turn: Turn = {
      rootText: "",
      activeRootId: null,
      subagentTexts: new Map(),
      lastSubId: null,
      outstanding: new Map(),
      seen: new Set(),
      traces: [],
      sawFinished: false,
      sawError: false,
      sawInterrupt: false,
      assistantId: null,
    };

    const ensureAssistant = () => {
      if (turn.assistantId) return turn.assistantId;
      const id = newId("msg");
      turn.assistantId = id;
      setMessages((current) => [
        ...current,
        {
          id,
          role: "assistant",
          text: silent ? "" : "Thinking…",
          meta: "HR assistant",
          timestamp: Date.now(),
          traces: [],
          pending: !silent,
        },
      ]);
      return id;
    };

    const publishAssistant = (text: string, traces: TraceView[], pending: boolean) => {
      const id = ensureAssistant();
      patchMessage(id, (message) => ({ ...message, text, traces, pending }));
    };

    try {
      const response = await postInvocation(input, csrfRef.current, controller.signal);
      if (response.status === 401) throw new SessionExpiredError();
      if (!response.ok) throw new Error(await readErrorDetail(response));
      await readSseJson(response, (event) => {
        const kind = event.type;
        const subId = subagentRunId(event);
        if (kind === "TEXT_MESSAGE_START" && !subId && event.messageId) {
          const messageId = String(event.messageId);
          if (
            turn.activeRootId
            && turn.activeRootId !== messageId
            && turn.rootText.trim()
            && !turn.rootText.endsWith("\n")
          ) {
            turn.rootText += "\n\n";
          }
          turn.activeRootId = messageId;
          return;
        }
        if (kind === "TEXT_MESSAGE_CONTENT") {
          const delta = typeof event.delta === "string" ? event.delta : "";
          if (!delta) return;
          if (subId) {
            const previous = turn.subagentTexts.get(subId) ?? "";
            turn.subagentTexts.set(subId, previous + delta);
            turn.lastSubId = subId;
            return;
          }
          turn.rootText += delta;
          publishAssistant(turn.rootText, turn.traces, false);
          return;
        }
        if (kind === "TOOL_CALL_START") {
          const callId = event.toolCallId ? String(event.toolCallId) : "";
          const callName = event.toolCallName ? String(event.toolCallName) : "";
          if (callId && callName) {
            turn.outstanding.set(callId, { name: callName, subId });
          }
          return;
        }
        if (kind === "TOOL_CALL_RESULT") {
          const id = event.toolCallId ? String(event.toolCallId) : "";
          const tracked = turn.outstanding.get(id);
          const name = tracked?.name || (event.toolCallName ? String(event.toolCallName) : "tool");
          turn.outstanding.delete(id);
          if (bareToolName(name) === "task") return;
          const result = parseToolResult(event.content);
          const serialized = result !== null ? stableStringify(result) : String(event.content ?? "");
          const bare = bareToolName(name);
          const dedupeKey = `${bare}\0${serialized}`;
          if (turn.seen.has(dedupeKey)) return;
          turn.seen.add(dedupeKey);
          applyMessages(fromToolResult(name, result));
          const summary = summarizeToolResult(name, result);
          const tag = isRecord(result) && result.reason_code ? ` · ${String(result.reason_code)}` : "";
          const label = summary !== "Completed" ? `${bare}${tag} · ${summary}` : `${bare}${tag}`;
          const traceKind: TraceView["kind"] = isRecord(result) && result.authorized === false
            ? "deny"
            : isRecord(result) && result.authorized === true
              ? "allow"
              : "info";
          turn.traces.push({ kind: traceKind, label, detail: result });
          if (turn.rootText || !silent) publishAssistant(turn.rootText, [...turn.traces], false);
          return;
        }
        if (kind === "RUN_FINISHED") {
          turn.sawFinished = true;
          turn.sawInterrupt = handleRunFinished(event, silent);
          return;
        }
        if (kind === "RUN_ERROR") {
          turn.sawError = true;
          const message = String(event.message || event.code || "Runtime error.");
          if (turn.assistantId && !turn.rootText.trim() && turn.traces.length === 0) {
            removeMessage(turn.assistantId);
            turn.assistantId = null;
          }
          appendMessage("error", message, "Runtime error");
          toast.error(message);
        }
      });

      let finalText = turn.rootText;
      if (!finalText.trim() && turn.subagentTexts.size > 0) {
        const preferred = turn.lastSubId ? turn.subagentTexts.get(turn.lastSubId) ?? "" : "";
        finalText = preferred.trim()
          ? preferred
          : [...turn.subagentTexts.values()].find((value) => value.trim()) ?? "";
      }
      if (turn.sawInterrupt && !finalText.trim() && !silent) {
        if (pendingEmployee.current) {
          finalText = "Please review and confirm your leave request in the card below.";
        } else if (pendingManagers.current.size > 0) {
          finalText = "Pending leave review loaded in the card below.";
        }
      }
      if (!finalText.trim() && turn.traces.length === 0) {
        if (turn.assistantId) removeMessage(turn.assistantId);
      } else if (turn.assistantId) {
        publishAssistant(finalText, turn.traces, false);
      } else if (!silent || finalText.trim() || turn.traces.length > 0) {
        const id = newId("msg");
        setMessages((current) => [
          ...current,
          {
            id,
            role: "assistant",
            text: finalText,
            meta: "HR assistant",
            timestamp: Date.now(),
            traces: turn.traces,
            pending: false,
          },
        ]);
      }
      return { sawRunError: turn.sawError, sawRunFinished: turn.sawFinished };
    } finally {
      signal?.removeEventListener("abort", onAbort);
      if (abortRef.current === controller) abortRef.current = null;
      if (invocationGen.current === generation) setBusyState(false);
    }
  }

  async function sendResume(resumePayload: ResumePayload, interruptId: string | null): Promise<boolean> {
    if (busyRef.current || status !== "ready") return false;
    setBusyState(true);
    clearPreviousTurnSurfaces({ preserveEmployeeConfirm: false, preserveManagerReviews: true });
    const input: InvocationBody = {
      threadId: threadRef.current,
      runId: newId("run"),
      messages: [],
      state: {},
      tools: [],
      context: [],
      forwardedProps: {
        resume: [resumePayload],
        command: { resume: resumePayload },
        ...rendererMetadata(),
      },
    };
    if (interruptId) {
      input.resume = [{ interruptId, status: "resolved", payload: resumePayload }];
    }
    try {
      const outcome = await runInvocation(input, "resume");
      return !(outcome.sawRunError && !outcome.sawRunFinished);
    } catch (error) {
      if (isAbort(error)) return false;
      if (error instanceof SessionExpiredError) {
        expire();
        return false;
      }
      const message = explainError(error);
      appendMessage("error", message, "Transport error");
      toast.error(message);
      return false;
    }
  }

  async function sendMessage(text: string) {
    const message = text.trim();
    if (!message || busyRef.current || status !== "ready") return;
    appendMessage("user", message, "You");
    setBusyState(true);
    clearPreviousTurnSurfaces({ preserveEmployeeConfirm: true, preserveManagerReviews: true });
    const input: InvocationBody = {
      threadId: threadRef.current,
      runId: newId("run"),
      messages: [{ id: newId("msg"), role: "user", content: message }],
      state: {},
      tools: [],
      context: [],
      forwardedProps: {
        ...(activeAgentRef.current ? { activeAgentId: activeAgentRef.current } : {}),
        ...rendererMetadata(),
      },
    };
    try {
      await runInvocation(input, "chat");
    } catch (error) {
      if (isAbort(error)) return;
      if (error instanceof SessionExpiredError) {
        expire();
        return;
      }
      const detail = explainError(error);
      appendMessage("error", detail, "Transport error");
      toast.error(detail);
    }
  }

  async function pollPending(signal?: AbortSignal, force = false) {
    if ((!force && busyRef.current) || !threadRef.current) return;
    setBusyState(true);
    const input: InvocationBody = {
      threadId: threadRef.current,
      runId: newId("run"),
      messages: [],
      state: {},
      tools: [],
      context: [],
      forwardedProps: {
        checkPendingReviews: true,
        ...rendererMetadata(),
      },
    };
    try {
      await runInvocation(input, "poll", signal);
    } catch (error) {
      if (isAbort(error) || signal?.aborted) return;
      if (error instanceof SessionExpiredError) {
        expire();
        return;
      }
      const detail = explainError(error);
      appendMessage("error", detail, "Review check failed");
      toast.error(detail);
    }
  }

  function restoreEmployee(saved: Record<string, unknown>) {
    if (pendingEmployee.current) return;
    pendingEmployee.current = saved;
    const wire = fromInterrupt(saved);
    if (wire.length > 0) applyMessages(wire);
  }

  async function onEmployeeConfirm(ctx: Record<string, unknown>) {
    const interrupt = pendingEmployee.current;
    if (!interrupt || interrupt.kind !== "employee_confirm") return;
    const proposed = isRecord(interrupt.arguments)
      ? interrupt.arguments
      : isRecord(interrupt.proposed)
        ? interrupt.proposed
        : interrupt;
    const merged: Record<string, unknown> = {
      ...proposed,
      start_date: ctx.start_date || proposed.start_date,
      end_date: ctx.end_date || proposed.end_date,
      leave_type: ctx.leave_type || proposed.leave_type,
      reason: ctx.reason != null ? ctx.reason : proposed.reason,
    };
    const idempotencyKey = proposed.idempotency_key || interrupt.idempotency_key;
    if (idempotencyKey) merged.idempotency_key = idempotencyKey;
    const rangeError = validateDateRange(merged.start_date, merged.end_date);
    if (rangeError) {
      appendMessage("error", rangeError, "Invalid range");
      return;
    }
    const interruptId = typeof interrupt._interruptId === "string" ? interrupt._interruptId : null;
    pendingEmployee.current = null;
    applyMessages(clearSurfacesFor("employee_confirm"));
    const ok = await sendResume({
      decision: "approve",
      kind: "employee_confirm",
      arguments: merged,
    }, interruptId);
    if (!ok) restoreEmployee(interrupt);
  }

  async function onEmployeeReject() {
    const interrupt = pendingEmployee.current;
    if (!interrupt || interrupt.kind !== "employee_confirm") return;
    const interruptId = typeof interrupt._interruptId === "string" ? interrupt._interruptId : null;
    const proposed = isRecord(interrupt.arguments)
      ? interrupt.arguments
      : isRecord(interrupt.proposed)
        ? interrupt.proposed
        : interrupt;
    const resumePayload: ResumePayload = { decision: "reject", kind: "employee_confirm" };
    const idempotencyKey = proposed.idempotency_key || interrupt.idempotency_key;
    if (idempotencyKey) resumePayload.idempotency_key = idempotencyKey;
    pendingEmployee.current = null;
    applyMessages(clearSurfacesFor("employee_confirm"));
    const ok = await sendResume(resumePayload, interruptId);
    if (ok) appendMessage("system", "You declined to submit this request.", "No request");
    else restoreEmployee(interrupt);
  }

  async function onEmployeeEdit(ctx: Record<string, unknown>) {
    const interrupt = pendingEmployee.current;
    if (!interrupt || interrupt.kind !== "employee_confirm") return;
    const interruptId = typeof interrupt._interruptId === "string" ? interrupt._interruptId : null;
    const proposed = isRecord(interrupt.arguments)
      ? interrupt.arguments
      : isRecord(interrupt.proposed)
        ? interrupt.proposed
        : interrupt;
    const nextStart = String(ctx.start_date || proposed.start_date || "").trim();
    const nextEnd = String(ctx.end_date || proposed.end_date || "").trim();
    const nextType = String(ctx.leave_type || proposed.leave_type || "annual").trim();
    const rangeError = validateDateRange(nextStart, nextEnd);
    if (rangeError) {
      appendMessage("error", rangeError, "Invalid range");
      return;
    }
    const edited: Record<string, unknown> = {
      ...proposed,
      leave_type: nextType,
      start_date: nextStart,
      end_date: nextEnd,
      reason: ctx.reason != null ? ctx.reason : proposed.reason,
    };
    const idempotencyKey = proposed.idempotency_key || interrupt.idempotency_key;
    if (idempotencyKey) edited.idempotency_key = idempotencyKey;
    pendingEmployee.current = null;
    applyMessages(clearSurfacesFor("employee_confirm"));
    const ok = await sendResume({
      decision: "edit",
      kind: "employee_confirm",
      arguments: edited,
    }, interruptId);
    if (!ok) restoreEmployee(interrupt);
  }

  async function onManagerDecision(ctx: Record<string, unknown>, decision: "approve" | "reject") {
    const requestId = ctx.request_id ? String(ctx.request_id) : "";
    let key = requestId;
    if (!key && pendingManagers.current.size === 1) {
      key = pendingManagers.current.keys().next().value ?? "";
    }
    let interrupt = key ? pendingManagers.current.get(key) : undefined;
    if (!interrupt && requestId) {
      for (const [candidate, item] of pendingManagers.current.entries()) {
        if (item.request_id === requestId || item._interruptId === requestId) {
          key = candidate;
          interrupt = item;
          break;
        }
      }
    }
    if (!interrupt || interrupt.kind !== "manager_review") return;
    const effectiveRequestId = requestId || String(interrupt.request_id || "");
    const interruptId = typeof interrupt._interruptId === "string" ? interrupt._interruptId : null;
    const effectiveKey = String(interrupt._reviewKey || key);
    pendingManagers.current.delete(effectiveKey);
    syncReviewCount();
    applyMessages(clearSurfacesFor("manager_review", effectiveKey));
    const ok = await sendResume({
      decision,
      kind: "manager_review",
      request_id: effectiveRequestId,
    }, interruptId);
    if (!ok && !pendingManagers.current.has(effectiveKey)) {
      pendingManagers.current.set(effectiveKey, interrupt);
      syncReviewCount();
      applyMessages(fromInterrupt(interrupt));
    }
  }

  actionRef.current = (action) => {
    const name = action.name;
    const ctx = isRecord(action.context) ? action.context : {};
    if (name === "employee_confirm_leave") void onEmployeeConfirm(ctx);
    else if (name === "employee_reject_leave") void onEmployeeReject();
    else if (name === "employee_edit_leave") void onEmployeeEdit(ctx);
    else if (name === "manager_approve_review") void onManagerDecision(ctx, "approve");
    else if (name === "manager_reject_review") void onManagerDecision(ctx, "reject");
  };

  async function openThread(nextThreadId: string) {
    if (busyRef.current) return;
    try {
      const detail = await getThread(nextThreadId);
      if (busyRef.current) return;
      abortRef.current?.abort();
      pendingEmployee.current = null;
      pendingManagers.current.clear();
      syncReviewCount();
      surfacesRef.current?.clear();
      activeAgentRef.current = detail.activeAgentId || "hr-assistant";
      setThread(detail.threadId);
      setMessages(toChatMessages(detail.messages));
      const wire = surfacesFromHistory(detail.messages);
      if (wire.length > 0) surfacesRef.current?.apply(wire);
      await pollPending();
    } catch (error) {
      if (error instanceof SessionExpiredError) expire();
      else toast.error(error instanceof Error ? error.message : "Could not open that conversation.");
    }
  }

  function newChat() {
    if (busyRef.current) return;
    abortRef.current?.abort();
    pendingEmployee.current = null;
    pendingManagers.current.clear();
    syncReviewCount();
    surfacesRef.current?.clear();
    activeAgentRef.current = "hr-assistant";
    setMessages([]);
    setThread(replaceThreadId());
  }

  async function refreshHistory() {
    const next = await listThreads();
    setThreads(next);
    return next;
  }

  async function removeThread(id: string) {
    await deleteThreadRequest(id, csrfRef.current);
    setThreads((current) => current.filter((thread) => thread.threadId !== id));
  }

  async function removeAllThreads() {
    await clearThreads(csrfRef.current);
    setThreads([]);
  }

  async function signOut() {
    const csrf = csrfRef.current;
    abortRef.current?.abort();
    try {
      const logoutUrl = await logout(csrf);
      if (logoutUrl) {
        const target = new URL(logoutUrl, window.location.origin);
        if (target.protocol === "https:" || target.protocol === "http:") {
          window.location.assign(target.href);
          return;
        }
      }
    } catch {
      /* fall through to a clean reload */
    }
    window.location.reload();
  }

  useEffect(() => {
    const abort = new AbortController();
    const oauthError = takeLoginErrorFromLocation();
    void (async () => {
      try {
        const me = await fetchMe();
        if (abort.signal.aborted) return;
        if (!me.authenticated) {
          setStatus("anonymous");
          setLoginError(oauthError);
          return;
        }
        csrfRef.current = me.csrfToken;
        setUserLabel(me.userLabel);
        const nextThread = isActiveThreadId(me.activeThreadId) ? me.activeThreadId : ensureThreadId();
        setThread(nextThread);
        setBusyState(true);
        setStatus("ready");
        try {
          const listed = await listThreads();
          if (abort.signal.aborted) return;
          setThreads(listed);
          if (listed.some((thread) => thread.threadId === nextThread)) {
            const detail = await getThread(nextThread);
            if (abort.signal.aborted) return;
            activeAgentRef.current = detail.activeAgentId || "hr-assistant";
            setThread(detail.threadId);
            setMessages(toChatMessages(detail.messages));
            const wire = surfacesFromHistory(detail.messages);
            if (wire.length > 0) surfacesRef.current?.apply(wire);
          }
          if (abort.signal.aborted) return;
          await pollPending(abort.signal, true);
        } catch (error) {
          if (abort.signal.aborted || isAbort(error)) return;
          setBusyState(false);
          if (error instanceof SessionExpiredError) {
            expire();
            return;
          }
          toast.error(error instanceof Error ? error.message : "Could not load conversation history.");
        }
      } catch (error) {
        if (abort.signal.aborted || isAbort(error)) return;
        setStatus("anonymous");
        setLoginError(
          error instanceof SessionExpiredError
            ? "Your session expired or was rejected. Please sign in again."
            : `Could not verify the session. ${error instanceof Error ? error.message : "Please try again."}`,
        );
      }
    })();
    return () => {
      abort.abort();
    };
    // Boot once. Later actions read the latest refs.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  return {
    status,
    loginError,
    userLabel,
    threadId,
    messages,
    busy,
    reviewCount,
    threads,
    surfaces,
    signIn: () => {
      window.location.href = "/auth/login";
    },
    signOut,
    newChat,
    sendMessage,
    openThread,
    refreshHistory,
    removeThread,
    removeAllThreads,
    refreshReviews: () => pollPending(),
  };
}
