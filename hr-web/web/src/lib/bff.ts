export class SessionExpiredError extends Error {
  constructor() {
    super("Session expired.");
    this.name = "SessionExpiredError";
  }
}

export interface AuthMe {
  authenticated: boolean;
  userLabel: string;
  sub: string;
  csrfToken: string;
  activeThreadId: string;
}

export interface ThreadSummary {
  threadId: string;
  title: string;
  updatedAt: number;
  activeAgentId: string;
  messageCount: number;
}

export interface StoredTrace {
  kind?: string;
  label?: string;
  toolName?: string;
  detail?: unknown;
}

export interface StoredMessage {
  role?: string;
  text?: string;
  meta?: string;
  timestamp?: number;
  traces?: StoredTrace[];
  cards?: unknown[];
}

export interface ThreadDetail extends ThreadSummary {
  messages: StoredMessage[];
}

export interface InvocationBody {
  threadId: string;
  runId: string;
  messages: Array<{ id: string; role: "user"; content: string }>;
  state: Record<string, unknown>;
  tools: unknown[];
  context: unknown[];
  forwardedProps: Record<string, unknown>;
  resume?: Array<{
    interruptId: string;
    status: "resolved";
    payload: unknown;
  }>;
}

async function readDetail(response: Response): Promise<string> {
  try {
    const body: unknown = await response.json();
    if (body && typeof body === "object" && "detail" in body) {
      const detail = (body as { detail?: unknown }).detail;
      if (typeof detail === "string" && detail) return detail;
    }
  } catch {
    /* non-JSON error pages */
  }
  return `Request failed (HTTP ${response.status}).`;
}

export async function fetchMe(): Promise<AuthMe> {
  const response = await fetch("/api/auth/me", {
    cache: "no-store",
    credentials: "include",
  });
  if (!response.ok) {
    return {
      authenticated: false,
      userLabel: "",
      sub: "",
      csrfToken: "",
      activeThreadId: "",
    };
  }
  const body: unknown = await response.json();
  const record = body && typeof body === "object" ? (body as Record<string, unknown>) : {};
  if (record.authenticated !== true) {
    return {
      authenticated: false,
      userLabel: "",
      sub: "",
      csrfToken: "",
      activeThreadId: "",
    };
  }
  return {
    authenticated: true,
    userLabel: typeof record.userLabel === "string" && record.userLabel
      ? record.userLabel
      : "Signed in",
    sub: typeof record.sub === "string" ? record.sub : "",
    csrfToken: typeof record.csrfToken === "string" ? record.csrfToken : "",
    activeThreadId: typeof record.activeThreadId === "string" ? record.activeThreadId : "",
  };
}

export async function logout(csrfToken: string): Promise<string> {
  const response = await fetch("/auth/logout", {
    method: "POST",
    credentials: "include",
    headers: csrfToken ? { "X-BFF-CSRF": csrfToken } : {},
  });
  if (!response.ok) return "";
  const body: unknown = await response.json();
  if (body && typeof body === "object" && typeof (body as { logoutUrl?: unknown }).logoutUrl === "string") {
    return (body as { logoutUrl: string }).logoutUrl;
  }
  return "";
}

export async function listThreads(): Promise<ThreadSummary[]> {
  const response = await fetch("/api/sessions", {
    cache: "no-store",
    credentials: "include",
  });
  if (response.status === 401) throw new SessionExpiredError();
  if (!response.ok) throw new Error(await readDetail(response));
  const body: unknown = await response.json();
  const threads = body && typeof body === "object" && Array.isArray((body as { threads?: unknown }).threads)
    ? (body as { threads: unknown[] }).threads
    : [];
  return threads.flatMap((entry) => {
    if (!entry || typeof entry !== "object") return [];
    const row = entry as Record<string, unknown>;
    if (typeof row.threadId !== "string" || !row.threadId) return [];
    return [{
      threadId: row.threadId,
      title: typeof row.title === "string" && row.title ? row.title : "Conversation",
      updatedAt: typeof row.updatedAt === "number" ? row.updatedAt : Date.now(),
      activeAgentId: typeof row.activeAgentId === "string" ? row.activeAgentId : "hr-assistant",
      messageCount: typeof row.messageCount === "number" ? row.messageCount : 0,
    }];
  });
}

export async function getThread(threadId: string): Promise<ThreadDetail> {
  const response = await fetch(`/api/sessions/${encodeURIComponent(threadId)}`, {
    cache: "no-store",
    credentials: "include",
  });
  if (response.status === 401) throw new SessionExpiredError();
  if (!response.ok) throw new Error(await readDetail(response));
  const body: unknown = await response.json();
  const row = body && typeof body === "object" ? (body as Record<string, unknown>) : {};
  return {
    threadId: typeof row.threadId === "string" ? row.threadId : threadId,
    title: typeof row.title === "string" && row.title ? row.title : "Conversation",
    updatedAt: typeof row.updatedAt === "number" ? row.updatedAt : Date.now(),
    activeAgentId: typeof row.activeAgentId === "string" ? row.activeAgentId : "hr-assistant",
    messageCount: Array.isArray(row.messages) ? row.messages.length : 0,
    messages: Array.isArray(row.messages) ? row.messages as StoredMessage[] : [],
  };
}

export async function deleteThread(threadId: string, csrfToken: string): Promise<void> {
  const response = await fetch(`/api/sessions/${encodeURIComponent(threadId)}`, {
    method: "DELETE",
    credentials: "include",
    headers: csrfToken ? { "X-BFF-CSRF": csrfToken } : {},
  });
  if (response.status === 401) throw new SessionExpiredError();
  if (!response.ok) throw new Error(await readDetail(response));
}

export async function clearThreads(csrfToken: string): Promise<void> {
  const response = await fetch("/api/sessions", {
    method: "DELETE",
    credentials: "include",
    headers: csrfToken ? { "X-BFF-CSRF": csrfToken } : {},
  });
  if (response.status === 401) throw new SessionExpiredError();
  if (!response.ok) throw new Error(await readDetail(response));
}

export async function postInvocation(
  body: InvocationBody,
  csrfToken: string,
  signal: AbortSignal,
): Promise<Response> {
  return fetch("/invocations", {
    method: "POST",
    credentials: "include",
    signal,
    headers: {
      "Content-Type": "application/json",
      Accept: "text/event-stream",
      "X-Amzn-Bedrock-AgentCore-Runtime-Session-Id": body.threadId,
      "X-Amzn-Trace-Id": newTraceHeader(),
      ...(csrfToken ? { "X-BFF-CSRF": csrfToken } : {}),
    },
    body: JSON.stringify(body),
  });
}

function newTraceHeader(): string {
  const epochHex = Math.floor(Date.now() / 1000).toString(16).padStart(8, "0");
  return `1-${epochHex}-${crypto.randomUUID()}`;
}

export async function readErrorDetail(response: Response): Promise<string> {
  return readDetail(response);
}
