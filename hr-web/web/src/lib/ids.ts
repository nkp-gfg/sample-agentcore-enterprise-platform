const THREAD_STORAGE_KEY = "hr-web.chat.threadId";
const SESSION_ID_RE = /^[A-Za-z0-9_-]{33,128}$/;

export function newId(prefix: string): string {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  const hex = Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
  return `${prefix}-${hex}`;
}

export function newXrayTraceId(): string {
  const epochHex = Math.floor(Date.now() / 1000).toString(16).padStart(8, "0");
  return `1-${epochHex}-${crypto.randomUUID()}`;
}

export function ensureThreadId(): string {
  try {
    const existing = sessionStorage.getItem(THREAD_STORAGE_KEY);
    if (existing && SESSION_ID_RE.test(existing)) return existing;
  } catch {
    /* sessionStorage can be unavailable */
  }
  return replaceThreadId();
}

export function replaceThreadId(): string {
  const fresh = newId("thread");
  rememberThreadId(fresh);
  return fresh;
}

export function rememberThreadId(threadId: string): void {
  try {
    sessionStorage.setItem(THREAD_STORAGE_KEY, threadId);
  } catch {
    /* ignore quota and privacy-mode failures */
  }
}

export function isActiveThreadId(value: string): boolean {
  return /^[A-Za-z0-9_-]{8,128}$/.test(value);
}
