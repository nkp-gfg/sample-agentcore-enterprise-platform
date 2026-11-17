const MAX_RESPONSE_BYTES = 2 * 1024 * 1024;

export async function readSseJson(
  response: Response,
  onEvent: (event: Record<string, unknown>) => void,
): Promise<void> {
  if (!response.body) throw new Error("Runtime returned no body.");
  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";
  let read = 0;
  for (;;) {
    const { value, done } = await reader.read();
    if (done) break;
    read += value.byteLength;
    if (read > MAX_RESPONSE_BYTES) {
      throw new Error("Runtime response exceeded safety limit.");
    }
    buffer += decoder.decode(value, { stream: true });
    let newlineIndex = buffer.indexOf("\n");
    while (newlineIndex !== -1) {
      const line = buffer.slice(0, newlineIndex).trimEnd();
      buffer = buffer.slice(newlineIndex + 1);
      if (line.startsWith("data:")) {
        const raw = line.slice(5).trim();
        if (raw) {
          try {
            const event: unknown = JSON.parse(raw);
            if (event && typeof event === "object" && !Array.isArray(event)) {
              onEvent(event as Record<string, unknown>);
            }
          } catch {
            /* skip malformed SSE payloads */
          }
        }
      }
      newlineIndex = buffer.indexOf("\n");
    }
  }
}
