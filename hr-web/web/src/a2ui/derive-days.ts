/** Inclusive calendar-day count. Returns "—" when a date is missing or reversed. */
export function deriveDays(args: { start?: unknown; end?: unknown }): string {
  const start = typeof args.start === "string" ? args.start : "";
  const end = typeof args.end === "string" ? args.end : "";
  if (!start || !end) return "—";
  const a = Date.parse(`${start}T00:00:00Z`);
  const b = Date.parse(`${end}T00:00:00Z`);
  if (Number.isNaN(a) || Number.isNaN(b) || b < a) return "—";
  return String(Math.round((b - a) / 86_400_000) + 1);
}

export function resolvedDays(
  days: unknown,
  startDate: unknown,
  endDate: unknown,
): string {
  if (typeof days === "number" && Number.isFinite(days)) return String(days);
  if (typeof days === "string") {
    const trimmed = days.trim();
    if (trimmed !== "" && Number.isFinite(Number(trimmed))) return trimmed;
  }
  return deriveDays({
    start: typeof startDate === "string" ? startDate : "",
    end: typeof endDate === "string" ? endDate : "",
  });
}
