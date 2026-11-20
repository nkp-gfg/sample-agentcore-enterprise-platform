/**
 * Tool-result and interrupt payloads to A2UI v1.0 wire messages.
 * Behavior matches hr-web/public/hr-tool-adapter.js, including surface ids
 * and reason codes. This module reads one JSON value and returns messages.
 */

export const PROTOCOL_VERSION = "1.0";
export const CATALOG_ID =
  "https://hr-web.local/catalogs/hr-platform-v1/catalog.json";

export const SURFACE_IDS = Object.freeze({
  leaveBalance: "surface-leave-balance",
  allowance: "surface-allowance",
  reports: "surface-direct-reports",
  probation: "surface-probation",
  employeeConfirm: "surface-employee-confirm",
  managerReview: "surface-manager-review",
  managerReviewFor: (key: string) => {
    const slug = String(key || "")
      .trim()
      .toLowerCase()
      .replace(/[^a-z0-9_-]+/g, "-");
    return slug ? `surface-manager-review-${slug}` : "surface-manager-review";
  },
  notice: (slug: string) => `surface-notice-${slug}`,
});

export interface A2uiCreateMessage {
  version: typeof PROTOCOL_VERSION;
  createSurface: {
    surfaceId: string;
    catalogId: string;
    components: Array<Record<string, unknown>>;
  };
}

export interface A2uiDeleteMessage {
  version: typeof PROTOCOL_VERSION;
  deleteSurface: { surfaceId: string };
}

export interface A2uiAdapterErrorMessage {
  version: typeof PROTOCOL_VERSION;
  error: { code: string; message: string };
}

export type A2uiWireMessage =
  | A2uiCreateMessage
  | A2uiDeleteMessage
  | A2uiAdapterErrorMessage;

type JsonRecord = Record<string, unknown>;

function isRecord(value: unknown): value is JsonRecord {
  return typeof value === "object" && value !== null;
}

export function reasonLabel(code: unknown): string {
  if (!code) return "—";
  if (code === "NOT_AUTHORIZED") return "Not allowed";
  if (code === "SERVICE_DISABLED") return "HR is paused";
  if (code === "PROBATION_PERIOD") return "On probation";
  if (code === "INSUFFICIENT_BALANCE") return "Over balance";
  if (code === "INVALID_RANGE") return "Invalid range";
  if (code === "OVERLAP") return "Overlap";
  if (code === "IDEMPOTENCY_CONFLICT") return "Key conflict";
  if (code === "NOT_REVIEWER") return "Not reviewer";
  if (code === "NOT_MAPPED") return "Unmapped caller";
  if (code === "DATA_UNAVAILABLE") return "Data unavailable";
  if (code === "INVALID_LEAVE_TYPE") return "Invalid leave type";
  if (code === "INVALID_ITEM") return "Invalid item";
  if (code === "CANCELLED_BY_EMPLOYEE") return "Cancelled";
  if (code === "INVALID_DECISION") return "Invalid decision";
  if (code === "RATE_LIMITED") return "Rate limited";
  if (code === "LIMIT_RECURSION") return "Turn limit reached";
  const text = String(code).replace(/_/g, " ").toLowerCase();
  return text.charAt(0).toUpperCase() + text.slice(1);
}

function createOne(
  surfaceId: string,
  properties: JsonRecord,
): A2uiCreateMessage {
  return {
    version: PROTOCOL_VERSION,
    createSurface: {
      surfaceId,
      catalogId: CATALOG_ID,
      components: [{ id: "root", ...properties }],
    },
  };
}

function deleteOne(surfaceId: string): A2uiDeleteMessage {
  return { version: PROTOCOL_VERSION, deleteSurface: { surfaceId } };
}

function recreate(
  surfaceId: string,
  properties: JsonRecord,
): A2uiWireMessage[] {
  return [deleteOne(surfaceId), createOne(surfaceId, properties)];
}

function reasonCode(result: JsonRecord | null): string | null {
  const code = result?.reason_code;
  return typeof code === "string" && code ? code : null;
}

function dataOf(result: JsonRecord | null): JsonRecord | null {
  if (!result || result.authorized !== true || !isRecord(result.data)) return null;
  return result.data;
}

function leaveBalance(result: unknown): A2uiWireMessage[] {
  const record = isRecord(result) ? result : null;
  const data = dataOf(record);
  if (!data) {
    return recreate(SURFACE_IDS.leaveBalance, {
      component: "LeaveBalanceCard",
      status: "err",
      statusLabel: reasonLabel(record?.reason_code),
      reasonCode: reasonCode(record),
    });
  }
  const messages = recreate(SURFACE_IDS.leaveBalance, {
    component: "LeaveBalanceCard",
    status: "ok",
    statusLabel: "OK",
    annualDays: typeof data.annual === "number" ? data.annual : null,
    sickDays: typeof data.sick === "number" ? data.sick : null,
    onProbation: Boolean(data.on_probation),
    probationEndDate: data.probation_end_date || null,
  });
  if (data.on_probation) {
    messages.push(
      ...recreate(SURFACE_IDS.probation, {
        component: "ProbationNotice",
        probationEndDate: data.probation_end_date || null,
        reasonCode: "PROBATION_PERIOD",
      }),
    );
  }
  return messages;
}

function allowance(result: unknown): A2uiWireMessage[] {
  const record = isRecord(result) ? result : null;
  const data = dataOf(record);
  if (!data) {
    return recreate(SURFACE_IDS.allowance, {
      component: "AllowanceCard",
      status: "err",
      statusLabel: reasonLabel(record?.reason_code),
      reasonCode: reasonCode(record),
    });
  }
  return recreate(SURFACE_IDS.allowance, {
    component: "AllowanceCard",
    status: data.amount == null ? "empty" : "ok",
    statusLabel: data.amount == null ? "No entry" : "OK",
    itemType: data.item_type != null ? String(data.item_type) : "",
    period: data.period != null ? String(data.period) : "",
    amount: data.amount == null ? null : data.amount,
    currency: data.currency ? String(data.currency) : "",
  });
}

function directReports(result: unknown): A2uiWireMessage[] {
  const record = isRecord(result) ? result : null;
  const data = dataOf(record);
  if (!data) {
    return recreate(SURFACE_IDS.reports, {
      component: "DirectReportsTable",
      status: "err",
      statusLabel: reasonLabel(record?.reason_code),
      reasonCode: reasonCode(record),
      reports: [],
    });
  }
  const reports = Array.isArray(data.reports) ? data.reports : [];
  return recreate(SURFACE_IDS.reports, {
    component: "DirectReportsTable",
    status: "ok",
    statusLabel: `${reports.length} direct`,
    reports: reports.map((entry) => {
      const row = isRecord(entry) ? entry : null;
      return {
        employee_id: row?.employee_id ? String(row.employee_id) : "",
        full_name: row?.full_name ? String(row.full_name) : "",
      };
    }),
  });
}

function leaveEligibility(result: unknown): A2uiWireMessage[] {
  if (!isRecord(result)) return [];
  if (result.authorized === false) {
    if (result.reason_code === "PROBATION_PERIOD") {
      const data = isRecord(result.data) ? result.data : null;
      return recreate(SURFACE_IDS.probation, {
        component: "ProbationNotice",
        probationEndDate: data?.probation_end_date || null,
        reasonCode: "PROBATION_PERIOD",
      });
    }
    return recreate(SURFACE_IDS.notice("eligibility-refused"), {
      component: "Notice",
      variant: "warn",
      title: "Leave eligibility",
      body: `Request is not eligible: ${reasonLabel(result.reason_code)}.`,
    });
  }
  return [deleteOne(SURFACE_IDS.notice("eligibility-refused"))];
}

function submitLeaveRequest(result: unknown): A2uiWireMessage[] {
  if (!isRecord(result)) return [];
  const messages: A2uiWireMessage[] = [
    deleteOne(SURFACE_IDS.employeeConfirm),
    deleteOne(SURFACE_IDS.notice("eligibility-refused")),
  ];
  const data = isRecord(result.data) ? result.data : null;
  if (result.authorized === true && data) {
    messages.push(
      deleteOne(SURFACE_IDS.notice("submit-refused")),
      deleteOne(SURFACE_IDS.notice("submit-cancelled")),
    );
    const reviewer = data.reviewer_employee_id
      ? ` (${String(data.reviewer_employee_id)})`
      : "";
    messages.push(
      ...recreate(SURFACE_IDS.notice("leave-submitted"), {
        component: "Notice",
        variant: "ok",
        title: "Leave submitted",
        body: `Request ${data.request_id || ""} is pending your manager's review${reviewer}.`,
      }),
    );
  } else if (result.reason_code === "CANCELLED_BY_EMPLOYEE") {
    messages.push(
      deleteOne(SURFACE_IDS.notice("submit-refused")),
      deleteOne(SURFACE_IDS.notice("leave-submitted")),
    );
    messages.push(
      ...recreate(SURFACE_IDS.notice("submit-cancelled"), {
        component: "Notice",
        variant: "info",
        title: "Request cancelled",
        body: "No leave request was submitted.",
      }),
    );
  } else {
    messages.push(
      deleteOne(SURFACE_IDS.notice("submit-cancelled")),
      deleteOne(SURFACE_IDS.notice("leave-submitted")),
    );
    messages.push(
      ...recreate(SURFACE_IDS.notice("submit-refused"), {
        component: "Notice",
        variant: "warn",
        title: "Submit refused",
        body: `Submission refused: ${reasonLabel(result.reason_code)}.`,
      }),
    );
  }
  return messages;
}

function recordLeaveDecision(result: unknown): A2uiWireMessage[] {
  if (!isRecord(result)) return [];
  const messages: A2uiWireMessage[] = [
    deleteOne(SURFACE_IDS.managerReview),
    deleteOne(SURFACE_IDS.notice("leave-decision")),
    deleteOne(SURFACE_IDS.notice("not-reviewer")),
    deleteOne(SURFACE_IDS.notice("decision-refused")),
  ];
  const data = isRecord(result.data) ? result.data : null;
  if (data?.request_id) {
    messages.push(deleteOne(SURFACE_IDS.managerReviewFor(String(data.request_id))));
  }
  if (result.authorized === true && data) {
    messages.push(
      ...recreate(SURFACE_IDS.notice("leave-decision"), {
        component: "Notice",
        variant: "ok",
        title: "Decision recorded",
        body: `Request ${data.request_id || ""} is now ${data.status || "updated"}.`,
      }),
    );
  } else if (result.reason_code === "NOT_REVIEWER") {
    messages.push(
      ...recreate(SURFACE_IDS.notice("not-reviewer"), {
        component: "Notice",
        variant: "warn",
        title: "Policy decision",
        body: "You are not the reviewer for that request. The row stays pending.",
      }),
    );
  } else {
    messages.push(
      ...recreate(SURFACE_IDS.notice("decision-refused"), {
        component: "Notice",
        variant: "warn",
        title: "Policy decision",
        body: reasonLabel(result.reason_code),
      }),
    );
  }
  return messages;
}

function compensation(result: unknown): A2uiWireMessage[] {
  if (!isRecord(result)) return [];
  if (result.authorized === true) return [];
  const body =
    result.reason_code && result.reason_code !== "NOT_AUTHORIZED"
      ? reasonLabel(result.reason_code)
      : "You are not allowed to see this salary.";
  return recreate(SURFACE_IDS.notice("compensation-refused"), {
    component: "Notice",
    variant: "warn",
    title: "Policy decision",
    body,
  });
}

const TOOL_HANDLERS: Record<string, (result: unknown) => A2uiWireMessage[]> =
  Object.freeze({
    get_leave_balance: leaveBalance,
    get_allowance: allowance,
    list_direct_reports: directReports,
    check_leave_eligibility: leaveEligibility,
    submit_leave_request: submitLeaveRequest,
    record_leave_decision: recordLeaveDecision,
    get_employee_compensation: compensation,
  });

function parseFiniteDays(rawDays: unknown): number | null {
  if (typeof rawDays === "number" && Number.isFinite(rawDays)) return rawDays;
  if (typeof rawDays === "string") {
    const trimmed = rawDays.trim();
    if (trimmed !== "" && Number.isFinite(Number(trimmed))) return Number(trimmed);
  }
  return null;
}

function employeeConfirmFromInterrupt(payload: JsonRecord): A2uiWireMessage[] {
  const proposed = isRecord(payload.arguments)
    ? payload.arguments
    : isRecord(payload.proposed)
      ? payload.proposed
      : payload;
  const days = parseFiniteDays(
    proposed.days != null ? proposed.days : payload.days,
  );
  const props: JsonRecord = {
    component: "EmployeeConfirmForm",
    interruptKind: "employee_confirm",
    leaveType: proposed.leave_type ? String(proposed.leave_type) : "",
    startDate: proposed.start_date ? String(proposed.start_date) : "",
    endDate: proposed.end_date ? String(proposed.end_date) : "",
    reason: proposed.reason ? String(proposed.reason) : "",
  };
  if (days !== null) props.days = days;
  return recreate(SURFACE_IDS.employeeConfirm, props);
}

function managerReviewFromInterrupt(payload: JsonRecord): A2uiWireMessage[] {
  const key = String(
    payload.request_id || payload._interruptId || payload.interrupt_id || "",
  );
  const days = parseFiniteDays(payload.days);
  const props: JsonRecord = {
    component: "ManagerReviewCard",
    interruptKind: "manager_review",
    requestId: payload.request_id ? String(payload.request_id) : "",
    employeeId: payload.employee_id ? String(payload.employee_id) : "",
    leaveType: payload.leave_type ? String(payload.leave_type) : "",
    startDate: payload.start_date ? String(payload.start_date) : "",
    endDate: payload.end_date ? String(payload.end_date) : "",
    reason: payload.reason != null ? String(payload.reason) : "",
  };
  if (days !== null) props.days = days;
  return recreate(SURFACE_IDS.managerReviewFor(key), props);
}

export function fromToolResult(
  toolName: unknown,
  result: unknown,
): A2uiWireMessage[] {
  const rawName = String(toolName || "");
  const bareName = rawName.includes("___") ? rawName.split("___").pop() || rawName : rawName;
  const handler = TOOL_HANDLERS[bareName];
  if (!handler) return [];
  try {
    return handler(result) || [];
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return [
      {
        version: PROTOCOL_VERSION,
        error: {
          code: "ADAPTER_FAILED",
          message: `Adapter for ${bareName} failed: ${message}`,
        },
      },
    ];
  }
}

export function fromInterrupt(payload: unknown): A2uiWireMessage[] {
  if (!isRecord(payload)) return [];
  if (payload.kind === "employee_confirm") return employeeConfirmFromInterrupt(payload);
  if (payload.kind === "manager_review") return managerReviewFromInterrupt(payload);
  return [];
}

export function clearSurfacesFor(kind: string, key?: string): A2uiDeleteMessage[] {
  if (kind === "employee_confirm") return [deleteOne(SURFACE_IDS.employeeConfirm)];
  if (kind === "manager_review") {
    return [
      deleteOne(key ? SURFACE_IDS.managerReviewFor(key) : SURFACE_IDS.managerReview),
    ];
  }
  return [];
}

export function clearNonReviewSurfaces(
  surfaceIds: Iterable<string>,
  {
    preserveEmployeeConfirm = false,
    preserveManagerReviews = true,
  }: { preserveEmployeeConfirm?: boolean; preserveManagerReviews?: boolean } = {},
): A2uiDeleteMessage[] {
  const out: A2uiDeleteMessage[] = [];
  for (const rawId of surfaceIds || []) {
    const id = String(rawId || "");
    if (!id) continue;
    if (id === SURFACE_IDS.employeeConfirm && preserveEmployeeConfirm) continue;
    if (
      (id === SURFACE_IDS.managerReview ||
        id.startsWith(`${SURFACE_IDS.managerReview}-`)) &&
      preserveManagerReviews
    ) {
      continue;
    }
    out.push(deleteOne(id));
  }
  return out;
}

export function sanitizeHistoryCards(a2uiMessages: unknown[]): unknown[] {
  return a2uiMessages.filter((msg) => {
    if (!isRecord(msg)) return false;
    const createSurface = isRecord(msg.createSurface) ? msg.createSurface : null;
    const components = createSurface && Array.isArray(createSurface.components)
      ? createSurface.components
      : [];
    const first = isRecord(components[0]) ? components[0] : null;
    const comp = first ? String(first.component || "") : "";
    if (comp === "EmployeeConfirmForm" || comp === "ManagerReviewCard") return false;
    return true;
  });
}
