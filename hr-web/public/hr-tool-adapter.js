/* hr-web — tool-result → A2UI wire-message adapter.
 *
 * The AgentCore runtime (module 6) still emits AG-UI events today: typed
 * tool-call-result JSON, not A2UI wire messages. This file translates each
 * known tool result into the A2UI v1.0 message shape (createSurface /
 * updateComponents / deleteSurface) the hand-rolled MessageProcessor
 * already consumes. When the runtime is later updated to emit A2UI messages
 * directly, this adapter collapses to pass-through and the renderer path
 * does not change. See hr-web/README.md § "A2UI design choice".
 *
 * There is NO AWS, NO SQL, and NO secret handling here: this module reads
 * one typed JSON object per tool result and returns a list of plain A2UI
 * messages.
 */

(() => {
  "use strict";

  const PROTOCOL_VERSION = "1.0";
  const CATALOG_ID = "https://hr-web.local/catalogs/hr-platform-v1/catalog.json";

  const SURFACE_IDS = Object.freeze({
    leaveBalance: "surface-leave-balance",
    allowance: "surface-allowance",
    reports: "surface-direct-reports",
    probation: "surface-probation",
    employeeConfirm: "surface-employee-confirm",
    managerReview: "surface-manager-review",
    notice: (slug) => `surface-notice-${slug}`,
  });

  function reasonLabel(code) {
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
    return String(code).replace(/_/g, " ").toLowerCase();
  }

  function _createOne(surfaceId, properties) {
    return {
      version: PROTOCOL_VERSION,
      createSurface: {
        surfaceId,
        catalogId: CATALOG_ID,
        components: [
          Object.assign({ id: "root" }, properties),
        ],
      },
    };
  }

  function _deleteOne(surfaceId) {
    return { version: PROTOCOL_VERSION, deleteSurface: { surfaceId } };
  }

  function _recreate(surfaceId, properties) {
    return [_deleteOne(surfaceId), _createOne(surfaceId, properties)];
  }

  /* ------------------------------------------------- per-tool mapping */

  function _leaveBalance(result) {
    const authorized = result && result.authorized === true && result.data;
    if (!authorized) {
      return _recreate(SURFACE_IDS.leaveBalance, {
        component: "LeaveBalanceCard",
        status: "err",
        statusLabel: reasonLabel(result && result.reason_code),
        reasonCode: (result && result.reason_code) || null,
      });
    }
    const d = result.data;
    const messages = _recreate(SURFACE_IDS.leaveBalance, {
      component: "LeaveBalanceCard",
      status: "ok",
      statusLabel: "OK",
      annualDays: typeof d.annual === "number" ? d.annual : null,
      sickDays: typeof d.sick === "number" ? d.sick : null,
      onProbation: Boolean(d.on_probation),
      probationEndDate: d.probation_end_date || null,
    });
    if (d.on_probation) {
      messages.push(..._recreate(SURFACE_IDS.probation, {
        component: "ProbationNotice",
        probationEndDate: d.probation_end_date || null,
        reasonCode: "PROBATION_PERIOD",
      }));
    }
    return messages;
  }

  function _allowance(result) {
    const authorized = result && result.authorized === true && result.data;
    if (!authorized) {
      return _recreate(SURFACE_IDS.allowance, {
        component: "AllowanceCard",
        status: "err",
        statusLabel: reasonLabel(result && result.reason_code),
        reasonCode: (result && result.reason_code) || null,
      });
    }
    const d = result.data;
    return _recreate(SURFACE_IDS.allowance, {
      component: "AllowanceCard",
      status: d.amount == null ? "empty" : "ok",
      statusLabel: d.amount == null ? "No entry" : "OK",
      itemType: d.item_type != null ? String(d.item_type) : "",
      period: d.period != null ? String(d.period) : "",
      amount: d.amount == null ? null : d.amount,
      currency: d.currency ? String(d.currency) : "",
    });
  }

  function _directReports(result) {
    const authorized = result && result.authorized === true && result.data;
    if (!authorized) {
      return _recreate(SURFACE_IDS.reports, {
        component: "DirectReportsTable",
        status: "err",
        statusLabel: reasonLabel(result && result.reason_code),
        reasonCode: (result && result.reason_code) || null,
        reports: [],
      });
    }
    const reports = Array.isArray(result.data.reports) ? result.data.reports : [];
    return _recreate(SURFACE_IDS.reports, {
      component: "DirectReportsTable",
      status: "ok",
      statusLabel: `${reports.length} direct`,
      reports: reports.map((r) => ({
        employee_id: r && r.employee_id ? String(r.employee_id) : "",
        full_name: r && r.full_name ? String(r.full_name) : "",
      })),
    });
  }

  function _leaveEligibility(result) {
    if (!result) return [];
    if (result.authorized === false && result.reason_code === "PROBATION_PERIOD") {
      return _recreate(SURFACE_IDS.probation, {
        component: "ProbationNotice",
        probationEndDate: (result.data && result.data.probation_end_date) || null,
        reasonCode: "PROBATION_PERIOD",
      });
    }
    return [];
  }

  function _submitLeaveRequest(result) {
    if (!result) return [];
    const messages = [_deleteOne(SURFACE_IDS.employeeConfirm)];
    if (result.authorized === true && result.data) {
      const slug = result.data.request_id
        ? String(result.data.request_id).toLowerCase().replace(/[^a-z0-9]+/g, "-")
        : `submit-${Date.now().toString(36)}`;
      messages.push(..._recreate(SURFACE_IDS.notice(slug), {
        component: "Notice",
        variant: "ok",
        title: "Leave submitted",
        body: `Request ${result.data.request_id || ""} is pending your manager's review.`,
      }));
    } else {
      messages.push(..._recreate(SURFACE_IDS.notice("submit-refused"), {
        component: "Notice",
        variant: "warn",
        title: "Submit refused",
        body: `Submission refused: ${reasonLabel(result.reason_code)}.`,
      }));
    }
    return messages;
  }

  function _recordLeaveDecision(result) {
    if (!result) return [];
    const messages = [_deleteOne(SURFACE_IDS.managerReview)];
    if (result.authorized === true && result.data) {
      const slug = result.data.request_id
        ? String(result.data.request_id).toLowerCase().replace(/[^a-z0-9]+/g, "-")
        : `decision-${Date.now().toString(36)}`;
      messages.push(..._recreate(SURFACE_IDS.notice(`decision-${slug}`), {
        component: "Notice",
        variant: "ok",
        title: "Decision recorded",
        body: `Request ${result.data.request_id || ""} is now ${result.data.status || "updated"}.`,
      }));
    } else if (result.reason_code === "NOT_REVIEWER") {
      messages.push(..._recreate(SURFACE_IDS.notice("not-reviewer"), {
        component: "Notice",
        variant: "warn",
        title: "Policy decision",
        body: "You are not the reviewer for that request. The row stays pending.",
      }));
    } else {
      messages.push(..._recreate(SURFACE_IDS.notice("decision-refused"), {
        component: "Notice",
        variant: "warn",
        title: "Policy decision",
        body: reasonLabel(result.reason_code),
      }));
    }
    return messages;
  }

  function _compensation(result) {
    if (!result) return [];
    if (result.authorized === true) return [];
    return _recreate(SURFACE_IDS.notice("compensation-refused"), {
      component: "Notice",
      variant: "warn",
      title: "Policy decision",
      body: "You are not allowed to see this salary.",
    });
  }

  const TOOL_HANDLERS = Object.freeze({
    get_leave_balance: _leaveBalance,
    get_allowance: _allowance,
    list_direct_reports: _directReports,
    check_leave_eligibility: _leaveEligibility,
    submit_leave_request: _submitLeaveRequest,
    record_leave_decision: _recordLeaveDecision,
    get_employee_compensation: _compensation,
  });

  /* ------------------------------------------------- interrupt mapping */

  function _employeeConfirmFromInterrupt(payload) {
    const proposed = payload.arguments || payload.proposed || payload;
    return _recreate(SURFACE_IDS.employeeConfirm, {
      component: "EmployeeConfirmForm",
      interruptKind: "employee_confirm",
      leaveType: proposed.leave_type ? String(proposed.leave_type) : "",
      startDate: proposed.start_date ? String(proposed.start_date) : "",
      endDate: proposed.end_date ? String(proposed.end_date) : "",
      days: proposed.days != null ? proposed.days : "",
      reason: proposed.reason ? String(proposed.reason) : "",
    });
  }

  function _managerReviewFromInterrupt(payload) {
    return _recreate(SURFACE_IDS.managerReview, {
      component: "ManagerReviewCard",
      interruptKind: "manager_review",
      requestId: payload.request_id ? String(payload.request_id) : "",
      employeeId: payload.employee_id ? String(payload.employee_id) : "",
      leaveType: payload.leave_type ? String(payload.leave_type) : "",
      startDate: payload.start_date ? String(payload.start_date) : "",
      endDate: payload.end_date ? String(payload.end_date) : "",
      days: payload.days != null ? payload.days : "",
      reason: payload.reason != null ? String(payload.reason) : "",
    });
  }

  /* ------------------------------------------------- public API */

  function fromToolResult(toolName, result) {
    const rawName = String(toolName || "");
    const bareName = rawName.includes("___") ? rawName.split("___").pop() : rawName;
    const handler = TOOL_HANDLERS[bareName];
    if (!handler) return [];
    try {
      return handler(result) || [];
    } catch (err) {
      return [{
        version: PROTOCOL_VERSION,
        error: {
          code: "ADAPTER_FAILED",
          message: `Adapter for ${bareName} failed: ${err.message}`,
        },
      }];
    }
  }

  function fromInterrupt(payload) {
    if (!payload || typeof payload !== "object") return [];
    if (payload.kind === "employee_confirm") return _employeeConfirmFromInterrupt(payload);
    if (payload.kind === "manager_review") return _managerReviewFromInterrupt(payload);
    return [];
  }

  function clearSurfacesFor(kind) {
    if (kind === "employee_confirm") return [_deleteOne(SURFACE_IDS.employeeConfirm)];
    if (kind === "manager_review") return [_deleteOne(SURFACE_IDS.managerReview)];
    return [];
  }

  window.HrToolAdapter = Object.freeze({
    PROTOCOL_VERSION,
    CATALOG_ID,
    SURFACE_IDS,
    TOOL_HANDLERS,
    reasonLabel,
    fromToolResult,
    fromInterrupt,
    clearSurfacesFor,
  });
})();
