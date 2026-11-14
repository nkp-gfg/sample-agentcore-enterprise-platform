/* hr-web — Enterprise & HR A2UI primitive renderers.
 *
 * Each export is an A2UI catalog component: a function
 * ``(properties, context) -> HTMLElement`` registered with the
 * MessageProcessor in ``hr-catalog.json``. The renderer is intentionally
 * dumb: it reads only the properties A2UI binds for it and never fetches,
 * decides, or routes. The two review primitives (EmployeeConfirmForm,
 * ManagerReviewCard) emit A2UI ``action`` events on button press; the app
 * shell turns a specific action into an AG-UI resume with
 * ``forwardedProps.resume``. The Reason field on the manager review is
 * drawn as plain text and NEVER written back into a prompt.
 *
 * See ui-primitives.md for the catalog of components, their fields, and
 * the action events each one emits.
 */

(() => {
  "use strict";

  const el = (tag, cls, text) => {
    const n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text !== undefined && text !== null) n.textContent = text;
    return n;
  };

  function _kv(dt, dd) {
    const row = document.createElement("div");
    row.append(el("dt", "", dt), el("dd", "", dd));
    return row;
  }

  function _tag(label, variant) {
    const t = el("span", "hr-card-tag", label);
    if (variant === "ok") t.classList.add("hr-card-tag--ok");
    else if (variant === "err") t.classList.add("hr-card-tag--err");
    else if (variant === "pending") t.classList.add("hr-card-tag--pending");
    else if (variant === "blocked") t.classList.add("hr-card-tag--blocked");
    return t;
  }

  function _formatDays(value) {
    if (typeof value === "number") return `${value} day${value === 1 ? "" : "s"}`;
    if (typeof value === "string" && value) return value;
    return "—";
  }

  function _formatAmount(value) {
    if (typeof value === "number") return value.toFixed(2);
    if (value == null) return "—";
    return String(value);
  }

  function _text(value) {
    return (value == null || value === "") ? "—" : String(value);
  }

  function deriveDays(args) {
    const start = typeof args.start === "string" ? args.start : "";
    const end = typeof args.end === "string" ? args.end : "";
    if (!start || !end) return "—";
    const a = Date.parse(`${start}T00:00:00Z`);
    const b = Date.parse(`${end}T00:00:00Z`);
    if (Number.isNaN(a) || Number.isNaN(b) || b < a) return "—";
    return String(Math.round((b - a) / 86_400_000) + 1);
  }

  function _resolvedDays(days, startDate, endDate) {
    if (typeof days === "number" && Number.isFinite(days)) return String(days);
    if (typeof days === "string") {
      const trimmed = days.trim();
      if (trimmed !== "" && Number.isFinite(Number(trimmed))) return trimmed;
    }
    return deriveDays({ start: startDate, end: endDate });
  }

  /* ------------------------------------------------- layout primitives */

  function Column(props, ctx) {
    const node = el("div", "a2ui-column");
    node.dataset.gap = props.gap || "md";
    node.dataset.align = props.align || "stretch";
    for (const childId of props.children || []) {
      const child = ctx.renderChild(childId);
      if (child) node.append(child);
    }
    return node;
  }

  function Row(props, ctx) {
    const node = el("div", "a2ui-row");
    node.dataset.gap = props.gap || "sm";
    node.dataset.align = props.align || "center";
    node.dataset.justify = props.justify || "start";
    for (const childId of props.children || []) {
      const child = ctx.renderChild(childId);
      if (child) node.append(child);
    }
    return node;
  }

  function Heading(props) {
    const level = [2, 3, 4].includes(props.level) ? props.level : 2;
    const node = document.createElement(`h${level}`);
    node.className = "a2ui-heading";
    node.append(el("span", "a2ui-heading-text", _text(props.text)));
    if (props.tag) {
      node.append(_tag(String(props.tag), props.tagVariant));
    }
    return node;
  }

  function TextComp(props) {
    const variant = ["muted", "error", "warning", "mono"].includes(props.variant)
      ? props.variant
      : "body";
    return el("p", `a2ui-text a2ui-text--${variant}`, _text(props.text));
  }

  function Button(props, ctx) {
    const variant = ["primary", "outline", "ghost"].includes(props.variant)
      ? props.variant
      : "primary";
    const cls = variant === "primary" ? "hr-button" : `hr-button hr-button--${variant}`;
    const btn = el("button", cls, _text(props.label));
    btn.type = "button";
    if (props.disabled) btn.disabled = true;
    btn.addEventListener("click", () => {
      if (!props.action || !props.action.event) return;
      ctx.emitAction(props.action.event);
    });
    return btn;
  }

  function Notice(props) {
    const variant = ["info", "ok", "warn", "err"].includes(props.variant)
      ? props.variant
      : "info";
    const node = el("div", `hr-notice hr-notice--${variant}`);
    if (props.title) node.append(el("strong", "hr-notice-title", String(props.title)));
    node.append(el("span", "hr-notice-body", _text(props.body)));
    return node;
  }

  /* ------------------------------------------------- HR primitives */

  function LeaveBalanceCard(props) {
    const card = el("section", "hr-card");
    const head = el("header", "hr-card-head");
    head.append(el("h2", "", "Leave balance"));
    const statusLabel = _text(props.statusLabel || "OK");
    head.append(_tag(statusLabel, props.status || "ok"));
    card.append(head);
    const dl = el("dl", "hr-kv");
    dl.append(_kv("Annual", _formatDays(props.annualDays)));
    dl.append(_kv("Sick", _formatDays(props.sickDays)));
    const probationText = props.onProbation
      ? (props.probationEndDate ? `Until ${props.probationEndDate}` : "On probation")
      : (props.status === "err" && props.onProbation == null ? "—" : "Not on probation");
    dl.append(_kv("Probation", probationText));
    card.append(dl);
    return card;
  }

  function AllowanceCard(props) {
    const card = el("section", "hr-card");
    const head = el("header", "hr-card-head");
    head.append(el("h2", "", "Allowance"));
    const variant = props.status === "err" ? "err"
      : props.status === "empty" ? "blocked"
      : "ok";
    head.append(_tag(_text(props.statusLabel || "OK"), variant));
    card.append(head);
    const dl = el("dl", "hr-kv");
    dl.append(_kv("Item", _text(props.itemType)));
    dl.append(_kv("Period", _text(props.period)));
    const amountValue = props.amount == null
      ? (props.status === "err" ? "—" : "No entry for this period")
      : `${_formatAmount(props.amount)} ${_text(props.currency || "")}`.trim();
    dl.append(_kv("Amount", amountValue));
    card.append(dl);
    return card;
  }

  function DirectReportsTable(props) {
    const card = el("section", "hr-card");
    const head = el("header", "hr-card-head");
    head.append(el("h2", "", "Direct reports"));
    const reports = Array.isArray(props.reports) ? props.reports : [];
    const variant = props.status === "err" ? "err" : "ok";
    head.append(_tag(_text(props.statusLabel || `${reports.length} direct`), variant));
    card.append(head);
    if (reports.length === 0) {
      const emptyMsg = props.status === "err"
        ? "Unable to load direct reports."
        : "No direct reports.";
      card.append(el("p", "hr-note", emptyMsg));
    } else {
      const ul = el("ul", "hr-reports");
      for (const r of reports) {
        const li = document.createElement("li");
        li.append(el("span", "mono", _text(r && r.employee_id)));
        li.append(el("span", "", _text((r && r.full_name) || (r && r.employee_id))));
        li.append(el("span", "hr-card-tag", "direct"));
        ul.append(li);
      }
      card.append(ul);
    }
    return card;
  }

  function ProbationNotice(props) {
    const card = el("section", "hr-card hr-card--notice");
    const head = el("header", "hr-card-head");
    head.append(el("h2", "", "On probation"));
    head.append(_tag("Leave blocked", "blocked"));
    card.append(head);
    const body = props.probationEndDate
      ? `Leave can be booked after ${props.probationEndDate}. Every leave type is blocked while probation is still active, on eligibility and on submit.`
      : "Every leave type is blocked while probation is still active, on eligibility and on submit.";
    card.append(el("p", "", body));
    return card;
  }

  function EmployeeConfirmForm(props, ctx) {
    const card = el("section", "hr-card hr-card--review");
    card.dataset.interruptKind = "employee_confirm";
    const head = el("header", "hr-card-head");
    head.append(el("h2", "", "Confirm leave request"));
    head.append(_tag("Awaiting your confirmation", "pending"));
    card.append(head);
    const dl = el("dl", "hr-kv");
    dl.append(_kv("Leave type", _text(props.leaveType)));
    dl.append(_kv("Start", _text(props.startDate)));
    dl.append(_kv("End", _text(props.endDate)));
    dl.append(_kv("Days", _text(_resolvedDays(props.days, props.startDate, props.endDate))));
    dl.append(_kv("Reason", _text(props.reason)));
    card.append(dl);
    card.append(el("p", "hr-note",
      "Confirming here submits one pending request. Your balance is not reduced "
      + "until your manager approves. Typing \u201capprove\u201d in the chat does nothing."));

    // Inline date/type editor (replaces blocked window.prompt() dialogs).
    const editBox = el("div", "hr-edit-box");
    editBox.hidden = true;
    const typeLabel = el("label", "hr-edit-field");
    typeLabel.append(el("span", "hr-edit-label", "Leave type"));
    const typeSelect = el("select", "hr-input hr-input--sm");
    for (const optVal of ["annual", "sick"]) {
      const opt = el("option", "", optVal);
      opt.value = optVal;
      if ((props.leaveType || "annual") === optVal) opt.selected = true;
      typeSelect.append(opt);
    }
    typeLabel.append(typeSelect);

    const startLabel = el("label", "hr-edit-field");
    startLabel.append(el("span", "hr-edit-label", "Start date (YYYY-MM-DD)"));
    const startInput = el("input", "hr-input hr-input--sm");
    startInput.type = "date";
    startInput.value = props.startDate || "";
    startLabel.append(startInput);

    const endLabel = el("label", "hr-edit-field");
    endLabel.append(el("span", "hr-edit-label", "End date (YYYY-MM-DD)"));
    const endInput = el("input", "hr-input hr-input--sm");
    endInput.type = "date";
    endInput.value = props.endDate || "";
    endLabel.append(endInput);

    editBox.append(typeLabel, startLabel, endLabel);
    card.append(editBox);

    const actions = el("div", "hr-actions");
    const buildPayload = () => ({
      kind: "employee_confirm",
      leave_type: typeSelect.value || props.leaveType || "",
      start_date: startInput.value || props.startDate || "",
      end_date: endInput.value || props.endDate || "",
      reason: props.reason || "",
    });
    const makeButton = (label, variant, actionName, onClick) => {
      const btn = el("button",
        `hr-button${variant ? " hr-button--" + variant : ""}`, label);
      btn.type = "button";
      btn.dataset.action = actionName;
      btn.addEventListener("click", onClick);
      return btn;
    };
    const rejectBtn = makeButton("Reject", "ghost", "employee_reject_leave", () =>
      ctx.emitAction({ name: "employee_reject_leave", context: buildPayload() }),
    );
    const editBtn = makeButton("Edit dates", "outline", "employee_edit_leave", () => {
      if (editBox.hidden) {
        editBox.hidden = false;
        editBtn.textContent = "Submit edited";
        editBtn.setAttribute("aria-expanded", "true");
        startInput.focus();
        return;
      }
      ctx.emitAction({ name: "employee_edit_leave", context: buildPayload() });
    });
    editBtn.setAttribute("aria-expanded", "false");
    const confirmBtn = makeButton("Confirm", "", "employee_confirm_leave", () =>
      ctx.emitAction({ name: "employee_confirm_leave", context: buildPayload() }),
    );
    actions.append(rejectBtn, editBtn, confirmBtn);
    card.append(actions);
    return card;
  }

  function ManagerReviewCard(props, ctx) {
    const card = el("section", "hr-card hr-card--review");
    card.dataset.interruptKind = "manager_review";
    const head = el("header", "hr-card-head");
    head.append(el("h2", "", "Pending review"));
    head.append(_tag("Awaiting your decision", "pending"));
    card.append(head);
    const dl = el("dl", "hr-kv");
    dl.append(_kv("Request", _text(props.requestId)));
    dl.append(_kv("Employee", _text(props.employeeId)));
    dl.append(_kv("Leave type", _text(props.leaveType)));
    dl.append(_kv("Start", _text(props.startDate)));
    dl.append(_kv("End", _text(props.endDate)));
    dl.append(_kv("Days", _text(_resolvedDays(props.days, props.startDate, props.endDate))));
    card.append(dl);
    const reason = el("div", "hr-reason");
    reason.append(el("span", "hr-reason-label",
      "Reason (shown as plain text; no model reads it)"));
    const body = el("pre", "hr-reason-body");
    body.textContent = props.reason != null ? String(props.reason) : "";
    reason.append(body);
    card.append(reason);
    const actions = el("div", "hr-actions");
    const ctxPayload = {
      kind: "manager_review",
      request_id: props.requestId || "",
    };
    const makeButton = (label, variant, actionName) => {
      const btn = el("button",
        `hr-button${variant ? " hr-button--" + variant : ""}`, label);
      btn.type = "button";
      btn.dataset.action = actionName;
      btn.addEventListener("click", () => ctx.emitAction(
        { name: actionName, context: ctxPayload },
      ));
      return btn;
    };
    actions.append(makeButton("Reject", "ghost", "manager_reject_review"));
    actions.append(makeButton("Approve", "", "manager_approve_review"));
    card.append(actions);
    return card;
  }

  /* ------------------------------------------------- bundle */

  const components = {
    Column,
    Row,
    Heading,
    Text: TextComp,
    Button,
    Notice,
    LeaveBalanceCard,
    AllowanceCard,
    DirectReportsTable,
    ProbationNotice,
    EmployeeConfirmForm,
    ManagerReviewCard,
  };

  const functions = {
    deriveDays,
  };

  window.HrCatalog = Object.freeze({
    components,
    functions,
    deriveDays,
    build(catalogDocument) {
      if (!catalogDocument || typeof catalogDocument !== "object") {
        throw new Error("hr-catalog.json did not parse to an object.");
      }
      const names = Object.keys(catalogDocument.components || {});
      for (const name of names) {
        if (!components[name]) {
          throw new Error(
            `hr-catalog.json declares ${name}, but hr-primitives.js does not draw it.`,
          );
        }
      }
      return {
        catalogId: catalogDocument.catalogId || "hr-platform-v1",
        protocolVersion: catalogDocument.protocolVersion || "1.0",
        components,
        functions,
      };
    },
  });
})();
