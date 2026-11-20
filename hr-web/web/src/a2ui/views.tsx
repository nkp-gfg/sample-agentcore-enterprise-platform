import { useState, type ReactNode } from "react";
import type { ComponentContext } from "@a2ui/web_core/v1_0";
import { Badge } from "@/components/ui/badge";
import { Button as UiButton } from "@/components/ui/button";
import { Card, CardContent, CardHeader } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { cn } from "@/lib/utils";
import { deriveDays, resolvedDays } from "./derive-days.ts";

export interface HrViewProps {
  props: Record<string, unknown>;
  buildChild: (id: string, basePath?: string) => ReactNode;
  context: ComponentContext;
}

function textOf(value: unknown): string {
  return value == null || value === "" ? "—" : String(value);
}

function formatDays(value: unknown): string {
  if (typeof value === "number") return `${value} day${value === 1 ? "" : "s"}`;
  if (typeof value === "string" && value) return value;
  return "—";
}

function formatAmount(value: unknown): string {
  if (typeof value === "number") return value.toFixed(2);
  if (value == null) return "—";
  return String(value);
}

function childrenOf(props: Record<string, unknown>, buildChild: HrViewProps["buildChild"]) {
  if (!Array.isArray(props.children)) return null;
  return props.children.map((child, index) => {
    const id = typeof child === "string"
      ? child
      : child && typeof child === "object" && "id" in child
        ? String((child as { id?: unknown }).id ?? "")
        : "";
    if (!id) return null;
    return <div key={`${id}-${index}`}>{buildChild(id)}</div>;
  });
}

const GAP: Record<string, string> = {
  none: "gap-0",
  sm: "gap-2",
  md: "gap-3",
  lg: "gap-5",
};

function gapClass(value: unknown, fallback: string): string {
  return GAP[typeof value === "string" ? value : ""] ?? GAP[fallback] ?? "gap-3";
}

function StatusBadge({
  label,
  tone,
}: {
  label: string;
  tone: "ok" | "err" | "pending" | "blocked";
}) {
  const toneClass = {
    ok: "border-emerald-200 bg-emerald-50 text-emerald-900",
    err: "border-red-200 bg-red-50 text-red-900",
    pending: "border-amber-200 bg-amber-50 text-amber-950",
    blocked: "border-stone-300 bg-stone-100 text-stone-800",
  }[tone];
  return (
    <Badge variant="outline" className={cn("h-auto py-0.5", toneClass)}>
      {label}
    </Badge>
  );
}

function FieldList({ rows }: { rows: Array<[string, string]> }) {
  return (
    <dl className="grid grid-cols-[7.5rem_minmax(0,1fr)] gap-x-4 gap-y-2 text-sm">
      {rows.map(([label, value]) => (
        <div key={label} className="contents">
          <dt className="text-muted-foreground">{label}</dt>
          <dd className="min-w-0 text-foreground">{value}</dd>
        </div>
      ))}
    </dl>
  );
}

export function ColumnView({ props, buildChild }: HrViewProps) {
  const align = props.align === "start" || props.align === "center" ? props.align : "stretch";
  return (
    <div
      className={cn(
        "flex flex-col",
        gapClass(props.gap, "md"),
        align === "start" && "items-start",
        align === "center" && "items-center",
        align === "stretch" && "items-stretch",
      )}
    >
      {childrenOf(props, buildChild)}
    </div>
  );
}

export function RowView({ props, buildChild }: HrViewProps) {
  const align = ["start", "center", "end", "baseline"].includes(String(props.align))
    ? String(props.align)
    : "center";
  const justify = ["start", "center", "end", "between"].includes(String(props.justify))
    ? String(props.justify)
    : "start";
  return (
    <div
      className={cn(
        "flex flex-row flex-wrap",
        gapClass(props.gap, "sm"),
        align === "start" && "items-start",
        align === "center" && "items-center",
        align === "end" && "items-end",
        align === "baseline" && "items-baseline",
        justify === "start" && "justify-start",
        justify === "center" && "justify-center",
        justify === "end" && "justify-end",
        justify === "between" && "justify-between",
      )}
    >
      {childrenOf(props, buildChild)}
    </div>
  );
}

export function HeadingView({ props }: HrViewProps) {
  const level = props.level === 3 || props.level === 4 ? props.level : 2;
  const Tag = `h${level}` as "h2" | "h3" | "h4";
  const tone = props.tagVariant === "ok"
    || props.tagVariant === "err"
    || props.tagVariant === "pending"
    || props.tagVariant === "blocked"
    ? props.tagVariant
    : "pending";
  return (
    <Tag className="flex flex-wrap items-center gap-2 font-heading text-xl font-medium tracking-tight">
      <span>{textOf(props.text)}</span>
      {props.tag ? <StatusBadge label={String(props.tag)} tone={tone} /> : null}
    </Tag>
  );
}

export function TextView({ props }: HrViewProps) {
  const variant = ["muted", "error", "warning", "mono"].includes(String(props.variant))
    ? String(props.variant)
    : "body";
  return (
    <p
      className={cn(
        "text-sm leading-6",
        variant === "body" && "text-foreground",
        variant === "muted" && "text-muted-foreground",
        variant === "error" && "text-red-800",
        variant === "warning" && "text-amber-900",
        variant === "mono" && "font-mono text-[13px] text-foreground",
      )}
    >
      {textOf(props.text)}
    </p>
  );
}

export function ButtonView({ props, context }: HrViewProps) {
  const variant = props.variant === "outline" || props.variant === "ghost"
    ? props.variant
    : "default";
  return (
    <UiButton
      type="button"
      variant={variant}
      disabled={props.disabled === true}
      onClick={() => {
        const action = props.action;
        if (typeof action === "function") {
          void action();
          return;
        }
        if (!action || typeof action !== "object") return;
        void context.dispatchAction(action as Record<string, unknown>);
      }}
    >
      {textOf(props.label)}
    </UiButton>
  );
}

export function NoticeView({ props }: HrViewProps) {
  const variant = ["info", "ok", "warn", "err"].includes(String(props.variant))
    ? String(props.variant)
    : "info";
  return (
    <div
      className={cn(
        "rounded-lg border px-3 py-2.5 text-sm",
        variant === "info" && "border-sky-200 bg-sky-50 text-sky-950",
        variant === "ok" && "border-emerald-200 bg-emerald-50 text-emerald-950",
        variant === "warn" && "border-amber-200 bg-amber-50 text-amber-950",
        variant === "err" && "border-red-200 bg-red-50 text-red-950",
      )}
    >
      {props.title ? <strong className="mr-2 font-medium">{String(props.title)}</strong> : null}
      <span>{textOf(props.body)}</span>
    </div>
  );
}

function HrCard({
  title,
  status,
  tone,
  children,
}: {
  title: string;
  status: string;
  tone: "ok" | "err" | "pending" | "blocked";
  children: ReactNode;
}) {
  return (
    <Card size="sm" className="shadow-none ring-border">
      <CardHeader className="flex-row items-center justify-between gap-3">
        <h2 className="font-heading text-lg font-medium tracking-tight">{title}</h2>
        <StatusBadge label={status} tone={tone} />
      </CardHeader>
      <CardContent className="flex flex-col gap-3">{children}</CardContent>
    </Card>
  );
}

export function LeaveBalanceCardView({ props }: HrViewProps) {
  const tone = props.status === "err" ? "err" : props.status === "pending" ? "pending" : "ok";
  const probation = props.onProbation
    ? (props.probationEndDate ? `Until ${String(props.probationEndDate)}` : "On probation")
    : props.status === "err" && props.onProbation == null
      ? "—"
      : "Not on probation";
  return (
    <HrCard title="Leave balance" status={textOf(props.statusLabel || "OK")} tone={tone}>
      <FieldList
        rows={[
          ["Annual", formatDays(props.annualDays)],
          ["Sick", formatDays(props.sickDays)],
          ["Probation", probation],
        ]}
      />
    </HrCard>
  );
}

export function AllowanceCardView({ props }: HrViewProps) {
  const tone = props.status === "err" ? "err" : props.status === "empty" ? "blocked" : "ok";
  const amount = props.amount == null
    ? (props.status === "err" ? "—" : "No entry for this period")
    : `${formatAmount(props.amount)} ${textOf(props.currency || "")}`.trim();
  return (
    <HrCard title="Allowance" status={textOf(props.statusLabel || "OK")} tone={tone}>
      <FieldList
        rows={[
          ["Item", textOf(props.itemType)],
          ["Period", textOf(props.period)],
          ["Amount", amount],
        ]}
      />
    </HrCard>
  );
}

export function DirectReportsTableView({ props }: HrViewProps) {
  const reports = Array.isArray(props.reports) ? props.reports : [];
  const tone = props.status === "err" ? "err" : "ok";
  return (
    <HrCard
      title="Direct reports"
      status={textOf(props.statusLabel || `${reports.length} direct`)}
      tone={tone}
    >
      {reports.length === 0 ? (
        <p className="text-sm text-muted-foreground">
          {props.status === "err" ? "Unable to load direct reports." : "No direct reports."}
        </p>
      ) : (
        <ul className="divide-y divide-border">
          {reports.map((entry, index) => {
            const row = entry && typeof entry === "object" ? entry as Record<string, unknown> : {};
            const employeeId = textOf(row.employee_id);
            const name = textOf(row.full_name || row.employee_id);
            return (
              <li key={`${employeeId}-${index}`} className="flex items-center gap-3 py-2 text-sm">
                <span className="font-mono text-xs text-muted-foreground">{employeeId}</span>
                <span className="min-w-0 flex-1">{name}</span>
                <Badge variant="outline">direct</Badge>
              </li>
            );
          })}
        </ul>
      )}
    </HrCard>
  );
}

export function ProbationNoticeView({ props }: HrViewProps) {
  const body = props.probationEndDate
    ? `Leave can be booked after ${String(props.probationEndDate)}. Every leave type is blocked while probation is still active, on eligibility and on submit.`
    : "Every leave type is blocked while probation is still active, on eligibility and on submit.";
  return (
    <HrCard title="On probation" status="Leave blocked" tone="blocked">
      <p className="text-sm leading-6">{body}</p>
    </HrCard>
  );
}

export function EmployeeConfirmFormView({ props, context }: HrViewProps) {
  const [editing, setEditing] = useState(false);
  const [leaveType, setLeaveType] = useState(
    props.leaveType === "sick" ? "sick" : "annual",
  );
  const [startDate, setStartDate] = useState(
    typeof props.startDate === "string" ? props.startDate : "",
  );
  const [endDate, setEndDate] = useState(
    typeof props.endDate === "string" ? props.endDate : "",
  );
  const payload = () => ({
    kind: "employee_confirm",
    leave_type: leaveType || (typeof props.leaveType === "string" ? props.leaveType : ""),
    start_date: startDate || (typeof props.startDate === "string" ? props.startDate : ""),
    end_date: endDate || (typeof props.endDate === "string" ? props.endDate : ""),
    reason: typeof props.reason === "string" ? props.reason : "",
  });
  const emit = (name: string) => {
    void context.dispatchAction({ event: { name, context: payload() } });
  };
  return (
    <HrCard title="Confirm leave request" status="Awaiting your confirmation" tone="pending">
      <FieldList
        rows={[
          ["Leave type", textOf(leaveType || props.leaveType)],
          ["Start", textOf(startDate || props.startDate)],
          ["End", textOf(endDate || props.endDate)],
          ["Days", textOf(resolvedDays(props.days, startDate || props.startDate, endDate || props.endDate))],
          ["Reason", textOf(props.reason)],
        ]}
      />
      <p className="text-sm leading-6 text-muted-foreground">
        Confirming here submits one pending request. Your balance is not reduced
        until your manager approves. Typing “approve” in the chat does nothing.
      </p>
      {editing ? (
        <div className="grid gap-3 sm:grid-cols-3">
          <label className="grid gap-1 text-sm">
            <span className="text-muted-foreground">Leave type</span>
            <select
              className="h-8 rounded-lg border border-input bg-background px-2.5 text-sm"
              value={leaveType}
              onChange={(event) => setLeaveType(event.target.value)}
            >
              <option value="annual">annual</option>
              <option value="sick">sick</option>
            </select>
          </label>
          <label className="grid gap-1 text-sm">
            <span className="text-muted-foreground">Start date</span>
            <Input
              type="date"
              value={startDate}
              onChange={(event) => setStartDate(event.target.value)}
            />
          </label>
          <label className="grid gap-1 text-sm">
            <span className="text-muted-foreground">End date</span>
            <Input
              type="date"
              value={endDate}
              onChange={(event) => setEndDate(event.target.value)}
            />
          </label>
        </div>
      ) : null}
      <div className="flex flex-wrap justify-end gap-2">
        <UiButton type="button" variant="ghost" onClick={() => emit("employee_reject_leave")}>
          Reject
        </UiButton>
        <UiButton
          type="button"
          variant="outline"
          aria-expanded={editing}
          onClick={() => {
            if (!editing) {
              setEditing(true);
              return;
            }
            emit("employee_edit_leave");
          }}
        >
          {editing ? "Submit edited" : "Edit dates"}
        </UiButton>
        <UiButton type="button" onClick={() => emit("employee_confirm_leave")}>
          Confirm
        </UiButton>
      </div>
    </HrCard>
  );
}

export function ManagerReviewCardView({ props, context }: HrViewProps) {
  const requestId = typeof props.requestId === "string" ? props.requestId : "";
  const emit = (name: string) => {
    void context.dispatchAction({
      event: {
        name,
        context: { kind: "manager_review", request_id: requestId },
      },
    });
  };
  return (
    <HrCard title="Pending review" status="Awaiting your decision" tone="pending">
      <FieldList
        rows={[
          ["Request", textOf(props.requestId)],
          ["Employee", textOf(props.employeeId)],
          ["Leave type", textOf(props.leaveType)],
          ["Start", textOf(props.startDate)],
          ["End", textOf(props.endDate)],
          ["Days", textOf(resolvedDays(props.days, props.startDate, props.endDate))],
        ]}
      />
      <div className="rounded-lg border border-border bg-muted/40 p-3">
        <p className="text-xs text-muted-foreground">
          Reason (shown as plain text; no model reads it)
        </p>
        <pre className="mt-1 whitespace-pre-wrap font-sans text-sm text-foreground">
          {props.reason != null ? String(props.reason) : ""}
        </pre>
      </div>
      <div className="flex flex-wrap justify-end gap-2">
        <UiButton type="button" variant="ghost" onClick={() => emit("manager_reject_review")}>
          Reject
        </UiButton>
        <UiButton type="button" onClick={() => emit("manager_approve_review")}>
          Approve
        </UiButton>
      </div>
    </HrCard>
  );
}

export const HR_VIEWS = {
  Column: ColumnView,
  Row: RowView,
  Heading: HeadingView,
  Text: TextView,
  Button: ButtonView,
  Notice: NoticeView,
  LeaveBalanceCard: LeaveBalanceCardView,
  AllowanceCard: AllowanceCardView,
  DirectReportsTable: DirectReportsTableView,
  ProbationNotice: ProbationNoticeView,
  EmployeeConfirmForm: EmployeeConfirmFormView,
  ManagerReviewCard: ManagerReviewCardView,
};

export { deriveDays };
