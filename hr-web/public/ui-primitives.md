# HR assistant — A2UI v1.0 primitives

The HR UI renders through the [A2UI v1.0 wire
protocol](https://a2ui.org/specification/v1_0/). This note documents the
catalog declared in [`hr-catalog.json`](./hr-catalog.json): the components
the renderer draws, the fields each one reads from a `createSurface` /
`updateComponents` message, and the `action` events each one emits on a
renderer-to-agent message.

Catalog id: `https://hr-web.local/catalogs/hr-platform-v1/catalog.json`
Protocol version: `1.0` (pinned on the server as `PublicConfig.a2ui_protocol_version`)

Two renderer messages flow in and out:

- **Agent → renderer**: `{"version": "1.0", "createSurface": {...}}` /
  `updateComponents` / `updateDataModel` / `deleteSurface`. Any message
  whose `version` field disagrees with the renderer's is refused with a
  `VERSION_MISMATCH` renderer error. See `hr-web/public/a2ui.js`.
- **Renderer → agent**: `{"version": "1.0", "action": {...}}` emitted by a
  Button press. The renderer also sends `{"version": "1.0", "error": {...}}`
  for every rejected inbound message; they are attached to the next
  AG-UI request's `forwardedProps.a2uiRendererErrors`.

The renderer-to-agent `action` carries `{name, surfaceId, sourceComponentId,
timestamp, context}`. The `name` is drawn from the component's
`action.event.name`. `context` is resolved against the surface's data model
first, then merged with the per-click payload the primitive adds.

## Layout primitives

### `Column`
A vertical stack of children.

| Field | Shape |
|---|---|
| `component` | `"Column"` |
| `gap` | `"none" | "sm" | "md" | "lg"` (default `"md"`) |
| `align` | `"start" | "center" | "stretch"` (default `"stretch"`) |
| `children` | array of child component ids |

### `Row`
A horizontal stack of children.

| Field | Shape |
|---|---|
| `component` | `"Row"` |
| `gap` | `"none" | "sm" | "md" | "lg"` (default `"sm"`) |
| `align` | `"start" | "center" | "end" | "baseline"` (default `"center"`) |
| `justify` | `"start" | "center" | "end" | "between"` (default `"start"`) |
| `children` | array of child component ids |

### `Heading`
A short section heading, optionally with a trailing status tag.

| Field | Shape |
|---|---|
| `component` | `"Heading"` |
| `text` | string |
| `level` | `2 | 3 | 4` (default `2`) |
| `tag` | string, optional trailing pill |
| `tagVariant` | `"ok" | "err" | "pending" | "blocked"` |

### `Text`
A paragraph.

| Field | Shape |
|---|---|
| `component` | `"Text"` |
| `text` | string |
| `variant` | `"body" | "muted" | "error" | "warning" | "mono"` |

### `Button`
A press. The only renderer-to-agent user-event the HR catalog emits.

| Field | Shape |
|---|---|
| `component` | `"Button"` |
| `label` | string |
| `variant` | `"primary" | "outline" | "ghost"` |
| `disabled` | boolean |
| `action.event.name` | string |
| `action.event.context` | object merged into the action's `context` |
| `action.event.userMessage` | optional, human-readable description |

## HR-specific primitives

### `LeaveBalanceCard`
Draws the response to `get_leave_balance`.

| Field | Shape |
|---|---|
| `annualDays` | number, days remaining |
| `sickDays` | number, days remaining |
| `onProbation` | boolean |
| `probationEndDate` | `YYYY-MM-DD` string or `null` |
| `status` | `"ok" | "err" | "pending"` |
| `statusLabel` | string shown as the pill |
| `reasonCode` | Policy reason code when `status === "err"` |

No actions. A refusal surfaces as the pill text only.

### `AllowanceCard`
Draws the response to `get_allowance`.

| Field | Shape |
|---|---|
| `itemType` | string |
| `period` | string |
| `amount` | number or `null` ("No entry for this period") |
| `currency` | string |
| `status` | `"ok" | "empty" | "err"` |
| `statusLabel` | string |
| `reasonCode` | Policy reason code when `status === "err"` |

No actions.

### `DirectReportsTable`
Draws the response to `list_direct_reports`.

| Field | Shape |
|---|---|
| `reports` | array of `{employee_id, full_name}` |
| `status` | `"ok" | "err"` |
| `statusLabel` | string |
| `reasonCode` | Policy reason code when `status === "err"` |

No actions.

### `ProbationNotice`
Shown when `check_leave_eligibility` refuses with `PROBATION_PERIOD`, and
when `get_leave_balance` reports `on_probation === true`.

| Field | Shape |
|---|---|
| `probationEndDate` | `YYYY-MM-DD` string or `null` |
| `reasonCode` | typically `"PROBATION_PERIOD"` |

No actions.

### `EmployeeConfirmForm`
The employee's own second-person-click gate on `submit_leave_request`. The
agent emits this primitive from the LangGraph `interrupt(kind="employee_confirm")`
after it has read the proposed arguments.

| Field | Shape |
|---|---|
| `interruptKind` | `"employee_confirm"` |
| `leaveType` | string |
| `startDate` | `YYYY-MM-DD` |
| `endDate` | `YYYY-MM-DD` |
| `days` | number or string (otherwise derived with `deriveDays`) |
| `reason` | string |

Actions emitted:

| action.name | Trigger | context payload |
|---|---|---|
| `employee_confirm_leave` | **Confirm** button | `{kind: "employee_confirm", leave_type, start_date, end_date, reason}` |
| `employee_reject_leave`  | **Reject** button  | `{kind: "employee_confirm"}` |
| `employee_edit_leave`    | **Edit** button    | `{kind: "employee_confirm", leave_type, start_date, end_date, reason}` (the shell prompts for new dates) |

`employee_confirm_leave` is the ONLY path that posts a
`forwardedProps.resume: [{decision: "approve", kind: "employee_confirm",
arguments: ...}]` to AG-UI. Typing "approve" in the chat is a plain user
turn: it is not wired to this action name.

### `ManagerReviewCard`
A single pending-review item. The agent emits this from
`interrupt(kind="manager_review")`. The reason is drawn as plain text and
NEVER reused as a model prompt — the orchestrator does not read
`context.reason` from this card.

| Field | Shape |
|---|---|
| `interruptKind` | `"manager_review"` |
| `requestId` | string |
| `employeeId` | string |
| `leaveType` | string |
| `startDate` | `YYYY-MM-DD` |
| `endDate` | `YYYY-MM-DD` |
| `days` | number or string |
| `reason` | string (drawn only; not fed back to the agent as a prompt) |

Actions emitted:

| action.name | Trigger | context payload |
|---|---|---|
| `manager_approve_review` | **Approve** button | `{kind: "manager_review", request_id}` |
| `manager_reject_review`  | **Reject** button  | `{kind: "manager_review", request_id}` |

Both actions become `forwardedProps.resume: [{decision, kind, request_id}]`
on the next AG-UI request. The gateway Lambda re-evaluates the authorization
policy (`NOT_REVIEWER`, `SERVICE_DISABLED`, `IDEMPOTENCY_CONFLICT`) on the
backend before the row is updated, so a forged resume from the dev console
still fails.

### `Notice`
A short status line surfaced after a decision or a policy refusal.

| Field | Shape |
|---|---|
| `variant` | `"info" | "ok" | "warn" | "err"` |
| `title` | string, optional |
| `body` | string |

No actions.

## Catalog functions

The one function the catalog exposes to the agent is `deriveDays`:

```
deriveDays({start: "2026-04-12", end: "2026-04-18"}) -> "7"
```

Returns `"—"` when either date is missing, unparsable, or `end < start`.
It is a plain client-side function, used in a Text's `text` property as
`{"@call": "deriveDays", "args": {"start": {"@path": "/trip/startDate"}, "end": {"@path": "/trip/endDate"}}}`.
No network, no secrets, no agent round-trip.
