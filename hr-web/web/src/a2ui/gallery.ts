/**
 * Sample A2UI v1.0 messages for the Catalog view.
 * Nothing here is sent to the agent. A button named gallery_ack is handled
 * in the page and answered with updateComponents.
 */

import { CATALOG_ID, PROTOCOL_VERSION } from "./hr-tool-adapter.ts";
import { deriveDays } from "./derive-days.ts";

export interface GallerySpecimen {
  id: string;
  title: string;
  blurb: string;
  messages: unknown[];
}

function createSurface(
  surfaceId: string,
  components: Array<Record<string, unknown>>,
): unknown {
  return {
    version: PROTOCOL_VERSION,
    createSurface: {
      surfaceId,
      catalogId: CATALOG_ID,
      components,
    },
  };
}

const NIGHTS = deriveDays({ start: "2026-12-01", end: "2026-12-03" });

export const GALLERY: GallerySpecimen[] = [
  {
    id: "layout",
    title: "Layout",
    blurb: "Column, Row, Heading, Text, and Button. The agent may only use names in the HR catalog.",
    messages: [
      createSurface("gallery-layout", [
        {
          id: "root",
          component: "Column",
          gap: "md",
          children: ["title", "copy", "row"],
        },
        {
          id: "title",
          component: "Heading",
          text: "HR catalog",
          level: 2,
          tag: "A2UI 1.0",
          tagVariant: "ok",
        },
        {
          id: "copy",
          component: "Text",
          variant: "muted",
          text: "Children are named by id. The root is the only component the surface mounts.",
        },
        {
          id: "row",
          component: "Row",
          gap: "sm",
          justify: "start",
          children: ["ok", "wait"],
        },
        {
          id: "ok",
          component: "Button",
          label: "Primary",
          variant: "primary",
          action: { event: { name: "gallery_ack" } },
        },
        {
          id: "wait",
          component: "Button",
          label: "Outline",
          variant: "outline",
          action: { event: { name: "gallery_ack" } },
        },
      ]),
    ],
  },
  {
    id: "leave",
    title: "Leave balance",
    blurb: "A composed surface: a heading, a muted line, then LeaveBalanceCard.",
    messages: [
      createSurface("gallery-leave", [
        {
          id: "root",
          component: "Column",
          gap: "md",
          children: ["title", "copy", "card"],
        },
        {
          id: "title",
          component: "Heading",
          text: "Leave balance",
          level: 3,
          tag: "Available",
          tagVariant: "ok",
        },
        {
          id: "copy",
          component: "Text",
          variant: "muted",
          text: "Sample data. A real balance replaces this card when the leave tool returns.",
        },
        {
          id: "card",
          component: "LeaveBalanceCard",
          annualDays: 18,
          sickDays: 7,
          onProbation: false,
          status: "ok",
          statusLabel: "Available",
        },
      ]),
    ],
  },
  {
    id: "allowance",
    title: "Allowance",
    blurb: "AllowanceCard for one payroll period.",
    messages: [
      createSurface("gallery-allowance", [
        {
          id: "root",
          component: "AllowanceCard",
          itemType: "telephone",
          period: "2026-10",
          amount: 45,
          currency: "EUR",
          status: "ok",
          statusLabel: "Paid",
        },
      ]),
    ],
  },
  {
    id: "reports",
    title: "Direct reports",
    blurb: "DirectReportsTable. One row per person.",
    messages: [
      createSurface("gallery-reports", [
        {
          id: "root",
          component: "DirectReportsTable",
          status: "ok",
          statusLabel: "2 direct",
          reports: [
            { employee_id: "E-1042", full_name: "Amina Rahman" },
            { employee_id: "E-1108", full_name: "Luis Ortega" },
          ],
        },
      ]),
    ],
  },
  {
    id: "probation",
    title: "Probation",
    blurb: "ProbationNotice. Leave stays blocked until the date on the card.",
    messages: [
      createSurface("gallery-probation", [
        {
          id: "root",
          component: "ProbationNotice",
          probationEndDate: "2026-06-30",
          reasonCode: "PROBATION_PERIOD",
        },
      ]),
    ],
  },
  {
    id: "confirm",
    title: "Employee confirm",
    blurb: `EmployeeConfirmForm. deriveDays(2026-12-01, 2026-12-03) is ${NIGHTS}. Buttons here do not submit leave.`,
    messages: [
      createSurface("gallery-confirm", [
        {
          id: "root",
          component: "EmployeeConfirmForm",
          leaveType: "annual",
          startDate: "2026-12-01",
          endDate: "2026-12-03",
          days: NIGHTS,
          reason: "Family trip",
          interruptKind: "employee_confirm",
        },
      ]),
    ],
  },
  {
    id: "review",
    title: "Manager review",
    blurb: "ManagerReviewCard. Approve and Reject on this page do not record a decision.",
    messages: [
      createSurface("gallery-review", [
        {
          id: "root",
          component: "ManagerReviewCard",
          requestId: "LR-2048",
          employeeId: "E-1001",
          leaveType: "annual",
          startDate: "2026-12-01",
          endDate: "2026-12-03",
          days: NIGHTS,
          reason: "Family trip",
          interruptKind: "manager_review",
        },
      ]),
    ],
  },
  {
    id: "action",
    title: "Local action",
    blurb: "Press the button. The page sends updateComponents. The agent is not called.",
    messages: [
      createSurface("gallery-action", [
        {
          id: "root",
          component: "Column",
          gap: "md",
          children: ["note", "go"],
        },
        {
          id: "note",
          component: "Notice",
          variant: "info",
          title: "Waiting",
          body: "This notice changes when you press the button.",
        },
        {
          id: "go",
          component: "Button",
          label: "Record locally",
          variant: "primary",
          action: { event: { name: "gallery_ack" } },
        },
      ]),
    ],
  },
];

export function galleryAckUpdate(): unknown {
  return {
    version: PROTOCOL_VERSION,
    updateComponents: {
      surfaceId: "gallery-action",
      components: [
        {
          id: "note",
          component: "Notice",
          variant: "ok",
          title: "Recorded locally",
          body: "The card changed in the browser. No leave request was sent.",
        },
      ],
    },
  };
}
