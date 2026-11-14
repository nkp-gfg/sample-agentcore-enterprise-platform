"""Manager review interrupt.

`custom-app-plan/human-review.md` § Manager review is the contract:

    After the tool returns a `pending` request, the next node interrupts
    with a JSON payload … No write happens before this `interrupt()`. After
    `Command(resume=...)` returns `approve`, the review node calls
    `record_leave_decision` once with `request_id` and `approve`. … `reject`
    sets `rejected` the same way. A policy deny leaves the row `pending`
    and the card open. … A second resume sees the row is no longer `pending`
    and does not update it again.

The review node is layer-2 runtime code, NOT a leaf. The model cannot call
`record_leave_decision`: no leaf is given the tool, and the Cedar permit for
it accepts only `agent_id` `review-node` (`docs/hr/tools.md`).

Who may resume the pause:

    `employee_confirm` → the owner of the thread
    `manager_review`   → `reviewer_employee_id` on the payload

`reason` text travels only in the interrupt payload. It is NEVER written
back into a model message (`custom-app-plan/god-agent.md` § Untrusted data).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Literal

from gateway_client import fetch_review_node_tool
from langchain_core.messages import ToolMessage
from langgraph.types import Command, interrupt

logger = logging.getLogger(__name__)


REVIEW_INTERRUPT_KIND = "manager_review"
EMPLOYEE_CONFIRM_KIND = "employee_confirm"

ALLOWED_MANAGER_DECISIONS = frozenset({"approve", "reject"})
ALLOWED_EMPLOYEE_DECISIONS = frozenset({"approve", "edit", "reject"})

NOT_REVIEWER_REASON = "NOT_REVIEWER"


@dataclass(frozen=True)
class PendingLeaveRequest:
    """One row returned by `submit_leave_request` with status `pending`."""

    request_id: str
    employee_id: str
    reviewer_employee_id: str
    leave_type: str
    start_date: str
    end_date: str
    days: int
    reason: str


@dataclass(frozen=True)
class ReviewOutcome:
    """Result of the review node after `Command(resume=...)` returns.

    - `status`: `approved`, `rejected`, `pending` (policy deny), or `not_reviewer`
    - `tool_message`: a ToolMessage wrapping the structured gateway response
      the node received, for the department agent to surface. No `reason`
      field from the pending row ever travels into it.
    """

    status: Literal["approved", "rejected", "pending", "not_reviewer"]
    reason_code: str
    tool_message: ToolMessage | None


def _manager_review_payload(request: PendingLeaveRequest) -> dict[str, Any]:
    """Card payload. Plain data; the frontend renders `reason` as text."""

    return {
        "kind": REVIEW_INTERRUPT_KIND,
        "request_id": request.request_id,
        "employee_id": request.employee_id,
        "reviewer_employee_id": request.reviewer_employee_id,
        "leave_type": request.leave_type,
        "start_date": request.start_date,
        "end_date": request.end_date,
        "days": request.days,
        # `reason` is the user's own text. It goes ONLY to the card. The
        # frontend renders it as plain text. No model reads it.
        "reason": request.reason,
    }


def _normalise_resume_payload(resume: Any) -> dict[str, Any]:
    """Accept both `{decision: "approve"}` and a bare string."""

    if isinstance(resume, dict):
        return resume
    if isinstance(resume, str):
        return {"decision": resume}
    raise ValueError(
        "Command(resume=...) payload must be a dict or a decision string; "
        f"got {type(resume).__name__}"
    )


def _is_decision_authorised(
    resume: dict[str, Any], expected_reviewer: str
) -> tuple[bool, str]:
    """The runtime checks the token before it applies the Command.

    The resume payload carries a verified `reviewer_employee_id` the entry
    point pulled from the token. The model cannot set it.
    """

    reviewer = (resume.get("reviewer_employee_id") or "").strip()
    if not reviewer:
        return False, "no reviewer_employee_id on resume"
    if reviewer != expected_reviewer:
        return False, "reviewer does not match"
    return True, ""


async def run_manager_review(
    request: PendingLeaveRequest,
    *,
    _resume_override: Any | None = None,
) -> Command | ReviewOutcome:
    """The manager-review interrupt.

    This function is called by a department node after
    `submit_leave_request` returns `pending`. It:

    1. emits an `interrupt()` with the card payload. No write has happened.
    2. on resume, checks the reviewer against the pending row's
       `manager_id`. Anyone else → `NOT_REVIEWER`, row stays pending.
    3. calls `hr-ops___record_leave_decision` through the gateway, with the
       review node's own `calling_agent: review-node` token, EXACTLY once.
    4. returns a `Command` the graph uses to advance state. Nothing writes
       the `reason` field back to a model.

    `_resume_override` is a test hook so the review node can be exercised
    without a running checkpointer; production code never passes it.
    """

    payload = _manager_review_payload(request)
    raw_resume = interrupt(payload) if _resume_override is None else _resume_override
    resume = _normalise_resume_payload(raw_resume)

    decision = (resume.get("decision") or "").strip().lower()
    if decision not in ALLOWED_MANAGER_DECISIONS:
        # `respond` is not an allowed decision. See human-review.md:
        # "The docs treat `respond` as the human acting as the tool, and a
        # model can read that message as a successful result."
        return ReviewOutcome(
            status="not_reviewer",
            reason_code="INVALID_DECISION",
            tool_message=None,
        )

    allowed, _reason = _is_decision_authorised(resume, request.reviewer_employee_id)
    if not allowed:
        # The pending row stays pending. The card stays open.
        return ReviewOutcome(
            status="not_reviewer",
            reason_code=NOT_REVIEWER_REASON,
            tool_message=None,
        )

    tool, _token = await fetch_review_node_tool()

    # One call. The Lambda is the arbiter: a policy deny leaves the row pending
    # (`human-review.md`), a second call on an already-approved row returns
    # `NOT_REVIEWER`. The runtime holds no `hr` credentials to write around it.
    try:
        tool_result = await tool.ainvoke(
            {
                "request_id": request.request_id,
                "decision": decision,
            }
        )
    except Exception as exc:  # noqa: BLE001 — surface as structured outcome
        logger.warning(
            "[REVIEW] record_leave_decision failed for %s: %s",
            request.request_id,
            exc,
        )
        return ReviewOutcome(
            status="pending",
            reason_code="DATA_UNAVAILABLE",
            tool_message=None,
        )

    # The Lambda's response shape is the structured `{"authorized": ...,
    # "reason_code": ..., "data": {...}}` block from `docs/hr/tools.md`.
    # Policy denies arrive as `authorized: false`; approvals and rejections
    # arrive as `authorized: true` with `status` in `data`.
    status_text, reason_code = _interpret_decision_result(tool_result, decision)

    return ReviewOutcome(
        status=status_text,
        reason_code=reason_code,
        tool_message=ToolMessage(
            content=str(tool_result),
            tool_call_id=f"review-{request.request_id}",
            name="hr-ops___record_leave_decision",
        ),
    )


def _interpret_decision_result(
    tool_result: Any,
    decision: str,
) -> tuple[Literal["approved", "rejected", "pending", "not_reviewer"], str]:
    """Translate the gateway response into a review outcome shape."""

    if not isinstance(tool_result, dict):
        return "pending", "UNKNOWN"

    if tool_result.get("authorized") is False:
        reason = (tool_result.get("reason_code") or "").strip() or "NOT_AUTHORIZED"
        if reason == NOT_REVIEWER_REASON:
            return "not_reviewer", reason
        # A policy deny leaves the row `pending` and the card open.
        return "pending", reason

    data = tool_result.get("data") or {}
    status = (data.get("status") or "").strip().lower()
    if status == "approved":
        return "approved", "ALLOW"
    if status == "rejected":
        return "rejected", "ALLOW"
    # Fall back to the caller's requested decision if the gateway omitted it.
    if decision == "approve":
        return "approved", "ALLOW"
    if decision == "reject":
        return "rejected", "ALLOW"
    return "pending", "UNKNOWN"
