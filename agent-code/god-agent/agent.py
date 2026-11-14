"""Layer-2 god-agent runtime.

One agent receives every request. It routes; it does not answer HR questions
itself. Three department agents each own three or fewer leaves. The six
leaves each own one gateway tool. Shapes and limits: `custom-app-plan/god-
agent.md`. Pauses: `custom-app-plan/human-review.md`.

Wiring summary — one file so Dockerfile ``CMD`` finds `app`:

    - `BedrockAgentCoreApp` serves the AG-UI SSE entry (`AGUI` protocol).
    - Accepts both native AG-UI `RunAgentInput` payloads (`hr-web`,
      `invoke.py --agui`, EBA Console) and CLI `{"prompt", "runtimeSessionId",
      "resume"}` payloads (`scripts/login_chat.py`).
    - `create_deep_agent` builds the god agent with three
      `CompiledSubAgent`-wrapped department graphs, `recursion_limit=40`,
      an `AsyncPostgresSaver` checkpointer on `agent_state`, and write-deny
      filesystem permissions.
    - Each department is itself a `create_deep_agent` compiled with
      `recursion_limit=25` whose children are leaf `create_agent` graphs.
    - Each leaf has one gateway tool and the two call-limit middlewares.
    - Per-employee rate limit (20 turns / 10 minutes on the verified `sub`)
      runs BEFORE any Bedrock call.
    - The HR kill switch is re-read on every invocation with a 30 s cache.
    - `GraphRecursionError` answers with the fixed string and logs
      ``LIMIT_RECURSION``.
"""

from __future__ import annotations

import json
import logging
import uuid
from typing import Any

from ag_ui.core import (
    EventType,
    RunAgentInput,
    RunErrorEvent,
    RunFinishedEvent,
    RunFinishedInterruptOutcome,
    RunStartedEvent,
    TextMessageContentEvent,
    TextMessageEndEvent,
    TextMessageStartEvent,
    ToolCallEndEvent,
    ToolCallResultEvent,
    ToolCallStartEvent,
)
from ag_ui.core import (
    Interrupt as AGUIInterrupt,
)
from bedrock_agentcore.runtime import BedrockAgentCoreApp, RequestContext
from checkpointer import (
    async_open_checkpointer,
    claim_or_verify_thread_owner,
    complete_pending_manager_review,
    get_pending_manager_review,
    list_pending_manager_reviews,
    save_pending_manager_review,
)
from copilotkit import LangGraphAGUIAgent
from deepagents import create_deep_agent, register_harness_profile
from deepagents.middleware.subagents import CompiledSubAgent
from fastapi.middleware.cors import CORSMiddleware
from filesystem import scratch_backend, write_deny_permission
from gateway_client import (
    drain_turn_tool_events,
    resolve_employee_id_for_sub,
    set_turn_context,
    take_turn_pending_review,
)
from guardrail import build_model
from langgraph.errors import GraphRecursionError
from langgraph.graph.state import CompiledStateGraph
from leaves import LEAF_SPECS, LeafSpec, build_leaf
from rate_limit import default_limiter
from review import PendingLeaveRequest, run_manager_review
from shared.auth import extract_user_id_from_context
from ssm_config import hr_tools_enabled
from subagents import harness_profile, refusal_subagent

logger = logging.getLogger(__name__)

# ─── Limits (god-agent.md § Limits) ─────────────────────────────────────────

GOD_RECURSION_LIMIT = 40
DEPARTMENT_RECURSION_LIMIT = 25

RECURSION_FALLBACK_TEXT = "I could not finish that. Please ask again."
RECURSION_LOG_CODE = "LIMIT_RECURSION"

SERVICE_DISABLED_TEXT = "The HR assistant is paused. Please try again in a few minutes."
RATE_LIMITED_TEXT = (
    "You have reached the HR assistant's limit of 20 turns per 10 minutes. "
    "Please try again shortly."
)

_HARNESS_PROFILE_KEY = "amazon_bedrock"

# ─── Prompts ────────────────────────────────────────────────────────────────

GOD_SYSTEM_PROMPT = (
    "You are the HR assistant's router. You are NOT an HR agent and you do "
    "not answer HR questions yourself. You have one tool: `task`. Call it to "
    "hand the question to the right department — `hr-operations` for leave "
    "balance, eligibility, and submission; `hr-payroll` for compensation and "
    "the caller's direct reports; `finance-payroll` for the telephone "
    "allowance. Write each `task` description as a plain natural-language "
    "question carrying the user's request and any ids provided — never write "
    "imperative 'use tool X' commands, because the subagent sees no history "
    "from you. Never answer a salary, a leave balance, or an allowance "
    "yourself. Never invent an employee_id. If a department refuses, say "
    "'You are not allowed to see this.' and do not retry from another angle."
)

HR_OPERATIONS_PROMPT = (
    "You are the HR Operations department. You have one tool: `task`. Route "
    "a leave-balance question to `leave-balance`, an eligibility check to "
    "`leave-eligibility`, and a leave submission to `leave-submit`. Pass the "
    "user's question and resolved dates/types in plain natural language; the "
    "leaf sees no history. Never call a gateway tool directly — only your "
    "leaves do."
)

HR_PAYROLL_PROMPT = (
    "You are the HR Payroll department. You have one tool: `task`. Route a "
    "compensation request to `compensation` and a 'my team' or direct-report "
    "question to `direct-reports`. Resolve a name by asking `direct-reports` "
    "first; zero matches means the caller is not allowed to see that person. "
    "Pass plain natural-language descriptions. Never call a gateway tool yourself."
)

FINANCE_PAYROLL_PROMPT = (
    "You are the Finance Payroll department. You have one tool: `task`. "
    "Route any allowance question to `allowance`. The v1 allowance is "
    "telephone only. Pass plain natural-language descriptions. Never call a "
    "gateway tool yourself."
)

_DEPARTMENT_PROMPTS = {
    "hr-operations": HR_OPERATIONS_PROMPT,
    "hr-payroll": HR_PAYROLL_PROMPT,
    "finance-payroll": FINANCE_PAYROLL_PROMPT,
}

_DEPARTMENT_DESCRIPTIONS = {
    "hr-operations": (
        "Leave balance, eligibility, and submission. Call with the caller's "
        "question and any ids already resolved."
    ),
    "hr-payroll": (
        "Compensation and direct-reports queries. Call with the caller's "
        "question and any resolved ids."
    ),
    "finance-payroll": (
        "Allowance queries (telephone, v1). Call with the caller's question."
    ),
}

_LEAF_TO_DEPARTMENT = {
    "leave-balance": "hr-operations",
    "leave-eligibility": "hr-operations",
    "leave-submit": "hr-operations",
    "compensation": "hr-payroll",
    "direct-reports": "hr-payroll",
    "allowance": "finance-payroll",
}

_profile_registered = False


def _register_harness_profile_once() -> None:
    global _profile_registered
    if _profile_registered:
        return
    register_harness_profile(_HARNESS_PROFILE_KEY, harness_profile())
    _profile_registered = True


def _group_leaves(
    leaf_graphs: list[tuple[LeafSpec, CompiledStateGraph]],
) -> dict[str, list[tuple[LeafSpec, CompiledStateGraph]]]:
    grouped: dict[str, list[tuple[LeafSpec, CompiledStateGraph]]] = {
        "hr-operations": [],
        "hr-payroll": [],
        "finance-payroll": [],
    }
    for spec, leaf in leaf_graphs:
        grouped[_LEAF_TO_DEPARTMENT[spec.name]].append((spec, leaf))
    return grouped


def _department_subagent(
    name: str,
    leaf_graphs: list[tuple[LeafSpec, CompiledStateGraph]],
) -> CompiledSubAgent:
    inner_children: list[CompiledSubAgent] = [
        CompiledSubAgent(
            name=spec.name,
            description=spec.description,
            runnable=leaf_graph,
            mode="isolated",
        )
        for spec, leaf_graph in leaf_graphs
    ]

    department_graph = create_deep_agent(
        model=build_model(),
        tools=[],
        system_prompt=_DEPARTMENT_PROMPTS[name],
        subagents=[refusal_subagent(), *inner_children],
        permissions=[write_deny_permission()],
        backend=scratch_backend(),
        checkpointer=False,
    ).with_config(recursion_limit=DEPARTMENT_RECURSION_LIMIT)

    return CompiledSubAgent(
        name=name,
        description=_DEPARTMENT_DESCRIPTIONS[name],
        runnable=department_graph,
        mode="isolated",
    )


def build_god_graph_from_leaves(
    leaf_graphs: list[tuple[LeafSpec, CompiledStateGraph]],
    *,
    checkpointer: Any,
) -> CompiledStateGraph:
    _register_harness_profile_once()

    grouped = _group_leaves(leaf_graphs)
    departments: list[CompiledSubAgent] = [
        _department_subagent(name, grouped[name])
        for name in ("hr-operations", "hr-payroll", "finance-payroll")
    ]

    return create_deep_agent(
        model=build_model(),
        tools=[],
        system_prompt=GOD_SYSTEM_PROMPT,
        subagents=[refusal_subagent(), *departments],
        permissions=[write_deny_permission()],
        backend=scratch_backend(),
        checkpointer=checkpointer,
    )


async def build_god_graph(*, checkpointer: Any) -> CompiledStateGraph:
    leaf_graphs: list[tuple[LeafSpec, CompiledStateGraph]] = []
    for spec in LEAF_SPECS:
        leaf = await build_leaf(spec)
        leaf_graphs.append((spec, leaf))
    return build_god_graph_from_leaves(leaf_graphs, checkpointer=checkpointer)


# ─── AG-UI SSE entry ────────────────────────────────────────────────────────

app = BedrockAgentCoreApp()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://127.0.0.1:8899", "http://localhost:8899"],
    allow_credentials=False,
    allow_methods=["POST", "OPTIONS"],
    allow_headers=[
        "Authorization",
        "Content-Type",
        "Accept",
        "X-Amzn-Bedrock-AgentCore-Runtime-Session-Id",
    ],
)


def _dump(event_model) -> dict[str, Any]:
    return event_model.model_dump(mode="json", by_alias=True, exclude_none=True)


def _refusal_event(message: str, code: str) -> dict[str, Any]:
    return _dump(RunErrorEvent(message=message, code=code))


def _text_events(text: str) -> list[dict[str, Any]]:
    msg_id = f"msg-{uuid.uuid4().hex[:16]}"
    return [
        _dump(
            TextMessageStartEvent(
                type=EventType.TEXT_MESSAGE_START,
                message_id=msg_id,
                role="assistant",
            )
        ),
        _dump(
            TextMessageContentEvent(
                type=EventType.TEXT_MESSAGE_CONTENT,
                message_id=msg_id,
                delta=text,
            )
        ),
        _dump(
            TextMessageEndEvent(
                type=EventType.TEXT_MESSAGE_END,
                message_id=msg_id,
            )
        ),
    ]


def _tool_result_events(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for item in events:
        call_id = item["tool_call_id"]
        name = item["tool_name"]
        content = json.dumps(item["result"])
        out.append(
            _dump(
                ToolCallStartEvent(
                    type=EventType.TOOL_CALL_START,
                    tool_call_id=call_id,
                    tool_call_name=name,
                )
            )
        )
        out.append(
            _dump(
                ToolCallEndEvent(
                    type=EventType.TOOL_CALL_END,
                    tool_call_id=call_id,
                )
            )
        )
        out.append(
            _dump(
                ToolCallResultEvent(
                    type=EventType.TOOL_CALL_RESULT,
                    message_id=f"toolmsg-{call_id}",
                    tool_call_id=call_id,
                    content=content,
                    role="tool",
                )
            )
        )
    return out


def _interrupt_finish_event(
    thread_id: str, run_id: str, payloads: list[dict[str, Any]]
) -> dict[str, Any]:
    agui_interrupts = [
        AGUIInterrupt(
            id=str(p.get("request_id") or f"int-{uuid.uuid4().hex[:12]}"),
            reason=str(p.get("kind") or "interrupt"),
            metadata={"langgraph": {"raw": p}},
        )
        for p in payloads
    ]
    return _dump(
        RunFinishedEvent(
            type=EventType.RUN_FINISHED,
            thread_id=thread_id,
            run_id=run_id,
            outcome=RunFinishedInterruptOutcome(
                type="interrupt",
                interrupts=agui_interrupts,
            ),
        )
    )


def _normalise_payload_to_agui(
    payload: dict[str, Any],
) -> tuple[RunAgentInput, dict[str, Any] | None, bool]:
    """Accept both AG-UI `RunAgentInput` and CLI `{"prompt", "runtimeSessionId", "resume"}`.

    Returns `(run_agent_input, extracted_resume_dict, check_pending_reviews)`.
    """
    data = dict(payload)
    if "messages" not in data and "prompt" in data:
        thread_id = str(
            data.get("threadId")
            or data.get("thread_id")
            or data.get("runtimeSessionId")
            or f"session-{uuid.uuid4().hex}"
        )
        run_id = str(
            data.get("runId") or data.get("run_id") or f"run-{uuid.uuid4().hex}"
        )
        prompt_text = str(data.get("prompt") or "").strip()
        msgs = (
            [
                {
                    "id": f"msg-{uuid.uuid4().hex[:12]}",
                    "role": "user",
                    "content": prompt_text,
                }
            ]
            if prompt_text
            else []
        )
        fwd: dict[str, Any] = dict(data.get("forwardedProps") or {})
        if data.get("resume") is not None and "resume" not in fwd:
            raw_res = data.pop("resume")
            fwd["resume"] = raw_res if isinstance(raw_res, list) else [raw_res]
        data = {
            "threadId": thread_id,
            "runId": run_id,
            "messages": msgs,
            "state": {},
            "tools": [],
            "context": [],
            "forwardedProps": fwd,
        }

    fwd = dict(data.get("forwardedProps") or data.get("forwarded_props") or {})
    check_pending = bool(
        fwd.get("checkPendingReviews") or fwd.get("check_pending_reviews")
    )

    # Extract any resume item sent via `input.resume`, `forwardedProps.resume`, or `forwardedProps.command.resume`.
    resume_dict: dict[str, Any] | None = None
    top_resume = data.get("resume")
    if isinstance(top_resume, list) and top_resume:
        first = top_resume[0]
        if isinstance(first, dict):
            inner = first.get("payload", first)
            resume_dict = inner if isinstance(inner, dict) else {"decision": str(inner)}
    elif isinstance(fwd.get("resume"), list) and fwd["resume"]:
        first = fwd["resume"][0]
        resume_dict = first if isinstance(first, dict) else {"decision": str(first)}
    elif (
        isinstance(fwd.get("command"), dict)
        and fwd["command"].get("resume") is not None
    ):
        inner = fwd["command"]["resume"]
        resume_dict = inner if isinstance(inner, dict) else {"decision": str(inner)}

    # Ensure LangGraphAGUIAgent sees `forwardedProps.command.resume` for employee_confirm resumes
    # when the caller passed `forwardedProps.resume` without an explicit `interruptId`.
    if (
        resume_dict is not None
        and resume_dict.get("kind") != "manager_review"
        and not data.get("resume")
    ):
        fwd["command"] = {"resume": resume_dict}
        data["forwardedProps"] = fwd

    input_data = RunAgentInput.model_validate(data)
    return input_data, resume_dict, check_pending


@app.entrypoint
async def invocations(payload: dict, context: RequestContext):
    """Main entrypoint — AG-UI SSE events for every AgentCore request."""
    # (1) Verified caller identity.
    try:
        user_id = extract_user_id_from_context(context)
    except ValueError as exc:
        logger.warning("Rejected unverified caller: %s", exc)
        yield _refusal_event("Unauthorized", "Unauthorized")
        return

    # (2) Kill switch (30 s cache).
    if not hr_tools_enabled():
        logger.info("[KILL-SWITCH] HR tools disabled, refusing without a model call")
        yield _refusal_event(SERVICE_DISABLED_TEXT, "SERVICE_DISABLED")
        return

    # (3) Normalize payload before rate-limit check so lightweight pending-review
    #     polls on sign-in do not burn the user's 20-turn quota.
    try:
        input_data, resume_dict, check_pending = _normalise_payload_to_agui(payload)
    except Exception as exc:  # noqa: BLE001
        logger.warning("Malformed payload: %s", exc)
        yield _refusal_event("Bad request", "BadRequest")
        return

    thread_id = input_data.thread_id
    run_id = input_data.run_id
    set_turn_context(user_id, thread_id)

    # Lightweight manager sign-in poll: emit any open manager_review cards for this reviewer.
    if check_pending:
        try:
            caller_emp = await resolve_employee_id_for_sub(user_id)
            reviews = await list_pending_manager_reviews(caller_emp)
            yield _dump(
                RunStartedEvent(
                    type=EventType.RUN_STARTED, thread_id=thread_id, run_id=run_id
                )
            )
            if reviews:
                yield _interrupt_finish_event(thread_id, run_id, reviews)
            else:
                yield _dump(
                    RunFinishedEvent(
                        type=EventType.RUN_FINISHED, thread_id=thread_id, run_id=run_id
                    )
                )
        except Exception as exc:
            logger.exception("Failed checking pending manager reviews")
            yield _refusal_event(str(exc) or "Check failed", "ReviewPollError")
        return

    # (4) Per-employee rate limit on the verified sub.
    gate = default_limiter().check_and_record(user_id)
    if not gate.allowed:
        logger.info(
            "[RATE-LIMIT] refused turn for %s (seen %d in window)",
            user_id,
            gate.turns_in_window,
        )
        yield _refusal_event(RATE_LIMITED_TEXT, "RATE_LIMITED")
        return

    # (5) Manager-review decision resume path.
    if resume_dict is not None and resume_dict.get("kind") == "manager_review":
        try:
            yield _dump(
                RunStartedEvent(
                    type=EventType.RUN_STARTED, thread_id=thread_id, run_id=run_id
                )
            )
            request_id = str(resume_dict.get("request_id") or "").strip()
            stored = (
                await get_pending_manager_review(request_id) if request_id else None
            )
            if not stored:
                for ev in _text_events(
                    "No pending leave review matched that request ID."
                ):
                    yield ev
                yield _dump(
                    RunFinishedEvent(
                        type=EventType.RUN_FINISHED, thread_id=thread_id, run_id=run_id
                    )
                )
                return

            caller_emp = await resolve_employee_id_for_sub(user_id)
            req_obj = PendingLeaveRequest(
                request_id=stored["request_id"],
                employee_id=stored["employee_id"],
                reviewer_employee_id=stored["reviewer_employee_id"],
                leave_type=stored["leave_type"],
                start_date=stored["start_date"],
                end_date=stored["end_date"],
                days=int(stored["days"]),
                reason=stored["reason"],
            )
            outcome = await run_manager_review(
                req_obj,
                _resume_override={
                    "decision": resume_dict.get("decision"),
                    "reviewer_employee_id": caller_emp,
                },
            )
            for ev in _tool_result_events(drain_turn_tool_events()):
                yield ev

            if outcome.status in {"approved", "rejected"}:
                await complete_pending_manager_review(request_id, outcome.status)
                for ev in _text_events(
                    f"Leave request {request_id} has been {outcome.status}."
                ):
                    yield ev
                yield _dump(
                    RunFinishedEvent(
                        type=EventType.RUN_FINISHED, thread_id=thread_id, run_id=run_id
                    )
                )
            elif outcome.status == "not_reviewer":
                for ev in _text_events(
                    "You are not authorised to review this leave request."
                ):
                    yield ev
                yield _interrupt_finish_event(thread_id, run_id, [stored])
            else:
                for ev in _text_events(
                    f"Could not record leave decision ({outcome.reason_code})."
                ):
                    yield ev
                yield _interrupt_finish_event(thread_id, run_id, [stored])
        except Exception as exc:
            logger.exception("Manager review resume failed")
            yield _refusal_event(str(exc) or "Review failed", "ReviewError")
        return

    # (6) Build the god graph and stream, enforcing per-user thread ownership.
    try:
        owns_thread = await claim_or_verify_thread_owner(thread_id, user_id)
        if not owns_thread:
            logger.warning(
                "Caller %s attempted to access thread %s owned by another user",
                user_id,
                thread_id,
            )
            yield _refusal_event(
                "Session belongs to another user. Start a new session.",
                "SessionForbidden",
            )
            return

        async with async_open_checkpointer() as checkpointer:
            graph = await build_god_graph(checkpointer=checkpointer)
            graph = graph.with_config(recursion_limit=GOD_RECURSION_LIMIT)

            agui = LangGraphAGUIAgent(
                name="god_agent",
                description="HR assistant router (god agent)",
                graph=graph,
                config={"configurable": {"actor_id": user_id}},
            )
            # `copilotkit.LangGraphAGUIAgent.__init__` does not forward parent
            # `ag_ui_langgraph.LangGraphAgent` flags; set them on the instance.
            agui.emit_interrupt_outcome = True
            agui.emit_raw_events = False
            try:
                async for event in agui.run(input_data):
                    if event is None:
                        continue
                    # Flush any leaf gateway tool results BEFORE terminal RUN_FINISHED
                    # so A2UI cards render on the client!
                    if event.type == EventType.RUN_FINISHED:
                        for tool_ev in _tool_result_events(drain_turn_tool_events()):
                            yield tool_ev
                        pending_review = take_turn_pending_review()
                        if pending_review is not None:
                            await save_pending_manager_review(pending_review, thread_id)
                            for txt_ev in _text_events(
                                f"Leave request {pending_review['request_id']} submitted "
                                f"(status: pending manager review by {pending_review['reviewer_employee_id']})."
                            ):
                                yield txt_ev
                    yield _dump(event)
            except GraphRecursionError:
                logger.warning(RECURSION_LOG_CODE)
                yield _refusal_event(RECURSION_FALLBACK_TEXT, RECURSION_LOG_CODE)
    except Exception as exc:
        logger.exception("God agent run failed")
        yield _dump(
            RunErrorEvent(
                message=str(exc) or type(exc).__name__,
                code=type(exc).__name__,
            )
        )


if __name__ == "__main__":
    app.run()
