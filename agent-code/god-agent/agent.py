"""Layer-2 god-agent runtime.

One agent receives every request. It routes; it does not answer HR questions
itself. Three department agents each own three or fewer leaves. The six
leaves each own one gateway tool. Shapes and limits: `custom-app-plan/god-
agent.md`. Pauses: `custom-app-plan/human-review.md`.

Wiring summary — one file so Dockerfile ``CMD`` finds `app`:

    - `BedrockAgentCoreApp` serves the AG-UI SSE entry (same as
      `agent-code/agui-langgraph-agent/agent.py`).
    - `create_deep_agent` builds the god agent with three
      `CompiledSubAgent`-wrapped department graphs, `recursion_limit=40`,
      a `PostgresSaver` checkpointer on `agent_state`, and the write-deny
      filesystem permission.
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

import logging
from typing import Any

from ag_ui.core import RunAgentInput, RunErrorEvent
from bedrock_agentcore.runtime import BedrockAgentCoreApp, RequestContext
from checkpointer import open_checkpointer
from copilotkit import LangGraphAGUIAgent
from deepagents import create_deep_agent, register_harness_profile
from deepagents.middleware.subagents import CompiledSubAgent
from filesystem import scratch_backend, write_deny_permission
from guardrail import build_model
from langgraph.errors import GraphRecursionError
from langgraph.graph.state import CompiledStateGraph
from leaves import LEAF_SPECS, LeafSpec, build_leaf
from rate_limit import default_limiter
from shared.auth import extract_user_id_from_context
from ssm_config import hr_tools_enabled
from subagents import harness_profile, refusal_subagent

logger = logging.getLogger(__name__)


# ─── Limits (god-agent.md § Limits) ─────────────────────────────────────────

GOD_RECURSION_LIMIT = 40
DEPARTMENT_RECURSION_LIMIT = 25

# Fixed answer for a recursion trip. god-agent.md:
#   "I could not finish that. Please ask again." and logs `LIMIT_RECURSION`.
RECURSION_FALLBACK_TEXT = "I could not finish that. Please ask again."
RECURSION_LOG_CODE = "LIMIT_RECURSION"

# Fixed answers for the kill switch and rate limit. Nothing goes to the model.
SERVICE_DISABLED_TEXT = "The HR assistant is paused. Please try again in a few minutes."
RATE_LIMITED_TEXT = (
    "You have reached the HR assistant's limit of 20 turns per 10 minutes. "
    "Please try again shortly."
)

# Which deepagents harness profile key owns our model. `ChatBedrock` reports
# `ls_provider='amazon_bedrock'`, which is the provider-wide key we register
# the `GeneralPurposeSubagentProfile(enabled=False)` profile under so every
# agent constructed below inherits it.
_HARNESS_PROFILE_KEY = "amazon_bedrock"


# ─── Prompts ────────────────────────────────────────────────────────────────

GOD_SYSTEM_PROMPT = (
    "You are the HR assistant's router. You are NOT an HR agent and you do "
    "not answer HR questions yourself. You have one tool: `task`. Call it to "
    "hand the question to the right department — `hr-operations` for leave "
    "balance, eligibility, and submission; `hr-payroll` for compensation and "
    "the caller's direct reports; `finance-payroll` for the telephone "
    "allowance. The department agents each route to a leaf that calls one "
    "gateway tool. Carry the user's question and any ids the caller provided "
    "in the `task` description — the subagent sees no history from you. "
    "Never answer a salary, a leave balance, or an allowance yourself. Never "
    "invent an employee_id. If a department refuses, say 'you are not "
    "allowed' and do not retry from another angle."
)

HR_OPERATIONS_PROMPT = (
    "You are the HR Operations department. You have one tool: `task`. Route "
    "a leave-balance question to `leave-balance`, an eligibility check to "
    "`leave-eligibility`, and a leave submission to `leave-submit`. Pass the "
    "user's question and the resolved ids; the leaf sees no history. Never "
    "call a gateway tool directly — only your leaves do."
)

HR_PAYROLL_PROMPT = (
    "You are the HR Payroll department. You have one tool: `task`. Route a "
    "compensation request to `compensation` and a 'my team' or direct-report "
    "question to `direct-reports`. Resolve a name by asking `direct-reports` "
    "first; zero matches means the caller is not allowed to see that person. "
    "Never call a gateway tool yourself."
)

FINANCE_PAYROLL_PROMPT = (
    "You are the Finance Payroll department. You have one tool: `task`. "
    "Route any allowance question to `allowance`. The v1 allowance is "
    "telephone only. Never call a gateway tool yourself."
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


# ─── Harness profile registration ───────────────────────────────────────────

_profile_registered = False


def _register_harness_profile_once() -> None:
    """Register the no-general-purpose profile exactly once per process.

    `custom-app-plan/god-agent.md` requires
    `general_purpose_subagent=GeneralPurposeSubagentProfile(enabled=False)`
    on the active harness profile. We register it for the Amazon Bedrock
    provider, which is what our `ChatBedrock` factory reports.
    """

    global _profile_registered
    if _profile_registered:
        return
    register_harness_profile(_HARNESS_PROFILE_KEY, harness_profile())
    _profile_registered = True


# ─── Graph construction ─────────────────────────────────────────────────────


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
    """Build one department `CompiledSubAgent` over its leaf graphs.

    `mode='isolated'` keeps the department's children from inheriting the
    god agent's message history. god-agent.md:

        A department agent does not inherit the god agent's message history.
        Each `task` call starts that agent fresh, so the description on the
        call has to carry the question and the ids the parent already
        resolved.
    """

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
        # Only the god agent is compiled with a checkpointer. The department
        # graphs share the parent's thread (human-review.md § Two pauses).
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
    """Assemble the god agent from pre-built leaf graphs.

    Public and synchronous so `tests/test_god_agent_build.py` can hand it
    stub leaf tools and skip the gateway. The production path is
    ``build_god_graph`` below.
    """

    _register_harness_profile_once()

    grouped = _group_leaves(leaf_graphs)
    departments: list[CompiledSubAgent] = [
        _department_subagent(name, grouped[name])
        for name in ("hr-operations", "hr-payroll", "finance-payroll")
    ]

    god_graph = create_deep_agent(
        model=build_model(),
        tools=[],
        system_prompt=GOD_SYSTEM_PROMPT,
        subagents=[refusal_subagent(), *departments],
        permissions=[write_deny_permission()],
        backend=scratch_backend(),
        checkpointer=checkpointer,
    )
    return god_graph


async def build_god_graph(*, checkpointer: Any) -> CompiledStateGraph:
    """Fetch per-leaf gateway tokens, build six leaves, assemble the graph."""

    leaf_graphs: list[tuple[LeafSpec, CompiledStateGraph]] = []
    for spec in LEAF_SPECS:
        leaf = await build_leaf(spec)
        leaf_graphs.append((spec, leaf))
    return build_god_graph_from_leaves(leaf_graphs, checkpointer=checkpointer)


# ─── AG-UI SSE entry ────────────────────────────────────────────────────────

app = BedrockAgentCoreApp()


def _refusal_event(message: str, code: str) -> dict[str, Any]:
    """Shape a fixed-text refusal as an AG-UI RunErrorEvent."""

    return RunErrorEvent(message=message, code=code).model_dump(
        mode="json", by_alias=True, exclude_none=True
    )


@app.entrypoint
async def invocations(payload: dict, context: RequestContext):
    """Main entrypoint — AG-UI SSE events for every AgentCore request.

    Request body shape: `prompt`, `runtimeSessionId`, plus a `resume` list for
    an open pause on that session (same shape the other AG-UI patterns use).

    Order of checks is deliberate:
      1. Authenticate the caller. A bad token never reaches Bedrock, the
         gateway, or the rate limiter.
      2. Kill switch. A paused assistant answers without a model call.
      3. Rate limit on the verified `sub`. 21st turn → refusal, no model.
      4. Build and run the graph. A recursion trip returns the fixed text
         and logs LIMIT_RECURSION; nothing else is masked.
    """

    # (1) Verified caller identity. Model prompts never carry a user id.
    try:
        user_id = extract_user_id_from_context(context)
    except ValueError as exc:
        logger.warning("Rejected unverified caller: %s", exc)
        yield _refusal_event("Unauthorized", "Unauthorized")
        return

    # (2) Kill switch. Re-read with the 30 s cache.
    if not hr_tools_enabled():
        logger.info("[KILL-SWITCH] HR tools disabled, refusing without a model call")
        yield _refusal_event(SERVICE_DISABLED_TEXT, "SERVICE_DISABLED")
        return

    # (3) Per-employee rate limit on the verified sub.
    gate = default_limiter().check_and_record(user_id)
    if not gate.allowed:
        logger.info(
            "[RATE-LIMIT] refused turn for %s (seen %d in window)",
            user_id,
            gate.turns_in_window,
        )
        yield _refusal_event(RATE_LIMITED_TEXT, "RATE_LIMITED")
        return

    # (4) Build the graph and stream.
    try:
        input_data = RunAgentInput.model_validate(payload)
    except Exception as exc:  # noqa: BLE001 — degrade a malformed AG-UI body
        logger.warning("Malformed AG-UI payload: %s", exc)
        yield _refusal_event("Bad request", "BadRequest")
        return

    try:
        with open_checkpointer() as checkpointer:
            graph = await build_god_graph(checkpointer=checkpointer)
            # LangGraph defaults to recursion_limit=10_007 (god-agent.md),
            # which is not a limit for this agent. 40 is the god agent's own.
            graph = graph.with_config(recursion_limit=GOD_RECURSION_LIMIT)

            agui = LangGraphAGUIAgent(
                name="god_agent",
                description="HR assistant router (god agent)",
                graph=graph,
                config={"configurable": {"actor_id": user_id}},
            )
            try:
                async for event in agui.run(input_data):
                    if event is not None:
                        yield event.model_dump(
                            mode="json", by_alias=True, exclude_none=True
                        )
            except GraphRecursionError:
                logger.warning(RECURSION_LOG_CODE)
                yield _refusal_event(RECURSION_FALLBACK_TEXT, RECURSION_LOG_CODE)
    except Exception as exc:
        logger.exception("God agent run failed")
        yield RunErrorEvent(
            message=str(exc) or type(exc).__name__,
            code=type(exc).__name__,
        ).model_dump(mode="json", by_alias=True, exclude_none=True)


if __name__ == "__main__":
    app.run()
