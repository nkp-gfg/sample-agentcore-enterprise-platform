"""Layer-2 god-agent build invariants.

`custom-app-plan/god-agent.md` and `human-review.md` lock a handful of
properties about the graph. These tests build the agent against stub tools
and fail if the graph regresses on any of them:

  (a) the god agent has `task` but not the six gateway tools
  (b) each leaf has its one gateway tool and no other
  (c) every `ChatBedrock` instance has `guardrails=...`
  (d) the checkpointer wiring points at `PostgresSaver`, not `MemorySaver`
  (e) `recursion_limit` and middleware call limits match the spec

No AWS calls: SSM reads are stubbed, the gateway credential provider is not
touched, and we do not instantiate boto3.
"""

from __future__ import annotations

import ast
import asyncio
import importlib
import sys
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest
from pydantic import BaseModel

REPO = Path(__file__).resolve().parents[1]
GOD_AGENT_DIR = REPO / "agent-code" / "god-agent"
AGENT_CODE_DIR = REPO / "agent-code"


@pytest.fixture(autouse=True)
def _env_and_sys_path(monkeypatch):
    """Isolate the module cache and inject the env RuntimeStack would set."""

    monkeypatch.setenv("PROJECT_NAME", "test-project")
    monkeypatch.setenv("ENVIRONMENT", "test")
    monkeypatch.setenv("GUARDRAIL_ID", "test-guardrail")
    monkeypatch.setenv("GUARDRAIL_VERSION", "DRAFT")
    monkeypatch.setenv("AWS_REGION_NAME", "us-east-1")
    monkeypatch.setenv("GATEWAY_URL", "https://gateway.invalid/mcp")
    monkeypatch.setenv("GATEWAY_CREDENTIAL_PROVIDER_NAME", "stub-provider")

    # Flat-module layout per the Dockerfile: `agent-code/god-agent/*.py`
    # and `agent-code/shared/*.py` sit beside each other at /app at runtime.
    added_paths = [str(AGENT_CODE_DIR), str(GOD_AGENT_DIR)]
    for path in added_paths:
        if path not in sys.path:
            sys.path.insert(0, path)

    # Drop any cached god-agent modules so the env vars above take effect.
    for name in list(sys.modules):
        if name in {
            "agent",
            "checkpointer",
            "filesystem",
            "gateway_client",
            "guardrail",
            "leaves",
            "rate_limit",
            "review",
            "ssm_config",
            "subagents",
        }:
            del sys.modules[name]

    yield

    for path in added_paths:
        while path in sys.path:
            sys.path.remove(path)


class _Empty(BaseModel):
    """Empty argument schema for the stub gateway tools."""


def _stub_tool(name: str):
    from langchain_core.tools import StructuredTool

    def _run() -> str:
        return "stub"

    return StructuredTool.from_function(
        func=_run,
        name=name,
        description=f"stub for {name}",
        args_schema=_Empty,
    )


async def _build_god_graph_with_stub_tools():
    gateway_client = importlib.import_module("gateway_client")
    leaves_module = importlib.import_module("leaves")
    agent_module = importlib.import_module("agent")

    async def fake_fetch_leaf_tool(calling_agent: str):
        return _stub_tool(gateway_client.LEAF_TOOL_MAP[calling_agent])

    # Rebind `fetch_leaf_tool` on both the gateway_client module and the
    # `leaves` module (which bound it at import time). Patching one but not
    # the other would miss the import-time alias.
    with (
        patch.object(
            gateway_client, "fetch_leaf_tool", side_effect=fake_fetch_leaf_tool
        ),
        patch.object(
            leaves_module, "fetch_leaf_tool", side_effect=fake_fetch_leaf_tool
        ),
    ):
        leaf_graphs = []
        for spec in leaves_module.LEAF_SPECS:
            tool = _stub_tool(gateway_client.LEAF_TOOL_MAP[spec.calling_agent])
            leaf_graphs.append((spec, leaves_module.build_leaf_from_tool(spec, tool)))
        # checkpointer=False keeps the compiled graph pure. The PostgresSaver
        # wiring is checked in its own tests below.
        return (
            agent_module.build_god_graph_from_leaves(leaf_graphs, checkpointer=False),
            leaf_graphs,
        )


def _tool_names(graph) -> set[str]:
    """All tool names a compiled LangGraph exposes.

    We walk the graph's nodes: `create_agent` collects tools onto its `tools`
    node, and `create_deep_agent` adds a `task` tool for the subagents. Both
    appear as `ToolNode`s whose `tools_by_name` is the authoritative map.
    """

    names: set[str] = set()
    for node in graph.get_graph().nodes.values():
        data = getattr(node, "data", None)
        tools_by_name = getattr(data, "tools_by_name", None)
        if tools_by_name is None and data is not None:
            tools_by_name = getattr(
                getattr(data, "runnable", None), "tools_by_name", None
            )
        if isinstance(tools_by_name, dict):
            names.update(tools_by_name)
    return names


# ─── Invariants driven directly from the compiled graph ────────────────────


def test_god_agent_has_task_but_not_the_six_gateway_tools():
    """(a) The god agent must only expose `task`."""

    graph, _ = asyncio.run(_build_god_graph_with_stub_tools())
    tool_names = _tool_names(graph)
    assert "task" in tool_names, (
        "god agent is missing the `task` tool — it cannot route to a "
        "department without it (god-agent.md)"
    )
    gateway_client = importlib.import_module("gateway_client")
    forbidden = set(gateway_client.LEAF_TOOL_MAP.values())
    leaked = forbidden & tool_names
    assert not leaked, (
        f"god agent sees gateway tools it must not call: {sorted(leaked)} — "
        "each gateway tool lives only on its leaf (docs/hr/tools.md)"
    )


def test_each_leaf_has_its_one_gateway_tool_and_no_other():
    """(b) One leaf → one tool, no bleed."""

    _, leaf_graphs = asyncio.run(_build_god_graph_with_stub_tools())
    gateway_client = importlib.import_module("gateway_client")
    for spec, leaf in leaf_graphs:
        tool_names = _tool_names(leaf)
        expected = gateway_client.LEAF_TOOL_MAP[spec.calling_agent]
        assert expected in tool_names, (
            f"leaf {spec.name!r} is missing its tool {expected!r}"
        )
        gateway_tool_names = set(gateway_client.LEAF_TOOL_MAP.values())
        unexpected = (tool_names & gateway_tool_names) - {expected}
        assert not unexpected, (
            f"leaf {spec.name!r} sees gateway tools it must not call: "
            f"{sorted(unexpected)}"
        )


# ─── Guardrails on every ChatBedrock (c) ───────────────────────────────────


def test_every_chatbedrock_carries_the_guardrail_block():
    """(c) Every model instance must declare `guardrails=...`.

    The factory is the only call site. If any model lacks the block, the
    IAM `DenyUngovernedInference` statement rejects the Converse call at
    runtime. We assert at build time instead of waiting for deploy.
    """

    guardrail = importlib.import_module("guardrail")
    block = guardrail.guardrail_block_for_tests()
    assert block == {
        "guardrails": {
            "guardrailIdentifier": "test-guardrail",
            "guardrailVersion": "DRAFT",
        }
    }, "guardrail factory did not resolve to the env-injected identifier"

    # And every model the factory produces must carry the block live.
    models = [guardrail.build_model() for _ in range(3)]
    for model in models:
        bound_kwargs = getattr(model, "guardrails", None)
        assert bound_kwargs == block["guardrails"], (
            f"ChatBedrock instance built by guardrail.build_model() does not "
            f"carry guardrails=...; got {bound_kwargs}"
        )


def test_guardrail_build_fails_without_an_identifier(monkeypatch):
    """A missing identifier is a boot-time failure, not a silent skip."""

    monkeypatch.delenv("GUARDRAIL_ID", raising=False)
    # Also stub SSM so it cannot provide one either.
    from shared import ssm

    def _no_parameter(name: str) -> str:
        raise ValueError(f"no such parameter: {name}")

    monkeypatch.setattr(ssm, "get_ssm_parameter", _no_parameter)

    guardrail = importlib.import_module("guardrail")
    guardrail._reset_cache_for_tests()
    # SSM raises ValueError when the identifier cannot be resolved; the
    # factory re-raises as RuntimeError when it hits the empty-check below.
    # Either shape is an acceptable fast fail — the point is NOT to proceed
    # silently to a `ChatBedrock(guardrails=…)` without a guardrail id.
    with pytest.raises((RuntimeError, ValueError)):
        guardrail.build_model()


# ─── Checkpointer (d) ───────────────────────────────────────────────────────


def test_checkpointer_wires_postgres_saver_not_memory_saver():
    """(d) The entry point opens a `PostgresSaver`, never a `MemorySaver`."""

    checkpointer = importlib.import_module("checkpointer")
    from langgraph.checkpoint.postgres import PostgresSaver

    # The open_checkpointer context manager yields a PostgresSaver built by
    # `PostgresSaver.from_conn_string(...)`. We stub both the SSM/secret
    # lookups and the saver's connection open so no cluster is contacted.
    opened: list[str] = []

    class _FakeSaver:
        def __init__(self) -> None:
            self.setup_called = False

        def setup(self) -> None:
            self.setup_called = True

        def __enter__(self):
            return self

        def __exit__(self, *_exc) -> None:
            return None

    fake = _FakeSaver()

    def fake_from_conn_string(conn_string: str, *, pipeline: bool = False):
        opened.append(conn_string)
        return fake

    import ssm_config

    ssm_config._reset_caches_for_tests()

    stub_cfg = ssm_config.HrDataConfig(
        endpoint="hr.cluster.invalid:5432",
        checkpoint_database="agent_state",
        master_secret_name="agentcore-workshop/dev/hr-data/master",
    )
    with (
        patch.object(
            PostgresSaver,
            "from_conn_string",
            staticmethod(fake_from_conn_string),
        ),
        # checkpointer imports `hr_data_config` as a direct symbol, so we
        # patch the attribute on the checkpointer module, not on ssm_config.
        patch.object(checkpointer, "hr_data_config", return_value=stub_cfg),
        patch.object(
            checkpointer,
            "_secret_value",
            return_value={"username": "postgres", "password": "stub"},
        ),
        patch.object(
            checkpointer,
            "_rds_auth_token",
            return_value="iam-token",
        ),
    ):
        checkpointer._reset_setup_flag_for_tests()
        with checkpointer.open_checkpointer() as saver:
            assert saver is fake
    assert fake.setup_called, "PostgresSaver.setup() must run on first open"
    assert any("dbname='agent_state'" in conn for conn in opened), (
        "the agent must connect to the `agent_state` database, not `hr`"
    )
    assert any("user='agent_checkpoint'" in conn for conn in opened), (
        "steady-state connections must use the `agent_checkpoint` role "
        "(docs/hr/modules.md § Database roles)"
    )
    # And no code path imports or constructs a MemorySaver. We parse the AST
    # and walk every import, attribute, and name — docstring hits (we quote
    # the spec, which contrasts with MemorySaver) are skipped.
    source = (GOD_AGENT_DIR / "checkpointer.py").read_text()
    tree = ast.parse(source)
    disallowed = "MemorySaver"
    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            for alias in getattr(node, "names", []):
                assert disallowed not in (alias.name or ""), (
                    "checkpointer.py must not import MemorySaver"
                )
        elif isinstance(node, ast.Name):
            assert node.id != disallowed, (
                "checkpointer.py must not reference MemorySaver — a pause "
                "that can sit for a day has to survive a container replacement"
            )
        elif isinstance(node, ast.Attribute):
            assert node.attr != disallowed, (
                "checkpointer.py must not reference MemorySaver"
            )
    assert "PostgresSaver" in source


# ─── Limits (e) ────────────────────────────────────────────────────────────


def test_recursion_limits_match_the_spec():
    """God agent run config = 40; department compiled graphs = 25."""

    agent_module = importlib.import_module("agent")
    assert agent_module.GOD_RECURSION_LIMIT == 40, (
        "god agent recursion_limit must be 40 (god-agent.md § Limits)"
    )
    assert agent_module.DEPARTMENT_RECURSION_LIMIT == 25, (
        "each department CompiledSubAgent must apply recursion_limit=25"
    )


def test_leaf_middleware_pins_the_call_limits():
    """Each leaf has ModelCallLimitMiddleware(4, end) and ToolCallLimit(2)."""

    import leaves as leaves_module

    tool = _stub_tool("stub-tool")
    leaf = leaves_module.build_leaf_from_tool(leaves_module.LEAF_SPECS[0], tool)

    model_call_hits: list[int] = []
    tool_call_hits: list[int] = []
    for node in leaf.get_graph().nodes.values():
        data = getattr(node, "data", None)
        for mw in _collect_middleware(data):
            classname = type(mw).__name__
            if classname == "ModelCallLimitMiddleware":
                assert getattr(mw, "run_limit", None) == 4, (
                    "leaf ModelCallLimitMiddleware must have run_limit=4"
                )
                assert getattr(mw, "exit_behavior", None) == "end", (
                    "leaf ModelCallLimitMiddleware must have exit_behavior='end'"
                )
                model_call_hits.append(1)
            elif classname == "ToolCallLimitMiddleware":
                assert getattr(mw, "run_limit", None) == 2, (
                    "leaf ToolCallLimitMiddleware must have run_limit=2"
                )
                tool_call_hits.append(1)

    # Source-level backstop. `build_leaf_from_tool` is the only entry point
    # that builds a leaf, and both middlewares must appear in its tree.
    source = (GOD_AGENT_DIR / "leaves.py").read_text()
    tree = ast.parse(source)
    middleware_calls = {
        node.func.id
        if isinstance(node.func, ast.Name)
        else getattr(node.func, "attr", "")
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
    }
    assert "ModelCallLimitMiddleware" in middleware_calls
    assert "ToolCallLimitMiddleware" in middleware_calls


def _collect_middleware(obj: Any) -> list[Any]:
    """Return every middleware instance we can find hanging off `obj`.

    LangChain's `create_agent` stores middlewares in a few places depending
    on version; we accept whatever we find rather than hard-coding one.
    """

    found: list[Any] = []
    for attr in ("middleware", "middlewares", "_middlewares"):
        value = getattr(obj, attr, None)
        if isinstance(value, (list, tuple)):
            found.extend(value)
    runnable = getattr(obj, "runnable", None)
    if runnable is not None and runnable is not obj:
        found.extend(_collect_middleware(runnable))
    return found


# ─── Routing shape ─────────────────────────────────────────────────────────


def test_six_leaves_mapped_to_three_departments():
    leaves_module = importlib.import_module("leaves")
    grouped = leaves_module.leaf_specs_for_department()
    assert sorted(grouped) == ["finance-payroll", "hr-operations", "hr-payroll"]
    assert {s.name for s in grouped["hr-operations"]} == {
        "leave-balance",
        "leave-eligibility",
        "leave-submit",
    }
    assert {s.name for s in grouped["hr-payroll"]} == {
        "compensation",
        "direct-reports",
    }
    assert {s.name for s in grouped["finance-payroll"]} == {"allowance"}


def test_calling_agent_names_match_the_spec():
    """The six leaf calling_agent names are fixed — Cedar binds each."""

    gateway_client = importlib.import_module("gateway_client")
    assert set(gateway_client.LEAF_TOOL_MAP) == {
        "leave-balance",
        "leave-eligibility",
        "leave-submit",
        "compensation",
        "direct-reports",
        "allowance",
    }
    assert gateway_client.REVIEW_NODE_CALLING_AGENT == "review-node"
    assert gateway_client.REVIEW_NODE_TOOL == "hr-ops___record_leave_decision"


# ─── Rate limit ────────────────────────────────────────────────────────────


def test_rate_limiter_refuses_the_21st_turn_in_the_10_minute_window():
    """R-08: 20 turns allowed in 10 minutes, the 21st is refused."""

    import rate_limit

    limiter = rate_limit.TurnRateLimiter(
        max_turns=20,
        window_seconds=600,
    )
    key = "sub-abc"
    base = 1_000.0
    for i in range(20):
        result = limiter.check_and_record(key, now=base + i)
        assert result.allowed, f"turn {i + 1} unexpectedly refused"
    refused = limiter.check_and_record(key, now=base + 21)
    assert refused.allowed is False
    assert refused.turns_in_window == 20
    assert refused.retry_after_seconds > 0


def test_rate_limiter_recovers_after_the_window():
    import rate_limit

    limiter = rate_limit.TurnRateLimiter(max_turns=2, window_seconds=10)
    limiter.check_and_record("u", now=0.0)
    limiter.check_and_record("u", now=1.0)
    assert limiter.check_and_record("u", now=2.0).allowed is False
    assert limiter.check_and_record("u", now=11.0).allowed is True


# ─── Kill switch ───────────────────────────────────────────────────────────


def test_kill_switch_caches_30_seconds(monkeypatch):
    import ssm_config

    calls: list[str] = []

    def fake_get_parameter(name: str) -> str:
        calls.append(name)
        return "true"

    monkeypatch.setattr(ssm_config, "get_ssm_parameter", fake_get_parameter)
    ssm_config._reset_caches_for_tests()

    # First check hits SSM.
    assert ssm_config._KILL_SWITCH.is_enabled(now=0.0) is True
    # Second within the TTL does not.
    assert ssm_config._KILL_SWITCH.is_enabled(now=29.0) is True
    # After the TTL, SSM is re-read.
    assert ssm_config._KILL_SWITCH.is_enabled(now=31.0) is True
    assert len(calls) == 2, f"expected two SSM reads across the TTL, got {calls}"


def test_kill_switch_refuses_on_a_missing_parameter(monkeypatch):
    """A deleted parameter is `SERVICE_DISABLED`, not an allow."""

    import ssm_config

    def fake_get_parameter(name: str) -> str:
        raise ValueError(f"SSM parameter not found: {name}")

    monkeypatch.setattr(ssm_config, "get_ssm_parameter", fake_get_parameter)
    ssm_config._reset_caches_for_tests()
    assert ssm_config._KILL_SWITCH.is_enabled(now=0.0) is False


# ─── Review node ───────────────────────────────────────────────────────────


def test_review_node_approve_calls_record_leave_decision_once():
    """`approve` resume → one `record_leave_decision` call with review-node."""

    import gateway_client
    import review as review_module

    captured: list[dict[str, Any]] = []

    class _FakeTool:
        name = gateway_client.REVIEW_NODE_TOOL

        async def ainvoke(self, args: dict[str, Any]):
            captured.append(args)
            return {
                "authorized": True,
                "reason_code": "ALLOW",
                "data": {
                    "request_id": args["request_id"],
                    "status": "approved",
                    "decided_by": "M1",
                },
            }

    async def fake_fetch():
        return _FakeTool(), "token"

    original = review_module.fetch_review_node_tool
    review_module.fetch_review_node_tool = fake_fetch
    try:
        request = review_module.PendingLeaveRequest(
            request_id="req-1",
            employee_id="E1",
            reviewer_employee_id="M1",
            leave_type="annual",
            start_date="2026-12-01",
            end_date="2026-12-02",
            days=2,
            reason="family event",
        )
        outcome = asyncio.run(
            review_module.run_manager_review(
                request,
                _resume_override={"decision": "approve", "reviewer_employee_id": "M1"},
            )
        )
    finally:
        review_module.fetch_review_node_tool = original

    assert outcome.status == "approved"
    assert len(captured) == 1
    assert captured[0] == {"request_id": "req-1", "decision": "approve"}


def test_review_node_refuses_a_non_reviewer_without_calling_the_tool():
    """E1 trying to approve E1's own pending request → NOT_REVIEWER."""

    import review as review_module

    called: list[Any] = []

    async def fake_fetch():
        called.append(1)
        raise AssertionError("tool must not be fetched for a NOT_REVIEWER")

    original = review_module.fetch_review_node_tool
    review_module.fetch_review_node_tool = fake_fetch
    try:
        request = review_module.PendingLeaveRequest(
            request_id="req-2",
            employee_id="E1",
            reviewer_employee_id="M1",
            leave_type="annual",
            start_date="2026-12-01",
            end_date="2026-12-02",
            days=2,
            reason="",
        )
        outcome = asyncio.run(
            review_module.run_manager_review(
                request,
                _resume_override={"decision": "approve", "reviewer_employee_id": "E1"},
            )
        )
    finally:
        review_module.fetch_review_node_tool = original

    assert outcome.status == "not_reviewer"
    assert outcome.reason_code == "NOT_REVIEWER"
    assert not called


def test_review_node_rejects_respond_and_edit_for_the_manager_card():
    """Only `approve` and `reject` are valid decisions on the manager card."""

    import review as review_module

    request = review_module.PendingLeaveRequest(
        request_id="req-3",
        employee_id="E1",
        reviewer_employee_id="M1",
        leave_type="annual",
        start_date="2026-12-01",
        end_date="2026-12-02",
        days=2,
        reason="",
    )
    for bad_decision in ("respond", "edit", "", "yes"):
        outcome = asyncio.run(
            review_module.run_manager_review(
                request,
                _resume_override={
                    "decision": bad_decision,
                    "reviewer_employee_id": "M1",
                },
            )
        )
        assert outcome.status == "not_reviewer", (
            f"decision {bad_decision!r} must not be accepted on the manager card"
        )


# ─── Filesystem + general-purpose ──────────────────────────────────────────


def test_filesystem_denies_every_write():
    import filesystem

    perm = filesystem.write_deny_permission()
    assert perm.operations == ["write"]
    assert perm.paths == ["/**"]
    assert perm.mode == "deny"


def test_harness_profile_disables_general_purpose():
    import subagents

    cfg = subagents.harness_profile()
    gp = cfg.general_purpose_subagent
    assert gp is not None, "the god agent must set general_purpose_subagent explicitly"
    assert gp.enabled is False, (
        "god-agent.md: GeneralPurposeSubagentProfile(enabled=False)"
    )

    fallback = subagents.refusal_subagent()
    assert fallback["name"] == subagents.GENERAL_PURPOSE_NAME
    assert fallback.get("tools") == [], (
        "the fallback general-purpose subagent must have no tools"
    )
    assert fallback.get("mode") == "isolated"


# ─── Model identity ────────────────────────────────────────────────────────


def test_default_model_is_the_in_region_bedrock_profile():
    """`openai.gpt-oss-120b-1:0` with no `eu.` or `us.` cross-region profile."""

    import guardrail

    model = guardrail.build_model()
    assert model.model_id == "openai.gpt-oss-120b-1:0"
    assert not model.model_id.startswith("eu.")
    assert not model.model_id.startswith("us.")


# ─── Pattern registration ──────────────────────────────────────────────────


def test_god_agent_is_in_the_runtime_pattern_allowlist():
    """The platform config and deploy.sh both list the pattern or module 6
    cannot select it. The pattern is an addition, not a replacement."""

    sys.path.insert(0, str(REPO))
    try:
        from infra_utils.platform_config import AGENT_PATTERNS, PlatformConfig
    finally:
        pass
    assert "god-agent" in AGENT_PATTERNS, (
        "'god-agent' must be in AGENT_PATTERNS so `agents.pattern: god-agent` "
        "validates in platform.yaml"
    )
    # And platform.yaml with the new pattern validates end to end.
    cfg = PlatformConfig.model_validate({"agents": {"pattern": "god-agent"}})
    assert cfg.agents.pattern == "god-agent"

    deploy_sh = (REPO / "scripts" / "deploy.sh").read_text()
    assert "god-agent" in deploy_sh, (
        "scripts/deploy.sh validates AGENT_PATTERN against its own allow-list "
        "and must also include the god-agent pattern"
    )
