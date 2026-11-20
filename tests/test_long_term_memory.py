"""Long-term memory stays partitioned by actor and is searched only where configured.

Preferences are always on the memory resource. Semantic facts are added only
when long-term memory is enabled. The four agents that store events must
search those same paths.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path
from typing import Any

import aws_cdk as cdk
import pytest
from aws_cdk.assertions import Template

from stacks.memory_stack import MemoryStack

REPO = Path(__file__).resolve().parents[1]
ENV = cdk.Environment(account="111111111111", region="us-east-1")

STRANDS_AGENTS = (
    "agent-code/strands-agent/agent.py",
    "agent-code/agui-strands-agent/agent.py",
)
LANGGRAPH_AGENTS = (
    "agent-code/langgraph-agent/agent.py",
    "agent-code/agui-langgraph-agent/agent.py",
)


def _load_helper():
    path = REPO / "agent-code" / "shared" / "long_term_memory.py"
    spec = importlib.util.spec_from_file_location("long_term_memory_under_test", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _templates(resource: dict[str, Any]) -> dict[str, list[str]]:
    found: dict[str, list[str]] = {}
    for strategy in resource["Properties"]["MemoryStrategies"]:
        for key, value in strategy.items():
            found[key] = value.get("NamespaceTemplates") or []
            assert "Namespaces" not in value
    return found


def _synth(use_long_term_memory: bool) -> dict[str, list[str]]:
    app = cdk.App()
    stack = MemoryStack(
        app,
        "MemoryNamespaces",
        project_name="memtest",
        environment="dev",
        use_long_term_memory=use_long_term_memory,
        env=ENV,
    )
    template = Template.from_stack(stack).to_json()
    resources = [
        resource
        for resource in template["Resources"].values()
        if resource["Type"] == "AWS::BedrockAgentCore::Memory"
    ]
    assert len(resources) == 1
    return _templates(resources[0])


def test_preference_namespace_is_always_searched(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    helper = _load_helper()
    monkeypatch.delenv("USE_LONG_TERM_MEMORY", raising=False)

    templates = helper.retrieval_namespace_templates()

    assert templates == [helper.PREFERENCE_NAMESPACE]
    assert helper.SEMANTIC_NAMESPACE not in templates
    assert "{actorId}" in helper.PREFERENCE_NAMESPACE


def test_semantic_namespace_is_absent_until_long_term_is_on(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    helper = _load_helper()
    monkeypatch.setenv("USE_LONG_TERM_MEMORY", "false")
    assert helper.SEMANTIC_NAMESPACE not in helper.retrieval_namespace_templates()

    monkeypatch.setenv("USE_LONG_TERM_MEMORY", "true")
    assert helper.retrieval_namespace_templates() == [
        helper.PREFERENCE_NAMESPACE,
        helper.SEMANTIC_NAMESPACE,
    ]


def test_memory_stack_uses_the_same_actor_scoped_templates() -> None:
    helper = _load_helper()

    short_term = _synth(False)
    assert short_term == {
        "UserPreferenceMemoryStrategy": [helper.PREFERENCE_NAMESPACE],
    }

    long_term = _synth(True)
    assert long_term["UserPreferenceMemoryStrategy"] == [helper.PREFERENCE_NAMESPACE]
    assert long_term["SemanticMemoryStrategy"] == [helper.SEMANTIC_NAMESPACE]
    assert "USER_ID" not in str(long_term)
    assert "AGENT_ID" not in str(long_term)


def test_prepare_turn_searches_preferences_only_when_semantic_is_off(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    helper = _load_helper()
    monkeypatch.delenv("USE_LONG_TERM_MEMORY", raising=False)
    monkeypatch.setenv("LTM_RELEVANCE_SCORE", "0.3")
    calls: dict[str, list] = {"events": [], "queries": []}

    class FakeClient:
        def __init__(self, region_name: str) -> None:
            assert region_name == "eu-west-1"

        def create_event(self, **kwargs: object) -> dict:
            calls["events"].append(kwargs)
            return {}

        def retrieve_memories(self, **kwargs: object) -> list[dict]:
            calls["queries"].append(kwargs)
            return [
                {"content": {"text": "likes tea"}, "score": 0.9},
                {"content": {"text": "too weak"}, "score": 0.1},
            ]

    monkeypatch.setattr(helper, "_memory_client", lambda region: FakeClient(region))

    notes = helper.prepare_turn_memory(
        memory_id="mem-1",
        actor_id="user-7",
        session_id="session-7",
        text="what shoes do I like",
        region="eu-west-1",
    )

    assert notes == "likes tea"
    assert calls["events"][0]["messages"] == [("what shoes do I like", "USER")]
    assert calls["events"][0]["actor_id"] == "user-7"
    assert [query["namespace_path"] for query in calls["queries"]] == [
        "/preferences/user-7/"
    ]


def test_prepare_turn_adds_facts_when_long_term_is_on(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    helper = _load_helper()
    monkeypatch.setenv("USE_LONG_TERM_MEMORY", "true")
    queried: list[str] = []

    class FakeClient:
        def __init__(self, region_name: str) -> None:
            del region_name

        def create_event(self, **kwargs: object) -> dict:
            del kwargs
            return {}

        def retrieve_memories(self, **kwargs: object) -> list[dict]:
            queried.append(str(kwargs["namespace_path"]))
            return [{"content": {"text": kwargs["namespace_path"]}, "score": 0.8}]

    monkeypatch.setattr(helper, "_memory_client", lambda region: FakeClient(region))

    notes = helper.prepare_turn_memory(
        memory_id="mem-1",
        actor_id="user-7",
        session_id="session-7",
        text="remind me",
        region="eu-west-1",
    )

    assert queried == ["/preferences/user-7/", "/facts/user-7/"]
    assert notes == "/preferences/user-7/\n/facts/user-7/"


def test_memory_backed_agents_wire_retrieval() -> None:
    for relative in STRANDS_AGENTS:
        source = (REPO / relative).read_text()
        assert "retrieval_targets()" in source
        assert "retrieval_config=" in source
    for relative in LANGGRAPH_AGENTS:
        source = (REPO / relative).read_text()
        assert "prepare_turn_memory(" in source
