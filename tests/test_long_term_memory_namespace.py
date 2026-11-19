"""Long-term memory namespaces must keep one caller's records from another.

The memory resource is created by ``stacks/memory_stack.py``. Short-term events
are stored with the actor id the session manager sends. Long-term strategies
are not: their namespace templates are resolved by substituting only the
placeholders the control-plane API names, and ``RetrieveMemoryRecords`` then
filters on that resolved namespace. These tests drive the product's memory
write path and fail while every caller resolves to the same namespace.
"""

from __future__ import annotations

import ast
import gzip
import importlib.util
import json
import os
import re
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import aws_cdk as cdk
import boto3
import pytest
from aws_cdk.assertions import Template
from bedrock_agentcore.memory.integrations.strands.memorystore.types import (
    resolve_namespace,
)

from stacks.memory_stack import MemoryStack
from stacks.runtime_stack import RuntimeStack

REPO = Path(__file__).resolve().parents[1]
ENV = cdk.Environment(account="111111111111", region="us-east-1")
MEMORY_ID = "platformmemory-abcdefghij"
ALICE = "alice-subject"
BOB = "bob-subject"
ALICE_DETAIL = "alpha-private-detail"
BOB_DETAIL = "beta-private-detail"
QUERY = "preference"

# botocore 1.43.72 (the floor declared in requirements.txt and in
# bedrock-agentcore 1.21.0) control-plane shape Namespace. A template is a
# literal plus optional {actorId}, {sessionId}, and {memoryStrategyId} tokens.
# botocore 1.44.6 widens the token to any {Identifier}; neither pattern treats
# the bare words USER_ID or AGENT_ID as tokens.
CONTROL_PLANE_NAMESPACE = re.compile(
    r"[a-zA-Z0-9\-_\/]*(\{(actorId|sessionId|memoryStrategyId)\}[a-zA-Z0-9\-_\/]*)*"
)


def _installed_shape(service: str, shape: str) -> dict[str, Any]:
    import botocore

    root = Path(botocore.__file__).parent / "data" / service
    model_path = next(root.rglob("service-2.json.gz"))
    with gzip.open(model_path, "rt") as handle:
        return json.load(handle)["shapes"][shape]


DATA_PLANE_NAMESPACE = re.compile(
    _installed_shape("bedrock-agentcore", "Namespace")["pattern"]
)
RETRIEVE_NAMESPACE_DOC = _installed_shape(
    "bedrock-agentcore", "RetrieveMemoryRecordsInput"
)["members"]["namespace"]["documentation"]


def _strategies_from_stack(use_long_term_memory: bool) -> list[dict[str, Any]]:
    app = cdk.App()
    stack = MemoryStack(
        app,
        "MemoryNamespace",
        project_name="prodtest",
        environment="dev",
        use_long_term_memory=use_long_term_memory,
        env=ENV,
    )
    template = Template.from_stack(stack).to_json()
    memories = [
        resource
        for resource in template["Resources"].values()
        if resource["Type"] == "AWS::BedrockAgentCore::Memory"
    ]
    assert len(memories) == 1
    strategies = []
    for entry in memories[0]["Properties"]["MemoryStrategies"]:
        kind, body = next(iter(entry.items()))
        templates = body.get("NamespaceTemplates") or body.get("Namespaces") or []
        strategies.append(
            {
                "kind": kind,
                "name": body["Name"],
                "templates": list(templates),
            }
        )
    return strategies


def _runtime_statements() -> list[dict[str, Any]]:
    app = cdk.App()
    stack = RuntimeStack(
        app,
        "RuntimeNamespace",
        project_name="prodtest",
        environment="dev",
        component_name="orchestrator",
        source_dir="tools/sample_tool",
        runtime_type="orchestrator",
        env=ENV,
    )
    template = Template.from_stack(stack).to_json()
    statements: list[dict[str, Any]] = []
    for resource in template["Resources"].values():
        if resource["Type"] != "AWS::IAM::Policy":
            continue
        document = resource["Properties"]["PolicyDocument"]
        found = document["Statement"]
        statements.extend(found if isinstance(found, list) else [found])
    return statements


def _allows_retrieve(statements: list[dict[str, Any]], namespace: str) -> bool:
    """True when a synthesized statement allows this RetrieveMemoryRecords call.

    The runtime role is what every agent session runs as. A statement with no
    condition does not distinguish namespaces. A namespace condition is honored
    only for the key the service authorizes the call on.
    """
    action = "bedrock-agentcore:RetrieveMemoryRecords"
    for statement in statements:
        if statement.get("Effect", "Allow") != "Allow":
            continue
        actions = statement.get("Action", [])
        if isinstance(actions, str):
            actions = [actions]
        if (
            action not in actions
            and "bedrock-agentcore:*" not in actions
            and "*" not in actions
        ):
            continue
        resources = statement.get("Resource", "*")
        if isinstance(resources, str):
            resources = [resources]
        if "*" not in resources:
            continue
        condition = statement.get("Condition") or {}
        if not condition:
            return True
        allowed: list[str] = []
        for operator, keys in condition.items():
            if not operator.lower().startswith("string"):
                continue
            values = keys.get("bedrock-agentcore:namespace")
            if values is None:
                continue
            if isinstance(values, str):
                values = [values]
            allowed.extend(values)
        if not allowed:
            return True
        if namespace in allowed or any(
            namespace.startswith(value.rstrip("*"))
            for value in allowed
            if value.endswith("*")
        ):
            return True
    return False


def _resolve(template: str, actor_id: str, session_id: str, strategy_name: str) -> str:
    """Resolve a strategy template the way retrieval and extraction do.

    ``resolve_namespace`` is the SDK helper shipped in bedrock-agentcore 1.21.0.
    It substitutes ``{actorId}`` and ``{sessionId}``. The session manager's
    retrieve path also substitutes ``{memoryStrategyId}``, which is the third
    token the 1.43.72 control-plane pattern allows. Any other text, including
    the literals USER_ID and AGENT_ID, is left unchanged.
    """
    if CONTROL_PLANE_NAMESPACE.fullmatch(template) is None:
        raise AssertionError(
            f"control plane would reject namespace template {template!r}"
        )
    resolved = resolve_namespace(template, actor_id, session_id).replace(
        "{memoryStrategyId}", strategy_name
    )
    if DATA_PLANE_NAMESPACE.fullmatch(resolved) is None:
        raise AssertionError(
            f"resolved namespace {resolved!r} is not a data-plane namespace"
        )
    return resolved


class _MemoryPlane:
    """Data plane stand-in built from the botocore shapes cited above.

    ``create_event`` keeps the short-term event under the actor id the caller
    sent. When ``extractionMode`` is omitted, the only enum value is SKIP, so
    extraction runs: each strategy template is resolved and the conversational
    or blob text is stored under that namespace. ``RetrieveMemoryRecords`` has
    no actor id. botocore 1.44.6 matches ``namespace`` exactly; botocore 1.43.72
    matches it as a prefix. ``match_mode`` selects which of those two contracts
    this call uses.
    """

    def __init__(self, strategies: list[dict[str, Any]]) -> None:
        self.strategies = strategies
        self.events: list[dict[str, Any]] = []
        self.records: list[dict[str, Any]] = []
        self.match_mode = "exact"
        self.meta = SimpleNamespace(region_name="us-east-1")
        self._record_serial = 0

    def list_events(self, **kwargs: Any) -> dict[str, Any]:
        actor_id = kwargs["actorId"]
        session_id = kwargs.get("sessionId")
        events = [
            event
            for event in self.events
            if event["actorId"] == actor_id
            and (session_id is None or event["sessionId"] == session_id)
        ]
        return {"events": events}

    def create_event(self, **kwargs: Any) -> dict[str, Any]:
        event_id = f"0000001752235548{len(self.events):03d}#97f30a6b"
        event = {
            "eventId": event_id,
            "memoryId": kwargs["memoryId"],
            "actorId": kwargs["actorId"],
            "sessionId": kwargs.get("sessionId", ""),
            "payload": kwargs.get("payload", []),
        }
        self.events.append(event)
        if kwargs.get("extractionMode") == "SKIP":
            return {"event": {"eventId": event_id}}
        texts = _payload_texts(event["payload"])
        for text in texts:
            for strategy in self.strategies:
                for template in strategy["templates"]:
                    namespace = _resolve(
                        template,
                        kwargs["actorId"],
                        kwargs.get("sessionId", ""),
                        strategy["name"],
                    )
                    self._record_serial += 1
                    self.records.append(
                        {
                            "memoryRecordId": f"mem-{'a' * 32}{self._record_serial:04d}",
                            "content": {"text": text},
                            "namespaces": [namespace],
                            "memoryStrategyId": strategy["name"],
                            "score": 1.0,
                        }
                    )
        return {"event": {"eventId": event_id}}

    def retrieve_memory_records(self, **kwargs: Any) -> dict[str, Any]:
        criteria = kwargs["searchCriteria"]
        query = criteria["searchQuery"].lower()
        top_k = criteria.get("topK", 20)
        requested = kwargs.get("namespace")
        namespace_path = kwargs.get("namespacePath")
        matched = []
        for record in self.records:
            if query not in record["content"]["text"].lower():
                continue
            if not any(
                _namespace_selected(
                    namespace, requested, namespace_path, self.match_mode
                )
                for namespace in record["namespaces"]
            ):
                continue
            matched.append(record)
        return {"memoryRecordSummaries": matched[:top_k]}

    def __getattr__(self, name: str) -> Any:
        def _unused(*_args: Any, **_kwargs: Any) -> dict[str, Any]:
            return {}

        return _unused


def _payload_texts(payload: list[dict[str, Any]]) -> list[str]:
    texts = []
    for item in payload:
        conversational = item.get("conversational")
        if conversational:
            texts.append(conversational["content"]["text"])
        blob = item.get("blob")
        if isinstance(blob, str):
            texts.append(blob)
    return texts


def _namespace_selected(
    stored: str,
    namespace: str | None,
    namespace_path: str | None,
    match_mode: str,
) -> bool:
    if namespace is not None:
        if match_mode == "exact":
            return stored == namespace
        if match_mode == "prefix":
            return stored.startswith(namespace)
        raise AssertionError(match_mode)
    if namespace_path is None:
        return False
    parent = namespace_path.rstrip("/")
    return stored == namespace_path or stored.startswith(parent + "/")


class _ClientPatch:
    def __init__(self, plane: _MemoryPlane) -> None:
        self.plane = plane
        self._session_client = boto3.Session.client
        self._boto_client = boto3.client

    def __enter__(self) -> _MemoryPlane:
        plane = self.plane

        def session_client(
            session: Any, service_name: str | None = None, *args: Any, **kwargs: Any
        ):
            name = (
                service_name if service_name is not None else kwargs.get("service_name")
            )
            if name == "bedrock-agentcore":
                return plane
            return self._session_client(session, service_name, *args, **kwargs)

        def boto_client(service_name: str | None = None, *args: Any, **kwargs: Any):
            name = (
                service_name if service_name is not None else kwargs.get("service_name")
            )
            if name == "bedrock-agentcore":
                return plane
            return self._boto_client(service_name, *args, **kwargs)

        boto3.Session.client = session_client  # type: ignore[method-assign]
        boto3.client = boto_client  # type: ignore[assignment]
        return plane

    def __exit__(self, *_exc: object) -> None:
        boto3.Session.client = self._session_client  # type: ignore[method-assign]
        boto3.client = self._boto_client  # type: ignore[assignment]


def _load_strands_agent():
    agent_dir = REPO / "agent-code" / "strands-agent"
    shared_dir = REPO / "agent-code"
    inserted = [str(agent_dir), str(shared_dir)]
    for path in reversed(inserted):
        sys.path.insert(0, path)
    sys.modules.pop("agent", None)
    sys.modules.pop("tools", None)
    sys.modules.pop("tools.code_interpreter", None)
    sys.modules.pop("tools.gateway", None)
    spec = importlib.util.spec_from_file_location(
        "product_strands_agent", agent_dir / "agent.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module, inserted


def _write_strands_turn(
    module: Any, actor_id: str, session_id: str, detail: str
) -> None:
    os.environ["MEMORY_ID"] = MEMORY_ID
    agent = module._create_agent(actor_id, session_id)
    session_manager = agent._session_manager
    assert session_manager is not None, "memory session manager was not attached"
    assert session_manager.config.actor_id == actor_id
    session_manager.append_message(
        {"role": "user", "content": [{"text": f"My preference is {detail}"}]},
        SimpleNamespace(agent_id="strands-agent"),
    )


def _write_langgraph_checkpoint(actor_id: str, thread_id: str, detail: str) -> None:
    from langgraph_checkpoint_aws import AgentCoreMemorySaver

    saver = AgentCoreMemorySaver(memory_id=MEMORY_ID, region_name="us-east-1")
    saver.put(
        {"configurable": {"thread_id": thread_id, "actor_id": actor_id}},
        {
            "v": 1,
            "id": f"ckpt{thread_id}",
            "ts": "2026-11-19T00:00:00+00:00",
            "channel_values": {"messages": f"My preference is {detail}"},
            "channel_versions": {"messages": 1},
            "versions_seen": {},
            "pending_sends": [],
        },
        {"source": "input", "step": 1, "writes": {}, "parents": {}},
        {"messages": 1},
    )


def _retrieved_text(plane: _MemoryPlane, namespace: str, match_mode: str) -> str:
    from bedrock_agentcore.memory.client import MemoryClient

    plane.match_mode = match_mode
    client = MemoryClient(region_name="us-east-1")
    client.gmdp_client = plane
    records = client.retrieve_memories(
        memory_id=MEMORY_ID,
        namespace=namespace,
        query=QUERY,
        top_k=100,
    )
    return "\n".join(record.get("content", {}).get("text", "") for record in records)


def _assert_isolated(plane: _MemoryPlane, strategies: list[dict[str, Any]]) -> None:
    statements = _runtime_statements()
    for strategy in strategies:
        template = strategy["templates"][0]
        alice_namespace = _resolve(template, ALICE, "sessionalice01", strategy["name"])
        bob_namespace = _resolve(template, BOB, "sessionbob0001", strategy["name"])
        assert _allows_retrieve(statements, bob_namespace), (
            "runtime role cannot call RetrieveMemoryRecords for the caller's namespace"
        )
        for match_mode in ("exact", "prefix"):
            text = _retrieved_text(plane, bob_namespace, match_mode)
            assert BOB_DETAIL in text, (
                f"{strategy['kind']} {match_mode} retrieve of {bob_namespace!r} "
                f"did not return the caller's own preference ({RETRIEVE_NAMESPACE_DOC})"
            )
            assert ALICE_DETAIL not in text, (
                f"{strategy['kind']} template {template!r} resolves {ALICE} to "
                f"{alice_namespace!r} and {BOB} to {bob_namespace!r}; "
                f"{match_mode} RetrieveMemoryRecords for {bob_namespace!r} included "
                f"the other caller's preference"
            )
        assert alice_namespace != bob_namespace, (
            f"{strategy['kind']} template {template!r} resolves both callers to {alice_namespace!r}"
        )


def _exercise(strategies: list[dict[str, Any]]) -> _MemoryPlane:
    plane = _MemoryPlane(strategies)
    with _ClientPatch(plane):
        module, inserted = _load_strands_agent()
        try:
            _write_strands_turn(module, ALICE, "sessionalice01", ALICE_DETAIL)
            _write_strands_turn(module, BOB, "sessionbob0001", BOB_DETAIL)
            _write_langgraph_checkpoint(ALICE, "threadalice01", ALICE_DETAIL)
            _write_langgraph_checkpoint(BOB, "threadbob00001", BOB_DETAIL)
        finally:
            for path in inserted:
                if path in sys.path:
                    sys.path.remove(path)
    bob_events = plane.list_events(
        memoryId=MEMORY_ID, actorId=BOB, sessionId="sessionbob0001"
    )
    bob_short_term = json.dumps(bob_events)
    assert ALICE_DETAIL not in bob_short_term
    assert any(event["actorId"] == ALICE for event in plane.events)
    assert any(event["actorId"] == BOB for event in plane.events)
    return plane


def test_actor_scoped_namespace_keeps_each_caller_separate() -> None:
    """The stand-in isolates callers when the template contains {actorId}.

    This is the same write and retrieve path as the product test. It stays
    green so a harness that always mixes records cannot be the reason the
    product test fails.
    """
    strategies = [
        {
            "kind": "UserPreferenceMemoryStrategy",
            "name": "preferences",
            "templates": ["/preferences/{actorId}/"],
        },
        {
            "kind": "SemanticMemoryStrategy",
            "name": "facts",
            "templates": ["/facts/{actorId}/"],
        },
    ]
    plane = _exercise(strategies)
    _assert_isolated(plane, strategies)


@pytest.mark.parametrize("use_long_term_memory", [False, True])
def test_deployed_strategies_do_not_return_another_callers_preferences(
    use_long_term_memory: bool,
) -> None:
    strategies = _strategies_from_stack(use_long_term_memory)
    assert strategies, "MemoryStack created no strategies"
    kinds = {strategy["kind"] for strategy in strategies}
    assert "UserPreferenceMemoryStrategy" in kinds
    if use_long_term_memory:
        assert "SemanticMemoryStrategy" in kinds
    plane = _exercise(strategies)
    _assert_isolated(plane, strategies)


def test_memory_backed_agents_pass_the_verified_subject_as_actor_id() -> None:
    """The entrypoint's verified subject is the actor id these agents store under."""
    roots = [
        REPO / "agent-code" / "strands-agent" / "agent.py",
        REPO / "agent-code" / "agui-strands-agent" / "agent.py",
        REPO / "agent-code" / "langgraph-agent" / "agent.py",
        REPO / "agent-code" / "agui-langgraph-agent" / "agent.py",
    ]
    for path in roots:
        source = path.read_text()
        assert "extract_user_id_from_context" in source
        tree = ast.parse(source)
        assigned_from_verifier = False
        used_as_actor = False
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Assign)
                and any(
                    isinstance(target, ast.Name) and target.id == "user_id"
                    for target in node.targets
                )
                and isinstance(node.value, ast.Call)
                and isinstance(node.value.func, ast.Name)
                and node.value.func.id == "extract_user_id_from_context"
            ):
                assigned_from_verifier = True
            if (
                isinstance(node, ast.keyword)
                and node.arg == "actor_id"
                and isinstance(node.value, ast.Name)
                and node.value.id == "user_id"
            ):
                used_as_actor = True
            if isinstance(node, ast.Dict):
                for key, value in zip(node.keys, node.values, strict=True):
                    if (
                        isinstance(key, ast.Constant)
                        and key.value == "actor_id"
                        and isinstance(value, ast.Name)
                        and value.id == "user_id"
                    ):
                        used_as_actor = True
        assert assigned_from_verifier, path.name
        assert used_as_actor, path.name
