"""Unit tests for the DynamoDB session store and ECS BFF boundary."""

from __future__ import annotations

import json
import sys
import time
from decimal import Decimal
from pathlib import Path
from typing import Any

import pytest

REPO = Path(__file__).resolve().parents[2]
HR_WEB = REPO / "hr-web"
if str(HR_WEB) not in sys.path:
    sys.path.insert(0, str(HR_WEB))

from bff.session_store import DynamoSessionStore


class _FakeTable:
    """Minimal in-memory DynamoDB Table double supporting PK/SK + GSI queries."""

    def __init__(self, key_fields: tuple[str, ...]) -> None:
        self._key_fields = key_fields
        self._rows: dict[tuple[Any, ...], dict[str, Any]] = {}

    def _key_of(self, item: dict[str, Any]) -> tuple[Any, ...]:
        return tuple(item[k] for k in self._key_fields)

    def put_item(self, *, Item: dict[str, Any]) -> dict[str, Any]:
        self._rows[self._key_of(Item)] = dict(Item)
        return {}

    def get_item(self, *, Key: dict[str, Any], ConsistentRead: bool = False) -> dict:
        del ConsistentRead
        k = tuple(Key[f] for f in self._key_fields)
        row = self._rows.get(k)
        return {"Item": dict(row)} if row is not None else {}

    def delete_item(
        self, *, Key: dict[str, Any], ReturnValues: str = "NONE"
    ) -> dict[str, Any]:
        k = tuple(Key[f] for f in self._key_fields)
        removed = self._rows.pop(k, None)
        if ReturnValues == "ALL_OLD" and removed is not None:
            return {"Attributes": dict(removed)}
        return {}

    def update_item(
        self,
        *,
        Key: dict[str, Any],
        UpdateExpression: str,
        ExpressionAttributeValues: dict[str, Any],
        ExpressionAttributeNames: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        del ExpressionAttributeNames
        k = tuple(Key[f] for f in self._key_fields)
        row = self._rows.setdefault(k, dict(Key))
        if "access_token = :at" in UpdateExpression:
            row["access_token"] = ExpressionAttributeValues[":at"]
            row["id_token"] = ExpressionAttributeValues[":it"]
            row["refresh_token"] = ExpressionAttributeValues[":rt"]
            row["expires_at"] = ExpressionAttributeValues[":exp"]
            row["updated_at"] = ExpressionAttributeValues[":upd"]
            row["ttl"] = ExpressionAttributeValues[":ttl"]
        elif "active_thread_id = :tid" in UpdateExpression:
            row["active_thread_id"] = ExpressionAttributeValues[":tid"]
            row["updated_at"] = ExpressionAttributeValues[":upd"]
            row["ttl"] = ExpressionAttributeValues[":ttl"]
        return {}

    def query(
        self,
        *,
        KeyConditionExpression: Any,
        IndexName: str | None = None,
        ScanIndexForward: bool = True,
        Limit: int = 100,
        ProjectionExpression: str | None = None,
    ) -> dict[str, Any]:
        del ProjectionExpression
        # Extract owner_sub from boto3 Key("owner_sub").eq(value)
        owner_sub = KeyConditionExpression._values[1]
        matched = [
            dict(r) for r in self._rows.values() if r.get("owner_sub") == owner_sub
        ]
        if IndexName == "owner_sub-updated_at-index":
            matched.sort(
                key=lambda r: int(r.get("updated_at", 0)),
                reverse=not ScanIndexForward,
            )
        return {"Items": matched[:Limit]}


def _make_store() -> tuple[DynamoSessionStore, _FakeTable, _FakeTable]:
    bff_tbl = _FakeTable(("pk",))
    chat_tbl = _FakeTable(("owner_sub", "thread_id"))
    return (
        DynamoSessionStore(
            bff_table=bff_tbl, chat_table=chat_tbl, session_ttl_hours=12
        ),
        bff_tbl,
        chat_tbl,
    )


def test_pkce_state_is_single_use_and_survives_across_store_instances() -> None:
    store_a, bff_tbl, chat_tbl = _make_store()
    store_b = DynamoSessionStore(bff_table=bff_tbl, chat_table=chat_tbl)

    store_a.put_pkce_state("state-1", verifier="ver-123", nonce="nonce-123")
    # Task B (different ECS instance) consumes the state created by Task A.
    popped = store_b.pop_pkce_state("state-1")
    assert popped is not None
    assert popped["verifier"] == "ver-123"
    assert popped["nonce"] == "nonce-123"
    # Second pop returns None (replay blocked).
    assert store_b.pop_pkce_state("state-1") is None


def test_session_and_chat_history_survive_ecs_restart_and_isolate_users() -> None:
    store_a, bff_tbl, chat_tbl = _make_store()
    sess = store_a.create_session(
        sub="sub-e1",
        user_label="e1@corp.example",
        access_token="access-1",
        id_token="id-1",
        refresh_token="refresh-1",
        expires_at=int(time.time()) + 3600,
    )
    store_a.set_active_thread(sess["session_id"], "thread-" + ("a" * 32))
    store_a.append_turn_messages(
        owner_sub="sub-e1",
        thread_id="thread-" + ("a" * 32),
        new_messages=[
            {
                "role": "user",
                "text": "How many leave days do I have?",
                "timestamp": 1000,
            },
            {
                "role": "assistant",
                "text": "You have 14 annual days.",
                "timestamp": 2000,
                "traces": [
                    {
                        "kind": "allow",
                        "label": "get_leave_balance · Annual 14d",
                        "toolName": "hr-ops___get_leave_balance",
                        "detail": {
                            "authorized": True,
                            "data": {"annual": 14.0, "sick": 7.5},
                        },
                    }
                ],
                "cards": [],
            },
        ],
    )

    # Simulate ECS restart / new task reading the same DynamoDB tables.
    store_b = DynamoSessionStore(bff_table=bff_tbl, chat_table=chat_tbl)
    restored_sess = store_b.get_session(sess["session_id"])
    assert restored_sess is not None
    assert restored_sess["sub"] == "sub-e1"
    assert restored_sess["active_thread_id"] == "thread-" + ("a" * 32)

    threads_e1 = store_b.list_chat_threads("sub-e1")
    assert len(threads_e1) == 1
    assert threads_e1[0]["title"] == "How many leave days do I have?"
    assert threads_e1[0]["messageCount"] == 2

    # Different user cannot see E1's threads.
    assert store_b.list_chat_threads("sub-m1") == []
    assert store_b.get_chat_thread("sub-m1", "thread-" + ("a" * 32)) is None

    # JSON serialization succeeds cleanly (Decimals from DynamoDB converted back).
    thread_detail = store_b.get_chat_thread("sub-e1", "thread-" + ("a" * 32))
    assert thread_detail is not None
    dumped = json.dumps(thread_detail)
    assert '"annual": 14' in dumped
    assert '"sick": 7.5' in dumped
    assert not isinstance(
        thread_detail["messages"][1]["traces"][0]["detail"]["data"]["annual"],
        Decimal,
    )


def test_bff_http_endpoints_and_restart_resilience() -> None:
    pytest.importorskip("fastapi")
    pytest.importorskip("httpx")
    pytest.importorskip("jwt")
    from bff.app import BffRuntime, BffSettings, create_app
    from fastapi.testclient import TestClient

    store, bff_tbl, chat_tbl = _make_store()
    settings = BffSettings(
        region="us-east-1",
        ssm_prefix="/hrtest/prod",
        oidc_issuer_url="https://cognito-idp.us-east-1.amazonaws.com/us-east-1_test",
        oidc_client_id="bff-client-id",
        oidc_client_secret="bff-secret",  # pragma: allowlist secret
        oidc_redirect_uri="https://hr.corp.internal/auth/callback",
        oidc_logout_uri="https://hr.corp.internal/",
        oidc_scope="openid email profile",
        bff_session_table="t1",
        chat_session_table="t2",
        exposure="private",
        cookie_secure=True,
        session_ttl_hours=12,
        runtime_arn_override="arn:aws:bedrock-agentcore:us-east-1:111111111111:runtime/orch-123",
    )

    rt1 = BffRuntime(settings, store=store)
    app1 = create_app(settings=settings, runtime=rt1)
    client1 = TestClient(app1)

    # 1. Config exposes BFF mode without leaking client secrets or runtime ARN.
    cfg_resp = client1.get("/config.json")
    assert cfg_resp.status_code == 200
    assert cfg_resp.headers["cache-control"] == "no-store"
    assert cfg_resp.headers["x-frame-options"] == "DENY"
    assert "connect-src 'self'" in cfg_resp.headers["content-security-policy"]
    assert cfg_resp.json() == {
        "auth_mode": "bff",
        "a2ui_protocol_version": "1.0",
        "exposure": "private",
    }

    # 2. Seed session as if /auth/callback ran on task 1, then hit task 2 (ECS restart).
    sess = store.create_session(
        sub="sub-e1",
        user_label="e1@corp.example",
        access_token="eyJ.fake.jwt",
        id_token="eyJ.fake.id",
        refresh_token="refresh-1",
        expires_at=int(time.time()) + 3600,
    )

    store_task2 = DynamoSessionStore(bff_table=bff_tbl, chat_table=chat_tbl)
    rt2 = BffRuntime(settings, store=store_task2)
    app2 = create_app(settings=settings, runtime=rt2)
    client2 = TestClient(app2)
    client2.cookies.set("hr_bff_sid", sess["session_id"])

    me = client2.get("/api/auth/me")
    assert me.status_code == 200
    assert me.json()["authenticated"] is True
    assert me.json()["userLabel"] == "e1@corp.example"

    # 3. Missing CSRF token on /invocations is rejected (403).
    bad_invoke = client2.post(
        "/invocations",
        json={"threadId": "thread-" + ("b" * 32), "messages": []},
        headers={"X-Amzn-Bedrock-AgentCore-Runtime-Session-Id": "thread-" + ("b" * 32)},
    )
    assert bad_invoke.status_code == 403

    # 4. Path traversal / unallowlisted static paths are 404.
    assert client2.get("/../server.py").status_code == 404
    assert client2.get("/ui-primitives.md").status_code == 404
