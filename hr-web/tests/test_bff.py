"""Unit tests for the DynamoDB session store and ECS BFF boundary."""

from __future__ import annotations

import asyncio
import json
import logging
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


def test_bff_http_endpoints_and_restart_resilience(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pytest.importorskip("fastapi")
    pytest.importorskip("httpx")
    pytest.importorskip("jwt")
    import bff.app as bff_app
    from bff.app import BffRuntime, BffSettings, create_app
    from fastapi.testclient import TestClient

    # The allowlist is what this test pins. Hide a local Vite build if one exists.
    monkeypatch.setattr(bff_app, "WEB_DIST", Path("/no/such/hr-web-dist"))

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


_OIDC_DISCOVERY = {
    "authorization_endpoint": "https://idp.example/oauth2/authorize",
    "token_endpoint": "https://idp.example/oauth2/token",
    "jwks_uri": "https://idp.example/.well-known/jwks.json",
    "issuer": "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_test",
}


class _FakeOAuthClient:
    """httpx stand-in that returns discovery JSON or raises a transport error."""

    def __init__(
        self,
        *,
        get_exc: BaseException | None = None,
        post_exc: BaseException | None = None,
    ) -> None:
        self.get_exc = get_exc
        self.post_exc = post_exc
        self.posts = 0
        self.gets = 0
        self.post_timeouts: list[object] = []
        self.get_timeouts: list[object] = []
        self.posted: list[Any] = []

    async def get(self, url: str, timeout: object = None):
        self.gets += 1
        self.get_timeouts.append(timeout)
        if self.get_exc is not None:
            raise self.get_exc
        import httpx

        return httpx.Response(
            200,
            json=dict(_OIDC_DISCOVERY),
            request=httpx.Request("GET", url),
        )

    async def post(self, url: str, data: object = None, timeout: object = None):
        self.posts += 1
        self.post_timeouts.append(timeout)
        self.posted.append(data)
        if self.post_exc is not None:
            raise self.post_exc
        raise AssertionError("token endpoint should not be called")


def _bff_settings():
    pytest.importorskip("fastapi")
    pytest.importorskip("httpx")
    from bff.app import BffSettings

    return BffSettings(
        region="us-east-1",
        ssm_prefix="/hrtest/prod",
        oidc_issuer_url="https://cognito-idp.us-east-1.amazonaws.com/us-east-1_test",
        oidc_client_id="bff-client-id",
        oidc_client_secret="bff-client-secret-do-not-log",  # pragma: allowlist secret
        oidc_redirect_uri="https://hr.corp.internal/auth/callback",
        oidc_logout_uri="https://hr.corp.internal/",
        oidc_scope="openid email profile",
        bff_session_table="t1",
        chat_session_table="t2",
        exposure="private",
        cookie_secure=True,
        session_ttl_hours=12,
    )


def _make_bff_client(http_client: object | None = None):
    pytest.importorskip("fastapi")
    pytest.importorskip("httpx")
    from bff.app import BffRuntime, create_app
    from fastapi.testclient import TestClient

    store, _, _ = _make_store()
    settings = _bff_settings()
    runtime = BffRuntime(settings, store=store, http_client=http_client)
    return store, runtime, TestClient(create_app(settings=settings, runtime=runtime))


@pytest.mark.parametrize("exc_name", ["ReadTimeout", "ConnectError"])
def test_auth_callback_token_transport_error_redirects(
    exc_name: str, caplog: pytest.LogCaptureFixture
) -> None:
    httpx = pytest.importorskip("httpx")
    pytest.importorskip("fastapi")
    http = _FakeOAuthClient(post_exc=getattr(httpx, exc_name)("timed out"))
    store, _runtime, client = _make_bff_client(http)
    store.put_pkce_state(
        "state-timeout",
        verifier="pkce-verifier-do-not-log",
        nonce="nonce-value",
    )
    expected_timeout = httpx.Timeout(connect=5.0, read=20.0, write=10.0, pool=5.0)
    with caplog.at_level(logging.WARNING, logger="hr-web-bff"):
        resp = client.get(
            "/auth/callback",
            params={"code": "auth-code-do-not-log", "state": "state-timeout"},
            follow_redirects=False,
        )
    assert resp.status_code == 302, resp.text
    assert resp.headers["location"].endswith("/?error=token_exchange_failed")
    assert "Internal Server Error" not in resp.text
    assert http.posts == 2
    assert http.get_timeouts == [10.0]
    assert http.post_timeouts == [expected_timeout, expected_timeout]
    assert http.posted[0]["code"] == "auth-code-do-not-log"
    assert "auth-code-do-not-log" not in caplog.text
    assert "pkce-verifier-do-not-log" not in caplog.text
    assert "bff-client-secret-do-not-log" not in caplog.text
    assert caplog.text.count(f"OIDC token request failed: {exc_name}") == 1


def test_auth_discovery_timeout_redirects(caplog: pytest.LogCaptureFixture) -> None:
    httpx = pytest.importorskip("httpx")
    pytest.importorskip("fastapi")
    http = _FakeOAuthClient(get_exc=httpx.ReadTimeout("timed out"))
    store, _runtime, client = _make_bff_client(http)
    with caplog.at_level(logging.WARNING, logger="hr-web-bff"):
        login = client.get("/auth/login", follow_redirects=False)
        store.put_pkce_state("state-discovery", verifier="ver", nonce="nonce")
        callback = client.get(
            "/auth/callback",
            params={"code": "auth-code-do-not-log", "state": "state-discovery"},
            follow_redirects=False,
        )
    assert login.status_code == 302, login.text
    assert login.headers["location"].endswith("/?error=oidc_discovery_failed")
    assert callback.status_code == 302, callback.text
    assert callback.headers["location"].endswith("/?error=oidc_discovery_failed")
    assert http.posts == 0
    assert http.get_timeouts == [10.0, 10.0]
    assert caplog.text.count("OIDC discovery failed: ReadTimeout") == 2
    assert "auth-code-do-not-log" not in caplog.text


def test_ensure_fresh_session_token_timeout_returns_none(
    caplog: pytest.LogCaptureFixture,
) -> None:
    httpx = pytest.importorskip("httpx")
    pytest.importorskip("fastapi")
    http = _FakeOAuthClient(post_exc=httpx.ReadTimeout("timed out"))
    store, runtime, _client = _make_bff_client(http)
    session = store.create_session(
        sub="sub-e1",
        user_label="e1@corp.example",
        access_token="access-1",
        id_token="id-1",
        refresh_token="refresh-token-do-not-log",
        expires_at=int(time.time()) - 120,
    )
    with caplog.at_level(logging.WARNING, logger="hr-web-bff"):
        fresh = asyncio.run(runtime.ensure_fresh_session(session))
    assert fresh is None
    assert store.get_session(session["session_id"]) is None
    assert http.posts == 2
    assert "refresh-token-do-not-log" not in caplog.text
    assert "bff-client-secret-do-not-log" not in caplog.text
    assert caplog.text.count("OIDC token request failed: ReadTimeout") == 1


def test_ensure_fresh_session_discovery_timeout_returns_none() -> None:
    httpx = pytest.importorskip("httpx")
    pytest.importorskip("fastapi")
    http = _FakeOAuthClient(get_exc=httpx.ReadTimeout("timed out"))
    store, runtime, _client = _make_bff_client(http)
    session = store.create_session(
        sub="sub-e1",
        user_label="e1@corp.example",
        access_token="access-1",
        id_token="id-1",
        refresh_token="refresh-token-do-not-log",
        expires_at=int(time.time()) - 120,
    )
    fresh = asyncio.run(runtime.ensure_fresh_session(session))
    assert fresh is None
    assert http.posts == 0
    assert store.get_session(session["session_id"]) is None


def test_public_allowlist_when_spa_dist_is_absent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    pytest.importorskip("fastapi")
    pytest.importorskip("httpx")
    import bff.app as bff_app

    monkeypatch.setattr(bff_app, "WEB_DIST", tmp_path / "no-such-dist")
    _store, _runtime, client = _make_bff_client()
    home = client.get("/")
    assert home.status_code == 200
    assert "AgentCore Enterprise" in home.text
    assert "text/html" in home.headers["content-type"]
    css = client.get("/styles.css")
    assert css.status_code == 200
    assert css.headers["content-type"] == "text/css; charset=utf-8"
    assert client.get("/ui-primitives.md").status_code == 404
    assert client.get("/../server.py").status_code == 404
    head_home = client.head("/")
    assert head_home.status_code == 200
    assert head_home.headers["content-type"].startswith("text/html")
    config = client.get("/config.json")
    assert config.status_code == 200
    assert config.headers["cache-control"] == "no-store"
    head_config = client.head("/config.json")
    assert head_config.status_code == 200
    assert head_config.headers["content-type"].startswith("application/json")
    assert head_config.headers["cache-control"] == "no-store"


def test_spa_dist_is_served_when_index_exists(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    pytest.importorskip("fastapi")
    pytest.importorskip("httpx")
    import bff.app as bff_app

    dist = tmp_path / "dist"
    assets = dist / "assets"
    assets.mkdir(parents=True)
    (dist / "index.html").write_text(
        "<!doctype html><title>spa-marker</title>", encoding="utf-8"
    )
    (assets / "app.js").write_text("console.log('spa-asset')", encoding="utf-8")
    (assets / "app.css").write_text("body{}", encoding="utf-8")
    (assets / "app.js.map").write_text("{}", encoding="utf-8")
    (assets / "font.woff2").write_bytes(b"woff")
    (dist / "favicon.svg").write_text(
        "<svg xmlns='http://www.w3.org/2000/svg'/>", encoding="utf-8"
    )
    (dist / "manifest.json").write_text("{}", encoding="utf-8")
    secret = tmp_path / "secret.txt"
    secret.write_text("TOP-SECRET-OUTSIDE", encoding="utf-8")
    (dist / "leak").symlink_to(secret)
    (assets / "leak.js").symlink_to(secret)
    (assets / "alias.js").symlink_to("app.js")

    monkeypatch.setattr(bff_app, "WEB_DIST", dist)
    _store, _runtime, client = _make_bff_client()

    home = client.get("/")
    assert home.status_code == 200
    assert "spa-marker" in home.text
    assert "AgentCore Enterprise" not in home.text
    assert home.headers["cache-control"] == "no-store"
    assert home.headers["content-type"].startswith("text/html")

    index = client.get("/index.html")
    assert index.status_code == 200
    assert index.headers["cache-control"] == "no-store"

    head_home = client.head("/")
    assert head_home.status_code == 200
    assert head_home.headers["content-type"].startswith("text/html")
    assert head_home.headers["cache-control"] == "no-store"

    config = client.get("/config.json")
    assert config.status_code == 200
    assert config.json()["auth_mode"] == "bff"
    assert config.headers["cache-control"] == "no-store"
    head_config = client.head("/config.json")
    assert head_config.status_code == 200
    assert head_config.headers["content-type"].startswith("application/json")
    assert head_config.headers["cache-control"] == "no-store"
    health = client.get("/healthz")
    assert health.status_code == 200
    assert health.json() == {"status": "ok"}

    script = client.get("/assets/app.js")
    assert script.status_code == 200
    assert "spa-asset" in script.text
    assert script.headers["content-type"].startswith("application/javascript")
    assert script.headers["cache-control"] == "public, max-age=31536000, immutable"

    css = client.get("/assets/app.css")
    assert css.status_code == 200
    assert css.headers["content-type"].startswith("text/css")
    assert css.headers["cache-control"] == "public, max-age=31536000, immutable"

    source_map = client.get("/assets/app.js.map")
    assert source_map.status_code == 200
    assert source_map.headers["content-type"].startswith("application/json")
    assert source_map.headers["cache-control"] == "public, max-age=31536000, immutable"

    font = client.get("/assets/font.woff2")
    assert font.status_code == 200
    assert font.headers["content-type"] == "font/woff2"
    assert font.headers["cache-control"] == "public, max-age=31536000, immutable"

    icon = client.get("/favicon.svg")
    assert icon.status_code == 200
    assert icon.headers["content-type"].startswith("image/svg+xml")
    assert "immutable" not in icon.headers.get("cache-control", "")

    manifest = client.get("/manifest.json")
    assert manifest.status_code == 200
    assert manifest.headers["content-type"].startswith("application/json")

    missing_asset = client.get("/assets/missing.js")
    assert missing_asset.status_code == 404
    assert missing_asset.headers["content-type"].startswith("application/json")
    assert missing_asset.json()["detail"] == "Resource not found."

    route = client.get("/employees/42")
    assert route.status_code == 200
    assert "spa-marker" in route.text
    assert route.headers["cache-control"] == "no-store"

    legacy_css = client.get("/styles.css")
    assert legacy_css.status_code == 200
    assert "spa-marker" in legacy_css.text
    assert "text/html" in legacy_css.headers["content-type"]

    leak = client.get("/leak")
    assert leak.status_code == 404
    assert "TOP-SECRET-OUTSIDE" not in leak.text
    asset_leak = client.get("/assets/leak.js")
    assert asset_leak.status_code == 404
    assert "TOP-SECRET-OUTSIDE" not in asset_leak.text

    alias = client.get("/assets/alias.js")
    assert alias.status_code == 200
    assert "spa-asset" in alias.text

    unknown_api = client.get("/api/not-a-route")
    assert unknown_api.status_code == 404
    assert "spa-marker" not in unknown_api.text
    assert unknown_api.headers["content-type"].startswith("application/json")
    unknown_auth = client.get("/auth/not-a-route")
    assert unknown_auth.status_code == 404
    assert "spa-marker" not in unknown_auth.text
    assert client.get("/invocations").status_code == 404

    root = dist.resolve()
    assert bff_app._resolve_dist_path(root, "leak") is None
    assert bff_app._resolve_dist_path(root, "../secret.txt") is None
    assert bff_app._resolve_dist_path(root, "assets/../../secret.txt") is None
    inside = bff_app._resolve_dist_path(root, "assets/app.js")
    assert inside is not None and inside.is_file() and inside.is_relative_to(root)
