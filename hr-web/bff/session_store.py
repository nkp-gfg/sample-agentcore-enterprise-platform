"""DynamoDB-backed OAuth session, PKCE state, and chat history store for hr-web BFF.

Storing both OAuth sessions (tokens, CSRF secret, active thread) and chat
transcripts in DynamoDB guarantees that ECS Fargate task restarts, rolling
deployments, and horizontal scaling events never disrupt the user's session or
lose conversation history in the UI.
"""

from __future__ import annotations

import json
import secrets
import time
from decimal import Decimal
from typing import Any

from boto3.dynamodb.conditions import Key


def _to_ddb(value: Any) -> Any:
    if isinstance(value, float):
        return Decimal(str(value))
    if isinstance(value, dict):
        return {k: _to_ddb(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_to_ddb(v) for v in value]
    return value


def _from_ddb(value: Any) -> Any:
    if isinstance(value, Decimal):
        return int(value) if value == int(value) else float(value)
    if isinstance(value, dict):
        return {k: _from_ddb(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_from_ddb(v) for v in value]
    return value


MAX_CHAT_THREADS_PER_USER = 30
MAX_MESSAGES_PER_THREAD = 200
MAX_ITEM_JSON_BYTES = 300_000
PKCE_TTL_SECONDS = 600


def _now_epoch() -> int:
    return int(time.time())


def _now_ms() -> int:
    return int(time.time() * 1000)


def _trim_messages_to_budget(messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Keep recent messages bounded well below DynamoDB's 400 KB item ceiling."""
    trimmed = [
        dict(m) for m in messages[-MAX_MESSAGES_PER_THREAD:] if isinstance(m, dict)
    ]
    while len(trimmed) > 1:
        encoded = json.dumps(trimmed, ensure_ascii=False, separators=(",", ":")).encode(
            "utf-8"
        )
        if len(encoded) <= MAX_ITEM_JSON_BYTES:
            break
        trimmed.pop(0)
    if len(trimmed) == 1:
        encoded = json.dumps(trimmed, ensure_ascii=False, separators=(",", ":")).encode(
            "utf-8"
        )
        if len(encoded) > MAX_ITEM_JSON_BYTES:
            single = dict(trimmed[0])
            single["traces"] = []
            single["cards"] = []
            single["text"] = str(single.get("text", ""))[:64_000]
            trimmed = [single]
    return trimmed


class DynamoSessionStore:
    """Thin wrapper over DynamoDB tables for BFF auth sessions and chat history."""

    def __init__(
        self,
        *,
        bff_table,
        chat_table,
        session_ttl_hours: int = 12,
    ) -> None:
        self._bff_table = bff_table
        self._chat_table = chat_table
        self._session_ttl_seconds = max(3600, int(session_ttl_hours) * 3600)

    # ── PKCE state (multi-task / restart-safe OIDC login) ──────────────────

    def put_pkce_state(
        self,
        state: str,
        *,
        verifier: str,
        nonce: str,
        ttl_seconds: int = PKCE_TTL_SECONDS,
    ) -> None:
        now = _now_epoch()
        self._bff_table.put_item(
            Item={
                "pk": f"pkce#{state}",
                "verifier": verifier,
                "nonce": nonce,
                "created_at": now,
                "ttl": now + ttl_seconds,
            }
        )

    def pop_pkce_state(self, state: str) -> dict[str, Any] | None:
        """Atomically consume a PKCE state record so login callbacks are single-use."""
        resp = self._bff_table.delete_item(
            Key={"pk": f"pkce#{state}"},
            ReturnValues="ALL_OLD",
        )
        item = resp.get("Attributes")
        if not item:
            return None
        if int(item.get("ttl", 0)) <= _now_epoch():
            return None
        return item

    # ── Auth sessions (HttpOnly cookie -> server-side tokens + CSRF) ───────

    def create_session(
        self,
        *,
        sub: str,
        user_label: str,
        access_token: str,
        id_token: str | None,
        refresh_token: str | None,
        expires_at: int,
        active_thread_id: str = "",
    ) -> dict[str, Any]:
        now = _now_epoch()
        session_id = secrets.token_urlsafe(32)
        csrf_token = secrets.token_urlsafe(32)
        item: dict[str, Any] = {
            "pk": f"sid#{session_id}",
            "session_id": session_id,
            "sub": sub,
            "user_label": user_label,
            "access_token": access_token,
            "id_token": id_token or "",
            "refresh_token": refresh_token or "",
            "expires_at": int(expires_at),
            "csrf_token": csrf_token,
            "active_thread_id": active_thread_id,
            "created_at": now,
            "updated_at": now,
            "ttl": now + self._session_ttl_seconds,
        }
        self._bff_table.put_item(Item=item)
        return item

    def get_session(self, session_id: str) -> dict[str, Any] | None:
        if not session_id:
            return None
        resp = self._bff_table.get_item(
            Key={"pk": f"sid#{session_id}"},
            ConsistentRead=True,
        )
        item = resp.get("Item")
        if not item:
            return None
        if int(item.get("ttl", 0)) <= _now_epoch():
            self.delete_session(session_id)
            return None
        return item

    def update_session_tokens(
        self,
        session_id: str,
        *,
        access_token: str,
        id_token: str | None,
        refresh_token: str | None,
        expires_at: int,
    ) -> None:
        now = _now_epoch()
        self._bff_table.update_item(
            Key={"pk": f"sid#{session_id}"},
            UpdateExpression=(
                "SET access_token = :at, id_token = :it, refresh_token = :rt, "
                "expires_at = :exp, updated_at = :upd, #ttl = :ttl"
            ),
            ExpressionAttributeNames={"#ttl": "ttl"},
            ExpressionAttributeValues={
                ":at": access_token,
                ":it": id_token or "",
                ":rt": refresh_token or "",
                ":exp": int(expires_at),
                ":upd": now,
                ":ttl": now + self._session_ttl_seconds,
            },
        )

    def set_active_thread(self, session_id: str, thread_id: str) -> None:
        now = _now_epoch()
        self._bff_table.update_item(
            Key={"pk": f"sid#{session_id}"},
            UpdateExpression="SET active_thread_id = :tid, updated_at = :upd, #ttl = :ttl",
            ExpressionAttributeNames={"#ttl": "ttl"},
            ExpressionAttributeValues={
                ":tid": thread_id,
                ":upd": now,
                ":ttl": now + self._session_ttl_seconds,
            },
        )

    def delete_session(self, session_id: str) -> None:
        if not session_id:
            return
        self._bff_table.delete_item(Key={"pk": f"sid#{session_id}"})

    # ── Chat threads & transcripts (owner_sub-isolated) ────────────────────

    def list_chat_threads(
        self,
        owner_sub: str,
        *,
        limit: int = MAX_CHAT_THREADS_PER_USER,
    ) -> list[dict[str, Any]]:
        if not owner_sub:
            return []
        resp = self._chat_table.query(
            IndexName="owner_sub-updated_at-index",
            KeyConditionExpression=Key("owner_sub").eq(owner_sub),
            ScanIndexForward=False,
            Limit=limit,
        )
        items = resp.get("Items", [])
        out: list[dict[str, Any]] = []
        for item in items:
            msgs = item.get("messages") or []
            out.append(
                {
                    "threadId": item.get("thread_id", ""),
                    "title": item.get("title", "Conversation"),
                    "activeAgentId": item.get("active_agent_id", "hr-assistant"),
                    "updatedAt": int(item.get("updated_at", 0)),
                    "messageCount": len(msgs),
                }
            )
        return out

    def get_chat_thread(self, owner_sub: str, thread_id: str) -> dict[str, Any] | None:
        if not owner_sub or not thread_id:
            return None
        resp = self._chat_table.get_item(
            Key={"owner_sub": owner_sub, "thread_id": thread_id},
            ConsistentRead=True,
        )
        item = resp.get("Item")
        if not item:
            return None
        return {
            "threadId": item.get("thread_id", thread_id),
            "title": item.get("title", "Conversation"),
            "activeAgentId": item.get("active_agent_id", "hr-assistant"),
            "updatedAt": int(item.get("updated_at", 0)),
            "messages": _from_ddb(list(item.get("messages") or [])),
        }

    def upsert_chat_thread(
        self,
        *,
        owner_sub: str,
        thread_id: str,
        title: str,
        active_agent_id: str,
        messages: list[dict[str, Any]],
    ) -> dict[str, Any]:
        now = _now_ms()
        bounded = _trim_messages_to_budget(messages)
        item = {
            "owner_sub": owner_sub,
            "thread_id": thread_id,
            "title": title[:80] or "Conversation",
            "activeAgentId": active_agent_id or "hr-assistant",
            "active_agent_id": active_agent_id or "hr-assistant",
            "updated_at": now,
            "messages": _to_ddb(bounded),
        }
        self._chat_table.put_item(Item=item)
        return item

    def append_turn_messages(
        self,
        *,
        owner_sub: str,
        thread_id: str,
        new_messages: list[dict[str, Any]],
        active_agent_id: str = "hr-assistant",
        title_hint: str = "",
    ) -> dict[str, Any]:
        if not new_messages:
            existing = self.get_chat_thread(owner_sub, thread_id)
            return existing or {
                "threadId": thread_id,
                "title": "Conversation",
                "activeAgentId": active_agent_id,
                "updatedAt": _now_ms(),
                "messages": [],
            }
        existing = self.get_chat_thread(owner_sub, thread_id)
        messages = list(existing["messages"]) if existing else []
        messages.extend(new_messages)
        title = existing["title"] if existing and existing.get("title") else title_hint
        if not title:
            for m in messages:
                if m.get("role") == "user" and str(m.get("text", "")).strip():
                    title = str(m["text"]).strip()[:64]
                    break
        return self.upsert_chat_thread(
            owner_sub=owner_sub,
            thread_id=thread_id,
            title=title or "Conversation",
            active_agent_id=(
                (existing.get("activeAgentId") if existing else "")
                or active_agent_id
                or "hr-assistant"
            ),
            messages=messages,
        )

    def delete_chat_thread(self, owner_sub: str, thread_id: str) -> None:
        if not owner_sub or not thread_id:
            return
        self._chat_table.delete_item(
            Key={"owner_sub": owner_sub, "thread_id": thread_id}
        )

    def clear_chat_threads(self, owner_sub: str) -> int:
        if not owner_sub:
            return 0
        resp = self._chat_table.query(
            KeyConditionExpression=Key("owner_sub").eq(owner_sub),
            ProjectionExpression="owner_sub, thread_id",
        )
        items = resp.get("Items", [])
        for item in items:
            self._chat_table.delete_item(
                Key={"owner_sub": owner_sub, "thread_id": item["thread_id"]}
            )
        return len(items)
