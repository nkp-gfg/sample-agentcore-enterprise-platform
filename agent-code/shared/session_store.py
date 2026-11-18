"""Bounded, per-caller map from runtime session id to an agent conversation id.

The runtime session id comes from the request body, so the caller chooses it.
Entries are keyed by the verified token subject *and* that id, so one caller
can never resume another caller's conversation, and the map is capped both per
subject and per process so a caller minting a fresh id on every request cannot
grow the process without bound. When an entry is evicted, ``on_evict`` is
handed the conversation id so the caller can release anything it keeps for it
(for example the Claude CLI's on-disk transcript).
"""

from __future__ import annotations

import logging
import re
import threading
from collections import OrderedDict
from collections.abc import Callable

logger = logging.getLogger(__name__)

# Matches the ids the platform's clients generate (UUID4, "session-<hex32>")
# and AgentCore's 33-character minimum, with a hard upper bound on length.
SESSION_ID_MIN_LENGTH = 33
SESSION_ID_MAX_LENGTH = 128
_SESSION_ID_RE = re.compile(
    rf"[A-Za-z0-9_-]{{{SESSION_ID_MIN_LENGTH},{SESSION_ID_MAX_LENGTH}}}"
)

DEFAULT_MAX_SESSIONS = 1024
DEFAULT_MAX_SESSIONS_PER_USER = 16


def is_valid_session_id(value: object) -> bool:
    """True when ``value`` is a session id this process is willing to retain."""
    return isinstance(value, str) and _SESSION_ID_RE.fullmatch(value) is not None


class SessionStore:
    """Thread-safe LRU map of (user_id, session_id) -> conversation id."""

    def __init__(
        self,
        max_sessions: int = DEFAULT_MAX_SESSIONS,
        max_sessions_per_user: int = DEFAULT_MAX_SESSIONS_PER_USER,
        on_evict: Callable[[str], None] | None = None,
    ) -> None:
        if max_sessions < 1 or max_sessions_per_user < 1:
            raise ValueError("session caps must be at least 1")
        self._max_sessions = max_sessions
        self._max_per_user = min(max_sessions_per_user, max_sessions)
        self._on_evict = on_evict
        self._lock = threading.Lock()
        self._entries: OrderedDict[tuple[str, str], str] = OrderedDict()
        self._by_user: dict[str, OrderedDict[str, None]] = {}

    def __len__(self) -> int:
        with self._lock:
            return len(self._entries)

    def get(self, user_id: str, session_id: str) -> str | None:
        """Conversation id for this caller's session, or None."""
        key = (user_id, session_id)
        with self._lock:
            value = self._entries.get(key)
            if value is not None:
                self._entries.move_to_end(key)
                self._by_user[user_id].move_to_end(session_id)
            return value

    def put(self, user_id: str, session_id: str, conversation_id: str) -> None:
        """Retain ``conversation_id`` for this caller's session, evicting the
        caller's oldest session, then the process's oldest, to stay in bounds."""
        if not user_id or not isinstance(user_id, str):
            raise ValueError("user_id is required")
        if not is_valid_session_id(session_id):
            raise ValueError("invalid session id")

        key = (user_id, session_id)
        released: list[str] = []
        with self._lock:
            previous = self._entries.get(key)
            if previous is not None:
                self._entries[key] = conversation_id
                self._entries.move_to_end(key)
                self._by_user[user_id].move_to_end(session_id)
                if previous != conversation_id:
                    released.append(previous)
            else:
                user_sessions = self._by_user.get(user_id)
                while user_sessions and len(user_sessions) >= self._max_per_user:
                    oldest, _ = user_sessions.popitem(last=False)
                    released.append(self._entries.pop((user_id, oldest)))
                while len(self._entries) >= self._max_sessions:
                    (old_user, old_session), old_value = self._entries.popitem(
                        last=False
                    )
                    released.append(old_value)
                    old_user_sessions = self._by_user[old_user]
                    old_user_sessions.pop(old_session, None)
                    if not old_user_sessions:
                        del self._by_user[old_user]
                self._entries[key] = conversation_id
                self._by_user.setdefault(user_id, OrderedDict())[session_id] = None

        for conversation in released:
            self._release(conversation)

    def _release(self, conversation_id: str) -> None:
        if self._on_evict is None:
            return
        try:
            self._on_evict(conversation_id)
        except Exception as exc:  # noqa: BLE001 — eviction cleanup is best effort
            logger.debug("Session eviction cleanup failed: %s", exc)
