"""Per-employee turn rate limit for the god agent.

`custom-app-plan/god-agent.md` § Limits:

    Runtime entry point: 20 turns per employee per 10 minutes, counted on
    the verified `sub`. Trips → "Answers without calling the model".

`docs/hr/acceptance.md` red-team row R-08 ("25 turns in 10 minutes") is the
behavioural gate: turns 21-25 are refused without a single Bedrock call.

The limiter lives in process memory. A runtime container is replaced from
time to time, and the window is 10 minutes, so an in-memory sliding counter
is enough — a cross-pod store would be the right answer when module 6 is
later horizontally scaled, but that is layer-3 work.
"""

from __future__ import annotations

import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass

DEFAULT_MAX_TURNS = 20
DEFAULT_WINDOW_SECONDS = 10 * 60


@dataclass(frozen=True)
class RateLimitResult:
    allowed: bool
    turns_in_window: int
    retry_after_seconds: float


class TurnRateLimiter:
    """Sliding-window rate limit on the verified `sub` (never on the prompt).

    Callers MUST key by a value they verified themselves (for example the
    `sub` claim validated in `shared/auth.extract_user_id_from_context`). A
    key that came from the model would let the agent rate-limit itself out of
    everyone else's conversation.
    """

    def __init__(
        self,
        *,
        max_turns: int = DEFAULT_MAX_TURNS,
        window_seconds: float = DEFAULT_WINDOW_SECONDS,
    ) -> None:
        if max_turns < 1:
            raise ValueError("max_turns must be >= 1")
        if window_seconds <= 0:
            raise ValueError("window_seconds must be > 0")
        self._max_turns = max_turns
        self._window_seconds = window_seconds
        self._events: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def check_and_record(
        self, key: str, *, now: float | None = None
    ) -> RateLimitResult:
        """Record a turn attempt and tell the caller whether to allow it.

        Thread-safe. One call per attempted turn. The call records the event
        only when the attempt is allowed, so a refused caller does not keep
        pushing their own window forward forever.
        """

        if not key:
            # No verified subject means we have nothing to rate-limit on, and
            # the entry point shouldn't have reached this call. Refuse loudly.
            raise ValueError("rate-limit key must be a non-empty verified subject")

        current_time = time.monotonic() if now is None else now
        window_start = current_time - self._window_seconds

        with self._lock:
            events = self._events[key]
            while events and events[0] <= window_start:
                events.popleft()

            if len(events) >= self._max_turns:
                oldest = events[0]
                retry_after = max(0.0, (oldest + self._window_seconds) - current_time)
                return RateLimitResult(
                    allowed=False,
                    turns_in_window=len(events),
                    retry_after_seconds=retry_after,
                )

            events.append(current_time)
            return RateLimitResult(
                allowed=True,
                turns_in_window=len(events),
                retry_after_seconds=0.0,
            )

    def reset(self) -> None:
        """Test hook: drop every window."""

        with self._lock:
            self._events.clear()


_DEFAULT_LIMITER = TurnRateLimiter()


def default_limiter() -> TurnRateLimiter:
    return _DEFAULT_LIMITER
