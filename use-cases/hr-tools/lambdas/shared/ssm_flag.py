"""The SSM kill switch for every HR Lambda.

docs/hr/policy.md § Reason codes lists `SERVICE_DISABLED` as the first
check — before OPA, before Postgres, before anything. docs/hr/modules.md
§ Kill switch and audit export locks the behaviour: anything other than
the literal string `true` returns `SERVICE_DISABLED`, and a missing or
unreadable parameter is also `SERVICE_DISABLED` — a missing kill switch
never falls open.

The stack sets `HR_KILL_SWITCH_PARAMETER` on each function to the full
SSM parameter name. The in-process cache is 30 s so a flip propagates
within 30 seconds of the write, without spending an SSM read per call.
"""

from __future__ import annotations

import logging
import os
import time

try:
    import boto3
except ImportError:  # pragma: no cover — stdlib-only unit tests
    boto3 = None  # type: ignore[assignment]

logger = logging.getLogger(__name__)

_CACHE: dict[str, tuple[float, bool]] = {}
_CACHE_TTL_SECONDS = 30.0


def is_service_enabled() -> bool:
    """Return True iff `HR_KILL_SWITCH_PARAMETER` is the literal `true`.

    Any other value, a missing parameter, or an SSM read error returns
    False. The caller MUST map False to `SERVICE_DISABLED` without
    reading any employee data.
    """
    name = os.environ.get("HR_KILL_SWITCH_PARAMETER", "")
    if not name:
        logger.warning("HR_KILL_SWITCH_PARAMETER is not set; refusing")
        return False
    now = time.monotonic()
    cached = _CACHE.get(name)
    if cached is not None and (now - cached[0]) < _CACHE_TTL_SECONDS:
        return cached[1]
    if boto3 is None:
        logger.warning("boto3 unavailable; refusing")
        return False
    try:
        ssm = boto3.client("ssm")
        value = ssm.get_parameter(Name=name)["Parameter"]["Value"]
    except Exception:
        logger.exception("could not read SSM kill switch %s", name)
        _CACHE[name] = (now, False)
        return False
    enabled = value == "true"
    _CACHE[name] = (now, enabled)
    return enabled


def _reset_cache_for_tests() -> None:
    """Only called by unit tests."""
    _CACHE.clear()
