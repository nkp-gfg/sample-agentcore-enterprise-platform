"""Shape every HR tool answers with.

docs/hr/tools.md § Responses pins the contract:

    {"authorized": true,  "reason_code": "ALLOW", "data": {...}}
    {"authorized": false, "reason_code": "NOT_AUTHORIZED"}

`data` is omitted when `authorized` is false. A policy deny, a crashed
Postgres, and a disabled service are all normal tool results — not
Lambda exceptions and not JSON-RPC `isError` — so the model cannot
fill in a number after a crash.

The gateway Lambda target contract wraps this in `{"content": [...]}`;
that is the dispatcher's job. This function only returns the business
object every per-tool handler produces.
"""

from __future__ import annotations

from typing import Any


def build_response(
    *, authorized: bool, reason_code: str, data: dict[str, Any] | None = None
) -> dict[str, Any]:
    """Return the shape docs/hr/tools.md § Responses pins.

    On an allow (`authorized=True`), `data` MUST be supplied — a tool
    that allows and returns no data is almost always a bug. On a deny
    (`authorized=False`), `data` is dropped even if the caller passed
    one, so an accidental payload cannot leak.
    """
    if authorized:
        if data is None:
            # Treat as a programming error — not something the caller can
            # recover from. The dispatcher turns this into a server-side
            # log without leaking details back through the gateway.
            raise ValueError("authorized responses MUST carry data")
        return {"authorized": True, "reason_code": reason_code, "data": dict(data)}
    return {"authorized": False, "reason_code": reason_code}
