"""Read caller identity from the Lambda event.

docs/hr/tools.md § Identity on the call pins the contract: the gateway
interceptor overwrites `caller_employee_id`, `agent_id`, and `session_id`
on the tool arguments after reading the gateway-validated JWT. The Lambda
trusts these three fields only because the interceptor wrote them; it
MUST NOT parse the token again, and it MUST ignore whatever the model
sent in those three fields.

This module centralises that read. A missing `caller_employee_id` means
the H3 pre-token Lambda added no `employee_id` claim (no active row for
that `sub`), which maps to `NOT_MAPPED` without calling OPA.
"""

from __future__ import annotations

from .errors import NotMapped


def get_identity(event: dict) -> tuple[str, str, str]:
    """Return (caller_employee_id, agent_id, session_id).

    Raises `NotMapped` when the interceptor wrote no `caller_employee_id`
    — the token carried no `employee_id` claim, so the H3 lookup either
    missed the row or the row is terminated.

    `agent_id` and `session_id` default to the empty string: the handler
    still logs them to `decision_log`, where an empty string is the
    correct "no value" signal (a NULL would look like a partial write).
    """
    caller = event.get("caller_employee_id")
    if not isinstance(caller, str) or not caller.strip():
        raise NotMapped("interceptor wrote no caller_employee_id")
    agent_id = event.get("agent_id") or ""
    session_id = event.get("session_id") or ""
    if not isinstance(agent_id, str):
        agent_id = ""
    if not isinstance(session_id, str):
        session_id = ""
    return caller, agent_id, session_id
