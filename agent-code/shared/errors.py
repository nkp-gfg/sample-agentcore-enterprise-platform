"""Fixed client-facing errors for agent entrypoints.

Exception text must never reach the caller. AWS SDK errors name the account,
the runtime role and the denied resource, and token rejections explain why a
token was refused. Entrypoints log the exception on the server and return one
of these fixed strings instead.

BedrockAgentCoreApp puts ``str(exception)`` on the response for anything that
escapes an entrypoint, so every entrypoint must catch its own failures.
"""

import logging

logger = logging.getLogger(__name__)

UNAUTHORIZED = "Unauthorized"
AGENT_RUN_FAILED = "Agent run failed"
TOOL_CALL_FAILED = "Tool call failed"

# AG-UI event types whose message the AG-UI libraries fill from str(exc).
_AGUI_ERROR_EVENT_TYPES = frozenset({"RUN_ERROR", "SUBAGENT_ERROR"})


def error_response(message: str) -> dict:
    return {"status": "error", "error": message}


def client_safe_strands_event(event: dict) -> dict:
    """Strip the exception text Strands puts in a forced-stop event."""
    if "force_stop_reason" in event:
        logger.error("Agent run force-stopped: %s", event["force_stop_reason"])
        event = {**event, "force_stop_reason": AGENT_RUN_FAILED}
    return event


def client_safe_agui_event(event: dict) -> dict:
    """Replace the message of an AG-UI error event with a fixed string."""
    if event.get("type") in _AGUI_ERROR_EVENT_TYPES:
        logger.error(
            "AG-UI %s: %s (code=%s)",
            event.get("type"),
            event.get("message"),
            event.get("code"),
        )
        event = {k: v for k, v in event.items() if k != "code"}
        event["message"] = AGENT_RUN_FAILED
    return event
