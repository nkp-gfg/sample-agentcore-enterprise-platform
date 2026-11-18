# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""AgentCore Gateway egress interceptor.

Applies a Bedrock Guardrail to Gateway traffic for defense-in-depth egress control:
  - REQUEST  interception point: guardrail runs with source=INPUT before the target is called
    (blocks prompt-injection, masks PII leaving the agent toward the tool/target).
  - RESPONSE interception point: guardrail runs with source=OUTPUT before the response returns
    to the caller (masks PII coming back from the target).

Interceptor contract (per AgentCore Gateway docs / CDK LambdaInterceptor):
  event  = {"mcp": {"gatewayRequest": {...}}}   for REQUEST
           {"mcp": {"gatewayResponse": {...}}}  for RESPONSE
  return = {"interceptorOutputVersion": "1.0",
            "mcp": {"transformedGatewayRequest": {...}}}   for REQUEST
           {"interceptorOutputVersion": "1.0",
            "mcp": {"transformedGatewayResponse": {...}}}  for RESPONSE

NOTE: the exact nested shape of gatewayRequest/gatewayResponse depends on the target type and
is treated generically here (all string leaves are scanned). Validate against live Gateway
traces before relying on it in production; the guardrail logic itself is target-agnostic.

Scanned objects are size-bounded before any guardrail call: payloads over _MAX_BYTES,
_MAX_DEPTH or _MAX_STRINGS are refused with the blocked response, and in-limit string leaves
are scanned together in chunks of at most _MAX_CHUNK_CHARS. Any scan failure (throttle,
timeout, exhausted time budget, unexpected error) is also a block, never a Lambda error.
"""

import json
import logging
import os
import time

import boto3
from botocore.config import Config

logger = logging.getLogger()
logger.setLevel(logging.INFO)

_GUARDRAIL_ID = os.environ.get("GUARDRAIL_ID", "")
_GUARDRAIL_VERSION = os.environ.get("GUARDRAIL_VERSION", "DRAFT")
_OUTPUT_VERSION = "1.0"

_MAX_BYTES = 32768
_MAX_DEPTH = 32
_MAX_STRINGS = 64
_MAX_CHUNK_CHARS = 8000

_CONNECT_TIMEOUT_S = 2
_READ_TIMEOUT_S = 5
# No guardrail call starts unless one full call can still finish inside the Lambda timeout.
_CALL_RESERVE_S = _CONNECT_TIMEOUT_S + _READ_TIMEOUT_S + 1
_DEFAULT_BUDGET_S = 30

_bedrock = boto3.client(
    "bedrock-runtime",
    config=Config(
        connect_timeout=_CONNECT_TIMEOUT_S,
        read_timeout=_READ_TIMEOUT_S,
        retries={"max_attempts": 1, "mode": "standard"},
    ),
)


class GuardrailBlocked(Exception):
    """Raised when the guardrail hard-blocks content (e.g. prompt injection, blocked PII)."""


class PayloadRejected(GuardrailBlocked):
    """Raised when a payload exceeds the scan bounds and is refused without scanning."""


def _check_bounds(node) -> None:
    """Refuse oversized payloads before scanning. Iterative, so deep nesting cannot overflow."""
    strings = 0
    visited = 0
    stack = [(node, 1)]
    while stack:
        current, depth = stack.pop()
        visited += 1
        # Every JSON value serializes to at least one byte, so this also caps the walk.
        if visited > _MAX_BYTES:
            raise PayloadRejected(f"payload exceeds {_MAX_BYTES} bytes")
        if isinstance(current, str):
            strings += 1
            if strings > _MAX_STRINGS:
                raise PayloadRejected(f"payload exceeds {_MAX_STRINGS} strings")
            continue
        if isinstance(current, dict):
            children = current.values()
        elif isinstance(current, list):
            children = current
        else:
            continue
        if depth > _MAX_DEPTH:
            raise PayloadRejected(f"payload nesting exceeds depth {_MAX_DEPTH}")
        stack.extend((child, depth + 1) for child in children)

    if len(json.dumps(node).encode("utf-8")) > _MAX_BYTES:
        raise PayloadRejected(f"payload exceeds {_MAX_BYTES} bytes")


def _string_leaves(node) -> list:
    if isinstance(node, dict):
        return [leaf for v in node.values() for leaf in _string_leaves(v)]
    if isinstance(node, list):
        return [leaf for v in node for leaf in _string_leaves(v)]
    if isinstance(node, str):
        return [node]
    return []


def _replace_leaves(node, replacements):
    if isinstance(node, dict):
        return {k: _replace_leaves(v, replacements) for k, v in node.items()}
    if isinstance(node, list):
        return [_replace_leaves(v, replacements) for v in node]
    if isinstance(node, str):
        return next(replacements)
    return node


def _raise_if_hard_blocked(resp) -> None:
    """Distinguish hard-block (deny) from anonymize (mask)."""
    for assessment in resp.get("assessments", []):
        # Prompt-attack / content filter blocks
        for f in assessment.get("contentPolicy", {}).get("filters", []):
            if f.get("action") == "BLOCKED":
                raise GuardrailBlocked(f"content filter {f.get('type')} blocked")
        # PII configured with BLOCK
        sens = assessment.get("sensitiveInformationPolicy", {})
        for pii in sens.get("piiEntities", []):
            if pii.get("action") == "BLOCKED":
                raise GuardrailBlocked(f"PII {pii.get('type')} blocked")


def _apply_guardrail(texts: list, source: str, deadline: float) -> list:
    """Run the guardrail once over a chunk of text segments. Returns the (masked) segments.

    source is "INPUT" (REQUEST) or "OUTPUT" (RESPONSE). Raises GuardrailBlocked on a deny.
    """
    if time.monotonic() > deadline:
        raise GuardrailBlocked("guardrail scan time budget exhausted")

    resp = _bedrock.apply_guardrail(
        guardrailIdentifier=_GUARDRAIL_ID,
        guardrailVersion=_GUARDRAIL_VERSION,
        source=source,
        content=[{"text": {"text": t}} for t in texts],
    )

    if resp.get("action") != "GUARDRAIL_INTERVENED":
        return texts

    _raise_if_hard_blocked(resp)

    # Otherwise it intervened by anonymizing — use the masked output text if present.
    outputs = resp.get("outputs") or []
    if len(outputs) == len(texts) and all(o.get("text") is not None for o in outputs):
        return [o["text"] for o in outputs]
    if len(texts) == 1:
        if outputs and outputs[0].get("text"):
            return [outputs[0]["text"]]
        return texts
    # Masked outputs cannot be mapped back to segments; rescan them one by one. This is
    # bounded by _MAX_STRINGS plus the chunk split count, and by the deadline.
    return [_apply_guardrail([t], source, deadline)[0] for t in texts]


def _scan_leaves(leaves: list, source: str, deadline: float) -> list:
    """Scan non-empty leaves in chunks of at most _MAX_CHUNK_CHARS. Returns masked leaves."""
    segments = []  # (leaf index, text piece)
    for index, leaf in enumerate(leaves):
        if not leaf.strip():
            continue
        for start in range(0, len(leaf), _MAX_CHUNK_CHARS):
            segments.append((index, leaf[start : start + _MAX_CHUNK_CHARS]))

    chunks, current, size = [], [], 0
    for segment in segments:
        if current and size + len(segment[1]) > _MAX_CHUNK_CHARS:
            chunks.append(current)
            current, size = [], 0
        current.append(segment)
        size += len(segment[1])
    if current:
        chunks.append(current)

    pieces = {}
    for chunk in chunks:
        masked = _apply_guardrail([text for _, text in chunk], source, deadline)
        for (index, _), text in zip(chunk, masked):
            pieces.setdefault(index, []).append(text)

    return [
        "".join(pieces[i]) if i in pieces else leaf for i, leaf in enumerate(leaves)
    ]


def _mask_tree(node, source: str, deadline: float):
    """Apply the guardrail to every string leaf in a bounded request/response object."""
    _check_bounds(node)
    if not _GUARDRAIL_ID:
        return node
    masked = _scan_leaves(_string_leaves(node), source, deadline)
    return _replace_leaves(node, iter(masked))


def _deadline(context) -> float:
    budget_s = _DEFAULT_BUDGET_S
    get_remaining = getattr(context, "get_remaining_time_in_millis", None)
    if callable(get_remaining):
        budget_s = get_remaining() / 1000
    return time.monotonic() + budget_s - _CALL_RESERVE_S


def _event_preview(event) -> str:
    try:
        return json.dumps(event)[:2000]
    except (RecursionError, TypeError, ValueError):
        return "<unserializable event>"


def _blocked_response(point: str, reason: str):
    """Return a safe, guardrail-blocked payload instead of the real request/response."""
    logger.warning("egress guardrail blocked (%s): %s", point, reason)
    key = (
        "transformedGatewayRequest"
        if point == "REQUEST"
        else "transformedGatewayResponse"
    )
    blocked = {"content": [{"type": "text", "text": "Blocked by egress guardrail."}]}
    return {"interceptorOutputVersion": _OUTPUT_VERSION, "mcp": {key: blocked}}


def _scan(node, point: str, source: str, deadline: float):
    """Return (masked object, None), or (None, block reason)."""
    try:
        return _mask_tree(node, source, deadline), None
    except GuardrailBlocked as exc:
        return None, str(exc)
    # Fail closed: throttles, timeouts, recursion and malformed responses are all blocks.
    except Exception as exc:
        logger.exception("egress guardrail scan failed (%s)", point)
        return None, f"scan failed: {type(exc).__name__}"


def handler(event, context):
    logger.info("interceptor event: %s", _event_preview(event))
    mcp = event.get("mcp", {}) or {}
    deadline = _deadline(context)

    if "gatewayRequest" in mcp:
        transformed, reason = _scan(mcp["gatewayRequest"], "REQUEST", "INPUT", deadline)
        if reason is not None:
            return _blocked_response("REQUEST", reason)
        return {
            "interceptorOutputVersion": _OUTPUT_VERSION,
            "mcp": {"transformedGatewayRequest": transformed},
        }

    if "gatewayResponse" in mcp:
        transformed, reason = _scan(
            mcp["gatewayResponse"], "RESPONSE", "OUTPUT", deadline
        )
        if reason is not None:
            return _blocked_response("RESPONSE", reason)
        return {
            "interceptorOutputVersion": _OUTPUT_VERSION,
            "mcp": {"transformedGatewayResponse": transformed},
        }

    # Unknown interception payload — pass through unchanged.
    logger.info("no gatewayRequest/gatewayResponse in event; passing through")
    return {"interceptorOutputVersion": _OUTPUT_VERSION, "mcp": mcp}
