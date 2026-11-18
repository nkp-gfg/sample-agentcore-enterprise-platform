# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""AgentCore Gateway egress interceptor.

Applies a Bedrock Guardrail to Gateway traffic for defense-in-depth egress control:
  - REQUEST  interception point: guardrail runs with source=INPUT before the target is called
    (blocks prompt-injection, masks PII leaving the agent toward the tool/target).
  - RESPONSE interception point: guardrail also runs with source=INPUT before the response
    returns to the caller. Tool results are untrusted content headed into the agent's
    context, and the PROMPT_ATTACK filter only evaluates INPUT (its output strength must be
    NONE), so scanning them as OUTPUT would skip prompt-injection detection entirely.

An intervention that returns no replacement text is treated as a block (fail closed), so
the original text is never passed through after the guardrail flagged it.

Interceptor contract (per AgentCore Gateway docs / CDK LambdaInterceptor):
  event  = {"mcp": {"gatewayRequest": {...}}}                         for REQUEST
           {"mcp": {"gatewayRequest": {...}, "gatewayResponse": {...}}} for RESPONSE
  return = {"interceptorOutputVersion": "1.0",
            "mcp": {"transformedGatewayRequest": {...}}}   for REQUEST
           {"interceptorOutputVersion": "1.0",
            "mcp": {"transformedGatewayResponse": {...}}}  for RESPONSE
  A transformedGatewayResponse makes the gateway answer with it immediately; fields it omits
  fall back to the original values, so a blocked response must always carry its own body.

NOTE: the exact nested shape of gatewayRequest/gatewayResponse depends on the target type and
is treated generically here (all string leaves are scanned). Validate against live Gateway
traces before relying on it in production; the guardrail logic itself is target-agnostic.
"""

import json
import logging
import os

import boto3

logger = logging.getLogger()
logger.setLevel(logging.INFO)

_GUARDRAIL_ID = os.environ.get("GUARDRAIL_ID", "")
_GUARDRAIL_VERSION = os.environ.get("GUARDRAIL_VERSION", "DRAFT")
_OUTPUT_VERSION = "1.0"

_bedrock = boto3.client("bedrock-runtime")


class GuardrailBlocked(Exception):
    """Raised when the guardrail hard-blocks content (e.g. prompt injection, blocked PII)."""


def _blocked_finding(node):
    """Return a label for the first assessment entry with action BLOCKED, else None.

    Walks every policy (content, PII, regex, topic, word, grounding) so a block from any
    control-library policy is honoured, not just the ones the default artifact ships.
    """
    if isinstance(node, dict):
        if node.get("action") == "BLOCKED":
            return node.get("type") or node.get("name") or "policy"
        for value in node.values():
            found = _blocked_finding(value)
            if found:
                return found
    elif isinstance(node, list):
        for value in node:
            found = _blocked_finding(value)
            if found:
                return found
    return None


def _apply_guardrail(text: str, source: str) -> str:
    """Run the guardrail over one text value. Returns masked text, or raises GuardrailBlocked."""
    if not text.strip() or not _GUARDRAIL_ID:
        return text

    resp = _bedrock.apply_guardrail(
        guardrailIdentifier=_GUARDRAIL_ID,
        guardrailVersion=_GUARDRAIL_VERSION,
        source=source,
        content=[{"text": {"text": text}}],
    )

    if resp.get("action") != "GUARDRAIL_INTERVENED":
        return text

    blocked = _blocked_finding(resp.get("assessments", []))
    if blocked:
        raise GuardrailBlocked(f"{blocked} blocked")

    # Otherwise it intervened by anonymizing — use the masked output text.
    outputs = resp.get("outputs") or []
    if outputs and outputs[0].get("text"):
        return outputs[0]["text"]
    raise GuardrailBlocked("guardrail intervened without replacement text")


def _mask_tree(node, source: str, cache: dict | None = None):
    """Recursively apply the guardrail to every string key and leaf in a request/response.

    Keys are scanned too: a target controls the whole result object, not just its values.
    cache dedupes identical strings within one invocation (repeated protocol keys).
    """
    if cache is None:
        cache = {}
    if isinstance(node, dict):
        out = {}
        for k, v in node.items():
            key = _mask_tree(k, source, cache)
            if key in out:
                raise GuardrailBlocked("masked keys collide")
            out[key] = _mask_tree(v, source, cache)
        return out
    if isinstance(node, list):
        return [_mask_tree(v, source, cache) for v in node]
    if isinstance(node, str):
        if node not in cache:
            cache[node] = _apply_guardrail(node, source)
        return cache[node]
    return node


def _jsonrpc_id(mcp: dict):
    for key in ("gatewayResponse", "gatewayRequest"):
        body = (mcp.get(key) or {}).get("body")
        if isinstance(body, dict) and "id" in body:
            return body["id"]
    return None


def _blocked_response(point: str, reason: str, mcp: dict):
    """Return a safe, guardrail-blocked payload instead of the real request/response.

    Both points return a full transformedGatewayResponse (status and body), which the gateway
    sends to the caller as-is; on REQUEST that also short-circuits the target call. The
    REQUEST output additionally replaces the request body so the original is never forwarded.
    """
    logger.warning("egress guardrail blocked (%s): %s", point, reason)
    body = {
        "jsonrpc": "2.0",
        "id": _jsonrpc_id(mcp),
        "result": {
            "content": [{"type": "text", "text": "Blocked by egress guardrail."}],
            "isError": True,
        },
    }
    out = {"transformedGatewayResponse": {"statusCode": 200, "body": body}}
    if point == "REQUEST":
        out["transformedGatewayRequest"] = {"body": body}
    return {"interceptorOutputVersion": _OUTPUT_VERSION, "mcp": out}


def handler(event, context):
    logger.info("interceptor event: %s", json.dumps(event)[:2000])
    mcp = event.get("mcp", {}) or {}

    # RESPONSE events carry the original gatewayRequest too, so check for the response first.
    if "gatewayResponse" in mcp:
        try:
            transformed = _mask_tree(mcp["gatewayResponse"], "INPUT")
        except GuardrailBlocked as exc:
            return _blocked_response("RESPONSE", str(exc), mcp)
        return {
            "interceptorOutputVersion": _OUTPUT_VERSION,
            "mcp": {"transformedGatewayResponse": transformed},
        }

    if "gatewayRequest" in mcp:
        try:
            transformed = _mask_tree(mcp["gatewayRequest"], "INPUT")
        except GuardrailBlocked as exc:
            return _blocked_response("REQUEST", str(exc), mcp)
        return {
            "interceptorOutputVersion": _OUTPUT_VERSION,
            "mcp": {"transformedGatewayRequest": transformed},
        }

    # Unknown interception payload — pass through unchanged.
    logger.info("no gatewayRequest/gatewayResponse in event; passing through")
    return {"interceptorOutputVersion": _OUTPUT_VERSION, "mcp": mcp}
