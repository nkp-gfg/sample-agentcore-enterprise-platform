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
           {"mcp": {"gatewayResponse": {...}}}  for RESPONSE (may also carry gatewayRequest)
  return = {"interceptorOutputVersion": "1.0",
            "mcp": {"transformedGatewayRequest": {...}}}   for REQUEST
           {"interceptorOutputVersion": "1.0",
            "mcp": {"transformedGatewayResponse": {...}}}  for RESPONSE

NOTE: the exact nested shape of gatewayRequest/gatewayResponse depends on the target type and
is treated generically here: the whole payload (keys, strings and non-string scalars) is
serialized to one JSON text and scanned in a single ApplyGuardrail call per direction, so a
value split across fields, or carried in a number or key, is evaluated as a whole. Validate
against live Gateway traces before relying on it in production; the guardrail logic itself is
target-agnostic.
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

# Upper bound on the serialized payload sent to the guardrail; larger payloads are refused
# unscanned so one call cannot be used to exhaust the Lambda or the guardrail quota.
MAX_SCAN_CHARS = 100_000

_bedrock = boto3.client("bedrock-runtime")


class GuardrailBlocked(Exception):
    """Raised when the guardrail hard-blocks content (e.g. prompt injection, blocked PII)."""


def _apply_guardrail(text: str, source: str) -> str:
    """Run the guardrail over one text value. Returns masked text, or raises GuardrailBlocked.

    source is "INPUT" (REQUEST) or "OUTPUT" (RESPONSE).
    """
    if not text.strip():
        return text

    resp = _bedrock.apply_guardrail(
        guardrailIdentifier=_GUARDRAIL_ID,
        guardrailVersion=_GUARDRAIL_VERSION,
        source=source,
        content=[{"text": {"text": text}}],
    )

    if resp.get("action") != "GUARDRAIL_INTERVENED":
        return text

    # Distinguish hard-block (deny) from anonymize (mask).
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

    # Otherwise it intervened by anonymizing — use the masked output text if present.
    outputs = resp.get("outputs") or []
    if outputs and outputs[0].get("text"):
        return outputs[0]["text"]
    return text


def _same_shape(original, masked) -> bool:
    """True if masking only rewrote string contents (including keys), never the structure."""
    if isinstance(original, dict):
        return (
            isinstance(masked, dict)
            and len(masked) == len(original)
            and all(
                _same_shape(a, b) for a, b in zip(original.values(), masked.values())
            )
        )
    if isinstance(original, list):
        return (
            isinstance(masked, list)
            and len(masked) == len(original)
            and all(_same_shape(a, b) for a, b in zip(original, masked))
        )
    if isinstance(original, str):
        return isinstance(masked, str)
    return type(masked) is type(original) and masked == original


def _guard_tree(node, source: str):
    """Scan a whole request/response as one text and return it, masked if the guardrail
    anonymized anything. Raises GuardrailBlocked on a block or anything it cannot scan."""
    if not _GUARDRAIL_ID:
        return node

    try:
        text = json.dumps(node, ensure_ascii=False)
    except (TypeError, ValueError, RecursionError) as exc:
        raise GuardrailBlocked(
            f"payload not serializable for scanning: {exc}"
        ) from None
    if len(text) > MAX_SCAN_CHARS:
        raise GuardrailBlocked(
            f"payload of {len(text)} chars exceeds scan cap of {MAX_SCAN_CHARS}"
        )

    masked_text = _apply_guardrail(text, source)
    if masked_text == text:
        return node

    try:
        masked = json.loads(masked_text)
    except (ValueError, RecursionError):
        raise GuardrailBlocked("masked payload is not valid JSON") from None
    if not _same_shape(node, masked):
        raise GuardrailBlocked("masking changed the payload structure")
    return masked


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


def handler(event, context):
    logger.info("interceptor event: %s", json.dumps(event)[:2000])
    mcp = event.get("mcp", {}) or {}

    # RESPONSE events can carry the originating gatewayRequest too, so check this first.
    if "gatewayResponse" in mcp:
        try:
            transformed = _guard_tree(mcp["gatewayResponse"], "OUTPUT")
        except GuardrailBlocked as exc:
            return _blocked_response("RESPONSE", str(exc))
        return {
            "interceptorOutputVersion": _OUTPUT_VERSION,
            "mcp": {"transformedGatewayResponse": transformed},
        }

    if "gatewayRequest" in mcp:
        try:
            transformed = _guard_tree(mcp["gatewayRequest"], "INPUT")
        except GuardrailBlocked as exc:
            return _blocked_response("REQUEST", str(exc))
        return {
            "interceptorOutputVersion": _OUTPUT_VERSION,
            "mcp": {"transformedGatewayRequest": transformed},
        }

    # Unknown interception payload — pass through unchanged.
    logger.info("no gatewayRequest/gatewayResponse in event; passing through")
    return {"interceptorOutputVersion": _OUTPUT_VERSION, "mcp": mcp}
