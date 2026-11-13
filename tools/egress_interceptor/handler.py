# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""AgentCore Gateway egress interceptor.

Applies a Bedrock Guardrail to Gateway traffic for defense-in-depth egress control:
  - REQUEST  interception point: guardrail runs with source=INPUT before the target is called
    (blocks prompt-injection, masks PII leaving the agent toward the tool/target).
  - RESPONSE interception point: guardrail runs with source=OUTPUT before the response returns
    to the caller (masks PII coming back from the target).

Interceptor contract (AgentCore Gateway, MCP targets):
  REQUEST  event: {"mcp": {"gatewayRequest": {"path", "httpMethod", "body"}, "gatewayResponse": null}}
  RESPONSE event: the same, plus "gatewayResponse": {"statusCode", "headers", "body"}
  REQUEST  output: {"mcp": {"transformedGatewayRequest": {"body": ...}}}
  RESPONSE output: {"mcp": {"transformedGatewayResponse": {"statusCode", "headers", "body"}}}
  Either point may return transformedGatewayResponse to answer the caller immediately.

Only tools/call is scanned: its arguments are what leaves toward a target and its
result is what a target sends back. Protocol traffic (initialize, tools/list) passes
through untouched; scanning it would rewrite JSON-RPC fields and cost one guardrail
call per schema string.
"""

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


def _apply_guardrail(text: str, source: str) -> str:
    """Run the guardrail over one text value. Returns masked text, or raises GuardrailBlocked.

    source is "INPUT" (REQUEST) or "OUTPUT" (RESPONSE).
    """
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


def _mask_tree(node, source: str):
    """Recursively apply the guardrail to every string leaf in a request/response object."""
    if isinstance(node, dict):
        return {k: _mask_tree(v, source) for k, v in node.items()}
    if isinstance(node, list):
        return [_mask_tree(v, source) for v in node]
    if isinstance(node, str):
        return _apply_guardrail(node, source)
    return node


def _output(**mcp):
    return {"interceptorOutputVersion": _OUTPUT_VERSION, "mcp": mcp}


def _blocked_response(point: str, reason: str, request_body: dict):
    """Answer the caller with a JSON-RPC tool error instead of the real request/response."""
    logger.warning("egress guardrail blocked (%s): %s", point, reason)
    return _output(
        transformedGatewayResponse={
            "statusCode": 200,
            "body": {
                "jsonrpc": "2.0",
                "id": request_body.get("id"),
                "result": {
                    "content": [{"type": "text", "text": "Blocked by egress guardrail."}],
                    "isError": True,
                },
            },
        }
    )


def _on_request(request_body: dict):
    body = dict(request_body)
    if body.get("method") == "tools/call":
        params = dict(body.get("params") or {})
        if "arguments" in params:
            params["arguments"] = _mask_tree(params["arguments"], "INPUT")
        body["params"] = params
    return _output(transformedGatewayRequest={"body": body})


def _on_response(request_body: dict, response: dict):
    body = response.get("body")
    if request_body.get("method") == "tools/call" and isinstance(body, dict) and "result" in body:
        body = {**body, "result": _mask_tree(body["result"], "OUTPUT")}
    transformed = {"body": body}
    # Streaming follow-up events carry only a body; status and headers are already sent.
    for key in ("statusCode", "headers"):
        if key in response:
            transformed[key] = response[key]
    return _output(transformedGatewayResponse=transformed)


def handler(event, context):
    mcp = event.get("mcp") or {}
    request_body = (mcp.get("gatewayRequest") or {}).get("body") or {}
    response = mcp.get("gatewayResponse")
    point = "REQUEST" if response is None else "RESPONSE"
    logger.info("interceptor %s method=%s", point, request_body.get("method"))

    try:
        if response is None:
            return _on_request(request_body)
        return _on_response(request_body, response)
    except GuardrailBlocked as exc:
        return _blocked_response(point, str(exc), request_body)
