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

HR identity promotion (phase H4 of the HR plan, custom-app-plan/phases.md § H4):

When `HR_IDENTITY_PROMOTION=1` is set on the interceptor function AND the
gateway is configured with `PassRequestHeaders: true`, the REQUEST pass (after
the guardrail scan) looks at the forwarded headers, decodes the gateway-
validated JWT without reverifying it (the gateway already did), and writes
`caller_employee_id`, `agent_id`, and `session_id` onto the tool arguments,
OVERWRITING whatever the model sent. The identity promotion only fires on
HR gateway targets (`hr-ops`, `hr-payroll`, `hr-finance`), so unrelated
gateway targets are unaffected even with the header pass-through on.

docs/hr/tools.md § Identity on the call is the source of truth.
"""

import base64
import binascii
import json
import logging
import os

import boto3

logger = logging.getLogger()
logger.setLevel(logging.INFO)

_GUARDRAIL_ID = os.environ.get("GUARDRAIL_ID", "")
_GUARDRAIL_VERSION = os.environ.get("GUARDRAIL_VERSION", "DRAFT")
_OUTPUT_VERSION = "1.0"

# docs/hr/tools.md § Routing names three HR gateway targets. Identity
# promotion only runs for these; every other gateway target sees the
# unmodified request body.
_HR_TARGET_PREFIXES = ("hr-ops___", "hr-payroll___", "hr-finance___")

_bedrock = boto3.client("bedrock-runtime")


class GuardrailBlocked(Exception):
    """Raised when the guardrail hard-blocks content (e.g. prompt injection, blocked PII)."""


class GuardrailUnavailable(Exception):
    """Raised when the Bedrock Guardrail call fails so the interceptor fails closed."""


def _apply_guardrail(text: str, source: str) -> str:
    """Run the guardrail over one text value. Returns masked text, or raises GuardrailBlocked.

    source is "INPUT" (REQUEST) or "OUTPUT" (RESPONSE).
    """
    if not text.strip() or not _GUARDRAIL_ID:
        return text

    try:
        resp = _bedrock.apply_guardrail(
            guardrailIdentifier=_GUARDRAIL_ID,
            guardrailVersion=_GUARDRAIL_VERSION,
            source=source,
            content=[{"text": {"text": text}}],
        )
    except Exception as exc:
        logger.exception("apply_guardrail failed (%s)", source)
        raise GuardrailUnavailable("egress guardrail unavailable") from exc

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
                    "content": [
                        {"type": "text", "text": "Blocked by egress guardrail."}
                    ],
                    "isError": True,
                },
            },
        }
    )


def _identity_promotion_enabled() -> bool:
    """docs/hr/tools.md § Identity on the call: the HR flag is read from
    an env var set by `stacks/gateway_stack.py` whenever hr-tools is in
    the use_cases block. Default off."""
    return os.environ.get("HR_IDENTITY_PROMOTION", "") == "1"


def _is_hr_tool(name) -> bool:
    return isinstance(name, str) and name.startswith(_HR_TARGET_PREFIXES)


def _header(headers, name: str):
    """Headers are case-insensitive. Normalise to the lowercase name once."""
    if not isinstance(headers, dict):
        return None
    lower = name.lower()
    for key, value in headers.items():
        if isinstance(key, str) and key.lower() == lower:
            return value
    return None


def _decode_jwt_claims(token: str) -> dict:
    """Base64-decode the JWT middle segment WITHOUT signature verification.

    The gateway has already validated the signature, the issuer, and the
    audience (that is what the CUSTOM_JWT authorizer does). Re-verifying
    here would be a second call to the IdP's JWKS endpoint per request,
    which is exactly the latency the gateway's cache exists to avoid.

    A malformed token returns {}; the Lambda layer then refuses with
    NOT_MAPPED because `caller_employee_id` is missing.
    """
    try:
        _header_b64, payload_b64, _signature_b64 = token.split(".")
    except ValueError:
        return {}
    pad = "=" * (-len(payload_b64) % 4)
    try:
        raw = base64.urlsafe_b64decode(payload_b64 + pad)
        claims = json.loads(raw)
    except (binascii.Error, ValueError, UnicodeDecodeError):
        return {}
    return claims if isinstance(claims, dict) else {}


def _promote_identity(params: dict, headers) -> dict:
    """Overwrite caller_employee_id, agent_id, and session_id on the
    tool arguments with the values the gateway already validated.

    docs/hr/tools.md § Identity on the call pins the contract: the
    Lambda trusts these three fields only because the interceptor
    overwrote them. The model MUST NOT be able to spoof them.
    """
    auth = _header(headers, "Authorization") or _header(headers, "authorization") or ""
    scheme, _, token = auth.partition(" ")
    claims: dict = {}
    if scheme.lower() == "bearer" and token:
        claims = _decode_jwt_claims(token)

    arguments = params.get("arguments")
    if not isinstance(arguments, dict):
        arguments = {}

    new_arguments = dict(arguments)
    # An empty string is the correct "no value" signal downstream —
    # the Lambda then raises NotMapped and refuses NOT_MAPPED. Keeping
    # a None could sneak through a `.get()` default upstream.
    new_arguments["caller_employee_id"] = str(claims.get("employee_id") or "")
    new_arguments["agent_id"] = str(claims.get("agent_id") or "")
    new_arguments["session_id"] = str(
        _header(headers, "Mcp-Session-Id")
        or _header(headers, "runtimeSessionId")
        or claims.get("runtimeSessionId")
        or ""
    )

    new_params = dict(params)
    new_params["arguments"] = new_arguments
    return new_params


def _on_request(request_body: dict, event_headers=None):
    body = dict(request_body)
    if body.get("method") == "tools/call":
        params = dict(body.get("params") or {})
        if "arguments" in params:
            params["arguments"] = _mask_tree(params["arguments"], "INPUT")
        # HR identity promotion runs AFTER the guardrail scan so the
        # masking never touches the token-derived fields. Only HR
        # targets are affected; everything else keeps the arguments
        # the model sent verbatim (minus any guardrail anonymisation).
        if _identity_promotion_enabled() and _is_hr_tool(params.get("name")):
            params = _promote_identity(params, event_headers)
        body["params"] = params
    return _output(transformedGatewayRequest={"body": body})


def _on_response(request_body: dict, response: dict):
    body = response.get("body")
    if (
        request_body.get("method") == "tools/call"
        and isinstance(body, dict)
        and "result" in body
    ):
        body = {**body, "result": _mask_tree(body["result"], "OUTPUT")}
    transformed = {"body": body}
    # Streaming follow-up events carry only a body; status and headers are already sent.
    for key in ("statusCode", "headers"):
        if key in response:
            transformed[key] = response[key]
    return _output(transformedGatewayResponse=transformed)


def handler(event, context):
    mcp = event.get("mcp") or {}
    gateway_request = mcp.get("gatewayRequest") or {}
    request_body = gateway_request.get("body") or {}
    # Only present when the gateway was configured with
    # PassRequestHeaders: true. The HR identity-promotion path is the
    # one caller that reads this; every other code path leaves them
    # untouched.
    request_headers = gateway_request.get("headers") or {}
    response = mcp.get("gatewayResponse")
    point = "REQUEST" if response is None else "RESPONSE"
    logger.info("interceptor %s method=%s", point, request_body.get("method"))

    try:
        if response is None:
            return _on_request(request_body, request_headers)
        return _on_response(request_body, response)
    except GuardrailBlocked as exc:
        return _blocked_response(point, str(exc), request_body)
    except GuardrailUnavailable:
        logger.error("egress guardrail unavailable (%s); failing closed", point)
        return _output(
            transformedGatewayResponse={
                "statusCode": 200,
                "body": {
                    "jsonrpc": "2.0",
                    "id": request_body.get("id"),
                    "result": {
                        "content": [
                            {"type": "text", "text": "Egress guardrail unavailable."}
                        ],
                        "isError": True,
                    },
                },
            }
        )
