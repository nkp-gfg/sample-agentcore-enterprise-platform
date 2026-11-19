"""Gateway response interception must redact the tool result.

AgentCore invokes one Lambda for both interception points. A response event
carries the original gateway request and the gateway response together. The
gateway sends the caller whatever object is returned as
``transformedGatewayResponse``; that is the only documented substitute for the
target result. These tests call the interceptor handler with that payload and
fail while the handler treats the event as a request.

They are expected to fail until the handler scans ``gatewayResponse`` with
source ``OUTPUT`` and returns that object as ``transformedGatewayResponse``.

Run:
    python -m pytest tests/test_egress_response_redaction.py -q
"""

import importlib.util
import json
import os
import re
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
HANDLER_PATH = REPO / "tools" / "egress_interceptor" / "handler.py"
POLICY_PATH = REPO / "control-library" / "guardrails" / "egress-default.json"

# Placeholder identifier. The deployed function reads GUARDRAIL_ID from its
# environment; an empty value makes _apply_guardrail return the input unchanged.
os.environ["GUARDRAIL_ID"] = "test-guardrail"
os.environ["GUARDRAIL_VERSION"] = "DRAFT"
os.environ["AWS_DEFAULT_REGION"] = "us-east-1"
os.environ["AWS_EC2_METADATA_DISABLED"] = "true"

_spec = importlib.util.spec_from_file_location("egress_interceptor_handler", HANDLER_PATH)
handler_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(handler_mod)

# Stable stand-ins for the entity types the shipped guardrail config names.
# Bedrock classifies the text; this stand-in only recognizes these literals so
# the handler's own BLOCKED-versus-anonymize parsing is what the test runs.
CARD_NUMBER = "4111111111111111"
NATIONAL_ID = "000-00-0000"
EMAIL = "ada@example.com"
PHONE = "555-010-0199"
ORDER_MARKER = "order shipped"

_PATTERNS = {
    "CREDIT_DEBIT_CARD_NUMBER": re.compile(rf"\b{CARD_NUMBER}\b"),
    "US_SOCIAL_SECURITY_NUMBER": re.compile(rf"\b{re.escape(NATIONAL_ID)}\b"),
    "EMAIL": re.compile(r"\b[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}\b"),
    "PHONE": re.compile(rf"\b{re.escape(PHONE)}\b"),
}


def _policy_actions():
    policy = json.loads(POLICY_PATH.read_text())
    return {
        entity["Type"]: entity["Action"]
        for entity in policy["SensitiveInformationPolicyConfig"]["PiiEntitiesConfig"]
    }


def _apply_guardrail_response(text, source):
    """Build an ApplyGuardrail response in the shape botocore 1.44.7 models.

    Action values are the API enums (BLOCKED, ANONYMIZED, NONE), chosen from
    the Action on each PII entity in the shipped guardrail document. The
    handler reads ``action``, ``assessments[].sensitiveInformationPolicy
    .piiEntities[].action``, and ``outputs[0].text``.
    """
    actions = _policy_actions()
    detected = []
    for entity_type, pattern in _PATTERNS.items():
        if pattern.search(text):
            detected.append(entity_type)

    if not detected:
        return {"action": "NONE", "outputs": [{"text": text}], "assessments": []}

    blocked = [entity for entity in detected if actions[entity] == "BLOCK"]
    if blocked:
        return {
            "action": "GUARDRAIL_INTERVENED",
            "outputs": [{"text": text}],
            "assessments": [
                {
                    "sensitiveInformationPolicy": {
                        "piiEntities": [
                            {"match": text, "type": blocked[0], "action": "BLOCKED"}
                        ],
                        "regexes": [],
                    }
                }
            ],
        }

    masked = text
    entities = []
    for entity_type in detected:
        if actions[entity_type] != "ANONYMIZE":
            continue
        masked = _PATTERNS[entity_type].sub("{" + entity_type + "}", masked)
        entities.append({"match": text, "type": entity_type, "action": "ANONYMIZED"})
    return {
        "action": "GUARDRAIL_INTERVENED",
        "outputs": [{"text": masked}],
        "assessments": [
            {
                "sensitiveInformationPolicy": {
                    "piiEntities": entities,
                    "regexes": [],
                }
            }
        ],
    }


class _GuardrailClient:
    def __init__(self):
        self.calls = []

    def apply_guardrail(self, **kwargs):
        self.calls.append(kwargs)
        text = kwargs["content"][0]["text"]["text"]
        return _apply_guardrail_response(text, kwargs["source"])


@pytest.fixture
def guardrail():
    client = _GuardrailClient()
    handler_mod._bedrock = client
    yield client
    handler_mod._bedrock = client


def _response_event(result_text, *, streaming=False):
    """Response-interceptor input from the AgentCore MCP interceptor contract.

    The documented response payload includes gatewayRequest and gatewayResponse.
    Request headers are omitted because this gateway sets passRequestHeaders
    to false. The sensitive value is only in the tool result.
    """
    gateway_response = {
        "statusCode": 200,
        "headers": {"Mcp-Session-Id": "session-1"},
        "body": {
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "content": [{"type": "text", "text": result_text}],
            },
        },
    }
    if streaming:
        gateway_response["isStreamingResponse"] = True
    return {
        "interceptorInputVersion": "1.0",
        "mcp": {
            "rawGatewayRequest": {"body": "{}"},
            "gatewayRequest": {
                "path": "/mcp",
                "httpMethod": "POST",
                "body": {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "tools/call",
                    "params": {
                        "name": "web-search",
                        "arguments": {"query": "order status"},
                    },
                },
            },
            "gatewayResponse": gateway_response,
        },
    }


def _request_event(argument_text):
    """Request-interceptor input: gatewayResponse is absent."""
    return {
        "interceptorInputVersion": "1.0",
        "mcp": {
            "gatewayRequest": {
                "path": "/mcp",
                "httpMethod": "POST",
                "body": {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "tools/call",
                    "params": {
                        "name": "web-search",
                        "arguments": {"query": argument_text},
                    },
                },
            }
        },
    }


def caller_visible_response(event, interceptor_output):
    """Body the gateway returns to the caller.

    The response-interceptor contract says that when the output contains
    transformedGatewayResponse, the gateway responds with that content even if
    transformedGatewayRequest is also present. The target result is already in
    gatewayResponse when the interceptor is invoked. With no transformed
    response to substitute, that target result is the body that remains.
    """
    produced = (interceptor_output.get("mcp") or {}).get("transformedGatewayResponse")
    if produced is not None:
        return produced
    return event["mcp"]["gatewayResponse"]


def _scanned(guardrail, text, source):
    return [
        call
        for call in guardrail.calls
        if call["source"] == source and call["content"][0]["text"]["text"] == text
    ]


def test_shipped_guardrail_blocks_ids_and_anonymizes_contact():
    actions = _policy_actions()
    assert actions["CREDIT_DEBIT_CARD_NUMBER"] == "BLOCK"
    assert actions["US_SOCIAL_SECURITY_NUMBER"] == "BLOCK"
    assert actions["EMAIL"] == "ANONYMIZE"
    assert actions["PHONE"] == "ANONYMIZE"
    assert actions["NAME"] == "ANONYMIZE"
    assert actions["ADDRESS"] == "ANONYMIZE"


@pytest.mark.parametrize(
    "result_text,secret,mask",
    [
        (f"{ORDER_MARKER}; contact {EMAIL}", EMAIL, "{EMAIL}"),
        (f"{ORDER_MARKER}; phone {PHONE}", PHONE, "{PHONE}"),
    ],
)
def test_response_event_anonymizes_contact_data(guardrail, result_text, secret, mask):
    event = _response_event(result_text)
    result = handler_mod.handler(event, None)

    visible = caller_visible_response(event, result)
    rendered = json.dumps(visible)
    assert result["interceptorOutputVersion"] == "1.0"
    assert "transformedGatewayResponse" in result["mcp"]
    assert secret not in rendered
    assert secret not in json.dumps(result)
    assert mask in rendered
    assert ORDER_MARKER in rendered
    # The object returned to the caller is the tool response, not the request.
    assert visible["body"]["result"]["content"][0]["text"].startswith(ORDER_MARKER)
    assert _scanned(guardrail, result_text, "OUTPUT")
    assert not _scanned(guardrail, result_text, "INPUT")


@pytest.mark.parametrize(
    "secret",
    [CARD_NUMBER, NATIONAL_ID],
)
def test_response_event_blocks_card_and_national_id(guardrail, secret):
    result_text = f"{ORDER_MARKER}; id {secret}"
    event = _response_event(result_text)
    result = handler_mod.handler(event, None)

    visible = caller_visible_response(event, result)
    assert result["mcp"]["transformedGatewayResponse"] == {
        "content": [{"type": "text", "text": "Blocked by egress guardrail."}]
    }
    assert secret not in json.dumps(visible)
    assert secret not in json.dumps(result)
    assert "transformedGatewayRequest" not in result["mcp"]
    assert _scanned(guardrail, result_text, "OUTPUT")
    assert not _scanned(guardrail, result_text, "INPUT")


def test_streaming_response_event_anonymizes_the_event_body(guardrail):
    result_text = f"{ORDER_MARKER}; contact {EMAIL}"
    event = _response_event(result_text, streaming=True)
    result = handler_mod.handler(event, None)

    visible = caller_visible_response(event, result)
    assert visible["isStreamingResponse"] is True
    assert EMAIL not in json.dumps(visible)
    assert "{EMAIL}" in json.dumps(visible)
    assert _scanned(guardrail, result_text, "OUTPUT")


def test_response_redaction_ignores_a_sensitive_request_field(guardrail):
    """A response event's request field is not the object the caller receives.

    The request carries a different email than the tool result. Scanning the
    request and returning it must not satisfy the assertion on the response.
    """
    event = _response_event(f"{ORDER_MARKER}; contact {EMAIL}")
    event["mcp"]["gatewayRequest"]["body"]["params"]["arguments"]["query"] = (
        "other@example.com"
    )
    result = handler_mod.handler(event, None)

    visible = caller_visible_response(event, result)
    tool_text = visible["body"]["result"]["content"][0]["text"]
    assert tool_text == f"{ORDER_MARKER}; contact {{EMAIL}}"
    assert "other@example.com" not in tool_text
    assert _scanned(guardrail, f"{ORDER_MARKER}; contact {EMAIL}", "OUTPUT")


def test_request_only_event_still_masks_input(guardrail):
    argument = f"reach me at {EMAIL}"
    event = _request_event(argument)
    result = handler_mod.handler(event, None)

    assert "transformedGatewayResponse" not in result["mcp"]
    query = result["mcp"]["transformedGatewayRequest"]["body"]["params"]["arguments"]["query"]
    assert query == "reach me at {EMAIL}"
    assert EMAIL not in query
    assert _scanned(guardrail, argument, "INPUT")
