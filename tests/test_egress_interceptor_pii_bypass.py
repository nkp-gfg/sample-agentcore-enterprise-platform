"""Spec for the gateway egress interceptor's card and SSN blocking.

The interceptor must stop a payment card number or US Social Security number
on the way to a tool and on the way back to the caller. These tests fail while
the handler scans each string leaf on its own and skips object keys and
non-string values.

The guardrail stand-in evaluates only the text of each ApplyGuardrail content
block. It blocks a credit card when that text's digits contain a 13 to 16
digit Luhn number, and a Social Security number when they contain the sample
nine-digit sequence below. It does not combine separate calls or blocks.
A combined scan of the whole payload, including keys and scalars, is what
makes the bypass cases trip the same rules.

Combined text longer than MAX_SCAN_CHARS must be refused without being sent
to the guardrail.
"""

import importlib.util
import json
import os
from pathlib import Path

import pytest

os.environ["AWS_DEFAULT_REGION"] = "us-east-1"
os.environ["AWS_EC2_METADATA_DISABLED"] = "true"
os.environ["GUARDRAIL_ID"] = "guardrail-under-test"
os.environ["GUARDRAIL_VERSION"] = "1"

MAX_SCAN_CHARS = 100_000

# Published test PAN (Luhn-valid, 16 digits) and the SSA's published sample SSN.
CARD = "4111111111111111"
CARD_LEFT = "41111111"
CARD_RIGHT = "11111111"
SSN_DIGITS = "219099999"
SSN_TEXT = "219-09-9999"
SSN_LEFT = "219-09"
SSN_RIGHT = "9999"

_HANDLER_PATH = (
    Path(__file__).resolve().parents[1] / "tools" / "egress_interceptor" / "handler.py"
)


def _luhn(number):
    total = 0
    double = False
    for char in reversed(number):
        digit = int(char)
        if double:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit
        double = not double
    return total % 10 == 0


def _digits(text):
    return "".join(char for char in text if char.isdigit())


def _card_in(text):
    digits = _digits(text)
    for length in (16, 15, 14, 13):
        for start in range(len(digits) - length + 1):
            if _luhn(digits[start : start + length]):
                return True
    return False


def _ssn_in(text):
    return SSN_DIGITS in _digits(text)


def _load_handler():
    spec = importlib.util.spec_from_file_location(
        "egress_interceptor_handler", _HANDLER_PATH
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def egress():
    return _load_handler()


@pytest.fixture
def guardrail(egress, monkeypatch):
    """Stand-in for bedrock-runtime ApplyGuardrail on one content list."""
    seen = []

    def apply_guardrail(
        *, guardrailIdentifier, guardrailVersion, source, content, **kwargs
    ):
        entities = []
        texts = []
        for block in content:
            text = block["text"]["text"]
            texts.append(text)
            if _card_in(text):
                entities.append(
                    {"type": "CREDIT_DEBIT_CARD_NUMBER", "action": "BLOCKED"}
                )
            if _ssn_in(text):
                entities.append(
                    {"type": "US_SOCIAL_SECURITY_NUMBER", "action": "BLOCKED"}
                )
        seen.append({"source": source, "texts": texts})
        if not entities:
            return {"action": "NONE", "assessments": [], "outputs": []}
        return {
            "action": "GUARDRAIL_INTERVENED",
            "assessments": [{"sensitiveInformationPolicy": {"piiEntities": entities}}],
            "outputs": [{"text": "blocked"}],
        }

    monkeypatch.setattr(egress._bedrock, "apply_guardrail", apply_guardrail)
    return seen


def _request_event(arguments):
    """MCP tools/call body as the REQUEST interceptor receives it."""
    return {
        "interceptorInputVersion": "1.0",
        "mcp": {
            "gatewayRequest": {
                "path": "/mcp",
                "httpMethod": "POST",
                "body": {
                    "jsonrpc": "2.0",
                    "id": "call",
                    "method": "tools/call",
                    "params": {
                        "name": "sample-tool___text_analysis_tool",
                        "arguments": arguments,
                    },
                },
            }
        },
    }


def _response_body(result):
    return {
        "statusCode": 200,
        "body": {
            "jsonrpc": "2.0",
            "id": "call",
            "result": result,
        },
    }


def _response_event(result):
    """RESPONSE interceptor event. The documented payload also carries the request."""
    event = _request_event({"text": "hello"})
    event["mcp"]["gatewayResponse"] = _response_body(result)
    return event


def _response_only_event(result):
    """Response branch with no request key, the shape that reaches that branch."""
    return {
        "interceptorInputVersion": "1.0",
        "mcp": {"gatewayResponse": _response_body(result)},
    }


def _assert_not_forwarded(result, fragments):
    assert result["interceptorOutputVersion"] == "1.0"
    encoded = json.dumps(result)
    for fragment in fragments:
        assert fragment not in encoded


def _assert_response_stopped(result, fragments):
    _assert_not_forwarded(result, fragments)
    assert "transformedGatewayResponse" in result["mcp"]


def _assert_scan_bounded(guardrail):
    assert len(guardrail) <= 1
    for call in guardrail:
        for text in call["texts"]:
            assert len(text) <= MAX_SCAN_CHARS


def test_request_forwards_text_that_is_not_card_or_ssn(egress, guardrail):
    result = egress.handler(_request_event({"text": "hello world", "N": 5}), None)
    encoded = json.dumps(result["mcp"]["transformedGatewayRequest"])
    assert "hello world" in encoded
    assert "Blocked by egress guardrail." not in encoded


def test_request_blocks_card_in_one_string(egress, guardrail):
    result = egress.handler(
        _request_event({"text": "4111 1111 1111 1111", "N": 5}), None
    )
    _assert_not_forwarded(result, ["4111 1111 1111 1111", CARD])
    assert guardrail[0]["source"] == "INPUT"


def test_request_blocks_ssn_in_one_string(egress, guardrail):
    result = egress.handler(_request_event({"text": SSN_TEXT, "N": 5}), None)
    _assert_not_forwarded(result, [SSN_TEXT, SSN_DIGITS])
    assert guardrail[0]["source"] == "INPUT"


def test_request_blocks_card_split_across_string_arguments(egress, guardrail):
    result = egress.handler(
        _request_event({"text": CARD_LEFT, "note": CARD_RIGHT}), None
    )
    _assert_not_forwarded(result, [CARD, CARD_LEFT, CARD_RIGHT])


def test_request_blocks_ssn_split_across_string_arguments(egress, guardrail):
    result = egress.handler(_request_event({"text": SSN_LEFT, "note": SSN_RIGHT}), None)
    _assert_not_forwarded(result, [SSN_TEXT, SSN_DIGITS, SSN_LEFT, SSN_RIGHT])


def test_request_blocks_card_split_across_text_and_integer(egress, guardrail):
    result = egress.handler(
        _request_event({"text": CARD_LEFT, "N": int(CARD_RIGHT)}), None
    )
    _assert_not_forwarded(result, [CARD, CARD_LEFT, CARD_RIGHT])


def test_request_blocks_card_supplied_as_integer(egress, guardrail):
    result = egress.handler(
        _request_event({"text": "count the words", "N": int(CARD)}), None
    )
    _assert_not_forwarded(result, [CARD])


def test_request_blocks_ssn_supplied_as_integer(egress, guardrail):
    result = egress.handler(
        _request_event({"text": "count the words", "N": int(SSN_DIGITS)}), None
    )
    _assert_not_forwarded(result, [SSN_DIGITS])


def test_request_blocks_card_supplied_as_object_key(egress, guardrail):
    result = egress.handler(
        _request_event({"text": "count the words", CARD: "marker"}), None
    )
    _assert_not_forwarded(result, [CARD])


def test_request_blocks_ssn_supplied_as_object_key(egress, guardrail):
    result = egress.handler(
        _request_event({"text": "count the words", SSN_TEXT: "marker"}), None
    )
    _assert_not_forwarded(result, [SSN_TEXT, SSN_DIGITS])


def test_request_blocks_card_split_across_nested_strings(egress, guardrail):
    result = egress.handler(
        _request_event({"text": "count", "parts": [CARD_LEFT, CARD_RIGHT]}),
        None,
    )
    _assert_not_forwarded(result, [CARD, CARD_LEFT, CARD_RIGHT])


def test_response_forwards_text_that_is_not_card_or_ssn(egress, guardrail):
    result = egress.handler(
        _response_event({"content": [{"type": "text", "text": "hello world"}]}),
        None,
    )
    _assert_response_stopped(result, [])
    encoded = json.dumps(result["mcp"]["transformedGatewayResponse"])
    assert "hello world" in encoded
    assert "Blocked by egress guardrail." not in encoded


def test_response_only_blocks_card_split_across_content_strings(egress, guardrail):
    result = egress.handler(
        _response_only_event(
            {
                "content": [
                    {"type": "text", "text": CARD_LEFT},
                    {"type": "text", "text": CARD_RIGHT},
                ]
            }
        ),
        None,
    )
    _assert_response_stopped(result, [CARD, CARD_LEFT, CARD_RIGHT])
    assert guardrail[0]["source"] == "OUTPUT"


def test_response_only_blocks_card_supplied_as_integer(egress, guardrail):
    result = egress.handler(
        _response_only_event(
            {"content": [{"type": "text", "text": "count"}], "N": int(CARD)}
        ),
        None,
    )
    _assert_response_stopped(result, [CARD])


def test_response_only_blocks_card_supplied_as_object_key(egress, guardrail):
    result = egress.handler(
        _response_only_event(
            {"content": [{"type": "text", "text": "count"}], CARD: "marker"}
        ),
        None,
    )
    _assert_response_stopped(result, [CARD])


def test_response_blocks_card_in_one_string(egress, guardrail):
    result = egress.handler(
        _response_event({"content": [{"type": "text", "text": CARD}]}), None
    )
    _assert_response_stopped(result, [CARD])


def test_response_blocks_ssn_in_one_string(egress, guardrail):
    result = egress.handler(
        _response_event({"content": [{"type": "text", "text": SSN_TEXT}]}), None
    )
    _assert_response_stopped(result, [SSN_TEXT, SSN_DIGITS])


def test_response_blocks_card_split_across_content_strings(egress, guardrail):
    result = egress.handler(
        _response_event(
            {
                "content": [
                    {"type": "text", "text": CARD_LEFT},
                    {"type": "text", "text": CARD_RIGHT},
                ]
            }
        ),
        None,
    )
    _assert_response_stopped(result, [CARD, CARD_LEFT, CARD_RIGHT])


def test_response_blocks_ssn_split_across_content_strings(egress, guardrail):
    result = egress.handler(
        _response_event(
            {
                "content": [
                    {"type": "text", "text": SSN_LEFT},
                    {"type": "text", "text": SSN_RIGHT},
                ]
            }
        ),
        None,
    )
    _assert_response_stopped(result, [SSN_TEXT, SSN_DIGITS, SSN_LEFT, SSN_RIGHT])


def test_response_blocks_card_supplied_as_integer(egress, guardrail):
    result = egress.handler(
        _response_event(
            {"content": [{"type": "text", "text": "count"}], "N": int(CARD)}
        ),
        None,
    )
    _assert_response_stopped(result, [CARD])


def test_response_blocks_ssn_supplied_as_integer(egress, guardrail):
    result = egress.handler(
        _response_event(
            {
                "content": [{"type": "text", "text": "count"}],
                "N": int(SSN_DIGITS),
            }
        ),
        None,
    )
    _assert_response_stopped(result, [SSN_DIGITS])


def test_response_blocks_card_supplied_as_object_key(egress, guardrail):
    result = egress.handler(
        _response_event({"content": [{"type": "text", "text": "count"}], CARD: "x"}),
        None,
    )
    _assert_response_stopped(result, [CARD])


def test_request_rejects_text_over_the_scan_cap(egress, guardrail):
    huge = "A" * (MAX_SCAN_CHARS + 1)
    result = egress.handler(_request_event({"text": huge, "N": 5}), None)
    _assert_not_forwarded(result, [huge])
    _assert_scan_bounded(guardrail)


def test_request_rejects_many_leaves_over_the_scan_cap(egress, guardrail):
    chunk = "B" * 1000
    extra = (MAX_SCAN_CHARS // len(chunk)) + 1
    result = egress.handler(
        _request_event({"text": chunk, "parts": [chunk] * extra}), None
    )
    _assert_not_forwarded(result, [chunk])
    _assert_scan_bounded(guardrail)


def test_response_rejects_text_over_the_scan_cap(egress, guardrail):
    huge = "C" * (MAX_SCAN_CHARS + 1)
    result = egress.handler(
        _response_event({"content": [{"type": "text", "text": huge}]}), None
    )
    _assert_response_stopped(result, [huge])
    _assert_scan_bounded(guardrail)
