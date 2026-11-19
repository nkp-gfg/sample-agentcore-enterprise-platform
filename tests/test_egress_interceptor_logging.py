"""The egress interceptor must not write raw gateway payloads to its logs.

The Lambda logs the first 2000 characters of the invocation event before
ApplyGuardrail runs. These tests call the deployed handler with the MCP
interceptor payload (tool arguments in gatewayRequest.body, no headers —
the stack sets pass_request_headers false) and require that a value the
guardrail masks or blocks never appear in the log line the runtime
forwards. They fail while that log statement is still there.
"""

import importlib.util
import json
import logging
import os
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]

# Module-level constants are read at import. Set them before loading the
# handler so the test takes the same path as the deployed function, which
# injects GUARDRAIL_ID.
os.environ["GUARDRAIL_ID"] = "egress-guardrail-test"
os.environ["GUARDRAIL_VERSION"] = "DRAFT"
os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")
os.environ.setdefault("AWS_EC2_METADATA_DISABLED", "true")

# Obvious placeholders. These are not payment cards, national IDs, or mailbox
# addresses; the handler never inspects the text itself. Bedrock does, and
# the stand-in below only classifies these markers.
CARD_MARKER = "PAYMENT-CARD-PLACEHOLDER"
EMAIL_MARKER = "CONTACT-EMAIL-PLACEHOLDER"
PROMPT_MARKER = "PROMPT-ATTACK-PLACEHOLDER"
RESPONSE_MARKER = "TARGET-REPLY-PLACEHOLDER"

# Text formatter from awslambdaric 2.2.1 LambdaLoggerHandler (plain text,
# the Lambda default this stack leaves unset). %(message)s is LogRecord.getMessage().
_LAMBDA_TEXT_FORMAT = (
    "[%(levelname)s]\t%(asctime)s.%(msecs)03dZ\t%(aws_request_id)s\t%(message)s\n"
)
_LAMBDA_TEXT_DATE = "%Y-%m-%dT%H:%M:%S"

_HANDLER = None


def _load_handler():
    global _HANDLER
    if _HANDLER is not None:
        return _HANDLER
    path = REPO / "tools" / "egress_interceptor" / "handler.py"
    spec = importlib.util.spec_from_file_location("egress_interceptor_handler", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    _HANDLER = module
    return module


class _LambdaTextSink(logging.Handler):
    """emit() matches LambdaLoggerHandler: format the record, keep the line.

    LambdaLoggerFilter sets aws_request_id before format. Without it the
    runtime formatter raises and Handler.handle drops the line.
    """

    def __init__(self):
        super().__init__()
        self.lines = []
        self.setFormatter(logging.Formatter(_LAMBDA_TEXT_FORMAT, _LAMBDA_TEXT_DATE))

    def filter(self, record):
        if not hasattr(record, "aws_request_id"):
            record.aws_request_id = ""
        return True

    def emit(self, record):
        self.lines.append(self.format(record))


@pytest.fixture
def interceptor():
    module = _load_handler()
    # handler.py sets the root logger to INFO at import. Put that back so an
    # earlier test cannot hide INFO records the Lambda runtime would ship.
    previous_level = module.logger.level
    module.logger.setLevel(logging.INFO)
    sink = _LambdaTextSink()
    module.logger.addHandler(sink)
    calls = []

    def apply_guardrail(**kwargs):
        text = kwargs["content"][0]["text"]["text"]
        calls.append({"text": text, "source": kwargs["source"]})
        if CARD_MARKER in text:
            return {
                "action": "GUARDRAIL_INTERVENED",
                "assessments": [
                    {
                        "sensitiveInformationPolicy": {
                            "piiEntities": [
                                {
                                    "type": "CREDIT_DEBIT_CARD_NUMBER",
                                    "action": "BLOCKED",
                                }
                            ]
                        }
                    }
                ],
            }
        if PROMPT_MARKER in text:
            return {
                "action": "GUARDRAIL_INTERVENED",
                "assessments": [
                    {
                        "contentPolicy": {
                            "filters": [{"type": "PROMPT_ATTACK", "action": "BLOCKED"}]
                        }
                    }
                ],
            }
        if EMAIL_MARKER in text:
            return {
                "action": "GUARDRAIL_INTERVENED",
                "assessments": [
                    {
                        "sensitiveInformationPolicy": {
                            "piiEntities": [{"type": "EMAIL", "action": "ANONYMIZED"}]
                        }
                    }
                ],
                "outputs": [{"text": text.replace(EMAIL_MARKER, "[ANONYMIZED]")}],
            }
        return {"action": "NONE"}

    original = module._bedrock.apply_guardrail
    module._bedrock.apply_guardrail = apply_guardrail
    try:
        yield module, sink, calls
    finally:
        module._bedrock.apply_guardrail = original
        module.logger.removeHandler(sink)
        module.logger.setLevel(previous_level)


def _tools_call_body(argument_text):
    """JSON-RPC body scripts/test_gateway.py posts for the sample tool."""
    return {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "sample-tool___text_analysis_tool",
            "arguments": {"text": argument_text, "N": 3},
        },
    }


def _request_event(argument_text):
    """REQUEST interceptor input: gatewayRequest only, headers omitted."""
    body = _tools_call_body(argument_text)
    return {
        "interceptorInputVersion": "1.0",
        "mcp": {
            "rawGatewayRequest": {"body": json.dumps(body)},
            "gatewayRequest": {
                "path": "/mcp",
                "httpMethod": "POST",
                "body": body,
            },
        },
    }


def _response_event(argument_text, response_text):
    """RESPONSE interceptor input as documented: request plus response.

    The published payload includes gatewayRequest, so this is the event the
    function receives on the RESPONSE interception point. A response-only
    event is built separately to exercise the branch that reads gatewayResponse.
    """
    body = _tools_call_body(argument_text)
    return {
        "interceptorInputVersion": "1.0",
        "mcp": {
            "rawGatewayRequest": {"body": json.dumps(body)},
            "gatewayRequest": {
                "path": "/mcp",
                "httpMethod": "POST",
                "body": body,
            },
            "gatewayResponse": {
                "statusCode": 200,
                "body": {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "result": {
                        "content": [{"type": "text", "text": response_text}],
                    },
                },
            },
        },
    }


def _response_only_event(response_text):
    return {
        "interceptorInputVersion": "1.0",
        "mcp": {
            "gatewayResponse": {
                "statusCode": 200,
                "body": {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "result": {
                        "content": [{"type": "text", "text": response_text}],
                    },
                },
            },
        },
    }


def _log_text(sink):
    return "".join(sink.lines)


def _assert_absent(sink, marker):
    rendered = _log_text(sink)
    assert marker not in rendered, rendered


def _assert_guardrail_saw(calls, marker, source):
    assert any(marker in call["text"] and call["source"] == source for call in calls)


def test_request_block_does_not_log_the_tool_argument(interceptor):
    module, sink, calls = interceptor
    event = _request_event(f"please store {CARD_MARKER} for the refund")

    result = module.handler(event, None)

    _assert_guardrail_saw(calls, CARD_MARKER, "INPUT")
    assert result["mcp"]["transformedGatewayRequest"] == {
        "content": [{"type": "text", "text": "Blocked by egress guardrail."}]
    }
    assert CARD_MARKER not in json.dumps(result)
    _assert_absent(sink, CARD_MARKER)


def test_request_anonymize_does_not_log_the_tool_argument(interceptor):
    module, sink, calls = interceptor
    event = _request_event(f"reach me at {EMAIL_MARKER}")

    result = module.handler(event, None)

    _assert_guardrail_saw(calls, EMAIL_MARKER, "INPUT")
    transformed = result["mcp"]["transformedGatewayRequest"]
    argument = transformed["body"]["params"]["arguments"]["text"]
    assert argument == "reach me at [ANONYMIZED]"
    assert EMAIL_MARKER not in json.dumps(result)
    _assert_absent(sink, EMAIL_MARKER)


def test_request_prompt_block_does_not_log_the_tool_argument(interceptor):
    module, sink, calls = interceptor
    event = _request_event(PROMPT_MARKER)

    result = module.handler(event, None)

    _assert_guardrail_saw(calls, PROMPT_MARKER, "INPUT")
    assert result["mcp"]["transformedGatewayRequest"]["content"][0]["text"] == (
        "Blocked by egress guardrail."
    )
    assert PROMPT_MARKER not in json.dumps(result)
    _assert_absent(sink, PROMPT_MARKER)


def test_request_block_still_hides_the_argument_when_the_event_exceeds_2000_chars(
    interceptor,
):
    """Tool arguments sit inside the prefix the handler slices to 2000 characters."""
    module, sink, calls = interceptor
    padding = "x" * 2500
    event = _request_event(f"{CARD_MARKER} {padding}")

    result = module.handler(event, None)

    _assert_guardrail_saw(calls, CARD_MARKER, "INPUT")
    assert CARD_MARKER not in json.dumps(result)
    _assert_absent(sink, CARD_MARKER)


def test_documented_response_event_does_not_log_request_or_target_text(interceptor):
    module, sink, calls = interceptor
    event = _response_event(
        f"account {CARD_MARKER}",
        f"tool echoed {RESPONSE_MARKER}",
    )

    result = module.handler(event, None)

    # The documented response payload also contains gatewayRequest, and the
    # handler handles that key first. The invocation still logs the whole
    # event, including the target text, before any of that.
    assert calls, "guardrail was not invoked"
    assert CARD_MARKER not in json.dumps(result)
    _assert_absent(sink, CARD_MARKER)
    _assert_absent(sink, RESPONSE_MARKER)


def test_response_block_does_not_log_the_target_text(interceptor):
    module, sink, calls = interceptor
    event = _response_only_event(f"balance for {CARD_MARKER}")

    result = module.handler(event, None)

    _assert_guardrail_saw(calls, CARD_MARKER, "OUTPUT")
    assert result["mcp"]["transformedGatewayResponse"] == {
        "content": [{"type": "text", "text": "Blocked by egress guardrail."}]
    }
    assert CARD_MARKER not in json.dumps(result)
    _assert_absent(sink, CARD_MARKER)


def test_response_anonymize_does_not_log_the_target_text(interceptor):
    module, sink, calls = interceptor
    event = _response_only_event(f"contact {EMAIL_MARKER}")

    result = module.handler(event, None)

    _assert_guardrail_saw(calls, EMAIL_MARKER, "OUTPUT")
    transformed = result["mcp"]["transformedGatewayResponse"]
    text = transformed["body"]["result"]["content"][0]["text"]
    assert text == "contact [ANONYMIZED]"
    assert EMAIL_MARKER not in json.dumps(result)
    _assert_absent(sink, EMAIL_MARKER)


def test_unrecognized_payload_does_not_log_its_raw_body(interceptor):
    """Same log statement runs when the payload is neither request nor response."""
    module, sink, calls = interceptor
    event = {
        "interceptorInputVersion": "1.0",
        "mcp": {"note": f"dropped {CARD_MARKER}"},
    }

    result = module.handler(event, None)

    assert calls == []
    assert result["mcp"] == event["mcp"]
    _assert_absent(sink, CARD_MARKER)


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-q"]))
