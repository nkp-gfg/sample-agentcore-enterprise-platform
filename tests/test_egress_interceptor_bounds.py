"""Bounds the gateway egress interceptor must enforce.

These tests exercise ``tools/egress_interceptor/handler.py`` on the MCP
interceptor event the Lambda is deployed to receive: a REQUEST event whose
``mcp.gatewayRequest`` is the parsed JSON-RPC body, and a RESPONSE event that
carries ``mcp.gatewayResponse`` (with and without ``gatewayRequest``, because
the handler scans those two objects in separate branches).

They fail while the handler walks every string leaf with no depth, string-count,
or byte-size limit. The required behavior is:

- Refuse, before any ``ApplyGuardrail`` call, when the scanned object
  (``gatewayRequest``, or ``gatewayResponse`` when that is the object the
  handler scans) exceeds any of:
  - 32768 UTF-8 bytes of ``json.dumps(node)`` with the standard-library
    default separators;
  - nesting depth 32, where depth counts list and dict containers from the
    scanned object downward and the scanned object itself counts as 1;
  - 64 string leaves (dict values and list items that are strings; dict keys
    are not leaves).
- Return the same blocked interceptor body the handler already returns when a
  guardrail assessment denies content:
  ``{"content": [{"type": "text", "text": "Blocked by egress guardrail."}]}``
  under ``transformedGatewayRequest`` when the event has ``gatewayRequest``,
  otherwise under ``transformedGatewayResponse``.
- For a payload inside those limits, concatenate the non-empty string leaves
  and call ``ApplyGuardrail`` once per chunk of at most 8000 characters, not
  once per leaf. A payload whose non-empty leaves fit in one chunk must
  produce exactly one call. The call uses ``source=INPUT`` for a request scan
  and ``source=OUTPUT`` for a response scan, and the returned tree still
  carries those leaves when the guardrail does not intervene.
- A ``ThrottlingException`` from ``ApplyGuardrail``, a botocore read timeout,
  or a recursion error is that same blocked response, not an exception that
  fails the Lambda.
"""

from __future__ import annotations

import importlib.util
import json
import os
import sys
import types
from pathlib import Path

import pytest
from botocore.exceptions import ClientError, ReadTimeoutError

REPO = Path(__file__).resolve().parents[1]

MAX_BYTES = 32768
MAX_DEPTH = 32
MAX_STRINGS = 64
MAX_CHUNK_CHARS = 8000
BLOCKED_TEXT = "Blocked by egress guardrail."
GUARDRAIL_ID = "guardrail-under-test"

os.environ["GUARDRAIL_ID"] = GUARDRAIL_ID
os.environ["GUARDRAIL_VERSION"] = "1"
os.environ["AWS_DEFAULT_REGION"] = "us-east-1"
os.environ["AWS_EC2_METADATA_DISABLED"] = "true"


class _GuardrailClient:
    def apply_guardrail(self, **kwargs):
        raise AssertionError("apply_guardrail was not armed for this test")


_stub_boto3 = types.ModuleType("boto3")
_stub_boto3.client = lambda *args, **kwargs: _GuardrailClient()
sys.modules["boto3"] = _stub_boto3

_spec = importlib.util.spec_from_file_location(
    "egress_interceptor_handler",
    REPO / "tools" / "egress_interceptor" / "handler.py",
)
handler = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(handler)


def _string_leaves(node) -> list[str]:
    if isinstance(node, dict):
        return [leaf for value in node.values() for leaf in _string_leaves(value)]
    if isinstance(node, list):
        return [leaf for value in node for leaf in _string_leaves(value)]
    if isinstance(node, str):
        return [node]
    return []


def _depth(node) -> int:
    if isinstance(node, dict):
        return 1 + max((_depth(value) for value in node.values()), default=0)
    if isinstance(node, list):
        return 1 + max((_depth(value) for value in node), default=0)
    return 0


def _byte_size(node) -> int:
    return len(json.dumps(node).encode("utf-8"))


def _nest(leaf, levels: int, kind: str):
    node = leaf
    for _ in range(levels):
        node = [node] if kind == "list" else {"k": node}
    return node


def _request_event(arguments):
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
                        "name": "sample-tool___text_analysis_tool",
                        "arguments": arguments,
                    },
                },
            }
        },
    }


def _response_event(body, *, include_request: bool):
    mcp = {
        "gatewayResponse": {
            "statusCode": 200,
            "body": body,
        }
    }
    if include_request:
        mcp = {**_request_event("hello")["mcp"], **mcp}
    return {"interceptorInputVersion": "1.0", "mcp": mcp}


def _arm(calls: list, exc: BaseException | None = None):
    def apply_guardrail(**kwargs):
        calls.append(kwargs)
        if exc is not None:
            raise exc
        return {"action": "NONE"}

    handler._bedrock.apply_guardrail = apply_guardrail


def _assert_blocked(result, point: str):
    key = (
        "transformedGatewayRequest"
        if point == "REQUEST"
        else "transformedGatewayResponse"
    )
    other = (
        "transformedGatewayResponse"
        if point == "REQUEST"
        else "transformedGatewayRequest"
    )
    assert result["interceptorOutputVersion"] == "1.0"
    assert other not in result["mcp"]
    assert result["mcp"][key] == {
        "content": [{"type": "text", "text": BLOCKED_TEXT}]
    }


def _call_text(kwargs) -> str:
    return "".join(item["text"]["text"] for item in kwargs["content"])


def _throttled() -> ClientError:
    return ClientError(
        {"Error": {"Code": "ThrottlingException", "Message": "Rate exceeded"}},
        "ApplyGuardrail",
    )


def _timed_out() -> ReadTimeoutError:
    return ReadTimeoutError(endpoint_url="https://bedrock-runtime.us-east-1.amazonaws.com")


@pytest.fixture
def calls():
    recorded: list = []
    _arm(recorded)
    return recorded


def test_request_list_just_over_depth_is_refused_before_scan(calls):
    """Depth 40 does not overflow the stack; only an explicit cap catches it."""
    event = _request_event(_nest("leaf", 40, "list"))
    scanned = event["mcp"]["gatewayRequest"]
    assert _depth(scanned) > MAX_DEPTH
    result = handler.handler(event, None)
    assert calls == []
    _assert_blocked(result, "REQUEST")


def test_request_dict_just_over_depth_is_refused_before_scan(calls):
    event = _request_event(_nest("leaf", 40, "dict"))
    assert _depth(event["mcp"]["gatewayRequest"]) > MAX_DEPTH
    result = handler.handler(event, None)
    assert calls == []
    _assert_blocked(result, "REQUEST")


@pytest.mark.parametrize("kind", ["list", "dict"])
def test_request_thousand_deep_is_blocked_not_a_recursion_crash(calls, kind):
    event = _request_event(_nest("leaf", 1000, kind))
    result = handler.handler(event, None)
    assert calls == []
    _assert_blocked(result, "REQUEST")


def test_request_string_fanout_is_refused_before_scan(calls):
    leaves = [f"leaf-{index:03d}" for index in range(80)]
    event = _request_event(leaves)
    assert len(_string_leaves(event["mcp"]["gatewayRequest"])) > MAX_STRINGS
    result = handler.handler(event, None)
    assert calls == []
    _assert_blocked(result, "REQUEST")


def test_request_over_byte_limit_is_refused_before_scan(calls):
    event = _request_event("A" * 40000)
    scanned = event["mcp"]["gatewayRequest"]
    assert _byte_size(scanned) > MAX_BYTES
    assert _depth(scanned) <= MAX_DEPTH
    assert len(_string_leaves(scanned)) <= MAX_STRINGS
    result = handler.handler(event, None)
    assert calls == []
    _assert_blocked(result, "REQUEST")


def test_request_within_limits_is_one_concatenated_guardrail_call(calls):
    leaves = [f"leaf-{index:03d}" for index in range(10)]
    event = _request_event(leaves)
    scanned = event["mcp"]["gatewayRequest"]
    nonempty = [leaf for leaf in _string_leaves(scanned) if leaf.strip()]
    assert _depth(scanned) <= MAX_DEPTH
    assert len(_string_leaves(scanned)) <= MAX_STRINGS
    assert _byte_size(scanned) <= MAX_BYTES
    assert sum(len(leaf) for leaf in nonempty) <= MAX_CHUNK_CHARS

    result = handler.handler(event, None)

    assert len(calls) == 1
    assert calls[0]["source"] == "INPUT"
    assert calls[0]["guardrailIdentifier"] == GUARDRAIL_ID
    blob = _call_text(calls[0])
    assert len(blob) <= MAX_CHUNK_CHARS
    for leaf in nonempty:
        assert leaf in blob
    transformed = result["mcp"]["transformedGatewayRequest"]
    assert transformed["body"]["params"]["arguments"] == leaves


def test_response_event_with_deep_request_is_blocked_not_a_crash(calls):
    """Documented RESPONSE payloads also include gatewayRequest, which this handler scans."""
    event = _response_event({"content": [{"type": "text", "text": "ok"}]}, include_request=True)
    event["mcp"]["gatewayRequest"]["body"]["params"]["arguments"] = _nest("leaf", 1000, "list")
    result = handler.handler(event, None)
    assert calls == []
    _assert_blocked(result, "REQUEST")


def test_response_event_with_request_string_fanout_is_refused_before_scan(calls):
    event = _response_event({"content": [{"type": "text", "text": "ok"}]}, include_request=True)
    event["mcp"]["gatewayRequest"]["body"]["params"]["arguments"] = [
        f"leaf-{index:03d}" for index in range(80)
    ]
    result = handler.handler(event, None)
    assert calls == []
    _assert_blocked(result, "REQUEST")


@pytest.mark.parametrize("kind", ["list", "dict"])
def test_response_only_thousand_deep_is_blocked_not_a_crash(calls, kind):
    event = _response_event(_nest("leaf", 1000, kind), include_request=False)
    result = handler.handler(event, None)
    assert calls == []
    _assert_blocked(result, "RESPONSE")


def test_response_only_string_fanout_is_refused_before_scan(calls):
    leaves = [f"leaf-{index:03d}" for index in range(80)]
    event = _response_event(leaves, include_request=False)
    assert len(_string_leaves(event["mcp"]["gatewayResponse"])) > MAX_STRINGS
    result = handler.handler(event, None)
    assert calls == []
    _assert_blocked(result, "RESPONSE")


def test_response_only_over_byte_limit_is_refused_before_scan(calls):
    event = _response_event("B" * 40000, include_request=False)
    assert _byte_size(event["mcp"]["gatewayResponse"]) > MAX_BYTES
    result = handler.handler(event, None)
    assert calls == []
    _assert_blocked(result, "RESPONSE")


def test_response_only_within_limits_is_one_concatenated_guardrail_call(calls):
    leaves = [f"out-{index:03d}" for index in range(10)]
    event = _response_event(leaves, include_request=False)
    scanned = event["mcp"]["gatewayResponse"]
    nonempty = [leaf for leaf in _string_leaves(scanned) if leaf.strip()]
    assert _depth(scanned) <= MAX_DEPTH
    assert len(_string_leaves(scanned)) <= MAX_STRINGS
    assert _byte_size(scanned) <= MAX_BYTES
    assert sum(len(leaf) for leaf in nonempty) <= MAX_CHUNK_CHARS

    result = handler.handler(event, None)

    assert len(calls) == 1
    assert calls[0]["source"] == "OUTPUT"
    blob = _call_text(calls[0])
    for leaf in nonempty:
        assert leaf in blob
    assert result["mcp"]["transformedGatewayResponse"]["body"] == leaves


@pytest.mark.parametrize(
    ("builder", "point"),
    [
        (lambda: _request_event("hello"), "REQUEST"),
        (lambda: _response_event(["hello", "world"], include_request=False), "RESPONSE"),
    ],
)
@pytest.mark.parametrize("error", [_throttled(), _timed_out()])
def test_guardrail_throttle_or_timeout_is_a_block(calls, builder, point, error):
    _arm(calls, error)
    result = handler.handler(builder(), None)
    _assert_blocked(result, point)
