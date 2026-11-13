"""Egress interceptor output must match the AgentCore Gateway interceptor contract.

The gateway rejects anything else with "InterceptorException - Received invalid
response from interceptor", which turns every MCP call into a 500.
"""

import importlib.util
from pathlib import Path
from unittest import mock

import pytest

HANDLER = Path(__file__).resolve().parents[1] / "tools" / "egress_interceptor" / "handler.py"


@pytest.fixture
def interceptor(monkeypatch):
    monkeypatch.setenv("GUARDRAIL_ID", "gr-test")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "eu-west-1")
    spec = importlib.util.spec_from_file_location("egress_interceptor_handler", HANDLER)
    module = importlib.util.module_from_spec(spec)
    with mock.patch("boto3.client"):
        spec.loader.exec_module(module)
    module._bedrock = mock.Mock()
    module._bedrock.apply_guardrail.return_value = {"action": "NONE"}
    return module


def _event(request_body, response=None):
    return {
        "interceptorInputVersion": "1.0",
        "mcp": {
            "gatewayRequest": {"path": "/mcp", "httpMethod": "POST", "headers": {}, "body": request_body, "context": None},
            "gatewayResponse": response,
            "rawGatewayRequest": {"body": "{}"},
        },
    }


TOOLS_LIST = {"jsonrpc": "2.0", "id": "tools/list", "method": "tools/list"}
TOOLS_CALL = {
    "jsonrpc": "2.0",
    "id": 7,
    "method": "tools/call",
    "params": {"name": "sample-tool___echo", "arguments": {"text": "hello"}},
}


def test_request_returns_only_the_body(interceptor):
    out = interceptor.handler(_event(TOOLS_LIST), None)
    assert out == {
        "interceptorOutputVersion": "1.0",
        "mcp": {"transformedGatewayRequest": {"body": TOOLS_LIST}},
    }


def test_protocol_traffic_is_not_sent_to_the_guardrail(interceptor):
    interceptor.handler(_event(TOOLS_LIST), None)
    interceptor.handler(_event(TOOLS_LIST, {"statusCode": 200, "body": {"result": {"tools": []}}}), None)
    interceptor._bedrock.apply_guardrail.assert_not_called()


def test_response_point_is_detected_even_though_gateway_request_is_present(interceptor):
    response = {"statusCode": 200, "headers": {"Mcp-Session-Id": "s"}, "body": {"jsonrpc": "2.0", "id": 7, "result": {"content": []}}}
    out = interceptor.handler(_event(TOOLS_CALL, response), None)
    assert list(out["mcp"]) == ["transformedGatewayResponse"]
    assert out["mcp"]["transformedGatewayResponse"] == response


def test_tool_arguments_are_scanned_as_input(interceptor):
    interceptor.handler(_event(TOOLS_CALL), None)
    interceptor._bedrock.apply_guardrail.assert_called_once()
    kwargs = interceptor._bedrock.apply_guardrail.call_args.kwargs
    assert kwargs["source"] == "INPUT"
    assert kwargs["content"] == [{"text": {"text": "hello"}}]


def test_tool_result_is_masked_as_output(interceptor):
    interceptor._bedrock.apply_guardrail.return_value = {
        "action": "GUARDRAIL_INTERVENED",
        "assessments": [],
        "outputs": [{"text": "{EMAIL}"}],
    }
    response = {"statusCode": 200, "body": {"jsonrpc": "2.0", "id": 7, "result": {"content": [{"type": "text", "text": "a@b.com"}]}}}
    out = interceptor.handler(_event(TOOLS_CALL, response), None)
    assert interceptor._bedrock.apply_guardrail.call_args.kwargs["source"] == "OUTPUT"
    body = out["mcp"]["transformedGatewayResponse"]["body"]
    assert body["result"]["content"][0]["text"] == "{EMAIL}"
    assert body["jsonrpc"] == "2.0" and body["id"] == 7


def test_blocked_request_short_circuits_with_a_jsonrpc_error(interceptor):
    interceptor._bedrock.apply_guardrail.return_value = {
        "action": "GUARDRAIL_INTERVENED",
        "assessments": [{"contentPolicy": {"filters": [{"type": "PROMPT_ATTACK", "action": "BLOCKED"}]}}],
    }
    out = interceptor.handler(_event(TOOLS_CALL), None)
    blocked = out["mcp"]["transformedGatewayResponse"]
    assert "transformedGatewayRequest" not in out["mcp"]
    assert blocked["statusCode"] == 200
    assert blocked["body"]["id"] == 7
    assert blocked["body"]["result"]["isError"] is True


def test_streaming_follow_up_keeps_body_only(interceptor):
    response = {"isStreamingResponse": True, "body": {"jsonrpc": "2.0", "id": 7, "result": {"content": []}}}
    out = interceptor.handler(_event(TOOLS_CALL, response), None)
    assert out["mcp"]["transformedGatewayResponse"] == {"body": response["body"]}
