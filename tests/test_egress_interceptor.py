"""Egress interceptor output must match the AgentCore Gateway interceptor contract.

The gateway rejects anything else with "InterceptorException - Received invalid
response from interceptor", which turns every MCP call into a 500.
"""

import base64
import importlib.util
import json
from pathlib import Path
from unittest import mock

import pytest

HANDLER = (
    Path(__file__).resolve().parents[1] / "tools" / "egress_interceptor" / "handler.py"
)


def _load_interceptor(monkeypatch, env=None):
    """Import the handler with the environment pinned before module load.

    The identity-promotion path reads HR_IDENTITY_PROMOTION at import
    time to warm its decision, so the env vars must be set before the
    spec loader runs.
    """
    monkeypatch.setenv("GUARDRAIL_ID", "gr-test")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "eu-west-1")
    monkeypatch.delenv("HR_IDENTITY_PROMOTION", raising=False)
    for key, value in (env or {}).items():
        monkeypatch.setenv(key, value)
    spec = importlib.util.spec_from_file_location("egress_interceptor_handler", HANDLER)
    module = importlib.util.module_from_spec(spec)
    with mock.patch("boto3.client"):
        spec.loader.exec_module(module)
    module._bedrock = mock.Mock()
    module._bedrock.apply_guardrail.return_value = {"action": "NONE"}
    return module


@pytest.fixture
def interceptor(monkeypatch):
    return _load_interceptor(monkeypatch)


@pytest.fixture
def hr_interceptor(monkeypatch):
    return _load_interceptor(monkeypatch, env={"HR_IDENTITY_PROMOTION": "1"})


def _event(request_body, response=None):
    return {
        "interceptorInputVersion": "1.0",
        "mcp": {
            "gatewayRequest": {
                "path": "/mcp",
                "httpMethod": "POST",
                "headers": {},
                "body": request_body,
                "context": None,
            },
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
    interceptor.handler(
        _event(TOOLS_LIST, {"statusCode": 200, "body": {"result": {"tools": []}}}), None
    )
    interceptor._bedrock.apply_guardrail.assert_not_called()


def test_response_point_is_detected_even_though_gateway_request_is_present(interceptor):
    response = {
        "statusCode": 200,
        "headers": {"Mcp-Session-Id": "s"},
        "body": {"jsonrpc": "2.0", "id": 7, "result": {"content": []}},
    }
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
    response = {
        "statusCode": 200,
        "body": {
            "jsonrpc": "2.0",
            "id": 7,
            "result": {"content": [{"type": "text", "text": "a@b.com"}]},
        },
    }
    out = interceptor.handler(_event(TOOLS_CALL, response), None)
    assert interceptor._bedrock.apply_guardrail.call_args.kwargs["source"] == "OUTPUT"
    body = out["mcp"]["transformedGatewayResponse"]["body"]
    assert body["result"]["content"][0]["text"] == "{EMAIL}"
    assert body["jsonrpc"] == "2.0" and body["id"] == 7


def test_blocked_request_short_circuits_with_a_jsonrpc_error(interceptor):
    interceptor._bedrock.apply_guardrail.return_value = {
        "action": "GUARDRAIL_INTERVENED",
        "assessments": [
            {
                "contentPolicy": {
                    "filters": [{"type": "PROMPT_ATTACK", "action": "BLOCKED"}]
                }
            }
        ],
    }
    out = interceptor.handler(_event(TOOLS_CALL), None)
    blocked = out["mcp"]["transformedGatewayResponse"]
    assert "transformedGatewayRequest" not in out["mcp"]
    assert blocked["statusCode"] == 200
    assert blocked["body"]["id"] == 7
    assert blocked["body"]["result"]["isError"] is True


def test_streaming_follow_up_keeps_body_only(interceptor):
    response = {
        "isStreamingResponse": True,
        "body": {"jsonrpc": "2.0", "id": 7, "result": {"content": []}},
    }
    out = interceptor.handler(_event(TOOLS_CALL, response), None)
    assert out["mcp"]["transformedGatewayResponse"] == {"body": response["body"]}


# ---------------------------------------------------------------------------
# HR identity promotion (phase H4 — custom-app-plan/phases.md § H4,
# docs/hr/tools.md § Identity on the call).
#
# The REQUEST pass must overwrite caller_employee_id, agent_id, and
# session_id on the tool arguments with values derived from the
# gateway-validated JWT + MCP session header. It must do that ONLY
# when (a) HR_IDENTITY_PROMOTION=1 is set AND (b) the tool is one of
# the three HR targets. Every other combination leaves the arguments
# the way the guardrail scan left them.
# ---------------------------------------------------------------------------


def _jwt(claims: dict) -> str:
    """Encode the minimum JWT shape the interceptor must parse.

    The gateway already validated the signature, so the interceptor
    MUST NOT reverify it. This helper writes a header + payload +
    signature with a static signature segment, just to keep the dotted
    shape valid.
    """
    header = (
        base64.urlsafe_b64encode(json.dumps({"alg": "none"}).encode())
        .rstrip(b"=")
        .decode()
    )
    payload = (
        base64.urlsafe_b64encode(json.dumps(claims).encode()).rstrip(b"=").decode()
    )
    return f"{header}.{payload}.sig"


def _hr_event(arguments=None, headers=None, tool="hr-ops___get_leave_balance"):
    if arguments is None:
        arguments = {}
    body = {
        "jsonrpc": "2.0",
        "id": 42,
        "method": "tools/call",
        "params": {"name": tool, "arguments": arguments},
    }
    return {
        "interceptorInputVersion": "1.0",
        "mcp": {
            "gatewayRequest": {
                "path": "/mcp",
                "httpMethod": "POST",
                "headers": headers or {},
                "body": body,
                "context": None,
            },
            "gatewayResponse": None,
            "rawGatewayRequest": {"body": "{}"},
        },
    }


def _arguments_after(output):
    """Pull the final tool arguments out of an interceptor REQUEST response."""
    return output["mcp"]["transformedGatewayRequest"]["body"]["params"]["arguments"]


def test_identity_promotion_off_default_leaves_hr_arguments_alone(interceptor):
    out = interceptor.handler(
        _hr_event(
            arguments={"caller_employee_id": "SPOOFED", "agent_id": "SPOOFED"},
            headers={
                "Authorization": f"Bearer {_jwt({'employee_id': 'E1', 'agent_id': 'leave-balance'})}"
            },
        ),
        None,
    )
    assert _arguments_after(out) == {
        "caller_employee_id": "SPOOFED",
        "agent_id": "SPOOFED",
    }


def test_identity_promotion_on_overwrites_hr_arguments_from_token(hr_interceptor):
    jwt = _jwt({"employee_id": "E1", "agent_id": "leave-balance"})
    out = hr_interceptor.handler(
        _hr_event(
            arguments={
                "caller_employee_id": "SPOOFED",
                "agent_id": "SPOOFED",
                "some_tool_field": "kept",
            },
            headers={
                "Authorization": f"Bearer {jwt}",
                "Mcp-Session-Id": "sess-abc",
            },
        ),
        None,
    )
    arguments = _arguments_after(out)
    # Token wins. Model-sent values are overwritten, not merged.
    assert arguments["caller_employee_id"] == "E1"
    assert arguments["agent_id"] == "leave-balance"
    assert arguments["session_id"] == "sess-abc"
    # Unrelated tool arguments are preserved.
    assert arguments["some_tool_field"] == "kept"


def test_identity_promotion_on_non_hr_tool_is_untouched(hr_interceptor):
    out = hr_interceptor.handler(
        _hr_event(
            tool="sample-tool___text_analysis_tool",
            arguments={
                "text": "hello",
                "caller_employee_id": "SPOOFED",
            },
            headers={
                "Authorization": f"Bearer {_jwt({'employee_id': 'E1', 'agent_id': 'leave-balance'})}"
            },
        ),
        None,
    )
    # Not an HR target: the model-sent arguments are the final arguments.
    assert _arguments_after(out) == {
        "text": "hello",
        "caller_employee_id": "SPOOFED",
    }


def test_identity_promotion_without_employee_id_claim_writes_empty_string(
    hr_interceptor,
):
    """docs/hr/modules.md § H3 claims: a terminated row or a sub with no
    row gets no employee_id claim. The interceptor still overwrites the
    model-sent value — the Lambda layer refuses with NOT_MAPPED when
    caller_employee_id is the empty string."""
    out = hr_interceptor.handler(
        _hr_event(
            arguments={"caller_employee_id": "SPOOFED", "agent_id": "SPOOFED"},
            headers={
                "Authorization": f"Bearer {_jwt({'agent_id': 'leave-balance'})}",
                "Mcp-Session-Id": "s",
            },
        ),
        None,
    )
    arguments = _arguments_after(out)
    assert arguments["caller_employee_id"] == ""
    assert arguments["agent_id"] == "leave-balance"
    assert arguments["session_id"] == "s"


def test_identity_promotion_without_authorization_header_clears_all_three(
    hr_interceptor,
):
    """Defence in depth: no Authorization header means no identity.
    The interceptor must still overwrite the three fields so the model
    cannot smuggle a value in through the arguments."""
    out = hr_interceptor.handler(
        _hr_event(
            arguments={
                "caller_employee_id": "SPOOFED",
                "agent_id": "SPOOFED",
                "session_id": "SPOOFED",
            },
            headers={},
        ),
        None,
    )
    arguments = _arguments_after(out)
    assert arguments["caller_employee_id"] == ""
    assert arguments["agent_id"] == ""
    assert arguments["session_id"] == ""


def test_identity_promotion_ignores_malformed_token(hr_interceptor):
    out = hr_interceptor.handler(
        _hr_event(
            arguments={"caller_employee_id": "SPOOFED"},
            headers={"Authorization": "Bearer not-a-jwt"},
        ),
        None,
    )
    arguments = _arguments_after(out)
    assert arguments["caller_employee_id"] == ""
    assert arguments["agent_id"] == ""


def test_identity_promotion_ignores_non_bearer_scheme(hr_interceptor):
    out = hr_interceptor.handler(
        _hr_event(
            arguments={"caller_employee_id": "SPOOFED"},
            headers={
                "Authorization": f"Basic {_jwt({'employee_id': 'E1', 'agent_id': 'leave-balance'})}",
                "Mcp-Session-Id": "s",
            },
        ),
        None,
    )
    arguments = _arguments_after(out)
    assert arguments["caller_employee_id"] == ""
    assert arguments["agent_id"] == ""
    assert arguments["session_id"] == "s"


def test_identity_promotion_header_name_lookup_is_case_insensitive(hr_interceptor):
    """Lambda / API Gateway normalisation varies between runtimes.
    Both HTTP/2 lowercase names and classic mixed case must work."""
    jwt = _jwt({"employee_id": "E1", "agent_id": "leave-balance"})
    for header_name in ("Authorization", "authorization", "AUTHORIZATION"):
        out = hr_interceptor.handler(
            _hr_event(
                arguments={"caller_employee_id": "SPOOFED"},
                headers={header_name: f"Bearer {jwt}", "mcp-session-id": "s"},
            ),
            None,
        )
        arguments = _arguments_after(out)
        assert arguments["caller_employee_id"] == "E1"
        assert arguments["agent_id"] == "leave-balance"
        assert arguments["session_id"] == "s"


def test_identity_promotion_runs_after_the_guardrail_scan(hr_interceptor):
    """The promotion step runs on the params the guardrail scan just
    returned. The scan's INPUT masking must never touch
    caller_employee_id, so the final value is the token's claim.
    """
    hr_interceptor._bedrock.apply_guardrail.return_value = {
        "action": "GUARDRAIL_INTERVENED",
        "assessments": [],
        "outputs": [{"text": "{MASKED}"}],
    }
    jwt = _jwt({"employee_id": "E1", "agent_id": "leave-balance"})
    out = hr_interceptor.handler(
        _hr_event(
            arguments={
                "caller_employee_id": "ignored",
                "some_text": "my email a@b.com",
            },
            headers={"Authorization": f"Bearer {jwt}", "Mcp-Session-Id": "s"},
        ),
        None,
    )
    arguments = _arguments_after(out)
    assert arguments["caller_employee_id"] == "E1"
    # The scan masked the free-text argument before the promotion ran;
    # the masked version is what the target sees.
    assert arguments["some_text"] == "{MASKED}"


@pytest.mark.parametrize("prefix", ["hr-ops", "hr-payroll", "hr-finance"])
def test_identity_promotion_runs_for_each_hr_target(hr_interceptor, prefix):
    jwt = _jwt({"employee_id": "E1", "agent_id": "leave-balance"})
    out = hr_interceptor.handler(
        _hr_event(
            tool=f"{prefix}___any_tool",
            arguments={"caller_employee_id": "SPOOFED"},
            headers={"Authorization": f"Bearer {jwt}"},
        ),
        None,
    )
    assert _arguments_after(out)["caller_employee_id"] == "E1"
