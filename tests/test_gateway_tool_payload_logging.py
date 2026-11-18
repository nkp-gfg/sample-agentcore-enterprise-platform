"""Caller text sent to the default gateway tool must not be stored in logs.

The Lambda runtime attaches a handler to the root logger and formats
``%(message)s`` into the line it writes to the telemetry sink (awslambdaric
``LambdaLoggerHandler.emit`` and the plain-text formatter in
``_setup_logging``). These tests install that same handler, pass the tool
argument map through ``json.loads`` the way ``LambdaMarshaller.unmarshal_request``
does, and invoke the handlers the gateway stack deploys.

They fail while those handlers still serialize the argument object or return
the exception string to the caller.
"""

from __future__ import annotations

import importlib.util
import json
import logging
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
# Obvious placeholder. Not a credential.
MARKER = "placeholder-sensitive-text"

# awslambdaric.bootstrap._setup_logging, plain-text branch.
_RUNTIME_TEXT_FORMAT = (
    "[%(levelname)s]\t%(asctime)s.%(msecs)03dZ\t%(aws_request_id)s\t%(message)s\n"
)
_RUNTIME_TEXT_DATEFMT = "%Y-%m-%dT%H:%M:%S"


class _ListSink:
    """Stand-in for StandardLogSink.log / FramedTelemetryLogSink.log.

    Both write the already-formatted message through unchanged. This sink
    keeps those strings so the test can read them.
    """

    def __init__(self) -> None:
        self.lines: list[str] = []

    def log(self, msg: str, frame_type: bytes | None = None) -> None:
        self.lines.append(msg)


class _LambdaLoggerFilter(logging.Filter):
    """Same role as awslambdaric.bootstrap.LambdaLoggerFilter.

    The plain-text formatter reads ``aws_request_id``. The runtime filter
    sets it (empty outside an invocation) and does not drop the record.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        record.aws_request_id = ""
        return True


class _LambdaLoggerHandler(logging.Handler):
    """Same emit path as awslambdaric.bootstrap.LambdaLoggerHandler."""

    def __init__(self, sink: _ListSink) -> None:
        super().__init__()
        self.sink = sink
        self.addFilter(_LambdaLoggerFilter())

    def emit(self, record: logging.LogRecord) -> None:
        self.sink.log(self.format(record))


class _ClientContext:
    def __init__(self, custom: dict) -> None:
        self.custom = custom


class _LambdaContext:
    """client_context.custom is where the gateway places bedrockAgentCoreToolName."""

    def __init__(self, tool_name: str) -> None:
        self.aws_request_id = "req-placeholder"
        self.client_context = _ClientContext(
            {
                "bedrockAgentCoreToolName": tool_name,
                "bedrockAgentCoreAwsRequestId": self.aws_request_id,
            }
        )


def _load(module_name: str, path: Path):
    spec = importlib.util.spec_from_file_location(module_name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _gateway_event(arguments: dict) -> dict:
    """The invocation body is the tool argument object, then json.loads."""
    return json.loads(json.dumps(arguments))


def _invoke(function, event, context):
    root = logging.getLogger()
    previous_level = root.level
    sink = _ListSink()
    runtime_handler = _LambdaLoggerHandler(sink)
    runtime_handler.setFormatter(
        logging.Formatter(_RUNTIME_TEXT_FORMAT, _RUNTIME_TEXT_DATEFMT)
    )
    root.addHandler(runtime_handler)
    try:
        result = function(event, context)
    finally:
        root.removeHandler(runtime_handler)
        root.setLevel(previous_level)
    return result, "".join(sink.lines)


def test_text_analysis_success_does_not_log_caller_text():
    handler = _load(
        "sample_tool_handler", REPO / "tools" / "sample_tool" / "handler.py"
    ).handler
    event = _gateway_event({"text": MARKER, "N": 3})

    result, logs = _invoke(
        handler, event, _LambdaContext("sample-tool___text_analysis_tool")
    )

    assert result["content"][0]["text"].startswith("Text analysis results:")
    assert "Word count: 1" in result["content"][0]["text"]
    # The tool name is still logged; the argument object is not. Seeing the
    # tool name also proves the sink received this invocation's records.
    assert "text_analysis_tool" in logs
    assert MARKER not in logs
    assert json.dumps(event) not in logs


def test_text_analysis_error_does_not_log_caller_text_or_return_exception():
    handler = _load(
        "sample_tool_handler_error", REPO / "tools" / "sample_tool" / "handler.py"
    ).handler
    # A string N is a caller-supplied argument. most_common rejects it, and the
    # handler logs the event before that failure.
    event = _gateway_event({"text": MARKER, "N": MARKER})

    result, logs = _invoke(
        handler, event, _LambdaContext("sample-tool___text_analysis_tool")
    )

    assert "error" in result
    assert "content" not in result
    assert "text_analysis_tool" in logs
    assert MARKER not in logs
    assert json.dumps(event) not in logs
    assert MARKER not in result["error"]
    assert "not supported between instances" not in result["error"]


def test_unexpected_tool_does_not_log_caller_text():
    handler = _load(
        "sample_tool_handler_unexpected",
        REPO / "tools" / "sample_tool" / "handler.py",
    ).handler
    event = _gateway_event({"text": MARKER, "N": 3})

    result, logs = _invoke(
        handler, event, _LambdaContext("sample-tool___other_tool")
    )

    assert "error" in result
    assert "other_tool" in logs
    assert MARKER not in logs
    assert json.dumps(event) not in logs
    assert MARKER not in result["error"]


def test_egress_interceptor_does_not_log_caller_text(monkeypatch):
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
    monkeypatch.setenv("AWS_EC2_METADATA_DISABLED", "true")
    monkeypatch.delenv("GUARDRAIL_ID", raising=False)
    interceptor = _load(
        "egress_interceptor_handler",
        REPO / "tools" / "egress_interceptor" / "handler.py",
    )
    interceptor._GUARDRAIL_ID = ""
    event = {
        "mcp": {
            "gatewayRequest": {
                "params": {
                    "name": "sample-tool___text_analysis_tool",
                    "arguments": {"text": MARKER, "N": 3},
                }
            }
        }
    }

    result, logs = _invoke(interceptor.handler, event, None)

    assert result["interceptorOutputVersion"] == "1.0"
    # With no guardrail id the request is forwarded unchanged. The log is the leak.
    forwarded = json.dumps(result)
    assert MARKER in forwarded
    assert MARKER not in logs
    assert json.dumps(event)[:2000] not in logs


def test_runtime_formatter_keeps_the_log_message():
    """The runtime formatter copies the record message into the sink line.

    Guards the stand-in: a capture that dropped the message would hide the bug.
    """
    root = logging.getLogger()
    previous_level = root.level
    sink = _ListSink()
    runtime_handler = _LambdaLoggerHandler(sink)
    runtime_handler.setFormatter(
        logging.Formatter(_RUNTIME_TEXT_FORMAT, _RUNTIME_TEXT_DATEFMT)
    )
    root.setLevel(logging.INFO)
    root.addHandler(runtime_handler)
    try:
        root.info("probe %s", MARKER)
    finally:
        root.removeHandler(runtime_handler)
        root.setLevel(previous_level)

    rendered = "".join(sink.lines)
    assert MARKER in rendered
    assert rendered.startswith("[INFO]")
