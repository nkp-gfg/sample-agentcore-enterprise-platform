# Adapted from fullstack-solution-template-for-agentcore
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import contextvars
import json
import logging
import os
import threading
import time
from contextlib import contextmanager

import boto3
from botocore.exceptions import ClientError

from .models import CodeIntExecutionResult

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

CODE_INTERPRETER_ID = "aws.codeinterpreter.v1"
SESSION_TIMEOUT_SECONDS = 900
MAX_START_ATTEMPTS_PER_TURN = 3


class CodeInterpreterSessionError(Exception):
    """No Code Interpreter session is available to this tool call."""


class _TurnSession:
    """The one Code Interpreter session a single agent turn may use."""

    def __init__(self):
        self.lock = threading.Lock()
        self.ci_client = None
        self.session_id = ""
        self.start_attempts = 0
        self.closed = False

    def close(self) -> None:
        with self.lock:
            self.closed = True
            ci_client, session_id = self.ci_client, self.session_id
            self.ci_client, self.session_id = None, ""
        if not session_id:
            return
        try:
            ci_client.stop_code_interpreter_session(
                codeInterpreterIdentifier=CODE_INTERPRETER_ID,
                sessionId=session_id,
            )
        except Exception as e:  # noqa: BLE001 — the session still expires on its timeout
            logger.error(
                "Failed to stop code interpreter session %s: %s", session_id, e
            )


_current_turn: contextvars.ContextVar[_TurnSession | None] = contextvars.ContextVar(
    "code_interpreter_turn", default=None
)


@contextmanager
def code_interpreter_turn():
    """Scope Code Interpreter use to one agent turn.

    Every tool call made inside the scope shares a single session, started on
    first use and stopped when the scope exits. Session ids supplied by the
    model are ignored. Tool calls made outside a scope are refused.

    Enter the scope before creating the ClaudeSDKClient so the SDK's tool
    handler tasks inherit it.
    """
    turn = _TurnSession()
    token = _current_turn.set(turn)
    try:
        yield
    finally:
        turn.close()
        try:
            _current_turn.reset(token)
        except ValueError:
            # The generator was finalized from a different context.
            _current_turn.set(None)


class CodeInterpreterClient:
    """Client for AgentCore Code Interpreter."""

    def __init__(self, region_name: str | None = None):
        region = region_name or os.environ.get(
            "AWS_REGION", os.environ.get("AWS_DEFAULT_REGION", "us-east-1")
        )
        self.ci_client = boto3.client("bedrock-agentcore", region_name=region)

    def _create_sessionid(self) -> str:
        try:
            session_response = self.ci_client.start_code_interpreter_session(
                codeInterpreterIdentifier=CODE_INTERPRETER_ID,
                name="mcpInteractionSession",
                sessionTimeoutSeconds=SESSION_TIMEOUT_SECONDS,
            )
        except ClientError as e:
            logger.error("***** Exception in create session %s", str(e))
            raise CodeInterpreterSessionError(f"Failed to create session: {e!s}") from e

        code_int_session_id = session_response["sessionId"]
        return code_int_session_id

    def _turn_session_id(self) -> str:
        turn = _current_turn.get()
        if turn is None:
            raise CodeInterpreterSessionError(
                "Code Interpreter is only available during an agent turn"
            )
        with turn.lock:
            if turn.closed:
                raise CodeInterpreterSessionError(
                    "The agent turn that owned this session has ended"
                )
            if turn.session_id:
                return turn.session_id
            if turn.start_attempts >= MAX_START_ATTEMPTS_PER_TURN:
                raise CodeInterpreterSessionError(
                    "Too many failed Code Interpreter session starts in this turn"
                )
            turn.start_attempts += 1
            turn.session_id = self._create_sessionid()
            turn.ci_client = self.ci_client
            return turn.session_id

    def _invoke_code_interpreter(
        self, operation: str, args: dict | None = None, code_int_session_id: str = ""
    ) -> CodeIntExecutionResult:
        start_time = time.time()
        requested_session_id = code_int_session_id
        code_int_session_id = self._turn_session_id()
        if requested_session_id and requested_session_id != code_int_session_id:
            logger.warning(
                "Ignoring code_int_session_id that does not belong to this turn"
            )
        try:
            response = self.ci_client.invoke_code_interpreter(
                codeInterpreterIdentifier=CODE_INTERPRETER_ID,
                sessionId=code_int_session_id,
                name=operation,
                arguments=args if args else {},
            )
            output = ""
            for event in response["stream"]:
                output = json.dumps(event["result"], indent=2)

            execution_time = time.time() - start_time

            return CodeIntExecutionResult(
                output=output,
                code_int_session_id=code_int_session_id,
                execution_time=execution_time,
                success=True,
            )
        except ClientError as e:
            logger.error("***** Exception in code interpreter invocation %s", str(e))
            execution_time = time.time() - start_time
            return CodeIntExecutionResult(
                output="",
                code_int_session_id=code_int_session_id,
                error=str(e),
                execution_time=execution_time,
                success=False,
            )

    def execute_code(
        self, code: str, language: str = "python", code_int_session_id: str = ""
    ) -> CodeIntExecutionResult:
        args = {"code": code, "language": language, "clearContext": False}
        return self._invoke_code_interpreter("executeCode", args, code_int_session_id)

    def execute_command(
        self, command: str, code_int_session_id: str = ""
    ) -> CodeIntExecutionResult:
        args = {"command": command}
        return self._invoke_code_interpreter(
            "executeCommand", args, code_int_session_id
        )

    def write_files(
        self, files: list, code_int_session_id: str = ""
    ) -> CodeIntExecutionResult:
        args = {"content": files}
        return self._invoke_code_interpreter("writeFiles", args, code_int_session_id)

    def read_files(
        self, paths: list, code_int_session_id: str = ""
    ) -> CodeIntExecutionResult:
        args = {"paths": paths}
        return self._invoke_code_interpreter("readFiles", args, code_int_session_id)
