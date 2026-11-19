# Adapted from fullstack-solution-template-for-agentcore
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import contextvars
import json
import logging
import os
import threading
import time

import boto3
from botocore.exceptions import ClientError

from .models import CodeIntExecutionResult

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

SESSION_TIMEOUT_SECONDS = 900
# Start a fresh sandbox slightly before the service would expire the old one.
_SESSION_RENEW_MARGIN_SECONDS = 30


class CodeInterpreterClient:
    """Client for AgentCore Code Interpreter.

    Every runtime shares one IAM role that may invoke any session of the
    managed interpreter, so the session id is the only thing separating one
    caller's sandbox from another's. Sessions are therefore created here and
    keyed by the caller the entrypoint verified (JWT subject plus runtime
    session id). Callers never pass a session id in.
    """

    def __init__(self, region_name: str = None):
        region = region_name or os.environ.get(
            "AWS_REGION", os.environ.get("AWS_DEFAULT_REGION", "us-east-1")
        )
        self.ci_client = boto3.client("bedrock-agentcore", region_name=region)
        self._caller: contextvars.ContextVar[tuple[str, str] | None] = (
            contextvars.ContextVar(f"code_int_caller_{id(self)}", default=None)
        )
        self._sessions: dict[tuple[str, str], tuple[str, float]] = {}
        self._lock = threading.Lock()

    def bind_caller(self, user_id: str, runtime_session_id: str) -> None:
        """Bind tool calls made from the current context to a verified caller.

        Must be called by the entrypoint with the subject returned by
        extract_user_id_from_context and the runtime session id, before the
        model can invoke any tool. Tasks started afterwards inherit the binding.
        """
        if not user_id or not runtime_session_id:
            raise ValueError(
                "Code Interpreter caller requires a user id and session id"
            )
        self._caller.set((str(user_id), str(runtime_session_id)))

    def clear_caller(self) -> None:
        self._caller.set(None)

    def _create_sessionid(self) -> str:
        try:
            session_response = self.ci_client.start_code_interpreter_session(
                codeInterpreterIdentifier="aws.codeinterpreter.v1",
                name="mcpInteractionSession",
                sessionTimeoutSeconds=SESSION_TIMEOUT_SECONDS,
            )
        except ClientError as e:
            logging.error("***** Exception in create session %s", str(e))
            raise Exception(f"Failed to create session: {str(e)}")

        code_int_session_id = session_response["sessionId"]
        return code_int_session_id

    def _session_for(self, caller: tuple[str, str], renew: bool = False) -> str:
        with self._lock:
            entry = self._sessions.get(caller)
            now = time.monotonic()
            if (
                renew
                or entry is None
                or now - entry[1]
                >= SESSION_TIMEOUT_SECONDS - _SESSION_RENEW_MARGIN_SECONDS
            ):
                entry = (self._create_sessionid(), now)
                self._sessions[caller] = entry
            return entry[0]

    def _invoke_code_interpreter(
        self, operation: str, args: dict = None
    ) -> CodeIntExecutionResult:
        start_time = time.time()
        caller = self._caller.get()
        if caller is None:
            logger.error("Code interpreter invoked without a verified caller")
            return CodeIntExecutionResult(
                output="",
                code_int_session_id="",
                error="Code Interpreter is unavailable: no verified caller for this request",
                execution_time=time.time() - start_time,
                success=False,
            )

        code_int_session_id = ""
        try:
            code_int_session_id = self._session_for(caller)
            try:
                response = self._invoke(operation, args, code_int_session_id)
            except ClientError as e:
                if (
                    e.response.get("Error", {}).get("Code")
                    != "ResourceNotFoundException"
                ):
                    raise
                code_int_session_id = self._session_for(caller, renew=True)
                response = self._invoke(operation, args, code_int_session_id)
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
            logging.error("***** Exception in code interpreter invocation %s", str(e))
            execution_time = time.time() - start_time
            return CodeIntExecutionResult(
                output="",
                code_int_session_id=code_int_session_id,
                error=str(e),
                execution_time=execution_time,
                success=False,
            )

    def _invoke(self, operation: str, args: dict | None, code_int_session_id: str):
        return self.ci_client.invoke_code_interpreter(
            codeInterpreterIdentifier="aws.codeinterpreter.v1",
            sessionId=code_int_session_id,
            name=operation,
            arguments=args if args else {},
        )

    def execute_code(
        self, code: str, language: str = "python"
    ) -> CodeIntExecutionResult:
        args = {"code": code, "language": language, "clearContext": False}
        return self._invoke_code_interpreter("executeCode", args)

    def execute_command(self, command: str) -> CodeIntExecutionResult:
        args = {"command": command}
        return self._invoke_code_interpreter("executeCommand", args)

    def write_files(self, files: list) -> CodeIntExecutionResult:
        args = {"content": files}
        return self._invoke_code_interpreter("writeFiles", args)

    def read_files(self, paths: list) -> CodeIntExecutionResult:
        args = {"paths": paths}
        return self._invoke_code_interpreter("readFiles", args)
