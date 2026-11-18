# Adapted from fullstack-solution-template-for-agentcore
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

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


class CodeInterpreterClosedError(RuntimeError):
    """Raised when a tool runs after the owning request has released the sandbox."""


class CodeInterpreterClient:
    """Client for AgentCore Code Interpreter.

    One instance belongs to one agent request. Every tool call in that request
    shares a single sandbox session, and close() must be called when the
    request ends; after that the instance refuses to start another session.
    """

    def __init__(self, region_name: str = None):
        region = region_name or os.environ.get(
            "AWS_REGION", os.environ.get("AWS_DEFAULT_REGION", "us-east-1")
        )
        self.ci_client = boto3.client("bedrock-agentcore", region_name=region)
        self._session_id = None
        self._closed = False
        self._lock = threading.Lock()

    def _get_session_id(self) -> str:
        with self._lock:
            if self._closed:
                raise CodeInterpreterClosedError(
                    "Code interpreter session has already been released"
                )
            if self._session_id is None:
                try:
                    session_response = self.ci_client.start_code_interpreter_session(
                        codeInterpreterIdentifier="aws.codeinterpreter.v1",
                        name="mcpInteractionSession",
                        sessionTimeoutSeconds=900,
                    )
                except ClientError as e:
                    logging.error("***** Exception in create session %s", str(e))
                    raise Exception(f"Failed to create session: {str(e)}")
                self._session_id = session_response["sessionId"]
            return self._session_id

    def close(self) -> None:
        """Stop the request's session and refuse to start another."""
        with self._lock:
            self._closed = True
            code_int_session_id = self._session_id
            self._session_id = None
        if code_int_session_id is None:
            return
        try:
            self.ci_client.stop_code_interpreter_session(
                codeInterpreterIdentifier="aws.codeinterpreter.v1",
                sessionId=code_int_session_id,
            )
        except Exception as e:  # noqa: BLE001 — close() runs in finally blocks
            logger.warning("Failed to stop code interpreter session: %s", str(e))

    def _invoke_code_interpreter(
        self, operation: str, args: dict = None
    ) -> CodeIntExecutionResult:
        start_time = time.time()
        code_int_session_id = ""
        try:
            code_int_session_id = self._get_session_id()

            response = self.ci_client.invoke_code_interpreter(
                codeInterpreterIdentifier="aws.codeinterpreter.v1",
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
            logging.error("***** Exception in code interpreter invocation %s", str(e))
            execution_time = time.time() - start_time
            return CodeIntExecutionResult(
                output="",
                code_int_session_id=code_int_session_id,
                error=str(e),
                execution_time=execution_time,
                success=False,
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
