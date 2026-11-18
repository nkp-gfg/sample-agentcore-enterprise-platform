# Adapted from fullstack-solution-template-for-agentcore
"""Core Code Interpreter tools for AgentCore."""

import json
import logging
import threading

logger = logging.getLogger(__name__)


class CodeInterpreterClosedError(RuntimeError):
    """Raised when code runs after the owning request has released the sandbox."""


class CodeInterpreterTools:
    """Tools for code execution via AgentCore Code Interpreter.

    One instance belongs to one agent request. It starts at most one sandbox
    session, and ``cleanup()`` must be called when the request ends; after
    that the instance refuses to start another session.
    """

    def __init__(self, region: str):
        """
        Initialize the code interpreter tools.

        Args:
            region: AWS region for code interpreter
        """
        self.region = region
        self._code_client = None
        self._identifier = None
        self._session_id = None
        self._closed = False
        # Frameworks run tool calls on worker threads, possibly in parallel,
        # and cleanup() can run while a tool call is still in flight.
        self._lock = threading.Lock()

    def _get_session(self):
        """Return (client, identifier, session_id), starting the session once."""
        with self._lock:
            if self._closed:
                raise CodeInterpreterClosedError(
                    "Code interpreter session has already been released"
                )
            if self._code_client is None:
                from bedrock_agentcore.tools.code_interpreter_client import (
                    CodeInterpreter,
                )

                client = CodeInterpreter(self.region)
                client.start()
                self._code_client = client
                self._identifier = client.identifier
                self._session_id = client.session_id
                logger.info(f"Started code interpreter in {self.region}")
            return self._code_client, self._identifier, self._session_id

    def cleanup(self):
        """Stop the code interpreter session and refuse to start another."""
        with self._lock:
            self._closed = True
            client = self._code_client
            identifier = self._identifier
            session_id = self._session_id
            self._code_client = None
            self._identifier = None
            self._session_id = None
        if client is None:
            return
        try:
            client.data_plane_client.stop_code_interpreter_session(
                codeInterpreterIdentifier=identifier, sessionId=session_id
            )
        except Exception as e:  # noqa: BLE001 — cleanup runs in finally blocks
            logger.warning(f"Failed to stop code interpreter session: {e}")

    def execute_python_securely(self, code: str) -> str:
        """
        Execute Python code in a secure AgentCore CodeInterpreter sandbox.

        Args:
            code: Python code to execute

        Returns:
            JSON string with execution result
        """
        try:
            client, identifier, session_id = self._get_session()
            # Invoke the bound session directly: CodeInterpreter.invoke starts a
            # fresh session when its own one has been stopped by cleanup().
            response = client.data_plane_client.invoke_code_interpreter(
                codeInterpreterIdentifier=identifier,
                sessionId=session_id,
                name="executeCode",
                arguments={"code": code, "language": "python", "clearContext": False},
            )

            results = []
            for event in response["stream"]:
                if "result" in event:
                    results.append(event["result"])

            return (
                json.dumps(results, indent=2)
                if results
                else json.dumps({"error": "No results returned"}, indent=2)
            )
        except Exception as e:
            logger.error(f"Code execution failed: {e}")
            return json.dumps({"error": f"Code execution failed: {str(e)}"}, indent=2)
