# Adapted from fullstack-solution-template-for-agentcore
"""Core Code Interpreter tools for AgentCore."""

import json
import logging

logger = logging.getLogger(__name__)


class CodeInterpreterTools:
    """Tools for code execution via AgentCore Code Interpreter."""

    def __init__(self, region: str):
        """
        Initialize the code interpreter tools.

        Args:
            region: AWS region for code interpreter
        """
        self.region = region
        self._code_client = None

    def _get_code_interpreter_client(self):
        """Get or create code interpreter client."""
        if self._code_client is None:
            from bedrock_agentcore.tools.code_interpreter_client import CodeInterpreter

            self._code_client = CodeInterpreter(self.region)
            self._code_client.start()
            logger.info(f"Started code interpreter in {self.region}")
        return self._code_client

    def cleanup(self):
        """
        Stop the code interpreter session, if one was started.

        Call this when the request that owns these tools ends. Otherwise the
        session keeps counting against the account's concurrent session quota
        until its timeout.
        """
        client, self._code_client = self._code_client, None
        if client is None:
            return
        try:
            client.stop()
        except Exception as e:  # noqa: BLE001 — the session still expires on its timeout
            logger.error(f"Failed to stop code interpreter session: {e}")

    def execute_python_securely(self, code: str) -> str:
        """
        Execute Python code in a secure AgentCore CodeInterpreter sandbox.

        Args:
            code: Python code to execute

        Returns:
            JSON string with execution result
        """
        client = self._get_code_interpreter_client()
        try:
            response = client.invoke(
                "executeCode",
                {"code": code, "language": "python", "clearContext": False},
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
        except Exception as e:  # noqa: BLE001 — report any failure to the model
            logger.error(f"Code execution failed: {e}")
            return json.dumps({"error": f"Code execution failed: {e!s}"}, indent=2)
