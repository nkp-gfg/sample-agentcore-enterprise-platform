# Adapted from fullstack-solution-template-for-agentcore
"""Core Code Interpreter tools for AgentCore."""

import json
import logging

from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)

# Returned to the caller in place of the AWS error, whose message can name the
# denied action and resource of the runtime role.
EXECUTION_FAILED = "Code execution failed"


def error_code(exc: BaseException) -> str:
    """Return the AWS error code for a failure, or the exception type name."""
    if isinstance(exc, ClientError):
        return exc.response.get("Error", {}).get("Code") or type(exc).__name__
    return type(exc).__name__


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

            code_client = CodeInterpreter(self.region)
            code_client.start()
            self._code_client = code_client
            logger.info(f"Started code interpreter in {self.region}")
        return self._code_client

    def cleanup(self):
        """
        Clean up code interpreter session.

        Note: AgentCore automatically cleans up inactive sessions after timeout,
        so manual cleanup is optional but recommended for immediate resource release.
        """
        if self._code_client:
            self._code_client.stop()
            self._code_client = None

    def execute_python_securely(self, code: str) -> str:
        """
        Execute Python code in a secure AgentCore CodeInterpreter sandbox.

        Args:
            code: Python code to execute

        Returns:
            JSON string with execution result
        """
        operation = "startCodeInterpreterSession"
        try:
            client = self._get_code_interpreter_client()
            operation = "executeCode"
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
        except Exception as e:  # noqa: BLE001 — the tool result must never carry the error text
            logger.error("Code interpreter %s failed: %s", operation, error_code(e))
            return json.dumps({"error": EXECUTION_FAILED}, indent=2)
