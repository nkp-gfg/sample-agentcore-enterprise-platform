"""Runtime protocol resolution for AgentCore runtimes.

Deliberately free of CDK imports so it stays unit-testable without
aws-cdk-lib (see tests/test_runtime_protocol.py).
"""

# CfnRuntime ProtocolConfiguration allowed values.
PROTOCOLS = ("HTTP", "MCP", "A2A", "AGUI")

# The runtime type normally decides the protocol.
_BY_RUNTIME_TYPE = {"orchestrator": "HTTP", "a2a_agent": "A2A", "mcp_server": "MCP"}

# Protocols where the caller is an external client presenting a Bearer token,
# so the runtime needs an inbound CUSTOM_JWT authorizer. A2A is excluded: those
# runtimes are invoked by the orchestrator, not by end users.
CLIENT_FACING = ("HTTP", "MCP", "AGUI")


def is_agui_pattern(dockerfile_pattern: str = "") -> bool:
    """True when `dockerfile_pattern` serves typed AG-UI SSE events."""
    return dockerfile_pattern.startswith("agui-") or dockerfile_pattern == "god-agent"


def resolve_protocol(runtime_type: str, dockerfile_pattern: str = "") -> str:
    """Protocol for a runtime, accounting for the AG-UI agent patterns.

    The agui-* patterns and `god-agent` serve AG-UI's typed SSE events on the
    same /invocations endpoint as an HTTP agent. The runtime has to be told, or
    it proxies those events as plain HTTP and AG-UI clients cannot consume them.
    """
    protocol = _BY_RUNTIME_TYPE.get(runtime_type, "HTTP")
    if protocol == "HTTP" and is_agui_pattern(dockerfile_pattern):
        return "AGUI"
    return protocol


def needs_jwt_authorizer(protocol: str) -> bool:
    """Whether this protocol should carry an inbound CUSTOM_JWT authorizer."""
    return protocol in CLIENT_FACING
