"""Region the agent's AWS clients must use."""

import os


def runtime_region() -> str:
    """Return the deployment region for Bedrock, Memory, Code Interpreter, and SSM.

    RuntimeStack injects AWS_REGION_NAME from platform.yaml and AgentCore Runtime
    sets AWS_REGION, so a deployed agent always has one. There is deliberately no
    hard-coded default: a silent fallback would send calls to the wrong region.
    """
    for name in ("AWS_REGION_NAME", "AWS_REGION", "AWS_DEFAULT_REGION"):
        value = os.environ.get(name, "").strip()
        if value:
            return value
    raise RuntimeError(
        "No AWS region configured: set AWS_REGION (AgentCore Runtime sets it for you)"
    )
