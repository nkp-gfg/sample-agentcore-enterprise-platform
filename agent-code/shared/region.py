"""Region the agent's AWS clients must use."""

import os

# Platform region (Ireland). RuntimeStack injects AWS_REGION_NAME from
# platform.yaml; the default only applies when that variable is absent.
DEFAULT_REGION = "eu-west-1"


def runtime_region() -> str:
    """Return the deployment region for Memory, Code Interpreter, and SSM."""
    return os.environ.get("AWS_REGION_NAME", "").strip() or DEFAULT_REGION
