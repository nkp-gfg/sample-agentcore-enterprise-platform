"""Code Agent — A2A sub-agent for code generation and analysis.

Serves the AgentCore A2A protocol contract (JSON-RPC on port 9000), not the
HTTP `/invocations` contract — see shared/a2a_serve.py for why that matters.
"""

import logging
import os

from shared.a2a_serve import serve_a2a
from strands import Agent
from strands.models import BedrockModel

logging.basicConfig(level=logging.INFO)

# EU geo inference profile, not Legacy-flagged. eu.anthropic.claude-sonnet-4-6
# replaces us.anthropic.claude-sonnet-4-6 so a runtime in eu-west-1 does not
# send inference to US regions. Bedrock routes this profile only to eu-west-1,
# eu-central-1, eu-west-3, eu-north-1, eu-south-1, and eu-south-2. Confirmed
# ACTIVE with list-inference-profiles in eu-west-1 on 2026-11-13. MODEL_ID
# still overrides this default (app.py / deploy.sh). A platform.yaml model_id
# is injected as MODEL_ID and this constant is then unused.
DEFAULT_MODEL_ID = "eu.anthropic.claude-sonnet-4-6"
MODEL_ID = os.environ.get("MODEL_ID", DEFAULT_MODEL_ID)

# When the platform enforces guardrailed-only Bedrock (security.require_guardrails),
# the runtime injects these and IAM denies any inference call without a guardrail.
_GUARDRAIL_KWARGS = (
    {
        "guardrail_id": os.environ["GUARDRAIL_ID"],
        "guardrail_version": os.environ.get("GUARDRAIL_VERSION", "DRAFT"),
    }
    if os.environ.get("GUARDRAIL_ID")
    else {}
)

SYSTEM_PROMPT = """You are a code generation and analysis agent. You help with:
- Writing Python, TypeScript, and other code
- Code review and debugging
- Explaining code patterns and best practices
- Generating infrastructure-as-code templates"""


def build_agent() -> Agent:
    """The agent advertised on the A2A agent card and invoked by callers."""
    return Agent(
        name="code_agent",
        description="Generates, reviews, and explains code, including IaC templates.",
        system_prompt=SYSTEM_PROMPT,
        model=BedrockModel(model_id=MODEL_ID, **_GUARDRAIL_KWARGS),
    )


if __name__ == "__main__":
    serve_a2a(build_agent())
