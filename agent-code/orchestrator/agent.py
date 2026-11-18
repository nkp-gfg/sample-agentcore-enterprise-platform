"""Workshop orchestrator agent — deployed to AgentCore Runtime."""

import logging
import os

from bedrock_agentcore.runtime import BedrockAgentCoreApp
from strands import Agent
from strands.models import BedrockModel

logger = logging.getLogger(__name__)

app = BedrockAgentCoreApp()

# Cross-region inference profile — current (not Legacy-flagged). Override per
# deployment via the MODEL_ID environment variable (see app.py / deploy.sh).
DEFAULT_MODEL_ID = "us.anthropic.claude-sonnet-4-6"
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

SYSTEM_PROMPT = """You are a helpful workshop assistant for the AgentCore Platform Accelerator.
You help participants understand and use Amazon Bedrock AgentCore services."""


@app.entrypoint
async def invoke(payload=None):
    query = payload.get("prompt", "Hello!") if payload else "Hello!"
    try:
        model = BedrockModel(model_id=MODEL_ID, **_GUARDRAIL_KWARGS)
        agent = Agent(system_prompt=SYSTEM_PROMPT, model=model)
        response = agent(query)
        text = response.message["content"][0]["text"]
    except Exception:
        # BedrockAgentCoreApp would return str(exception), and AWS errors name
        # the account, role and denied resource. Keep the detail in the logs.
        logger.exception("Agent run failed")
        return {"status": "error", "error": "Agent run failed"}
    return {"status": "success", "response": text}


if __name__ == "__main__":
    app.run()
