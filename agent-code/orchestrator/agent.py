"""Workshop orchestrator agent — deployed to AgentCore Runtime."""

import os

from bedrock_agentcore.runtime import BedrockAgentCoreApp
from shared.region import runtime_region
from strands import Agent
from strands.models import BedrockModel

app = BedrockAgentCoreApp()

# Fallback only when MODEL_ID is unset. Deploy injects platform.yaml
# agents.model_id as MODEL_ID (production requires it), so the deployed model
# can be any Bedrock model available in the deployment region.
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

SYSTEM_PROMPT = """You are a helpful workshop assistant for the AgentCore Platform Accelerator.
You help participants understand and use Amazon Bedrock AgentCore services."""


@app.entrypoint
async def invoke(payload=None):
    query = payload.get("prompt", "Hello!") if payload else "Hello!"
    model = BedrockModel(
        model_id=MODEL_ID, region_name=runtime_region(), **_GUARDRAIL_KWARGS
    )
    agent = Agent(system_prompt=SYSTEM_PROMPT, model=model)
    response = agent(query)
    return {"status": "success", "response": response.message["content"][0]["text"]}


if __name__ == "__main__":
    app.run()
