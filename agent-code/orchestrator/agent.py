"""Workshop orchestrator agent — deployed to AgentCore Runtime."""

import os

from bedrock_agentcore.runtime import BedrockAgentCoreApp
from strands import Agent
from strands.models import BedrockModel

app = BedrockAgentCoreApp()

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

SYSTEM_PROMPT = """You are a helpful workshop assistant for the AgentCore Platform Accelerator.
You help participants understand and use Amazon Bedrock AgentCore services."""


@app.entrypoint
async def invoke(payload=None):
    query = payload.get("prompt", "Hello!") if payload else "Hello!"
    model = BedrockModel(model_id=MODEL_ID, **_GUARDRAIL_KWARGS)
    agent = Agent(system_prompt=SYSTEM_PROMPT, model=model)
    response = agent(query)
    return {"status": "success", "response": response.message["content"][0]["text"]}


if __name__ == "__main__":
    app.run()
