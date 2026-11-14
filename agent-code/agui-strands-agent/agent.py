# Adapted from fullstack-solution-template-for-agentcore
"""AG-UI Strands agent with Gateway MCP tools, Memory, and Code Interpreter.

Uses ag-ui-strands to produce native AG-UI SSE events.
AgentCore proxies these unchanged when deployed with --protocol AGUI.
"""

import logging
import os

from ag_ui.core import RunAgentInput, RunErrorEvent
from ag_ui_strands import StrandsAgent
from bedrock_agentcore.memory.integrations.strands.config import AgentCoreMemoryConfig
from bedrock_agentcore.memory.integrations.strands.session_manager import (
    AgentCoreMemorySessionManager,
)
from bedrock_agentcore.runtime import BedrockAgentCoreApp, RequestContext
from shared.auth import extract_user_id_from_context
from shared.region import runtime_region
from strands import Agent
from strands.models import BedrockModel
from tools.code_interpreter import StrandsCodeInterpreterTools
from tools.gateway import create_gateway_mcp_client

logger = logging.getLogger(__name__)

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

SYSTEM_PROMPT = (
    "You are a helpful assistant with access to tools via the Gateway and Code Interpreter. "
    "When asked about your tools, list them and explain what they do."
)


def _build_model() -> BedrockModel:
    return BedrockModel(
        model_id=MODEL_ID,
        region_name=runtime_region(),
        temperature=0.1,
        **_GUARDRAIL_KWARGS,
    )


def _create_session_manager(
    user_id: str, session_id: str
) -> AgentCoreMemorySessionManager:
    memory_id = os.environ.get("MEMORY_ID")
    if not memory_id:
        raise ValueError("MEMORY_ID environment variable is required")
    config = AgentCoreMemoryConfig(
        memory_id=memory_id, session_id=session_id, actor_id=user_id
    )
    return AgentCoreMemorySessionManager(
        agentcore_memory_config=config,
        region_name=runtime_region(),
    )


def _create_agent(user_id: str, session_id: str) -> Agent:
    """Create a Strands Agent with Gateway MCP tools, Memory, and Code Interpreter."""
    tools = []
    try:
        gateway_client = create_gateway_mcp_client()
        if gateway_client is not None:
            tools.append(gateway_client)
    except Exception as e:  # noqa: BLE001 — degrade gracefully on any gateway failure
        logger.warning(
            "[AGENT] Gateway not available, continuing without gateway tools: %s", e
        )

    region = runtime_region()
    code_tools = StrandsCodeInterpreterTools(region)
    tools.append(code_tools.execute_python_securely)

    return Agent(
        name="strands_agent",
        system_prompt=SYSTEM_PROMPT,
        tools=tools,
        model=_build_model(),
        session_manager=_create_session_manager(user_id, session_id),
    )


class ActorAwareStrandsAgent(StrandsAgent):
    """StrandsAgent that creates the agent per-request with fresh MCP context."""

    def __init__(self, *, user_id: str, session_id: str, name: str, description: str):
        self._user_id = user_id
        self._session_id = session_id
        super().__init__(
            agent=Agent(model=_build_model(), system_prompt=SYSTEM_PROMPT),
            name=name,
            description=description,
        )

    async def run(self, input_data: RunAgentInput):
        thread_id = input_data.thread_id or "default"
        self._agents_by_thread[thread_id] = _create_agent(
            self._user_id, self._session_id
        )
        async for event in super().run(input_data):
            yield event


@app.entrypoint
async def invocations(payload: dict, context: RequestContext):
    input_data = RunAgentInput.model_validate(payload)
    try:
        user_id = extract_user_id_from_context(context)
    except ValueError as e:
        # Token missing, malformed, or failed verification. Log the reason,
        # return a generic rejection so the response leaks no auth detail.
        logger.warning("Rejected unverified caller: %s", e)
        yield RunErrorEvent(message="Unauthorized", code="Unauthorized").model_dump(
            mode="json", by_alias=True, exclude_none=True
        )
        return

    agent = ActorAwareStrandsAgent(
        user_id=user_id,
        session_id=input_data.thread_id,
        name="agui_strands_agent",
        description="AG-UI Strands agent with Gateway MCP tools and Code Interpreter",
    )

    try:
        async for event in agent.run(input_data):
            if event is not None:
                yield event.model_dump(mode="json", by_alias=True, exclude_none=True)
    except Exception:
        logger.exception("Agent run failed")
        yield RunErrorEvent(
            message="An internal error occurred. Please try again.",
            code="AgentError",
        ).model_dump(mode="json", by_alias=True, exclude_none=True)


if __name__ == "__main__":
    app.run()
