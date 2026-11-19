"""Workshop orchestrator agent — deployed to AgentCore Runtime."""

import hmac
import logging
import os

from bedrock_agentcore.runtime import BedrockAgentCoreApp, RequestContext
from starlette.exceptions import HTTPException
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

# Two ways a caller is accepted, and nothing else:
# - AgentCore Runtime: RuntimeStack injects COGNITO_ISSUER_URL and forwards the
#   caller's Authorization header; the JWT is verified here (shared/auth.py).
# - Local container (docker/docker-compose.yml): the operator sets
#   ORCHESTRATOR_LOCAL_SECRET and sends it in LOCAL_SECRET_HEADER.
# With neither configured every invocation is refused.
LOCAL_SECRET_HEADER = "X-Orchestrator-Local-Secret"
_LOCAL_SECRET = os.environ.get("ORCHESTRATOR_LOCAL_SECRET", "").encode("utf-8")
_JWT_ISSUER_CONFIGURED = bool(os.environ.get("COGNITO_ISSUER_URL", "").strip())

if _JWT_ISSUER_CONFIGURED:
    from shared.auth import extract_user_id_from_context

SYSTEM_PROMPT = """You are a helpful workshop assistant for the AgentCore Platform Accelerator.
You help participants understand and use Amazon Bedrock AgentCore services."""


def _authorize(context: RequestContext | None) -> None:
    """Raise HTTP 403 unless this request's own headers identify a trusted caller."""
    request = getattr(context, "request", None)
    if request is None:
        raise HTTPException(status_code=403, detail="Forbidden")

    presented = request.headers.get(LOCAL_SECRET_HEADER, "").encode("utf-8")
    if _LOCAL_SECRET and presented and hmac.compare_digest(presented, _LOCAL_SECRET):
        return

    authorization = request.headers.get("Authorization")
    if _JWT_ISSUER_CONFIGURED and authorization:
        try:
            extract_user_id_from_context(
                RequestContext(
                    session_id=context.session_id,
                    request_headers={"Authorization": authorization},
                    request=request,
                )
            )
            return
        except ValueError as exc:
            logger.warning("Rejected unverified caller: %s", exc)

    raise HTTPException(status_code=403, detail="Forbidden")


@app.entrypoint
async def invoke(payload, context: RequestContext):
    _authorize(context)
    query = payload.get("prompt", "Hello!") if payload else "Hello!"
    model = BedrockModel(model_id=MODEL_ID, **_GUARDRAIL_KWARGS)
    agent = Agent(system_prompt=SYSTEM_PROMPT, model=model)
    response = agent(query)
    return {"status": "success", "response": response.message["content"][0]["text"]}


if __name__ == "__main__":
    app.run()
