"""One factory for every `ChatBedrock` in the god agent.

All ten agents (one god, three departments, six leaves) go through this
module. The factory is the only call site that constructs a `ChatBedrock`, so
`tests/test_god_agent_build.py` can assert "every model carries the
guardrail" by walking the compiled graphs and failing if any model lacks
`guardrails=...`.

The guardrail identifier and version come from SSM parameters published by
the platform (`/{project}/{env}/agents/guardrail-id` and `.../guardrail-version`).
RuntimeStack also sets `GUARDRAIL_ID` / `GUARDRAIL_VERSION` on the container
for compatibility with the workshop patterns, so we prefer those and fall
back to SSM — a deployment without them fails loudly rather than silently
skipping the guardrail block.
"""

from __future__ import annotations

import logging
import os
from functools import lru_cache

from langchain_aws import ChatBedrock
from shared.region import runtime_region
from shared.ssm import get_ssm_parameter

logger = logging.getLogger(__name__)


# Model per `custom-app-plan/god-agent.md`:
#   "`openai.gpt-oss-120b-1:0` through the `ChatBedrock` instance this
#   platform already builds. The doc samples that name Gemini, Claude, or
#   `eu.` profiles are not the model for this account."
DEFAULT_MODEL_ID = "openai.gpt-oss-120b-1:0"


def _ssm_base() -> str:
    project = os.environ.get("PROJECT_NAME", "").strip()
    environment = os.environ.get("ENVIRONMENT", "").strip()
    if not project or not environment:
        raise RuntimeError(
            "PROJECT_NAME and ENVIRONMENT must be set to resolve the "
            "guardrail SSM parameters — RuntimeStack injects both."
        )
    return f"/{project}/{environment}"


@lru_cache(maxsize=1)
def _guardrail_block() -> dict[str, dict[str, str]]:
    """Return the ``guardrails=...`` kwarg every model must carry.

    The block is cached for the container's lifetime — the guardrail id does
    not change without a redeploy, and the SSM read happens once per boot.
    """

    identifier = os.environ.get("GUARDRAIL_ID", "").strip()
    version = os.environ.get("GUARDRAIL_VERSION", "").strip()

    if not identifier:
        identifier = get_ssm_parameter(f"{_ssm_base()}/agents/guardrail-id")
    if not version:
        try:
            version = get_ssm_parameter(f"{_ssm_base()}/agents/guardrail-version")
        except Exception as exc:  # noqa: BLE001 — a missing version pins to DRAFT
            logger.warning(
                "[GUARDRAIL] no published version (%s), falling back to DRAFT",
                exc,
            )
            version = "DRAFT"

    if not identifier:
        # `require_guardrails: true` in production means IAM denies any
        # inference call without a guardrail (see stacks/runtime_stack.py
        # `DenyUngovernedInference`). An empty identifier is a hard fail here
        # rather than a silent `AccessDenied` on the first turn.
        raise RuntimeError(
            "No guardrail configured for the god agent: set GUARDRAIL_ID or "
            "publish /{project}/{env}/agents/guardrail-id. production-"
            "principles.md requires every one of the ten `ChatBedrock` "
            "instances to carry the block."
        )

    return {
        "guardrails": {
            "guardrailIdentifier": identifier,
            "guardrailVersion": version,
        }
    }


def build_model(
    *,
    model_id: str | None = None,
    temperature: float = 0.1,
    streaming: bool = True,
) -> ChatBedrock:
    """Build a `ChatBedrock` that always carries the platform guardrail.

    The model id defaults to `openai.gpt-oss-120b-1:0`; MODEL_ID (injected by
    RuntimeStack from `agents.model_id` in `platform.yaml`) wins when set so
    the environment can override to a different in-region Bedrock model, but
    `eu.` and `us.` cross-region profiles stay blocked by the organisation
    SCP (see `custom-app-plan/god-agent.md` and `review.md`).
    """

    resolved_model_id = (
        model_id or os.environ.get("MODEL_ID", "").strip() or DEFAULT_MODEL_ID
    )
    return ChatBedrock(
        model_id=resolved_model_id,
        region_name=runtime_region(),
        temperature=temperature,
        streaming=streaming,
        beta_use_converse_api=True,
        **_guardrail_block(),
    )


def guardrail_block_for_tests() -> dict[str, dict[str, str]]:
    """Expose the resolved guardrail kwarg so tests can assert on it.

    Production code never imports this: the agent passes the model instance
    itself around, and the model keeps the block on the Converse call.
    """

    return _guardrail_block()


def _reset_cache_for_tests() -> None:
    _guardrail_block.cache_clear()
