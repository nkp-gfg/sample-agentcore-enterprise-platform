"""Per-leaf gateway MCP clients.

Each of the six leaves receives exactly one tool. `docs/hr/tools.md` § Routing
maps leaf → gateway tool:

    leave-balance      → hr-ops___get_leave_balance
    leave-eligibility  → hr-ops___check_leave_eligibility
    leave-submit       → hr-ops___submit_leave_request
    compensation       → hr-payroll___get_employee_compensation
    direct-reports     → hr-payroll___list_direct_reports
    allowance          → hr-finance___get_allowance

The leaf's `agent_id` claim is set by the identity pre-token Lambda
(`docs/hr/modules.md` § H3 claims) from the `clientMetadata.calling_agent`
value we pass to `GetResourceOauth2Token` through
`@requires_access_token(custom_parameters={"calling_agent": ...})`. The model
never supplies that value — we hard-code it from the leaf name below.

Cedar binds each tool to exactly one `agent_id`, so a leaf asking for the
wrong tool gets a Cedar deny and the Lambda is never called
(`docs/hr/tools.md` § Cedar permits).
"""

from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable

from bedrock_agentcore.identity.auth import requires_access_token
from langchain_core.tools import BaseTool
from langchain_mcp_adapters.client import MultiServerMCPClient
from shared.jwt_claims import gateway_token_scopes
from ssm_config import gateway_config

logger = logging.getLogger(__name__)


# Fixed `calling_agent` → gateway tool name map. One row per leaf.
LEAF_TOOL_MAP: dict[str, str] = {
    "leave-balance": "hr-ops___get_leave_balance",
    "leave-eligibility": "hr-ops___check_leave_eligibility",
    "leave-submit": "hr-ops___submit_leave_request",
    "compensation": "hr-payroll___get_employee_compensation",
    "direct-reports": "hr-payroll___list_direct_reports",
    "allowance": "hr-finance___get_allowance",
}

# The review node uses its own calling_agent, which carries a Cedar permit no
# leaf has. `custom-app-plan/human-review.md` and `docs/hr/tools.md`.
REVIEW_NODE_CALLING_AGENT = "review-node"
REVIEW_NODE_TOOL = "hr-ops___record_leave_decision"


ALLOWED_CALLING_AGENTS: frozenset[str] = frozenset(LEAF_TOOL_MAP) | {
    REVIEW_NODE_CALLING_AGENT,
}


class UnknownCallingAgent(ValueError):
    """The code tried to request a token with a `calling_agent` the identity
    Lambda would refuse.

    The Lambda rejects anything outside the fixed set in
    `docs/hr/modules.md` § H3 claims, which keeps a mistyped constant from
    silently becoming a no-`agent_id` call that Cedar then denies as "no
    agent_id" rather than "wrong agent_id". We raise before we ever call out.
    """


def _assert_known_calling_agent(calling_agent: str) -> None:
    if calling_agent not in ALLOWED_CALLING_AGENTS:
        raise UnknownCallingAgent(
            f"calling_agent={calling_agent!r} is not one of "
            f"{sorted(ALLOWED_CALLING_AGENTS)}"
        )


# ── Token acquisition ──────────────────────────────────────────────────────


def build_token_fetcher(calling_agent: str) -> Callable[[], Awaitable[str]]:
    """Build an async callable that returns a gateway token for `calling_agent`.

    The returned function fetches a fresh token per call through
    `@requires_access_token` — Token Vault handles refresh and client-secret
    reads. We bind the `custom_parameters` map at build time so the model
    cannot change which leaf we are impersonating; see `review.md`:

        The runtime code sets `calling_agent`, one token per leaf. The model
        cannot set it.
    """

    _assert_known_calling_agent(calling_agent)
    provider = gateway_config().credential_provider_name

    @requires_access_token(
        provider_name=provider,
        auth_flow="M2M",
        scopes=gateway_token_scopes(),
        custom_parameters={"calling_agent": calling_agent},
    )
    async def _fetch(access_token: str) -> str:
        return access_token

    return _fetch


# ── MCP client construction ────────────────────────────────────────────────


def _mcp_client(token: str) -> MultiServerMCPClient:
    gw = gateway_config()
    return MultiServerMCPClient(
        {
            "gateway": {
                "transport": "streamable_http",
                "url": gw.url,
                "headers": {"Authorization": f"Bearer {token}"},
            }
        }
    )


async def fetch_leaf_tool(calling_agent: str) -> BaseTool:
    """Return exactly the one gateway tool this leaf is allowed to call.

    This is the invariant `tests/test_god_agent_build.py` asserts:
        (b) each leaf has its one gateway tool and no other.

    If the gateway returns more tools (filter drift, Cedar misconfiguration),
    we drop everything except the one named in `LEAF_TOOL_MAP[calling_agent]`
    so the leaf never sees a tool it isn't bound to in Cedar.
    """

    if calling_agent not in LEAF_TOOL_MAP:
        raise UnknownCallingAgent(
            f"{calling_agent!r} is not a leaf — only {sorted(LEAF_TOOL_MAP)} "
            "have a gateway tool. The review node calls its tool from "
            "review.py, not from a leaf."
        )
    tool_name = LEAF_TOOL_MAP[calling_agent]

    fetch_token = build_token_fetcher(calling_agent)
    token = await fetch_token()

    client = _mcp_client(token)
    tools = await client.get_tools()
    for tool in tools:
        if getattr(tool, "name", None) == tool_name:
            return tool
    raise RuntimeError(
        f"gateway did not expose {tool_name!r} to leaf {calling_agent!r} — "
        "check the Cedar permit and the agent_id claim the pre-token Lambda "
        "attached to this M2M token."
    )


async def fetch_review_node_tool() -> tuple[BaseTool, str]:
    """Return the `record_leave_decision` tool bound to the review node.

    The second element is the resolved token so the caller can pass it to
    the gateway on the specific JSON-RPC `tools/call` the review node makes.
    The token is held only for the duration of the review node's call —
    nothing writes it to the checkpoint, the scratch state, or a log.
    """

    fetch_token = build_token_fetcher(REVIEW_NODE_CALLING_AGENT)
    token = await fetch_token()

    client = _mcp_client(token)
    tools = await client.get_tools()
    for tool in tools:
        if getattr(tool, "name", None) == REVIEW_NODE_TOOL:
            return tool, token
    raise RuntimeError(
        f"gateway did not expose {REVIEW_NODE_TOOL!r} to the review node — "
        "its Cedar permit (`docs/hr/tools.md`) must accept agent_id "
        f"{REVIEW_NODE_CALLING_AGENT!r}."
    )
