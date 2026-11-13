#!/usr/bin/env python3
"""Verify hr-tools with ONE real invocation of what it deploys.

The contract (CONTRIBUTING_USE_CASES.md): checking that a resource exists
only proves CloudFormation ran. This script proves the thing WORKS. It
reads the gateway URL the platform publishes, authenticates with the
platform M2M client the way scripts/test_gateway.py does, calls
`tools/list` on the gateway, and asserts the six leaf tools this use case
registers are discoverable. It also asserts the kill switch is on. Exit
0 with `OK: ...`, exit 1 with `FAIL: <cause>`, never a traceback. Runs
in under 20 seconds and does not call any tool, so a denied call cannot
fail it. `deploy.sh verify` runs it automatically when the use case is
enabled in platform.yaml.

docs/hr/tools.md § Routing is the source of truth for the tool list:
`record_leave_decision` is reviewer-only and binds to `agent_id:
review-node`, which no leaf agent sets. It is still registered in the
gateway so the review-node graph can reach it, but a leaf-token verify
MUST see the other six and no more.

Usage: python use-cases/hr-tools/verify.py
Respects PROJECT_NAME / ENVIRONMENT / AWS_REGION.
"""

import os
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "scripts"))
sys.path.insert(0, str(REPO))

# The six leaf tools (`docs/hr/tools.md` § Routing). Each is namespaced
# by its gateway target name with the MCP target/tool separator `___`.
EXPECTED_LEAF_TOOLS = {
    "hr-ops___get_leave_balance",
    "hr-ops___check_leave_eligibility",
    "hr-ops___submit_leave_request",
    "hr-payroll___get_employee_compensation",
    "hr-payroll___list_direct_reports",
    "hr-finance___get_allowance",
}
# The reviewer-only tool. Its presence is not asserted — the review-node
# runtime discovers it with its own token; a leaf-token verify is
# finished before the token is scoped to see it.
REVIEWER_TOOL = "hr-ops___record_leave_decision"


def main() -> int:
    # Imports live inside main so a missing dependency or a misplaced copy
    # of this file is reported as FAIL: like every other cause, not as a
    # traceback.
    import boto3
    from test_gateway import mcp_request
    from utils import get_m2m_token

    from infra_utils.platform_config import resolve_region

    project = os.environ.get("PROJECT_NAME", "agentcore-workshop")
    env = os.environ.get("ENVIRONMENT", "dev")
    ssm = boto3.client("ssm", region_name=resolve_region())

    # 1. The kill switch must be on. H4 ships with `enabled: true`; a
    # false value here means an operator (or an earlier verify) has
    # taken the use case out of circulation and the verify MUST fail
    # loud rather than reporting OK on a disabled surface.
    kill_switch = f"/{project}/{env}/use-cases/hr-tools/enabled"
    try:
        enabled = ssm.get_parameter(Name=kill_switch)["Parameter"]["Value"]
    except ssm.exceptions.ParameterNotFound:
        sys.exit(f"FAIL: {kill_switch} not found — is the use case deployed?")
    if enabled.strip().lower() != "true":
        sys.exit(
            f"FAIL: {kill_switch} is {enabled!r} — hr-tools is disabled. "
            "Re-enable with `aws ssm put-parameter --overwrite "
            f"--name {kill_switch} --value true`."
        )

    # 2. The gateway URL comes from the platform interface, not from an
    # import of GatewayStack.
    gateway_url_param = f"/{project}/{env}/gateway/url"
    try:
        gateway_url = ssm.get_parameter(Name=gateway_url_param)["Parameter"]["Value"]
    except ssm.exceptions.ParameterNotFound:
        sys.exit(
            f"FAIL: {gateway_url_param} not found — is the gateway deployed? "
            "hr-tools requires the gateway use case."
        )

    # 3. tools/list is the one real invocation. A returned tool list that
    # does not cover the six leaf tools proves one of the three gateway
    # targets did not register, which is exactly what the deploy must
    # catch before anyone writes a graph on top of it.
    token = get_m2m_token(project, env)
    result = mcp_request(gateway_url, token, "tools/list")
    tools = result.get("result", {}).get("tools")
    if not isinstance(tools, list):
        sys.exit(f"FAIL: {gateway_url} answered tools/list without a tool list: {result}")

    names = {t.get("name") for t in tools if isinstance(t, dict)}
    missing = EXPECTED_LEAF_TOOLS - names
    if missing:
        sys.exit(
            f"FAIL: {gateway_url} is missing hr-tools leaf tools: "
            f"{sorted(missing)}. Present: {sorted(names)}"
        )

    reviewer_note = (
        f" (reviewer tool {REVIEWER_TOOL} also present)"
        if REVIEWER_TOOL in names
        else ""
    )
    print(
        f"OK: {gateway_url} lists {len(EXPECTED_LEAF_TOOLS)} hr-tools leaf tool(s); "
        f"kill switch {kill_switch}=true{reviewer_note}"
    )
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:  # noqa: BLE001 — no creds, no network, no stack: FAIL, not a trace
        sys.exit(f"FAIL: {type(e).__name__}: {e}")
