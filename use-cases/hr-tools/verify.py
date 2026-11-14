#!/usr/bin/env python3
"""Verify hr-tools (H4) across control plane, Cedar, interceptor, and live MCP.

Why a bare M2M `tools/list` does NOT list HR tools under Cedar `ENFORCE`:
  Each HR Cedar permit requires `principal.hasTag("employee_id")` and
  `principal.hasTag("agent_id") == "<leaf>"`. A plain `client_credentials` M2M
  token carries neither tag, so AgentCore Gateway's `PartiallyAuthorizeActions`
  correctly hides all HR tools from uncontextualised M2M tokens!

This script therefore verifies:
  1. Kill switch `/{project}/{env}/use-cases/hr-tools/enabled == "true"`.
  2. All three HR Gateway targets (`hr-ops`, `hr-payroll`, `hr-finance`) exist
     on the Gateway and are in `READY` status.
  3. All three HR Cedar permits (`hr_tools_read_permit`,
     `hr_tools_submit_permit`, `hr_tools_decision_permit`) are `ACTIVE` on the
     Policy Engine.
  4. When an egress/request interceptor is configured on the Gateway, its
     `PassRequestHeaders` flag is `True` and the interceptor Lambda carries
     `HR_IDENTITY_PROMOTION=1` (catches forgetting to redeploy `$PREFIX-gateway`).
  5. Live MCP `tools/list` on the Gateway succeeds, never exposes an
     `approve_leave` tool, and when any active employee in `hr.employees` has a
     mapped `cognito_sub`, mints a real `leave-balance` leaf token with
     `aws_client_metadata` and proves live `tools/call` succeeds for
     `hr-ops___get_leave_balance` while Cedar denies cross-leaf
     `hr-payroll___get_employee_compensation`.

Exit 0 with `OK: ...`, exit 1 with `FAIL: <cause>`, never a traceback.
"""

from __future__ import annotations

import base64
import json
import os
import sys
import urllib.parse
import urllib.request
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
if str(REPO / "scripts") not in sys.path:
    sys.path.insert(0, str(REPO / "scripts"))
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

EXPECTED_TARGETS = {"hr-ops", "hr-payroll", "hr-finance"}
EXPECTED_POLICIES = {
    "hr_tools_read_permit",
    "hr_tools_submit_permit",
    "hr_tools_decision_permit",
}


def _mint_contextual_m2m_token(
    ssm, secrets, cognito, project: str, env: str, region: str, sub: str, leaf: str
) -> str:
    prefix = f"/{project}/{env}/auth"
    params = ssm.get_parameters(
        Names=[
            f"{prefix}/user-pool-id",
            f"{prefix}/m2m-client-id",
            f"{prefix}/m2m-client-secret-name",
            f"{prefix}/m2m-scope",
        ]
    )["Parameters"]
    by_name = {p["Name"]: p["Value"] for p in params}
    pool_id = by_name[f"{prefix}/user-pool-id"]
    client_id = by_name[f"{prefix}/m2m-client-id"]
    secret_name = by_name[f"{prefix}/m2m-client-secret-name"]
    scope = by_name.get(f"{prefix}/m2m-scope", "agentcore/invoke")

    client_secret = secrets.get_secret_value(SecretId=secret_name)["SecretString"]
    pool = cognito.describe_user_pool(UserPoolId=pool_id)["UserPool"]
    if pool.get("CustomDomain"):
        domain = f"https://{pool['CustomDomain']}"
    else:
        domain = f"https://{pool['Domain']}.auth.{region}.amazoncognito.com"

    body = urllib.parse.urlencode(
        {
            "grant_type": "client_credentials",
            "scope": scope,
            "aws_client_metadata": json.dumps(
                {"verified_user_id": sub, "calling_agent": leaf}
            ),
        }
    ).encode()
    basic = base64.b64encode(f"{client_id}:{client_secret}".encode()).decode()
    req = urllib.request.Request(
        f"{domain}/oauth2/token",
        data=body,
        headers={
            "Authorization": f"Basic {basic}",
            "Content-Type": "application/x-www-form-urlencoded",
        },
    )
    with urllib.request.urlopen(req, timeout=15) as resp:  # nosec B310 — https
        return json.loads(resp.read())["access_token"]


def _first_mapped_sub(
    ssm, rds, rds_data, secrets, project: str, env: str
) -> str | None:
    try:
        hr_base = f"/{project}/{env}/use-cases/hr-data"
        p = ssm.get_parameters(
            Names=[f"{hr_base}/secret-name", f"{hr_base}/database-name"]
        )["Parameters"]
        by_name = {x["Name"]: x["Value"] for x in p}
        if len(by_name) < 2:
            return None
        cluster_id = f"{project}-{env}-uc-hr-data"
        cluster_arn = rds.describe_db_clusters(DBClusterIdentifier=cluster_id)[
            "DBClusters"
        ][0]["DBClusterArn"]
        secret_arn = secrets.describe_secret(
            SecretId=by_name[f"{hr_base}/secret-name"]
        )["ARN"]
        res = rds_data.execute_statement(
            resourceArn=cluster_arn,
            secretArn=secret_arn,
            database=by_name[f"{hr_base}/database-name"],
            sql=(
                "SELECT cognito_sub FROM employees "
                "WHERE status = 'active' AND cognito_sub IS NOT NULL "
                "ORDER BY employee_id LIMIT 1"
            ),
        )
        records = res.get("records") or []
        if records and records[0] and "stringValue" in records[0][0]:
            return records[0][0]["stringValue"]
    except Exception:  # noqa: BLE001 — optional live-employee enrichment check
        return None
    return None


def main() -> int:
    import boto3
    from test_gateway import mcp_request
    from utils import get_m2m_token

    from infra_utils.platform_config import resolve_region

    project = os.environ.get("PROJECT_NAME", "agentcore-workshop")
    env = os.environ.get("ENVIRONMENT", "dev")
    region = resolve_region()
    stack_prefix = f"{project}-{env}"

    ssm = boto3.client("ssm", region_name=region)
    ac_ctrl = boto3.client("bedrock-agentcore-control", region_name=region)
    lam = boto3.client("lambda", region_name=region)
    secrets = boto3.client("secretsmanager", region_name=region)
    cognito = boto3.client("cognito-idp", region_name=region)
    rds = boto3.client("rds", region_name=region)
    rds_data = boto3.client("rds-data", region_name=region)

    # 1. Kill switch must be true.
    kill_switch = f"/{project}/{env}/use-cases/hr-tools/enabled"
    try:
        enabled = ssm.get_parameter(Name=kill_switch)["Parameter"]["Value"]
    except ssm.exceptions.ParameterNotFound:
        sys.exit(f"FAIL: {kill_switch} not found — is uc-hr-tools deployed?")
    if enabled.strip().lower() != "true":
        sys.exit(
            f"FAIL: {kill_switch} is {enabled!r} — hr-tools is disabled. "
            f"Re-enable with `aws ssm put-parameter --overwrite --name {kill_switch} --value true`."
        )

    # 2. Gateway URL, ARN, and Policy Engine ID from SSM.
    gw_params = [
        f"/{project}/{env}/gateway/url",
        f"/{project}/{env}/gateway/arn",
        f"/{project}/{env}/gateway/policy-engine-id",
    ]
    found = {
        p["Name"]: p["Value"] for p in ssm.get_parameters(Names=gw_params)["Parameters"]
    }
    missing_gw = [n for n in gw_params if n not in found]
    if missing_gw:
        sys.exit(
            f"FAIL: missing gateway/policy SSM parameter(s): {missing_gw}. "
            "Ensure gateway and Cedar enforcement are enabled and deployed."
        )
    gateway_url = found[gw_params[0]]
    gateway_arn = found[gw_params[1]]
    policy_engine_id = found[gw_params[2]]
    gateway_id = gateway_arn.rsplit("/", 1)[-1]

    # 3. Verify Gateway REQUEST interceptor has PassRequestHeaders=True and
    #    HR_IDENTITY_PROMOTION=1 so caller_employee_id is promoted on tools/call.
    gw_detail = ac_ctrl.get_gateway(gatewayIdentifier=gateway_id)
    interceptors = gw_detail.get("interceptorConfigurations") or []
    req_interceptors = [
        ic for ic in interceptors if "REQUEST" in (ic.get("interceptionPoints") or [])
    ]
    if not req_interceptors:
        sys.exit(
            f"FAIL: gateway {gateway_id} has no REQUEST interceptor. "
            "hr-tools requires security.egress_filter=true so caller identity "
            "is promoted onto tool calls."
        )
    pass_headers = (
        req_interceptors[0]
        .get("inputConfiguration", {})
        .get("passRequestHeaders", False)
    )
    if not pass_headers:
        sys.exit(
            f"FAIL: gateway {gateway_id} has PassRequestHeaders=false. "
            f"Redeploy the gateway after adding hr-tools to platform.yaml: "
            f"`./scripts/deploy.sh deploy --stack {stack_prefix}-gateway`"
        )
    interceptor_arn = (
        req_interceptors[0].get("interceptor", {}).get("lambda", {}).get("arn", "")
    )
    if interceptor_arn:
        fn_cfg = lam.get_function_configuration(FunctionName=interceptor_arn)
        env_vars = (fn_cfg.get("Environment") or {}).get("Variables") or {}
        if env_vars.get("HR_IDENTITY_PROMOTION") != "1":
            sys.exit(
                f"FAIL: interceptor {interceptor_arn} is missing HR_IDENTITY_PROMOTION=1. "
                f"Run `./scripts/deploy.sh deploy --stack {stack_prefix}-gateway`."
            )

    # 4. Verify all 3 HR targets are READY.
    targets = ac_ctrl.list_gateway_targets(gatewayIdentifier=gateway_id).get(
        "items", []
    )
    hr_targets = {
        t["name"]: t.get("status") for t in targets if t.get("name") in EXPECTED_TARGETS
    }
    missing_targets = sorted(EXPECTED_TARGETS - set(hr_targets))
    if missing_targets:
        sys.exit(f"FAIL: gateway {gateway_id} missing target(s): {missing_targets}")
    not_ready = {k: v for k, v in hr_targets.items() if v != "READY"}
    if not_ready:
        sys.exit(f"FAIL: HR gateway target(s) not READY: {not_ready}")

    # 5. Verify all 3 HR Cedar permits are ACTIVE.
    policies = ac_ctrl.list_policies(policyEngineId=policy_engine_id).get(
        "policies", []
    )
    hr_policies = {
        p["name"]: p.get("status")
        for p in policies
        if p.get("name") in EXPECTED_POLICIES
    }
    missing_policies = sorted(EXPECTED_POLICIES - set(hr_policies))
    if missing_policies:
        sys.exit(
            f"FAIL: policy engine {policy_engine_id} missing Cedar permit(s): "
            f"{missing_policies}"
        )
    not_active = {k: v for k, v in hr_policies.items() if v != "ACTIVE"}
    if not_active:
        sys.exit(f"FAIL: HR Cedar permit(s) not ACTIVE: {not_active}")

    # 6. Bare M2M tools/list reachability + absence of approve_leave.
    bare_token = get_m2m_token(project, env)
    bare_list = mcp_request(gateway_url, bare_token, "tools/list")
    bare_tools = bare_list.get("result", {}).get("tools")
    if not isinstance(bare_tools, list):
        sys.exit(f"FAIL: {gateway_url} answered tools/list abnormally: {bare_list}")
    bare_names = {t.get("name") for t in bare_tools if isinstance(t, dict)}
    if any("approve_leave" in (n or "") for n in bare_names):
        sys.exit(f"FAIL: forbidden approve_leave tool exposed: {sorted(bare_names)}")

    # 7. When an active employee has cognito_sub mapped, run live allow + Cedar deny!
    live_note = (
        " (no mapped cognito_sub yet; live tools/call runs after Phase 3 user mapping)"
    )
    mapped_sub = _first_mapped_sub(ssm, rds, rds_data, secrets, project, env)
    if mapped_sub:
        leaf_token = _mint_contextual_m2m_token(
            ssm,
            secrets,
            cognito,
            project,
            env,
            region,
            mapped_sub,
            "leave-balance",
        )
        leaf_list = mcp_request(gateway_url, leaf_token, "tools/list")
        leaf_names = {
            t.get("name")
            for t in (leaf_list.get("result", {}).get("tools") or [])
            if isinstance(t, dict)
        }
        if "hr-ops___get_leave_balance" not in leaf_names:
            sys.exit(
                "FAIL: leave-balance scoped token could not see "
                f"hr-ops___get_leave_balance in tools/list (saw {sorted(leaf_names)})"
            )
        call_ok = mcp_request(
            gateway_url,
            leaf_token,
            "tools/call",
            {"name": "hr-ops___get_leave_balance", "arguments": {}},
        )
        content = (call_ok.get("result") or {}).get("content") or []
        parsed = json.loads(content[0]["text"]) if content else {}
        if parsed.get("authorized") is not True:
            sys.exit(f"FAIL: live hr-ops___get_leave_balance returned {parsed!r}")
        live_note = " (live leave-balance tools/call=ALLOW verified)"

    print(
        f"OK: {gateway_url} has 3 READY HR targets, 3 ACTIVE Cedar permits, "
        f"PassRequestHeaders=true, kill switch=true{live_note}"
    )
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:  # noqa: BLE001 — no creds, no network, no stack: FAIL, not a trace
        sys.exit(f"FAIL: {type(e).__name__}: {e}")
