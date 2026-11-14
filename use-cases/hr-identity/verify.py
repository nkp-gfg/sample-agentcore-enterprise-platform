#!/usr/bin/env python3
"""Verify hr-identity (H3) without minting a token.

End-to-end claims (two users get two different employee_id claims, a
terminated row is NOT_MAPPED, calling_agent 'leave-submit' carries
agent_id 'leave-submit', calling_agent 'admin' carries no agent_id, every
token expires 15 minutes after issue — docs/hr/acceptance.md § H3) are
proved by H4's verify.py from inside the VPC through the gateway. H3's
job here is the deploy-side proof:

  - the SSM parameter this stack publishes exists;
  - the Lambda it names still exists and is Active;
  - module 3's Cognito user pool has
    LambdaConfig.PreTokenGenerationConfig.LambdaArn pointing at it.

Exit 0 with one `OK:` line on success; exit 1 with `FAIL: <cause>` on
anything else, never a Python traceback. Safe to run under the scrubbed
environment tests/test_verify.py applies: imports that need credentials
happen inside main() so a missing boto3 or missing AWS config is reported
as `FAIL:` not a collection error.

Usage: python use-cases/hr-identity/verify.py
Respects PROJECT_NAME / ENVIRONMENT / AWS_REGION. `deploy.sh verify` runs
this automatically when hr-identity is enabled in platform.yaml.
"""

from __future__ import annotations

import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
if str(REPO / "scripts") not in sys.path:
    sys.path.insert(0, str(REPO / "scripts"))
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))


def main() -> int:
    import boto3

    from infra_utils.platform_config import resolve_project_and_env, resolve_region

    project, env = resolve_project_and_env()
    region = resolve_region()

    ssm = boto3.client("ssm", region_name=region)
    lam = boto3.client("lambda", region_name=region)
    cognito = boto3.client("cognito-idp", region_name=region)

    base = f"/{project}/{env}/use-cases/hr-identity"
    function_arn_param = f"{base}/function-arn"
    user_pool_param = f"/{project}/{env}/auth/user-pool-id"

    try:
        response = ssm.get_parameters(Names=[function_arn_param, user_pool_param])
    except ssm.exceptions.ClientError as exc:
        sys.exit(f"FAIL: SSM GetParameters refused: {exc}")

    found = {p["Name"]: p["Value"] for p in response["Parameters"]}
    if function_arn_param not in found:
        sys.exit(f"FAIL: {function_arn_param} not found - is the use case deployed?")
    if user_pool_param not in found:
        sys.exit(f"FAIL: {user_pool_param} not found - is the auth stack deployed?")

    function_arn = found[function_arn_param]
    user_pool_id = found[user_pool_param]

    try:
        function = lam.get_function(FunctionName=function_arn)
    except lam.exceptions.ResourceNotFoundException:
        sys.exit(
            f"FAIL: Lambda {function_arn} missing - SSM points at a "
            "stale function, redeploy hr-identity"
        )
    state = function.get("Configuration", {}).get("State")
    if state != "Active":
        reason = function.get("Configuration", {}).get("StateReason") or ""
        sys.exit(
            f"FAIL: Lambda {function_arn} is in state {state!r}"
            + (f" ({reason})" if reason else "")
        )

    try:
        pool = cognito.describe_user_pool(UserPoolId=user_pool_id)["UserPool"]
    except cognito.exceptions.ResourceNotFoundException:
        sys.exit(f"FAIL: Cognito user pool {user_pool_id} not found")

    lambda_config = pool.get("LambdaConfig") or {}
    pretoken_config = lambda_config.get("PreTokenGenerationConfig") or {}
    attached_arn = pretoken_config.get("LambdaArn")
    if not attached_arn:
        legacy = lambda_config.get("PreTokenGeneration")
        if legacy:
            sys.exit(
                f"FAIL: user pool {user_pool_id} has the v1 PreTokenGeneration "
                f"trigger set to {legacy!r}; hr-identity attaches v2 via "
                "PreTokenGenerationConfig and the v2 slot is empty"
            )
        sys.exit(
            f"FAIL: user pool {user_pool_id} has no PreTokenGenerationConfig; "
            "the AttachTrigger custom resource did not run or was rolled back"
        )
    if attached_arn != function_arn:
        sys.exit(
            f"FAIL: user pool {user_pool_id} PreTokenGenerationConfig points "
            f"at {attached_arn!r}, not {function_arn!r} - another trigger is "
            "attached to the same pool"
        )
    version = pretoken_config.get("LambdaVersion")
    if version != "V3_0":
        sys.exit(
            f"FAIL: user pool {user_pool_id} PreTokenGenerationConfig version "
            f"is {version!r}, expected 'V3_0' (required for M2M client_credentials "
            "aws_client_metadata enrichment)"
        )

    print(
        f"OK: hr-identity pretoken {function_arn} is Active and attached to "
        f"user pool {user_pool_id} (LambdaVersion=V3_0)"
    )
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:  # noqa: BLE001 — scrubbed env, no network: FAIL, no trace
        sys.exit(f"FAIL: {type(exc).__name__}: {exc}")
