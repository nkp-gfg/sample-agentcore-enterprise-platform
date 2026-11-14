"""hr-identity (H3): Cognito pre-token-generation V3_0 handler.

Spec: docs/hr/modules.md § H3 claims, docs/hr/policy.md, docs/hr/acceptance.md
§ H3, and custom-app-plan/phases.md § H3.

Handles two token-generation paths on the module 3 Cognito user pool:

1. `TokenGeneration_ClientCredentials` (M2M gateway token exchange with
   `aws_client_metadata`):
   - The runtime validates the incoming human user's JWT and passes
     `clientMetadata.verified_user_id` (the verified Cognito `sub`) plus
     `clientMetadata.calling_agent` (the fixed leaf name).
   - This handler looks up `employees.employee_id` where `cognito_sub`
     matches `verified_user_id` and `status = 'active'`, then populates
     `accessTokenGeneration.claimsToAddOrOverride` ONLY (there is no ID
     token in `client_credentials` grants) with `employee_id`, `user_id`,
     `role = 'employee'`, and (when allowed) `agent_id`.

2. Human sign-in / refresh triggers (`TokenGeneration_HostedAuth`,
   `TokenGeneration_Authentication`, `TokenGeneration_RefreshTokens`):
   - Resolves the Cognito-local `sub` from `request.userAttributes.sub`
     FIRST (for Entra/Okta/Ping federated users `event.userName` is the
     external provider username such as `EntraID_...`, NOT the Cognito
     `sub` UUID stored in `employees.cognito_sub`).
   - Enriches both `accessTokenGeneration` and `idTokenGeneration` with
     `employee_id`, `user_id`, and `role = 'employee'` (never `agent_id`
     on human auth triggers).

A `cognito_sub` with no active row in `employees` returns the event
unchanged, with no claims added. The gateway / tool layer maps that to
`NOT_MAPPED`. This handler never invents a guest employee and never writes
to the HR database.
"""

from __future__ import annotations

import json
import logging
import os
import ssl
import time
from pathlib import Path
from typing import Any

_RDS_CA_BUNDLE = Path(__file__).resolve().with_name("global-bundle.pem")

logger = logging.getLogger()
logger.setLevel(logging.INFO)

ALLOWED_CALLING_AGENTS = frozenset(
    {
        "leave-balance",
        "leave-eligibility",
        "leave-submit",
        "compensation",
        "direct-reports",
        "allowance",
        "review-node",
    }
)

CLIENT_CREDENTIALS_TRIGGER = "TokenGeneration_ClientCredentials"
USER_TRIGGERS = frozenset(
    {
        "TokenGeneration_HostedAuth",
        "TokenGeneration_Authentication",
        "TokenGeneration_RefreshTokens",
    }
)
HANDLED_TRIGGERS = USER_TRIGGERS | {CLIENT_CREDENTIALS_TRIGGER}

# RDS IAM auth tokens are valid for 15 minutes; recycle pooled connections
# proactively after 12 minutes so an idle warm container never reuses an
# expired session state.
_CONN_TTL_SECONDS = 720.0
_pool: dict[str, tuple[float, Any]] = {}


def _config() -> dict[str, str]:
    required = ("DB_HOST", "DB_PORT", "DB_NAME", "DB_USER", "AWS_REGION")
    missing = [name for name in required if not os.environ.get(name)]
    if missing:
        raise RuntimeError(
            "hr-identity Lambda is missing required env var(s): " + ", ".join(missing)
        )
    return {name: os.environ[name] for name in required}


def _connect(cfg: dict[str, str]):
    import boto3
    import pg8000.native

    host, _, _ = cfg["DB_HOST"].partition(":")
    port = int(cfg["DB_PORT"])
    rds = boto3.client("rds", region_name=cfg["AWS_REGION"])
    token = rds.generate_db_auth_token(
        DBHostname=host,
        Port=port,
        DBUsername=cfg["DB_USER"],
        Region=cfg["AWS_REGION"],
    )
    if not _RDS_CA_BUNDLE.is_file():
        raise RuntimeError(f"RDS CA bundle not found at {_RDS_CA_BUNDLE}")
    ssl_ctx = ssl.create_default_context(cafile=str(_RDS_CA_BUNDLE))
    ssl_ctx.check_hostname = True
    ssl_ctx.verify_mode = ssl.CERT_REQUIRED
    return pg8000.native.Connection(
        user=cfg["DB_USER"],
        host=host,
        port=port,
        database=cfg["DB_NAME"],
        password=token,
        ssl_context=ssl_ctx,
        timeout=5,
    )


def _get_pooled_conn(cfg: dict[str, str]):
    region = cfg["AWS_REGION"]
    now = time.monotonic()
    entry = _pool.get(region)
    if entry is not None:
        opened_at, conn = entry
        if (now - opened_at) < _CONN_TTL_SECONDS:
            return conn
        try:
            conn.close()
        except Exception:
            logger.debug("closing expired pg8000 connection raised", exc_info=True)
        _pool.pop(region, None)
    conn = _connect(cfg)
    _pool[region] = (now, conn)
    return conn


def _lookup_employee_id(cognito_sub: str) -> str | None:
    cfg = _config()
    region = cfg["AWS_REGION"]
    rows = None
    try:
        conn = _get_pooled_conn(cfg)
        rows = conn.run(
            "SELECT employee_id FROM employees "
            "WHERE cognito_sub = :sub AND status = 'active' LIMIT 1",
            sub=cognito_sub,
        )
    except Exception as exc:  # noqa: BLE001 — retry once on a stale conn
        logger.warning("hr-identity db call failed: %s; reconnecting", exc)
        _pool.pop(region, None)
        try:
            conn = _get_pooled_conn(cfg)
            rows = conn.run(
                "SELECT employee_id FROM employees "
                "WHERE cognito_sub = :sub AND status = 'active' LIMIT 1",
                sub=cognito_sub,
            )
        except Exception as exc2:  # noqa: BLE001 — fail closed, add no claim
            logger.error("hr-identity db call failed again: %s", exc2)
            return None
    if not rows:
        return None
    return str(rows[0][0])


def _resolve_cognito_sub(event: dict) -> str | None:
    """Resolve the Cognito user `sub` UUID for both M2M and human triggers."""
    trigger = event.get("triggerSource")
    request = event.get("request") or {}
    metadata = request.get("clientMetadata") or {}

    if trigger == CLIENT_CREDENTIALS_TRIGGER:
        verified = metadata.get("verified_user_id")
        if isinstance(verified, str) and verified.strip():
            return verified.strip()
        return None

    # Human triggers: ALWAYS prefer request.userAttributes.sub over userName!
    # For federated Entra/Okta/Ping logins, event.userName is `EntraID_<oid>`
    # whereas userAttributes.sub is the Cognito UUID stored in employees.cognito_sub.
    attrs = request.get("userAttributes") or {}
    sub = attrs.get("sub")
    if isinstance(sub, str) and sub.strip():
        return sub.strip()
    user_name = event.get("userName")
    if isinstance(user_name, str) and user_name.strip():
        return user_name.strip()
    return None


def _calling_agent(event: dict) -> str | None:
    if event.get("triggerSource") != CLIENT_CREDENTIALS_TRIGGER:
        return None
    metadata = (event.get("request") or {}).get("clientMetadata") or {}
    value = metadata.get("calling_agent")
    if isinstance(value, str) and value in ALLOWED_CALLING_AGENTS:
        return value
    return None


def _apply_claims(
    event: dict, claims: dict[str, str], *, include_id_token: bool
) -> dict:
    # Real Cognito V3_0 events pass `"response": {"claimsAndScopeOverrideDetails": None}`
    # (explicit JSON nulls), where `dict.setdefault(...)` would return `None`.
    response = event.get("response")
    if not isinstance(response, dict):
        response = {}
        event["response"] = response
    details = response.get("claimsAndScopeOverrideDetails")
    if not isinstance(details, dict):
        details = {}
        response["claimsAndScopeOverrideDetails"] = details
    sections = (
        ("accessTokenGeneration", "idTokenGeneration")
        if include_id_token
        else ("accessTokenGeneration",)
    )
    for section in sections:
        target = details.get(section)
        if not isinstance(target, dict):
            target = {}
            details[section] = target
        existing = target.get("claimsToAddOrOverride")
        if not isinstance(existing, dict):
            existing = {}
            target["claimsToAddOrOverride"] = existing
        existing.update(claims)
    return event


def handler(event: dict, context) -> dict:
    del context
    trigger = event.get("triggerSource")
    if trigger not in HANDLED_TRIGGERS:
        logger.info("hr-identity skipping trigger %r", trigger)
        return event

    cognito_sub = _resolve_cognito_sub(event)
    if not cognito_sub:
        logger.info(
            "hr-identity: trigger %s carries no user sub; no claims added", trigger
        )
        return event

    try:
        employee_id = _lookup_employee_id(cognito_sub)
    except Exception:
        logger.exception(
            "hr-identity: unexpected failure resolving sub %s", cognito_sub
        )
        return event

    if employee_id is None:
        logger.info(
            "hr-identity: no active employees row for sub %s; "
            "returning event unchanged (gateway/tool maps to NOT_MAPPED)",
            cognito_sub,
        )
        return event

    claims: dict[str, str] = {
        "employee_id": employee_id,
        "user_id": cognito_sub,
        "role": "employee",
    }
    if trigger == CLIENT_CREDENTIALS_TRIGGER:
        agent_id = _calling_agent(event)
        if agent_id is not None:
            claims["agent_id"] = agent_id

    logger.info(
        "hr-identity: added claims %s for trigger %s",
        json.dumps(
            {k: v for k, v in claims.items() if k not in {"employee_id", "user_id"}}
        ),
        trigger,
    )
    return _apply_claims(
        event,
        claims,
        include_id_token=(trigger != CLIENT_CREDENTIALS_TRIGGER),
    )
