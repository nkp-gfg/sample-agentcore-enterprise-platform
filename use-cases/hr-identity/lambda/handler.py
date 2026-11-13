"""hr-identity (H3): Cognito pre-token-generation handler.

Spec: docs/hr/modules.md § H3 claims, docs/hr/policy.md, docs/hr/acceptance.md
§ H3, and custom-app-plan/phases.md § H3.

Runs on every `TokenGeneration_HostedAuth` and `TokenGeneration_RefreshTokens`
event emitted by the module 3 Cognito user pool, looks up the signed-in
employee in the HR database, and adds three claims that the H4 HR tool
Lambdas and the gateway's Cedar permits need:

    employee_id   — the business id from employees.employee_id
    role          — the constant "employee" (v1: there is no role column;
                    hr_admin and payroll_admin do not exist here)
    agent_id      — only when request.clientMetadata.calling_agent is one of
                    the seven allowed leaf names; any other value (e.g.
                    "admin") results in no agent_id claim, which makes every
                    HR tool a Cedar deny

A cognito_sub with no active row in `employees` returns the event
unchanged, with no claims added. The gateway Lambda then maps that to the
NOT_MAPPED reason code per docs/hr/policy.md § Reason codes. This handler
does not invent a guest employee, and it never writes to the HR database.

Database connectivity
---------------------
boto3's `rds.generate_db_auth_token` mints a short-lived (15-minute) IAM
auth token that is passed as the PostgreSQL password. The Lambda executes
in the module C private subnets and connects to the Aurora writer endpoint
on 5432 inside the VPC — no master-secret value ever reaches this Lambda.
The `hr_identity` database role has SELECT on `employee_id`, `cognito_sub`,
and `status` of `employees` only (docs/hr/modules.md § Database roles).

The connection pool is keyed by region (one per Lambda container). Nothing
is cached across invocations beyond that pool: the IAM token expires in 15
minutes and the endpoint / database-name are read once on cold start.
"""

from __future__ import annotations

import json
import logging
import os
import ssl
from typing import Any

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

HANDLED_TRIGGERS = frozenset(
    {"TokenGeneration_HostedAuth", "TokenGeneration_RefreshTokens"}
)

_pool: dict[str, Any] = {}


def _config() -> dict[str, str]:
    """Return the runtime config the CDK stack injects as environment variables.

    Validated once per cold start. A missing variable is a deploy-time
    misconfiguration, so the handler fails closed (no claims added) rather
    than guessing values.
    """
    required = ("DB_HOST", "DB_PORT", "DB_NAME", "DB_USER", "AWS_REGION")
    missing = [name for name in required if not os.environ.get(name)]
    if missing:
        raise RuntimeError(
            "hr-identity Lambda is missing required env var(s): " + ", ".join(missing)
        )
    return {name: os.environ[name] for name in required}


def _connect(cfg: dict[str, str]):
    """Open a TLS PostgreSQL connection authenticated with an RDS IAM token.

    boto3's generate_db_auth_token returns a SigV4-signed URL that Aurora
    accepts as the password when iam_database_authentication is on. The
    token is valid for 15 minutes, so a warm container reuses one if the
    cached connection is still live; otherwise a new one is opened.

    Imported here, not at module scope, so the handler imports cleanly even
    when the pg8000 layer is absent (the deployed Lambda needs it; a bare
    `import handler` for a unit test does not).
    """
    import boto3
    import pg8000.native

    rds = boto3.client("rds", region_name=cfg["AWS_REGION"])
    token = rds.generate_db_auth_token(
        DBHostname=cfg["DB_HOST"],
        Port=int(cfg["DB_PORT"]),
        DBUsername=cfg["DB_USER"],
        Region=cfg["AWS_REGION"],
    )
    ssl_ctx = ssl.create_default_context()
    return pg8000.native.Connection(
        user=cfg["DB_USER"],
        host=cfg["DB_HOST"],
        port=int(cfg["DB_PORT"]),
        database=cfg["DB_NAME"],
        password=token,
        ssl_context=ssl_ctx,
        timeout=5,
    )


def _lookup_employee_id(cognito_sub: str) -> str | None:
    """Return the business employee_id for an active Cognito sub, or None.

    The exact grant the `hr_identity` role has (docs/hr/modules.md § Database
    roles): `SELECT employee_id, cognito_sub, status ON employees`. The
    query reads nothing else and runs as one statement with a bound
    parameter — no model input ever reaches this function.
    """
    cfg = _config()
    conn = _pool.get(cfg["AWS_REGION"])
    rows = None
    try:
        if conn is None:
            conn = _connect(cfg)
            _pool[cfg["AWS_REGION"]] = conn
        rows = conn.run(
            "SELECT employee_id FROM employees "
            "WHERE cognito_sub = :sub AND status = 'active' LIMIT 1",
            sub=cognito_sub,
        )
    except Exception as exc:  # noqa: BLE001 — retry once on a stale conn
        logger.warning("hr-identity db call failed: %s; reconnecting", exc)
        _pool.pop(cfg["AWS_REGION"], None)
        try:
            conn = _connect(cfg)
            _pool[cfg["AWS_REGION"]] = conn
            rows = conn.run(
                "SELECT employee_id FROM employees "
                "WHERE cognito_sub = :sub AND status = 'active' LIMIT 1",
                sub=cognito_sub,
            )
        except Exception as exc2:  # noqa: BLE001 — return None, caller adds no claim
            logger.error("hr-identity db call failed again: %s", exc2)
            return None
    if not rows:
        return None
    return str(rows[0][0])


def _resolve_cognito_sub(event: dict) -> str | None:
    """Pull the Cognito sub out of the event in the order the trigger documents.

    event.userName is a Cognito sub for a native user pool account; for a
    federated user it is the provider-side identifier. event.request
    .userAttributes.sub is always the Cognito-local sub, which is the exact
    value that H1's employees.cognito_sub stores.
    """
    user_name = event.get("userName")
    if user_name:
        return str(user_name)
    attrs = (event.get("request") or {}).get("userAttributes") or {}
    sub = attrs.get("sub")
    if sub:
        return str(sub)
    return None


def _calling_agent(event: dict) -> str | None:
    """Return a leaf agent_id from clientMetadata, or None when it is not allowed.

    The runtime code sets clientMetadata.calling_agent per docs/hr/modules.md
    § H3 claims. A value outside the seven allowed leaf names (including the
    explicit 'admin' case called out in docs/hr/acceptance.md § H3) results
    in no agent_id claim — the gateway then denies every HR tool via Cedar.
    """
    metadata = (event.get("request") or {}).get("clientMetadata") or {}
    value = metadata.get("calling_agent")
    if isinstance(value, str) and value in ALLOWED_CALLING_AGENTS:
        return value
    return None


def _apply_claims(event: dict, claims: dict[str, str]) -> dict:
    """Return the event with claimsAndScopeOverrideDetails filled in.

    Pre-Token v2 lets a handler add or override claims in both the ID token
    and the access token. The gateway and Cedar only read the access token,
    but adding the same claims to the ID token keeps the two in sync and is
    what runtime browsers expect — mismatched claims across the pair are a
    known source of hard-to-debug authorization bugs.
    """
    response = event.setdefault("response", {})
    details = response.setdefault("claimsAndScopeOverrideDetails", {})
    for section in ("accessTokenGeneration", "idTokenGeneration"):
        target = details.setdefault(section, {})
        existing = target.setdefault("claimsToAddOrOverride", {})
        existing.update(claims)
    return event


def handler(event: dict, context) -> dict:
    """Pre-token-generation trigger entry point.

    Returns the event with claimsAndScopeOverrideDetails populated when a
    mapping is found, unchanged otherwise. Any unhandled trigger source is
    returned as-is — a safety net for new trigger types Cognito may add.
    """
    del context  # Lambda runtime passes it; the handler does not use it.
    trigger = event.get("triggerSource")
    if trigger not in HANDLED_TRIGGERS:
        logger.info("hr-identity skipping trigger %r", trigger)
        return event

    cognito_sub = _resolve_cognito_sub(event)
    if not cognito_sub:
        logger.info("hr-identity: event carries no cognito sub; no claims added")
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
            "returning event unchanged (gateway maps to NOT_MAPPED)",
            cognito_sub,
        )
        return event

    claims: dict[str, str] = {
        "employee_id": employee_id,
        "role": "employee",
    }
    agent_id = _calling_agent(event)
    if agent_id is not None:
        claims["agent_id"] = agent_id

    logger.info(
        "hr-identity: added claims %s for sub %s",
        json.dumps({k: v for k, v in claims.items() if k != "employee_id"}),
        cognito_sub,
    )
    return _apply_claims(event, claims)
