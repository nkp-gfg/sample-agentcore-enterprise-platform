"""RDS IAM auth for the HR Lambdas.

docs/hr/modules.md § Database roles lists the four roles the HR Lambdas
connect as — `hr_reader`, `hr_writer`, `hr_audit`, and (identity-only,
not used here) `hr_identity`. Each Lambda connects with an RDS IAM token
for the role its IAM policy allows. A token is valid for 15 minutes;
nothing on the Lambda side caches a token for longer.

The master cluster secret is for H1 only. No code path in H4 reads it.

`DataUnavailable` is raised on every connection error; the handler maps
that to the `DATA_UNAVAILABLE` reason code without any DB side-effects.
"""

from __future__ import annotations

import logging
import os
from contextlib import contextmanager

from .errors import DataUnavailable

logger = logging.getLogger(__name__)

RDS_PORT = 5432

# docs/hr/modules.md § Database roles — the four role names H1 creates.
# A role that H1 did not create is refused here instead of silently
# attempting an RDS IAM token and leaking a non-informative error.
VALID_ROLES = {"hr_reader", "hr_writer", "hr_audit"}


def _env(name: str) -> str:
    value = os.environ.get(name, "")
    if not value:
        raise DataUnavailable(f"missing environment variable: {name}")
    return value


def _generate_iam_token(host: str, user: str, region: str) -> str:
    try:
        import boto3  # local import so unit tests do not need boto3
    except ImportError as exc:
        raise DataUnavailable("boto3 unavailable") from exc
    rds = boto3.client("rds", region_name=region)
    return rds.generate_db_auth_token(
        DBHostname=host, Port=RDS_PORT, DBUsername=user, Region=region
    )


@contextmanager
def connect(role: str):
    """Open a psycopg connection as the named database role.

    docs/hr/modules.md: `hr_reader` for read tools, `hr_writer` for the
    two writes, `hr_audit` for the decision_log insert on every call.

    The function is a context manager so the caller never forgets to
    close the connection — a stray open connection against an RDS
    serverless cluster scales idle ACUs.
    """
    if role not in VALID_ROLES:
        raise DataUnavailable(f"refusing to connect as unknown role: {role!r}")
    endpoint = _env("HR_DB_ENDPOINT")
    db_name = _env("HR_DB_NAME")
    region = os.environ.get("AWS_REGION") or _env("HR_AWS_REGION")
    host, _, _port = endpoint.partition(":")
    try:
        import psycopg  # local import so unit tests and synth do not require it
    except ImportError as exc:
        raise DataUnavailable("psycopg unavailable") from exc
    try:
        token = _generate_iam_token(host, role, region)
    except Exception as exc:
        raise DataUnavailable(f"could not mint RDS IAM token for {role}") from exc
    try:
        connection = psycopg.connect(
            host=host,
            port=RDS_PORT,
            dbname=db_name,
            user=role,
            password=token,
            sslmode="require",
            connect_timeout=5,
        )
    except Exception as exc:
        raise DataUnavailable(f"could not connect to {host} as {role}") from exc
    try:
        yield connection
    finally:
        try:
            connection.close()
        except Exception:
            logger.debug("psycopg connection close raised", exc_info=True)
