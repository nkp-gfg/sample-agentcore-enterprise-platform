"""Lambda-backed CloudFormation custom resource that provisions the HR data layer.

Runs on stack CREATE/UPDATE to:
  1. Create the empty `agent_state` database for the god agent's LangGraph
     checkpointer, if it is not already there.
  2. Apply `schema.sql` in the `hr` database.
  3. If `Seed` is "true" in the resource properties, apply `seed.sql` in the
     `hr` database.

All SQL goes through the RDS Data API, so this Lambda does NOT need to run in
the VPC. It authenticates to RDS Data API with IAM, which proxies to Aurora
with the Secrets Manager master secret the stack already created.

On DELETE this does nothing, because `retain_data` is the default: dropping
HR data on stack teardown would make `destroy --stack uc-hr-data` destructive
in a way the HR plan explicitly refuses (docs/hr/modules.md "Destroy").

Properties (passed from stack.py via the CustomResource):
  ClusterArn      — the Aurora cluster ARN
  SecretArn       — the master Secrets Manager secret ARN
  Database        — the HR database name (default "hr", from the use-case config)
  CheckpointDb    — the checkpointer database name (always "agent_state")
  Seed            — "true" to apply seed.sql after schema.sql, anything else to skip
  Version         — any string. Changing it forces a CREATE/UPDATE run

Logs are intentionally light on content: no SQL text is logged, so a failure
in seed.sql cannot leak salary numbers through CloudWatch.
"""

from __future__ import annotations

import logging
import os
import re
import time
from collections.abc import Iterable
from pathlib import Path

import boto3

logger = logging.getLogger()
logger.setLevel(os.environ.get("LOG_LEVEL", "INFO"))

_HERE = Path(__file__).resolve().parent
_SCHEMA_SQL = _HERE / "schema.sql"
_SEED_SQL = _HERE / "seed.sql"

# RDS Data API ExecuteStatement has a 240 s cap. Our schema fits comfortably in
# a single statement list, but we still split so one bad DDL does not take the
# rest down with it.
_rds = boto3.client("rds-data")


def on_event(event: dict, _context) -> dict:
    """CloudFormation custom-resource entry point."""
    request_type = event["RequestType"]
    properties = event["ResourceProperties"]
    physical_id = event.get("PhysicalResourceId") or "hr-data-provisioner"

    logger.info(
        "provisioner invoked: request_type=%s physical_id=%s seed=%s",
        request_type,
        physical_id,
        properties.get("Seed"),
    )

    if request_type == "Delete":
        # Retain policy: no DROP DATABASE, no TRUNCATE. Teardown is a manual,
        # auditable step and not part of `destroy --stack`.
        return {"PhysicalResourceId": physical_id}

    cluster_arn = properties["ClusterArn"]
    secret_arn = properties["SecretArn"]
    database = properties.get("Database") or "hr"
    checkpoint_db = properties.get("CheckpointDb") or "agent_state"
    seed = str(properties.get("Seed", "false")).lower() == "true"

    _wait_until_cluster_reachable(cluster_arn, secret_arn)
    _ensure_database(cluster_arn, secret_arn, checkpoint_db)
    _apply_sql_file(cluster_arn, secret_arn, database, _SCHEMA_SQL)
    if seed:
        _apply_sql_file(cluster_arn, secret_arn, database, _SEED_SQL)

    return {
        "PhysicalResourceId": physical_id,
        "Data": {
            "Database": database,
            "CheckpointDatabase": checkpoint_db,
            "Seeded": "true" if seed else "false",
        },
    }


def _wait_until_cluster_reachable(cluster_arn: str, secret_arn: str) -> None:
    """Aurora Serverless v2 may still be scaling up when the stack signals
    the custom resource. Poll ExecuteStatement with a trivial SELECT until it
    returns, or give up with a clear error. 300 s matches the Lambda timeout.
    """
    deadline = time.monotonic() + 270
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        try:
            _rds.execute_statement(
                resourceArn=cluster_arn,
                secretArn=secret_arn,
                database="postgres",
                sql="SELECT 1",
            )
            return
        except _rds.exceptions.DatabaseNotFoundException:
            # The "postgres" admin database exists on a freshly created cluster
            # as soon as the first instance is in-service; absence here means
            # Data API cannot reach it yet. Keep retrying.
            last_error = None
            time.sleep(5)
        except Exception as exc:  # noqa: BLE001 — retry everything with backoff
            last_error = exc
            logger.info("cluster not reachable yet: %s", type(exc).__name__)
            time.sleep(5)
    tail = f": {type(last_error).__name__}: {last_error}" if last_error else ""
    raise RuntimeError(
        "Aurora cluster not reachable via Data API within the timeout" + tail
    )


def _ensure_database(cluster_arn: str, secret_arn: str, name: str) -> None:
    """Create `name` in the default `postgres` admin database if it does not
    already exist. CREATE DATABASE cannot run inside a transaction, so this
    runs through Data API outside the schema transaction below.
    """
    if not re.fullmatch(r"[a-z_][a-z0-9_]{0,62}", name):
        raise ValueError(f"unsafe database name: {name!r}")
    existing = _rds.execute_statement(
        resourceArn=cluster_arn,
        secretArn=secret_arn,
        database="postgres",
        sql="SELECT 1 FROM pg_database WHERE datname = :name",
        parameters=[{"name": "name", "value": {"stringValue": name}}],
    )
    if existing.get("records"):
        logger.info("database %s already present", name)
        return
    _rds.execute_statement(
        resourceArn=cluster_arn,
        secretArn=secret_arn,
        database="postgres",
        sql=f'CREATE DATABASE "{name}"',
    )
    logger.info("database %s created", name)


def _apply_sql_file(
    cluster_arn: str, secret_arn: str, database: str, path: Path
) -> None:
    """Split a .sql file into statements and run each through Data API.

    Statements are wrapped in a single transaction (begin → each statement →
    commit) so a mid-file failure leaves the database in the previous state.
    """
    statements = list(_split_statements(path.read_text()))
    logger.info("applying %s: %d statement(s)", path.name, len(statements))

    transaction = _rds.begin_transaction(
        resourceArn=cluster_arn, secretArn=secret_arn, database=database
    )["transactionId"]
    try:
        for index, sql in enumerate(statements, start=1):
            _rds.execute_statement(
                resourceArn=cluster_arn,
                secretArn=secret_arn,
                database=database,
                transactionId=transaction,
                sql=sql,
            )
    except Exception:
        try:
            _rds.rollback_transaction(
                resourceArn=cluster_arn,
                secretArn=secret_arn,
                transactionId=transaction,
            )
        except Exception:
            logger.exception("rollback failed; original error follows")
        logger.info("rolled back %s", path.name)
        raise
    _rds.commit_transaction(
        resourceArn=cluster_arn,
        secretArn=secret_arn,
        transactionId=transaction,
    )


def _split_statements(sql: str) -> Iterable[str]:
    """Split a Postgres script into standalone statements.

    Handles the features our files use: line comments (`--`), single-quoted
    strings, and dollar-quoted blocks (`$$ ... $$` or `$tag$ ... $tag$`) that
    legitimately contain semicolons. Block comments (`/* ... */`) and bytea
    hex literals are not used by schema.sql / seed.sql, so are not parsed.
    """
    result: list[str] = []
    buf: list[str] = []
    i = 0
    n = len(sql)
    dollar_tag: str | None = None
    in_single = False
    while i < n:
        ch = sql[i]
        # Line comment
        if (
            not in_single
            and dollar_tag is None
            and ch == "-"
            and sql[i : i + 2] == "--"
        ):
            end = sql.find("\n", i)
            if end == -1:
                i = n
            else:
                i = end
            continue
        # Dollar-quoted block
        if not in_single:
            if dollar_tag is None and ch == "$":
                match = re.match(r"\$(\w*)\$", sql[i:])
                if match:
                    dollar_tag = match.group(0)
                    buf.append(dollar_tag)
                    i += len(dollar_tag)
                    continue
            elif dollar_tag is not None and sql[i : i + len(dollar_tag)] == dollar_tag:
                buf.append(dollar_tag)
                i += len(dollar_tag)
                dollar_tag = None
                continue
        # Single-quoted string
        if dollar_tag is None and ch == "'":
            in_single = not in_single
            buf.append(ch)
            i += 1
            continue
        # Statement end
        if ch == ";" and not in_single and dollar_tag is None:
            stmt = "".join(buf).strip()
            if stmt:
                result.append(stmt)
            buf = []
            i += 1
            continue
        buf.append(ch)
        i += 1
    tail = "".join(buf).strip()
    if tail:
        result.append(tail)
    return result
