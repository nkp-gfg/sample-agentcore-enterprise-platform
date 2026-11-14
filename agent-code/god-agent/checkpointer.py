"""PostgresSaver / AsyncPostgresSaver on the `agent_state` database.

`custom-app-plan/god-agent.md` § Checkpointer and `docs/hr/modules.md` § Database roles:
  - H1 creates the `agent_state` database and the `agent_checkpoint` role
    (granted `rds_iam` and `USAGE, CREATE ON SCHEMA public`, with zero access
    to the `hr` database).
  - The runtime connects ONLY as `agent_checkpoint` using short-lived (15 min)
    RDS IAM authentication tokens — the runtime never uses H1's master secret.
  - `AsyncPostgresSaver` backs the live async AG-UI streaming entrypoint so
    `aget_tuple` / `aput` work natively; `PostgresSaver` is retained for
    synchronous callers and build-invariant tests.
  - Two companion metadata tables (`hr_thread_owners` and `hr_pending_reviews`)
    live in `agent_state` (owned by `agent_checkpoint`) to isolate sessions per
    verified Cognito `sub` and persist open manager-review cards across
    container replacements.
"""

from __future__ import annotations

import contextlib
import json
import logging
from collections.abc import AsyncIterator, Iterator
from pathlib import Path
from typing import Any

import boto3
import psycopg
from langgraph.checkpoint.postgres import PostgresSaver
from langgraph.checkpoint.postgres.aio import AsyncPostgresSaver
from shared.region import runtime_region
from ssm_config import hr_data_config

logger = logging.getLogger(__name__)

_SETUP_COMPLETED = False
_ASYNC_SETUP_COMPLETED = False

_COMPANION_DDL = """
CREATE TABLE IF NOT EXISTS hr_thread_owners (
    thread_id   text PRIMARY KEY,
    owner_sub   text NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS hr_pending_reviews (
    request_id           text PRIMARY KEY,
    thread_id            text NOT NULL,
    employee_id          text NOT NULL,
    reviewer_employee_id text NOT NULL,
    leave_type           text NOT NULL,
    start_date           text NOT NULL,
    end_date             text NOT NULL,
    days                 integer NOT NULL,
    reason               text NOT NULL,
    status               text NOT NULL DEFAULT 'pending',
    created_at           timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS hr_pending_reviews_reviewer_idx
    ON hr_pending_reviews (reviewer_employee_id, status);
"""


_RDS_CA_BUNDLE = Path(__file__).resolve().with_name("global-bundle.pem")


def _agent_checkpoint_conn_string() -> str:
    """RDS IAM authentication for the `agent_checkpoint` role on `agent_state`."""
    cfg = hr_data_config()
    host, port = _split_endpoint(cfg.endpoint)
    token = _rds_auth_token(cfg.endpoint, "agent_checkpoint")
    return _libpq(
        host=host,
        port=str(port),
        dbname=cfg.checkpoint_database,
        user="agent_checkpoint",
        password=token,
        sslmode="verify-full",
        sslrootcert=str(_RDS_CA_BUNDLE),
    )


def _libpq(**kv: str) -> str:
    parts = []
    for key, value in kv.items():
        if value is None:
            continue
        escaped = value.replace("\\", "\\\\").replace("'", "\\'")
        parts.append(f"{key}='{escaped}'")
    return " ".join(parts)


def _secret_value(secret_name: str) -> dict[str, str]:
    """Kept for backwards-compatible unit test stubs; unused at runtime."""
    client = boto3.client("secretsmanager", region_name=runtime_region())
    resp = client.get_secret_value(SecretId=secret_name)
    raw = resp.get("SecretString") or "{}"
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise RuntimeError(f"Secret {secret_name!r} is not a JSON object")  # noqa: TRY004
    return value


def _rds_auth_token(endpoint: str, username: str) -> str:
    host, port = _split_endpoint(endpoint)
    client = boto3.client("rds", region_name=runtime_region())
    return client.generate_db_auth_token(
        DBHostname=host,
        Port=port,
        DBUsername=username,
    )


def _split_endpoint(endpoint: str) -> tuple[str, int]:
    if ":" in endpoint:
        host, _, port_str = endpoint.rpartition(":")
        try:
            return host, int(port_str)
        except ValueError:
            return endpoint, 5432
    return endpoint, 5432


def ensure_checkpoint_tables() -> None:
    """Create checkpoint tables synchronously via `agent_checkpoint` RDS IAM auth."""
    global _SETUP_COMPLETED
    if _SETUP_COMPLETED:
        return
    conn_str = _agent_checkpoint_conn_string()
    with PostgresSaver.from_conn_string(conn_str) as saver:
        saver.setup()
    _SETUP_COMPLETED = True


@contextlib.contextmanager
def open_checkpointer() -> Iterator[PostgresSaver]:
    """Synchronous `PostgresSaver` context manager (used by sync callers/tests)."""
    ensure_checkpoint_tables()
    with PostgresSaver.from_conn_string(_agent_checkpoint_conn_string()) as saver:
        yield saver


@contextlib.asynccontextmanager
async def async_open_checkpointer() -> AsyncIterator[AsyncPostgresSaver]:
    """Async `AsyncPostgresSaver` context manager required by `LangGraphAGUIAgent`."""
    global _ASYNC_SETUP_COMPLETED
    conn_str = _agent_checkpoint_conn_string()
    async with AsyncPostgresSaver.from_conn_string(conn_str) as saver:
        if not _ASYNC_SETUP_COMPLETED:
            await saver.setup()
            async with await psycopg.AsyncConnection.connect(
                conn_str, autocommit=True
            ) as aconn:
                await aconn.execute(_COMPANION_DDL)
            _ASYNC_SETUP_COMPLETED = True
        yield saver


async def claim_or_verify_thread_owner(thread_id: str, caller_sub: str) -> bool:
    """Bind `thread_id` to `caller_sub` on first use; return False if owned by someone else."""
    conn_str = _agent_checkpoint_conn_string()
    async with await psycopg.AsyncConnection.connect(
        conn_str, autocommit=True
    ) as aconn:
        await aconn.execute(_COMPANION_DDL)
        async with aconn.cursor() as cur:
            await cur.execute(
                """
                INSERT INTO hr_thread_owners (thread_id, owner_sub)
                VALUES (%s, %s)
                ON CONFLICT (thread_id) DO NOTHING
                """,
                (thread_id, caller_sub),
            )
            await cur.execute(
                "SELECT owner_sub FROM hr_thread_owners WHERE thread_id = %s",
                (thread_id,),
            )
            row = await cur.fetchone()
            return bool(row and row[0] == caller_sub)


async def save_pending_manager_review(payload: dict[str, Any], thread_id: str) -> None:
    """Persist an open manager-review card in `agent_state`."""
    conn_str = _agent_checkpoint_conn_string()
    async with await psycopg.AsyncConnection.connect(
        conn_str, autocommit=True
    ) as aconn:
        await aconn.execute(_COMPANION_DDL)
        async with aconn.cursor() as cur:
            await cur.execute(
                """
                INSERT INTO hr_pending_reviews
                    (request_id, thread_id, employee_id, reviewer_employee_id,
                     leave_type, start_date, end_date, days, reason, status)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, 'pending')
                ON CONFLICT (request_id) DO NOTHING
                """,
                (
                    str(payload["request_id"]),
                    str(thread_id),
                    str(payload["employee_id"]),
                    str(payload["reviewer_employee_id"]),
                    str(payload["leave_type"]),
                    str(payload["start_date"]),
                    str(payload["end_date"]),
                    int(payload["days"]),
                    str(payload.get("reason") or ""),
                ),
            )


async def get_pending_manager_review(request_id: str) -> dict[str, Any] | None:
    conn_str = _agent_checkpoint_conn_string()
    async with await psycopg.AsyncConnection.connect(
        conn_str, autocommit=True
    ) as aconn:
        await aconn.execute(_COMPANION_DDL)
        async with aconn.cursor() as cur:
            await cur.execute(
                """
                SELECT request_id, thread_id, employee_id, reviewer_employee_id,
                       leave_type, start_date, end_date, days, reason, status
                FROM hr_pending_reviews
                WHERE request_id = %s
                """,
                (request_id,),
            )
            row = await cur.fetchone()
            if not row:
                return None
            return {
                "kind": "manager_review",
                "request_id": row[0],
                "thread_id": row[1],
                "employee_id": row[2],
                "reviewer_employee_id": row[3],
                "leave_type": row[4],
                "start_date": row[5],
                "end_date": row[6],
                "days": row[7],
                "reason": row[8],
                "status": row[9],
            }


async def list_pending_manager_reviews(
    reviewer_employee_id: str,
) -> list[dict[str, Any]]:
    if not reviewer_employee_id:
        return []
    conn_str = _agent_checkpoint_conn_string()
    async with await psycopg.AsyncConnection.connect(
        conn_str, autocommit=True
    ) as aconn:
        await aconn.execute(_COMPANION_DDL)
        async with aconn.cursor() as cur:
            await cur.execute(
                """
                SELECT request_id, thread_id, employee_id, reviewer_employee_id,
                       leave_type, start_date, end_date, days, reason
                FROM hr_pending_reviews
                WHERE reviewer_employee_id = %s AND status = 'pending'
                ORDER BY created_at ASC
                """,
                (reviewer_employee_id,),
            )
            rows = await cur.fetchall()
            return [
                {
                    "kind": "manager_review",
                    "request_id": r[0],
                    "thread_id": r[1],
                    "employee_id": r[2],
                    "reviewer_employee_id": r[3],
                    "leave_type": r[4],
                    "start_date": r[5],
                    "end_date": r[6],
                    "days": r[7],
                    "reason": r[8],
                }
                for r in rows
            ]


async def complete_pending_manager_review(request_id: str, status: str) -> None:
    conn_str = _agent_checkpoint_conn_string()
    async with await psycopg.AsyncConnection.connect(
        conn_str, autocommit=True
    ) as aconn:
        await aconn.execute(_COMPANION_DDL)
        async with aconn.cursor() as cur:
            await cur.execute(
                "UPDATE hr_pending_reviews SET status = %s WHERE request_id = %s",
                (status, request_id),
            )


def _reset_setup_flag_for_tests() -> None:
    global _SETUP_COMPLETED, _ASYNC_SETUP_COMPLETED
    _SETUP_COMPLETED = False
    _ASYNC_SETUP_COMPLETED = False
