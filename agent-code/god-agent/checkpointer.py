"""PostgresSaver on the `agent_state` database.

`custom-app-plan/god-agent.md` § Checkpointer:

    Only the god agent is compiled with a checkpointer. The department
    graphs are compiled without one, so a pause belongs to the parent's
    thread and `Command(resume=...)` on that thread continues the leaf that
    paused.

    H1 creates an empty database named `agent_state` on the same cluster.
    The agent does not create that database. It reads the name from SSM
    (`use-cases/hr-data/checkpoint-database`) and calls
    `PostgresSaver.setup()` to create the checkpoint tables. The import is
    `langgraph.checkpoint.postgres`. This is not the `hr` database and it
    is not `MemorySaver`. `MemorySaver` dies with the process. The runtime
    container is replaced. A review that can sit for a day has to be in
    Postgres.

Operational notes:

- Setup runs with the H1 **master secret** (owner of the empty database),
  called once per container boot. `PostgresSaver.setup()` is idempotent.
- Steady-state connections use **agent_checkpoint** (RDS IAM auth, 15 min
  tokens). The runtime has no access to the `hr` database and no SELECT on
  any HR table. `docs/hr/modules.md` § Database roles.
- `thread_id` is a UUID. The runtime passes it per-request; this module is
  a thin factory.
"""

from __future__ import annotations

import contextlib
import json
import logging
from collections.abc import Iterator

import boto3
from langgraph.checkpoint.postgres import PostgresSaver
from shared.region import runtime_region
from ssm_config import hr_data_config

logger = logging.getLogger(__name__)


_SETUP_COMPLETED = False
_SETUP_MARKER_KEY = "_god_agent_checkpoint_setup_done"


# ─── Connection strings ─────────────────────────────────────────────────────


def _master_conn_string() -> str:
    """Build a libpq connection string using the H1 master secret.

    Used ONLY by `PostgresSaver.setup()` to create the checkpoint tables.
    After setup completes, the agent switches to the `agent_checkpoint`
    role via RDS IAM auth.
    """

    cfg = hr_data_config()
    secret = _secret_value(cfg.master_secret_name)
    username = secret.get("username") or "postgres"
    password = secret.get("password") or ""
    if not password:
        raise RuntimeError(
            "H1 master secret has no password — refusing to build a "
            "connection string. Check the secret shape in hr-data/stack.py."
        )

    return _libpq(
        host=cfg.endpoint,
        dbname=cfg.checkpoint_database,
        user=username,
        password=password,
    )


def _agent_checkpoint_conn_string() -> str:
    """RDS IAM authentication for the `agent_checkpoint` role.

    AWS mints a 15-minute token per connect (`docs/hr/modules.md`). We mint
    a fresh one every time the entry point opens the checkpointer, so the
    token never lands in a cache that outlives the request.
    """

    cfg = hr_data_config()
    token = _rds_auth_token(cfg.endpoint, "agent_checkpoint")
    return _libpq(
        host=cfg.endpoint,
        dbname=cfg.checkpoint_database,
        user="agent_checkpoint",
        password=token,
        sslmode="require",
    )


def _libpq(**kv: str) -> str:
    """Build a libpq keyword/value connection string with safe quoting.

    Values go through single-quote escaping — libpq's rules — so an endpoint
    with a dot or a secret with a special character never changes the meaning
    of a later keyword.
    """

    parts = []
    for key, value in kv.items():
        if value is None:
            continue
        escaped = value.replace("\\", "\\\\").replace("'", "\\'")
        parts.append(f"{key}='{escaped}'")
    return " ".join(parts)


# ─── AWS helpers ────────────────────────────────────────────────────────────


def _secret_value(secret_name: str) -> dict[str, str]:
    client = boto3.client("secretsmanager", region_name=runtime_region())
    resp = client.get_secret_value(SecretId=secret_name)
    raw = resp.get("SecretString") or "{}"
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise RuntimeError(
            f"Secret {secret_name!r} is not JSON — expected the Aurora "
            'default shape (`{{"username": ..., "password": ...}}`).'
        ) from exc
    if not isinstance(value, dict):
        # The secret shape is fixed by H1 (Aurora default `{"username",
        # "password"}`); anything else is a configuration error, so surface
        # it as a RuntimeError to the operator rather than an opaque KeyError.
        raise RuntimeError(  # noqa: TRY004 — operator-facing config failure
            f"Secret {secret_name!r} is not a JSON object"
        )
    return value


def _rds_auth_token(endpoint: str, username: str) -> str:
    """Mint a fresh RDS IAM auth token for `username` at `endpoint`.

    Parses `host:port` from the endpoint; defaults to the Postgres port.
    """

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


# ─── Public entry points ────────────────────────────────────────────────────


def ensure_checkpoint_tables() -> None:
    """Create the checkpoint tables once per process.

    Called from the entry point before the first request. `PostgresSaver.
    setup()` is idempotent, so the one-shot guard is a latency optimisation
    rather than a correctness requirement.
    """

    global _SETUP_COMPLETED
    if _SETUP_COMPLETED:
        return
    with PostgresSaver.from_conn_string(_master_conn_string()) as saver:
        saver.setup()
    _SETUP_COMPLETED = True


@contextlib.contextmanager
def open_checkpointer() -> Iterator[PostgresSaver]:
    """Open a short-lived `PostgresSaver` for one invocation.

    The runtime opens a new connection pool per request so the `agent_
    checkpoint` IAM token never outlives the turn. Setup runs on the first
    call and short-circuits thereafter.
    """

    ensure_checkpoint_tables()
    with PostgresSaver.from_conn_string(_agent_checkpoint_conn_string()) as saver:
        yield saver


def _reset_setup_flag_for_tests() -> None:
    global _SETUP_COMPLETED
    _SETUP_COMPLETED = False
