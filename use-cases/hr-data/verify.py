#!/usr/bin/env python3
"""Verify hr-data (H1) over AWS APIs and RDS Data API (HTTPS, no VPC needed).

The laptop is not in the VPC, so this script does not reach the cluster on
port 5432. Instead it proves:

  - the four SSM parameters the HR plan commits to are present;
  - the Aurora cluster is `available`, encrypted, IAM-auth enabled, Data API
    enabled (`HttpEndpointEnabled`), and has `DeletionProtection` matching
    `retain_data` in `platform.yaml`;
  - the master secret exists and is CMK-encrypted;
  - via RDS Data API (HTTPS), all six HR tables, all five database roles, and
    the `agent_state` database actually exist inside PostgreSQL (and when
    `seed: true`, the nine demo employee rows are present).

Exit 0 with one `OK:` line on success; exit 1 with `FAIL: <cause>` on anything
else, never a Python traceback.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
if str(REPO / "scripts") not in sys.path:
    sys.path.insert(0, str(REPO / "scripts"))
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

CHECKPOINT_DATABASE_NAME = "agent_state"
EXPECTED_TABLES = (
    "employees",
    "salaries",
    "leave_balances",
    "leave_requests",
    "payroll_items",
    "decision_log",
)
EXPECTED_ROLES = (
    "hr_reader",
    "hr_writer",
    "hr_audit",
    "hr_identity",
    "agent_checkpoint",
)


def _hr_data_manifest_settings() -> tuple[bool, bool]:
    """Return `(retain_data, seed)` from platform.yaml if present."""
    from infra_utils.platform_config import load_platform_config

    cfg_path = Path(os.environ.get("PLATFORM_CONFIG") or (REPO / "platform.yaml"))
    if not cfg_path.is_file():
        return True, False
    cfg = load_platform_config(cfg_path)
    block = (cfg.use_cases or {}).get("hr-data") or {}
    return bool(block.get("retain_data", True)), bool(block.get("seed", False))


def main() -> int:
    import boto3

    from infra_utils.platform_config import resolve_region

    project = os.environ.get("PROJECT_NAME", "agentcore-workshop")
    env = os.environ.get("ENVIRONMENT", "dev")
    region = resolve_region()
    expect_retain, expect_seed = _hr_data_manifest_settings()

    ssm = boto3.client("ssm", region_name=region)
    rds = boto3.client("rds", region_name=region)
    rds_data = boto3.client("rds-data", region_name=region)
    secrets = boto3.client("secretsmanager", region_name=region)

    base = f"/{project}/{env}/use-cases/hr-data"
    required = {
        "endpoint": f"{base}/endpoint",
        "secret_name": f"{base}/secret-name",
        "database_name": f"{base}/database-name",
        "checkpoint_database": f"{base}/checkpoint-database",
    }

    try:
        response = ssm.get_parameters(Names=list(required.values()))
    except ssm.exceptions.ClientError as exc:  # pragma: no cover
        sys.exit(f"FAIL: SSM GetParameters refused: {exc}")

    found = {p["Name"]: p["Value"] for p in response["Parameters"]}
    missing = [name for name in required.values() if name not in found]
    if missing:
        sys.exit(
            "FAIL: hr-data SSM parameters missing — is the use case deployed? "
            f"Missing: {', '.join(sorted(missing))}"
        )
    values = {key: found[name] for key, name in required.items()}

    if values["checkpoint_database"] != CHECKPOINT_DATABASE_NAME:
        sys.exit(
            "FAIL: "
            f"{required['checkpoint_database']} is "
            f"{values['checkpoint_database']!r}, expected "
            f"{CHECKPOINT_DATABASE_NAME!r}"
        )

    cluster_id = f"{project}-{env}-uc-hr-data"
    try:
        clusters = rds.describe_db_clusters(DBClusterIdentifier=cluster_id)[
            "DBClusters"
        ]
    except rds.exceptions.DBClusterNotFoundFault:
        sys.exit(
            f"FAIL: Aurora cluster {cluster_id} not found — is the stack deployed?"
        )
    if not clusters:
        sys.exit(f"FAIL: Aurora cluster {cluster_id} not found")

    cluster = clusters[0]
    status = cluster.get("Status")
    if status != "available":
        sys.exit(
            f"FAIL: Aurora cluster {cluster_id} is in status {status!r}, "
            "expected 'available'"
        )
    if not cluster.get("StorageEncrypted"):
        sys.exit(f"FAIL: cluster {cluster_id} storage is not encrypted")
    if not cluster.get("IAMDatabaseAuthenticationEnabled"):
        sys.exit(f"FAIL: cluster {cluster_id} does not have IAM auth enabled")
    if not cluster.get("HttpEndpointEnabled"):
        sys.exit(f"FAIL: cluster {cluster_id} does not have RDS Data API enabled")
    if expect_retain and not cluster.get("DeletionProtection"):
        sys.exit(f"FAIL: cluster {cluster_id} deletion protection is off")

    endpoint = cluster.get("Endpoint")
    if endpoint and endpoint != values["endpoint"]:
        sys.exit(
            f"FAIL: SSM endpoint {values['endpoint']!r} does not match the "
            f"live cluster endpoint {endpoint!r}"
        )

    try:
        secret = secrets.describe_secret(SecretId=values["secret_name"])
    except secrets.exceptions.ResourceNotFoundException:
        sys.exit(
            f"FAIL: master secret {values['secret_name']} missing from Secrets Manager"
        )
    if not secret.get("KmsKeyId"):
        sys.exit(f"FAIL: master secret {values['secret_name']} is not CMK-encrypted")

    cluster_arn = cluster["DBClusterArn"]
    secret_arn = secret["ARN"]

    # Verify schema, roles, checkpoint db, and optional seed over HTTPS Data API.
    tables_res = rds_data.execute_statement(
        resourceArn=cluster_arn,
        secretArn=secret_arn,
        database=values["database_name"],
        sql=(
            "SELECT table_name FROM information_schema.tables "
            "WHERE table_schema = 'public'"
        ),
    )
    present_tables = {row[0]["stringValue"] for row in tables_res.get("records", [])}
    missing_tables = sorted(set(EXPECTED_TABLES) - present_tables)
    if missing_tables:
        sys.exit(f"FAIL: {values['database_name']} missing table(s): {missing_tables}")

    roles_res = rds_data.execute_statement(
        resourceArn=cluster_arn,
        secretArn=secret_arn,
        database=values["database_name"],
        sql="SELECT rolname FROM pg_roles",
    )
    present_roles = {row[0]["stringValue"] for row in roles_res.get("records", [])}
    missing_roles = sorted(set(EXPECTED_ROLES) - present_roles)
    if missing_roles:
        sys.exit(f"FAIL: cluster missing DB role(s): {missing_roles}")

    rds_data.execute_statement(
        resourceArn=cluster_arn,
        secretArn=secret_arn,
        database=values["checkpoint_database"],
        sql="SELECT 1",
    )

    if expect_seed:
        count_res = rds_data.execute_statement(
            resourceArn=cluster_arn,
            secretArn=secret_arn,
            database=values["database_name"],
            sql="SELECT count(*) FROM employees",
        )
        emp_count = count_res["records"][0][0]["longValue"]
        if emp_count < 9:
            sys.exit(f"FAIL: seed=true but employees table has only {emp_count} row(s)")

    print(
        "OK: hr-data cluster "
        f"{cluster_id} available (hr db {values['database_name']!r}, "
        f"checkpoint db {values['checkpoint_database']!r}, "
        "6 tables + 5 roles verified)"
    )
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:  # noqa: BLE001 — scrubbed env, no network: FAIL, no trace
        sys.exit(f"FAIL: {type(exc).__name__}: {exc}")
