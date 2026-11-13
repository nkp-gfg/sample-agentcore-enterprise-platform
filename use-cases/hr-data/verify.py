#!/usr/bin/env python3
"""Verify hr-data (H1) without opening a SQL connection.

The laptop is not in the VPC, so this script does not reach the cluster on
5432. Phase H4's verify.py exercises the database through the gateway tools
from inside the VPC. H1's job here is to prove that:

  - the stack is deployed and healthy;
  - the four SSM parameters the HR plan commits to are present;
  - each one points at an object that currently exists (the Aurora cluster,
    the master secret) rather than a stale handle from a half-destroyed
    deploy.

Exit 0 with one `OK:` line on success; exit 1 with `FAIL: <cause>` on anything
else, never a Python traceback. Safe to run under the scrubbed environment
tests/test_verify.py applies: imports that need credentials happen inside
main() so a missing boto3 or missing AWS config is reported as `FAIL:` not a
collection error.

Usage: python use-cases/hr-data/verify.py
Respects PROJECT_NAME / ENVIRONMENT / AWS_REGION. `deploy.sh verify` runs this
automatically when hr-data is enabled in platform.yaml.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
if str(REPO / "scripts") not in sys.path:
    sys.path.insert(0, str(REPO / "scripts"))

CHECKPOINT_DATABASE_NAME = "agent_state"


def main() -> int:
    # Imports inside main() so a missing dependency surfaces through the
    # outer try/except as `FAIL:`, not a traceback at module load time.
    import boto3

    from infra_utils.platform_config import resolve_region

    project = os.environ.get("PROJECT_NAME", "agentcore-workshop")
    env = os.environ.get("ENVIRONMENT", "dev")
    region = resolve_region()

    ssm = boto3.client("ssm", region_name=region)
    rds = boto3.client("rds", region_name=region)
    secrets = boto3.client("secretsmanager", region_name=region)

    base = f"/{project}/{env}/use-cases/hr-data"
    required = {
        "endpoint": f"{base}/endpoint",
        "secret_name": f"{base}/secret-name",
        "database_name": f"{base}/database-name",
        "checkpoint_database": f"{base}/checkpoint-database",
    }

    values: dict[str, str] = {}
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
    for key, name in required.items():
        values[key] = found[name]

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
    if not cluster.get("DeletionProtection"):
        # retain_data: true is the default. If this is off, a destroy can
        # drop the production data. Fail loudly even though the stack
        # otherwise looks healthy.
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

    print(
        "OK: hr-data cluster "
        f"{cluster_id} available (hr db {values['database_name']!r}, "
        f"checkpoint db {values['checkpoint_database']!r}, "
        f"secret {values['secret_name']!r})"
    )
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:  # noqa: BLE001 — scrubbed env, no network: FAIL, no trace
        sys.exit(f"FAIL: {type(exc).__name__}: {exc}")
