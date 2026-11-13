"""hr-data (H1): Aurora PostgreSQL Serverless v2 for the HR assistant.

Spec: docs/hr/modules.md § hr-data, docs/hr/schema.md, docs/hr/policy.md, and
custom-app-plan/phases.md § Layer 1 detail. This stack:

  - Creates one Aurora PostgreSQL Serverless v2 cluster in the module C
    private subnets, storage-encrypted with the module E KMS CMK.
  - Creates the `hr` database (from `use_cases.hr-data.database_name`,
    default "hr") and an empty `agent_state` database for the god agent's
    LangGraph checkpointer. H1 does NOT create the checkpoint tables; the
    agent runs `PostgresSaver.setup()` itself at Layer 2.
  - Applies `provisioner/schema.sql` to the `hr` database on every deploy
    (idempotent). Applies `provisioner/seed.sql` only when
    `use_cases.hr-data.seed: true`.
  - Creates the five database roles (`hr_reader`, `hr_writer`, `hr_audit`,
    `hr_identity`, and `agent_checkpoint`) with the exact grants from
    docs/hr/modules.md. Lambdas will use RDS IAM authentication (H3, H4).
    The master secret is for schema apply only.
  - Publishes four SSM parameters under
    `/{project}/{environment}/use-cases/hr-data/`: endpoint, secret-name,
    database-name, checkpoint-database. No passwords in SSM.

Deliberate non-goals (docs/hr/README.md "What is not in v1"):
  - No HR Lambdas, no gateway targets, no Cedar permits (H4).
  - No pre-token Lambda (H3).
  - No Postgres row-level security.

Platform-interface compliance (docs/PLATFORM_INTERFACE.md):
  - Reads networking + security outputs through SSM only; never imports
    from stacks/*.
  - No CDK cross-stack dependency on a platform stack, so
    `deploy.sh deploy --stack ...-uc-hr-data` deploys only this stack.

Retention (docs/hr/modules.md): `retain_data: true` is the default. With it,
`destroy --stack` removes the stack and keeps the cluster, the secret, and
the backups. Dropping salary rows is a later, explicit step.
"""

from __future__ import annotations

import json
from pathlib import Path

import aws_cdk as cdk
from aws_cdk import aws_ec2 as ec2
from aws_cdk import aws_iam as iam
from aws_cdk import aws_kms as kms
from aws_cdk import aws_lambda as lambda_
from aws_cdk import aws_logs as logs
from aws_cdk import aws_rds as rds
from aws_cdk import aws_secretsmanager as secretsmanager
from aws_cdk import aws_ssm as ssm
from aws_cdk import custom_resources as cr
from constructs import Construct

CHECKPOINT_DATABASE_NAME = "agent_state"


class HrDataStack(cdk.Stack):
    def __init__(
        self,
        scope: Construct,
        id: str,
        *,
        ctx: dict,
        config: dict,
        **kwargs,
    ) -> None:
        super().__init__(scope, id, **kwargs)

        prefix = ctx["prefix"]
        ssm_prefix = ctx["ssm_prefix"]

        database_name = str(config.get("database_name", "hr"))
        retain_data = bool(config.get("retain_data", True))
        seed = bool(config.get("seed", False))

        lifecycle = (
            cdk.RemovalPolicy.RETAIN if retain_data else cdk.RemovalPolicy.DESTROY
        )

        # --------------------------------------------------------------
        # Platform imports (SSM only — never import stacks/*)
        # --------------------------------------------------------------

        vpc_id = ssm.StringParameter.value_for_string_parameter(
            self, f"{ssm_prefix}/networking/vpc-id"
        )
        private_subnet_ids_param = ssm.StringParameter.value_for_string_parameter(
            self, f"{ssm_prefix}/networking/private-subnet-ids"
        )
        # Networking publishes exactly two private subnets today (two AZs,
        # docs/modules/networking.md). Fn::Select by index renders as a
        # CloudFormation intrinsic, so this stays synth-safe without an
        # AWS call. If a future networking stack publishes more than two
        # subnets, add them here explicitly; Aurora requires ≥2.
        subnet_ids_list = cdk.Fn.split(",", private_subnet_ids_param)
        private_subnet_ids = [
            cdk.Fn.select(0, subnet_ids_list),
            cdk.Fn.select(1, subnet_ids_list),
        ]
        runtime_security_group_id = ssm.StringParameter.value_for_string_parameter(
            self, f"{ssm_prefix}/networking/runtime-security-group-id"
        )

        # Security stack does not publish an SSM parameter; its KMS CMK is
        # exposed only as a Python attribute. Use the deterministic alias
        # (stacks/security_stack.py line 36). This produces a stable grant
        # path for Aurora, the master secret, and the custom resource.
        kms_alias = kms.Alias.from_alias_name(
            self, "PlatformKey", f"alias/{prefix}-agentcore"
        )

        # --------------------------------------------------------------
        # Networking: dedicated DB security group and the one egress rule
        # that lets runtime pods reach it. The runtime SG itself is not
        # modified; we add a new CfnSecurityGroupEgress that lives in this
        # stack and references the imported SG by id.
        # --------------------------------------------------------------

        db_security_group = ec2.CfnSecurityGroup(
            self,
            "DBSecurityGroup",
            group_description=f"HR data Aurora PostgreSQL SG for {prefix}",
            vpc_id=vpc_id,
            security_group_ingress=[
                ec2.CfnSecurityGroup.IngressProperty(
                    ip_protocol="tcp",
                    from_port=5432,
                    to_port=5432,
                    source_security_group_id=runtime_security_group_id,
                    description="PostgreSQL 5432 from AgentCore runtime pods",
                )
            ],
        )

        ec2.CfnSecurityGroupEgress(
            self,
            "RuntimeToDBEgress",
            group_id=runtime_security_group_id,
            ip_protocol="tcp",
            from_port=5432,
            to_port=5432,
            destination_security_group_id=db_security_group.attr_group_id,
            description="To hr-data Aurora PostgreSQL",
        )

        db_subnet_group = rds.CfnDBSubnetGroup(
            self,
            "SubnetGroup",
            db_subnet_group_description=f"HR data subnet group for {prefix}",
            subnet_ids=private_subnet_ids,
        )
        db_subnet_group.apply_removal_policy(lifecycle)

        # --------------------------------------------------------------
        # Master secret. One record with username + password. Encrypted
        # with the platform CMK. Retained in production, so credentials
        # survive a stack delete and can be used to recover.
        # --------------------------------------------------------------

        master_secret = secretsmanager.Secret(
            self,
            "MasterSecret",
            description=f"HR data master credentials for {prefix}",
            encryption_key=kms_alias,
            generate_secret_string=secretsmanager.SecretStringGenerator(
                secret_string_template=json.dumps({"username": "hr_master"}),
                generate_string_key="password",
                exclude_characters="\"@/\\'",
                password_length=32,
            ),
            removal_policy=lifecycle,
        )

        # --------------------------------------------------------------
        # Aurora PostgreSQL Serverless v2 cluster (L1 to avoid synth-time
        # VPC lookups; the platform interface forbids importing stacks/*).
        # --------------------------------------------------------------

        cluster = rds.CfnDBCluster(
            self,
            "Cluster",
            engine="aurora-postgresql",
            engine_mode="provisioned",
            # Aurora PostgreSQL 15.x is the current major on Serverless v2 in
            # all AgentCore regions; Data API is supported since 15.3.
            engine_version="15.5",
            db_cluster_identifier=f"{prefix}-uc-hr-data",
            db_subnet_group_name=db_subnet_group.ref,
            vpc_security_group_ids=[db_security_group.attr_group_id],
            master_username="hr_master",
            # Dynamic reference; the value never appears in the synthesized
            # template or in cdk.out. Same pattern as stacks/auth_stack.py.
            master_user_password=cdk.SecretValue.secrets_manager(
                master_secret.secret_name, json_field="password"
            ).unsafe_unwrap(),
            database_name=database_name,
            storage_encrypted=True,
            kms_key_id=kms_alias.key_arn,
            enable_iam_database_authentication=True,
            deletion_protection=retain_data,
            backup_retention_period=14,
            # Data API: the provisioner Lambda and future admin tooling can
            # run SQL without a VPC connection. Not reachable by the H4
            # Lambdas: those connect on 5432 with RDS IAM tokens from inside
            # the VPC (docs/hr/modules.md).
            enable_http_endpoint=True,
            enable_cloudwatch_logs_exports=["postgresql"],
            serverless_v2_scaling_configuration=(
                rds.CfnDBCluster.ServerlessV2ScalingConfigurationProperty(
                    min_capacity=0.5,
                    max_capacity=2.0,
                )
            ),
        )
        cluster.apply_removal_policy(lifecycle)

        instance = rds.CfnDBInstance(
            self,
            "WriterInstance",
            db_cluster_identifier=cluster.ref,
            db_instance_class="db.serverless",
            engine="aurora-postgresql",
            publicly_accessible=False,
        )
        instance.apply_removal_policy(lifecycle)
        instance.add_dependency(cluster)

        # --------------------------------------------------------------
        # CloudWatch log group for the exported postgresql log stream.
        # Matches the retention allow-list in stacks/observability_stack.py
        # (30/90/180/365). HR keeps 365 days.
        # --------------------------------------------------------------

        logs.LogGroup(
            self,
            "PostgresLogs",
            log_group_name=(f"/aws/rds/cluster/{prefix}-uc-hr-data/postgresql"),
            retention=logs.RetentionDays.ONE_YEAR,
            removal_policy=lifecycle,
        )

        # --------------------------------------------------------------
        # Provisioner Lambda + CloudFormation custom resource. Runs on
        # every CREATE/UPDATE to apply schema.sql and (optionally) seed.sql.
        # DELETE is a no-op so `destroy --stack` never drops salary rows.
        # --------------------------------------------------------------

        provisioner_role = iam.Role(
            self,
            "ProvisionerRole",
            assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"),
            managed_policies=[
                iam.ManagedPolicy.from_aws_managed_policy_name(
                    "service-role/AWSLambdaBasicExecutionRole"
                ),
            ],
        )
        provisioner_role.add_to_policy(
            iam.PolicyStatement(
                actions=[
                    "rds-data:ExecuteStatement",
                    "rds-data:BatchExecuteStatement",
                    "rds-data:BeginTransaction",
                    "rds-data:CommitTransaction",
                    "rds-data:RollbackTransaction",
                ],
                resources=[cluster.attr_db_cluster_arn],
            )
        )
        provisioner_role.add_to_policy(
            iam.PolicyStatement(
                actions=["secretsmanager:GetSecretValue"],
                resources=[master_secret.secret_arn],
            )
        )
        # The master secret is CMK-encrypted, so the provisioner needs
        # Decrypt on the key, scoped via kms:ViaService to Secrets Manager
        # so a compromised provisioner cannot abuse it elsewhere.
        provisioner_role.add_to_policy(
            iam.PolicyStatement(
                actions=["kms:Decrypt"],
                resources=[kms_alias.key_arn],
                conditions={
                    "StringEquals": {
                        "kms:ViaService": (
                            f"secretsmanager.{self.region}.amazonaws.com"
                        )
                    }
                },
            )
        )

        provisioner = lambda_.Function(
            self,
            "Provisioner",
            runtime=lambda_.Runtime.PYTHON_3_13,
            handler="handler.on_event",
            code=lambda_.Code.from_asset(str(Path(__file__).parent / "provisioner")),
            role=provisioner_role,
            timeout=cdk.Duration.minutes(5),
            memory_size=512,
            description=f"Applies schema.sql and seed.sql for {prefix}-uc-hr-data",
        )

        provider = cr.Provider(
            self,
            "ProvisionerProvider",
            on_event_handler=provisioner,
        )

        provision = cdk.CustomResource(
            self,
            "Provision",
            service_token=provider.service_token,
            properties={
                "ClusterArn": cluster.attr_db_cluster_arn,
                "SecretArn": master_secret.secret_arn,
                "Database": database_name,
                "CheckpointDb": CHECKPOINT_DATABASE_NAME,
                "Seed": "true" if seed else "false",
                # Bust the custom resource cache on every change so an updated
                # schema.sql or a flipped seed flag triggers a re-run.
                "SchemaVersion": _asset_fingerprint(
                    Path(__file__).parent / "provisioner"
                ),
            },
        )
        provision.node.add_dependency(instance)

        # --------------------------------------------------------------
        # Platform-interface outputs (docs/hr/modules.md § SSM interface).
        # No passwords.
        # --------------------------------------------------------------

        ssm.StringParameter(
            self,
            "SSMEndpoint",
            parameter_name=f"{ssm_prefix}/use-cases/hr-data/endpoint",
            string_value=cluster.attr_endpoint_address,
            description=(
                "Aurora cluster writer endpoint for use-cases/hr-data. "
                "Consumers: hr-tools, hr-identity, operators."
            ),
        )
        ssm.StringParameter(
            self,
            "SSMSecretName",
            parameter_name=f"{ssm_prefix}/use-cases/hr-data/secret-name",
            string_value=master_secret.secret_name,
            description=(
                "Secrets Manager name of the HR master credentials. Lambdas "
                "use RDS IAM auth for runtime queries; this is for the "
                "provisioner and operator recovery only."
            ),
        )
        ssm.StringParameter(
            self,
            "SSMDatabaseName",
            parameter_name=f"{ssm_prefix}/use-cases/hr-data/database-name",
            string_value=database_name,
            description=(
                "HR database name on the cluster. Default 'hr'. Consumers: "
                "hr-tools, hr-identity."
            ),
        )
        ssm.StringParameter(
            self,
            "SSMCheckpointDatabase",
            parameter_name=(f"{ssm_prefix}/use-cases/hr-data/checkpoint-database"),
            string_value=CHECKPOINT_DATABASE_NAME,
            description=(
                "Empty database the god agent initialises for its LangGraph "
                "Postgres checkpointer. H1 creates the database only; the "
                "agent creates the checkpoint tables with PostgresSaver.setup()."
            ),
        )

        cdk.CfnOutput(self, "ClusterArn", value=cluster.attr_db_cluster_arn)
        cdk.CfnOutput(self, "SecretName", value=master_secret.secret_name)
        cdk.CfnOutput(self, "DatabaseName", value=database_name)
        cdk.CfnOutput(self, "CheckpointDatabase", value=CHECKPOINT_DATABASE_NAME)


def _asset_fingerprint(directory: Path) -> str:
    """Return a short, deterministic hash of every file in a directory.

    CDK fingerprints Lambda assets internally, but the custom-resource property
    `SchemaVersion` has to change for CloudFormation to invoke the provider on
    an UPDATE. Hashing the SQL + handler guarantees that every change to
    schema.sql or seed.sql forces a re-run; a cosmetic change to this file
    does not.
    """
    import hashlib

    hasher = hashlib.sha256()
    for file in sorted(directory.rglob("*")):
        if not file.is_file():
            continue
        hasher.update(file.name.encode("utf-8"))
        hasher.update(b"\0")
        hasher.update(file.read_bytes())
        hasher.update(b"\0")
    return hasher.hexdigest()[:12]


def build(app, ctx: dict, config: dict) -> None:
    """Entry point the platform calls for each enabled use case."""
    HrDataStack(
        app,
        f"{ctx['prefix']}-uc-hr-data",
        ctx=ctx,
        config=config,
        env=ctx["cdk_env"],
    )
