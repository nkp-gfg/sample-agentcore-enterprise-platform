"""hr-identity (H3): pre-token-generation Lambda on the Cognito user pool.

Spec: docs/hr/modules.md § hr-identity + § H3 claims, docs/hr/policy.md,
docs/hr/acceptance.md § H3, custom-app-plan/phases.md § H3 and § Layer 1
detail § H3, custom-app-plan/review.md § Locked decisions.

This stack builds:
  - One Python 3.13 Lambda function (the pre-token handler in `lambda/`).
  - Its IAM role: VPC ENI management, rds-db:connect as the hr_identity
    database user, SSM GetParameter on the four inputs it reads at cold
    start, and CloudWatch Logs.
  - No new security group. The Lambda joins the module C runtime SG
    (looked up by id from SSM) because hr-data's DB SG only accepts
    ingress from that one SG; creating a new SG here would need a
    matching ingress rule added into hr-data's SG, and hr-data does not
    expose its SG id through SSM. Reusing the runtime SG also keeps HTTPS
    egress to STS / RDS / SSM / CloudWatch Logs routed through the same
    VPC endpoints the runtime pods already use.
  - A CloudWatch log group with 365-day retention (matches every HR
    component's retention per docs/hr/modules.md).
  - A Lambda layer whose asset is `layer/`. The pure-Python PostgreSQL
    driver (pg8000) is installed into `layer/python/` by the operator
    before `cdk deploy` runs (see walkthrough.md). The layer source dir
    stays part of the asset so every change picks up a new asset hash.
  - Two AwsCustomResource nodes on the Cognito user pool (looked up by
    id from SSM — never `UserPool.from_lookup`, never `import stacks`):
    one ATTACHes the pre-token trigger via UpdateUserPool on CREATE and
    UPDATE; one DETACHes it on DELETE so `destroy --stack` leaves module
    3's user pool clean.
  - lambda.CfnPermission that lets cognito-idp.amazonaws.com invoke the
    function on that user pool's ARN (the trigger cannot fire without
    this permission even after UpdateUserPool succeeds).
  - One SSM parameter under /{project}/{environment}/use-cases/hr-identity/
    carrying the Lambda ARN, for operators and the detach-on-destroy step.

Platform-interface compliance (docs/PLATFORM_INTERFACE.md):
  - Reads every platform input through SSM parameters only; no `import
    stacks`, no synth-time AWS calls (no `Vpc.from_lookup`, no
    `UserPool.from_lookup`).
  - Takes no CDK cross-stack dependency on auth, networking, security,
    or hr-data. `deploy.sh deploy --stack ...-uc-hr-identity` deploys
    only this stack (docs/hr/modules.md § Deploy and destroy).
"""

from __future__ import annotations

import shutil
import subprocess  # nosec B404 — pip-install into the layer asset at synth time
import sys
from pathlib import Path

import aws_cdk as cdk
from aws_cdk import aws_iam as iam
from aws_cdk import aws_lambda as lambda_
from aws_cdk import aws_logs as logs
from aws_cdk import aws_ssm as ssm
from aws_cdk import custom_resources as cr
from constructs import Construct

HR_IDENTITY_DB_USER = "hr_identity"


class HrIdentityStack(cdk.Stack):
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
        del config  # hr-identity has no tunables in v1; present for build() parity

        prefix = ctx["prefix"]
        ssm_prefix = ctx["ssm_prefix"]

        # --------------------------------------------------------------
        # Platform inputs via SSM (deploy-time resolution; no AWS calls
        # at synth; no `import stacks.*`).
        # --------------------------------------------------------------

        user_pool_id = ssm.StringParameter.value_for_string_parameter(
            self, f"{ssm_prefix}/auth/user-pool-id"
        )
        db_endpoint = ssm.StringParameter.value_for_string_parameter(
            self, f"{ssm_prefix}/use-cases/hr-data/endpoint"
        )
        db_name = ssm.StringParameter.value_for_string_parameter(
            self, f"{ssm_prefix}/use-cases/hr-data/database-name"
        )
        private_subnet_ids_param = ssm.StringParameter.value_for_string_parameter(
            self, f"{ssm_prefix}/networking/private-subnet-ids"
        )
        runtime_security_group_id = ssm.StringParameter.value_for_string_parameter(
            self, f"{ssm_prefix}/networking/runtime-security-group-id"
        )

        # --------------------------------------------------------------
        # IAM role. RDS IAM auth needs rds-db:connect on a resource ARN
        # that names the DB user, not a DBI. Scoping to the user keeps
        # this role safely useless for every other database role.
        # --------------------------------------------------------------

        lambda_role = iam.Role(
            self,
            "FunctionRole",
            assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"),
            managed_policies=[
                iam.ManagedPolicy.from_aws_managed_policy_name(
                    "service-role/AWSLambdaVPCAccessExecutionRole"
                ),
            ],
            description=(
                f"Execution role for {prefix}-uc-hr-identity-pretoken. "
                "RDS IAM auth as the hr_identity database user, VPC + Logs."
            ),
        )
        # rds-db:connect targets a virtual resource that names the
        # `dbuser` the token is signed for. Resource shape per
        # https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/UsingWithRDS.IAMDBAuth.IAMPolicy.html.
        # dbi-resource-id is wildcarded because the Aurora cluster lives
        # in the hr-data stack and we discover it by endpoint at runtime.
        lambda_role.add_to_policy(
            iam.PolicyStatement(
                sid="RdsIamAuthAsHrIdentity",
                actions=["rds-db:connect"],
                resources=[
                    self.format_arn(
                        service="rds-db",
                        resource="dbuser",
                        resource_name=f"*/{HR_IDENTITY_DB_USER}",
                        arn_format=cdk.ArnFormat.COLON_RESOURCE_NAME,
                    ),
                ],
            )
        )

        # --------------------------------------------------------------
        # CloudWatch log group with 365-day retention. HR keeps 365 days
        # (docs/hr/modules.md § Kill switch and audit export).
        # --------------------------------------------------------------

        log_group = logs.LogGroup(
            self,
            "FunctionLogs",
            log_group_name=f"/aws/lambda/{prefix}-uc-hr-identity-pretoken",
            retention=logs.RetentionDays.ONE_YEAR,
            removal_policy=cdk.RemovalPolicy.RETAIN_ON_UPDATE_OR_DELETE,
        )

        # --------------------------------------------------------------
        # Lambda layer carrying the pure-Python PostgreSQL driver
        # (pg8000). The asset is `layer/` with a committed `python/`
        # directory; the operator installs pg8000 into it before
        # `cdk deploy` per walkthrough.md. The CDK synth works offline
        # with an empty directory — the Lambda would fail at import
        # time, but no synth test depends on that.
        # --------------------------------------------------------------

        # pg8000 is pure Python, so a synth-time `pip install --target`
        # populates `layer/python/` deterministically on any deployer OS.
        # The committed `.gitignore` keeps the installed wheels out of
        # version control; the asset hash reflects their content.
        _install_pg8000_into_layer(Path(__file__).parent / "layer" / "python")

        driver_layer = lambda_.LayerVersion(
            self,
            "PostgresDriverLayer",
            layer_version_name=f"{prefix}-uc-hr-identity-pg",
            code=lambda_.Code.from_asset(str(Path(__file__).parent / "layer")),
            compatible_runtimes=[lambda_.Runtime.PYTHON_3_13],
            compatible_architectures=[lambda_.Architecture.X86_64],
            description=(
                "Pure-Python PostgreSQL driver (pg8000) for hr-identity. "
                "Installed into layer/python/ at CDK synth so no manual "
                "pip-install step is required before deploy."
            ),
        )

        # --------------------------------------------------------------
        # The pre-token function. Asset: the `lambda/` folder. Memory and
        # timeout are generous enough for a single cold-start DB handshake
        # plus a one-row lookup; the 5-second connect timeout in the
        # handler keeps a wedged database from stretching the trigger.
        # --------------------------------------------------------------

        pretoken_function = lambda_.Function(
            self,
            "PretokenFunction",
            function_name=f"{prefix}-uc-hr-identity-pretoken",
            runtime=lambda_.Runtime.PYTHON_3_13,
            architecture=lambda_.Architecture.X86_64,
            handler="handler.handler",
            code=lambda_.Code.from_asset(str(Path(__file__).parent / "lambda")),
            role=lambda_role,
            timeout=cdk.Duration.seconds(10),
            memory_size=256,
            layers=[driver_layer],
            log_group=log_group,
            environment={
                "DB_HOST": db_endpoint,
                "DB_PORT": "5432",
                "DB_NAME": db_name,
                "DB_USER": HR_IDENTITY_DB_USER,
            },
            description=(
                "Cognito pre-token V3_0 trigger: resolves the signed-in "
                "employee in hr-data and adds employee_id, user_id, role, "
                "and (when allowed) agent_id claims. See "
                "docs/hr/modules.md § H3 claims."
            ),
        )
        cfn_pretoken = pretoken_function.node.default_child  # type: ignore[assignment]
        cfn_pretoken.add_property_override(
            "VpcConfig",
            {
                "SubnetIds": cdk.Fn.split(",", private_subnet_ids_param),
                "SecurityGroupIds": [runtime_security_group_id],
            },
        )

        # Cognito calls the Lambda through the same sourceArn the trigger
        # points at. Without this permission UpdateUserPool succeeds but
        # the trigger throws AccessDeniedException at invocation time.
        user_pool_arn = self.format_arn(
            service="cognito-idp",
            resource="userpool",
            resource_name=user_pool_id,
            arn_format=cdk.ArnFormat.SLASH_RESOURCE_NAME,
        )
        lambda_.CfnPermission(
            self,
            "AllowCognitoInvoke",
            action="lambda:InvokeFunction",
            function_name=pretoken_function.function_arn,
            principal="cognito-idp.amazonaws.com",
            source_arn=user_pool_arn,
            source_account=self.account,
        )

        # --------------------------------------------------------------
        # Safely attach/detach the V3_0 pre-token trigger via a read-modify-
        # write CustomResource (`trigger_manager/handler.py`). Preserves every
        # existing UserPool attribute (DeletionProtection, AdminCreateUserConfig,
        # Policies, other triggers) and ensures UserPoolTier is ESSENTIALS/PLUS
        # so V3_0 `TokenGeneration_ClientCredentials` + `aws_client_metadata`
        # is active for M2M gateway token exchanges.
        # --------------------------------------------------------------

        trigger_manager_role = iam.Role(
            self,
            "TriggerUpdaterRole",
            assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"),
            managed_policies=[
                iam.ManagedPolicy.from_aws_managed_policy_name(
                    "service-role/AWSLambdaBasicExecutionRole"
                ),
            ],
            description=(
                "DescribeUserPool + UpdateUserPool permissions for safely "
                "attaching/detaching the hr-identity V3_0 pre-token trigger."
            ),
        )
        trigger_manager_role.add_to_policy(
            iam.PolicyStatement(
                sid="UpdateUserPoolTrigger",
                actions=[
                    "cognito-idp:DescribeUserPool",
                    "cognito-idp:UpdateUserPool",
                ],
                resources=[user_pool_arn],
            )
        )

        trigger_manager_fn = lambda_.Function(
            self,
            "TriggerManagerFunction",
            runtime=lambda_.Runtime.PYTHON_3_13,
            handler="handler.on_event",
            code=lambda_.Code.from_asset(
                str(Path(__file__).parent / "trigger_manager")
            ),
            role=trigger_manager_role,
            timeout=cdk.Duration.minutes(2),
            memory_size=256,
            description=f"Attaches/detaches V3_0 pre-token trigger on {prefix} user pool",
        )

        trigger_provider = cr.Provider(
            self,
            "TriggerManagerProvider",
            on_event_handler=trigger_manager_fn,
        )

        attach = cdk.CustomResource(
            self,
            "AttachTrigger",
            service_token=trigger_provider.service_token,
            properties={
                "UserPoolId": user_pool_id,
                "LambdaArn": pretoken_function.function_arn,
                "LambdaVersion": "V3_0",
            },
        )
        attach.node.add_dependency(pretoken_function)

        # --------------------------------------------------------------
        # Platform-interface output. One parameter — operators look up
        # the Lambda ARN, and the detach step can reference it too.
        # --------------------------------------------------------------

        ssm.StringParameter(
            self,
            "SSMFunctionArn",
            parameter_name=f"{ssm_prefix}/use-cases/hr-identity/function-arn",
            string_value=pretoken_function.function_arn,
            description=(
                "ARN of the hr-identity pre-token Lambda attached to the "
                "module 3 Cognito user pool. Consumers: operators, the "
                "detach-on-destroy step."
            ),
        )

        cdk.CfnOutput(self, "FunctionArn", value=pretoken_function.function_arn)
        cdk.CfnOutput(self, "UserPoolArn", value=user_pool_arn)


_PG8000_LAYER_DEPS = (
    "pg8000==1.31.5",
    # scramp 1.5.0 removed scramp.make_channel_binding called by pg8000 1.31.5;
    # python-dateutil>=3 conflicts with Lambda botocore (<3.0.0,>=2.1).
    "scramp==1.4.9",
    "python-dateutil>=2.8.2,<3.0.0",
)
_PG8000_PIN = " ".join(_PG8000_LAYER_DEPS)


def _install_pg8000_into_layer(target: Path) -> None:
    """Install the pinned pg8000 + transitive deps into the layer's python/ dir.

    Runs at CDK synth time with the deployer's own Python. pg8000 is pure
    Python, so there is no manylinux concern — any OS the deployer runs on
    produces the same layer content. Idempotent: if the pin sentinel matches
    `_PG8000_PIN`, this is a no-op.
    """
    target.mkdir(parents=True, exist_ok=True)

    sentinel = target / ".pg8000-pin"
    if sentinel.exists() and sentinel.read_text().strip() == _PG8000_PIN:
        return

    # Clear previous installs so a bump leaves no stale files behind.
    for child in target.iterdir():
        if child.name == ".gitignore":
            continue
        if child.is_dir():
            shutil.rmtree(child)
        else:
            child.unlink()

    subprocess.run(  # nosec B603 — fixed argv, sys.executable, pinned deps
        [
            sys.executable,
            "-m",
            "pip",
            "install",
            "--quiet",
            "--no-color",
            "--disable-pip-version-check",
            "--target",
            str(target),
            "--upgrade",
            *_PG8000_LAYER_DEPS,
        ],
        check=True,
    )
    sentinel.write_text(_PG8000_PIN + "\n")


def build(app, ctx: dict, config: dict) -> None:
    """Entry point the platform calls for each enabled use case."""
    HrIdentityStack(
        app,
        f"{ctx['prefix']}-uc-hr-identity",
        ctx=ctx,
        config=config,
        env=ctx["cdk_env"],
    )
