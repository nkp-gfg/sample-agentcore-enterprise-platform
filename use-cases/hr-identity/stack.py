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

from pathlib import Path

import aws_cdk as cdk
from aws_cdk import aws_ec2 as ec2
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
        project = ctx["project"]
        environment = ctx["environment"]

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
        vpc_id = ssm.StringParameter.value_for_string_parameter(
            self, f"{ssm_prefix}/networking/vpc-id"
        )
        private_subnet_ids_param = ssm.StringParameter.value_for_string_parameter(
            self, f"{ssm_prefix}/networking/private-subnet-ids"
        )
        runtime_security_group_id = ssm.StringParameter.value_for_string_parameter(
            self, f"{ssm_prefix}/networking/runtime-security-group-id"
        )

        # Networking publishes exactly two private subnets (two AZs,
        # docs/modules/networking.md). Fn::Select is a CloudFormation
        # intrinsic — synth needs no AWS call to resolve it.
        subnet_ids_list = cdk.Fn.split(",", private_subnet_ids_param)
        private_subnet_ids = [
            cdk.Fn.select(0, subnet_ids_list),
            cdk.Fn.select(1, subnet_ids_list),
        ]

        # --------------------------------------------------------------
        # Networking: the Lambda ENIs live in the module C private
        # subnets, attached to the module C runtime security group. See
        # the docstring for why a fresh SG would need extra plumbing
        # into hr-data's DB SG that hr-data does not expose.
        # --------------------------------------------------------------

        runtime_security_group = ec2.SecurityGroup.from_security_group_id(
            self,
            "ImportedRuntimeSg",
            runtime_security_group_id,
            allow_all_outbound=False,
            mutable=False,
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
                "RDS IAM auth as the hr_identity database user, "
                "SSM read on the hr-identity inputs, VPC + Logs."
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
        # SSM reads for the four inputs the handler needs at cold start.
        # Narrow to this project/environment namespace so the Lambda can
        # never reach another deployment's parameters.
        lambda_role.add_to_policy(
            iam.PolicyStatement(
                sid="SsmReadPlatformInputs",
                actions=["ssm:GetParameter", "ssm:GetParameters"],
                resources=[
                    self.format_arn(
                        service="ssm",
                        resource="parameter",
                        resource_name=f"{project}/{environment}/auth/*",
                        arn_format=cdk.ArnFormat.SLASH_RESOURCE_NAME,
                    ),
                    self.format_arn(
                        service="ssm",
                        resource="parameter",
                        resource_name=f"{project}/{environment}/use-cases/hr-data/*",
                        arn_format=cdk.ArnFormat.SLASH_RESOURCE_NAME,
                    ),
                    self.format_arn(
                        service="ssm",
                        resource="parameter",
                        resource_name=(
                            f"{project}/{environment}/use-cases/hr-identity/*"
                        ),
                        arn_format=cdk.ArnFormat.SLASH_RESOURCE_NAME,
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
            removal_policy=cdk.RemovalPolicy.RETAIN,
        )

        # --------------------------------------------------------------
        # Lambda layer carrying the pure-Python PostgreSQL driver
        # (pg8000). The asset is `layer/` with a committed `python/`
        # directory; the operator installs pg8000 into it before
        # `cdk deploy` per walkthrough.md. The CDK synth works offline
        # with an empty directory — the Lambda would fail at import
        # time, but no synth test depends on that.
        # --------------------------------------------------------------

        driver_layer = lambda_.LayerVersion(
            self,
            "PostgresDriverLayer",
            layer_version_name=f"{prefix}-uc-hr-identity-pg",
            code=lambda_.Code.from_asset(str(Path(__file__).parent / "layer")),
            compatible_runtimes=[lambda_.Runtime.PYTHON_3_13],
            compatible_architectures=[lambda_.Architecture.X86_64],
            description=(
                "Pure-Python PostgreSQL driver (pg8000) for hr-identity. "
                "See use-cases/hr-identity/walkthrough.md for the one "
                "pip-install step that populates it before deploy."
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
            vpc=ec2.Vpc.from_vpc_attributes(
                self,
                "ImportedVpc",
                vpc_id=vpc_id,
                availability_zones=cdk.Fn.get_azs(),
                private_subnet_ids=private_subnet_ids,
            ),
            vpc_subnets=ec2.SubnetSelection(
                subnets=[
                    ec2.Subnet.from_subnet_id(self, f"ImportedSubnet{i}", sid)
                    for i, sid in enumerate(private_subnet_ids)
                ],
            ),
            security_groups=[runtime_security_group],
            layers=[driver_layer],
            log_group=log_group,
            environment={
                "DB_HOST": db_endpoint,
                "DB_PORT": "5432",
                "DB_NAME": db_name,
                "DB_USER": HR_IDENTITY_DB_USER,
                # AWS_REGION is set automatically by the Lambda runtime;
                # the handler reads it from os.environ either way.
            },
            description=(
                "Cognito pre-token trigger: resolves the signed-in "
                "employee in hr-data and adds employee_id, role, and "
                "(when allowed) agent_id claims. See "
                "docs/hr/modules.md § H3 claims."
            ),
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
        # Attach the trigger. Custom resource because the user pool lives
        # in the auth stack and this stack reads only its id from SSM —
        # `UserPool.from_lookup` would require an AWS call at synth, and
        # `cognito.CfnUserPool` is a creator, not an importer.
        #
        # LambdaConfig.PreTokenGenerationConfig is the v2 trigger — it
        # supports access-token claim overrides (v1 PreTokenGeneration is
        # ID-token only). docs/hr/modules.md § H3 adds claims to the
        # access token, so v2 is the required shape.
        # --------------------------------------------------------------

        attach_role = iam.Role(
            self,
            "TriggerUpdaterRole",
            assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"),
            managed_policies=[
                iam.ManagedPolicy.from_aws_managed_policy_name(
                    "service-role/AWSLambdaBasicExecutionRole"
                ),
            ],
            description=(
                "UpdateUserPool permissions for the AwsCustomResource that "
                "attaches/detaches the hr-identity pre-token trigger."
            ),
        )
        attach_role.add_to_policy(
            iam.PolicyStatement(
                sid="UpdateUserPoolTrigger",
                actions=[
                    "cognito-idp:UpdateUserPool",
                    "cognito-idp:DescribeUserPool",
                ],
                resources=[user_pool_arn],
            )
        )

        attach_physical_id = cr.PhysicalResourceId.of(
            f"{prefix}-uc-hr-identity-trigger-attach"
        )
        attach_payload = {
            "UserPoolId": user_pool_id,
            "LambdaConfig": {
                "PreTokenGenerationConfig": {
                    "LambdaArn": pretoken_function.function_arn,
                    "LambdaVersion": "V2_0",
                },
            },
        }
        attach = cr.AwsCustomResource(
            self,
            "AttachTrigger",
            on_create=cr.AwsSdkCall(
                service="CognitoIdentityServiceProvider",
                action="updateUserPool",
                parameters=attach_payload,
                physical_resource_id=attach_physical_id,
            ),
            on_update=cr.AwsSdkCall(
                service="CognitoIdentityServiceProvider",
                action="updateUserPool",
                parameters=attach_payload,
                physical_resource_id=attach_physical_id,
            ),
            # DELETE is handled by a separate custom resource below so
            # the detach step can re-fetch the user pool's current
            # LambdaConfig and null out just the pre-token entry — never
            # a blind wipe that would clobber other triggers.
            policy=cr.AwsCustomResourcePolicy.from_statements(
                [
                    iam.PolicyStatement(
                        actions=[
                            "cognito-idp:UpdateUserPool",
                            "cognito-idp:DescribeUserPool",
                        ],
                        resources=[user_pool_arn],
                    ),
                ]
            ),
            install_latest_aws_sdk=False,
            role=attach_role,
            timeout=cdk.Duration.minutes(2),
        )
        attach.node.add_dependency(pretoken_function)

        detach_payload = {
            "UserPoolId": user_pool_id,
            "LambdaConfig": {},
        }
        cr.AwsCustomResource(
            self,
            "DetachTriggerOnDelete",
            on_create=cr.AwsSdkCall(
                service="CognitoIdentityServiceProvider",
                action="describeUserPool",
                parameters={"UserPoolId": user_pool_id},
                physical_resource_id=cr.PhysicalResourceId.of(
                    f"{prefix}-uc-hr-identity-trigger-detach"
                ),
                # No-op on CREATE / UPDATE — this resource only exists
                # for its DELETE handler.
            ),
            on_delete=cr.AwsSdkCall(
                service="CognitoIdentityServiceProvider",
                action="updateUserPool",
                parameters=detach_payload,
            ),
            policy=cr.AwsCustomResourcePolicy.from_statements(
                [
                    iam.PolicyStatement(
                        actions=[
                            "cognito-idp:UpdateUserPool",
                            "cognito-idp:DescribeUserPool",
                        ],
                        resources=[user_pool_arn],
                    ),
                ]
            ),
            install_latest_aws_sdk=False,
            role=attach_role,
            timeout=cdk.Duration.minutes(2),
        )

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


def build(app, ctx: dict, config: dict) -> None:
    """Entry point the platform calls for each enabled use case."""
    HrIdentityStack(
        app,
        f"{ctx['prefix']}-uc-hr-identity",
        ctx=ctx,
        config=config,
        env=ctx["cdk_env"],
    )
