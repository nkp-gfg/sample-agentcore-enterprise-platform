"""Frontend Stack — ECS Express Mode BFF + WAFv2 + DynamoDB.

Provides hosting for ``hr-web``:
  - One ECS Express Mode service. It runs the UI and the FastAPI backend in
    the same container and creates the HTTPS Application Load Balancer, the
    certificate, and the ``https://<service>.ecs.<region>.on.aws`` address.
  - ``frontend.exposure: public`` places the tasks in the VPC public subnets
    (internet-facing load balancer). ``private`` uses the private subnets.
  - Regional AWS WAFv2 on the Express Mode load balancer.
  - Image build via CodeBuild -> ECR. Express Mode's default task architecture
    is X86_64, so the image is built for linux/amd64.
  - DynamoDB tables for OAuth/PKCE sessions and per-user chat transcripts.
  - Confidential Cognito ``BffClient`` so tokens stay server-side.
"""

from __future__ import annotations

import os

import aws_cdk as cdk
from aws_cdk import (
    CustomResource,
)
from aws_cdk import (
    aws_codebuild as codebuild,
)
from aws_cdk import (
    aws_cognito as cognito,
)
from aws_cdk import (
    aws_dynamodb as dynamodb,
)
from aws_cdk import (
    aws_ec2 as ec2,
)
from aws_cdk import (
    aws_ecr as ecr,
)
from aws_cdk import (
    aws_iam as iam,
)
from aws_cdk import (
    aws_kms as kms,
)
from aws_cdk import (
    aws_lambda as _lambda,
)
from aws_cdk import (
    aws_s3_assets as s3_assets,
)
from aws_cdk import (
    aws_secretsmanager as secretsmanager,
)
from aws_cdk import (
    aws_ssm as ssm,
)
from aws_cdk import (
    aws_wafv2 as wafv2,
)
from aws_cdk import (
    custom_resources as cr,
)
from constructs import Construct

from infra_utils.source_hash import compute_source_hash


class FrontendStack(cdk.Stack):
    def __init__(
        self,
        scope: Construct,
        id: str,
        *,
        project_name: str,
        environment: str,
        vpc: ec2.IVpc,
        exposure: str = "private",
        domain_name: str = "",
        certificate_arn: str = "",
        allowed_cidrs: list[str] | None = None,
        waf_rate_limit: int = 2000,
        min_capacity: int = 2,
        max_capacity: int = 10,
        cpu: int = 512,
        memory_mib: int = 1024,
        session_ttl_hours: int = 12,
        log_retention_days: int = 30,
        retain_data: bool = False,
        kms_key_arn: str = "",
        idp_mode: str = "brokered",
        issuer_url: str = "",
        user_pool_id: str = "",
        supported_identity_providers: list[cognito.UserPoolClientIdentityProvider]
        | None = None,
        direct_client_id: str = "",
        direct_client_secret_name: str = "",
        **kwargs,
    ):
        super().__init__(scope, id, **kwargs)

        if exposure not in {"private", "public"}:
            raise ValueError(
                f"FrontendStack exposure must be 'private' or 'public', got {exposure!r}"
            )

        prefix = f"{project_name}-{environment}"
        is_public = exposure == "public"
        allowed_cidrs = list(allowed_cidrs or [])
        kms_key = (
            kms.Key.from_key_arn(self, "PlatformKmsKey", kms_key_arn)
            if kms_key_arn
            else None
        )
        lifecycle_policy = (
            cdk.RemovalPolicy.RETAIN_ON_UPDATE_OR_DELETE
            if retain_data
            else cdk.RemovalPolicy.DESTROY
        )

        # Express Mode creates the service log group. log_retention_days is
        # kept on the constructor so existing callers do not break.
        del log_retention_days

        # Express Mode names the public URL from the service name:
        # https://<service>.ecs.<region>.on.aws
        # A customer domain, when set, is only the OAuth callback. Express
        # Mode still terminates TLS with the certificate it requests.
        service_name = f"{prefix}-hr-web"
        express_host = f"{service_name}.ecs.{self.region}.on.aws"
        self._frontend_url = (
            f"https://{domain_name}" if domain_name else f"https://{express_host}"
        )
        redirect_uri = f"{self._frontend_url}/auth/callback"
        logout_uri = f"{self._frontend_url}/"
        express_subnets = vpc.select_subnets(
            subnet_type=(
                ec2.SubnetType.PUBLIC
                if is_public
                else ec2.SubnetType.PRIVATE_WITH_EGRESS
            )
        ).subnet_ids
        # Customer ACM ARNs are not attached. Express Mode requests the cert.
        del certificate_arn

        # ── 3. AWS WAFv2 Regional WebACL attached to the ALB ───────────────
        waf_rules: list[wafv2.CfnWebACL.RuleProperty] = []
        if allowed_cidrs:
            ip_set = wafv2.CfnIPSet(
                self,
                "AllowedCidrsIpSet",
                name=f"{prefix}-bff-allowed-cidrs",
                scope="REGIONAL",
                ip_address_version="IPV4",
                addresses=allowed_cidrs,
            )
            waf_rules.append(
                wafv2.CfnWebACL.RuleProperty(
                    name="BlockOutsideAllowedCidrs",
                    priority=1,
                    action=wafv2.CfnWebACL.RuleActionProperty(block={}),
                    statement=wafv2.CfnWebACL.StatementProperty(
                        not_statement=wafv2.CfnWebACL.NotStatementProperty(
                            statement=wafv2.CfnWebACL.StatementProperty(
                                ip_set_reference_statement=wafv2.CfnWebACL.IPSetReferenceStatementProperty(
                                    arn=ip_set.attr_arn
                                )
                            )
                        )
                    ),
                    visibility_config=wafv2.CfnWebACL.VisibilityConfigProperty(
                        cloud_watch_metrics_enabled=True,
                        metric_name=f"{prefix}-waf-cidr-block",
                        sampled_requests_enabled=True,
                    ),
                )
            )

        waf_rules.extend(
            [
                wafv2.CfnWebACL.RuleProperty(
                    name="RateLimitPerIp",
                    priority=10,
                    action=wafv2.CfnWebACL.RuleActionProperty(block={}),
                    statement=wafv2.CfnWebACL.StatementProperty(
                        rate_based_statement=wafv2.CfnWebACL.RateBasedStatementProperty(
                            limit=waf_rate_limit,
                            aggregate_key_type="IP",
                        )
                    ),
                    visibility_config=wafv2.CfnWebACL.VisibilityConfigProperty(
                        cloud_watch_metrics_enabled=True,
                        metric_name=f"{prefix}-waf-rate-limit",
                        sampled_requests_enabled=True,
                    ),
                ),
                wafv2.CfnWebACL.RuleProperty(
                    name="AWSManagedRulesAmazonIpReputationList",
                    priority=20,
                    override_action=wafv2.CfnWebACL.OverrideActionProperty(none={}),
                    statement=wafv2.CfnWebACL.StatementProperty(
                        managed_rule_group_statement=wafv2.CfnWebACL.ManagedRuleGroupStatementProperty(
                            vendor_name="AWS",
                            name="AWSManagedRulesAmazonIpReputationList",
                        )
                    ),
                    visibility_config=wafv2.CfnWebACL.VisibilityConfigProperty(
                        cloud_watch_metrics_enabled=True,
                        metric_name=f"{prefix}-waf-ip-reputation",
                        sampled_requests_enabled=True,
                    ),
                ),
                wafv2.CfnWebACL.RuleProperty(
                    name="AWSManagedRulesKnownBadInputsRuleSet",
                    priority=30,
                    override_action=wafv2.CfnWebACL.OverrideActionProperty(none={}),
                    statement=wafv2.CfnWebACL.StatementProperty(
                        managed_rule_group_statement=wafv2.CfnWebACL.ManagedRuleGroupStatementProperty(
                            vendor_name="AWS",
                            name="AWSManagedRulesKnownBadInputsRuleSet",
                        )
                    ),
                    visibility_config=wafv2.CfnWebACL.VisibilityConfigProperty(
                        cloud_watch_metrics_enabled=True,
                        metric_name=f"{prefix}-waf-bad-inputs",
                        sampled_requests_enabled=True,
                    ),
                ),
                wafv2.CfnWebACL.RuleProperty(
                    name="AWSManagedRulesCommonRuleSet",
                    priority=40,
                    override_action=wafv2.CfnWebACL.OverrideActionProperty(none={}),
                    statement=wafv2.CfnWebACL.StatementProperty(
                        managed_rule_group_statement=wafv2.CfnWebACL.ManagedRuleGroupStatementProperty(
                            vendor_name="AWS",
                            name="AWSManagedRulesCommonRuleSet",
                            # Chat payloads (AG-UI messages + forwardedProps) can exceed 8 KB.
                            rule_action_overrides=[
                                wafv2.CfnWebACL.RuleActionOverrideProperty(
                                    name="SizeRestrictions_BODY",
                                    action_to_use=wafv2.CfnWebACL.RuleActionProperty(
                                        count={}
                                    ),
                                )
                            ],
                        )
                    ),
                    visibility_config=wafv2.CfnWebACL.VisibilityConfigProperty(
                        cloud_watch_metrics_enabled=True,
                        metric_name=f"{prefix}-waf-common",
                        sampled_requests_enabled=True,
                    ),
                ),
            ]
        )

        web_acl = wafv2.CfnWebACL(
            self,
            "BffWebAcl",
            name=f"{prefix}-bff-waf",
            scope="REGIONAL",
            default_action=wafv2.CfnWebACL.DefaultActionProperty(allow={}),
            rules=waf_rules,
            visibility_config=wafv2.CfnWebACL.VisibilityConfigProperty(
                cloud_watch_metrics_enabled=True,
                metric_name=f"{prefix}-bff-waf",
                sampled_requests_enabled=True,
            ),
        )
        # The association is created after the Express Mode load balancer exists.

        # ── 4. DynamoDB Tables (Auth Sessions + Chat History) ──────────────
        table_encryption = (
            dynamodb.TableEncryption.CUSTOMER_MANAGED
            if kms_key is not None
            else dynamodb.TableEncryption.AWS_MANAGED
        )
        # A rolled-back first create can leave RETAIN resources behind.
        # FRONTEND_ADOPT_RETAINED=1 references them instead of creating
        # names CloudFormation would reject.
        adopt_retained = os.environ.get("FRONTEND_ADOPT_RETAINED") == "1"
        if adopt_retained:
            bff_sessions_table = dynamodb.Table.from_table_attributes(
                self,
                "BffSessionsTable",
                table_name=f"{prefix}-bff-sessions",
                encryption_key=kms_key,
                grant_index_permissions=True,
            )
            chat_sessions_table = dynamodb.Table.from_table_attributes(
                self,
                "ChatSessionsTable",
                table_name=f"{prefix}-chat-sessions",
                encryption_key=kms_key,
                grant_index_permissions=True,
            )
        else:
            bff_sessions_table = dynamodb.Table(
                self,
                "BffSessionsTable",
                table_name=f"{prefix}-bff-sessions",
                partition_key=dynamodb.Attribute(
                    name="pk", type=dynamodb.AttributeType.STRING
                ),
                billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
                time_to_live_attribute="ttl",
                encryption=table_encryption,
                encryption_key=kms_key,
                point_in_time_recovery_specification=dynamodb.PointInTimeRecoverySpecification(
                    point_in_time_recovery_enabled=True
                ),
                removal_policy=lifecycle_policy,
            )
            chat_sessions_table = dynamodb.Table(
                self,
                "ChatSessionsTable",
                table_name=f"{prefix}-chat-sessions",
                partition_key=dynamodb.Attribute(
                    name="owner_sub", type=dynamodb.AttributeType.STRING
                ),
                sort_key=dynamodb.Attribute(
                    name="thread_id", type=dynamodb.AttributeType.STRING
                ),
                billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
                encryption=table_encryption,
                encryption_key=kms_key,
                point_in_time_recovery_specification=dynamodb.PointInTimeRecoverySpecification(
                    point_in_time_recovery_enabled=True
                ),
                removal_policy=lifecycle_policy,
            )
            chat_sessions_table.add_global_secondary_index(
                index_name="owner_sub-updated_at-index",
                partition_key=dynamodb.Attribute(
                    name="owner_sub", type=dynamodb.AttributeType.STRING
                ),
                sort_key=dynamodb.Attribute(
                    name="updated_at", type=dynamodb.AttributeType.NUMBER
                ),
            )

        # ── 5. Confidential OAuth Client (Tokens Stay in ECS + DynamoDB) ───
        if idp_mode == "direct":
            if not direct_client_id or not direct_client_secret_name:
                raise ValueError(
                    "FrontendStack in direct mode requires direct_client_id and direct_client_secret_name"
                )
            self._bff_client_id = direct_client_id
            oidc_scope = f"openid email profile {direct_client_id}/.default"
            direct_secret = secretsmanager.Secret.from_secret_name_v2(
                self, "BffDirectClientSecret", direct_client_secret_name
            )
            bff_secret_arn = direct_secret.secret_arn
        else:
            if not user_pool_id:
                raise ValueError("FrontendStack in brokered mode requires user_pool_id")
            imported_pool = cognito.UserPool.from_user_pool_id(
                self, "ImportedUserPool", user_pool_id
            )
            providers = supported_identity_providers or [
                cognito.UserPoolClientIdentityProvider.COGNITO
            ]
            bff_client = cognito.UserPoolClient(
                self,
                "BffClient",
                user_pool=imported_pool,
                user_pool_client_name=f"{prefix}-bff-client",
                generate_secret=True,
                auth_flows=cognito.AuthFlow(user_password=False, user_srp=False),
                supported_identity_providers=providers,
                o_auth=cognito.OAuthSettings(
                    flows=cognito.OAuthFlows(authorization_code_grant=True),
                    scopes=[
                        cognito.OAuthScope.OPENID,
                        cognito.OAuthScope.EMAIL,
                        cognito.OAuthScope.PROFILE,
                    ],
                    callback_urls=(
                        [redirect_uri]
                        if domain_name
                        else ["https://localhost/auth/callback"]
                    ),
                    logout_urls=(
                        [logout_uri] if domain_name else ["https://localhost/"]
                    ),
                ),
            )
            bff_client_secret_store = secretsmanager.Secret(
                self,
                "BffClientSecret",
                description=f"Confidential OAuth client secret for {prefix} ECS BFF",
                secret_string_value=bff_client.user_pool_client_secret,
                encryption_key=kms_key,
                removal_policy=lifecycle_policy,
            )
            self._bff_client_id = bff_client.user_pool_client_id
            oidc_scope = "openid email profile"
            bff_secret_arn = bff_client_secret_store.secret_arn

        # ── 6. Remote ARM64 Image Build (ECR + CodeBuild, no local Docker) ─
        repo_root = os.path.dirname(os.path.dirname(__file__))
        abs_hr_web_dir = os.path.join(repo_root, "hr-web")
        source_hash = compute_source_hash(abs_hr_web_dir)

        if adopt_retained:
            ecr_repo = ecr.Repository.from_repository_name(
                self, "BffEcrRepo", f"{prefix}-hr-web-bff"
            )
        else:
            ecr_repo = ecr.Repository(
                self,
                "BffEcrRepo",
                repository_name=f"{prefix}-hr-web-bff",
                removal_policy=lifecycle_policy,
                empty_on_delete=not retain_data,
                image_scan_on_push=True,
                image_tag_mutability=ecr.TagMutability.IMMUTABLE,
                lifecycle_rules=[
                    ecr.LifecycleRule(
                        max_image_count=10, description="Keep last 10 images"
                    )
                ],
            )
        # Hash excludes skip node_modules/dist; Asset exclude keeps them out of the zip.
        source_asset = s3_assets.Asset(
            self,
            "BffSourceAsset",
            path=abs_hr_web_dir,
            exclude=[
                "node_modules",
                "web/node_modules",
                "web/dist",
                "__pycache__",
                ".venv",
                ".git",
                "tests",
                "**/__pycache__",
            ],
            ignore_mode=cdk.IgnoreMode.GLOB,
        )

        build_project = codebuild.Project(
            self,
            "BffBuild",
            project_name=f"{prefix}-build-hr-web-bff",
            description="Build linux/amd64 image for the ECS Express Mode BFF",
            environment=codebuild.BuildEnvironment(
                build_image=codebuild.LinuxBuildImage.STANDARD_7_0,
                privileged=True,
                compute_type=codebuild.ComputeType.MEDIUM,
            ),
            timeout=cdk.Duration.minutes(30),
            build_spec=codebuild.BuildSpec.from_object(
                {
                    "version": "0.2",
                    "phases": {
                        "pre_build": {
                            "commands": [
                                "aws ecr get-login-password --region $AWS_DEFAULT_REGION | docker login --username AWS --password-stdin $ACCOUNT_ID.dkr.ecr.$AWS_DEFAULT_REGION.amazonaws.com",
                                "aws s3 cp $SOURCE_S3_URI source.zip",
                                "mkdir -p source && unzip -o source.zip -d source/",
                            ]
                        },
                        "build": {
                            "commands": [
                                "cd source/",
                                "docker build --platform linux/amd64 -t $REPO_URI:$IMAGE_TAG .",
                            ]
                        },
                        "post_build": {
                            "commands": [
                                'REPO_NAME="${REPO_URI##*/}"',
                                'aws ecr describe-images --repository-name "$REPO_NAME" --image-ids imageTag="$IMAGE_TAG" >/dev/null 2>&1 || docker push $REPO_URI:$IMAGE_TAG',
                            ]
                        },
                    },
                }
            ),
        )
        ecr_repo.grant_push(build_project)
        build_project.add_to_role_policy(
            iam.PolicyStatement(
                sid="DescribeImmutableTag",
                actions=["ecr:DescribeImages"],
                resources=[ecr_repo.repository_arn],
            )
        )
        source_asset.grant_read(build_project)

        # The waiter Lambda cannot run for the 30 minute CodeBuild timeout.
        # Provider is_complete is a new short invocation every 30 seconds.
        trigger_code = _lambda.Code.from_asset(os.path.join(repo_root, "infra_utils"))

        def _codebuild_poll_policy() -> iam.PolicyStatement:
            return iam.PolicyStatement(
                actions=["codebuild:StartBuild", "codebuild:BatchGetBuilds"],
                resources=[build_project.project_arn],
            )

        on_event_fn = _lambda.Function(
            self,
            "BffBuildOnEvent",
            function_name=f"{prefix}-build-hr-web-on-event",
            runtime=_lambda.Runtime.PYTHON_3_13,
            handler="build_trigger_lambda.on_event",
            code=trigger_code,
            timeout=cdk.Duration.seconds(60),
            memory_size=256,
        )
        is_complete_fn = _lambda.Function(
            self,
            "BffBuildIsComplete",
            function_name=f"{prefix}-build-hr-web-is-complete",
            runtime=_lambda.Runtime.PYTHON_3_13,
            handler="build_trigger_lambda.is_complete",
            code=trigger_code,
            timeout=cdk.Duration.seconds(30),
            memory_size=256,
        )
        on_event_fn.add_to_role_policy(_codebuild_poll_policy())
        is_complete_fn.add_to_role_policy(_codebuild_poll_policy())
        build_provider = cr.Provider(
            self,
            "BffBuildProvider",
            on_event_handler=on_event_fn,
            is_complete_handler=is_complete_fn,
            query_interval=cdk.Duration.seconds(30),
            total_timeout=cdk.Duration.minutes(35),
        )
        build_trigger = CustomResource(
            self,
            "BffImageBuild",
            service_token=build_provider.service_token,
            properties={
                "ProjectName": build_project.project_name,
                "EnvironmentOverrides": [
                    {
                        "name": "SOURCE_S3_URI",
                        "value": source_asset.s3_object_url,
                        "type": "PLAINTEXT",
                    },
                    {"name": "IMAGE_TAG", "value": source_hash, "type": "PLAINTEXT"},
                    {
                        "name": "REPO_URI",
                        "value": ecr_repo.repository_uri,
                        "type": "PLAINTEXT",
                    },
                    {"name": "ACCOUNT_ID", "value": self.account, "type": "PLAINTEXT"},
                ],
                "SourceHash": source_hash,
            },
        )
        build_trigger.node.add_dependency(build_project)

        # ── 7. ECS Express Mode service (UI + BFF, HTTPS ALB, scaling) ─
        task_role = iam.Role(
            self,
            "BffTaskRole",
            assumed_by=iam.ServicePrincipal("ecs-tasks.amazonaws.com"),
            description="hr-web BFF data-plane access: DynamoDB, SSM, and KMS",
        )
        execution_role = iam.Role(
            self,
            "BffExecutionRole",
            assumed_by=iam.ServicePrincipal("ecs-tasks.amazonaws.com"),
            managed_policies=[
                iam.ManagedPolicy.from_aws_managed_policy_name(
                    "service-role/AmazonECSTaskExecutionRolePolicy"
                )
            ],
            description="Pull the hr-web image and the OIDC client secret",
        )
        execution_role.add_to_policy(
            iam.PolicyStatement(
                actions=["secretsmanager:GetSecretValue"],
                resources=[bff_secret_arn],
            )
        )
        infra_role = iam.Role(
            self,
            "ExpressInfrastructureRole",
            assumed_by=iam.ServicePrincipal("ecs.amazonaws.com"),
            managed_policies=[
                iam.ManagedPolicy.from_aws_managed_policy_name(
                    "service-role/AmazonECSInfrastructureRoleforExpressGatewayServices"
                )
            ],
            description="Lets ECS Express Mode create the load balancer and scaling",
        )
        bff_sessions_table.grant_read_write_data(task_role)
        chat_sessions_table.grant_read_write_data(task_role)
        if kms_key_arn:
            task_role.add_to_policy(
                iam.PolicyStatement(
                    sid="DynamoDbCmkAccess",
                    actions=["kms:Decrypt", "kms:Encrypt", "kms:GenerateDataKey*"],
                    resources=[kms_key_arn],
                )
            )
            execution_role.add_to_policy(
                iam.PolicyStatement(
                    sid="SecretCmkDecrypt",
                    actions=["kms:Decrypt", "kms:DescribeKey"],
                    resources=[kms_key_arn],
                )
            )
        task_role.add_to_policy(
            iam.PolicyStatement(
                sid="ReadOrchestratorRuntimeArn",
                actions=["ssm:GetParameter"],
                resources=[
                    self.format_arn(
                        service="ssm",
                        resource="parameter",
                        resource_name=(
                            f"{project_name}/{environment}/runtimes/orchestrator/arn"
                        ),
                    )
                ],
            )
        )

        container_env = {
            "PROJECT_NAME": project_name,
            "ENVIRONMENT": environment,
            "AWS_REGION_NAME": self.region,
            "BFF_SSM_PREFIX": f"/{project_name}/{environment}",
            "OIDC_ISSUER_URL": issuer_url,
            "OIDC_CLIENT_ID": self._bff_client_id,
            "OIDC_SCOPE": oidc_scope,
            "BFF_SESSION_TABLE": bff_sessions_table.table_name,
            "CHAT_SESSION_TABLE": chat_sessions_table.table_name,
            "FRONTEND_EXPOSURE": exposure,
            "COOKIE_SECURE": "true",
            "SESSION_TTL_HOURS": str(session_ttl_hours),
        }
        if domain_name:
            container_env["OIDC_REDIRECT_URI"] = redirect_uri
            container_env["OIDC_LOGOUT_URI"] = logout_uri
        express = cdk.CfnResource(
            self,
            "HrWebExpress",
            type="AWS::ECS::ExpressGatewayService",
            properties={
                "ServiceName": service_name,
                "ExecutionRoleArn": execution_role.role_arn,
                "InfrastructureRoleArn": infra_role.role_arn,
                "TaskRoleArn": task_role.role_arn,
                "Cpu": str(cpu),
                "Memory": str(memory_mib),
                "HealthCheckPath": "/healthz",
                "NetworkConfiguration": {"Subnets": express_subnets},
                "ScalingTarget": {
                    "MinTaskCount": min_capacity,
                    "MaxTaskCount": max_capacity,
                },
                "PrimaryContainer": {
                    "Image": f"{ecr_repo.repository_uri}:{source_hash}",
                    "ContainerPort": 8080,
                    "Environment": [
                        {"Name": key, "Value": value}
                        for key, value in container_env.items()
                    ],
                    "Secrets": [
                        {"Name": "OIDC_CLIENT_SECRET", "ValueFrom": bff_secret_arn}
                    ],
                },
            },
        )
        build_trigger.node.add_dependency(ecr_repo)
        express.node.add_dependency(build_trigger)
        express.node.add_dependency(infra_role)
        express.node.add_dependency(execution_role)

        load_balancer_arn = express.get_att(
            "ECSManagedResourceArns.IngressPath.LoadBalancerArn"
        ).to_string()
        wafv2.CfnWebACLAssociation(
            self,
            "BffAlbWafAssociation",
            resource_arn=load_balancer_arn,
            web_acl_arn=web_acl.attr_arn,
        )
        idle_fn = _lambda.Function(
            self,
            "AlbIdleTimeoutFn",
            runtime=_lambda.Runtime.PYTHON_3_13,
            handler="index.handler",
            timeout=cdk.Duration.seconds(60),
            code=_lambda.Code.from_inline(
                "import boto3\n"
                "def handler(event, context):\n"
                "    if event['RequestType'] != 'Delete':\n"
                "        boto3.client('elbv2').modify_load_balancer_attributes(\n"
                "            LoadBalancerArn=event['ResourceProperties']['LoadBalancerArn'],\n"
                "            Attributes=[{'Key': 'idle_timeout.timeout_seconds', 'Value': '300'}],\n"
                "        )\n"
                "    return {'PhysicalResourceId': 'express-alb-idle-timeout'}\n"
            ),
        )
        idle_fn.add_to_role_policy(
            iam.PolicyStatement(
                actions=["elasticloadbalancing:ModifyLoadBalancerAttributes"],
                resources=["*"],
            )
        )
        idle_provider = cr.Provider(
            self,
            "AlbIdleTimeoutProvider",
            on_event_handler=idle_fn,
        )
        CustomResource(
            self,
            "AlbIdleTimeout",
            service_token=idle_provider.service_token,
            properties={"LoadBalancerArn": load_balancer_arn},
        )
        if idp_mode != "direct" and not domain_name:
            # The public hostname is generated (ag-<id>.ecs.<region>.on.aws),
            # so it is not known until the service exists. Register that
            # hostname as the Cognito callback after create.
            callback_fn = _lambda.Function(
                self,
                "CallbackRegistrarFn",
                runtime=_lambda.Runtime.PYTHON_3_13,
                handler="index.handler",
                timeout=cdk.Duration.seconds(60),
                code=_lambda.Code.from_inline(
                    "import boto3\n"
                    "def handler(event, context):\n"
                    "    if event['RequestType'] == 'Delete':\n"
                    "        return {'PhysicalResourceId': 'bff-callback'}\n"
                    "    props = event['ResourceProperties']\n"
                    "    raw = props['Endpoint'].strip().rstrip('/')\n"
                    "    base = raw if '://' in raw else 'https://' + raw\n"
                    "    cognito = boto3.client('cognito-idp')\n"
                    "    current = cognito.describe_user_pool_client(\n"
                    "        UserPoolId=props['UserPoolId'], ClientId=props['ClientId']\n"
                    "    )['UserPoolClient']\n"
                    "    cognito.update_user_pool_client(\n"
                    "        UserPoolId=props['UserPoolId'],\n"
                    "        ClientId=props['ClientId'],\n"
                    "        ClientName=current['ClientName'],\n"
                    "        CallbackURLs=[base + '/auth/callback'],\n"
                    "        LogoutURLs=[base + '/'],\n"
                    "        AllowedOAuthFlows=current.get('AllowedOAuthFlows') or ['code'],\n"
                    "        AllowedOAuthScopes=current.get('AllowedOAuthScopes') or ['openid', 'email', 'profile'],\n"
                    "        AllowedOAuthFlowsUserPoolClient=True,\n"
                    "        SupportedIdentityProviders=current.get('SupportedIdentityProviders') or ['COGNITO'],\n"
                    "        ExplicitAuthFlows=current.get('ExplicitAuthFlows') or ['ALLOW_REFRESH_TOKEN_AUTH'],\n"
                    "    )\n"
                    "    return {'PhysicalResourceId': base, 'Data': {'Url': base}}\n"
                ),
            )
            callback_fn.add_to_role_policy(
                iam.PolicyStatement(
                    actions=[
                        "cognito-idp:DescribeUserPoolClient",
                        "cognito-idp:UpdateUserPoolClient",
                    ],
                    resources=[
                        self.format_arn(
                            service="cognito-idp",
                            resource="userpool",
                            resource_name=user_pool_id,
                            arn_format=cdk.ArnFormat.SLASH_RESOURCE_NAME,
                        )
                    ],
                )
            )
            callback_provider = cr.Provider(
                self,
                "CallbackRegistrarProvider",
                on_event_handler=callback_fn,
            )
            callback_resource = CustomResource(
                self,
                "CallbackRegistrar",
                service_token=callback_provider.service_token,
                properties={
                    "Endpoint": express.get_att("Endpoint").to_string(),
                    "UserPoolId": user_pool_id,
                    "ClientId": self._bff_client_id,
                },
            )
            # Endpoint already includes https://. Do not prefix it again.
            # Do not GetAtt CallbackRegistrar.Url: that response has no Url.
            self._frontend_url = express.get_att("Endpoint").to_string()
            # Keep the registrar. It writes the Cognito callback. SSM does not
            # read its response.
            callback_resource.node.add_dependency(express)

        # ── 8. SSM Parameters & Outputs (non-secret only) ──────────────────
        ssm.StringParameter(
            self,
            "SSMFrontendUrl",
            parameter_name=f"/{project_name}/{environment}/frontend/url",
            string_value=self._frontend_url,
        )
        ssm.StringParameter(
            self,
            "SSMFrontendExposure",
            parameter_name=f"/{project_name}/{environment}/frontend/exposure",
            string_value=exposure,
        )
        ssm.StringParameter(
            self,
            "SSMBffClientId",
            parameter_name=f"/{project_name}/{environment}/frontend/bff-client-id",
            string_value=self._bff_client_id,
        )

        cdk.CfnOutput(self, "FrontendUrl", value=self._frontend_url)
        cdk.CfnOutput(self, "FrontendExposure", value=exposure)
        cdk.CfnOutput(self, "WebAclArn", value=web_acl.attr_arn)
        cdk.CfnOutput(self, "EcsClusterName", value="default")
        cdk.CfnOutput(self, "EcsServiceName", value=service_name)
        cdk.CfnOutput(self, "BffSessionTableName", value=bff_sessions_table.table_name)
        cdk.CfnOutput(
            self, "ChatSessionTableName", value=chat_sessions_table.table_name
        )
        cdk.CfnOutput(self, "BffClientId", value=self._bff_client_id)

    @property
    def bff_client_id(self) -> str:
        return self._bff_client_id

    @property
    def frontend_url(self) -> str:
        return self._frontend_url
