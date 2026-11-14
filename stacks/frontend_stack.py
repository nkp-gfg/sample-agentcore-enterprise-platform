"""Frontend Stack — WAFv2 + Public/Private ALB + Auto-Scaling ECS Fargate BFF + DynamoDB.

Provides an enterprise-hardened hosting stack for ``hr-web``:
  - Regional AWS WAFv2 WebACL protecting the Application Load Balancer in both
    ``private`` (internal ALB) and ``public`` (internet-facing ALB) modes.
  - One-line exposure switch via ``frontend.exposure: private | public`` in
    ``platform.yaml`` (no hardcoded ALB name, so CloudFormation replaces the
    load balancer cleanly when switching schemes).
  - Auto-scaling ARM64 ECS Fargate BFF (CPU, memory, and ALB request-count
    burst scaling across AZs), built remotely via CodeBuild -> ECR.
  - DynamoDB tables for OAuth/PKCE sessions (``BffSessions``) and per-user
    chat transcripts (``ChatSessions``) so ECS restarts or scale events never
    interrupt user sessions or lose chat history.
  - Confidential Cognito ``BffClient`` (or direct Entra app registration) so
    tokens stay server-side in DynamoDB and never reach browser JavaScript.
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
    aws_ecs as ecs,
)
from aws_cdk import (
    aws_elasticloadbalancingv2 as elbv2,
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
    aws_logs as logs,
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
            cdk.RemovalPolicy.RETAIN if retain_data else cdk.RemovalPolicy.DESTROY
        )

        retention_by_days = {
            30: logs.RetentionDays.ONE_MONTH,
            90: logs.RetentionDays.THREE_MONTHS,
            180: logs.RetentionDays.SIX_MONTHS,
            365: logs.RetentionDays.ONE_YEAR,
        }
        log_retention = retention_by_days.get(
            log_retention_days, logs.RetentionDays.ONE_MONTH
        )

        # ── 1. Security Groups (ALB + ECS BFF) ─────────────────────────────
        alb_sg = ec2.SecurityGroup(
            self,
            "AlbSecurityGroup",
            vpc=vpc,
            description="HR Web BFF Application Load Balancer",
            allow_all_outbound=False,
        )
        ecs_sg = ec2.SecurityGroup(
            self,
            "EcsSecurityGroup",
            vpc=vpc,
            description="HR Web BFF ECS Fargate tasks",
            allow_all_outbound=False,
        )

        ingress_peers: list[ec2.IPeer]
        if allowed_cidrs:
            ingress_peers = [ec2.Peer.ipv4(cidr) for cidr in allowed_cidrs]
        elif is_public:
            ingress_peers = [ec2.Peer.any_ipv4()]
        else:
            ingress_peers = [ec2.Peer.ipv4(vpc.vpc_cidr_block)]

        for peer in ingress_peers:
            if certificate_arn:
                alb_sg.add_ingress_rule(
                    peer, ec2.Port.tcp(443), "HTTPS ingress to BFF ALB"
                )
                alb_sg.add_ingress_rule(
                    peer, ec2.Port.tcp(80), "HTTP redirect to HTTPS"
                )
            else:
                alb_sg.add_ingress_rule(
                    peer, ec2.Port.tcp(80), "HTTP ingress to BFF ALB"
                )

        alb_sg.add_egress_rule(
            ecs_sg, ec2.Port.tcp(8080), "Forward HTTP traffic to ECS BFF tasks"
        )
        ecs_sg.add_ingress_rule(
            alb_sg, ec2.Port.tcp(8080), "Accept HTTP traffic from ALB"
        )
        ecs_sg.add_egress_rule(
            ec2.Peer.any_ipv4(),
            ec2.Port.tcp(443),
            "HTTPS to VPC endpoints, OIDC IdP, DynamoDB, and SSM",
        )

        # ── 2. Application Load Balancer (public or internal by config) ────
        # Intentionally omit load_balancer_name so flipping exposure between
        # 'private' and 'public' replaces the ALB cleanly without collisions.
        alb = elbv2.ApplicationLoadBalancer(
            self,
            "BffAlb",
            vpc=vpc,
            internet_facing=is_public,
            vpc_subnets=ec2.SubnetSelection(
                subnet_type=(
                    ec2.SubnetType.PUBLIC
                    if is_public
                    else ec2.SubnetType.PRIVATE_WITH_EGRESS
                )
            ),
            security_group=alb_sg,
            drop_invalid_header_fields=True,
            idle_timeout=cdk.Duration.seconds(300),
        )

        target_group = elbv2.ApplicationTargetGroup(
            self,
            "BffTargetGroup",
            vpc=vpc,
            port=8080,
            protocol=elbv2.ApplicationProtocol.HTTP,
            target_type=elbv2.TargetType.IP,
            deregistration_delay=cdk.Duration.seconds(30),
            health_check=elbv2.HealthCheck(
                path="/healthz",
                interval=cdk.Duration.seconds(15),
                timeout=cdk.Duration.seconds(5),
                healthy_threshold_count=2,
                unhealthy_threshold_count=3,
            ),
        )

        if certificate_arn:
            alb.add_listener(
                "HttpsListener",
                port=443,
                protocol=elbv2.ApplicationProtocol.HTTPS,
                ssl_policy=elbv2.SslPolicy.TLS13_RES,
                certificates=[elbv2.ListenerCertificate.from_arn(certificate_arn)],
                open=False,
                default_target_groups=[target_group],
            )
            alb.add_listener(
                "HttpRedirectListener",
                port=80,
                protocol=elbv2.ApplicationProtocol.HTTP,
                open=False,
                default_action=elbv2.ListenerAction.redirect(
                    protocol="HTTPS", port="443", permanent=True
                ),
            )
        else:
            alb.add_listener(
                "HttpListener",
                port=80,
                protocol=elbv2.ApplicationProtocol.HTTP,
                open=False,
                default_target_groups=[target_group],
            )

        scheme = "https" if certificate_arn else "http"
        host = domain_name or alb.load_balancer_dns_name
        self._frontend_url = f"{scheme}://{host}"
        redirect_uri = f"{self._frontend_url}/auth/callback"
        logout_uri = f"{self._frontend_url}/"

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
        wafv2.CfnWebACLAssociation(
            self,
            "BffAlbWafAssociation",
            resource_arn=alb.load_balancer_arn,
            web_acl_arn=web_acl.attr_arn,
        )

        # ── 4. DynamoDB Tables (Auth Sessions + Chat History) ──────────────
        table_encryption = (
            dynamodb.TableEncryption.CUSTOMER_MANAGED
            if kms_key is not None
            else dynamodb.TableEncryption.AWS_MANAGED
        )
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
            bff_secret_for_ecs = ecs.Secret.from_secrets_manager(direct_secret)
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
                    callback_urls=[redirect_uri],
                    logout_urls=[logout_uri],
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
            bff_secret_for_ecs = ecs.Secret.from_secrets_manager(
                bff_client_secret_store
            )

        # ── 6. Remote ARM64 Image Build (ECR + CodeBuild, no local Docker) ─
        repo_root = os.path.dirname(os.path.dirname(__file__))
        abs_hr_web_dir = os.path.join(repo_root, "hr-web")
        source_hash = compute_source_hash(abs_hr_web_dir)

        ecr_repo = ecr.Repository(
            self,
            "BffEcrRepo",
            repository_name=f"{prefix}-hr-web-bff",
            removal_policy=lifecycle_policy,
            empty_on_delete=not retain_data,
            image_scan_on_push=True,
            lifecycle_rules=[
                ecr.LifecycleRule(max_image_count=10, description="Keep last 10 images")
            ],
        )
        source_asset = s3_assets.Asset(self, "BffSourceAsset", path=abs_hr_web_dir)

        build_project = codebuild.Project(
            self,
            "BffBuild",
            project_name=f"{prefix}-build-hr-web-bff",
            description="Build ARM64 container image for hr-web ECS BFF",
            environment=codebuild.BuildEnvironment(
                build_image=codebuild.LinuxArmBuildImage.AMAZON_LINUX_2_STANDARD_3_0,
                privileged=True,
                compute_type=codebuild.ComputeType.SMALL,
            ),
            timeout=cdk.Duration.minutes(20),
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
                                "docker build --platform linux/arm64 -t $REPO_URI:$IMAGE_TAG .",
                                "docker tag $REPO_URI:$IMAGE_TAG $REPO_URI:latest",
                            ]
                        },
                        "post_build": {
                            "commands": [
                                "docker push $REPO_URI:$IMAGE_TAG",
                                "docker push $REPO_URI:latest",
                            ]
                        },
                    },
                }
            ),
        )
        ecr_repo.grant_push(build_project)
        source_asset.grant_read(build_project)

        trigger_fn = _lambda.Function(
            self,
            "BffBuildTrigger",
            function_name=f"{prefix}-build-trigger-hr-web-bff",
            runtime=_lambda.Runtime.PYTHON_3_13,
            handler="build_trigger_lambda.handler",
            code=_lambda.Code.from_asset(os.path.join(repo_root, "infra_utils")),
            timeout=cdk.Duration.minutes(15),
            memory_size=256,
        )
        trigger_fn.add_to_role_policy(
            iam.PolicyStatement(
                actions=["codebuild:StartBuild", "codebuild:BatchGetBuilds"],
                resources=[build_project.project_arn],
            )
        )
        build_trigger = CustomResource(
            self,
            "BffBuildTriggerCR",
            service_token=trigger_fn.function_arn,
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

        # ── 7. ECS Cluster + Auto-Scaling Fargate BFF Service ──────────────
        cluster = ecs.Cluster(
            self,
            "BffCluster",
            cluster_name=f"{prefix}-frontend",
            vpc=vpc,
            container_insights_v2=ecs.ContainerInsights.ENABLED,
        )

        bff_log_group = logs.LogGroup(
            self,
            "BffLogGroup",
            log_group_name=f"/aws/ecs/{prefix}-hr-web-bff",
            retention=log_retention,
            removal_policy=lifecycle_policy,
        )

        task_def = ecs.FargateTaskDefinition(
            self,
            "BffTaskDef",
            cpu=cpu,
            memory_limit_mib=memory_mib,
            runtime_platform=ecs.RuntimePlatform(
                cpu_architecture=ecs.CpuArchitecture.ARM64,
                operating_system_family=ecs.OperatingSystemFamily.LINUX,
            ),
        )
        task_def.add_container(
            "hr-web-bff",
            image=ecs.ContainerImage.from_ecr_repository(ecr_repo, tag=source_hash),
            port_mappings=[ecs.PortMapping(container_port=8080)],
            logging=ecs.LogDrivers.aws_logs(
                stream_prefix="hr-web-bff",
                log_group=bff_log_group,
            ),
            environment={
                "PROJECT_NAME": project_name,
                "ENVIRONMENT": environment,
                "AWS_REGION_NAME": self.region,
                "BFF_SSM_PREFIX": f"/{project_name}/{environment}",
                "OIDC_ISSUER_URL": issuer_url,
                "OIDC_CLIENT_ID": self._bff_client_id,
                "OIDC_REDIRECT_URI": redirect_uri,
                "OIDC_LOGOUT_URI": logout_uri,
                "OIDC_SCOPE": oidc_scope,
                "BFF_SESSION_TABLE": bff_sessions_table.table_name,
                "CHAT_SESSION_TABLE": chat_sessions_table.table_name,
                "FRONTEND_EXPOSURE": exposure,
                "COOKIE_SECURE": "true" if certificate_arn else "false",
                "SESSION_TTL_HOURS": str(session_ttl_hours),
            },
            secrets={"OIDC_CLIENT_SECRET": bff_secret_for_ecs},
        )

        bff_sessions_table.grant_read_write_data(task_def.task_role)
        chat_sessions_table.grant_read_write_data(task_def.task_role)
        if kms_key_arn:
            task_def.task_role.add_to_policy(
                iam.PolicyStatement(
                    sid="DynamoDbCmkAccess",
                    actions=["kms:Decrypt", "kms:Encrypt", "kms:GenerateDataKey*"],
                    resources=[kms_key_arn],
                )
            )
            task_def.obtain_execution_role().add_to_policy(
                iam.PolicyStatement(
                    sid="SecretCmkDecrypt",
                    actions=["kms:Decrypt", "kms:DescribeKey"],
                    resources=[kms_key_arn],
                )
            )
        task_def.task_role.add_to_policy(
            iam.PolicyStatement(
                sid="ReadOrchestratorRuntimeArn",
                actions=["ssm:GetParameter"],
                resources=[
                    self.format_arn(
                        service="ssm",
                        resource="parameter",
                        resource_name=f"{project_name}/{environment}/runtimes/orchestrator/arn",
                    )
                ],
            )
        )

        service = ecs.FargateService(
            self,
            "BffService",
            cluster=cluster,
            task_definition=task_def,
            desired_count=min_capacity,
            vpc_subnets=ec2.SubnetSelection(
                subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS
            ),
            security_groups=[ecs_sg],
            assign_public_ip=False,
            circuit_breaker=ecs.DeploymentCircuitBreaker(rollback=True),
            health_check_grace_period=cdk.Duration.seconds(60),
        )
        service.attach_to_application_target_group(target_group)
        service.node.add_dependency(build_trigger)

        scalable = service.auto_scale_task_count(
            min_capacity=min_capacity,
            max_capacity=max_capacity,
        )
        scalable.scale_on_cpu_utilization(
            "CpuScaling",
            target_utilization_percent=60,
            scale_in_cooldown=cdk.Duration.seconds(300),
            scale_out_cooldown=cdk.Duration.seconds(30),
        )
        scalable.scale_on_memory_utilization(
            "MemoryScaling",
            target_utilization_percent=70,
            scale_in_cooldown=cdk.Duration.seconds(300),
            scale_out_cooldown=cdk.Duration.seconds(30),
        )
        scalable.scale_on_request_count(
            "RequestBurstScaling",
            requests_per_target=300,
            target_group=target_group,
            scale_in_cooldown=cdk.Duration.seconds(300),
            scale_out_cooldown=cdk.Duration.seconds(30),
        )

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
        cdk.CfnOutput(self, "EcsClusterName", value=cluster.cluster_name)
        cdk.CfnOutput(self, "EcsServiceName", value=service.service_name)
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
