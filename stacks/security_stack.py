"""Security Stack — KMS CMK, IAM policy templates, CloudTrail."""

import aws_cdk as cdk
from aws_cdk import aws_cloudtrail as cloudtrail
from aws_cdk import aws_iam as iam
from aws_cdk import aws_kms as kms
from aws_cdk import aws_s3 as s3
from constructs import Construct


class SecurityStack(cdk.Stack):
    def __init__(
        self,
        scope: Construct,
        id: str,
        *,
        project_name: str,
        environment: str,
        enable_kms: bool = True,
        enable_cloudtrail: bool = True,
        retain_data: bool = False,
        **kwargs,
    ):
        super().__init__(scope, id, **kwargs)

        prefix = f"{project_name}-{environment}"
        lifecycle_policy = (
            cdk.RemovalPolicy.RETAIN if retain_data else cdk.RemovalPolicy.DESTROY
        )

        # KMS CMK for AgentCore Memory encryption
        self.kms_key = (
            kms.Key(
                self,
                "AgentCoreKey",
                alias=f"alias/{prefix}-agentcore",
                description=f"CMK for {project_name} AgentCore resources",
                enable_key_rotation=True,
                removal_policy=lifecycle_policy,
            )
            if enable_kms
            else None
        )

        if self.kms_key:
            # The observability stack encrypts its SNS topics with this key.
            # CloudWatch alarms and EventBridge rules publish to them, and SNS
            # needs the publisher to be able to use the key. Limited to this
            # account's resources.
            self.kms_key.add_to_resource_policy(
                iam.PolicyStatement(
                    sid="AllowAlarmAndEventPublishersToEncryptedTopics",
                    principals=[
                        iam.ServicePrincipal("cloudwatch.amazonaws.com"),
                        iam.ServicePrincipal("events.amazonaws.com"),
                    ],
                    actions=["kms:Decrypt", "kms:GenerateDataKey*"],
                    resources=["*"],
                    conditions={"StringEquals": {"aws:SourceAccount": self.account}},
                )
            )

        # CloudTrail for AgentCore API auditing
        if enable_cloudtrail:
            trail_bucket = s3.Bucket(
                self,
                "TrailBucket",
                bucket_name=f"{prefix}-cloudtrail-{self.account}",
                removal_policy=lifecycle_policy,
                auto_delete_objects=not retain_data,
                encryption=(
                    s3.BucketEncryption.KMS
                    if retain_data and self.kms_key
                    else s3.BucketEncryption.S3_MANAGED
                ),
                encryption_key=self.kms_key if retain_data else None,
                enforce_ssl=True,
                block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
                versioned=retain_data,
            )
            trail_access_logs_bucket = s3.Bucket(
                self,
                "TrailAccessLogsBucket",
                bucket_name=f"{prefix}-cloudtrail-access-logs-{self.account}",
                removal_policy=lifecycle_policy,
                auto_delete_objects=not retain_data,
                encryption=s3.BucketEncryption.S3_MANAGED,
                enforce_ssl=True,
                block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
                versioned=retain_data,
            )
            trail_access_logs_bucket.add_to_resource_policy(
                iam.PolicyStatement(
                    sid="AllowS3ServerAccessLogs",
                    principals=[iam.ServicePrincipal("logging.s3.amazonaws.com")],
                    actions=["s3:PutObject"],
                    resources=[
                        trail_access_logs_bucket.arn_for_objects("access-logs/*")
                    ],
                    conditions={
                        "StringEquals": {"aws:SourceAccount": self.account},
                        "ArnLike": {"aws:SourceArn": trail_bucket.bucket_arn},
                    },
                )
            )
            cfn_trail_bucket = trail_bucket.node.default_child  # type: ignore[assignment]
            cfn_trail_bucket.logging_configuration = (
                s3.CfnBucket.LoggingConfigurationProperty(
                    destination_bucket_name=trail_access_logs_bucket.bucket_name,
                    log_file_prefix="access-logs/",
                )
            )
            cfn_trail_bucket.add_dependency(
                trail_access_logs_bucket.node.default_child  # type: ignore[arg-type]
            )
            cloudtrail.Trail(
                self,
                "AgentCoreTrail",
                trail_name=f"{prefix}-agentcore-trail",
                bucket=trail_bucket,
                enable_file_validation=True,
                is_multi_region_trail=retain_data,
            )

        if self.kms_key:
            cdk.CfnOutput(self, "KmsKeyArn", value=self.kms_key.key_arn)
