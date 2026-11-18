"""Reusable AgentCore IAM Role construct."""

import re

import aws_cdk as cdk
from aws_cdk import aws_iam as iam
from constructs import Construct

# A literal SSM path segment. IAM treats "*" and "?" as wildcards and "${...}" as a
# policy variable, and "/" would add a level, so any of them would widen the grant.
_PARAMETER_PATH_SEGMENT = re.compile(r"[A-Za-z0-9_.-]+")


def environment_parameters_arn(
    scope: Construct, *, project_name: str, environment: str
) -> str:
    """ARN pattern for /{project_name}/{environment}/* in the scope's own region and account.

    Every environment publishes its discovery parameters (auth client ids, the machine
    client's secret name, gateway URL, ...) under its own prefix, and several environments
    can share a project name in one account. A runtime role reads only its own prefix.
    """
    for label, value in (("project_name", project_name), ("environment", environment)):
        if not isinstance(value, str) or not _PARAMETER_PATH_SEGMENT.fullmatch(value):
            raise ValueError(
                f"{label} must be a literal SSM path segment ([A-Za-z0-9_.-]+), got {value!r}"
            )
    return cdk.Stack.of(scope).format_arn(
        service="ssm",
        resource="parameter",
        resource_name=f"{project_name}/{environment}/*",
        arn_format=cdk.ArnFormat.SLASH_RESOURCE_NAME,
    )


class AgentCoreRole(iam.Role):
    """IAM Role for AgentCore Runtime with standard permissions."""

    def __init__(
        self,
        scope: Construct,
        id: str,
        *,
        project_name: str,
        environment: str,
        component_name: str,
        extra_policy_statements: list[iam.PolicyStatement] | None = None,
        **kwargs,
    ):
        super().__init__(
            scope,
            id,
            assumed_by=iam.ServicePrincipal("bedrock-agentcore.amazonaws.com"),
            role_name=f"{project_name}-{component_name}-role",
            **kwargs,
        )

        # Core permissions every AgentCore runtime needs
        self.add_to_policy(
            iam.PolicyStatement(
                actions=[
                    "ecr:BatchGetImage",
                    "ecr:GetDownloadUrlForLayer",
                    "ecr:GetAuthorizationToken",
                ],
                resources=["*"],
            )
        )
        self.add_to_policy(
            iam.PolicyStatement(
                actions=[
                    "logs:CreateLogGroup",
                    "logs:CreateLogStream",
                    "logs:PutLogEvents",
                ],
                resources=[
                    "arn:aws:logs:*:*:log-group:/aws/bedrock-agentcore/runtimes/*"
                ],
            )
        )
        self.add_to_policy(
            iam.PolicyStatement(
                actions=["xray:PutTraceSegments", "xray:PutTelemetryRecords"],
                resources=["*"],
            )
        )
        self.add_to_policy(
            iam.PolicyStatement(
                actions=[
                    "cloudwatch:PutMetricData",
                ],
                resources=["*"],
                conditions={
                    "StringEquals": {"cloudwatch:namespace": "bedrock-agentcore"}
                },
            )
        )
        self.add_to_policy(
            iam.PolicyStatement(
                actions=[
                    "bedrock:InvokeModel",
                    "bedrock:Converse",
                    "bedrock:ConverseStream",
                ],
                resources=["arn:aws:bedrock:*::foundation-model/*"],
            )
        )
        # Least-privilege (item 2): scope SSM reads to this environment's parameter path
        # rather than "*". See control-library/iam/runtime-execution-least-privilege.json for
        # the full reference policy (ECR/logs/bedrock scoping) teams can adopt.
        self.add_to_policy(
            iam.PolicyStatement(
                actions=["ssm:GetParameter", "ssm:GetParameters"],
                resources=[
                    environment_parameters_arn(
                        self,
                        project_name=project_name,
                        environment=environment,
                    )
                ],
            )
        )

        for stmt in extra_policy_statements or []:
            self.add_to_policy(stmt)
