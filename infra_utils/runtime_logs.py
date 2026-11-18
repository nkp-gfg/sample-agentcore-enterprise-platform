"""CloudWatch Logs grant for one AgentCore Runtime's own application log group.

AgentCore writes a runtime's stdout to
``/aws/bedrock-agentcore/runtimes/<agent_runtime_id>-<endpoint_name>``. A grant
on ``runtimes/*`` would let every runtime role write (and plant events in) every
other runtime's log group, so the grant names exactly one group, in this
stack's account and region.

The runtime id only exists once the runtime does, while the runtime needs its
role first. The grant therefore lives in its own ``AWS::IAM::Policy`` rather
than the role's default policy: that policy carries the ECR pull permissions
the runtime needs at creation, and must not wait for the runtime.
"""

from __future__ import annotations

import aws_cdk as cdk
from aws_cdk import aws_iam as iam
from constructs import Construct

RUNTIME_LOG_GROUP_PREFIX = "/aws/bedrock-agentcore/runtimes/"
DEFAULT_ENDPOINT_NAME = "DEFAULT"


def _reject_wildcards(name: str, value: str) -> None:
    if not cdk.Token.is_unresolved(value) and ("*" in value or "?" in value):
        raise ValueError(f"{name} must name one runtime log group, got {value!r}")


def runtime_log_group_arn(
    scope: Construct,
    runtime_id: str,
    endpoint_name: str = DEFAULT_ENDPOINT_NAME,
) -> str:
    """ARN of ``runtime_id``'s log group for ``endpoint_name`` in this stack's account/region."""
    _reject_wildcards("runtime_id", runtime_id)
    _reject_wildcards("endpoint_name", endpoint_name)
    return cdk.Stack.of(scope).format_arn(
        service="logs",
        resource="log-group",
        resource_name=f"{RUNTIME_LOG_GROUP_PREFIX}{runtime_id}-{endpoint_name}",
        arn_format=cdk.ArnFormat.COLON_RESOURCE_NAME,
    )


def runtime_log_statements(
    scope: Construct,
    runtime_id: str,
    endpoint_name: str = DEFAULT_ENDPOINT_NAME,
) -> list[iam.PolicyStatement]:
    group_arn = runtime_log_group_arn(scope, runtime_id, endpoint_name)
    return [
        iam.PolicyStatement(
            sid="RuntimeLogGroup",
            actions=["logs:CreateLogGroup"],
            resources=[group_arn],
        ),
        iam.PolicyStatement(
            sid="RuntimeLogStreams",
            actions=["logs:CreateLogStream", "logs:PutLogEvents"],
            resources=[f"{group_arn}:log-stream:*"],
        ),
    ]


def attach_runtime_log_policy(
    scope: Construct,
    construct_id: str,
    role: iam.IRole,
    runtime_id: str,
    endpoint_name: str = DEFAULT_ENDPOINT_NAME,
) -> iam.Policy:
    """Let ``role`` write only ``runtime_id``'s own log group."""
    return iam.Policy(
        scope,
        construct_id,
        roles=[role],
        statements=runtime_log_statements(scope, runtime_id, endpoint_name),
    )
