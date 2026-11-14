"""hr-tools — the HR assistant tool layer (phase H4 of the HR plan).

docs/hr/README.md is the authoritative spec; docs/hr/tools.md pins the
tool names, Cedar permits and interceptor rules; docs/hr/policy.md
pins the authorization input and reason codes; docs/hr/modules.md pins
the database roles and the SSM interface.

This stack deploys:

- Three CDK Lambda functions, one per gateway target (`hr-ops`,
  `hr-payroll`, `hr-finance`). Each Lambda bundles the per-tool
  handler packages under `lambdas/<tool>/` plus the shared library
  (`lambdas/shared/`, including `authz.py` for deterministic in-process
  authorization evaluation).
- Three IAM roles, one per Lambda, each with the minimum
  `rds-db:connect` set docs/hr/modules.md § Database roles lists.
- Three AgentCore Gateway Lambda targets, one per Lambda. The tool
  schemas in the targets match docs/hr/tools.md § Arguments.
- Three Cedar permits from docs/hr/tools.md § Cedar permits. Every
  permit is bound to the one leaf `agent_id` that may call it, and
  the stack asserts every permit becomes `ACTIVE` through explicit
  CloudFormation dependencies; a permit that fails to create is a
  failed deploy, not a silent deny.
- One SSM kill switch `use-cases/hr-tools/enabled` with the initial
  value `true` (docs/hr/modules.md § Kill switch and audit export).
- Per-Lambda CloudWatch log groups with 365-day retention.
- When `audit_stream_arn` is set in `platform.yaml`, a CloudWatch
  Logs subscription filter on each Lambda log group that forwards
  every line to the SIEM Firehose stream.

Rules every HR module keeps (custom-app-plan/phases.md § Rules every
HR module keeps) that this file locks:

- Never `import stacks.*`. Everything from the platform is read via
  the SSM interface, resolved at deploy time with
  `ssm.StringParameter.value_for_string_parameter`.
- The gateway role is granted `lambda:InvokeFunction` on the HR
  Lambdas and nothing else. The gateway stack's role already covers
  `{prefix}-tool-*`; our three functions are named to match, and
  each function also carries a resource policy that limits the
  caller to `bedrock-agentcore.amazonaws.com` in the same account.
"""

from __future__ import annotations

import hashlib
import shutil
import subprocess  # nosec B404 — pip-install into the Lambda asset at synth time
import sys
import tempfile
from pathlib import Path

import aws_cdk as cdk
from aws_cdk import aws_bedrockagentcore as agentcore
from aws_cdk import aws_iam as iam
from aws_cdk import aws_lambda as _lambda
from aws_cdk import aws_logs as logs
from aws_cdk import aws_ssm as ssm
from constructs import Construct

HERE = Path(__file__).resolve().parent

# ---------------------------------------------------------------------------
# Target → tool catalogue. docs/hr/tools.md § Routing is the source of truth.
# Changing a tool name here without changing docs/hr/tools.md breaks the
# Cedar permits below, which name the actions one-by-one.
# ---------------------------------------------------------------------------

READ_TOOLS: dict[str, list[str]] = {
    # five read tools, one Cedar permit covers all of them (see below)
    "hr-payroll": ["get_employee_compensation", "list_direct_reports"],
    "hr-ops": ["get_leave_balance", "check_leave_eligibility"],
    "hr-finance": ["get_allowance"],
}

# The one write a leaf may make and the reviewer-only decision. Keeping
# them separate from the read map makes the Cedar permit boundary
# obvious — the read permit never lists these actions.
HROPS_WRITE_TOOLS: list[str] = ["submit_leave_request"]
HROPS_REVIEW_TOOLS: list[str] = ["record_leave_decision"]

# Every tool a target Lambda bundles — reads + write + review for hr-ops,
# reads only for hr-payroll and hr-finance.
TARGET_TOOLS: dict[str, list[str]] = {
    "hr-ops": READ_TOOLS["hr-ops"] + HROPS_WRITE_TOOLS + HROPS_REVIEW_TOOLS,
    "hr-payroll": list(READ_TOOLS["hr-payroll"]),
    "hr-finance": list(READ_TOOLS["hr-finance"]),
}

# docs/hr/modules.md § Database roles — hr-ops is the only target role
# that may connect as hr_writer.
TARGET_DB_ROLES: dict[str, list[str]] = {
    "hr-ops": ["hr_reader", "hr_writer", "hr_audit"],
    "hr-payroll": ["hr_reader", "hr_audit"],
    "hr-finance": ["hr_reader", "hr_audit"],
}

# docs/hr/tools.md § Routing maps each leaf to the tool it may call.
# The Cedar permit below names the leaf by that `agent_id`.
LEAF_FOR_TOOL: dict[str, str] = {
    "get_leave_balance": "leave-balance",
    "check_leave_eligibility": "leave-eligibility",
    "submit_leave_request": "leave-submit",
    "get_employee_compensation": "compensation",
    "list_direct_reports": "direct-reports",
    "get_allowance": "allowance",
    "record_leave_decision": "review-node",
}

# docs/hr/tools.md § Arguments — the tool schemas the gateway exposes.
# `caller_employee_id` is intentionally NOT in any schema: the
# interceptor overwrites that field, and docs/hr/tools.md § Identity
# on the call forbids the model from seeing it.
TOOL_SCHEMAS: dict[str, dict] = {
    "get_employee_compensation": {
        "Name": "get_employee_compensation",
        "Description": (
            "Return the compensation for the caller or a direct report. "
            "Defaults to the caller when employee_id is omitted."
        ),
        "InputSchema": {
            "Type": "object",
            "Properties": {
                "employee_id": {
                    "Type": "string",
                    "Description": (
                        "Target employee. Any id other than the caller is "
                        "only a lookup; the token's employee_id is still "
                        "the caller."
                    ),
                },
            },
        },
    },
    "list_direct_reports": {
        "Name": "list_direct_reports",
        "Description": "List the caller's direct reports, one hop only.",
        "InputSchema": {"Type": "object", "Properties": {}},
    },
    "get_leave_balance": {
        "Name": "get_leave_balance",
        "Description": "Return the caller's remaining annual and sick leave.",
        "InputSchema": {"Type": "object", "Properties": {}},
    },
    "check_leave_eligibility": {
        "Name": "check_leave_eligibility",
        "Description": (
            "Check whether the caller may take leave in the requested range. "
            "No row is created; the matching submit_leave_request call is."
        ),
        "InputSchema": {
            "Type": "object",
            "Properties": {
                "leave_type": {"Type": "string", "Enum": ["annual", "sick"]},
                "start_date": {"Type": "string", "Description": "YYYY-MM-DD"},
                "end_date": {"Type": "string", "Description": "YYYY-MM-DD"},
            },
            "Required": ["leave_type", "start_date", "end_date"],
        },
    },
    "submit_leave_request": {
        "Name": "submit_leave_request",
        "Description": (
            "Submit a pending leave request for the caller. "
            "Idempotent on (employee_id, idempotency_key)."
        ),
        "InputSchema": {
            "Type": "object",
            "Properties": {
                "leave_type": {"Type": "string", "Enum": ["annual", "sick"]},
                "start_date": {"Type": "string", "Description": "YYYY-MM-DD"},
                "end_date": {"Type": "string", "Description": "YYYY-MM-DD"},
                "reason": {"Type": "string"},
                "idempotency_key": {"Type": "string"},
            },
            "Required": [
                "leave_type",
                "start_date",
                "end_date",
                "reason",
                "idempotency_key",
            ],
        },
    },
    "get_allowance": {
        "Name": "get_allowance",
        "Description": (
            "Return the caller's allowance for the given item_type and period. "
            "period defaults to the previous UTC calendar month."
        ),
        "InputSchema": {
            "Type": "object",
            "Properties": {
                "item_type": {"Type": "string", "Enum": ["telephone"]},
                "period": {"Type": "string", "Description": "YYYY-MM"},
            },
            "Required": ["item_type"],
        },
    },
    "record_leave_decision": {
        "Name": "record_leave_decision",
        "Description": (
            "Reviewer-only: record the manager's decision on a pending "
            "leave_requests row. Cedar restricts callers to the review node."
        ),
        "InputSchema": {
            "Type": "object",
            "Properties": {
                "request_id": {"Type": "string"},
                "decision": {"Type": "string", "Enum": ["approve", "reject"]},
            },
            "Required": ["request_id", "decision"],
        },
    },
}


class HrToolsStack(cdk.Stack):
    def __init__(
        self,
        scope: Construct,
        id: str,
        *,
        ctx: dict,
        config: dict,
        **kw,
    ) -> None:
        super().__init__(scope, id, **kw)

        prefix = ctx["prefix"]
        ssm_prefix = ctx["ssm_prefix"]

        # ─────────────────────────────────────────────────────────────
        # Platform interface (docs/hr/modules.md § SSM interface).
        # Every value is a CloudFormation dynamic reference resolved at
        # deploy time; no core stack is imported.
        # ─────────────────────────────────────────────────────────────
        gateway_url = ssm.StringParameter.value_for_string_parameter(
            self, f"{ssm_prefix}/gateway/url"
        )
        gateway_arn = ssm.StringParameter.value_for_string_parameter(
            self, f"{ssm_prefix}/gateway/arn"
        )
        policy_engine_id = ssm.StringParameter.value_for_string_parameter(
            self, f"{ssm_prefix}/gateway/policy-engine-id"
        )
        # docs/hr/modules.md § SSM interface also lists:
        #   - identity/gateway-credential-provider-name (used by the
        #     runtime to mint gateway tokens; the Lambda layer has no
        #     role for it)
        #   - use-cases/hr-data/secret-name (operators only; H3 and H4
        #     never read the master-secret value)
        # Neither is needed inside this template, so skipping their
        # SSM dynamic references keeps the template free of dead
        # Parameters and the Design-time diff clean.

        hr_db_endpoint = ssm.StringParameter.value_for_string_parameter(
            self, f"{ssm_prefix}/use-cases/hr-data/endpoint"
        )
        hr_db_name = ssm.StringParameter.value_for_string_parameter(
            self, f"{ssm_prefix}/use-cases/hr-data/database-name"
        )

        private_subnet_ids_param = ssm.StringParameter.value_for_string_parameter(
            self, f"{ssm_prefix}/networking/private-subnet-ids"
        )
        runtime_security_group_id = ssm.StringParameter.value_for_string_parameter(
            self, f"{ssm_prefix}/networking/runtime-security-group-id"
        )

        audit_stream_arn = (config.get("audit_stream_arn") or "").strip()

        # ─────────────────────────────────────────────────────────────
        # Kill switch — SSM parameter with initial value 'true'
        # (docs/hr/modules.md § Kill switch and audit export). An
        # operator flips it with `aws ssm put-parameter --overwrite`;
        # the Lambda layer refuses within 30 s of the flip.
        # ─────────────────────────────────────────────────────────────
        kill_switch_name = f"{ssm_prefix}/use-cases/hr-tools/enabled"
        kill_switch = ssm.StringParameter(
            self,
            "HrToolsEnabled",
            parameter_name=kill_switch_name,
            string_value="true",
            description=(
                "Kill switch for every HR tool. Anything other than 'true' "
                "returns SERVICE_DISABLED within 30 s. See "
                "docs/hr/modules.md § Kill switch and audit export."
            ),
        )

        # ─────────────────────────────────────────────────────────────
        # Lambda functions, one per gateway target.
        # ─────────────────────────────────────────────────────────────
        functions: dict[str, _lambda.Function] = {}
        roles: dict[str, iam.Role] = {}
        log_groups: dict[str, logs.LogGroup] = {}

        shared_env = {
            "HR_KILL_SWITCH_PARAMETER": kill_switch_name,
            "HR_DB_ENDPOINT": hr_db_endpoint,
            "HR_DB_NAME": hr_db_name,
        }

        for target_name, tool_names in TARGET_TOOLS.items():
            role = _build_lambda_role(
                self,
                target_name=target_name,
                prefix=prefix,
                db_roles=TARGET_DB_ROLES[target_name],
                kill_switch_parameter_name=kill_switch_name,
            )
            roles[target_name] = role

            log_group = logs.LogGroup(
                self,
                f"Logs-{target_name}",
                log_group_name=f"/aws/lambda/{prefix}-tool-{target_name}",
                retention=logs.RetentionDays.ONE_YEAR,  # docs/hr/modules.md: 365 days
                removal_policy=cdk.RemovalPolicy.RETAIN_ON_UPDATE_OR_DELETE,
            )
            log_groups[target_name] = log_group

            asset_dir = _build_lambda_asset(target_name, tool_names)

            function = _lambda.Function(
                self,
                f"Tool-{target_name}",
                function_name=f"{prefix}-tool-{target_name}",
                runtime=_lambda.Runtime.PYTHON_3_13,
                handler="handler.handler",
                code=_lambda.Code.from_asset(asset_dir),
                architecture=_lambda.Architecture.ARM_64,
                timeout=cdk.Duration.seconds(30),
                memory_size=512,
                role=role,
                log_group=log_group,
                environment=shared_env,
            )

            # VPC placement: hr-data lives in the private subnets published
            # by the networking stack. CDK cannot build a Subnet from a
            # dynamic SSM list, so we set VpcConfig directly on the
            # underlying CfnFunction. The role was given the VPC
            # execution policy above so ENIs can attach.
            cfn_function = function.node.default_child  # type: ignore[assignment]
            cfn_function.add_property_override(
                "VpcConfig",
                {
                    "SubnetIds": cdk.Fn.split(",", private_subnet_ids_param),
                    "SecurityGroupIds": [runtime_security_group_id],
                },
            )

            # The gateway invokes the Lambda with the AgentCore service
            # principal. Scope the resource policy to this account AND this
            # exact gateway ARN (matching stacks/gateway_stack.py) so no
            # other gateway in the account can invoke HR Lambdas.
            function.add_permission(
                "AgentCoreInvoke",
                principal=iam.ServicePrincipal("bedrock-agentcore.amazonaws.com"),
                source_account=self.account,
                source_arn=gateway_arn,
            )

            # Audit export (docs/hr/modules.md § Kill switch and audit
            # export). When audit_stream_arn is set, subscribe the log
            # group to the Firehose stream; when it is empty the SIEM
            # gap stays recorded in the risk register and no filter is
            # created.
            if audit_stream_arn:
                _build_audit_subscription(
                    self,
                    target_name=target_name,
                    log_group=log_group,
                    audit_stream_arn=audit_stream_arn,
                )

            functions[target_name] = function

        # ─────────────────────────────────────────────────────────────
        # Gateway Lambda targets. The gateway role (in the core
        # gateway stack) already allows invoke on {prefix}-tool-*; the
        # per-function resource policy added above locks the caller to
        # our account and service principal.
        # ─────────────────────────────────────────────────────────────
        targets: list[agentcore.CfnGatewayTarget] = []
        gateway_identifier = _extract_gateway_identifier(gateway_arn)
        for target_name, function in functions.items():
            tool_schema = [TOOL_SCHEMAS[name] for name in TARGET_TOOLS[target_name]]
            target = agentcore.CfnGatewayTarget(
                self,
                f"Target-{target_name}",
                name=target_name,
                gateway_identifier=gateway_identifier,
                credential_provider_configurations=[
                    {"credentialProviderType": "GATEWAY_IAM_ROLE"},
                ],
                target_configuration={"mcp": {}},
            )
            # CDK strips the "lambda" key because it is a Python reserved
            # word and the L1 property mapping does not handle it; set
            # it directly, the same way the core gateway stack does.
            target.add_property_override(
                "TargetConfiguration.Mcp.Lambda",
                {
                    "LambdaArn": function.function_arn,
                    "ToolSchema": {"InlinePayload": tool_schema},
                },
            )
            targets.append(target)

        # ─────────────────────────────────────────────────────────────
        # Cedar permits (docs/hr/tools.md § Cedar permits). Three
        # permits: read (five tools), write (submit_leave_request),
        # decision (record_leave_decision). Each permit depends on
        # every target so Cedar can validate the action names before
        # it tries to compile; a permit that fails to compile fails
        # the deploy (CloudFormation surfaces the error).
        # ─────────────────────────────────────────────────────────────
        self._build_cedar_permits(
            policy_engine_id=policy_engine_id,
            gateway_arn=gateway_arn,
            targets=targets,
        )

        # ─────────────────────────────────────────────────────────────
        # Outputs.
        # ─────────────────────────────────────────────────────────────
        cdk.CfnOutput(self, "KillSwitchParameter", value=kill_switch.parameter_name)
        cdk.CfnOutput(self, "GatewayUrl", value=gateway_url)
        for target_name, function in functions.items():
            cdk.CfnOutput(
                self,
                f"Function-{target_name}",
                value=function.function_arn,
            )

    def _build_cedar_permits(
        self,
        *,
        policy_engine_id: str,
        gateway_arn: str,
        targets: list[agentcore.CfnGatewayTarget],
    ) -> None:
        """Deploy the three Cedar permits docs/hr/tools.md § Cedar permits pins.

        docs/hr/tools.md § Cedar permits says "A policy that failed to
        create leaves the gateway denying every call", so every policy
        is dependent on every target to guarantee the actions already
        exist when Cedar validates them; CloudFormation then fails the
        stack deploy if one of them does not reach `ACTIVE`.
        """
        read_actions = ",\n             ".join(
            f'AgentCore::Action::"{target}___{tool}"'
            for target, tools in READ_TOOLS.items()
            for tool in tools
        )
        read_when_clauses = " ||\n   ".join(
            f'(action == AgentCore::Action::"{target}___{tool}" '
            f'&& principal.getTag("agent_id") == "{LEAF_FOR_TOOL[tool]}")'
            for target, tools in READ_TOOLS.items()
            for tool in tools
        )
        read_permit = (
            "permit(\n"
            "  principal is AgentCore::OAuthUser,\n"
            "  action in [" + read_actions + "],\n"
            f'  resource == AgentCore::Gateway::"{gateway_arn}"\n'
            ") when {\n"
            '  principal.hasTag("employee_id") && principal.hasTag("agent_id") &&\n'
            "  (" + read_when_clauses + ")\n"
            "};\n"
        )

        write_permit = (
            "permit(\n"
            "  principal is AgentCore::OAuthUser,\n"
            '  action == AgentCore::Action::"hr-ops___submit_leave_request",\n'
            f'  resource == AgentCore::Gateway::"{gateway_arn}"\n'
            ") when {\n"
            '  principal.hasTag("employee_id") && principal.hasTag("agent_id") &&\n'
            '  principal.getTag("agent_id") == "leave-submit"\n'
            "};\n"
        )

        review_permit = (
            "permit(\n"
            "  principal is AgentCore::OAuthUser,\n"
            '  action == AgentCore::Action::"hr-ops___record_leave_decision",\n'
            f'  resource == AgentCore::Gateway::"{gateway_arn}"\n'
            ") when {\n"
            '  principal.hasTag("employee_id") && principal.hasTag("agent_id") &&\n'
            '  principal.getTag("agent_id") == "review-node"\n'
            "};\n"
        )

        # Cedar policy names are a service-level identifier, not a
        # CFN logical id: letters, digits, and underscores only, up to
        # 48 characters. Keep them short and descriptive here so an
        # operator reading CloudTrail policy-create events can tell
        # the three permits apart.
        policy_specs = (
            ("CedarPermitReadTools", "hr_tools_read_permit", read_permit),
            ("CedarPermitSubmitLeave", "hr_tools_submit_permit", write_permit),
            (
                "CedarPermitRecordDecision",
                "hr_tools_decision_permit",
                review_permit,
            ),
        )
        for construct_id, service_name, statement in policy_specs:
            policy = agentcore.CfnPolicy(
                self,
                construct_id,
                name=service_name,
                policy_engine_id=policy_engine_id,
                definition=agentcore.CfnPolicy.PolicyDefinitionProperty(
                    cedar=agentcore.CfnPolicy.CedarPolicyProperty(statement=statement),
                ),
            )
            for target in targets:
                policy.node.add_dependency(target)


# ---------------------------------------------------------------------------
# Lambda role builder
# ---------------------------------------------------------------------------


def _build_lambda_role(
    stack: cdk.Stack,
    *,
    target_name: str,
    prefix: str,
    db_roles: list[str],
    kill_switch_parameter_name: str,
) -> iam.Role:
    """Create the per-target Lambda IAM role.

    docs/hr/modules.md § Database roles lists the `rds-db:connect`
    grants. The IAM resource format is:

        arn:aws:rds-db:<region>:<account>:dbuser:<db-resource-id>/<role>

    The DB resource ID is not in SSM, so the statement uses a `*`
    wildcard on the resource id and names each role explicitly. The
    role identifier narrows the grant to the exact users H1 created.
    """
    role = iam.Role(
        stack,
        f"LambdaRole-{target_name}",
        role_name=f"{prefix}-tool-{target_name}-role",
        assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"),
        managed_policies=[
            iam.ManagedPolicy.from_aws_managed_policy_name(
                "service-role/AWSLambdaBasicExecutionRole"
            ),
            # VPC placement needs network-interface permissions; without
            # this the Lambda hangs in INIT and never runs.
            iam.ManagedPolicy.from_aws_managed_policy_name(
                "service-role/AWSLambdaVPCAccessExecutionRole"
            ),
        ],
    )
    for db_role in db_roles:
        role.add_to_policy(
            iam.PolicyStatement(
                sid=f"RdsConnect{db_role.title().replace('_', '')}",
                actions=["rds-db:connect"],
                resources=[
                    f"arn:aws:rds-db:{stack.region}:{stack.account}:dbuser:*/{db_role}"
                ],
            )
        )
    # The kill-switch SSM read is a pre-policy check; every Lambda gets
    # exactly that parameter and nothing else.
    role.add_to_policy(
        iam.PolicyStatement(
            sid="ReadKillSwitchParameter",
            actions=["ssm:GetParameter"],
            resources=[
                f"arn:aws:ssm:{stack.region}:{stack.account}:parameter{kill_switch_parameter_name}"
            ],
        )
    )
    return role


def _extract_gateway_identifier(gateway_arn: str) -> str:
    """Return the gateway identifier from an ARN SSM dynamic reference.

    The gateway ARN format is
        arn:aws:bedrock-agentcore:<region>:<account>:gateway/<identifier>

    CloudFormation Fn::Select + Fn::Split is the only way to pull the
    last segment out of a dynamic reference (we cannot string-split in
    Python at synth time because the value is still a token).
    """
    return cdk.Fn.select(1, cdk.Fn.split(":gateway/", gateway_arn))


# ---------------------------------------------------------------------------
# Audit export
# ---------------------------------------------------------------------------


def _build_audit_subscription(
    stack: cdk.Stack,
    *,
    target_name: str,
    log_group: logs.LogGroup,
    audit_stream_arn: str,
) -> None:
    """Forward the Lambda log group to the SIEM Firehose stream.

    docs/hr/modules.md § Kill switch and audit export: HR log groups
    deliver the decision_log JSON line to Firehose. The filter_pattern
    is empty so every line goes through — the SIEM owns the filter.
    """
    firehose_role = iam.Role(
        stack,
        f"AuditFirehoseRole-{target_name}",
        assumed_by=iam.ServicePrincipal(
            f"logs.{stack.region}.amazonaws.com",
        ),
    )
    firehose_role.add_to_policy(
        iam.PolicyStatement(
            actions=["firehose:PutRecord", "firehose:PutRecordBatch"],
            resources=[audit_stream_arn],
        )
    )
    logs.CfnSubscriptionFilter(
        stack,
        f"AuditSubscription-{target_name}",
        destination_arn=audit_stream_arn,
        filter_pattern="",
        log_group_name=log_group.log_group_name,
        role_arn=firehose_role.role_arn,
    )


# ---------------------------------------------------------------------------
# Asset packaging
# ---------------------------------------------------------------------------


def _build_lambda_asset(target_name: str, tool_names: list[str]) -> str:
    """Prepare the Lambda zip asset on disk.

    CDK's `_lambda.Code.from_asset` wants a directory tree to zip. The
    repo keeps per-tool handlers under `lambdas/<tool>/` and shared
    helpers (including `shared/authz.py`) under `lambdas/shared/`;
    stack.py assembles the flat `/var/task` layout under a tempdir and
    points `from_asset` at it.

    The tempdir path is NOT in the asset hash — only the content is —
    so a stable tree produces a stable hash.
    """
    bundle = Path(tempfile.mkdtemp(prefix=f"hr-tools-{target_name}-"))

    # psycopg[binary] driver. Lambda runtime is linux/aarch64 (`ARM_64`), so
    # manylinux2014_aarch64 wheels are cached once and copied into each target
    # bundle before overlaying our own packages.
    requirements = HERE / "lambdas" / "requirements.txt"
    if requirements.exists():
        _copy_cached_manylinux_deps(requirements, bundle)
        shutil.copy(requirements, bundle / "requirements.txt")

    # shared library — bundled into every target Lambda so the
    # per-tool handlers can `from shared import ...`.
    shutil.copytree(HERE / "lambdas" / "shared", bundle / "shared", dirs_exist_ok=True)

    # dispatcher → /var/task/handler.py. The CDK function sets
    # `handler="handler.handler"` so Lambda imports this one file.
    shutil.copy(HERE / "lambdas" / "dispatcher.py", bundle / "handler.py")

    # per-tool handler packages — one per tool_name.
    for tool in tool_names:
        shutil.copytree(HERE / "lambdas" / tool, bundle / tool, dirs_exist_ok=True)

    return str(bundle)


def _copy_cached_manylinux_deps(requirements: Path, bundle: Path) -> None:
    """Install linux/aarch64 wheels once per requirements hash and copy into `bundle`."""
    req_hash = hashlib.sha256(requirements.read_bytes()).hexdigest()[:16]
    cache_dir = Path(tempfile.gettempdir()) / f"hr-tools-aarch64-deps-{req_hash}"
    sentinel = cache_dir / ".installed"
    if not sentinel.exists():
        if cache_dir.exists():
            shutil.rmtree(cache_dir)
        cache_dir.mkdir(parents=True, exist_ok=True)
        subprocess.run(  # nosec B603 — fixed argv, sys.executable, fixed requirements
            [
                sys.executable,
                "-m",
                "pip",
                "install",
                "--quiet",
                "--no-color",
                "--disable-pip-version-check",
                "--target",
                str(cache_dir),
                "--platform",
                "manylinux2014_aarch64",
                "--implementation",
                "cp",
                "--python-version",
                "3.13",
                "--only-binary=:all:",
                "--upgrade",
                "-r",
                str(requirements),
            ],
            check=True,
        )
        sentinel.write_text(req_hash + "\n")

    for item in cache_dir.iterdir():
        if item.name == ".installed":
            continue
        dest = bundle / item.name
        if item.is_dir():
            shutil.copytree(item, dest, dirs_exist_ok=True)
        else:
            shutil.copy2(item, dest)


# ---------------------------------------------------------------------------
# Entry point — the platform calls this for each enabled use case.
# ---------------------------------------------------------------------------


def build(app, ctx: dict, config: dict) -> None:
    HrToolsStack(
        app,
        f"{ctx['prefix']}-uc-hr-tools",
        ctx=ctx,
        config=config,
        env=ctx["cdk_env"],
    )
