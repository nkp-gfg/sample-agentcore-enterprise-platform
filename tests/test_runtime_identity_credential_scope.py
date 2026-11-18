"""Runtime roles must not mint tokens for every workload identity or provider.

The role attached to each AgentCore runtime is the credential a compromised
container inherits, and in migration mode the adapter copies that environment
into the customer process. These tests synthesize that role and decide the
calls the attack would make.

IAM rules the decisions follow, from the public docs (not from this repo):

- An explicit deny overrides an allow. Identity policies and SCPs are
  intersected: both must allow, and a deny in either wins.
  https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic.html
- ``Resource "*"`` matches every resource. ``*`` and ``?`` match inside an ARN
  segment, and a ``*`` that ends a segment may cross colon boundaries.
  https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_resource.html
- At one organization node, attached SCPs combine as a union of allows and a
  deny from any of them. ``FullAWSAccess`` allows every action and stays
  attached unless an administrator removes it; the identity SCP is an extra
  deny. A permission still needs an allow at every level above the account.
  https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps_evaluation.html
- These AgentCore actions list required resource types (the service
  authorization reference marks them with ``*``). The call is allowed only
  when every required resource in the request is allowed:
  GetWorkloadAccessToken, GetWorkloadAccessTokenForJWT, and
  GetWorkloadAccessTokenForUserId require ``workload-identity`` and
  ``workload-identity-directory``. CreateWorkloadIdentity requires those two.
  GetResourceOauth2Token also requires ``oauth2credentialprovider`` and
  ``token-vault``. ARN shapes are
  ``workload-identity-directory/${DirectoryId}/workload-identity/${WorkloadIdentityName}``,
  ``workload-identity-directory/${DirectoryId}``,
  ``token-vault/${TokenVaultId}``, and
  ``token-vault/${TokenVaultId}/oauth2credentialprovider/${Name}``.
  https://docs.aws.amazon.com/service-authorization/latest/reference/list_amazonbedrockagentcore.html

The service authorization reference's ARN uses ``oauth2credentialprovider``.
The control-library example uses ``oauth2-credential-provider``. A request is
built for both spellings, because a policy that still matches either one
still authorizes that spelling.

Actions on the same ``AgentCoreAccess`` statement that are not identity or
credential reads (InvokeAgentRuntime, InvokeGateway, GetGateway, ListGateways,
the memory actions, and the browser actions) are a separate wildcard and are
not asserted here.
"""

from __future__ import annotations

import re
import sys
import types
from pathlib import Path

import aws_cdk as cdk
import pytest
from aws_cdk.assertions import Template

from infra_utils.policy_loader import load_control
from stacks.identity_stack import IdentityStack
from stacks.runtime_stack import RuntimeStack

REPO = Path(__file__).resolve().parents[1]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

ACCOUNT = "111111111111"
REGION = "us-east-1"
PARTITION = "aws"
PROJECT = "acme"
ENVIRONMENT = "dev"
ENV = cdk.Environment(account=ACCOUNT, region=REGION)

# Names the caller chooses. They are not this runtime's name.
FOREIGN_IDENTITY = "other-team-workload"
MINTED_IDENTITY = "attacker-minted"

# Organizations attaches this managed SCP until an administrator replaces it.
# The user guide describes it as the policy that allows all services and actions.
FULL_AWS_ACCESS = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
}

PROVIDER_SPELLINGS = ("oauth2credentialprovider", "oauth2-credential-provider")

# Condition keys the caller of these APIs cannot choose. A missing value means
# the condition is not met. Every other key is a request field or tag the
# caller can set, so an Allow that only constrains one of those still applies.
CALLER_FIXED_CONDITION_PREFIXES = (
    "aws:principal",
    "aws:source",
    "aws:via",
    "aws:securetransport",
    "aws:requestedregion",
    "aws:currenttime",
    "aws:epoch",
    "aws:userid",
    "aws:username",
    "aws:multifactorauth",
    "aws:tokenissuetime",
)


def _as_list(value):
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _arn_from_getatt(logical_id: str, attribute: str, template: dict) -> str:
    """Concrete ARN for a same-stack GetAtt that the runtime policy already uses.

    ECR pull is scoped to the repository ARN via Fn::GetAtt. Identity resources
    that a fix introduces the same way have to resolve too, or a token would
    hide the resource the statement actually names.
    """
    resource = template["Resources"][logical_id]
    properties = resource.get("Properties", {})
    kind = resource["Type"]
    if kind == "AWS::ECR::Repository" and attribute == "Arn":
        name = properties.get("RepositoryName")
        if not isinstance(name, str):
            raise AssertionError(f"ECR repository name is not concrete: {name}")
        return f"arn:{PARTITION}:ecr:{REGION}:{ACCOUNT}:repository/{name}"
    if kind == "AWS::IAM::Role" and attribute == "Arn":
        name = properties.get("RoleName")
        if not isinstance(name, str):
            raise AssertionError(f"role name is not concrete: {name}")
        return f"arn:{PARTITION}:iam::{ACCOUNT}:role/{name}"
    raise AssertionError(
        f"unresolved policy Fn::GetAtt {logical_id}.{attribute} ({kind})"
    )


def resolve_cfn(node, template: dict | None = None):
    """Resolve the intrinsics CDK leaves in a policy document for a fixed env."""
    if isinstance(node, list):
        return [resolve_cfn(item, template) for item in node]
    if isinstance(node, dict):
        if set(node) == {"Ref"}:
            ref = node["Ref"]
            known = {
                "AWS::Partition": PARTITION,
                "AWS::AccountId": ACCOUNT,
                "AWS::Region": REGION,
            }
            if ref not in known:
                raise AssertionError(f"unresolved policy Ref {ref}")
            return known[ref]
        if set(node) == {"Fn::Join"}:
            delimiter, parts = node["Fn::Join"]
            return delimiter.join(resolve_cfn(part, template) for part in parts)
        if set(node) == {"Fn::GetAtt"}:
            logical_id, attribute = node["Fn::GetAtt"]
            if template is None:
                raise AssertionError(f"Fn::GetAtt {logical_id}.{attribute} without a template")
            return _arn_from_getatt(logical_id, attribute, template)
        if set(node) == {"Fn::Sub"}:
            body = node["Fn::Sub"]
            mapping = {}
            if isinstance(body, list):
                body, mapping = body
            mapping = resolve_cfn(mapping, template)

            def substitute(match):
                key = match.group(1)
                if key in mapping:
                    value = mapping[key]
                elif key in ("AWS::Partition", "AWS::AccountId", "AWS::Region"):
                    value = resolve_cfn({"Ref": key}, template)
                else:
                    raise AssertionError(f"unresolved Fn::Sub variable {key}")
                if not isinstance(value, str):
                    raise AssertionError(f"Fn::Sub variable {key} is not a string")
                return value

            return re.sub(r"\$\{([^}]+)\}", substitute, body)
        if any(key.startswith("Fn::") or key == "Ref" for key in node):
            raise AssertionError(f"unresolved policy intrinsic {sorted(node)}")
        return {key: resolve_cfn(value, template) for key, value in node.items()}
    return node


def _wildcard_to_regex(pattern: str) -> str:
    pieces = []
    for char in pattern:
        if char == "*":
            pieces.append(".*")
        elif char == "?":
            pieces.append(".")
        else:
            pieces.append(re.escape(char))
    return "".join(pieces)


def arn_matches(pattern: str, arn: str) -> bool:
    """Resource-element match, including a trailing ``*`` crossing colons."""
    if pattern == "*":
        return True
    pattern_segments = pattern.split(":")
    arn_segments = arn.split(":")

    def match_segments(remaining_pattern, remaining_arn) -> bool:
        if not remaining_pattern:
            return not remaining_arn
        segment = remaining_pattern[0]
        rest = remaining_pattern[1:]
        if segment.endswith("*"):
            prefix = segment[:-1]
            prefix_re = _wildcard_to_regex(prefix) + ".*"
            for take in range(1, len(remaining_arn) + 1):
                candidate = ":".join(remaining_arn[:take])
                if re.fullmatch(prefix_re, candidate) and match_segments(
                    rest, remaining_arn[take:]
                ):
                    return True
            return False
        if not remaining_arn:
            return False
        if re.fullmatch(_wildcard_to_regex(segment), remaining_arn[0]) is None:
            return False
        return match_segments(rest, remaining_arn[1:])

    return match_segments(pattern_segments, arn_segments)


def action_matches(pattern: str, action: str) -> bool:
    return re.fullmatch(_wildcard_to_regex(pattern.lower()), action.lower()) is not None


def _statement_selects_action(statement: dict, action: str) -> bool:
    actions = _as_list(statement.get("Action"))
    not_actions = _as_list(statement.get("NotAction"))
    if actions and not any(action_matches(pattern, action) for pattern in actions):
        return False
    if not_actions and any(action_matches(pattern, action) for pattern in not_actions):
        return False
    if not actions and not not_actions:
        return False
    return True


def _resource_patterns(statement: dict) -> list[str]:
    return [str(pattern) for pattern in _as_list(statement.get("Resource"))]


def _not_resource_patterns(statement: dict) -> list[str]:
    return [str(pattern) for pattern in _as_list(statement.get("NotResource"))]


def _statement_selects_resource(statement: dict, resource: str) -> bool:
    resources = _resource_patterns(statement)
    not_resources = _not_resource_patterns(statement)
    if not resources and not not_resources:
        return False
    if resources and not any(arn_matches(pattern, resource) for pattern in resources):
        return False
    if any(arn_matches(pattern, resource) for pattern in not_resources):
        return False
    return True


def _caller_can_choose(key: str) -> bool:
    lowered = key.lower()
    return not lowered.startswith(CALLER_FIXED_CONDITION_PREFIXES)


def _values_of(raw) -> list[str]:
    return [str(item) for item in _as_list(raw)]


def _like(pattern: str, value: str, *, ignore_case: bool) -> bool:
    flags = re.IGNORECASE if ignore_case else 0
    return re.fullmatch(_wildcard_to_regex(pattern), value, flags) is not None


def _operator_holds(operator: str, policy_values: list[str], request_value: str) -> bool:
    base = operator
    for suffix in ("IfExists",):
        if base.endswith(suffix):
            raise AssertionError(f"unsupported condition operator {operator}")
    comparisons = {
        "StringEquals": lambda pattern, value: pattern == value,
        "StringNotEquals": lambda pattern, value: pattern != value,
        "StringLike": lambda pattern, value: _like(pattern, value, ignore_case=False),
        "StringNotLike": lambda pattern, value: not _like(
            pattern, value, ignore_case=False
        ),
        "ArnEquals": lambda pattern, value: arn_matches(pattern, value),
        "ArnNotEquals": lambda pattern, value: not arn_matches(pattern, value),
        "ArnLike": lambda pattern, value: _like(pattern, value, ignore_case=True),
        "ArnNotLike": lambda pattern, value: not _like(pattern, value, ignore_case=True),
    }
    if base not in comparisons:
        raise AssertionError(f"unsupported condition operator {operator}")
    compare = comparisons[base]
    # A single-valued key matches when any policy value matches.
    return any(compare(pattern, request_value) for pattern in policy_values)


def condition_matches(condition: dict | None, context: dict[str, str]) -> bool:
    """True when the statement's condition is met for this caller.

    Missing caller-fixed keys are not met. Missing caller-chosen keys are met
    when the caller can supply a value that satisfies the operator, which is
    the case for the user id, the workload name, and request tags on these APIs.
    """
    if not condition:
        return True
    for operator, keys in condition.items():
        if operator.startswith(("ForAllValues:", "ForAnyValue:")):
            raise AssertionError(f"unsupported condition operator {operator}")
        if not isinstance(keys, dict):
            raise AssertionError(f"condition {operator} is not a key map")
        for key, raw in keys.items():
            policy_values = _values_of(raw)
            if key in context:
                if not _operator_holds(operator, policy_values, context[key]):
                    return False
                continue
            if not _caller_can_choose(key):
                return False
            if operator.startswith(("StringNot", "ArnNot")):
                # The caller can present a value outside a finite deny-list.
                if any(value in ("*", "") for value in policy_values):
                    return False
                continue
            if not policy_values:
                return False
    return True


def _statements(policy_documents: list[dict]) -> list[dict]:
    statements = []
    for document in policy_documents:
        statements.extend(document.get("Statement", []))
    return statements


def _matching(statements, effect: str, action: str, resource: str, context: dict):
    for statement in statements:
        if statement.get("Effect", "Allow") != effect:
            continue
        if not _statement_selects_action(statement, action):
            continue
        if not _statement_selects_resource(statement, resource):
            continue
        if not condition_matches(statement.get("Condition"), context):
            continue
        yield statement


def resource_allowed(statements, action: str, resource: str, context: dict) -> bool:
    if any(_matching(statements, "Deny", action, resource, context)):
        return False
    return any(_matching(statements, "Allow", action, resource, context))


def request_allowed(
    identity_documents: list[dict],
    action: str,
    resources: list[str],
    context: dict[str, str],
    scp_documents: list[dict] | None = None,
) -> bool:
    """Allow only when every required resource is allowed and none is denied.

    SCP documents, when given, are one organization node (FullAWSAccess plus
    the extra deny policies). They are unioned with each other and then
    intersected with the identity documents.
    """
    identity = _statements(identity_documents)
    for resource in resources:
        if not resource_allowed(identity, action, resource, context):
            return False
    if not scp_documents:
        return True
    scps = _statements(scp_documents)
    for resource in resources:
        if any(_matching(scps, "Deny", action, resource, context)):
            return False
        if not any(_matching(scps, "Allow", action, resource, context)):
            return False
    return True


def action_granted_anywhere(statements, action: str, context: dict) -> bool:
    """True when some satisfiable Allow for ``action`` is not covered by a Deny.

    A Deny whose resource is ``*``, or whose resource list equals the Allow,
    covers that Allow. A leftover exact ARN is still a grant.
    """
    for statement in statements:
        if statement.get("Effect", "Allow") != "Allow":
            continue
        if not _statement_selects_action(statement, action):
            continue
        if not condition_matches(statement.get("Condition"), context):
            continue
        patterns = _resource_patterns(statement) or ["*"]
        for pattern in patterns:
            covered = False
            for deny in statements:
                if deny.get("Effect") != "Deny":
                    continue
                if not _statement_selects_action(deny, action):
                    continue
                if not condition_matches(deny.get("Condition"), context):
                    continue
                if _not_resource_patterns(deny):
                    continue
                deny_patterns = _resource_patterns(deny)
                if "*" in deny_patterns or pattern in deny_patterns:
                    covered = True
                    break
            if not covered:
                return True
    return False


def directory_arn() -> str:
    return (
        f"arn:{PARTITION}:bedrock-agentcore:{REGION}:{ACCOUNT}:"
        "workload-identity-directory/default"
    )


def workload_identity_arn(name: str) -> str:
    return f"{directory_arn()}/workload-identity/{name}"


def token_vault_arn() -> str:
    return f"arn:{PARTITION}:bedrock-agentcore:{REGION}:{ACCOUNT}:token-vault/default"


def provider_arn(name: str, spelling: str) -> str:
    return f"{token_vault_arn()}/{spelling}/{name}"


def workload_token_resources(identity_name: str) -> list[str]:
    return [workload_identity_arn(identity_name), directory_arn()]


def oauth_token_resources(identity_name: str, provider_name: str, spelling: str) -> list[str]:
    return [
        provider_arn(provider_name, spelling),
        token_vault_arn(),
        workload_identity_arn(identity_name),
        directory_arn(),
    ]


def _runtime_template(component_name: str, provider_name: str | None) -> dict:
    app = cdk.App()
    extra = {}
    if provider_name is not None:
        extra["GATEWAY_CREDENTIAL_PROVIDER_NAME"] = provider_name
    RuntimeStack(
        app,
        f"runtime-{component_name}",
        project_name=PROJECT,
        environment=ENVIRONMENT,
        component_name=component_name,
        source_dir="agent-code",
        runtime_type="orchestrator" if component_name == "orchestrator" else "a2a_agent",
        dockerfile_pattern="" if component_name == "orchestrator" else component_name,
        extra_env_vars=extra,
        env=ENV,
    )
    return Template.from_stack(app.node.find_child(f"runtime-{component_name}")).to_json()


def _provider_names() -> dict[str, str]:
    app = cdk.App()
    stack = IdentityStack(
        app,
        "identity",
        project_name=PROJECT,
        environment=ENVIRONMENT,
        gateway_m2m_client_id="client-id",
        gateway_m2m_client_secret_name="secret-name",
        cognito_discovery_url="https://example.invalid/.well-known/openid-configuration",
        google_client_id="google-client",
        google_client_secret_name="google-secret-name",
        github_client_id="github-client",
        github_client_secret_name="github-secret-name",
        notion_client_id="notion-client",
        notion_client_secret_name="notion-secret-name",
        env=ENV,
    )
    template = Template.from_stack(stack).to_json()
    names = {}
    for resource in template["Resources"].values():
        if resource["Type"] != "AWS::BedrockAgentCore::OAuth2CredentialProvider":
            continue
        logical = resource["Properties"]["Name"]
        if not isinstance(logical, str):
            raise AssertionError(f"provider name is not concrete: {logical}")
        names[logical] = logical
    return {
        "gateway": stack.gateway_credential_provider_name,
        "others": sorted(
            name
            for name in names
            if name != stack.gateway_credential_provider_name
        ),
    }


def _runtime_role(template: dict) -> tuple[dict, dict, dict[str, str]]:
    runtime = next(
        resource
        for resource in template["Resources"].values()
        if resource["Type"] == "AWS::BedrockAgentCore::Runtime"
    )
    role_arn = runtime["Properties"]["RoleArn"]
    if not (isinstance(role_arn, dict) and "Fn::GetAtt" in role_arn):
        raise AssertionError(f"runtime RoleArn is not a role GetAtt: {role_arn}")
    logical_id, attribute = role_arn["Fn::GetAtt"]
    if attribute != "Arn":
        raise AssertionError(f"runtime RoleArn attribute is {attribute}")
    role = template["Resources"][logical_id]
    if role["Type"] != "AWS::IAM::Role":
        raise AssertionError(f"runtime role type is {role['Type']}")
    properties = role["Properties"]
    if properties.get("PermissionsBoundary") or properties.get("ManagedPolicyArns"):
        raise AssertionError(
            "runtime role has a boundary or managed policy this evaluator cannot read"
        )
    documents = []
    for inline in _as_list(properties.get("Policies")):
        documents.append(resolve_cfn(inline["PolicyDocument"], template))
    for resource in template["Resources"].values():
        if resource["Type"] != "AWS::IAM::Policy":
            continue
        attached = resource["Properties"].get("Roles", [])
        if {"Ref": logical_id} not in attached:
            continue
        documents.append(resolve_cfn(resource["Properties"]["PolicyDocument"], template))
    if not documents:
        raise AssertionError("runtime role has no policy document")
    role_name = properties.get("RoleName")
    if not isinstance(role_name, str):
        raise AssertionError(f"runtime role name is not concrete: {role_name}")
    context = {
        "aws:PrincipalArn": f"arn:{PARTITION}:iam::{ACCOUNT}:role/{role_name}",
    }
    merged = {"Version": "2012-10-17", "Statement": _statements(documents)}
    return runtime, merged, context


@pytest.fixture(scope="module")
def providers() -> dict[str, str]:
    return _provider_names()


def _configured_provider(template: dict) -> str | None:
    runtime = next(
        resource
        for resource in template["Resources"].values()
        if resource["Type"] == "AWS::BedrockAgentCore::Runtime"
    )
    env = runtime["Properties"].get("EnvironmentVariables", {})
    value = env.get("GATEWAY_CREDENTIAL_PROVIDER_NAME")
    if value is None:
        return None
    if not isinstance(value, str) or not value:
        raise AssertionError(f"gateway provider env is not a concrete name: {value}")
    return value


# ── Evaluator locks. These pass on a scoped policy and fail on "*". ──


def test_resource_wildcard_examples_from_the_iam_user_guide():
    bucket = "arn:aws:s3:::amzn-s3-demo-bucket/*/test/*"
    assert arn_matches(bucket, "arn:aws:s3:::amzn-s3-demo-bucket/1/2/test/object.jpg")
    assert arn_matches(bucket, "arn:aws:s3:::amzn-s3-demo-bucket/1///test///object.jpg")
    assert not arn_matches(bucket, "arn:aws:s3:::amzn-s3-demo-bucket/1-test/object.jpg")
    assert not arn_matches(bucket, "arn:aws:s3:::amzn-s3-demo-bucket/test/object.jpg")
    assert arn_matches("*", workload_identity_arn(FOREIGN_IDENTITY))


def test_parent_directory_prefix_matches_a_child_identity():
    """A trailing star on the shared directory authorizes every identity."""
    pattern = directory_arn() + "*"
    assert arn_matches(pattern, workload_identity_arn(FOREIGN_IDENTITY))
    assert arn_matches(token_vault_arn() + "*", provider_arn("google", "oauth2credentialprovider"))


def test_scoped_policy_allows_one_pair_and_denies_the_other():
    identity = "finance-agent"
    provider = "entra-graph"
    document = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "bedrock-agentcore:GetWorkloadAccessToken",
                    "bedrock-agentcore:GetWorkloadAccessTokenForJWT",
                ],
                "Resource": [directory_arn(), workload_identity_arn(identity)],
            },
            {
                "Effect": "Allow",
                "Action": "bedrock-agentcore:GetResourceOauth2Token",
                "Resource": [
                    directory_arn(),
                    workload_identity_arn(identity),
                    token_vault_arn(),
                    provider_arn(provider, "oauth2credentialprovider"),
                ],
            },
            {
                "Effect": "Deny",
                "Action": "bedrock-agentcore:GetWorkloadAccessTokenForUserId",
                "Resource": "*",
            },
        ],
    }
    context = {"aws:PrincipalArn": f"arn:aws:iam::{ACCOUNT}:role/finance-runtime-role"}
    assert request_allowed(
        [document],
        "bedrock-agentcore:GetWorkloadAccessToken",
        workload_token_resources(identity),
        context,
    )
    assert not request_allowed(
        [document],
        "bedrock-agentcore:GetWorkloadAccessToken",
        workload_token_resources(FOREIGN_IDENTITY),
        context,
    )
    assert request_allowed(
        [document],
        "bedrock-agentcore:GetResourceOauth2Token",
        oauth_token_resources(identity, provider, "oauth2credentialprovider"),
        context,
    )
    assert not request_allowed(
        [document],
        "bedrock-agentcore:GetResourceOauth2Token",
        oauth_token_resources(identity, "acme-dev-google-oauth", "oauth2credentialprovider"),
        context,
    )
    assert not request_allowed(
        [document],
        "bedrock-agentcore:GetResourceOauth2Token",
        oauth_token_resources(FOREIGN_IDENTITY, provider, "oauth2credentialprovider"),
        context,
    )
    # The provider ARN alone is one of four required resources. Allowing only
    # that ARN must not authorize the call.
    provider_only = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "bedrock-agentcore:GetResourceOauth2Token",
                "Resource": provider_arn(provider, "oauth2credentialprovider"),
            }
        ],
    }
    assert not request_allowed(
        [provider_only],
        "bedrock-agentcore:GetResourceOauth2Token",
        oauth_token_resources(identity, provider, "oauth2credentialprovider"),
        context,
    )
    # An allow of the identity in one statement and the provider in another
    # still authorizes the call: each required resource is checked on its own.
    split = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "bedrock-agentcore:GetResourceOauth2Token",
                "Resource": [directory_arn(), workload_identity_arn(identity)],
            },
            {
                "Effect": "Allow",
                "Action": "bedrock-agentcore:GetResourceOauth2Token",
                "Resource": [
                    token_vault_arn(),
                    provider_arn(provider, "oauth2credentialprovider"),
                ],
            },
        ],
    }
    assert request_allowed(
        [split],
        "bedrock-agentcore:GetResourceOauth2Token",
        oauth_token_resources(identity, provider, "oauth2credentialprovider"),
        context,
    )
    denied = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": "bedrock-agentcore:GetWorkloadAccessToken", "Resource": "*"},
            {"Effect": "Deny", "Action": "bedrock-agentcore:GetWorkloadAccessToken", "Resource": "*"},
        ],
    }
    assert not request_allowed(
        [denied],
        "bedrock-agentcore:GetWorkloadAccessToken",
        workload_token_resources(FOREIGN_IDENTITY),
        context,
    )
    assert not action_granted_anywhere(
        denied["Statement"], "bedrock-agentcore:GetWorkloadAccessToken", context
    )


def test_identity_scp_denies_only_the_userid_action_on_top_of_full_aws_access():
    scp = load_control("scp.identity.deny-workload-token-for-userid")
    context = {
        "aws:PrincipalArn": (
            f"arn:aws:iam::{ACCOUNT}:role/{PROJECT}-{ENVIRONMENT}-orchestrator-runtime-role"
        )
    }
    role = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "bedrock-agentcore:GetWorkloadAccessToken",
                    "bedrock-agentcore:GetWorkloadAccessTokenForJWT",
                    "bedrock-agentcore:GetWorkloadAccessTokenForUserId",
                    "bedrock-agentcore:GetResourceOauth2Token",
                    "bedrock-agentcore:CreateWorkloadIdentity",
                ],
                "Resource": "*",
            }
        ],
    }
    resources = workload_token_resources(FOREIGN_IDENTITY)
    assert not request_allowed(
        [role],
        "bedrock-agentcore:GetWorkloadAccessTokenForUserId",
        resources,
        context,
        scp_documents=[FULL_AWS_ACCESS, scp],
    )
    # The exemption pattern does not name this runtime role, so the deny matches.
    exempt = {
        "aws:PrincipalArn": (
            f"arn:aws:iam::{ACCOUNT}:role/__no_principal_may_mint_tokens_by_userid__"
        )
    }
    assert request_allowed(
        [role],
        "bedrock-agentcore:GetWorkloadAccessTokenForUserId",
        resources,
        exempt,
        scp_documents=[FULL_AWS_ACCESS, scp],
    )
    for action in (
        "bedrock-agentcore:GetWorkloadAccessToken",
        "bedrock-agentcore:GetWorkloadAccessTokenForJWT",
        "bedrock-agentcore:GetResourceOauth2Token",
        "bedrock-agentcore:CreateWorkloadIdentity",
    ):
        assert request_allowed(
            [role],
            action,
            resources
            if action != "bedrock-agentcore:GetResourceOauth2Token"
            else oauth_token_resources(
                FOREIGN_IDENTITY, "acme-dev-google-oauth", "oauth2credentialprovider"
            ),
            context,
            scp_documents=[FULL_AWS_ACCESS, scp],
        )


# ── The synthesized runtime role. These fail while Resource "*" remains. ──


COMPONENTS = (
    pytest.param("orchestrator", True, id="orchestrator"),
    pytest.param("code-agent", False, id="code-agent"),
    pytest.param("research-agent", True, id="research-agent"),
)


@pytest.mark.parametrize("component_name,uses_gateway", COMPONENTS)
def test_runtime_role_denies_tokens_for_another_workload_identity(
    component_name, uses_gateway, providers
):
    template = _runtime_template(
        component_name, providers["gateway"] if uses_gateway else None
    )
    _runtime, policy, context = _runtime_role(template)
    scp = load_control("scp.identity.deny-workload-token-for-userid")
    for action in (
        "bedrock-agentcore:GetWorkloadAccessToken",
        "bedrock-agentcore:GetWorkloadAccessTokenForJWT",
    ):
        resources = workload_token_resources(FOREIGN_IDENTITY)
        assert not request_allowed([policy], action, resources, context), action
        assert not request_allowed(
            [policy],
            action,
            resources,
            context,
            scp_documents=[FULL_AWS_ACCESS, scp],
        ), f"{action} stays allowed under the identity SCP"


@pytest.mark.parametrize("component_name,uses_gateway", COMPONENTS)
def test_runtime_role_does_not_grant_create_or_userid_token(
    component_name, uses_gateway, providers
):
    template = _runtime_template(
        component_name, providers["gateway"] if uses_gateway else None
    )
    _runtime, policy, context = _runtime_role(template)
    statements = policy["Statement"]
    assert not action_granted_anywhere(
        statements, "bedrock-agentcore:CreateWorkloadIdentity", context
    )
    assert not request_allowed(
        [policy],
        "bedrock-agentcore:CreateWorkloadIdentity",
        workload_token_resources(MINTED_IDENTITY),
        context,
    )
    assert not action_granted_anywhere(
        statements, "bedrock-agentcore:GetWorkloadAccessTokenForUserId", context
    )
    assert not request_allowed(
        [policy],
        "bedrock-agentcore:GetWorkloadAccessTokenForUserId",
        workload_token_resources(FOREIGN_IDENTITY),
        context,
    )


@pytest.mark.parametrize("component_name,uses_gateway", COMPONENTS)
def test_runtime_role_denies_oauth_tokens_for_other_providers(
    component_name, uses_gateway, providers
):
    template = _runtime_template(
        component_name, providers["gateway"] if uses_gateway else None
    )
    _runtime, policy, context = _runtime_role(template)
    configured = _configured_provider(template)
    if uses_gateway:
        assert configured == providers["gateway"]
    else:
        assert configured is None

    forbidden = list(providers["others"])
    if configured is None:
        forbidden.append(providers["gateway"])
    # The configured gateway provider is still forbidden for a different identity.
    identities = [FOREIGN_IDENTITY, MINTED_IDENTITY]
    for provider_name in forbidden:
        for spelling in PROVIDER_SPELLINGS:
            for identity_name in identities:
                assert not request_allowed(
                    [policy],
                    "bedrock-agentcore:GetResourceOauth2Token",
                    oauth_token_resources(identity_name, provider_name, spelling),
                    context,
                ), f"{component_name} can read {provider_name} as {identity_name} ({spelling})"
    if configured is not None:
        for spelling in PROVIDER_SPELLINGS:
            assert not request_allowed(
                [policy],
                "bedrock-agentcore:GetResourceOauth2Token",
                oauth_token_resources(FOREIGN_IDENTITY, configured, spelling),
                context,
            )


@pytest.mark.parametrize("component_name,uses_gateway", COMPONENTS)
def test_runtime_role_denies_other_providers_client_secrets(
    component_name, uses_gateway, providers
):
    """GetSecretValue on the token-vault prefix reads every provider's secret.

    The runtime comment says GetResourceOauth2Token reads that secret with the
    caller's identity. A wildcard under oauth2/ authorizes a secret whose name
    is another provider.
    """
    template = _runtime_template(
        component_name, providers["gateway"] if uses_gateway else None
    )
    _runtime, policy, context = _runtime_role(template)
    for provider_name in providers["others"]:
        secret = (
            f"arn:{PARTITION}:secretsmanager:{REGION}:{ACCOUNT}:secret:"
            f"bedrock-agentcore-identity!default/oauth2/{provider_name}-AbCd12"
        )
        assert not request_allowed(
            [policy], "secretsmanager:GetSecretValue", [secret], context
        ), secret


def test_migration_child_receives_the_runtime_environment(monkeypatch):
    """The customer process is started with the runtime's environment intact."""
    runtime = types.ModuleType("bedrock_agentcore.runtime")

    class BedrockAgentCoreApp:
        def entrypoint(self, fn):
            return fn

        def run(self):
            raise AssertionError("the test must not start the server")

    runtime.BedrockAgentCoreApp = BedrockAgentCoreApp
    package = types.ModuleType("bedrock_agentcore")
    package.runtime = runtime
    monkeypatch.setitem(sys.modules, "bedrock_agentcore", package)
    monkeypatch.setitem(sys.modules, "bedrock_agentcore.runtime", runtime)

    sys.path.insert(0, str(REPO / "migration" / "adapter"))
    try:
        import adapter
    finally:
        sys.path.pop(0)

    parent = {
        "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI": "placeholder-not-a-credential",
        "AWS_REGION": REGION,
        "PROJECT_NAME": PROJECT,
        "ENVIRONMENT": ENVIRONMENT,
    }
    child = adapter.build_child_env(parent, {})
    assert child["AWS_CONTAINER_CREDENTIALS_RELATIVE_URI"] == parent[
        "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI"
    ]
    assert child["AWS_REGION"] == REGION
