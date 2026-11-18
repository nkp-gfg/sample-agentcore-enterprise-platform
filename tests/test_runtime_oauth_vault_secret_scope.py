"""Every runtime role may read only the gateway OAuth client secret.

AgentCore Identity stores each OAuth credential provider's client secret in
Secrets Manager under

    bedrock-agentcore-identity!default/oauth2/<provider-name>

and appends a hyphen plus six characters to that name in the secret ARN
(botocore's GetSecretValue example returns
``secret:MyTestDatabaseSecret-a1b2c3`` for a secret named
``MyTestDatabaseSecret``). The AgentCore identity getting-started policy
grants ``secretsmanager:GetSecretValue`` on

    arn:aws:secretsmanager:<region>:<account>:secret:bedrock-agentcore-identity!default/oauth2/<provider-name>*

so the execution role can read that client secret. ``GetSecretValue``
returns the stored ``SecretString``.

This platform creates the gateway provider and, when configured, Google,
GitHub, and Notion providers in the same default vault. The runtime
execution role is what code inside the runtime microVM uses. It may read
the gateway provider's secret. It must not read any other provider's
secret in that vault.

These tests fail while the role's resource is ``oauth2/*``.
"""

from __future__ import annotations

import importlib.util
import os
import re
from pathlib import Path

import aws_cdk as cdk
import pytest

from stacks.auth_stack import AuthStack
from stacks.identity_stack import IdentityStack
from stacks.runtime_stack import RuntimeStack

_ADAPTER_PATH = Path(__file__).resolve().parents[1] / "migration" / "adapter" / "adapter.py"
_adapter_spec = importlib.util.spec_from_file_location("migration_adapter", _ADAPTER_PATH)
assert _adapter_spec is not None and _adapter_spec.loader is not None
_adapter = importlib.util.module_from_spec(_adapter_spec)
_adapter_spec.loader.exec_module(_adapter)
Child = _adapter.Child
build_child_env = _adapter.build_child_env

ACCOUNT = "111111111111"
REGION = "us-east-1"
PROJECT = "vaulttest"
ENVIRONMENT = "dev"
ENV = cdk.Environment(account=ACCOUNT, region=REGION)
PREFIX = f"{PROJECT}-{ENVIRONMENT}"
# Shape from botocore data/secretsmanager/2017-10-17/examples-1.json
# GetSecretValue output ARN: secret:MyTestDatabaseSecret-a1b2c3
SECRET_SUFFIXES = ("a1b2c3", "Zz09Xx")
VAULT_SECRET_NAME_PREFIX = "bedrock-agentcore-identity!default/oauth2/"
# A provider this repo does not create. It still lives in the account's
# default vault, so a resource of oauth2/* covers it.
FOREIGN_PROVIDER = "another-workload-provider"


def _templates():
    app = cdk.App()
    auth = AuthStack(
        app,
        "auth",
        project_name=PROJECT,
        environment=ENVIRONMENT,
        env=ENV,
    )
    identity = IdentityStack(
        app,
        "identity",
        project_name=PROJECT,
        environment=ENVIRONMENT,
        gateway_m2m_client_id=auth.m2m_client_id,
        gateway_m2m_client_secret_name=auth.m2m_client_secret_name,
        cognito_discovery_url=auth.discovery_url,
        google_client_id="google-client-id",
        google_client_secret_name=f"{PREFIX}-google-oauth-secret",
        github_client_id="github-client-id",
        github_client_secret_name=f"{PREFIX}-github-oauth-secret",
        notion_client_id="notion-client-id",
        notion_client_secret_name=f"{PREFIX}-notion-oauth-secret",
        env=ENV,
    )
    identity.add_dependency(auth)

    runtimes = {}
    common = dict(
        project_name=PROJECT,
        environment=ENVIRONMENT,
        source_dir="agent-code",
        env=ENV,
    )
    runtimes["orchestrator"] = RuntimeStack(
        app,
        "runtime-orchestrator",
        component_name="orchestrator",
        runtime_type="orchestrator",
        extra_env_vars={
            "GATEWAY_CREDENTIAL_PROVIDER_NAME": identity.gateway_credential_provider_name,
        },
        **common,
    )
    runtimes["research-agent"] = RuntimeStack(
        app,
        "runtime-research",
        component_name="research-agent",
        runtime_type="a2a_agent",
        dockerfile_pattern="research-agent",
        extra_env_vars={
            "GATEWAY_CREDENTIAL_PROVIDER_NAME": identity.gateway_credential_provider_name,
        },
        **common,
    )
    runtimes["code-agent"] = RuntimeStack(
        app,
        "runtime-code",
        component_name="code-agent",
        runtime_type="a2a_agent",
        dockerfile_pattern="code-agent",
        **common,
    )
    runtimes["migration"] = RuntimeStack(
        app,
        "runtime-migration",
        component_name="migrated-agent",
        runtime_type="orchestrator",
        build_context="migration/simulation/existing-ec2-agent",
        build_dockerfile="Dockerfile",
        adapter_dir="migration/adapter",
        migration_secret_names=["API_TOKEN"],
        extra_env_vars={
            "GATEWAY_CREDENTIAL_PROVIDER_NAME": identity.gateway_credential_provider_name,
        },
        **common,
    )
    for stack in runtimes.values():
        stack.add_dependency(identity)

    assembly = app.synth()
    return {
        "auth": assembly.get_stack_by_name("auth").template,
        "identity": assembly.get_stack_by_name("identity").template,
        "runtimes": {
            name: assembly.get_stack_by_name(stack.node.id).template
            for name, stack in runtimes.items()
        },
    }


@pytest.fixture(scope="module")
def templates():
    return _templates()


def _as_list(value):
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _resolve_cfn(value):
    """Resolve the intrinsics this stack uses in IAM resource ARNs.

    ``AWS::Partition`` is ``aws`` for the commercial region this app synths.
    Anything else stays unresolved so a match cannot succeed by skipping it.
    """
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        return [_resolve_cfn(item) for item in value]
    if isinstance(value, dict) and set(value) == {"Ref"}:
        refs = {
            "AWS::Partition": "aws",
            "AWS::Region": REGION,
            "AWS::AccountId": ACCOUNT,
        }
        if value["Ref"] not in refs:
            return None
        return refs[value["Ref"]]
    if isinstance(value, dict) and set(value) == {"Fn::Join"}:
        separator, parts = value["Fn::Join"]
        resolved = [_resolve_cfn(part) for part in parts]
        if any(part is None for part in resolved):
            return None
        return separator.join(resolved)
    if isinstance(value, dict) and set(value) == {"Fn::Sub"}:
        template = value["Fn::Sub"]
        if not isinstance(template, str):
            return None
        replacements = {
            "${AWS::Partition}": "aws",
            "${AWS::Region}": REGION,
            "${AWS::AccountId}": ACCOUNT,
        }
        for token, concrete in replacements.items():
            template = template.replace(token, concrete)
        if "${" in template:
            return None
        return template
    return None


def _strings(value):
    """Yield concrete strings from a CloudFormation resource list."""
    resolved = _resolve_cfn(value)
    if resolved is None:
        yield None
        return
    if isinstance(resolved, list):
        for item in resolved:
            if isinstance(item, str):
                yield item
            else:
                yield None
        return
    if isinstance(resolved, str):
        yield resolved
        return
    yield None


def iam_resource_matches(pattern: str, arn: str) -> bool:
    """IAM Resource wildcard match.

    ``*`` is any combination of characters and ``?`` is one character.
    A ``*`` matches across ``:`` only when it is the last character of its
    colon-separated ARN segment. Other wildcards stay inside the segment,
    and ``*`` still matches ``/`` inside a segment.
    """
    return _segments_match(pattern.split(":"), arn.split(":"))


def _segment_regex(pattern: str, *, final_star_crosses_colons: bool) -> str:
    parts: list[str] = []
    for index, char in enumerate(pattern):
        last = index == len(pattern) - 1
        if char == "*":
            if last and final_star_crosses_colons:
                parts.append(".*")
            else:
                parts.append("[^:]*")
        elif char == "?":
            parts.append("[^:]")
        else:
            parts.append(re.escape(char))
    return "".join(parts)


def _segments_match(pattern_segments: list[str], arn_segments: list[str]) -> bool:
    if not pattern_segments:
        return not arn_segments
    head, *rest = pattern_segments
    crosses = head.endswith("*")
    if crosses and not rest:
        text = ":".join(arn_segments)
        return re.fullmatch(_segment_regex(head, final_star_crosses_colons=True), text) is not None
    if not arn_segments:
        return False
    within = _segment_regex(head, final_star_crosses_colons=False)
    if re.fullmatch(within, arn_segments[0]) and _segments_match(rest, arn_segments[1:]):
        return True
    if not crosses:
        return False
    # A trailing star may consume additional colon-separated segments.
    for take in range(2, len(arn_segments) + 1):
        joined = ":".join(arn_segments[:take])
        if re.fullmatch(
            _segment_regex(head, final_star_crosses_colons=True), joined
        ) and _segments_match(rest, arn_segments[take:]):
            return True
    return False


def _action_matches(pattern: str, action: str) -> bool:
    regex = "".join(".*" if char == "*" else re.escape(char) for char in pattern)
    return re.fullmatch(regex, action, flags=re.IGNORECASE) is not None


def _statement_selects_action(statement: dict, action: str) -> bool:
    if "NotAction" in statement:
        return not any(
            _action_matches(pattern, action) for pattern in _as_list(statement["NotAction"])
        )
    return any(_action_matches(pattern, action) for pattern in _as_list(statement.get("Action")))


def _statement_selects_resource(statement: dict, arn: str) -> bool:
    if "Resource" in statement and "NotResource" in statement:
        raise AssertionError(f"statement has both Resource and NotResource: {statement}")
    if "NotResource" in statement:
        patterns = list(_strings(statement["NotResource"]))
        if any(pattern is None for pattern in patterns):
            raise AssertionError(f"unresolved NotResource: {statement['NotResource']}")
        return not any(iam_resource_matches(pattern, arn) for pattern in patterns)
    patterns = list(_strings(statement.get("Resource")))
    if any(pattern is None for pattern in patterns):
        raise AssertionError(f"unresolved Resource: {statement.get('Resource')}")
    return any(iam_resource_matches(pattern, arn) for pattern in patterns)


def _condition_matches_direct_call(condition: dict | None) -> bool:
    """True when a direct GetSecretValue, with no service-via keys, satisfies it.

    A direct call does not carry ``aws:CalledVia`` or ``aws:ViaAWSService``.
    Missing keys do not satisfy String/Arn equality or pattern operators.
    ``Null`` is evaluated against that absence. An operator this helper does
    not know fails the test instead of being treated as a match.
    """
    if not condition:
        return True
    context = {
        "aws:RequestedRegion": REGION,
        "aws:PrincipalAccount": ACCOUNT,
    }
    for operator, comparisons in condition.items():
        if not _operator_matches(operator, comparisons, context):
            return False
    return True


def _operator_matches(operator: str, comparisons: dict, context: dict) -> bool:
    base = operator
    if_exists = base.endswith("IfExists")
    if if_exists:
        base = base[: -len("IfExists")]
    quantifier = None
    for prefix in ("ForAllValues:", "ForAnyValue:"):
        if base.startswith(prefix):
            quantifier = prefix[:-1]
            base = base[len(prefix) :]
            break
    if base not in {
        "StringEquals",
        "StringNotEquals",
        "StringLike",
        "StringNotLike",
        "ArnEquals",
        "ArnNotEquals",
        "ArnLike",
        "ArnNotLike",
        "Null",
        "Bool",
    }:
        raise AssertionError(f"unsupported IAM condition operator {operator}")
    for key, expected in comparisons.items():
        present = key in context
        if not present and if_exists and base != "Null":
            continue
        actual = context.get(key)
        expected_values = [str(item) for item in _as_list(expected)]
        if base == "Null":
            wants_missing = expected_values[0].lower() == "true"
            if (actual is None) != wants_missing:
                return False
            continue
        if actual is None:
            return False
        actual_values = [actual]
        matched = [
            _value_matches(base, candidate, expected_value)
            for candidate in actual_values
            for expected_value in expected_values
        ]
        if quantifier == "ForAllValues":
            ok = all(
                any(_value_matches(base, candidate, expected_value) for expected_value in expected_values)
                for candidate in actual_values
            )
        elif quantifier == "ForAnyValue":
            ok = any(matched)
        else:
            ok = any(matched)
        if not ok:
            return False
    return True


def _value_matches(operator: str, actual: str, expected: str) -> bool:
    if operator in {"StringLike", "ArnLike"}:
        regex = "".join(".*" if char == "*" else "." if char == "?" else re.escape(char) for char in expected)
        return re.fullmatch(regex, actual) is not None
    if operator in {"StringNotLike", "ArnNotLike"}:
        regex = "".join(".*" if char == "*" else "." if char == "?" else re.escape(char) for char in expected)
        return re.fullmatch(regex, actual) is None
    if operator in {"StringNotEquals", "ArnNotEquals"}:
        return actual != expected
    if operator == "Bool":
        return actual.lower() == expected.lower()
    return actual == expected


def _statements(policy_document: dict) -> list[dict]:
    return list(policy_document.get("Statement", []))


def _role_policy_documents(template: dict, role_logical_id: str) -> list[dict]:
    documents = []
    role = template["Resources"][role_logical_id]
    for inline in role["Properties"].get("Policies", []) or []:
        documents.append(inline["PolicyDocument"])
    for resource in template["Resources"].values():
        if resource.get("Type") != "AWS::IAM::Policy":
            continue
        attached = resource["Properties"].get("Roles", [])
        if any(_refers_to(item, role_logical_id) for item in attached):
            documents.append(resource["Properties"]["PolicyDocument"])
    if not documents:
        raise AssertionError(f"no policies attached to {role_logical_id}")
    return documents


def _refers_to(value, logical_id: str) -> bool:
    if isinstance(value, str):
        return value == logical_id
    if isinstance(value, dict):
        if value.get("Ref") == logical_id:
            return True
        get_att = value.get("Fn::GetAtt")
        if isinstance(get_att, list) and get_att and get_att[0] == logical_id:
            return True
        if isinstance(get_att, str) and get_att.split(".")[0] == logical_id:
            return True
    return False


def _runtime_binding(template: dict) -> tuple[str, dict]:
    runtime = next(
        resource
        for resource in template["Resources"].values()
        if resource["Type"] == "AWS::BedrockAgentCore::Runtime"
    )
    role_arn = runtime["Properties"]["RoleArn"]
    get_att = role_arn.get("Fn::GetAtt") if isinstance(role_arn, dict) else None
    if not isinstance(get_att, list) or len(get_att) < 2 or get_att[1] != "Arn":
        raise AssertionError(f"runtime RoleArn is not the execution role ARN: {role_arn}")
    return get_att[0], runtime["Properties"]


def direct_get_secret_value_allowed(template: dict, role_logical_id: str, secret_arn: str) -> bool:
    """Identity-policy decision for a direct secretsmanager:GetSecretValue.

    Explicit deny wins. An allow counts only when its resource matches the
    secret ARN and its conditions match a direct call.
    """
    action = "secretsmanager:GetSecretValue"
    statements = [
        statement
        for document in _role_policy_documents(template, role_logical_id)
        for statement in _statements(document)
    ]
    for statement in statements:
        effect = statement.get("Effect", "Allow")
        if effect != "Deny":
            continue
        if _statement_selects_action(statement, action) and _statement_selects_resource(
            statement, secret_arn
        ) and _condition_matches_direct_call(statement.get("Condition")):
            return False
    for statement in statements:
        if statement.get("Effect", "Allow") != "Allow":
            continue
        if _statement_selects_action(statement, action) and _statement_selects_resource(
            statement, secret_arn
        ) and _condition_matches_direct_call(statement.get("Condition")):
            return True
    return False


def direct_ssm_get_parameter_allowed(template: dict, role_logical_id: str, parameter_arn: str) -> bool:
    action = "ssm:GetParameter"
    statements = [
        statement
        for document in _role_policy_documents(template, role_logical_id)
        for statement in _statements(document)
    ]
    for statement in statements:
        if statement.get("Effect", "Allow") != "Allow":
            continue
        if _statement_selects_action(statement, action) and _statement_selects_resource(
            statement, parameter_arn
        ) and _condition_matches_direct_call(statement.get("Condition")):
            return True
    return False


def vault_secret_arn(provider_name: str, suffix: str) -> str:
    return (
        f"arn:aws:secretsmanager:{REGION}:{ACCOUNT}:secret:"
        f"{VAULT_SECRET_NAME_PREFIX}{provider_name}-{suffix}"
    )


def ssm_parameter_arn(parameter_name: str) -> str:
    return f"arn:aws:ssm:{REGION}:{ACCOUNT}:parameter{parameter_name}"


def _provider_names(identity_template: dict) -> dict[str, str]:
    names = {}
    for logical_id, resource in identity_template["Resources"].items():
        if resource["Type"] != "AWS::BedrockAgentCore::OAuth2CredentialProvider":
            continue
        name = resource["Properties"]["Name"]
        if not isinstance(name, str):
            raise AssertionError(f"{logical_id} provider name is not concrete: {name}")
        names[logical_id] = name
    return names


def _ssm_parameter_names(template: dict) -> set[str]:
    return {
        resource["Properties"]["Name"]
        for resource in template["Resources"].values()
        if resource["Type"] == "AWS::SSM::Parameter"
        and isinstance(resource["Properties"].get("Name"), str)
    }


def test_iam_resource_wildcards_follow_the_documented_segment_rules():
    """Examples from IAM JSON policy elements: Resource.

    ``*`` matches ``/`` and the empty string inside a segment. It does not
    match across the characters the examples say are unmatched.
    """
    pattern = "arn:aws:s3:::amzn-s3-demo-bucket/*/test/*"
    matches = [
        "arn:aws:s3:::amzn-s3-demo-bucket/1/test/object.jpg",
        "arn:aws:s3:::amzn-s3-demo-bucket/1/2/test/object.jpg",
        "arn:aws:s3:::amzn-s3-demo-bucket/1/2/test/3/object.jpg",
        "arn:aws:s3:::amzn-s3-demo-bucket/1/2/3/test/4/object.jpg",
        "arn:aws:s3:::amzn-s3-demo-bucket/1///test///object.jpg",
        "arn:aws:s3:::amzn-s3-demo-bucket/1/test/.jpg",
        "arn:aws:s3:::amzn-s3-demo-bucket//test/object.jpg",
        "arn:aws:s3:::amzn-s3-demo-bucket/1/test/",
    ]
    misses = [
        "arn:aws:s3:::amzn-s3-demo-bucket/1-test/object.jpg",
        "arn:aws:s3:::amzn-s3-demo-bucket/test/object.jpg",
        "arn:aws:s3:::amzn-s3-demo-bucket/1/2/test.jpg",
    ]
    for arn in matches:
        assert iam_resource_matches(pattern, arn), arn
    for arn in misses:
        assert not iam_resource_matches(pattern, arn), arn
    assert iam_resource_matches("*", vault_secret_arn("any-provider", "a1b2c3"))
    assert not iam_resource_matches(
        "arn:aws:secretsmanager:us-east-1:111111111111:secret:other/*",
        vault_secret_arn("gateway", "a1b2c3"),
    )


def test_runtime_roles_cannot_read_other_vault_client_secrets(templates):
    """Direct GetSecretValue on a non-gateway provider secret is allowed.

    The identity stack's provider names are the path component AgentCore
    uses for that provider's client secret. The role attached to each
    runtime is the execution role code in that runtime uses.
    """
    identity = templates["identity"]
    auth = templates["auth"]
    provider_names = _provider_names(identity)
    gateway_name = provider_names["GatewayM2M"]
    other_names = sorted(name for logical_id, name in provider_names.items() if logical_id != "GatewayM2M")
    assert other_names == [
        f"{PREFIX}-github-oauth",
        f"{PREFIX}-google-oauth",
        f"{PREFIX}-notion-oauth",
    ], other_names
    assert gateway_name == f"{PREFIX}-gateway-m2m"

    auth_parameters = _ssm_parameter_names(auth)
    identity_parameters = _ssm_parameter_names(identity)
    client_id_parameter = f"/{PROJECT}/{ENVIRONMENT}/auth/m2m-client-id"
    provider_parameter = f"/{PROJECT}/{ENVIRONMENT}/identity/gateway-credential-provider-name"
    assert client_id_parameter in auth_parameters
    assert provider_parameter in identity_parameters

    # The M2M client whose id is published is the client_credentials client
    # for the agentcore/invoke scope. Its client id is what a caller pairs
    # with the vault client secret.
    m2m_clients = [
        resource["Properties"]
        for resource in auth["Resources"].values()
        if resource["Type"] == "AWS::Cognito::UserPoolClient"
        and resource["Properties"].get("ClientName") == f"{PREFIX}-m2m-client-v2"
    ]
    assert len(m2m_clients) == 1
    flows = m2m_clients[0]["AllowedOAuthFlows"]
    assert flows == ["client_credentials"]
    assert "agentcore/invoke" in str(m2m_clients[0]["AllowedOAuthScopes"])

    readable_foreign = []
    missing_gateway = []
    unreadable_parameters = []
    for runtime_name, template in templates["runtimes"].items():
        role_logical_id, runtime_properties = _runtime_binding(template)
        role = template["Resources"][role_logical_id]
        assume = role["Properties"]["AssumeRolePolicyDocument"]
        services = [
            statement["Principal"]["Service"]
            for statement in assume["Statement"]
            if statement.get("Effect") == "Allow" and "Service" in statement.get("Principal", {})
        ]
        assert services == ["bedrock-agentcore.amazonaws.com"], (runtime_name, services)
        assert role["Properties"]["RoleName"] == f"{PREFIX}-{runtime_name if runtime_name != 'migration' else 'migrated-agent'}-runtime-role"

        env = runtime_properties["EnvironmentVariables"]
        if runtime_name != "code-agent":
            assert env["GATEWAY_CREDENTIAL_PROVIDER_NAME"] == gateway_name

        for suffix in SECRET_SUFFIXES:
            gateway_arn = vault_secret_arn(gateway_name, suffix)
            if not direct_get_secret_value_allowed(template, role_logical_id, gateway_arn):
                missing_gateway.append(f"{runtime_name} {gateway_arn}")
            for provider_name in [*other_names, FOREIGN_PROVIDER]:
                secret_arn = vault_secret_arn(provider_name, suffix)
                if direct_get_secret_value_allowed(template, role_logical_id, secret_arn):
                    readable_foreign.append(f"{runtime_name} {provider_name} suffix={suffix}")

        for parameter_name in (client_id_parameter, provider_parameter):
            if not direct_ssm_get_parameter_allowed(
                template, role_logical_id, ssm_parameter_arn(parameter_name)
            ):
                unreadable_parameters.append(f"{runtime_name} {parameter_name}")

    assert not missing_gateway, (
        "the gateway provider secret must stay readable by the runtime role: "
        f"{missing_gateway}"
    )
    assert not unreadable_parameters, (
        "the runtime role must still be able to read the published client id "
        f"and gateway provider name: {unreadable_parameters}"
    )
    assert not readable_foreign, (
        "runtime execution roles can secretsmanager:GetSecretValue the client "
        f"secret of providers other than {gateway_name}: {readable_foreign}"
    )


def test_migration_child_process_receives_the_runtime_environment():
    """The migrated customer process is started with the runtime environment.

    Credential material is not used here. The placeholder values prove the
    adapter copies the runtime environment, including the variables a
    container credential provider puts there, into the child process.
    """
    parent = {
        "PATH": os.environ.get("PATH", "/usr/bin"),
        "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI": "placeholder-relative-uri",
        "AWS_ACCESS_KEY_ID": "placeholder-access-key-id",
        "AWS_SECRET_ACCESS_KEY": "placeholder-secret-access-key",
        "AWS_SESSION_TOKEN": "placeholder-session-token",
        "PROJECT_NAME": PROJECT,
        "ENVIRONMENT": ENVIRONMENT,
    }
    child_env = build_child_env(parent, {})
    for key, value in parent.items():
        assert child_env[key] == value

    destination = Path("/tmp/runtime-vault-child-env.txt")
    if destination.exists():
        destination.unlink()
    child = Child(
        [
            "/bin/sh",
            "-c",
            'printf %s "$AWS_CONTAINER_CREDENTIALS_RELATIVE_URI" > /tmp/runtime-vault-child-env.txt',
        ],
        child_env,
    )
    # Child.start is the path main() uses: Popen(..., env=self.env).
    child.start()
    assert child.proc is not None
    assert child.proc.wait(timeout=10) == 0
    assert destination.read_text() == "placeholder-relative-uri"
