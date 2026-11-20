"""Brokered Cognito hosted-domain prefix must not be precomputable.

An outsider who knows the project name, the environment name, the account id,
and the region can create a user pool in their own account and call
CreateUserPoolDomain first. Prefix domains are a single (region, prefix) name:
DescribeUserPoolDomain takes only Domain and returns one AWSAccountId
(botocore 1.43.72, cognito-idp 2016-04-18). CloudFormation then submits that
same prefix as AWS::Cognito::UserPoolDomain.Domain (aws-cdk-lib 2.265.0 copies
CognitoDomainOptions.domainPrefix onto that property). CreateStack's default
OnFailure is ROLLBACK, so a failed domain rolls the auth stack back. The CDK
CLI work graph skips every stack that was still waiting (aws-cdk 2.1135.1,
WorkGraph.skipRest) and cli() sets process.exitCode = 1, which scripts/deploy.sh
treats as a failed deploy.

These tests fail while the prefix is still that public formula. Direct mode is
not covered: AuthStack returns before it creates a domain. dashboard/monitor.py
only echoes the DomainUrl output and does not derive a prefix.
"""

from __future__ import annotations

import hashlib
import importlib
import io
import json
import re
import sys
from pathlib import Path
from typing import Any

import aws_cdk as cdk
import pytest
from aws_cdk.assertions import Template
from botocore.exceptions import ClientError

from infra_utils.platform_config import PlatformConfig, design_plan
from stacks.auth_stack import AuthStack

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "scripts"))

import utils  # noqa: E402

VICTIM_ACCOUNT = "111111111111"
ATTACKER_ACCOUNT = "999999999999"
REGION = "us-east-1"
# Published hostname, no scheme and no path. Machine login and the design
# read-back must use this parameter instead of rebuilding the public prefix.
HOSTED_DOMAIN_SUFFIX = "auth/hosted-domain"
PREFIX_PATTERN = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
# Amazon Cognito rejects these substrings in a prefix domain.
RESERVED_PREFIX_WORDS = ("aws", "amazon", "cognito")
PRODUCT_SOURCES = (
    REPO / "stacks" / "auth_stack.py",
    REPO / "scripts" / "utils.py",
    REPO / "infra_utils" / "platform_config.py",
    REPO / "app.py",
)

# Placeholder returned by the fake token endpoint. Not a credential.
STUB_TOKEN = "stub-token-from-fake-urlopen"
STUB_SECRET = "stub-secret-from-fake-secrets-manager"
STUB_SECRET_NAME = "agentcore/test/m2m"


class DomainAlreadyAssociated(Exception):
    """CreateUserPoolDomain InvalidParameterException for a taken prefix.

    The API lists InvalidParameterException. The Cognito troubleshooting guide
    documents the message "Domain already associated with another user pool"
    when that name already has an owner. DescribeUserPoolDomain can return only
    one owner for a prefix, so a second account's create cannot succeed.
    """


class PrefixRegistry:
    """Region-scoped prefix namespace from DescribeUserPoolDomain.

    The request has a Domain member and no account or user-pool member. The
    response DomainDescription carries one AWSAccountId and one UserPoolId.
    """

    def __init__(self) -> None:
        self.owners: dict[tuple[str, str], tuple[str, str]] = {}

    def create(
        self, *, account: str, region: str, domain: str, user_pool_id: str
    ) -> None:
        if not PREFIX_PATTERN.fullmatch(domain):
            raise DomainAlreadyAssociated(
                f"prefix {domain!r} is not a CreateUserPoolDomain prefix"
            )
        if any(word in domain for word in RESERVED_PREFIX_WORDS):
            raise DomainAlreadyAssociated(
                f"prefix {domain!r} uses a reserved Cognito word"
            )
        key = (region, domain)
        current = self.owners.get(key)
        if current is not None and current != (account, user_pool_id):
            raise DomainAlreadyAssociated(
                "Domain already associated with another user pool."
            )
        self.owners[key] = (account, user_pool_id)


def _make_unique_id(components: list[str]) -> str:
    """aws-cdk-lib 2.265.0 Names.uniqueId / makeUniqueId, lowercased for Cognito.

    The hash is md5 of the path joined by '/', first 8 hex chars, uppercased
    in CDK. Cognito prefixes are lowercase, so a 'fix' that lowercases this id
    is still computable from the public stack path.
    """
    components = [component for component in components if component != "Default"]
    if len(components) == 1:
        candidate = re.sub(r"[^A-Za-z0-9]", "", components[0])
        if len(candidate) <= 255:
            return candidate.lower()
    deduped: list[str] = []
    for component in components:
        if not deduped or not deduped[-1].endswith(component):
            deduped.append(component)
    human = "".join(
        re.sub(r"[^A-Za-z0-9]", "", component)
        for component in deduped
        if component != "Resource"
    )[:240]
    digest = hashlib.md5("/".join(components).encode()).hexdigest()[:8]
    return (human + digest).lower()


def _product_literals() -> set[str]:
    text = "\n".join(path.read_text() for path in PRODUCT_SOURCES)
    return set(re.findall(r"""['"]([A-Za-z0-9-]{1,63})['"]""", text))


def computable_prefixes(project: str, environment: str, account: str, region: str) -> set[str]:
    """Every prefix an outsider can compute from public names and this repo."""
    formula = f"{project}-{environment}-{account}"
    seeds = [
        formula,
        f"{project}-{environment}-{account}-{region}",
        f"{project}{environment}{account}",
        f"{environment}-{project}-{account}",
        f"{account}-{project}-{environment}",
        f"{project}-{environment}",
        _make_unique_id([f"{project}-{environment}-auth", "UserPool", "Domain"]),
    ]
    materials = [
        formula,
        f"{project}/{environment}/{account}",
        f"{project}/{environment}/{account}/{region}",
        f"{project}-{environment}-{account}-{region}",
    ]
    candidates = {seed.lower() for seed in seeds}
    for material in materials:
        for algorithm in ("md5", "sha1", "sha256"):
            digest = hashlib.new(algorithm, material.encode()).hexdigest()
            for length in (8, 12, 16, 20, 32, 63):
                candidates.add(digest[:length])
            candidates.add(f"{formula}-{digest[:8]}")
            candidates.add(f"{digest[:12]}-{formula}"[:63])
    for literal in _product_literals():
        lowered = literal.lower()
        candidates.add(lowered)
        candidates.add(f"{formula}-{lowered}")
        candidates.add(f"{lowered}-{formula}")
    return {item[:63].strip("-") for item in candidates if PREFIX_PATTERN.fullmatch(item[:63].strip("-"))}


def _resolve(value: Any, account: str, region: str) -> Any:
    if isinstance(value, str):
        return value
    if not isinstance(value, dict) or len(value) != 1:
        return value
    key, body = next(iter(value.items()))
    if key == "Ref" and body == "AWS::AccountId":
        return account
    if key == "Ref" and body == "AWS::Region":
        return region
    if key == "Fn::Join":
        separator, parts = body
        return separator.join(str(_resolve(part, account, region)) for part in parts)
    if key == "Fn::Sub":
        template = body[0] if isinstance(body, list) else body
        resolved = template.replace("${AWS::AccountId}", account).replace(
            "${AWS::Region}", region
        )
        if isinstance(body, list):
            for name, item in body[1].items():
                resolved = resolved.replace(
                    "${" + name + "}", str(_resolve(item, account, region))
                )
        if "${" in resolved:
            return value
        return resolved
    return value


def _synth(project: str, environment: str, account: str, **kwargs: Any) -> dict[str, Any]:
    app = cdk.App()
    stack = AuthStack(
        app,
        f"{project}-{environment}-auth",
        project_name=project,
        environment=environment,
        env=cdk.Environment(account=account, region=REGION),
        **kwargs,
    )
    return Template.from_stack(stack).to_json()


def _domain_resource(template: dict[str, Any]) -> dict[str, Any]:
    matches = [
        resource
        for resource in template["Resources"].values()
        if resource["Type"] == "AWS::Cognito::UserPoolDomain"
    ]
    assert len(matches) == 1, "brokered auth must still create one hosted domain"
    return matches[0]


def _prefix_and_hostname(
    template: dict[str, Any], account: str
) -> tuple[str | None, str]:
    """Prefix submitted to CreateUserPoolDomain, and the hostname clients use.

    None for the prefix means the name is not a concrete string an outsider can
    register ahead of the deploy (a custom domain the account already controls,
    or a value produced at deploy time). The hostname is still required so
    machine login does not invent one.
    """
    properties = _domain_resource(template)["Properties"]
    if "CustomDomainConfig" in properties:
        certificate = properties["CustomDomainConfig"]
        assert "CertificateArn" in json.dumps(certificate)
        hostname = _resolve(properties["Domain"], account, REGION)
        assert isinstance(hostname, str) and "." in hostname
        return None, hostname
    resolved = _resolve(properties["Domain"], account, REGION)
    if not isinstance(resolved, str):
        return None, ""
    return resolved, f"{resolved}.auth.{REGION}.amazoncognito.com"


def _hosted_domain_parameter(template: dict[str, Any]) -> Any | None:
    expected_suffix = f"/{HOSTED_DOMAIN_SUFFIX}"
    for resource in template["Resources"].values():
        if resource["Type"] != "AWS::SSM::Parameter":
            continue
        name = resource["Properties"].get("Name", "")
        if isinstance(name, str) and name.endswith(expected_suffix):
            return resource["Properties"]["Value"]
    return None


def _deploy_auth(
    template: dict[str, Any],
    *,
    account: str,
    registry: PrefixRegistry,
    project: str,
    environment: str,
) -> dict[str, Any]:
    """CloudFormation create of the auth stack against the prefix registry.

    DisableRollback defaults to false and OnFailure defaults to ROLLBACK, so a
    domain create that raises does not leave the user pool or the clients.
    """
    prefix, hostname = _prefix_and_hostname(template, account)
    published = _hosted_domain_parameter(template)
    if published is not None:
        rendered = _resolve(published, account, REGION)
        if isinstance(rendered, str):
            assert formula_host(project, environment, account) not in rendered
        elif prefix is not None:
            assert formula_host(project, environment, account) not in json.dumps(
                published
            )

    if prefix is None:
        return {
            "status": "CREATE_COMPLETE",
            "user_pool": True,
            "hostname": hostname or str(published),
        }
    try:
        registry.create(
            account=account,
            region=REGION,
            domain=prefix,
            user_pool_id=f"{REGION}_victim",
        )
    except DomainAlreadyAssociated:
        return {"status": "ROLLBACK_COMPLETE", "user_pool": False, "hostname": None}
    return {"status": "CREATE_COMPLETE", "user_pool": True, "hostname": hostname}


def _attacker_claims(registry: PrefixRegistry, prefixes: set[str]) -> None:
    """Claim only prefixes Cognito would accept. Reserved words are rejected
    by the service, so they are not a name an outsider can hold."""
    for prefix in prefixes:
        if any(word in prefix for word in RESERVED_PREFIX_WORDS):
            continue
        registry.create(
            account=ATTACKER_ACCOUNT,
            region=REGION,
            domain=prefix,
            user_pool_id=f"{REGION}_attacker",
        )


def formula_host(project: str, environment: str, account: str) -> str:
    return f"{project}-{environment}-{account}.auth.{REGION}.amazoncognito.com"


def _load_app():
    import os

    os.environ["CDK_DEFAULT_ACCOUNT"] = VICTIM_ACCOUNT
    os.environ["CDK_DEFAULT_REGION"] = REGION
    os.environ.pop("PROJECT_NAME", None)
    os.environ.pop("ENVIRONMENT", None)
    os.environ.pop("IDP_MODE", None)
    sys.path.insert(0, str(REPO))
    if "app" in sys.modules:
        return importlib.reload(sys.modules["app"])
    return importlib.import_module("app")


def test_preclaimed_public_prefix_cannot_block_default_brokered_deploy() -> None:
    """Repository defaults: project agentcore-workshop, environment dev, brokered."""
    application = _load_app()
    stacks = {
        child.node.id: child
        for child in application.app.node.children
        if isinstance(child, cdk.Stack)
    }
    auth = stacks["agentcore-workshop-dev-auth"]
    template = Template.from_stack(auth).to_json()
    registry = PrefixRegistry()
    _attacker_claims(
        registry,
        computable_prefixes("agentcore-workshop", "dev", VICTIM_ACCOUNT, REGION),
    )

    created: dict[str, str] = {}
    for name, stack in stacks.items():
        if name.endswith("-auth"):
            continue
        waiting_on_auth = any(
            dependency.node.id == auth.node.id for dependency in stack.dependencies
        )
        if not waiting_on_auth:
            continue
        outcome = _deploy_auth(
            template,
            account=VICTIM_ACCOUNT,
            registry=registry,
            project="agentcore-workshop",
            environment="dev",
        )
        if outcome["status"] != "CREATE_COMPLETE":
            # aws-cdk 2.1135.1 WorkGraph.failed -> skipRest, then cli exit 1.
            # scripts/deploy.sh exits 1 on that status and does not deploy dependents.
            created[name] = "skipped"
        else:
            created[name] = "CREATE_COMPLETE"

    outcome = _deploy_auth(
        template,
        account=VICTIM_ACCOUNT,
        registry=registry,
        project="agentcore-workshop",
        environment="dev",
    )
    assert outcome["status"] == "CREATE_COMPLETE"
    assert outcome["user_pool"] is True
    assert _hosted_domain_parameter(template) is not None
    assert created
    assert all(status == "CREATE_COMPLETE" for status in created.values()), created

    # A second deploy submits the same template. It must not depend on the
    # attacker releasing the public formula.
    again = _deploy_auth(
        template,
        account=VICTIM_ACCOUNT,
        registry=registry,
        project="agentcore-workshop",
        environment="dev",
    )
    assert again["status"] == "CREATE_COMPLETE"


@pytest.mark.parametrize(
    ("project", "environment", "account", "idp_type", "idp_config"),
    [
        ("agentcore-workshop", "dev", VICTIM_ACCOUNT, "cognito", None),
        ("widget", "prod", "222222222222", "cognito", None),
        (
            "agentcore-workshop",
            "dev",
            VICTIM_ACCOUNT,
            "entra_id",
            {
                "tenant_id": "22222222-3333-4444-5555-666666666666",
                "client_id": "entra-client",
                "client_secret_name": "agentcore/entra-secret",
            },
        ),
    ],
)
def test_brokered_prefix_survives_every_precomputable_claim(
    project: str,
    environment: str,
    account: str,
    idp_type: str,
    idp_config: dict[str, str] | None,
) -> None:
    template = _synth(
        project,
        environment,
        account,
        idp_type=idp_type,
        idp_mode="brokered",
        idp_config=idp_config,
    )
    registry = PrefixRegistry()
    _attacker_claims(
        registry, computable_prefixes(project, environment, account, REGION)
    )
    outcome = _deploy_auth(
        template,
        account=account,
        registry=registry,
        project=project,
        environment=environment,
    )
    assert outcome["status"] == "CREATE_COMPLETE", outcome
    assert _hosted_domain_parameter(template) is not None
    prefix, hostname = _prefix_and_hostname(template, account)
    if prefix is not None:
        assert prefix not in computable_prefixes(project, environment, account, REGION)
        assert PREFIX_PATTERN.fullmatch(prefix)
        assert hostname == f"{prefix}.auth.{REGION}.amazoncognito.com"
    output = template["Outputs"]["DomainUrl"]["Value"]
    rendered = _resolve(output, account, REGION)
    assert isinstance(rendered, str)
    assert formula_host(project, environment, account) not in rendered
    assert hostname in rendered


def test_hosted_domain_prefix_is_stable_across_synthesis() -> None:
    first = _synth("agentcore-workshop", "dev", VICTIM_ACCOUNT)
    second = _synth("agentcore-workshop", "dev", VICTIM_ACCOUNT)
    assert json.dumps(
        _domain_resource(first)["Properties"]["Domain"], sort_keys=True
    ) == json.dumps(_domain_resource(second)["Properties"]["Domain"], sort_keys=True)


def test_machine_login_uses_published_hosted_domain() -> None:
    stored = "k3m9q7v2n8p4r6t1.auth.eu-west-1.amazoncognito.com"
    predictable = "myproj-prod-111122223333.auth.eu-west-1.amazoncognito.com"
    captured: dict[str, Any] = {}

    class PublishedDomain(FakeAuthClients):
        def get_parameter(self, Name):
            if Name.endswith(HOSTED_DOMAIN_SUFFIX):
                return {"Parameter": {"Value": stored}}
            return super().get_parameter(Name)

    _patch_token_clients(PublishedDomain, captured)
    token = utils.get_m2m_token("myproj", "prod", "eu-west-1")
    assert token == STUB_TOKEN
    assert captured["req"].full_url == f"https://{stored}/oauth2/token"
    assert predictable not in captured["req"].full_url


def test_machine_login_does_not_invent_the_public_prefix_when_unpublished() -> None:
    captured: dict[str, Any] = {}

    class MissingDomain(FakeAuthClients):
        def get_parameter(self, Name):
            if Name.endswith(HOSTED_DOMAIN_SUFFIX):
                raise ClientError(
                    {"Error": {"Code": "ParameterNotFound", "Message": "missing"}},
                    "GetParameter",
                )
            return super().get_parameter(Name)

    _patch_token_clients(MissingDomain, captured)
    with pytest.raises((Exception, SystemExit)):
        utils.get_m2m_token("myproj", "prod", "eu-west-1")
    assert "req" not in captured


def test_brokered_design_plan_does_not_publish_the_public_prefix() -> None:
    config = PlatformConfig.model_validate(
        {
            "deployment": {"platform_account": "111122223333"},
            "identity": {
                "idp": "entra_id",
                "mode": "brokered",
                "tenant_id": "11111111-2222-3333-4444-555555555555",
                "client_id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
                "client_secret_name": "agentcore/idp-client-secret",
            },
        }
    )
    text = "\n".join(design_plan(config, account="444333641315"))
    assert (
        "agentcore-workshop-dev-444333641315.auth.us-east-1.amazoncognito.com"
        not in text
    )


class FakeAuthClients:
    def get_parameter(self, Name):
        if Name.endswith("auth/mode"):
            return {"Parameter": {"Value": "brokered"}}
        if Name.endswith("auth/user-pool-id"):
            return {"Parameter": {"Value": "pool-123"}}
        if Name.endswith("auth/m2m-client-id"):
            return {"Parameter": {"Value": "client-abc"}}
        if Name.endswith("auth/m2m-client-secret-name"):
            return {"Parameter": {"Value": STUB_SECRET_NAME}}
        raise ClientError(
            {"Error": {"Code": "ParameterNotFound", "Message": Name}},
            "GetParameter",
        )

    def get_secret_value(self, SecretId):
        assert SecretId == STUB_SECRET_NAME
        return {"SecretString": STUB_SECRET}

    def get_caller_identity(self):
        return {"Account": "111122223333"}


def _patch_token_clients(client_type: type, captured: dict[str, Any]) -> None:
    utils.boto3.client = lambda *args, **kwargs: client_type()  # type: ignore[method-assign]

    def fake_urlopen(req):
        captured["req"] = req
        return io.BytesIO(json.dumps({"access_token": STUB_TOKEN}).encode())

    utils.urllib.request.urlopen = fake_urlopen  # type: ignore[method-assign]


@pytest.fixture(autouse=True)
def _restore_utils_clients():
    original_client = utils.boto3.client
    original_urlopen = utils.urllib.request.urlopen
    yield
    utils.boto3.client = original_client
    utils.urllib.request.urlopen = original_urlopen
