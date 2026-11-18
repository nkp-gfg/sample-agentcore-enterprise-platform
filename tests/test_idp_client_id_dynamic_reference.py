"""identity.client_id must not carry a CloudFormation dynamic reference.

A manifest author can set identity.client_id to a {{resolve:...}} string.
Placeholder checks only reject a few sentinel words, and AuthStack copies
that string into the Cognito OIDC provider client id. In direct Entra mode
the same string is also stored in plaintext SSM parameters and in the
downstream client-id fields app.py passes to Identity, Gateway, and Runtime.

These tests fail while that copy is still possible. They pass once the value
is rejected before any of those resources are written.
"""

from __future__ import annotations

import json
from pathlib import Path

import aws_cdk as cdk
import pytest
from pydantic import ValidationError

from infra_utils.platform_config import (
    PlatformConfig,
    apply_environment_overrides,
    to_env,
)
from stacks.auth_stack import AuthStack
from stacks.gateway_stack import GatewayStack
from stacks.identity_stack import IdentityStack
from stacks.runtime_stack import RuntimeStack

ACCOUNT = "111122223333"
REGION = "us-east-1"
ENV = cdk.Environment(account=ACCOUNT, region=REGION)
TENANT = "3f2b1c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5d"
SECRET_NAME = "agentcore/idp-client-secret"
MARKER = "example-deploy-secret"
LEGITIMATE_IDS = (
    "entra-client",
    "okta-client",
    "ping-client",
    "9a8b7c6d-1234-4abc-9def-000111222333",
)

# Whole-value and embedded forms. CloudFormation resolves the reference when
# it appears as a resource property, including when other text is concatenated
# around it (direct mode stores "{client_id}/.default" as the machine scope).
DYNAMIC_CLIENT_IDS = (
    "{{resolve:secretsmanager:example-deploy-secret}}",
    "{{resolve:secretsmanager:example-deploy-secret:SecretString}}",
    "{{resolve:secretsmanager:example-deploy-secret:SecretString:password}}",
    "{{resolve:ssm:example-deploy-secret}}",
    "{{resolve:ssm-secure:example-deploy-secret}}",
    "id-{{resolve:secretsmanager:example-deploy-secret:SecretString}}",
    "bad{id}",
)


@pytest.fixture(autouse=True)
def _strict_placeholders(monkeypatch: pytest.MonkeyPatch) -> None:
    # deploy.sh unsets this. A real deploy must not treat sentinels as warnings.
    monkeypatch.delenv("PLATFORM_ALLOW_PLACEHOLDERS", raising=False)


def _manifest(
    idp: str,
    mode: str,
    client_id: str,
    issuer_url: str = "",
) -> dict:
    identity: dict[str, str] = {
        "idp": idp,
        "mode": mode,
        "client_id": client_id,
        "client_secret_name": SECRET_NAME,
    }
    if idp == "entra_id":
        identity["tenant_id"] = TENANT
    else:
        identity["issuer_url"] = issuer_url or "https://corp.example.net/oauth2/default"
    return {
        "project": "agentcore",
        "environment": "test",
        "deployment": {"platform_account": ACCOUNT},
        "identity": identity,
    }


def _idp_config(config: PlatformConfig) -> dict[str, str]:
    """The idp_config dict app.py builds from the exported manifest."""
    env = to_env(config)
    return {
        "tenant_id": env.get("IDP_TENANT_ID", ""),
        "client_id": env.get("IDP_CLIENT_ID", ""),
        "client_secret_name": env.get("IDP_CLIENT_SECRET_NAME", ""),
        "issuer_url": env.get("IDP_ISSUER_URL", ""),
    }


def _synth_auth(tmp_path: Path, **kwargs) -> None:
    app = cdk.App(outdir=str(tmp_path / "auth"))
    AuthStack(
        app,
        "Auth",
        project_name="agentcore",
        environment="test",
        env=ENV,
        **kwargs,
    )
    app.synth()


def _synth_direct_deploy(tmp_path: Path, config: PlatformConfig) -> None:
    """Direct mode, following app.py: auth, then identity, gateway, and runtime."""
    idp_config = _idp_config(config)
    app = cdk.App(outdir=str(tmp_path / "direct"))
    auth = AuthStack(
        app,
        "Auth",
        project_name="agentcore",
        environment="test",
        idp_type="entra_id",
        idp_mode="direct",
        idp_config=idp_config,
        env=ENV,
    )
    IdentityStack(
        app,
        "Identity",
        project_name="agentcore",
        environment="test",
        gateway_m2m_client_id=auth.app_client_id,
        gateway_m2m_client_secret_name=auth.m2m_client_secret_name,
        cognito_discovery_url=auth.discovery_url,
        env=ENV,
    )
    GatewayStack(
        app,
        "Gateway",
        project_name="agentcore",
        environment="test",
        cognito_issuer_url=auth.issuer_url,
        cognito_allowed_clients=[],
        allowed_audience=[auth.app_client_id],
        enable_web_search=False,
        env=ENV,
    )
    RuntimeStack(
        app,
        "Runtime",
        project_name="agentcore",
        environment="test",
        component_name="orchestrator",
        source_dir="agent-code",
        dockerfile_pattern="orchestrator",
        runtime_type="orchestrator",
        cognito_issuer_url=auth.issuer_url,
        cognito_allowed_clients=[],
        allowed_audience=[auth.app_client_id],
        extra_env_vars={
            "GATEWAY_TOKEN_SCOPES": f"{auth.app_client_id}/.default",
            "COGNITO_ALLOWED_CLIENTS": auth.app_client_id,
        },
        env=ENV,
    )
    app.synth()


def _tree_text(tmp_path: Path) -> str:
    parts: list[str] = []
    for path in tmp_path.rglob("*"):
        if path.is_file():
            parts.append(path.read_text(errors="replace"))
    return "\n".join(parts)


def _assert_rejected_before_write(tmp_path: Path, fn) -> None:
    with pytest.raises((ValidationError, ValueError)):
        fn()
    assert MARKER not in _tree_text(tmp_path)


@pytest.mark.parametrize("client_id", DYNAMIC_CLIENT_IDS)
@pytest.mark.parametrize(
    ("idp", "mode"),
    [
        ("entra_id", "brokered"),
        ("entra_id", "direct"),
        ("okta", "brokered"),
        ("ping", "brokered"),
    ],
)
def test_manifest_rejects_dynamic_reference_client_id(
    idp: str, mode: str, client_id: str
) -> None:
    with pytest.raises(ValidationError):
        PlatformConfig.model_validate(_manifest(idp, mode, client_id))


@pytest.mark.parametrize("client_id", DYNAMIC_CLIENT_IDS)
def test_env_override_rejects_dynamic_reference_client_id(client_id: str) -> None:
    """deploy.sh revalidates IDP_CLIENT_ID through the manifest model."""
    base = PlatformConfig.model_validate(
        _manifest("okta", "brokered", "okta-client")
    )
    with pytest.raises(ValidationError):
        apply_environment_overrides(base, {"IDP_CLIENT_ID": client_id})


@pytest.mark.parametrize("client_id", LEGITIMATE_IDS)
@pytest.mark.parametrize(
    ("idp", "mode"),
    [
        ("entra_id", "brokered"),
        ("entra_id", "direct"),
        ("okta", "brokered"),
        ("ping", "brokered"),
    ],
)
def test_manifest_accepts_idp_client_id_charset(
    idp: str, mode: str, client_id: str
) -> None:
    config = PlatformConfig.model_validate(_manifest(idp, mode, client_id))
    assert config.identity.client_id == client_id
    assert "{{resolve:" not in config.identity.client_id


@pytest.mark.parametrize(
    ("idp", "client_id"),
    [
        ("entra_id", "{{resolve:secretsmanager:example-deploy-secret:SecretString}}"),
        ("okta", "{{resolve:ssm:example-deploy-secret}}"),
        ("ping", "id-{{resolve:ssm-secure:example-deploy-secret}}"),
    ],
)
def test_brokered_deploy_does_not_publish_client_id_reference(
    tmp_path: Path, idp: str, client_id: str
) -> None:
    def deploy() -> None:
        config = PlatformConfig.model_validate(_manifest(idp, "brokered", client_id))
        _synth_auth(
            tmp_path,
            idp_type=idp,
            idp_mode="brokered",
            idp_config=_idp_config(config),
        )

    _assert_rejected_before_write(tmp_path, deploy)


def test_direct_deploy_does_not_publish_client_id_reference(tmp_path: Path) -> None:
    client_id = "{{resolve:secretsmanager:example-deploy-secret:SecretString}}"

    def deploy() -> None:
        config = PlatformConfig.model_validate(
            _manifest("entra_id", "direct", client_id)
        )
        _synth_direct_deploy(tmp_path, config)

    _assert_rejected_before_write(tmp_path, deploy)


@pytest.mark.parametrize("idp", ["okta", "ping"])
def test_issuer_url_dynamic_reference_is_not_published(
    tmp_path: Path, idp: str
) -> None:
    issuer = "https://{{resolve:secretsmanager:example-deploy-secret:SecretString}}"

    def deploy() -> None:
        config = PlatformConfig.model_validate(
            _manifest(idp, "brokered", f"{idp}-client", issuer_url=issuer)
        )
        _synth_auth(
            tmp_path,
            idp_type=idp,
            idp_mode="brokered",
            idp_config=_idp_config(config),
        )

    with pytest.raises(ValidationError):
        PlatformConfig.model_validate(
            _manifest(idp, "brokered", f"{idp}-client", issuer_url=issuer)
        )
    _assert_rejected_before_write(tmp_path, deploy)


@pytest.mark.parametrize(
    ("idp", "mode", "client_id"),
    [
        (
            "okta",
            "brokered",
            "{{resolve:secretsmanager:example-deploy-secret:SecretString}}",
        ),
        ("ping", "brokered", "{{resolve:ssm:example-deploy-secret}}"),
        (
            "entra_id",
            "brokered",
            "id-{{resolve:ssm-secure:example-deploy-secret}}",
        ),
        (
            "entra_id",
            "direct",
            "{{resolve:secretsmanager:example-deploy-secret:SecretString}}",
        ),
    ],
)
def test_auth_stack_refuses_client_id_that_bypasses_the_manifest(
    tmp_path: Path, idp: str, mode: str, client_id: str
) -> None:
    """Context and env reach AuthStack without a second manifest read."""

    def deploy() -> None:
        idp_config = {
            "tenant_id": TENANT,
            "client_id": client_id,
            "client_secret_name": SECRET_NAME,
            "issuer_url": "https://corp.example.net/oauth2/default",
        }
        _synth_auth(tmp_path, idp_type=idp, idp_mode=mode, idp_config=idp_config)

    with pytest.raises(ValueError):
        deploy()
    assert MARKER not in _tree_text(tmp_path)


def test_legitimate_brokered_client_id_is_published_unchanged(tmp_path: Path) -> None:
    config = PlatformConfig.model_validate(
        _manifest("okta", "brokered", "okta-client")
    )
    _synth_auth(
        tmp_path,
        idp_type="okta",
        idp_mode="brokered",
        idp_config=_idp_config(config),
    )
    template = json.loads((tmp_path / "auth" / "Auth.template.json").read_text())
    provider = next(
        resource
        for resource in template["Resources"].values()
        if resource["Type"] == "AWS::Cognito::UserPoolIdentityProvider"
    )
    assert provider["Properties"]["ProviderDetails"]["client_id"] == "okta-client"
    assert MARKER not in _tree_text(tmp_path)


def test_direct_mode_publishes_client_id_as_plaintext_ssm(tmp_path: Path) -> None:
    """The parameters a runtime can read are String, not SecureString."""
    client_id = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
    config = PlatformConfig.model_validate(
        _manifest("entra_id", "direct", client_id)
    )
    _synth_direct_deploy(tmp_path, config)
    template = json.loads((tmp_path / "direct" / "Auth.template.json").read_text())
    published = {
        resource["Properties"]["Name"]: resource["Properties"]
        for resource in template["Resources"].values()
        if resource["Type"] == "AWS::SSM::Parameter"
    }
    for name in (
        "/agentcore/test/auth/app-client-id",
        "/agentcore/test/auth/m2m-client-id",
        "/agentcore/test/auth/m2m-scope",
    ):
        assert published[name]["Type"] == "String"
        assert published[name]["Value"] in {client_id, f"{client_id}/.default"}

    runtime = json.loads((tmp_path / "direct" / "Runtime.template.json").read_text())
    statements = []
    for resource in runtime["Resources"].values():
        if resource["Type"] != "AWS::IAM::Policy":
            continue
        statements.extend(resource["Properties"]["PolicyDocument"]["Statement"])
    ssm = next(
        statement
        for statement in statements
        if statement.get("Sid") == "SSMAccess"
    )
    assert "ssm:GetParameter" in ssm["Action"]
    assert "arn:aws:ssm:*:*:parameter/agentcore/*" in ssm["Resource"]
