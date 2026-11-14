"""Synthesis and config tests for the WAF + public/private ALB + ECS Fargate + DynamoDB BFF."""

from __future__ import annotations

import json
from typing import Any

import aws_cdk as cdk
import pytest
from aws_cdk.assertions import Template

from infra_utils.platform_config import PlatformConfig
from stacks.auth_stack import AuthStack
from stacks.frontend_stack import FrontendStack
from stacks.networking_stack import NetworkingStack
from stacks.runtime_stack import RuntimeStack
from stacks.security_stack import SecurityStack

ENV = cdk.Environment(account="111111111111", region="us-east-1")


def _resources(template: dict[str, Any], resource_type: str) -> list[dict[str, Any]]:
    return [
        resource
        for resource in template["Resources"].values()
        if resource["Type"] == resource_type
    ]


def test_frontend_config_validation_and_contract() -> None:
    cfg = PlatformConfig.model_validate(
        {
            "security": {"networking": True},
            "frontend": {
                "enabled": True,
                "exposure": "private",
                "min_capacity": 2,
                "max_capacity": 12,
                "allowed_cidrs": ["10.10.0.0/16"],
            },
        }
    )
    assert "agentcore-workshop-dev-frontend" in cfg.expected_stacks()

    # Switching to public is a single config change.
    pub = PlatformConfig.model_validate(
        {
            "security": {"networking": True},
            "frontend": {
                "enabled": True,
                "exposure": "public",
                "domain_name": "hr.corp.internal",
                "certificate_arn": "arn:aws:acm:us-east-1:111111111111:certificate/abc-123",
            },
        }
    )
    assert pub.frontend.exposure == "public"

    # Requires VPC networking.
    with pytest.raises(ValueError, match="security.networking=true"):
        PlatformConfig.model_validate({"frontend": {"enabled": True}})

    # Invalid Fargate CPU/memory pairing is rejected.
    with pytest.raises(ValueError, match="memory_mib"):
        PlatformConfig.model_validate(
            {
                "security": {"networking": True},
                "frontend": {"enabled": True, "cpu": 256, "memory_mib": 4096},
            }
        )

    # Custom domain requires ACM cert.
    with pytest.raises(ValueError, match="certificate_arn"):
        PlatformConfig.model_validate(
            {
                "security": {"networking": True},
                "frontend": {"enabled": True, "domain_name": "hr.corp.internal"},
            }
        )

    # max_capacity must be >= min_capacity.
    with pytest.raises(ValueError, match="max_capacity"):
        PlatformConfig.model_validate(
            {
                "security": {"networking": True},
                "frontend": {"enabled": True, "min_capacity": 4, "max_capacity": 2},
            }
        )


def _synth_frontend(
    *,
    exposure: str = "private",
    retain_data: bool = True,
    allowed_cidrs: list[str] | None = None,
    certificate_arn: str = "",
    domain_name: str = "",
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    app = cdk.App()
    net = NetworkingStack(
        app,
        "test-net",
        project_name="hrtest",
        environment="prod",
        enable_vpc_endpoints=True,
        retain_data=retain_data,
        env=ENV,
    )
    sec = SecurityStack(
        app,
        "test-sec",
        project_name="hrtest",
        environment="prod",
        retain_data=retain_data,
        env=ENV,
    )
    auth = AuthStack(
        app,
        "test-auth",
        project_name="hrtest",
        environment="prod",
        idp_type="entra_id",
        idp_config={
            "tenant_id": "11111111-2222-3333-4444-555555555555",
            "client_id": "entra-client-id",
            "client_secret_name": "agentcore/idp-client-secret",  # pragma: allowlist secret
        },
        retain_data=retain_data,
        env=ENV,
    )
    fe = FrontendStack(
        app,
        "test-frontend",
        project_name="hrtest",
        environment="prod",
        vpc=net.vpc,
        exposure=exposure,
        domain_name=domain_name,
        certificate_arn=certificate_arn,
        allowed_cidrs=allowed_cidrs,
        min_capacity=2,
        max_capacity=10,
        retain_data=retain_data,
        kms_key_arn=sec.kms_key.key_arn if sec.kms_key else "",
        issuer_url=auth.issuer_url,
        user_pool_id=auth.user_pool.user_pool_id,
        supported_identity_providers=auth.supported_identity_providers,
        env=ENV,
    )
    rt = RuntimeStack(
        app,
        "test-runtime",
        project_name="hrtest",
        environment="prod",
        component_name="orchestrator",
        source_dir="agent-code",
        dockerfile_pattern="god-agent",
        runtime_type="orchestrator",
        cognito_issuer_url=auth.issuer_url,
        cognito_allowed_clients=[fe.bff_client_id, auth.m2m_client_id],
        include_ssm_web_client=False,
        restrict_to_vpce_id=net.agentcore_vpce_id,
        network_mode="VPC",
        subnet_ids=net.private_subnet_ids,
        security_group_ids=[net.runtime_security_group.security_group_id],
        retain_data=retain_data,
        env=ENV,
    )
    return (
        Template.from_stack(fe).to_json(),
        Template.from_stack(rt).to_json(),
        Template.from_stack(net).to_json(),
    )


def test_private_frontend_synthesizes_internal_alb_waf_fargate_scaling_and_dynamodb() -> (
    None
):
    fe_tpl, rt_tpl, net_tpl = _synth_frontend(
        exposure="private",
        retain_data=True,
        allowed_cidrs=["10.20.0.0/16"],
    )

    # 1. Internal ALB behind Regional WAFv2 + IPSet.
    albs = _resources(fe_tpl, "AWS::ElasticLoadBalancingV2::LoadBalancer")
    assert len(albs) == 1
    assert albs[0]["Properties"]["Scheme"] == "internal"
    assert "Name" not in albs[0]["Properties"]  # allows clean private <-> public switch

    waf_acls = _resources(fe_tpl, "AWS::WAFv2::WebACL")
    assert len(waf_acls) == 1
    assert waf_acls[0]["Properties"]["Scope"] == "REGIONAL"
    rule_names = {r["Name"] for r in waf_acls[0]["Properties"]["Rules"]}
    assert {
        "BlockOutsideAllowedCidrs",
        "RateLimitPerIp",
        "AWSManagedRulesAmazonIpReputationList",
        "AWSManagedRulesKnownBadInputsRuleSet",
        "AWSManagedRulesCommonRuleSet",
    } <= rule_names
    assert len(_resources(fe_tpl, "AWS::WAFv2::WebACLAssociation")) == 1
    assert len(_resources(fe_tpl, "AWS::WAFv2::IPSet")) == 1

    # 2. ALB SG has no 0.0.0.0/0 ingress in private mode.
    sgs = _resources(fe_tpl, "AWS::EC2::SecurityGroup")
    alb_sg = next(
        s["Properties"]
        for s in sgs
        if "HR Web BFF Application Load Balancer" in s["Properties"]["GroupDescription"]
    )
    cidrs = [r.get("CidrIp") for r in alb_sg.get("SecurityGroupIngress", [])]
    assert "0.0.0.0/0" not in cidrs
    assert "10.20.0.0/16" in cidrs

    # 3. Auto-scaling ARM64 ECS Fargate service.
    task_defs = _resources(fe_tpl, "AWS::ECS::TaskDefinition")
    assert len(task_defs) == 1
    assert task_defs[0]["Properties"]["RuntimePlatform"]["CpuArchitecture"] == "ARM64"
    container = task_defs[0]["Properties"]["ContainerDefinitions"][0]
    secret_names = {s["Name"] for s in container["Secrets"]}
    assert "OIDC_CLIENT_SECRET" in secret_names
    env_map = {e["Name"]: e["Value"] for e in container["Environment"]}
    assert env_map["FRONTEND_EXPOSURE"] == "private"
    assert "OIDC_CLIENT_SECRET" not in env_map

    scalable = _resources(fe_tpl, "AWS::ApplicationAutoScaling::ScalableTarget")
    assert len(scalable) == 1
    assert scalable[0]["Properties"]["MinCapacity"] == 2
    assert scalable[0]["Properties"]["MaxCapacity"] == 10
    assert len(_resources(fe_tpl, "AWS::ApplicationAutoScaling::ScalingPolicy")) == 3

    # 4. DynamoDB BffSessions + ChatSessions tables retained & CMK-encrypted.
    tables = _resources(fe_tpl, "AWS::DynamoDB::Table")
    assert len(tables) == 2
    for tbl in tables:
        assert tbl["DeletionPolicy"] == "Retain"
        assert tbl["Properties"]["BillingMode"] == "PAY_PER_REQUEST"
        assert tbl["Properties"]["SSESpecification"]["SSEEnabled"] is True
        assert tbl["Properties"]["PointInTimeRecoverySpecification"][
            "PointInTimeRecoveryEnabled"
        ]
    assert not _resources(fe_tpl, "Custom::ECRAutoDeleteImages")
    assert not _resources(fe_tpl, "Custom::S3AutoDeleteObjects")

    # 5. Runtime locked to VPC Endpoint + confidential BffClient only (no WebClient).
    policies = _resources(rt_tpl, "AWS::BedrockAgentCore::ResourcePolicy")
    assert len(policies) == 1
    policy_doc = json.dumps(policies[0]["Properties"]["Policy"])
    assert "aws:SourceVpce" in policy_doc
    assert "aws:ViaAWSService" in policy_doc

    runtimes = _resources(rt_tpl, "AWS::BedrockAgentCore::Runtime")
    assert len(runtimes) == 1
    allowed_clients = runtimes[0]["Properties"]["AuthorizerConfiguration"][
        "CustomJWTAuthorizer"
    ]["AllowedClients"]
    assert len(allowed_clients) == 2

    # 6. NetworkingStack publishes the AgentCore VPCE ID to SSM.
    net_ssm = [
        p["Properties"]["Name"] for p in _resources(net_tpl, "AWS::SSM::Parameter")
    ]
    assert "/hrtest/prod/networking/agentcore-vpce-id" in net_ssm


def test_public_frontend_with_acm_cert_uses_internet_facing_https_alb() -> None:
    fe_tpl, _, _ = _synth_frontend(
        exposure="public",
        retain_data=False,
        certificate_arn="arn:aws:acm:us-east-1:111111111111:certificate/abc-123",
        domain_name="hr.corp.internal",
    )

    albs = _resources(fe_tpl, "AWS::ElasticLoadBalancingV2::LoadBalancer")
    assert albs[0]["Properties"]["Scheme"] == "internet-facing"

    listeners = _resources(fe_tpl, "AWS::ElasticLoadBalancingV2::Listener")
    ports = {l["Properties"]["Port"] for l in listeners}
    assert ports == {80, 443}
    https_listener = next(
        l["Properties"] for l in listeners if l["Properties"]["Port"] == 443
    )
    assert https_listener["Protocol"] == "HTTPS"

    # Confidential BffClient registers the HTTPS /auth/callback redirect URI.
    clients = _resources(fe_tpl, "AWS::Cognito::UserPoolClient")
    assert len(clients) == 1
    assert clients[0]["Properties"]["GenerateSecret"] is True
    assert clients[0]["Properties"]["CallbackURLs"] == [
        "https://hr.corp.internal/auth/callback"
    ]
    assert clients[0]["Properties"]["LogoutURLs"] == ["https://hr.corp.internal/"]
