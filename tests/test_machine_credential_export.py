"""Brokered credential upgrade must not publish the machine client secret.

scripts/deploy.sh migration step 1 deploys the auth stack with
``-c retain_legacy_m2m_export=true``. app.py then passes the Cognito machine
client secret into the identity stack. CDK turns that cross-stack reference
into an auth-stack output whose value is the DescribeUserPoolClient
``UserPoolClient.ClientSecret`` attribute.

These tests synthesize that app entry point and resolve the output the way
CloudFormation and the shipped custom-resource handler do. They fail while
that output exists and pass once the upgrade keeps only the Secrets Manager
name.
"""

from __future__ import annotations

import importlib.metadata
import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
# Obvious placeholder. Not a credential.
PLACEHOLDER_SECRET = "placeholder-machine-credential"
SECRET_ATTRIBUTE = "UserPoolClient.ClientSecret"


def _synth(tmp_path: Path, context: dict) -> Path:
    outdir = tmp_path / "cdk.out"
    outdir.mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    env.update(
        {
            "CDK_DEFAULT_ACCOUNT": "111111111111",
            "CDK_DEFAULT_REGION": "us-east-1",
            "CDK_OUTDIR": str(outdir),
            "CDK_CONTEXT_JSON": json.dumps(
                {
                    "platform_config": str(tmp_path / "no-platform.yaml"),
                    "@aws-cdk/core:checkSecretUsage": True,
                    **context,
                }
            ),
        }
    )
    subprocess.run(
        [sys.executable, str(ROOT / "app.py")],
        cwd=ROOT,
        env=env,
        check=True,
        capture_output=True,
        text=True,
    )
    return outdir


def _template(outdir: Path, suffix: str) -> dict:
    matches = list(outdir.glob(f"*-{suffix}.template.json"))
    assert len(matches) == 1, matches
    return json.loads(matches[0].read_text())


def _flatten(value):
    """Flatten nested SDK responses the way aws-cdk-lib 2.278.0 does.

    packages/@aws-cdk/aws-custom-resource-sdk-adapter/lib/api-call.ts flatten().
    Arrays are objects in that runtime, so their indexes become path segments.
    """

    flat: dict[str, object] = {}

    def recurse(node, path: tuple[str, ...]) -> None:
        if isinstance(node, dict):
            for key, child in node.items():
                recurse(child, (*path, str(key)))
            return
        if isinstance(node, list):
            for index, child in enumerate(node):
                recurse(child, (*path, str(index)))
            return
        flat[".".join(path)] = node

    recurse(value, ())
    return flat


def _join_literal(value) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, dict) and "Fn::Join" in value:
        return "".join(_join_literal(part) for part in value["Fn::Join"][1])
    if isinstance(value, dict) and set(value) == {"Ref"}:
        # The call JSON already supplies the surrounding quotes.
        return "REF:" + value["Ref"]
    raise AssertionError(f"unsupported CloudFormation fragment: {value!r}")


def _ref_token(value: str) -> str:
    assert value.startswith("REF:"), value
    return value.removeprefix("REF:")


def _walk_getatt(node):
    if isinstance(node, dict):
        getatt = node.get("Fn::GetAtt")
        if isinstance(getatt, list) and len(getatt) == 2:
            yield getatt[0], getatt[1]
        for child in node.values():
            yield from _walk_getatt(child)
    elif isinstance(node, list):
        for child in node:
            yield from _walk_getatt(child)


def _handler_masks_getatt(outdir: Path, template: dict) -> bool:
    """Read NoEcho from the custom-resource code this synthesis embedded."""

    functions = [
        resource
        for resource in template["Resources"].values()
        if resource["Type"] == "AWS::Lambda::Function"
        and isinstance(resource.get("Properties", {}).get("Code"), dict)
        and "S3Key" in resource["Properties"]["Code"]
    ]
    assert functions, "auth template has no custom-resource provider"
    seen = False
    masks = False
    for function in functions:
        key = function["Properties"]["Code"]["S3Key"]
        asset = outdir / f"asset.{key.removesuffix('.zip')}" / "index.js"
        if not asset.exists():
            continue
        source = asset.read_text(errors="replace")
        if "NoEcho:!0" in source or "NoEcho:true" in source or "NoEcho: true" in source:
            seen = True
            masks = True
        elif "NoEcho:!1" in source or "NoEcho:false" in source or "NoEcho: false" in source:
            seen = True
            masks = False
    assert seen, "shipped custom-resource handler did not set NoEcho"
    return masks


def _describe_call(resource: dict) -> dict:
    encoded = resource["Properties"].get("Update") or resource["Properties"]["Create"]
    parsed = json.loads(_join_literal(encoded))
    for field in ("UserPoolId", "ClientId"):
        parsed["parameters"][field] = _ref_token(parsed["parameters"][field])
    parsed["physicalResourceId"]["id"] = _ref_token(parsed["physicalResourceId"]["id"])
    return parsed


def machine_secret_outputs(outdir: Path, auth: dict) -> list[dict]:
    """Stack outputs whose DescribeStacks value is the machine client secret.

    CloudFormation returns custom-resource ``Data`` through ``Fn::GetAtt``.
    The provider in this synthesis sets ``NoEcho`` false, so GetAtt is the
    field itself. A stack output of that GetAtt is the OutputValue
    DescribeStacks returns.
    """

    published_client_ids = {
        output["Value"]["Ref"]
        for output in auth.get("Outputs", {}).values()
        if isinstance(output.get("Value"), dict) and "Ref" in output["Value"]
    }
    domain_published = any(
        isinstance(output.get("Value"), str) and ".amazoncognito.com" in output["Value"]
        for output in auth.get("Outputs", {}).values()
    )
    secret_outputs = [
        (output_key, logical_id)
        for output_key, output in auth.get("Outputs", {}).items()
        for logical_id, attribute in _walk_getatt(output.get("Value"))
        if attribute == SECRET_ATTRIBUTE
    ]
    if not secret_outputs or _handler_masks_getatt(outdir, auth):
        return []
    leaks = []
    for output_key, logical_id in secret_outputs:
        resource = auth["Resources"][logical_id]
        assert resource["Type"] == "Custom::DescribeCognitoUserPoolClient"
        call = _describe_call(resource)
        assert call["service"] == "CognitoIdentityServiceProvider"
        assert call["action"] == "describeUserPoolClient"
        assert "outputPath" not in call and "outputPaths" not in call
        client_logical_id = call["parameters"]["ClientId"]
        client = auth["Resources"][client_logical_id]["Properties"]
        response = {
            "UserPoolClient": {
                "ClientId": "placeholder-client-id",
                "ClientSecret": PLACEHOLDER_SECRET,
                "AllowedOAuthFlows": client["AllowedOAuthFlows"],
                "AllowedOAuthScopes": client["AllowedOAuthScopes"],
            }
        }
        flat = _flatten(response)
        assert flat[SECRET_ATTRIBUTE] == PLACEHOLDER_SECRET
        leaks.append(
            {
                "output_key": output_key,
                "output_value": PLACEHOLDER_SECRET,
                "client_logical_id": client_logical_id,
                "generate_secret": client.get("GenerateSecret") is True,
                "client_credentials": "client_credentials"
                in client.get("AllowedOAuthFlows", []),
                "invoke_scope": "agentcore/invoke" in client.get("AllowedOAuthScopes", []),
                "client_id_published": client_logical_id in published_client_ids,
                "token_endpoint_host_published": domain_published,
            }
        )
    return leaks


def _provider_secret(identity: dict):
    provider = next(
        resource
        for resource in identity["Resources"].values()
        if resource["Type"] == "AWS::BedrockAgentCore::OAuth2CredentialProvider"
    )
    return provider["Properties"]["Oauth2ProviderConfigInput"]["CustomOauth2ProviderConfig"][
        "ClientSecret"
    ]


def test_deploy_script_upgrade_uses_the_context_under_test():
    script = (ROOT / "scripts" / "deploy.sh").read_text()
    step = script.split("Migration 1/3", 1)[1].split("Migration 2/3", 1)[0]
    assert 'npx cdk deploy "${PREFIX}-auth" --exclusively' in step
    assert "-c retain_legacy_m2m_export=true" in step


def test_brokered_upgrade_does_not_publish_machine_client_secret(tmp_path):
    outdir = _synth(tmp_path, {"retain_legacy_m2m_export": "true"})
    auth = _template(outdir, "auth")
    identity = _template(outdir, "identity")
    leaks = machine_secret_outputs(outdir, auth)

    for leak in leaks:
        assert leak["generate_secret"]
        assert leak["client_credentials"]
        assert leak["invoke_scope"]
        assert leak["client_id_published"]
        assert leak["token_endpoint_host_published"]
        assert leak["output_value"] == PLACEHOLDER_SECRET
    assert leaks == [], leaks

    secret = _provider_secret(identity)
    rendered = json.dumps(secret)
    assert "resolve:secretsmanager" in rendered
    assert SECRET_ATTRIBUTE not in rendered
    assert "UserPoolClientClientSecret" not in rendered


def test_other_m2m_contexts_do_not_publish_machine_client_secret(tmp_path):
    contexts = [
        {},
        {"retain_legacy_m2m_client": "true"},
        {"transition_m2m_consumers": "true"},
        {
            "idp_mode": "direct",
            "idp_type": "entra_id",
            "idp_tenant_id": "placeholder-tenant",
            "idp_client_id": "placeholder-client",
            "idp_client_secret_name": "placeholder-secret-name",
            "retain_legacy_m2m_export": "true",
        },
    ]
    for context in contexts:
        case = tmp_path / json.dumps(context, sort_keys=True)
        outdir = _synth(case, context)
        auth = _template(outdir, "auth")
        identity = _template(outdir, "identity")
        assert machine_secret_outputs(outdir, auth) == [], context
        rendered = json.dumps(_provider_secret(identity))
        assert "resolve:secretsmanager" in rendered, context
        assert SECRET_ATTRIBUTE not in rendered, context
        assert "UserPoolClientClientSecret" not in rendered, context


def test_installed_cdk_matches_the_handler_these_tests_read():
    # The resolver follows the handler embedded by the installed library.
    version = importlib.metadata.version("aws-cdk-lib")
    assert tuple(int(part) for part in version.split(".")[:2]) >= (2, 265)
