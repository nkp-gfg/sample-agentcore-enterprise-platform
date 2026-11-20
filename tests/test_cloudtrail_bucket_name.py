"""The CloudTrail trail bucket must not be pre-claimable in the global S3 namespace.

Shipped presets turn the security stack on and publish the project and
environment used in the bucket name. S3 general-purpose bucket names in the
default global namespace are unique across accounts, so another account can
create that name first and CloudFormation cannot create the trail bucket.

These tests fail until the synthesized bucket is no longer a name another
account can create from the preset, the region, and the deploying account id.
Omitting ``BucketName`` (CloudFormation then assigns a unique id), using the
account-regional namespace, or adding a suffix that is not reproduced by a
second synthesis of the same public inputs all satisfy the check.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import aws_cdk as cdk
import pytest
from aws_cdk.assertions import Template

from infra_utils.platform_config import load_platform_config, to_env
from stacks.security_stack import SecurityStack

REPO = Path(__file__).resolve().parents[1]
# Stand-in for the deploying account. deploy.sh exports the caller account as
# CDK_DEFAULT_ACCOUNT; the value is not a credential.
DEPLOYING_ACCOUNT = "111111111111"


def presets_with_cloudtrail() -> list[Path]:
    found: list[Path] = []
    for path in sorted((REPO / "presets").glob("*.yaml")):
        config = load_platform_config(path)
        if config.security.cloudtrail_alerting:
            found.append(path)
    return found


PRESETS = presets_with_cloudtrail()


def cfg(yaml_env: dict[str, str], env_key: str, default: str) -> str:
    """app.py cfg() with no CDK context and no process-env override.

    Precedence there is context, then the environment, then platform.yaml,
    then the legacy default. A preset deploy leaves the first two empty, so
    the shipped file is what reaches the stack.
    """
    return yaml_env.get(env_key, "") or default


def synthesize_security_stack(preset: Path, account: str) -> dict[str, Any]:
    """Build the security stack the way app.py does for this preset."""
    yaml_env = to_env(load_platform_config(preset))
    assert yaml_env["ENABLE_SECURITY"] == "true"

    project = cfg(yaml_env, "PROJECT_NAME", "agentcore-workshop")
    environment = cfg(yaml_env, "ENVIRONMENT", "dev")
    region = cfg(yaml_env, "AWS_REGION", "us-east-1")
    production_mode = cfg(yaml_env, "DEPLOYMENT_MODE", "workshop") == "production"
    prefix = f"{project}-{environment}"

    app = cdk.App()
    stack = SecurityStack(
        app,
        f"{prefix}-security",
        project_name=project,
        environment=environment,
        enable_kms=True,
        enable_cloudtrail=True,
        retain_data=production_mode,
        env=cdk.Environment(account=account, region=region),
    )
    return Template.from_stack(stack).to_json()


def resolve_name(value: Any, account: str, region: str) -> str:
    """Resolve the bucket-name intrinsics synthesis leaves in the template."""
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        return "".join(resolve_name(part, account, region) for part in value)
    if not isinstance(value, dict):
        raise AssertionError(f"unexpected bucket name form: {value!r}")
    if set(value) == {"Ref"}:
        ref = value["Ref"]
        if ref == "AWS::AccountId":
            return account
        if ref == "AWS::Region":
            return region
        raise AssertionError(f"bucket name depends on {ref}, which is not a public input")
    if "Fn::Join" in value:
        separator, parts = value["Fn::Join"]
        return separator.join(resolve_name(part, account, region) for part in parts)
    if "Fn::Sub" in value:
        sub = value["Fn::Sub"]
        if isinstance(sub, str):
            template, mapping = sub, {}
        else:
            template, mapping = sub
        rendered = template.replace("${AWS::AccountId}", account).replace(
            "${AWS::Region}", region
        )
        for key, mapped in mapping.items():
            rendered = rendered.replace(
                "${" + key + "}", resolve_name(mapped, account, region)
            )
        if "${" in rendered:
            raise AssertionError(f"unresolved bucket name substitution: {rendered}")
        return rendered
    raise AssertionError(f"unexpected bucket name form: {value!r}")


def preclaimable_global_names(
    template: dict[str, Any], account: str, region: str
) -> list[str]:
    """Global bucket names another account could create before this deploy.

    An account-regional bucket is not in that set: only the bucket's own
    account can create a name in that namespace. A missing ``BucketName`` is
    not in it either: CloudFormation assigns the name when the stack is
    deployed.
    """
    names: list[str] = []
    for resource in template["Resources"].values():
        if resource["Type"] != "AWS::S3::Bucket":
            continue
        props = resource.get("Properties") or {}
        namespace = props.get("BucketNamespace", "global")
        bucket_name = props.get("BucketName")
        bucket_prefix = props.get("BucketNamePrefix")
        if namespace == "account-regional":
            if bucket_name is None and bucket_prefix is not None:
                continue
            if bucket_name is not None:
                rendered = resolve_name(bucket_name, account, region)
                suffix = f"-{account}-{region}-an"
                if rendered.endswith(suffix):
                    continue
            names.append(
                resolve_name(bucket_name, account, region)
                if bucket_name is not None
                else json.dumps(bucket_prefix, sort_keys=True)
            )
            continue
        if bucket_name is None and bucket_prefix is None:
            continue
        if bucket_name is not None:
            names.append(resolve_name(bucket_name, account, region))
        else:
            names.append(resolve_name(bucket_prefix, account, region))
    return names


def assert_trail_depends_on_its_bucket(template: dict[str, Any]) -> None:
    trails = [
        (logical_id, resource)
        for logical_id, resource in template["Resources"].items()
        if resource["Type"] == "AWS::CloudTrail::Trail"
    ]
    assert len(trails) == 1, "the security stack did not create the CloudTrail trail"
    _, trail = trails[0]
    bucket_ref = trail["Properties"]["S3BucketName"]
    assert isinstance(bucket_ref, dict) and set(bucket_ref) == {"Ref"}, bucket_ref
    bucket_id = bucket_ref["Ref"]
    assert template["Resources"][bucket_id]["Type"] == "AWS::S3::Bucket"
    dependencies = trail.get("DependsOn", [])
    if isinstance(dependencies, str):
        dependencies = [dependencies]
    assert dependencies, "trail has no dependency on the bucket it logs to"
    assert any(
        bucket_id in json.dumps(template["Resources"][dependency])
        for dependency in dependencies
    ), "trail does not wait on a resource that references its bucket"


@pytest.mark.parametrize("preset", PRESETS, ids=lambda path: path.name)
def test_preset_cloudtrail_bucket_is_not_preclaimable(preset: Path) -> None:
    region = cfg(to_env(load_platform_config(preset)), "AWS_REGION", "us-east-1")
    first = synthesize_security_stack(preset, DEPLOYING_ACCOUNT)
    second = synthesize_security_stack(preset, DEPLOYING_ACCOUNT)
    assert_trail_depends_on_its_bucket(first)
    assert_trail_depends_on_its_bucket(second)

    first_names = preclaimable_global_names(first, DEPLOYING_ACCOUNT, region)
    second_names = preclaimable_global_names(second, DEPLOYING_ACCOUNT, region)
    # A suffix drawn again on each synthesis is not knowable ahead of deploy.
    # A name both syntheses reproduce is knowable to anyone who can read the
    # preset and the account id.
    assert first_names != second_names or not first_names, (
        f"{preset.name} publishes global CloudTrail bucket name(s) {first_names}. "
        "Another account can create that name first; stack creation then fails "
        "and the trail, which depends on the bucket, is not created."
    )


def test_workshop_presets_do_not_share_one_preclaimable_bucket() -> None:
    """security-focused and platform-team ship the same project and environment."""
    shared = [
        REPO / "presets" / name
        for name in ("security-focused.yaml", "platform-team.yaml")
    ]
    assert all(path in PRESETS for path in shared)
    names = []
    for preset in shared:
        region = cfg(to_env(load_platform_config(preset)), "AWS_REGION", "us-east-1")
        template = synthesize_security_stack(preset, DEPLOYING_ACCOUNT)
        names.append(preclaimable_global_names(template, DEPLOYING_ACCOUNT, region))
    assert names[0] != names[1] or not names[0], (
        f"both workshop presets publish {names[0]}, so one pre-created bucket "
        "blocks both deploys"
    )
