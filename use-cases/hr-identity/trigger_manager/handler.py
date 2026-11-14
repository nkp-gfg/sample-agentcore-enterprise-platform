"""CloudFormation custom resource that safely attaches/detaches the Cognito Pre-Token V3_0 trigger.

Why a read-modify-write handler instead of a raw `AwsCustomResource(updateUserPool)`:
  - `cognito-idp:UpdateUserPool` has full-replacement semantics on top-level
    pool attributes: calling it with only `UserPoolId` and `LambdaConfig` risks
    resetting `DeletionProtection`, `AdminCreateUserConfig` (self-signup!),
    `Policies`, or `AccountRecoverySetting`, and sending `LambdaConfig: {}` on
    DELETE wipes unrelated triggers.
  - Pre-Token V3_0 (`TokenGeneration_ClientCredentials` + `aws_client_metadata`)
    requires `UserPoolTier` to be `ESSENTIALS` or `PLUS`.

This handler calls `DescribeUserPool`, preserves every mutable pool setting,
ensures `UserPoolTier` is at least `ESSENTIALS`, attaches `PreTokenGenerationConfig`
(`V3_0`) on Create/Update, and removes ONLY the pre-token keys matching our
Lambda ARN on Delete.
"""

from __future__ import annotations

import logging
import os

import boto3

logger = logging.getLogger()
logger.setLevel(os.environ.get("LOG_LEVEL", "INFO"))

# Exact set of mutable keys accepted by cognito-idp:UpdateUserPool.
_MUTABLE_POOL_KEYS = (
    "Policies",
    "DeletionProtection",
    "LambdaConfig",
    "AutoVerifiedAttributes",
    "SmsVerificationMessage",
    "EmailVerificationMessage",
    "EmailVerificationSubject",
    "VerificationMessageTemplate",
    "SmsAuthenticationMessage",
    "UserAttributeUpdateSettings",
    "MfaConfiguration",
    "DeviceConfiguration",
    "EmailConfiguration",
    "SmsConfiguration",
    "UserPoolTags",
    "AdminCreateUserConfig",
    "UserPoolAddOns",
    "AccountRecoverySetting",
    "UserPoolTier",
)


def _clean_update_kwargs(pool: dict) -> dict:
    kwargs: dict = {"UserPoolId": pool["Id"]}
    for key in _MUTABLE_POOL_KEYS:
        if key in pool and pool[key] is not None:
            kwargs[key] = pool[key]

    # DescribeUserPool returns UnusedAccountValidityDays inside AdminCreateUserConfig
    # even when PasswordPolicy.TemporaryPasswordValidityDays is authoritative; Cognito
    # rejects UpdateUserPool if both are sent simultaneously.
    admin_cfg = dict(kwargs.get("AdminCreateUserConfig") or {})
    if "UnusedAccountValidityDays" in admin_cfg:
        admin_cfg.pop("UnusedAccountValidityDays", None)
        kwargs["AdminCreateUserConfig"] = admin_cfg

    return kwargs


def on_event(event: dict, _context) -> dict:
    request_type = event["RequestType"]
    props = event["ResourceProperties"]
    user_pool_id = props["UserPoolId"]
    lambda_arn = props["LambdaArn"]
    lambda_version = props.get("LambdaVersion") or "V3_0"
    physical_id = (
        event.get("PhysicalResourceId") or f"hr-identity-trigger-{user_pool_id}"
    )

    region = os.environ.get("AWS_REGION") or None
    cognito = boto3.client("cognito-idp", region_name=region)

    try:
        pool = cognito.describe_user_pool(UserPoolId=user_pool_id)["UserPool"]
    except cognito.exceptions.ResourceNotFoundException:
        if request_type == "Delete":
            logger.info("UserPool %s already gone on Delete; skipping", user_pool_id)
            return {"PhysicalResourceId": physical_id}
        raise

    update_kwargs = _clean_update_kwargs(pool)
    lambda_config = dict(update_kwargs.get("LambdaConfig") or {})

    if request_type in {"Create", "Update"}:
        current_tier = update_kwargs.get("UserPoolTier")
        if current_tier in {None, "", "LITE"}:
            update_kwargs["UserPoolTier"] = "ESSENTIALS"
        lambda_config["PreTokenGeneration"] = lambda_arn
        lambda_config["PreTokenGenerationConfig"] = {
            "LambdaArn": lambda_arn,
            "LambdaVersion": lambda_version,
        }
        update_kwargs["LambdaConfig"] = lambda_config
        cognito.update_user_pool(**update_kwargs)
        logger.info(
            "Attached PreTokenGenerationConfig (%s) %s to %s",
            lambda_version,
            lambda_arn,
            user_pool_id,
        )
    elif request_type == "Delete":
        cfg = lambda_config.get("PreTokenGenerationConfig") or {}
        changed = False
        if cfg.get("LambdaArn") == lambda_arn:
            lambda_config.pop("PreTokenGenerationConfig", None)
            changed = True
        if lambda_config.get("PreTokenGeneration") == lambda_arn:
            lambda_config.pop("PreTokenGeneration", None)
            changed = True
        if changed:
            update_kwargs["LambdaConfig"] = lambda_config
            cognito.update_user_pool(**update_kwargs)
            logger.info(
                "Detached PreTokenGenerationConfig %s from %s",
                lambda_arn,
                user_pool_id,
            )
        else:
            logger.info(
                "Trigger %s was not attached to %s on Delete; skipping UpdateUserPool",
                lambda_arn,
                user_pool_id,
            )

    return {"PhysicalResourceId": physical_id}
