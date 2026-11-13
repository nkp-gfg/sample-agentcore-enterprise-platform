# Adapted from fullstack-solution-template-for-agentcore
"""
SSM Parameter Store utilities for agent patterns.

Provides a single shared function for fetching parameters from AWS SSM
Parameter Store, used by agents to retrieve configuration values like
Gateway URLs that are set during deployment.
"""

import logging

import boto3

from shared.region import runtime_region

logger = logging.getLogger(__name__)


def get_ssm_parameter(parameter_name: str) -> str:
    """
    Fetch a parameter value from AWS SSM Parameter Store.

    SSM Parameter Store is AWS's service for storing configuration values
    securely. This function retrieves values like Gateway URLs and other
    stack-specific configuration that are set during CDK deployment.

    Args:
        parameter_name (str): The full SSM parameter name/path
            (e.g. '/{project}/{environment}/gateway/url').

    Returns:
        str: The parameter value.

    Raises:
        ValueError: If the parameter is not found or cannot be retrieved.
    """
    ssm = boto3.client("ssm", region_name=runtime_region())
    try:
        response = ssm.get_parameter(Name=parameter_name)
        return response["Parameter"]["Value"]
    except ssm.exceptions.ParameterNotFound:
        raise ValueError(f"SSM parameter not found: {parameter_name}")
    except Exception as e:  # noqa: BLE001 — wrap any retrieval failure in ValueError
        raise ValueError(f"Failed to retrieve SSM parameter {parameter_name}: {e}")
