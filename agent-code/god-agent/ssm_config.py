"""Startup-time SSM lookups for the god-agent runtime.

The SSM parameters this pattern reads are documented in
`docs/hr/modules.md` § SSM interface and `docs/PLATFORM_INTERFACE.md`.
Process-lifetime constants are cached once; the HR kill switch is re-read
with a 30-second TTL so an operator can pause the assistant without a
redeploy.
"""

from __future__ import annotations

import logging
import os
import time
from dataclasses import dataclass

from shared.ssm import get_ssm_parameter

logger = logging.getLogger(__name__)

_HR_DATA_ENDPOINT = "use-cases/hr-data/endpoint"
_HR_DATA_CHECKPOINT_DATABASE = "use-cases/hr-data/checkpoint-database"
_HR_DATA_SECRET_NAME = "use-cases/hr-data/secret-name"
_HR_TOOLS_ENABLED = "use-cases/hr-tools/enabled"

_AUTH_ISSUER_URL = "auth/issuer-url"
_AUTH_M2M_CLIENT_ID = "auth/m2m-client-id"
_AUTH_M2M_SECRET_NAME = "auth/m2m-client-secret-name"
_AUTH_M2M_SCOPE = "auth/m2m-scope"

_KILL_SWITCH_TTL_SECONDS = 30.0


def _ssm_base_path() -> str:
    project = os.environ.get("PROJECT_NAME", "").strip()
    environment = os.environ.get("ENVIRONMENT", "").strip()
    if not project or not environment:
        raise RuntimeError(
            "PROJECT_NAME and ENVIRONMENT must be set — RuntimeStack injects "
            "both into the container. Refusing to guess the SSM path."
        )
    return f"/{project}/{environment}"


def _full_path(leaf: str) -> str:
    return f"{_ssm_base_path()}/{leaf}"


@dataclass(frozen=True)
class HrDataConfig:
    """Connection shape for the Aurora cluster H1 provisions."""

    endpoint: str
    checkpoint_database: str
    master_secret_name: str = ""


@dataclass(frozen=True)
class GatewayConfig:
    """How the leaves reach the gateway."""

    url: str
    credential_provider_name: str


@dataclass(frozen=True)
class AuthM2MConfig:
    """Cognito M2M coordinates for `client_credentials` + `aws_client_metadata`."""

    issuer_url: str
    client_id: str
    client_secret_name: str
    scope: str


class _CachedConfig:
    def __init__(self) -> None:
        self._hr_data: HrDataConfig | None = None
        self._gateway: GatewayConfig | None = None
        self._auth_m2m: AuthM2MConfig | None = None

    def hr_data(self) -> HrDataConfig:
        if self._hr_data is None:
            secret_name = ""
            try:
                secret_name = get_ssm_parameter(_full_path(_HR_DATA_SECRET_NAME))
            except Exception:  # noqa: BLE001 — runtime connects via RDS IAM, not master secret
                secret_name = ""
            self._hr_data = HrDataConfig(
                endpoint=get_ssm_parameter(_full_path(_HR_DATA_ENDPOINT)),
                checkpoint_database=get_ssm_parameter(
                    _full_path(_HR_DATA_CHECKPOINT_DATABASE)
                ),
                master_secret_name=secret_name,
            )
        return self._hr_data

    def gateway(self) -> GatewayConfig:
        if self._gateway is None:
            url = os.environ.get("GATEWAY_URL", "").strip()
            if not url:
                url = get_ssm_parameter(f"{_ssm_base_path()}/gateway/url")
            provider = os.environ.get("GATEWAY_CREDENTIAL_PROVIDER_NAME", "").strip()
            if not provider:
                provider = get_ssm_parameter(
                    f"{_ssm_base_path()}/identity/gateway-credential-provider-name"
                )
            self._gateway = GatewayConfig(url=url, credential_provider_name=provider)
        return self._gateway

    def auth_m2m(self) -> AuthM2MConfig:
        if self._auth_m2m is None:
            issuer = os.environ.get("COGNITO_ISSUER_URL", "").strip()
            if not issuer:
                issuer = get_ssm_parameter(_full_path(_AUTH_ISSUER_URL))
            client_id = get_ssm_parameter(_full_path(_AUTH_M2M_CLIENT_ID))
            secret_name = get_ssm_parameter(_full_path(_AUTH_M2M_SECRET_NAME))
            try:
                scope = get_ssm_parameter(_full_path(_AUTH_M2M_SCOPE))
            except Exception:  # noqa: BLE001
                scope = os.environ.get("GATEWAY_TOKEN_SCOPES", "agentcore/invoke")
            self._auth_m2m = AuthM2MConfig(
                issuer_url=issuer,
                client_id=client_id,
                client_secret_name=secret_name,
                scope=scope,
            )
        return self._auth_m2m


_CACHE = _CachedConfig()


def hr_data_config() -> HrDataConfig:
    return _CACHE.hr_data()


def gateway_config() -> GatewayConfig:
    return _CACHE.gateway()


def auth_m2m_config() -> AuthM2MConfig:
    return _CACHE.auth_m2m()


class _KillSwitchState:
    def __init__(self) -> None:
        self._value: bool | None = None
        self._expires_at: float = 0.0

    def is_enabled(self, now: float | None = None) -> bool:
        current = now if now is not None else time.monotonic()
        if self._value is None or current >= self._expires_at:
            raw = ""
            try:
                raw = get_ssm_parameter(_full_path(_HR_TOOLS_ENABLED))
            except Exception as exc:  # noqa: BLE001 — a missing switch is a deny
                logger.warning(
                    "[KILL-SWITCH] could not read %s: %s — treating as disabled",
                    _HR_TOOLS_ENABLED,
                    exc,
                )
            self._value = raw.strip().lower() == "true"
            self._expires_at = current + _KILL_SWITCH_TTL_SECONDS
        return self._value

    def invalidate(self) -> None:
        self._value = None
        self._expires_at = 0.0


_KILL_SWITCH = _KillSwitchState()


def hr_tools_enabled() -> bool:
    return _KILL_SWITCH.is_enabled()


def _reset_caches_for_tests() -> None:
    _CACHE._hr_data = None
    _CACHE._gateway = None
    _CACHE._auth_m2m = None
    _KILL_SWITCH.invalidate()
