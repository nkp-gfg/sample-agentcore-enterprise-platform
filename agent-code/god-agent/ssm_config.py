"""Startup-time SSM lookups for the god-agent runtime.

The six SSM parameters this pattern reads are documented in
`docs/hr/modules.md` § SSM interface and in `custom-app-plan/god-agent.md`.
Four are process-lifetime constants (endpoint, checkpoint database, master
secret, gateway URL, gateway credential provider). The fifth is the HR kill
switch, which we re-read on every invocation with a 30-second cache so an
operator can pause the assistant without a redeploy.

Nothing here parses an untrusted string into a model message. Values travel
only to boto3, psycopg, or the gateway credential provider.
"""

from __future__ import annotations

import logging
import os
import time
from dataclasses import dataclass

from shared.ssm import get_ssm_parameter

logger = logging.getLogger(__name__)


# Required SSM parameters, keyed by the role each one fills in the agent.
# Paths follow `/{project}/{environment}/<use-case-or-shared>/<name>` — the
# same convention `agent-code/agui-langgraph-agent/tools/gateway.py` uses.
_HR_DATA_ENDPOINT = "use-cases/hr-data/endpoint"
_HR_DATA_CHECKPOINT_DATABASE = "use-cases/hr-data/checkpoint-database"
_HR_DATA_SECRET_NAME = "use-cases/hr-data/secret-name"
_HR_TOOLS_ENABLED = "use-cases/hr-tools/enabled"

# Kill-switch cache. 30 s matches the H4 acceptance ("set `enabled` to `false`
# and every tool returns `SERVICE_DISABLED` within 30 seconds") — the longest
# a stale cache may delay the switch.
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
    """Connection shape for the Aurora cluster H1 provisions.

    `endpoint` is the writer endpoint published to SSM. `checkpoint_database`
    is the empty database H1 creates for the layer-2 checkpointer. The master
    secret name is used ONLY to bootstrap the checkpoint tables via
    `PostgresSaver.setup()`; the agent then operates as `agent_checkpoint`,
    which is the role `docs/hr/modules.md` § Database roles names for this
    runtime. See `custom-app-plan/god-agent.md` § Checkpointer.
    """

    endpoint: str
    checkpoint_database: str
    master_secret_name: str


@dataclass(frozen=True)
class GatewayConfig:
    """How the leaves reach the gateway and ask for per-leaf tokens."""

    url: str
    credential_provider_name: str


class _CachedConfig:
    """Lazy, process-lifetime cache for the four startup SSM parameters.

    SSM calls fail-fast rather than silently default: we want a redeploy to
    notice a missing parameter at boot, not a tool call at 3 am.
    """

    def __init__(self) -> None:
        self._hr_data: HrDataConfig | None = None
        self._gateway: GatewayConfig | None = None

    def hr_data(self) -> HrDataConfig:
        if self._hr_data is None:
            self._hr_data = HrDataConfig(
                endpoint=get_ssm_parameter(_full_path(_HR_DATA_ENDPOINT)),
                checkpoint_database=get_ssm_parameter(
                    _full_path(_HR_DATA_CHECKPOINT_DATABASE)
                ),
                master_secret_name=get_ssm_parameter(_full_path(_HR_DATA_SECRET_NAME)),
            )
        return self._hr_data

    def gateway(self) -> GatewayConfig:
        if self._gateway is None:
            # GATEWAY_URL and GATEWAY_CREDENTIAL_PROVIDER_NAME are the names
            # RuntimeStack already injects for the other patterns, so the
            # runtime has them without an SSM call. SSM is the documented
            # fallback for operators who know the convention.
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


_CACHE = _CachedConfig()


def hr_data_config() -> HrDataConfig:
    return _CACHE.hr_data()


def gateway_config() -> GatewayConfig:
    return _CACHE.gateway()


# ── Kill switch ─────────────────────────────────────────────────────────────


class _KillSwitchState:
    """30-second cache for `use-cases/hr-tools/enabled`.

    An operator sets the value to something other than "true" to pause the
    assistant. The god agent re-reads the parameter on every invocation but
    never more than once every 30 seconds, matching the H4 acceptance window.
    """

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
                # A deleted parameter is `SERVICE_DISABLED`, not an allow
                # (H4 acceptance: "`enabled` parameter deleted" → disabled).
                logger.warning(
                    "[KILL-SWITCH] could not read %s: %s — treating as disabled",
                    _HR_TOOLS_ENABLED,
                    exc,
                )
            self._value = raw.strip().lower() == "true"
            self._expires_at = current + _KILL_SWITCH_TTL_SECONDS
        return self._value

    def invalidate(self) -> None:
        """Test hook: drop the cached value so the next check hits SSM."""

        self._value = None
        self._expires_at = 0.0


_KILL_SWITCH = _KillSwitchState()


def hr_tools_enabled() -> bool:
    return _KILL_SWITCH.is_enabled()


def _reset_caches_for_tests() -> None:
    """Drop every cache. Test-only helper, not called from production paths."""

    _CACHE._hr_data = None
    _CACHE._gateway = None
    _KILL_SWITCH.invalidate()
