"""The identity check must read the live gateway authorizer.

``deploy.sh verify`` runs ``scripts/verify.py``, which runs
``scripts/check_identity.py`` and then ``scripts/test_gateway.py`` whenever
the footprint has an auth stack and a gateway. Today the identity check
returns success after the SSM ``auth/mode`` string matches, and in direct
mode after a minted token matches the SSM issuer and audience. Neither step
calls ``GetGateway``. The gateway test then calls tools with only the
designed machine token, so an allow-list that also names another client
still looks healthy.

These tests fail while that gap is present. They pass once the live
authorizer on the gateway SSM ``gateway/url`` points at — and, when an
orchestrator runtime id is published, the live runtime authorizer — is the
design, and once the gateway call also proves a client outside that design
is rejected. A read of a different gateway, or a read that is not repeated
for the gateway script after the identity script, does not count.

Not covered here: ``use-cases/_template/verify.py`` (scaffold, not invoked)
and ``scripts/invoke.py`` ``list_tools`` / runtime invoke, which also present
only the designed token. A2A runtimes have no JWT authorizer
(``infra_utils/runtime_protocol.py``) and are out of this check.
"""

from __future__ import annotations

import importlib.util
import os
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(REPO / "scripts"))
sys.path.insert(0, str(REPO / "tests"))

os.environ["PROJECT_NAME"] = "agentcore-workshop"
os.environ["ENVIRONMENT"] = "dev"
os.environ["AWS_REGION"] = "us-east-1"
os.environ["AWS_DEFAULT_REGION"] = "us-east-1"
os.environ["AWS_EC2_METADATA_DISABLED"] = "true"
os.environ["AWS_ACCESS_KEY_ID"] = "testing"
os.environ["AWS_SECRET_ACCESS_KEY"] = "testing"
os.environ.setdefault("IDP_MODE", "brokered")

import check_identity  # noqa: E402
import test_gateway  # noqa: E402
import verify as verify_mod  # noqa: E402
from authorizer_world import (  # noqa: E402
    DECOY_GATEWAY_ID,
    LIVE_GATEWAY_ID,
    ORCHESTRATOR_RUNTIME_ID,
    STATE_ENV,
    AuthorizerWorld,
    dump,
)

PRELOAD = REPO / "tests" / "authorizer_preload"


def exit_code(fn) -> int | str:
    try:
        rc = fn()
    except SystemExit as exc:
        rc = exc.code
    return 0 if rc is None else rc


@pytest.fixture
def world():
    installed: list[AuthorizerWorld] = []

    def start(**kwargs) -> AuthorizerWorld:
        item = AuthorizerWorld(**kwargs)
        item.install()
        installed.append(item)
        return item

    yield start
    for item in installed:
        item.restore()


def _identity(mode: str) -> int | str:
    os.environ["IDP_MODE"] = mode
    return exit_code(check_identity.main)


def _gateway() -> int | str:
    sys.argv = ["test_gateway.py"]
    return exit_code(test_gateway.main)


def test_brokered_identity_rejects_an_added_gateway_client(world):
    """SSM mode matches. The live gateway still lists the designed clients
    and also an added one. ListGateways offers a decoy whose authorizer
    matches the design first."""
    item = world(mode="brokered", gateway_divergence="client")
    rc = _identity("brokered")
    assert rc != 0
    assert LIVE_GATEWAY_ID in item.get_gateway_ids
    assert item.get_gateway_ids != [DECOY_GATEWAY_ID]


def test_brokered_identity_rejects_a_replaced_discovery_url(world):
    item = world(mode="brokered", gateway_divergence="discovery")
    assert _identity("brokered") != 0
    assert LIVE_GATEWAY_ID in item.get_gateway_ids


def test_direct_identity_rejects_an_added_audience(world):
    """The minted token still matches the SSM issuer and audience. The live
    authorizer's audience list also names another audience."""
    item = world(mode="direct", gateway_divergence="audience")
    rc = _identity("direct")
    assert rc != 0
    assert LIVE_GATEWAY_ID in item.get_gateway_ids


def test_direct_identity_rejects_an_added_client_list(world):
    item = world(mode="direct", gateway_divergence="direct-client")
    assert _identity("direct") != 0
    assert LIVE_GATEWAY_ID in item.get_gateway_ids


def test_direct_identity_rejects_a_replaced_discovery_url(world):
    item = world(mode="direct", gateway_divergence="discovery")
    assert _identity("direct") != 0
    assert LIVE_GATEWAY_ID in item.get_gateway_ids


def test_identity_rejects_a_divergent_orchestrator_authorizer(world):
    """The gateway matches. The orchestrator runtime published in SSM does
    not. A2A runtimes are not part of this assertion."""
    item = world(
        mode="brokered",
        include_runtime=True,
        runtime_divergence="client",
    )
    rc = _identity("brokered")
    assert rc != 0
    assert ORCHESTRATOR_RUNTIME_ID in item.get_runtime_ids
    assert LIVE_GATEWAY_ID in item.get_gateway_ids


def test_matching_authorizer_is_accepted_only_after_the_live_gateway_is_read(world):
    item = world(mode="brokered", include_runtime=True)
    assert _identity("brokered") == 0
    assert LIVE_GATEWAY_ID in item.get_gateway_ids
    assert ORCHESTRATOR_RUNTIME_ID in item.get_runtime_ids


def test_direct_matching_authorizer_keeps_the_token_mint(world):
    """The SSM token comparison stays. It is not a substitute for GetGateway."""
    item = world(mode="direct", include_runtime=True)
    assert _identity("direct") == 0
    assert LIVE_GATEWAY_ID in item.get_gateway_ids
    assert ORCHESTRATOR_RUNTIME_ID in item.get_runtime_ids


def test_gateway_test_fails_when_the_live_allow_list_has_an_extra_client(world):
    item = world(mode="brokered", gateway_divergence="client")
    assert _gateway() != 0
    assert LIVE_GATEWAY_ID in item.get_gateway_ids
    assert any(
        exchange["claims"].get("client_id") == "designed-m2m-client"
        and exchange["status"] == 200
        for exchange in item.http_exchanges
    )


def test_direct_gateway_test_fails_when_the_audience_list_grew(world):
    item = world(mode="direct", gateway_divergence="audience")
    os.environ["IDP_MODE"] = "direct"
    assert _gateway() != 0
    assert LIVE_GATEWAY_ID in item.get_gateway_ids


def test_gateway_test_proves_a_client_outside_the_design_is_rejected(world):
    """GetGateway reports the design, and the endpoint enforces it. The
    gateway script still has to present a token the design does not name and
    observe the rejection. Sending only the designed machine token is not
    that proof."""
    item = world(mode="brokered")
    assert _gateway() == 0
    assert item.rejected_outside_probe()
    assert not item.accepted_outside_probe()


def test_gateway_test_fails_when_the_endpoint_accepts_a_client_getgateway_does_not_name(
    world,
):
    """The control-plane read and the gateway the script calls disagree.
    Looking the authorizer up once, then calling tools with the designed
    token, reports success while a client outside the design is accepted."""
    item = world(mode="brokered", open_enforcement=True)
    assert _gateway() != 0
    assert item.accepted_outside_probe()
    assert LIVE_GATEWAY_ID in item.get_gateway_ids


def _hello_platform_verify():
    path = REPO / "use-cases" / "hello-platform" / "verify.py"
    spec = importlib.util.spec_from_file_location("hello_platform_verify", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_hello_platform_verify_fails_when_an_extra_client_is_accepted(world):
    hello = _hello_platform_verify()
    item = world(mode="brokered", gateway_divergence="client")
    os.environ["IDP_MODE"] = "brokered"
    rc = exit_code(hello.main)
    assert rc != 0
    assert LIVE_GATEWAY_ID in item.get_gateway_ids or item.accepted_outside_probe()


def test_verify_does_not_stay_green_when_the_gateway_changes_after_identity(
    world, tmp_path, monkeypatch
):
    """Identity runs first, against the design authorizer. The gateway script
    then sees an added client on the same gateway URL. Success from the
    earlier read must not carry the footprint."""
    item = AuthorizerWorld(
        mode="brokered",
        gateway_divergence="client",
        diverge_for_scripts=("test_gateway.py",),
    )
    state = tmp_path / "world.json"
    dump(item, state)
    monkeypatch.setenv(STATE_ENV, str(state))
    monkeypatch.setenv("IDP_MODE", "brokered")
    monkeypatch.setenv(
        "PYTHONPATH",
        os.pathsep.join([str(PRELOAD), str(REPO / "tests"), os.environ.get("PYTHONPATH", "")]),
    )
    # Parent process: STS for verify.main. Children load the same world via
    # sitecustomize and do not share this object.
    parent = world(mode="brokered")

    def only_the_authorizer_scripts(*args, **kwargs):
        return [
            ("identity", ["check_identity.py"]),
            ("gateway", ["test_gateway.py"]),
        ]

    monkeypatch.setattr(verify_mod, "checks_for", only_the_authorizer_scripts)
    rc = verify_mod.main()
    assert rc != 0
    assert parent.get_gateway_ids == []
