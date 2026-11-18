"""Shell boundaries for scripts/check-contract.sh.

The parity script builds a CDK ``--app`` command from each preset path and,
for a federated preset, from each account id in that file. The AWS CDK CLI
runs that string with a shell. A command substitution in a preset or
contract-fixture filename must not run. A substitution in a federated
account id must not run either.

The tests copy the real script and the real platform-config loader into a
throwaway tree, install the repo's pinned CDK CLI, and invoke the script.
They do not reimplement the command construction. A marker file is the
proof a substitution ran: the assertion is that the marker was not created.
The script may still exit non-zero when synthesis has no cloud assembly.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
GREENFIELD = (REPO / "presets" / "greenfield.yaml").read_text()
FEDERATED = (REPO / "presets" / "federated.yaml").read_text()
# The same CLI pin as .github/workflows/secret-boundary.yml. contract-parity
# installs aws-cdk without a pin; this build is the one the repository names.
CDK_VERSION = "2.1135.1"


def _require_loader_imports() -> None:
    missing = []
    for name in ("yaml", "pydantic"):
        try:
            __import__(name)
        except ImportError:
            missing.append(name)
    if missing:
        pytest.fail(
            "platform_config needs "
            + " and ".join(missing)
            + " (pip install -r requirements.txt) before these tests can reach CDK"
        )


@pytest.fixture(scope="session")
def cdk_cli(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """Install aws-cdk once. Each case symlinks this node_modules into its tree."""
    _require_loader_imports()
    dest = tmp_path_factory.mktemp("aws-cdk-cli")
    subprocess.run(
        ["npm", "install", "--silent", f"aws-cdk@{CDK_VERSION}"],
        cwd=dest,
        check=True,
    )
    binary = dest / "node_modules" / ".bin" / "cdk"
    version = subprocess.run(
        [str(binary), "--version"],
        check=True,
        capture_output=True,
        text=True,
    )
    assert version.stdout.startswith(CDK_VERSION), version.stdout
    return dest / "node_modules"


def _stage(tmp_path: Path, cdk_modules: Path) -> Path:
    root = tmp_path / "repo"
    (root / "scripts").mkdir(parents=True)
    (root / "infra_utils").mkdir()
    (root / "presets").mkdir()
    shutil.copy(REPO / "scripts" / "check-contract.sh", root / "scripts" / "check-contract.sh")
    shutil.copy(
        REPO / "infra_utils" / "platform_config.py",
        root / "infra_utils" / "platform_config.py",
    )
    (root / "infra_utils" / "__init__.py").write_text("")
    # Synthesis itself is irrelevant. The stub only proves the app command
    # started; the marker under test is created by the shell, before Python.
    (root / "app.py").write_text("raise SystemExit(0)\n")
    (root / "node_modules").symlink_to(cdk_modules, target_is_directory=True)
    return root


def _run(root: Path) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["PY"] = "python3"
    return subprocess.run(
        ["bash", str(root / "scripts" / "check-contract.sh")],
        cwd=root,
        env=env,
        capture_output=True,
        text=True,
    )


def _payload(marker_name: str) -> str:
    # No slash: the substitution text is a single filename. No space: a
    # federated account is word-split before it is stored.
    return "$(id>" + marker_name + ")"


def test_preset_filename_substitution_does_not_run(tmp_path: Path, cdk_cli: Path) -> None:
    root = _stage(tmp_path, cdk_cli)
    marker = root / "preset-marker"
    name = _payload(marker.name) + ".yaml"
    (root / "presets" / name).write_text(GREENFIELD)

    result = _run(root)

    assert not marker.exists(), (
        "a preset filename was executed by the CDK --app shell\n"
        f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
    )


def test_contract_fixture_filename_substitution_does_not_run(
    tmp_path: Path, cdk_cli: Path
) -> None:
    root = _stage(tmp_path, cdk_cli)
    # A real preset keeps the presets glob from staying literal. An unmatched
    # presets/*.yaml aborts the script before the fixture directory is read.
    (root / "presets" / "greenfield.yaml").write_text(GREENFIELD)
    fixture_dir = root / "tests" / "fixtures" / "contract"
    fixture_dir.mkdir(parents=True)
    marker = root / "fixture-marker"
    (fixture_dir / (_payload(marker.name) + ".yaml")).write_text(GREENFIELD)

    result = _run(root)

    assert not marker.exists(), (
        "a contract-fixture filename was executed by the CDK --app shell\n"
        f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
    )


def test_federated_platform_account_substitution_does_not_run(
    tmp_path: Path, cdk_cli: Path
) -> None:
    root = _stage(tmp_path, cdk_cli)
    marker = root / "platform-account-marker"
    account = _payload(marker.name)
    preset = FEDERATED.replace('platform_account: "000000000000"', f'platform_account: "{account}"')
    (root / "presets" / "federated.yaml").write_text(preset)

    result = _run(root)

    assert not marker.exists(), (
        "deployment.platform_account was executed by the CDK --app shell\n"
        f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
    )


def test_federated_workload_account_substitution_does_not_run(
    tmp_path: Path, cdk_cli: Path
) -> None:
    root = _stage(tmp_path, cdk_cli)
    marker = root / "workload-account-marker"
    account = _payload(marker.name)
    preset = FEDERATED.replace(
        'workload_accounts: ["123456789012"]',
        f'workload_accounts: ["{account}"]',
    )
    (root / "presets" / "federated.yaml").write_text(preset)

    result = _run(root)

    assert not marker.exists(), (
        "deployment.workload_accounts was executed by the CDK --app shell\n"
        f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
    )
