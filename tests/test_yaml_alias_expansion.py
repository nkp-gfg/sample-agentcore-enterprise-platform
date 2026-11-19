"""Refuse YAML aliases and oversized contract documents before PyYAML expands them.

These tests fail while the deployment-contract loaders still call
``yaml.safe_load`` with no alias or size guard. They pass once every entry
point below refuses the document before PyYAML builds the expanded graph.

A file of a few hundred bytes whose nested merge aliases point at one mapping
is enough: PyYAML 6.0.3 copies those pairs in ``SafeConstructor.flatten_mapping``
until a depth-7 document no longer fits in a few hundred megabytes. One more
level is larger than a GitHub-hosted ``ubuntu-latest`` runner. The same
``safe_load`` is what ``scripts/check-contract.sh`` runs on every
``presets/*.yaml`` and ``tests/fixtures/contract/*.yaml``, and what
``load_platform_config`` runs again for ``--stacks``.

Refusal rules (this is the spec):

* If the document contains a YAML alias, refuse it and include ``alias`` in
  the error text. An anchor that is never referenced is not an alias.
* If the file is larger than 256 KiB (262144 bytes), refuse it and include
  ``size`` in the error text. Measure the on-disk byte length and refuse
  before parsing. An oversized document that also contains aliases must not
  be expanded and must report the size failure.

Entry points that share the rule:

* ``preset_accounts`` and ``sides_of`` in ``scripts/check-contract.sh``
* ``infra_utils.platform_config.load_platform_config``
* ``infra_utils.platform_config.discover_use_cases``
* ``infra_utils.policy_loader.load_catalog``
"""

from __future__ import annotations

import re
import resource
import subprocess
import sys
import textwrap
import time
from pathlib import Path

import pytest

from infra_utils.platform_config import load_platform_config

REPO = Path(__file__).resolve().parents[1]
SCRIPT = REPO / "scripts" / "check-contract.sh"
MAX_BYTES = 256 * 1024
ADDRESS_LIMIT = 768 * 1024 * 1024
# Depth 7 crosses the address cap in well under this; a refusal returns at once.
REFUSAL_DEADLINE_SECONDS = 5.0

ALIAS_ERROR = re.compile(r"alias", re.IGNORECASE)
SIZE_ERROR = re.compile(r"size", re.IGNORECASE)


def _nested_merge_bomb(*, depth: int = 7, fanout: int = 10, keys: int = 10) -> str:
    """Small document. Nested ``<<`` aliases make PyYAML copy mapping pairs."""
    lines = ["a0: &a0"]
    lines.extend(f"  k{i}: v" for i in range(keys))
    for level in range(1, depth + 1):
        lines.append(f"a{level}: &a{level}")
        lines.append("  <<:")
        lines.extend(f"    - *a{level - 1}" for _ in range(fanout))
    lines.append(f"root: *a{depth}")
    return "\n".join(lines) + "\n"


def _simple_alias() -> str:
    return "marker: &marker kept\ncopied: *marker\n"


def _oversized(payload: str) -> str:
    pad = "# pad\n" * ((MAX_BYTES // 6) + 8)
    text = pad + payload
    assert len(text.encode()) > MAX_BYTES
    return text


def _plain_oversized() -> str:
    text = "note: " + ("x" * (MAX_BYTES + 32)) + "\n"
    assert len(text.encode()) > MAX_BYTES
    assert "*" not in text and "&" not in text
    return text


def _shell_function(name: str) -> str:
    text = SCRIPT.read_text()
    match = re.search(rf"^{re.escape(name)}\(\) \{{.*?^\}}", text, re.M | re.S)
    if match is None:
        raise AssertionError(f"{name}() is not defined in {SCRIPT}")
    return match.group(0)


def _limit_address_space() -> None:
    resource.setrlimit(resource.RLIMIT_AS, (ADDRESS_LIMIT, ADDRESS_LIMIT))


def _run_bounded(argv: list[str], *, stdin: str | None = None) -> subprocess.CompletedProcess[str]:
    started = time.monotonic()
    completed = subprocess.run(
        argv,
        input=stdin,
        text=True,
        capture_output=True,
        cwd=REPO,
        preexec_fn=_limit_address_space,
        timeout=30,
        check=False,
    )
    completed.elapsed = time.monotonic() - started  # type: ignore[attr-defined]
    return completed


def _assert_refused(completed: subprocess.CompletedProcess[str], pattern: re.Pattern[str]) -> None:
    combined = f"{completed.stdout}\n{completed.stderr}"
    assert completed.returncode > 0, combined
    assert completed.returncode < 128, combined
    assert "MemoryError" not in combined
    assert "ACCEPTED" not in completed.stdout
    assert completed.elapsed < REFUSAL_DEADLINE_SECONDS, combined  # type: ignore[attr-defined]
    assert pattern.search(combined), combined


def _python_child(source: str, *args: str) -> subprocess.CompletedProcess[str]:
    return _run_bounded([sys.executable, "-c", textwrap.dedent(source), *args])


def _run_shell(function_name: str, *files: Path) -> subprocess.CompletedProcess[str]:
    wiring = SCRIPT.read_text()
    assert "CONFIGS=(presets/*.yaml)" in wiring
    assert 'CONFIGS+=(tests/fixtures/contract/*.yaml)' in wiring
    assert 'preset_accounts "${CONFIGS[@]}"' in wiring
    assert 'sides_of "$preset"' in wiring
    script = "\n".join(
        [
            "set -euo pipefail",
            f"PY={sys.executable}",
            _shell_function(function_name),
            function_name + ' "$@"',
        ]
    )
    return _run_bounded(["bash", "-c", script, "bash", *(str(p) for p in files)])


def _write(tmp: Path, name: str, text: str) -> Path:
    path = tmp / name
    path.write_text(text)
    return path


LOAD_CONFIG = """
    import sys
    from infra_utils.platform_config import load_platform_config
    try:
        load_platform_config(sys.argv[1])
    except MemoryError:
        sys.stderr.write("MemoryError\\n")
        raise SystemExit(2)
    print("ACCEPTED")
"""

DISCOVER = """
    import sys
    from pathlib import Path
    from infra_utils.platform_config import discover_use_cases
    try:
        discover_use_cases(Path(sys.argv[1]))
    except MemoryError:
        sys.stderr.write("MemoryError\\n")
        raise SystemExit(2)
    print("ACCEPTED")
"""

CATALOG = """
    import sys
    from infra_utils.policy_loader import load_catalog
    try:
        load_catalog(sys.argv[1])
    except MemoryError:
        sys.stderr.write("MemoryError\\n")
        raise SystemExit(2)
    print("ACCEPTED")
"""


def test_shipped_greenfield_preset_still_loads():
    """A preset with no aliases, under the size cap, stays valid."""
    loaded = load_platform_config(REPO / "presets" / "greenfield.yaml")
    assert loaded.project == "agentcore-workshop"


@pytest.mark.parametrize(
    "function_name",
    ["preset_accounts", "sides_of"],
)
def test_contract_shell_rejects_yaml_alias(function_name, tmp_path):
    path = _write(tmp_path, "preset.yaml", _simple_alias())
    _assert_refused(_run_shell(function_name, path), ALIAS_ERROR)


@pytest.mark.parametrize(
    "function_name",
    ["preset_accounts", "sides_of"],
)
def test_contract_shell_rejects_nested_merge_without_expanding(function_name, tmp_path):
    path = _write(tmp_path, "preset.yaml", _nested_merge_bomb())
    _assert_refused(_run_shell(function_name, path), ALIAS_ERROR)


@pytest.mark.parametrize(
    "function_name",
    ["preset_accounts", "sides_of"],
)
def test_contract_shell_rejects_oversize_preset_before_parse(function_name, tmp_path):
    path = _write(tmp_path, "preset.yaml", _oversized(_nested_merge_bomb()))
    _assert_refused(_run_shell(function_name, path), SIZE_ERROR)


@pytest.mark.parametrize(
    "function_name",
    ["preset_accounts", "sides_of"],
)
def test_contract_shell_rejects_oversize_preset_without_aliases(function_name, tmp_path):
    path = _write(tmp_path, "preset.yaml", _plain_oversized())
    _assert_refused(_run_shell(function_name, path), SIZE_ERROR)


def test_load_platform_config_rejects_yaml_alias(tmp_path):
    path = _write(tmp_path, "platform.yaml", _simple_alias())
    _assert_refused(_python_child(LOAD_CONFIG, str(path)), ALIAS_ERROR)


def test_load_platform_config_rejects_nested_merge_without_expanding(tmp_path):
    path = _write(tmp_path, "platform.yaml", _nested_merge_bomb())
    _assert_refused(_python_child(LOAD_CONFIG, str(path)), ALIAS_ERROR)


def test_load_platform_config_rejects_oversize_before_parse(tmp_path):
    path = _write(tmp_path, "platform.yaml", _oversized(_nested_merge_bomb()))
    _assert_refused(_python_child(LOAD_CONFIG, str(path)), SIZE_ERROR)


def test_load_platform_config_rejects_oversize_without_aliases(tmp_path):
    path = _write(tmp_path, "platform.yaml", _plain_oversized())
    _assert_refused(_python_child(LOAD_CONFIG, str(path)), SIZE_ERROR)


def _manifest_dir(tmp: Path, text: str) -> Path:
    case = tmp / "sample-case"
    case.mkdir()
    (case / "manifest.yaml").write_text(text)
    return tmp


def test_discover_use_cases_rejects_yaml_alias(tmp_path):
    root = _manifest_dir(tmp_path, _simple_alias())
    _assert_refused(_python_child(DISCOVER, str(root)), ALIAS_ERROR)


def test_discover_use_cases_rejects_nested_merge_without_expanding(tmp_path):
    root = _manifest_dir(tmp_path, _nested_merge_bomb())
    _assert_refused(_python_child(DISCOVER, str(root)), ALIAS_ERROR)


def test_discover_use_cases_rejects_oversize_before_parse(tmp_path):
    root = _manifest_dir(tmp_path, _oversized(_nested_merge_bomb()))
    _assert_refused(_python_child(DISCOVER, str(root)), SIZE_ERROR)


def test_discover_use_cases_rejects_oversize_without_aliases(tmp_path):
    root = _manifest_dir(tmp_path, _plain_oversized())
    _assert_refused(_python_child(DISCOVER, str(root)), SIZE_ERROR)


def _library(tmp: Path, text: str) -> Path:
    (tmp / "catalog.yaml").write_text(text)
    return tmp


def test_load_catalog_rejects_yaml_alias(tmp_path):
    root = _library(tmp_path, _simple_alias())
    _assert_refused(_python_child(CATALOG, str(root)), ALIAS_ERROR)


def test_load_catalog_rejects_nested_merge_without_expanding(tmp_path):
    root = _library(tmp_path, _nested_merge_bomb())
    _assert_refused(_python_child(CATALOG, str(root)), ALIAS_ERROR)


def test_load_catalog_rejects_oversize_before_parse(tmp_path):
    root = _library(tmp_path, _oversized(_nested_merge_bomb()))
    _assert_refused(_python_child(CATALOG, str(root)), SIZE_ERROR)


def test_load_catalog_rejects_oversize_without_aliases(tmp_path):
    root = _library(tmp_path, _plain_oversized())
    _assert_refused(_python_child(CATALOG, str(root)), SIZE_ERROR)
