"""Untrusted YAML must not expand aliases or grow without a file-size cap.

``yaml.safe_load`` (PyYAML 6.0.3, the version ``requirements.txt`` installs)
still builds alias targets. ``Composer.compose_node`` returns the anchored
node, and ``SafeConstructor.flatten_mapping`` copies merge-key entries on
every use, so a sub-kilobyte document expands while the loader runs.
``UseCaseManifest`` validation happens after that, and a directory that does
not start with ``_`` is parsed even when ``platform.yaml`` never enables it.

Overriding ``ignore_aliases`` on a ``SafeLoader`` subclass does not stop
this. In 6.0.3 that method is only called while dumping (``representer.py``).
These tests require the load to reject the document.

Every product loader that ``safe_load``s pull-request YAML is covered:

- ``discover_use_cases`` and ``scripts/usecase.py list`` (what
  ``deploy.sh usecase`` execs, including the shell-check and pytest gates)
- ``load_platform_config``
- ``infra_utils.policy_loader.load_catalog``
- both ``yaml.safe_load`` heredocs in ``scripts/check-contract.sh``

Left untested, on purpose: ``yaml.safe_load`` inside ``tests/test_alarms.py``,
``tests/test_guardrail_enforcement.py``, ``tests/test_migration_config.py``,
and ``tests/test_platform_config.py``. Those read fixed preset paths from the
test suite. A new ``use-cases/<name>/manifest.yaml`` never reaches them.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest
import yaml

REPO = Path(__file__).resolve().parents[1]
MAX_FILE_BYTES = 64 * 1024
# Importing the config stack peaks well under this far above a normal parse,
# and well under the expansion of the merge-alias fixture below.
MEMORY_SLACK_KB = 64 * 1024

_VALID_MANIFEST = """\
name: ok-case
owner: platform
summary: A manifest with no aliases.
stacks: [uc-ok-case]
"""

_ALIAS_MANIFEST = """\
name: &n alias-case
owner: *n
summary: *n
stacks: [uc-alias-case]
"""

_VALID_PLATFORM = """\
project: demo
environment: dev
region: us-east-1
"""

_ALIAS_PLATFORM = """\
project: &p demo
environment: *p
region: us-east-1
"""

_ALIAS_CATALOG = """\
controls: &c []
copy: *c
"""


def _alias_bomb() -> str:
    """Nested merge aliases. Width 10 and depth 5 stay under 2 KiB on disk."""
    width = 10
    depth = 5
    lines = ["a: &a"]
    lines.extend(f"  k{i}: v" for i in range(width))
    prev = "a"
    for level in range(depth):
        name = chr(ord("b") + level)
        lines.append(f"{name}: &{name}")
        lines.extend(f"  <<: *{prev}" for _ in range(width))
        prev = name
    lines.append("root: &root")
    lines.extend(f"  <<: *{prev}" for _ in range(width))
    text = "\n".join(lines) + "\n"
    size = len(text.encode())
    if size > 2048:
        raise RuntimeError(f"alias fixture is {size} bytes; keep it under 2 KiB")
    return text


def _oversize_invalid_yaml() -> bytes:
    """Larger than 64 KiB and not valid YAML, so a parse-first loader errors."""
    line = b"# " + (b"A" * 80) + b"\n"
    body = b"[\n" + (line * 900)
    if len(body) <= MAX_FILE_BYTES:
        raise RuntimeError(f"oversize fixture is only {len(body)} bytes")
    return body


def _heredocs() -> list[str]:
    text = (REPO / "scripts" / "check-contract.sh").read_text()
    blocks = []
    for part in text.split("<<'PYEOF'\n")[1:]:
        blocks.append(part.split("\nPYEOF", 1)[0])
    if len(blocks) < 2:
        raise RuntimeError("check-contract.sh no longer has two YAML heredocs")
    return blocks


def _write_input(tmp_path: Path, kind: str, payload: str | bytes) -> Path:
    data = payload.encode() if isinstance(payload, str) else payload
    if kind in {"discover", "usecase-list"}:
        root = tmp_path / kind
        manifest = root / "bomb" / "manifest.yaml"
        manifest.parent.mkdir(parents=True)
        manifest.write_bytes(data)
        return root
    if kind == "catalog":
        root = tmp_path / "library"
        root.mkdir(parents=True)
        target = root / "catalog.yaml"
        target.write_bytes(data)
        return root
    target = tmp_path / "input.yaml"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(data)
    return target


def _measure(kind: str, path: Path) -> tuple[int, str, str]:
    completed = subprocess.run(
        [sys.executable, str(Path(__file__).resolve()), kind, str(path)],
        check=False,
        capture_output=True,
        text=True,
        timeout=60,
    )
    protocol: dict[str, str] = {}
    for line in completed.stderr.splitlines():
        if line.startswith(("HWM_KB=", "ERROR=")):
            key, value = line.split("=", 1)
            protocol[key] = value
    if completed.returncode != 0 or "HWM_KB" not in protocol:
        raise AssertionError(
            f"{kind} worker failed (rc={completed.returncode})\n"
            f"stdout:\n{completed.stdout}\nstderr:\n{completed.stderr}"
        )
    return int(protocol["HWM_KB"]), protocol.get("ERROR", "NONE"), completed.stdout


def _assert_bomb_is_bounded(kind: str, bomb_path: Path, baseline_path: Path) -> None:
    base_hwm, base_err, _base_out = _measure(kind, baseline_path)
    assert base_err == "NONE", f"{kind} rejected a shipped-size document: {base_err}"
    hwm, err, _out = _measure(kind, bomb_path)
    size = _payload_size(kind, bomb_path)
    assert hwm < base_hwm + MEMORY_SLACK_KB, (
        f"{kind} expanded a {size}-byte alias document to {hwm} KiB "
        f"(baseline {base_hwm} KiB). Reject aliases before the loader expands them."
    )
    assert err != "NONE", (
        f"{kind} accepted a {size}-byte alias document (peak {hwm} KiB)"
    )


def _payload_size(kind: str, path: Path) -> int:
    if kind in {"discover", "usecase-list"}:
        return (path / "bomb" / "manifest.yaml").stat().st_size
    if kind == "catalog":
        return (path / "catalog.yaml").stat().st_size
    return path.stat().st_size


def _require_rejection(action) -> None:
    try:
        action()
    except Exception:  # noqa: BLE001 — any refusal is enough; acceptance is the failure
        return
    raise AssertionError("document was accepted")


def _require_rejection_before_parse(action) -> None:
    try:
        action()
    except yaml.YAMLError as exc:
        raise AssertionError(f"file reached the YAML parser: {exc}") from exc
    except Exception:  # noqa: BLE001 — a size refusal is not a parse error
        return
    raise AssertionError("oversized file was accepted")


def test_shipped_use_case_manifest_still_loads():
    from infra_utils.platform_config import discover_use_cases

    found = discover_use_cases()
    assert "hello-platform" in found


def test_small_platform_yaml_still_loads(tmp_path: Path):
    from infra_utils.platform_config import load_platform_config

    path = tmp_path / "platform.yaml"
    path.write_text(_VALID_PLATFORM)
    config = load_platform_config(path)
    assert config.project == "demo"
    assert config.environment == "dev"


def test_shipped_catalog_still_loads():
    from infra_utils.policy_loader import load_catalog

    catalog = load_catalog(REPO / "control-library")
    assert catalog["controls"]


def test_contract_heredoc_still_reads_federated_accounts():
    preset = REPO / "presets" / "federated.yaml"
    for index, _source in enumerate(_heredocs()):
        _hwm, err, out = _measure(f"contract:{index}", preset)
        assert err == "NONE", err
        assert "000000000000" in out


def test_discover_rejects_scalar_aliases(tmp_path: Path):
    from infra_utils.platform_config import discover_use_cases

    root = tmp_path / "use-cases"
    manifest = root / "alias-case" / "manifest.yaml"
    manifest.parent.mkdir(parents=True)
    manifest.write_text(_ALIAS_MANIFEST)
    _require_rejection(lambda: discover_use_cases(root))


def test_platform_config_rejects_scalar_aliases(tmp_path: Path):
    from infra_utils.platform_config import load_platform_config

    path = tmp_path / "platform.yaml"
    path.write_text(_ALIAS_PLATFORM)
    _require_rejection(lambda: load_platform_config(path))


def test_catalog_rejects_scalar_aliases(tmp_path: Path):
    from infra_utils.policy_loader import load_catalog

    root = tmp_path / "library"
    root.mkdir()
    (root / "catalog.yaml").write_text(_ALIAS_CATALOG)
    _require_rejection(lambda: load_catalog(root))


def test_discover_rejects_oversize_file_before_parse(tmp_path: Path):
    from infra_utils.platform_config import discover_use_cases

    root = _write_input(tmp_path, "discover", _oversize_invalid_yaml())
    _require_rejection_before_parse(lambda: discover_use_cases(root))


def test_platform_config_rejects_oversize_file_before_parse(tmp_path: Path):
    from infra_utils.platform_config import load_platform_config

    path = _write_input(tmp_path, "platform", _oversize_invalid_yaml())
    _require_rejection_before_parse(lambda: load_platform_config(path))


def test_catalog_rejects_oversize_file_before_parse(tmp_path: Path):
    from infra_utils.policy_loader import load_catalog

    root = _write_input(tmp_path, "catalog", _oversize_invalid_yaml())
    _require_rejection_before_parse(lambda: load_catalog(root))


def test_contract_heredocs_reject_oversize_before_parse(tmp_path: Path):
    path = _write_input(tmp_path, "contract", _oversize_invalid_yaml())
    for source in _heredocs():
        _require_rejection_before_parse(
            lambda source=source: _exec_heredoc(source, path)
        )


@pytest.mark.parametrize(
    "kind",
    [
        "discover",
        "usecase-list",
        "platform",
        "catalog",
        "contract:0",
        "contract:1",
    ],
)
def test_merge_alias_bomb_stays_bounded(tmp_path: Path, kind: str):
    bomb = _alias_bomb()
    if kind in {"discover", "usecase-list"}:
        baseline = _write_input(tmp_path / "base", kind, _VALID_MANIFEST)
        # The valid fixture's directory name has to match the manifest name.
        written = tmp_path / "base" / kind / "bomb"
        target = written.parent / "ok-case"
        written.rename(target)
        bomb_path = _write_input(tmp_path / "bomb", kind, bomb)
    elif kind == "catalog":
        baseline = REPO / "control-library"
        bomb_path = _write_input(tmp_path / "bomb", kind, bomb)
    elif kind == "platform":
        baseline = _write_input(tmp_path / "base", kind, _VALID_PLATFORM)
        bomb_path = _write_input(tmp_path / "bomb", kind, bomb)
    else:
        baseline = REPO / "presets" / "federated.yaml"
        bomb_path = _write_input(tmp_path / "bomb", kind, bomb)
    _assert_bomb_is_bounded(kind, bomb_path, baseline)


def _exec_heredoc(source: str, path: Path) -> None:
    previous = sys.argv
    sys.argv = ["check-contract", str(path)]
    try:
        exec(compile(source, "scripts/check-contract.sh", "exec"), {})  # noqa: S102
    finally:
        sys.argv = previous


def _worker_main(kind: str, path: str) -> None:
    error = "NONE"
    try:
        _worker_dispatch(kind, path)
    except SystemExit as exc:
        if exc.code not in (0, None):
            error = "SystemExit"
    except Exception as exc:  # noqa: BLE001 — record whatever the loader raised
        error = type(exc).__name__
    hwm = 0
    for line in Path("/proc/self/status").read_text().splitlines():
        if line.startswith("VmHWM:"):
            hwm = int(line.split()[1])
    print(f"HWM_KB={hwm}", file=sys.stderr)
    print(f"ERROR={error}", file=sys.stderr)


def _worker_dispatch(kind: str, path: str) -> None:
    sys.path.insert(0, str(REPO))
    target = Path(path)
    if kind == "discover":
        from infra_utils.platform_config import discover_use_cases

        discover_use_cases(target)
        return
    if kind == "platform":
        from infra_utils.platform_config import load_platform_config

        load_platform_config(target)
        return
    if kind == "catalog":
        from infra_utils.policy_loader import load_catalog

        load_catalog(target)
        return
    if kind == "usecase-list":
        import importlib.util

        spec = importlib.util.spec_from_file_location(
            "usecase_under_test", REPO / "scripts" / "usecase.py"
        )
        module = importlib.util.module_from_spec(spec)
        assert spec.loader is not None
        spec.loader.exec_module(module)
        code = module.main(
            [
                "--use-cases-dir",
                path,
                "--manifest",
                str(REPO / "platform.yaml"),
                "list",
            ]
        )
        if code:
            raise RuntimeError(f"usecase list exited {code}")
        return
    if kind.startswith("contract:"):
        source = _heredocs()[int(kind.split(":", 1)[1])]
        _exec_heredoc(source, target)
        return
    raise RuntimeError(f"unknown worker kind {kind}")


if __name__ == "__main__":
    _worker_main(sys.argv[1], sys.argv[2])
