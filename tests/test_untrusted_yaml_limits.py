"""Untrusted YAML loaded from a pull request must not expand aliases or grow without a bound.

The control-library workflow and the deployment-contract job both parse files a
pull request can replace. Those parsers must:

* reject YAML aliases (anchors that another node references), including nested
  merge-key aliases, and
* refuse a document larger than ``MAX_UNTRUSTED_YAML_BYTES`` before the parser
  runs.

``MAX_UNTRUSTED_YAML_BYTES`` is 65536. That is above every catalog and preset
shipped in this tree (``control-library/catalog.yaml`` is 14147 bytes; the
largest preset is under 4 KiB) and is the limit both loaders share so they
cannot drift.

A file that is over the limit and is not valid YAML must fail with an error
that is not ``yaml.YAMLError``. A parser error means the bytes were parsed
before the size check.

These tests fail while the loaders still call ``yaml.safe_load`` with no alias
or size limit.
"""

from __future__ import annotations

import importlib.util
import re
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from infra_utils.platform_config import discover_use_cases, load_platform_config
from infra_utils.policy_loader import load_catalog, load_control, load_control_text

REPO = Path(__file__).resolve().parents[1]
MAX_UNTRUSTED_YAML_BYTES = 65536

_ALIAS_RE = re.compile(r"alias", re.IGNORECASE)
_SIZE_RE = re.compile(r"byte|size|limit", re.IGNORECASE)


def _nested_merge_aliases() -> str:
    """A short document whose merge-key aliases multiply while they are parsed.

    PyYAML's SafeConstructor.flatten_mapping copies every merged pair into a new
    list. Four levels of eight aliases is 8**4 pairs from a few hundred bytes.
    One more level multiplies that by eight again. There is no cap in the loader.
    """
    lines = ["a: &a {k: v}"]
    prev = "a"
    width = 8
    for i in range(4):
        name = f"n{i}"
        refs = ", ".join([f"*{prev}"] * width)
        lines.append(f"{name}: &{name} {{<<: [{refs}]}}")
        prev = name
    lines.append(f"root: *{prev}")
    return "\n".join(lines) + "\n"


def _valid_catalog(nbytes: int) -> bytes:
    head = b'version: 1\ndescription: "'
    tail = b'"\ncontrols: []\n'
    filler = nbytes - len(head) - len(tail)
    if filler < 1:
        raise RuntimeError(f"catalog frame is larger than {nbytes} bytes")
    return head + (b"x" * filler) + tail


def _catalog_root(tmp_path: Path, contents: bytes | str) -> Path:
    root = tmp_path / "control-library"
    root.mkdir()
    data = contents.encode() if isinstance(contents, str) else contents
    (root / "catalog.yaml").write_bytes(data)
    return root


def _assert_alias_refused(exc: BaseException) -> None:
    assert _ALIAS_RE.search(str(exc)), f"alias refusal did not name aliases: {exc!r}"


def _assert_refused_for_size_before_parse(exc: BaseException) -> None:
    assert not isinstance(exc, yaml.YAMLError), (
        "over-limit file reached the YAML parser: " + str(exc)
    )
    assert _SIZE_RE.search(str(exc)), f"size refusal did not name the limit: {exc!r}"


def _install_expansion_guard(monkeypatch: pytest.MonkeyPatch) -> None:
    """Fail if merge-key aliases are copied out before the loader refuses.

    A check that runs after ``yaml.safe_load`` still builds the expanded pair
    list inside ``SafeConstructor.flatten_mapping``. Refusal has to happen
    before that copy. The guard raises ``AssertionError``, which the callers
    below do not treat as a successful alias refusal.
    """
    from yaml.constructor import SafeConstructor

    original = SafeConstructor.flatten_mapping

    def wrapped(self, node):
        original(self, node)
        if len(node.value) > 32:
            raise AssertionError(
                f"merge aliases expanded to {len(node.value)} pairs before refusal"
            )

    monkeypatch.setattr(SafeConstructor, "flatten_mapping", wrapped)


def _call_expecting_alias_refusal(fn) -> None:
    try:
        fn()
    except AssertionError:
        raise
    except Exception as exc:  # noqa: BLE001 — any refusal is checked for an alias message
        _assert_alias_refused(exc)
    else:
        pytest.fail("loader accepted a document that uses aliases")


def _load_validator():
    path = REPO / "scripts" / "validate_control_library.py"
    spec = importlib.util.spec_from_file_location(
        "validate_control_library_under_test", path
    )
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _contract_function(name: str) -> str:
    script = (REPO / "scripts" / "check-contract.sh").read_text()
    marker = f"{name}() {{"
    start = script.index(marker)
    end = script.index("\n}\n", start)
    return script[start : end + 3]


def _contract_python(name: str) -> str:
    function = _contract_function(name)
    start = function.index("<<'PYEOF'\n") + len("<<'PYEOF'\n")
    end = function.index("\nPYEOF")
    return function[start:end]


def _run_contract_function(
    name: str, args: list[str]
) -> subprocess.CompletedProcess[str]:
    quoted = " ".join(subprocess.list2cmdline([arg]) for arg in args)
    program = "\n".join(
        [
            "set -euo pipefail",
            f"PY={subprocess.list2cmdline([sys.executable])}",
            _contract_function(name),
            f"{name} {quoted}",
        ]
    )
    return subprocess.run(
        ["bash", "-c", program],
        capture_output=True,
        text=True,
        check=False,
    )


def test_shipped_catalog_is_under_the_limit_and_loads():
    """The shared limit has to sit above the catalog this tree already ships."""
    raw = (REPO / "control-library" / "catalog.yaml").read_bytes()
    assert len(raw) <= MAX_UNTRUSTED_YAML_BYTES
    catalog = load_catalog(REPO / "control-library")
    assert catalog["controls"]


def test_catalog_at_the_byte_limit_loads(tmp_path: Path):
    raw = _valid_catalog(MAX_UNTRUSTED_YAML_BYTES)
    assert len(raw) == MAX_UNTRUSTED_YAML_BYTES
    catalog = load_catalog(_catalog_root(tmp_path, raw))
    assert catalog["version"] == 1
    assert catalog["controls"] == []


def test_catalog_aliases_are_rejected(tmp_path: Path):
    root = _catalog_root(tmp_path, "version: &v 1\ndescription: *v\ncontrols: []\n")
    with pytest.raises(Exception) as exc:
        load_catalog(root)
    _assert_alias_refused(exc.value)


def test_nested_merge_key_aliases_are_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    document = _nested_merge_aliases()
    assert len(document.encode()) < MAX_UNTRUSTED_YAML_BYTES
    root = _catalog_root(tmp_path, document)
    _install_expansion_guard(monkeypatch)
    _call_expecting_alias_refusal(lambda: load_catalog(root))


def test_catalog_one_byte_over_the_limit_is_refused(tmp_path: Path):
    raw = _valid_catalog(MAX_UNTRUSTED_YAML_BYTES + 1)
    assert len(raw) == MAX_UNTRUSTED_YAML_BYTES + 1
    root = _catalog_root(tmp_path, raw)
    with pytest.raises(Exception) as exc:
        load_catalog(root)
    _assert_refused_for_size_before_parse(exc.value)


def test_over_limit_catalog_is_refused_before_the_parser_runs(tmp_path: Path):
    # The leading ':' is not valid YAML. safe_load raises yaml.YAMLError after
    # reading the whole file. A size check that runs first must not do that.
    payload = b":\n" + (b"A" * MAX_UNTRUSTED_YAML_BYTES)
    assert len(payload) > MAX_UNTRUSTED_YAML_BYTES
    root = _catalog_root(tmp_path, payload)
    with pytest.raises(Exception) as exc:
        load_catalog(root)
    _assert_refused_for_size_before_parse(exc.value)


@pytest.mark.parametrize("loader", [load_control, load_control_text])
def test_control_loaders_reject_an_alias_catalog(tmp_path: Path, loader):
    root = _catalog_root(
        tmp_path,
        "version: &v 1\ndescription: *v\ncontrols:\n  - id: example\n    file: missing.json\n",
    )
    with pytest.raises(Exception) as exc:
        loader("example", library_root=root)
    _assert_alias_refused(exc.value)


def test_validator_refuses_an_alias_catalog(tmp_path: Path):
    root = _catalog_root(tmp_path, "version: &v 1\ndescription: *v\ncontrols: []\n")
    validator = _load_validator()
    validator._LIBRARY_ROOT = root
    validator.errors.clear()
    validator.warnings.clear()
    with pytest.raises(Exception) as exc:
        validator.validate()
    _assert_alias_refused(exc.value)


def test_validator_refuses_an_over_limit_catalog_before_parse(tmp_path: Path):
    root = _catalog_root(tmp_path, b":\n" + (b"A" * MAX_UNTRUSTED_YAML_BYTES))
    validator = _load_validator()
    validator._LIBRARY_ROOT = root
    validator.errors.clear()
    validator.warnings.clear()
    with pytest.raises(Exception) as exc:
        validator.main()
    _assert_refused_for_size_before_parse(exc.value)


def test_platform_config_rejects_aliases(tmp_path: Path):
    # These values match the schema. safe_load currently returns a config.
    path = tmp_path / "platform.yaml"
    path.write_text("project: &name agentcore\nenvironment: *name\nregion: us-east-1\n")
    with pytest.raises(Exception) as exc:
        load_platform_config(path)
    _assert_alias_refused(exc.value)


def test_platform_config_rejects_nested_merge_aliases(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    path = tmp_path / "platform.yaml"
    path.write_text(_nested_merge_aliases())
    _install_expansion_guard(monkeypatch)
    _call_expecting_alias_refusal(lambda: load_platform_config(path))


def test_platform_config_one_byte_over_the_limit_is_refused(tmp_path: Path):
    path = tmp_path / "platform.yaml"
    path.write_bytes(_valid_catalog(MAX_UNTRUSTED_YAML_BYTES + 1))
    with pytest.raises(Exception) as exc:
        load_platform_config(path)
    _assert_refused_for_size_before_parse(exc.value)


def test_platform_config_over_limit_file_is_refused_before_parse(tmp_path: Path):
    path = tmp_path / "platform.yaml"
    path.write_bytes(b":\n" + (b"A" * MAX_UNTRUSTED_YAML_BYTES))
    with pytest.raises(Exception) as exc:
        load_platform_config(path)
    _assert_refused_for_size_before_parse(exc.value)


def _use_case(tmp_path: Path, contents: bytes | str) -> Path:
    folder = tmp_path / "hello-demo"
    folder.mkdir()
    data = contents.encode() if isinstance(contents, str) else contents
    (folder / "manifest.yaml").write_bytes(data)
    return tmp_path


def test_use_case_manifest_merge_aliases_are_not_expanded(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    root = _use_case(tmp_path, _nested_merge_aliases())
    _install_expansion_guard(monkeypatch)
    _call_expecting_alias_refusal(lambda: discover_use_cases(root))


def test_use_case_manifest_aliases_are_rejected(tmp_path: Path):
    root = _use_case(
        tmp_path,
        "name: &n hello-demo\nowner: *n\nsummary: demo\nstacks:\n  - uc-demo\n",
    )
    with pytest.raises(Exception) as exc:
        discover_use_cases(root)
    _assert_alias_refused(exc.value)


def test_use_case_manifest_over_limit_is_refused_before_parse(tmp_path: Path):
    root = _use_case(tmp_path, b":\n" + (b"A" * MAX_UNTRUSTED_YAML_BYTES))
    with pytest.raises(Exception) as exc:
        discover_use_cases(root)
    _assert_refused_for_size_before_parse(exc.value)


@pytest.mark.parametrize("function_name", ["preset_accounts", "sides_of"])
def test_contract_snippet_does_not_expand_merge_aliases(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, function_name: str
):
    """The Python embedded in check-contract.sh is a second parser of preset files."""
    preset = tmp_path / "preset.yaml"
    preset.write_text(_nested_merge_aliases())
    code = _contract_python(function_name)
    monkeypatch.setattr(sys, "argv", ["-", str(preset)])
    _install_expansion_guard(monkeypatch)

    def run() -> None:
        exec(compile(code, f"scripts/check-contract.sh:{function_name}", "exec"), {})  # noqa: S102

    _call_expecting_alias_refusal(run)


@pytest.mark.parametrize("function_name", ["preset_accounts", "sides_of"])
def test_contract_script_rejects_alias_presets(tmp_path: Path, function_name: str):
    preset = tmp_path / "preset.yaml"
    preset.write_text(
        "project: &name agentcore\nenvironment: *name\nregion: us-east-1\n"
    )
    result = _run_contract_function(function_name, [str(preset)])
    combined = result.stdout + result.stderr
    assert result.returncode != 0, combined
    assert _ALIAS_RE.search(combined), combined


@pytest.mark.parametrize("function_name", ["preset_accounts", "sides_of"])
def test_contract_script_rejects_over_limit_presets_before_parse(
    tmp_path: Path, function_name: str
):
    preset = tmp_path / "preset.yaml"
    preset.write_bytes(b":\n" + (b"A" * MAX_UNTRUSTED_YAML_BYTES))
    result = _run_contract_function(function_name, [str(preset)])
    combined = result.stdout + result.stderr
    assert result.returncode != 0, combined
    # A parser traceback names ParserError, ScannerError, or ComposerError.
    # The size check has to win before that, and it has to say so.
    assert "ParserError" not in combined
    assert "ScannerError" not in combined
    assert "ComposerError" not in combined
    assert _SIZE_RE.search(combined), combined
