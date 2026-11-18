"""CI must not execute a newer signed hashicorp/aws build.

The org-guardrails module constrains hashicorp/aws to >= 5.0 and ships no
dependency lock file. The Control Library workflow and the GitLab terraform
job both run terraform init and terraform validate. These tests stand in for
registry.terraform.io with the provider-registry protocol Terraform actually
uses, publish a benign 5.0.0 build and a signed 5.99.0 build, and run the
init/validate commands those jobs contain.

They fail while init selects 5.99.0 and validate starts that plugin. They pass
once the module pins one exact provider version, .terraform.lock.hcl records
that selection with package hashes, and both jobs run
`terraform init -lockfile=readonly`, so 5.99.0 is not started.
"""

from __future__ import annotations

import hashlib
import json
import os
import platform
import re
import shutil
import stat
import subprocess
import textwrap
import threading
import zipfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.request import urlopen

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
GITHUB_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "control-library.yml"
GITLAB_CI = REPO_ROOT / ".gitlab-ci.yml"
MODULE_RELATIVE = Path("control-library/terraform/org-guardrails")

BENIGN_VERSION = "5.0.0"
ATTACK_VERSION = "5.99.0"
MARKER_ENV = "TF_PROVIDER_ATTACK_MARKER"

_TERRAFORM_BINARIES: dict[str, Path] = {}
_RELEASE_INDEX: dict | None = None


def _os_arch() -> tuple[str, str]:
    system = platform.system().lower()
    machine = platform.machine().lower()
    os_name = {"linux": "linux", "darwin": "darwin"}.get(system)
    arch = {"x86_64": "amd64", "amd64": "amd64", "aarch64": "arm64", "arm64": "arm64"}.get(machine)
    if os_name is None or arch is None:
        raise RuntimeError(f"unsupported platform {system} {machine}")
    return os_name, arch


def _release_index() -> dict:
    global _RELEASE_INDEX
    if _RELEASE_INDEX is None:
        with urlopen("https://releases.hashicorp.com/terraform/index.json", timeout=60) as response:
            _RELEASE_INDEX = json.load(response)
    return _RELEASE_INDEX


def _version_key(version: str) -> tuple:
    parts = []
    for piece in version.split("."):
        number = ""
        for character in piece:
            if character.isdigit():
                number += character
            else:
                break
        parts.append(int(number or "0"))
    return tuple(parts)


def _highest_version(predicate) -> str:
    matches = [version for version in _release_index()["versions"] if predicate(version)]
    if not matches:
        raise RuntimeError("no terraform release matched the CI version selector")
    return max(matches, key=_version_key)


def _terraform_binary(version: str) -> Path:
    cached = _TERRAFORM_BINARIES.get(version)
    if cached is not None:
        return cached
    os_name, arch = _os_arch()
    builds = _release_index()["versions"][version]["builds"]
    url = next(build["url"] for build in builds if build["os"] == os_name and build["arch"] == arch)
    destination_dir = Path("/tmp/terraform-provider-pin-test") / version
    binary = destination_dir / "terraform"
    if not binary.exists():
        destination_dir.mkdir(parents=True, exist_ok=True)
        archive = destination_dir / "terraform.zip"
        with urlopen(url, timeout=120) as response, archive.open("wb") as handle:
            shutil.copyfileobj(response, handle)
        with zipfile.ZipFile(archive) as zipped:
            zipped.extract("terraform", destination_dir)
        binary.chmod(binary.stat().st_mode | stat.S_IEXEC)
    _TERRAFORM_BINARIES[version] = binary
    return binary


def _github_terraform_version() -> str:
    document = yaml.safe_load(GITHUB_WORKFLOW.read_text())
    job = document["jobs"]["validate-terraform"]
    for step in job["steps"]:
        if step.get("uses", "").startswith("hashicorp/setup-terraform@"):
            requested = (step.get("with") or {}).get("terraform_version", "latest")
            if requested in (None, "latest"):
                return _highest_version(lambda version: True)
            return requested
    raise AssertionError("validate-terraform does not install Terraform")


def _gitlab_terraform_version() -> str:
    document = yaml.safe_load(GITLAB_CI.read_text())
    image = document["terraform"]["image"]["name"]
    tag = image.rsplit(":", 1)[-1]
    return _highest_version(lambda version: version == tag or version.startswith(tag + "."))


def _github_commands() -> list[tuple[str | None, str]]:
    document = yaml.safe_load(GITHUB_WORKFLOW.read_text())
    commands = []
    for step in document["jobs"]["validate-terraform"]["steps"]:
        run = step.get("run")
        if not run:
            continue
        working_directory = step.get("working-directory")
        for line in run.splitlines():
            stripped = line.strip()
            if stripped.startswith("terraform ") and any(flag in stripped.split() for flag in ("init", "validate")):
                commands.append((working_directory, stripped))
    if not commands:
        raise AssertionError("validate-terraform has no terraform init/validate command")
    return commands


def _gitlab_commands() -> list[tuple[str | None, str]]:
    document = yaml.safe_load(GITLAB_CI.read_text())
    commands = []
    for line in document["terraform"]["script"]:
        stripped = line.strip()
        if "org-guardrails" in stripped and any(flag in stripped.split() for flag in ("init", "validate")):
            commands.append((None, stripped))
    if not commands:
        raise AssertionError("GitLab terraform job has no org-guardrails init/validate command")
    return commands


def _provider_zip(version: str, record_execution: bool) -> bytes:
    if record_execution:
        script = textwrap.dedent(
            f"""\
            #!/bin/sh
            if [ -n "${MARKER_ENV}" ]; then
              printf '%s\\n' '{version}' > "${MARKER_ENV}"
            fi
            exit 0
            """
        )
    else:
        script = "#!/bin/sh\nexit 0\n"
    from io import BytesIO

    buffer = BytesIO()
    info = zipfile.ZipInfo("terraform-provider-aws")
    info.external_attr = 0o100755 << 16
    info.create_system = 3
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr(info, script)
    return buffer.getvalue()


def _signing_key(gpg_home: Path) -> str:
    gpg_home.mkdir(mode=0o700, parents=True, exist_ok=True)
    environment = os.environ.copy()
    environment["GNUPGHOME"] = str(gpg_home)
    batch = textwrap.dedent(
        """\
        %no-protection
        Key-Type: RSA
        Key-Length: 2048
        Key-Usage: sign
        Name-Real: Registry Test
        Name-Email: registry-test@example.com
        Expire-Date: 0
        %commit
        """
    )
    subprocess.run(
        ["gpg", "--batch", "--gen-key"],
        input=batch,
        text=True,
        check=True,
        env=environment,
        capture_output=True,
    )
    exported = subprocess.run(
        ["gpg", "--armor", "--export", "registry-test@example.com"],
        check=True,
        env=environment,
        capture_output=True,
        text=True,
    )
    return exported.stdout


def _sign(gpg_home: Path, document: bytes) -> bytes:
    environment = os.environ.copy()
    environment["GNUPGHOME"] = str(gpg_home)
    completed = subprocess.run(
        [
            "gpg",
            "--batch",
            "--local-user",
            "registry-test@example.com",
            "--detach-sign",
            "--output",
            "-",
        ],
        input=document,
        check=True,
        env=environment,
        capture_output=True,
    )
    return completed.stdout


class _Registry:
    def __init__(self, packages: dict[str, dict[str, bytes | str]]):
        self.packages = packages
        registry = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):  # noqa: N802 - stdlib handler name
                path = self.path.split("?", 1)[0]
                body = registry._body_for(path)
                if body is None:
                    self.send_response(404)
                    self.end_headers()
                    self.wfile.write(b"not found")
                    return
                content_type = "application/json" if path.endswith("/versions") or "/download/" in path else "application/octet-stream"
                self.send_response(200)
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, format, *args):  # noqa: A002 - stdlib signature
                return

        self._httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.base = f"http://127.0.0.1:{self._httpd.server_address[1]}"
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)
        self._thread.start()

    def _body_for(self, path: str) -> bytes | None:
        if path == "/v1/providers/hashicorp/aws/versions":
            versions = []
            for version in sorted(self.packages, key=_version_key):
                versions.append(
                    {
                        "version": version,
                        "protocols": ["5.0"],
                        "platforms": [{"os": _os_arch()[0], "arch": _os_arch()[1]}],
                    }
                )
            return json.dumps({"versions": versions}).encode()
        prefix = "/v1/providers/hashicorp/aws/"
        marker = "/download/"
        if path.startswith(prefix) and marker in path:
            version, _, platform_path = path[len(prefix) :].partition(marker)
            os_name, _, arch = platform_path.partition("/")
            package = self.packages.get(version)
            if package is None or (os_name, arch) != _os_arch():
                return None
            filename = package["filename"]
            payload = {
                "protocols": ["5.0"],
                "os": os_name,
                "arch": arch,
                "filename": filename,
                "download_url": f"{self.base}/artifacts/{filename}",
                "shasum": package["shasum"],
                "shasums_url": f"{self.base}/artifacts/{version}.SHA256SUMS",
                "shasums_signature_url": f"{self.base}/artifacts/{version}.SHA256SUMS.sig",
                "signing_keys": {"gpg_public_keys": [{"ascii_armor": package["public_key"], "trust_signature": ""}]},
            }
            return json.dumps(payload).encode()
        artifact_prefix = "/artifacts/"
        if path.startswith(artifact_prefix):
            name = path[len(artifact_prefix) :]
            for package in self.packages.values():
                if name == package["filename"]:
                    return package["zip"]
                if name == f"{package['version']}.SHA256SUMS":
                    return package["sums"]
                if name == f"{package['version']}.SHA256SUMS.sig":
                    return package["signature"]
        return None

    def close(self):
        self._httpd.shutdown()
        self._httpd.server_close()


@pytest.fixture(scope="module")
def registry(tmp_path_factory):
    gpg_home = tmp_path_factory.mktemp("gnupg")
    public_key = _signing_key(gpg_home)
    os_name, arch = _os_arch()
    packages = {}
    for version, record_execution in ((BENIGN_VERSION, False), (ATTACK_VERSION, True)):
        payload = _provider_zip(version, record_execution)
        filename = f"terraform-provider-aws_{version}_{os_name}_{arch}.zip"
        digest = hashlib.sha256(payload).hexdigest()
        sums = f"{digest}  {filename}\n".encode()
        packages[version] = {
            "version": version,
            "filename": filename,
            "zip": payload,
            "shasum": digest,
            "sums": sums,
            "signature": _sign(gpg_home, sums),
            "public_key": public_key,
        }
    server = _Registry(packages)
    yield server
    server.close()


def _cli_config(base_url: str, directory: Path) -> Path:
    path = directory / "terraform.rc"
    path.write_text(
        textwrap.dedent(
            f"""\
            host "registry.terraform.io" {{
              services = {{
                "providers.v1" = "{base_url}/v1/providers/"
              }}
            }}
            """
        )
    )
    return path


def _run_commands(commands: list[tuple[str | None, str]], terraform: Path, worktree: Path, marker: Path, registry: _Registry) -> subprocess.CompletedProcess:
    home = worktree / "home"
    home.mkdir()
    lines = ["set -euo pipefail"]
    for working_directory, command in commands:
        if working_directory:
            lines.append(f"cd {shlex_quote(str(worktree / working_directory))}")
        lines.append(command)
    environment = os.environ.copy()
    environment["PATH"] = str(terraform.parent) + os.pathsep + environment.get("PATH", "")
    environment["HOME"] = str(home)
    environment["TF_CLI_CONFIG_FILE"] = str(_cli_config(registry.base, worktree))
    environment[MARKER_ENV] = str(marker)
    environment["CHECKPOINT_DISABLE"] = "1"
    environment["TF_IN_AUTOMATION"] = "1"
    environment.pop("TF_PLUGIN_CACHE_DIR", None)
    environment.pop("TF_PLUGIN_CACHE_MAY_BREAK_DEPENDENCY_LOCK_FILE", None)
    return subprocess.run(
        ["bash", "-c", "\n".join(lines)],
        cwd=worktree,
        env=environment,
        text=True,
        capture_output=True,
        timeout=180,
    )


def shlex_quote(value: str) -> str:
    return "'" + value.replace("'", "'\\''") + "'"


def _copy_module(destination: Path) -> None:
    source = REPO_ROOT / "control-library"
    target = destination / "control-library"
    shutil.copytree(source, target, ignore=shutil.ignore_patterns(".terraform"))


def _force_unpinned_constraint(worktree: Path) -> None:
    versions = worktree / MODULE_RELATIVE / "versions.tf"
    versions.write_text(
        textwrap.dedent(
            """\
            terraform {
              required_version = ">= 1.3.0"

              required_providers {
                aws = {
                  source  = "hashicorp/aws"
                  version = ">= 5.0"
                }
              }
            }
            """
        )
    )
    lock = worktree / MODULE_RELATIVE / ".terraform.lock.hcl"
    if lock.exists():
        lock.unlink()


def _assert_attack_executed(result: subprocess.CompletedProcess, marker: Path) -> None:
    details = f"exit={result.returncode}\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}"
    if not marker.exists():
        raise AssertionError(
            "the stand-in registry's signed hashicorp/aws "
            f"{ATTACK_VERSION} build did not run under an unpinned >= 5.0 constraint, "
            "so this test cannot tell a fix from a broken registry.\n"
            + details
        )


def _assert_provider_is_pinned(init_commands: list[str]) -> None:
    versions = (REPO_ROOT / MODULE_RELATIVE / "versions.tf").read_text()
    match = re.search(r'source\s*=\s*"hashicorp/aws"(?P<body>.*?)\n\s*\}', versions, re.S)
    if match is None:
        raise AssertionError("versions.tf does not require hashicorp/aws")
    version_match = re.search(r'version\s*=\s*"(?P<constraint>[^"]+)"', match.group("body"))
    if version_match is None:
        raise AssertionError("hashicorp/aws has no version constraint")
    constraint = version_match.group("constraint").strip()
    if re.fullmatch(r"=?\s*\d+\.\d+\.\d+", constraint) is None:
        raise AssertionError(
            f"hashicorp/aws version constraint {constraint!r} is not an exact version"
        )
    pinned = constraint.lstrip("= ").strip()
    lock_path = REPO_ROOT / MODULE_RELATIVE / ".terraform.lock.hcl"
    if not lock_path.is_file():
        raise AssertionError(f"missing dependency lock file {lock_path.relative_to(REPO_ROOT)}")
    lock_text = lock_path.read_text()
    if "registry.terraform.io/hashicorp/aws" not in lock_text:
        raise AssertionError("lock file does not record registry.terraform.io/hashicorp/aws")
    if re.search(rf'version\s+=\s+"{re.escape(pinned)}"', lock_text) is None:
        raise AssertionError(f"lock file does not pin hashicorp/aws {pinned}")
    if not re.search(r'"(?:h1|zh):[^"]+"', lock_text):
        raise AssertionError("lock file has no provider package hash")
    for command in init_commands:
        if "init" in command.split() and "-lockfile=readonly" not in command:
            raise AssertionError(f"terraform init is missing -lockfile=readonly: {command}")


def _assert_attack_not_executed(result: subprocess.CompletedProcess, marker: Path) -> None:
    if marker.exists():
        observed = marker.read_text().strip()
        raise AssertionError(
            "CI terraform init/validate executed signed hashicorp/aws "
            f"{observed}, which satisfies >= 5.0 and is not the pinned build.\n"
            f"exit={result.returncode}\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}"
        )


def _exercise(commands, terraform_version: str, registry: _Registry, tmp_path: Path, pinned_tree: bool) -> tuple[subprocess.CompletedProcess, Path]:
    worktree = tmp_path / ("product" if pinned_tree else "unpinned")
    worktree.mkdir()
    _copy_module(worktree)
    if not pinned_tree:
        _force_unpinned_constraint(worktree)
    marker = tmp_path / ("product-marker" if pinned_tree else "unpinned-marker")
    result = _run_commands(commands, _terraform_binary(terraform_version), worktree, marker, registry)
    return result, marker


# These commands are the vulnerable shape of the CI jobs: init without a
# read-only lock file, then validate. The harness always uses them so it still
# proves this Terraform executes a signed newer provider when the constraint
# allows it, including after the workflows themselves gain -lockfile=readonly.
_HARNESS_COMMANDS = [
    (str(MODULE_RELATIVE), "terraform init -backend=false -input=false"),
    (str(MODULE_RELATIVE), "terraform validate"),
]


def test_github_control_library_job_does_not_run_newer_signed_aws_provider(registry, tmp_path):
    commands = _github_commands()
    version = _github_terraform_version()
    unpinned_result, unpinned_marker = _exercise(_HARNESS_COMMANDS, version, registry, tmp_path, pinned_tree=False)
    _assert_attack_executed(unpinned_result, unpinned_marker)
    product_result, product_marker = _exercise(commands, version, registry, tmp_path, pinned_tree=True)
    _assert_attack_not_executed(product_result, product_marker)
    _assert_provider_is_pinned([command for _, command in commands])


def test_gitlab_terraform_job_does_not_run_newer_signed_aws_provider(registry, tmp_path):
    commands = _gitlab_commands()
    version = _gitlab_terraform_version()
    unpinned_result, unpinned_marker = _exercise(_HARNESS_COMMANDS, version, registry, tmp_path, pinned_tree=False)
    _assert_attack_executed(unpinned_result, unpinned_marker)
    product_result, product_marker = _exercise(commands, version, registry, tmp_path, pinned_tree=True)
    _assert_attack_not_executed(product_result, product_marker)
    _assert_provider_is_pinned([command for _, command in commands])
