"""Floating CDK and Python installs in GitLab CI execute registry code.

The cdk-synth job (``.gitlab-ci.yml``) runs ``npx --yes cdk``,
``npm install -g aws-cdk``, and ``pip install -r requirements.txt`` with no
digest. The other GitLab jobs pip-install tools the same way, and
``scripts/deploy.sh`` globally installs ``aws-cdk`` the same way. These tests
replay those commands against a registry this process serves. Every version
that registry publishes runs code that records the job environment.

The tests that replay the repository's commands fail while that code runs.
They pass once those commands no longer execute a registry package whose
digest the client did not pin: either the command stops fetching the package,
or npm/pip reject the bytes before lifecycle or build code runs.

``test_client_hash_mismatch_stops_before_package_code`` is the passing
control. It uses the same registry and shows a declared digest that does not
match the published bytes stops the run before package code.

Not covered here: ``.github/workflows/`` (``.gitlab-ci.yml`` says those
workflows never ran; the remote is GitLab) and the ``pip`` / ``npm`` lines in
the docs and README, which are instructions rather than a job this repository
runs.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import textwrap
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
import yaml
from pip._vendor.packaging.requirements import Requirement
from pip._vendor.packaging.utils import canonicalize_name
from pip._vendor.packaging.version import Version

REPO_ROOT = Path(__file__).resolve().parents[1]
GITLAB_CI = REPO_ROOT / ".gitlab-ci.yml"
DEPLOY_SH = REPO_ROOT / "scripts" / "deploy.sh"
REQUIREMENTS = REPO_ROOT / "requirements.txt"

# Placeholder only. The fixture records whether the variable is set, never its
# value, and this string is not a credential.
TOKEN_PLACEHOLDER = "placeholder-not-a-secret"
CHECKOUT_MARKER = "repository-checkout"

EXACT_VERSION = re.compile(r"@(\d+\.\d+\.\d+)\b")


def _sha512_sri(data: bytes) -> str:
    digest = base64.b64encode(hashlib.sha512(data).digest()).decode()
    return f"sha512-{digest}"


def _npm_record_script(package: str) -> str:
    return textwrap.dedent(
        f"""\
        const fs = require('fs');
        const path = require('path');
        const out = process.env.SENTINEL_PATH;
        if (!out) process.exit(0);
        const dir = process.env.CI_PROJECT_DIR || '';
        let checkout = 'unread';
        try {{
          const body = fs.readFileSync(path.join(dir, 'checkout-marker.txt'), 'utf8').trim();
          checkout = body === {CHECKOUT_MARKER!r} ? 'read' : 'mismatch';
        }} catch (e) {{
          checkout = 'unread';
        }}
        const record = {{
          manager: 'npm',
          package: {package!r},
          event: process.env.npm_lifecycle_event || 'bin',
          token: process.env.CI_JOB_TOKEN ? 'present' : 'absent',
          checkout,
        }};
        fs.appendFileSync(out, JSON.stringify(record) + '\\n');
        """
    )


def _python_backend(package: str, version: str) -> str:
    dist = package.replace("-", "_")
    return textwrap.dedent(
        f"""\
        import base64, hashlib, json, os, zipfile

        NAME = {package!r}
        VERSION = {version!r}
        DIST = {dist!r}

        def _record(event):
            out = os.environ.get("SENTINEL_PATH")
            if not out:
                return
            directory = os.environ.get("CI_PROJECT_DIR", "")
            checkout = "unread"
            marker = os.path.join(directory, "checkout-marker.txt")
            try:
                body = open(marker, encoding="utf-8").read().strip()
            except OSError:
                body = None
            if body == {CHECKOUT_MARKER!r}:
                checkout = "read"
            elif body is not None:
                checkout = "mismatch"
            record = {{
                "manager": "pip",
                "package": NAME,
                "event": event,
                "token": "present" if os.environ.get("CI_JOB_TOKEN") else "absent",
                "checkout": checkout,
            }}
            with open(out, "a", encoding="utf-8") as handle:
                handle.write(json.dumps(record) + "\\n")

        _record("import")

        def get_requires_for_build_wheel(config_settings=None):
            _record("get_requires_for_build_wheel")
            return []

        def _digest(text):
            raw = hashlib.sha256(text.encode()).digest()
            return "sha256=" + base64.urlsafe_b64encode(raw).decode().rstrip("=")

        def build_wheel(wheel_directory, config_settings=None, metadata_directory=None):
            _record("build_wheel")
            info = f"{{DIST}}-{{VERSION}}.dist-info"
            metadata = f"Metadata-Version: 2.1\\nName: {{NAME}}\\nVersion: {{VERSION}}\\n"
            wheel_txt = (
                "Wheel-Version: 1.0\\nGenerator: supply-chain-fixture\\n"
                "Root-Is-Purelib: true\\nTag: py3-none-any\\n"
            )
            files = {{
                f"{{info}}/METADATA": metadata,
                f"{{info}}/WHEEL": wheel_txt,
                f"{{DIST}}/__init__.py": "",
            }}
            record_lines = [
                f"{{path}},{{_digest(content)}},{{len(content.encode())}}"
                for path, content in files.items()
            ]
            record_lines.append(f"{{info}}/RECORD,,")
            files[f"{{info}}/RECORD"] = "\\n".join(record_lines) + "\\n"
            wheel_name = f"{{DIST}}-{{VERSION}}-py3-none-any.whl"
            target = os.path.join(wheel_directory, wheel_name)
            with zipfile.ZipFile(target, "w") as archive:
                for path, content in files.items():
                    archive.writestr(path, content)
            return wheel_name
        """
    )


def _sdist(package: str, version: str) -> bytes:
    dist = package.replace("-", "_")
    root = f"{dist}-{version}"
    pyproject = (
        "[build-system]\n"
        "requires = []\n"
        'build-backend = "evil_backend"\n'
        'backend-path = ["."]\n'
    )
    blob = _tar(
        {
            f"{root}/pyproject.toml": pyproject,
            f"{root}/evil_backend.py": _python_backend(package, version),
        }
    )
    return blob


def _tar(files: dict[str, str]) -> bytes:
    from io import BytesIO

    buffer = BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
        for name, content in files.items():
            data = content.encode()
            info = tarfile.TarInfo(name)
            info.size = len(data)
            archive.addfile(info, BytesIO(data))
    return buffer.getvalue()


def _npm_tarball(package: str, version: str) -> bytes:
    script = _npm_record_script(package)
    manifest = {
        "name": package,
        "version": version,
        "bin": {"cdk": "bin/cdk.js"},
        "scripts": {
            "preinstall": "node preinstall.js",
            "install": "node install.js",
            "postinstall": "node postinstall.js",
        },
    }
    files = {
        f"package/package.json": json.dumps(manifest),
        "package/preinstall.js": script,
        "package/install.js": script,
        "package/postinstall.js": script,
        "package/bin/cdk.js": script,
    }
    return _tar(files)


class Registry(threading.Thread):
    """Local npm registry and PEP 503 index. Every published artifact runs code."""

    def __init__(self, npm_versions: dict[str, set[str]], python_versions: dict[str, set[str]]):
        super().__init__(daemon=True)
        self.npm_versions = {
            name: set(versions) or {"99.0.0"} for name, versions in npm_versions.items()
        }
        for name in ("cdk", "aws-cdk"):
            self.npm_versions.setdefault(name, set()).update({"99.0.0", "2.9999.0", "1.9999.0"})
        self.python_versions = python_versions
        self.requests: list[str] = []
        self._tarballs: dict[tuple[str, str], bytes] = {}
        self._sdists: dict[tuple[str, str], bytes] = {}
        self._lock = threading.Lock()
        self._httpd = ThreadingHTTPServer(("127.0.0.1", 0), self._handler())
        self.port = self._httpd.server_address[1]
        self.base = f"http://127.0.0.1:{self.port}"

    def _handler(self):
        registry = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, fmt: str, *args) -> None:
                return

            def do_GET(self) -> None:  # noqa: N802
                registry._get(self)

            def do_POST(self) -> None:  # noqa: N802
                registry.requests.append(f"POST {self.path}")
                body = b"{}"
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        return Handler

    def run(self) -> None:
        self._httpd.serve_forever()

    def close(self) -> None:
        self._httpd.shutdown()
        self._httpd.server_close()

    def _npm_bytes(self, package: str, version: str) -> bytes:
        key = (package, version)
        with self._lock:
            if key not in self._tarballs:
                self._tarballs[key] = _npm_tarball(package, version)
            return self._tarballs[key]

    def _sdist_bytes(self, package: str, version: str) -> bytes:
        key = (canonicalize_name(package), version)
        with self._lock:
            if key not in self._sdists:
                self._sdists[key] = _sdist(package, version)
            return self._sdists[key]

    def _send(self, handler: BaseHTTPRequestHandler, status: int, body: bytes, content_type: str) -> None:
        handler.send_response(status)
        handler.send_header("Content-Type", content_type)
        handler.send_header("Content-Length", str(len(body)))
        handler.end_headers()
        handler.wfile.write(body)

    def _get(self, handler: BaseHTTPRequestHandler) -> None:
        path = handler.path.split("?", 1)[0]
        self.requests.append(f"GET {path}")
        if path.startswith("/simple/"):
            self._simple(handler, path)
            return
        if "/-/" in path and path.endswith(".tgz"):
            package, filename = path.strip("/").split("/-/", 1)
            version = filename[len(package) + 1 : -len(".tgz")]
            # Any tarball path is the malicious release, including versions a
            # lockfile names. A client digest that does not match these bytes
            # is rejected by npm before install scripts.
            body = self._npm_bytes(package, version or "0.0.0")
            self._send(handler, 200, body, "application/octet-stream")
            return
        name = path.strip("/")
        if name in self.npm_versions:
            self._send(handler, 200, self._packument(name), "application/json")
            return
        self._send(handler, 404, b"not found", "text/plain")

    def _packument(self, name: str) -> bytes:
        versions = {}
        for version in sorted(self.npm_versions[name], key=Version):
            data = self._npm_bytes(name, version)
            versions[version] = {
                "name": name,
                "version": version,
                "bin": {"cdk": "bin/cdk.js"},
                # The registry manifest advertises install scripts. Arborist
                # runs them from this field, or reloads them from the tarball
                # when hasInstallScript is set.
                "hasInstallScript": True,
                "scripts": {
                    "preinstall": "node preinstall.js",
                    "install": "node install.js",
                    "postinstall": "node postinstall.js",
                },
                "dist": {
                    "tarball": f"{self.base}/{name}/-/{name}-{version}.tgz",
                    "integrity": _sha512_sri(data),
                    "shasum": hashlib.sha1(data).hexdigest(),
                },
            }
        # Unpinned specs resolve to this dist-tag. It is a release the
        # repository did not pin.
        latest = "99.0.0" if "99.0.0" in versions else sorted(versions, key=Version)[-1]
        packument = {"name": name, "dist-tags": {"latest": latest}, "versions": versions}
        return json.dumps(packument).encode()

    def _simple(self, handler: BaseHTTPRequestHandler, path: str) -> None:
        parts = [part for part in path.split("/") if part]
        if len(parts) == 1:
            self._send(handler, 200, b"<html><body></body></html>", "text/html")
            return
        if len(parts) == 2:
            name = canonicalize_name(parts[1])
            versions = self.python_versions.get(name, set())
            links = []
            for version in sorted(versions, key=Version):
                filename = f"{name.replace('-', '_')}-{version}.tar.gz"
                links.append(
                    f'<a href="{self.base}/simple/{name}/{filename}">{filename}</a>'
                )
            body = ("<html><body>" + "".join(links) + "</body></html>").encode()
            self._send(handler, 200, body, "text/html")
            return
        name = canonicalize_name(parts[1])
        filename = parts[2]
        version = filename[len(name.replace("-", "_")) + 1 : -len(".tar.gz")]
        body = self._sdist_bytes(name, version)
        self._send(handler, 200, body, "application/octet-stream")


def _satisfying_version(requirement: Requirement) -> str:
    exact = [spec.version for spec in requirement.specifier if spec.operator in {"==", "==="}]
    if exact:
        return exact[-1]
    candidates = [
        "0.0.1",
        "0.4.6",
        "0.999.0",
        "1.0.0",
        "1.43.72",
        "1.999.0",
        "1.9999.0",
        "2.13.4",
        "2.34.2",
        "2.265.0",
        "2.999.0",
        "2.9999.0",
        "6.0.3",
        "9.1.1",
        "10.8.1",
        "10.999.0",
        "99.0.0",
    ]
    for spec in requirement.specifier:
        candidates.append(spec.version)
    matching = []
    for candidate in candidates:
        try:
            if requirement.specifier.contains(candidate, prereleases=False):
                matching.append(candidate)
        except Exception:
            continue
    if not matching:
        return "99.0.0"
    return max(matching, key=Version)


def _python_targets(*texts: str) -> dict[str, set[str]]:
    targets: dict[str, set[str]] = {}

    def add(text: str) -> None:
        cleaned = text.split("--hash", 1)[0].strip().strip("\\").strip()
        if not cleaned or cleaned.startswith("-"):
            return
        try:
            requirement = Requirement(cleaned)
        except Exception:
            return
        version = _satisfying_version(requirement)
        targets.setdefault(canonicalize_name(requirement.name), set()).add(version)

    for text in texts:
        for raw in text.splitlines():
            line = raw.split("#", 1)[0].strip()
            if not line or line.startswith("-"):
                continue
            if "requirements.txt" in line and "pip install" in line:
                continue
            if "pip install" in line:
                parts = line.split()
                for part in parts:
                    if part.startswith("-") or part in {"pip", "install", "python3", "-m"}:
                        continue
                    if part.endswith("pip"):
                        continue
                    add(part)
                continue
            add(line)
    return targets


def _npm_targets(*texts: str) -> dict[str, set[str]]:
    found: dict[str, set[str]] = {"cdk": set(), "aws-cdk": set()}
    for text in texts:
        for match in EXACT_VERSION.finditer(text):
            for name in ("cdk", "aws-cdk"):
                if f"{name}@{match.group(1)}" in text:
                    found[name].add(match.group(1))
    return found


def _load_jobs() -> dict:
    return yaml.safe_load(GITLAB_CI.read_text())


def _job_commands(job: dict) -> list[str]:
    commands = []
    for key in ("before_script", "script"):
        for item in job.get(key) or []:
            command = str(item).strip()
            if command.startswith("apt-get"):
                continue
            commands.append(command)
    return commands


def _pip_commands(job: dict) -> list[str]:
    return [command for command in _job_commands(job) if "pip install" in command]


def _read_events(path: Path) -> list[dict]:
    if not path.exists():
        return []
    events = []
    for line in path.read_text().splitlines():
        if line.strip():
            events.append(json.loads(line))
    return events


def _workspace(tmp: Path) -> Path:
    destination = tmp / "repo"
    shutil.copytree(
        REPO_ROOT,
        destination,
        ignore=shutil.ignore_patterns(".git", ".venv", ".cache", "node_modules"),
    )
    (destination / "checkout-marker.txt").write_text(CHECKOUT_MARKER + "\n")
    return destination


def _environment(tmp: Path, registry: Registry, workspace: Path, sentinel: Path) -> dict[str, str]:
    env = os.environ.copy()
    env.update(
        {
            "HOME": str(tmp / "home"),
            "npm_config_registry": registry.base,
            "npm_config_cache": str(tmp / "npm-cache"),
            "npm_config_prefix": str(tmp / "npm-prefix"),
            "npm_config_audit": "false",
            "npm_config_fund": "false",
            "npm_config_update_notifier": "false",
            # The job does not set ignore-scripts. npm's default is false;
            # do not inherit a developer config that would hide the scripts.
            "npm_config_ignore_scripts": "false",
            # A digest mismatch is EINTEGRITY on the first response. npm's
            # default retries repeat that failure; they do not run scripts.
            "npm_config_fetch_retries": "0",
            "PIP_INDEX_URL": f"{registry.base}/simple",
            "PIP_TRUSTED_HOST": "127.0.0.1",
            "PIP_DISABLE_PIP_VERSION_CHECK": "1",
            "PIP_NO_CACHE_DIR": "1",
            "SENTINEL_PATH": str(sentinel),
            "CI_PROJECT_DIR": str(workspace),
            "CI_JOB_TOKEN": TOKEN_PLACEHOLDER,
        }
    )
    for key in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN"):
        env.pop(key, None)
    # The GitLab image starts with an empty site-packages. A pip that already
    # has a requirement would skip the download the job performs.
    venv = tmp / "empty-site"
    subprocess.run([sys.executable, "-m", "venv", str(venv)], check=True, env=env)
    env["PATH"] = str(venv / "bin") + os.pathsep + env["PATH"]
    env["PYTHONNOUSERSITE"] = "1"
    return env


def _run(commands: list[str], workspace: Path, env: dict[str, str]) -> None:
    for command in commands:
        subprocess.run(
            ["bash", "-lc", command],
            cwd=workspace,
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=180,
            check=False,
        )


def _replay(tmp: Path, commands: list[str], texts: list[str]) -> list[dict]:
    registry = Registry(_npm_targets(*texts), _python_targets(*texts))
    registry.start()
    try:
        workspace = _workspace(tmp)
        sentinel = tmp / "sentinel.log"
        _run(commands, workspace, _environment(tmp, registry, workspace, sentinel))
        return _read_events(sentinel)
    finally:
        registry.close()


def _assert_no_execution(events: list[dict]) -> None:
    assert events == [], (
        "a package fetched without a client digest ran inside the job workspace "
        f"and could see the checkout and CI_JOB_TOKEN: {events}"
    )


def test_cdk_synth_job_does_not_run_floating_registry_code(tmp_path: Path):
    job = _load_jobs()["cdk-synth"]
    commands = _job_commands(job)
    texts = commands + [REQUIREMENTS.read_text(), DEPLOY_SH.read_text()]
    events = _replay(tmp_path, commands, texts)
    _assert_no_execution(events)


@pytest.mark.parametrize("job_name", ["ruff", "shell", "control-library", "pytest"])
def test_gitlab_job_does_not_run_floating_python_install(tmp_path: Path, job_name: str):
    job = _load_jobs()[job_name]
    commands = _pip_commands(job)
    assert commands, job_name
    events = _replay(tmp_path, commands, commands + [REQUIREMENTS.read_text()])
    _assert_no_execution(events)


def test_deploy_sh_does_not_run_floating_cdk_cli(tmp_path: Path):
    source = DEPLOY_SH.read_text()
    commands = []
    for line in source.splitlines():
        stripped = line.strip()
        if stripped.startswith("#") or "log_error" in stripped or "log_info" in stripped:
            continue
        match = re.search(
            r"(?:^|if\s+)(npm install -g (?:aws-)?cdk(?:@[^\s;\"']*)?)",
            stripped,
        )
        if match:
            commands.append(match.group(1))
    assert commands == ["npm install -g aws-cdk"]
    events = _replay(tmp_path, commands, [source])
    _assert_no_execution(events)


def test_client_hash_mismatch_stops_before_package_code(tmp_path: Path):
    """A digest the client declares is checked before package code runs.

    The published bytes are the same packages the other tests install. The
    declared sha512 and sha256 are not the digest of those bytes.
    """
    registry = Registry({"aws-cdk": {"2.1148.1"}, "cdk": set()}, {"colorama": {"99.0.0"}})
    registry.start()
    try:
        workspace = _workspace(tmp_path)
        sentinel = tmp_path / "sentinel.log"
        env = _environment(tmp_path, registry, workspace, sentinel)
        tarball = registry._npm_bytes("aws-cdk", "2.1148.1")
        assert _sha512_sri(tarball) != _sha512_sri(b"not-the-tarball")
        declared = _sha512_sri(b"not-the-tarball")
        package_json = {
            "name": "pin-check",
            "version": "1.0.0",
            "dependencies": {"aws-cdk": "2.1148.1"},
        }
        lock = {
            "name": "pin-check",
            "version": "1.0.0",
            "lockfileVersion": 3,
            "requires": True,
            "packages": {
                "": {
                    "name": "pin-check",
                    "version": "1.0.0",
                    "dependencies": {"aws-cdk": "2.1148.1"},
                },
                "node_modules/aws-cdk": {
                    "version": "2.1148.1",
                    "resolved": f"{registry.base}/aws-cdk/-/aws-cdk-2.1148.1.tgz",
                    "integrity": declared,
                },
            },
        }
        project = tmp_path / "pin"
        project.mkdir()
        (project / "package.json").write_text(json.dumps(package_json))
        (project / "package-lock.json").write_text(json.dumps(lock))
        npm = subprocess.run(
            ["npm", "ci", "--ignore-scripts=false"],
            cwd=project,
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            timeout=120,
            check=False,
            text=True,
        )
        assert npm.returncode != 0
        requirements = tmp_path / "hashed.txt"
        requirements.write_text(
            "colorama==99.0.0 \\\n"
            "    --hash=sha256:" + ("0" * 64) + "\n"
        )
        pip = subprocess.run(
            [
                "python3",
                "-m",
                "pip",
                "install",
                "--require-hashes",
                "-r",
                str(requirements),
            ],
            cwd=workspace,
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            timeout=120,
            check=False,
            text=True,
        )
        assert pip.returncode != 0
        assert _read_events(sentinel) == []
        assert any(request.startswith("GET /aws-cdk/-/") for request in registry.requests)
        assert any("colorama" in request for request in registry.requests)
    finally:
        registry.close()
