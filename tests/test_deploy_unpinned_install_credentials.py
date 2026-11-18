"""Deploy must not run unpinned installer code where AWS credentials are readable.

``scripts/deploy.sh`` reaches ``check_prereqs`` and ``setup_venv`` for every
action except the ones that return earlier. ``check_prereqs`` runs
``npm install -g aws-cdk`` when ``cdk`` is not already resolvable, and
``setup_venv`` runs ``pip install -r requirements.txt`` after
``check_credentials``. Neither command pins an exact artifact with a hash,
and both inherit the operator environment, including the AWS credential
variables and the shared credentials file.

These tests publish a release that satisfies those install specs and run the
real deploy actions against it. The tests fail while that release's install
or import code can read the credential channels. They pass once the deploy
script rejects that release (exact pin plus hash check) or runs installer
code where those channels are not readable.

Run:

    python3 -m unittest tests.test_deploy_unpinned_install_credentials

Actions covered, because each one falls through to the same install prelude:
deploy, build, workshop, destroy, verify, synth, diff, export, ls, list.

Not covered, because they return before that prelude or never hold the
deploy credential: doctor, design, config, usecase, migrate, ``workshop
--dry-run``, ``--module D``, the CI install jobs, and the agent image
Dockerfiles.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import tarfile
import textwrap
import threading
import unittest
import zipfile
from base64 import urlsafe_b64encode
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote, urlparse

REPO = Path(__file__).resolve().parents[1]
# Parent of the npm symlink, not its resolved target. Resolving lands in
# npm's package bin, which has no node binary and makes the shell wrapper
# fail before it can install anything.
NODE_BIN = Path(shutil.which("npm") or "").parent
ACTIONS = (
    "deploy",
    "build",
    "workshop",
    "destroy",
    "verify",
    "synth",
    "diff",
    "export",
    "ls",
    "list",
)
CREDENTIAL_CHANNELS = (
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "AWS_SECURITY_TOKEN",
    "AWS_SHARED_CREDENTIALS_FILE",
    "HOME/.aws/credentials",
    "HOME/.aws/config",
    "AWS_WEB_IDENTITY_TOKEN_FILE",
    "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
    "AWS_CONTAINER_CREDENTIALS_FULL_URI",
)
ACCESS_KEY = "placeholder-access-key"
SECRET_KEY = "placeholder-secret-key"
SESSION_TOKEN = "placeholder-session-token"
VERSION_SEEDS = (
    "99.0.0",
    "10.99.0",
    "2.99.0",
    "1.99.0",
    "0.99.0",
    "9.9.9",
    "8.99.0",
)


def _requirement_lines(requirements: Path) -> list[str]:
    lines = []
    for raw in requirements.read_text(encoding="utf-8").splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith("-"):
            continue
        lines.append(line)
    return lines


def _pick_version(specifier: str) -> str:
    from pip._vendor.packaging.requirements import Requirement

    if specifier and not specifier[0].isdigit() and specifier[0] not in "<>!=~":
        requirement = Requirement(specifier)
    else:
        requirement = Requirement(f"candidate{specifier}")
    candidates = list(VERSION_SEEDS)
    for major in range(0, 30):
        for minor in (0, 8, 13, 43, 99):
            for patch in (0, 1, 3, 72):
                candidates.append(f"{major}.{minor}.{patch}")
    seen = set()
    for candidate in candidates:
        if candidate in seen:
            continue
        seen.add(candidate)
        if requirement.specifier.contains(candidate, prereleases=False):
            return candidate
    raise AssertionError(f"no published version satisfies {specifier!r}")


def _direct_requirements(requirements: Path) -> list[tuple[str, str]]:
    from pip._vendor.packaging.requirements import Requirement
    from pip._vendor.packaging.utils import canonicalize_name

    selected = []
    for line in _requirement_lines(requirements):
        requirement = Requirement(line)
        version = _pick_version(str(requirement.specifier))
        selected.append((canonicalize_name(requirement.name), version))
    return selected


def _sha256_record(data: bytes) -> str:
    digest = urlsafe_b64encode(hashlib.sha256(data).digest()).decode("ascii").rstrip("=")
    return f"sha256={digest}"


def _write_sdist(directory: Path, project: str, version: str) -> Path:
    module = "credprobe_" + project.replace("-", "_")
    backend = textwrap.dedent(
        f"""\
        import base64
        import hashlib
        import json
        import os
        import zipfile
        from pathlib import Path

        PACKAGE = {project!r}
        VERSION = {version!r}
        MODULE = {module!r}

        def _channels():
            found = []
            for name in (
                "AWS_ACCESS_KEY_ID",
                "AWS_SECRET_ACCESS_KEY",
                "AWS_SESSION_TOKEN",
                "AWS_SECURITY_TOKEN",
                "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
                "AWS_CONTAINER_CREDENTIALS_FULL_URI",
            ):
                if os.environ.get(name):
                    found.append(name)
            shared = os.environ.get("AWS_SHARED_CREDENTIALS_FILE")
            if shared and os.path.isfile(shared) and os.access(shared, os.R_OK):
                found.append("AWS_SHARED_CREDENTIALS_FILE")
            home = os.environ.get("HOME", "")
            for label, candidate in (
                ("HOME/.aws/credentials", os.path.join(home, ".aws", "credentials")),
                ("HOME/.aws/config", os.path.join(home, ".aws", "config")),
            ):
                if candidate and os.path.isfile(candidate) and os.access(candidate, os.R_OK):
                    found.append(label)
            web = os.environ.get("AWS_WEB_IDENTITY_TOKEN_FILE")
            if web and os.path.isfile(web) and os.access(web, os.R_OK):
                found.append("AWS_WEB_IDENTITY_TOKEN_FILE")
            return found

        def _record(stage):
            out = os.environ.get("CRED_PROBE_DIR")
            if not out:
                return
            Path(out).mkdir(parents=True, exist_ok=True)
            dest = Path(out) / f"pip-{{PACKAGE}}-{{stage}}-{{os.getpid()}}.json"
            suffix = 0
            while dest.exists():
                suffix += 1
                dest = Path(out) / f"pip-{{PACKAGE}}-{{stage}}-{{os.getpid()}}-{{suffix}}.json"
            dest.write_text(json.dumps({{
                "ecosystem": "pip",
                "package": PACKAGE,
                "stage": stage,
                "channels": _channels(),
            }}))

        def get_requires_for_build_wheel(config_settings=None):
            _record("get_requires_for_build_wheel")
            return []

        def build_wheel(wheel_directory, config_settings=None, metadata_directory=None):
            _record("build_wheel")
            info = PACKAGE.replace("-", "_") + "-" + VERSION + ".dist-info"
            runtime = (
                "import json, os\\n"
                "from pathlib import Path\\n"
                "channels = []\\n"
                "for name in ('AWS_ACCESS_KEY_ID','AWS_SECRET_ACCESS_KEY','AWS_SESSION_TOKEN','AWS_SECURITY_TOKEN','AWS_CONTAINER_CREDENTIALS_RELATIVE_URI','AWS_CONTAINER_CREDENTIALS_FULL_URI'):\\n"
                "    if os.environ.get(name):\\n"
                "        channels.append(name)\\n"
                "shared = os.environ.get('AWS_SHARED_CREDENTIALS_FILE')\\n"
                "if shared and os.path.isfile(shared) and os.access(shared, os.R_OK):\\n"
                "    channels.append('AWS_SHARED_CREDENTIALS_FILE')\\n"
                "home = os.environ.get('HOME', '')\\n"
                "for label, candidate in (('HOME/.aws/credentials', os.path.join(home, '.aws', 'credentials')), ('HOME/.aws/config', os.path.join(home, '.aws', 'config'))):\\n"
                "    if candidate and os.path.isfile(candidate) and os.access(candidate, os.R_OK):\\n"
                "        channels.append(label)\\n"
                "web = os.environ.get('AWS_WEB_IDENTITY_TOKEN_FILE')\\n"
                "if web and os.path.isfile(web) and os.access(web, os.R_OK):\\n"
                "    channels.append('AWS_WEB_IDENTITY_TOKEN_FILE')\\n"
                "out = os.environ.get('CRED_PROBE_DIR')\\n"
                "if out:\\n"
                "    Path(out).mkdir(parents=True, exist_ok=True)\\n"
                "    dest = Path(out) / ('pip-' + {module!r} + '-import-' + str(os.getpid()) + '.json')\\n"
                "    suffix = 0\\n"
                "    while dest.exists():\\n"
                "        suffix += 1\\n"
                "        dest = Path(out) / ('pip-' + {module!r} + '-import-' + str(os.getpid()) + '-' + str(suffix) + '.json')\\n"
                "    dest.write_text(json.dumps({{'ecosystem':'pip','package':{project!r},'stage':'import','channels':channels}}))\\n"
            )
            files = {{
                MODULE + ".py": runtime.encode(),
                MODULE + ".pth": ("import " + MODULE + "\\n").encode(),
                info + "/METADATA": (
                    "Metadata-Version: 2.1\\n"
                    f"Name: {{PACKAGE}}\\n"
                    f"Version: {{VERSION}}\\n"
                ).encode(),
                info + "/WHEEL": (
                    "Wheel-Version: 1.0\\n"
                    "Generator: credprobe\\n"
                    "Root-Is-Purelib: true\\n"
                    "Tag: py3-none-any\\n"
                ).encode(),
            }}
            record_lines = []
            for name, data in sorted(files.items()):
                record_lines.append(f"{{name}},{{_wheel_hash(data)}},{{len(data)}}")
            record_lines.append(info + "/RECORD,,")
            files[info + "/RECORD"] = ("\\n".join(record_lines) + "\\n").encode()
            filename = PACKAGE.replace("-", "_") + "-" + VERSION + "-py3-none-any.whl"
            target = Path(wheel_directory) / filename
            with zipfile.ZipFile(target, "w") as wheel:
                for name, data in files.items():
                    wheel.writestr(name, data)
            return filename

        def _wheel_hash(data):
            digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).decode().rstrip("=")
            return "sha256=" + digest
        """
    )
    root = directory / f"{project}-{version}"
    root.mkdir(parents=True)
    (root / "pyproject.toml").write_text(
        textwrap.dedent(
            f"""\
            [build-system]
            requires = []
            build-backend = "credprobe_backend"
            backend-path = ["."]

            [project]
            name = "{project}"
            version = "{version}"
            """
        ),
        encoding="utf-8",
    )
    (root / "credprobe_backend.py").write_text(backend, encoding="utf-8")
    archive = directory / f"{project}-{version}.tar.gz"
    with tarfile.open(archive, "w:gz") as tar:
        tar.add(root, arcname=root.name)
    return archive


def _npm_probe_source() -> str:
    return textwrap.dedent(
        """\
        const fs = require("fs");
        const path = require("path");

        function readable(candidate) {
          try {
            fs.accessSync(candidate, fs.constants.R_OK);
            return fs.statSync(candidate).isFile();
          } catch (error) {
            return false;
          }
        }

        function record(stage) {
          const channels = [];
          for (const name of [
            "AWS_ACCESS_KEY_ID",
            "AWS_SECRET_ACCESS_KEY",
            "AWS_SESSION_TOKEN",
            "AWS_SECURITY_TOKEN",
            "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
            "AWS_CONTAINER_CREDENTIALS_FULL_URI",
          ]) {
            if (process.env[name]) channels.push(name);
          }
          const shared = process.env.AWS_SHARED_CREDENTIALS_FILE;
          if (shared && readable(shared)) channels.push("AWS_SHARED_CREDENTIALS_FILE");
          const home = process.env.HOME || "";
          if (readable(path.join(home, ".aws", "credentials"))) {
            channels.push("HOME/.aws/credentials");
          }
          if (readable(path.join(home, ".aws", "config"))) {
            channels.push("HOME/.aws/config");
          }
          const web = process.env.AWS_WEB_IDENTITY_TOKEN_FILE;
          if (web && readable(web)) channels.push("AWS_WEB_IDENTITY_TOKEN_FILE");
          const out = process.env.CRED_PROBE_DIR;
          if (!out) return;
          fs.mkdirSync(out, { recursive: true });
          const dest = path.join(
            out,
            `npm-aws-cdk-${stage}-${process.pid}-${Date.now()}.json`
          );
          fs.writeFileSync(dest, JSON.stringify({
            ecosystem: "npm",
            package: "aws-cdk",
            stage,
            channels,
          }));
        }

        if (require.main === module) {
          record(process.argv[2] || "cli");
        }

        module.exports = { record };
        """
    )


def _write_npm_tarball(directory: Path) -> tuple[Path, str]:
    root = directory / "package"
    root.mkdir(parents=True)
    (root / "probe.js").write_text(_npm_probe_source(), encoding="utf-8")
    (root / "cdk.js").write_text(
        textwrap.dedent(
            """\
            const { record } = require("./probe.js");
            record("cli");
            if (process.argv.includes("--version")) {
              console.log("99.0.0");
              process.exit(0);
            }
            process.exit(1);
            """
        ),
        encoding="utf-8",
    )
    (root / "package.json").write_text(
        json.dumps(
            {
                "name": "aws-cdk",
                "version": "99.0.0",
                "bin": {"cdk": "cdk.js"},
                "scripts": {
                    "preinstall": "node probe.js preinstall",
                    "install": "node probe.js install",
                    "postinstall": "node probe.js postinstall",
                },
            }
        ),
        encoding="utf-8",
    )
    archive = directory / "aws-cdk-99.0.0.tgz"
    with tarfile.open(archive, "w:gz") as tar:
        tar.add(root, arcname="package")
    return archive, hashlib.sha1(archive.read_bytes()).hexdigest()


def _resolve_python() -> Path:
    found = shutil.which("python3.13")
    if found:
        return Path(found).resolve()
    standalone = Path("/tmp/py313/python/bin/python3.13")
    if standalone.exists():
        return standalone
    fallback = shutil.which("python3")
    if not fallback:
        raise AssertionError("python3 is required to satisfy deploy.sh's python3.13 check")
    return Path(fallback).resolve()


def _load_reports(directory: Path) -> list[dict]:
    reports = []
    if not directory.exists():
        return reports
    for path in sorted(directory.glob("*.json")):
        reports.append(json.loads(path.read_text(encoding="utf-8")))
    return reports


def _leaks(reports: list[dict]) -> list[dict]:
    return [report for report in reports if report.get("channels")]


class _RegistryState:
    def __init__(self) -> None:
        self.sdists: dict[str, Path] = {}
        self.versions: dict[str, str] = {}
        self.npm_tarball: Path | None = None
        self.npm_shasum = ""
        self.requests: list[str] = []
        self.base_url = ""


class _RegistryHandler(BaseHTTPRequestHandler):
    state: _RegistryState

    def log_message(self, fmt: str, *args) -> None:
        return

    def do_GET(self) -> None:  # noqa: N802 - stdlib handler name
        parsed = urlparse(self.path)
        path = unquote(parsed.path)
        self.state.requests.append(path)
        if path in ("/aws-cdk", "/aws-cdk/"):
            self._send(200, self._packument().encode(), "application/json")
            return
        if path == "/aws-cdk/-/aws-cdk-99.0.0.tgz":
            assert self.state.npm_tarball is not None
            self._send(200, self.state.npm_tarball.read_bytes(), "application/octet-stream")
            return
        if path.startswith("/simple/"):
            parts = [part for part in path.split("/") if part]
            if len(parts) == 1:
                body = "".join(
                    f'<a href="{self.state.base_url}/simple/{name}/">{name}</a>\n'
                    for name in sorted(self.state.sdists)
                )
                self._send(200, body.encode(), "text/html")
                return
            name = parts[1]
            archive = self.state.sdists.get(name)
            if archive is None:
                self._send(404, b"missing", "text/plain")
                return
            href = f"{self.state.base_url}/packages/{archive.name}"
            body = (
                "<!DOCTYPE html><html><body>"
                f'<a href="{href}">{archive.name}</a>'
                "</body></html>"
            )
            self._send(200, body.encode(), "text/html")
            return
        if path.startswith("/packages/"):
            name = path.rsplit("/", 1)[-1]
            for archive in self.state.sdists.values():
                if archive.name == name:
                    self._send(200, archive.read_bytes(), "application/octet-stream")
                    return
        self._send(404, b"missing", "text/plain")

    def _packument(self) -> str:
        tarball = f"{self.state.base_url}/aws-cdk/-/aws-cdk-99.0.0.tgz"
        return json.dumps(
            {
                "name": "aws-cdk",
                "dist-tags": {"latest": "99.0.0"},
                "versions": {
                    "99.0.0": {
                        "name": "aws-cdk",
                        "version": "99.0.0",
                        "hasInstallScript": True,
                        "bin": {"cdk": "cdk.js"},
                        "scripts": {
                            "preinstall": "node probe.js preinstall",
                            "install": "node probe.js install",
                            "postinstall": "node probe.js postinstall",
                        },
                        "dist": {
                            "tarball": tarball,
                            "shasum": self.state.npm_shasum,
                        },
                    }
                },
            }
        )

    def _send(self, status: int, body: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class DeployUnpinnedInstallCredentialsTest(unittest.TestCase):
    registry: _RegistryState
    httpd: ThreadingHTTPServer
    requirements: list[tuple[str, str]]

    @classmethod
    def setUpClass(cls) -> None:
        if not NODE_BIN.joinpath("npm").exists() and not shutil.which("npm"):
            raise AssertionError("npm is required to exercise check_prereqs")
        cls.work = Path(
            subprocess.check_output(["mktemp", "-d", "/tmp/deploy-cred-test.XXXXXX"], text=True).strip()
        )
        cls.registry = _RegistryState()
        _RegistryHandler.state = cls.registry
        packages = cls.work / "packages"
        packages.mkdir()
        cls.requirements = _direct_requirements(REPO / "requirements.txt")
        for name, version in cls.requirements:
            cls.registry.sdists[name] = _write_sdist(packages, name, version)
            cls.registry.versions[name] = version
        cls.registry.npm_tarball, cls.registry.npm_shasum = _write_npm_tarball(cls.work / "npm")
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", 0), _RegistryHandler)
        cls.registry.base_url = f"http://127.0.0.1:{cls.httpd.server_address[1]}"
        thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        thread.start()
        cls._assert_canary_sees_credentials()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.httpd.shutdown()
        shutil.rmtree(cls.work, ignore_errors=True)

    @classmethod
    def _assert_canary_sees_credentials(cls) -> None:
        probe = cls.work / "canary-probe"
        home = cls.work / "canary-home"
        prefix = cls.work / "canary-prefix"
        env = cls._environment(home, prefix, probe)
        python = env["PATH"].split(os.pathsep)[1]
        # PATH is prefix/bin, harness-or-python, ... The interpreter is python3.13 on PATH.
        npm = subprocess.run(
            ["npm", "install", "-g", "aws-cdk"],
            cwd=cls.work,
            env=env,
            timeout=120,
            capture_output=True,
            text=True,
        )
        if npm.returncode != 0:
            raise AssertionError(
                "npm canary install failed\n"
                + npm.stdout[-3000:]
                + npm.stderr[-3000:]
                + "\nrequests: "
                + ", ".join(cls.registry.requests)
            )
        venv = cls.work / "canary-venv"
        subprocess.run([shutil.which("python3.13", path=env["PATH"]), "-m", "venv", str(venv)], check=True, env=env)
        pip = subprocess.run(
            [str(venv / "bin" / "pip"), "install", "-r", str(REPO / "requirements.txt")],
            cwd=cls.work,
            env=env,
            timeout=180,
            capture_output=True,
            text=True,
        )
        if pip.returncode != 0:
            raise AssertionError(
                "canary packages were not installable by the same pip the deploy script runs\n"
                + pip.stdout[-2000:]
                + pip.stderr[-2000:]
            )
        subprocess.run([str(venv / "bin" / "python"), "-c", "pass"], check=True, env=env, timeout=60)
        reports = _load_reports(probe)
        leaks = _leaks(reports)
        npm_stages = {report["stage"] for report in leaks if report["ecosystem"] == "npm"}
        pip_stages = {report["stage"] for report in leaks if report["ecosystem"] == "pip"}
        if "preinstall" not in npm_stages and "install" not in npm_stages and "postinstall" not in npm_stages:
            raise AssertionError(
                "npm lifecycle canary did not observe credentials\n"
                + npm.stdout[-2000:]
                + npm.stderr[-2000:]
                + "\nrequests: "
                + ", ".join(cls.registry.requests[:30])
            )
        if "get_requires_for_build_wheel" not in pip_stages and "build_wheel" not in pip_stages:
            raise AssertionError(f"pip build canary did not observe credentials: {reports}")
        if "import" not in pip_stages:
            raise AssertionError(f"import canary did not observe credentials: {reports}")
        del python

    @classmethod
    def _environment(cls, home: Path, prefix: Path, probe: Path) -> dict[str, str]:
        home.mkdir(parents=True, exist_ok=True)
        (home / "tmp").mkdir(exist_ok=True)
        (home / "npm-cache").mkdir(exist_ok=True)
        aws_dir = home / ".aws"
        aws_dir.mkdir(exist_ok=True)
        (aws_dir / "credentials").write_text(
            "[default]\n"
            f"aws_access_key_id = {ACCESS_KEY}\n"
            f"aws_secret_access_key = {SECRET_KEY}\n",
            encoding="utf-8",
        )
        (aws_dir / "config").write_text("[default]\nregion = us-east-1\n", encoding="utf-8")
        os.chmod(aws_dir / "credentials", 0o600)
        prefix.mkdir(parents=True, exist_ok=True)
        (prefix / "bin").mkdir(exist_ok=True)
        probe.mkdir(parents=True, exist_ok=True)
        harness = home / "harness-bin"
        harness.mkdir(exist_ok=True)
        aws = harness / "aws"
        aws.write_text(
            textwrap.dedent(
                """\
                #!/bin/bash
                args="$*"
                if [[ "$args" == *--version* ]]; then
                  printf '%s\\n' 'aws-cli/2.0.0 placeholder'
                  exit 0
                fi
                if [[ "$args" == *get-caller-identity* ]]; then
                  if [[ "$args" == *Account* ]]; then
                    printf '%s\\n' '111111111111'
                  elif [[ "$args" == *Arn* ]]; then
                    printf '%s\\n' 'arn:aws:iam::111111111111:user/placeholder'
                  fi
                  exit 0
                fi
                if [[ "$args" == *configure* && "$args" == *get* && "$args" == *region* ]]; then
                  printf '%s\\n' 'us-east-1'
                  exit 0
                fi
                exit 1
                """
            ),
            encoding="utf-8",
        )
        aws.chmod(0o755)
        python = _resolve_python()
        if python.name != "python3.13":
            link = harness / "python3.13"
            if not link.exists():
                link.symlink_to(python)
            python_path = str(harness)
        else:
            python_path = str(python.parent)
        path = os.pathsep.join(
            [
                str(prefix / "bin"),
                str(harness),
                python_path,
                str(NODE_BIN),
                "/usr/bin",
                "/bin",
            ]
        )
        return {
            "PATH": path,
            "HOME": str(home),
            "TMPDIR": str(home / "tmp"),
            "LANG": "C.UTF-8",
            "USER": "deployer",
            "AWS_ACCESS_KEY_ID": ACCESS_KEY,
            "AWS_SECRET_ACCESS_KEY": SECRET_KEY,
            "AWS_SESSION_TOKEN": SESSION_TOKEN,
            "AWS_SHARED_CREDENTIALS_FILE": str(aws_dir / "credentials"),
            "AWS_REGION": "us-east-1",
            "AWS_DEFAULT_REGION": "us-east-1",
            "CRED_PROBE_DIR": str(probe),
            "PIP_INDEX_URL": f"{cls.registry.base_url}/simple",
            "PIP_TRUSTED_HOST": "127.0.0.1",
            "PIP_DISABLE_PIP_VERSION_CHECK": "1",
            "PIP_NO_CACHE_DIR": "1",
            "NPM_CONFIG_REGISTRY": f"{cls.registry.base_url}/",
            "NPM_CONFIG_PREFIX": str(prefix),
            "NPM_CONFIG_CACHE": str(home / "npm-cache"),
            "NPM_CONFIG_AUDIT": "false",
            "NPM_CONFIG_FUND": "false",
            "NPM_CONFIG_UPDATE_NOTIFIER": "false",
            "NPM_CONFIG_STRICT_SSL": "false",
            "NPM_CONFIG_FETCH_RETRIES": "1",
            "NON_INTERACTIVE": "1",
        }

    def test_deploy_actions_do_not_expose_credentials_to_satisfying_releases(self) -> None:
        (self.work / "canary-home" / "tmp").mkdir(exist_ok=True)
        failures = []
        for action in ACTIONS:
            with self.subTest(action=action):
                failure = self._run_action(action)
                if failure:
                    failures.append(failure)
        if failures:
            self.fail("\n".join(failures))

    def _run_action(self, action: str) -> str:
        root = self.work / action
        if root.exists():
            shutil.rmtree(root)
        shutil.copytree(
            REPO,
            root,
            ignore=shutil.ignore_patterns(
                ".git",
                ".venv",
                "__pycache__",
                ".pytest_cache",
                "cdk.out",
                "node_modules",
            ),
        )
        home = root / "operator-home"
        prefix = root / "npm-prefix"
        probe = root / "probe"
        (home / "tmp").mkdir(parents=True, exist_ok=True)
        (home / "npm-cache").mkdir(parents=True, exist_ok=True)
        del self.registry.requests[:]
        env = self._environment(home, prefix, probe)
        try:
            completed = subprocess.run(
                ["bash", str(root / "scripts" / "deploy.sh"), action, "--yes"],
                cwd=root,
                env=env,
                timeout=180,
                capture_output=True,
                text=True,
            )
        except subprocess.TimeoutExpired as exc:
            stdout = (exc.stdout or "")[-1500:]
            stderr = (exc.stderr or "")[-1500:]
            return f"{action}: timed out before the install finished\n{stdout}\n{stderr}"
        requests = list(self.registry.requests)
        missing_python = [
            name
            for name, _version in self.requirements
            if not any(f"/simple/{name}" in path for path in requests)
        ]
        npm_hit = any(path.rstrip("/") == "/aws-cdk" for path in requests)
        leaks = _leaks(_load_reports(probe))
        problems = []
        if missing_python or not npm_hit:
            tail = (completed.stdout + completed.stderr)[-2000:]
            problems.append(
                f"{action}: installer did not resolve the unpinned specs "
                f"(missing python index hits {missing_python}, npm aws-cdk hit {npm_hit}). "
                f"exit {completed.returncode}. output:\n{tail}"
            )
        if leaks:
            summary = [
                f"{item['ecosystem']}:{item['package']}:{item['stage']} -> {', '.join(item['channels'])}"
                for item in leaks
            ]
            problems.append(
                f"{action}: package code that satisfies the unpinned install read AWS credential channels:\n"
                + "\n".join(summary)
            )
        return "\n".join(problems)


if __name__ == "__main__":
    unittest.main()
