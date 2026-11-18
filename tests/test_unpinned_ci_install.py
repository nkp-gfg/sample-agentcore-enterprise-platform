#!/usr/bin/env python3
"""Spec for the contract-parity supply-chain finding.

These tests fail while a GitHub Actions job installs a floating npm package or
an unpinned pip range and that install executes package code. They pass once
those jobs reject a replaced or newly published artifact before any of its
code runs.

The harness is a local registry. It publishes one malicious release that
satisfies every floating tag and version range these workflows install. The
release's install script reads the job workspace, including the git
credentials file actions/checkout leaves behind when persist-credentials is
left at its default. A digest or hash pin fails closed on that release and
does not run the script.

Run:
    python3 tests/test_unpinned_ci_install.py
"""

from __future__ import annotations

import base64
import hashlib
import os
import shutil
import socket
import subprocess
import tarfile
import textwrap
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parents[1]
CANARY_NAME = ".install-canary"
PLACEHOLDER_TOKEN = "placeholder-job-token"

# Versions that satisfy the ranges in requirements.txt and the workflow
# install lines. A newly published release in each accepted range.
PIP_VERSIONS = {
    "aws-cdk-lib": "99.0.0",
    "constructs": "10.99.0",
    "pyyaml": "99.0.0",
    "boto3": "99.0.0",
    "botocore": "99.0.0",
    "requests": "99.0.0",
    "colorama": "99.0.0",
    "pytest": "99.0.0",
    "pydantic": "2.99.0",
    "checkov": "99.0.0",
    "ruff": "99.0.0",
}

# Install steps that share the unpinned-install path. Each entry is the
# workflow-relative path, the step name, and the shell that step runs.
INSTALL_STEPS = [
    (
        ".github/workflows/contract-parity.yml",
        "Install CDK and app dependencies",
        True,
    ),
    (
        ".github/workflows/secret-boundary.yml",
        "Install CDK and application dependencies",
        True,
    ),
    (
        ".github/workflows/control-library.yml",
        "Install dependencies",
        False,
    ),
    (
        ".github/workflows/python-lint.yml",
        "Install ruff",
        False,
    ),
    (
        ".github/workflows/shell-checks.yml",
        "Install the config dependencies",
        False,
    ),
]


def _step_script(workflow_path: str, step_name: str) -> str:
    document = yaml.safe_load((REPO / workflow_path).read_text())
    for job in document["jobs"].values():
        for step in job["steps"]:
            if step.get("name") == step_name:
                return step["run"]
    raise AssertionError(f"no step {step_name!r} in {workflow_path}")


def _integrity(blob: bytes) -> str:
    digest = base64.b64encode(hashlib.sha512(blob).digest()).decode()
    return "sha512-" + digest


def _npm_tarball(name: str, version: str, destination: Path) -> str:
    root = destination.parent / f"src-{name}-{version}"
    package = root / name
    (package / "bin").mkdir(parents=True)
    (package / "package.json").write_text(
        textwrap.dedent(
            f"""\
            {{
              "name": "{name}",
              "version": "{version}",
              "hasInstallScript": true,
              "bin": {{"cdk": "bin/cdk.js"}},
              "scripts": {{"preinstall": "node preinstall.js"}}
            }}
            """
        )
    )
    (package / "preinstall.js").write_text(
        "require('./record.js')('npm-preinstall')\n"
    )
    (package / "bin" / "cdk.js").write_text(
        "#!/usr/bin/env node\nrequire('../record.js')('npm-bin')\n"
    )
    (package / "record.js").write_text(_RECORD_JS)
    with tarfile.open(destination, "w:gz") as archive:
        archive.add(package, arcname=name)
    return _integrity(destination.read_bytes())


_RECORD_JS = textwrap.dedent(
    r"""
    const fs = require('fs')
    const path = require('path')
    module.exports = function record(kind) {
      const ws = process.env.GITHUB_WORKSPACE
      if (!ws) process.exit(0)
      const lines = [kind]
      const readme = path.join(ws, 'README.md')
      if (fs.existsSync(readme) && fs.readFileSync(readme, 'utf8').includes('workspace-sentinel')) {
        lines.push('readme-ok')
      }
      const cfg = path.join(ws, '.git', 'config')
      if (fs.existsSync(cfg)) {
        for (const line of fs.readFileSync(cfg, 'utf8').split('\n')) {
          const trimmed = line.trim()
          if (!trimmed.startsWith('path')) continue
          const target = trimmed.split('=').slice(1).join('=').trim()
          const blob = fs.readFileSync(target, 'utf8')
          const b64 = blob.split('basic ')[1].trim()
          const decoded = Buffer.from(b64, 'base64').toString('utf8')
          if (decoded === 'x-access-token:' + 'placeholder-job-token') lines.push('token-visible')
        }
      }
      fs.appendFileSync(path.join(ws, '.install-canary'), lines.join('\n') + '\n')
    }
    """
)


def _sdist(name: str, version: str, destination: Path) -> None:
    folder = destination.parent / f"src-{name}-{version}" / f"{name}-{version}"
    folder.mkdir(parents=True)
    module = name.replace("-", "_")
    (folder / "setup.py").write_text(
        textwrap.dedent(
            f"""\
            import base64
            import os
            import pathlib

            ws = pathlib.Path(os.environ["GITHUB_WORKSPACE"])
            lines = ["pip-setup"]
            readme = ws / "README.md"
            if readme.is_file() and "workspace-sentinel" in readme.read_text():
                lines.append("readme-ok")
            cfg = ws / ".git" / "config"
            if cfg.is_file():
                for line in cfg.read_text().splitlines():
                    if not line.strip().startswith("path"):
                        continue
                    blob = pathlib.Path(line.split("=", 1)[1].strip()).read_text()
                    decoded = base64.b64decode(blob.split("basic ", 1)[1].strip()).decode()
                    if decoded == "x-access-token:placeholder-job-token":
                        lines.append("token-visible")
            (ws / ".install-canary").write_text("\\n".join(lines) + "\\n")
            from setuptools import setup
            setup(name={name!r}, version={version!r}, py_modules=[{module!r}])
            """
        )
    )
    (folder / f"{module}.py").write_text(
        "import os, pathlib\n"
        "ws = os.environ.get('GITHUB_WORKSPACE')\n"
        "if ws:\n"
        "    pathlib.Path(ws, '.install-canary').open('a').write('pip-import\\n')\n"
    )
    with tarfile.open(destination, "w:gz") as archive:
        archive.add(folder, arcname=f"{name}-{version}")


class _Index(BaseHTTPRequestHandler):
    root: Path
    npm_integrity: str
    port: int

    def log_message(self, fmt: str, *args) -> None:
        return

    def do_GET(self) -> None:  # noqa: N802
        path = self.path.split("?", 1)[0]
        if path.rstrip("/").endswith("/aws-cdk"):
            body = self._packument().encode()
            ctype = "application/json"
        elif path.endswith(".tgz"):
            body = (self.root / "aws-cdk.tgz").read_bytes()
            ctype = "application/octet-stream"
        else:
            relative = path.lstrip("/")
            if relative.endswith("/"):
                relative += "index.html"
            candidate = self.root / relative
            if not candidate.is_file():
                self.send_response(404)
                self.end_headers()
                return
            body = candidate.read_bytes()
            ctype = "text/html" if candidate.suffix == ".html" else "application/octet-stream"
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _packument(self) -> str:
        import json

        def version(number: str) -> dict:
            return {
                "name": "aws-cdk",
                "version": number,
                "hasInstallScript": True,
                "bin": {"cdk": "bin/cdk.js"},
                "scripts": {"preinstall": "node preinstall.js"},
                "dist": {
                    "tarball": f"http://127.0.0.1:{self.port}/aws-cdk/-/aws-cdk-{number}.tgz",
                    "integrity": self.npm_integrity,
                },
            }

        # latest is the new malicious release. 2.1135.1 is the same bytes
        # served for the version the secret-boundary job names, with no
        # integrity pin in that job to reject them.
        return json.dumps(
            {
                "name": "aws-cdk",
                "dist-tags": {"latest": "9.9.9"},
                "versions": {
                    "9.9.9": version("9.9.9"),
                    "2.1135.1": version("2.1135.1"),
                },
            }
        )


def _start_index(root: Path, integrity: str) -> tuple[ThreadingHTTPServer, int]:
    class Handler(_Index):
        pass

    Handler.root = root
    Handler.npm_integrity = integrity
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    Handler.port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, Handler.port


def _prepare_index(root: Path) -> str:
    npm_tarball = root / "aws-cdk.tgz"
    integrity = _npm_tarball("aws-cdk", "9.9.9", npm_tarball)
    packages = root / "packages"
    simple = root / "simple"
    packages.mkdir()
    for name, version in PIP_VERSIONS.items():
        tarball = packages / f"{name}-{version}.tar.gz"
        _sdist(name, version, tarball)
        digest = hashlib.sha256(tarball.read_bytes()).hexdigest()
        page = simple / name
        page.mkdir(parents=True)
        (page / "index.html").write_text(
            "<!DOCTYPE html><html><body>"
            f'<a href="../../packages/{tarball.name}#sha256={digest}">{tarball.name}</a>'
            "</body></html>\n"
        )
    return integrity


def _workspace(root: Path) -> Path:
    workspace = root / "workspace"
    runner = root / "runner"
    workspace.mkdir()
    runner.mkdir()
    (workspace / "README.md").write_text("workspace-sentinel\n")
    (workspace / "requirements.txt").write_text((REPO / "requirements.txt").read_text())
    credential = runner / "git-credentials-aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee.config"
    basic = base64.b64encode(f"x-access-token:{PLACEHOLDER_TOKEN}".encode()).decode()
    credential.write_text(
        '[http "https://github.com/"]\n'
        f"\textraheader = AUTHORIZATION: basic {basic}\n"
    )
    git_dir = workspace / ".git"
    git_dir.mkdir()
    (git_dir / "config").write_text(
        f'[includeIf "gitdir:{git_dir}"]\n\tpath = {credential}\n'
    )
    return workspace


def _run_step(script: str, workspace: Path, index_port: int, prefix: Path) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    for key in list(env):
        if key.lower().startswith("npm_config_"):
            env.pop(key)
    env.update(
        {
            "GITHUB_WORKSPACE": str(workspace),
            "RUNNER_TEMP": str(workspace.parent / "runner"),
            "npm_config_registry": f"http://127.0.0.1:{index_port}",
            "npm_config_prefix": str(prefix),
            "npm_config_cache": str(workspace.parent / "npm-cache"),
            "npm_config_audit": "false",
            "npm_config_fund": "false",
            "npm_config_update_notifier": "false",
            "PIP_INDEX_URL": f"http://127.0.0.1:{index_port}/simple",
            "PIP_DISABLE_PIP_VERSION_CHECK": "1",
            "PIP_NO_CACHE_DIR": "1",
            "PATH": str(prefix / "bin") + os.pathsep + env.get("PATH", ""),
        }
    )
    prefix.mkdir(parents=True, exist_ok=True)
    return subprocess.run(
        ["bash", "--noprofile", "--norc", "-e", "-o", "pipefail", "-c", script],
        cwd=workspace,
        env=env,
        text=True,
        capture_output=True,
        timeout=180,
    )


def _assert_quiet(workflow: str, step: str, invoke_cdk: bool) -> None:
    root = Path(os.environ.get("TMPDIR", "/tmp")) / f"unpinned-{os.getpid()}-{step.replace(' ', '-')}"
    if root.exists():
        shutil.rmtree(root)
    root.mkdir(parents=True)
    server = None
    try:
        integrity = _prepare_index(root / "index")
        server, port = _start_index(root / "index", integrity)
        workspace = _workspace(root)
        script = _step_script(workflow, step)
        result = _run_step(script, workspace, port, root / "prefix")
        if result.returncode == 0 and invoke_cdk:
            _run_step("npx --no-install cdk --version", workspace, port, root / "prefix")
        canary = workspace / CANARY_NAME
        if canary.exists():
            raise SystemExit(
                f"{workflow} step {step!r} executed package code:\n"
                f"{canary.read_text()}\n"
                f"--- stdout ---\n{result.stdout}\n--- stderr ---\n{result.stderr}"
            )
        if result.returncode == 0 and invoke_cdk:
            return
    finally:
        if server is not None:
            server.shutdown()
        shutil.rmtree(root, ignore_errors=True)


def test_contract_parity_install_does_not_execute_floating_packages() -> None:
    _assert_quiet(*INSTALL_STEPS[0])


def test_sibling_installs_do_not_execute_floating_packages() -> None:
    for workflow, step, invoke_cdk in INSTALL_STEPS[1:]:
        _assert_quiet(workflow, step, invoke_cdk)


def main() -> None:
    test_contract_parity_install_does_not_execute_floating_packages()
    test_sibling_installs_do_not_execute_floating_packages()
    print("ok")


if __name__ == "__main__":
    main()
