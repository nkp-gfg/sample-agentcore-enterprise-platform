"""Claude agent image builds must not execute a floated npm dependency.

`agent-code/claude-sdk-agent/Dockerfile` and
`agent-code/claude-sdk-multi-agent/Dockerfile` install
`@anthropic-ai/claude-code@2.1.73` with `npm install -g`. That release has no
direct dependencies and no install script that npm runs for a registry
install. It does declare optionalDependencies on `@img/sharp-*` at `^0.34.2`.
With no lockfile, npm selects the newest matching release while the image is
built, and npm 11.20.0 (the npm bundled with the Node.js 26 LTS that
`setup_lts.x` installs) runs that release's preinstall, install, and
postinstall scripts unless they are disabled.

These tests publish one higher release inside that range, whose scripts write
a file into the install prefix, then run the npm commands from each
Dockerfile. The install must succeed, that file must not exist, and the
floated release must not be unpacked. They fail until the Dockerfiles install
the CLI from a committed lockfile (for example `npm ci`) and do not run
dependency lifecycle scripts.

Run:

    python3 -m pytest tests/test_claude_image_npm_supply_chain.py -q
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import shutil
import stat
import subprocess
import tarfile
import threading
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
CONTEXT = REPO / "agent-code"
DOCKERFILES = (
    CONTEXT / "claude-sdk-agent" / "Dockerfile",
    CONTEXT / "claude-sdk-multi-agent" / "Dockerfile",
)
# CodeBuild builds these images with `docker build --platform linux/arm64`
# (stacks/runtime_stack.py). The same Dockerfiles also install the glibc x64
# optional package when the builder's cpu is x64, so both are exercised.
BUILD_CPUS = ("arm64", "x64")
NPM_VERSION = "11.20.0"
ATTACK_VERSION = "0.34.99"
PINNED_SPEC = "@anthropic-ai/claude-code@2.1.73"
SHARP_PACKAGES = (
    "@img/sharp-linux-arm64",
    "@img/sharp-linux-x64",
    "@img/sharp-linux-arm",
    "@img/sharp-win32-x64",
    "@img/sharp-win32-arm64",
    "@img/sharp-darwin-x64",
    "@img/sharp-darwin-arm64",
    "@img/sharp-linuxmusl-x64",
    "@img/sharp-linuxmusl-arm64",
)
UPSTREAM = "https://registry.npmjs.org"
MUTATION_NAME = "supply-chain-mutation"
SCRIPT = (
    "node -e \"const fs=require('fs');const path=require('path');"
    "const prefix=process.env.npm_config_prefix;"
    "if(!prefix) process.exit(0);"
    f"fs.appendFileSync(path.join(prefix, '{MUTATION_NAME}'), "
    "(process.env.npm_lifecycle_event||'script')+'\\n')\""
)
SCRIPTS = {"preinstall": SCRIPT, "install": SCRIPT, "postinstall": SCRIPT}


def _logical_lines(text: str) -> list[str]:
    lines: list[str] = []
    current = ""
    for raw in text.splitlines():
        stripped = raw.strip()
        if not current and (not stripped or stripped.startswith("#")):
            continue
        if stripped.endswith("\\"):
            current += stripped[:-1].rstrip() + " "
            continue
        current += stripped
        lines.append(current.strip())
        current = ""
    if current.strip():
        lines.append(current.strip())
    return lines


def _instructions(text: str) -> list[tuple[str, str]]:
    found = []
    for line in _logical_lines(text):
        name, _, rest = line.partition(" ")
        if name.upper() == name and name.isalpha():
            found.append((name, rest.strip()))
    return found


def _is_npm_command(command: str) -> bool:
    stripped = command.strip()
    if stripped == "npm" or stripped.startswith("npm "):
        return True
    for separator in ("&&", "||", ";", "|"):
        if (
            f"{separator} npm " in f" {stripped}"
            or f"{separator} npm" == stripped[-len(separator) - 4 :]
        ):
            return True
    return "&& npm " in stripped or "; npm " in stripped or "| npm " in stripped


def _sha1(data: bytes) -> str:
    return hashlib.sha1(data).hexdigest()


def _sha512_integrity(data: bytes) -> str:
    import base64

    return "sha512-" + base64.b64encode(hashlib.sha512(data).digest()).decode()


def _tarball(manifest: dict) -> bytes:
    payload = json.dumps(manifest, sort_keys=True).encode()
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as archive:
        info = tarfile.TarInfo("package/package.json")
        info.size = len(payload)
        info.mtime = 0
        archive.addfile(info, io.BytesIO(payload))
    return buf.getvalue()


class Registry:
    """Upstream npm registry plus one attacker release of each sharp package.

    Packuments and real tarballs are proxied unchanged except for the injected
    version, so a lockfile that pins a real release still verifies.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._tarballs: dict[str, bytes] = {}
        self._manifests: dict[str, dict] = {}
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), self._handler())
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    @property
    def url(self) -> str:
        host, port = self.server.server_address[:2]
        return f"http://{host}:{port}"

    def close(self) -> None:
        self.server.shutdown()
        self.thread.join(timeout=5)

    def _handler(self):
        registry = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, fmt: str, *args) -> None:
                return

            def do_GET(self) -> None:
                path = urllib.parse.unquote(self.path.split("?", 1)[0])
                blob = registry._tarball_for(path)
                if blob is not None:
                    self._send(200, "application/octet-stream", blob)
                    return
                try:
                    status, body = registry._fetch(
                        self.path, self.headers.get("Accept")
                    )
                except urllib.error.HTTPError as exc:
                    detail = exc.read()
                    self._send(exc.code, "text/plain", detail or str(exc).encode())
                    return
                body = registry._inject(path, body)
                self._send(status, "application/json", body)

            def do_POST(self) -> None:
                length = int(self.headers.get("Content-Length", "0") or 0)
                if length:
                    self.rfile.read(length)
                self._send(200, "application/json", b"{}")

            def _send(self, status: int, content_type: str, body: bytes) -> None:
                self.send_response(status)
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        return Handler

    def _fetch(self, path: str, accept: str | None) -> tuple[int, bytes]:
        request = urllib.request.Request(
            UPSTREAM + path,
            headers={
                "Accept": accept or "application/json",
                "Accept-Encoding": "identity",
                "User-Agent": "claude-image-supply-chain-test",
            },
        )
        with urllib.request.urlopen(request, timeout=60) as response:
            return response.status, response.read()

    def _tarball_for(self, path: str) -> bytes | None:
        with self._lock:
            return self._tarballs.get(path)

    def _inject(self, path: str, body: bytes) -> bytes:
        if "/-/" in path:
            return body
        name = path.lstrip("/")
        if name not in SHARP_PACKAGES:
            return body
        document = json.loads(body)
        versions = document.get("versions") or {}
        with self._lock:
            manifest = self._manifests.get(name)
            if manifest is None:
                base = versions.get("0.34.5")
                if base is None:
                    raise AssertionError(f"{name} packument has no 0.34.5 to clone")
                packed = {
                    "name": name,
                    "version": ATTACK_VERSION,
                    "os": base.get("os"),
                    "cpu": base.get("cpu"),
                    "libc": base.get("libc"),
                    "scripts": SCRIPTS,
                }
                blob = _tarball(packed)
                short = name.split("/", 1)[1]
                tarball_path = f"/{name}/-/{short}-{ATTACK_VERSION}.tgz"
                self._tarballs[tarball_path] = blob
                manifest = {
                    **packed,
                    "dist": {
                        "tarball": self.url + tarball_path,
                        "shasum": _sha1(blob),
                        "integrity": _sha512_integrity(blob),
                    },
                }
                self._manifests[name] = manifest
        versions[ATTACK_VERSION] = manifest
        document["versions"] = versions
        if isinstance(document.get("time"), dict):
            document["time"][ATTACK_VERSION] = "2026-11-20T00:00:00.000Z"
        return json.dumps(document).encode()


class Npm:
    def __init__(self, root: Path) -> None:
        tarball = root / f"npm-{NPM_VERSION}.tgz"
        request = urllib.request.Request(
            f"{UPSTREAM}/npm/-/npm-{NPM_VERSION}.tgz",
            headers={"User-Agent": "claude-image-supply-chain-test"},
        )
        with urllib.request.urlopen(request, timeout=120) as response:
            tarball.write_bytes(response.read())
        with tarfile.open(tarball, "r:gz") as archive:
            archive.extractall(root, filter="data")
        cli = root / "package" / "bin" / "npm-cli.js"
        bindir = root / "bin"
        bindir.mkdir()
        wrapper = bindir / "npm"
        # --prefix only for global installs. A local `npm ci` must stay in
        # the directory the Dockerfile copied the lockfile into; forcing
        # prefix on every invocation would send that install somewhere else.
        wrapper.write_text(
            "#!/bin/sh\n"
            "global=0\n"
            'for arg in "$@"; do\n'
            '  case "$arg" in\n'
            "    -g|--global) global=1 ;;\n"
            "  esac\n"
            "done\n"
            'if [ "$global" = 1 ]; then\n'
            f'  exec node {cli} --prefix "$IMAGE_PREFIX" "$@"\n'
            "fi\n"
            f'exec node {cli} "$@"\n'
        )
        wrapper.chmod(wrapper.stat().st_mode | stat.S_IEXEC)
        self.bin = wrapper
        self.cache = root / "cache"
        self.cache.mkdir()
        self.user_npmrc = root / "user.npmrc"
        self.global_npmrc = root / "global.npmrc"
        self.user_npmrc.write_text("")
        self.global_npmrc.write_text("")


def _resolve(sandbox: Path, workdir: Path, path: str) -> Path:
    if path.startswith("/"):
        return sandbox / path.lstrip("/")
    return workdir / path


def _copy_into(source: Path, dest: Path) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    if source.is_dir():
        if dest.exists() and dest.is_dir():
            target = dest / source.name
        else:
            target = dest
        shutil.copytree(source, target, dirs_exist_ok=True)
        return
    if dest.is_dir() or str(dest).endswith("/"):
        dest.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, dest / source.name)
        return
    shutil.copy2(source, dest)


def _apply_copy(context: Path, sandbox: Path, workdir: Path, args: str) -> None:
    import shlex

    parts = [part for part in shlex.split(args) if not part.startswith("--")]
    if len(parts) < 2:
        raise AssertionError(f"COPY needs a source and a destination: {args}")
    dest_arg = parts[-1]
    dest = _resolve(sandbox, workdir, dest_arg)
    if len(parts) > 2 or dest_arg.endswith("/"):
        dest.mkdir(parents=True, exist_ok=True)
    for src in parts[:-1]:
        source = context / src
        if not source.exists():
            raise AssertionError(f"COPY source is not in the build context: {src}")
        _copy_into(source, dest)


def run_dockerfile_npm(
    dockerfile: Path,
    npm: Npm,
    registry: Registry,
    sandbox: Path,
    cpu: str,
) -> list[subprocess.CompletedProcess[str]]:
    """Apply COPY/ENV/WORKDIR from the Dockerfile, then run each npm RUN.

    The registry, cache, and platform are supplied around the Dockerfile's own
    command line. A global install's prefix is a writable stand-in for the
    image prefix so the test does not need to be root; lifecycle scripts still
    run inside that prefix, which is the filesystem the image build keeps.
    """
    text = dockerfile.read_text()
    sandbox.mkdir(parents=True, exist_ok=True)
    workdir = sandbox
    env = os.environ.copy()
    env.update(
        {
            "HOME": str(sandbox / "home"),
            "IMAGE_PREFIX": str(sandbox / "prefix"),
            "npm_config_registry": registry.url,
            "npm_config_cache": str(npm.cache),
            "npm_config_cpu": cpu,
            "npm_config_os": "linux",
            "npm_config_libc": "glibc",
            "npm_config_update_notifier": "false",
            "npm_config_userconfig": str(npm.user_npmrc),
            "npm_config_globalconfig": str(npm.global_npmrc),
            "PATH": f"{npm.bin.parent}{os.pathsep}{env.get('PATH', '')}",
        }
    )
    (sandbox / "prefix").mkdir()
    (sandbox / "home").mkdir()
    ran: list[subprocess.CompletedProcess[str]] = []
    for name, args in _instructions(text):
        if name == "WORKDIR":
            workdir = _resolve(sandbox, sandbox, args)
            workdir.mkdir(parents=True, exist_ok=True)
        elif name == "ENV":
            key, separator, value = args.partition("=")
            if separator:
                env[key.strip()] = value
        elif name == "COPY":
            _apply_copy(CONTEXT, sandbox, workdir, args)
        elif name == "RUN" and _is_npm_command(args):
            ran.append(
                subprocess.run(
                    ["bash", "-lc", args],
                    cwd=workdir,
                    env=env,
                    text=True,
                    capture_output=True,
                    timeout=180,
                    check=False,
                )
            )
    if PINNED_SPEC in text and not ran:
        raise AssertionError(
            f"{dockerfile.relative_to(REPO)} still names {PINNED_SPEC} "
            "but no npm command was executed"
        )
    return ran


def _installed_attack_versions(prefix: Path) -> list[str]:
    found = []
    for manifest_path in prefix.rglob("package.json"):
        try:
            manifest = json.loads(manifest_path.read_text())
        except json.JSONDecodeError:
            continue
        if manifest.get("version") == ATTACK_VERSION and str(
            manifest.get("name", "")
        ).startswith("@img/sharp-"):
            found.append(f"{manifest['name']}@{manifest['version']} ({manifest_path})")
    return found


@pytest.fixture(scope="session")
def npm_tool(tmp_path_factory: pytest.TempPathFactory) -> Npm:
    return Npm(tmp_path_factory.mktemp("npm-11-20-0"))


@pytest.fixture(scope="session")
def registry() -> Registry:
    server = Registry()
    try:
        yield server
    finally:
        server.close()


@pytest.mark.parametrize("dockerfile", DOCKERFILES, ids=lambda path: path.parent.name)
@pytest.mark.parametrize("cpu", BUILD_CPUS)
def test_floated_sharp_release_cannot_modify_the_agent_image(
    dockerfile: Path, cpu: str, npm_tool: Npm, registry: Registry, tmp_path: Path
) -> None:
    sandbox = tmp_path / "image"
    results = run_dockerfile_npm(dockerfile, npm_tool, registry, sandbox, cpu)
    assert results, f"{dockerfile.name} did not run an npm install"
    failed = [result for result in results if result.returncode != 0]
    assert not failed, (
        f"npm command failed for {dockerfile.parent.name} cpu={cpu}:\n"
        + "\n".join(result.stderr[-2000:] for result in failed)
    )
    mutation = sandbox / "prefix" / MUTATION_NAME
    installed = _installed_attack_versions(sandbox / "prefix")
    assert not mutation.exists() and not installed, (
        f"{dockerfile.parent.name} on linux/{cpu} unpacked a {ATTACK_VERSION} "
        f"release of an @img/sharp optional dependency of {PINNED_SPEC} and "
        "ran its lifecycle scripts.\n"
        f"scripts wrote: {mutation.read_text() if mutation.exists() else '(no file)'}\n"
        f"installed: {installed or '(version not left on disk)'}\n"
        "Install the CLI with npm ci from a committed lockfile and do not run "
        "dependency lifecycle scripts."
    )
