"""A new release of an unpinned agent dependency must not run during the image install.

The runtime build (``stacks/runtime_stack.py``) docker-builds the agent
Dockerfiles and pushes that image for AgentCore to start with the runtime
role. Those Dockerfiles ``pip install`` direct requirements that are not
exact pins, as root, before ``USER``. pip selects the newest version the
specifier allows and, for an sdist, runs the package's build backend before
the later ``python`` start executes any ``.pth`` file the wheel installed.

The index used here is the index the Dockerfile already consults, with one
extra file on the project page: a freshly published release. That is the
registry input the install accepts today. The assertions below fail while
that release's code runs, and pass once the install no longer fetches or
executes it (exact pins and hashes both do that) and once the install is no
longer the root step of the image build.

Images whose direct requirements are already exact pins are not part of this
new-release path: ``agent-code/agui-strands-agent`` and
``agent-code/agui-langgraph-agent``. ``migration/simulation`` is a sample
customer image, not a Dockerfile ``RuntimeStack`` builds. Both are left
untested here.
"""

from __future__ import annotations

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
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
RUNTIME_STACK = REPO / "stacks" / "runtime_stack.py"
APP = REPO / "app.py"

# Pip shipped in the official images these Dockerfiles FROM, resolved from
# the image tag to CPython's ensurepip (the Dockerfiles do not upgrade pip):
#   public.ecr.aws/docker/library/python:3.11-slim -> CPython 3.11.18, pip 24.0
#   public.ecr.aws/docker/library/python:3.12-slim -> CPython 3.12.16, pip 25.0.1
#   public.ecr.aws/docker/library/python:3.13-slim -> CPython 3.13.18, pip 26.2.2
PIP_BY_PYTHON = {"3.11": "24.0", "3.12": "25.0.1", "3.13": "26.2.2"}

ATTACK_VERSION = "99.99.99"

# Every product image whose install accepts a newly published release.
# Kept as an explicit list so the install is still exercised after the pins
# land; discovery below also picks up any other runtime Dockerfile that grows
# a non-exact direct requirement.
REQUIRED_IMAGES = (
    "agent-code/orchestrator/Dockerfile",
    "agent-code/code-agent/Dockerfile",
    "agent-code/research-agent/Dockerfile",
    "agent-code/claude-sdk-agent/Dockerfile",
    "agent-code/claude-sdk-multi-agent/Dockerfile",
    "agent-code/strands-agent/Dockerfile",
    "agent-code/langgraph-agent/Dockerfile",
    "migration/adapter/Dockerfile",
)

_REQ_LINE = re.compile(r"^([A-Za-z0-9][A-Za-z0-9_.-]*)(\[[^\]]+\])?\s*([^#]*)$")
_EXACT = re.compile(r"^===\s*\S+$|^==\s*[0-9][^\s,]*$")


def _canonicalize(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _wheel_name(canonical: str) -> str:
    return canonical.replace("-", "_")


def _join_continuations(text: str) -> list[str]:
    logical: list[str] = []
    buf = ""
    for raw in text.splitlines():
        stripped = raw.strip()
        if not buf and (not stripped or stripped.startswith("#")):
            continue
        if stripped.endswith("\\"):
            buf += stripped[:-1] + " "
            continue
        buf += stripped
        logical.append(buf.strip())
        buf = ""
    if buf.strip():
        logical.append(buf.strip())
    return logical


def _instructions(text: str) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    for line in _join_continuations(text):
        parts = line.split(None, 1)
        if len(parts) < 2:
            continue
        out.append((parts[0].upper(), parts[1]))
    return out


def _parse_requirement(text: str) -> tuple[str, str, str] | None:
    """Return (canonical name, extras csv, specifier) or None if not a requirement."""
    cleaned = text.strip().strip("\"'")
    if not cleaned or cleaned.startswith(("#", "-")):
        return None
    cleaned = cleaned.split(";", 1)[0]
    cleaned = re.sub(r"\s--hash=\S+", "", cleaned).strip()
    match = _REQ_LINE.match(cleaned)
    if not match:
        return None
    name, extras, spec = match.group(1), match.group(2) or "", match.group(3)
    extra_csv = extras.strip("[]")
    return _canonicalize(name), extra_csv, spec.strip()


def _is_exact(spec: str) -> bool:
    return (
        bool(spec) and bool(_EXACT.match(spec)) and "*" not in spec and "," not in spec
    )


def _requirement_from_token(token: str) -> tuple[str, str, str] | None:
    if token.startswith("-") or token in {".", ".."}:
        return None
    return _parse_requirement(token)


_PIP_INSTALL = re.compile(
    r"(?:python3?\s+-m\s+)?pip3?\s+install\b(?:\s+(?:\"[^\"]*\"|'[^']*'|[^\s;&|]+))*"
)


def _pip_commands(script: str) -> list[str]:
    """pip install invocations in a Dockerfile RUN body, not apt installs."""
    return [match.group(0).strip() for match in _PIP_INSTALL.finditer(script)]


def _iter_install_args(command: str) -> list[str]:
    try:
        import shlex

        tokens = shlex.split(command)
    except ValueError:
        tokens = command.split()
    if "install" not in tokens:
        return []
    tokens = tokens[tokens.index("install") + 1 :]
    args: list[str] = []
    skip_next = False
    for token in tokens:
        if skip_next:
            skip_next = False
            continue
        if token in {"-r", "--requirement", "-c", "--constraint", "-f", "--find-links"}:
            skip_next = True
            continue
        if token.startswith("-"):
            continue
        parsed = _requirement_from_token(token)
        if parsed:
            args.append(token.strip("\"'"))
    return args


def _requirement_files(command: str) -> list[str]:
    try:
        import shlex

        tokens = shlex.split(command)
    except ValueError:
        tokens = command.split()
    files: list[str] = []
    for index, token in enumerate(tokens):
        if token in {"-r", "--requirement"} and index + 1 < len(tokens):
            files.append(tokens[index + 1].strip("\"'"))
        elif token.startswith("--requirement="):
            files.append(token.split("=", 1)[1].strip("\"'"))
    return files


def _read_requirements(path: Path) -> list[tuple[str, str, str]]:
    parsed: list[tuple[str, str, str]] = []
    if not path.is_file():
        return parsed
    for line in path.read_text().splitlines():
        item = _parse_requirement(line)
        if item:
            parsed.append(item)
    return parsed


def _copy_pairs(arg: str) -> list[tuple[str, str]]:
    """Return (workdir-relative dest, context-relative source) for a COPY."""
    tokens = [token for token in arg.split() if not token.startswith("--")]
    if len(tokens) < 2:
        return []
    dest_token, sources = tokens[-1], tokens[:-1]
    pairs = []
    directory_dest = dest_token == "." or dest_token.endswith("/") or len(sources) > 1
    for source in sources:
        if directory_dest:
            dest = (
                Path(source).name
                if dest_token == "."
                else str(Path(dest_token) / Path(source).name)
            )
        else:
            dest = dest_token
        pairs.append((dest, source))
    return pairs


def _context_for(dockerfile: Path) -> Path:
    rel = dockerfile.relative_to(REPO).as_posix()
    if rel.startswith("agent-code/"):
        # RuntimeStack builds ``-f <pattern>/Dockerfile .`` with context agent-code/.
        return REPO / "agent-code"
    if rel == "migration/adapter/Dockerfile":
        # The migration buildspec's context is the adapter directory.
        return REPO / "migration" / "adapter"
    raise AssertionError(f"no runtime build context for {rel}")


def _pip_version_for(dockerfile_text: str) -> str:
    match = re.search(
        r"^FROM\s+\S*python:(3\.\d+)",
        dockerfile_text,
        re.MULTILINE,
    )
    if not match:
        # migration/adapter/Dockerfile is FROM ${SOURCE_IMAGE}. The product's
        # own agent images ship pip 26.2.2 (CPython 3.13.18) and pip 24.0
        # (CPython 3.11.18); the adapter command is what selects the release.
        # Exercise the newer of those two.
        return PIP_BY_PYTHON["3.13"]
    minor = match.group(1)
    if minor not in PIP_BY_PYTHON:
        raise AssertionError(f"no pinned pip for base image Python {minor}")
    return PIP_BY_PYTHON[minor]


def _privileges_dropped(command: str) -> bool:
    if re.search(r"\b(runuser|gosu)\s+(?!root\b|0\b)\S+", command):
        return True
    if re.search(r"\bsudo\s+-u\s+(?!root\b|0\b)\S+", command):
        return True
    return bool(re.search(r"\bsu\s+(?!-|root\b|0\b)\S+", command))


class _ImageInstall:
    def __init__(self, dockerfile: Path):
        self.dockerfile = dockerfile
        self.rel = dockerfile.relative_to(REPO).as_posix()
        self.text = dockerfile.read_text()
        self.context = _context_for(dockerfile)
        self.pip_version = _pip_version_for(self.text)
        self.commands: list[tuple[str, str]] = []
        self.requirements: list[tuple[str, str, str]] = []
        self.pip_users: list[str] = []
        # COPY operations as (image workdir, raw arg), replayed into the temp root.
        self._copies: list[tuple[str, str]] = []
        self._walk()

    def _walk(self) -> None:
        # Base image Config.User is empty. Docker runs the following steps as root
        # until a USER instruction.
        user = "root"
        image_workdir = "/"
        # dest path relative to the image workdir -> source path in the build context
        copied: dict[tuple[str, str], Path] = {}
        for opcode, arg in _instructions(self.text):
            if opcode == "WORKDIR":
                image_workdir = arg.split()[0]
                continue
            if opcode == "USER":
                user = arg.split()[0]
                continue
            if opcode == "COPY":
                self._copies.append((image_workdir, arg))
                for dest, src in _copy_pairs(arg):
                    copied[(image_workdir, dest)] = self.context / src
                continue
            if opcode != "RUN":
                continue
            for command in _pip_commands(arg):
                self.commands.append((image_workdir, command))
                effective = user if not _privileges_dropped(command) else "nonroot"
                self.pip_users.append(effective)
                for rel in _requirement_files(command):
                    source = copied.get((image_workdir, rel))
                    if source is not None:
                        self.requirements.extend(_read_requirements(source))
                for token in _iter_install_args(command):
                    parsed = _parse_requirement(token)
                    if parsed:
                        self.requirements.append(parsed)

    def floated(self) -> list[tuple[str, str, str]]:
        return [item for item in self.requirements if not _is_exact(item[2])]

    def prepare(self, root: Path) -> list[tuple[Path, str]]:
        """Replay COPY into ``root`` (standing in for the image workdir) and
        return (cwd, shell command) pairs for each pip install."""
        workdirs: dict[str, Path] = {}

        def host_for(image_workdir: str) -> Path:
            # These Dockerfiles use a single WORKDIR. Map it onto ``root``.
            folder = workdirs.get(image_workdir)
            if folder is None:
                folder = root
                workdirs[image_workdir] = folder
                folder.mkdir(parents=True, exist_ok=True)
            return folder

        for image_workdir, arg in self._copies:
            tokens = arg.split()
            # ``COPY --chown=... src dest`` is not used before these installs.
            tokens = [token for token in tokens if not token.startswith("--")]
            if len(tokens) < 2:
                continue
            dest_token = tokens[-1]
            sources = tokens[:-1]
            dest_root = host_for(image_workdir)
            directory_dest = (
                dest_token == "." or dest_token.endswith("/") or len(sources) > 1
            )
            # Absolute image paths must stay inside the temp root. Path
            # division drops the left operand when the right one is absolute.
            placed = dest_root / dest_token.removeprefix("/")
            for source in sources:
                src_path = self.context / source
                if directory_dest:
                    dest_dir = dest_root if dest_token == "." else placed
                    dest_path = dest_dir / Path(source).name
                else:
                    dest_path = placed
                if src_path.is_dir():
                    shutil.copytree(src_path, dest_path, dirs_exist_ok=True)
                elif src_path.is_file():
                    dest_path.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(src_path, dest_path)
                # A missing source is a Dockerfile bug the install will surface.

        commands: list[tuple[Path, str]] = []
        for image_workdir, command in self.commands:
            commands.append((host_for(image_workdir), command))
        return commands


def _images() -> list[_ImageInstall]:
    found: dict[str, _ImageInstall] = {}
    for rel in REQUIRED_IMAGES:
        path = REPO / rel
        assert path.is_file(), rel
        found[rel] = _ImageInstall(path)
    # Any other runtime Dockerfile with a non-exact direct requirement.
    candidates = list((REPO / "agent-code").glob("*/Dockerfile"))
    candidates.append(REPO / "migration" / "adapter" / "Dockerfile")
    for path in candidates:
        rel = path.relative_to(REPO).as_posix()
        if rel in found:
            continue
        image = _ImageInstall(path)
        if image.floated():
            found[rel] = image
    return [found[key] for key in sorted(found)]


def _images_with_commands(
    tmp: Path,
) -> list[tuple[_ImageInstall, list[tuple[Path, str]]]]:
    prepared = []
    for image in _images():
        root = tmp / image.rel.replace("/", "_")
        commands = image.prepare(root)
        prepared.append((image, commands))
    return prepared


def _write_sdist(directory: Path, canonical: str, extras: set[str]) -> Path:
    """Sdist whose build backend records that it ran, and whose wheel plants a .pth."""
    version = ATTACK_VERSION
    folder_name = f"{canonical}-{version}"
    stage = directory / folder_name
    stage.mkdir(parents=True)
    extra_items = [repr(extra) for extra in sorted(extras) if extra]
    extras_src = "(" + ", ".join(extra_items) + ("," if extra_items else "") + ")"
    backend = f"""\
import base64, hashlib, os, zipfile
from pathlib import Path

NAME = {canonical!r}
VERSION = {version!r}
WHEEL = {(_wheel_name(canonical) + "-" + version)!r}
EXTRAS = {extras_src}

def _mark(kind):
    path = os.environ.get("ATTACK_MARKER")
    if not path:
        return
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, "a", encoding="utf-8") as handle:
        handle.write("%s euid=%s\\n" % (kind, os.geteuid()))

def get_requires_for_build_wheel(config_settings=None):
    _mark("get_requires")
    return []

def get_requires_for_build_editable(config_settings=None):
    _mark("get_requires")
    return []

def _metadata():
    lines = [
        "Metadata-Version: 2.1",
        "Name: %s" % NAME,
        "Version: %s" % VERSION,
    ]
    for extra in EXTRAS:
        lines.append("Provides-Extra: %s" % extra)
    return ("\\n".join(lines) + "\\n").encode()

def _wheel_bytes():
    marker = os.environ.get("ATTACK_MARKER", "")
    # One physical line: site.py execs a .pth line only when it starts with import.
    payload = (
        "import os,pathlib; pathlib.Path(%r).open('a',encoding='utf-8').write('startup euid='+str(os.geteuid()))"
        % marker
    ).encode()
    dist_info = WHEEL + ".dist-info"
    files = {{
        "attack.pth": payload,
        dist_info + "/METADATA": _metadata(),
        dist_info + "/WHEEL": b"Wheel-Version: 1.0\\nGenerator: attack-fixture\\nRoot-Is-Purelib: true\\nTag: py3-none-any\\n",
    }}
    record_lines = []
    for name, data in sorted(files.items()):
        digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).decode().rstrip("=")
        record_lines.append("%s,sha256=%s,%d" % (name, digest, len(data)))
    record_lines.append(dist_info + "/RECORD,,")
    files[dist_info + "/RECORD"] = ("\\n".join(record_lines) + "\\n").encode()
    return files

def build_wheel(wheel_directory, config_settings=None, metadata_directory=None):
    _mark("build_wheel")
    filename = WHEEL + "-py3-none-any.whl"
    path = Path(wheel_directory) / filename
    with zipfile.ZipFile(path, "w") as archive:
        for name, data in _wheel_bytes().items():
            archive.writestr(name, data)
    return filename

def prepare_metadata_for_build_wheel(metadata_directory, config_settings=None):
    _mark("prepare_metadata")
    dist_info = WHEEL + ".dist-info"
    dest = Path(metadata_directory) / dist_info
    dest.mkdir(parents=True, exist_ok=True)
    (dest / "METADATA").write_bytes(_metadata())
    (dest / "WHEEL").write_bytes(b"Wheel-Version: 1.0\\nGenerator: attack-fixture\\nRoot-Is-Purelib: true\\nTag: py3-none-any\\n")
    return dist_info
"""
    (stage / "attacker_backend.py").write_text(backend)
    (stage / "pyproject.toml").write_text(
        textwrap.dedent(
            f"""\
            [build-system]
            requires = []
            build-backend = "attacker_backend"
            backend-path = ["."]

            [project]
            name = "{canonical}"
            version = "{version}"
            """
        )
    )
    archive_path = directory / f"{canonical}-{version}.tar.gz"
    with tarfile.open(archive_path, "w:gz") as archive:
        archive.add(stage, arcname=folder_name)
    return archive_path


class _Index(threading.Thread):
    def __init__(self, files: dict[str, Path]):
        super().__init__(daemon=True)
        self.files = files
        self._digests = {
            name: hashlib.sha256(path.read_bytes()).hexdigest()
            for name, path in files.items()
        }

        outer = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, fmt: str, *args) -> None:
                return

            def do_HEAD(self) -> None:
                self._handle(head=True)

            def do_GET(self) -> None:
                self._handle(head=False)

            def _handle(self, head: bool) -> None:
                path = self.path.split("?", 1)[0]
                if path.startswith("/packages/"):
                    name = path.rsplit("/", 1)[-1]
                    blob = outer.files.get(name)
                    if blob is None or not blob.is_file():
                        self.send_error(404)
                        return
                    data = blob.read_bytes()
                    self.send_response(200)
                    self.send_header("Content-Type", "application/octet-stream")
                    self.send_header("Content-Length", str(len(data)))
                    self.end_headers()
                    if not head:
                        self.wfile.write(data)
                    return
                if not path.startswith("/simple/"):
                    self.send_error(404)
                    return
                project = [part for part in path.split("/") if part][1:]
                if not project:
                    self.send_error(404)
                    return
                canonical = _canonicalize(project[0])
                body = outer._simple_page(canonical)
                data = json.dumps(body).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/vnd.pypi.simple.v1+json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                if not head:
                    self.wfile.write(data)

        self._httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = self._httpd.server_address[1]

    def _simple_page(self, canonical: str) -> dict:
        upstream = self._upstream(canonical)
        filename = f"{canonical}-{ATTACK_VERSION}.tar.gz"
        if filename in self.files:
            upstream.setdefault("files", []).append(
                {
                    "filename": filename,
                    "url": f"http://127.0.0.1:{self.port}/packages/{filename}",
                    "hashes": {"sha256": self._digests[filename]},
                    "requires-python": ">=3.9",
                    "yanked": False,
                }
            )
        upstream.setdefault("name", canonical)
        upstream.setdefault("files", [])
        return upstream

    def _upstream(self, canonical: str) -> dict:
        url = f"https://pypi.org/simple/{canonical}/"
        request = urllib.request.Request(
            url,
            headers={
                "Accept": "application/vnd.pypi.simple.v1+json",
                "User-Agent": "agent-image-install-test",
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=60) as response:
                payload = json.loads(response.read().decode())
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                return {"name": canonical, "files": []}
            raise
        if not isinstance(payload, dict):
            raise TypeError(f"unexpected simple index document for {canonical}")
        return payload

    def run(self) -> None:
        self._httpd.serve_forever()

    def stop(self) -> None:
        self._httpd.shutdown()


def _secure_refusal(output: str) -> bool:
    lowered = output.lower()
    needles = (
        "hash",
        "unpinned",
        "these packages do not match",
        "could not find a version that satisfies",
        "no matching distribution",
    )
    return any(needle in lowered for needle in needles)


@pytest.fixture(scope="module")
def built_images(tmp_path_factory: pytest.TempPathFactory):
    root = tmp_path_factory.mktemp("image-installs")
    prepared = _images_with_commands(root)
    files_dir = root / "sdists"
    files_dir.mkdir()
    extras_by_name: dict[str, set[str]] = {}
    for image, _commands in prepared:
        for canonical, extra_csv, spec in image.requirements:
            if _is_exact(spec):
                continue
            extras_by_name.setdefault(canonical, set())
            for extra in extra_csv.split(","):
                extra = extra.strip()
                if extra:
                    extras_by_name[canonical].add(extra)
    blobs: dict[str, Path] = {}
    for canonical, extras in extras_by_name.items():
        archive = _write_sdist(files_dir / canonical, canonical, extras)
        blobs[archive.name] = archive
    index = _Index(blobs)
    index.start()
    yield prepared, index
    index.stop()


def _run_install(
    image: _ImageInstall, commands: list[tuple[Path, str]], index: _Index, tmp: Path
):
    venv = tmp / "venv"
    subprocess.check_call(
        [sys.executable, "-m", "venv", str(venv)],
        stdout=subprocess.DEVNULL,
    )
    pip = venv / "bin" / "pip"
    subprocess.check_call(
        [
            str(pip),
            "install",
            "--disable-pip-version-check",
            f"pip=={image.pip_version}",
        ],
        stdout=subprocess.DEVNULL,
    )
    marker = tmp / "marker.txt"
    env = os.environ.copy()
    env["PATH"] = str(venv / "bin") + os.pathsep + env.get("PATH", "")
    env["PIP_INDEX_URL"] = f"http://127.0.0.1:{index.port}/simple"
    env["PIP_DISABLE_PIP_VERSION_CHECK"] = "1"
    env["ATTACK_MARKER"] = str(marker)
    # The local index is the stand-in for the default index. Keep a proxy from
    # steering 127.0.0.1 at something else; pypi.org is fetched by the index.
    prior = env.get("NO_PROXY", env.get("no_proxy", ""))
    env["NO_PROXY"] = ",".join(
        part for part in ("127.0.0.1", "localhost", prior) if part
    )
    env["no_proxy"] = env["NO_PROXY"]
    outputs: list[str] = []
    return_code = 0
    for cwd, command in commands:
        completed = subprocess.run(
            ["bash", "-c", command],
            cwd=cwd,
            env=env,
            text=True,
            capture_output=True,
            timeout=300,
            check=False,
        )
        outputs.append(f"$ {command}\n{completed.stdout}\n{completed.stderr}")
        if completed.returncode != 0:
            return_code = completed.returncode
            break
    # The image CMD starts Python. site.py executes ``import `` lines in .pth
    # files while doing that, which is the runtime half of the planted wheel.
    startup = subprocess.run(
        [str(venv / "bin" / "python"), "-c", "pass"],
        env=env,
        text=True,
        capture_output=True,
        timeout=60,
        check=False,
    )
    freeze = subprocess.run(
        [str(venv / "bin" / "pip"), "freeze"],
        env=env,
        text=True,
        capture_output=True,
        timeout=60,
        check=False,
    )
    marker_text = marker.read_text() if marker.is_file() else ""
    return {
        "return_code": return_code,
        "output": "\n".join(outputs),
        "startup": startup.stderr + startup.stdout,
        "freeze": freeze.stdout,
        "marker": marker_text,
    }


def test_default_presets_and_runtime_publish_the_built_image():
    """The install under test is the image the default deploy builds and runs.

    Greenfield and distributed select the orchestrator pattern. RuntimeStack
    builds that Dockerfile in a privileged CodeBuild project, pushes the tag
    it just built, and starts that tag with the runtime role whose policy
    reads memory, the identity token vault, and workload access tokens.
    """
    for preset in ("presets/greenfield.yaml", "presets/distributed.yaml"):
        text = (REPO / preset).read_text()
        assert re.search(r"(?m)^agents:\n(?:  .*\n)*  pattern: orchestrator\b", text), (
            preset
        )

    app = APP.read_text()
    assert 'cfg("agent_pattern", "AGENT_PATTERN", "orchestrator")' in app
    assert "dockerfile_pattern=agent_pattern" in app
    assert 'dockerfile_pattern="code-agent"' in app
    assert 'dockerfile_pattern="research-agent"' in app

    stack = RUNTIME_STACK.read_text()
    assert "privileged=True" in stack
    assert (
        "docker build --platform linux/arm64 -f {dockerfile_pattern}/Dockerfile -t $REPO_URI:$IMAGE_TAG ."
        in stack
    )
    assert "docker push $REPO_URI:$IMAGE_TAG" in stack
    assert "repo.grant_push(build_project)" in stack
    assert '"role_arn": runtime_role.role_arn' in stack
    assert 'f"{repo.repository_uri}:{image_tag}"' in stack
    for action in (
        "bedrock-agentcore:CreateEvent",
        "bedrock-agentcore:GetEvent",
        "bedrock-agentcore:RetrieveMemoryRecords",
        "bedrock-agentcore:GetWorkloadAccessToken",
        "bedrock-agentcore:GetWorkloadAccessTokenForJWT",
        "bedrock-agentcore:GetWorkloadAccessTokenForUserId",
        "bedrock-agentcore:GetResourceOauth2Token",
        "secretsmanager:GetSecretValue",
    ):
        assert action in stack


@pytest.mark.parametrize("rel", REQUIRED_IMAGES)
def test_requirement_install_does_not_run_as_root(rel: str):
    """The pip install that fetches agent dependencies is a root step today.

    The official Python base images leave Config.User empty, so the RUN before
    the first USER instruction executes as root. A non-root install (a USER
    before that RUN, or the pip command itself dropped to another user) is the
    fix this asserts.
    """
    image = _ImageInstall(REPO / rel)
    assert image.commands, f"{rel} no longer installs Python packages"
    root_commands = [
        command
        for user, (_cwd, command) in zip(image.pip_users, image.commands, strict=True)
        if user in {"", "root", "0"}
    ]
    assert not root_commands, (
        f"{rel} installs dependencies as root: {root_commands}. "
        "The base image does not set a user, and this RUN is before USER."
    )


def test_new_release_code_does_not_run_during_image_install(built_images, tmp_path):
    """Publishing a newer release of a direct requirement must not execute it.

    For each runtime image, run the Dockerfile's own pip install commands
    against an index that also offers that release. The release's build
    backend and the .pth it would install must not run.
    """
    prepared, index = built_images
    failures: list[str] = []
    for image, commands in prepared:
        assert commands, f"{image.rel} has no pip install to execute"
        floated = image.floated()
        for canonical, _extras, _spec in floated:
            page_url = f"http://127.0.0.1:{index.port}/simple/{canonical}/"
            with urllib.request.urlopen(page_url, timeout=60) as response:
                body = response.read()
            assert ATTACK_VERSION.encode() in body, (
                f"the index did not offer the new {canonical} release to {image.rel}"
            )
        result = _run_install(
            image, commands, index, tmp_path / image.rel.replace("/", "_")
        )
        executed = result["marker"].strip()
        installed = ATTACK_VERSION in result["freeze"]
        if executed or installed:
            failures.append(
                f"{image.rel} executed the new release with pip {image.pip_version}\n"
                f"marker:\n{executed or '(empty)'}\n"
                f"freeze contains {ATTACK_VERSION}: {installed}\n"
                f"pip exit {result['return_code']}\n{result['output'][-4000:]}\n"
                f"startup:\n{result['startup'][-1000:]}"
            )
            continue
        if result["return_code"] != 0 and not _secure_refusal(result["output"]):
            failures.append(
                f"{image.rel} install failed without refusing the new release "
                f"(pip {image.pip_version}, exit {result['return_code']}):\n"
                f"{result['output'][-4000:]}"
            )
    assert not failures, "\n\n".join(failures)
