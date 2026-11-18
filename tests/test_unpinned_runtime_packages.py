"""Supply-chain installs of bedrock-agentcore and boto3 into runtime images.

These tests fail while a migration or agent image build will accept a higher
or substituted release of those packages. They pass once every install named
here pins both packages to an exact version and checks the wheel hashes, so
the release served by the index is not what the runtime process imports.
"""

from __future__ import annotations

import base64
import hashlib
import http.server
import io
import json
import os
import re
import shlex
import shutil
import socket
import subprocess
import sys
import textwrap
import threading
import uuid
import zipfile
from pathlib import Path

import aws_cdk as cdk
import pytest
from aws_cdk.assertions import Template
from pip._vendor.packaging.requirements import Requirement
from pip._vendor.packaging.utils import canonicalize_name
from pip._vendor.packaging.version import Version

from stacks.runtime_stack import RuntimeStack

REPO = Path(__file__).resolve().parents[1]
ENV = cdk.Environment(account="111111111111", region="us-east-1")
NONCE = uuid.uuid4().hex
BEDROCK = "bedrock-agentcore"
BOTO3 = "boto3"
# Both versions are attacker-controlled bytes. A minimum constraint selects the
# higher one; an exact pin without a hash still selects the substituted wheel.
BEDROCK_ATTACK_VERSIONS = ("1.21.0", "9.9.9")
BOTO3_ATTACK_VERSIONS = ("1.43.35", "99.0.0")
ATTACK_VERSIONS = {
    BEDROCK: set(BEDROCK_ATTACK_VERSIONS),
    BOTO3: set(BOTO3_ATTACK_VERSIONS),
}
DATA_PLANE_ACTIONS = {
    "bedrock-agentcore:InvokeAgentRuntime",
    "bedrock-agentcore:InvokeGateway",
    "bedrock-agentcore:GetWorkloadAccessToken",
    "bedrock-agentcore:GetWorkloadAccessTokenForJWT",
    "bedrock-agentcore:GetWorkloadAccessTokenForUserId",
    "bedrock-agentcore:CreateEvent",
    "bedrock-agentcore:RetrieveMemoryRecords",
}

# Entrypoints that import bedrock-agentcore while the image build installs it
# from an unpinned requirement. code-agent installs the same unpinned
# requirement but its entrypoint never imports the package, so it is not here.
# agui-langgraph-agent, agui-strands-agent, and langgraph-agent already require
# bedrock-agentcore==1.21.0, so a higher release is not selected; hash
# substitution of that exact file is not covered.
RUNTIME_IMAGE_INSTALLS = (
    {
        "id": "strands-agent",
        "dockerfile": REPO / "agent-code/strands-agent/Dockerfile",
        "requirements": REPO / "agent-code/strands-agent/requirements.txt",
        "entrypoint": REPO / "agent-code/strands-agent/agent.py",
        "pythonpath": [REPO / "agent-code", REPO / "agent-code/strands-agent"],
        "packages": (BEDROCK,),
    },
    {
        "id": "orchestrator",
        "dockerfile": REPO / "agent-code/orchestrator/Dockerfile",
        "requirements": REPO / "agent-code/orchestrator/requirements.txt",
        "entrypoint": REPO / "agent-code/orchestrator/agent.py",
        "pythonpath": [REPO / "agent-code", REPO / "agent-code/orchestrator"],
        "packages": (BEDROCK,),
    },
    {
        "id": "research-agent",
        "dockerfile": REPO / "agent-code/research-agent/Dockerfile",
        "requirements": REPO / "agent-code/research-agent/requirements.txt",
        "entrypoint": REPO / "agent-code/research-agent/agent.py",
        "pythonpath": [REPO / "agent-code", REPO / "agent-code/research-agent"],
        "packages": (BEDROCK,),
        "stubs": {
            "uvicorn.py": "def run(*_a, **_k):\n    pass\n",
            "jwt.py": "class PyJWKClient:\n    def __init__(self, *_a, **_k):\n        pass\n",
            "strands/__init__.py": "class Agent:\n    def __init__(self, *_a, **_k):\n        pass\n",
            "strands/models.py": "class BedrockModel:\n    def __init__(self, *_a, **_k):\n        pass\n",
            "strands/multiagent/__init__.py": "",
            "strands/multiagent/a2a.py": "class A2AServer:\n    def __init__(self, *_a, **_k):\n        pass\n",
        },
    },
    {
        "id": "claude-sdk-agent",
        "dockerfile": REPO / "agent-code/claude-sdk-agent/Dockerfile",
        "requirements": REPO / "agent-code/claude-sdk-agent/requirements.txt",
        "entrypoint": REPO / "agent-code/claude-sdk-agent/agent.py",
        "pythonpath": [REPO / "agent-code", REPO / "agent-code/claude-sdk-agent"],
        "packages": (BEDROCK, BOTO3),
    },
    {
        "id": "claude-sdk-multi-agent",
        "dockerfile": REPO / "agent-code/claude-sdk-multi-agent/Dockerfile",
        "requirements": REPO / "agent-code/claude-sdk-multi-agent/requirements.txt",
        "entrypoint": REPO / "agent-code/claude-sdk-multi-agent/agent.py",
        "pythonpath": [
            REPO / "agent-code",
            REPO / "agent-code/claude-sdk-multi-agent",
        ],
        "packages": (BEDROCK, BOTO3),
        "stubs": {
            "claude_agent_sdk.py": "class AgentDefinition:\n    def __init__(self, *_a, **_k):\n        pass\n",
        },
    },
)


def _wheel(name: str, version: str, files: dict[str, bytes]) -> tuple[str, bytes]:
    distribution = name.replace("-", "_")
    info = f"{distribution}-{version}.dist-info"
    metadata = (
        "Metadata-Version: 2.1\n"
        f"Name: {name}\n"
        f"Version: {version}\n"
        "Summary: index fixture\n"
        "Requires-Python: >=3.8\n"
        "Provides-Extra: crypto\n"
        "Provides-Extra: a2a\n"
    ).encode()
    wheel_meta = (
        b"Wheel-Version: 1.0\n"
        b"Generator: test_unpinned_runtime_packages\n"
        b"Root-Is-Purelib: true\n"
        b"Tag: py3-none-any\n"
    )
    payload = {f"{info}/METADATA": metadata, f"{info}/WHEEL": wheel_meta, **files}
    record = []
    for path, data in sorted(payload.items()):
        digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).decode().rstrip("=")
        record.append(f"{path},sha256={digest},{len(data)}")
    record.append(f"{info}/RECORD,,")
    payload[f"{info}/RECORD"] = ("\n".join(record) + "\n").encode()
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for path, data in payload.items():
            archive.writestr(path, data)
    return f"{distribution}-{version}-py3-none-any.whl", buffer.getvalue()


def _bedrock_files() -> dict[str, bytes]:
    marker = "ATTACK_BEDROCK_MARKER"
    init = textwrap.dedent(
        f"""
        import os
        from pathlib import Path
        path = os.environ.get({marker!r}, "")
        if path:
            Path(path).write_text("import bedrock_agentcore {NONCE}\\n")
        """
    ).encode()
    runtime = textwrap.dedent(
        f"""
        import os
        class RequestContext:
            pass
        class BedrockAgentCoreApp:
            def __init__(self, *_args, **_kwargs):
                path = os.environ.get({marker!r}, "")
                if path:
                    with open(path, "a", encoding="utf-8") as handle:
                        handle.write("BedrockAgentCoreApp {NONCE}\\n")
            def entrypoint(self, function):
                return function
            def run(self):
                return None
        """
    ).encode()
    auth = b"def requires_access_token(*_a, **_k):\n    return lambda function: function\n"
    return {
        "bedrock_agentcore/__init__.py": init,
        "bedrock_agentcore/runtime.py": runtime,
        "bedrock_agentcore/identity/__init__.py": b"",
        "bedrock_agentcore/identity/auth.py": auth,
    }


def _boto3_files() -> dict[str, bytes]:
    marker = "ATTACK_BOTO_MARKER"
    init = textwrap.dedent(
        f"""
        import os
        from pathlib import Path
        def _note(text):
            path = os.environ.get({marker!r}, "")
            if path:
                Path(path).open("a", encoding="utf-8").write(text + "\\n")
        _note("import boto3 {NONCE}")
        def client(*_args, **_kwargs):
            _note("boto3.client {NONCE}")
            raise RuntimeError("attacker boto3 client")
        def Session(*_args, **_kwargs):
            _note("boto3.Session {NONCE}")
            raise RuntimeError("attacker boto3 session")
        """
    ).encode()
    return {"boto3/__init__.py": init}


def _requirement_lines(path: Path) -> list[str]:
    lines = []
    for raw in path.read_text().splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith("-"):
            continue
        lines.append(line)
    return lines


def _version_for(requirement: Requirement) -> str:
    for spec in requirement.specifier:
        if spec.operator in {"==", "==="}:
            return spec.version
    for spec in requirement.specifier:
        if spec.operator in {">=", ">", "~="}:
            return spec.version
    return "1.0.0"


def _build_index(root: Path) -> None:
    packages = root / "packages"
    simple = root / "simple"
    packages.mkdir()
    simple.mkdir()
    wheels: dict[str, list[tuple[str, bytes]]] = {}

    def add(name: str, version: str, files: dict[str, bytes]) -> None:
        filename, blob = _wheel(name, version, files)
        (packages / filename).write_bytes(blob)
        wheels.setdefault(canonicalize_name(name), []).append((filename, blob))

    for version in BEDROCK_ATTACK_VERSIONS:
        add(BEDROCK, version, _bedrock_files())
    for version in BOTO3_ATTACK_VERSIONS:
        add(BOTO3, version, _boto3_files())

    requirement_files = [case["requirements"] for case in RUNTIME_IMAGE_INSTALLS]
    for path in requirement_files:
        for line in _requirement_lines(path):
            requirement = Requirement(line)
            if canonicalize_name(requirement.name) in {BEDROCK, BOTO3}:
                continue
            version = _version_for(requirement)
            if not requirement.specifier.contains(Version(version), prereleases=True):
                raise RuntimeError(f"no stub version satisfies {line}")
            add(requirement.name, version, {})

    for name, built in wheels.items():
        page = simple / name
        page.mkdir()
        links = []
        for filename, blob in built:
            digest = hashlib.sha256(blob).hexdigest()
            links.append(
                f'<a href="/packages/{filename}#sha256={digest}">{filename}</a>'
            )
        (page / "index.html").write_text(
            "<!DOCTYPE html><html><body>\n" + "<br>\n".join(links) + "\n</body></html>\n"
        )


class _QuietHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, _format: str, *_args) -> None:
        return


@pytest.fixture(scope="module")
def attacker_index(tmp_path_factory: pytest.TempPathFactory) -> str:
    root = tmp_path_factory.mktemp("index")
    _build_index(root)
    def handler(*args, **kwargs):
        return _QuietHandler(*args, directory=str(root), **kwargs)

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    port = server.server_address[1]
    with socket.create_connection(("127.0.0.1", port), timeout=5):
        pass
    yield f"http://127.0.0.1:{port}/simple/"
    server.shutdown()


def _join_dockerfile(text: str) -> list[str]:
    instructions = []
    buffer = ""
    for raw in text.splitlines():
        stripped = raw.strip()
        if not buffer and (not stripped or stripped.startswith("#")):
            continue
        buffer = f"{buffer} {stripped}".strip() if buffer else stripped
        if buffer.endswith("\\"):
            buffer = buffer[:-1].rstrip()
            continue
        instructions.append(buffer)
        buffer = ""
    if buffer:
        instructions.append(buffer)
    return instructions


def _split_chain(command: str) -> list[str]:
    parts: list[str] = []
    buf: list[str] = []
    quote = ""
    index = 0
    while index < len(command):
        char = command[index]
        if quote:
            buf.append(char)
            if char == quote:
                quote = ""
            index += 1
            continue
        if char in {"'", '"'}:
            quote = char
            buf.append(char)
            index += 1
            continue
        if command.startswith("&&", index) or command.startswith("||", index):
            parts.append("".join(buf).strip())
            buf = []
            index += 2
            continue
        buf.append(char)
        index += 1
    parts.append("".join(buf).strip())
    return [part for part in parts if part]


def _pip_install_args(command: str) -> list[str] | None:
    try:
        tokens = shlex.split(command)
    except ValueError:
        return None
    if "pip" not in tokens or "install" not in tokens:
        return None
    return tokens[tokens.index("install") + 1 :]


def _install_commands(dockerfile: Path) -> list[list[str]]:
    commands = []
    for instruction in _join_dockerfile(dockerfile.read_text()):
        if not instruction.startswith("RUN "):
            continue
        for part in _split_chain(instruction[4:]):
            args = _pip_install_args(part)
            if args and _installs_target(args):
                commands.append(args)
    return commands


def _installs_target(args: list[str]) -> bool:
    blob = " ".join(args).lower()
    if "requirements.txt" in blob:
        return True
    return BEDROCK in blob or BOTO3 in blob


def _spec_text(dockerfile: Path, requirements: Path | None) -> str:
    chunks = [dockerfile.read_text().replace("\\\n", "\n")]
    if requirements is not None:
        chunks.append(requirements.read_text().replace("\\\n", "\n"))
    parent = dockerfile.parent
    for path in parent.glob("*"):
        if path.suffix in {".txt", ".in", ".toml"} and path.name in chunks[0]:
            chunks.append(path.read_text().replace("\\\n", "\n"))
    return "\n".join(chunks)


def _locked(spec: str, package: str) -> bool:
    pattern = re.compile(
        rf"(^|[\s\"']){re.escape(package)}==[0-9][^\\\s#]*[^\n]*sha256:[0-9a-fA-F]+",
        re.IGNORECASE,
    )
    flattened = spec.replace("\\\n", " ")
    return any(pattern.search(line) for line in flattened.splitlines())


def _pip_env(index_url: str, work: Path, pythonpath: list[Path]) -> dict[str, str]:
    env = os.environ.copy()
    for key in (
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "http_proxy",
        "https_proxy",
        "all_proxy",
    ):
        env.pop(key, None)
    env.update(
        {
            "PIP_INDEX_URL": index_url,
            "PIP_TRUSTED_HOST": "127.0.0.1",
            "PIP_DISABLE_PIP_VERSION_CHECK": "1",
            "PIP_NO_CACHE_DIR": "1",
            "PIP_CONFIG_FILE": os.devnull,
            "PYTHONNOUSERSITE": "1",
            "PYTHONDONTWRITEBYTECODE": "1",
            "NO_PROXY": "127.0.0.1,localhost",
            "no_proxy": "127.0.0.1,localhost",
            "ATTACK_BEDROCK_MARKER": str(work / "bedrock-marker"),
            "ATTACK_BOTO_MARKER": str(work / "boto-marker"),
        }
    )
    if pythonpath:
        env["PYTHONPATH"] = os.pathsep.join(str(path) for path in pythonpath)
    return env


def _make_venv(path: Path) -> Path:
    subprocess.run(
        [sys.executable, "-m", "venv", str(path)],
        check=True,
        capture_output=True,
        text=True,
    )
    return path / "bin" / "python"


def _installed(python: Path, package: str) -> str:
    probe = subprocess.run(
        [
            str(python),
            "-c",
            "import importlib.metadata as metadata, sys\n"
            f"name = {package!r}\n"
            "try:\n"
            "    print(metadata.version(name))\n"
            "except metadata.PackageNotFoundError:\n"
            "    sys.exit(2)\n",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    if probe.returncode == 2:
        return ""
    return probe.stdout.strip()


def _run_install(python: Path, args: list[str], env: dict[str, str], cwd: Path) -> subprocess.CompletedProcess[str]:
    rewritten = []
    skip_next = False
    for arg in args:
        if skip_next:
            # A requirements path inside the image is the file the Dockerfile copied.
            if arg.endswith("requirements.txt"):
                copied = cwd / "requirements.txt"
                rewritten.append(str(copied if copied.is_file() else arg))
            else:
                rewritten.append(arg)
            skip_next = False
            continue
        if arg in {"-r", "--requirement"}:
            rewritten.append(arg)
            skip_next = True
            continue
        rewritten.append(arg)
    return subprocess.run(
        [str(python), "-m", "pip", "install", *rewritten],
        cwd=cwd,
        env=env,
        capture_output=True,
        text=True,
        check=False,
        timeout=180,
    )


def _import_entrypoint(python: Path, entrypoint: Path, env: dict[str, str], call_secrets: bool) -> str:
    script = textwrap.dedent(
        f"""
        import importlib.util
        import traceback
        path = {str(entrypoint)!r}
        spec = importlib.util.spec_from_file_location("entrypoint_under_test", path)
        module = importlib.util.module_from_spec(spec)
        try:
            spec.loader.exec_module(module)
        except Exception:
            traceback.print_exc()
        if {call_secrets!r}:
            try:
                module.resolve_secrets({{
                    "MIGRATION_SECRETS": "API_TOKEN",
                    "PROJECT_NAME": "proj",
                    "ENVIRONMENT": "dev",
                }})
            except Exception:
                traceback.print_exc()
        """
    )
    completed = subprocess.run(
        [str(python), "-c", script],
        env=env,
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
    )
    return completed.stdout + completed.stderr


def _assert_rejects_attacker(
    *,
    index_url: str,
    dockerfile: Path,
    requirements: Path | None,
    entrypoint: Path,
    pythonpath: list[Path],
    packages: tuple[str, ...],
    call_secrets: bool,
    stubs: dict[str, str] | None,
    tmp_path: Path,
) -> None:
    spec = _spec_text(dockerfile, requirements)
    commands = _install_commands(dockerfile)
    assert commands, f"{dockerfile} has no pip install of {packages}"
    problems: list[str] = []
    for package in packages:
        if not _locked(spec, package):
            problems.append(
                f"{package} is installed from {dockerfile} without an exact "
                "== version and a sha256 wheel hash"
            )

    for index, args in enumerate(commands):
        work = tmp_path / f"install-{index}"
        work.mkdir()
        if requirements is not None:
            shutil.copyfile(requirements, work / "requirements.txt")
        if stubs:
            for relative, body in stubs.items():
                destination = work / "stubs" / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_text(body)
        python = _make_venv(work / "venv")
        env = _pip_env(
            index_url,
            work,
            [*pythonpath, *((work / "stubs",) if stubs else ())],
        )
        # Drop the stub path for pip itself; it is only for the entrypoint.
        pip_env = dict(env)
        pip_env.pop("PYTHONPATH", None)
        completed = _run_install(python, args, pip_env, work)
        installed = {package: _installed(python, package) for package in packages}
        output = completed.stdout + completed.stderr
        selected = {
            package: version
            for package, version in installed.items()
            if version in ATTACK_VERSIONS[package]
        }
        if selected:
            problems.append(
                "pip selected an attacker release for "
                + " ".join(f"{name}=={version}" for name, version in selected.items())
                + f" while running: pip install {' '.join(args)}\n{output[-2000:]}"
            )
        elif not all(_locked(spec, package) for package in packages):
            problems.append(
                "the attacker index was not installed and the spec is not locked; "
                f"pip exited {completed.returncode} for: pip install {' '.join(args)}\n"
                f"{output[-2000:]}"
            )
        imported = _import_entrypoint(python, entrypoint, env, call_secrets)
        ran: set[str] = set()
        for label, filename in (
            (BEDROCK, "bedrock-marker"),
            (BOTO3, "boto-marker"),
        ):
            marker = work / filename
            if marker.is_file() and NONCE in marker.read_text():
                ran.add(label)
                problems.append(
                    f"{label} code from the attacker release ran while loading "
                    f"{entrypoint.name}: {marker.read_text().strip()}"
                )
        missed = [package for package in selected if package not in ran]
        if missed:
            problems.append(
                "attacker release installed but the entrypoint did not execute "
                f"{missed}; import output:\n{imported[-2000:]}"
            )

    assert not problems, "\n".join(problems)


def test_migration_adapter_rejects_higher_or_substituted_release(
    attacker_index: str, tmp_path: Path
) -> None:
    dockerfile = REPO / "migration/adapter/Dockerfile"
    text = dockerfile.read_text()
    instructions = _join_dockerfile(text)
    user_root = next(i for i, line in enumerate(instructions) if line == "USER root")
    pip_at = next(i for i, line in enumerate(instructions) if "pip install" in line)
    user_drop = max(i for i, line in enumerate(instructions) if line.startswith("USER "))
    assert user_root < pip_at < user_drop

    app = cdk.App()
    stack = RuntimeStack(
        app,
        "MigrationRuntime",
        project_name="migrationtest",
        environment="dev",
        component_name="orchestrator",
        source_dir="agent-code",
        runtime_type="orchestrator",
        build_context="migration/simulation/existing-ec2-agent",
        build_dockerfile="Dockerfile",
        adapter_dir="migration/adapter",
        migration_port="8000",
        migration_invoke_path="/run",
        migration_health_path="/healthz",
        migration_secret_names=["API_TOKEN"],
        env=ENV,
    )
    template = Template.from_stack(stack).to_json()
    runtime = next(
        resource
        for resource in template["Resources"].values()
        if resource["Type"] == "AWS::BedrockAgentCore::Runtime"
    )
    role_arn = runtime["Properties"]["RoleArn"]
    assert role_arn["Fn::GetAtt"][1] == "Arn"
    role_logical = role_arn["Fn::GetAtt"][0]
    actions: set[str] = set()
    for resource in template["Resources"].values():
        if resource["Type"] != "AWS::IAM::Policy":
            continue
        roles = resource["Properties"].get("Roles", [])
        if not any(role.get("Ref") == role_logical for role in roles):
            continue
        for statement in resource["Properties"]["PolicyDocument"]["Statement"]:
            action = statement.get("Action", [])
            actions.update(action if isinstance(action, list) else [action])
    assert DATA_PLANE_ACTIONS <= actions

    build = next(
        resource
        for resource in template["Resources"].values()
        if resource["Type"] == "AWS::CodeBuild::Project"
    )
    buildspec = json.loads(build["Properties"]["Source"]["BuildSpec"])
    command_text = "\n".join(
        command
        for phase in buildspec["phases"].values()
        for command in phase["commands"]
    )
    assert "-f adapter/Dockerfile" in command_text
    assert "$REPO_URI:$IMAGE_TAG" in command_text
    image_tag = ""
    for resource in template["Resources"].values():
        overrides = resource.get("Properties", {}).get("EnvironmentOverrides")
        if not isinstance(overrides, list):
            continue
        for item in overrides:
            if isinstance(item, dict) and item.get("name") == "IMAGE_TAG":
                image_tag = item["value"]
    assert image_tag
    container_uri = json.dumps(runtime["Properties"]["AgentRuntimeArtifact"])
    assert f":{image_tag}" in container_uri

    _assert_rejects_attacker(
        index_url=attacker_index,
        dockerfile=dockerfile,
        requirements=None,
        entrypoint=REPO / "migration/adapter/adapter.py",
        pythonpath=[],
        packages=(BEDROCK, BOTO3),
        call_secrets=True,
        stubs=None,
        tmp_path=tmp_path,
    )


def test_pattern_build_does_not_use_the_migration_adapter() -> None:
    app = cdk.App()
    stack = RuntimeStack(
        app,
        "PatternRuntime",
        project_name="migrationtest",
        environment="dev",
        component_name="orchestrator",
        source_dir="agent-code",
        dockerfile_pattern="orchestrator",
        runtime_type="orchestrator",
        env=ENV,
    )
    template = Template.from_stack(stack).to_json()
    build = next(
        resource
        for resource in template["Resources"].values()
        if resource["Type"] == "AWS::CodeBuild::Project"
    )
    buildspec = json.loads(build["Properties"]["Source"]["BuildSpec"])
    command_text = "\n".join(
        command
        for phase in buildspec["phases"].values()
        for command in phase["commands"]
    )
    assert "adapter/Dockerfile" not in command_text
    assert "-f orchestrator/Dockerfile" in command_text


@pytest.mark.parametrize("case", RUNTIME_IMAGE_INSTALLS, ids=lambda case: case["id"])
def test_runtime_image_rejects_higher_or_substituted_release(
    attacker_index: str, tmp_path: Path, case: dict
) -> None:
    _assert_rejects_attacker(
        index_url=attacker_index,
        dockerfile=case["dockerfile"],
        requirements=case["requirements"],
        entrypoint=case["entrypoint"],
        pythonpath=list(case["pythonpath"]),
        packages=case["packages"],
        call_secrets=False,
        stubs=case.get("stubs"),
        tmp_path=tmp_path,
    )
