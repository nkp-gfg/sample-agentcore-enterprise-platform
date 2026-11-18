"""The Claude image build must not execute an unauthenticated remote setup script.

These tests fail while agent-code/claude-sdk-agent/Dockerfile and
agent-code/claude-sdk-multi-agent/Dockerfile pipe the NodeSource setup URL to
bash as root. A body served for that URL is executed by the same
``curl -fsSL URL | bash -`` pipeline Docker runs, and the runtime user can
still invoke what it planted. They pass once that pipeline is gone, or the
body is rejected by an integrity check before any of it runs.

Run:
    pytest tests/test_nodesource_setup_script.py
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import aws_cdk as cdk
import pytest
from aws_cdk.assertions import Template

from infra_utils.platform_config import load_platform_config, to_env
from stacks.runtime_stack import RuntimeStack

REPO = Path(__file__).resolve().parents[1]
ENV = cdk.Environment(account="111111111111", region="us-east-1")
CLAUDE_PATTERNS = ("claude-sdk-agent", "claude-sdk-multi-agent")
SETUP_URL = "https://deb.nodesource.com/setup_lts.x"
PLANTED_PATH = "/usr/local/bin/setup-planted"
URL_RE = re.compile(r"https?://[^\s\"']+")


def _logical_lines(text: str) -> list[str]:
    lines: list[str] = []
    buffer = ""
    for raw in text.splitlines():
        stripped = raw.strip()
        if not buffer and (not stripped or stripped.startswith("#")):
            continue
        if stripped.endswith("\\"):
            buffer += stripped[:-1].rstrip() + " "
            continue
        buffer += stripped
        lines.append(buffer.strip())
        buffer = ""
    if buffer.strip():
        lines.append(buffer.strip())
    return lines


def _split_shell(command: str) -> list[str]:
    parts: list[str] = []
    chunk: list[str] = []
    index = 0
    while index < len(command):
        if command.startswith("&&", index):
            parts.append("".join(chunk).strip())
            chunk = []
            index += 2
            continue
        if command[index] == ";":
            parts.append("".join(chunk).strip())
            chunk = []
            index += 1
            continue
        chunk.append(command[index])
        index += 1
    tail = "".join(chunk).strip()
    if tail:
        parts.append(tail)
    return [part for part in parts if part]


def _executed_setup_urls(command: str) -> list[str]:
    """URLs whose body is passed to a shell before any checksum of that body."""
    urls: list[str] = []
    downloaded: dict[str, str] = {}
    verified: set[str] = set()
    for part in _split_shell(command):
        checksum = bool(
            re.search(r"\b(sha256sum|sha512sum|sha384sum)\b.*\s-c\b", part)
            or "gpg --verify" in part
            or re.search(r"\bgpgv\b", part)
        )
        if checksum:
            verified.update(part.split())
        piped = re.search(
            r"\b(curl|wget)\b.*\|\s*(sudo\s+)?(ba)?sh\b", part
        )
        if piped:
            urls.extend(URL_RE.findall(part))
        output = re.search(r"(?:-o|--output|-O)\s+(\S+)", part)
        fetched = URL_RE.findall(part) if re.search(r"\b(curl|wget)\b", part) else []
        if output and fetched:
            downloaded[output.group(1)] = fetched[-1]
        executed = re.search(r"\b(?:bash|sh)\b\s+(\S+)", part)
        if executed:
            target = executed.group(1)
            if target in downloaded and target not in verified:
                urls.append(downloaded[target])
    return urls


def _root_setup_runs(dockerfile: str) -> list[str]:
    runs: list[str] = []
    for line in _logical_lines(dockerfile):
        if line.upper().startswith("USER "):
            break
        if not line.upper().startswith("RUN "):
            continue
        command = line[4:].strip()
        if _executed_setup_urls(command):
            runs.append(command)
    return runs


def _useradd_and_user(dockerfile: str) -> tuple[str | None, str | None]:
    useradd = None
    user = None
    for line in _logical_lines(dockerfile):
        if line.startswith("RUN ") and "useradd" in line and useradd is None:
            useradd = line[4:].strip()
        if line.upper().startswith("USER "):
            user = line.split(None, 1)[1].strip()
            break
    return useradd, user


def _build_commands(pattern: str) -> tuple[str, str]:
    app = cdk.App()
    stack = RuntimeStack(
        app,
        f"Setup{pattern}",
        project_name="agentcore-workshop",
        environment="dev",
        component_name="orchestrator",
        source_dir="agent-code",
        dockerfile_pattern=pattern,
        runtime_type="orchestrator",
        env=ENV,
    )
    template = Template.from_stack(stack).to_json()
    buildspec = ""
    container_uri = ""
    for resource in template["Resources"].values():
        if resource["Type"] == "AWS::CodeBuild::Project":
            spec = json.loads(resource["Properties"]["Source"]["BuildSpec"])
            buildspec = "\n".join(
                command
                for phase in spec["phases"].values()
                for command in phase["commands"]
            )
        if resource["Type"] == "AWS::BedrockAgentCore::Runtime":
            container_uri = json.dumps(
                resource["Properties"]["AgentRuntimeArtifact"]["ContainerConfiguration"][
                    "ContainerUri"
                ]
            )
    return buildspec, container_uri


def _docker() -> list[str]:
    if shutil.which("docker") and subprocess.run(
        ["docker", "info"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    ).returncode == 0:
        return ["docker"]
    return ["sudo", "docker"]


class _SetupServer(ThreadingHTTPServer):
    def __init__(self) -> None:
        handler = self._handler()
        super().__init__(("127.0.0.1", 0), handler)
        self.requests = 0
        thread = threading.Thread(target=self.serve_forever, daemon=True)
        thread.start()

    def _handler(self):
        server = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802
                server.requests += 1
                body = (
                    "printf '%s\\n' '#!/bin/sh' 'echo planted-by-setup' "
                    f"> {PLANTED_PATH}\n"
                    f"chmod 755 {PLANTED_PATH}\n"
                    f"id -u > {PLANTED_PATH}-uid\n"
                    f"chmod 644 {PLANTED_PATH}-uid\n"
                ).encode()
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, fmt: str, *args: object) -> None:
                return

        return Handler


def _runtime_sees_plant(dockerfile_text: str, command: str, attacker: str) -> str:
    """Run the Dockerfile's root setup command. Return planted output, or ''."""
    base = next(
        line.split(None, 1)[1]
        for line in _logical_lines(dockerfile_text)
        if line.upper().startswith("FROM ")
    )
    useradd, user = _useradd_and_user(dockerfile_text)
    rewritten = command.replace(SETUP_URL, attacker)
    docker = _docker()
    name = "nodesource-setup-probe"
    image = "nodesource-setup-probe:plant"
    subprocess.run([*docker, "rm", "-f", name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    run = subprocess.run(
        [
            *docker,
            "run",
            "--name",
            name,
            "--network",
            "host",
            "--user",
            "root",
            base,
            "/bin/sh",
            "-c",
            rewritten,
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    subprocess.run(
        [*docker, "commit", name, image],
        check=True,
        stdout=subprocess.DEVNULL,
    )
    subprocess.run([*docker, "rm", "-f", name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if run.returncode != 0:
        # The fetch ran far enough to commit. A later failure must not hide a plant.
        pass
    if useradd and user:
        subprocess.run(
            [*docker, "run", "--name", name, "--user", "root", image, "/bin/sh", "-c", useradd],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        subprocess.run(
            [*docker, "commit", name, image],
            check=True,
            stdout=subprocess.DEVNULL,
        )
        subprocess.run([*docker, "rm", "-f", name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        user_flag = ["--user", user]
    else:
        user_flag = []
    probed = subprocess.run(
        [*docker, "run", "--rm", "--entrypoint", PLANTED_PATH, *user_flag, image],
        capture_output=True,
        text=True,
    )
    subprocess.run([*docker, "rmi", "-f", image], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return probed.stdout


def test_multi_agent_preset_builds_the_claude_dockerfile() -> None:
    config = load_platform_config(REPO / "presets" / "multi-agent.yaml")
    assert config.migration is None
    assert config.agents.pattern == "claude-sdk-multi-agent"
    assert to_env(config)["AGENT_PATTERN"] == "claude-sdk-multi-agent"
    buildspec, container_uri = _build_commands("claude-sdk-multi-agent")
    assert (
        "docker build --platform linux/arm64 -f claude-sdk-multi-agent/Dockerfile "
        "-t $REPO_URI:$IMAGE_TAG ."
    ) in buildspec
    assert "docker push $REPO_URI:$IMAGE_TAG" in buildspec
    assert "dkr.ecr." in container_uri


@pytest.mark.parametrize("pattern", CLAUDE_PATTERNS)
def test_pattern_build_publishes_that_dockerfile(pattern: str) -> None:
    buildspec, container_uri = _build_commands(pattern)
    assert (
        f"docker build --platform linux/arm64 -f {pattern}/Dockerfile "
        "-t $REPO_URI:$IMAGE_TAG ."
    ) in buildspec
    assert "docker push $REPO_URI:$IMAGE_TAG" in buildspec
    assert "docker push $REPO_URI:latest" in buildspec
    assert "dkr.ecr." in container_uri


@pytest.mark.parametrize("pattern", CLAUDE_PATTERNS)
def test_setup_script_cannot_plant_code_in_the_runtime_image(pattern: str) -> None:
    dockerfile_text = (REPO / "agent-code" / pattern / "Dockerfile").read_text()
    runs = _root_setup_runs(dockerfile_text)
    if not runs:
        return
    server = _SetupServer()
    try:
        attacker = f"http://127.0.0.1:{server.server_address[1]}/setup_lts.x"
        planted = [
            _runtime_sees_plant(dockerfile_text, command, attacker) for command in runs
        ]
    finally:
        server.shutdown()
    assert planted == [""] * len(runs)
