"""The dashboard status file must not be readable off the loopback interface.

monitor.py writes dashboard/public/status.json. The workshop completion
message and the migration demo script tell the operator to publish that
directory with python -m http.server and no bind address. These tests run
those commands and require a client on another interface to be refused,
while the operator on 127.0.0.1 still receives the monitor document.

They fail while a documented command accepts that off-host request.
"""

import fcntl
import http.client
import json
import os
import re
import shlex
import signal
import socket
import stat
import struct
import subprocess
import sys
import time
from contextlib import contextmanager
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "dashboard"))

from monitor import poll, write_status

ACCOUNT = "111111111111"
ISSUER = "https://issuer.example.invalid/workshop"
GATEWAY = "https://gateway.example.invalid/mcp"
RUNTIME_ARN = "arn:aws:bedrock-agentcore:us-east-1:111111111111:runtime/placeholder"
APP_CLIENT = "placeholder-app-client"
WEB_CLIENT = "placeholder-web-client"
M2M_CLIENT = "placeholder-m2m-client"
UNREVIEWED = "unreviewed-output-value"
PROJECT = "workshop"
ENVIRONMENT = "dev"
PREFIX = f"{PROJECT}-{ENVIRONMENT}"

_COMMAND_RE = re.compile(r"(?:cd\s+\S+\s+&&\s+)?python3\s+-m\s+http\.server\b[^\"'`]*")
_OPTION_WITH_VALUE = {
    "-b",
    "--bind",
    "-d",
    "--directory",
    "-p",
    "--protocol",
}


def _http_server_commands(relative: str) -> list[str]:
    text = (REPO / relative).read_text()
    commands = []
    for line in text.splitlines():
        match = _COMMAND_RE.search(line)
        if match:
            commands.append(match.group(0).strip())
    return commands


def _argv_and_port(command: str) -> tuple[list[str], int]:
    """Split the operator command. `cd <dir> &&` only selects the directory."""
    parts = shlex.split(command)
    if parts[:1] == ["cd"] and "&&" in parts:
        parts = parts[parts.index("&&") + 1 :]
    if parts[:3] != ["python3", "-m", "http.server"]:
        raise AssertionError(f"not an http.server command: {command}")
    port = 8000
    skip_next = False
    for token in parts[3:]:
        if skip_next:
            skip_next = False
            continue
        if token in _OPTION_WITH_VALUE:
            skip_next = True
            continue
        if any(token.startswith(f"{name}=") for name in _OPTION_WITH_VALUE):
            continue
        if token.isdigit():
            port = int(token)
    return parts, port


def _up_non_loopback_ipv4() -> str:
    for name in sorted(os.listdir("/sys/class/net")):
        if name == "lo":
            continue
        state_path = Path("/sys/class/net") / name / "operstate"
        if not state_path.is_file() or state_path.read_text().strip() != "up":
            continue
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            packed = fcntl.ioctl(
                sock.fileno(),
                0x8915,  # SIOCGIFADDR
                struct.pack("256s", name.encode()[:15]),
            )
        except OSError:
            continue
        finally:
            sock.close()
        address = socket.inet_ntoa(packed[20:24])
        if not address.startswith("127."):
            return address
    raise AssertionError("this host has no up non-loopback IPv4 address")


def _deployment_status(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict:
    manifest = tmp_path / "platform.yaml"
    manifest.write_text(
        f"project: {PROJECT}\nenvironment: {ENVIRONMENT}\nregion: us-east-1\n"
    )
    monkeypatch.setenv("PLATFORM_CONFIG", str(manifest))
    for name in (
        "PROJECT_NAME",
        "ENVIRONMENT",
        "AWS_REGION",
        "AWS_DEFAULT_REGION",
    ):
        monkeypatch.delenv(name, raising=False)

    outputs = {
        "auth": [
            {"OutputKey": "IssuerUrl", "OutputValue": ISSUER},
            {"OutputKey": "AppClientId", "OutputValue": APP_CLIENT},
            {"OutputKey": "WebClientId", "OutputValue": WEB_CLIENT},
            {"OutputKey": "M2MClientId", "OutputValue": M2M_CLIENT},
            {"OutputKey": "ClientSecret", "OutputValue": UNREVIEWED},
        ],
        "gateway": [
            {"OutputKey": "GatewayUrl", "OutputValue": GATEWAY},
            {"OutputKey": "ClientSecret", "OutputValue": UNREVIEWED},
        ],
        "runtime-orchestrator": [
            {"OutputKey": "RuntimeArn", "OutputValue": RUNTIME_ARN},
            {"OutputKey": "ClientSecret", "OutputValue": UNREVIEWED},
        ],
    }
    root = f"/{PROJECT}/{ENVIRONMENT}"
    parameters = [
        {"Name": f"{root}/auth/issuer-url", "Value": ISSUER},
        {"Name": f"{root}/auth/app-client-id", "Value": APP_CLIENT},
        {"Name": f"{root}/auth/web-client-id", "Value": WEB_CLIENT},
        {"Name": f"{root}/auth/m2m-client-id", "Value": M2M_CLIENT},
        {"Name": f"{root}/gateway/url", "Value": GATEWAY},
        {"Name": f"{root}/runtimes/orchestrator/arn", "Value": RUNTIME_ARN},
        {"Name": f"{root}/custom/display-name", "Value": UNREVIEWED},
    ]

    class _Pages:
        def __init__(self, pages):
            self.pages = pages

        def paginate(self, **_kwargs):
            return self.pages

    class _CloudFormation:
        def describe_stacks(self, StackName, **_kwargs):
            suffix = StackName.removeprefix(f"{PREFIX}-")
            return {
                "Stacks": [
                    {
                        "StackStatus": "CREATE_COMPLETE",
                        "Outputs": outputs.get(suffix, []),
                    }
                ]
            }

        def get_paginator(self, name):
            assert name == "list_stack_resources"
            return _Pages([{"StackResourceSummaries": []}])

    class _SSM:
        def get_paginator(self, name):
            assert name == "get_parameters_by_path"
            return _Pages([{"Parameters": parameters}])

    class _STS:
        def get_caller_identity(self):
            return {"Account": ACCOUNT}

    def factory(service, region_name):
        assert region_name == "us-east-1"
        return {
            "cloudformation": _CloudFormation(),
            "ssm": _SSM(),
            "sts": _STS(),
        }[service]

    return poll(factory)


def _assert_monitor_document(payload: dict) -> None:
    assert payload["account"] == ACCOUNT
    assert payload["deployment"]["polled_account"] == ACCOUNT
    auth = payload["stacks"][f"{PREFIX}-auth"]["outputs"]
    assert auth["IssuerUrl"] == ISSUER
    assert auth["AppClientId"] == APP_CLIENT
    assert auth["WebClientId"] == WEB_CLIENT
    assert auth["M2MClientId"] == M2M_CLIENT
    gateway = payload["stacks"][f"{PREFIX}-gateway"]["outputs"]
    assert gateway["GatewayUrl"] == GATEWAY
    runtime = payload["stacks"][f"{PREFIX}-runtime-orchestrator"]["outputs"]
    assert runtime["RuntimeArn"] == RUNTIME_ARN
    parameters = payload["ssm_parameters"]
    assert parameters["auth/issuer-url"] == ISSUER
    assert parameters["auth/app-client-id"] == APP_CLIENT
    assert parameters["auth/web-client-id"] == WEB_CLIENT
    assert parameters["auth/m2m-client-id"] == M2M_CLIENT
    assert parameters["gateway/url"] == GATEWAY
    assert parameters["runtimes/orchestrator/arn"] == RUNTIME_ARN
    serialized = json.dumps(payload)
    assert UNREVIEWED not in serialized
    assert "ClientSecret" not in serialized


def _http_get(host: str, port: int) -> tuple[int, bytes]:
    connection = http.client.HTTPConnection(host, port, timeout=2)
    try:
        connection.request("GET", "/status.json")
        response = connection.getresponse()
        return response.status, response.read()
    finally:
        connection.close()


def _wait_until_listening(port: int) -> None:
    deadline = time.monotonic() + 5
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                return
        except OSError as exc:
            last_error = exc
            time.sleep(0.05)
    raise AssertionError(f"server did not listen on 127.0.0.1:{port}: {last_error}")


@contextmanager
def _serve(command: str, cwd: Path, log_path: Path):
    """Run the operator command with bash, the shell the workshop tells them to use."""
    _argv, port = _argv_and_port(command)
    log_handle = log_path.open("w", encoding="utf-8")
    process = subprocess.Popen(
        ["bash", "-c", command],
        cwd=cwd,
        stdout=log_handle,
        stderr=subprocess.STDOUT,
        start_new_session=True,
    )
    try:
        _wait_until_listening(port)
        if process.poll() is not None:
            raise AssertionError(log_path.read_text())
        yield port
    finally:
        log_handle.close()
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGTERM)
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=2)


def _assert_loopback_only(command: str, cwd: Path, status_path: Path, log_path: Path):
    assert stat.S_IMODE(status_path.stat().st_mode) == 0o600
    remote = _up_non_loopback_ipv4()
    with _serve(command, cwd, log_path) as port:
        status, body = _http_get("127.0.0.1", port)
        assert status == 200, log_path.read_text()
        _assert_monitor_document(json.loads(body))
        try:
            remote_status, remote_body = _http_get(remote, port)
        except ConnectionRefusedError:
            return
        except OSError as exc:
            pytest.fail(
                f"{command!r} from {cwd} did not refuse {remote}:{port}: {exc!r}"
            )
        same_map = remote_body == body
        pytest.fail(
            f"{command!r} from {cwd} accepted {remote}:{port} "
            f"(HTTP {remote_status}, deployment map delivered={same_map}). "
            f"Server log: {log_path.read_text().strip()}"
        )


def _write_monitor_file(sandbox: Path, document: dict) -> Path:
    destination = sandbox / "dashboard" / "public" / "status.json"
    write_status(destination, document)
    return destination


def test_workshop_completion_command_is_loopback_only(tmp_path, monkeypatch):
    commands = _http_server_commands("migration/simulation/run-workshop.sh")
    assert len(commands) == 1
    command = commands[0]
    sandbox = tmp_path / "repo"
    _write_monitor_file(sandbox, _deployment_status(tmp_path, monkeypatch))
    # The completion message prints `cd dashboard && ...`, which the operator
    # runs from the repository root.
    _assert_loopback_only(
        command,
        sandbox,
        sandbox / "dashboard" / "public" / "status.json",
        tmp_path / "workshop-server.log",
    )


def test_demo_script_command_from_dashboard_directory_is_loopback_only(
    tmp_path, monkeypatch
):
    commands = _http_server_commands("migration/simulation/DEMO_SCRIPT.md")
    assert len(commands) == 1
    command = commands[0]
    sandbox = tmp_path / "repo"
    _write_monitor_file(sandbox, _deployment_status(tmp_path, monkeypatch))
    # `-d public` is the monitor output only when the server cwd is dashboard/,
    # the directory the demo script names on the preceding line.
    _assert_loopback_only(
        command,
        sandbox / "dashboard",
        sandbox / "dashboard" / "public" / "status.json",
        tmp_path / "demo-server.log",
    )


def test_demo_script_pasted_at_repository_root_does_not_publish_monitor_status(
    tmp_path, monkeypatch
):
    """A blind paste leaves the parent cwd at the repository root.

    `cd dashboard && python3 monitor.py &` runs the directory change in the
    backgrounded list, so the following http.server line still uses `-d public`
    relative to the repository root. That must not return the monitor file to
    another interface.
    """
    commands = _http_server_commands("migration/simulation/DEMO_SCRIPT.md")
    command = commands[0]
    sandbox = tmp_path / "repo"
    status_path = _write_monitor_file(
        sandbox, _deployment_status(tmp_path, monkeypatch)
    )
    remote = _up_non_loopback_ipv4()
    with _serve(command, sandbox, tmp_path / "demo-root-server.log") as port:
        try:
            _remote_status, remote_body = _http_get(remote, port)
        except ConnectionRefusedError:
            return
        assert status_path.read_bytes() not in remote_body
        assert ACCOUNT.encode() not in remote_body


def test_readme_status_server_is_loopback_only(tmp_path, monkeypatch):
    commands = _http_server_commands("README.md")
    assert len(commands) == 1
    sandbox = tmp_path / "repo"
    _write_monitor_file(sandbox, _deployment_status(tmp_path, monkeypatch))
    _assert_loopback_only(
        commands[0],
        sandbox,
        sandbox / "dashboard" / "public" / "status.json",
        tmp_path / "readme-server.log",
    )


def test_participant_guide_status_server_is_loopback_only(tmp_path, monkeypatch):
    commands = _http_server_commands("docs/PARTICIPANT_GUIDE.md")
    assert len(commands) == 1
    sandbox = tmp_path / "repo"
    _write_monitor_file(sandbox, _deployment_status(tmp_path, monkeypatch))
    _assert_loopback_only(
        commands[0],
        sandbox,
        sandbox / "dashboard" / "public" / "status.json",
        tmp_path / "guide-server.log",
    )


def test_package_status_script_is_loopback_only(tmp_path, monkeypatch):
    script = json.loads((REPO / "dashboard" / "package.json").read_text())["scripts"][
        "start:status"
    ]
    sandbox = tmp_path / "repo"
    _write_monitor_file(sandbox, _deployment_status(tmp_path, monkeypatch))
    _assert_loopback_only(
        script,
        sandbox / "dashboard",
        sandbox / "dashboard" / "public" / "status.json",
        tmp_path / "package-server.log",
    )
