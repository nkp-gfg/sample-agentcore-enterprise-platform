"""Runtime invokes must target only the runtime this deployment created.

The operator scripts read ``runtimes/<component>/arn`` from SSM and then send
the platform machine token (HTTP and AG-UI) or sign ``InvokeAgentRuntime``
with the operator's credentials (A2A). Those SSM parameters are not the
authority for which runtime was created. The authority is the CloudFormation
output ``RuntimeArn`` on stack ``{project}-{environment}-runtime-{component}``
(export ``{project}-{environment}-{component}-runtime-arn``). ``RuntimeId`` on
that same output is the only id that may be passed to ``GetAgentRuntime``.

SSM ``runtimes/<component>/arn`` and ``runtimes/<component>/id`` are writable
by anyone with ``ssm:PutParameter`` and must not be trusted on their own.
``ListAgentRuntimes`` also returns other runtimes in the account; being in
that list is not enough.

When the resolved target is anything else, the invoke must raise before the
data plane is contacted. A later read of the same SSM parameter must not
replace the value that was accepted.
"""

from __future__ import annotations

import io
import json
import os
import signal
import sys
import urllib.parse
import urllib.request
from pathlib import Path

import boto3
import pytest
from botocore.awsrequest import AWSResponse
from botocore.exceptions import ClientError

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "scripts"))

# invoke.REGION is fixed at import. Pin it for this module, then restore the
# process environment so the rest of the suite is unchanged.
_REGION_KEYS = ("AWS_REGION", "AWS_DEFAULT_REGION")
_SAVED_REGION = {key: os.environ.get(key) for key in _REGION_KEYS}
os.environ["AWS_REGION"] = "eu-west-1"
os.environ["AWS_DEFAULT_REGION"] = "eu-west-1"
import invoke  # noqa: E402

for _key, _value in _SAVED_REGION.items():
    if _value is None:
        os.environ.pop(_key, None)
    else:
        os.environ[_key] = _value

PROJECT = "myproj"
ENV = "dev"
REGION = "eu-west-1"
ACCOUNT = "111122223333"
OTHER_ACCOUNT = "999988887777"
SUFFIX = "Ab12Cd"
COMPONENTS = ("orchestrator", "code-agent", "research-agent")

# Obvious placeholders. These are not credentials.
MACHINE_TOKEN = "placeholder-machine-token"
CLIENT_SECRET = "placeholder-client-secret"
ACCESS_KEY_ID = "placeholder-access-key-id"
SECRET_ACCESS_KEY = "placeholder-secret-access-key"
SESSION_TOKEN = "placeholder-session-token"
DECOY_ARN = (
    f"arn:aws:bedrock-agentcore:{REGION}:{ACCOUNT}:runtime/attacker_runtime-Zz99"
)

_REAL_BOTO3_CLIENT = boto3.client
RECORDS: list[tuple[str, str, str]] = []


def _runtime_name(component: str, generation: int = 1) -> str:
    name = f"{PROJECT}_{ENV}_{component}".replace("-", "_")
    if component == "orchestrator" and generation > 1:
        name = f"{name}_g{generation}"
    return name


def created_arn(component: str, generation: int = 1) -> str:
    """ARN stored on the runtime stack this deployment created."""
    return (
        f"arn:aws:bedrock-agentcore:{REGION}:{ACCOUNT}:runtime/"
        f"{_runtime_name(component, generation)}-{SUFFIX}"
    )


def created_id(component: str) -> str:
    return f"created-{component}-id"


def stack_name(component: str) -> str:
    return f"{PROJECT}-{ENV}-runtime-{component}"


def export_name(component: str) -> str:
    return f"{PROJECT}-{ENV}-{component}-runtime-arn"


def _variants(component: str) -> dict[str, str]:
    legit = created_arn(component)
    return {
        "other-account": (
            f"arn:aws:bedrock-agentcore:{REGION}:{OTHER_ACCOUNT}:runtime/"
            f"{_runtime_name(component)}-{SUFFIX}"
        ),
        "other-region": (
            f"arn:aws:bedrock-agentcore:us-west-2:{ACCOUNT}:runtime/"
            f"{_runtime_name(component)}-{SUFFIX}"
        ),
        "other-name": DECOY_ARN,
        "other-suffix": legit.replace(SUFFIX, "Evil99"),
        "trailing-space": legit + " ",
    }


class _Body:
    def __init__(self, data: bytes):
        self._data = io.BytesIO(data)

    def read(self, n: int = -1) -> bytes:
        return self._data.read(n)

    def __enter__(self):
        return self

    def __exit__(self, *args) -> bool:
        return False


class DeploymentAws:
    """AWS stand-in. CloudFormation outputs are the created runtime.

    SSM runtime parameters and any other runtime id resolve to attacker
    controlled values. ``ListAgentRuntimes`` includes a same-account decoy
    so an "any runtime in the account" check is not treated as a match.
    """

    def __init__(self):
        self.created = {component: created_arn(component) for component in COMPONENTS}
        self.ssm_arn = {
            component: [self.created[component]] for component in COMPONENTS
        }
        self.ssm_id = {component: ["attacker-runtime-id"] for component in COMPONENTS}

    def client(self, service: str, region_name: str | None = None, **kwargs):
        if service == "bedrock-agentcore":
            client = _REAL_BOTO3_CLIENT(
                service,
                region_name=region_name or REGION,
                aws_access_key_id=ACCESS_KEY_ID,
                aws_secret_access_key=SECRET_ACCESS_KEY,
                aws_session_token=SESSION_TOKEN,
            )
            client.meta.events.register(
                "before-send.bedrock-agentcore.InvokeAgentRuntime",
                _capture_signed_invoke,
            )
            return client
        return _Service(service, self)


class _Service:
    def __init__(self, service: str, world: DeploymentAws):
        self.service = service
        self.world = world

    def get_parameter(self, Name: str):
        suffix = Name.removeprefix(f"/{PROJECT}/{ENV}/")
        static = {
            "auth/mode": "brokered",
            "auth/user-pool-id": "pool-123",
            "auth/m2m-client-id": "client-abc",
            "auth/app-client-id": "app-client-123",
            "auth/m2m-client-secret-name": "placeholder-secret-name",
        }
        if suffix in static:
            return {"Parameter": {"Value": static[suffix]}}
        for component in COMPONENTS:
            if suffix == f"runtimes/{component}/arn":
                queue = self.world.ssm_arn[component]
                value = queue.pop(0) if len(queue) > 1 else queue[0]
                return {"Parameter": {"Value": value}}
            if suffix == f"runtimes/{component}/id":
                queue = self.world.ssm_id[component]
                value = queue.pop(0) if len(queue) > 1 else queue[0]
                return {"Parameter": {"Value": value}}
        raise ClientError(
            {"Error": {"Code": "ParameterNotFound", "Message": Name}},
            "GetParameter",
        )

    def get_secret_value(self, SecretId: str):
        assert SecretId == "placeholder-secret-name"
        return {"SecretString": CLIENT_SECRET}

    def get_caller_identity(self):
        return {"Account": ACCOUNT}

    def describe_stacks(self, StackName: str):
        for component in COMPONENTS:
            if StackName == stack_name(component):
                return {
                    "Stacks": [
                        {
                            "StackName": StackName,
                            "StackStatus": "UPDATE_COMPLETE",
                            "Outputs": [
                                {
                                    "OutputKey": "RuntimeArn",
                                    "OutputValue": self.world.created[component],
                                    "ExportName": export_name(component),
                                },
                                {
                                    "OutputKey": "RuntimeId",
                                    "OutputValue": created_id(component),
                                },
                            ],
                        }
                    ]
                }
        raise ClientError(
            {"Error": {"Code": "ValidationError", "Message": StackName}},
            "DescribeStacks",
        )

    def list_exports(self):
        return {
            "Exports": [
                {
                    "Name": export_name(component),
                    "Value": self.world.created[component],
                }
                for component in COMPONENTS
            ]
        }

    def get_agent_runtime(self, agentRuntimeId: str, **kwargs):
        for component in COMPONENTS:
            if agentRuntimeId == created_id(component):
                return {
                    "agentRuntimeArn": self.world.created[component],
                    "agentRuntimeName": _runtime_name(component),
                    "agentRuntimeId": agentRuntimeId,
                }
        return {
            "agentRuntimeArn": DECOY_ARN,
            "agentRuntimeName": "attacker_runtime",
            "agentRuntimeId": agentRuntimeId,
        }

    def list_agent_runtimes(self, **kwargs):
        runtimes = [
            {
                "agentRuntimeArn": self.world.created[component],
                "agentRuntimeName": _runtime_name(component),
                "agentRuntimeId": created_id(component),
            }
            for component in COMPONENTS
        ]
        runtimes.append(
            {
                "agentRuntimeArn": DECOY_ARN,
                "agentRuntimeName": "attacker_runtime",
                "agentRuntimeId": "attacker-runtime-id",
            }
        )
        return {"agentRuntimes": runtimes}


def _header_text(value) -> str:
    if isinstance(value, bytes):
        return value.decode()
    return "" if value is None else str(value)


def _capture_signed_invoke(request, **kwargs):
    headers = {
        str(key): _header_text(value) for key, value in request.headers.items()
    }
    RECORDS.append(("sdk", request.url, headers.get("Authorization", "")))
    payload = json.dumps(
        {"result": {"artifacts": [{"parts": [{"kind": "text", "text": "ok"}]}]}}
    ).encode()
    return AWSResponse(
        request.url,
        200,
        {
            "Content-Type": "application/json",
            "Content-Length": str(len(payload)),
        },
        io.BytesIO(payload),
    )


def _capture_urlopen(req, timeout=None, *args, **kwargs):
    url = req.full_url
    if "/oauth2/token" in url:
        return _Body(json.dumps({"access_token": MACHINE_TOKEN}).encode())
    authorization = ""
    if hasattr(req, "get_header"):
        authorization = req.get_header("Authorization") or ""
    RECORDS.append(("http", url, authorization))
    return _Body(b'{"status":"success","response":"ok"}')


@pytest.fixture
def aws(monkeypatch):
    RECORDS.clear()
    world = DeploymentAws()
    monkeypatch.setenv("AWS_REGION", REGION)
    monkeypatch.setenv("AWS_DEFAULT_REGION", REGION)
    monkeypatch.setenv("PROJECT_NAME", PROJECT)
    monkeypatch.setenv("ENVIRONMENT", ENV)
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", ACCESS_KEY_ID)
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", SECRET_ACCESS_KEY)
    monkeypatch.setenv("AWS_SESSION_TOKEN", SESSION_TOKEN)
    monkeypatch.setattr(boto3, "client", world.client)
    monkeypatch.setattr(urllib.request, "urlopen", _capture_urlopen)
    return world


def _targets() -> list[str]:
    return [urllib.parse.unquote(url) for _kind, url, _auth in RECORDS]


def _auth_label(authorization: str) -> str:
    if authorization == f"Bearer {MACHINE_TOKEN}":
        return "bearer machine token"
    if authorization.startswith("AWS4-HMAC-SHA256 ") and ACCESS_KEY_ID in authorization:
        return "sigv4 caller credentials"
    if authorization.startswith("Bearer "):
        return "bearer token"
    return "no caller credential"


def _assert_refused(call) -> None:
    RECORDS.clear()
    raised = False
    try:
        call()
    except BaseException:
        raised = True
    contacted = [
        f"{_auth_label(authorization)} -> {urllib.parse.unquote(url)}"
        for _kind, url, authorization in RECORDS
    ]
    assert contacted == [], (
        "data plane was contacted before the invoke was refused: "
        + "; ".join(contacted)
    )
    assert raised, "the invoke must refuse a runtime this deployment did not create"


def _http(world, component, value: str):
    world.ssm_arn[component] = [value]


@pytest.mark.parametrize("label", sorted(_variants("orchestrator")))
def test_orchestrator_http_refuses_ssm_arn_that_is_not_the_created_runtime(
    aws, label
):
    _http(aws, "orchestrator", _variants("orchestrator")[label])
    _assert_refused(
        lambda: invoke.invoke_agent("health", invoke.new_session_id())
    )


@pytest.mark.parametrize("label", sorted(_variants("orchestrator")))
def test_orchestrator_agui_refuses_ssm_arn_that_is_not_the_created_runtime(
    aws, label
):
    _http(aws, "orchestrator", _variants("orchestrator")[label])
    _assert_refused(
        lambda: invoke.invoke_agui("health", invoke.new_session_id())
    )


@pytest.mark.parametrize("component", ("code-agent", "research-agent"))
@pytest.mark.parametrize("label", ("other-account", "other-name", "other-suffix"))
def test_a2a_refuses_ssm_arn_that_is_not_the_created_runtime(aws, component, label):
    aws.ssm_arn[component] = [_variants(component)[label]]
    _assert_refused(
        lambda: invoke.invoke_a2a(
            "health", invoke.new_session_id(), component
        )
    )


def test_require_success_path_refuses_before_posting_the_machine_token(aws):
    """verify.py's migration check calls invoke with --require-success."""
    aws.ssm_arn["orchestrator"] = [_variants("orchestrator")["other-name"]]
    _assert_refused(
        lambda: invoke.invoke_agent(
            "health",
            invoke.new_session_id(),
            require_success=True,
        )
    )


@pytest.mark.parametrize(
    "argv",
    (
        ["invoke.py", "health"],
        ["invoke.py", "--agui", "health"],
        ["invoke.py", "--require-success", "health"],
        ["invoke.py", "--a2a", "code-agent", "health"],
        ["invoke.py", "--a2a", "research-agent", "health"],
    ),
)
def test_invoke_cli_refuses_poisoned_runtime_parameter(aws, monkeypatch, argv):
    if "--a2a" in argv:
        component = argv[argv.index("--a2a") + 1]
    else:
        component = "orchestrator"
    aws.ssm_arn[component] = [_variants(component)["other-name"]]
    monkeypatch.setattr(sys, "argv", argv)
    _assert_refused(invoke.main)


@pytest.mark.parametrize(
    "call",
    (
        lambda: invoke.invoke_agent("health", invoke.new_session_id()),
        lambda: invoke.invoke_agui("health", invoke.new_session_id()),
    ),
)
def test_http_second_ssm_read_cannot_redirect_the_machine_token(aws, call):
    """The accepted SSM value is the one that is used.

    The first read matches the created runtime. A second read of the same
    parameter returns the decoy. Sending the machine token to that decoy
    fails even if the first value was checked.
    """
    legit = created_arn("orchestrator")
    aws.ssm_arn["orchestrator"] = [legit, DECOY_ARN]
    RECORDS.clear()
    call()
    targets = _targets()
    assert targets, "a matching runtime ARN should still be invoked"
    for target in targets:
        assert DECOY_ARN not in target
        assert legit in target
    for _kind, _url, authorization in RECORDS:
        assert authorization == f"Bearer {MACHINE_TOKEN}"


@pytest.mark.parametrize("component", ("code-agent", "research-agent"))
def test_a2a_second_ssm_read_cannot_redirect_the_signed_invoke(aws, component):
    legit = created_arn(component)
    aws.ssm_arn[component] = [legit, DECOY_ARN]
    RECORDS.clear()
    invoke.invoke_a2a("health", invoke.new_session_id(), component)
    targets = _targets()
    assert targets, "a matching runtime ARN should still be invoked"
    for target in targets:
        assert DECOY_ARN not in target
        assert legit in target
    for _kind, _url, authorization in RECORDS:
        assert authorization.startswith("AWS4-HMAC-SHA256 ")
        assert ACCESS_KEY_ID in authorization


@pytest.mark.parametrize(
    "call",
    (
        pytest.param(
            lambda: invoke.invoke_agent(
                "health", invoke.new_session_id(), runtime_arn=DECOY_ARN
            ),
            id="http",
        ),
        pytest.param(
            lambda: invoke.invoke_agui(
                "health", invoke.new_session_id(), runtime_arn=DECOY_ARN
            ),
            id="agui",
        ),
        pytest.param(
            lambda: invoke.invoke_a2a(
                "health",
                invoke.new_session_id(),
                "code-agent",
                runtime_arn=DECOY_ARN,
            ),
            id="a2a",
        ),
    ),
)
def test_explicit_runtime_arn_is_refused_when_it_is_not_the_created_runtime(
    aws, call
):
    _assert_refused(call)


def test_orchestrator_generation_mismatch_is_refused(aws):
    """Generation 2 is a different created runtime than the generation 1 name."""
    aws.created["orchestrator"] = created_arn("orchestrator", generation=2)
    aws.ssm_arn["orchestrator"] = [created_arn("orchestrator", generation=1)]
    _assert_refused(
        lambda: invoke.invoke_agent("health", invoke.new_session_id())
    )


def test_matching_ssm_arn_still_sends_the_machine_token_to_that_runtime(aws):
    RECORDS.clear()
    invoke.invoke_agent("health", invoke.new_session_id(), require_success=True)
    invoke.invoke_agui("health", invoke.new_session_id())
    targets = _targets()
    legit = created_arn("orchestrator")
    assert len(targets) == 2
    for target in targets:
        assert legit in target
        assert DECOY_ARN not in target
    for kind, _url, authorization in RECORDS:
        assert kind == "http"
        assert authorization == f"Bearer {MACHINE_TOKEN}"


@pytest.mark.parametrize("component", ("code-agent", "research-agent"))
def test_matching_a2a_arn_is_signed_with_the_caller_credentials(aws, component):
    RECORDS.clear()
    invoke.invoke_a2a("health", invoke.new_session_id(), component)
    targets = _targets()
    assert len(targets) == 1
    assert created_arn(component) in targets[0]
    assert DECOY_ARN not in targets[0]
    kind, _url, authorization = RECORDS[0]
    assert kind == "sdk"
    assert authorization.startswith("AWS4-HMAC-SHA256 ")
    assert ACCESS_KEY_ID in authorization


class _Response:
    status_code = 200
    text = ""

    def iter_lines(self, decode_unicode=False):
        return []


def _load_test_agent():
    import test_agent

    return test_agent


@pytest.mark.parametrize("component", ("orchestrator", "code-agent"))
def test_interactive_tester_refuses_poisoned_runtime_parameter(
    aws, monkeypatch, component
):
    test_agent = _load_test_agent()
    aws.ssm_arn[component] = [_variants(component)["other-name"]]
    posts: list[tuple[str, str]] = []

    def post(url, headers, **kwargs):
        posts.append((url, headers.get("Authorization", "")))
        return _Response()

    answers = iter(["operator", "hello", "exit"])
    monkeypatch.setattr(sys, "argv", ["test_agent.py", "--component", component])
    monkeypatch.setattr(
        test_agent,
        "authenticate_cognito",
        lambda *args, **kwargs: (
            "placeholder-user-access-token",
            "placeholder-id-token",
            "user-1",
        ),
    )
    monkeypatch.setattr("builtins.input", lambda *args, **kwargs: next(answers))
    monkeypatch.setattr("getpass.getpass", lambda *args, **kwargs: "placeholder-password")
    monkeypatch.setattr(test_agent.requests, "post", post)
    previous = signal.getsignal(signal.SIGINT)
    raised = False
    try:
        try:
            test_agent.main()
        except BaseException:
            raised = True
    finally:
        signal.signal(signal.SIGINT, previous)
    contacted = [
        f"{_auth_label(authorization)} -> {urllib.parse.unquote(url)}"
        for url, authorization in posts
    ]
    assert contacted == [], (
        "interactive tester posted a bearer token for a runtime ARN that "
        "this deployment did not create: " + "; ".join(contacted)
    )
    assert raised, "the interactive tester must refuse a runtime this deployment did not create"


def test_interactive_tester_still_invokes_the_created_runtime(aws, monkeypatch):
    test_agent = _load_test_agent()
    posts: list[tuple[str, str]] = []
    prompts = iter(["operator", "hello", "exit"])

    def post(url, headers, **kwargs):
        posts.append((url, headers.get("Authorization", "")))
        return _Response()

    monkeypatch.setattr(sys, "argv", ["test_agent.py", "--component", "orchestrator"])
    monkeypatch.setattr(
        test_agent,
        "authenticate_cognito",
        lambda *args, **kwargs: (
            "placeholder-user-access-token",
            "placeholder-id-token",
            "user-1",
        ),
    )
    monkeypatch.setattr(
        "builtins.input", lambda *args, **kwargs: next(prompts)
    )
    monkeypatch.setattr("getpass.getpass", lambda *args, **kwargs: "placeholder-password")
    monkeypatch.setattr(test_agent.requests, "post", post)
    previous = signal.getsignal(signal.SIGINT)
    try:
        test_agent.main()
    finally:
        signal.signal(signal.SIGINT, previous)
    assert len(posts) == 1
    url, authorization = posts[0]
    assert created_arn("orchestrator") in urllib.parse.unquote(url)
    assert authorization == "Bearer placeholder-user-access-token"
