"""A runtime role must not be able to invoke every AgentCore runtime.

The multi-agent and platform-team presets deploy the code and research agents
as A2A runtimes. Those runtimes have no JWT authorizer, and neither agent
checks the caller. The only gate is ``bedrock-agentcore:InvokeAgentRuntime``.
Each runtime role is granted that action on ``*``, so a caller who holds the
code-agent role can read the research runtime ARN from the project SSM
parameter and invoke it. The research agent then runs the prompt and calls
the gateway with the machine credential its own process obtains.

These tests describe the fixed boundary: only the orchestrator role may call
``InvokeAgentRuntime``, and only on the code-agent and research-agent runtime
ARNs published in SSM. They fail while every runtime role still has the
action on ``*``.
"""

from __future__ import annotations

import importlib.util
import json
import re
import socket
import subprocess
import sys
import tempfile
import threading
import uuid
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parents[1]
ACCOUNT = "111111111111"
REGION = "us-east-1"
INVOKE = "bedrock-agentcore:InvokeAgentRuntime"
# Sibling data-plane action. It is not granted today; a fix that only renames
# the over-broad grant onto it would still let a runtime role invoke a runtime.
INVOKE_ACTIONS = (
    INVOKE,
    "bedrock-agentcore:InvokeAgentRuntimeForUser",
)
UNRELATED_RUNTIME_ARN = (
    "arn:aws:bedrock-agentcore:us-east-1:999999999999:runtime/other-project_dev_other"
)

SYNTH = r"""
import json, os, sys
repo, preset, dest = sys.argv[1:]
os.chdir(repo)
sys.path.insert(0, repo)
os.environ["CDK_DEFAULT_ACCOUNT"] = "111111111111"
os.environ["CDK_DEFAULT_REGION"] = "us-east-1"
os.environ["PLATFORM_CONFIG"] = preset
import app
templates = {stack.stack_name: stack.template for stack in app.app.synth().stacks}
with open(dest, "w", encoding="utf-8") as handle:
    json.dump(templates, handle)
"""


def _glob(pattern: str, text: str) -> bool:
    """Match ``*`` and ``?`` inside one ARN segment, or across segments when
    the caller already joined them.

    ``*`` matches any characters, including ``/``. This is the resource-ARN
    wildcard rule in the IAM User Guide (``reference_policies_elements_resource``):
    a wildcard expands inside a colon-separated segment, and a segment whose
    last character is ``*`` may also expand past a colon.
    """
    regex = []
    for char in pattern:
        if char == "*":
            regex.append(".*")
        elif char == "?":
            regex.append(".")
        else:
            regex.append(re.escape(char))
    return re.fullmatch("".join(regex), text) is not None


def _arn_match(pattern: list[str], value: list[str]) -> bool:
    if not pattern and not value:
        return True
    if not pattern or not value:
        return False
    head, rest = pattern[0], pattern[1:]
    if head.endswith("*"):
        if _glob(head, value[0]) and _arn_match(rest, value[1:]):
            return True
        for take in range(2, len(value) + 1):
            if _glob(head, ":".join(value[:take])) and _arn_match(rest, value[take:]):
                return True
        return False
    if not _glob(head, value[0]):
        return False
    return _arn_match(rest, value[1:])


def resource_matches(pattern: str, resource: str) -> bool:
    """Whether an IAM ``Resource`` pattern matches one concrete ARN."""
    if pattern == "*":
        return True
    return _arn_match(pattern.split(":"), resource.split(":"))


def _check_resource_matcher() -> None:
    """The decision below is only as strong as this matcher."""
    parameter = (
        "arn:aws:ssm:us-east-1:111111111111:parameter/"
        "agentcore-workshop/dev/runtimes/research-agent/arn"
    )
    assert resource_matches("arn:aws:ssm:*:*:parameter/agentcore-workshop/*", parameter)
    assert resource_matches("*", UNRELATED_RUNTIME_ARN)
    assert not resource_matches(
        "arn:aws:bedrock-agentcore:us-east-1:111111111111:runtime/research",
        UNRELATED_RUNTIME_ARN,
    )
    # A trailing wildcard segment crosses colons, so this pattern is every
    # runtime, not one runtime. The boundary test rejects it.
    assert resource_matches("arn:aws:bedrock-agentcore:*", UNRELATED_RUNTIME_ARN)
    # From the IAM guide: ``*`` matches ``/`` inside a segment, but it does
    # not invent missing path pieces.
    assert resource_matches(
        "arn:aws:s3:::amzn-s3-demo-bucket/*/test/*",
        "arn:aws:s3:::amzn-s3-demo-bucket/1/2/test/object.jpg",
    )
    assert not resource_matches(
        "arn:aws:s3:::amzn-s3-demo-bucket/*/test/*",
        "arn:aws:s3:::amzn-s3-demo-bucket/1-test/object.jpg",
    )


def synthesize(preset: str) -> dict[str, dict[str, Any]]:
    """CloudFormation templates for one shipped preset, from ``app.py``."""
    with tempfile.TemporaryDirectory() as tmp:
        dest = str(Path(tmp) / "templates.json")
        completed = subprocess.run(
            [sys.executable, "-c", SYNTH, str(REPO), preset, dest],
            cwd=REPO,
            capture_output=True,
            text=True,
            check=False,
        )
        if completed.returncode != 0:
            raise AssertionError(
                f"cdk synth failed for {preset}\n{completed.stderr}\n{completed.stdout}"
            )
        return json.loads(Path(dest).read_text(encoding="utf-8"))


def _resolve(
    node: Any,
    stack: str,
    templates: dict[str, dict[str, Any]],
    seen: set[tuple[str, str]] | None = None,
) -> Any:
    """Resolve the intrinsics that a runtime ARN travels through.

    SSM publishes ``Fn::GetAtt`` of ``AgentRuntimeArn``. A cross-stack grant
    reaches that same value through ``Fn::ImportValue``. The allow/deny
    decision has to compare those resolved strings, so a policy that names a
    different attribute or a different stack does not count as authorizing
    the runtime the caller would actually invoke.
    """
    seen = seen or set()
    if isinstance(node, list):
        return [_resolve(item, stack, templates, seen) for item in node]
    if isinstance(node, dict):
        if set(node) == {"Ref"}:
            return f"ref:{stack}/{node['Ref']}"
        if "Fn::GetAtt" in node:
            raw = node["Fn::GetAtt"]
            if isinstance(raw, str):
                logical, _, attr = raw.partition(".")
            else:
                logical, attr = raw[0], raw[1]
            if attr == "AgentRuntimeArn":
                return (
                    f"arn:aws:bedrock-agentcore:{REGION}:{ACCOUNT}:runtime/{stack}/{logical}"
                )
            return f"attr:{stack}/{logical}/{attr}"
        if "Fn::Join" in node:
            delimiter, parts = node["Fn::Join"]
            resolved = _resolve(parts, stack, templates, seen)
            return delimiter.join(part if isinstance(part, str) else json.dumps(part) for part in resolved)
        if "Fn::ImportValue" in node:
            export_name = _resolve(node["Fn::ImportValue"], stack, templates, seen)
            key = (stack, str(export_name))
            if key in seen:
                return f"cycle:{export_name}"
            seen.add(key)
            for other, template in templates.items():
                for output in (template.get("Outputs") or {}).values():
                    export = output.get("Export", {}).get("Name")
                    if _resolve(export, other, templates, seen) == export_name:
                        return _resolve(output["Value"], other, templates, seen)
            return f"import:{export_name}"
        if "Fn::Sub" in node:
            raw = node["Fn::Sub"]
            if isinstance(raw, str):
                return raw
            template, mapping = raw
            resolved_map = _resolve(mapping, stack, templates, seen)
            def replace(match: re.Match[str]) -> str:
                value = resolved_map.get(match.group(1), match.group(0))
                return value if isinstance(value, str) else json.dumps(value)
            return re.sub(r"\$\{([^}]+)\}", replace, template)
    return node


def _roles_by_component(templates: dict[str, dict[str, Any]]) -> dict[str, tuple[str, str]]:
    """Map ``code-agent`` / ``research-agent`` / ``orchestrator`` to (stack, logical id)."""
    found: dict[str, tuple[str, str]] = {}
    for stack, template in templates.items():
        for logical, resource in template["Resources"].items():
            if resource["Type"] != "AWS::IAM::Role":
                continue
            name = resource["Properties"].get("RoleName")
            if not isinstance(name, str) or not name.endswith("-runtime-role"):
                continue
            component = name.removesuffix("-runtime-role").rsplit("-", 1)[-1]
            # component names themselves contain hyphens: code-agent, research-agent
            for candidate in ("code-agent", "research-agent", "orchestrator"):
                if name.endswith(f"-{candidate}-runtime-role"):
                    found[candidate] = (stack, logical)
    return found


def _statements_for(
    templates: dict[str, dict[str, Any]], stack: str, logical: str
) -> list[dict[str, Any]]:
    template = templates[stack]
    role = template["Resources"][logical]
    if role["Properties"].get("ManagedPolicyArns"):
        raise AssertionError(
            f"{stack}/{logical} attaches managed policies this test does not expand: "
            f"{role['Properties']['ManagedPolicyArns']}"
        )
    statements: list[dict[str, Any]] = []
    for policy in role["Properties"].get("Policies") or []:
        body = policy["PolicyDocument"]["Statement"]
        statements.extend(body if isinstance(body, list) else [body])
    for resource in template["Resources"].values():
        if resource["Type"] != "AWS::IAM::Policy":
            continue
        attached = False
        for target in resource["Properties"].get("Roles") or []:
            if target == {"Ref": logical} or target == logical:
                attached = True
        if not attached:
            continue
        body = resource["Properties"]["PolicyDocument"]["Statement"]
        statements.extend(body if isinstance(body, list) else [body])
    if not statements:
        raise AssertionError(f"no identity policy statements for {stack}/{logical}")
    return statements


def _statement_covers(statement: dict[str, Any], action: str, resource: str, stack: str, templates: dict[str, Any]) -> bool:
    actions = statement.get("Action", [])
    if isinstance(actions, str):
        actions = [actions]
    if not any(resource_matches(item, action) for item in actions):
        return False
    patterns = statement.get("Resource", [])
    if isinstance(patterns, str):
        patterns = [patterns]
    not_resources = statement.get("NotResource", [])
    if isinstance(not_resources, str):
        not_resources = [not_resources]
    resolved = [_resolve(pattern, stack, templates) for pattern in patterns]
    excluded = [_resolve(pattern, stack, templates) for pattern in not_resources]
    if patterns and not any(
        isinstance(pattern, str) and resource_matches(pattern, resource) for pattern in resolved
    ):
        return False
    if not patterns and not not_resources:
        return False
    if any(isinstance(pattern, str) and resource_matches(pattern, resource) for pattern in excluded):
        return False
    return True


def identity_allows(
    templates: dict[str, dict[str, Any]],
    component: str,
    action: str,
    resource: str,
) -> bool:
    """Same-account identity-policy decision for one runtime role.

    An explicit unconditional deny wins. An allow matches when its action and
    resource match. A condition is treated as satisfied: ignoring a condition
    that still lets this resource through would hide a grant that does not
    actually bind the action to the runtime being invoked. The IAM guide
    (``reference_policies_evaluation-logic_policy-eval-basics``) denies on an
    explicit deny, then allows when an identity policy allows the request.
    """
    stack, logical = _roles_by_component(templates)[component]
    denied = False
    allowed = False
    for statement in _statements_for(templates, stack, logical):
        if not _statement_covers(statement, action, resource, stack, templates):
            continue
        if statement.get("Effect", "Allow") == "Deny":
            if "Condition" not in statement:
                denied = True
            continue
        allowed = True
    if denied:
        return False
    return allowed


def published_runtime_arn(templates: dict[str, dict[str, Any]], component: str) -> str:
    """The ARN a caller receives from ``ssm:GetParameter`` on the runtime parameter.

    ``RuntimeStack`` writes ``/{project}/{environment}/runtimes/{component}/arn``
    with the runtime's ``AgentRuntimeArn``. Invoking a different id than this
    value is not the call the attack, or the orchestrator, makes.
    """
    suffix = f"/runtimes/{component}/arn"
    for stack, template in templates.items():
        for resource in template["Resources"].values():
            if resource["Type"] != "AWS::SSM::Parameter":
                continue
            name = resource["Properties"].get("Name", "")
            if isinstance(name, str) and name.endswith(suffix):
                value = _resolve(resource["Properties"]["Value"], stack, templates)
                if not isinstance(value, str) or not value.startswith("arn:aws:bedrock-agentcore:"):
                    raise AssertionError(
                        f"SSM parameter {name} does not publish a runtime ARN: {value!r}"
                    )
                return value
    raise AssertionError(f"no SSM runtime ARN parameter for {component}")


def assert_invoke_boundary(templates: dict[str, dict[str, Any]]) -> None:
    roles = _roles_by_component(templates)
    for component in ("orchestrator", "code-agent", "research-agent"):
        if component not in roles:
            raise AssertionError(f"preset did not synthesize a {component} runtime role")
    published = {component: published_runtime_arn(templates, component) for component in roles}
    a2a_targets = (published["code-agent"], published["research-agent"])

    for caller in ("code-agent", "research-agent"):
        for action in INVOKE_ACTIONS:
            # The research runtime is the one whose gateway credential the
            # caller does not otherwise present, so it is checked first.
            ordered = (
                ("research-agent", published["research-agent"]),
                ("code-agent", published["code-agent"]),
                ("orchestrator", published["orchestrator"]),
                ("unrelated", UNRELATED_RUNTIME_ARN),
            )
            for target, arn in ordered:
                assert not identity_allows(templates, caller, action, arn), (
                    f"{caller} role is allowed {action} on {target} ({arn}). "
                    "A2A runtime roles must not be able to invoke any runtime."
                )

    for action in INVOKE_ACTIONS:
        assert not identity_allows(templates, "orchestrator", action, published["orchestrator"]), (
            "orchestrator role must not invoke its own runtime ARN"
        )
        assert not identity_allows(templates, "orchestrator", action, UNRELATED_RUNTIME_ARN), (
            f"orchestrator role must not be granted {action} beyond the code-agent "
            "and research-agent runtime ARNs"
        )
    for arn in a2a_targets:
        assert identity_allows(templates, "orchestrator", INVOKE, arn), (
            "orchestrator role must be allowed InvokeAgentRuntime on the runtime ARN "
            f"published in SSM, not on some other id: {arn}"
        )


def _load_module(name: str, path: Path) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise AssertionError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _research_agent_executes_unauthenticated_prompt(provider_name: str) -> None:
    """POST the ``message/send`` envelope from ``scripts/invoke.py`` with no
    caller credential. The research process, not the request, obtains the
    gateway token and the gateway tool call presents that token.
    """
    strands = importlib.util.find_spec("strands")
    mcp_spec = importlib.util.find_spec("mcp")
    identity_spec = importlib.util.find_spec("bedrock_agentcore")
    if strands is None or mcp_spec is None or identity_spec is None:
        raise AssertionError(
            "the data-plane check needs strands-agents[a2a]==1.52.0, "
            "bedrock-agentcore==1.21.0, and mcp==1.29.0"
        )

    port = _free_port()
    prompt = "attacker prompt for the research agent"
    seen: dict[str, list[Any]] = {"auth": [], "calls": [], "identity": []}
    workload_token = "placeholder-workload-token"
    gateway_token = "placeholder-gateway-access-token"

    class _IdentityApi:
        def create_workload_identity(self, **kwargs: Any) -> dict[str, str]:
            seen["identity"].append(("create_workload_identity", kwargs))
            return {"name": kwargs.get("name", "workload-under-test")}

        def get_workload_access_token_for_user_id(self, **kwargs: Any) -> dict[str, str]:
            seen["identity"].append(("get_workload_access_token_for_user_id", kwargs))
            return {"workloadAccessToken": workload_token}

        def get_workload_access_token(self, **kwargs: Any) -> dict[str, str]:
            seen["identity"].append(("get_workload_access_token", kwargs))
            return {"workloadAccessToken": workload_token}

        def get_resource_oauth2_token(self, **kwargs: Any) -> dict[str, str]:
            seen["identity"].append(("get_resource_oauth2_token", kwargs))
            return {"accessToken": gateway_token}

    import boto3

    real_client = boto3.client

    def patched_client(service_name: str, *args: Any, **kwargs: Any) -> Any:
        if service_name in ("bedrock-agentcore", "bedrock-agentcore-control"):
            return _IdentityApi()
        return real_client(service_name, *args, **kwargs)

    boto3.client = patched_client
    previous = Path.cwd()
    work = Path(tempfile.mkdtemp(prefix="a2a-boundary-"))
    try:
        os_chdir = work
        import os

        os.chdir(os_chdir)
        os.environ["AWS_REGION"] = REGION
        os.environ["AWS_DEFAULT_REGION"] = REGION
        os.environ["GATEWAY_CREDENTIAL_PROVIDER_NAME"] = provider_name
        os.environ["GATEWAY_URL"] = f"http://127.0.0.1:{port}/mcp"
        os.environ["PROJECT_NAME"] = "agentcore-workshop"
        os.environ["ENVIRONMENT"] = "dev"
        sys.path.insert(0, str(REPO / "agent-code"))
        sys.path.insert(0, str(REPO / "agent-code" / "research-agent"))
        sys.path.insert(0, str(REPO / "agent-code" / "code-agent"))

        from mcp.server.fastmcp import FastMCP
        import uvicorn
        from strands.models.bedrock import BedrockModel

        gateway = FastMCP("gateway", host="127.0.0.1", port=port, stateless_http=True)

        @gateway.tool()
        def web_search(query: str) -> str:
            seen["calls"].append(query)
            return "search-result-marker"

        class _Recording:
            def __init__(self, app: Any) -> None:
                self.app = app

            async def __call__(self, scope: dict, receive: Any, send: Any) -> None:
                if scope["type"] == "http":
                    headers = {
                        key.decode().lower(): value.decode()
                        for key, value in scope.get("headers", [])
                    }
                    seen["auth"].append(headers.get("authorization"))
                await self.app(scope, receive, send)

        server = uvicorn.Server(
            uvicorn.Config(
                _Recording(gateway.streamable_http_app()),
                host="127.0.0.1",
                port=port,
                log_level="error",
            )
        )
        thread = threading.Thread(target=server.run, daemon=True)
        thread.start()
        for _ in range(50):
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                    break
            except OSError:
                import time

                time.sleep(0.1)
        else:
            raise AssertionError("local gateway did not start")

        async def model_stream(
            self: Any,
            messages: list[dict[str, Any]],
            tool_specs: list[dict[str, Any]] | None = None,
            system_prompt: str | None = None,
            **kwargs: Any,
        ):
            user_text = " ".join(
                block["text"]
                for message in messages
                if message.get("role") == "user"
                for block in message.get("content", [])
                if isinstance(block, dict) and "text" in block
            )
            already_called = any(
                isinstance(block, dict) and "toolResult" in block
                for message in messages
                for block in message.get("content", [])
            )
            if tool_specs and not already_called:
                yield {"messageStart": {"role": "assistant"}}
                yield {
                    "contentBlockStart": {
                        "contentBlockIndex": 0,
                        "start": {
                            "toolUse": {
                                "toolUseId": "tool-1",
                                "name": tool_specs[0]["name"],
                            }
                        },
                    }
                }
                yield {
                    "contentBlockDelta": {
                        "contentBlockIndex": 0,
                        "delta": {"toolUse": {"input": json.dumps({"query": user_text})}},
                    }
                }
                yield {"contentBlockStop": {"contentBlockIndex": 0}}
                yield {"messageStop": {"stopReason": "tool_use"}}
                return
            yield {"messageStart": {"role": "assistant"}}
            yield {
                "contentBlockDelta": {
                    "contentBlockIndex": 0,
                    "delta": {"text": user_text or "no-prompt"},
                }
            }
            yield {"contentBlockStop": {"contentBlockIndex": 0}}
            yield {"messageStop": {"stopReason": "end_turn"}}

        BedrockModel.stream = model_stream  # type: ignore[method-assign]

        import shared.a2a_serve as serve_mod

        captured: dict[str, Any] = {}

        def capture_app(app: Any, host: str, port: int, **kwargs: Any) -> None:
            captured["app"] = app
            captured["host"] = host
            captured["port"] = port

        serve_mod.uvicorn.run = capture_app
        research = _load_module(
            "research_agent_under_test",
            REPO / "agent-code" / "research-agent" / "agent.py",
        )
        serve_mod.serve_a2a(research.build_agent())
        assert captured["host"] == "0.0.0.0"
        assert captured["port"] == 9000

        from starlette.testclient import TestClient

        envelope = {
            "jsonrpc": "2.0",
            "id": str(uuid.uuid4()),
            "method": "message/send",
            "params": {
                "message": {
                    "role": "user",
                    "parts": [{"kind": "text", "text": prompt}],
                    "messageId": str(uuid.uuid4()),
                }
            },
        }
        response = TestClient(captured["app"]).post(
            "/",
            json=envelope,
            headers={"X-Untrusted-Caller": "not-a-credential"},
        )
        assert response.status_code == 200, response.text
        assert prompt in response.text
        assert seen["calls"] == [prompt], seen["calls"]
        assert seen["auth"], "gateway client never presented a credential"
        assert all(header == f"Bearer {gateway_token}" for header in seen["auth"]), seen["auth"]
        oauth = [call for kind, call in seen["identity"] if kind == "get_resource_oauth2_token"]
        assert oauth, seen["identity"]
        assert oauth[0]["resourceCredentialProviderName"] == provider_name
        assert oauth[0]["oauth2Flow"] == "M2M"
        assert oauth[0]["workloadIdentityToken"] == workload_token
        assert workload_token not in response.text
        assert "X-Untrusted-Caller" not in json.dumps(oauth)

        code = _load_module(
            "code_agent_under_test",
            REPO / "agent-code" / "code-agent" / "agent.py",
        )
        captured.clear()
        serve_mod.serve_a2a(code.build_agent())
        code_prompt = "attacker prompt for the code agent"
        code_envelope = {
            "jsonrpc": "2.0",
            "id": str(uuid.uuid4()),
            "method": "message/send",
            "params": {
                "message": {
                    "role": "user",
                    "parts": [{"kind": "text", "text": code_prompt}],
                    "messageId": str(uuid.uuid4()),
                }
            },
        }
        code_response = TestClient(captured["app"]).post("/", json=code_envelope)
        assert code_response.status_code == 200, code_response.text
        assert code_prompt in code_response.text
        server.should_exit = True
        thread.join(timeout=5)
    finally:
        boto3.client = real_client
        import os

        os.chdir(previous)


def _provider_name(templates: dict[str, dict[str, Any]]) -> str:
    for template in templates.values():
        for resource in template["Resources"].values():
            if resource["Type"] != "AWS::BedrockAgentCore::Runtime":
                continue
            env = resource["Properties"].get("EnvironmentVariables", {})
            if resource["Properties"].get("ProtocolConfiguration") != "A2A":
                continue
            if "GATEWAY_CREDENTIAL_PROVIDER_NAME" not in env:
                continue
            name = env["GATEWAY_CREDENTIAL_PROVIDER_NAME"]
            if not isinstance(name, str) or not name:
                raise AssertionError(f"research runtime provider name is not concrete: {name!r}")
            return name
    raise AssertionError("research runtime did not receive GATEWAY_CREDENTIAL_PROVIDER_NAME")


def test_resource_matcher_follows_iam_wildcard_rules() -> None:
    _check_resource_matcher()


def test_preset_runtime_roles_cannot_invoke_other_runtimes() -> None:
    """Both shipped presets that turn A2A on, plus the call those roles can make."""
    multi_agent = synthesize("presets/multi-agent.yaml")
    provider = _provider_name(multi_agent)
    code_has_no_authorizer = False
    research_has_no_authorizer = False
    for template in multi_agent.values():
        for resource in template["Resources"].values():
            if resource["Type"] != "AWS::BedrockAgentCore::Runtime":
                continue
            if resource["Properties"].get("ProtocolConfiguration") != "A2A":
                continue
            assert "AuthorizerConfiguration" not in resource["Properties"]
            env = resource["Properties"].get("EnvironmentVariables", {})
            if "GATEWAY_CREDENTIAL_PROVIDER_NAME" in env:
                research_has_no_authorizer = True
            else:
                code_has_no_authorizer = True
                assert "GATEWAY_URL" not in env
    assert code_has_no_authorizer and research_has_no_authorizer
    _research_agent_executes_unauthenticated_prompt(provider)
    assert_invoke_boundary(multi_agent)
    assert_invoke_boundary(synthesize("presets/platform-team.yaml"))
