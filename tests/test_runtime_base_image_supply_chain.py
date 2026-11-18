"""Runtime images must not follow a moved public Python base tag.

The agent Dockerfiles are built by the runtime CodeBuild project and the
resulting image is what AgentCore runs with the runtime role. These tests
are the spec for that path: they fail while a public tag can still become
the image that the runtime is allowed to start.

Not covered here, because they do not publish the AgentCore runtime image:
`.gitlab-ci.yml` job images, the CodeBuild environment image
`aws/codebuild/amazonlinux2-aarch64-standard:3.0`, and
`migration/adapter/Dockerfile` (its base is the customer image named by
`SOURCE_IMAGE`). The Claude Dockerfiles also download a NodeSource setup
script during `RUN`; that installer is a separate supply-chain input.
"""

from __future__ import annotations

import json
import os

os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")
os.environ.setdefault("AWS_REGION", "us-east-1")

import shutil
import stat
import subprocess
import textwrap
from pathlib import Path
from typing import Any

import aws_cdk as cdk
import boto3
import pytest
import urllib.request
from aws_cdk.assertions import Template

import infra_utils.build_trigger_lambda as build_trigger_lambda
from infra_utils.source_hash import component_image_tag
from stacks.runtime_stack import RuntimeStack

REPO = Path(__file__).resolve().parents[1]
ENV = cdk.Environment(account="111111111111", region="us-east-1")

# Image references the runtime Dockerfiles use today. A fix keeps each one
# and appends @sha256:<64 hex>, which is the digest BuildKit resolves instead
# of the tag.
RUNTIME_BASES = {
    "agent-code/orchestrator/Dockerfile": "public.ecr.aws/docker/library/python:3.11-slim",
    "agent-code/strands-agent/Dockerfile": "public.ecr.aws/docker/library/python:3.13-slim",
    "agent-code/langgraph-agent/Dockerfile": "public.ecr.aws/docker/library/python:3.13-slim",
    "agent-code/agui-langgraph-agent/Dockerfile": "public.ecr.aws/docker/library/python:3.12-slim",
    "agent-code/agui-strands-agent/Dockerfile": "public.ecr.aws/docker/library/python:3.13-slim",
    "agent-code/code-agent/Dockerfile": "public.ecr.aws/docker/library/python:3.13-slim",
    "agent-code/research-agent/Dockerfile": "public.ecr.aws/docker/library/python:3.13-slim",
    "agent-code/claude-sdk-agent/Dockerfile": "public.ecr.aws/docker/library/python:3.13-slim",
    "agent-code/claude-sdk-multi-agent/Dockerfile": "public.ecr.aws/docker/library/python:3.13-slim",
    "migration/simulation/existing-ec2-agent/Dockerfile": "public.ecr.aws/docker/library/python:3.12-slim",
}
PLACEHOLDER_BASE = "public.ecr.aws/docker/library/python:3.11-slim"
PATTERNS = [
    "orchestrator",
    "strands-agent",
    "langgraph-agent",
    "agui-langgraph-agent",
    "agui-strands-agent",
    "code-agent",
    "research-agent",
    "claude-sdk-agent",
    "claude-sdk-multi-agent",
]
CRITICAL = {"name": "CVE-2024-0001", "severity": "CRITICAL"}
DIGEST_A = "sha256:" + ("a" * 64)
DIGEST_B = "sha256:" + ("b" * 64)
DIGEST_OTHER = "sha256:" + ("c" * 64)


def _resources(template: dict[str, Any], resource_type: str) -> dict[str, dict[str, Any]]:
    return {
        logical_id: resource
        for logical_id, resource in template["Resources"].items()
        if resource["Type"] == resource_type
    }


def _synth_runtime(**kwargs: Any) -> dict[str, Any]:
    app = cdk.App()
    stack = RuntimeStack(
        app,
        "RuntimeSupplyChain",
        project_name="proj",
        environment="dev",
        env=ENV,
        **kwargs,
    )
    return Template.from_stack(stack).to_json()


def _buildspec(template: dict[str, Any]) -> dict[str, Any]:
    project = next(iter(_resources(template, "AWS::CodeBuild::Project").values()))
    return json.loads(project["Properties"]["Source"]["BuildSpec"])


def _commands(spec: dict[str, Any]) -> list[str]:
    # buildspec 0.2 runs phases in this order, and each phase's commands share
    # one shell. A failing command skips the rest of that phase (and, with no
    # on-failure override, fails the build). See the CodeBuild buildspec reference.
    ordered = []
    for phase in ("install", "pre_build", "build", "post_build"):
        body = spec.get("phases", {}).get(phase)
        if not body:
            continue
        ordered.extend(body.get("commands", []))
    return ordered


def _first_from(dockerfile: Path) -> str:
    """First Dockerfile FROM image, using the instruction the builder sees."""
    logical: list[str] = []
    pending = ""
    for raw in dockerfile.read_text().splitlines():
        stripped = raw.strip()
        if not pending and (not stripped or stripped.startswith("#")):
            continue
        if raw.rstrip().endswith("\\"):
            pending += raw.rstrip()[:-1] + " "
            continue
        logical.append((pending + raw).strip())
        pending = ""
    for line in logical:
        parts = line.split()
        if not parts or parts[0] != "FROM":
            continue
        tokens = parts[1:]
        index = 0
        while index < len(tokens):
            token = tokens[index]
            if token.startswith("--"):
                index += 1 if "=" in token else 2
                continue
            return token
    raise AssertionError(f"{dockerfile} has no FROM instruction")


def _digest_pinned(reference: str, base: str) -> bool:
    prefix = base + "@sha256:"
    if not reference.startswith(prefix):
        return False
    digest = reference[len(prefix) :]
    return len(digest) == 64 and all(char in "0123456789abcdef" for char in digest)


def _docker(*args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    sock = Path("/var/run/docker.sock")
    if sock.exists() and os.access(sock, os.R_OK | os.W_OK):
        command = ["docker", *args]
    else:
        command = ["sudo", "docker", *args]
    return subprocess.run(
        command,
        check=check,
        capture_output=True,
        text=True,
    )


def _marker_image(directory: Path, label: str) -> str:
    context = directory / label
    context.mkdir()
    (context / "identity").write_text(label)
    (context / "Dockerfile").write_text("FROM scratch\nCOPY identity /identity\n")
    built = _docker(
        "build",
        "--platform",
        "linux/arm64",
        "-q",
        "-t",
        f"base-supply-{label}",
        str(context),
    )
    return built.stdout.strip()


def _repository_name(template: dict[str, Any]) -> str:
    repository = next(iter(_resources(template, "AWS::ECR::Repository").values()))
    return repository["Properties"]["RepositoryName"]


def _deployed_tag(template: dict[str, Any]) -> str:
    runtime = next(iter(_resources(template, "AWS::BedrockAgentCore::Runtime").values()))
    uri = runtime["Properties"]["AgentRuntimeArtifact"]["ContainerConfiguration"]["ContainerUri"]
    tail = uri["Fn::Join"][1][-1]
    assert isinstance(tail, str) and tail.startswith(":")
    return tail[1:]


def _scan_result(digest: str, status: str, critical: bool) -> dict[str, Any]:
    finding = [CRITICAL] if critical else []
    return {
        "imageScanStatus": {"status": status},
        "imageScanFindings": {"findings": finding, "enhancedFindings": finding},
        "imageId": {"imageDigest": digest or DIGEST_A},
    }


class _ScanState:
    """ECR scan responses for one release attempt.

    `critical` reports a critical finding for the deployed tag on every read
    and a clean scan for every other tag. `toctou` reports a clean digest on
    the first findings read and a different digest with a critical finding on
    the next read. `pending` never leaves IN_PROGRESS.
    """

    def __init__(self, mode: str, repository: str, tag: str) -> None:
        self.mode = mode
        self.repository = repository
        self.tag = tag
        self.finding_reads = 0
        self.calls: list[tuple[str, dict[str, Any]]] = []

    def _image(self, arguments: dict[str, Any]) -> tuple[str | None, str | None]:
        image = arguments.get("imageId") or {}
        if not image and arguments.get("imageIds"):
            image = arguments["imageIds"][0]
        return image.get("imageTag"), image.get("imageDigest")

    def _about_deployed_image(self, arguments: dict[str, Any]) -> bool:
        if arguments.get("repositoryName") != self.repository:
            return False
        tag, digest = self._image(arguments)
        if tag == "latest":
            return False
        return tag in (None, self.tag) or digest in (DIGEST_A, DIGEST_B)

    def describe_image_scan_findings(self, **arguments: Any) -> dict[str, Any]:
        self.calls.append(("describe_image_scan_findings", arguments))
        self.finding_reads += 1
        if not self._about_deployed_image(arguments):
            return _scan_result(DIGEST_OTHER, "COMPLETE", False)
        if self.mode == "pending":
            return _scan_result(DIGEST_A, "IN_PROGRESS", False)
        if self.mode == "critical":
            return _scan_result(DIGEST_A, "COMPLETE", True)
        if self.finding_reads == 1:
            return _scan_result(DIGEST_A, "COMPLETE", False)
        return _scan_result(DIGEST_B, "COMPLETE", True)

    def get_waiter(self, name: str) -> Any:
        if name != "image_scan_complete":
            raise AssertionError(name)
        scanner = self

        class _Waiter:
            def wait(self, **arguments: Any) -> None:
                for _attempt in range(3):
                    response = scanner.describe_image_scan_findings(**arguments)
                    status = response["imageScanStatus"]["status"]
                    if status == "COMPLETE":
                        return
                    if status == "FAILED":
                        raise RuntimeError("image scan failed")
                raise RuntimeError("image scan did not complete")

        return _Waiter()

    def get_paginator(self, name: str) -> Any:
        if name != "describe_image_scan_findings":
            raise AssertionError(name)
        scanner = self

        class _Paginator:
            def paginate(self, **arguments: Any) -> Any:
                yield scanner.describe_image_scan_findings(**arguments)

        return _Paginator()

    def describe_images(self, **arguments: Any) -> dict[str, Any]:
        self.calls.append(("describe_images", arguments))
        tag, _digest = self._image(arguments)
        deployed = self._about_deployed_image(arguments)
        digest = DIGEST_A if deployed else DIGEST_OTHER
        if deployed and self.mode == "toctou" and self.finding_reads:
            digest = DIGEST_B
        return {"imageDetails": [{"imageDigest": digest, "imageTags": [tag or self.tag]}]}


def _write_stubs(directory: Path) -> None:
    aws_path = directory / "aws"
    docker_path = directory / "docker"
    aws_path.write_text(
        textwrap.dedent(
            """\
            #!/usr/bin/env python3
            import json, os, sys
            args = sys.argv[1:]
            log = open(os.environ["STUB_LOG"], "a")
            log.write("aws " + " ".join(args) + "\\n")
            log.close()

            def option(flag):
                if flag not in args:
                    return ""
                return args[args.index(flag) + 1]

            if args[:2] == ["s3", "cp"]:
                dest = args[-1]
                import zipfile
                with zipfile.ZipFile(dest, "w") as archive:
                    archive.writestr("Dockerfile", "FROM scratch\\n")
                sys.exit(0)
            if args[:2] == ["ecr", "get-login-password"]:
                sys.stdout.write("password\\n")
                sys.exit(0)
            if args[:3] == ["ecr", "wait", "image-scan-complete"] or (
                len(args) >= 2 and args[0] == "ecr" and args[1] == "wait"
            ):
                mode = os.environ["SCAN_MODE"]
                sys.exit(255 if mode == "pending" else 0)
            if args[:2] == ["ecr", "describe-image-scan-findings"]:
                # The state file is the call counter shared with this process tree.
                count_path = os.environ["SCAN_COUNT"]
                count = int(open(count_path).read() or "0") + 1
                open(count_path, "w").write(str(count))
                repository = option("--repository-name")
                image = option("--image-id")
                tag = ""
                digest = ""
                if image.startswith("imageTag="):
                    tag = image.split("=", 1)[1]
                elif image.startswith("imageDigest="):
                    digest = image.split("=", 1)[1]
                deployed_repo = os.environ["DEPLOYED_REPOSITORY"]
                deployed_tag = os.environ["DEPLOYED_TAG"]
                mode = os.environ["SCAN_MODE"]
                about_deployed = repository == deployed_repo and tag != "latest" and (
                    tag in ("", deployed_tag) or digest in (
                        os.environ["DIGEST_A"], os.environ["DIGEST_B"]
                    )
                )
                status = "COMPLETE"
                critical = False
                chosen = os.environ["DIGEST_A"]
                if not about_deployed:
                    chosen = os.environ["DIGEST_OTHER"]
                elif mode == "pending":
                    status = "IN_PROGRESS"
                elif mode == "critical":
                    critical = True
                elif count == 1:
                    chosen = os.environ["DIGEST_A"]
                else:
                    chosen = os.environ["DIGEST_B"]
                    critical = True
                finding = [{"name": "CVE-2024-0001", "severity": "CRITICAL"}] if critical else []
                json.dump({
                    "imageScanStatus": {"status": status},
                    "imageScanFindings": {"findings": finding, "enhancedFindings": finding},
                    "imageId": {"imageDigest": digest or chosen},
                    "repositoryName": repository,
                }, sys.stdout)
                sys.exit(0)
            sys.exit(0)
            """
        )
    )
    docker_path.write_text(
        textwrap.dedent(
            """\
            #!/usr/bin/env python3
            import os, sys
            open(os.environ["STUB_LOG"], "a").write("docker " + " ".join(sys.argv[1:]) + "\\n")
            sys.exit(0)
            """
        )
    )
    for path in (aws_path, docker_path):
        path.chmod(path.stat().st_mode | stat.S_IEXEC)


def _run_buildspec(template: dict[str, Any], mode: str, work: Path) -> int:
    state_dir = work / "stubs"
    state_dir.mkdir()
    _write_stubs(state_dir)
    (state_dir / "count").write_text("0")
    (state_dir / "log").write_text("")
    script = "set -e\n" + "\n".join(_commands(_buildspec(template))) + "\n"
    env = os.environ.copy()
    env.update(
        {
            "PATH": f"{state_dir}:{env.get('PATH', '')}",
            "SCAN_MODE": mode,
            "SCAN_COUNT": str(state_dir / "count"),
            "STUB_LOG": str(state_dir / "log"),
            "DEPLOYED_REPOSITORY": _repository_name(template),
            "DEPLOYED_TAG": _deployed_tag(template),
            "DIGEST_A": DIGEST_A,
            "DIGEST_B": DIGEST_B,
            "DIGEST_OTHER": DIGEST_OTHER,
            "REPO_URI": (
                f"111111111111.dkr.ecr.us-east-1.amazonaws.com/{_repository_name(template)}"
            ),
            "IMAGE_TAG": _deployed_tag(template),
            "SOURCE_S3_URI": "s3://source/source.zip",
            "AWS_DEFAULT_REGION": "us-east-1",
            "ACCOUNT_ID": "111111111111",
            "HOME": str(work),
        }
    )
    completed = subprocess.run(
        ["bash", "-c", script],
        cwd=work,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    (work / "build-stdout").write_text(completed.stdout)
    (work / "build-stderr").write_text(completed.stderr)
    (work / "stub-log").write_text((state_dir / "log").read_text())
    return completed.returncode


class _CodeBuild:
    def __init__(self, status: str) -> None:
        self.status = status

    def start_build(self, **_kwargs: Any) -> dict[str, Any]:
        return {"build": {"id": "build-1"}}

    def batch_get_builds(self, **_kwargs: Any) -> dict[str, Any]:
        return {"builds": [{"buildStatus": self.status}]}


class _Response:
    def read(self) -> bytes:
        return b""

    def __enter__(self) -> _Response:
        return self

    def __exit__(self, *_args: object) -> bool:
        return False


def _invoke_trigger(
    monkeypatch: pytest.MonkeyPatch,
    template: dict[str, Any],
    mode: str,
    build_status: str,
) -> list[str]:
    repository = _repository_name(template)
    tag = _deployed_tag(template)
    scan = _ScanState(mode, repository, tag)
    codebuild = _CodeBuild(build_status)
    statuses: list[str] = []
    reasons: list[str] = []

    def client(service_name: str, *_args: Any, **_kwargs: Any) -> Any:
        if service_name == "ecr":
            return scan
        if service_name == "codebuild":
            return codebuild
        raise AssertionError(service_name)

    def urlopen(request: urllib.request.Request, *_args: Any, **_kwargs: Any) -> _Response:
        body = json.loads(request.data.decode())
        statuses.append(body["Status"])
        reasons.append(body.get("Reason", ""))
        return _Response()

    monkeypatch.setattr(boto3, "client", client)
    monkeypatch.setattr(build_trigger_lambda.boto3, "client", client)
    monkeypatch.setattr(build_trigger_lambda, "codebuild", codebuild)
    monkeypatch.setattr(build_trigger_lambda.time, "sleep", lambda _seconds: None)
    monkeypatch.setattr(build_trigger_lambda.urllib.request, "urlopen", urlopen)
    build_trigger_lambda.handler(
        {
            "RequestType": "Create",
            "ResponseURL": "https://cloudformation-custom-resource-response.s3.amazonaws.com/response",
            "StackId": "arn:aws:cloudformation:us-east-1:111111111111:stack/runtime/id",
            "RequestId": "request",
            "LogicalResourceId": "BuildTriggerCR",
            "ResourceProperties": {
                "ProjectName": "proj-dev-build-orchestrator",
                "SourceHash": tag,
                "EnvironmentOverrides": [
                    {
                        "name": "IMAGE_TAG",
                        "value": tag,
                        "type": "PLAINTEXT",
                    },
                    {
                        "name": "REPO_URI",
                        "value": f"111111111111.dkr.ecr.us-east-1.amazonaws.com/{repository}",
                        "type": "PLAINTEXT",
                    },
                    {"name": "ACCOUNT_ID", "value": "111111111111", "type": "PLAINTEXT"},
                ],
            },
        },
        None,
    )
    return statuses, reasons


def _release_statuses(
    monkeypatch: pytest.MonkeyPatch,
    template: dict[str, Any],
    mode: str,
    work: Path,
) -> list[str]:
    exit_code = _run_buildspec(template, mode, work)
    build_status = "SUCCEEDED" if exit_code == 0 else "FAILED"
    return _invoke_trigger(monkeypatch, template, mode, build_status), exit_code


@pytest.fixture(scope="module")
def orchestrator_template() -> dict[str, Any]:
    return _synth_runtime(
        component_name="orchestrator",
        source_dir="agent-code",
        dockerfile_pattern="orchestrator",
        runtime_type="orchestrator",
    )


def test_runtime_dockerfiles_pin_the_base_digest() -> None:
    unpinned = []
    for relative, base in RUNTIME_BASES.items():
        reference = _first_from(REPO / relative)
        if not _digest_pinned(reference, base):
            unpinned.append(f"{relative} builds FROM {reference}")
    assert not unpinned, (
        "each runtime Dockerfile must keep its public Python tag and append "
        "@sha256:<64 lowercase hex>:\n" + "\n".join(unpinned)
    )


def test_missing_source_placeholder_pins_the_base_digest() -> None:
    placeholder = REPO / ".cdk-placeholder"
    shutil.rmtree(placeholder, ignore_errors=True)
    try:
        template = _synth_runtime(
            component_name="orchestrator",
            source_dir="source-dir-that-is-not-in-the-repo",
            runtime_type="orchestrator",
        )
        reference = _first_from(placeholder / "Dockerfile")
        assert _digest_pinned(reference, PLACEHOLDER_BASE), reference
        commands = "\n".join(_commands(_buildspec(template)))
        assert "docker build --platform linux/arm64 -t $REPO_URI:$IMAGE_TAG ." in commands
    finally:
        shutil.rmtree(placeholder, ignore_errors=True)


def test_codebuild_builds_each_pattern_dockerfile() -> None:
    unpinned: list[str] = []
    for pattern in PATTERNS:
        template = _synth_runtime(
            component_name="orchestrator" if pattern == "orchestrator" else pattern,
            source_dir="agent-code",
            dockerfile_pattern=pattern,
            runtime_type="a2a_agent" if pattern in {"code-agent", "research-agent"} else "orchestrator",
        )
        commands = "\n".join(_commands(_buildspec(template)))
        expected = (
            f"docker build --platform linux/arm64 -f {pattern}/Dockerfile "
            "-t $REPO_URI:$IMAGE_TAG ."
        )
        assert expected in commands
        reference = _first_from(REPO / "agent-code" / pattern / "Dockerfile")
        base = RUNTIME_BASES[f"agent-code/{pattern}/Dockerfile"]
        unpinned.append(reference if not _digest_pinned(reference, base) else "")
    missing = [item for item in unpinned if item]
    assert not missing, missing


def test_moved_public_tag_is_not_the_base_that_docker_build_selects(tmp_path: Path) -> None:
    """BuildKit (and the legacy builder) select whatever digest the tag points
    at. Tagging a replacement image with the Dockerfile's base name must not
    make `docker build` select it once the FROM line is digest-pinned.
    """
    replaced = _marker_image(tmp_path, "replaced")
    assert replaced.startswith("sha256:")
    followed: list[str] = []
    try:
        for relative, base in RUNTIME_BASES.items():
            reference = _first_from(REPO / relative)
            _docker("tag", "base-supply-replaced", base)
            context = tmp_path / relative.replace("/", "_")
            context.mkdir()
            (context / "Dockerfile").write_text(f"FROM {reference}\n")
            built = _docker(
                "build",
                "--platform",
                "linux/arm64",
                "-t",
                "runtime-base-check",
                str(context),
                check=False,
            )
            log = built.stdout + built.stderr
            if "@sha256:" not in reference and built.returncode != 0:
                followed.append(f"{relative} did not build:\n{log}")
            elif replaced in log:
                followed.append(
                    f"{relative} resolved {reference} to the replaced image {replaced}"
                )
    finally:
        for base in set(RUNTIME_BASES.values()):
            _docker("rmi", "-f", base, check=False)
        _docker("rmi", "-f", "base-supply-replaced", "runtime-base-check", check=False)
    assert not followed, "\n".join(followed)


def test_runtime_repository_tags_are_immutable(orchestrator_template: dict[str, Any]) -> None:
    repository = next(iter(_resources(orchestrator_template, "AWS::ECR::Repository").values()))
    properties = repository["Properties"]
    assert properties.get("ImageTagMutability") == "IMMUTABLE", properties
    assert "ImageTagMutabilityExclusionFilters" not in properties
    runtime = next(
        iter(_resources(orchestrator_template, "AWS::BedrockAgentCore::Runtime").values())
    )
    assert "BuildTriggerCR" in runtime["DependsOn"]
    tag = _deployed_tag(orchestrator_template)
    assert tag == component_image_tag(str(REPO / "agent-code"), "orchestrator")
    statements = [
        statement
        for policy in _resources(orchestrator_template, "AWS::IAM::Policy").values()
        for statement in policy["Properties"]["PolicyDocument"]["Statement"]
    ]
    bedrock = next(statement for statement in statements if statement.get("Sid") == "BedrockModels")
    assert "bedrock:InvokeModel" in bedrock["Action"]
    agentcore = next(
        statement for statement in statements if statement.get("Sid") == "AgentCoreAccess"
    )
    assert "bedrock-agentcore:CreateEvent" in agentcore["Action"]
    role_logical_id = runtime["Properties"]["RoleArn"]["Fn::GetAtt"][0]
    trust = orchestrator_template["Resources"][role_logical_id]
    principals = json.dumps(trust["Properties"]["AssumeRolePolicyDocument"])
    assert "bedrock-agentcore.amazonaws.com" in principals


def test_migration_runtime_repository_tags_are_immutable() -> None:
    template = _synth_runtime(
        component_name="orchestrator",
        source_dir="agent-code",
        runtime_type="orchestrator",
        build_context="migration/simulation/existing-ec2-agent",
        build_dockerfile="Dockerfile",
        adapter_dir="migration/adapter",
    )
    repository = next(iter(_resources(template, "AWS::ECR::Repository").values()))
    assert repository["Properties"].get("ImageTagMutability") == "IMMUTABLE"
    commands = "\n".join(_commands(_buildspec(template)))
    assert "docker build --platform linux/arm64 -f context/Dockerfile" in commands
    reference = _first_from(REPO / "migration/simulation/existing-ec2-agent/Dockerfile")
    assert _digest_pinned(reference, RUNTIME_BASES["migration/simulation/existing-ec2-agent/Dockerfile"])


@pytest.mark.parametrize("mode", ["critical", "toctou", "pending"])
def test_runtime_is_not_released_when_the_deployed_image_scan_is_not_clean(
    monkeypatch: pytest.MonkeyPatch,
    orchestrator_template: dict[str, Any],
    tmp_path: Path,
    mode: str,
) -> None:
    (statuses, reasons), _exit_code = _release_statuses(
        monkeypatch, orchestrator_template, mode, tmp_path
    )
    assert "SUCCESS" not in statuses, (
        f"{mode}: CloudFormation was told the build succeeded; "
        f"stub log:\n{(tmp_path / 'stub-log').read_text()}"
    )
    assert statuses == ["FAILED"]
    reason = reasons[0]
    assert "AttributeError" not in reason
    assert "Traceback" not in reason
    assert reason == "Build FAILED" or any(
        word in reason.lower() for word in ("scan", "critical", "digest", "finding")
    ), reason
