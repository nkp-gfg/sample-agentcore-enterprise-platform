"""Substituted packages must not run during the migration image build.

The migration preset builds ``migration/simulation/existing-ec2-agent`` and
then ``migration/adapter`` in privileged CodeBuild, and deploys that image as
the orchestrator runtime. Both Dockerfiles install unpinned packages as root.
pip (the copy in the simulation image's base) executes a source distribution's
``setup.py`` while installing, and the runtime later imports those packages.

These tests publish a substitute release that satisfies the declared
specifier and point that pip at only that index. They fail while the install
accepts the substitute and runs it. They pass when the image's pip command
rejects the substitute on its hash before any install or import code runs.

The same unpinned root install exists in ``agent-code/*/Dockerfile`` for the
non-migration presets. Those builds are not on the migration preset's
CodeBuild path and are not covered here.
"""

from __future__ import annotations

import json
import os
import shlex
import shutil
import subprocess
import textwrap
from pathlib import Path
from typing import Any

import aws_cdk as cdk
import pytest
from aws_cdk.assertions import Template

from infra_utils.platform_config import load_platform_config, to_env
from stacks.runtime_stack import RuntimeStack

REPO = Path(__file__).resolve().parents[1]
PRESET = REPO / "presets" / "migration.yaml"
ENV = cdk.Environment(account="111111111111", region="us-east-1")
SETUPTOOLS_VERSION = "84.2.1"
BASE_IMAGE = "public.ecr.aws/docker/library/python:3.12-slim"
HASH_REFUSALS = (
    "THESE PACKAGES DO NOT MATCH THE HASHES FROM THE REQUIREMENTS FILE",
    "Hashes are required in --require-hashes mode",
    "In --require-hashes mode, all requirements must have their versions pinned",
)
# Actions the migrated runtime role grants the image that imports the package.
GATEWAY_ACTION = "bedrock-agentcore:InvokeGateway"
MEMORY_ACTIONS = (
    "bedrock-agentcore:CreateEvent",
    "bedrock-agentcore:RetrieveMemoryRecords",
)
TOKEN_VAULT_SID = "AgentCoreIdentityTokenVaultSecrets"


def _resources(template: dict[str, Any], resource_type: str) -> list[dict[str, Any]]:
    return [
        resource
        for resource in template["Resources"].values()
        if resource["Type"] == resource_type
    ]


def _migration_template() -> dict[str, Any]:
    """Synthesize the orchestrator the way ``app.py`` does for this preset."""
    config = load_platform_config(PRESET)
    env = to_env(config)
    app = cdk.App()
    stack = RuntimeStack(
        app,
        "MigrationRuntime",
        project_name=config.project,
        environment=config.environment,
        component_name="orchestrator",
        source_dir="agent-code",
        dockerfile_pattern=config.agents.pattern,
        runtime_type="orchestrator",
        build_context=env["MIGRATION_BUILD_CONTEXT"],
        build_dockerfile=env.get("MIGRATION_BUILD_DOCKERFILE", "Dockerfile"),
        adapter_dir="migration/adapter",
        migration_port=env.get("MIGRATION_PORT", "8000"),
        migration_invoke_path=env.get("MIGRATION_INVOKE_PATH", "/run"),
        migration_health_path=env.get("MIGRATION_HEALTH_PATH", "/healthz"),
        migration_secret_names=[
            name for name in env.get("MIGRATION_SECRETS", "").split(",") if name
        ],
        env=ENV,
    )
    return Template.from_stack(stack).to_json()


def _buildspec(template: dict[str, Any]) -> str:
    spec = _resources(template, "AWS::CodeBuild::Project")[0]["Properties"]["Source"][
        "BuildSpec"
    ]
    if not isinstance(spec, str):
        spec = json.dumps(spec)
    parsed = json.loads(spec)
    return "\n".join(
        command for phase in parsed["phases"].values() for command in phase["commands"]
    )


def _statements(template: dict[str, Any]) -> list[dict[str, Any]]:
    statements = []
    for policy in _resources(template, "AWS::IAM::Policy"):
        document = policy["Properties"]["PolicyDocument"]
        statements.extend(document["Statement"])
    return statements


def _logical_lines(dockerfile: str) -> list[str]:
    logical: list[str] = []
    buffer = ""
    for raw in dockerfile.splitlines():
        stripped = raw.strip()
        if not buffer and (not stripped or stripped.startswith("#")):
            continue
        buffer = f"{buffer} {stripped}".strip() if buffer else stripped
        if buffer.endswith("\\"):
            buffer = buffer[:-1].rstrip()
            continue
        logical.append(buffer)
        buffer = ""
    if buffer:
        logical.append(buffer)
    return logical


def _normalize_user(user: str) -> str:
    user = user.strip()
    if user in {"", "root", "0"}:
        return "0:0"
    if ":" not in user:
        return f"{user}:{user}"
    return user


def _pip_steps(dockerfile: str, substitutions: dict[str, str]) -> list[tuple[str, str]]:
    """Pip installs in the Dockerfile, paired with the USER in effect."""
    user = "0:0"
    steps: list[tuple[str, str]] = []
    for line in _logical_lines(dockerfile):
        if line.startswith("USER "):
            raw = line.split(None, 1)[1]
            for name, value in substitutions.items():
                raw = raw.replace("${" + name + "}", value).replace("$" + name, value)
            user = _normalize_user(raw)
            continue
        if line.startswith("RUN ") and "pip install" in line:
            steps.append((user, line[4:].strip()))
    return steps


def _final_user(dockerfile: str, substitutions: dict[str, str]) -> str:
    user = "0:0"
    for line in _logical_lines(dockerfile):
        if line.startswith("USER "):
            raw = line.split(None, 1)[1]
            for name, value in substitutions.items():
                raw = raw.replace("${" + name + "}", value).replace("$" + name, value)
            user = _normalize_user(raw)
    return user


def _requirement_names(text: str) -> list[tuple[str, str]]:
    """Return (project, version) for every requirement a command installs.

    An exact ``==`` pin is reproduced so a version pin without a hash still
    selects the substitute. Anything else is published as 9.9.9, which
    satisfies an unpinned or minimum-version requirement.
    """
    found: list[tuple[str, str]] = []
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith("-"):
            continue
        body = line.split(";", 1)[0].split("--hash", 1)[0].strip()
        name = body.split("[", 1)[0]
        for separator in ("===", "==", ">=", "<=", "~=", "!=", ">", "<"):
            name = name.split(separator, 1)[0]
        name = name.strip()
        if not name:
            continue
        version = "9.9.9"
        if "==" in body and "===" not in body:
            version = body.split("==", 1)[1].strip().split()[0]
        found.append((name, version))
    return found


def _requirements_from_command(command: str, context: Path) -> list[tuple[str, str]]:
    requirements: list[tuple[str, str]] = []
    for segment in command.replace("||", "&&").split("&&"):
        if "pip" not in segment or "install" not in segment:
            continue
        tokens = shlex.split(segment)
        index = 0
        valued = {
            "-r",
            "--requirement",
            "-c",
            "--constraint",
            "-i",
            "--index-url",
            "--extra-index-url",
            "-f",
            "--find-links",
            "--hash",
            "-t",
            "--target",
        }
        while index < len(tokens):
            token = tokens[index]
            if token in {"-r", "--requirement"}:
                requirement_file = Path(tokens[index + 1])
                if not requirement_file.is_absolute():
                    requirement_file = context / requirement_file
                requirements.extend(_requirement_names(requirement_file.read_text()))
                index += 2
                continue
            if token in valued:
                index += 2
                continue
            if token.startswith("-") or token in {
                "pip",
                "pip3",
                "python",
                "python3",
                "-m",
                "install",
            }:
                index += 1
                continue
            requirements.extend(_requirement_names(token))
            index += 1
    return requirements


def _pep503(name: str) -> str:
    return name.lower().replace("_", "-")


def _write_substitute(root: Path, dist: str, version: str) -> None:
    """Source tree whose setup.py and import both record the effective uid."""
    slug = _pep503(dist)
    package = root / slug
    package.mkdir(parents=True)
    (package / "setup.py").write_text(
        textwrap.dedent(
            f"""
            import os
            from pathlib import Path
            marker = Path("/attack") / "install-{slug}"
            try:
                marker.parent.mkdir(parents=True, exist_ok=True)
                marker.write_text(f"install euid={{os.geteuid()}}\\n")
            except OSError:
                pass
            from setuptools import find_packages, setup
            setup(name={dist!r}, version={version!r}, packages=find_packages())
            """
        ).lstrip()
    )
    (package / "pyproject.toml").write_text(
        textwrap.dedent(
            f"""
            [build-system]
            requires = ["setuptools=={SETUPTOOLS_VERSION}"]
            build-backend = "setuptools.build_meta"
            """
        ).lstrip()
    )
    if slug == "strands-agents":
        module = package / "strands"
        models = module / "models"
        models.mkdir(parents=True)
        (module / "__init__.py").write_text(
            textwrap.dedent(
                """
                import os
                from pathlib import Path
                Path("/attack/import-strands-agents").write_text(
                    f"import euid={os.geteuid()}\\n"
                )

                class Agent:
                    def __init__(self, *args, **kwargs):
                        pass

                    def __call__(self, *args, **kwargs):
                        return "ok"
                """
            ).lstrip()
        )
        (models / "__init__.py").write_text("")
        (models / "bedrock.py").write_text(
            textwrap.dedent(
                """
                class BedrockModel:
                    def __init__(self, *args, **kwargs):
                        pass
                """
            ).lstrip()
        )
        return
    if slug == "bedrock-agentcore":
        module = package / "bedrock_agentcore"
        module.mkdir()
        (module / "__init__.py").write_text("")
        (module / "runtime.py").write_text(
            textwrap.dedent(
                """
                import os
                from pathlib import Path
                Path("/attack/import-bedrock-agentcore").write_text(
                    f"import euid={os.geteuid()}\\n"
                )

                class BedrockAgentCoreApp:
                    def __init__(self, *args, **kwargs):
                        pass

                    def entrypoint(self, fn):
                        return fn
                """
            ).lstrip()
        )
        return
    module_name = slug.replace("-", "_")
    module = package / module_name
    module.mkdir()
    (module / "__init__.py").write_text(
        textwrap.dedent(
            f"""
            import os
            from pathlib import Path
            Path("/attack/import-{slug}").write_text(
                f"import euid={{os.geteuid()}}\\n"
            )

            def client(*args, **kwargs):
                raise RuntimeError("substitute package has no credentials")
            """
        ).lstrip()
    )


def _index_html(directory: Path) -> None:
    links = []
    for artifact in sorted(directory.iterdir()):
        if artifact.name == "index.html" or not artifact.is_file():
            continue
        links.append(f'<a href="{artifact.name}">{artifact.name}</a>')
    (directory / "index.html").write_text(
        "<!DOCTYPE html><html><body>" + "<br>".join(links) + "</body></html>\n"
    )


def _docker(*args: str, **kwargs: Any) -> subprocess.CompletedProcess[str]:
    if shutil.which("docker") is None:
        pytest.fail("docker is required to run the migration image install")
    return subprocess.run(
        ["docker", *args],
        check=False,
        capture_output=True,
        text=True,
        **kwargs,
    )


@pytest.fixture(scope="module")
def setuptools_wheel(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """The build backend pip installs before it executes setup.py."""
    destination = tmp_path_factory.mktemp("setuptools")
    result = _docker(
        "run",
        "--rm",
        "-v",
        f"{destination}:/wheels",
        BASE_IMAGE,
        "python",
        "-m",
        "pip",
        "download",
        "-d",
        "/wheels",
        f"setuptools=={SETUPTOOLS_VERSION}",
    )
    assert result.returncode == 0, result.stderr
    wheels = list(destination.glob("setuptools-*.whl"))
    assert len(wheels) == 1, result.stdout + result.stderr
    return wheels[0]


def _build_index(
    requirements: list[tuple[str, str]],
    work: Path,
    setuptools_wheel: Path,
) -> Path:
    work.mkdir(parents=True, exist_ok=True)
    sources = work / "sources"
    dist = work / "dist"
    simple = work / "simple"
    dist.mkdir()
    simple.mkdir()
    # One substitute per project. A later == pin replaces the default version.
    chosen: dict[str, str] = {}
    for name, version in requirements:
        chosen[_pep503(name)] = version
    for name, version in chosen.items():
        _write_substitute(sources, name, version)
    wheel_dir = work / "wheels"
    wheel_dir.mkdir()
    wheel_target = wheel_dir / setuptools_wheel.name
    wheel_target.write_bytes(setuptools_wheel.read_bytes())
    result = _docker(
        "run",
        "--rm",
        "-v",
        f"{sources}:/sources",
        "-v",
        f"{dist}:/dist",
        "-v",
        f"{wheel_dir}:/wheels:ro",
        BASE_IMAGE,
        "sh",
        "-c",
        "set -e; python -m pip install -q --no-index /wheels/setuptools-*.whl"
        " && for project in /sources/*; do"
        ' (cd "$project" && python setup.py -q sdist -d /dist);'
        " done",
    )
    assert result.returncode == 0, result.stdout + result.stderr
    setuptools_dir = simple / "setuptools"
    setuptools_dir.mkdir()
    (setuptools_dir / setuptools_wheel.name).write_bytes(setuptools_wheel.read_bytes())
    _index_html(setuptools_dir)
    for name, version in chosen.items():
        filename = f"{name.replace('-', '_')}-{version}.tar.gz"
        artifact = dist / filename
        assert artifact.is_file(), sorted(path.name for path in dist.iterdir())
        folder = simple / name
        folder.mkdir(exist_ok=True)
        (folder / artifact.name).write_bytes(artifact.read_bytes())
        _index_html(folder)
    return simple


def _run_install(
    *,
    image: str,
    context: Path,
    command: str,
    user: str,
    index: Path,
    runtime_user: str,
    import_script: str,
    work: Path,
    extra_mounts: list[tuple[Path, str]] | None = None,
) -> tuple[str, str, list[Path]]:
    work.mkdir(parents=True, exist_ok=True)
    attack = work / "attack"
    attack.mkdir()
    os.chmod(attack, 0o777)
    script_dir = work / "scripts"
    script_dir.mkdir()
    (script_dir / "run_as.py").write_text(
        textwrap.dedent(
            """
            import os
            import sys

            gid, uid, command = sys.argv[1], sys.argv[2], sys.argv[3]
            if uid not in {"0", "root"}:
                os.setgid(int(gid))
                os.setuid(int(uid))
            os.execvp("sh", ["sh", "-c", command])
            """
        ).lstrip()
    )
    (script_dir / "import_child.py").write_text(import_script)
    (script_dir / "run.sh").write_text(
        textwrap.dedent(
            """
            #!/bin/sh
            chmod 777 /attack
            python /scripts/run_as.py "$INSTALL_GID" "$INSTALL_UID" "$PIP_CMD" \\
                > /attack/pip.out 2>&1
            echo $? > /attack/pip.status
            if [ "$(cat /attack/pip.status)" = "0" ]; then
                python /scripts/import_child.py >> /attack/pip.out 2>&1
            fi
            chmod -R a+rwX /attack || true
            """
        ).lstrip()
    )
    uid, gid = user.split(":")
    mounts = [
        "-v",
        f"{index}:/index:ro",
        "-v",
        f"{context}:/app:ro",
        "-v",
        f"{attack}:/attack",
        "-v",
        f"{script_dir}:/scripts:ro",
    ]
    for host, container in extra_mounts or []:
        mounts.extend(["-v", f"{host}:{container}:ro"])
    result = _docker(
        "run",
        "--rm",
        "-e",
        "PIP_INDEX_URL=file:///index/",
        "-e",
        "PIP_DISABLE_PIP_VERSION_CHECK=1",
        "-e",
        f"PIP_CMD={command}",
        "-e",
        f"INSTALL_UID={uid}",
        "-e",
        f"INSTALL_GID={gid}",
        "-e",
        f"RUNTIME_USER={runtime_user}",
        "-w",
        "/app",
        *mounts,
        image,
        "sh",
        "/scripts/run.sh",
    )
    assert result.returncode == 0, result.stdout + result.stderr
    output = (attack / "pip.out").read_text()
    status = (attack / "pip.status").read_text().strip()
    markers = [
        path
        for path in attack.iterdir()
        if path.name.startswith(("install-", "import-"))
    ]
    return status, output, markers


def _assert_substitute_rejected(status: str, output: str, markers: list[Path]) -> None:
    details = "\n".join(
        f"{path.name}: {path.read_text().strip()}" for path in sorted(markers)
    )
    assert not markers, (
        "substituted package code ran before the install was refused:\n" + details
    )
    assert status != "0", output
    assert any(message in output for message in HASH_REFUSALS), output


def _assert_runtime_can_use_the_role(template: dict[str, Any]) -> None:
    project = _resources(template, "AWS::CodeBuild::Project")[0]
    assert project["Properties"]["Environment"]["PrivilegedMode"] is True
    spec = _buildspec(template)
    assert (
        "docker build --platform linux/arm64 -f context/Dockerfile "
        "-t migration-source:local context/"
    ) in spec
    assert "adapter/Dockerfile" in spec
    assert "docker push $REPO_URI:$IMAGE_TAG" in spec
    runtime = _resources(template, "AWS::BedrockAgentCore::Runtime")[0]["Properties"]
    assert "RoleArn" in runtime
    assert "ContainerConfiguration" in runtime["AgentRuntimeArtifact"]
    statements = _statements(template)
    agentcore = next(
        statement
        for statement in statements
        if statement.get("Sid") == "AgentCoreAccess"
    )
    actions = agentcore["Action"]
    assert GATEWAY_ACTION in actions
    for action in MEMORY_ACTIONS:
        assert action in actions
    vault = next(
        statement for statement in statements if statement.get("Sid") == TOKEN_VAULT_SID
    )
    assert vault["Action"] == "secretsmanager:GetSecretValue"
    assert "bedrock-agentcore-identity" in json.dumps(vault["Resource"])


def test_migration_preset_image_rejects_substituted_strands_agents(
    tmp_path: Path, setuptools_wheel: Path
) -> None:
    template = _migration_template()
    _assert_runtime_can_use_the_role(template)
    config = load_platform_config(PRESET)
    env = to_env(config)
    context = (REPO / env["MIGRATION_BUILD_CONTEXT"]).resolve()
    dockerfile_name = env.get("MIGRATION_BUILD_DOCKERFILE", "Dockerfile")
    dockerfile = (context / dockerfile_name).read_text()
    steps = _pip_steps(dockerfile, {})
    assert steps, dockerfile
    user, command = steps[0]
    requirements = _requirements_from_command(command, context)
    assert any(_pep503(name) == "strands-agents" for name, _version in requirements)
    index = _build_index(requirements, tmp_path / "index", setuptools_wheel)
    runtime_user = _final_user(dockerfile, {})
    import_script = textwrap.dedent(
        """
        import os

        import sys

        uid, gid = os.environ["RUNTIME_USER"].split(":")
        os.setgid(int(gid))
        os.setuid(int(uid))
        sys.path.insert(0, "/app")
        import server

        server.get_agent()
        """
    ).lstrip()
    status, output, markers = _run_install(
        image=BASE_IMAGE,
        context=context,
        command=command,
        user=user,
        index=index,
        runtime_user=runtime_user,
        import_script=import_script,
        work=tmp_path / "run",
    )
    _assert_substitute_rejected(status, output, markers)


def test_migration_adapter_rejects_substituted_packages(
    tmp_path: Path, setuptools_wheel: Path
) -> None:
    template = _migration_template()
    spec = _buildspec(template)
    assert (
        'docker build --platform linux/arm64 --build-arg SOURCE_IMAGE="$SOURCE_IMAGE"'
        in spec
    )
    assert "--build-arg CHILD_USER=" in spec
    assert "-f adapter/Dockerfile" in spec
    source_dockerfile = (
        REPO
        / to_env(load_platform_config(PRESET))["MIGRATION_BUILD_CONTEXT"]
        / "Dockerfile"
    ).read_text()
    child_user = _final_user(source_dockerfile, {})
    adapter = (REPO / "migration" / "adapter" / "Dockerfile").read_text()
    steps = _pip_steps(adapter, {"CHILD_USER": child_user.split(":")[0]})
    assert len(steps) == 1, adapter
    user, command = steps[0]
    assert "||" in command
    requirements = _requirements_from_command(command, REPO / "migration" / "adapter")
    names = {_pep503(name) for name, _version in requirements}
    assert names == {"bedrock-agentcore", "boto3"}
    index = _build_index(requirements, tmp_path / "index", setuptools_wheel)
    runtime_user = _final_user(adapter, {"CHILD_USER": child_user})
    import_script = textwrap.dedent(
        """
        import os
        import sys

        uid, gid = os.environ["RUNTIME_USER"].split(":")
        os.setgid(int(gid))
        os.setuid(int(uid))
        sys.path.insert(0, "/adapter")
        import adapter

        try:
            adapter.resolve_secrets(
                {
                    "MIGRATION_SECRETS": "JIRA_TOKEN",
                    "PROJECT_NAME": "agentcore-workshop",
                    "ENVIRONMENT": "dev",
                }
            )
        except Exception:
            pass
        """
    ).lstrip()
    status, output, markers = _run_install(
        image=BASE_IMAGE,
        context=REPO / "migration" / "adapter",
        command=command,
        user=user,
        index=index,
        runtime_user=runtime_user,
        import_script=import_script,
        work=tmp_path / "run",
        extra_mounts=[(REPO / "migration" / "adapter", "/adapter")],
    )
    _assert_substitute_rejected(status, output, markers)
