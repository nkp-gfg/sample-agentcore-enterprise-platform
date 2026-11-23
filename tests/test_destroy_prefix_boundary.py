"""Destroy must not delete a second deployment whose name nests under this prefix.

project ``acme`` / environment ``prod`` has prefix ``acme-prod``. project
``acme-prod`` / environment ``ops`` is a different deployment whose stack
names are ``acme-prod-ops-*``. A full ``destroy --yes`` of the shorter
deployment currently lists every CloudFormation stack and every CodeBuild or
Lambda log group whose name starts with ``acme-prod-``, then deletes those
matches. These tests run ``scripts/deploy.sh destroy`` and require the
shorter deployment's own leftovers to be deleted while the nested deployment
is left in place.

The AWS CLI and CloudWatch Logs are not called. The ``aws`` double on PATH
evaluates the script's ``--query`` with jmespath 1.0.1 (the release inside
the range AWS CLI 2.42.2 declares, ``jmespath>=0.7.1,<1.1.0``) and keeps a
log group only when its name starts with ``--log-group-name-prefix``. That
is the ``DescribeLogGroups`` contract: ``logGroupNamePrefix`` is "The prefix
to match" (aws-cli 2.42.2 ``awscli/botocore/data/logs/2014-03-28/service-2.json``,
shape ``DescribeLogGroupsRequest``). Text output follows aws-cli 2.42.2
``awscli/text.py`` ``_format_scalar_list``: a bare list is joined with tabs.
``jmespath.functions._func_starts_with`` is ``str.startswith``.

Sibling reads that use the same unanchored stack prefix, and are not deleted
by this sweep, are left untested: ``print_summary`` (``scripts/deploy.sh``
around the ``starts_with(StackName,'${PREFIX}')`` query) and
``export_artifacts`` (the same query). ``scripts/check_observability.py``
filters delivery sources with ``startswith(prefix)`` and does not delete.
Secrets Manager and SSM deletes in the sweep use exact ids, not this prefix.
"""

from __future__ import annotations

import json
import os
import shutil
import stat
import subprocess
import textwrap
from pathlib import Path

import pytest

from infra_utils.platform_config import PlatformConfig

REPO = Path(__file__).resolve().parents[1]
DEPLOY = REPO / "scripts" / "deploy.sh"

SHORT = {"project": "acme", "environment": "prod", "region": "us-east-1"}
LONG = {"project": "acme-prod", "environment": "ops", "region": "us-east-1"}
SHORT_PREFIX = "acme-prod"
LONG_PREFIX = "acme-prod-ops"

# Suffixes this repository synthesizes for one project/environment. The
# current acme/prod manifest does not enable networking, security, or A2A;
# those stacks are still this deployment's leftovers when a later destroy
# runs with them turned off.
OWN_STACK_SUFFIXES = (
    "auth",
    "identity",
    "gateway",
    "memory",
    "observability",
    "runtime-orchestrator",
    "runtime-code-agent",
    "runtime-research-agent",
    "networking",
    "security",
)

# Log groups this deployment's CodeBuild projects and Lambda functions use.
# CodeBuild's sample build event names the group ``/aws/codebuild/<project>``
# (CodeBuild user guide, "Build notifications input format reference").
# Lambda groups follow the explicit name in networking_stack.py and the
# function names in runtime_stack.py and gateway_stack.py.
OWN_LOG_GROUPS = (
    "/aws/codebuild/acme-prod-build-orchestrator",
    "/aws/lambda/acme-prod-build-trigger-orchestrator",
    "/aws/lambda/acme-prod-egress-interceptor",
    "/aws/lambda/acme-prod-migration-network-probe",
)
FOREIGN_LOG_GROUPS = tuple(
    name.replace("/acme-prod-", "/acme-prod-ops-", 1) for name in OWN_LOG_GROUPS
)
NEAR_MISS_LOG_GROUPS = (
    "/aws/codebuild/acme-production-build-orchestrator",
    "/aws/lambda/acme-production-egress-interceptor",
)


AWS_DOUBLE = r'''
#!/usr/bin/env python3
"""Stand-in for AWS CLI 2.42.2 query and prefix listing. See the test module."""
import json
import os
import sys

import jmespath

def flag(name):
    if name not in sys.argv:
        return None
    return sys.argv[sys.argv.index(name) + 1]

def flags(name):
    if name not in sys.argv:
        return []
    values = []
    for token in sys.argv[sys.argv.index(name) + 1 :]:
        if token.startswith("--"):
            break
        values.append(token)
    return values

def text_list(values):
    # awscli/text.py _format_scalar_list for a bare list of scalars.
    if not values:
        return
    sys.stdout.write("\t".join(str(item) for item in values))
    sys.stdout.write("\n")

def log():
    with open(os.environ["AWS_STUB_LOG"], "a", encoding="utf-8") as handle:
        handle.write(json.dumps(sys.argv[1:]) + "\n")

def load_state():
    path = os.environ["AWS_STUB_STATE"]
    if not os.path.exists(path):
        return {}
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)

def save_state(data):
    with open(os.environ["AWS_STUB_STATE"], "w", encoding="utf-8") as handle:
        json.dump(data, handle)

log()
argv = sys.argv[1:]
if argv[:1] == ["--version"]:
    print("aws-cli/2.42.2 Python/3.12.3 Linux/6.12 exe/x86_64")
    raise SystemExit(0)

service, operation = (argv + ["", ""])[:2]
if (service, operation) == ("sts", "get-caller-identity"):
    query = flag("--query")
    if query == "Account":
        print("111111111111")
    elif query == "Arn":
        print("arn:aws:iam::111111111111:user/destroy-boundary-test")
    else:
        print('{"Account":"111111111111"}')
    raise SystemExit(0)

if (service, operation) == ("ssm", "get-parameters"):
    value = load_state().get(flag("--names"))
    if flag("--query") == "Parameters[0].Value":
        print("None" if value is None else value)
    raise SystemExit(0)

if (service, operation) == ("ssm", "put-parameter"):
    state = load_state()
    state[flag("--name")] = flag("--value")
    save_state(state)
    raise SystemExit(0)

if (service, operation) in {
    ("ssm", "delete-parameter"),
    ("ssm", "delete-parameters"),
    ("ssm", "get-parameters-by-path"),
}:
    if operation == "get-parameters-by-path":
        print("[]")
    raise SystemExit(0)

if (service, operation) == ("secretsmanager", "describe-secret"):
    raise SystemExit(254)

if (service, operation) == ("secretsmanager", "get-secret-value"):
    # The script asks only for length(SecretString). Print that count, never a secret.
    if flag("--query") == "length(SecretString)":
        print("4")
    raise SystemExit(0)

if (service, operation) == ("cloudformation", "delete-stack"):
    raise SystemExit(0)
if (service, operation) == ("logs", "delete-log-group"):
    raise SystemExit(0)

catalog = json.load(open(os.environ["AWS_STUB_CATALOG"], encoding="utf-8"))

if (service, operation) == ("cloudformation", "list-stacks"):
    allowed = set(flags("--stack-status-filter"))
    summaries = []
    for stack in catalog["stacks"]:
        if allowed and stack["status"] not in allowed:
            continue
        summaries.append(
            {"StackName": stack["name"], "StackStatus": stack["status"]}
        )
    found = jmespath.search(flag("--query"), {"StackSummaries": summaries})
    if isinstance(found, list):
        text_list(found)
    elif found not in (None, ""):
        print(found)
    raise SystemExit(0)

if (service, operation) == ("logs", "describe-log-groups"):
    prefix = flag("--log-group-name-prefix") or ""
    # DescribeLogGroups documents logGroupNamePrefix as the prefix to match
    # and returns names ASCII-sorted.
    matched = sorted(name for name in catalog["log_groups"] if name.startswith(prefix))
    found = jmespath.search(
        flag("--query"),
        {"logGroups": [{"logGroupName": name} for name in matched]},
    )
    if isinstance(found, list):
        text_list(found)
    elif found not in (None, ""):
        print(found)
    raise SystemExit(0)

if (service, operation) == ("cloudformation", "describe-stacks"):
    print("[]")
    raise SystemExit(0)

sys.stderr.write("unhandled aws argv: %s\n" % " ".join(argv))
raise SystemExit(0)
'''


NPX_DOUBLE = """#!/bin/sh
printf '%s\\n' "$*" >> "$NPX_STUB_LOG"
echo "aws-cdk 2.200.0"
exit 0
"""

PYTHON_DOUBLE = r"""#!/bin/sh
if [ "$1" = "--version" ]; then
  echo "Python 3.13.0"
  exit 0
fi
if [ "$1" = "-m" ] && [ "$2" = "venv" ]; then
  mkdir -p "$3/bin"
  printf '%s\n' '#!/bin/sh' 'exit 0' > "$3/bin/pip"
  chmod +x "$3/bin/pip"
  printf '%s\n' 'pip() { return 0; }' > "$3/bin/activate"
  exit 0
fi
exec python3 "$@"
"""


def _write_executable(path: Path, contents: str) -> None:
    path.write_text(contents)
    path.chmod(path.stat().st_mode | stat.S_IEXEC)


def _own_stack_names() -> set[str]:
    return {f"{SHORT_PREFIX}-{suffix}" for suffix in OWN_STACK_SUFFIXES}


def _foreign_stack_names() -> set[str]:
    config = PlatformConfig.model_validate(LONG)
    return set(config.expected_stacks())


def _catalog() -> dict:
    foreign = _foreign_stack_names()
    stacks = [
        {"name": name, "status": "CREATE_COMPLETE"} for name in sorted(_own_stack_names())
    ]
    stacks.extend(
        {"name": name, "status": "CREATE_COMPLETE"} for name in sorted(foreign)
    )
    stacks.append({"name": "acme-production-auth", "status": "CREATE_COMPLETE"})
    stacks.append({"name": "othercorp-prod-auth", "status": "CREATE_COMPLETE"})
    stacks.append(
        {"name": f"{LONG_PREFIX}-security", "status": "DELETE_COMPLETE"}
    )
    return {
        "stacks": stacks,
        "log_groups": list(OWN_LOG_GROUPS + FOREIGN_LOG_GROUPS + NEAR_MISS_LOG_GROUPS),
    }


def _calls(log_path: Path) -> list[list[str]]:
    if not log_path.is_file():
        return []
    return [json.loads(line) for line in log_path.read_text().splitlines() if line]


def _deleted(calls: list[list[str]], service: str, operation: str, flag_name: str) -> set[str]:
    found = set()
    for argv in calls:
        if argv[:2] != [service, operation]:
            continue
        if flag_name in argv:
            found.add(argv[argv.index(flag_name) + 1])
    return found


@pytest.fixture(autouse=True)
def _remove_stub_venv():
    yield
    activate = REPO / ".venv" / "bin" / "activate"
    if activate.is_file() and "pip() { return 0; }" in activate.read_text():
        shutil.rmtree(REPO / ".venv")


def _workshop_manifest() -> str:
    return "project: acme\nenvironment: prod\nregion: us-east-1\n"


def _production_manifest() -> str:
    """A validated production manifest for the same acme/prod prefix.

    platform_account matches the account the aws double reports so the
    script's account pin is satisfied. client_secret_name is a name, not a secret.
    """
    return textwrap.dedent(
        """\
        project: acme
        environment: prod
        region: us-east-1
        deployment:
          mode: production
          platform_account: "111111111111"
        identity:
          idp: entra_id
          tenant_id: 3f2b1c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5d
          client_id: 9a8b7c6d-1234-4abc-9def-000111222333
          client_secret_name: agentcore/idp-client-secret
        agents:
          pattern: strands-agent
          model_id: us.anthropic.claude-sonnet-4-6
          allowed_models:
            - us.anthropic.claude-sonnet-4-6
        gateway:
          web_search: "off"
        security:
          networking: true
          cloudtrail_alerting: true
          resource_policies: true
          egress_filter: true
          require_guardrails: true
          cedar:
            enabled: true
            mode: ENFORCE
          traceability: true
          org_id: o-abc123def456
        observability:
          transaction_search: true
          alarms: true
          alarm_email: ops@corp.internal
          log_retention_days: 90
        """
    )


def _run_deploy(
    tmp_path: Path,
    args: list[str],
    env_extra: dict[str, str] | None = None,
    stdin: str = "",
    manifest: str | None = None,
) -> subprocess.CompletedProcess[str]:
    work = tmp_path
    bindir = work / "bin"
    bindir.mkdir()
    _write_executable(bindir / "aws", textwrap.dedent(AWS_DOUBLE).lstrip("\n"))
    _write_executable(bindir / "npx", NPX_DOUBLE)
    _write_executable(bindir / "python3.13", PYTHON_DOUBLE)
    _write_executable(bindir / "npm", "#!/bin/sh\necho 10.0.0\nexit 0\n")
    catalog = work / "catalog.json"
    catalog.write_text(json.dumps(_catalog()))
    manifest_path = work / "platform.yaml"
    manifest_path.write_text(manifest if manifest is not None else _workshop_manifest())
    env = os.environ.copy()
    env.pop("DEPLOYMENT_MODE", None)
    env.pop("PROJECT_NAME", None)
    env.pop("ENVIRONMENT", None)
    env["PATH"] = f"{bindir}{os.pathsep}{env.get('PATH', '')}"
    env["PLATFORM_CONFIG"] = str(manifest_path)
    env["AWS_STUB_CATALOG"] = str(catalog)
    env["AWS_STUB_STATE"] = str(work / "ssm.json")
    env["AWS_STUB_LOG"] = str(work / "aws.log")
    env["NPX_STUB_LOG"] = str(work / "npx.log")
    env["AWS_PAGER"] = ""
    if env_extra:
        env.update(env_extra)
    return subprocess.run(
        ["bash", str(DEPLOY), *args],
        cwd=REPO,
        env=env,
        input=stdin,
        text=True,
        capture_output=True,
        timeout=60,
        check=False,
    )


def _aws_log(tmp_path: Path) -> list[list[str]]:
    return _calls(tmp_path / "aws.log")


def test_platform_accepts_nested_deployment_names():
    """Both names are valid configs, and the longer stack names sit under the shorter prefix."""
    short = PlatformConfig.model_validate(SHORT)
    long = PlatformConfig.model_validate(LONG)
    short_names = set(short.expected_stacks())
    long_names = set(long.expected_stacks())
    assert short_names
    assert long_names
    assert short_names.isdisjoint(long_names)
    assert all(name.startswith(f"{SHORT_PREFIX}-") for name in short_names)
    assert all(name.startswith(f"{LONG_PREFIX}-") for name in long_names)
    assert all(name.startswith(f"{SHORT_PREFIX}-") for name in long_names)
    assert f"{SHORT_PREFIX}-auth" in short_names
    assert f"{LONG_PREFIX}-auth" in long_names
    assert f"{LONG_PREFIX}-gateway" in long_names
    assert f"{LONG_PREFIX}-runtime-orchestrator" in long_names


def _assert_boundary(tmp_path: Path, *, delete_logs: bool) -> None:
    calls = _aws_log(tmp_path)
    deleted_stacks = _deleted(calls, "cloudformation", "delete-stack", "--stack-name")
    deleted_logs = _deleted(calls, "logs", "delete-log-group", "--log-group-name")
    foreign = _foreign_stack_names()
    assert deleted_stacks == _own_stack_names(), (
        "full destroy deleted a different stack set than this deployment's "
        f"own suffixes.\n deleted={sorted(deleted_stacks)}\n"
        f"foreign still present={sorted(foreign & deleted_stacks)}"
    )
    assert deleted_stacks.isdisjoint(foreign)
    assert "acme-production-auth" not in deleted_stacks
    assert "othercorp-prod-auth" not in deleted_stacks
    assert f"{LONG_PREFIX}-security" not in deleted_stacks
    if delete_logs:
        assert deleted_logs == set(OWN_LOG_GROUPS), sorted(deleted_logs)
    else:
        assert deleted_logs == set()
    assert deleted_logs.isdisjoint(FOREIGN_LOG_GROUPS)
    assert deleted_logs.isdisjoint(NEAR_MISS_LOG_GROUPS)
    secret_deletes = [
        argv
        for argv in calls
        if argv[:2] == ["secretsmanager", "delete-secret"]
        and any(LONG_PREFIX in token for token in argv)
    ]
    assert secret_deletes == []


def test_destroy_yes_deletes_only_this_deployment(tmp_path: Path):
    """``destroy --yes`` skips the footprint prompt and confirms the sweep."""
    result = _run_deploy(tmp_path, ["destroy", "--yes"])
    assert result.returncode == 0, (
        f"deploy.sh exited {result.returncode}\n{result.stdout}\n{result.stderr}"
    )
    _assert_boundary(tmp_path, delete_logs=True)


def test_destroy_prompt_yes_deletes_only_this_deployment(tmp_path: Path):
    """Answering y to the footprint prompt and both sweep prompts is the same confirmation."""
    result = _run_deploy(tmp_path, ["destroy"], stdin="y\ny\ny\n")
    assert result.returncode == 0, (
        f"deploy.sh exited {result.returncode}\n{result.stdout}\n{result.stderr}"
    )
    _assert_boundary(tmp_path, delete_logs=True)


def test_production_destroy_yes_keeps_logs_and_other_deployment(tmp_path: Path):
    """Production mode skips log deletion and still must not cross the prefix boundary."""
    result = _run_deploy(
        tmp_path,
        ["destroy", "--yes"],
        manifest=_production_manifest(),
    )
    assert result.returncode == 0, (
        f"deploy.sh exited {result.returncode}\n{result.stdout}\n{result.stderr}"
    )
    _assert_boundary(tmp_path, delete_logs=False)


def test_noninteractive_without_yes_does_not_sweep(tmp_path: Path):
    """NON_INTERACTIVE without --yes may destroy synthesized stacks and must not sweep."""
    result = _run_deploy(
        tmp_path,
        ["destroy"],
        env_extra={"NON_INTERACTIVE": "1"},
    )
    assert result.returncode == 0, (
        f"deploy.sh exited {result.returncode}\n{result.stdout}\n{result.stderr}"
    )
    calls = _aws_log(tmp_path)
    assert _deleted(calls, "cloudformation", "delete-stack", "--stack-name") == set()
    assert _deleted(calls, "logs", "delete-log-group", "--log-group-name") == set()


def test_explicit_stack_destroy_rejects_nested_deployment_name(tmp_path: Path):
    """``--stack`` is the authorization check for a named destroy. A nested name is not this deployment."""
    foreign = f"{LONG_PREFIX}-auth"
    result = _run_deploy(tmp_path, ["destroy", "--stack", foreign, "--yes"])
    npx_log = (tmp_path / "npx.log").read_text() if (tmp_path / "npx.log").is_file() else ""
    calls = _aws_log(tmp_path)
    assert result.returncode != 0, (
        "nested stack name was accepted as belonging to the shorter deployment\n"
        f"{result.stdout}\n{npx_log}"
    )
    assert foreign not in npx_log
    assert "destroy" not in npx_log
    assert foreign not in _deleted(calls, "cloudformation", "delete-stack", "--stack-name")


def test_explicit_stack_destroy_still_allows_this_deployment(tmp_path: Path):
    own = f"{SHORT_PREFIX}-auth"
    result = _run_deploy(tmp_path, ["destroy", "--stack", own, "--yes"])
    assert result.returncode == 0, (
        f"deploy.sh exited {result.returncode}\n{result.stdout}\n{result.stderr}"
    )
    npx_log = (tmp_path / "npx.log").read_text()
    assert own in npx_log
    assert "destroy" in npx_log
    calls = _aws_log(tmp_path)
    assert _deleted(calls, "cloudformation", "delete-stack", "--stack-name") == set()
    assert f"{LONG_PREFIX}-auth" not in npx_log
