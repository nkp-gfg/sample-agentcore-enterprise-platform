"""Untrusted retired-client checkpoints must not become JWT authorizer clients.

The brokered deploy reads /{project}/{environment}/auth/m2m-retired-client-id and
passes that string to CDK as retired_m2m_client_id. app.py appends it to the
gateway and runtime allow lists. These tests fail while that string is still
accepted when it is not the previous machine client.

Direct mode is not covered: rotate_legacy_m2m_client deletes the checkpoint
instead of publishing it, and the direct branches in app.py do not append it.
A2A runtimes are not covered as invoke targets: needs_jwt_authorizer is false
for A2A, so those templates never install this allow list.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import textwrap
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "agent-code" / "shared"))

from jwt_claims import TokenRejected, validate_claims  # noqa: E402

ISSUER = "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_example"
PREVIOUS_MACHINE_CLIENT = "previous-machine-client"
PUBLIC_WEB_CLIENT = "public-web-client"
OTHER_CLIENT = "attacker-chosen-client"
# Stand-ins for the two clients the brokered template already authorizes
# (app client and current machine client). Both are CloudFormation references,
# not literals, so the claim check has to keep them when it reads a template.
DEPLOYED_CLIENTS = ("deployment-app-client", "deployment-machine-client")

PROJECT = "agentcore-workshop"
ENVIRONMENT = "dev"
PREFIX = f"{PROJECT}-{ENVIRONMENT}"
RETIRED_PARAMETER = f"/{PROJECT}/{ENVIRONMENT}/auth/m2m-retired-client-id"


def _run_rotation(
    tmp_path: Path,
    *,
    checkpoint: str,
    legacy_output: str,
    flip_checkpoint_to: str | None = None,
) -> subprocess.CompletedProcess[str]:
    """Run the real rotate_legacy_m2m_client against a file-backed SSM stub.

    The stub returns the same text the deploy script already documents for
    `aws ssm get-parameters --query Parameters[0].Value --output text`: the
    stored string, or None when the name is absent. After the first read of
    the retired-client parameter, the stub can replace the stored value so a
    later read of that same parameter observes a different client id.
    """
    store = tmp_path / "ssm"
    store.mkdir()
    (store / RETIRED_PARAMETER.replace("/", "_")).write_text(checkpoint)
    script = tmp_path / "run-rotation.sh"
    script.write_text(
        textwrap.dedent(
            f"""\
            #!/usr/bin/env bash
            set -euo pipefail
            REPO={str(REPO)!r}
            STORE={str(store)!r}
            INVOCATIONS={str(tmp_path / "invocations")!r}
            LEGACY_OUTPUT={legacy_output!r}
            FLIP_TO={flip_checkpoint_to or ""!r}
            RETIRED_KEY={RETIRED_PARAMETER.replace("/", "_")!r}
            : > "$INVOCATIONS"

            log_error() {{ printf 'ERROR %s\\n' "$*" >&2; }}
            log_step() {{ printf 'STEP %s\\n' "$*" >&2; }}
            log_info() {{ printf 'INFO %s\\n' "$*" >&2; }}

            aws() {{
                printf 'aws %s\\n' "$*" >> "$INVOCATIONS"
                local op="$1 $2" name="" arg
                while [ "$#" -gt 0 ]; do
                    arg="$1"
                    shift
                    case "$arg" in
                        --name|--names) name="${{1:-}}"; shift ;;
                    esac
                done
                case "$op" in
                    "ssm get-parameter"|"ssm get-parameters")
                        local key="${{name//\\//_}}"
                        if [ ! -f "$STORE/$key" ]; then
                            printf 'None\\n'
                            return 0
                        fi
                        cat "$STORE/$key"
                        printf '\\n'
                        if [ -n "$FLIP_TO" ] && [ "$key" = "$RETIRED_KEY" ]; then
                            printf '%s' "$FLIP_TO" > "$STORE/$key"
                            FLIP_TO=""
                        fi
                        ;;
                    "cloudformation describe-stacks")
                        printf '%s\\n' "$LEGACY_OUTPUT"
                        ;;
                    "cloudformation list-stacks")
                        printf '1\\n'
                        ;;
                    *)
                        ;;
                esac
            }}

            npx() {{
                printf 'npx %s\\n' "$*" >> "$INVOCATIONS"
                if [ "${{1:-}}" = "cdk" ] && [ "${{2:-}}" = "ls" ]; then
                    printf '%s\\n' \\
                        "{PREFIX}-gateway" \\
                        "{PREFIX}-runtime-orchestrator" \\
                        "{PREFIX}-runtime-code-agent" \\
                        "{PREFIX}-runtime-research-agent"
                fi
            }}

            eval "$(sed -n '/^read_optional_rotation_parameter()/,/^}}/p' "$REPO/scripts/deploy.sh")"
            eval "$(sed -n '/^rotate_legacy_m2m_client()/,/^}}/p' "$REPO/scripts/deploy.sh")"

            PROJECT_NAME={PROJECT!r}
            ENVIRONMENT={ENVIRONMENT!r}
            PREFIX={PREFIX!r}
            AWS_REGION=us-east-1
            IDP_MODE=brokered
            DEPLOYMENT_STRATEGY=centralized
            CONTEXT_ARGS=(-c "project=$PROJECT_NAME" -c "environment=$ENVIRONMENT")
            M2M_ROTATION_CONTEXT_ARGS=()

            set +e
            rotate_legacy_m2m_client
            status=$?
            set -e
            if [ "$status" -eq 0 ]; then
                # Both brokered callers forward whatever the helper left behind:
                # the full deploy, then one targeted stack from deploy_stacks.
                npx cdk deploy --all --require-approval never \\
                    "${{CONTEXT_ARGS[@]}}" "${{M2M_ROTATION_CONTEXT_ARGS[@]}}"
                npx cdk deploy "{PREFIX}-gateway" --require-approval never \\
                    "${{CONTEXT_ARGS[@]}}" "${{M2M_ROTATION_CONTEXT_ARGS[@]}}"
            fi
            exit "$status"
            """
        )
    )
    return subprocess.run(
        ["bash", str(script)],
        cwd=REPO,
        text=True,
        capture_output=True,
        check=False,
    )


def _invocations(tmp_path: Path) -> str:
    return (tmp_path / "invocations").read_text()


def _assert_client_never_deployed(
    tmp_path: Path, result: subprocess.CompletedProcess[str], client_id: str
) -> None:
    """The client id must not reach cdk, and no drain parameter is written."""
    invocations = _invocations(tmp_path)
    lines = invocations.splitlines()
    leaked = [line for line in lines if client_id in line and line.startswith("npx ")]
    deploys = [line for line in lines if line.startswith("npx cdk deploy")]
    wrote_parameter = [line for line in lines if line.startswith("aws ssm put-parameter")]
    assert leaked == [], (
        f"{client_id} was passed to cdk before rejection:\\n"
        + "\n".join(leaked)
        + f"\nhelper status {result.returncode}\n{result.stderr}"
    )
    assert deploys == [], (
        "cdk deploy ran before the untrusted checkpoint was rejected:\\n"
        + "\n".join(deploys)
        + f"\n{result.stderr}"
    )
    assert wrote_parameter == [], (
        "rotation wrote an SSM parameter before rejecting the checkpoint:\\n"
        + "\n".join(wrote_parameter)
        + f"\n{result.stderr}"
    )


def test_public_web_client_checkpoint_is_rejected_when_no_legacy_client_remains(
    tmp_path: Path,
) -> None:
    """Steady state: the old machine client is already gone, and someone has
    written the public web client id into the retired-client parameter."""
    result = _run_rotation(
        tmp_path,
        checkpoint=PUBLIC_WEB_CLIENT,
        legacy_output="None",
    )
    _assert_client_never_deployed(tmp_path, result, PUBLIC_WEB_CLIENT)


def test_public_web_client_checkpoint_does_not_override_previous_machine_client(
    tmp_path: Path,
) -> None:
    """The previous machine client is still in the auth stack outputs, and the
    checkpoint names a different client."""
    result = _run_rotation(
        tmp_path,
        checkpoint=PUBLIC_WEB_CLIENT,
        legacy_output=PREVIOUS_MACHINE_CLIENT,
    )
    _assert_client_never_deployed(tmp_path, result, PUBLIC_WEB_CLIENT)


def test_arbitrary_checkpoint_is_rejected(tmp_path: Path) -> None:
    result = _run_rotation(
        tmp_path,
        checkpoint=OTHER_CLIENT,
        legacy_output=PREVIOUS_MACHINE_CLIENT,
    )
    _assert_client_never_deployed(tmp_path, result, OTHER_CLIENT)


def test_retired_client_is_not_reread_between_check_and_deploy(tmp_path: Path) -> None:
    """The first read matches the previous machine client. A later read of the
    same parameter returns the public web client. Only the value that was
    checked may be deployed."""
    result = _run_rotation(
        tmp_path,
        checkpoint=PREVIOUS_MACHINE_CLIENT,
        legacy_output=PREVIOUS_MACHINE_CLIENT,
        flip_checkpoint_to=PUBLIC_WEB_CLIENT,
    )
    invocations = _invocations(tmp_path)
    assert PUBLIC_WEB_CLIENT not in invocations, (
        f"a later read of {RETIRED_PARAMETER} replaced the checked client:\\n"
        f"{invocations}\\n{result.stderr}"
    )
    assert result.returncode == 0, result.stderr
    assert f"retired_m2m_client_id={PREVIOUS_MACHINE_CLIENT}" in invocations


def _synth(tmp_path: Path, context: dict, platform_yaml: str | None = None) -> dict:
    out = tmp_path / "cdk.out"
    out.mkdir()
    env = os.environ.copy()
    env.update(
        {
            "CDK_OUTDIR": str(out),
            "CDK_DEFAULT_ACCOUNT": "111111111111",
            "CDK_DEFAULT_REGION": "us-east-1",
            "CDK_CONTEXT_JSON": json.dumps(context),
        }
    )
    if platform_yaml is None:
        env["PLATFORM_CONFIG"] = str(tmp_path / "missing-platform.yaml")
    else:
        config = tmp_path / "platform.yaml"
        config.write_text(platform_yaml)
        env["PLATFORM_CONFIG"] = str(config)
    completed = subprocess.run(
        [sys.executable, str(REPO / "app.py")],
        cwd=REPO,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    templates = {}
    for path in sorted(out.glob("*.template.json")):
        templates[path.name] = json.loads(path.read_text())
    assert templates, "app.py produced no templates"
    return templates


def _allow_lists_include(templates: dict, client_id: str) -> tuple[str, ...]:
    """Clients the synthesized authorizers and runtime env actually name.

    CloudFormation references count as the deployment's own app and machine
    clients. A literal client id is added only when a template contains it.
    """
    clients = list(DEPLOYED_CLIENTS)
    for template in templates.values():
        if client_id in json.dumps(template):
            clients.append(client_id)
            break
    return tuple(clients)


def _assert_token_rejected(templates: dict, client_id: str) -> None:
    allowed = _allow_lists_include(templates, client_id)
    accepted = []
    for claims in (
        {
            "iss": ISSUER,
            "client_id": client_id,
            "sub": "attacker-user",
            "token_use": "access",
        },
        {
            "iss": ISSUER,
            "aud": client_id,
            "sub": "attacker-user",
            "token_use": "id",
        },
    ):
        try:
            validate_claims(claims, ISSUER, allowed)
        except TokenRejected:
            continue
        accepted.append(claims["token_use"])
    serialized = json.dumps(templates)
    assert accepted == [], (
        f"synthesized allow list {allowed} accepted {accepted} for {client_id}"
    )
    assert client_id not in serialized, (
        f"{client_id} is still present in a synthesized template"
    )


def _workshop_pool(templates: dict) -> tuple[dict, dict, dict]:
    auth = templates[f"{PREFIX}-auth.template.json"]
    user_pool = next(
        resource["Properties"]
        for resource in auth["Resources"].values()
        if resource["Type"] == "AWS::Cognito::UserPool"
    )
    web = next(
        resource["Properties"]
        for resource in auth["Resources"].values()
        if resource["Type"] == "AWS::Cognito::UserPoolClient"
        and resource["Properties"].get("ClientName") == f"{PREFIX}-web-client"
    )
    parameter = next(
        resource["Properties"]
        for resource in auth["Resources"].values()
        if resource["Type"] == "AWS::SSM::Parameter"
        and resource["Properties"].get("Name") == f"/{PROJECT}/{ENVIRONMENT}/auth/web-client-id"
    )
    return user_pool, web, parameter


def test_brokered_deploy_does_not_authorize_retired_public_web_client(tmp_path: Path) -> None:
    templates = _synth(
        tmp_path,
        {
            "retired_m2m_client_id": PUBLIC_WEB_CLIENT,
            "project": PROJECT,
            "environment": ENVIRONMENT,
            "idp_type": "cognito",
            "idp_mode": "brokered",
        },
    )
    user_pool, web, parameter = _workshop_pool(templates)
    assert user_pool["AdminCreateUserConfig"]["AllowAdminCreateUserOnly"] is False
    assert web["GenerateSecret"] is False
    assert "ALLOW_USER_SRP_AUTH" in web["ExplicitAuthFlows"]
    assert web["AllowedOAuthFlows"] == ["code"]
    assert "Policies" not in parameter
    retired_names = [
        resource["Properties"].get("Name", "")
        for resource in templates[f"{PREFIX}-auth.template.json"]["Resources"].values()
        if resource["Type"] == "AWS::SSM::Parameter"
    ]
    assert RETIRED_PARAMETER not in retired_names
    _assert_token_rejected(templates, PUBLIC_WEB_CLIENT)


def test_brokered_deploy_does_not_authorize_arbitrary_retired_client(tmp_path: Path) -> None:
    templates = _synth(
        tmp_path,
        {
            "retired_m2m_client_id": OTHER_CLIENT,
            "project": PROJECT,
            "environment": ENVIRONMENT,
            "idp_mode": "brokered",
        },
    )
    _assert_token_rejected(templates, OTHER_CLIENT)


def test_federated_workload_does_not_authorize_retired_public_web_client(
    tmp_path: Path,
) -> None:
    templates = _synth(
        tmp_path,
        {
            "retired_m2m_client_id": PUBLIC_WEB_CLIENT,
            "project": PROJECT,
            "environment": ENVIRONMENT,
            "idp_mode": "brokered",
        },
        platform_yaml=textwrap.dedent(
            """\
            project: agentcore-workshop
            environment: dev
            region: us-east-1
            deployment:
              strategy: federated
              platform_account: "222222222222"
              workload_accounts: ["111111111111"]
              federation:
                gateway_url: "https://gateway.internal/mcp"
                issuer_url: "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_example"
                m2m_client_id: previous-machine-client
                m2m_client_secret_name: workload/m2m-secret-name
            identity:
              idp: cognito
              mode: brokered
            """
        ),
    )
    assert f"{PREFIX}-gateway.template.json" not in templates
    assert f"{PREFIX}-runtime-orchestrator.template.json" in templates
    _assert_token_rejected(templates, PUBLIC_WEB_CLIENT)
