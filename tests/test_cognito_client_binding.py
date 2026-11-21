"""The chat tester must not submit a typed password to an unchecked Cognito client.

scripts/test_agent.py reads auth/app-client-id from SSM and passes it to
authenticate_cognito. That helper describes the client on the published user
pool, ignores a failure, and calls InitiateAuth with USER_PASSWORD_AUTH.
InitiateAuth carries only ClientId (botocore 1.43.72 service model
cognito-idp/2016-04-18 InitiateAuthRequest): the client id selects the pool.
These tests drive the real tester and the real botocore JSON serializer, and
they fail while a password is serialized to a client id that the latest
DescribeUserPoolClient against the published pool did not confirm.
"""

from __future__ import annotations

import base64
import json
import sys
from pathlib import Path

import pytest
from botocore.awsrequest import AWSResponse

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

import test_agent
import utils

PUBLISHED_POOL = "us-east-1_RealPool1"
LEGIT_CLIENT = "legitclientid"
ATTACKER_CLIENT = "attackerclientid"
OPERATOR = "operator"
# Obvious placeholder. The assertion messages never include it.
TYPED_PASSWORD = "placeholder-not-a-secret"
PROJECT = "agentcore-workshop"
ENV = "dev"
PREFIX = f"/{PROJECT}/{ENV}"
APP_CLIENT_PARAM = f"{PREFIX}/auth/app-client-id"
USER_POOL_PARAM = f"{PREFIX}/auth/user-pool-id"
RUNTIME_PARAM = f"{PREFIX}/runtimes/orchestrator/arn"
RUNTIME_ARN = "arn:aws:bedrock-agentcore:us-east-1:111111111111:runtime/placeholder"


def _unsigned_id_token() -> str:
    """JWT-shaped stand-in. authenticate_cognito only base64-decodes the payload."""
    header = (
        base64.b64encode(json.dumps({"alg": "none", "typ": "JWT"}).encode())
        .decode()
        .rstrip("=")
    )
    payload = (
        base64.b64encode(json.dumps({"sub": "operator-sub"}).encode())
        .decode()
        .rstrip("=")
    )
    return f"{header}.{payload}."


class PublishedPool:
    """Published user pool and the SSM values the tester reads.

    DescribeUserPoolClient against PUBLISHED_POOL succeeds only for client ids
    in ``members``. After the first successful describe, membership of that
    client is removed and auth/app-client-id flips to the attacker client, so
    a second resolution sees a different id. InitiateAuth has no UserPoolId;
    a client id that the latest describe did not confirm is another pool's
    client. A USER_PASSWORD_AUTH body for that client is the submission the
    user-migration trigger receives as request.password when the user is not
    in that pool.
    """

    def __init__(self, app_client_id: str, describe_error: str) -> None:
        self.describe_error = describe_error
        self.members = {LEGIT_CLIENT}
        self.parameters = {
            USER_POOL_PARAM: PUBLISHED_POOL,
            APP_CLIENT_PARAM: app_client_id,
            RUNTIME_PARAM: RUNTIME_ARN,
        }
        self.events: list[dict] = []
        self.unbound_client_ids: list[str] = []
        self.initiate_client_ids: list[str] = []
        self._seq = 0

    def _note(self, kind: str, **data: object) -> dict:
        self._seq += 1
        event = {"seq": self._seq, "kind": kind, **data}
        self.events.append(event)
        return event

    def bound_client_id(self) -> str | None:
        describes = [event for event in self.events if event["kind"] == "describe"]
        if not describes:
            return None
        last = describes[-1]
        if not last["ok"]:
            return None
        if last["pool_id"] != PUBLISHED_POOL:
            return None
        if last["returned_client_id"] != last["requested_client_id"]:
            return None
        for event in self.events:
            if event["seq"] <= last["seq"]:
                continue
            if event["kind"] == "ssm" and event["name"] == APP_CLIENT_PARAM:
                return None
        return str(last["returned_client_id"])

    def handle(self, model, params, **kwargs):
        body = json.loads(params["body"].decode())
        operation = model.name
        if operation == "GetParameter":
            name = body["Name"]
            self._note("ssm", name=name)
            if name not in self.parameters:
                return _error("ParameterNotFound", "missing")
            return _ok({"Parameter": {"Value": self.parameters[name]}})
        if operation == "AdminGetUser":
            self._note(
                "admin_get_user",
                pool_id=body["UserPoolId"],
                username=body["Username"],
            )
            if body["UserPoolId"] == PUBLISHED_POOL and body["Username"] == OPERATOR:
                return _ok({"Username": OPERATOR})
            return _error("UserNotFoundException", "missing user")
        if operation == "DescribeUserPoolClient":
            requested = body["ClientId"]
            pool_id = body["UserPoolId"]
            ok = pool_id == PUBLISHED_POOL and requested in self.members
            self._note(
                "describe",
                ok=ok,
                pool_id=pool_id,
                requested_client_id=requested,
                returned_client_id=requested if ok else None,
            )
            if ok:
                # The confirmed client is no longer what a later lookup sees.
                self.members.discard(requested)
                self.parameters[APP_CLIENT_PARAM] = ATTACKER_CLIENT
                return _ok(
                    {
                        "UserPoolClient": {
                            "ClientId": requested,
                            "UserPoolId": pool_id,
                        }
                    }
                )
            return _error(self.describe_error, "client is not in the published pool")
        if operation == "InitiateAuth":
            client_id = body["ClientId"]
            auth_parameters = body.get("AuthParameters") or {}
            self.initiate_client_ids.append(client_id)
            self._note("initiate", client_id=client_id, flow=body.get("AuthFlow"))
            password_submitted = (
                body.get("AuthFlow") == "USER_PASSWORD_AUTH"
                and "PASSWORD" in auth_parameters
            )
            if password_submitted and client_id != self.bound_client_id():
                self.unbound_client_ids.append(client_id)
            if client_id != LEGIT_CLIENT:
                return _error("NotAuthorizedException", "rejected")
            return _ok(
                {
                    "AuthenticationResult": {
                        "AccessToken": "placeholder-access-token",
                        "IdToken": _unsigned_id_token(),
                    }
                }
            )
        return _error("InternalErrorException", f"unexpected {operation}")


def _ok(payload: dict) -> tuple:
    return AWSResponse(None, 200, {}, None), payload


def _error(code: str, message: str) -> tuple:
    parsed = {
        "ResponseMetadata": {"HTTPStatusCode": 400},
        "Error": {"Code": code, "Message": message},
    }
    return AWSResponse(None, 400, {}, None), parsed


def _run_chat_tester(monkeypatch: pytest.MonkeyPatch, pool: PublishedPool) -> None:
    monkeypatch.setenv("AWS_REGION", "us-east-1")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_EC2_METADATA_DISABLED", "true")
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "test_agent.py",
            "--project",
            PROJECT,
            "--env",
            ENV,
            "--component",
            "orchestrator",
        ],
    )
    answers = iter([OPERATOR, "exit"])

    def fake_input(prompt: str = "") -> str:
        try:
            return next(answers)
        except StopIteration:
            raise EOFError

    monkeypatch.setattr("builtins.input", fake_input)
    monkeypatch.setattr(test_agent.getpass, "getpass", lambda prompt="": TYPED_PASSWORD)

    real_client = utils.boto3.client

    def client(service_name: str, *args, **kwargs):
        created = real_client(service_name, *args, **kwargs)
        created.meta.events.register("before-call.*.*", pool.handle)
        return created

    monkeypatch.setattr(utils.boto3, "client", client)
    try:
        test_agent.main()
    except (SystemExit, EOFError):
        return


def _assert_password_stayed_with_confirmed_client(pool: PublishedPool) -> None:
    assert not pool.unbound_client_ids, (
        "InitiateAuth submitted the typed password to a client id that "
        "DescribeUserPoolClient had not confirmed on the published user pool: "
        + ", ".join(pool.unbound_client_ids)
    )


@pytest.mark.parametrize(
    "describe_error",
    ["ResourceNotFoundException", "NotAuthorizedException"],
)
def test_ssm_client_outside_published_pool_is_not_sent_the_password(
    monkeypatch: pytest.MonkeyPatch,
    describe_error: str,
) -> None:
    pool = PublishedPool(ATTACKER_CLIENT, describe_error)
    _run_chat_tester(monkeypatch, pool)
    _assert_password_stayed_with_confirmed_client(pool)
    assert pool.initiate_client_ids == []


def test_confirmed_client_still_signs_in_and_a_later_resolution_cannot_retarget(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Sign-in still uses the client id the published pool confirmed.

    The first successful DescribeUserPoolClient drops that client from the
    pool and replaces auth/app-client-id. InitiateAuth must still be the one
    confirmed client. Resolving the client id again, or describing it again
    and continuing, submits the password to the replacement and fails.
    """
    pool = PublishedPool(LEGIT_CLIENT, "ResourceNotFoundException")
    _run_chat_tester(monkeypatch, pool)
    _assert_password_stayed_with_confirmed_client(pool)
    assert pool.initiate_client_ids == [LEGIT_CLIENT]
