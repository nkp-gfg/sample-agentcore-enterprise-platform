"""Regression tests for end-to-end HR Part 2 execution paths on v3.

Covers the real-AWS failure points identified in the v3 human-execution audit:
  1. SQL DDL validity (no `GRANT CONNECT ON DATABASE CURRENT_DATABASE()`,
     `decided_by_layer` check constraint allows `policy` and `tool`).
  2. `hr-identity` Pre-Token V3_0 handler:
     - `TokenGeneration_ClientCredentials` reads `clientMetadata.verified_user_id`
       and enriches `accessTokenGeneration` ONLY (no `idTokenGeneration`).
     - Federated `TokenGeneration_HostedAuth` prefers `userAttributes.sub` over
       `EntraID_<oid>` `userName`.
  3. `hr-identity` `trigger_manager` read-modify-write `UpdateUserPool`:
     - Preserves `DeletionProtection`, `AdminCreateUserConfig`, `Policies`, and
       other `LambdaConfig` triggers; upgrades `LITE` -> `ESSENTIALS`; sets `V3_0`.
     - On `Delete`, removes ONLY our `PreTokenGenerationConfig`/`PreTokenGeneration`.
  4. `hr-tools` dispatcher & handlers:
     - `NOT_MAPPED` is audited by dispatcher (`decided_by_layer='tool'`).
     - `get_employee_compensation` never queries `salaries` on deny and logs
       `decided_by_layer='policy'`.
     - `submit_leave_request` returns `employee_id` and `reviewer_employee_id`
       and enforces idempotency (`ALLOW` on same body, `IDEMPOTENCY_CONFLICT` on
       different body).
  5. `god-agent` payload normalisation accepts both CLI `{"prompt",
     "runtimeSessionId", "resume"}` and AG-UI `RunAgentInput`.
"""

from __future__ import annotations

import contextlib
import datetime as _dt
import importlib.util
import json
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

REPO = Path(__file__).resolve().parents[1]


@pytest.fixture(autouse=True)
def _clean_shared_modules():
    yield
    for mod_name in list(sys.modules):
        if mod_name in {
            "shared",
            "dispatcher",
            "get_employee_compensation",
            "submit_leave_request",
            "agent",
            "checkpointer",
            "filesystem",
            "gateway_client",
            "guardrail",
            "leaves",
            "rate_limit",
            "review",
            "ssm_config",
            "subagents",
        } or mod_name.startswith(
            ("shared.", "get_employee_compensation.", "submit_leave_request.")
        ):
            sys.modules.pop(mod_name, None)


def _load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


def test_sql_files_have_valid_dynamic_database_grants_and_no_opa():
    schema_sql = (
        REPO / "use-cases" / "hr-data" / "provisioner" / "schema.sql"
    ).read_text()
    agent_sql = (
        REPO / "use-cases" / "hr-data" / "provisioner" / "agent_state_schema.sql"
    ).read_text()

    for content in (schema_sql, agent_sql):
        assert "DATABASE CURRENT_DATABASE()" not in content.upper()
        assert "current_database()" in content
        assert "opa" not in content.lower()

    assert "CHECK (decided_by_layer IN ('policy', 'tool'))" in schema_sql


def test_hr_identity_v3_client_credentials_and_federated_sub_resolution():
    mod = _load_module(
        "hr_identity_handler_test",
        REPO / "use-cases" / "hr-identity" / "lambda" / "handler.py",
    )

    with patch.object(
        mod,
        "_lookup_employee_id",
        side_effect=lambda sub: {"sub-e1-uuid": "E1"}.get(sub),
    ):
        # 1. M2M client_credentials with aws_client_metadata: accessTokenGeneration ONLY!
        m2m_event = {
            "triggerSource": "TokenGeneration_ClientCredentials",
            "userName": "m2m-client-id",
            "request": {
                "clientMetadata": {
                    "verified_user_id": "sub-e1-uuid",
                    "calling_agent": "leave-balance",
                }
            },
        }
        out = mod.handler(m2m_event, None)
        details = out["response"]["claimsAndScopeOverrideDetails"]
        assert "idTokenGeneration" not in details
        claims = details["accessTokenGeneration"]["claimsToAddOrOverride"]
        assert claims == {
            "employee_id": "E1",
            "user_id": "sub-e1-uuid",
            "role": "employee",
            "agent_id": "leave-balance",
        }

        # 2. Disallowed calling_agent ('admin') -> no agent_id claim added.
        bad_agent_event = {
            "triggerSource": "TokenGeneration_ClientCredentials",
            "request": {
                "clientMetadata": {
                    "verified_user_id": "sub-e1-uuid",
                    "calling_agent": "admin",
                }
            },
        }
        out_bad = mod.handler(bad_agent_event, None)
        bad_claims = out_bad["response"]["claimsAndScopeOverrideDetails"][
            "accessTokenGeneration"
        ]["claimsToAddOrOverride"]
        assert "agent_id" not in bad_claims
        assert bad_claims["employee_id"] == "E1"

        # 3. Federated Entra HostedAuth: userName is EntraID_oid, userAttributes.sub is UUID!
        federated_event = {
            "triggerSource": "TokenGeneration_HostedAuth",
            "userName": "EntraID_00000000-1111-2222-3333-444444444444",
            "request": {
                "userAttributes": {"sub": "sub-e1-uuid", "email": "E1@example.com"},
            },
        }
        out_fed = mod.handler(federated_event, None)
        fed_details = out_fed["response"]["claimsAndScopeOverrideDetails"]
        assert (
            fed_details["accessTokenGeneration"]["claimsToAddOrOverride"]["employee_id"]
            == "E1"
        )
        assert (
            fed_details["idTokenGeneration"]["claimsToAddOrOverride"]["employee_id"]
            == "E1"
        )


def test_trigger_manager_preserves_pool_settings_and_detaches_cleanly():
    mod = _load_module(
        "hr_identity_trigger_mgr_test",
        REPO / "use-cases" / "hr-identity" / "trigger_manager" / "handler.py",
    )

    existing_pool = {
        "Id": "eu-west-1_Pool123",
        "Name": "prod-pool",
        "DeletionProtection": "ACTIVE",
        "UserPoolTier": "LITE",
        "Policies": {"PasswordPolicy": {"MinimumLength": 12}},
        "AdminCreateUserConfig": {
            "AllowAdminCreateUserOnly": True,
            "UnusedAccountValidityDays": 7,
        },
        "LambdaConfig": {
            "PostConfirmation": "arn:aws:lambda:eu-west-1:111111111111:function:keep-me"
        },
    }
    fake_cognito = MagicMock()
    fake_cognito.describe_user_pool.return_value = {"UserPool": existing_pool}

    fn_arn = "arn:aws:lambda:eu-west-1:111111111111:function:hr-pretoken"

    with patch("boto3.client", return_value=fake_cognito):
        mod.on_event(
            {
                "RequestType": "Create",
                "ResourceProperties": {
                    "UserPoolId": "eu-west-1_Pool123",
                    "LambdaArn": fn_arn,
                    "LambdaVersion": "V3_0",
                },
            },
            None,
        )
        call_kwargs = fake_cognito.update_user_pool.call_args.kwargs
        assert call_kwargs["DeletionProtection"] == "ACTIVE"
        assert call_kwargs["AdminCreateUserConfig"] == {
            "AllowAdminCreateUserOnly": True
        }
        assert call_kwargs["UserPoolTier"] == "ESSENTIALS"
        assert call_kwargs["LambdaConfig"] == {
            "PostConfirmation": "arn:aws:lambda:eu-west-1:111111111111:function:keep-me",
            "PreTokenGeneration": fn_arn,
            "PreTokenGenerationConfig": {
                "LambdaArn": fn_arn,
                "LambdaVersion": "V3_0",
            },
        }

        # Simulate Delete when both PostConfirmation and our PreTokenGeneration exist.
        existing_pool["LambdaConfig"] = dict(call_kwargs["LambdaConfig"])
        existing_pool["UserPoolTier"] = "ESSENTIALS"
        fake_cognito.update_user_pool.reset_mock()

        mod.on_event(
            {
                "RequestType": "Delete",
                "ResourceProperties": {
                    "UserPoolId": "eu-west-1_Pool123",
                    "LambdaArn": fn_arn,
                },
            },
            None,
        )
        del_kwargs = fake_cognito.update_user_pool.call_args.kwargs
        assert del_kwargs["DeletionProtection"] == "ACTIVE"
        assert del_kwargs["LambdaConfig"] == {
            "PostConfirmation": "arn:aws:lambda:eu-west-1:111111111111:function:keep-me"
        }


def test_hr_tools_dispatcher_and_handlers_enforce_two_phase_read_and_idempotency(
    monkeypatch,
):
    lambdas_dir = REPO / "use-cases" / "hr-tools" / "lambdas"
    monkeypatch.syspath_prepend(str(lambdas_dir))

    import dispatcher
    import shared
    from shared import ssm_flag

    monkeypatch.setattr(ssm_flag, "is_service_enabled", lambda: True)
    monkeypatch.setattr(
        "get_employee_compensation.handler.is_service_enabled", lambda: True
    )
    monkeypatch.setattr("submit_leave_request.handler.is_service_enabled", lambda: True)

    audit_rows: list[dict] = []

    def fake_log_decision(**kwargs):
        audit_rows.append(kwargs)

    monkeypatch.setattr(shared, "log_decision", fake_log_decision)
    monkeypatch.setattr(dispatcher, "log_decision", fake_log_decision)
    monkeypatch.setattr(
        "get_employee_compensation.handler.log_decision", fake_log_decision
    )
    monkeypatch.setattr("submit_leave_request.handler.log_decision", fake_log_decision)

    # 1. Unmapped caller -> dispatcher catches NotMapped and logs decided_by_layer='tool'.
    ctx = SimpleNamespace(
        client_context=SimpleNamespace(
            custom={
                "bedrockAgentCoreToolName": "hr-payroll___get_employee_compensation"
            }
        )
    )
    unmapped_res = dispatcher.handler({"caller_employee_id": ""}, ctx)
    parsed_unmapped = json.loads(unmapped_res["content"][0]["text"])
    assert parsed_unmapped == {"authorized": False, "reason_code": "NOT_MAPPED"}
    assert audit_rows[-1]["reason_code"] == "NOT_MAPPED"
    assert audit_rows[-1]["decided_by_layer"] == "tool"

    # 2. Denied salary lookup (E1 reading M1) NEVER executes SELECT base_salary!
    executed_sql: list[str] = []

    class _CompCursor:
        def execute(self, sql, params=()):
            executed_sql.append(sql)
            self._sql = sql

        def fetchone(self):
            if "FROM employees" in self._sql:
                return ("active", None, "M1")
            raise AssertionError("salaries table MUST NOT be queried on deny!")

        def __enter__(self):
            return self

        def __exit__(self, *_a):
            pass

    class _CompConn:
        def cursor(self):
            return _CompCursor()

    @contextlib.contextmanager
    def fake_comp_connect(_role):
        yield _CompConn()

    monkeypatch.setattr("get_employee_compensation.handler.connect", fake_comp_connect)
    deny_res = dispatcher.handler(
        {
            "caller_employee_id": "E1",
            "agent_id": "compensation",
            "session_id": "sess-1",
            "employee_id": "M1",
        },
        ctx,
    )
    parsed_deny = json.loads(deny_res["content"][0]["text"])
    assert parsed_deny == {"authorized": False, "reason_code": "NOT_AUTHORIZED"}
    assert not any("base_salary" in s for s in executed_sql)
    assert audit_rows[-1]["decided_by_layer"] == "policy"

    # 3. submit_leave_request returns employee_id + reviewer_employee_id and handles idempotency.
    stored_requests: dict[tuple[str, str], tuple] = {}

    class _SubmitCursor:
        def __init__(self):
            self._next = None

        def execute(self, sql, params=()):
            if "WHERE employee_id = %s AND idempotency_key = %s" in sql:
                self._next = stored_requests.get((params[0], params[1]))
            elif "SELECT probation_end_date, manager_id FROM employees" in sql:
                self._next = (_dt.date(2020, 7, 1), "M1")
            elif "SELECT manager_id FROM employees" in sql:
                self._next = ("M1",)
            elif "SELECT remaining_days FROM leave_balances" in sql:
                self._next = (14.0,)
            elif "SELECT 1 FROM leave_requests" in sql:
                self._next = None
            elif "INSERT INTO leave_requests" in sql:
                req_id, emp_id, ltype, sdate, edate, rsn, ikey = params
                stored_requests[(emp_id, ikey)] = (
                    req_id,
                    ltype,
                    sdate,
                    edate,
                    rsn,
                    "pending",
                )
                self._next = None

        def fetchone(self):
            return self._next

        def __enter__(self):
            return self

        def __exit__(self, *_a):
            pass

    class _SubmitConn:
        def cursor(self):
            return _SubmitCursor()

        def commit(self):
            pass

        def rollback(self):
            pass

    @contextlib.contextmanager
    def fake_submit_connect(_role):
        yield _SubmitConn()

    monkeypatch.setattr("submit_leave_request.handler.connect", fake_submit_connect)
    submit_ctx = SimpleNamespace(
        client_context=SimpleNamespace(
            custom={"bedrockAgentCoreToolName": "hr-ops___submit_leave_request"}
        )
    )
    first_submit = json.loads(
        dispatcher.handler(
            {
                "caller_employee_id": "E1",
                "agent_id": "leave-submit",
                "session_id": "sess-1",
                "leave_type": "annual",
                "start_date": "2026-12-01",
                "end_date": "2026-12-03",
                "reason": "trip",
                "idempotency_key": "idem-1",
            },
            submit_ctx,
        )["content"][0]["text"]
    )
    assert first_submit["authorized"] is True
    assert first_submit["data"]["employee_id"] == "E1"
    assert first_submit["data"]["reviewer_employee_id"] == "M1"
    assert first_submit["data"]["days"] == 3

    # Replay with identical body -> returns same request_id!
    replay_submit = json.loads(
        dispatcher.handler(
            {
                "caller_employee_id": "E1",
                "agent_id": "leave-submit",
                "session_id": "sess-1",
                "leave_type": "annual",
                "start_date": "2026-12-01",
                "end_date": "2026-12-03",
                "reason": "trip",
                "idempotency_key": "idem-1",
            },
            submit_ctx,
        )["content"][0]["text"]
    )
    assert replay_submit["authorized"] is True
    assert replay_submit["data"]["request_id"] == first_submit["data"]["request_id"]

    # Replay with different dates -> IDEMPOTENCY_CONFLICT!
    conflict_submit = json.loads(
        dispatcher.handler(
            {
                "caller_employee_id": "E1",
                "agent_id": "leave-submit",
                "session_id": "sess-1",
                "leave_type": "annual",
                "start_date": "2026-12-01",
                "end_date": "2026-12-05",
                "reason": "trip",
                "idempotency_key": "idem-1",
            },
            submit_ctx,
        )["content"][0]["text"]
    )
    assert conflict_submit == {
        "authorized": False,
        "reason_code": "IDEMPOTENCY_CONFLICT",
    }


def test_god_agent_normalises_both_cli_and_agui_payloads(monkeypatch):
    for mod_name in list(sys.modules):
        if mod_name == "shared" or mod_name.startswith("shared."):
            sys.modules.pop(mod_name, None)

    god_dir = REPO / "agent-code" / "god-agent"
    agent_code_dir = REPO / "agent-code"
    monkeypatch.syspath_prepend(str(agent_code_dir))
    monkeypatch.syspath_prepend(str(god_dir))
    monkeypatch.setenv("PROJECT_NAME", "test")
    monkeypatch.setenv("ENVIRONMENT", "dev")
    monkeypatch.setenv("GUARDRAIL_ID", "gr-1")
    monkeypatch.setenv("AWS_REGION_NAME", "eu-west-1")

    agent_mod = _load_module("god_agent_entry_test", god_dir / "agent.py")

    cli_input, resume_dict, check_pending = agent_mod._normalise_payload_to_agui(
        {
            "prompt": "How many leaves do I have?",
            "runtimeSessionId": "session-" + ("a" * 32),
        }
    )
    assert cli_input.thread_id == "session-" + ("a" * 32)
    assert len(cli_input.messages) == 1
    assert cli_input.messages[0].content == "How many leaves do I have?"
    assert resume_dict is None
    assert check_pending is False

    mgr_input, mgr_resume, _ = agent_mod._normalise_payload_to_agui(
        {
            "threadId": "thread-" + ("b" * 32),
            "runId": "run-1",
            "messages": [],
            "forwardedProps": {
                "resume": [
                    {
                        "decision": "approve",
                        "kind": "manager_review",
                        "request_id": "lr-123",
                    }
                ]
            },
        }
    )
    assert mgr_input.thread_id == "thread-" + ("b" * 32)
    assert mgr_resume == {
        "decision": "approve",
        "kind": "manager_review",
        "request_id": "lr-123",
    }


def test_part2_stacks_use_retain_except_on_create_and_deferred_deletion_protection():
    """Ensure a failed first create rolls back cleanly without wedging ROLLBACK_FAILED
    or leaving orphaned fixed-name LogGroups/DBClusters that block retry."""
    import aws_cdk as cdk
    from aws_cdk.assertions import Template

    ctx = {
        "project": "rbtest",
        "environment": "prod",
        "prefix": "rbtest-prod",
        "ssm_prefix": "/rbtest/prod",
        "region": "eu-west-1",
        "cdk_env": cdk.Environment(account="111111111111", region="eu-west-1"),
    }

    app = cdk.App()
    hr_data_mod = _load_module(
        "hr_data_stack_rb_test", REPO / "use-cases" / "hr-data" / "stack.py"
    )
    hr_id_mod = _load_module(
        "hr_id_stack_rb_test", REPO / "use-cases" / "hr-identity" / "stack.py"
    )
    hr_tools_mod = _load_module(
        "hr_tools_stack_rb_test", REPO / "use-cases" / "hr-tools" / "stack.py"
    )

    hr_data_mod.build(app, ctx, {"retain_data": True, "seed": True})
    hr_id_mod.build(app, ctx, {})
    hr_tools_mod.build(app, ctx, {})

    data_tpl = Template.from_stack(
        app.node.find_child("rbtest-prod-uc-hr-data")
    ).to_json()
    id_tpl = Template.from_stack(
        app.node.find_child("rbtest-prod-uc-hr-identity")
    ).to_json()
    tools_tpl = Template.from_stack(
        app.node.find_child("rbtest-prod-uc-hr-tools")
    ).to_json()

    # 1. CfnDBCluster starts with DeletionProtection=False so first-create rollback
    #    can delete it if WriterInstance/Provision fails; Provision enables it after SQL!
    clusters = [
        r for r in data_tpl["Resources"].values() if r["Type"] == "AWS::RDS::DBCluster"
    ]
    assert len(clusters) == 1
    assert clusters[0]["Properties"]["DeletionProtection"] is False
    assert clusters[0]["DeletionPolicy"] == "RetainExceptOnCreate"

    # 2. All retained fixed-name LogGroups across H1, H3, H4 use RetainExceptOnCreate,
    #    never plain Retain (which strands fixed log-group names on initial rollback).
    for tpl_name, tpl in (
        ("hr-data", data_tpl),
        ("hr-identity", id_tpl),
        ("hr-tools", tools_tpl),
    ):
        for lid, res in tpl["Resources"].items():
            if res["Type"] == "AWS::Logs::LogGroup" and "DeletionPolicy" in res:
                assert res["DeletionPolicy"] == "RetainExceptOnCreate", (
                    f"{tpl_name}:{lid} uses {res['DeletionPolicy']} instead of RetainExceptOnCreate"
                )
