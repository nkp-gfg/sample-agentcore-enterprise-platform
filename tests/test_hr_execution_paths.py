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
import os
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

REPO = Path(__file__).resolve().parents[1]

_GOD_AGENT_RUNTIME_DEPS = (
    "ag_ui",
    "bedrock_agentcore",
    "copilotkit",
    "deepagents",
    "jwt",
    "langchain_aws",
    "langchain_core",
    "langchain_mcp_adapters",
    "langgraph",
    "mcp",
    "psycopg",
)


def _require_runtime_deps(*modules: str) -> None:
    if os.environ.get("GOD_AGENT_REQUIRE_RUNTIME_TESTS") == "1":
        return
    missing: list[str] = []
    for mod in modules:
        top = mod.split(".", 1)[0]
        existing = sys.modules.get(top)
        if existing is not None and getattr(existing, "__spec__", None) is None:
            missing.append(mod)
            continue
        try:
            if (
                importlib.util.find_spec(top) is None
                or importlib.util.find_spec(mod) is None
            ):
                missing.append(mod)
        except (ImportError, ValueError):
            missing.append(mod)
    if missing:
        pytest.skip(
            "god-agent container dependencies not installed in host venv "
            f"({', '.join(missing)}); install agent-code/god-agent/requirements.txt "
            "or set GOD_AGENT_REQUIRE_RUNTIME_TESTS=1"
        )


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
            "god_agent_entry_test",
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
        # On Aurora PostgreSQL 16+/17+, rds_superuser (hr_master) gets ADMIN
        # OPTION with SET FALSE on newly created roles, so ALTER DEFAULT
        # PRIVILEGES FOR ROLE <other_role> fails with SQLState 42501.
        assert "ALTER DEFAULT PRIVILEGES FOR ROLE" not in content.upper()

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
        # 1. M2M client_credentials with aws_client_metadata and real Cognito V3_0
        #    explicit null `"claimsAndScopeOverrideDetails": None`: accessTokenGeneration ONLY!
        m2m_event = {
            "triggerSource": "TokenGeneration_ClientCredentials",
            "userName": "m2m-client-id",
            "request": {
                "clientMetadata": {
                    "verified_user_id": "sub-e1-uuid",
                    "calling_agent": "leave-balance",
                }
            },
            "response": {"claimsAndScopeOverrideDetails": None},
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
    _require_runtime_deps(*_GOD_AGENT_RUNTIME_DEPS)
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


def test_god_agent_normalises_resume_status_and_snake_case_interrupt_id(monkeypatch):
    _require_runtime_deps(*_GOD_AGENT_RUNTIME_DEPS)
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

    # 1. hr-web EmployeeConfirmForm sends resume=[{interruptId, payload}] without `status`.
    confirm_input, confirm_resume, _ = agent_mod._normalise_payload_to_agui(
        {
            "threadId": "thread-" + ("c" * 32),
            "runId": "run-confirm-1",
            "messages": [],
            "resume": [
                {
                    "interruptId": "int-1",
                    "payload": {
                        "decision": "approve",
                        "kind": "employee_confirm",
                    },
                }
            ],
        }
    )
    assert confirm_input.resume is not None
    assert len(confirm_input.resume) == 1
    assert confirm_input.resume[0].interrupt_id == "int-1"
    assert confirm_input.resume[0].status == "resolved"
    assert confirm_resume == {"decision": "approve", "kind": "employee_confirm"}

    # 2. snake_case `interrupt_id` without `interruptId` is normalized cleanly.
    snake_input, snake_resume, _ = agent_mod._normalise_payload_to_agui(
        {
            "threadId": "thread-" + ("d" * 32),
            "runId": "run-confirm-2",
            "messages": [],
            "resume": [
                {
                    "interrupt_id": "int-snake",
                    "payload": {
                        "decision": "edit",
                        "kind": "employee_confirm",
                        "arguments": {"leave_type": "annual"},
                    },
                }
            ],
        }
    )
    assert snake_input.resume is not None
    assert snake_input.resume[0].interrupt_id == "int-snake"
    assert snake_input.resume[0].status == "resolved"
    assert snake_resume == {
        "decision": "edit",
        "kind": "employee_confirm",
        "arguments": {"leave_type": "annual"},
    }

    # 3. Explicit `status: "cancelled"` is preserved.
    cancel_input, cancel_resume, _ = agent_mod._normalise_payload_to_agui(
        {
            "threadId": "thread-" + ("e" * 32),
            "runId": "run-cancel-1",
            "messages": [],
            "resume": [{"interruptId": "int-2", "status": "cancelled"}],
        }
    )
    assert cancel_input.resume is not None
    assert cancel_input.resume[0].interrupt_id == "int-2"
    assert cancel_input.resume[0].status == "cancelled"
    assert cancel_resume is not None and cancel_resume.get("kind") != "manager_review"

    # 4. CLI prompt mode with resume still populates forwardedProps.command.resume.
    cli_res_input, cli_res_dict, _ = agent_mod._normalise_payload_to_agui(
        {
            "prompt": "",
            "runtimeSessionId": "session-" + ("f" * 32),
            "resume": [{"decision": "approve", "kind": "employee_confirm"}],
        }
    )
    assert cli_res_dict == {"decision": "approve", "kind": "employee_confirm"}
    assert cli_res_input.forwarded_props["command"] == {
        "resume": {"decision": "approve", "kind": "employee_confirm"}
    }


def test_god_agent_sets_subagent_attribution_flags_in_source():
    import ast

    source = (REPO / "agent-code" / "god-agent" / "agent.py").read_text()
    tree = ast.parse(source)

    attr_values: dict[str, object] = {}
    ctor_kwargs: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if (
                    isinstance(target, ast.Attribute)
                    and isinstance(target.value, ast.Name)
                    and target.value.id == "agui"
                    and isinstance(node.value, ast.Constant)
                ):
                    attr_values[target.attr] = node.value.value
        elif (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "LangGraphAGUIAgent"
        ):
            ctor_kwargs.update(kw.arg for kw in node.keywords if kw.arg)

    assert attr_values.get("emit_interrupt_outcome") is True
    assert attr_values.get("emit_raw_events") is False
    assert attr_values.get("subagent_visibility") == "attributed"
    assert attr_values.get("emit_subagent_events") is True
    assert "subagent_visibility" not in ctor_kwargs
    assert "emit_subagent_events" not in ctor_kwargs


def test_god_agent_invocations_deduplicates_streamed_tool_results(monkeypatch):
    import asyncio

    _require_runtime_deps(*_GOD_AGENT_RUNTIME_DEPS)
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
    gateway_mod = sys.modules["gateway_client"]

    from ag_ui.core import (
        EventType,
        RunFinishedEvent,
        RunStartedEvent,
        ToolCallEndEvent,
        ToolCallResultEvent,
        ToolCallStartEvent,
    )

    created_agents: list[object] = []

    class _FakeAGUI:
        def __init__(self, *, name, description, graph, config):
            self.name = name
            self.description = description
            self.graph = graph
            self.config = config
            self.emit_interrupt_outcome = False
            self.emit_raw_events = True
            self.subagent_visibility = "inline"
            self.emit_subagent_events = False
            created_agents.append(self)

        async def run(self, input_data):
            yield RunStartedEvent(
                type=EventType.RUN_STARTED,
                thread_id=input_data.thread_id,
                run_id=input_data.run_id,
            )
            yield ToolCallStartEvent(
                type=EventType.TOOL_CALL_START,
                tool_call_id="tc-1",
                tool_call_name="hr-ops___get_leave_balance",
            )
            yield ToolCallEndEvent(
                type=EventType.TOOL_CALL_END,
                tool_call_id="tc-1",
            )
            yield ToolCallResultEvent(
                type=EventType.TOOL_CALL_RESULT,
                message_id="tm-1",
                tool_call_id="tc-1",
                content=json.dumps(
                    {
                        "authorized": True,
                        "reason_code": "ALLOW",
                        "data": {"annual": 12, "sick": 5},
                    }
                ),
                role="tool",
            )
            # Simulate gateway_client recording both the already-streamed tool
            # and a hypothetical tool that bypassed agui.run().
            gateway_mod.record_turn_tool_event(
                "hr-ops___get_leave_balance",
                {"authorized": True, "reason_code": "ALLOW", "data": {"annual": 12}},
            )
            gateway_mod.record_turn_tool_event(
                "hr-finance___get_allowance",
                {"authorized": True, "reason_code": "ALLOW", "data": {"amount": 50}},
            )
            yield RunFinishedEvent(
                type=EventType.RUN_FINISHED,
                thread_id=input_data.thread_id,
                run_id=input_data.run_id,
            )

    @contextlib.asynccontextmanager
    async def _fake_checkpointer():
        yield object()

    class _FakeGraph:
        def with_config(self, **_kwargs):
            return self

    async def _fake_build_god_graph(*, checkpointer):
        return _FakeGraph()

    async def _fake_claim(_thread_id, _user_id):
        return True

    monkeypatch.setattr(agent_mod, "extract_user_id_from_context", lambda _ctx: "sub-1")
    monkeypatch.setattr(agent_mod, "hr_tools_enabled", lambda: True)
    monkeypatch.setattr(agent_mod, "claim_or_verify_thread_owner", _fake_claim)
    monkeypatch.setattr(agent_mod, "async_open_checkpointer", _fake_checkpointer)
    monkeypatch.setattr(agent_mod, "build_god_graph", _fake_build_god_graph)
    monkeypatch.setattr(agent_mod, "LangGraphAGUIAgent", _FakeAGUI)
    monkeypatch.setattr(
        agent_mod,
        "default_limiter",
        lambda: SimpleNamespace(
            check_and_record=lambda _u: SimpleNamespace(allowed=True, turns_in_window=1)
        ),
    )

    async def _collect():
        events = []
        async for ev in agent_mod.invocations(
            {
                "threadId": "thread-" + ("g" * 32),
                "runId": "run-1",
                "messages": [{"id": "m1", "role": "user", "content": "leave balance"}],
            },
            SimpleNamespace(),
        ):
            events.append(ev)
        return events

    events = asyncio.run(_collect())
    assert len(created_agents) == 1
    assert created_agents[0].subagent_visibility == "attributed"
    assert created_agents[0].emit_subagent_events is True

    start_names = [
        ev["toolCallName"] for ev in events if ev.get("type") == "TOOL_CALL_START"
    ]
    assert start_names.count("hr-ops___get_leave_balance") == 1
    assert start_names.count("hr-finance___get_allowance") == 1
    result_events = [ev for ev in events if ev.get("type") == "TOOL_CALL_RESULT"]
    assert len(result_events) == 2


def test_gateway_client_leave_submit_handles_agui_cancelled(monkeypatch):
    import asyncio

    _require_runtime_deps(
        "bedrock_agentcore",
        "jwt",
        "langchain_core",
        "langchain_mcp_adapters",
        "langgraph",
        "mcp",
    )
    for mod_name in list(sys.modules):
        if mod_name == "shared" or mod_name.startswith("shared."):
            sys.modules.pop(mod_name, None)

    god_dir = REPO / "agent-code" / "god-agent"
    agent_code_dir = REPO / "agent-code"
    monkeypatch.syspath_prepend(str(agent_code_dir))
    monkeypatch.syspath_prepend(str(god_dir))

    gw = _load_module("gateway_client", god_dir / "gateway_client.py")
    tool = gw.build_local_leaf_tool("leave-submit")

    async def _unexpected_gateway(*_args, **_kwargs):
        raise AssertionError("call_gateway_tool must not run on cancelled interrupt")

    monkeypatch.setattr(gw, "call_gateway_tool", _unexpected_gateway)
    monkeypatch.setattr(
        gw,
        "interrupt",
        lambda _payload: {"__agui_cancelled__": True, "interrupt_id": "int-1"},
    )

    res = asyncio.run(
        tool.coroutine(
            leave_type="annual",
            start_date="2026-12-01",
            end_date="2026-12-02",
            reason="trip",
        )
    )
    assert res == {"authorized": False, "reason_code": "CANCELLED_BY_EMPLOYEE"}


def test_login_chat_reply_text_prefers_root_over_subagent_deltas():
    mod = _load_module("login_chat_test", REPO / "scripts" / "login_chat.py")
    try:
        sse = "\n".join(
            [
                "data: "
                + json.dumps(
                    {
                        "type": "TEXT_MESSAGE_CONTENT",
                        "messageId": "m-leaf",
                        "delta": "Your balance is 12 annual days.",
                        "subagentRunId": "tools:leaf-1",
                    }
                ),
                "data: "
                + json.dumps(
                    {
                        "type": "TEXT_MESSAGE_CONTENT",
                        "messageId": "m-dept",
                        "delta": "Your balance is 12 annual days.",
                        "subagentRunId": "tools:dept-1",
                    }
                ),
                "data: "
                + json.dumps(
                    {
                        "type": "TEXT_MESSAGE_CONTENT",
                        "messageId": "m-root",
                        "delta": "You have 12 annual days remaining.",
                    }
                ),
                "data: " + json.dumps({"type": "RUN_FINISHED"}),
            ]
        )
        assert mod._reply_text(sse) == "You have 12 annual days remaining."

        subagent_only_sse = "\n".join(
            [
                "data: "
                + json.dumps(
                    {
                        "type": "TEXT_MESSAGE_CONTENT",
                        "messageId": "m-leaf",
                        "delta": "Subagent fallback text.",
                        "subagentRunId": "tools:leaf-1",
                    }
                ),
                "data: " + json.dumps({"type": "RUN_FINISHED"}),
            ]
        )
        assert mod._reply_text(subagent_only_sse) == "Subagent fallback text."
    finally:
        sys.modules.pop("login_chat_test", None)


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

    # 3. Every AWS::BedrockAgentCore::GatewayTarget InlinePayload SchemaDefinition
    #    uses ONLY CloudFormation SchemaDefinitionProperty keys (no `Enum`).
    allowed_schema_keys = {"Type", "Description", "Items", "Properties", "Required"}

    def _assert_cfn_schema(node: dict, path: str) -> None:
        extra = set(node) - allowed_schema_keys
        assert not extra, f"{path} has unsupported SchemaDefinition keys: {extra}"
        for prop_name, prop_schema in (node.get("Properties") or {}).items():
            _assert_cfn_schema(prop_schema, f"{path}.Properties.{prop_name}")
        if isinstance(node.get("Items"), dict):
            _assert_cfn_schema(node["Items"], f"{path}.Items")

    for lid, res in tools_tpl["Resources"].items():
        if res["Type"] == "AWS::BedrockAgentCore::GatewayTarget":
            payload = res["Properties"]["TargetConfiguration"]["Mcp"]["Lambda"][
                "ToolSchema"
            ]["InlinePayload"]
            for tool_def in payload:
                _assert_cfn_schema(tool_def["InputSchema"], f"{lid}:{tool_def['Name']}")

    # 4. hr-identity layer pins scramp<1.5 so scramp.make_channel_binding exists
    #    for pg8000 1.31.5 TLS channel-binding handshakes.
    layer_python = REPO / "use-cases" / "hr-identity" / "layer" / "python"
    scramp_init = (layer_python / "scramp" / "__init__.py").read_text()
    assert "make_channel_binding" in scramp_init, (
        "hr-identity layer installed scramp>=1.5 without make_channel_binding"
    )
