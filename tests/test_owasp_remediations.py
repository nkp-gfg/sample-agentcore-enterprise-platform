"""Unit and CDK synthesis tests for OWASP Top 10 security remediations."""

from __future__ import annotations

import ast
import asyncio
import base64
import contextlib
import importlib.util
import io
import json
import ssl
import sys
import time
import types
import urllib.error
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import aws_cdk as cdk
import pytest
from aws_cdk.assertions import Template

REPO = Path(__file__).resolve().parents[1]
ENV = cdk.Environment(account="111111111111", region="us-east-1")


def _load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


def _resources(template: dict, resource_type: str) -> list[dict]:
    return [
        resource
        for resource in template["Resources"].values()
        if resource["Type"] == resource_type
    ]


# ── 1. Claude SDK per-user session isolation & subagent tool restriction ──


@pytest.mark.parametrize("pattern", ["claude-sdk-agent", "claude-sdk-multi-agent"])
def test_claude_sdk_session_map_is_scoped_by_user_id_after_auth(pattern):
    src = (REPO / "agent-code" / pattern / "agent.py").read_text()
    tree = ast.parse(src)

    # _session_map must be looked up and written with (user_id, runtime_session_id)
    assert "_session_map.get((user_id, runtime_session_id))" in src
    assert "_session_map[(user_id, runtime_session_id)] = msg.session_id" in src
    assert "_session_map.get(runtime_session_id)" not in src
    assert "_session_map[runtime_session_id]" not in src

    # Ensure user_id is resolved before _session_map.get(...)
    auth_pos = src.index("extract_user_id_from_context(context)")
    get_pos = src.index("_session_map.get((user_id, runtime_session_id))")
    assert auth_pos < get_pos

    # Validate AST parse succeeds cleanly
    assert tree is not None


def test_claude_sdk_multi_agent_subagent_removes_local_fs_tools_and_sets_disallowed():
    subagents_src = (
        REPO / "agent-code" / "claude-sdk-multi-agent" / "agents" / "subagents.py"
    ).read_text()
    tree = ast.parse(subagents_src)

    # Extract tools=[...] and disallowedTools=... inside AgentDefinition
    agent_def_calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and getattr(node.func, "id", None) == "AgentDefinition"
    ]
    assert len(agent_def_calls) == 1
    kw = {k.arg: k.value for k in agent_def_calls[0].keywords if k.arg}
    assert "tools" in kw
    tools = [el.value for el in kw["tools"].elts if isinstance(el, ast.Constant)]
    for forbidden in ("Read", "Grep", "Glob", "Bash", "Write", "Edit"):
        assert forbidden not in tools
    assert "disallowedTools" in kw
    assert "DISALLOWED_TOOLS" in subagents_src

    parent_src = (
        REPO / "agent-code" / "claude-sdk-multi-agent" / "agent.py"
    ).read_text()
    assert "from agents.subagents import DISALLOWED_TOOLS" in parent_src
    assert "disallowed_tools=list(DISALLOWED_TOOLS)" in parent_src


# ── 2. hr-identity claim restriction & TLS verification ──


def test_hr_identity_never_stamps_agent_id_on_human_triggers():
    mod = _load_module(
        "hr_identity_owasp_test",
        REPO / "use-cases" / "hr-identity" / "lambda" / "handler.py",
    )
    try:
        with patch.object(mod, "_lookup_employee_id", return_value="E1"):
            for trigger in (
                "TokenGeneration_HostedAuth",
                "TokenGeneration_Authentication",
                "TokenGeneration_RefreshTokens",
            ):
                event = {
                    "triggerSource": trigger,
                    "userName": "e1-user",
                    "request": {
                        "userAttributes": {"sub": "sub-e1-uuid"},
                        "clientMetadata": {"calling_agent": "review-node"},
                    },
                    "response": {"claimsAndScopeOverrideDetails": None},
                }
                out = mod.handler(event, None)
                details = out["response"]["claimsAndScopeOverrideDetails"]
                access_claims = details["accessTokenGeneration"][
                    "claimsToAddOrOverride"
                ]
                id_claims = details["idTokenGeneration"]["claimsToAddOrOverride"]
                assert "agent_id" not in access_claims
                assert "agent_id" not in id_claims
                assert access_claims["employee_id"] == "E1"
    finally:
        sys.modules.pop("hr_identity_owasp_test", None)


def test_hr_identity_uses_rds_ca_bundle_with_verify_required_and_check_hostname(
    monkeypatch,
):
    bundle = REPO / "use-cases" / "hr-identity" / "lambda" / "global-bundle.pem"
    assert bundle.is_file()
    ctx_test = ssl.create_default_context(cafile=str(bundle))
    assert ctx_test.cert_store_stats()["x509_ca"] >= 1

    mod = _load_module(
        "hr_identity_tls_test",
        REPO / "use-cases" / "hr-identity" / "lambda" / "handler.py",
    )
    try:
        captured: dict = {}

        class _FakeConn:
            pass

        fake_pg = types.ModuleType("pg8000")
        fake_pg_native = types.ModuleType("pg8000.native")

        def _fake_connection(**kwargs):
            captured.update(kwargs)
            return _FakeConn()

        fake_pg_native.Connection = _fake_connection
        fake_pg.native = fake_pg_native

        fake_rds = MagicMock()
        fake_rds.generate_db_auth_token.return_value = "rds-iam-token"

        monkeypatch.setitem(sys.modules, "pg8000", fake_pg)
        monkeypatch.setitem(sys.modules, "pg8000.native", fake_pg_native)
        with patch("boto3.client", return_value=fake_rds):
            mod._connect(
                {
                    "DB_HOST": "aurora.example.rds.amazonaws.com:5432",
                    "DB_PORT": "5432",
                    "DB_NAME": "hr",
                    "DB_USER": "hr_identity",
                    "AWS_REGION": "us-east-1",
                }
            )
        ssl_ctx = captured["ssl_context"]
        assert ssl_ctx.verify_mode == ssl.CERT_REQUIRED
        assert ssl_ctx.check_hostname is True
    finally:
        sys.modules.pop("hr_identity_tls_test", None)


# ── 3. shared/auth.py SSRF, redirect, transient OIDC cache, Bearer parsing ──


def test_shared_auth_https_no_redirect_transient_discovery_and_bearer_parsing(
    monkeypatch,
):
    # Provide lightweight stubs for jwt and bedrock_agentcore so this runs in CI
    # without container dependencies installed.
    fake_jwt = types.ModuleType("jwt")

    class _FakePyJWKClientError(Exception):
        pass

    class _FakePyJWKClientConnectionError(_FakePyJWKClientError):
        pass

    class _FakePyJWTError(Exception):
        pass

    class _FakePyJWKClient:
        def __init__(self, uri, cache_keys=False, **_kw):
            self.uri = uri
            self.cache_keys = cache_keys
            self.headers = {}
            self.timeout = 30
            self.jwk_set_cache = None

        def get_signing_key_from_jwt(self, _token):
            self.fetch_data()
            return SimpleNamespace(key="public-key")

    fake_jwt.PyJWKClient = _FakePyJWKClient
    fake_jwt.PyJWKClientError = _FakePyJWKClientError
    fake_jwt.PyJWKClientConnectionError = _FakePyJWKClientConnectionError
    fake_jwt.PyJWTError = _FakePyJWTError
    fake_jwt.decode = lambda **_kw: {
        "iss": "https://idp.example.com",
        "aud": "c1",
        "sub": "u1",
    }

    fake_bc = types.ModuleType("bedrock_agentcore")
    fake_bc_id = types.ModuleType("bedrock_agentcore.identity")
    fake_bc_id_auth = types.ModuleType("bedrock_agentcore.identity.auth")
    fake_bc_id_auth.requires_access_token = lambda **_kw: lambda fn: fn
    fake_bc_rt = types.ModuleType("bedrock_agentcore.runtime")
    fake_bc_rt.RequestContext = object

    monkeypatch.setitem(sys.modules, "jwt", fake_jwt)
    monkeypatch.setitem(sys.modules, "bedrock_agentcore", fake_bc)
    monkeypatch.setitem(sys.modules, "bedrock_agentcore.identity", fake_bc_id)
    monkeypatch.setitem(sys.modules, "bedrock_agentcore.identity.auth", fake_bc_id_auth)
    monkeypatch.setitem(sys.modules, "bedrock_agentcore.runtime", fake_bc_rt)
    monkeypatch.syspath_prepend(str(REPO / "agent-code"))
    monkeypatch.setenv("COGNITO_ISSUER_URL", "https://idp.example.com")
    monkeypatch.setenv("COGNITO_ALLOWED_CLIENTS", "c1")

    for name in list(sys.modules):
        if name == "shared" or name.startswith("shared."):
            sys.modules.pop(name, None)

    from shared import auth

    try:
        # 1. Non-HTTPS URL is rejected
        with pytest.raises(ValueError, match="https://"):
            auth._validate_https_url("http://insecure.example.com/jwks", "JWKS URL")
        with pytest.raises(ValueError, match="https://"):
            auth._validate_https_url("https:///no-host", "JWKS URL")

        # 2. HTTP redirects are refused
        handler = auth._NoRedirectHandler()
        req = auth.urllib.request.Request(
            "https://idp.example.com/.well-known/openid-configuration"
        )
        with pytest.raises(urllib.error.HTTPError, match="redirects are disabled"):
            handler.redirect_request(
                req, None, 302, "Found", {}, "https://evil.example"
            )

        # 3. Transient OIDC discovery failure does NOT permanently cache fallback
        calls: list[str] = []

        class _FakeOpener:
            def open(self, req_obj, timeout=5):
                url = req_obj.full_url if hasattr(req_obj, "full_url") else str(req_obj)
                calls.append(url)
                if url.endswith("/.well-known/openid-configuration"):
                    if calls.count(url) == 1:
                        raise urllib.error.URLError("transient network blip")
                    return io.BytesIO(
                        json.dumps(
                            {"jwks_uri": "https://idp.example.com/custom/keys"}
                        ).encode()
                    )
                return io.BytesIO(json.dumps({"keys": []}).encode())

        monkeypatch.setattr(auth, "_no_redirect_opener", lambda: _FakeOpener())
        auth._jwks_client = None

        # First call: discovery fails -> uses fallback, does NOT lock in _jwks_client
        assert auth._signing_key("tok1") == "public-key"
        assert auth._jwks_client is None
        assert calls[-1] == "https://idp.example.com/.well-known/jwks.json"

        # Second call: retries discovery -> succeeds -> caches custom jwks_uri
        assert auth._signing_key("tok2") == "public-key"
        assert auth._jwks_client is not None
        assert auth._jwks_client.uri == "https://idp.example.com/custom/keys"

        # 4. Case-insensitive Bearer parsing + rejects Basic
        ctx_lower = SimpleNamespace(request_headers={"authorization": "bearer jwt-tok"})
        assert auth.extract_user_id_from_context(ctx_lower) == "u1"

        ctx_basic = SimpleNamespace(request_headers={"Authorization": "Basic abc"})
        with pytest.raises(ValueError, match="Bearer"):
            auth.extract_user_id_from_context(ctx_basic)
    finally:
        for name in list(sys.modules):
            if name == "shared" or name.startswith("shared."):
                sys.modules.pop(name, None)


# ── 4. hr-tools DB verify-full, TOCTOU, reason length, audit logging ──


def test_hr_tools_db_uses_verify_full_and_bundled_ca(monkeypatch):
    bundle = REPO / "use-cases" / "hr-tools" / "lambdas" / "global-bundle.pem"
    assert bundle.is_file()

    lambdas_dir = REPO / "use-cases" / "hr-tools" / "lambdas"
    monkeypatch.syspath_prepend(str(lambdas_dir))
    monkeypatch.setenv("HR_DB_ENDPOINT", "aurora.example.rds.amazonaws.com:5432")
    monkeypatch.setenv("HR_DB_NAME", "hr")
    monkeypatch.setenv("AWS_REGION", "us-east-1")

    for name in list(sys.modules):
        if name == "shared" or name.startswith("shared."):
            sys.modules.pop(name, None)

    from shared import db

    captured: dict = {}
    fake_psycopg = types.ModuleType("psycopg")

    def _fake_connect(**kwargs):
        captured.update(kwargs)
        return MagicMock()

    fake_psycopg.connect = _fake_connect
    monkeypatch.setitem(sys.modules, "psycopg", fake_psycopg)
    monkeypatch.setattr(db, "_generate_iam_token", lambda *_a: "iam-token")

    with db.connect("hr_reader"):
        pass

    assert captured["sslmode"] == "verify-full"
    assert Path(captured["sslrootcert"]).resolve() == bundle.resolve()


def test_hr_tools_compensation_toctou_and_secondary_audit_logs(monkeypatch):
    lambdas_dir = REPO / "use-cases" / "hr-tools" / "lambdas"
    monkeypatch.syspath_prepend(str(lambdas_dir))
    for name in list(sys.modules):
        if name in {
            "shared",
            "dispatcher",
            "get_employee_compensation",
            "submit_leave_request",
            "get_leave_balance",
        } or name.startswith(
            (
                "shared.",
                "get_employee_compensation.",
                "submit_leave_request.",
                "get_leave_balance.",
            )
        ):
            sys.modules.pop(name, None)

    import dispatcher
    import get_employee_compensation.handler as comp
    import get_leave_balance.handler as bal
    import submit_leave_request.handler as sub

    audit_rows: list[dict] = []
    monkeypatch.setattr(comp, "is_service_enabled", lambda: True)
    monkeypatch.setattr(sub, "is_service_enabled", lambda: True)
    monkeypatch.setattr(bal, "is_service_enabled", lambda: True)
    monkeypatch.setattr(comp, "log_decision", lambda **kw: audit_rows.append(kw))
    monkeypatch.setattr(sub, "log_decision", lambda **kw: audit_rows.append(kw))
    monkeypatch.setattr(bal, "log_decision", lambda **kw: audit_rows.append(kw))
    monkeypatch.setattr(dispatcher, "log_decision", lambda **kw: audit_rows.append(kw))

    # 1. TOCTOU: single connection opened; manager changes between first and second read -> denied
    connect_calls = 0

    class _ToctouCursor:
        def __init__(self):
            self._emp_reads = 0
            self._sql = ""

        def execute(self, sql, params=()):
            self._sql = sql

        def fetchone(self):
            if "FROM employees" in self._sql:
                self._emp_reads += 1
                if self._emp_reads == 1:
                    return ("active", "M1", "E1")
                return ("terminated", "M2", "E1")
            if "FROM salaries" in self._sql:
                return (100000, "USD")
            return None

        def __enter__(self):
            return self

        def __exit__(self, *_a):
            pass

    class _ToctouConn:
        def cursor(self):
            return _ToctouCursor()

    @contextlib.contextmanager
    def _one_conn(_role):
        nonlocal connect_calls
        connect_calls += 1
        yield _ToctouConn()

    monkeypatch.setattr(comp, "connect", _one_conn)
    res = comp.handler(
        {"caller_employee_id": "M1", "agent_id": "compensation", "employee_id": "E1"},
        None,
    )
    assert res == {"authorized": False, "reason_code": "NOT_AUTHORIZED"}
    assert connect_calls == 1
    assert audit_rows[-1]["allow"] is False
    assert audit_rows[-1]["reason_code"] == "NOT_AUTHORIZED"

    # 2. submit_leave_request enforces reason <= 500
    res_long = sub.handler(
        {
            "caller_employee_id": "E1",
            "agent_id": "leave-submit",
            "leave_type": "annual",
            "start_date": "2026-12-01",
            "end_date": "2026-12-02",
            "reason": "x" * 501,
            "idempotency_key": "k1",
        },
        None,
    )
    assert res_long == {"authorized": False, "reason_code": "INVALID_RANGE"}
    assert audit_rows[-1]["allow"] is False

    # 3. get_leave_balance missing employee_row logs DATA_UNAVAILABLE
    class _EmptyBalCursor:
        def execute(self, *_a):
            pass

        def fetchone(self):
            return None

        def fetchall(self):
            return []

        def __enter__(self):
            return self

        def __exit__(self, *_a):
            pass

    @contextlib.contextmanager
    def _empty_bal_conn(_role):
        yield SimpleNamespace(cursor=lambda: _EmptyBalCursor())

    monkeypatch.setattr(bal, "connect", _empty_bal_conn)
    res_bal = bal.handler(
        {"caller_employee_id": "E1", "agent_id": "leave-balance"}, None
    )
    assert res_bal == {"authorized": False, "reason_code": "DATA_UNAVAILABLE"}
    assert audit_rows[-1]["allow"] is False
    assert audit_rows[-1]["reason_code"] == "DATA_UNAVAILABLE"

    # 4. dispatcher logs DATA_UNAVAILABLE on unexpected exception
    ctx = SimpleNamespace(
        client_context=SimpleNamespace(
            custom={"bedrockAgentCoreToolName": "hr-ops___get_leave_balance"}
        )
    )
    fake_mod = types.ModuleType("get_leave_balance.handler")
    fake_mod.handler = MagicMock(side_effect=RuntimeError("boom"))
    monkeypatch.setattr(dispatcher.importlib, "import_module", lambda _n: fake_mod)
    disp_out = json.loads(
        dispatcher.handler(
            {
                "caller_employee_id": "E1",
                "agent_id": "leave-balance",
                "session_id": "s1",
            },
            ctx,
        )["content"][0]["text"]
    )
    assert disp_out == {"authorized": False, "reason_code": "DATA_UNAVAILABLE"}
    assert audit_rows[-1]["allow"] is False
    assert audit_rows[-1]["reason_code"] == "DATA_UNAVAILABLE"


# ── 5. god-agent rate limiter pruning & review limiter ──


def test_rate_limiter_prunes_stale_entries_and_provides_review_limiter(monkeypatch):
    monkeypatch.syspath_prepend(str(REPO / "agent-code" / "god-agent"))
    sys.modules.pop("rate_limit", None)
    import rate_limit

    limiter = rate_limit.TurnRateLimiter(max_turns=5, window_seconds=10)
    limiter.check_and_record("stale-user", now=0.0)
    assert "stale-user" in limiter._events
    limiter.check_and_record("active-user", now=20.0)
    assert "stale-user" not in limiter._events
    assert "active-user" in limiter._events

    rev = rate_limit.review_limiter()
    rev.reset()
    for i in range(rate_limit.REVIEW_MAX_TURNS):
        assert rev.check_and_record("mgr", now=100.0 + i * 0.1).allowed is True
    assert rev.check_and_record("mgr", now=105.0).allowed is False


# ── 6. Generic error responses (no str(exc) leakage) ──


@pytest.mark.parametrize(
    "rel_path",
    [
        "agent-code/god-agent/agent.py",
        "agent-code/agui-langgraph-agent/agent.py",
        "agent-code/agui-strands-agent/agent.py",
        "agent-code/langgraph-agent/agent.py",
        "agent-code/strands-agent/agent.py",
        "tools/sample_tool/handler.py",
    ],
)
def test_agent_and_tool_handlers_do_not_return_raw_exception_text(rel_path):
    src = (REPO / rel_path).read_text()
    assert "str(exc)" not in src
    assert "str(e)" not in src


def test_sample_tool_returns_generic_internal_error():
    mod = _load_module(
        "sample_tool_owasp_test", REPO / "tools" / "sample_tool" / "handler.py"
    )
    try:
        bad_ctx = SimpleNamespace(
            client_context=SimpleNamespace(
                custom={"bedrockAgentCoreToolName": "sample-tool___text_analysis_tool"}
            )
        )
        out = mod.handler({"text": None}, bad_ctx)
        assert out == {"error": "Internal server error"}
    finally:
        sys.modules.pop("sample_tool_owasp_test", None)


# ── 7. Dockerfiles & god-agent gateway_client static/runtime checks ──


def test_dockerfiles_hardened():
    for pattern in ("claude-sdk-agent", "claude-sdk-multi-agent"):
        df = (REPO / "agent-code" / pattern / "Dockerfile").read_text()
        assert "nodesource.com" not in df
        assert "| bash" not in df
        assert "sha256sum -c -" in df

    orch_df = (REPO / "agent-code" / "orchestrator" / "Dockerfile").read_text()
    assert "python:3.13-slim" in orch_df
    assert "python:3.11-slim" not in orch_df

    god_df = (REPO / "agent-code" / "god-agent" / "Dockerfile").read_text()
    assert "COPY god-agent/global-bundle.pem ." in god_df
    assert (REPO / "agent-code" / "god-agent" / "global-bundle.pem").is_file()


def test_god_agent_gateway_client_schemas_https_and_m2m_checks(monkeypatch):
    if importlib.util.find_spec("langchain_core") is None:
        pytest.skip("god-agent dependencies not installed in host venv")

    monkeypatch.syspath_prepend(str(REPO / "agent-code"))
    monkeypatch.syspath_prepend(str(REPO / "agent-code" / "god-agent"))
    for name in ("gateway_client", "ssm_config"):
        sys.modules.pop(name, None)

    import gateway_client as gw
    from pydantic import ValidationError

    # HTTPS validation
    with pytest.raises(ValueError, match="https://"):
        gw._validate_https_url("http://insecure.example", "gateway_url")

    # Tightened schemas
    assert (
        gw._AllowanceArgs(item_type="telephone", period="2026-10").item_type
        == "telephone"
    )
    with pytest.raises(ValidationError):
        gw._AllowanceArgs(item_type="housing")
    with pytest.raises(ValidationError):
        gw._LeaveCheckArgs(
            leave_type="sabbatical", start_date="2026-12-01", end_date="2026-12-02"
        )
    with pytest.raises(ValidationError):
        gw._LeaveCheckArgs(
            leave_type="annual", start_date="12/01/2026", end_date="2026-12-02"
        )
    with pytest.raises(ValidationError):
        gw._LeaveSubmitArgs(
            leave_type="annual",
            start_date="2026-12-01",
            end_date="2026-12-02",
            reason="a" * 501,
        )

    # M2M claim verification in resolve_employee_id_for_sub
    def _make_jwt(payload: dict) -> str:
        hdr = base64.urlsafe_b64encode(b'{"alg":"RS256"}').rstrip(b"=").decode()
        body = (
            base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
        )
        return f"{hdr}.{body}.sig"

    monkeypatch.setattr(
        gw,
        "auth_m2m_config",
        lambda: SimpleNamespace(
            issuer_url="https://cognito-idp.us-east-1.amazonaws.com/us-east-1_test",
            client_id="m2m",
            client_secret_name="sec",
            scope="",
        ),
    )

    async def _good_mint(*_a):
        return _make_jwt(
            {
                "iss": "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_test",
                "sub": "m2m",
                "exp": time.time() + 300,
                "user_id": "sub-1",
                "employee_id": "E1",
            }
        )

    monkeypatch.setattr(gw, "mint_leaf_gateway_token", _good_mint)
    assert asyncio.run(gw.resolve_employee_id_for_sub("sub-1")) == "E1"

    async def _bad_iss_mint(*_a):
        return _make_jwt(
            {
                "iss": "https://evil.example",
                "sub": "m2m",
                "exp": time.time() + 300,
                "employee_id": "E1",
            }
        )

    monkeypatch.setattr(gw, "mint_leaf_gateway_token", _bad_iss_mint)
    with pytest.raises(ValueError, match="issuer"):
        asyncio.run(gw.resolve_employee_id_for_sub("sub-1"))


# ── 8. CDK stacks & control-library hardening ──


def test_security_stack_enables_file_validation_and_access_logging_in_non_prod():
    from stacks.security_stack import SecurityStack

    app = cdk.App()
    tpl = Template.from_stack(
        SecurityStack(
            app,
            "DevSecurity",
            project_name="devtest",
            environment="dev",
            retain_data=False,
            env=ENV,
        )
    ).to_json()

    trail = _resources(tpl, "AWS::CloudTrail::Trail")[0]["Properties"]
    assert trail["EnableLogFileValidation"] is True

    buckets = _resources(tpl, "AWS::S3::Bucket")
    assert len(buckets) == 2
    assert any("LoggingConfiguration" in b["Properties"] for b in buckets)


def test_networking_stack_adds_vpc_flow_logs_without_requiring_org_id():
    from stacks.networking_stack import NetworkingStack

    app = cdk.App()
    tpl = Template.from_stack(
        NetworkingStack(
            app,
            "DevNet",
            project_name="devtest",
            environment="dev",
            enable_vpc_endpoints=True,
            org_id="",
            env=ENV,
        )
    ).to_json()

    flow_logs = _resources(tpl, "AWS::EC2::FlowLog")
    assert len(flow_logs) == 1
    assert flow_logs[0]["Properties"]["TrafficType"] == "ALL"


def test_gateway_stack_creates_per_tool_iam_roles():
    from stacks.gateway_stack import GatewayStack

    app = cdk.App()
    tpl = Template.from_stack(
        GatewayStack(
            app,
            "ToolsGateway",
            project_name="devtest",
            environment="dev",
            cognito_issuer_url="https://cognito-idp.us-east-1.amazonaws.com/us-east-1_ex",
            cognito_allowed_clients=["c1"],
            tool_configs={
                "tool-a": {"source_dir": "tools/sample_tool", "tool_schema": []},
                "tool-b": {"source_dir": "tools/sample_tool", "tool_schema": []},
            },
            env=ENV,
        )
    ).to_json()

    fns = _resources(tpl, "AWS::Lambda::Function")
    role_refs = {json.dumps(f["Properties"]["Role"]) for f in fns}
    assert len(role_refs) == 2


def test_hr_identity_stack_removes_unused_ssm_policy():
    sys.path.insert(0, str(REPO))
    hr_id_mod = _load_module(
        "hr_id_stack_owasp_test", REPO / "use-cases" / "hr-identity" / "stack.py"
    )
    try:
        app = cdk.App()
        ctx = {
            "project": "t",
            "environment": "dev",
            "prefix": "t-dev",
            "ssm_prefix": "/t/dev",
            "region": "us-east-1",
            "cdk_env": ENV,
        }
        hr_id_mod.build(app, ctx, {})
        tpl = Template.from_stack(app.node.find_child("t-dev-uc-hr-identity")).to_json()
        policies = json.dumps(_resources(tpl, "AWS::IAM::Policy"))
        assert "SsmReadPlatformInputs" not in policies
    finally:
        sys.modules.pop("hr_id_stack_owasp_test", None)


def test_runtime_stack_synthesizes_scoped_identity_credential_provider_policy():
    from stacks.runtime_stack import RuntimeStack

    app = cdk.App()
    tpl = Template.from_stack(
        RuntimeStack(
            app,
            "ScopedRuntime",
            project_name="devtest",
            environment="dev",
            component_name="orchestrator",
            source_dir="tools/sample_tool",
            runtime_type="orchestrator",
            extra_env_vars={
                "GATEWAY_CREDENTIAL_PROVIDER_NAME": "devtest-dev-gateway-m2m"
            },
            env=ENV,
        )
    ).to_json()

    policies = json.dumps(_resources(tpl, "AWS::IAM::Policy"))
    assert "AllowOwnWorkloadIdentityTokens" in policies
    assert "AllowScopedOauth2CredentialProvider" in policies
    assert "workload-identity/devtest_dev_orchestrator" in policies
    assert "oauth2-credential-provider/devtest-dev-gateway-m2m" in policies


def test_default_cedar_read_policy_constrains_principal_to_oauth_user():
    from infra_utils.policy_loader import load_control_text

    permit = load_control_text(
        "cedar.gateway-default.permit-read",
        {"gateway_arn": "arn:aws:bedrock-agentcore:us-east-1:111122223333:gateway/gw"},
    )
    assert "principal is AgentCore::OAuthUser" in permit
    assert "forbid(" not in permit
