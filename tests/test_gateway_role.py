"""The gateway role must be complete before the gateway is created.

Each case here failed a live deploy:
  - The gateway invokes the egress interceptor with its own role. Without an
    explicit lambda:InvokeFunction on the interceptor, every MCP call is a 500.
  - The gateway must depend on the role (and so its DefaultPolicy) and on the
    policy-engine access policy, or a fresh deploy can create it before those
    permissions are attached.

Parsed from source: the CI test job has no aws-cdk-lib.
"""

import ast
from pathlib import Path

GATEWAY_STACK = Path(__file__).resolve().parents[1] / "stacks" / "gateway_stack.py"


def _statement(sid: str) -> dict:
    for node in ast.walk(ast.parse(GATEWAY_STACK.read_text())):
        if isinstance(node, ast.Call) and getattr(node.func, "attr", None) == "PolicyStatement":
            kwargs = {kw.arg: kw.value for kw in node.keywords}
            if isinstance(kwargs.get("sid"), ast.Constant) and kwargs["sid"].value == sid:
                return {k: ast.unparse(v) for k, v in kwargs.items()}
    raise AssertionError(f"no PolicyStatement with sid {sid!r}")


def test_gateway_role_can_invoke_only_the_interceptor():
    statement = _statement("InvokeEgressInterceptor")
    assert statement["actions"] == "['lambda:InvokeFunction']"
    assert statement["resources"] == "[self._interceptor_fn.function_arn]"


def test_policy_engine_access_covers_the_not_yet_created_gateway():
    statement = _statement("EvaluatePolicyEngine")
    assert "policy_engine.attr_policy_engine_arn" in statement["resources"]
    assert "gateway_arn_pattern" in statement["resources"]
    assert 'resource_name=f"{gw_name}-*"' in GATEWAY_STACK.read_text()


def test_gateway_waits_for_its_role_and_policy_engine_access():
    source = GATEWAY_STACK.read_text()
    assert "self._gateway.node.add_dependency(gw_role)" in source
    assert "self._gateway.node.add_dependency(policy_engine_access)" in source
