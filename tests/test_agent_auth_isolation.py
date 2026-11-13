"""A failed token check must be the only thing reported as "Unauthorized".

Strands raises ValueError when an MCP tool fails to load. When the token check
shared an `except ValueError` with agent creation, a gateway 500 came back as
"Unauthorized". Where the check sat in a broad `except Exception`, JWT
validation details were echoed to the caller; outside any try, a bad token
crashed the stream instead of returning a clean error.

So in every agent pattern: the token check is the only statement in its own
`try`, and its `except ValueError` yields "Unauthorized" and returns.

Parsed from source: the CI test job has no agent dependencies installed.
"""

import ast
from pathlib import Path

import pytest

AGENT_CODE = Path(__file__).resolve().parents[1] / "agent-code"
AUTH_CALL = "extract_user_id_from_context"


def _patterns() -> list[Path]:
    return sorted(
        p for p in AGENT_CODE.glob("*/agent.py") if f"{AUTH_CALL}(context)" in p.read_text()
    )


def _calls_auth(node: ast.AST) -> bool:
    return any(
        isinstance(n, ast.Call) and getattr(n.func, "id", None) == AUTH_CALL
        for n in ast.walk(node)
    )


def test_every_jwt_verifying_pattern_is_checked():
    names = {p.parent.name for p in _patterns()}
    assert {"strands-agent", "langgraph-agent", "agui-strands-agent"} <= names


@pytest.mark.parametrize("agent", _patterns(), ids=lambda p: p.parent.name)
def test_token_check_has_its_own_try_and_generic_rejection(agent):
    tree = ast.parse(agent.read_text())
    tries = [t for t in ast.walk(tree) if isinstance(t, ast.Try) and _calls_auth(t)]
    assert tries, f"{AUTH_CALL} is not inside any try block"

    for block in tries:
        auth_statements = [s for s in block.body if _calls_auth(s)]
        assert block.body == auth_statements, (
            "the try around the token check must contain nothing else, or a "
            "ValueError from tools or the model is reported as Unauthorized"
        )
        handlers = [
            h for h in block.handlers if isinstance(h.type, ast.Name) and h.type.id == "ValueError"
        ]
        assert handlers, "the token check must catch ValueError"
        handler_source = ast.unparse(handlers[0])
        assert "Unauthorized" in handler_source
        assert any(isinstance(s, ast.Return) for s in handlers[0].body), (
            "the rejection must stop the request"
        )
        assert "str(e)" not in handler_source, "the auth failure reason must not reach the caller"
