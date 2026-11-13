"""Evaluate `use-cases/hr-tools/policy/authz.rego` in-process.

docs/hr/policy.md pins the contract: the tool builds the input, the
policy file produces `{allow, reason_code, policy_version}`, and the
first-match reason-code order lives in the Rego file. H4 and H2 use
the same OPA CLI and the same bundled file — a change to a rule bumps
`policy_version` in the same commit.

The stack bundles the OPA binary and `authz.rego` into the Lambda zip.
The handler sets `OPA_BINARY` and `HR_POLICY_FILE` so this module does
not have to guess paths. Any failure to run the binary or parse its
output raises `PolicyUnavailable`, which the handler maps to the
`POLICY_UNAVAILABLE` reason code. A failed eval must never fall open.
"""

from __future__ import annotations

import json
import logging
import os
import subprocess  # nosec B404 — we execute our own vendored opa binary
from pathlib import Path

from .errors import PolicyUnavailable

logger = logging.getLogger(__name__)


def _opa_binary() -> str:
    return os.environ.get("OPA_BINARY") or "opa"


def _policy_file() -> Path:
    path = os.environ.get("HR_POLICY_FILE")
    if path:
        return Path(path)
    # Fallback: /var/task/authz.rego when the stack bundled it next to
    # the handlers. Tests set HR_POLICY_FILE explicitly.
    return Path(__file__).resolve().parent.parent / "authz.rego"


def opa_evaluate(document: dict) -> dict:
    """Return `{"allow": bool, "reason_code": str, "policy_version": str}`.

    docs/hr/policy.md specifies the query is `data.hr.authz.decision`.
    Anything else is a `POLICY_UNAVAILABLE` by construction.
    """
    binary = _opa_binary()
    policy = _policy_file()
    if not policy.is_file():
        logger.error("policy file missing: %s", policy)
        raise PolicyUnavailable(f"policy file not found: {policy}")
    try:
        completed = subprocess.run(  # nosec B603 — fixed args, no shell
            [
                binary,
                "eval",
                "--data",
                str(policy),
                "--stdin-input",
                "--format",
                "json",
                "data.hr.authz.decision",
            ],
            input=json.dumps(document),
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        logger.exception("opa eval could not be run")
        raise PolicyUnavailable(str(exc)) from exc
    if completed.returncode not in (0, 1):
        logger.error(
            "opa eval exited rc=%s stderr=%s", completed.returncode, completed.stderr
        )
        raise PolicyUnavailable(
            f"opa exited rc={completed.returncode}: {completed.stderr.strip()}"
        )
    try:
        payload = json.loads(completed.stdout)
        value = payload["result"][0]["expressions"][0]["value"]
    except (ValueError, KeyError, IndexError) as exc:
        logger.exception("opa eval returned unparseable JSON")
        raise PolicyUnavailable(f"opa output malformed: {exc}") from exc
    if not isinstance(value, dict):
        raise PolicyUnavailable(f"opa returned non-object decision: {value!r}")
    if "allow" not in value or "reason_code" not in value:
        raise PolicyUnavailable(f"opa decision missing required fields: {value!r}")
    return {
        "allow": bool(value["allow"]),
        "reason_code": str(value["reason_code"]),
        "policy_version": str(value.get("policy_version") or ""),
    }
