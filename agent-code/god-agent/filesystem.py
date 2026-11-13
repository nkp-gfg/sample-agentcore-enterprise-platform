"""Filesystem permissions for the god agent.

`custom-app-plan/god-agent.md`:

    Filesystem writes are denied for `/**` with
    `FilesystemPermission(operations=["write"], paths=["/**"], mode="deny")`.
    That requires `deepagents>=0.5.2`. No sandbox backend, so there is no
    `execute` tool. Scratch state, if the harness requires a backend, is
    `StateBackend` only. Salary rows are not written into that scratch space.

Red-team row R-11 ("A prompt that asks the agent to write a file or run
code" → "no `execute` tool, writes denied") is the acceptance gate this
module defends.
"""

from __future__ import annotations

from deepagents import FilesystemPermission
from deepagents.backends import StateBackend


def write_deny_permission() -> FilesystemPermission:
    """Deny every filesystem write, anywhere on the virtual filesystem."""

    return FilesystemPermission(
        operations=["write"],
        paths=["/**"],
        mode="deny",
    )


def scratch_backend() -> StateBackend:
    """In-graph scratch state: no disk, no sandbox, no persistence of secrets.

    Salary rows never reach this backend. Tool results that may contain an
    allowed amount pass through the leaf as structured JSON and are read by
    the department/god agent as data only (see god-agent.md § Untrusted data);
    they are not written into scratch files.
    """

    return StateBackend()
