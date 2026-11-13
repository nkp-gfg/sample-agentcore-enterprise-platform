"""Regression tests for the capability-oriented repository layout."""

from pathlib import Path, PurePosixPath

from scripts.check_repository_structure import (
    check_agent_runtime_shape,
    check_compatibility_links,
    check_top_level_directories,
    run_checks,
)

REPO_ROOT = Path(__file__).resolve().parents[1]


def test_current_repository_structure_passes():
    assert run_checks(REPO_ROOT) == []


def test_unregistered_top_level_directory_fails():
    errors = check_top_level_directories([PurePosixPath("new-component/file.py")])
    assert errors == ["unregistered top-level directory: new-component"]


def test_hr_web_is_a_registered_top_level_directory():
    """Layer 3 of the HR plan lives at hr-web/ by design.

    The directory is a static frontend plus a loopback-only Python server,
    following the dashboard/ precedent. It is not a CloudFormation stack and
    is not a new agent-code pattern, so the structure check must accept it
    the same way it accepts dashboard/.
    """
    errors = check_top_level_directories(
        [
            PurePosixPath("hr-web/server.py"),
            PurePosixPath("hr-web/public/index.html"),
            PurePosixPath("hr-web/tests/test_server_boundary.py"),
        ]
    )
    assert errors == []


def test_legacy_capability_root_fails_with_migration_guidance():
    errors = check_top_level_directories(
        [PurePosixPath("migration-adapter/adapter.py")]
    )
    assert errors == ["legacy capability root must not return: migration-adapter"]


def test_terraform_compatibility_link_is_preserved():
    assert check_compatibility_links(REPO_ROOT) == []


def test_agent_runtime_requires_build_contract():
    errors = check_agent_runtime_shape([PurePosixPath("agent-code/example/agent.py")])
    assert errors == [
        (
            "agent-code/example: missing runtime contract file(s): "
            "Dockerfile, requirements.txt"
        )
    ]


def test_agent_runtime_requires_entrypoint():
    errors = check_agent_runtime_shape(
        [
            PurePosixPath("agent-code/example/Dockerfile"),
            PurePosixPath("agent-code/example/requirements.txt"),
        ]
    )
    assert errors == ["agent-code/example: missing runtime contract file(s): agent.py"]
