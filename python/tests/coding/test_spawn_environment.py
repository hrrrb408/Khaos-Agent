"""Regression coverage for the final subprocess environment boundary."""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

from khaos.coding.execution.environment import scrub_spawn_environment
from khaos.coding.execution.models import ExecutionRequest, PermissionProfile
from khaos.coding.execution.supervisor import ProcessSupervisor


def test_scrub_spawn_environment_removes_secret_suffixes_without_mutating_input():
    original = {
        "PATH": "/usr/bin",
        "OPENAI_API_KEY": "secret",
        "VENDOR_TOKEN": "token",
        "CI": "1",
    }

    scrubbed = scrub_spawn_environment(original)

    assert scrubbed == {"PATH": "/usr/bin", "CI": "1"}
    assert original["OPENAI_API_KEY"] == "secret"


def test_scrub_spawn_environment_only_preserves_explicit_trusted_contract():
    scrubbed = scrub_spawn_environment(
        {
            "KHAOS_BROWSER_SANDBOX_TOKEN": "launcher-only",
            "OPENAI_API_KEY": "secret",
        },
        preserve={"KHAOS_BROWSER_SANDBOX_TOKEN"},
    )

    assert scrubbed == {"KHAOS_BROWSER_SANDBOX_TOKEN": "launcher-only"}


def test_scrub_spawn_environment_keeps_only_pinned_git_config_suppression():
    assert scrub_spawn_environment(
        {
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_SYSTEM": os.devnull,
        }
    ) == {
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_SYSTEM": os.devnull,
    }
    assert scrub_spawn_environment(
        {"GIT_CONFIG_GLOBAL": "/tmp/attacker.gitconfig"}
    ) == {}


@pytest.mark.asyncio
async def test_supervisor_final_spawn_scrubs_secret_after_allowlist(tmp_path: Path):
    """A real child cannot read a credential even when the caller allowed it."""
    profile = PermissionProfile(
        environment_keys=frozenset({"PATH", "OPENAI_API_KEY", "VENDOR_TOKEN"}),
    )
    request = ExecutionRequest(
        (
            sys.executable,
            "-c",
            "import os; print(os.getenv('OPENAI_API_KEY', '<missing>')); "
            "print(os.getenv('VENDOR_TOKEN', '<missing>'))",
        ),
        tmp_path,
        permission_profile=profile,
    )
    supervisor = ProcessSupervisor()

    result = await supervisor.run(
        request,
        cwd=tmp_path,
        env={
            "PATH": os.environ.get("PATH", ""),
            "OPENAI_API_KEY": "secret",
            "VENDOR_TOKEN": "token",
        },
        enforce_resource_limits=False,
        use_native_launcher=False,
    )
    await supervisor.shutdown()

    assert result.status == "passed"
    assert result.stdout.splitlines() == ["<missing>", "<missing>"]


def test_git_semantic_environment_never_crosses_spawn_boundary() -> None:
    """Config/hook/retarget env must not reach any spawned git command.

    A SAFE-classified ``git diff`` is only proven read-only while the
    executable graph stays the classified argv: GIT_EXTERNAL_DIFF or the
    GIT_CONFIG_KEY_n/VALUE_n inline-config pairs would silently change git
    semantics, and GIT_DIR/GIT_WORK_TREE would retarget the repository.
    """
    hostile = {
        "GIT_EXTERNAL_DIFF": "/workspace/evil-diff",
        "GIT_PAGER": "/workspace/evil-pager",
        "PAGER": "/workspace/evil-pager",
        "GIT_CONFIG_COUNT": "2",
        "GIT_CONFIG_KEY_0": "core.pager",
        "GIT_CONFIG_VALUE_0": "/workspace/evil-pager",
        "GIT_CONFIG_KEY_1": "diff.external",
        "GIT_CONFIG_VALUE_1": "/workspace/evil-diff",
        "GIT_DIR": "/workspace/other-repo/.git",
        "GIT_WORK_TREE": "/workspace/other-repo",
        "GIT_INDEX_FILE": "/workspace/other-repo/.git/index",
        "GIT_OBJECT_DIRECTORY": "/workspace/other-repo/.git/objects",
        "GIT_ALTERNATE_OBJECT_DIRECTORIES": "/tmp/evil-objects",
        "PATH": "/usr/bin:/bin",
    }
    scrubbed = scrub_spawn_environment(hostile)
    assert "PATH" in scrubbed
    for key in hostile:
        if key == "PATH":
            continue
        assert key not in scrubbed, key
