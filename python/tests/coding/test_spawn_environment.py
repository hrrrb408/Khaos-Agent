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
