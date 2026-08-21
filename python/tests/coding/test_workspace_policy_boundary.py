"""Contract tests for the shared protected-workspace policy."""

from __future__ import annotations

from pathlib import Path

from khaos.coding.workspace.policy import (
    PROTECTED_WORKSPACE_NAMES,
    is_protected_workspace_name,
    path_reaches_protected_metadata,
)


def test_protected_name_check_is_case_insensitive_and_shared() -> None:
    assert ".git" in PROTECTED_WORKSPACE_NAMES
    assert is_protected_workspace_name(".GIT")
    assert is_protected_workspace_name("KHAOS_POLICY.YAML")
    assert not is_protected_workspace_name("src")


def test_path_policy_checks_every_component() -> None:
    assert path_reaches_protected_metadata(Path("src/.git/config"))
    assert path_reaches_protected_metadata("nested/.CoDeX/settings")
    assert not path_reaches_protected_metadata("src/main.py")
