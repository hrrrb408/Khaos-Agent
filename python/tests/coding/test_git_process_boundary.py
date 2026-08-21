"""Contract tests for the trusted Git process owner."""

import inspect

import khaos.coding.workspace.trusted_git as trusted_git_module
from khaos.coding.workspace.git_process import (
    TrustedGitProcessOwner,
    TrustedGitProcessState,
)


def test_trusted_git_runner_consumes_one_process_owner() -> None:
    source = inspect.getsource(trusted_git_module)
    assert "class TrustedGitProcessOwner" not in source
    assert "class TrustedGitProcessState" not in source
    assert trusted_git_module.TrustedGitProcessOwner is TrustedGitProcessOwner
    assert TrustedGitProcessState.QUARANTINED.value == "quarantined"
