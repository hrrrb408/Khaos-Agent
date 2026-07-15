"""Real Windows-runner contracts while the native sandbox is unsupported."""

from __future__ import annotations

import sys

import pytest

from khaos.coding.execution import BackendSelector, UnsupportedBackend
from khaos.coding.planning.safe_workspace_path import SafePathError
from khaos.coding.workspace.boundary import SafeWorkspaceFS


pytestmark = [
    pytest.mark.windows_fail_closed,
    pytest.mark.skipif(sys.platform != "win32", reason="real Windows runner evidence"),
]


async def test_windows_agent_execution_has_no_host_fallback():
    backend = BackendSelector().select(writable=True)

    assert isinstance(backend, UnsupportedBackend)
    with pytest.raises(PermissionError, match="Windows"):
        await backend.execute(object())


def test_windows_workspace_mutation_refuses_missing_dirfd_capability(tmp_path):
    target = tmp_path / "must-not-exist.txt"

    with pytest.raises(SafePathError, match="O_NOFOLLOW/dir_fd"):
        SafeWorkspaceFS(tmp_path)

    assert not target.exists()
