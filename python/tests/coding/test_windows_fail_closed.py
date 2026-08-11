"""Real Windows-runner contracts for the native sandbox and fail-closed path."""

from __future__ import annotations

import os
import shutil
import sys

import pytest
from khaos.coding.execution import (
    BackendSelector,
    ExecutionRequest,
    FileSystemAccess,
    PermissionProfile,
    ResourceBudget,
    UnsupportedBackend,
    WindowsSandboxBackend,
)
from khaos.coding.planning.safe_workspace_path import SafePathError
from khaos.coding.workspace.boundary import SafeWorkspaceFS

pytestmark = [
    pytest.mark.windows_fail_closed,
    pytest.mark.skipif(sys.platform != "win32", reason="real Windows runner evidence"),
]


async def test_windows_agent_execution_has_no_host_fallback(tmp_path):
    backend = BackendSelector().select(writable=True)
    availability = await backend.probe()

    if isinstance(backend, UnsupportedBackend):
        # Developer machines may not have the native helper built.  The
        # contract remains fail-closed unless CI explicitly requires native
        # evidence.
        if os.environ.get("KHAOS_REQUIRE_WINDOWS_NATIVE") == "1":
            pytest.fail(availability.reason)
        assert availability.available is False
        assert availability.network_enforced is False
        with pytest.raises(PermissionError, match="Windows"):
            await backend.execute(object())
        return

    assert isinstance(backend, WindowsSandboxBackend)
    assert availability.available is True
    assert availability.network_enforced is True

    workspace = tmp_path / "workspace"
    workspace.mkdir()
    try:
        profile = PermissionProfile(
            filesystem=FileSystemAccess.WORKSPACE_WRITE,
            resources=ResourceBudget(timeout_seconds=20),
        ).bind_workspace(workspace)
        request = ExecutionRequest(
            (sys.executable, "-c", "from pathlib import Path; Path('inside.txt').write_text('ok')"),
            workspace,
            environment={"PATH": os.environ.get("PATH", "")},
            permission_profile=profile,
        )
        result = await backend.execute(request)
        assert result.status == "passed", result.stderr
        assert (workspace / "inside.txt").read_text() == "ok"
    finally:
        shutil.rmtree(workspace, ignore_errors=True)


def test_windows_workspace_mutation_refuses_missing_dirfd_capability(tmp_path):
    target = tmp_path / "must-not-exist.txt"

    with pytest.raises(SafePathError, match="O_NOFOLLOW/dir_fd"):
        SafeWorkspaceFS(tmp_path)

    assert not target.exists()
