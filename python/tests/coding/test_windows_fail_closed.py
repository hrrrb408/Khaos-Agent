"""Real Windows-runner contracts for the native sandbox and fail-closed path."""

from __future__ import annotations

import json
import os
import shutil
import socket
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
    outside = tmp_path / "outside.txt"
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    listener.settimeout(0.2)
    port = listener.getsockname()[1]
    try:
        profile = PermissionProfile(
            filesystem=FileSystemAccess.WORKSPACE_WRITE,
            resources=ResourceBudget(timeout_seconds=20),
        ).bind_workspace(workspace)
        probe = (
            "import json, os, socket, subprocess, sys; "
            "from pathlib import Path; "
            "inside = Path('inside.txt'); inside.write_text('ok'); "
            "outside = Path(sys.argv[1]); "
            "try: outside.write_text('must-not-write'); outside_denied = False\n"
            "except OSError: outside_denied = True\n"
            "try: socket.create_connection(('127.0.0.1', int(sys.argv[2])), 0.5); network_blocked = False\n"
            "except OSError: network_blocked = True\n"
            "try: subprocess.run([os.path.join(os.environ['SystemRoot'], 'System32', 'cmd.exe'), '/c', 'exit', '0'], check=False); descendant_blocked = False\n"
            "except OSError: descendant_blocked = True\n"
            "Path('probe.json').write_text(json.dumps({'inside_written': inside.exists(), 'outside_denied': outside_denied, 'network_blocked': network_blocked, 'descendant_blocked': descendant_blocked}))"
        )
        request = ExecutionRequest(
            (sys.executable, "-c", probe, str(outside), str(port)),
            workspace,
            environment={"PATH": os.environ.get("PATH", "")},
            permission_profile=profile,
        )
        result = await backend.execute(request)
        assert result.status == "passed", (
            f"{result.stderr}; duration_ms={result.duration_ms}; "
            f"diagnostics={result.diagnostics}"
        )
        assert (workspace / "inside.txt").read_text() == "ok"
        evidence = json.loads((workspace / "probe.json").read_text())
        assert evidence == {
            "inside_written": True,
            "outside_denied": True,
            "network_blocked": True,
            "descendant_blocked": True,
        }
        with pytest.raises(socket.timeout):
            listener.accept()
    finally:
        listener.close()
        shutil.rmtree(workspace, ignore_errors=True)


def test_windows_workspace_mutation_refuses_missing_dirfd_capability(tmp_path):
    target = tmp_path / "must-not-exist.txt"

    with pytest.raises(SafePathError, match="O_NOFOLLOW/dir_fd"):
        SafeWorkspaceFS(tmp_path)

    assert not target.exists()
