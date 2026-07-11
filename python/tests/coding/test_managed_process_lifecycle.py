"""Real process-tree lifecycle evidence for managed Coding processes."""

from __future__ import annotations

import asyncio
import os
import subprocess
import sys
from pathlib import Path

import pytest

from khaos.coding.execution import ExecutionRequest, ExecutionService, HostExecutionBackend, ManagedProcessHandle, ResourceBudget
from khaos.coding.workspace.manager import WorkspaceManager


def _repo(path: Path) -> Path:
    path.mkdir()
    for command in (
        ["git", "init", "-q"],
        ["git", "config", "user.email", "test@example.com"],
        ["git", "config", "user.name", "Test"],
    ):
        subprocess.run(command, cwd=path, check=True)
    (path / "README.md").write_text("base\n", encoding="utf-8")
    subprocess.run(["git", "add", "."], cwd=path, check=True)
    subprocess.run(["git", "commit", "-qm", "base"], cwd=path, check=True)
    return path


async def _eventually_dead(pid: int) -> bool:
    for _ in range(50):
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return True
        await asyncio.sleep(0.05)
    return False


@pytest.mark.asyncio
@pytest.mark.skipif(os.name != "posix", reason="process-group semantics are POSIX-only")
async def test_execution_service_shutdown_terminates_parent_child_and_grandchild(tmp_path: Path):
    repository = _repo(tmp_path / "repo")
    manager = WorkspaceManager(tmp_path / "worktrees")
    workspace = await manager.create(repository, "tree-task")
    pid_file = workspace.worktree_path / "pids.txt"
    child = "import os,time; open('pids.txt','a').write(str(os.getpid())+'\\n'); time.sleep(120)"
    parent = (
        "import os,subprocess,sys,time; "
        "open('pids.txt','w').write(str(os.getpid())+'\\n'); "
        f"subprocess.Popen([sys.executable,'-c',{child!r}]); time.sleep(120)"
    )

    async def spawn(context, temporary_home):
        process = await asyncio.create_subprocess_exec(
            *context.argv,
            cwd=str(context.cwd),
            env=context.environment,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            start_new_session=True,
        )
        return ManagedProcessHandle(context.correlation_id, process, temporary_home=temporary_home)

    service = ExecutionService(HostExecutionBackend(), manager, managed_process_factory=spawn)
    handle = await service.start_managed_process(
        ExecutionRequest(
            (sys.executable, "-c", parent), workspace.worktree_path,
            task_id=workspace.task_id, workspace_id=workspace.id,
            budget=ResourceBudget(timeout_seconds=10),
        )
    )
    for _ in range(50):
        if pid_file.exists() and len(pid_file.read_text(encoding="utf-8").splitlines()) == 2:
            break
        await asyncio.sleep(0.05)
    pids = [int(value) for value in pid_file.read_text(encoding="utf-8").splitlines()]
    assert handle.returncode is None
    await service.shutdown()
    assert service._closed is True
    assert all([await _eventually_dead(pid) for pid in pids])
    assert not handle._temporary_home.exists()
    await service.shutdown()  # idempotent
    with pytest.raises(RuntimeError, match="shut down"):
        await service.start_managed_process(
            ExecutionRequest((sys.executable, "-c", "pass"), workspace.worktree_path, task_id=workspace.task_id, workspace_id=workspace.id)
        )

