"""Agent-facing Docker sandbox tools routed through ExecutionService."""

from __future__ import annotations

import re
import shlex
from pathlib import Path
from typing import Any

from khaos.coding.execution.docker import DEFAULT_DOCKER_IMAGE
from khaos.coding.execution.models import ExecutionRequest, NetworkPolicy, ResourceBudget


_MEMORY_PATTERN = re.compile(r"^(\d+)([kKmMgG])$")


async def sandbox_exec(
    command: str,
    image: str = DEFAULT_DOCKER_IMAGE,
    project_dir: str = ".",
    network: bool = False,
    cpus: float = 1.0,
    memory: str = "512m",
    timeout: int = 30,
    client: Any = None,
    execution_service=None,
    workspace_manager=None,
    task_id: str | None = None,
    workspace_id: str | None = None,
) -> dict[str, Any]:
    """Execute fixed argv inside the active TaskWorkspace Docker sandbox."""
    argv = tuple(shlex.split(command))
    if not argv:
        raise ValueError("command must not be empty")
    if client is not None:
        raise PermissionError("direct Docker clients are unavailable to Agent tools")
    if execution_service is None or not task_id or not workspace_id:
        raise PermissionError("sandbox_exec requires an active TaskWorkspace")
    workspace = execution_service.workspace_manager.get(workspace_id)
    if workspace is None or workspace.task_id != task_id:
        raise PermissionError("task/workspace binding is invalid")
    root = workspace.worktree_path.expanduser().resolve()
    if project_dir not in {"", "."} and Path(project_dir).expanduser().resolve() != root:
        raise PermissionError("project_dir must match the active TaskWorkspace")
    if network:
        raise PermissionError("unsupported: sandbox_exec network access is disabled")
    if not 0.1 <= cpus <= 8.0:
        raise ValueError("cpus must be between 0.1 and 8.0")
    if not 1 <= timeout <= 3600:
        raise ValueError("timeout must be between 1 and 3600 seconds")
    memory_bytes = _parse_memory(memory)
    request = ExecutionRequest(
        argv=argv,
        cwd=root,
        environment={"KHAOS_DOCKER_IMAGE": image},
        allowed_environment_keys=frozenset({"KHAOS_DOCKER_IMAGE"}),
        network_policy=NetworkPolicy.NONE,
        budget=ResourceBudget(
            timeout_seconds=float(timeout), output_bytes=65536, pids=256,
            cpu_count=cpus, memory_bytes=memory_bytes, tmpfs_bytes=256 * 1024 * 1024,
        ),
        task_id=task_id,
        workspace_id=workspace_id,
        access_mode="workspace-write",
        backend_hint="docker",
    )
    result = await execution_service.execute(request)
    return {
        "container_id": str(result.diagnostics.get("container_id", "")),
        "command": command,
        "network": False,
        "returncode": result.return_code if result.return_code is not None else -1,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "backend": "docker",
        "workspace_id": workspace_id,
        "cleanup": result.diagnostics.get("cleanup", "unknown"),
    }


async def sandbox_build(
    dockerfile: str,
    context: str = ".",
    tag: str = "khaos-sandbox:latest",
    timeout: int = 120,
    client: Any = None,
) -> dict[str, Any]:
    """Reject Agent-triggered image builds; images are administrator-managed."""
    return {
        "tag": tag,
        "returncode": -1,
        "stdout": "",
        "stderr": "unsupported: sandbox image builds are internal maintenance operations",
    }


def _parse_memory(value: str) -> int:
    match = _MEMORY_PATTERN.fullmatch(value)
    if match is None:
        raise ValueError("memory must use k, m, or g units")
    amount = int(match.group(1))
    multiplier = {"k": 1024, "m": 1024**2, "g": 1024**3}[match.group(2).lower()]
    result = amount * multiplier
    if not 64 * 1024**2 <= result <= 16 * 1024**3:
        raise ValueError("memory must be between 64m and 16g")
    return result


def validate_task_workspace(workspace_path: str | Path, repository_root: str | Path) -> Path:
    """Compatibility helper for internal mount validation; handlers use WorkspaceManager."""
    workspace = Path(workspace_path).expanduser().resolve()
    repository = Path(repository_root).expanduser().resolve()
    if workspace == repository:
        raise PermissionError("Docker sandbox cannot mount the main repository")
    if not (workspace / ".git").is_file():
        raise PermissionError("Docker sandbox requires an active Git Worktree")
    return workspace
