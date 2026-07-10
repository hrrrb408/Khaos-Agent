"""Docker sandbox tools for isolated command execution."""

from __future__ import annotations

import asyncio
import shlex
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass
class SandboxConfig:
    """Sandbox resource and isolation configuration."""

    image: str = "python:3.13-slim"
    project_dir: str = "."
    network: bool = False
    cpus: float = 1.0
    memory: str = "512m"
    timeout: int = 30
    pids_limit: int = 256
    tmp_mb: int = 256


class DockerSandboxClient:
    """Small async wrapper around the Docker CLI."""

    async def create(self, config: SandboxConfig) -> str:
        """Create a stopped container and return its id."""
        project_dir = str(Path(config.project_dir).expanduser().resolve())
        command = [
            "docker",
            "create",
            "--rm",
            "--read-only",
            "--tmpfs",
            f"/tmp:rw,noexec,nosuid,nodev,size={config.tmp_mb}m",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--pids-limit",
            str(config.pids_limit),
            "--network",
            "none" if not config.network else "bridge",
            "--cpus",
            str(config.cpus),
            "--memory",
            config.memory,
            "-v",
            f"{project_dir}:/workspace:rw",
            "-w",
            "/workspace",
            config.image,
            "sleep",
            "3600",
        ]
        result = await _run_exec(command, timeout=config.timeout)
        if result["returncode"] != 0:
            raise RuntimeError(result["stderr"] or result["stdout"])
        return result["stdout"].strip()

    async def start(self, container_id: str, timeout: int) -> None:
        result = await _run_exec(["docker", "start", container_id], timeout=timeout)
        if result["returncode"] != 0:
            raise RuntimeError(result["stderr"] or result["stdout"])

    async def exec(self, container_id: str, command: str, timeout: int) -> dict[str, Any]:
        return await _run_exec(
            ["docker", "exec", container_id, "sh", "-lc", command],
            timeout=timeout,
        )

    async def stop(self, container_id: str, timeout: int) -> None:
        await _run_exec(["docker", "stop", container_id], timeout=timeout)

    async def remove(self, container_id: str, timeout: int) -> None:
        await _run_exec(["docker", "rm", "-f", container_id], timeout=timeout)

    async def build(
        self,
        dockerfile: str,
        context: str,
        tag: str,
        timeout: int,
    ) -> dict[str, Any]:
        return await _run_exec(
            [
                "docker",
                "build",
                "-f",
                str(Path(dockerfile).expanduser().resolve()),
                "-t",
                tag,
                str(Path(context).expanduser().resolve()),
            ],
            timeout=timeout,
        )


async def sandbox_exec(
    command: str,
    image: str = "python:3.13-slim",
    project_dir: str = ".",
    network: bool = False,
    cpus: float = 1.0,
    memory: str = "512m",
    timeout: int = 30,
    client: DockerSandboxClient | None = None,
) -> dict[str, Any]:
    """Create a Docker sandbox, execute a command, then destroy it."""
    _validate_command(command)
    config = SandboxConfig(image, project_dir, network, cpus, memory, timeout)
    docker = client or DockerSandboxClient()
    container_id = ""
    try:
        container_id = await docker.create(config)
        await docker.start(container_id, timeout)
        result = await docker.exec(container_id, command, timeout)
        return {
            "container_id": container_id,
            "command": command,
            "network": network,
            "returncode": result["returncode"],
            "stdout": result["stdout"],
            "stderr": result["stderr"],
        }
    finally:
        if container_id:
            try:
                await docker.stop(container_id, timeout)
            finally:
                await docker.remove(container_id, timeout)


async def sandbox_build(
    dockerfile: str,
    context: str = ".",
    tag: str = "khaos-sandbox:latest",
    timeout: int = 120,
    client: DockerSandboxClient | None = None,
) -> dict[str, Any]:
    """Build a Docker image for sandbox use."""
    docker = client or DockerSandboxClient()
    result = await docker.build(dockerfile, context, tag, timeout)
    return {
        "tag": tag,
        "returncode": result["returncode"],
        "stdout": result["stdout"],
        "stderr": result["stderr"],
    }


async def _run_exec(args: list[str], timeout: int) -> dict[str, Any]:
    process = await asyncio.create_subprocess_exec(
        *args,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=timeout)
    except asyncio.TimeoutError as exc:
        process.kill()
        await process.wait()
        raise TimeoutError(f"docker command timed out after {timeout}s") from exc
    return {
        "args": args,
        "returncode": int(process.returncode or 0),
        "stdout": stdout.decode("utf-8", errors="replace"),
        "stderr": stderr.decode("utf-8", errors="replace"),
    }


def _validate_command(command: str) -> None:
    if not shlex.split(command):
        raise ValueError("command must not be empty")


def validate_task_workspace(workspace_path: str | Path, repository_root: str | Path) -> Path:
    """Reject Docker mounts that are not an active task Worktree path."""
    workspace = Path(workspace_path).expanduser().resolve()
    repository = Path(repository_root).expanduser().resolve()
    if workspace == repository or repository in workspace.parents:
        raise PermissionError("Docker sandbox cannot mount the main repository")
    if not (workspace / ".git").exists() and not (workspace / ".git").is_file():
        raise PermissionError("Docker sandbox requires an active Git Worktree")
    return workspace
