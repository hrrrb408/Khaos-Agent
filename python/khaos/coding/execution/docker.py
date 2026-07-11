"""Docker execution backend consuming only resolved TaskWorkspace contexts."""

from __future__ import annotations

import asyncio
import os
import tempfile
import time
from pathlib import Path

from khaos.coding.execution.models import ExecutionResult, NetworkPolicy, ResolvedExecutionContext


_DENIED_ENV_KEYS = frozenset({
    "HOME", "SSH_AUTH_SOCK", "GH_TOKEN", "GITHUB_TOKEN", "DOCKER_HOST",
    "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "LD_PRELOAD", "DYLD_INSERT_LIBRARIES",
    "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "GOOGLE_APPLICATION_CREDENTIALS",
})


class DockerBackend:
    """Run fixed-argv commands in hardened, ephemeral Docker containers."""

    name = "docker"

    def __init__(self, *, allowed_images: set[str] | None = None, docker_binary: str = "docker") -> None:
        self.allowed_images = frozenset(allowed_images or {"python:3.13-slim"})
        self.docker_binary = docker_binary
        self._active: dict[str, str] = {}
        self._artifacts: set[Path] = set()
        self._lock = asyncio.Lock()

    async def execute_resolved(self, context: ResolvedExecutionContext) -> ExecutionResult:
        self._validate_context(context)
        image = _image_from_environment(context.environment)
        if image not in self.allowed_images:
            raise PermissionError("Docker image is not in the configured allowlist")
        inspected = await self._run_cli(("image", "inspect", image), timeout=10)
        if inspected[0] != 0:
            raise PermissionError("Docker image is unavailable locally; automatic pull is disabled")

        execution_id = context.correlation_id
        container_name = f"khaos-{execution_id}"
        relative_cwd = context.cwd.relative_to(context.worktree_path)
        container_cwd = Path("/workspace") / relative_cwd
        argv = [
            self.docker_binary, "run", "--name", container_name, "--rm",
            "--read-only", "--tmpfs", f"/tmp:rw,noexec,nosuid,nodev,size={context.budget.tmpfs_bytes}",
            "--user", "65534:65534", "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges", "--pids-limit", str(context.budget.pids),
            "--cpus", str(context.budget.cpu_count), "--memory", str(context.budget.memory_bytes),
            "--network", "none", "--mount",
            f"type=bind,src={context.worktree_path},dst=/workspace,rw",
            "--workdir", str(container_cwd),
        ]
        env_file = self._write_env_file(context)
        if env_file is not None:
            argv.extend(["--env-file", str(env_file)])
        argv.extend([image, *context.argv])

        started = time.monotonic()
        process = await asyncio.create_subprocess_exec(
            *argv,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            start_new_session=True,
        )
        async with self._lock:
            self._active[execution_id] = container_name
        status = "failed"
        return_code = None
        diagnostics: dict[str, object] = {"container_id": container_name, "cleanup": "pending"}
        try:
            try:
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(), timeout=context.budget.timeout_seconds
                )
                return_code = process.returncode
                status = "passed" if return_code == 0 else "failed"
            except asyncio.TimeoutError:
                stdout, stderr = b"", b"docker execution timed out"
                status = "timed-out"
                await self._cleanup_container(container_name)
                if process.returncode is None:
                    process.kill()
                    await process.wait()
            limit = context.budget.output_bytes
            combined_size = len(stdout) + len(stderr)
            if combined_size > limit:
                artifact = self._write_output_artifact(execution_id, stdout, stderr)
                diagnostics.update({
                    "output_truncated": True,
                    "output_bytes_dropped": combined_size - limit,
                    "output_artifact": str(artifact),
                })
            stdout_limit = min(len(stdout), limit)
            stderr_limit = max(0, limit - stdout_limit)
            return ExecutionResult(
                execution_id, status, return_code,
                stdout[:stdout_limit].decode("utf-8", errors="replace"),
                stderr[:stderr_limit].decode("utf-8", errors="replace"),
                int((time.monotonic() - started) * 1000), diagnostics,
            )
        finally:
            await self._cleanup_container(container_name)
            diagnostics["cleanup"] = "removed"
            async with self._lock:
                self._active.pop(execution_id, None)
            if env_file is not None:
                env_file.unlink(missing_ok=True)

    async def execute(self, request):
        raise PermissionError("DockerBackend requires ResolvedExecutionContext")

    async def terminate(self, execution_id: str) -> None:
        async with self._lock:
            container_name = self._active.get(execution_id)
        if container_name is not None:
            await self._cleanup_container(container_name)

    async def shutdown(self) -> None:
        async with self._lock:
            active = tuple(self._active.values())
        for container_name in active:
            await self._cleanup_container(container_name)
        for artifact in tuple(self._artifacts):
            artifact.unlink(missing_ok=True)
            self._artifacts.discard(artifact)

    def _validate_context(self, context: ResolvedExecutionContext) -> None:
        if context.workspace_state not in {"ready", "running", "verifying"}:
            raise PermissionError("Docker execution requires an active writable Workspace state")
        if context.access_mode != "workspace-write":
            raise PermissionError("Docker execution requires workspace-write access")
        if context.network_policy is not NetworkPolicy.NONE:
            raise PermissionError("unsupported Docker network policy")
        if context.worktree_path == context.repository_root:
            raise PermissionError("main repository cannot be mounted read-write")
        if context.writable_roots != (context.worktree_path,):
            raise PermissionError("Docker writable roots must equal the active TaskWorkspace")
        if context.cwd != context.worktree_path and context.worktree_path not in context.cwd.parents:
            raise PermissionError("Docker cwd is outside the active TaskWorkspace")
        if not (context.worktree_path / ".git").is_file():
            raise PermissionError("Docker mount is not an active Git Worktree")
        if not context.argv:
            raise ValueError("Docker argv must not be empty")
        if _DENIED_ENV_KEYS & context.allowed_environment_keys:
            raise PermissionError("Docker environment allowlist contains sensitive keys")

    def _write_env_file(self, context: ResolvedExecutionContext) -> Path | None:
        values = {
            key: value for key, value in context.environment.items()
            if key in context.allowed_environment_keys
        }
        values.pop("KHAOS_DOCKER_IMAGE", None)
        if not values:
            return None
        descriptor, name = tempfile.mkstemp(prefix="khaos-docker-env-")
        path = Path(name)
        try:
            os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
                for key, value in values.items():
                    if "\n" in key or "\n" in value:
                        raise ValueError("Docker environment values must be single-line")
                    stream.write(f"{key}={value}\n")
        except Exception:
            path.unlink(missing_ok=True)
            raise
        return path

    def _write_output_artifact(self, execution_id: str, stdout: bytes, stderr: bytes) -> Path:
        descriptor, name = tempfile.mkstemp(prefix=f"khaos-docker-{execution_id}-", suffix=".log")
        path = Path(name)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(stdout)
            stream.write(b"\n--- stderr ---\n")
            stream.write(stderr)
        self._artifacts.add(path)
        return path

    async def _cleanup_container(self, container_name: str) -> None:
        await self._run_cli(("stop", "--time", "2", container_name), timeout=5)
        await self._run_cli(("kill", container_name), timeout=5)
        await self._run_cli(("rm", "-f", container_name), timeout=5)
        inspected = await self._run_cli(("inspect", container_name), timeout=5)
        if inspected[0] == 0:
            raise RuntimeError("Docker container cleanup could not be verified")

    async def _run_cli(self, args: tuple[str, ...], *, timeout: float) -> tuple[int, str, str]:
        try:
            process = await asyncio.create_subprocess_exec(
                self.docker_binary, *args,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        except FileNotFoundError:
            return -1, "", "Docker CLI not installed"
        try:
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=timeout)
        except asyncio.TimeoutError:
            process.kill()
            await process.wait()
            return -1, "", "Docker CLI timed out"
        return (
            int(process.returncode or 0),
            stdout.decode("utf-8", errors="replace"),
            stderr.decode("utf-8", errors="replace"),
        )


def _image_from_environment(environment: dict[str, str]) -> str:
    return environment.get("KHAOS_DOCKER_IMAGE", "python:3.13-slim")
