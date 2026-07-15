"""Docker execution backend consuming only resolved TaskWorkspace contexts."""

from __future__ import annotations

import asyncio
import os
import re
import secrets
import tempfile
import uuid
from dataclasses import dataclass, field
from pathlib import Path

from khaos.coding.execution.models import (
    ExecutionRequest,
    ExecutionResult,
    NetworkPolicy,
    ResolvedExecutionContext,
    ResourceBudget,
)
from khaos.coding.execution.supervisor import ProcessSupervisor


_DENIED_ENV_KEYS = frozenset({
    "HOME", "SSH_AUTH_SOCK", "GH_TOKEN", "GITHUB_TOKEN", "DOCKER_HOST",
    "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "LD_PRELOAD", "DYLD_INSERT_LIBRARIES",
    "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "GOOGLE_APPLICATION_CREDENTIALS",
})
DEFAULT_DOCKER_IMAGE = (
    "python@sha256:eb43ff125d8d58d7449dcba7d336c23bcac412f526d861db493b9994d8010280"
)
_DIGEST_PINNED_IMAGE = re.compile(
    r"^[a-z0-9][a-z0-9._/-]*(?::[a-zA-Z0-9._-]+)?@sha256:[0-9a-f]{64}$"
)
_SAFE_EXECUTION_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
_OWNER_LABEL = "io.khaos.owner-nonce"


@dataclass
class _ContainerLease:
    name: str
    owner_nonce: str
    cleanup_lock: asyncio.Lock = field(default_factory=asyncio.Lock)


class DockerBackend:
    """Run fixed-argv commands in hardened, ephemeral Docker containers."""

    name = "docker"

    def __init__(
        self,
        *,
        allowed_images: set[str] | None = None,
        docker_binary: str = "docker",
        supervisor: ProcessSupervisor | None = None,
    ) -> None:
        self.allowed_images = frozenset(
            allowed_images or {DEFAULT_DOCKER_IMAGE}
        )
        if not self.allowed_images or any(
            _DIGEST_PINNED_IMAGE.fullmatch(image) is None
            for image in self.allowed_images
        ):
            raise ValueError(
                "Docker image allowlist entries must be pinned by sha256 digest"
            )
        self.docker_binary = docker_binary
        self.supervisor = supervisor or ProcessSupervisor()
        self._active: dict[str, _ContainerLease] = {}
        self._lock = asyncio.Lock()

    async def execute_resolved(self, context: ResolvedExecutionContext) -> ExecutionResult:
        self._validate_context(context)
        image = _image_from_environment(context.environment)
        if image not in self.allowed_images:
            raise PermissionError("Docker image is not in the configured allowlist")
        if _DIGEST_PINNED_IMAGE.fullmatch(image) is None:
            raise PermissionError("Docker image must be pinned by sha256 digest")
        inspected = await self._run_cli(("image", "inspect", image), timeout=10)
        if inspected[0] != 0:
            raise PermissionError("Docker image is unavailable locally; automatic pull is disabled")

        execution_id = context.correlation_id
        if _SAFE_EXECUTION_ID.fullmatch(execution_id) is None:
            raise PermissionError("execution id is unsafe for a container name")
        container_name = f"khaos-{execution_id}"
        lease = _ContainerLease(container_name, secrets.token_hex(16))
        relative_cwd = context.cwd.relative_to(context.worktree_path)
        container_cwd = Path("/workspace") / relative_cwd
        argv = [
            self.docker_binary, "run", "--name", container_name, "--rm",
            "--pull", "never", "--init", "--ipc", "none",
            "--label", f"{_OWNER_LABEL}={lease.owner_nonce}",
            "--label", f"io.khaos.execution={execution_id}",
            "--read-only", "--tmpfs", f"/tmp:rw,noexec,nosuid,nodev,size={context.budget.tmpfs_bytes}",
            "--user", "65534:65534", "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges", "--pids-limit", str(context.budget.pids),
            "--cpus", str(context.budget.cpu_count), "--memory", str(context.budget.memory_bytes),
            "--network", "none", "--mount",
            f"type=bind,src={context.worktree_path},dst=/workspace",
            "--workdir", str(container_cwd),
        ]
        env_file = self._write_env_file(context)
        if env_file is not None:
            argv.extend(["--env-file", str(env_file)])
        argv.extend([image, *context.argv])

        async with self._lock:
            self._active[execution_id] = lease
        diagnostics: dict[str, object] = {
            "container_id": container_name,
            "cleanup": "pending",
        }
        try:
            docker_request = ExecutionRequest(
                argv=tuple(argv),
                cwd=context.cwd,
                permission_profile=context.permission_profile,
                correlation_id=execution_id,
            )
            result = await self.supervisor.run(
                docker_request,
                cwd=context.cwd,
                env={"PATH": os.environ.get("PATH", "")},
            )
            diagnostics.update(result.diagnostics)
            return ExecutionResult(
                execution_id=execution_id,
                status=result.status,
                return_code=result.return_code,
                stdout=result.stdout,
                stderr=result.stderr,
                duration_ms=result.duration_ms,
                diagnostics=diagnostics,
            )
        finally:
            try:
                await self._cleanup_container(lease)
                diagnostics["cleanup"] = "removed"
            finally:
                async with self._lock:
                    self._active.pop(execution_id, None)
                if env_file is not None:
                    env_file.unlink(missing_ok=True)

    async def execute(self, request):
        raise PermissionError("DockerBackend requires ResolvedExecutionContext")

    async def terminate(self, execution_id: str) -> None:
        await self.supervisor.terminate(execution_id)
        async with self._lock:
            lease = self._active.get(execution_id)
        if lease is not None:
            await self._cleanup_container(lease)

    async def shutdown(self) -> None:
        await self.supervisor.shutdown()
        async with self._lock:
            active = tuple(self._active.values())
        for lease in active:
            await self._cleanup_container(lease)

    def _validate_context(self, context: ResolvedExecutionContext) -> None:
        profile = context.permission_profile
        if profile is None:
            raise PermissionError("Docker execution requires a permission profile")
        profile.validate_resolved()
        if context.access_mode != profile.filesystem.value:
            raise PermissionError("resolved access mode differs from permission profile")
        if context.network_policy is not profile.network:
            raise PermissionError("resolved network policy differs from permission profile")
        if context.writable_roots != profile.writable_roots:
            raise PermissionError("resolved writable roots differ from permission profile")
        if context.allowed_environment_keys != profile.environment_keys:
            raise PermissionError("resolved environment keys differ from permission profile")
        if context.budget != profile.resources:
            raise PermissionError("resolved resource budget differs from permission profile")
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
        if any(character in str(context.worktree_path) for character in (",", "\n", "\r", "\x00")):
            raise PermissionError("Docker workspace path is unsafe for mount syntax")
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

    async def _cleanup_container(self, lease: _ContainerLease) -> None:
        async with lease.cleanup_lock:
            inspected = await self._run_cli(
                (
                    "inspect",
                    "--format",
                    f'{{{{ index .Config.Labels "{_OWNER_LABEL}" }}}}',
                    lease.name,
                ),
                timeout=5,
            )
            if inspected[0] != 0:
                return
            if inspected[1].strip() != lease.owner_nonce:
                raise PermissionError(
                    "refusing to clean up a container not owned by this execution"
                )
            await self._run_cli(("stop", "--time", "2", lease.name), timeout=5)
            await self._run_cli(("kill", lease.name), timeout=5)
            await self._run_cli(("rm", "-f", lease.name), timeout=5)
            verified = await self._run_cli(
                ("inspect", lease.name), timeout=5
            )
            if verified[0] == 0:
                raise RuntimeError(
                    "Docker container cleanup could not be verified"
                )

    async def _run_cli(self, args: tuple[str, ...], *, timeout: float) -> tuple[int, str, str]:
        try:
            result = await self.supervisor.run(
                ExecutionRequest(
                    (self.docker_binary, *args),
                    Path.cwd(),
                    budget=ResourceBudget(
                        timeout_seconds=timeout,
                        output_bytes=16 * 1024,
                    ),
                    correlation_id=f"docker-cli-{uuid.uuid4().hex[:12]}",
                ),
                env={"PATH": os.environ.get("PATH", "")},
            )
        except FileNotFoundError:
            return -1, "", "Docker CLI not installed"
        if result.status == "timed-out":
            return -1, "", "Docker CLI timed out"
        return (
            int(result.return_code if result.return_code is not None else -1),
            result.stdout,
            result.stderr,
        )


def _image_from_environment(environment: dict[str, str]) -> str:
    return environment.get("KHAOS_DOCKER_IMAGE", DEFAULT_DOCKER_IMAGE)
