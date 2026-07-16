"""Single execution entry point for terminal, tests, sandbox and LSP."""

from __future__ import annotations

import asyncio
import os
import tempfile
import uuid
from pathlib import Path

from khaos.coding.execution.managed import ManagedProcessHandle
from khaos.coding.execution.models import (
    ExecutionRequest,
    ExecutionResult,
    FileSystemAccess,
    NetworkPolicy,
    PermissionProfile,
    ResolvedExecutionContext,
)
from khaos.coding.execution.supervisor import (
    ProcessSupervisor,
    resource_limit_preexec,
)
from khaos.coding.workspace.models import WorkspaceState


class ExecutionService:
    def __init__(
        self,
        backend=None,
        workspace_manager=None,
        docker_backend=None,
        managed_process_factory=None,
        backend_selector=None,
        process_supervisor: ProcessSupervisor | None = None,
    ) -> None:
        self.process_supervisor = process_supervisor or ProcessSupervisor()
        self.backend = backend
        self.backend_selector = backend_selector
        self.workspace_manager = workspace_manager
        self.docker_backend = docker_backend
        self.managed_process_factory = managed_process_factory
        self._active: dict[str, tuple[str, str, object]] = {}
        self._closed = False
        if self.backend is not None and hasattr(self.backend, "supervisor"):
            self.backend.supervisor = self.process_supervisor
        if self.docker_backend is not None and hasattr(
            self.docker_backend, "supervisor"
        ):
            self.docker_backend.supervisor = self.process_supervisor
        if self.backend_selector is not None:
            self.backend_selector.set_supervisor(self.process_supervisor)

    async def execute(self, request: ExecutionRequest) -> ExecutionResult:
        if self._closed:
            raise RuntimeError("execution service is shut down")
        resolved_context = None
        profile = request.permission_profile
        if profile is None:  # Defensive: ExecutionRequest currently always normalizes this.
            raise PermissionError("execution request has no permission profile")
        # Production runtime services use a per-request selector.  Both read
        # and write requests must then be bound to the active TaskWorkspace;
        # explicitly injected backends are reserved for trusted tests/admin
        # adapters and retain their existing standalone behavior.
        requires_workspace = (
            self.backend_selector is not None
            or profile.filesystem is FileSystemAccess.WORKSPACE_WRITE
        )
        if requires_workspace:
            if self.workspace_manager is None or not request.task_id or not request.workspace_id:
                raise PermissionError(
                    f"{profile.filesystem.value} requires an active TaskWorkspace"
                )
            workspace = self.workspace_manager.get(request.workspace_id)
            if workspace is None or workspace.task_id != request.task_id:
                raise PermissionError("task/workspace binding is invalid")
            if workspace.state in {
                WorkspaceState.CANCELLED,
                WorkspaceState.CLEANING,
                WorkspaceState.CLEANED,
                WorkspaceState.FAILED,
            }:
                raise PermissionError("workspace is not executable")
            root = workspace.worktree_path.resolve()
            cwd = request.cwd.expanduser().resolve()
            if cwd != root and root not in cwd.parents:
                raise PermissionError("cwd is outside the task workspace")
            repository_root = workspace.repository_root.expanduser().resolve()
            if request.backend_hint == "docker":
                if root == repository_root:
                    raise PermissionError("task Worktree cannot be the main repository")
                if not (root / ".git").is_file():
                    raise PermissionError("workspace is not an active Git Worktree")
            correlation_id = request.correlation_id or uuid.uuid4().hex[:12]
            profile = profile.bind_workspace(root)
            profile.validate_resolved()
            request = ExecutionRequest(
                argv=request.argv,
                cwd=cwd,
                environment=request.environment,
                task_id=request.task_id,
                workspace_id=request.workspace_id,
                backend_hint=request.backend_hint,
                correlation_id=correlation_id,
                permission_profile=profile,
            )
            resolved_context = ResolvedExecutionContext(
                request.task_id, request.workspace_id, workspace.state.value,
                repository_root, root, cwd,
                profile.writable_roots, profile.filesystem.value,
                profile.network, profile.resources, request.environment,
                profile.environment_keys, request.argv, correlation_id, profile,
            )
        backend = self.backend_selector.select(
            writable=profile.filesystem is FileSystemAccess.WORKSPACE_WRITE
        ) if self.backend_selector is not None else self.backend
        if backend is None:
            raise PermissionError("execution refused: no execution backend configured")
        if request.backend_hint == "docker":
            if self.docker_backend is None:
                from khaos.coding.execution.docker import DockerBackend

                self.docker_backend = DockerBackend(
                    supervisor=self.process_supervisor
                )
            backend = self.docker_backend
        if request.backend_hint == "docker" and resolved_context is None:
            raise PermissionError("Docker execution requires resolved TaskWorkspace context")
        if resolved_context is not None and hasattr(backend, "execute_resolved"):
            self._active[resolved_context.correlation_id] = (
                resolved_context.task_id, resolved_context.workspace_id, backend
            )
            try:
                result = await backend.execute_resolved(resolved_context)
            finally:
                self._active.pop(resolved_context.correlation_id, None)
        else:
            result = await backend.execute(request)
        return result

    async def terminate(self, execution_id: str) -> None:
        process_terminated = await self.process_supervisor.terminate(execution_id)
        active = self._active.get(execution_id)
        if active is None and process_terminated:
            return
        backend = active[2] if active is not None else self.backend
        if backend is None and self.backend_selector is not None:
            backend = self.backend_selector.select(writable=False)
        if isinstance(backend, ManagedProcessHandle):
            await backend.aclose()
        else:
            await backend.terminate(execution_id)
        self._active.pop(execution_id, None)

    async def start_managed_process(self, request: ExecutionRequest) -> ManagedProcessHandle:
        """Start a registered LSP-style stdio process in an active TaskWorkspace."""
        if self._closed:
            raise RuntimeError("execution service is shut down")
        if not request.task_id or not request.workspace_id or self.workspace_manager is None:
            raise PermissionError("managed process requires an active TaskWorkspace")
        if request.network_policy is not NetworkPolicy.NONE:
            raise PermissionError("managed process network policy must be none")
        if not request.argv:
            raise ValueError("managed process argv must not be empty")
        workspace = self.workspace_manager.get(request.workspace_id)
        if workspace is None or workspace.task_id != request.task_id:
            raise PermissionError("task/workspace binding is invalid")
        if workspace.state not in {WorkspaceState.READY, WorkspaceState.RUNNING, WorkspaceState.VERIFYING}:
            raise PermissionError("workspace is not available for managed process")
        root = workspace.worktree_path.expanduser().resolve()
        cwd = request.cwd.expanduser().resolve()
        if cwd != root and root not in cwd.parents:
            raise PermissionError("managed process cwd is outside the task workspace")
        if not (root / ".git").is_file():
            raise PermissionError("managed process requires an active Git Worktree")
        backend = (
            self.backend_selector.select(writable=False)
            if self.backend_selector is not None
            else self.backend
        )
        if backend is None or (
            self.managed_process_factory is None
            and backend.__class__.__name__ in {"HostExecutionBackend", "UnsupportedBackend"}
        ):
            raise PermissionError("unsupported: managed process backend is unavailable")
        execution_id = request.correlation_id or uuid.uuid4().hex[:12]
        temporary_home = Path(tempfile.mkdtemp(prefix="khaos-lsp-home-"))
        temporary_tmp = temporary_home / "tmp"
        temporary_tmp.mkdir(mode=0o700)
        environment = {
            "PATH": os.environ.get("PATH", ""),
            "LANG": os.environ.get("LANG", "C.UTF-8"),
            "HOME": str(temporary_home),
            "TMPDIR": str(temporary_tmp),
        }
        resolved = ResolvedExecutionContext(
            request.task_id, request.workspace_id, workspace.state.value,
            workspace.repository_root.expanduser().resolve(), root, cwd, (),
            "read-only", NetworkPolicy.NONE, request.budget, environment,
            frozenset(environment), request.argv, execution_id,
            PermissionProfile(
                filesystem=FileSystemAccess.READ_ONLY,
                network=NetworkPolicy.NONE,
                environment_keys=frozenset(environment),
                resources=request.budget,
            ).bind_workspace(root),
        )
        try:
            if self.managed_process_factory is not None:
                handle = await self.managed_process_factory(resolved, temporary_home)
            else:
                argv = self._managed_argv(resolved, backend, temporary_home)
                process = await asyncio.create_subprocess_exec(
                    *argv, cwd=str(cwd), env=environment,
                    stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE, start_new_session=True,
                    preexec_fn=resource_limit_preexec(request.budget),
                )
                watchdog = await self.process_supervisor.register_process(
                    execution_id,
                    process,
                    budget=request.budget,
                    tmp_root=(
                        temporary_home
                        if backend.__class__.__name__ == "MacOSSandboxBackend"
                        else None
                    ),
                    sandbox_storage_paths=(
                        ("/home/khaos", "/tmp")
                        if backend.__class__.__name__ == "LinuxBubblewrapBackend"
                        else ()
                    ),
                )
                handle = ManagedProcessHandle(
                    execution_id, process, temporary_home=temporary_home,
                    stderr_limit=request.budget.output_bytes,
                    supervisor=self.process_supervisor,
                    resource_watchdog=watchdog,
                )
        except Exception:
            import shutil

            shutil.rmtree(temporary_home, ignore_errors=True)
            raise
        self._active[execution_id] = (request.task_id, request.workspace_id, handle)
        return handle

    def _managed_argv(
        self,
        context: ResolvedExecutionContext,
        backend,
        temporary_home: Path,
    ) -> tuple[str, ...]:
        backend_name = backend.__class__.__name__
        if backend_name == "MacOSSandboxBackend":
            sandbox_profile = backend.profile(
                context.worktree_path,
                writable=False,
                unreadable_roots=context.permission_profile.unreadable_roots,
                runtime_roots=backend.runtime_read_roots(
                    context.argv, context.worktree_path
                ),
                synthetic_home=temporary_home,
                synthetic_tmp=temporary_home / "tmp",
            )
            return (
                "/usr/bin/sandbox-exec",
                "-p",
                sandbox_profile,
                *context.argv,
            )
        if backend_name == "LinuxBubblewrapBackend":
            prefix = backend.argv_prefix(
                context.worktree_path,
                cwd=context.cwd,
                writable=False,
                unreadable_roots=context.permission_profile.unreadable_roots,
                synthetic_home=temporary_home,
                resources=context.resources,
                command=context.argv,
                environment=context.environment,
            )
            return (*prefix, "--", *context.argv)
        raise PermissionError("unsupported: managed process backend cannot enforce network isolation")

    async def shutdown(self) -> None:
        if self._closed:
            return
        self._closed = True
        for execution_id in tuple(self._active):
            await self.terminate(execution_id)
        await self.process_supervisor.shutdown()
        if self.docker_backend is not None:
            await self.docker_backend.shutdown()
