"""Single execution entry point for terminal, tests, sandbox and LSP."""

from __future__ import annotations

import asyncio
import os
import tempfile
import uuid
from pathlib import Path

from khaos.coding.execution.managed import ManagedProcessHandle
from khaos.coding.execution.models import ExecutionRequest, ExecutionResult, NetworkPolicy, ResolvedExecutionContext
from khaos.coding.workspace.models import WorkspaceState


class ExecutionService:
    def __init__(self, backend, workspace_manager=None, docker_backend=None, managed_process_factory=None) -> None:
        self.backend = backend
        self.workspace_manager = workspace_manager
        self.docker_backend = docker_backend
        self.managed_process_factory = managed_process_factory
        self._active: dict[str, tuple[str, str, object]] = {}
        self._closed = False

    async def execute(self, request: ExecutionRequest) -> ExecutionResult:
        if self._closed:
            raise RuntimeError("execution service is shut down")
        resolved_context = None
        if request.access_mode == "workspace-write":
            if self.workspace_manager is None or not request.task_id or not request.workspace_id:
                raise PermissionError("workspace-write requires an active TaskWorkspace")
            workspace = self.workspace_manager.get(request.workspace_id)
            if workspace is None or workspace.task_id != request.task_id:
                raise PermissionError("task/workspace binding is invalid")
            if workspace.state in {WorkspaceState.CANCELLED, WorkspaceState.CLEANING, WorkspaceState.CLEANED, WorkspaceState.FAILED}:
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
            request = ExecutionRequest(
                request.argv, cwd, (root,), request.environment,
                request.allowed_environment_keys, request.network_policy,
                request.budget, request.task_id, request.workspace_id,
                request.access_mode, request.backend_hint, correlation_id,
            )
            resolved_context = ResolvedExecutionContext(
                request.task_id, request.workspace_id, workspace.state.value,
                repository_root, root, cwd, (root,), request.access_mode,
                request.network_policy, request.budget, request.environment,
                request.allowed_environment_keys, request.argv, correlation_id,
            )
        backend = self.backend
        if request.backend_hint == "docker":
            if self.docker_backend is None:
                from khaos.coding.execution.docker import DockerBackend

                self.docker_backend = DockerBackend()
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
        active = self._active.get(execution_id)
        backend = active[2] if active is not None else self.backend
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
        if self.managed_process_factory is None and self.backend.__class__.__name__ in {"HostExecutionBackend", "UnsupportedBackend"}:
            raise PermissionError("unsupported: managed process backend is unavailable")
        execution_id = request.correlation_id or uuid.uuid4().hex[:12]
        temporary_home = Path(tempfile.mkdtemp(prefix="khaos-lsp-home-"))
        environment = {
            "PATH": os.environ.get("PATH", ""),
            "LANG": os.environ.get("LANG", "C.UTF-8"),
            "HOME": str(temporary_home),
            "TMPDIR": tempfile.gettempdir(),
        }
        resolved = ResolvedExecutionContext(
            request.task_id, request.workspace_id, workspace.state.value,
            workspace.repository_root.expanduser().resolve(), root, cwd, (),
            "read-only", NetworkPolicy.NONE, request.budget, environment,
            frozenset(environment), request.argv, execution_id,
        )
        try:
            if self.managed_process_factory is not None:
                handle = await self.managed_process_factory(resolved, temporary_home)
            else:
                argv = self._managed_argv(resolved)
                process = await asyncio.create_subprocess_exec(
                    *argv, cwd=str(cwd), env=environment,
                    stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE, start_new_session=True,
                )
                handle = ManagedProcessHandle(
                    execution_id, process, temporary_home=temporary_home,
                    stderr_limit=request.budget.output_bytes,
                )
        except Exception:
            import shutil

            shutil.rmtree(temporary_home, ignore_errors=True)
            raise
        self._active[execution_id] = (request.task_id, request.workspace_id, handle)
        return handle

    def _managed_argv(self, context: ResolvedExecutionContext) -> tuple[str, ...]:
        backend_name = self.backend.__class__.__name__
        if backend_name == "MacOSSandboxBackend":
            return ("sandbox-exec", "-p", self.backend.profile(context.worktree_path), *context.argv)
        if backend_name == "LinuxBubblewrapBackend":
            return (*self.backend.argv_prefix(context.worktree_path), *context.argv)
        raise PermissionError("unsupported: managed process backend cannot enforce network isolation")

    async def shutdown(self) -> None:
        if self._closed:
            return
        self._closed = True
        for execution_id in tuple(self._active):
            await self.terminate(execution_id)
        if self.docker_backend is not None:
            await self.docker_backend.shutdown()
