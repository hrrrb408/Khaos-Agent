"""Single execution entry point for terminal, tests, sandbox and LSP."""

from __future__ import annotations

import asyncio
import logging
import os
import tempfile
import uuid
from collections.abc import Awaitable, Callable
from dataclasses import replace
from enum import Enum
from pathlib import Path

logger = logging.getLogger(__name__)


class _ShutdownState(str, Enum):
    """Terminal state of ExecutionService shutdown (round-13 review P0-1)."""

    OPEN = "open"
    CLOSING = "closing"
    CLOSED = "closed"
    QUARANTINED = "quarantined"


class ExecutionServiceShutdownError(RuntimeError):
    """Typed error when shutdown partially fails (round-13 P0-1)."""

from khaos.coding.execution.binding import open_execution_directory_binding
from khaos.coding.execution.managed import ManagedProcessHandle
from khaos.coding.execution.models import (
    ExecutionRequest,
    ExecutionResult,
    FileSystemAccess,
    NetworkPolicy,
    PermissionProfile,
    ResolvedExecutionContext,
)
from khaos.coding.execution.native_launcher import build_process_launch
from khaos.coding.execution.supervisor import (
    ProcessSupervisor,
)
from khaos.coding.workspace.models import WorkspaceState
from khaos.coding.workspace.storage import (
    WorkspaceStorageLimits,
    capture_workspace_snapshot,
)


class ExecutionService:
    def __init__(
        self,
        backend=None,
        workspace_manager=None,
        docker_backend=None,
        managed_process_factory=None,
        backend_selector=None,
        process_supervisor: ProcessSupervisor | None = None,
        principal_id: str = "legacy",
        project_id: str = "",
        runtime_id: str = "",
    ) -> None:
        self.process_supervisor = process_supervisor or ProcessSupervisor()
        self.backend = backend
        self.backend_selector = backend_selector
        self.workspace_manager = workspace_manager
        self.docker_backend = docker_backend
        self.managed_process_factory = managed_process_factory
        self._active: dict[str, tuple[str, str, object]] = {}
        # Round-13 review P0-1: typed shutdown state machine (same pattern as
        # RuntimeResult and ManagedProcess).  ``_closed`` is a backward-compat
        # property that reads ``_shutdown_state``.
        self._shutdown_task: asyncio.Task[None] | None = None
        self._shutdown_state = _ShutdownState.OPEN
        self._shutdown_error: BaseException | None = None
        self.principal_id = principal_id
        self.project_id = project_id
        self.runtime_id = runtime_id
        self._authority_bound = False
        if self.workspace_manager is not None and hasattr(
            self.workspace_manager, "storage_authority"
        ):
            self.process_supervisor.storage_authority = (
                self.workspace_manager.storage_authority
            )
        if self.backend is not None and hasattr(self.backend, "supervisor"):
            self.backend.supervisor = self.process_supervisor
        if self.docker_backend is not None and hasattr(
            self.docker_backend, "supervisor"
        ):
            self.docker_backend.supervisor = self.process_supervisor
        if self.backend_selector is not None:
            self.backend_selector.set_supervisor(self.process_supervisor)

    @property
    def _closed(self) -> bool:
        """Backward-compat: True only when cleanly CLOSED (not QUARANTINED)."""
        return self._shutdown_state is _ShutdownState.CLOSED

    def bind_runtime_authority(
        self, *, principal_id: str, project_id: str, runtime_id: str
    ) -> None:
        """Bind this service once to one runtime authority tuple."""
        authority = (principal_id, project_id, runtime_id)
        current = (self.principal_id, self.project_id, self.runtime_id)
        if self._authority_bound and current != authority:
            raise PermissionError(
                "ExecutionService cannot be shared across runtime authorities"
            )
        if self._active:
            raise RuntimeError("cannot bind ExecutionService with active executions")
        self.principal_id, self.project_id, self.runtime_id = authority
        self._authority_bound = True

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
            workspace = self.workspace_manager.require(
                request.workspace_id,
                task_id=request.task_id,
                principal_id=self.principal_id,
                project_id=self.project_id,
                runtime_id=self.runtime_id,
            )
            if workspace.state in {
                WorkspaceState.CANCELLED,
                WorkspaceState.CLEANING,
                WorkspaceState.CLEANED,
                WorkspaceState.FAILED,
            }:
                raise PermissionError("workspace is not executable")
            await self.workspace_manager.verify_git_identity(request.workspace_id)
            # Keep the workspace/cwd paths lexical after the authority check.
            # The final backend launch pins both directories with O_NOFOLLOW
            # directory handles; resolving here would create another
            # symlink-following lookup in the TOCTOU window.
            root = workspace.worktree_path.expanduser().absolute()
            cwd = request.cwd.expanduser().absolute()
            root_info = os.stat(root, follow_symlinks=False)
            cwd_info = os.stat(cwd, follow_symlinks=False)
            root_identity = (int(root_info.st_dev), int(root_info.st_ino))
            cwd_identity = (int(cwd_info.st_dev), int(cwd_info.st_ino))
            if cwd != root and root not in cwd.parents:
                raise PermissionError("cwd is outside the task workspace")
            repository_root = workspace.repository_root.expanduser().absolute()
            storage_limits = getattr(
                workspace, "storage_limits", WorkspaceStorageLimits()
            )
            storage_baseline = getattr(workspace, "storage_baseline", None)
            if storage_baseline is None:
                storage_baseline = await asyncio.to_thread(
                    capture_workspace_snapshot, root
                )
                workspace.storage_baseline = storage_baseline
            if not storage_baseline.complete:
                raise PermissionError(
                    "TaskWorkspace storage baseline is incomplete"
                )
            if request.backend_hint == "docker":
                if root == repository_root:
                    raise PermissionError("task Worktree cannot be the main repository")
                if not (root / ".git").is_file():
                    raise PermissionError("workspace is not an active Git Worktree")
            correlation_id = request.correlation_id or uuid.uuid4().hex[:12]
            profile = replace(
                profile,
                resources=replace(
                    profile.resources,
                    workspace_bytes=min(
                        profile.resources.workspace_bytes, storage_limits.bytes
                    ),
                    workspace_entries=min(
                        profile.resources.workspace_entries,
                        storage_limits.entries,
                    ),
                ),
            ).bind_workspace(root)
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
                workspace_baseline=storage_baseline,
                workspace_root_identity=root_identity,
                workspace_cwd_identity=cwd_identity,
            )
            resolved_context = ResolvedExecutionContext(
                request.task_id, request.workspace_id, workspace.state.value,
                repository_root, root, cwd,
                profile.writable_roots, profile.filesystem.value,
                profile.network, profile.resources, request.environment,
                profile.environment_keys, request.argv, correlation_id, profile,
                storage_baseline, root_identity, cwd_identity,
            )
        if self.backend_selector is not None:
            backend = await self.backend_selector.select_async(
                writable=profile.filesystem is FileSystemAccess.WORKSPACE_WRITE
            )
        else:
            backend = self.backend
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
        # Round-14 §1: revalidate the worktree root inode AND Git identity as
        # the last step before the backend launches the subprocess.  ``require``
        # (above) and ``verify_git_identity`` both ran earlier in this method,
        # leaving a TOCTOU window in which a concurrent writer (e.g. a prior
        # subprocess, or a hook fired by a git operation) could swap the
        # worktree directory out from under the validated path.  This shrinks
        # the window to the final await before ``create_subprocess_exec`` and
        # turns a successful swap into a refusal (the post-exec re-verify below
        # would otherwise only quarantine *after* the child has run).
        if (
            resolved_context is not None
            and self.workspace_manager is not None
            and request.task_id
            and request.workspace_id
        ):
            await self.workspace_manager.verify_execution_root(request.workspace_id)
        try:
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
        except asyncio.CancelledError:
            if resolved_context is not None:
                await self._verify_or_quarantine_git_identity(
                    resolved_context.workspace_id
                )
                await self._quarantine_cancelled_storage_violation(
                    resolved_context
                )
            raise
        if resolved_context is not None:
            await self._verify_or_quarantine_git_identity(
                resolved_context.workspace_id
            )
            await self._cleanup_workspace_on_storage_violation(
                resolved_context.workspace_id, result
            )
        return result

    async def _verify_or_quarantine_git_identity(
        self, workspace_id: str
    ) -> None:
        """Never return from execution after linked-worktree metadata drift."""
        try:
            await self.workspace_manager.verify_git_identity(workspace_id)
        except Exception as exc:
            await self.workspace_manager.quarantine(workspace_id)
            raise PermissionError(
                "TaskWorkspace Git identity changed during execution"
            ) from exc

    async def _quarantine_cancelled_storage_violation(
        self, context: ResolvedExecutionContext
    ) -> None:
        """Account a cancelled process after its tree has been terminated."""
        authority = getattr(self.workspace_manager, "storage_authority", None)
        workspace = self.workspace_manager.get(context.workspace_id)
        limits = getattr(workspace, "storage_limits", None)
        if authority is None or limits is None:
            await self.workspace_manager.quarantine(context.workspace_id)
            return
        violation = await asyncio.to_thread(
            authority.assess,
            context.worktree_path,
            context.workspace_baseline,
            limits,
        )
        if violation is not None:
            await self.workspace_manager.quarantine(context.workspace_id)

    async def _cleanup_workspace_on_storage_violation(
        self, workspace_id: str, result: ExecutionResult
    ) -> None:
        violation = result.diagnostics.get("resource_violation")
        if not isinstance(violation, dict) or violation.get("kind") not in {
            "workspace-bytes",
            "workspace-entries",
            "workspace-observation",
        }:
            return
        try:
            transition = await self.workspace_manager.quarantine(workspace_id)
            result.diagnostics["workspace_quarantine"] = (
                "updated"
                if transition.value == "updated"
                else "failed"
            )
            result.diagnostics["workspace_cleanup"] = transition.value
        except Exception as exc:  # noqa: BLE001 - quarantine failures are recorded in the result
            result.diagnostics["workspace_cleanup"] = "failed"
            result.diagnostics["workspace_cleanup_error"] = type(exc).__name__

    def _make_managed_on_terminal(self) -> "Callable[[str], Awaitable[None]]":
        """Build the ``on_terminal`` callback injected into ManagedProcessHandle.

        P2-2: when a managed process reaches a terminal state via ANY path
        (natural exit through ``wait()``, or explicit ``aclose()``/terminate),
        this pops the execution's entry from ``_active``.  ``dict.pop`` with a
        default is safe against the concurrent pop already done by
        ``terminate()`` / ``shutdown()``.
        """
        active = self._active

        async def _on_terminal(execution_id: str) -> None:
            active.pop(execution_id, None)

        return _on_terminal

    async def terminate(self, execution_id: str) -> None:
        process_terminated = await self.process_supervisor.terminate(execution_id)
        active = self._active.get(execution_id)
        if active is None and process_terminated:
            return
        backend = active[2] if active is not None else self.backend
        if backend is None and self.backend_selector is not None:
            backend = await self.backend_selector.select_async(writable=False)
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
        workspace = self.workspace_manager.require(
            request.workspace_id,
            task_id=request.task_id,
            principal_id=self.principal_id,
            project_id=self.project_id,
            runtime_id=self.runtime_id,
        )
        if workspace.state not in {WorkspaceState.READY, WorkspaceState.RUNNING, WorkspaceState.VERIFYING}:
            raise PermissionError("workspace is not available for managed process")
        await self.workspace_manager.verify_git_identity(request.workspace_id)
        # Round-15 A-3: the managed-process (LSP) path also launches a
        # subprocess into the worktree and previously skipped the pre-exec
        # inode + git-identity re-validation that the foreground execute()
        # path performs.  Run the same check here so a worktree/.git swap is
        # refused before the long-lived child is launched.
        await self.workspace_manager.verify_execution_root(request.workspace_id)
        root = workspace.worktree_path.expanduser().absolute()
        cwd = request.cwd.expanduser().absolute()
        root_info = os.stat(root, follow_symlinks=False)
        cwd_info = os.stat(cwd, follow_symlinks=False)
        root_identity = (int(root_info.st_dev), int(root_info.st_ino))
        cwd_identity = (int(cwd_info.st_dev), int(cwd_info.st_ino))
        if cwd != root and root not in cwd.parents:
            raise PermissionError("managed process cwd is outside the task workspace")
        if not (root / ".git").is_file():
            raise PermissionError("managed process requires an active Git Worktree")
        backend = (
            await self.backend_selector.select_async(writable=False)
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
            workspace.repository_root.expanduser().absolute(), root, cwd, (),
            "read-only", NetworkPolicy.NONE, request.budget, environment,
            frozenset(environment), request.argv, execution_id,
            PermissionProfile(
                filesystem=FileSystemAccess.READ_ONLY,
                network=NetworkPolicy.NONE,
                environment_keys=frozenset(environment),
                resources=request.budget,
            ).bind_workspace(root),
            workspace_root_identity=root_identity,
            workspace_cwd_identity=cwd_identity,
        )
        try:
            if self.managed_process_factory is not None:
                handle = await self.managed_process_factory(resolved, temporary_home)
            else:
                directory_binding = open_execution_directory_binding(
                    root,
                    cwd,
                    expected_root_identity=root_identity,
                    expected_cwd_identity=cwd_identity,
                )
                try:
                    argv = self._managed_argv(resolved, backend, temporary_home)
                    launch = build_process_launch(
                        argv,
                        cwd=cwd,
                        directory_binding=directory_binding,
                        budget=request.budget,
                        enforce_resource_limits=True,
                    )
                    process = await asyncio.create_subprocess_exec(
                        *launch.argv,
                        cwd=launch.cwd,
                        env=environment,
                        stdin=asyncio.subprocess.PIPE,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE,
                        start_new_session=launch.start_new_session,
                        pass_fds=launch.pass_fds,
                    )
                finally:
                    directory_binding.close()
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
                    # P2-2: pop this execution's entry from ``_active`` when
                    # the process reaches a terminal state via ANY path
                    # (natural exit through ``wait()``, or explicit
                    # ``aclose()``).  Without this a process that exited
                    # naturally stayed in ``_active`` forever (stale
                    # execution id, state-API inconsistency).
                    on_terminal=self._make_managed_on_terminal(),
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
                preserve_workspace_path=context.workspace_root_identity is not None,
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
        """Shut down all active executions, the supervisor, and the Docker backend.

        Round-13 review P0-1: previously ``_closed=True`` was set BEFORE any
        cleanup, so a ``terminate()`` exception left remaining executions,
        the supervisor, and the Docker backend alive — and a retry returned
        success immediately.  Now each step runs independently (one failure
        does not skip the rest), the typed state machine tracks OPEN →
        CLOSING → CLOSED/QUARANTINED, and every caller awaits the SAME shared
        shutdown task so no one sees a false success.
        """
        if self._shutdown_state is _ShutdownState.CLOSED:
            return
        if self._shutdown_state is _ShutdownState.QUARANTINED:
            raise ExecutionServiceShutdownError(
                f"ExecutionService was already partially shut down with "
                f"errors; resources may not be fully released"
            ) from self._shutdown_error
        if self._shutdown_task is not None:
            await asyncio.shield(self._shutdown_task)
            return
        self._shutdown_task = asyncio.ensure_future(self._run_shutdown())
        await asyncio.shield(self._shutdown_task)

    async def _run_shutdown(self) -> None:
        """The actual shutdown sequence — runs exactly once."""
        self._shutdown_state = _ShutdownState.CLOSING
        errors: list[Exception] = []

        # Each active execution is terminated independently — one failure
        # must not skip the rest.
        for execution_id in tuple(self._active):
            try:
                await self.terminate(execution_id)
            except Exception as exc:  # noqa: BLE001 — collect, don't abort
                errors.append(exc)
                logger.debug(
                    "ExecutionService shutdown: terminate(%s) failed",
                    execution_id, exc_info=True,
                )

        # Supervisor and Docker backend are always attempted.
        try:
            await self.process_supervisor.shutdown()
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)
            logger.debug("ExecutionService shutdown: supervisor shutdown failed", exc_info=True)

        if self.docker_backend is not None:
            try:
                await self.docker_backend.shutdown()
            except Exception as exc:  # noqa: BLE001
                errors.append(exc)
                logger.debug("ExecutionService shutdown: docker backend shutdown failed", exc_info=True)

        if errors:
            self._shutdown_error = errors[0]
            self._shutdown_state = _ShutdownState.QUARANTINED
            raise ExecutionServiceShutdownError(
                f"ExecutionService shutdown completed with {len(errors)} "
                f"error(s): " + "; ".join(type(e).__name__ for e in errors)
            ) from errors[0]
        self._shutdown_state = _ShutdownState.CLOSED
