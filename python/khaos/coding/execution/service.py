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
from typing import TYPE_CHECKING, Any, cast

from khaos.coding.execution.binding import open_execution_directory_binding
from khaos.coding.execution.capability import SandboxDecision
from khaos.coding.execution.cleanup_ledger import CleanupInvariantError, CleanupLedger
from khaos.coding.execution.environment import scrub_spawn_environment
from khaos.coding.execution.identity import executable_identity
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
from khaos.coding.execution.supervisor import ProcessSupervisor
from khaos.coding.workspace.models import WorkspaceState
from khaos.coding.workspace.storage import (
    WorkspaceStorageLimits,
    capture_workspace_snapshot,
)

if TYPE_CHECKING:
    from khaos.coding.workspace.manager import WorkspaceManager

logger = logging.getLogger(__name__)


class _ShutdownState(str, Enum):
    """Terminal state of ExecutionService shutdown (round-13 review P0-1)."""

    OPEN = "open"
    CLOSING = "closing"
    CLOSED = "closed"
    QUARANTINED = "quarantined"


class ExecutionServiceShutdownError(RuntimeError):
    """Typed error when shutdown partially fails (round-13 P0-1)."""


class ExecutionService:
    def __init__(
        self,
        backend=None,
        workspace_manager: WorkspaceManager | None = None,
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
        # A managed handle owns a real process, stderr task, watchdog, and
        # synthetic HOME before it can be published to ``_active``.  Keep a
        # synchronous service-owned record for that acquire -> publish gap so
        # cancellation while waiting for ``_admission_lock`` cannot orphan
        # the handle or its temporary filesystem.
        self._pending_managed_handles: dict[str, ManagedProcessHandle] = {}
        # Round-13 review P0-1: typed shutdown state machine (same pattern as
        # RuntimeResult and ManagedProcess).  ``_closed`` is a backward-compat
        # property that reads ``_shutdown_state``.
        self._shutdown_task: asyncio.Task[None] | None = None
        self._shutdown_state = _ShutdownState.OPEN
        self._shutdown_error: BaseException | None = None
        # Round-14 review P0-2: admission registry.  ``_initializing`` tracks
        # executions that have been admitted (passed the OPEN check) but have
        # not yet been published to ``_active`` (they're in the workspace/
        # backend/process-await phase).  shutdown() owns both ``_active`` AND
        # ``_initializing``, so a late-publish after shutdown can detect the
        # closed admission and terminate the just-started process.
        self._admission_lock = asyncio.Lock()
        self._initializing: dict[str, asyncio.Task] = {}
        # Batch 15.3 (round-15 review §九): per-step completion ledger so
        # a QUARANTINED shutdown is retryable — only failed steps are
        # retried, completed steps (supervisor/docker/individual
        # terminates) are skipped.  Previously QUARANTINED was a permanent
        # graveyard: a second shutdown() re-raised the original error and
        # never attempted the remaining steps.
        self._cleanup_ledger = CleanupLedger()
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

    @property
    def admission_closed(self) -> bool:
        """Compatibility alias for the execution-generation fence."""
        return self.generation_admission_closed

    @property
    def generation_admission_closed(self) -> bool:
        """True when this service no longer admits another execution."""
        return self._shutdown_state is not _ShutdownState.OPEN

    @property
    def child_admission_closed(self) -> bool:
        """True when this service cannot admit another child execution."""
        return self._shutdown_state is not _ShutdownState.OPEN

    @property
    def terminal_closed(self) -> bool:
        """True only after every child owner has a terminal proof."""
        return (
            self._shutdown_state is _ShutdownState.CLOSED
            and self._terminal_ownership_proof()
        )

    @property
    def is_quarantined(self) -> bool:
        """True when shutdown retained an unproven execution resource."""
        return self._shutdown_state is _ShutdownState.QUARANTINED

    def owns_execution(self, execution_id: str) -> bool:
        """Expose the service ownership oracle used by parent owners."""
        return (
            execution_id in self._active
            or execution_id in self._initializing
            or execution_id in self._pending_managed_handles
        )

    def owned_resources(self) -> tuple[str, ...]:
        """Describe active and in-flight child ownership transactions."""
        resources = [f"execution:{execution_id}" for execution_id in self._active]
        resources.extend(
            f"initializing:{execution_id}" for execution_id in self._initializing
        )
        resources.extend(
            f"pending_managed:{execution_id}"
            for execution_id in self._pending_managed_handles
        )
        return tuple(sorted(resources))

    def terminal_postcondition(self) -> bool:
        """Return the service-level terminal ownership proof."""
        return self.terminal_closed and self._terminal_ownership_proof()

    def _terminal_ownership_proof(self) -> bool:
        """Prove that the service and its shared supervisor are terminal."""
        if self.docker_backend is not None and not _resource_owner_terminal(
            self.docker_backend
        ):
            return False
        return (
            not self._active
            and not self._initializing
            and not self._pending_managed_handles
            and _resource_owner_terminal(self.process_supervisor)
        )

    async def close(self) -> None:
        """ResourceOwner alias for :meth:`shutdown`."""
        await self.shutdown()

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
        if self._active or self._initializing or self._pending_managed_handles:
            raise RuntimeError("cannot bind ExecutionService with owned executions")
        self.principal_id, self.project_id, self.runtime_id = authority
        self._authority_bound = True

    async def execute(self, request: ExecutionRequest) -> ExecutionResult:
        # Round-15 review P0-A: admission transaction.  Previously the OPEN
        # check was a bare ``if`` with no lock, so a shutdown that began
        # after the check but before the backend spawned would leave a
        # late-spawned process unowned.  Now the OPEN check + admission
        # reservation are atomic under ``_admission_lock``, and the
        # reservation is popped only after the execution publishes to
        # ``_active`` (or fails).  ``shutdown()`` cancels every
        # ``_initializing`` task so a late publish is impossible.
        async with self._admission_lock:
            if self._shutdown_state is not _ShutdownState.OPEN:
                raise RuntimeError(
                    f"execution service is {self._shutdown_state.value}, "
                    f"not accepting new executions"
                )
            admission_id = request.correlation_id or uuid.uuid4().hex[:12]
            current_task = asyncio.current_task()
            if current_task is not None:
                self._initializing[admission_id] = current_task
        try:
            return await self._execute_after_admission(request, admission_id)
        finally:
            # Pop the admission reservation so shutdown() can observe an
            # empty ``_initializing`` once every in-flight execution has
            # either published to ``_active`` or exited.
            async with self._admission_lock:
                self._initializing.pop(admission_id, None)

    async def _execute_after_admission(
        self, request: ExecutionRequest, admission_id: str
    ) -> ExecutionResult:
        """The body of ``execute()`` after the admission reservation."""
        # Round-15 review P0-A: re-check OPEN after every significant await.
        # If shutdown raced us, abort before spawning.
        if self._shutdown_state is not _ShutdownState.OPEN:
            raise RuntimeError(
                f"execution service is {self._shutdown_state.value}, "
                f"not accepting new executions"
            )
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
            correlation_id = admission_id
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
                executable_identity=request.executable_identity,
                sandbox_decision=request.sandbox_decision,
            )
            assert request.task_id is not None
            assert request.workspace_id is not None
            resolved_context = ResolvedExecutionContext(
                request.task_id, request.workspace_id, workspace.state.value,
                repository_root, root, cwd,
                profile.writable_roots, profile.filesystem.value,
                profile.network, profile.resources, request.environment,
                profile.environment_keys, request.argv, correlation_id, profile,
                storage_baseline, root_identity, cwd_identity,
                request.executable_identity,
                request.sandbox_decision,
            )
        if self.backend_selector is not None:
            writable = profile.filesystem is FileSystemAccess.WORKSPACE_WRITE
            if request.sandbox_decision is not None:
                selector_method = getattr(
                    self.backend_selector, "select_async_with_decision", None
                )
                if not callable(selector_method):
                    raise PermissionError(
                        "sandbox decision cannot be verified by this backend selector"
                    )
                verified_selector = cast(
                    Callable[..., Awaitable[tuple[Any, SandboxDecision]]],
                    selector_method,
                )
                backend, observed_decision = await verified_selector(
                    writable=writable,
                    network_mode=profile.network.value,
                )
                if observed_decision.digest() != request.sandbox_decision.digest():
                    raise PermissionError(
                        "sandbox capability decision changed before execution"
                    )
            else:
                backend = await self.backend_selector.select_async(writable=writable)
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
        if request.executable_identity != executable_identity(
            request.argv, request.environment
        ):
            raise PermissionError(
                "executable identity changed before execution"
            )
        if request.sandbox_decision is not None:
            if (
                request.sandbox_decision.filesystem_mode != profile.filesystem.value
                or request.sandbox_decision.network_mode != profile.network.value
            ):
                raise PermissionError(
                    "sandbox decision does not match the resolved permission profile"
                )
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
        # Round-15 review P0-A: final re-check before publishing to _active.
        # If shutdown began during any of the awaits above, abort now —
        # the backend's subprocess spawn is the irrevocable step.
        if self._shutdown_state is not _ShutdownState.OPEN:
            raise RuntimeError(
                f"execution service is {self._shutdown_state.value}, "
                f"not accepting new executions"
            )
        try:
            if resolved_context is not None and hasattr(backend, "execute_resolved"):
                execution_id = resolved_context.correlation_id
                # Publish atomically with the admission fence.  Shutdown
                # takes the same lock before moving OPEN → CLOSING, so it
                # either sees this execution in ``_active`` or this request
                # is rejected before the backend can acquire a resource.
                async with self._admission_lock:
                    if self._shutdown_state is not _ShutdownState.OPEN:
                        raise RuntimeError(
                            f"execution service is {self._shutdown_state.value}, "
                            "not accepting new executions"
                        )
                    self._active[execution_id] = (
                        resolved_context.task_id,
                        resolved_context.workspace_id,
                        backend,
                    )
                    # Pop from _initializing now that we have published to
                    # _active.  Shutdown's initializing cancellation must not
                    # cancel this task; the terminate loop owns it now.
                    self._initializing.pop(execution_id, None)
                try:
                    result = await backend.execute_resolved(resolved_context)
                finally:
                    async with self._admission_lock:
                        self._active.pop(execution_id, None)
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
        assert self.workspace_manager is not None
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
        assert self.workspace_manager is not None
        authority = getattr(self.workspace_manager, "storage_authority", None)
        workspace = self.workspace_manager.get(context.workspace_id)
        limits = getattr(workspace, "storage_limits", None)
        quarantine = getattr(self.workspace_manager, "quarantine", None)
        if authority is None or limits is None:
            if callable(quarantine):
                await cast("Callable[[str], Awaitable[object]]", quarantine)(
                    context.workspace_id
                )
            else:
                # Production WorkspaceManager always exposes quarantine. A
                # reduced adapter may not have storage accounting at all; the
                # execution backend has already completed its own cleanup, so
                # record the missing optional workspace observation instead of
                # turning cancellation into an unhandled AttributeError.
                logger.warning(
                    "workspace quarantine unavailable after cancelled execution: %s",
                    context.workspace_id,
                )
            return
        violation = await asyncio.to_thread(
            authority.assess,
            context.worktree_path,
            context.workspace_baseline,
            limits,
        )
        if violation is not None:
            if callable(quarantine):
                await cast("Callable[[str], Awaitable[object]]", quarantine)(
                    context.workspace_id
                )
            else:
                logger.warning(
                    "workspace quarantine unavailable for storage violation: %s",
                    context.workspace_id,
                )

    async def _cleanup_workspace_on_storage_violation(
        self, workspace_id: str, result: ExecutionResult
    ) -> None:
        assert self.workspace_manager is not None
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
        pending = self._pending_managed_handles.get(execution_id)
        if pending is not None:
            await pending.aclose()
            if not _resource_owner_terminal(pending):
                raise CleanupInvariantError(
                    f"pending managed process {execution_id} lacks terminal proof"
                )
            async with self._admission_lock:
                if self._pending_managed_handles.get(execution_id) is pending:
                    self._pending_managed_handles.pop(execution_id, None)
            return

        process_terminated = await self.process_supervisor.terminate(execution_id)
        active = self._active.get(execution_id)
        if active is None and process_terminated:
            # ProcessSupervisor.terminate() proves process death but retains
            # its registry entry until an explicit unregister proof.  Do not
            # return while that external owner still reports the execution.
            if _supervisor_owns(self.process_supervisor, execution_id):
                await self.process_supervisor.unregister_process(execution_id)
                if _supervisor_owns(self.process_supervisor, execution_id):
                    raise CleanupInvariantError(
                        f"execution {execution_id} remains owned by supervisor"
                    )
            return
        backend = active[2] if active is not None else self.backend
        if backend is None and self.backend_selector is not None:
            backend = await self.backend_selector.select_async(writable=False)
        if isinstance(backend, ManagedProcessHandle):
            await backend.aclose()
            if not _resource_owner_terminal(backend):
                raise CleanupInvariantError(
                    f"managed process {execution_id} lacks terminal proof"
                )
        else:
            await cast("Any", backend).terminate(execution_id)
            if _has_resource_owner(backend) and not _resource_owner_released(
                backend, execution_id
            ):
                raise CleanupInvariantError(
                    f"execution backend {execution_id} retains owned resources"
                )
        if _supervisor_owns(self.process_supervisor, execution_id):
            await self.process_supervisor.unregister_process(execution_id)
            if _supervisor_owns(self.process_supervisor, execution_id):
                raise CleanupInvariantError(
                    f"execution {execution_id} remains owned by supervisor"
                )
        async with self._admission_lock:
            if active is not None and self._active.get(execution_id) is active:
                self._active.pop(execution_id, None)

    async def start_managed_process(self, request: ExecutionRequest) -> ManagedProcessHandle:
        """Start a registered LSP-style stdio process in an active TaskWorkspace.

        Round-15 review P0-A/P0-2: this method now uses the SAME admission
        transaction as ``execute()`` — the OPEN check + ``_initializing``
        reservation are atomic under ``_admission_lock``, and the
        reservation is popped only after the handle publishes to
        ``_active`` (or fails).  ``shutdown()`` cancels every
        ``_initializing`` task so a late publish is impossible.

        Round-15 review P0-2 (CancelledError rollback): the spawn
        transaction wraps ``create_subprocess_exec`` through
        ``register_process`` in a ``try/except BaseException`` so a
        ``CancelledError`` (a ``BaseException`` in 3.11+) that arrives
        AFTER the process was spawned but BEFORE ownership publication
        kills+waits the orphaned process and removes the temporary HOME
        before re-raising.  Previously ``except Exception`` left the
        process alive when the caller was cancelled mid-spawn.
        """
        # Round-15 review P0-A: admission transaction — atomically check
        # OPEN and reserve a slot in ``_initializing`` so shutdown() owns
        # this in-flight spawn.
        async with self._admission_lock:
            if self._shutdown_state is not _ShutdownState.OPEN:
                raise RuntimeError(
                    f"execution service is {self._shutdown_state.value}, "
                    f"not accepting new executions"
                )
            admission_id = request.correlation_id or uuid.uuid4().hex[:12]
            current_task = asyncio.current_task()
            if current_task is not None:
                self._initializing[admission_id] = current_task
        try:
            return await self._start_managed_after_admission(request, admission_id)
        finally:
            # Pop the admission reservation so shutdown() can observe an
            # empty ``_initializing`` once every in-flight managed spawn
            # has either published to ``_active`` or exited.
            async with self._admission_lock:
                self._initializing.pop(admission_id, None)

    async def _start_managed_after_admission(
        self, request: ExecutionRequest, admission_id: str
    ) -> ManagedProcessHandle:
        """The body of ``start_managed_process`` after the admission reservation."""
        # Round-15 review P0-A: re-check OPEN after every significant await.
        if self._shutdown_state is not _ShutdownState.OPEN:
            raise RuntimeError(
                f"execution service is {self._shutdown_state.value}, "
                f"not accepting new executions"
            )
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
        execution_id = admission_id
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
        # Round-15 review P0-A: final re-check before the irrevocable spawn.
        # If shutdown began during any of the awaits above, abort now —
        # ``create_subprocess_exec`` is the irrevocable step.
        if self._shutdown_state is not _ShutdownState.OPEN:
            import shutil

            shutil.rmtree(temporary_home, ignore_errors=True)
            raise RuntimeError(
                f"execution service is {self._shutdown_state.value}, "
                f"not accepting new executions"
            )
        # Round-15 review P0-2: spawn transaction.  ``except BaseException``
        # (not ``except Exception``) so a ``CancelledError`` arriving after
        # ``create_subprocess_exec`` succeeded but before ownership
        # publication triggers a kill+wait of the orphaned process and
        # removal of the temporary HOME.  Without this the process would
        # leak: the caller has abandoned the coroutine, the supervisor
        # hasn't been told about it, and ``_active`` doesn't reference it.
        spawned_process: asyncio.subprocess.Process | None = None
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
                        env=scrub_spawn_environment(environment),
                        stdin=asyncio.subprocess.PIPE,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE,
                        start_new_session=launch.start_new_session,
                        pass_fds=launch.pass_fds,
                    )
                finally:
                    directory_binding.close()
                spawned_process = process
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
        except BaseException:
            # Round-15 review P0-2: spawn committed but ownership
            # publication failed (caller cancelled, supervisor closed
            # during spawn, register_process raised, etc.).  Kill the
            # just-spawned process group so it cannot outlive the
            # transaction, then remove the temporary HOME.  The supervisor
            # helper ``_kill_orphaned_process`` swallows all errors because
            # this is best-effort cleanup of a half-spawned child the
            # caller is about to abandon.
            import shutil

            if spawned_process is not None:
                from khaos.coding.execution.supervisor import _kill_orphaned_process

                await _kill_orphaned_process(spawned_process)
            shutil.rmtree(temporary_home, ignore_errors=True)
            raise
        # This assignment is deliberately synchronous and is the first
        # operation after handle construction/factory return.  There must be
        # no cancellable await before the service owns the handle.
        self._pending_managed_handles[execution_id] = handle
        # Round-15 review P0-A: publish to ``_active`` only after the
        # transaction committed.  If shutdown began between the OPEN
        # re-check above and here, the handle is fully formed — terminate
        # it immediately so the process doesn't outlive the service.
        async with self._admission_lock:
            if self._shutdown_state is _ShutdownState.OPEN:
                self._pending_managed_handles.pop(execution_id, None)
                self._active[execution_id] = (
                    request.task_id, request.workspace_id, handle,
                )
                # Pop from _initializing — see _execute_after_admission for
                # rationale.  Shutdown cannot cancel this task after the
                # publication lock is released; it will see _active instead.
                self._initializing.pop(execution_id, None)
                published = True
            else:
                published = False
        if not published:
            try:
                await handle.aclose()
                if not _resource_owner_terminal(handle):
                    raise CleanupInvariantError(
                        f"managed process {execution_id} lacks terminal proof"
                    )
            except Exception:  # noqa: BLE001 — retain failure for caller
                logger.debug(
                    "managed process %s aclose failed during late shutdown detection",
                    execution_id, exc_info=True,
                )
            else:
                self._pending_managed_handles.pop(execution_id, None)
            raise RuntimeError(
                f"execution service is {self._shutdown_state.value}, "
                f"not accepting new executions"
            )
        return handle

    def _managed_argv(
        self,
        context: ResolvedExecutionContext,
        backend,
        temporary_home: Path,
    ) -> tuple[str, ...]:
        assert context.permission_profile is not None
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
                resources=context.budget,
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

        Batch 15.3 (round-15 review §八/§九): QUARANTINED is now retryable.
        A second ``shutdown()`` call after a partial failure uses the
        ``CleanupLedger`` to skip already-completed steps (successful
        terminates, supervisor, docker) and only retries the failed ones.
        Previously QUARANTINED was a permanent graveyard that re-raised the
        original error without attempting any remaining cleanup.
        """
        # Fence admission and create/reuse the shared task under the same
        # lock used by publish transactions.  This closes the window where
        # shutdown was requested but a final managed-process publication
        # still observed OPEN and escaped _active.
        async with self._admission_lock:
            if self._shutdown_state is _ShutdownState.CLOSED:
                if self._terminal_ownership_proof():
                    return
                # A CLOSED flag without an ownership proof is itself a
                # lifecycle invariant violation.  Retain the state as
                # retryable quarantine rather than returning false success.
                self._shutdown_state = _ShutdownState.QUARANTINED
            if self._shutdown_state is _ShutdownState.OPEN:
                self._shutdown_state = _ShutdownState.CLOSING
            shutdown_task = self._shutdown_task
            if shutdown_task is None or shutdown_task.done():
                shutdown_task = asyncio.ensure_future(self._run_shutdown())
                self._shutdown_task = shutdown_task
        await asyncio.shield(shutdown_task)

    async def _run_shutdown(self) -> None:
        """The actual shutdown sequence — may run multiple times via retry.

        Round-14 review P0-3: CancelledError (BaseException in Python 3.11+)
        is caught explicitly per step — the cancel is recorded, remaining
        steps continue, and the cancel is re-raised AFTER all cleanup is
        attempted.  This prevents a cancel from leaving the service in
        CLOSING with supervisor/docker alive.

        Batch 15.3: the ``CleanupLedger`` records each completed step so a
        retry (after QUARANTINED) skips them.  ``_active.pop()`` on
        successful terminate is the natural per-execution ledger — only
        failed terminates remain in ``_active`` for the retry.
        """
        self._shutdown_state = _ShutdownState.CLOSING
        self._cleanup_ledger.reset_errors()
        cancel_requested = False

        async def _run_step(label: str, action, verify, generation=None) -> None:
            nonlocal cancel_requested
            try:
                await self._cleanup_ledger.run_step(
                    label,
                    action=action,
                    verify=verify,
                    resource_generation=generation,
                )
            except asyncio.CancelledError:
                # run_step records cancellation as an error before re-raising;
                # continue independent cleanup, but never allow CLOSED.
                cancel_requested = True
                logger.debug("ExecutionService shutdown step %s cancelled", label)
            except Exception:  # noqa: BLE001 — run_step records the failure
                logger.debug(
                    "ExecutionService shutdown step %s failed",
                    label,
                    exc_info=True,
                )

        # Each active execution is terminated independently — one failure
        # must not skip the rest.  The concrete active tuple identity binds
        # the ledger step to the resource generation it actually cleaned.
        for execution_id, active in tuple(self._active.items()):
            await _run_step(
                f"terminate:{execution_id}",
                lambda execution_id=execution_id: self.terminate(execution_id),
                lambda execution_id=execution_id: not self.owns_execution(execution_id),
                generation=id(active),
            )

        async def _cancel_initializing() -> None:
            initializing = tuple(self._initializing.items())
            for _, init_task in initializing:
                init_task.cancel()
            if initializing:
                await asyncio.gather(
                    *(task for _, task in initializing),
                    return_exceptions=True,
                )
            for execution_id, init_task in initializing:
                if not init_task.done():
                    raise RuntimeError(
                        f"initializing execution task remains: {execution_id}"
                    )
                if self._initializing.get(execution_id) is init_task:
                    self._initializing.pop(execution_id, None)
            if self._initializing:
                raise RuntimeError(
                    "initializing execution ownership changed during shutdown"
                )

        await _run_step(
            "initializing:cancel",
            _cancel_initializing,
            lambda: not self._initializing,
            generation=id(self._initializing),
        )

        async def _close_pending_managed() -> None:
            errors: list[BaseException] = []
            for execution_id, handle in tuple(self._pending_managed_handles.items()):
                try:
                    await handle.aclose()
                    if not _resource_owner_terminal(handle):
                        raise CleanupInvariantError(
                            f"pending managed process {execution_id} lacks terminal proof"
                        )
                except asyncio.CancelledError:
                    raise
                except BaseException as exc:  # noqa: BLE001 — retain pending owner
                    errors.append(exc)
                    continue
                self._pending_managed_handles.pop(execution_id, None)
            if errors:
                raise RuntimeError(
                    f"{len(errors)} pending managed process(es) did not close"
                ) from errors[0]

        await _run_step(
            "pending_managed:close",
            _close_pending_managed,
            lambda: not self._pending_managed_handles,
            generation=id(self._pending_managed_handles),
        )

        # Docker backend must be shut down BEFORE the supervisor — Docker
        # cleanup runs ``docker rm/stop/kill`` via ``supervisor.run()``, so
        # closing the supervisor first causes SupervisorClosedError during
        # container cleanup.  The supervisor is the last resource to close.
        if self.docker_backend is not None:
            await _run_step(
                "docker:shutdown",
                self.docker_backend.shutdown,
                lambda: _resource_owner_terminal(self.docker_backend),
                generation=id(self.docker_backend),
            )

        await _run_step(
            "supervisor:shutdown",
            self.process_supervisor.shutdown,
            lambda: _resource_owner_terminal(self.process_supervisor),
            generation=id(self.process_supervisor),
        )

        async def _terminal_proof_step() -> None:
            return None

        await _run_step(
            "terminal:proof",
            _terminal_proof_step,
            self._terminal_ownership_proof,
            generation=id(self),
        )

        errors = self._cleanup_ledger.errors
        if errors:
            self._shutdown_error = errors[0]
            self._shutdown_state = _ShutdownState.QUARANTINED
            raise ExecutionServiceShutdownError(
                f"ExecutionService shutdown completed with {len(errors)} "
                f"error(s): " + "; ".join(type(e).__name__ for e in errors)
            ) from errors[0]
        self._shutdown_state = _ShutdownState.CLOSED
        # Cancellation is recorded by run_step and therefore normally falls
        # through the error branch above.  Keep this guard for cancellation
        # raised by a custom action after it has independently proven all
        # resources terminal.
        if cancel_requested:
            raise asyncio.CancelledError()


def _has_resource_owner(component: object) -> bool:
    """Return whether an object exposes the ResourceOwner proof surface."""
    return all(
        callable(getattr(component, name, None))
        for name in ("terminal_postcondition", "owned_resources")
    )


def _resource_owner_terminal(component: object) -> bool:
    """Require both terminal proof and an empty independent resource oracle."""
    if not _has_resource_owner(component):
        return False
    owner = cast("Any", component)
    try:
        terminal_closed = bool(getattr(owner, "terminal_closed"))
        terminal_proof = bool(owner.terminal_postcondition())
        resources = tuple(owner.owned_resources())
    except Exception:  # noqa: BLE001 — an unknown owner is not terminal
        return False
    return terminal_closed and terminal_proof and not resources


def _resource_owner_released(component: object, execution_id: str) -> bool:
    """Prove one execution was released without closing its whole owner.

    DockerBackend and similar multiplexed owners remain OPEN for other
    executions after one lease is terminated. A per-execution oracle is
    preferred; older owners can prove release through stable descriptors.
    Backend-wide CLOSED is reserved for service shutdown.
    """
    owns = getattr(component, "owns_execution", None)
    if callable(owns):
        try:
            return owns(execution_id) is False
        except Exception:  # noqa: BLE001 — an unreadable oracle is unknown
            return False
    try:
        resources = tuple(cast("Any", component).owned_resources())
    except Exception:  # noqa: BLE001 — an unreadable oracle is unknown
        return False
    return not any(execution_id in resource for resource in resources)


def _supervisor_owns(supervisor: object, execution_id: str) -> bool:
    """Use a strict bool so test doubles cannot fake external ownership."""
    owns = getattr(supervisor, "owns_execution", None)
    if not callable(owns):
        return False
    try:
        return owns(execution_id) is True
    except Exception:  # noqa: BLE001 — treat an unreadable oracle as unknown
        return False
