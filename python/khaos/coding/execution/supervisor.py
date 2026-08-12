"""Unified lifecycle supervision for Agent-owned subprocess trees."""

# KHAOS-PRIVILEGED-SPAWN owner=ProcessSupervisor threat-model=child-tree-lifecycle boundary=execution-service

from __future__ import annotations

import asyncio
import logging
import math
import os
import signal
import stat
import subprocess
import sys
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

from khaos.coding.execution.binding import (
    ExecutionDirectoryBinding,
    open_execution_directory_binding,
)
from khaos.coding.execution.environment import scrub_spawn_environment
from khaos.coding.execution.identity import (
    executable_identity,
    open_executable_authority,
)
from khaos.coding.execution.models import ExecutionRequest, ExecutionResult
from khaos.coding.execution.native_launcher import build_process_launch
from khaos.coding.workspace.storage import (
    WorkspaceStorageAuthority,
    WorkspaceStorageLimits,
    WorkspaceStorageSnapshot,
    capture_workspace_snapshot,
)

logger = logging.getLogger(__name__)


class _SupervisorState(str, Enum):
    """Round-15 review P0-B: ProcessSupervisor admission fence state machine.

    Invariants:
      CLOSED  ⇒ _active == ∅ AND future registration impossible
      CLOSING ⇒ no new registrations accepted
    """

    OPEN = "open"
    CLOSING = "closing"
    CLOSED = "closed"
    QUARANTINED = "quarantined"


class SupervisorQuarantinedError(RuntimeError):
    """Round-17: raised when the supervisor is quarantined (resources retained)."""


class SupervisorClosedError(RuntimeError):
    """Raised when a registration is attempted after shutdown."""


@dataclass
class _ActiveProcess:
    process: asyncio.subprocess.Process
    termination_callback: Callable[[], Awaitable[None]] | None = None
    termination_requested: bool = False
    termination_lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    watchdog_task: asyncio.Task[dict | None] | None = None


@dataclass
class _PendingSpawn:
    """Owner record for the interval between admission and child publish."""

    ready: asyncio.Event = field(default_factory=asyncio.Event)
    done: asyncio.Event = field(default_factory=asyncio.Event)
    process: asyncio.subprocess.Process | None = None
    active: _ActiveProcess | None = None
    termination_requested: bool = False
    error: BaseException | None = None


class ProcessSupervisor:
    """Own process groups, bounded output, cancellation, and teardown.

    Round-15 review P0-B: the supervisor now carries its own admission fence
    (``_SupervisorState``) so that ``run()`` and ``register_process()``
    reject new children once ``shutdown()`` has begun — even if a future
    caller bypasses ``ExecutionService``.  Previously the supervisor only
    snapshotted ``_active`` at shutdown time, so a process spawned *after*
    the snapshot but *before* ``CLOSED`` would survive undetected.
    """

    def __init__(
        self,
        *,
        termination_grace_seconds: float = 2.0,
        storage_authority: WorkspaceStorageAuthority | None = None,
    ) -> None:
        if termination_grace_seconds <= 0:
            raise ValueError("termination grace period must be positive")
        self.termination_grace_seconds = termination_grace_seconds
        self.storage_authority = storage_authority or WorkspaceStorageAuthority()
        self._active: dict[str, _ActiveProcess] = {}
        self._pending_spawns: dict[str, _PendingSpawn] = {}
        self._registry_lock = asyncio.Lock()
        self._state = _SupervisorState.OPEN
        # Round-17 review §四: shared shutdown task so concurrent shutdown()
        # callers observe the same result (like ExecutionService).
        self._shutdown_task: asyncio.Task[None] | None = None

    @property
    def active_execution_ids(self) -> tuple[str, ...]:
        return tuple(sorted(self._active))

    @property
    def pending_execution_ids(self) -> tuple[str, ...]:
        """Return spawn transactions not yet released by their owner."""
        return tuple(sorted(self._pending_spawns))

    def owns_execution(self, execution_id: str) -> bool:
        """Return whether the supervisor still owns an execution id."""
        return execution_id in self._active or execution_id in self._pending_spawns

    @property
    def is_closed(self) -> bool:
        """True when the supervisor no longer accepts new children.

        Round-17 review §四: this is the admission fence property (not OPEN).
        Use ``terminal_closed`` to check whether all resources are proven
        terminated.  Kept for backward compatibility.
        """
        return self._state is not _SupervisorState.OPEN

    @property
    def admission_closed(self) -> bool:
        """Round-17: True when new registrations are permanently rejected."""
        return self._state is not _SupervisorState.OPEN

    @property
    def generation_admission_closed(self) -> bool:
        """True when this supervisor cannot admit another process generation."""
        return self._state is not _SupervisorState.OPEN

    @property
    def child_admission_closed(self) -> bool:
        """True when this supervisor cannot register another child process."""
        return self._state is not _SupervisorState.OPEN

    @property
    def terminal_closed(self) -> bool:
        """Round-17: True only when CLOSED (all resources proven terminated)."""
        return (
            self._state is _SupervisorState.CLOSED
            and not self._active
            and not self._pending_spawns
        )

    @property
    def is_quarantined(self) -> bool:
        """Round-17: True when QUARANTINED (resources may still be alive)."""
        return self._state is _SupervisorState.QUARANTINED

    def owned_resources(self) -> tuple[str, ...]:
        """Round-17 review §十四: descriptors of currently-held processes.

        Returns one descriptor per active process and per child watchdog.
        The watchdog is part of the transitive ownership graph: removing a
        process entry before its watchdog is settled would make an empty
        registry a false terminal proof.
        """
        resources: list[str] = []
        for execution_id in self.active_execution_ids:
            resources.append(f"execution:{execution_id}")
            active = self._active.get(execution_id)
            if active is not None and active.watchdog_task is not None and not active.watchdog_task.done():
                resources.append(f"watchdog:{execution_id}")
        resources.extend(
            f"spawn:{execution_id}"
            for execution_id in self.pending_execution_ids
            if execution_id not in self._active
        )
        return tuple(resources)

    def terminal_postcondition(self) -> bool:
        """Round-17 review §十四: True when every owned process is reaped.

        For the supervisor this means every retained process is terminal and
        every child watchdog has settled.  The registry is intentionally
        checked rather than treated as a source of truth: a cleanup path may
        remove an entry only after these proofs succeed.
        """
        for active in self._active.values():
            if active.process.returncode is None:
                return False
            if active.watchdog_task is not None and not active.watchdog_task.done():
                return False
        return len(self._active) == 0 and len(self._pending_spawns) == 0

    async def close(self) -> None:
        """Round-17 review §十四: ResourceOwner protocol — alias for
        :meth:`shutdown`.  Concurrent callers observe the same result
        via the shared ``_shutdown_task``."""
        await self.shutdown()

    async def run(
        self,
        request: ExecutionRequest,
        *,
        cwd: Path | None = None,
        execution_root: Path | None = None,
        env: dict[str, str] | None = None,
        enforce_resource_limits: bool = True,
        enforce_resource_watchdog: bool | None = None,
        tmp_root: Path | None = None,
        sandbox_storage_paths: tuple[str, ...] = (),
        workspace_root: Path | None = None,
        workspace_baseline: WorkspaceStorageSnapshot | None = None,
        workspace_limits: WorkspaceStorageLimits | None = None,
        directory_binding: ExecutionDirectoryBinding | None = None,
        use_native_launcher: bool = True,
        preserve_directory_fds: bool = False,
        termination_callback: Callable[[], Awaitable[None]] | None = None,
    ) -> ExecutionResult:
        """Run one foreground process with bounded, fairly split output.

        ``use_native_launcher=False`` is reserved for a trusted control-plane
        client such as the Docker CLI.  That client is not the user payload;
        its own backend validates the request and applies the container
        boundary.  It still receives a new session, but it must not inherit
        the payload's host directory/rlimit launcher arguments.

        ``termination_callback`` is an optional backend-owned kernel cleanup
        hook.  It runs after the direct child is reaped and before captured
        output is drained, which lets a namespace backend terminate
        descendants that are not in the supervisor's process group.
        """
        execution_id = request.correlation_id
        if not execution_id:
            raise ValueError("supervised execution requires a correlation id")
        # Round-15 review P0-B: admission fence — reject if the supervisor
        # has begun shutdown.  This is the defence-in-depth that survives
        # even if a future caller bypasses ExecutionService.
        if self._state is not _SupervisorState.OPEN:
            raise SupervisorClosedError(
                f"ProcessSupervisor is {self._state.value}, "
                f"not accepting new executions"
            )
        watchdog_enabled = (
            enforce_resource_limits
            if enforce_resource_watchdog is None
            else enforce_resource_watchdog
        )
        if workspace_root is not None and workspace_baseline is None:
            workspace_baseline = await asyncio.to_thread(
                capture_workspace_snapshot, workspace_root
            )
        if workspace_baseline is not None and not workspace_baseline.complete:
            raise PermissionError("TaskWorkspace storage baseline is incomplete")
        assert request.permission_profile is not None
        if workspace_limits is None:
            workspace_limits = WorkspaceStorageLimits(
                request.permission_profile.resources.workspace_bytes,
                request.permission_profile.resources.workspace_entries,
            )
        if directory_binding is None and (
            execution_root is not None
            or request.workspace_root_identity is not None
            or request.workspace_cwd_identity is not None
        ):
            directory_binding = open_execution_directory_binding(
                execution_root or workspace_root or request.cwd,
                cwd or request.cwd,
                expected_root_identity=request.workspace_root_identity,
                expected_cwd_identity=request.workspace_cwd_identity,
            )
        started = time.monotonic()
        launch = None
        # Round-15 review P0-B: re-check the admission fence immediately
        # before spawn.  The check at the top guards against the common
        # case; this one closes the window between the top-of-method check
        # and the actual ``create_subprocess_exec`` (which may follow
        # several awaits for workspace baseline / directory binding).
        if self._state is not _SupervisorState.OPEN:
            if directory_binding is not None:
                directory_binding.close()
            raise SupervisorClosedError(
                f"ProcessSupervisor is {self._state.value}, "
                f"not accepting new executions"
            )
        # Final choke point: do not inherit the agent/desktop environment
        # even if an upstream backend accidentally included a credential in
        # its allowlist or overlay.  An explicit env mapping also prevents
        # asyncio from implicitly inheriting the parent environment.
        safe_environment = scrub_spawn_environment(env or {})
        observed_identity = executable_identity(request.argv, safe_environment)
        if request.executable_identity != observed_identity:
            if directory_binding is not None:
                directory_binding.close()
            raise PermissionError("executable identity changed before native spawn")
        if use_native_launcher:
            authority = None
            try:
                authority = open_executable_authority(
                    request.argv,
                    safe_environment,
                    expected_identity=request.executable_identity,
                )
                launch = build_process_launch(
                    request.argv,
                    cwd=cwd or request.cwd,
                    directory_binding=directory_binding,
                    budget=(
                        request.permission_profile.resources
                        if enforce_resource_limits
                        else None
                    ),
                    enforce_resource_limits=enforce_resource_limits,
                    preserve_directory_fds=preserve_directory_fds,
                    environment=safe_environment,
                    expected_identity=request.executable_identity,
                    executable_authority=authority,
                )
            except BaseException:
                if authority is not None:
                    authority.close()
                if directory_binding is not None:
                    directory_binding.close()
                raise
        try:
            pending_spawn = await self._reserve_spawn(execution_id)
        except BaseException:
            if directory_binding is not None:
                directory_binding.close()
            if launch is not None:
                launch.close_owned_fds()
            raise
        process: asyncio.subprocess.Process | None = None
        spawn_task = asyncio.create_task(
            asyncio.create_subprocess_exec(
                *(launch.argv if launch is not None else request.argv),
                cwd=(
                    launch.cwd
                    if launch is not None
                    else str(cwd or request.cwd)
                ),
                env=safe_environment,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                start_new_session=(
                    launch.start_new_session if launch is not None else True
                ),
                pass_fds=(launch.pass_fds if launch is not None else ()),
            ),
            name=f"khaos-spawn:{execution_id}",
        )
        try:
            process = await asyncio.shield(spawn_task)
            pending_spawn.process = process
        except asyncio.CancelledError:
            # Cancellation of the caller must not cancel the native spawn
            # task and lose a child between the pending registry and process
            # publication.  Finish the spawn transaction, kill the child if
            # one was created, then retain the cancellation outcome.
            try:
                process = await asyncio.shield(spawn_task)
                pending_spawn.process = process
                if process is None:
                    raise RuntimeError("subprocess spawn returned no process")
                await _kill_orphaned_process(process)
            except BaseException as spawn_error:
                await self._finish_pending_spawn(
                    execution_id, pending_spawn, error=spawn_error
                )
                raise
            await self._finish_pending_spawn(
                execution_id,
                pending_spawn,
                error=RuntimeError("subprocess spawn cancelled before registration"),
            )
            raise
        except BaseException as spawn_error:
            await self._finish_pending_spawn(
                execution_id, pending_spawn, error=spawn_error
            )
            raise
        finally:
            # ``finally`` (not ``except``) so ``CancelledError`` — a
            # ``BaseException`` — still closes the directory binding.
            if directory_binding is not None:
                directory_binding.close()
            if launch is not None:
                launch.close_owned_fds()
        if process is None:
            await self._finish_pending_spawn(
                execution_id,
                pending_spawn,
                error=RuntimeError("subprocess spawn did not produce a process"),
            )
            raise RuntimeError("subprocess spawn did not produce a process")
        active = _ActiveProcess(
            process,
            termination_callback=termination_callback,
        )
        storage_roots = _storage_roots(
            process.pid, tmp_root, sandbox_storage_paths
        )
        # Create and publish the watchdog before registering the process.
        # Once the process enters ``_active``, the registry entry is a
        # complete ownership record; shutdown cannot observe a process and
        # then race with a later watchdog publication.
        watchdog_task = asyncio.create_task(
            _resource_watchdog(
                process, active, request.permission_profile.resources,
                self._terminate_active,
                storage_roots=storage_roots,
                workspace_root=workspace_root,
                workspace_baseline=workspace_baseline,
                workspace_limits=workspace_limits,
                storage_authority=self.storage_authority,
            ) if watchdog_enabled else _no_resource_violation()
        )
        active.watchdog_task = watchdog_task
        try:
            await self._register(execution_id, active, pending_spawn)
        except BaseException:
            # Round-15 review P0-2: spawn committed but registration
            # failed (supervisor closed during spawn, or duplicate id).
            # Kill the just-spawned process group so we don't leak it.
            try:
                await _kill_orphaned_process(process)
            finally:
                watchdog_task.cancel()
                await asyncio.gather(watchdog_task, return_exceptions=True)
                await self._finish_pending_spawn(
                    execution_id,
                    pending_spawn,
                    error=RuntimeError("spawn ownership registration failed"),
                )
            raise
        if process is None:
            raise RuntimeError("subprocess spawn returned no process")
        total_limit = request.permission_profile.resources.output_bytes
        stdout_limit = (total_limit + 1) // 2
        stderr_limit = total_limit // 2
        stdout_task = asyncio.create_task(
            _drain_bounded(process.stdout, stdout_limit)
        )
        stderr_task = asyncio.create_task(
            _drain_bounded(process.stderr, stderr_limit)
        )
        status = "failed"
        diagnostics: dict[str, object] = {}
        # Batch 11.6 (round-11 §十): track the race tasks so the finally
        # block can cancel + await them on every exit path (including
        # CancelledError).  Without this, a cancelled long-timeout run
        # leaves the deadline sleep task alive until its original deadline.
        process_wait_task: asyncio.Task[int] | None = None
        deadline_task: asyncio.Task[None] | None = None
        try:
            try:
                # Batch 10.1 (round-10 §四): replace the returncode-based
                # signal-death heuristic (PR #115) with a TRUE deadline
                # race.  We race ``process.wait()`` against a deadline
                # sleep task and record WHICH task won.  Only when the
                # deadline task wins (the process was still running when
                # the deadline elapsed) do we classify as timed-out.  A
                # process that exits on its own — for ANY reason,
                # including signal death (SIGTERM/SIGKILL), exit(200),
                # OOM kill, or external admin kill — keeps its real
                # status (passed/failed).  This stops masking crashes
                # and external kills as timeouts.
                timeout_seconds = (
                    request.permission_profile.resources.timeout_seconds
                )
                process_wait_task = asyncio.create_task(process.wait())
                if timeout_seconds is not None:
                    deadline_task = asyncio.create_task(
                        asyncio.sleep(timeout_seconds)
                    )
                wait_set: set[asyncio.Task[Any]] = {process_wait_task}
                if deadline_task is not None:
                    wait_set.add(deadline_task)
                done, _pending = await asyncio.wait(
                    wait_set, return_when=asyncio.FIRST_COMPLETED,
                )
                if process_wait_task in done:
                    # Process completion wins a same-loop tie with the
                    # deadline task.  ``asyncio.wait`` may return both tasks
                    # in ``done`` when a child exits at the deadline
                    # boundary; terminal process evidence must not be
                    # reclassified as a timeout merely because the deadline
                    # sleeper was also ready.  Only a deadline task that is
                    # done while the process wait is still pending proves a
                    # genuine timeout.
                    if deadline_task is not None:
                        deadline_task.cancel()
                    status = "passed" if process.returncode == 0 else "failed"
                elif deadline_task is not None and deadline_task in done:
                    # Deadline elapsed first → genuine timeout.  Cancel
                    # the wait task, terminate the process group, mark
                    # timed-out.  The process may have already exited
                    # (Docker daemon race) — _terminate_active is a no-op
                    # when returncode is set, but the deadline proof
                    # stands: the configured budget elapsed.
                    process_wait_task.cancel()
                    active.termination_requested = True
                    await self._terminate_active(active)
                    status = "timed-out"
                    diagnostics.update(
                        {
                            "timeout_seconds": timeout_seconds,
                            "process_group_terminated": True,
                        }
                    )
            except asyncio.CancelledError:
                active.termination_requested = True
                await asyncio.shield(self._terminate_active(active))
                await asyncio.shield(
                    asyncio.gather(stdout_task, stderr_task)
                )
                watchdog_task.cancel()
                raise
            try:
                # The supervisor owns the watchdog task, so shutdown may
                # cancel it after proving that the process has terminated.
                # Shield the child await and distinguish that owner-side
                # cancellation from cancellation of this run itself; the
                # latter must still propagate to the caller.
                resource_violation = await asyncio.shield(watchdog_task)
            except asyncio.CancelledError:
                current_task = asyncio.current_task()
                if (
                    not watchdog_task.cancelled()
                    or (current_task is not None and current_task.cancelling())
                ):
                    raise
                resource_violation = None
            if resource_violation is None and workspace_root is not None:
                resource_violation = await asyncio.to_thread(
                    self.storage_authority.assess,
                    workspace_root,
                    workspace_baseline,
                    workspace_limits,
                )
            if resource_violation is not None:
                status = "resource-exhausted"
                diagnostics["resource_violation"] = resource_violation
            elif active.termination_requested and status != "timed-out":
                status = "cancelled"
            stdout, stdout_total = await stdout_task
            stderr, stderr_total = await stderr_task
        finally:
            # Batch 11.6: cancel + await ALL race tasks on every exit
            # path so no pending task outlives run().  This closes the
            # leak where a cancelled long-timeout run left the deadline
            # sleeper alive until its original deadline.
            pending_tasks: list[asyncio.Task[Any]] = [t for t in (process_wait_task, deadline_task) if t is not None]
            for t in pending_tasks:
                if not t.done():
                    t.cancel()
            if pending_tasks:
                await asyncio.gather(*pending_tasks, return_exceptions=True)
            if not watchdog_task.done():
                watchdog_task.cancel()
                await asyncio.gather(watchdog_task, return_exceptions=True)
            try:
                await self._unregister(execution_id, active)
            finally:
                await self._finish_pending_spawn(execution_id, pending_spawn)

        diagnostics.update(
            {
                "output_truncated": (
                    stdout_total > len(stdout) or stderr_total > len(stderr)
                ),
                "stdout_truncated": stdout_total > len(stdout),
                "stderr_truncated": stderr_total > len(stderr),
                "stdout_bytes_dropped": max(0, stdout_total - len(stdout)),
                "stderr_bytes_dropped": max(0, stderr_total - len(stderr)),
                "process_group_terminated": bool(
                    diagnostics.get("process_group_terminated")
                    or active.termination_requested
                ),
                "resource_limits": _resource_limit_diagnostics(
                    request.permission_profile.resources
                ) if enforce_resource_limits else {
                    "enforced_by": "external-backend",
                },
            }
        )
        return ExecutionResult(
            execution_id=execution_id,
            status=status,
            return_code=process.returncode,
            stdout=stdout.decode("utf-8", errors="replace"),
            stderr=stderr.decode("utf-8", errors="replace"),
            duration_ms=int((time.monotonic() - started) * 1000),
            diagnostics=diagnostics,
        )

    async def register_process(
        self,
        execution_id: str,
        process: asyncio.subprocess.Process,
        *,
        budget=None,
        tmp_root: Path | None = None,
        sandbox_storage_paths: tuple[str, ...] = (),
    ) -> asyncio.Task[dict | None] | None:
        """Register and resource-watch a managed stdio process.

        Round-15 review P0-B: rejects registration after shutdown has begun.
        If registration fails for ANY reason (supervisor closed, duplicate
        id), the just-spawned process is killed so the caller doesn't leak it.
        """
        if self._state is not _SupervisorState.OPEN:
            await _kill_orphaned_process(process)
            raise SupervisorClosedError(
                f"ProcessSupervisor is {self._state.value}, "
                f"not accepting new registrations"
            )
        active = _ActiveProcess(process)
        watchdog_task: asyncio.Task[dict | None] | None = None
        if budget is not None:
            storage_roots = _storage_roots(
                process.pid, tmp_root, sandbox_storage_paths
            )
            watchdog_task = asyncio.create_task(
                _resource_watchdog(
                    process, active, budget, self._terminate_active,
                    storage_roots=storage_roots,
                )
            )
            active.watchdog_task = watchdog_task
        try:
            await self._register(execution_id, active)
        except BaseException:
            # Round-15 review P0-2: spawn committed but registration
            # failed — kill the process group so we don't leak it.
            try:
                await _kill_orphaned_process(process)
            finally:
                if watchdog_task is not None:
                    watchdog_task.cancel()
                    await asyncio.gather(watchdog_task, return_exceptions=True)
            raise
        return watchdog_task

    async def unregister_process(self, execution_id: str) -> None:
        async with self._registry_lock:
            active = self._active.get(execution_id)
        if active is None:
            return
        if active.process.returncode is None:
            raise RuntimeError(
                f"cannot unregister live process {execution_id}; terminal proof is missing"
            )
        await self._settle_watchdog(active)
        async with self._registry_lock:
            if self._active.get(execution_id) is active:
                self._active.pop(execution_id, None)

    async def terminate(self, execution_id: str) -> bool:
        """Terminate one complete process group, returning whether it existed."""
        async with self._registry_lock:
            active = self._active.get(execution_id)
            pending = self._pending_spawns.get(execution_id)
        if active is None:
            if pending is None:
                return False
            pending.termination_requested = True
            await asyncio.shield(pending.ready.wait())
            async with self._registry_lock:
                active = self._active.get(execution_id)
                still_pending = self._pending_spawns.get(execution_id)
            if active is None:
                if still_pending is not None:
                    await asyncio.shield(still_pending.done.wait())
                return True
        active.termination_requested = True
        await self._terminate_active(active)
        current_pending = self._pending_spawns.get(execution_id)
        if current_pending is not None:
            await asyncio.shield(current_pending.done.wait())
        return True

    async def shutdown(self) -> None:
        """Shut down all active child processes.

        Round-17 review §四: shutdown now uses a shared ``_shutdown_task``
        so concurrent callers observe the same result — the second caller
        no longer sees ``CLOSING`` and returns a false success while the
        first caller may still fail to QUARANTINED.  All callers await the
        SAME task.

        Round-17 review §四: CancelledError during ``terminate()`` now
        enters QUARANTINED (not CLOSED) because the process may still be
        alive — ownership release is unproven.  Previously CancelledError
        was swallowed as ``cancel_requested`` and the supervisor
        transitioned to CLOSED, losing the retry opportunity forever.

        The registry is released one entry at a time only after the process
        and its watchdog have both reached terminal state.  A final
        ``dict.clear()`` is deliberately forbidden: dropping an entry is not
        evidence that its real resource disappeared.

        Round-17 review §四 (amendment): the admission fence (OPEN →
        CLOSING) is set IMMEDIATELY in ``shutdown()`` before the
        ``_run_shutdown`` task is scheduled, so that ``register_process``
        and ``run()`` reject even before ``_run_shutdown`` starts running.
        Previously the state transition happened inside ``_run_shutdown``,
        creating a race window where registration could slip in after
        ``shutdown()`` was called but before the task ran.
        """
        if self._state is _SupervisorState.CLOSED:
            return
        # Set the admission fence IMMEDIATELY (before creating the task)
        # so register_process/run() reject even before _run_shutdown
        # starts.  QUARANTINED is already admission-closed (not OPEN).
        if self._state is _SupervisorState.OPEN:
            self._state = _SupervisorState.CLOSING
        # Reuse an in-flight shutdown task so concurrent callers observe
        # the same result.  A completed (failed) task is NOT reused —
        # QUARANTINED is retryable and a new task is created.
        if self._shutdown_task is not None and not self._shutdown_task.done():
            await asyncio.shield(self._shutdown_task)
            return
        self._shutdown_task = asyncio.ensure_future(self._run_shutdown())
        await asyncio.shield(self._shutdown_task)

    async def _run_shutdown(self) -> None:
        """The actual shutdown sequence — may run multiple times via retry."""
        if self._state is _SupervisorState.CLOSED:
            return
        # QUARANTINED is retryable — transition back to CLOSING so we
        # attempt to terminate any remaining active processes.
        if self._state is _SupervisorState.QUARANTINED:
            if not self._active:
                self._state = _SupervisorState.CLOSED
                return
            self._state = _SupervisorState.CLOSING
        # CLOSING (set by shutdown()) or OPEN (direct call) — proceed
        # with the actual cleanup.  No early return for CLOSING: the
        # admission fence was set by shutdown() before scheduling this
        # task, and we need to actually run the cleanup.
        elif self._state is _SupervisorState.OPEN:
            self._state = _SupervisorState.CLOSING
        errors: list[Exception] = []
        cancel_requested = False
        execution_ids = tuple(
            sorted(set(self.active_execution_ids) | set(self.pending_execution_ids))
        )
        for execution_id in execution_ids:
            try:
                # Round-17: shield each terminate so an outer cancellation
                # does not interrupt the process kill before returncode
                # is confirmed.  If CancelledError still occurs (from
                # inside terminate), record it as an error — ownership
                # release is unproven.
                await asyncio.shield(self.terminate(execution_id))
                async with self._registry_lock:
                    active = self._active.get(execution_id)
                    pending = self._pending_spawns.get(execution_id)
                if active is not None:
                    await asyncio.shield(self._settle_watchdog(active))
                    if active.process.returncode is None:
                        raise RuntimeError(
                            f"process {execution_id} remains live after terminate"
                        )
                    async with self._registry_lock:
                        if self._active.get(execution_id) is active:
                            self._active.pop(execution_id, None)
                        else:
                            raise RuntimeError(
                                f"execution {execution_id} ownership changed during shutdown"
                            )
                if pending is not None:
                    await asyncio.shield(pending.done.wait())
            except asyncio.CancelledError:
                cancel_requested = True
                errors.append(RuntimeError(
                    f"terminate({execution_id}) cancelled — process death unproven"
                ))
                logger.debug(
                    "ProcessSupervisor shutdown: terminate(%s) cancelled",
                    execution_id,
                )
            except Exception as exc:
                errors.append(exc)
                logger.debug(
                    "ProcessSupervisor shutdown: terminate(%s) failed",
                    execution_id, exc_info=True,
                )
        if errors:
            self._state = _SupervisorState.QUARANTINED
            raise SupervisorClosedError(
                f"ProcessSupervisor shutdown completed with "
                f"{len(errors)} error(s): "
                + "; ".join(type(e).__name__ for e in errors)
            ) from errors[0]
        # Do not clear the registry to manufacture the CLOSED invariant.
        # Any surviving entry is a failed terminal proof and must remain
        # visible for quarantine/retry.
        if self._active or self._pending_spawns:
            self._state = _SupervisorState.QUARANTINED
            raise SupervisorClosedError(
                "ProcessSupervisor shutdown left owned resources after cleanup"
            )
        self._state = _SupervisorState.CLOSED
        if cancel_requested:
            raise asyncio.CancelledError()

    async def _reserve_spawn(self, execution_id: str) -> _PendingSpawn:
        """Publish spawn ownership before the native create call."""
        async with self._registry_lock:
            if self._state is not _SupervisorState.OPEN:
                raise SupervisorClosedError(
                    f"ProcessSupervisor is {self._state.value}, "
                    f"not accepting new executions"
                )
            if execution_id in self._active or execution_id in self._pending_spawns:
                raise RuntimeError(f"execution id is already active: {execution_id}")
            pending = _PendingSpawn()
            self._pending_spawns[execution_id] = pending
            return pending

    async def _register(
        self,
        execution_id: str,
        active: _ActiveProcess,
        pending: _PendingSpawn | None = None,
    ) -> None:
        async with self._registry_lock:
            current_pending = self._pending_spawns.get(execution_id)
            if self._state is not _SupervisorState.OPEN and current_pending is not pending:
                raise SupervisorClosedError(
                    f"ProcessSupervisor is {self._state.value}, "
                    f"cannot register execution {execution_id}"
                )
            if execution_id in self._active:
                raise RuntimeError(f"execution id is already active: {execution_id}")
            self._active[execution_id] = active
            if current_pending is not None:
                current_pending.active = active
                current_pending.ready.set()

    async def _unregister(
        self, execution_id: str, active: _ActiveProcess
    ) -> None:
        if active.process.returncode is None:
            raise RuntimeError(
                f"cannot unregister live process {execution_id}; terminal proof is missing"
            )
        await self._settle_watchdog(active)
        async with self._registry_lock:
            if self._active.get(execution_id) is active:
                self._active.pop(execution_id, None)

    async def _finish_pending_spawn(
        self,
        execution_id: str,
        pending: _PendingSpawn,
        *,
        error: BaseException | None = None,
    ) -> None:
        async with self._registry_lock:
            current = self._pending_spawns.get(execution_id)
            if current is not pending:
                return
            if error is not None:
                pending.error = error
            pending.ready.set()
            pending.done.set()
            self._pending_spawns.pop(execution_id, None)

    async def _settle_watchdog(self, active: _ActiveProcess) -> None:
        """Cancel and await a watchdog before releasing its owner entry."""
        watchdog = active.watchdog_task
        if watchdog is None:
            return
        if not watchdog.done():
            watchdog.cancel()
        try:
            await asyncio.wait_for(
                asyncio.gather(watchdog, return_exceptions=True),
                timeout=max(self.termination_grace_seconds, 0.1),
            )
        except TimeoutError as exc:
            raise RuntimeError("process watchdog did not reach terminal state") from exc
        if not watchdog.done():
            raise RuntimeError("process watchdog remains pending after cancellation")
        if watchdog.cancelled():
            return
        watchdog_error = watchdog.exception()
        if watchdog_error is not None and not isinstance(watchdog_error, asyncio.CancelledError):
            raise RuntimeError("process watchdog failed before terminal proof") from watchdog_error

    async def _terminate_active(self, active: _ActiveProcess) -> None:
        async with active.termination_lock:
            process = active.process
            if process.returncode is None:
                _signal_process_group(process, signal.SIGTERM)
                try:
                    await asyncio.wait_for(
                        process.wait(), timeout=self.termination_grace_seconds
                    )
                except TimeoutError:
                    force_signal = getattr(signal, "SIGKILL", signal.SIGTERM)
                    _signal_process_group(process, force_signal, force=True)
                    await process.wait()
            # A native sandbox may have descendants that are outside the
            # supervisor's process group (for example after bwrap creates a
            # PID namespace).  Invoke the backend-owned kernel terminator
            # even when the launcher itself has already exited; otherwise
            # those descendants can retain stdout/stderr pipes forever and
            # prevent the supervisor from reaching a terminal result.
            if active.termination_callback is not None:
                await active.termination_callback()


async def _no_resource_violation() -> None:
    return None


async def _drain_bounded(
    stream: asyncio.StreamReader | None, limit: int
) -> tuple[bytes, int]:
    if stream is None:
        return b"", 0
    retained = bytearray()
    total = 0
    while True:
        chunk = await stream.read(8192)
        if not chunk:
            break
        total += len(chunk)
        remaining = limit - len(retained)
        if remaining > 0:
            retained.extend(chunk[:remaining])
    return bytes(retained), total


def _signal_process_group(
    process: asyncio.subprocess.Process,
    sig: signal.Signals,
    *,
    force: bool = False,
) -> None:
    if process.returncode is not None:
        return
    if os.name == "posix" and process.pid is not None:
        try:
            os.killpg(process.pid, sig)
            return
        except ProcessLookupError:
            return
        except OSError:
            pass
    if force:
        process.kill()
    else:
        process.terminate()


async def _kill_orphaned_process(process: asyncio.subprocess.Process) -> None:
    """Round-15 review P0-2: best-effort kill+wait for a process whose
    ownership publication failed.  Swallows all errors — this is cleanup
    of a half-spawned child that the caller is about to abandon."""
    if process.returncode is not None:
        return
    try:
        _signal_process_group(process, signal.SIGKILL, force=True)
    except BaseException:  # noqa: BLE001 — best-effort orphan cleanup
        return
    try:
        await asyncio.wait_for(process.wait(), timeout=2.0)
    except BaseException:
        logger.debug("orphaned process did not settle after SIGKILL", exc_info=True)


def _resource_limit_diagnostics(budget) -> dict[str, object]:
    return {
        "posix_rlimit_enforced": os.name == "posix",
        "process_tree_watchdog_enforced": os.name == "posix",
        "pids": budget.pids,
        "memory_bytes": budget.memory_bytes,
        "memory_limit_kind": (
            "supervisor-watchdog" if sys.platform == "darwin"
            else "address-space"
        ),
        "file_bytes": budget.file_bytes,
        "open_files": budget.open_files,
        "cpu_quota_enforced": False,
        "cpu_time_seconds": max(1, math.ceil(budget.cpu_time_seconds)),
        "tmpfs_bytes": budget.tmpfs_bytes,
        "filesystem_entries": budget.filesystem_entries,
        "workspace_bytes": budget.workspace_bytes,
        "workspace_entries": budget.workspace_entries,
    }


async def _resource_watchdog(
    process,
    active,
    budget,
    terminate,
    *,
    storage_roots: tuple[Path, ...] = (),
    workspace_root: Path | None = None,
    workspace_baseline: WorkspaceStorageSnapshot | None = None,
    workspace_limits: WorkspaceStorageLimits | None = None,
    storage_authority: WorkspaceStorageAuthority | None = None,
) -> dict | None:
    """Bound process-tree and writable synthetic filesystem resources."""
    if process.pid is None:
        return None
    process_tree_supported = os.name == "posix"
    if not process_tree_supported and not storage_roots and workspace_root is None:
        return None
    while process.returncode is None:
        if process_tree_supported:
            process_count, resident_bytes = await asyncio.to_thread(
                _process_group_usage, process.pid
            )
            deleted_bytes, deleted_complete = await asyncio.to_thread(
                _deleted_open_file_usage, process.pid
            )
            if not deleted_complete:
                # /proc is a live view: a process can exit between listing
                # its fd directory and reading one of the entries.  Treat a
                # single incomplete sample as an observation race, not as a
                # workspace violation.  A second sample after one event-loop
                # turn still fails closed when the accounting is genuinely
                # unavailable while the process remains alive.
                await asyncio.sleep(0.01)
                deleted_bytes, deleted_complete = await asyncio.to_thread(
                    _deleted_open_file_usage, process.pid
                )
                if not deleted_complete and process.returncode is not None:
                    # The process reached terminal state during the retry;
                    # there is no remaining live process tree to account.
                    deleted_bytes, deleted_complete = 0, True
        else:
            process_count, resident_bytes = 0, 0
            deleted_bytes, deleted_complete = 0, True
        violation = None
        if process_tree_supported and process_count > budget.pids:
            violation = {
                "kind": "pids", "observed": process_count,
                "limit": budget.pids,
            }
        elif process_tree_supported and resident_bytes > budget.memory_bytes:
            violation = {
                "kind": "memory", "observed": resident_bytes,
                "limit": budget.memory_bytes,
            }
        elif storage_roots:
            temporary_bytes, filesystem_entries = await asyncio.to_thread(
                _directory_usage, storage_roots
            )
            if temporary_bytes > budget.tmpfs_bytes:
                violation = {
                    "kind": "tmpfs",
                    "observed": temporary_bytes,
                    "limit": budget.tmpfs_bytes,
                }
            elif filesystem_entries > budget.filesystem_entries:
                violation = {
                    "kind": "filesystem-entries",
                    "observed": filesystem_entries,
                    "limit": budget.filesystem_entries,
                }
        if violation is None and workspace_root is not None:
            if storage_authority is None or workspace_limits is None:
                violation = {
                    "kind": "workspace-observation",
                    "observed": "authority-unavailable",
                    "limit": "authority-required",
                }
            elif not deleted_complete:
                violation = {
                    "kind": "workspace-observation",
                    "observed": "deleted-open-files-unobservable",
                    "limit": "complete-process-fd-accounting",
                }
            else:
                violation = await asyncio.to_thread(
                    storage_authority.assess,
                    workspace_root,
                    workspace_baseline,
                    workspace_limits,
                    extra_allocated_bytes=deleted_bytes,
                )
        if violation is not None:
            active.termination_requested = True
            await terminate(active)
            return violation
        await asyncio.sleep(0.05)
    return None


def _storage_roots(
    process_id: int | None,
    host_root: Path | None,
    sandbox_paths: tuple[str, ...],
) -> tuple[Path, ...]:
    roots = [host_root] if host_root is not None else []
    if sys.platform.startswith("linux") and process_id is not None:
        namespace_root = Path(f"/proc/{process_id}/root")
        for value in sandbox_paths:
            path = Path(value)
            if not path.is_absolute() or ".." in path.parts:
                raise ValueError("sandbox storage paths must be absolute and normalized")
            roots.append(namespace_root / str(path).lstrip("/"))
    return tuple(roots)


def _directory_usage(roots: tuple[Path, ...]) -> tuple[int, int]:
    total = 0
    entries = 0
    seen: set[tuple[int, int]] = set()
    for root in roots:
        try:
            iterator = os.walk(root, followlinks=False)
        except OSError:
            continue
        for directory, subdirectories, files in iterator:
            entries += len(subdirectories)
            for name in files:
                try:
                    value = os.stat(
                        Path(directory) / name, follow_symlinks=False
                    )
                except OSError:
                    continue
                identity = (value.st_dev, value.st_ino)
                if identity in seen:
                    continue
                seen.add(identity)
                entries += 1
                if stat.S_ISREG(value.st_mode):
                    total += value.st_size
    return total, entries


def _process_group_usage(process_group_id: int) -> tuple[int, int]:
    if sys.platform.startswith("linux"):
        return _linux_process_group_usage(process_group_id)
    if sys.platform == "darwin":
        return _darwin_process_group_usage(process_group_id)
    return 0, 0


def _deleted_open_file_usage(process_group_id: int) -> tuple[int, bool]:
    """Account unlinked files still consuming blocks in a supervised group."""
    if sys.platform.startswith("linux"):
        return _linux_deleted_open_file_usage(process_group_id)
    if sys.platform == "darwin":
        return _darwin_deleted_open_file_usage(process_group_id)
    return 0, False


def _linux_deleted_open_file_usage(
    process_group_id: int,
) -> tuple[int, bool]:
    total = 0
    complete = True
    seen: set[tuple[int, int]] = set()
    for pid in _linux_process_group_pids(process_group_id):
        fd_root = Path(f"/proc/{pid}/fd")
        try:
            descriptors = tuple(fd_root.iterdir())
        except FileNotFoundError:
            continue
        except OSError:
            complete = False
            continue
        for descriptor in descriptors:
            try:
                target = os.readlink(descriptor)
                if not target.endswith(" (deleted)"):
                    continue
                info = os.stat(descriptor)
            except FileNotFoundError:
                continue
            except OSError:
                complete = False
                continue
            if not stat.S_ISREG(info.st_mode):
                continue
            identity = (info.st_dev, info.st_ino)
            if identity in seen:
                continue
            seen.add(identity)
            allocated = int(getattr(info, "st_blocks", 0)) * 512
            total += max(allocated, info.st_size if allocated <= 0 else 0)
    return total, complete


def _darwin_deleted_open_file_usage(
    process_group_id: int,
) -> tuple[int, bool]:
    try:
        completed = subprocess.run(
            (
                "/usr/sbin/lsof", "-nP", "-a", f"-g{process_group_id}",
                "+L1", "-F", "pfsDi",
            ),
            capture_output=True,
            text=True,
            timeout=0.5,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return 0, False
    if completed.returncode not in {0, 1}:
        return 0, False
    total = 0
    seen: set[tuple[str, str]] = set()
    current_pid = ""
    current_fd = ""
    current_device = ""
    current_inode = ""
    current_size = 0

    def commit() -> None:
        nonlocal total
        if not current_fd:
            return
        identity = (
            current_device,
            current_inode or f"{current_pid}:{current_fd}",
        )
        if identity not in seen:
            seen.add(identity)
            total += max(0, current_size)

    for line in completed.stdout.splitlines():
        if not line:
            continue
        field, value = line[0], line[1:]
        if field == "p":
            commit()
            current_pid = value
            current_fd = ""
            current_device = ""
            current_inode = ""
            current_size = 0
        elif field == "f":
            commit()
            current_fd = value
            current_device = ""
            current_inode = ""
            current_size = 0
        elif field == "D":
            current_device = value
        elif field == "i":
            current_inode = value
        elif field == "s":
            try:
                current_size = int(value)
            except ValueError:
                return 0, False
    commit()
    return total, True


def _linux_process_group_pids(process_group_id: int) -> tuple[int, ...]:
    values: list[int] = []
    for stat_path in Path("/proc").glob("[0-9]*/stat"):
        try:
            fields = stat_path.read_text(encoding="utf-8").rsplit(")", 1)[1].split()
            if int(fields[2]) == process_group_id:
                values.append(int(stat_path.parent.name))
        except (OSError, ValueError, IndexError):
            continue
    return tuple(values)


def _darwin_process_group_usage(process_group_id: int) -> tuple[int, int]:
    import ctypes

    class ProcTaskInfo(ctypes.Structure):
        _fields_ = [
            ("virtual_size", ctypes.c_uint64),
            ("resident_size", ctypes.c_uint64),
            ("total_user", ctypes.c_uint64),
            ("total_system", ctypes.c_uint64),
            ("threads_user", ctypes.c_uint64),
            ("threads_system", ctypes.c_uint64),
            ("policy", ctypes.c_int32),
            ("faults", ctypes.c_int32),
            ("pageins", ctypes.c_int32),
            ("cow_faults", ctypes.c_int32),
            ("messages_sent", ctypes.c_int32),
            ("messages_received", ctypes.c_int32),
            ("syscalls_mach", ctypes.c_int32),
            ("syscalls_unix", ctypes.c_int32),
            ("csw", ctypes.c_int32),
            ("threadnum", ctypes.c_int32),
            ("numrunning", ctypes.c_int32),
            ("priority", ctypes.c_int32),
        ]

    libproc = ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True)
    required = libproc.proc_listpids(2, process_group_id, None, 0)
    if required <= 0:
        return 0, 0
    capacity = max(1, required // ctypes.sizeof(ctypes.c_int) + 8)
    pids = (ctypes.c_int * capacity)()
    returned = libproc.proc_listpids(
        2, process_group_id, ctypes.byref(pids), ctypes.sizeof(pids)
    )
    count = max(0, returned // ctypes.sizeof(ctypes.c_int))
    resident_bytes = 0
    live_count = 0
    for pid in pids[:count]:
        if pid <= 0:
            continue
        info = ProcTaskInfo()
        size = libproc.proc_pidinfo(
            pid, 4, 0, ctypes.byref(info), ctypes.sizeof(info)
        )
        if size == ctypes.sizeof(info):
            live_count += 1
            resident_bytes += int(info.resident_size)
    return live_count, resident_bytes


def _linux_process_group_usage(process_group_id: int) -> tuple[int, int]:
    count = 0
    resident_bytes = 0
    page_size = os.sysconf("SC_PAGE_SIZE")
    for stat_path in Path("/proc").glob("[0-9]*/stat"):
        try:
            fields = stat_path.read_text(encoding="utf-8").rsplit(")", 1)[1].split()
            if int(fields[2]) != process_group_id:
                continue
            count += 1
            resident_bytes += int(fields[21]) * page_size
        except (OSError, ValueError, IndexError):
            continue
    return count, resident_bytes
