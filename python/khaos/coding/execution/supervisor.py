"""Unified lifecycle supervision for Agent-owned subprocess trees."""

from __future__ import annotations

import asyncio
import math
import os
import signal
import stat
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

from khaos.coding.execution.models import ExecutionRequest, ExecutionResult
from khaos.coding.workspace.storage import (
    WorkspaceStorageAuthority,
    WorkspaceStorageLimits,
    WorkspaceStorageSnapshot,
    capture_workspace_snapshot,
)


@dataclass
class _ActiveProcess:
    process: asyncio.subprocess.Process
    termination_requested: bool = False
    termination_lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    watchdog_task: asyncio.Task[dict | None] | None = None


class ProcessSupervisor:
    """Own process groups, bounded output, cancellation, and teardown."""

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
        self._registry_lock = asyncio.Lock()

    @property
    def active_execution_ids(self) -> tuple[str, ...]:
        return tuple(sorted(self._active))

    async def run(
        self,
        request: ExecutionRequest,
        *,
        cwd: Path | None = None,
        env: dict[str, str] | None = None,
        enforce_resource_limits: bool = True,
        enforce_resource_watchdog: bool | None = None,
        tmp_root: Path | None = None,
        sandbox_storage_paths: tuple[str, ...] = (),
        workspace_root: Path | None = None,
        workspace_baseline: WorkspaceStorageSnapshot | None = None,
        workspace_limits: WorkspaceStorageLimits | None = None,
    ) -> ExecutionResult:
        """Run one foreground process with bounded, fairly split output."""
        execution_id = request.correlation_id
        if not execution_id:
            raise ValueError("supervised execution requires a correlation id")
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
        if workspace_limits is None:
            workspace_limits = WorkspaceStorageLimits(
                request.permission_profile.resources.workspace_bytes,
                request.permission_profile.resources.workspace_entries,
            )
        started = time.monotonic()
        process = await asyncio.create_subprocess_exec(
            *request.argv,
            cwd=str(cwd or request.cwd),
            env=env,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            start_new_session=True,
            preexec_fn=(
                resource_limit_preexec(request.permission_profile.resources)
                if enforce_resource_limits else None
            ),
        )
        active = _ActiveProcess(process)
        await self._register(execution_id, active)
        storage_roots = _storage_roots(
            process.pid, tmp_root, sandbox_storage_paths
        )
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
        try:
            try:
                await asyncio.wait_for(
                    process.wait(),
                    timeout=request.permission_profile.resources.timeout_seconds,
                )
                status = "passed" if process.returncode == 0 else "failed"
            except asyncio.TimeoutError:
                active.termination_requested = True
                await self._terminate_active(active)
                status = "timed-out"
                diagnostics.update(
                    {
                        "timeout_seconds": (
                            request.permission_profile.resources.timeout_seconds
                        ),
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
            resource_violation = await watchdog_task
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
            if not watchdog_task.done():
                watchdog_task.cancel()
            await self._unregister(execution_id, active)

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
        """Register and resource-watch a managed stdio process."""
        active = _ActiveProcess(process)
        await self._register(execution_id, active)
        if budget is not None:
            storage_roots = _storage_roots(
                process.pid, tmp_root, sandbox_storage_paths
            )
            active.watchdog_task = asyncio.create_task(
                _resource_watchdog(
                    process, active, budget, self._terminate_active,
                    storage_roots=storage_roots,
                )
            )
        return active.watchdog_task

    async def unregister_process(self, execution_id: str) -> None:
        async with self._registry_lock:
            active = self._active.pop(execution_id, None)
        if (
            active is not None
            and active.watchdog_task is not None
            and not active.watchdog_task.done()
        ):
            active.watchdog_task.cancel()

    async def terminate(self, execution_id: str) -> bool:
        """Terminate one complete process group, returning whether it existed."""
        async with self._registry_lock:
            active = self._active.get(execution_id)
        if active is None:
            return False
        active.termination_requested = True
        await self._terminate_active(active)
        return True

    async def shutdown(self) -> None:
        for execution_id in self.active_execution_ids:
            await self.terminate(execution_id)

    async def _register(
        self, execution_id: str, active: _ActiveProcess
    ) -> None:
        async with self._registry_lock:
            if execution_id in self._active:
                await self._terminate_active(active)
                raise RuntimeError(f"execution id is already active: {execution_id}")
            self._active[execution_id] = active

    async def _unregister(
        self, execution_id: str, active: _ActiveProcess
    ) -> None:
        async with self._registry_lock:
            if self._active.get(execution_id) is active:
                self._active.pop(execution_id, None)

    async def _terminate_active(self, active: _ActiveProcess) -> None:
        async with active.termination_lock:
            process = active.process
            if process.returncode is not None:
                return
            _signal_process_group(process, signal.SIGTERM)
            try:
                await asyncio.wait_for(
                    process.wait(), timeout=self.termination_grace_seconds
                )
                return
            except asyncio.TimeoutError:
                force_signal = getattr(signal, "SIGKILL", signal.SIGTERM)
                _signal_process_group(process, force_signal, force=True)
                await process.wait()


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


def resource_limit_preexec(budget):
    """Build a POSIX child hook that makes declared budgets non-optional."""
    if os.name != "posix":
        return None

    def apply_limits() -> None:
        import resource

        limits = [
            (resource.RLIMIT_FSIZE, budget.file_bytes),
            (resource.RLIMIT_NOFILE, budget.open_files),
            (
                resource.RLIMIT_CPU,
                max(1, math.ceil(budget.cpu_time_seconds)),
            ),
        ]
        # Darwin exposes RLIMIT_AS/RLIMIT_RSS constants but rejects attempts
        # to lower them. Memory is enforced by the supervisor watchdog there.
        if sys.platform != "darwin":
            limits.append((resource.RLIMIT_AS, budget.memory_bytes))
        for resource_id, requested in limits:
            _, hard = resource.getrlimit(resource_id)
            effective = requested
            if hard != resource.RLIM_INFINITY:
                effective = min(effective, hard)
            resource.setrlimit(resource_id, (effective, effective))

    return apply_limits


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
        else:
            process_count, resident_bytes = 0, 0
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
            else:
                violation = await asyncio.to_thread(
                    storage_authority.assess,
                    workspace_root,
                    workspace_baseline,
                    workspace_limits,
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
