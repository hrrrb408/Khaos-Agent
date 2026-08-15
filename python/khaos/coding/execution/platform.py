"""Platform sandbox capability probes and command builders."""

# KHAOS-PRIVILEGED-SPAWN owner=ExecutionBackend threat-model=kernel-sandbox-and-resource-control boundary=execution-service

from __future__ import annotations

import asyncio
import json
import logging
import math
import os
import re
import secrets
import shutil
import stat
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Literal, cast

from khaos.coding.execution.binding import (
    ExecutionDirectoryBinding,
    open_execution_directory_binding,
)
from khaos.coding.execution.capability import (
    BackendAvailability,
    SandboxDecision,
    _cached_availability,
    _capability_evidence,
    _CapabilityCacheEntry,
)
from khaos.coding.execution.capability import (
    CapabilityEvidence as _CapabilityEvidence,
)
from khaos.coding.execution.environment import scrub_spawn_environment
from khaos.coding.execution.identity import executable_identity
from khaos.coding.execution.models import ExecutionResult, NetworkPolicy, ResourceBudget
from khaos.coding.execution.supervisor import ProcessSupervisor
from khaos.security.identity_isolation import linux_job_namespace_args

logger = logging.getLogger(__name__)

# The Windows helper performs a bounded native ACL/firewall startup
# transaction before it creates the Job Object child.  Existing venv trees can
# take longer than the command's own execution budget because Windows
# propagates inheritable AppContainer ACEs synchronously.
WINDOWS_HELPER_STARTUP_GRACE_SECONDS = 75

# A capability probe performs several bounded ``icacls`` and ``netsh``
# transactions, then restores every ACL and firewall rule before it returns.
# The outer timeout must cover the complete setup/child/cleanup transaction;
# otherwise killing the helper halfway through cleanup could strand a
# temporary security rule.  Each privileged helper command remains bounded
# separately, and this finite ceiling still fails closed on a hung probe.
WINDOWS_NATIVE_PROBE_TIMEOUT_SECONDS = 180

# Backwards-compatible public import for callers that historically imported
# the evidence model from this module instead of ``capability``.
CapabilityEvidence = _CapabilityEvidence


@dataclass
class KernelResourceLease:
    """Owner record for one kernel cgroup until external removal is proven."""

    execution_id: str
    path: Path
    quarantined: bool = False

    def descriptor(self) -> str:
        return f"cgroup:{self.execution_id}:{self.path}"


@dataclass
class _WindowsOwnedProcess:
    """Complete ownership record for one native Windows helper."""

    process: asyncio.subprocess.Process
    wait_task: asyncio.Task[int] | None = None
    reaped_return_code: int | None = None
    stdout_task: asyncio.Task[tuple[str, bool]] | None = None
    stderr_task: asyncio.Task[tuple[str, bool]] | None = None
    termination_lock: asyncio.Lock = field(default_factory=asyncio.Lock)


@dataclass
class _WindowsPendingSpawn:
    """Owner record published before the native helper spawn begins."""

    spawn_task: asyncio.Task[asyncio.subprocess.Process] | None = None
    process: _WindowsOwnedProcess | None = None
    termination_requested: bool = False
    error: BaseException | None = None
    done: asyncio.Event = field(default_factory=asyncio.Event)


class LinuxBubblewrapBackendState(str, Enum):
    """Lifecycle states for the Linux kernel-resource owner."""

    OPEN = "open"
    CLOSING = "closing"
    QUARANTINED = "quarantined"
    CLOSED = "closed"


class UnsupportedBackend:
    name = "unsupported"

    def __init__(
        self, reason: str = "no supported sandbox backend"
    ) -> None:
        self.reason = reason

    async def probe(self) -> BackendAvailability:
        return BackendAvailability(self.name, False, False, self.reason)

    async def execute(self, request):
        raise PermissionError(
            "execution refused: no safe execution backend "
            f"(infrastructure unsupported: {self.reason})"
        )

    async def terminate(self, execution_id: str) -> None:
        return None


class WindowsSandboxBackend:
    """Native Windows backend: AppContainer, token, Job, ACL/WFP helper.

    The Python process is only the lifecycle owner.  The native helper owns
    the irreversible Windows operations and refuses to start a child unless
    its capability probe has proved the restricted-token, AppContainer/no-
    network, Job Object, private workspace ACL, and Windows Firewall
    (WFP-backed) layers.  There is no
    subprocess/Host fallback when the helper is missing or its probe is
    incomplete.
    """

    name = "windows-native"

    def __init__(self, supervisor=None) -> None:
        self.supervisor = supervisor
        self._capability_cache: _CapabilityCacheEntry | None = None
        self._active: dict[str, _WindowsOwnedProcess] = {}
        self._pending_spawns: dict[str, _WindowsPendingSpawn] = {}
        self._orphans: dict[str, _WindowsOwnedProcess] = {}
        self._registry_lock = asyncio.Lock()
        self._state = "open"
        self._close_task: asyncio.Task[None] | None = None
        self._quarantined = False

    @property
    def state(self) -> str:
        return self._state

    @property
    def admission_closed(self) -> bool:
        return self._state != "open"

    @property
    def generation_admission_closed(self) -> bool:
        return self.admission_closed

    @property
    def child_admission_closed(self) -> bool:
        return self.admission_closed

    @property
    def is_quarantined(self) -> bool:
        return self._quarantined or bool(self._orphans)

    async def probe(self) -> BackendAvailability:
        return await asyncio.to_thread(self.probe_capability)

    def probe_capability(self) -> BackendAvailability:
        if self._quarantined:
            return BackendAvailability(
                self.name,
                False,
                False,
                "Windows sandbox cleanup is unproven; backend quarantined",
            )
        if sys.platform != "win32":
            return BackendAvailability(self.name, False, False, "Windows backend used on a non-Windows platform")
        helper = _windows_sandbox_helper()
        if helper is None:
            return BackendAvailability(
                self.name,
                False,
                False,
                "Windows khaos-windows-sandbox helper unavailable; Host fallback is forbidden",
            )
        try:
            evidence = _capability_evidence((helper,))
            cached = _cached_availability(self._capability_cache, evidence)
            if cached is not None:
                return cached
            completed = subprocess.run(
                (str(helper), "--probe"),
                capture_output=True,
                text=True,
                timeout=WINDOWS_NATIVE_PROBE_TIMEOUT_SECONDS,
                check=False,
            )
            payload = json.loads(completed.stdout or "{}")
            required = (
                "restricted_token",
                "job_object",
                "process_tree",
                "acl",
                "wfp",
                "appcontainer",
            )
            passed = (
                completed.returncode == 0
                and isinstance(payload, dict)
                and set(payload) == set(required)
                and all(payload[key] is True for key in required)
            )
            availability = BackendAvailability(
                self.name,
                passed,
                passed,
                "" if passed else (
                    "Windows native sandbox probe failed: "
                    f"rc={completed.returncode} stdout={completed.stdout!r} "
                    f"stderr={completed.stderr[-500:]!r}"
                ),
                evidence,
            )
        except (OSError, subprocess.SubprocessError, ValueError, TypeError) as exc:
            availability = BackendAvailability(
                self.name,
                False,
                False,
                f"Windows native sandbox probe unavailable: {type(exc).__name__}: {exc}",
                evidence if "evidence" in locals() else None,
            )
        self._capability_cache = (
            _CapabilityCacheEntry(availability, evidence)
            if "evidence" in locals()
            else None
        )
        return availability

    async def execute(self, request):
        profile = _validated_profile(request)
        if self._state != "open" or self._quarantined:
            raise PermissionError(
                "execution refused: Windows sandbox cleanup is unproven; backend quarantined"
            )
        if sys.platform != "win32":
            raise PermissionError("Windows native backend cannot execute on this platform")
        availability = self.probe_capability()
        if not availability.available:
            raise PermissionError(
                "execution refused: Windows native sandbox is unavailable: "
                f"{availability.reason}"
            )
        helper = _windows_sandbox_helper()
        if helper is None:
            raise PermissionError("execution refused: Windows sandbox helper disappeared")
        worktree = profile.workspace_roots[0]
        environment = {
            key: value
            for key, value in request.environment.items()
            if key in profile.environment_keys
        }
        environment.setdefault("PATH", os.defpath)
        environment = scrub_spawn_environment(environment)
        # The native helper resolves icacls/netsh from the Windows system
        # root. AppContainer process creation also needs the host's temporary
        # and user-profile metadata to construct its low-box environment.  In
        # particular, LOCALAPPDATA is the parent of the per-execution
        # AppContainer profile; omitting it makes CreateProcessW fail on some
        # hosted Windows runners with ERROR_ENVVAR_NOT_FOUND.
        # These values are trusted host metadata, not model-controlled
        # environment input, and are never allowed to widen the requested
        # executable environment with secrets.
        for key in (
            "SystemRoot",
            "SystemDrive",
            "WINDIR",
            "TEMP",
            "TMP",
            "LOCALAPPDATA",
            "USERPROFILE",
            "HOMEDRIVE",
            "HOMEPATH",
            "COMSPEC",
            "PATHEXT",
        ):
            value = os.environ.get(key)
            if value:
                environment[key] = value
        # Keep native-helper phase tracing opt-in and CI-only. It is useful
        # for diagnosing platform TCB latency, but must never become an
        # ambient production setting or expose host metadata by default.
        if os.environ.get("KHAOS_WINDOWS_SANDBOX_TRACE") == "1":
            environment["KHAOS_WINDOWS_SANDBOX_TRACE"] = "1"
        lease = profile.network_broker
        if lease is not None and (
            lease.uses_network_namespace or lease.host != "127.0.0.1"
        ):
            raise PermissionError(
                "Windows brokered execution requires a loopback NetworkBroker lease"
            )
        helper_args = [
            str(helper),
            "--workspace", str(worktree),
            "--cwd", str(request.cwd),
            "--network", profile.network.value,
            "--memory-bytes", str(profile.resources.memory_bytes),
            "--cpu-seconds", str(max(1, int(profile.resources.cpu_time_seconds))),
            "--timeout-seconds",
            str(max(1, math.ceil(profile.resources.timeout_seconds))),
        ]
        command_argv = list(request.argv)
        python_launcher = "requested-executable"
        staged_runtime_root: Path | None = None
        # A venv executable needs its lexical ``pyvenv.cfg`` and the base
        # interpreter runtime. These paths come from the trusted Khaos Python
        # runtime, not from model-controlled request fields. Stage the exact
        # runtime inputs into a disposable private tree so the native helper
        # never mutates an active venv or the shared host tool cache.
        try:
            requested_executable = request.argv[0]
            if not Path(requested_executable).is_absolute():
                requested_executable = shutil.which(
                    requested_executable, path=environment.get("PATH")
                ) or requested_executable
            requested_path = Path(requested_executable).resolve()
            trusted_python_paths = {
                Path(sys.executable).resolve(),
                Path(getattr(sys, "_base_executable", sys.executable)).resolve(),
            }
            same_as_khaos_python = requested_path in trusted_python_paths
        except (OSError, RuntimeError):
            same_as_khaos_python = False
        if same_as_khaos_python:
            seen_runtime_paths: set[Path] = set()
            base_executable = Path(
                getattr(sys, "_base_executable", sys.executable)
            ).expanduser().resolve()
            if not base_executable.is_file():
                raise PermissionError(
                    "execution refused: trusted Windows base Python executable is unavailable"
                )
            import_root_paths: list[Path] = []
            runtime_acl_roots: list[Path] = []
            # On Windows a venv's Scripts/python.exe is a redirector that
            # starts the base interpreter as a second process. The native
            # child-process policy must apply to the interpreter that executes
            # the request, so launch a staged copy of the trusted base
            # executable under the native policy.
            python_launcher = "staged-base-executable"
            venv_root = Path(sys.prefix).expanduser().resolve()
            site_packages = venv_root / "Lib" / "site-packages"
            source_root = Path(__file__).resolve().parents[3]
            staging_task = asyncio.create_task(
                asyncio.to_thread(
                    _stage_windows_python_runtime,
                    base_executable,
                    base_root=Path(sys.base_prefix).expanduser().resolve(),
                    site_packages=site_packages,
                    source_root=source_root,
                )
            )
            try:
                staged_runtime_root = await asyncio.shield(staging_task)
            except asyncio.CancelledError:
                staging_error: BaseException | None = None
                try:
                    await self._await_cleanup(staging_task)
                except asyncio.CancelledError:
                    pass
                except BaseException as error:  # noqa: BLE001 - preserve cancellation
                    staging_error = error
                    logger.debug(
                        "trusted Windows runtime staging failed: %s",
                        type(error).__name__,
                    )
                if staging_error is None and not staging_task.cancelled():
                    staged_runtime_root = staging_task.result()
                if staged_runtime_root is not None:
                    try:
                        await self._await_cleanup(
                            asyncio.to_thread(
                                _remove_windows_python_runtime,
                                staged_runtime_root,
                            )
                        )
                    except asyncio.CancelledError:
                        # The removal task is complete; preserve the original
                        # cancellation after its terminal cleanup.
                        pass
                    except BaseException as cleanup_error:
                        self._quarantined = True
                        raise PermissionError(
                            "Windows sandbox runtime staging cleanup is unproven"
                        ) from cleanup_error
                raise
            except (OSError, shutil.Error) as exc:
                raise PermissionError(
                    "execution refused: trusted Windows Python runtime staging failed"
                ) from exc
            command_argv[0] = str(
                staged_runtime_root / base_executable.name
            )
            environment["PYTHONHOME"] = str(staged_runtime_root)
            staged_source_root = staged_runtime_root / "source"
            if (staged_source_root / "khaos").is_dir():
                import_root_paths.append(staged_source_root)
            staged_site_packages = staged_runtime_root / "site-packages"
            if staged_site_packages.is_dir():
                import_root_paths.append(staged_site_packages)
            runtime_acl_roots.append(staged_runtime_root)
            import_roots = [str(path) for path in import_root_paths]
            if import_roots:
                environment["PYTHONPATH"] = os.pathsep.join(dict.fromkeys(import_roots))
            environment["PYTHONNOUSERSITE"] = "1"
            environment["PYTHONDONTWRITEBYTECODE"] = "1"
            # Network-none trusted Python uses the per-execution AppContainer
            # as its network authority.  This is required because Windows
            # Firewall image rules do not provide a dependable loopback
            # boundary on every supported runner.  Brokered execution keeps
            # the restricted-token path and its loopback-only WFP rules.
            # The staged runtime contains the standard-library zip/DLLs,
            # trusted package inputs, and the source package. Its ACL is the
            # only runtime ACL transaction for trusted Python.
            base_root = Path(sys.base_prefix).expanduser().resolve()
            runtime_roots = [
                *runtime_acl_roots,
            ]
            if staged_runtime_root is None:
                runtime_roots.append(base_root / "DLLs")
            for path in runtime_roots:
                if path.is_dir() and path not in seen_runtime_paths:
                    helper_args.extend(("--runtime-root", str(path)))
                    seen_runtime_paths.add(path)
            standard_library_zip = base_root / (
                f"python{sys.version_info.major}{sys.version_info.minor}.zip"
            )
            if staged_runtime_root is None and not standard_library_zip.is_file():
                standard_library = base_root / "Lib"
                if standard_library.is_dir() and standard_library not in seen_runtime_paths:
                    helper_args.extend(("--runtime-root", str(standard_library)))
                    seen_runtime_paths.add(standard_library)
            base_runtime_files = [] if staged_runtime_root is not None else [
                base_root / f"python{sys.version_info.major}{sys.version_info.minor}.dll",
                standard_library_zip,
            ]
            if staged_runtime_root is None and profile.network is not NetworkPolicy.NONE:
                base_runtime_files.insert(0, base_executable)
            for path in base_runtime_files:
                if path.is_file() and path not in seen_runtime_paths:
                    helper_args.extend(("--runtime-file", str(path)))
                    seen_runtime_paths.add(path)
        if lease is not None:
            environment.update(lease.proxy_environment())
            helper_args.extend(("--proxy-host", lease.host, "--proxy-port", str(lease.port)))
        helper_args.extend(("--", *command_argv))
        flags = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
        process: asyncio.subprocess.Process | None = None
        owner: _WindowsOwnedProcess | None = None
        pending_spawn = await self._reserve_spawn(request.correlation_id)
        spawn_task = asyncio.create_task(
            asyncio.create_subprocess_exec(
                *helper_args,
                cwd=str(request.cwd),
                env=environment,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                creationflags=flags,
            ),
            name=f"khaos-windows-helper-spawn:{request.correlation_id}",
        )
        pending_spawn.spawn_task = spawn_task
        try:
            process = await asyncio.shield(spawn_task)
            owner = await self._publish_process(
                request.correlation_id, pending_spawn, process
            )
        except asyncio.CancelledError:
            # The spawn task is shielded and the pending owner remains
            # published until it produces a process or a terminal error.
            # Repeated cancellation only records the request; it cannot make
            # the child disappear from the ownership graph.
            try:
                process = await self._await_spawn_result(pending_spawn)
                if process is not None:
                    owner = await self._publish_process(
                        request.correlation_id, pending_spawn, process
                    )
                    await self._await_cleanup(
                        self._terminate_process(request.correlation_id)
                    )
                else:
                    await self._finish_pending_spawn(
                        request.correlation_id,
                        pending_spawn,
                        error=RuntimeError("Windows helper spawn returned no process"),
                    )
            except BaseException as cleanup_error:  # noqa: BLE001 - retain owner
                if owner is not None:
                    async with self._registry_lock:
                        still_owned = bool(
                            request.correlation_id in self._active
                            or request.correlation_id in self._orphans
                            or request.correlation_id in self._pending_spawns
                        )
                    if still_owned:
                        await self._retain_orphan(
                            request.correlation_id, owner, error=cleanup_error
                        )
                elif not spawn_task.done():
                    self._quarantined = True
                else:
                    await self._finish_pending_spawn(
                        request.correlation_id,
                        pending_spawn,
                        error=cleanup_error,
                    )
            raise
        except OSError as exc:
            await self._finish_pending_spawn(
                request.correlation_id, pending_spawn, error=exc
            )
            raise PermissionError("Windows sandbox helper could not start") from exc
        except BaseException as exc:
            await self._finish_pending_spawn(
                request.correlation_id, pending_spawn, error=exc
            )
            raise
        if process is None or owner is None:
            await self._finish_pending_spawn(
                request.correlation_id,
                pending_spawn,
                error=RuntimeError("Windows helper spawn did not publish a process"),
            )
            raise PermissionError("Windows sandbox helper ownership was not published")
        started = asyncio.get_running_loop().time()
        stdout_task = asyncio.create_task(
            _read_windows_output(process.stdout, profile.resources.output_bytes // 2)
        )
        stderr_task = asyncio.create_task(
            _read_windows_output(
                process.stderr,
                profile.resources.output_bytes - profile.resources.output_bytes // 2,
            )
        )
        owner.stdout_task = stdout_task
        owner.stderr_task = stderr_task
        status = "failed"
        timed_out = False
        try:
            try:
                await asyncio.wait_for(
                    self._wait_for_process(owner),
                    timeout=(
                        profile.resources.timeout_seconds
                        + WINDOWS_HELPER_STARTUP_GRACE_SECONDS
                    ),
                )
            except TimeoutError:
                timed_out = True
                await self._await_cleanup(
                    self._terminate_process(request.correlation_id)
                )
            stdout, stdout_truncated = await stdout_task
            stderr, stderr_truncated = await stderr_task
            return_code = (
                owner.reaped_return_code
                if owner.reaped_return_code is not None
                else process.returncode
            )
            status = (
                "timed-out"
                if timed_out or return_code == 124
                else ("passed" if return_code == 0 else "failed")
            )
            diagnostics = {
                "backend": self.name,
                "restricted_token": True,
                "appcontainer": (
                    profile.network is NetworkPolicy.NONE
                ),
                "job_object": True,
                "process_tree": True,
                "workspace_acl": True,
                "wfp_network_policy": profile.network.value,
                "network_authority": (
                    "appcontainer" if profile.network is NetworkPolicy.NONE else "wfp-loopback"
                ),
                "python_launcher": python_launcher,
                "stdout_truncated": stdout_truncated,
                "stderr_truncated": stderr_truncated,
            }
            return ExecutionResult(
                execution_id=request.correlation_id,
                status=status,
                return_code=return_code,
                stdout=stdout,
                stderr=stderr,
                duration_ms=int((asyncio.get_running_loop().time() - started) * 1000),
                diagnostics=diagnostics,
            )
        finally:
            cleanup_cancelled = False
            cleanup_error: BaseException | None = None
            if owner is not None:
                try:
                    await self._await_cleanup(
                        self._terminate_process(request.correlation_id)
                    )
                except asyncio.CancelledError:
                    # _await_cleanup has already finished the owner operation;
                    # preserve the caller's cancellation after the remaining
                    # runtime cleanup rather than turning it into a false
                    # helper-cleanup failure.
                    cleanup_cancelled = True
                except BaseException as error:  # noqa: BLE001 - retain owner
                    cleanup_error = error
                    self._quarantined = True
            if staged_runtime_root is not None:
                try:
                    await self._await_cleanup(
                        asyncio.to_thread(
                            _remove_windows_python_runtime,
                            staged_runtime_root,
                        )
                    )
                except asyncio.CancelledError:
                    cleanup_cancelled = True
                except BaseException as error:  # noqa: BLE001 - retain quarantine
                    cleanup_error = cleanup_error or error
                    self._quarantined = True
            if cleanup_error is not None:
                raise PermissionError(
                    "Windows sandbox helper cleanup is unproven"
                ) from cleanup_error
            if cleanup_cancelled:
                raise asyncio.CancelledError()

    async def terminate(self, execution_id: str) -> None:
        await self._terminate_process(execution_id)

    async def _reserve_spawn(self, execution_id: str) -> _WindowsPendingSpawn:
        async with self._registry_lock:
            if self._state != "open":
                raise PermissionError(
                    f"Windows sandbox backend is {self._state}; spawn refused"
                )
            if (
                execution_id in self._active
                or execution_id in self._pending_spawns
                or execution_id in self._orphans
            ):
                raise RuntimeError(f"duplicate Windows helper execution id: {execution_id}")
            pending = _WindowsPendingSpawn()
            self._pending_spawns[execution_id] = pending
            return pending

    async def _await_spawn_result(
        self, pending: _WindowsPendingSpawn
    ) -> asyncio.subprocess.Process | None:
        task = pending.spawn_task
        if task is None:
            raise RuntimeError("Windows helper spawn task was not published")
        while True:
            try:
                return await asyncio.shield(task)
            except asyncio.CancelledError:
                pending.termination_requested = True
                continue

    async def _publish_process(
        self,
        execution_id: str,
        pending: _WindowsPendingSpawn,
        process: asyncio.subprocess.Process,
    ) -> _WindowsOwnedProcess:
        owner = _WindowsOwnedProcess(process)
        async with self._registry_lock:
            if self._pending_spawns.get(execution_id) is not pending:
                self._orphans[execution_id] = owner
                self._quarantined = True
                raise RuntimeError(
                    f"Windows helper pending owner disappeared: {execution_id}"
                )
            pending.process = owner
            self._active[execution_id] = owner
            self._pending_spawns.pop(execution_id, None)
            pending.done.set()
        return owner

    async def _finish_pending_spawn(
        self,
        execution_id: str,
        pending: _WindowsPendingSpawn,
        *,
        error: BaseException,
    ) -> None:
        pending.error = error
        async with self._registry_lock:
            if self._pending_spawns.get(execution_id) is pending:
                self._pending_spawns.pop(execution_id, None)
                pending.done.set()

    async def _retain_orphan(
        self,
        execution_id: str,
        owner: _WindowsOwnedProcess,
        *,
        error: BaseException,
    ) -> None:
        self._quarantined = True
        async with self._registry_lock:
            self._active.pop(execution_id, None)
            self._orphans[execution_id] = owner
            pending = self._pending_spawns.pop(execution_id, None)
            if pending is not None:
                pending.error = error
                pending.done.set()

    async def _wait_for_process(self, owner: _WindowsOwnedProcess) -> int:
        if owner.reaped_return_code is not None:
            return owner.reaped_return_code
        if owner.wait_task is None:
            owner.wait_task = asyncio.create_task(owner.process.wait())
        return_code = await asyncio.shield(owner.wait_task)
        owner.reaped_return_code = return_code
        return return_code

    async def _settle_output(self, owner: _WindowsOwnedProcess) -> None:
        tasks = tuple(
            task
            for task in (owner.stdout_task, owner.stderr_task)
            if task is not None
        )
        if not tasks:
            return
        done, pending = await asyncio.wait(tasks, timeout=5)
        if pending:
            raise RuntimeError("Windows helper output pipes did not reach terminal state")
        await asyncio.gather(*done, return_exceptions=False)

    async def _release_owner(
        self, execution_id: str, owner: _WindowsOwnedProcess
    ) -> None:
        if owner.reaped_return_code is None and owner.process.returncode is None:
            raise RuntimeError(
                f"Windows helper {execution_id} lacks terminal process proof"
            )
        await self._settle_output(owner)
        async with self._registry_lock:
            if self._active.get(execution_id) is owner:
                self._active.pop(execution_id, None)
            elif self._orphans.get(execution_id) is owner:
                self._orphans.pop(execution_id, None)

    async def _terminate_process(self, execution_id: str) -> None:
        async with self._registry_lock:
            owner = self._active.get(execution_id) or self._orphans.get(execution_id)
            pending = self._pending_spawns.get(execution_id)
        if owner is None and pending is not None:
            pending.termination_requested = True
            process = await self._await_spawn_result(pending)
            if process is None:
                await self._finish_pending_spawn(
                    execution_id,
                    pending,
                    error=RuntimeError("Windows helper spawn returned no process"),
                )
                return
            owner = await self._publish_process(execution_id, pending, process)
        if owner is None:
            return
        async with owner.termination_lock:
            try:
                owner_process = owner.process
                if owner_process.returncode is None:
                    if owner_process.stdin is not None:
                        try:
                            owner_process.stdin.write(b"\x01")
                            await owner_process.stdin.drain()
                            owner_process.stdin.close()
                        except (BrokenPipeError, ConnectionError, OSError):
                            self._quarantined = True
                    if owner.wait_task is None:
                        owner.wait_task = asyncio.create_task(owner_process.wait())
                    try:
                        await asyncio.wait_for(
                            asyncio.shield(owner.wait_task), timeout=5
                        )
                    except TimeoutError:
                        owner_process.kill()
                        await asyncio.shield(owner.wait_task)
                    owner.reaped_return_code = owner.wait_task.result()
                elif owner.reaped_return_code is None:
                    owner.reaped_return_code = owner_process.returncode
                await self._release_owner(execution_id, owner)
            except BaseException as exc:
                await self._retain_orphan(execution_id, owner, error=exc)
                raise

    async def _await_cleanup(self, awaitable) -> None:
        """Finish cleanup despite repeated caller cancellation."""
        task = asyncio.ensure_future(awaitable)
        cancelled = False
        while not task.done():
            try:
                await asyncio.shield(task)
            except asyncio.CancelledError:
                cancelled = True
                continue
        await task
        if cancelled:
            raise asyncio.CancelledError()

    async def close(self) -> None:
        if self._state == "closed" and self.terminal_closed:
            return
        if self._state == "open":
            self._state = "closing"
        if self._close_task is None or self._close_task.done():
            self._close_task = asyncio.ensure_future(self._run_close())
        await asyncio.shield(self._close_task)

    async def _run_close(self) -> None:
        errors: list[BaseException] = []
        execution_ids = tuple(
            sorted(set(self._active) | set(self._pending_spawns) | set(self._orphans))
        )
        for execution_id in execution_ids:
            try:
                await self._await_cleanup(self._terminate_process(execution_id))
            except BaseException as exc:  # noqa: BLE001 - retain owner for retry
                errors.append(exc)
        if errors or self._active or self._pending_spawns or self._orphans:
            self._state = "quarantined"
            self._quarantined = True
            cause = errors[0] if errors else None
            raise RuntimeError("Windows sandbox backend cleanup is unproven") from cause
        self._quarantined = False
        self._state = "closed"

    def owned_resources(self) -> tuple[str, ...]:
        resources = [f"windows-helper:{key}" for key in sorted(self._active)]
        resources.extend(
            f"windows-helper-spawn:{key}" for key in sorted(self._pending_spawns)
        )
        resources.extend(f"windows-helper-orphan:{key}" for key in sorted(self._orphans))
        return tuple(resources)

    @property
    def terminal_closed(self) -> bool:
        return (
            self._state == "closed"
            and not self._active
            and not self._pending_spawns
            and not self._orphans
            and not self._quarantined
        )

    def terminal_postcondition(self) -> bool:
        return self.terminal_closed


async def _read_windows_output(
    stream: asyncio.StreamReader | None, limit: int
) -> tuple[str, bool]:
    if stream is None:
        return "", False
    chunks: list[bytes] = []
    retained = 0
    truncated = False
    while True:
        chunk = await stream.read(64 * 1024)
        if not chunk:
            break
        if retained < limit:
            keep = min(limit - retained, len(chunk))
            chunks.append(chunk[:keep])
            retained += keep
            truncated = truncated or keep < len(chunk)
        else:
            truncated = True
    return b"".join(chunks).decode("utf-8", errors="replace"), truncated


def _windows_sandbox_helper() -> Path | None:
    if sys.platform != "win32":
        return None
    repository_root = Path(__file__).resolve().parents[4]
    configured = os.environ.get("KHAOS_WINDOWS_SANDBOX_HELPER", "").strip()
    candidates = [Path(configured)] if configured else []
    candidates.extend(
        (
            repository_root / "rust" / "khaos-core" / "target" / "release" / "khaos-windows-sandbox.exe",
            repository_root / "rust" / "khaos-core" / "target" / "debug" / "khaos-windows-sandbox.exe",
        )
    )
    located = shutil.which("khaos-windows-sandbox.exe")
    if located:
        candidates.append(Path(located))
    for candidate in candidates:
        try:
            resolved = candidate.expanduser().resolve(strict=True)
            info = resolved.stat()
        except OSError:
            continue
        if resolved.is_file() and info.st_size > 0:
            return resolved
    return None


def _stage_windows_python_runtime(
    base_executable: Path,
    *,
    base_root: Path,
    site_packages: Path,
    source_root: Path,
) -> Path:
    """Copy trusted Python inputs into an isolated, disposable runtime tree."""
    staging_root = Path(tempfile.mkdtemp(prefix="khaos-windows-runtime-"))
    try:
        shutil.copy2(base_executable, staging_root / base_executable.name)
        for runtime_file in base_root.iterdir():
            if not runtime_file.is_file():
                continue
            if _windows_runtime_path_is_reparse(runtime_file):
                # Hosted Python installations commonly expose python3.exe as
                # a reparse/alias next to the resolved python.exe. It is not
                # part of the staged interpreter contract and must not cause
                # the required resolved runtime to fail closed.
                continue
            if runtime_file.suffix.lower() == ".dll" or runtime_file.name.endswith("._pth"):
                shutil.copy2(runtime_file, staging_root / runtime_file.name)
        standard_library_zip = base_root / (
            f"python{sys.version_info.major}{sys.version_info.minor}.zip"
        )
        if standard_library_zip.is_file():
            shutil.copy2(standard_library_zip, staging_root / standard_library_zip.name)
        else:
            standard_library = base_root / "Lib"
            if not standard_library.is_dir():
                raise FileNotFoundError(
                    f"trusted Python standard library is unavailable: {standard_library}"
                )
            _copy_windows_runtime_tree(
                standard_library,
                staging_root / "Lib",
                ignore=shutil.ignore_patterns("__pycache__"),
            )
        dlls = base_root / "DLLs"
        if dlls.is_dir():
            _copy_windows_runtime_tree(
                dlls,
                staging_root / "DLLs",
                ignore=shutil.ignore_patterns("__pycache__"),
            )
        if site_packages.is_dir():
            _copy_windows_runtime_tree(
                site_packages,
                staging_root / "site-packages",
                ignore=shutil.ignore_patterns("__pycache__", "*.pth", "*.egg-link"),
            )
        source_package = source_root / "khaos"
        if source_package.is_dir():
            _copy_windows_runtime_tree(
                source_package,
                staging_root / "source" / "khaos",
                ignore=shutil.ignore_patterns("__pycache__"),
            )
        return staging_root
    except (OSError, shutil.Error):
        shutil.rmtree(staging_root, ignore_errors=True)
        raise


def _windows_runtime_path_is_reparse(path: Path) -> bool:
    metadata = path.lstat()
    return path.is_symlink() or bool(
        getattr(metadata, "st_file_attributes", 0)
        & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    )


def _copy_windows_runtime_tree(
    source: Path,
    destination: Path,
    *,
    ignore,
) -> None:
    if _windows_runtime_path_is_reparse(source):
        raise PermissionError(f"trusted Windows runtime contains a reparse point: {source}")
    for root, directories, files in os.walk(source, followlinks=False):
        for name in (*directories, *files):
            candidate = Path(root) / name
            if _windows_runtime_path_is_reparse(candidate):
                raise PermissionError(
                    f"trusted Windows runtime contains a reparse point: {candidate}"
                )
    shutil.copytree(source, destination, symlinks=False, ignore=ignore)


def _remove_windows_python_runtime(staging_root: Path) -> None:
    """Remove a disposable trusted runtime after the helper is fully closed."""
    resolved = staging_root.expanduser().resolve()
    temporary_root = Path(tempfile.gettempdir()).expanduser().resolve()
    if (
        resolved.parent != temporary_root
        or not resolved.name.startswith("khaos-windows-runtime-")
    ):
        raise RuntimeError("refusing to remove an unrecognized Windows runtime staging path")
    shutil.rmtree(resolved)


class BackendSelector:
    """Select an OS-enforced backend; Agent execution never falls back to host."""

    def __init__(self, supervisor=None) -> None:
        self.supervisor = supervisor

    def set_supervisor(self, supervisor) -> None:
        self.supervisor = supervisor

    def select(self, *, writable: bool):
        if sys.platform == "darwin":
            backend = MacOSSandboxBackend(self.supervisor)
            try:
                availability = backend.probe_capability()
            except Exception:  # noqa: BLE001 - unavailable sandbox probes fail closed
                availability = BackendAvailability(
                    backend.name,
                    False,
                    False,
                    "sandbox-exec capability probe raised an exception",
                )
            if availability.available and availability.network_enforced:
                return backend
        elif sys.platform.startswith("linux"):
            backend = LinuxBubblewrapBackend(self.supervisor)
            try:
                availability = backend.probe_capability()
            except Exception as exc:  # noqa: BLE001 - unavailable sandbox probes fail closed
                availability = BackendAvailability(
                    backend.name,
                    False,
                    False,
                    f"bwrap isolation probe raised {type(exc).__name__}: {exc}",
                )
            if availability.available and availability.network_enforced:
                return backend
            # bwrap present but cannot enforce isolation (e.g. GitHub-hosted
            # runner blocks network namespace creation).  Writable execution
            # must fail closed as infrastructure-unsupported, never degrade to
            # a plain host subprocess.
            if writable:
                return UnsupportedBackend()
        if sys.platform.startswith("win"):
            backend = WindowsSandboxBackend(self.supervisor)
            try:
                availability = backend.probe_capability()
            except Exception as exc:  # noqa: BLE001 - Windows probes fail closed
                availability = BackendAvailability(
                    backend.name,
                    False,
                    False,
                    f"Windows native sandbox probe raised {type(exc).__name__}: {exc}",
                )
            if availability.available and availability.network_enforced:
                return backend
            return UnsupportedBackend(
                availability.reason
                or "Windows native sandbox unavailable; Host fallback is forbidden"
            )
        return UnsupportedBackend()

    async def select_async(self, *, writable: bool):
        """Select after the real kernel capability probe off the event loop."""
        import asyncio

        return await asyncio.to_thread(self.select, writable=writable)

    def select_with_decision(
        self, *, writable: bool, network_mode: str = "none"
    ) -> tuple[object, SandboxDecision]:
        """Select a backend and retain the exact probe evidence it used."""
        backend = self.select(writable=writable)
        if isinstance(backend, UnsupportedBackend):
            raise PermissionError(
                "execution refused: no kernel-enforced sandbox backend "
                f"({backend.reason})"
            )
        availability: BackendAvailability | None = None
        cache = getattr(backend, "_capability_cache", None)
        if cache is not None:
            availability = cache.availability
        if availability is None:
            probe = getattr(backend, "probe_capability", None)
            if not callable(probe):
                raise PermissionError(
                    "selected sandbox backend does not expose capability evidence"
                )
            availability = cast(BackendAvailability, probe())
        assert availability is not None
        return backend, SandboxDecision.from_backend(
            backend,
            availability,
            writable=writable,
            network_mode=network_mode,
        )

    async def select_async_with_decision(
        self, *, writable: bool, network_mode: str = "none"
    ) -> tuple[object, SandboxDecision]:
        """Run selection and evidence binding off the event loop."""
        return await asyncio.to_thread(
            self.select_with_decision,
            writable=writable,
            network_mode=network_mode,
        )


class MacOSSandboxBackend:
    name = "macos-sandbox-exec"

    def __init__(self, supervisor=None) -> None:
        self.supervisor = supervisor
        self._capability_cache: _CapabilityCacheEntry | None = None

    @staticmethod
    def runtime_read_roots(
        command: tuple[str, ...], workspace: Path
    ) -> tuple[Path, ...]:
        return _runtime_read_roots(command, workspace)

    async def probe(self) -> BackendAvailability:
        import asyncio

        return await asyncio.to_thread(self.probe_capability)

    def probe_capability(self) -> BackendAvailability:
        """Execute Seatbelt and prove write and network denial before use."""
        if (
            sys.platform != "darwin"
            or shutil.which("sandbox-exec") is None
        ):
            return BackendAvailability(
                self.name, False, False, "sandbox-exec unavailable"
            )
        try:
            evidence = _capability_evidence(
                (Path("/usr/bin/sandbox-exec"), Path(sys.executable))
            )
        except (OSError, subprocess.SubprocessError) as exc:
            return BackendAvailability(
                self.name,
                False,
                False,
                "sandbox-exec TCB evidence unavailable: "
                f"{type(exc).__name__}: {exc}",
            )
        cached = _cached_availability(self._capability_cache, evidence)
        if cached is not None:
            return cached
        try:
            with tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                workspace = root / "workspace"
                outside = root / "outside.txt"
                workspace.mkdir()
                script = "\n".join(
                    (
                        "from pathlib import Path",
                        "import socket, subprocess",
                        "Path('inside.txt').write_text('ok')",
                        f"try: Path({str(outside)!r}).write_text('denied')",
                        "except OSError: pass",
                        "else: raise SystemExit('outside write allowed')",
                        "try: socket.create_connection(('1.1.1.1', 53), timeout=0.2)",
                        "except OSError: pass",
                        "else: raise SystemExit('network allowed')",
                        ("for command in (('/usr/bin/pbpaste',), "
                         "('/usr/bin/security', 'list-keychains')):"),
                        "    result = subprocess.run(command, capture_output=True)",
                        "    if result.returncode == 0:",
                        "        raise SystemExit(f'host IPC allowed: {command[0]}')",
                    )
                )
                completed = subprocess.run(
                    (
                        "/usr/bin/sandbox-exec",
                        "-p",
                        self.profile(
                            workspace,
                            runtime_roots=_runtime_read_roots(
                                (sys.executable,), workspace
                            ),
                        ),
                        sys.executable,
                        "-c",
                        script,
                    ),
                    cwd=workspace,
                    capture_output=True,
                    timeout=5,
                    check=False,
                )
                passed = (
                    completed.returncode == 0
                    and (workspace / "inside.txt").is_file()
                    and not outside.exists()
                )
                stderr = completed.stderr.decode(
                    "utf-8", errors="replace"
                ).strip()[:500]
        except (OSError, subprocess.SubprocessError) as exc:
            availability = BackendAvailability(
                self.name,
                False,
                False,
                f"sandbox-exec probe could not run: {type(exc).__name__}: {exc}",
            )
        else:
            availability = BackendAvailability(
                self.name,
                passed,
                passed,
                "" if passed else (
                    "sandbox-exec isolation probe failed "
                    f"(rc={completed.returncode}): {stderr}"
                ),
            )
        availability = BackendAvailability(
            availability.name,
            availability.available,
            availability.network_enforced,
            availability.reason,
            evidence,
        )
        self._capability_cache = _CapabilityCacheEntry(availability, evidence)
        return availability

    def profile(
        self,
        worktree: Path,
        *,
        writable: bool = True,
        unreadable_roots: tuple[Path, ...] = (),
        runtime_roots: tuple[Path, ...] = (),
        synthetic_home: Path | None = None,
        synthetic_tmp: Path | None = None,
        preserve_workspace_path: bool = False,
        network_broker=None,
    ) -> str:
        workspace = (
            worktree.expanduser().absolute()
            if preserve_workspace_path
            else worktree.expanduser().resolve()
        )
        read_roots = _deduplicate_paths(
            (
                workspace,
                *_macos_system_read_roots(),
                *runtime_roots,
                *(() if synthetic_home is None else (synthetic_home.expanduser().absolute(),)),
                *(() if synthetic_tmp is None else (synthetic_tmp.expanduser().absolute(),)),
            ),
            preserve_paths=(workspace,) if preserve_workspace_path else (),
        )
        read_rules = "".join(
            f'(allow file-read* (subpath "{_seatbelt_escape(path)}"))'
            for path in read_roots if path.exists()
        )
        literal_reads = "".join(
            f'(allow file-read* (literal "{_seatbelt_escape(path)}"))'
            for path in _macos_literal_read_files() if path.exists()
        )
        metadata_ancestors = _deduplicate_paths(
            (*read_roots, *tuple(
                ancestor
                for path in read_roots
                for ancestor in reversed(path.parents)
                if ancestor != Path("/")
            )),
            preserve_paths=(workspace,) if preserve_workspace_path else (),
        )
        metadata_rules = "".join(
            '(allow file-read-metadata '
            f'(literal "{_seatbelt_escape(path)}"))'
            for path in metadata_ancestors
        )
        executable_map_rules = "".join(
            f'(allow file-map-executable (subpath "{_seatbelt_escape(path)}"))'
            for path in read_roots if path.exists()
        )
        write_roots = tuple(
            path for path in (
                workspace if writable else None,
                synthetic_home.expanduser().absolute() if synthetic_home else None,
                synthetic_tmp.expanduser().absolute() if synthetic_tmp else None,
            ) if path is not None
        )
        write_rules = "".join(
            f'(allow file-write* (subpath "{_seatbelt_escape(path)}"))'
            for path in write_roots
        )
        from khaos.coding.workspace.boundary import PROTECTED_WORKSPACE_NAMES

        protected_write_rules = "".join(
            f'(deny file-write* (literal "{_seatbelt_escape(path)}"))'
            f'(deny file-write* (subpath "{_seatbelt_escape(path)}"))'
            for path in (
                workspace / name for name in sorted(PROTECTED_WORKSPACE_NAMES)
            )
        )
        protected_read_rules = (
            '(deny file-read* (subpath "/private/tmp"))'
            '(deny file-read* (subpath "/tmp"))'
        )
        mach_lookup_rules = "".join(
            f'(allow mach-lookup (global-name "{service}"))'
            for service in _macos_runtime_mach_services()
        )
        # unreadable_roots are deliberately not represented as deny exceptions:
        # deny-default plus the positive allowlist makes all non-runtime host
        # paths invisible, including credential roots not known in advance.
        _ = unreadable_roots
        network_rules = "(deny network*)"
        if network_broker is not None:
            if network_broker.host != "127.0.0.1":
                raise PermissionError("macOS broker endpoint must be loopback")
            network_rules = (
                '(allow network-outbound (remote ip "127.0.0.1") '
                f'(remote tcp "{network_broker.port}"))'
                "(deny network*)"
            )
        return (
            "(version 1)(deny default)(allow process-exec process-fork)"
            "(allow signal (target same-sandbox))"
            "(allow process-info* (target same-sandbox))"
            "(allow sysctl-read)"
            # Do not grant a root-level file-read rule: on Seatbelt this
            # makes unrelated host paths such as /private/tmp traversable and
            # defeats the positive read-root allowlist below.
            '(allow file-read* file-write-data (literal "/dev/null"))'
            '(allow file-read* (literal "/dev/random"))'
            '(allow file-read* (literal "/dev/urandom"))'
            # Seatbelt needs metadata for the filesystem root while resolving
            # an allowlisted executable.  On macOS 26, it also needs data
            # access to the root directory entry itself; this is narrower
            # than allowing file-read* on "/" and does not expose recursive
            # contents outside the roots above.
            '(allow file-read-data (literal "/"))'
            '(allow file-read-metadata (literal "/"))'
            f"{metadata_rules}{read_rules}{literal_reads}"
            f"{executable_map_rules}{write_rules}"
            f"{protected_write_rules}{protected_read_rules}{mach_lookup_rules}"
            f"{network_rules}"
        )

    async def execute(self, request):
        from dataclasses import replace
        profile = _validated_profile(request)
        writable = profile.filesystem.value == "workspace-write"
        worktree = profile.workspace_roots[0]
        with tempfile.TemporaryDirectory(prefix="khaos-home-") as home_value:
            # macOS exposes /var as a symlink to /private/var.  Bind the
            # environment and Seatbelt rules to the same canonical identity;
            # otherwise HOME uses the lexical /var path while the profile
            # allows /private/var and legitimate synthetic-home writes fail.
            home = Path(home_value).resolve()
            sandbox_tmp = home / "tmp"
            sandbox_tmp.mkdir(mode=0o700)
            sandbox_profile = self.profile(
                worktree,
                writable=writable,
                unreadable_roots=profile.unreadable_roots,
                runtime_roots=_runtime_read_roots(request.argv, worktree),
                synthetic_home=home,
                synthetic_tmp=sandbox_tmp,
                preserve_workspace_path=request.workspace_root_identity is not None,
                network_broker=profile.network_broker,
            )
            sandboxed_argv = (
                "/usr/bin/sandbox-exec", "-p", sandbox_profile,
                *request.argv,
            )
            environment = _sandbox_environment(
                profile, request.environment,
                home=str(home), tmpdir=str(sandbox_tmp),
            )
            sandboxed = replace(
                request,
                argv=sandboxed_argv,
                executable_identity=executable_identity(
                    sandboxed_argv, environment
                ),
            )
            supervisor = self.supervisor or ProcessSupervisor()
            self.supervisor = supervisor
            try:
                return await supervisor.run(
                    sandboxed,
                    cwd=request.cwd.expanduser().absolute(),
                    execution_root=worktree,
                    env=environment,
                    tmp_root=home,
                    workspace_root=worktree if writable else None,
                    workspace_baseline=request.workspace_baseline,
                )
            except (OSError, PermissionError):
                self._capability_cache = None
                raise

    async def terminate(self, execution_id: str) -> None:
        if self.supervisor is not None:
            await self.supervisor.terminate(execution_id)


class LinuxBubblewrapBackend:
    name = "linux-bwrap"

    def __init__(self, supervisor=None) -> None:
        self.supervisor = supervisor
        self._capability_cache: _CapabilityCacheEntry | None = None
        self._cgroup_leases: dict[str, KernelResourceLease] = {}
        self._release_tasks: dict[str, asyncio.Task[None]] = {}
        self._lock = asyncio.Lock()
        self._state = LinuxBubblewrapBackendState.OPEN
        self._shutdown_task: asyncio.Task[None] | None = None
        self._shutdown_error: BaseException | None = None

    @property
    def state(self) -> str:
        """Return the ResourceOwner lifecycle state."""
        return self._state.value

    @property
    def admission_closed(self) -> bool:
        """Reject new cgroup generations after close or quarantine."""
        return self._state is not LinuxBubblewrapBackendState.OPEN

    @property
    def generation_admission_closed(self) -> bool:
        return self.admission_closed

    @property
    def child_admission_closed(self) -> bool:
        return self.admission_closed

    @property
    def terminal_closed(self) -> bool:
        """Close is proven only after every cgroup path is absent."""
        return (
            self._state is LinuxBubblewrapBackendState.CLOSED
            and not self._cgroup_leases
            and not self._release_tasks
        )

    @property
    def is_quarantined(self) -> bool:
        return self._state is LinuxBubblewrapBackendState.QUARANTINED

    def owned_resources(self) -> tuple[str, ...]:
        """Expose cgroups and in-flight cleanup transactions to the oracle."""
        resources = tuple(
            lease.descriptor()
            for _, lease in sorted(self._cgroup_leases.items())
        )
        cleanup = tuple(
            f"cgroup-cleanup:{execution_id}"
            for execution_id, task in sorted(self._release_tasks.items())
            if not task.done()
        )
        return resources + cleanup

    def owns_execution(self, execution_id: str) -> bool:
        return (
            execution_id in self._cgroup_leases
            or execution_id in self._release_tasks
        )

    def terminal_postcondition(self) -> bool:
        """Return an independent proof of kernel-resource termination."""
        return self.terminal_closed and not self.owned_resources()

    async def close(self) -> None:
        """Retry cgroup cleanup until the external path oracle is empty."""
        async with self._lock:
            if self.terminal_closed:
                return
            if self._state is LinuxBubblewrapBackendState.OPEN or self._state is LinuxBubblewrapBackendState.QUARANTINED:
                self._state = LinuxBubblewrapBackendState.CLOSING
            if self._shutdown_task is None or self._shutdown_task.done():
                self._shutdown_task = asyncio.create_task(
                    self._shutdown_impl(),
                    name="khaos-linux-cgroup-owner-shutdown",
                )
            shutdown_task = self._shutdown_task
        await asyncio.shield(shutdown_task)

    async def shutdown(self) -> None:
        """ResourceOwner-compatible shutdown alias."""
        await self.close()

    async def _shutdown_impl(self) -> None:
        errors: list[BaseException] = []
        try:
            execution_ids = tuple(sorted(self._cgroup_leases))
            for execution_id in execution_ids:
                try:
                    await asyncio.shield(self._release_cgroup_lease(execution_id))
                except asyncio.CancelledError as exc:
                    errors.append(exc)
                except BaseException as exc:  # noqa: BLE001 - retain lease for retry
                    errors.append(exc)
            if self._cgroup_leases or self._release_tasks:
                errors.append(
                    RuntimeError(
                        "Linux cgroup owner shutdown left kernel resources owned"
                    )
                )
            if errors:
                self._shutdown_error = errors[0]
                self._state = LinuxBubblewrapBackendState.QUARANTINED
                raise RuntimeError(
                    f"Linux cgroup owner shutdown completed with {len(errors)} error(s)"
                ) from errors[0]
            self._shutdown_error = None
            self._state = LinuxBubblewrapBackendState.CLOSED
        except asyncio.CancelledError as exc:
            self._shutdown_error = exc
            self._state = LinuxBubblewrapBackendState.QUARANTINED
            raise

    def _retain_lease_after_rejected_admission(
        self, execution_id: str, cgroup: Path
    ) -> KernelResourceLease:
        lease = KernelResourceLease(execution_id, cgroup)
        self._cgroup_leases[execution_id] = lease
        return lease

    async def _register_cgroup_lease(
        self, execution_id: str, cgroup: Path
    ) -> KernelResourceLease:
        async with self._lock:
            if execution_id in self._cgroup_leases:
                raise RuntimeError(f"duplicate Linux cgroup execution: {execution_id}")
            if self._state is not LinuxBubblewrapBackendState.OPEN:
                return self._retain_lease_after_rejected_admission(execution_id, cgroup)
            lease = KernelResourceLease(execution_id, cgroup)
            self._cgroup_leases[execution_id] = lease
            return lease

    async def probe(self) -> BackendAvailability:
        import asyncio

        return await asyncio.to_thread(self.probe_capability)

    def probe_capability(self) -> BackendAvailability:
        """Actually execute bwrap to verify --unshare-net/--unshare-pid AND
        the writable workspace bind actually work.

        A ``shutil.which`` check is not sufficient: some platforms (notably
        GitHub-hosted ubuntu-latest) ship bwrap but block the network
        namespace creation with EPERM on RTM_NEWADDR.  Additionally, a
        ``--tmpfs /tmp`` can shadow a worktree that lives under ``/tmp``
        (the default pytest tmp_path location), making the writable bind
        invisible and the sandboxed process fall back to read-only ``/``.

        The probe uses the same empty-root topology as production: a tmpfs
        root, explicitly mounted runtime directories, a synthetic HOME,
        bounded /tmp, and exactly one workspace bind.  It therefore catches
        accidental regressions to a host-root bind as well as namespace
        failures.
        """
        if not sys.platform.startswith("linux") or shutil.which("bwrap") is None:
            return BackendAvailability(self.name, False, False, "bwrap unavailable on this platform")
        launcher = _linux_sandbox_launcher()
        if launcher is None:
            return BackendAvailability(
                self.name, False, False,
                "khaos-sandbox-launcher unavailable; no_new_privs/seccomp TCB is required",
            )
        evidence = _capability_evidence(
            (Path(_resolve_bwrap_path()), launcher),
            cgroup_root=_linux_cgroup_root(),
        )
        cached = _cached_availability(self._capability_cache, evidence)
        if cached is not None:
            return cached
        cgroup: Path | None = None
        try:
            with tempfile.TemporaryDirectory() as tmp, \
                    tempfile.TemporaryDirectory(prefix="khaos-home-") as home:
                budget = ResourceBudget()
                cgroup = _create_linux_cgroup(budget, Path(tmp))
                prefix = self.argv_prefix(
                    Path(tmp), cwd=Path(tmp), synthetic_home=Path(home),
                    resources=budget, command=("/bin/sh",),
                )
                completed = subprocess.run(
                    (
                        str(launcher), "--join-cgroup",
                        str(cgroup / "cgroup.procs"), "--", *prefix, "--",
                        str(launcher), "--", "/bin/sh", "-c",
                        "echo probe > .probe && cat .probe",
                    ),
                    capture_output=True,
                    timeout=10,
                    check=False,
                )
        except (OSError, subprocess.SubprocessError) as exc:
            availability = BackendAvailability(
                self.name,
                False,
                False,
                f"bwrap isolation probe could not run: {type(exc).__name__}: {exc}",
            )
            availability = BackendAvailability(
                availability.name,
                availability.available,
                availability.network_enforced,
                availability.reason,
                evidence,
            )
            self._capability_cache = _CapabilityCacheEntry(availability, evidence)
            if cgroup is not None:
                _remove_linux_cgroup(cgroup)
            return availability
        if completed.returncode == 0 and b"probe" in completed.stdout:
            availability = BackendAvailability(self.name, True, True)
        else:
            stderr = completed.stderr.decode("utf-8", errors="replace").strip()
            availability = BackendAvailability(
                self.name, False, False,
                f"bwrap isolation probe failed (rc={completed.returncode}): {stderr}",
            )
        availability = BackendAvailability(
            availability.name,
            availability.available,
            availability.network_enforced,
            availability.reason,
            evidence,
        )
        self._capability_cache = _CapabilityCacheEntry(availability, evidence)
        if cgroup is not None:
            _remove_linux_cgroup(cgroup)
        return availability

    SANDBOX_WORKDIR = "/workspace"

    def argv_prefix(
        self,
        worktree: Path,
        *,
        cwd: Path | None = None,
        writable: bool = True,
        unreadable_roots: tuple[Path, ...] = (),
        synthetic_home: Path | None = None,
        resources: ResourceBudget | None = None,
        command: tuple[str, ...] = (),
        environment: dict[str, str] | None = None,
        workspace_source: str | None = None,
        network_broker=None,
        include_network_authority: bool = True,
        network_mode: Literal["isolated", "shared"] = "isolated",
    ) -> tuple[str, ...]:
        canonical_worktree = worktree.expanduser().absolute()
        canonical_cwd = (cwd or canonical_worktree).expanduser().absolute()
        if (
            canonical_cwd != canonical_worktree
            and canonical_worktree not in canonical_cwd.parents
        ):
            raise PermissionError("sandbox cwd is outside the active workspace")
        relative_cwd = canonical_cwd.relative_to(canonical_worktree)
        sandbox_cwd = Path(self.SANDBOX_WORKDIR) / relative_cwd
        budget = resources or ResourceBudget()
        home = (synthetic_home or canonical_worktree / ".khaos-home").expanduser().absolute()
        home.mkdir(mode=0o700, parents=True, exist_ok=True)
        workspace_mount = workspace_source or str(canonical_worktree)
        prefix = [
            _resolve_bwrap_path(),  # P1-1: validated absolute path, not bare PATH
            "--tmpfs", "/",
            "--dir", "/home",
            "--dir", "/etc",
            # A full bwrap --dev also creates devpts and can require a
            # privileged root/overflow UID mapping.  That mapping is not
            # available to the non-root Agent inside the production Docker
            # composition.  Keep the device namespace minimal and explicit;
            # no host device tree or PTY namespace is needed for piped tool
            # execution.
            "--tmpfs", "/dev",
            # --dev-bind is required for device access under the tmpfs's
            # default nodev mount.  These are the only four device nodes
            # exposed; /dev/null is needed for ordinary output redirection.
            "--dev-bind", "/dev/null", "/dev/null",
            "--dev-bind", "/dev/zero", "/dev/zero",
            "--dev-bind", "/dev/random", "/dev/random",
            "--dev-bind", "/dev/urandom", "/dev/urandom",
            "--proc", "/proc",
            "--size", str(budget.tmpfs_bytes),
            "--tmpfs", "/home/khaos",
            "--size", str(budget.tmpfs_bytes),
            "--tmpfs", "/tmp",
            "--bind" if writable else "--ro-bind", workspace_mount, self.SANDBOX_WORKDIR,
        ]
        if writable:
            from khaos.coding.workspace.boundary import PROTECTED_WORKSPACE_NAMES

            for name in sorted(PROTECTED_WORKSPACE_NAMES):
                metadata = canonical_worktree / name
                if metadata.exists():
                    prefix.extend(
                        (
                            "--ro-bind",
                            (
                                f"{workspace_source}/{name}"
                                if workspace_source is not None
                                else str(metadata)
                            ),
                            f"{self.SANDBOX_WORKDIR}/{name}",
                        )
                    )
        for link in (Path("/bin"), Path("/sbin"), Path("/lib"), Path("/lib64")):
            if link.is_symlink():
                prefix.extend(("--symlink", os.readlink(link), str(link)))
        runtime_roots = _linux_runtime_read_roots(command, canonical_worktree)
        for runtime_root in runtime_roots:
            prefix.extend(("--ro-bind", str(runtime_root), str(runtime_root)))
        for literal in _linux_literal_read_files():
            if literal.is_file():
                prefix.extend(("--ro-bind", str(literal), str(literal)))
        launcher = _linux_sandbox_launcher()
        if launcher is not None:
            prefix.extend(("--ro-bind", str(launcher), str(launcher)))
        landlock_read_roots = {
            "/usr",
            "/etc",
            "/dev",
            "/proc",
            "/home",
            *(str(path) for path in runtime_roots),
            *(str(path) for path in _linux_literal_read_files()),
        }
        landlock_write_roots = {"/home/khaos", "/tmp"}
        if writable:
            landlock_write_roots.add(self.SANDBOX_WORKDIR)
        else:
            landlock_read_roots.add(self.SANDBOX_WORKDIR)
        safe_environment = _sandbox_environment(
            None,
            environment or {},
            home="/home/khaos",
            tmpdir="/tmp",
            network_broker=network_broker,
            include_network_authority=include_network_authority,
        )
        # The inner Rust launcher consumes these values only after bwrap has
        # created the final mount namespace.  JSON avoids ambiguous ':' path
        # splitting and makes the allowlist part of the exact spawn plan.
        safe_environment.update(
            {
                "KHAOS_LANDLOCK_REQUIRED": "1",
                "KHAOS_LANDLOCK_READ_ROOTS": json.dumps(
                    sorted(landlock_read_roots), separators=(",", ":")
                ),
                "KHAOS_LANDLOCK_WRITE_ROOTS": json.dumps(
                    sorted(landlock_write_roots), separators=(",", ":")
                ),
            }
        )
        prefix.append("--clearenv")
        for key, value in sorted(safe_environment.items()):
            prefix.extend(("--setenv", key, value))
        # deny-default mount construction makes unreadable roots absent.  They
        # must never be mounted merely to cover them with another mount.
        _ = unreadable_roots
        if network_mode not in {"isolated", "shared"}:
            raise ValueError(f"unsupported Linux bubblewrap network mode: {network_mode}")
        network_namespace = bool(
            network_broker is not None
            and getattr(network_broker, "uses_network_namespace", False)
        )
        network_option = (
            "--share-net"
            if network_mode == "shared" or network_namespace
            else "--unshare-net"
        )
        prefix.extend((
            network_option,
            *linux_job_namespace_args(),
            "--unshare-pid", "--unshare-ipc", "--unshare-uts",
            "--new-session", "--die-with-parent",
            "--chdir", str(sandbox_cwd),
        ))
        return tuple(prefix)

    async def execute(self, request):
        from dataclasses import replace
        if self.admission_closed:
            raise PermissionError(
                f"Linux bubblewrap backend is {self._state.value}, not accepting executions"
            )
        profile = _validated_profile(request)
        writable = profile.filesystem.value == "workspace-write"
        worktree = profile.workspace_roots[0]
        with tempfile.TemporaryDirectory(prefix="khaos-home-") as home_value:
            try:
                cgroup = await asyncio.to_thread(
                    _create_linux_cgroup, profile.resources, worktree
                )
            except OSError as exc:
                raise PermissionError(
                    f"execution refused: delegated cgroup v2 limits unavailable: {exc}"
                ) from exc
            execution_id = request.correlation_id
            try:
                lease = await self._register_cgroup_lease(execution_id, cgroup)
            except BaseException:
                # A duplicate execution id or a cancellation during
                # registration must not orphan the just-created cgroup. If
                # its external disappearance cannot be proven, retain it
                # under a unique lease so the backend remains the owner.
                try:
                    await asyncio.shield(
                        asyncio.to_thread(_remove_linux_cgroup, cgroup)
                    )
                except BaseException as cleanup_error:
                    orphan_id = (
                        f"{execution_id}:orphan:{secrets.token_hex(8)}"
                    )
                    async with self._lock:
                        self._cgroup_leases[orphan_id] = KernelResourceLease(
                            orphan_id, cgroup, quarantined=True
                        )
                        self._state = LinuxBubblewrapBackendState.QUARANTINED
                    raise RuntimeError(
                        "Linux cgroup registration failed and orphan cleanup "
                        "was not proven"
                    ) from cleanup_error
                raise
            if self.admission_closed:
                try:
                    await asyncio.shield(self._release_cgroup_lease(execution_id))
                except BaseException as exc:
                    raise PermissionError(
                        "execution refused: Linux cgroup admission closed and cleanup is unproven"
                    ) from exc
                raise PermissionError(
                    f"Linux bubblewrap backend is {self._state.value}, not accepting executions"
                )
            directory_binding: ExecutionDirectoryBinding | None = None
            try:
                directory_binding = open_execution_directory_binding(
                    worktree,
                    request.cwd,
                    expected_root_identity=request.workspace_root_identity,
                    expected_cwd_identity=request.workspace_cwd_identity,
                )
                workspace_source = (
                    directory_binding.proc_path(directory_binding.root_fd)
                    if sys.platform.startswith("linux")
                    else None
                )
                prefix = self.argv_prefix(
                    worktree,
                    cwd=request.cwd,
                    writable=writable,
                    unreadable_roots=profile.unreadable_roots,
                    synthetic_home=Path(home_value),
                    resources=profile.resources,
                    command=request.argv,
                    environment=request.environment,
                    network_broker=profile.network_broker,
                    include_network_authority=False,
                    # bwrap resolves bind sources in the launching mount
                    # namespace.  An inherited proc-fd keeps that source tied
                    # to the already-validated directory inode.
                    workspace_source=workspace_source,
                )
                launcher = _linux_sandbox_launcher()
                if launcher is None:
                    raise PermissionError(
                        "execution refused: no_new_privs/seccomp launcher unavailable"
                    )
                if self.admission_closed:
                    raise PermissionError(
                        f"Linux bubblewrap backend is {self._state.value}, "
                        "not accepting executions"
                    )
                if profile.network_broker is not None and profile.network_broker.uses_network_namespace:
                    sandboxed_argv = (
                        str(launcher), "--network-authority", "--cgroup",
                        str(lease.path / "cgroup.procs"), "--", *prefix, "--",
                        str(launcher), "--", *request.argv,
                    )
                    outer_environment = _linux_network_outer_environment(
                        profile, request.environment
                    )
                else:
                    sandboxed_argv = (
                        str(launcher), "--join-cgroup",
                        str(lease.path / "cgroup.procs"), "--", *prefix, "--",
                        str(launcher), "--", *request.argv,
                    )
                    # The bwrap prefix already carries the model-approved
                    # child environment via --clearenv/--setenv.  Keep the
                    # host-side launcher environment empty in the normal
                    # path; only the namespace join contract is allowed in
                    # the network-authority path above.
                    outer_environment = {}
                sandboxed = replace(
                    request,
                    argv=sandboxed_argv,
                    executable_identity=executable_identity(
                        sandboxed_argv, outer_environment
                    ),
                )
                supervisor = self.supervisor or ProcessSupervisor()
                self.supervisor = supervisor
                return await supervisor.run(
                    sandboxed,
                    cwd=request.cwd.expanduser().absolute(),
                    execution_root=worktree,
                    sandbox_storage_paths=("/home/khaos", "/tmp"),
                    workspace_root=worktree if writable else None,
                    workspace_baseline=request.workspace_baseline,
                    directory_binding=directory_binding,
                    preserve_directory_fds=True,
                    env=outer_environment,
                    termination_callback=(
                        lambda: asyncio.to_thread(
                            _kill_linux_cgroup_processes, lease.path
                        )
                    ),
                )
            except (OSError, PermissionError):
                self._capability_cache = None
                raise
            finally:
                # ProcessSupervisor closes the binding after spawn; this is
                # idempotent and also covers failures before supervisor.run.
                if directory_binding is not None:
                    directory_binding.close()
                await self._release_cgroup_lease(execution_id)

    async def terminate(self, execution_id: str) -> None:
        had_lease = execution_id in self._cgroup_leases
        errors: list[BaseException] = []
        if self.supervisor is not None:
            try:
                await self.supervisor.terminate(execution_id)
            except BaseException as exc:  # noqa: BLE001 - cleanup must continue
                errors.append(exc)
        if had_lease:
            try:
                await asyncio.shield(self._release_cgroup_lease(execution_id))
            except BaseException as exc:  # noqa: BLE001 - retain lease on failure
                errors.append(exc)
        if errors:
            if had_lease:
                self._state = LinuxBubblewrapBackendState.QUARANTINED
            raise errors[0]

    async def _release_cgroup_lease(self, execution_id: str) -> None:
        """Release only after the kernel path is absent; retain on failure."""
        async with self._lock:
            if execution_id not in self._cgroup_leases:
                return
            cleanup_task = self._release_tasks.get(execution_id)
            if cleanup_task is None or cleanup_task.done():
                cleanup_task = asyncio.create_task(
                    self._release_cgroup_lease_impl(execution_id),
                    name=f"khaos-linux-cgroup-cleanup:{execution_id}",
                )
                self._release_tasks[execution_id] = cleanup_task
        await asyncio.shield(cleanup_task)

    async def _release_cgroup_lease_impl(self, execution_id: str) -> None:
        lease = self._cgroup_leases.get(execution_id)
        if lease is None:
            return
        try:
            await asyncio.to_thread(_remove_linux_cgroup, lease.path)
            if lease.path.exists():
                raise RuntimeError(
                    f"cgroup disappearance was not proven: {lease.path}"
                )
        except BaseException as exc:
            lease.quarantined = True
            self._shutdown_error = exc
            self._state = LinuxBubblewrapBackendState.QUARANTINED
            raise
        finally:
            current = asyncio.current_task()
            if current is not None and self._release_tasks.get(execution_id) is current:
                self._release_tasks.pop(execution_id, None)
        self._cgroup_leases.pop(execution_id, None)


def _resolve_bwrap_path() -> str:
    """P1-1 (round-13): resolve bwrap to a validated absolute path.

    Reuses the browser path's ``_validate_tcb_binary`` to enforce the same
    canonical-path, owner/mode, parent-chain checks. A bare PATH lookup is
    permitted only under explicit ``KHAOS_DEV_MODE=1``.
    """
    from khaos.security.browser_sandbox import BrowserSandboxError, _validate_tcb_binary
    require = not _development_mode()
    located = shutil.which("bwrap")
    if located is None:
        if require:
            raise PermissionError("bubblewrap ('bwrap') required but not found")
        return "bwrap"
    if require:
        try:
            return _validate_tcb_binary(located, label="coding bwrap")
        except BrowserSandboxError as exc:
            raise PermissionError(f"coding bwrap TCB validation failed: {exc}") from exc
    return located


def _linux_sandbox_launcher() -> Path | None:
    """Resolve the reviewed Rust execution inner TCB.

    P1-1 (round-13): secure production mode
    validates the launcher via ``_validate_tcb_binary`` (canonical path,
    owner/mode, parent chain) — the same checks the browser path uses.
    Production Docker/systemd deployments must provide a dedicated
    capability-free execution copy through
    ``KHAOS_EXECUTION_SANDBOX_LAUNCHER``.  The browser launcher remains a
    separate ``KHAOS_SANDBOX_LAUNCHER`` because only its authenticated helper
    path needs the file capability for ``setns``; it is never a coding
    execution fallback.  Dev mode accepts any candidate that is a regular
    executable file, but still keeps the browser authority path separate.
    """
    configured = os.environ.get("KHAOS_EXECUTION_SANDBOX_LAUNCHER", "").strip()
    candidates: list[Path] = []
    if configured:
        candidates.append(Path(configured).expanduser())
    repository_root = Path(__file__).resolve().parents[4]
    candidates.extend((
        repository_root / "rust" / "khaos-core" / "target" / "release"
        / "khaos-sandbox-launcher",
    ))
    # P1-1: target/debug is dev-only; skip it in production.
    if _development_mode():
        candidates.append(
            repository_root / "rust" / "khaos-core" / "target" / "debug"
            / "khaos-sandbox-launcher"
        )
    located = shutil.which("khaos-execution-sandbox-launcher")
    if located:
        candidates.append(Path(located))
    require = not _development_mode()
    for candidate in candidates:
        canonical = candidate.resolve()
        if not (canonical.is_file() and os.access(canonical, os.X_OK)):
            continue
        if require:
            from khaos.security.browser_sandbox import (
                BrowserSandboxError,
                _validate_tcb_binary,
            )
            try:
                validated = _validate_tcb_binary(str(canonical), label="coding launcher")
                return Path(validated)
            except BrowserSandboxError:
                continue
        return canonical
    return None


def _development_mode() -> bool:
    """Only the exact explicit opt-in enables development fallbacks."""
    return os.environ.get("KHAOS_DEV_MODE") == "1"


def _mountinfo_has_cgroup_v2_path(path: Path, mountinfo: str) -> bool:
    """Return whether ``path`` is on a mount whose filesystem is cgroup2."""
    for line in mountinfo.splitlines():
        before_separator, separator, after_separator = line.partition(" - ")
        if not separator:
            continue
        fields = before_separator.split()
        filesystem = after_separator.split()
        if len(fields) < 5 or not filesystem or filesystem[0] != "cgroup2":
            continue
        mountpoint = Path(
            re.sub(
                r"\\([0-7]{3})",
                lambda match: chr(int(match.group(1), 8)),
                fields[4],
            )
        )
        if path == mountpoint or mountpoint in path.parents:
            return True
    return False


def _path_is_on_cgroup_v2_mount(path: Path) -> bool:
    """Check the kernel mount table instead of trusting a directory marker."""
    try:
        mountinfo = Path("/proc/self/mountinfo").read_text(encoding="ascii")
    except (OSError, UnicodeError):
        return False
    return _mountinfo_has_cgroup_v2_path(path, mountinfo)


def _linux_cgroup_root() -> Path | None:
    """Return a writable delegated cgroup-v2 subtree, if available."""
    if not sys.platform.startswith("linux"):
        return None
    configured = os.environ.get("KHAOS_CGROUP_ROOT", "").strip()
    root = Path(configured) if configured else Path("/sys/fs/cgroup/khaos")
    try:
        if not root.is_absolute() or root.is_symlink():
            return None
        root.mkdir(mode=0o700, parents=True, exist_ok=True)
        canonical = root.resolve()
        if not (canonical / "cgroup.controllers").is_file():
            return None
        if not _path_is_on_cgroup_v2_mount(canonical):
            return None
        if not os.access(canonical, os.W_OK):
            return None
        return canonical
    except OSError:
        return None


def _create_linux_cgroup(
    budget: ResourceBudget, workspace: Path,
) -> Path:
    """Create and fully configure a per-execution cgroup-v2 leaf."""
    root = _linux_cgroup_root()
    if root is None:
        raise OSError("cgroup root is not a writable delegated v2 subtree")
    group = root / f"exec-{os.getpid()}-{secrets.token_hex(8)}"
    current_limit = "create leaf"
    try:
        group.mkdir(mode=0o700)
        period = 100_000
        quota = max(1_000, int(budget.cpu_count * period))
        io_rate = max(
            1024 * 1024,
            min(
                256 * 1024 * 1024,
                int(budget.workspace_bytes / max(1.0, budget.timeout_seconds)),
            ),
        )
        device = workspace.resolve().stat().st_dev
        limits = {
            "pids.max": str(budget.pids),
            "memory.max": str(budget.memory_bytes),
            "memory.swap.max": "0",
            "cpu.max": f"{quota} {period}",
            "io.max": (
                f"{os.major(device)}:{os.minor(device)} "
                f"rbps={io_rate} wbps={io_rate}"
            ),
        }
        for name, value in limits.items():
            current_limit = name
            (group / name).write_text(value, encoding="ascii")
        return group
    except OSError as exc:
        _remove_linux_cgroup(group)
        raise OSError(f"failed to configure {current_limit}: {exc}") from exc


def _remove_linux_cgroup(group: Path) -> None:
    """Remove a cgroup-v2 leaf using the proper kill → wait → rmdir flow.

    Round-4 review Batch 4 (§13.4): previously this method only called
    ``group.rmdir()`` and silently ignored failures — a live payload
    kept the leaf non-empty, causing the cgroup to leak.  The proper
    cgroup v2 teardown flow is:

    1. Write ``1`` to ``cgroup.kill`` — synchronously kills all
       processes in the cgroup (including descendants).
    2. Wait for ``cgroup.events`` to report ``populated=0`` — the
       kernel has reaped all processes.
    3. Remove descendant cgroups (if any) bottom-up.
    4. ``rmdir`` the leaf.

    If any step fails, the cgroup is left in place and the error is raised.
    The owning backend retains its kernel lease and enters quarantine; a
    later explicit retry may only clear the lease after the path disappears.
    """
    if not group.is_dir():
        return
    # Step 1-2: kill all processes in the cgroup and prove that the kernel
    # has reaped them before attempting to remove the leaf.
    _kill_linux_cgroup_processes(group)
    # Step 3: remove descendant cgroups bottom-up (if any).
    descendants: list[Path] = []
    for child in group.rglob("*"):
        if child.is_dir():
            descendants.append(child)
    failures: list[BaseException] = []
    for child in sorted(descendants, reverse=True):
        try:
            child.rmdir()
        except OSError as exc:
            failures.append(exc)
    if failures:
        raise RuntimeError(
            f"cgroup descendants could not be removed: {group}"
        ) from failures[0]
    # Step 4: rmdir the leaf.
    group.rmdir()
    if group.exists():
        raise RuntimeError(f"cgroup disappearance was not proven: {group}")


def _kill_linux_cgroup_processes(group: Path) -> None:
    """Kill every process in a cgroup and prove that it became empty.

    This is deliberately separate from ``_remove_linux_cgroup`` because the
    process supervisor must perform kernel-level tree termination *before*
    it drains captured output.  Removing the cgroup belongs to the backend's
    final lease release and must happen only after the supervisor has reached
    a terminal process result.
    """
    import time

    if not group.is_dir():
        return
    kill_file = group / "cgroup.kill"
    if not kill_file.is_file():
        raise OSError(f"cgroup.kill is unavailable: {group}")
    kill_file.write_text("1", encoding="ascii")
    events_file = group / "cgroup.events"
    if not events_file.is_file():
        raise OSError(f"cgroup.events is unavailable: {group}")
    deadline = time.monotonic() + 5.0
    while time.monotonic() < deadline:
        content = events_file.read_text(encoding="ascii")
        if "populated 0" in content or "populated=0" in content:
            return
        time.sleep(0.1)
    raise TimeoutError(f"cgroup remained populated: {group}")


def _validated_profile(request):
    profile = request.permission_profile
    if profile is None:
        raise PermissionError("execution request has no permission profile")
    profile.validate_resolved()
    if profile.network.value == "brokered":
        lease = profile.network_broker
        if lease is not None:
            lease.validate()
        valid_endpoint = (
            lease is not None
            and 1 <= lease.port <= 65535
            and (
                lease.host == "127.0.0.1"
                or (
                    lease.uses_network_namespace
                    and _is_private_ipv4(lease.host)
                )
            )
        )
        if not valid_endpoint:
            raise PermissionError(
                "brokered network policy requires a loopback or kernel-namespace NetworkLease"
            )
        # ``valid_endpoint`` proves this value is present, but Pyright cannot
        # retain that narrowing across the boolean expression above.
        assert lease is not None
        if sys.platform.startswith("linux") and not lease.uses_network_namespace:
            raise PermissionError(
                "Linux brokered execution requires a kernel-network-namespace NetworkLease"
            )
    elif profile.network.value != "none":
        raise PermissionError(
            f"platform backend cannot enforce requested network policy: {profile.network.value}"
        )
    return profile


def _seatbelt_escape(path: Path) -> str:
    return str(path).replace("\\", "\\\\").replace('"', '\\"')


def _deduplicate_paths(
    paths: tuple[Path, ...],
    *,
    preserve_paths: tuple[Path, ...] = (),
) -> tuple[Path, ...]:
    result: list[Path] = []
    seen: set[Path] = set()
    preserved = set(preserve_paths)
    for path in paths:
        lexical = path.expanduser().absolute()
        canonical = lexical if lexical in preserved else lexical.resolve()
        if canonical not in seen:
            result.append(canonical)
            seen.add(canonical)
    return tuple(result)


def _runtime_read_roots(
    command: tuple[str, ...], workspace: Path
) -> tuple[Path, ...]:
    """Return the narrow installation root needed to launch argv[0]."""
    if not command:
        return ()
    executable = command[0]
    located = shutil.which(executable) if not Path(executable).is_absolute() else executable
    if not located:
        return ()
    lexical = Path(located).expanduser().absolute()
    resolved = Path(located).expanduser().resolve()
    canonical_workspace = workspace.expanduser().absolute()
    venv_roots: tuple[Path, ...] = ()
    if len(lexical.parents) >= 2:
        possible_venv = lexical.parents[1]
        if (
            (possible_venv / "pyvenv.cfg").is_file()
            and possible_venv != canonical_workspace
            and canonical_workspace not in possible_venv.parents
        ):
            # Python resolves the executable symlink to its base install, but
            # ``site.py`` still reads pyvenv.cfg through the lexical venv
            # path. Both narrow roots are therefore required.
            venv_roots = (possible_venv.resolve(),)
    if resolved == canonical_workspace or canonical_workspace in resolved.parents:
        return venv_roots
    for root in _macos_system_read_roots():
        if resolved == root or root in resolved.parents:
            return venv_roots
    parents = resolved.parents
    if len(parents) < 2:
        return (*venv_roots, resolved)
    # /opt/homebrew/bin/python -> /opt/homebrew; framework and application
    # binaries receive their product root rather than the user's whole HOME.
    if resolved.parts[:3] == ("/", "opt", "homebrew"):
        return (*venv_roots, Path("/opt/homebrew"))
    if "Library" in resolved.parts and "Frameworks" in resolved.parts:
        index = resolved.parts.index("Frameworks")
        return (*venv_roots, Path(*resolved.parts[: index + 2]))
    if ".app" in "".join(resolved.parts):
        for index, part in enumerate(resolved.parts):
            if part.endswith(".app"):
                return (*venv_roots, Path(*resolved.parts[: index + 1]))
    candidate = parents[1]
    home = Path.home().resolve()
    if candidate == home or candidate in home.parents:
        return (*venv_roots, resolved)
    return (*venv_roots, candidate)


def _macos_system_read_roots() -> tuple[Path, ...]:
    return tuple(
        path for path in (
            Path("/System"), Path("/usr"), Path("/bin"), Path("/sbin"),
            Path("/Library/Apple"),
            Path("/private/var/db/dyld"),
            Path("/System/Volumes/Preboot/Cryptexes/OS"),
        ) if path.exists()
    )


def _macos_literal_read_files() -> tuple[Path, ...]:
    return tuple(
        path for path in (
            Path("/etc/hosts"), Path("/etc/passwd"), Path("/etc/group"),
            Path("/etc/localtime"),
            # /etc is a symlink to /private/etc on macOS. Seatbelt matches
            # the canonical path for these libc inputs, so allow only the
            # concrete files instead of a broad /private read rule.
            Path("/private/etc/hosts"), Path("/private/etc/passwd"),
            Path("/private/etc/group"), Path("/private/etc/localtime"),
        ) if path.exists()
    )


def _macos_runtime_mach_services() -> tuple[str, ...]:
    """Minimal lookup needed for libc account/group resolution."""
    return ("com.apple.system.opendirectoryd.libinfo",)


def _linux_runtime_read_roots(
    command: tuple[str, ...], workspace: Path
) -> tuple[Path, ...]:
    roots = [
        path for path in (
            Path("/usr"), Path("/bin"), Path("/sbin"), Path("/lib"),
            Path("/lib64"),
        ) if path.exists() and not path.is_symlink()
    ]
    roots.extend(_runtime_read_roots(command, workspace))
    return _deduplicate_paths(tuple(roots))


def _linux_literal_read_files() -> tuple[Path, ...]:
    return tuple(
        path for path in (
            Path("/etc/ld.so.cache"), Path("/etc/ld.so.conf"),
            Path("/etc/nsswitch.conf"), Path("/etc/passwd"),
            Path("/etc/group"), Path("/etc/localtime"),
        ) if path.exists()
    )


def _sandbox_environment(
    profile,
    requested: dict[str, str],
    *,
    home: str,
    tmpdir: str,
    network_broker=None,
    include_network_authority: bool = True,
) -> dict[str, str]:
    allowed_keys = (
        profile.environment_keys if profile is not None
        else frozenset({"PATH", "LANG", "LC_ALL", "TERM"})
    )
    environment = {
        key: value for key, value in requested.items() if key in allowed_keys
    }
    environment.setdefault("PATH", os.defpath)
    environment.setdefault("LANG", "C.UTF-8")
    environment.update({"HOME": home, "TMPDIR": tmpdir, "TMP": tmpdir, "TEMP": tmpdir})
    environment = scrub_spawn_environment(environment)
    lease = network_broker
    if lease is None and profile is not None:
        lease = getattr(profile, "network_broker", None)
    if lease is not None:
        environment.update(lease.proxy_environment())
        if include_network_authority and lease.namespace_environment:
            environment.update(dict(lease.namespace_environment))
    return environment


def _linux_network_outer_environment(profile, requested: dict[str, str]) -> dict[str, str]:
    """Build the scrubbed environment consumed only by the outer TCB launcher."""
    allowed = {
        key: value
        for key, value in requested.items()
        if key in profile.environment_keys
    }
    allowed.setdefault("PATH", os.defpath)
    environment = scrub_spawn_environment(allowed)
    lease = profile.network_broker
    if lease is None or not lease.namespace_environment:
        raise PermissionError("Linux network authority lease is missing its join contract")
    environment.update(dict(lease.namespace_environment))
    return environment


def _is_private_ipv4(value: str) -> bool:
    import ipaddress

    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    return address.version == 4 and address.is_private and not address.is_loopback
