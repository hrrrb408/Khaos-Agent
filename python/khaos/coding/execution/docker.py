"""Docker execution backend consuming only resolved TaskWorkspace contexts."""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import re
import secrets
import tempfile
import uuid
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

from khaos.coding.execution.capability import DockerSandboxDecision
from khaos.coding.execution.environment import scrub_spawn_environment
from khaos.coding.execution.identity import (
    container_command_identity,
    executable_identity,
)
from khaos.coding.execution.models import (
    ExecutionRequest,
    ExecutionResult,
    NetworkPolicy,
    ResolvedExecutionContext,
    ResourceBudget,
)
from khaos.coding.execution.supervisor import ProcessSupervisor, SupervisorClosedError

logger = logging.getLogger(__name__)

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
_DELETED_FILE_EXIT_CODE = 173
_DOCKER_HARDENING_GENERATION = "docker-hardened-v2"
_CLEANUP_VERIFY_ATTEMPTS = 20
_CLEANUP_VERIFY_INTERVAL_SECONDS = 0.1
_DELETED_FILE_WATCHDOG = r'''
import os, signal, stat, subprocess, sys, time
limit = int(sys.argv[1])
command = sys.argv[3:]
process = subprocess.Popen(command, start_new_session=True)
process_group = str(process.pid)
observation_failures = 0

def process_group_pids(group_id):
    members = []
    complete = True
    try:
        pids = os.listdir('/proc')
    except OSError:
        return members, False
    for pid in pids:
        if not pid.isdigit():
            continue
        stat_path = f'/proc/{pid}/stat'
        try:
            with open(stat_path, encoding='ascii') as stat_file:
                stat_line = stat_file.read()
            closing_parenthesis = stat_line.rfind(')')
            if closing_parenthesis < 0:
                if pid == group_id:
                    complete = False
                continue
            fields = stat_line[closing_parenthesis + 2:].split()
            if len(fields) < 3 or fields[2] != group_id:
                continue
        except (FileNotFoundError, ProcessLookupError):
            continue
        except OSError:
            # Unrelated namespace processes may be hidden from this user;
            # only an observation failure for our own process is fatal.
            if pid == group_id:
                complete = False
            continue
        members.append(pid)
    return members, complete

while process.poll() is None:
    total = 0
    seen = set()
    complete = True
    pids, group_complete = process_group_pids(process_group)
    complete = complete and group_complete
    for pid in pids:
        root = f'/proc/{pid}/fd'
        try:
            names = os.listdir(root)
        except (FileNotFoundError, ProcessLookupError):
            continue
        except OSError:
            complete = False
            continue
        for name in names:
            path = f'{root}/{name}'
            try:
                target = os.readlink(path)
                if not target.endswith(' (deleted)'):
                    continue
                info = os.stat(path)
            except (FileNotFoundError, ProcessLookupError):
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
            blocks = getattr(info, 'st_blocks', 0) * 512
            total += blocks if blocks > 0 else info.st_size
    if total > limit:
        # A child can become a zombie between poll() and /proc/<pid>/fd
        # inspection. Its descriptors are no longer observable, but it is
        # already terminal and no deleted-open allocation can continue to
        # grow. Preserve fail-closed behavior while the child is live.
        if process.poll() is not None:
            break
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait()
        raise SystemExit(173)
    if not complete:
        if process.poll() is not None:
            break
        observation_failures += 1
        if observation_failures < 3:
            time.sleep(0.01)
            continue
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait()
        raise SystemExit(173)
    observation_failures = 0
    time.sleep(0.05)
raise SystemExit(process.returncode)
'''.strip()


@dataclass
class _ContainerLease:
    name: str
    owner_nonce: str
    cleanup_lock: asyncio.Lock = field(default_factory=asyncio.Lock)


class DockerBackendState(str, Enum):
    """Lifecycle states for the Docker resource owner."""

    OPEN = "OPEN"
    CLOSING = "CLOSING"
    QUARANTINED = "QUARANTINED"
    CLOSED = "CLOSED"


class DockerBackendClosedError(RuntimeError):
    """Raised when a Docker execution is admitted after closure begins."""


@dataclass
class _InflightLease:
    """Owner-held finalizer lease independent from the caller task.

    The finalizer task is created while the execution is admitted.  It waits
    on ``completion_event`` and removes the registry entry itself, so a
    caller cancellation (including repeated cancellation) cannot cancel the
    only task that knows how to release the in-flight marker.
    """

    execution_id: str
    completion_event: asyncio.Event
    finalizer_task: asyncio.Task[None]
    container_lease: _ContainerLease | None = None
    diagnostics: dict[str, object] | None = None
    cleanup_paths: tuple[Path, ...] = ()


class DockerBackend:
    """Run fixed-argv commands in hardened, ephemeral Docker containers."""

    name = "docker"

    def __init__(
        self,
        *,
        allowed_images: set[str] | None = None,
        docker_binary: str = "docker",
        supervisor: ProcessSupervisor | None = None,
        shutdown_timeout_seconds: float = 15.0,
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
        if shutdown_timeout_seconds <= 0:
            raise ValueError("Docker shutdown timeout must be positive")
        self.shutdown_timeout_seconds = float(shutdown_timeout_seconds)
        self._active: dict[str, _ContainerLease] = {}
        self._lock = asyncio.Lock()
        self._state = DockerBackendState.OPEN
        self._shutdown_task: asyncio.Task[None] | None = None
        # A container lease can disappear before the execute coroutine has
        # returned from its final cleanup block. Keep an owner-created
        # finalizer task so service shutdown cannot close the shared
        # supervisor underneath its last cleanup await.  The task is
        # registered before the caller can reach its first await.
        self._inflight: set[str] = set()
        self._inflight_events: dict[str, asyncio.Event] = {}
        self._inflight_leases: dict[str, _InflightLease] = {}
        self._inflight_idle = asyncio.Event()
        self._inflight_idle.set()
        self._shutdown_started = False
        self._shutdown_complete = False
        self._shutdown_error: BaseException | None = None

    @property
    def terminal_closed(self) -> bool:
        """True only after every container lease has been externally released."""
        return (
            self._state is DockerBackendState.CLOSED
            and self._shutdown_complete
            and not self._active
            and not self._inflight
            and not self._inflight_leases
        )

    @property
    def state(self) -> str:
        """Return the public lifecycle state used by ResourceOwner."""
        return self._state.value

    @property
    def admission_closed(self) -> bool:
        """True once shutdown or quarantine has closed new execution admission."""
        return self._state is not DockerBackendState.OPEN

    @property
    def generation_admission_closed(self) -> bool:
        """Docker has one backend generation, closed at first shutdown request."""
        return self.admission_closed

    @property
    def child_admission_closed(self) -> bool:
        """Docker cannot accept child resources after its backend fence closes."""
        return self.admission_closed

    @property
    def is_quarantined(self) -> bool:
        """True when a container lease remains after a failed cleanup."""
        return self._state is DockerBackendState.QUARANTINED

    def owned_resources(self) -> tuple[str, ...]:
        """Return the container leases retained by this backend."""
        return tuple(
            f"container:{execution_id}:{lease.name}"
            for execution_id, lease in sorted(self._active.items())
        ) + tuple(
            f"execution-finalizer:{execution_id}"
            for execution_id in sorted(
                self._inflight | set(self._inflight_leases)
            )
        )

    def owns_execution(self, execution_id: str) -> bool:
        """Return whether this backend still owns one execution lease.

        The backend can remain OPEN while one execution is terminated. A
        per-execution oracle is distinct from the backend-wide
        ``terminal_closed`` proof used during runtime shutdown.
        """
        return (
            execution_id in self._active
            or execution_id in self._inflight
            or execution_id in self._inflight_leases
        )

    def terminal_postcondition(self) -> bool:
        """Return the independent terminal proof for Docker ownership."""
        return self.terminal_closed and not self.owned_resources()

    async def execute_resolved(self, context: ResolvedExecutionContext) -> ExecutionResult:
        """Execute one resolved request while retaining finalizer ownership."""
        execution_id = context.correlation_id
        await self._begin_inflight(execution_id)
        try:
            return await self._execute_resolved(context)
        finally:
            await self._end_inflight(execution_id)

    async def _execute_resolved(self, context: ResolvedExecutionContext) -> ExecutionResult:
        self._validate_context(context)
        image = _image_from_environment(context.environment)
        if image not in self.allowed_images:
            raise PermissionError("Docker image is not in the configured allowlist")
        if _DIGEST_PINNED_IMAGE.fullmatch(image) is None:
            raise PermissionError("Docker image must be pinned by sha256 digest")
        inspected = await self._run_cli(("image", "inspect", image), timeout=10)
        if inspected[0] != 0:
            raise PermissionError("Docker image is unavailable locally; automatic pull is disabled")
        if context.sandbox_decision is not None:
            await self._verify_docker_decision(context, image)

        execution_id = context.correlation_id
        if _SAFE_EXECUTION_ID.fullmatch(execution_id) is None:
            raise PermissionError("execution id is unsafe for a container name")
        container_name = f"khaos-{execution_id}"
        lease = _ContainerLease(container_name, secrets.token_hex(16))
        relative_cwd = context.cwd.relative_to(context.worktree_path)
        container_cwd = Path("/workspace") / relative_cwd
        # ProcessSupervisor owns the host-side Docker CLI timeout/cancel and
        # DockerBackend owns container cleanup.  Disable Docker's default
        # signal proxy so a supervisor SIGTERM cannot be forwarded to the
        # payload and returned as 128+signal (143 for SIGTERM), which races
        # the supervisor deadline and makes a real timeout look like a
        # payload failure.
        argv = [
            self.docker_binary, "run", "--name", container_name, "--rm",
            "--pull", "never", "--init", "--sig-proxy=false", "--ipc", "none",
            "--label", f"{_OWNER_LABEL}={lease.owner_nonce}",
            "--label", f"io.khaos.execution={execution_id}",
            "--read-only", "--tmpfs", f"/tmp:rw,noexec,nosuid,nodev,size={context.budget.tmpfs_bytes}",
            "--user", "65534:65534", "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges", "--pids-limit", str(context.budget.pids),
            "--cpus", str(context.budget.cpu_count), "--memory", str(context.budget.memory_bytes),
            "--ulimit", f"fsize={context.budget.file_bytes}:{context.budget.file_bytes}",
            "--ulimit", f"nofile={context.budget.open_files}:{context.budget.open_files}",
            "--network", "none", "--mount",
            f"type=bind,src={context.worktree_path},dst=/workspace",
        ]
        from khaos.coding.workspace.policy import PROTECTED_WORKSPACE_NAMES

        for name in sorted(PROTECTED_WORKSPACE_NAMES):
            source = context.worktree_path / name
            if not source.exists() or source.is_symlink():
                raise PermissionError(
                    f"protected workspace mount target is unavailable: {name}"
                )
            argv.extend(
                (
                    "--mount",
                    f"type=bind,src={source},dst=/workspace/{name},readonly",
                )
            )
        argv.extend(("--workdir", str(container_cwd)))
        env_file = self._write_env_file(context)
        if env_file is not None:
            argv.extend(["--env-file", str(env_file)])
        argv.extend([
            image,
            "python",
            "-c",
            _DELETED_FILE_WATCHDOG,
            str(context.budget.workspace_bytes),
            "--",
            *context.argv,
        ])

        diagnostics: dict[str, object] = {
            "container_id": container_name,
            "cleanup": "pending",
        }

        try:
            async with self._lock:
                self._require_open_locked()
                if execution_id in self._active:
                    raise RuntimeError(
                        f"Docker execution is already active: {execution_id}"
                    )
                self._active[execution_id] = lease
                inflight = self._inflight_leases.get(execution_id)
                if inflight is None:
                    self._active.pop(execution_id, None)
                    raise RuntimeError(
                        f"Docker execution lost its in-flight ownership: {execution_id}"
                    )
                # The owner finalizer now owns container cleanup.  Publishing
                # this lease before the host Docker CLI spawn makes the
                # acquisition transaction monotonic: shutdown can never
                # observe an unowned late-spawn window.
                inflight.container_lease = lease
                inflight.diagnostics = diagnostics
                inflight.cleanup_paths = (
                    (env_file,) if env_file is not None else ()
                )
        except BaseException:
            # Admission can close after the env file is created but before
            # the container lease is published.  The normal execution
            # finally block does not own that gap, so unlink the secret-safe
            # temporary file here before rejecting the request.
            if env_file is not None:
                env_file.unlink(missing_ok=True)
            raise
        try:
            await self._before_supervisor_run(execution_id)
            docker_environment = {"PATH": os.environ.get("PATH", os.defpath)}
            docker_request = ExecutionRequest(
                argv=tuple(argv),
                cwd=context.cwd,
                environment=docker_environment,
                permission_profile=context.permission_profile,
                correlation_id=execution_id,
                workspace_root_identity=context.workspace_root_identity,
                workspace_cwd_identity=context.workspace_cwd_identity,
                executable_identity=executable_identity(tuple(argv), docker_environment),
                sandbox_decision=context.sandbox_decision,
                spawn_plan=context.spawn_plan,
            )
            result = await self.supervisor.run(
                docker_request,
                cwd=context.cwd,
                execution_root=context.worktree_path,
                env={"PATH": os.environ.get("PATH", "")},
                # The Docker daemon enforces the request's pids/CPU/memory/
                # tmpfs limits on the container. Applying the payload's
                # RLIMIT_AS to the host-side Go Docker CLI can prevent that
                # control process from starting before a container exists.
                enforce_resource_limits=False,
                enforce_resource_watchdog=True,
                workspace_root=context.worktree_path,
                workspace_baseline=context.workspace_baseline,
                use_native_launcher=True,
            )
            diagnostics.update(result.diagnostics)
            status = result.status
            if result.return_code == _DELETED_FILE_EXIT_CODE:
                status = "resource-exhausted"
                diagnostics["resource_violation"] = {
                    "kind": "workspace-bytes",
                    "observed": "deleted-open-file-budget-exceeded",
                    "limit": context.budget.workspace_bytes,
                }
            return ExecutionResult(
                execution_id=execution_id,
                status=status,
                return_code=result.return_code,
                stdout=result.stdout,
                stderr=result.stderr,
                duration_ms=result.duration_ms,
                diagnostics=diagnostics,
            )
        finally:
            # Cleanup is deliberately performed by the owner-created
            # in-flight finalizer after the execution transaction reaches its
            # terminal point.  A caller cancellation cannot cancel the only
            # task that knows the container lease and its external oracle.
            pass

    async def _before_supervisor_run(self, execution_id: str) -> None:
        """Test seam kept before the supervisor's monotonic spawn reserve."""
        _ = execution_id

    async def prepare_decision(
        self,
        *,
        image: str,
        workspace: Path,
        budget: ResourceBudget,
        argv: tuple[str, ...],
        filesystem_mode: str = "workspace-write",
    ) -> DockerSandboxDecision:
        """Resolve the concrete Docker daemon/image/hardening authority."""
        if image not in self.allowed_images:
            raise PermissionError("Docker image is not in the configured allowlist")
        if _DIGEST_PINNED_IMAGE.fullmatch(image) is None:
            raise PermissionError("Docker image must be pinned by sha256 digest")
        image_result = await self._run_cli(("image", "inspect", image), timeout=10)
        if image_result[0] != 0:
            raise PermissionError(
                "Docker image is unavailable locally; automatic pull is disabled"
            )
        daemon_result = await self._run_cli(
            ("info", "--format", "{{.ID}}|{{.Driver}}|{{.SecurityOptions}}"),
            timeout=10,
        )
        if daemon_result[0] != 0:
            raise PermissionError("Docker daemon identity could not be verified")
        docker_env = {"PATH": os.environ.get("PATH", os.defpath)}
        binary_identity = executable_identity((self.docker_binary,), docker_env)
        daemon_identity = _canonical_digest(
            {"stdout": daemon_result[1].strip(), "stderr": daemon_result[2].strip()}
        )
        image_digest = image.split("@sha256:", 1)[1]
        return DockerSandboxDecision(
            backend_name="docker",
            capability_evidence_digest=_canonical_digest(
                {"binary": binary_identity, "daemon": daemon_identity}
            ),
            filesystem_mode=filesystem_mode,
            network_mode=NetworkPolicy.NONE.value,
            kernel_enforced=True,
            platform=os.uname().sysname.lower() if hasattr(os, "uname") else "unknown",
            launcher_digest=binary_identity,
            docker_binary_identity=binary_identity,
            daemon_identity_digest=daemon_identity,
            image_reference=image,
            image_digest=image_digest,
            uid="65534:65534",
            capabilities=("ALL",),
            no_new_privileges=True,
            read_only_rootfs=True,
            workspace_mount_policy_digest=_workspace_mount_policy_digest(workspace),
            budget_digest=budget.digest(),
            hardening_generation=_DOCKER_HARDENING_GENERATION,
            command_digest=_canonical_digest(argv),
        )

    async def _verify_docker_decision(
        self, context: ResolvedExecutionContext, image: str
    ) -> None:
        decision = context.sandbox_decision
        if not isinstance(decision, DockerSandboxDecision):
            raise PermissionError(
                "Docker execution requires a concrete DockerSandboxDecision"
            )
        observed = await self.prepare_decision(
            image=image,
            workspace=context.worktree_path,
            budget=context.budget,
            argv=context.argv,
            filesystem_mode=context.access_mode,
        )
        if observed.digest() != decision.digest():
            raise PermissionError(
                "Docker sandbox decision changed before execution"
            )

    async def execute(self, request):
        raise PermissionError("DockerBackend requires ResolvedExecutionContext")

    async def terminate(self, execution_id: str) -> None:
        await self.supervisor.terminate(execution_id)
        await self._wait_for_execution_idle(execution_id)
        await self._release_retained_lease(execution_id)

    async def shutdown(self) -> None:
        # Clean up containers.  Do NOT close the supervisor here — the
        # supervisor is shared with ExecutionService which owns its
        # lifecycle.  ExecutionService._run_shutdown() closes the
        # supervisor after docker_backend.shutdown() returns.
        async with self._lock:
            if self.terminal_closed:
                return
            if self._shutdown_task is None or self._shutdown_task.done():
                # Close admission atomically with publishing the shared
                # shutdown task.  A second caller must join this exact task,
                # not start a competing cleanup pass.
                self._state = DockerBackendState.CLOSING
                self._shutdown_started = True
                self._shutdown_complete = False
                self._shutdown_error = None
                self._shutdown_task = asyncio.create_task(
                    self._shutdown_impl(),
                    name="khaos-docker-backend-shutdown",
                )
            shutdown_task = self._shutdown_task
        await asyncio.shield(shutdown_task)

    async def close(self) -> None:
        """ResourceOwner alias for :meth:`shutdown`."""
        await self.shutdown()

    async def _shutdown_impl(self) -> None:
        errors: list[BaseException] = []
        try:
            async with self._lock:
                execution_ids = tuple(
                    sorted(set(self._active) | set(self._inflight))
                )
            for execution_id in execution_ids:
                try:
                    # Stop the host-side Docker CLI.  The owner finalizer
                    # performs Docker stop/rm and keeps the lease until the
                    # external inspect oracle proves disappearance.
                    await self.supervisor.terminate(execution_id)
                    await self._wait_for_execution_idle(execution_id)
                    await self._release_retained_lease(execution_id)
                except asyncio.CancelledError:
                    raise
                except BaseException as exc:  # noqa: BLE001 — retain lease for retry
                    errors.append(exc)
                    continue

            async with self._lock:
                finalizers = tuple(
                    lease.finalizer_task for lease in self._inflight_leases.values()
                )
            if finalizers:
                done, pending = await asyncio.wait(
                    finalizers,
                    timeout=self.shutdown_timeout_seconds,
                )
                for task in done:
                    if task.cancelled():
                        errors.append(
                            RuntimeError("Docker execution finalizer task was cancelled")
                        )
                    else:
                        exception = task.exception()
                        if exception is not None:
                            errors.append(exception)
                if pending:
                    errors.append(
                        TimeoutError(
                            "Docker shutdown timed out waiting for execution finalizers"
                        )
                    )
            async with self._lock:
                stale_ownership = bool(
                    self._active or self._inflight or self._inflight_leases
                )
            if stale_ownership:
                errors.append(
                    RuntimeError(
                        "Docker shutdown left owned container or finalizer leases"
                    )
                )
            if errors:
                primary = errors[0]
                async with self._lock:
                    self._state = DockerBackendState.QUARANTINED
                    self._shutdown_error = primary
                    self._shutdown_complete = False
                raise RuntimeError(
                    f"Docker shutdown completed with {len(errors)} error(s)"
                ) from primary
            async with self._lock:
                if self._active or self._inflight or self._inflight_leases:
                    primary = RuntimeError(
                        "Docker shutdown could not prove empty ownership registries"
                    )
                    self._state = DockerBackendState.QUARANTINED
                    self._shutdown_error = primary
                    self._shutdown_complete = False
                    raise primary
                self._state = DockerBackendState.CLOSED
                self._shutdown_complete = True
                self._shutdown_error = None
        except asyncio.CancelledError:
            async with self._lock:
                self._state = DockerBackendState.QUARANTINED
                self._shutdown_error = asyncio.CancelledError()
                self._shutdown_complete = False
            raise

    async def _begin_inflight(self, execution_id: str) -> None:
        async with self._lock:
            self._require_open_locked()
            if execution_id in self._inflight_leases:
                raise RuntimeError(f"Docker execution is already in flight: {execution_id}")
            event = asyncio.Event()
            finalizer_task = asyncio.create_task(
                self._finalize_inflight(execution_id, event),
                name=f"khaos-docker-finalizer:{execution_id}",
            )
            lease = _InflightLease(execution_id, event, finalizer_task)
            self._inflight.add(execution_id)
            self._inflight_events[execution_id] = event
            self._inflight_leases[execution_id] = lease
            self._inflight_idle.clear()

    async def _end_inflight(self, execution_id: str) -> None:
        lease = self._mark_inflight_complete(execution_id)
        if lease is not None:
            await asyncio.shield(lease.finalizer_task)

    def _mark_inflight_complete(self, execution_id: str) -> _InflightLease | None:
        """Publish completion without an await or cancellation point."""
        lease = self._inflight_leases.get(execution_id)
        if lease is not None:
            lease.completion_event.set()
        return lease

    async def _finalize_inflight(
        self, execution_id: str, completion_event: asyncio.Event
    ) -> None:
        await completion_event.wait()
        async with self._lock:
            inflight = self._inflight_leases.get(execution_id)
        if inflight is None or inflight.completion_event is not completion_event:
            return
        try:
            container = inflight.container_lease
            if container is not None:
                cleaned = await asyncio.shield(self._cleanup_container(container))
                if not cleaned:
                    raise RuntimeError(
                        f"Docker container cleanup remained unproven: {container.name}"
                    )
                async with self._lock:
                    if self._active.get(execution_id) is container:
                        self._active.pop(execution_id, None)
                if inflight.diagnostics is not None:
                    inflight.diagnostics["cleanup"] = "removed"
        except BaseException as exc:
            if inflight.diagnostics is not None:
                inflight.diagnostics["cleanup"] = "unproven"
                inflight.diagnostics["cleanup_error"] = type(exc).__name__
            await self._enter_quarantine(exc)
            raise
        finally:
            for path in inflight.cleanup_paths:
                path.unlink(missing_ok=True)
            async with self._lock:
                current = self._inflight_leases.get(execution_id)
                if current is inflight:
                    self._inflight_leases.pop(execution_id, None)
                    self._inflight_events.pop(execution_id, None)
                    self._inflight.discard(execution_id)
                    if not self._inflight:
                        self._inflight_idle.set()

    async def _wait_for_execution_idle(self, execution_id: str) -> None:
        async with self._lock:
            lease = self._inflight_leases.get(execution_id)
        if lease is None:
            return
        try:
            await asyncio.wait_for(
                asyncio.shield(lease.finalizer_task),
                timeout=self.shutdown_timeout_seconds,
            )
        except TimeoutError:
            await self._enter_quarantine(
                TimeoutError(f"Docker execution finalizer did not settle: {execution_id}")
            )
            raise
        except asyncio.CancelledError as exc:
            await self._enter_quarantine(exc)
            raise
        except Exception:
            # The finalizer has already retained the external lease and
            # entered QUARANTINED.  A subsequent release attempt below is the
            # explicit recovery path; never manufacture an empty registry.
            logger.debug(
                "Docker execution finalizer retained lease: %s",
                execution_id,
                exc_info=True,
            )

    async def _release_retained_lease(self, execution_id: str) -> None:
        """Retry a lease left in quarantine after its finalizer failed."""
        async with self._lock:
            if execution_id in self._inflight_leases:
                return
            lease = self._active.get(execution_id)
        if lease is None:
            return
        if not await self._cleanup_container(lease):
            raise RuntimeError(
                f"Docker container cleanup remained unproven: {lease.name}"
            )
        async with self._lock:
            if self._active.get(execution_id) is lease:
                self._active.pop(execution_id, None)

    async def _enter_quarantine(self, error: BaseException) -> None:
        async with self._lock:
            if self._state is not DockerBackendState.CLOSED:
                self._state = DockerBackendState.QUARANTINED
                self._shutdown_started = True
                self._shutdown_complete = False
                self._shutdown_error = error

    def _require_open_locked(self) -> None:
        if self._state is not DockerBackendState.OPEN:
            raise DockerBackendClosedError(
                f"Docker backend is not open: {self._state.value}"
            )

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
        decision = context.sandbox_decision
        if not isinstance(decision, DockerSandboxDecision):
            raise PermissionError("Docker execution has no concrete command authority")
        if context.executable_identity != container_command_identity(
            decision.image_digest,
            context.argv,
            command_digest=decision.command_digest,
        ):
            raise PermissionError(
                "Docker command identity is not bound to the image digest and argv"
            )
        if _DENIED_ENV_KEYS & context.allowed_environment_keys:
            raise PermissionError("Docker environment allowlist contains sensitive keys")

    def _write_env_file(self, context: ResolvedExecutionContext) -> Path | None:
        values = {
            key: value for key, value in context.environment.items()
            if key in context.allowed_environment_keys
        }
        values = scrub_spawn_environment(values)
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

    async def _cleanup_container(self, lease: _ContainerLease) -> bool:
        async with lease.cleanup_lock:
            try:
                inspected = await self._run_cli(
                    (
                        "inspect",
                        "--format",
                        f'{{{{ index .Config.Labels "{_OWNER_LABEL}" }}}}',
                        lease.name,
                    ),
                    timeout=5,
                )
            except SupervisorClosedError:
                # The supervisor was closed by ExecutionService.shutdown()
                # while this cleanup was racing (e.g. from execute()'s
                # finally block).  The container will be cleaned up by
                # docker system prune or a future restart; we cannot run
                # docker CLI commands without the supervisor.
                logger.warning(
                    "docker container cleanup skipped (supervisor closed): "
                    "%s", lease.name,
                )
                return False
            if inspected[0] != 0:
                if _docker_object_absent(inspected):
                    return True
                raise RuntimeError(
                    f"Docker container inspection failed for {lease.name}"
                )
            if inspected[1].strip() != lease.owner_nonce:
                raise PermissionError(
                    "refusing to clean up a container not owned by this execution"
                )
            stop_command = ("stop", "--time", "2", lease.name)
            stop_result = await self._run_cli(stop_command, timeout=5)
            if stop_result[0] != 0 and not _docker_object_absent(stop_result):
                # ``docker stop`` already terminates the container.  Calling
                # ``docker kill`` unconditionally afterwards turns a
                # successful stop into a false cleanup failure because Docker
                # reports "container is not running" for the redundant kill.
                kill_command = ("kill", lease.name)
                kill_result = await self._run_cli(kill_command, timeout=5)
                if kill_result[0] != 0 and not _docker_object_absent(kill_result):
                    raise RuntimeError(
                        f"Docker cleanup command failed: {' '.join(kill_command)}"
                    )
            rm_command = ("rm", "-f", lease.name)
            rm_result = await self._run_cli(rm_command, timeout=5)
            if (
                rm_result[0] != 0
                and not _docker_object_absent(rm_result)
                and not _docker_removal_in_progress(rm_result)
            ):
                raise RuntimeError(
                    f"Docker cleanup command failed: {' '.join(rm_command)}"
                )
            for attempt in range(_CLEANUP_VERIFY_ATTEMPTS):
                verified = await self._run_cli(
                    ("inspect", lease.name), timeout=5
                )
                if _docker_object_absent(verified):
                    return True
                if verified[0] != 0:
                    raise RuntimeError(
                        "Docker container disappearance was not proven: "
                        f"{lease.name}"
                    )
                if attempt + 1 < _CLEANUP_VERIFY_ATTEMPTS:
                    await asyncio.sleep(_CLEANUP_VERIFY_INTERVAL_SECONDS)
            raise RuntimeError(
                f"Docker container cleanup could not be verified: {lease.name}"
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
                enforce_resource_limits=False,
                use_native_launcher=False,
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


def _docker_object_absent(result: tuple[int, str, str]) -> bool:
    """Recognize Docker's explicit missing-object response as terminal proof."""
    if result[0] == 0:
        return False
    message = f"{result[1]}\n{result[2]}".lower()
    return any(
        marker in message
        for marker in ("no such object", "not found", "no such container")
    )


def _docker_removal_in_progress(result: tuple[int, str, str]) -> bool:
    """Recognize Docker's asynchronous ``--rm`` deletion race."""
    if result[0] == 0:
        return False
    message = f"{result[1]}\n{result[2]}".lower()
    return "removal of container" in message and "already in progress" in message


def _canonical_digest(value: object) -> str:
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _workspace_mount_policy_digest(workspace: Path) -> str:
    from khaos.coding.workspace.policy import PROTECTED_WORKSPACE_NAMES

    return _canonical_digest(
        {
            "workspace": str(workspace.expanduser().absolute()),
            "writable": ["/workspace"],
            "readonly": [
                f"/workspace/{name}"
                for name in sorted(PROTECTED_WORKSPACE_NAMES)
            ],
        }
    )
