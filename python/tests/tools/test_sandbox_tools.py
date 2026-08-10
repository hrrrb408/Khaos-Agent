import asyncio
import inspect
import os
import shutil
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest

from khaos.coding.execution.capability import DockerSandboxDecision
from khaos.coding.execution.docker import (
    DEFAULT_DOCKER_IMAGE,
    DockerBackend,
    DockerBackendClosedError,
    _ContainerLease,
    _DOCKER_HARDENING_GENERATION,
    _canonical_digest,
    _workspace_mount_policy_digest,
)
from khaos.coding.execution.host import HostExecutionBackend
from khaos.coding.execution.identity import (
    container_command_identity,
    executable_identity,
)
from khaos.coding.execution.models import (
    ExecutionResult,
    NetworkPolicy,
    ResolvedExecutionContext,
    ResourceBudget,
)
from khaos.coding.execution.service import ExecutionService
from khaos.coding.workspace.models import WorkspaceState
from khaos.coding.workspace.boundary import PROTECTED_WORKSPACE_NAMES
from khaos.tools.registry import create_runtime_registry
from khaos.tools.sandbox_tools import sandbox_build, sandbox_exec


class _FakeDockerBackend:
    name = "docker"

    def __init__(self):
        self.contexts = []
        self.shutdown_called = False

    @property
    def terminal_closed(self):
        return True

    def owned_resources(self):
        return ()

    def terminal_postcondition(self):
        return self.terminal_closed and not self.owned_resources()

    async def execute_resolved(self, context):
        self.contexts.append(context)
        return ExecutionResult(
            context.correlation_id, "passed", 0, "ok\n", "", 1,
            {"container_id": "container-1", "cleanup": "removed"},
        )

    async def prepare_decision(
        self, *, image, workspace, budget, argv, filesystem_mode="workspace-write"
    ):
        image_digest = image.split("@sha256:", 1)[-1]
        command_digest = "fake-command-digest"
        binary_identity = "fake-docker-binary"
        daemon_identity = "fake-docker-daemon"
        return DockerSandboxDecision(
            backend_name="docker",
            capability_evidence_digest="fake-capability-evidence",
            filesystem_mode=filesystem_mode,
            network_mode=NetworkPolicy.NONE.value,
            kernel_enforced=True,
            platform=sys.platform,
            launcher_digest=binary_identity,
            docker_binary_identity=binary_identity,
            daemon_identity_digest=daemon_identity,
            image_reference=image,
            image_digest=image_digest,
            uid="65534:65534",
            capabilities=("ALL",),
            no_new_privileges=True,
            read_only_rootfs=True,
            workspace_mount_policy_digest="fake-mount-policy",
            budget_digest=budget.digest(),
            hardening_generation="fake-hardening",
            command_digest=command_digest,
        )

    async def terminate(self, execution_id):
        return None

    async def shutdown(self):
        self.shutdown_called = True


class _BlockingDockerBackend(_FakeDockerBackend):
    def __init__(self):
        super().__init__()
        self.started = asyncio.Event()
        self.released = asyncio.Event()
        self.terminated = []

    async def execute_resolved(self, context):
        self.contexts.append(context)
        self.started.set()
        await self.released.wait()
        return ExecutionResult(
            context.correlation_id, "failed", -1, "", "cancelled", 1,
            {"container_id": "container-blocking", "cleanup": "removed"},
        )

    async def terminate(self, execution_id):
        self.terminated.append(execution_id)
        self.released.set()

    async def shutdown(self):
        self.shutdown_called = True
        self.released.set()


def _install_protected_guards(worktree: Path) -> None:
    for name in PROTECTED_WORKSPACE_NAMES - {".git"}:
        (worktree / name).mkdir(exist_ok=True)


def _service(tmp_path, *, task_id="task", state=WorkspaceState.RUNNING, docker_backend=None):
    worktree = tmp_path / "worktree"
    worktree.mkdir(exist_ok=True)
    (worktree / ".git").write_text("gitdir: ../repo/.git/worktrees/task\n", encoding="utf-8")
    _install_protected_guards(worktree)
    repository = tmp_path / "repo"
    repository.mkdir(exist_ok=True)
    workspace = SimpleNamespace(
        task_id=task_id,
        worktree_path=worktree,
        repository_root=repository,
        state=state,
    )
    manager = SimpleNamespace(
        get=lambda workspace_id: workspace if workspace_id == "workspace" else None,
        require=lambda workspace_id, **_authority: (
            workspace if workspace_id == "workspace" else None
        ),
        verify_git_identity=AsyncMock(),
        verify_execution_root=AsyncMock(),
    )
    backend = docker_backend or _FakeDockerBackend()
    return ExecutionService(HostExecutionBackend(), manager, backend), workspace, backend


async def test_sandbox_exec_routes_through_execution_service_and_docker_backend(tmp_path):
    service, workspace, backend = _service(tmp_path)

    result = await sandbox_exec(
        "python -V", project_dir=str(workspace.worktree_path), timeout=5,
        execution_service=service, task_id="task", workspace_id="workspace",
    )

    assert result == {
        "container_id": "container-1", "command": "python -V", "network": False,
        "returncode": 0, "stdout": "ok\n", "stderr": "", "backend": "docker",
        "workspace_id": "workspace", "cleanup": "removed",
        "raw_returncode": 0, "status": "passed", "timed_out": False,
    }
    context = backend.contexts[0]
    assert context.task_id == "task"
    assert context.workspace_id == "workspace"
    assert context.repository_root == workspace.repository_root.resolve()
    assert context.worktree_path == workspace.worktree_path.resolve()
    assert context.cwd == workspace.worktree_path.resolve()
    assert context.writable_roots == (workspace.worktree_path.resolve(),)
    assert context.access_mode == "workspace-write"
    assert context.network_policy is NetworkPolicy.NONE
    assert context.argv == ("python", "-V")


@pytest.mark.parametrize(
    "violation",
    ["missing", "cross-task", "cancelled", "failed", "cleaned", "main-repository", "not-worktree", "other-directory"],
)
async def test_sandbox_exec_rejects_invalid_workspace_and_mounts(tmp_path, violation):
    state = WorkspaceState.RUNNING
    if violation in {"cancelled", "failed", "cleaned"}:
        state = WorkspaceState(violation)
    service, workspace, _ = _service(tmp_path, state=state)
    task_id = "task"
    workspace_id = "workspace"
    project_dir = "."
    if violation == "missing":
        workspace_id = "missing"
    elif violation == "cross-task":
        task_id = "other"
    elif violation == "main-repository":
        workspace.worktree_path = workspace.repository_root
        (workspace.repository_root / ".git").write_text("gitdir", encoding="utf-8")
    elif violation == "not-worktree":
        (workspace.worktree_path / ".git").unlink()
    elif violation == "other-directory":
        project_dir = str(tmp_path)
    with pytest.raises(PermissionError):
        await sandbox_exec(
            "true", project_dir=project_dir, execution_service=service,
            task_id=task_id, workspace_id=workspace_id,
        )


async def test_sandbox_exec_rejects_network_image_client_and_resource_injection(tmp_path):
    service, _, _ = _service(tmp_path)
    base = {"execution_service": service, "task_id": "task", "workspace_id": "workspace"}
    with pytest.raises(PermissionError, match="network access"):
        await sandbox_exec("true", network=True, **base)
    with pytest.raises(PermissionError, match="direct Docker clients"):
        await sandbox_exec("true", client=object(), **base)
    with pytest.raises(ValueError, match="cpus"):
        await sandbox_exec("true", cpus=99, **base)
    with pytest.raises(ValueError, match="memory"):
        await sandbox_exec("true", memory="1m", **base)
    with pytest.raises(ValueError, match="empty"):
        await sandbox_exec("", **base)


async def test_sandbox_build_is_internal_fail_closed(tmp_path):
    result = await sandbox_build(str(tmp_path / "Dockerfile"), context=str(tmp_path))
    assert result["returncode"] == -1
    assert "internal maintenance" in result["stderr"]


def test_sandbox_registry_capabilities_and_static_process_audit():
    registry = create_runtime_registry()
    sandbox = registry.get("sandbox_exec")
    assert sandbox.modes == ("coding",)
    assert {capability.name for capability in sandbox.capabilities} == {
        "process.execute", "filesystem.write",
    }
    assert all(capability.scopes == frozenset({"task-workspace"}) for capability in sandbox.capabilities)
    build = registry.get("sandbox_build")
    assert build.modes == ("internal",)
    assert {capability.name for capability in build.capabilities} == {"host.integration"}
    import khaos.tools.sandbox_tools as module
    source = inspect.getsource(module)
    for forbidden in ("create_subprocess_exec", "create_subprocess_shell", "subprocess.run", "subprocess.Popen", "os.system", "shell=True"):
        assert forbidden not in source


class _FakeProcess:
    def __init__(self, stdout=b"ok\n", stderr=b"", returncode=0, delay=0):
        self._stdout = stdout
        self._stderr = stderr
        self.returncode = returncode
        self.delay = delay
        self.killed = False
        self.pid = None
        self.stdout = asyncio.StreamReader()
        self.stdout.feed_data(stdout)
        self.stdout.feed_eof()
        self.stderr = asyncio.StreamReader()
        self.stderr.feed_data(stderr)
        self.stderr.feed_eof()

    async def communicate(self):
        if self.delay:
            await asyncio.sleep(self.delay)
        return self._stdout, self._stderr

    def kill(self):
        self.killed = True
        self.returncode = -9

    def terminate(self):
        self.returncode = -15

    async def wait(self):
        if self.delay:
            await asyncio.sleep(self.delay)
        return self.returncode


class _InspectableDockerBackend(DockerBackend):
    def __init__(self, *, shutdown_timeout_seconds=15.0):
        super().__init__(
            allowed_images={DEFAULT_DOCKER_IMAGE},
            # The fake CLI observations below do not need a Docker daemon,
            # but DockerBackend still asks ProcessSupervisor to open the host
            # command through its native executable authority.  GitHub's
            # macOS runners do not ship the Docker CLI, so use the current
            # Python executable as a portable authority for this test double.
            # The fixed Docker argv remains fully asserted by the tests.
            docker_binary=sys.executable,
            shutdown_timeout_seconds=shutdown_timeout_seconds,
        )
        self.cli_calls = []
        self.removed = set()
        self.foreign_owner = False

    async def _run_cli(self, args, *, timeout):
        self.cli_calls.append(args)
        if args[:2] == ("image", "inspect"):
            return 0, "image", ""
        if args[:2] == ("inspect", "--format"):
            name = args[-1]
            if name in self.removed:
                return 1, "", "not found"
            for lease in self._active.values():
                if lease.name == name:
                    return 0, (
                        "foreign" if self.foreign_owner else lease.owner_nonce
                    ), ""
            return 1, "", "not found"
        if args[:1] == ("rm",):
            self.removed.add(args[-1])
            return 0, "", ""
        if args[:1] == ("inspect",):
            return 1, "", "not found"
        return 0, "", ""


def _resolved(
    tmp_path,
    *,
    image=DEFAULT_DOCKER_IMAGE,
    budget=None,
    environment=None,
    argv=("python", "-V"),
    execution_id="exec-1",
    docker_binary="docker",
):
    worktree = tmp_path / "worktree"
    worktree.mkdir(exist_ok=True)
    (worktree / ".git").write_text("gitdir: ../repo/.git/worktrees/task\n", encoding="utf-8")
    _install_protected_guards(worktree)
    repository = tmp_path / "repo"
    repository.mkdir(exist_ok=True)
    env = {"KHAOS_DOCKER_IMAGE": image, **(environment or {})}
    budget_value = budget or ResourceBudget()
    image_digest = image.split("@sha256:", 1)[-1]
    docker_env = {"PATH": os.environ.get("PATH", os.defpath)}
    binary_identity = executable_identity((docker_binary,), docker_env)
    daemon_identity = _canonical_digest({"stdout": "", "stderr": ""})
    command_digest = _canonical_digest(argv)
    decision = DockerSandboxDecision(
        backend_name="docker",
        capability_evidence_digest=_canonical_digest(
            {"binary": binary_identity, "daemon": daemon_identity}
        ),
        filesystem_mode="workspace-write",
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
        workspace_mount_policy_digest=_workspace_mount_policy_digest(worktree),
        budget_digest=budget_value.digest(),
        hardening_generation=_DOCKER_HARDENING_GENERATION,
        command_digest=command_digest,
    )
    return ResolvedExecutionContext(
        "task", "workspace", "running", repository, worktree, worktree, (worktree,),
        "workspace-write", NetworkPolicy.NONE, budget_value, env,
        frozenset(env), argv, execution_id,
        executable_identity=container_command_identity(
            image_digest, argv, command_digest=command_digest
        ),
        sandbox_decision=decision,
    )


async def test_docker_backend_builds_hardened_fixed_argv(tmp_path):
    backend = _InspectableDockerBackend()
    process = _FakeProcess()
    with patch("khaos.coding.execution.docker.asyncio.create_subprocess_exec", new=AsyncMock(return_value=process)) as spawn:
        result = await backend.execute_resolved(
            _resolved(tmp_path, docker_binary=backend.docker_binary)
        )
    launch_argv = spawn.await_args.args
    assert "--exec-fd" in launch_argv
    argv = launch_argv[launch_argv.index("--") + 1:]
    assert argv[:2] == (backend.docker_binary, "run")
    assert "--read-only" in argv
    assert "--tmpfs" in argv and any(str(item).startswith("/tmp:rw,noexec,nosuid,nodev") for item in argv)
    assert argv[argv.index("--user") + 1] == "65534:65534"
    assert argv[argv.index("--cap-drop") + 1] == "ALL"
    assert argv[argv.index("--security-opt") + 1] == "no-new-privileges"
    assert argv[argv.index("--network") + 1] == "none"
    assert argv[argv.index("--pull") + 1] == "never"
    assert "--init" in argv
    assert "--sig-proxy=false" in argv
    assert argv[argv.index("--ipc") + 1] == "none"
    assert argv[argv.index("--pids-limit") + 1] == "256"
    assert argv[argv.index("--cpus") + 1] == "1.0"
    assert argv[argv.index("--memory") + 1] == str(512 * 1024 * 1024)
    ulimits = [
        argv[index + 1]
        for index, value in enumerate(argv[:-1])
        if value == "--ulimit"
    ]
    assert "fsize=67108864:67108864" in ulimits
    assert "nofile=256:256" in ulimits
    mounts = [
        argv[index + 1]
        for index, value in enumerate(argv[:-1])
        if value == "--mount"
    ]
    assert mounts == [
        f"type=bind,src={tmp_path / 'worktree'},dst=/workspace",
        *[
            (
                f"type=bind,src={tmp_path / 'worktree' / name},"
                f"dst=/workspace/{name},readonly"
            )
            for name in sorted(PROTECTED_WORKSPACE_NAMES)
        ],
    ]
    assert str(tmp_path / "repo") not in " ".join(argv)
    assert "/var/run/docker.sock" not in " ".join(argv)
    assert argv[-3:] == ("--", "python", "-V")
    assert result.diagnostics["cleanup"] == "removed"


async def test_docker_backend_prepares_concrete_daemon_and_hardening_decision(tmp_path):
    backend = _InspectableDockerBackend()
    decision = await backend.prepare_decision(
        image=DEFAULT_DOCKER_IMAGE,
        workspace=(tmp_path / "worktree"),
        budget=ResourceBudget(),
        argv=("python", "-V"),
    )

    assert decision.backend_name == "docker"
    assert decision.image_reference == DEFAULT_DOCKER_IMAGE
    assert decision.image_digest == DEFAULT_DOCKER_IMAGE.split("@sha256:", 1)[1]
    assert decision.network_mode == "none"
    assert decision.uid == "65534:65534"
    assert decision.capabilities == ("ALL",)
    assert decision.no_new_privileges is True
    assert decision.read_only_rootfs is True
    assert decision.budget_digest == ResourceBudget().digest()
    assert decision.command_digest


async def test_docker_deleted_open_file_watchdog_maps_to_resource_violation(tmp_path):
    backend = _InspectableDockerBackend()
    process = _FakeProcess(returncode=173)
    with patch(
        "khaos.coding.execution.docker.asyncio.create_subprocess_exec",
        new=AsyncMock(return_value=process),
    ):
        result = await backend.execute_resolved(
            _resolved(tmp_path, docker_binary=backend.docker_binary)
        )

    assert result.status == "resource-exhausted"
    assert result.diagnostics["resource_violation"]["kind"] == "workspace-bytes"


async def test_docker_backend_rejects_unavailable_or_unapproved_image_without_pull(tmp_path):
    backend = _InspectableDockerBackend()
    with pytest.raises(PermissionError, match="allowlist"):
        await backend.execute_resolved(
            _resolved(
                tmp_path,
                image="evil/latest",
                docker_binary=backend.docker_binary,
            )
        )
    missing = "example.invalid/khaos@sha256:" + "1" * 64
    backend.allowed_images = frozenset({missing})

    async def missing_cli(args, *, timeout):
        backend.cli_calls.append(args)
        return 1, "", "missing"

    backend._run_cli = missing_cli
    with pytest.raises(PermissionError, match="automatic pull"):
        await backend.execute_resolved(
            _resolved(tmp_path, image=missing, docker_binary=backend.docker_binary)
        )
    assert not any(call[:1] == ("pull",) for call in backend.cli_calls)


def test_docker_backend_requires_digest_pinned_allowlist():
    with pytest.raises(ValueError, match="digest"):
        DockerBackend(allowed_images={"python:3.13-slim"})


async def test_docker_cleanup_refuses_foreign_container_name_collision(tmp_path):
    backend = _InspectableDockerBackend()
    backend.foreign_owner = True
    process = _FakeProcess(stderr=b"name already in use", returncode=125)

    with patch(
        "khaos.coding.execution.docker.asyncio.create_subprocess_exec",
        new=AsyncMock(return_value=process),
    ):
        with pytest.raises(PermissionError, match="not owned"):
            await backend.execute_resolved(
                _resolved(tmp_path, docker_binary=backend.docker_binary)
            )

    destructive = {"stop", "kill", "rm"}
    assert not any(call[0] in destructive for call in backend.cli_calls)
    # The foreign collision is deliberately retained as an owned lease;
    # silently dropping it would manufacture a false cleanup proof.
    assert backend._active


async def test_docker_backend_rejects_mount_option_injection_path(tmp_path):
    backend = _InspectableDockerBackend()
    context = _resolved(tmp_path, docker_binary=backend.docker_binary)
    unsafe = tmp_path / "worktree,dst=host"
    context.worktree_path.rename(unsafe)
    context = ResolvedExecutionContext(
        **{
            **context.__dict__,
            "worktree_path": unsafe,
            "cwd": unsafe,
            "writable_roots": (unsafe,),
            "permission_profile": context.permission_profile.bind_workspace(
                unsafe
            ),
        }
    )

    with pytest.raises(PermissionError, match="mount syntax"):
        await backend.execute_resolved(context)


@pytest.mark.parametrize("violation", ["network", "writable-root", "sensitive-env", "main-repository"])
async def test_docker_backend_rejects_untrusted_resolved_context(tmp_path, violation):
    backend = _InspectableDockerBackend()
    context = _resolved(tmp_path, docker_binary=backend.docker_binary)
    if violation == "network":
        context = ResolvedExecutionContext(
            **{**context.__dict__, "network_policy": NetworkPolicy.UNRESTRICTED_WITH_APPROVAL}
        )
    elif violation == "writable-root":
        context = ResolvedExecutionContext(
            **{**context.__dict__, "writable_roots": (tmp_path,)}
        )
    elif violation == "sensitive-env":
        context = ResolvedExecutionContext(
            **{
                **context.__dict__,
                "environment": {**context.environment, "GH_TOKEN": "secret"},
                "allowed_environment_keys": frozenset({*context.allowed_environment_keys, "GH_TOKEN"}),
            }
        )
    else:
        context = ResolvedExecutionContext(
            **{**context.__dict__, "repository_root": context.worktree_path}
        )
    with pytest.raises(PermissionError):
        await backend.execute_resolved(context)


async def test_docker_backend_timeout_cleanup_output_truncation_and_shutdown(tmp_path):
    backend = _InspectableDockerBackend()
    budget = ResourceBudget(timeout_seconds=0.01, output_bytes=4)
    process = _FakeProcess(stdout=b"0123456789", returncode=None, delay=0.05)
    with patch("khaos.coding.execution.docker.asyncio.create_subprocess_exec", new=AsyncMock(return_value=process)):
        result = await backend.execute_resolved(
            _resolved(
                tmp_path,
                budget=budget,
                docker_binary=backend.docker_binary,
            )
        )
    assert result.status == "timed-out"
    assert process.returncode in {-15, -9}
    assert result.diagnostics["process_group_terminated"] is True
    assert any(call[:1] == ("rm",) for call in backend.cli_calls)
    assert result.diagnostics["cleanup"] == "removed"

    backend._active["active"] = _ContainerLease("khaos-active", "owner")
    await backend.shutdown()
    assert any(call[-1:] == ("khaos-active",) for call in backend.cli_calls)


async def test_docker_backend_closes_admission_before_shutdown_cleanup():
    backend = _InspectableDockerBackend()
    await backend.shutdown()

    assert backend.state == "CLOSED"
    assert backend.admission_closed
    assert backend.terminal_closed
    with pytest.raises(DockerBackendClosedError, match="CLOSED"):
        await backend._begin_inflight("after-close")


async def test_docker_backend_concurrent_shutdown_joins_shared_task():
    backend = _InspectableDockerBackend()
    started = asyncio.Event()
    release = asyncio.Event()
    original_shutdown_impl = backend._shutdown_impl

    async def delayed_shutdown_impl():
        started.set()
        await release.wait()
        await original_shutdown_impl()

    backend._shutdown_impl = delayed_shutdown_impl
    first = asyncio.create_task(backend.shutdown())
    await started.wait()
    shared_task = backend._shutdown_task
    second = asyncio.create_task(backend.shutdown())
    await asyncio.sleep(0)

    assert backend.state == "CLOSING"
    assert backend._shutdown_task is shared_task
    release.set()
    await asyncio.gather(first, second)
    assert backend.terminal_closed


async def test_docker_backend_shutdown_spawn_barrier_keeps_late_child_owned(tmp_path):
    """Shutdown must wait for a Docker CLI spawn reserved after lease publish."""
    backend = _InspectableDockerBackend()
    spawn_entered = asyncio.Event()
    release_spawn = asyncio.Event()
    process = _FakeProcess()

    async def delayed_spawn(*_args, **_kwargs):
        spawn_entered.set()
        await release_spawn.wait()
        return process

    context = _resolved(tmp_path, docker_binary=backend.docker_binary)
    with patch(
        "khaos.coding.execution.docker.asyncio.create_subprocess_exec",
        new=delayed_spawn,
    ):
        running = asyncio.create_task(backend.execute_resolved(context))
        await spawn_entered.wait()
        assert backend._active
        shutdown = asyncio.create_task(backend.shutdown())
        await asyncio.sleep(0)
        assert backend.state == "CLOSING"
        assert not backend.terminal_closed
        assert any(
            resource.startswith("container:exec-1:")
            for resource in backend.owned_resources()
        )
        release_spawn.set()
        result, _ = await asyncio.gather(running, shutdown)

    assert result.status in {"passed", "cancelled"}
    assert backend.terminal_closed
    assert backend.owned_resources() == ()
    assert "khaos-exec-1" in backend.removed


async def test_docker_backend_shutdown_timeout_quarantines_and_retry_closes():
    backend = _InspectableDockerBackend(shutdown_timeout_seconds=0.01)
    await backend._begin_inflight("slow-finalizer")

    with pytest.raises(RuntimeError, match="shutdown completed"):
        await backend.shutdown()

    assert backend.is_quarantined
    assert not backend.terminal_closed
    assert backend.owned_resources() == ("execution-finalizer:slow-finalizer",)

    backend._mark_inflight_complete("slow-finalizer")
    await backend.shutdown()
    assert backend.state == "CLOSED"
    assert backend.terminal_closed
    assert backend.owned_resources() == ()


async def test_docker_backend_finalizer_survives_double_cancellation():
    backend = _InspectableDockerBackend()
    await backend._begin_inflight("double-cancel")
    lease = backend._inflight_leases["double-cancel"]
    await backend._lock.acquire()
    waiter = asyncio.create_task(backend._end_inflight("double-cancel"))
    try:
        await asyncio.sleep(0)
        waiter.cancel()
        waiter.cancel()
        with pytest.raises(asyncio.CancelledError):
            await waiter
    finally:
        backend._lock.release()

    await asyncio.wait_for(lease.finalizer_task, timeout=1)
    assert backend._inflight == set()
    assert backend._inflight_leases == {}
    await backend.shutdown()


async def test_docker_backend_truncates_output_without_unbounded_artifact(tmp_path):
    backend = _InspectableDockerBackend()
    process = _FakeProcess(stdout=b"0123456789", stderr=b"abcdefghij")
    with patch("khaos.coding.execution.docker.asyncio.create_subprocess_exec", new=AsyncMock(return_value=process)):
        result = await backend.execute_resolved(
            _resolved(
                tmp_path,
                budget=ResourceBudget(output_bytes=8),
                docker_binary=backend.docker_binary,
            )
        )
    assert len(result.stdout.encode()) + len(result.stderr.encode()) <= 8
    assert result.diagnostics["output_truncated"] is True
    assert result.diagnostics["stdout_bytes_dropped"] == 6
    assert result.diagnostics["stderr_bytes_dropped"] == 6
    assert "output_artifact" not in result.diagnostics
    await backend.shutdown()


async def test_execution_service_shutdown_closes_docker_backend(tmp_path):
    service, _, backend = _service(tmp_path)
    await service.shutdown()
    assert backend.shutdown_called is True


@pytest.mark.parametrize("action", ["cancel", "shutdown"])
async def test_runtime_cancel_and_shutdown_release_active_docker_execution(tmp_path, action):
    backend = _BlockingDockerBackend()
    service, _, _ = _service(tmp_path, docker_backend=backend)
    running = asyncio.create_task(sandbox_exec(
        "python -V", execution_service=service,
        task_id="task", workspace_id="workspace",
    ))
    await backend.started.wait()
    execution_id = next(iter(service._active))
    if action == "cancel":
        await service.terminate(execution_id)
    else:
        await service.shutdown()
    result = await running
    assert result["cleanup"] == "removed"
    assert not service._active
    if action == "cancel":
        assert backend.terminated == [execution_id]
    else:
        assert backend.shutdown_called is True


def _docker_available():
    if shutil.which("docker") is None:
        return False
    return subprocess.run(
        ["docker", "info"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False
    ).returncode == 0


async def _bind_real_docker_decision(
    backend: DockerBackend,
    context: ResolvedExecutionContext,
) -> ResolvedExecutionContext:
    """Bind a real Docker context to the backend's current observations."""
    decision = await backend.prepare_decision(
        image=context.environment["KHAOS_DOCKER_IMAGE"],
        workspace=context.worktree_path,
        budget=context.budget,
        argv=context.argv,
        filesystem_mode=context.access_mode,
    )
    return ResolvedExecutionContext(
        **{**context.__dict__, "sandbox_decision": decision}
    )


@pytest.mark.docker_lifecycle_soak
@pytest.mark.docker_sandbox_real
@pytest.mark.skipif(
    os.environ.get("KHAOS_RUN_DOCKER_LIFECYCLE_SOAK") != "1",
    reason="Docker lifecycle soak is enabled only by the nightly workflow",
)
@pytest.mark.skipif(not _docker_available(), reason="Docker daemon unavailable")
async def test_real_docker_lifecycle_soak(tmp_path):
    """Repeatedly prove container cleanup without an ownership-ledger leak."""
    iterations = int(os.environ.get("KHAOS_DOCKER_SOAK_ITERATIONS", "100"))
    if not 100 <= iterations <= 500:
        raise AssertionError("KHAOS_DOCKER_SOAK_ITERATIONS must be between 100 and 500")
    backend = DockerBackend(allowed_images={DEFAULT_DOCKER_IMAGE})
    for index in range(iterations):
        context = await _bind_real_docker_decision(
            backend,
            _resolved(tmp_path, execution_id=f"soak-{index:03d}"),
        )
        result = await backend.execute_resolved(context)
        assert result.status == "passed", result.diagnostics
        assert result.diagnostics["cleanup"] == "removed"
        assert backend.owned_resources() == ()
    await backend.shutdown()
    assert backend.terminal_closed


@pytest.mark.skipif(not _docker_available(), reason="Docker daemon unavailable")
@pytest.mark.docker_sandbox_real
async def test_real_docker_workspace_isolation_e2e(tmp_path):
    repository = tmp_path / "repo"
    worktree = tmp_path / "worktree"
    repository.mkdir()
    subprocess.run(["git", "init", "-b", "main"], cwd=repository, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=repository, check=True)
    subprocess.run(["git", "config", "user.name", "Tester"], cwd=repository, check=True)
    (repository / "base.txt").write_text("base\n", encoding="utf-8")
    subprocess.run(["git", "add", "base.txt"], cwd=repository, check=True)
    subprocess.run(["git", "commit", "-m", "base"], cwd=repository, check=True, capture_output=True)
    subprocess.run(
        ["git", "worktree", "add", "-b", "task/docker", str(worktree), "HEAD"],
        cwd=repository, check=True, capture_output=True,
    )
    _install_protected_guards(worktree)
    worktree.chmod(0o777)
    workspace = SimpleNamespace(
        task_id="task", worktree_path=worktree, repository_root=repository,
        state=WorkspaceState.RUNNING,
    )
    manager = SimpleNamespace(
        get=lambda workspace_id: workspace if workspace_id == "workspace" else None,
        require=lambda workspace_id, **_authority: (
            workspace if workspace_id == "workspace" else None
        ),
        verify_git_identity=AsyncMock(),
        verify_execution_root=AsyncMock(),
    )
    service = ExecutionService(
        HostExecutionBackend(), manager,
        DockerBackend(allowed_images={DEFAULT_DOCKER_IMAGE}),
    )
    script = (
        "import os,pathlib,socket;"
        "assert os.getuid()!=0;"
        "pathlib.Path('/workspace/container.txt').write_text('ok');"
        "assert not pathlib.Path('/host-main').exists();"
        "\ntry:\n pathlib.Path('/rootfs-probe').write_text('x'); raise AssertionError('rootfs writable')"
        "\nexcept OSError: pass"
        "\ns=socket.socket(); s.settimeout(.2)"
        "\ntry:\n s.connect(('1.1.1.1',53)); raise AssertionError('network reachable')"
        "\nexcept OSError: pass"
        "\nprint('isolated')"
    )
    result = await sandbox_exec(
        f'python -c "{script}"', execution_service=service,
        task_id="task", workspace_id="workspace", timeout=10,
    )
    assert result["returncode"] == 0, result["stderr"]
    assert result["stdout"].strip() == "isolated"
    assert (worktree / "container.txt").read_text(encoding="utf-8") == "ok"
    assert not (repository / "container.txt").exists()
    await service.shutdown()


@pytest.mark.skipif(not _docker_available(), reason="Docker daemon unavailable")
@pytest.mark.docker_sandbox_real
async def test_real_docker_deleted_open_file_budget_is_enforced(tmp_path):
    command = (
        "import os,time; "
        "fd=os.open('/workspace/deleted.bin', os.O_CREAT|os.O_RDWR, 0o600); "
        "os.unlink('/workspace/deleted.bin'); os.write(fd, b'x'*16384); "
        "os.fsync(fd); time.sleep(30)"
    )
    context = _resolved(
        tmp_path,
        budget=ResourceBudget(
            workspace_bytes=4096,
            file_bytes=1024 * 1024,
            timeout_seconds=10,
        ),
        argv=("python", "-c", command),
    )
    context.worktree_path.chmod(0o777)
    backend = DockerBackend(allowed_images={DEFAULT_DOCKER_IMAGE})
    decision = await backend.prepare_decision(
        image=DEFAULT_DOCKER_IMAGE,
        workspace=context.worktree_path,
        budget=context.budget,
        argv=context.argv,
    )
    context = ResolvedExecutionContext(
        **{**context.__dict__, "sandbox_decision": decision}
    )

    result = await backend.execute_resolved(context)

    assert result.status == "resource-exhausted"
    assert result.diagnostics["resource_violation"]["kind"] == "workspace-bytes"


@pytest.mark.skipif(not _docker_available(), reason="Docker daemon unavailable")
@pytest.mark.docker_sandbox_real
@pytest.mark.parametrize("action", ["timeout", "cancel", "shutdown"])
async def test_real_docker_lifecycle_cleanup_e2e(tmp_path, action):
    repository = tmp_path / "repo"
    worktree = tmp_path / "worktree"
    repository.mkdir()
    subprocess.run(["git", "init", "-b", "main"], cwd=repository, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=repository, check=True)
    subprocess.run(["git", "config", "user.name", "Tester"], cwd=repository, check=True)
    (repository / "base.txt").write_text("base\n", encoding="utf-8")
    subprocess.run(["git", "add", "base.txt"], cwd=repository, check=True)
    subprocess.run(["git", "commit", "-m", "base"], cwd=repository, check=True, capture_output=True)
    subprocess.run(
        ["git", "worktree", "add", "-b", f"task/{action}", str(worktree), "HEAD"],
        cwd=repository, check=True, capture_output=True,
    )
    _install_protected_guards(worktree)
    worktree.chmod(0o777)
    workspace = SimpleNamespace(
        task_id="task", worktree_path=worktree, repository_root=repository,
        state=WorkspaceState.RUNNING,
    )
    manager = SimpleNamespace(
        get=lambda workspace_id: workspace if workspace_id == "workspace" else None,
        require=lambda workspace_id, **_authority: (
            workspace if workspace_id == "workspace" else None
        ),
        verify_git_identity=AsyncMock(),
        verify_execution_root=AsyncMock(),
    )
    backend = DockerBackend(allowed_images={DEFAULT_DOCKER_IMAGE})
    service = ExecutionService(HostExecutionBackend(), manager, backend)
    running = asyncio.create_task(sandbox_exec(
        'python -c "import time; time.sleep(30)"',
        execution_service=service, task_id="task", workspace_id="workspace",
        timeout=1 if action == "timeout" else 30,
    ))
    if action != "timeout":
        for _ in range(100):
            if backend._active:
                break
            await asyncio.sleep(0.05)
        assert backend._active
        execution_id = next(iter(backend._active))
        container_name = backend._active[execution_id].name
        if action == "cancel":
            await service.terminate(execution_id)
        else:
            await service.shutdown()
        await running
        inspected = subprocess.run(
            ["docker", "inspect", container_name], capture_output=True, check=False
        )
        assert inspected.returncode != 0
    else:
        result = await running
        assert result["returncode"] == -1
        assert result["timed_out"] is True
        assert result["status"] == "timed-out"
        assert result["cleanup"] == "removed"
        container_name = result["container_id"]
        inspected = subprocess.run(
            ["docker", "inspect", container_name], capture_output=True, check=False
        )
        assert inspected.returncode != 0
    # Do not inspect every ``khaos-*`` container: push and pull_request
    # workflows can legitimately share one runner/daemon concurrently.  The
    # per-execution container was checked above, and the backend registry is
    # the authoritative ownership scope for this test.
    assert backend._active == {}
    await service.shutdown()
    assert backend.terminal_closed
    assert backend.owned_resources() == ()
