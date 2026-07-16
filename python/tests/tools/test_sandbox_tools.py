import asyncio
import inspect
import shutil
import subprocess
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest

from khaos.coding.execution.docker import (
    DEFAULT_DOCKER_IMAGE,
    DockerBackend,
    _ContainerLease,
)
from khaos.coding.execution.host import HostExecutionBackend
from khaos.coding.execution.models import (
    ExecutionResult,
    NetworkPolicy,
    ResolvedExecutionContext,
    ResourceBudget,
)
from khaos.coding.execution.service import ExecutionService
from khaos.coding.workspace.models import WorkspaceState
from khaos.tools.registry import create_runtime_registry
from khaos.tools.sandbox_tools import sandbox_build, sandbox_exec


class _FakeDockerBackend:
    name = "docker"

    def __init__(self):
        self.contexts = []
        self.shutdown_called = False

    async def execute_resolved(self, context):
        self.contexts.append(context)
        return ExecutionResult(
            context.correlation_id, "passed", 0, "ok\n", "", 1,
            {"container_id": "container-1", "cleanup": "removed"},
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


def _service(tmp_path, *, task_id="task", state=WorkspaceState.RUNNING, docker_backend=None):
    worktree = tmp_path / "worktree"
    worktree.mkdir(exist_ok=True)
    (worktree / ".git").write_text("gitdir: ../repo/.git/worktrees/task\n", encoding="utf-8")
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
        verify_git_identity=AsyncMock(),
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
    assert sandbox.modes == ["coding"]
    assert {capability.name for capability in sandbox.capabilities} == {
        "process.execute", "filesystem.write",
    }
    assert all(capability.scopes == frozenset({"task-workspace"}) for capability in sandbox.capabilities)
    build = registry.get("sandbox_build")
    assert build.modes == ["internal"]
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
    def __init__(self):
        super().__init__(allowed_images={DEFAULT_DOCKER_IMAGE})
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


def _resolved(tmp_path, *, image=DEFAULT_DOCKER_IMAGE, budget=None, environment=None):
    worktree = tmp_path / "worktree"
    worktree.mkdir(exist_ok=True)
    (worktree / ".git").write_text("gitdir: ../repo/.git/worktrees/task\n", encoding="utf-8")
    repository = tmp_path / "repo"
    repository.mkdir(exist_ok=True)
    env = {"KHAOS_DOCKER_IMAGE": image, **(environment or {})}
    return ResolvedExecutionContext(
        "task", "workspace", "running", repository, worktree, worktree, (worktree,),
        "workspace-write", NetworkPolicy.NONE, budget or ResourceBudget(), env,
        frozenset(env), ("python", "-V"), "exec-1",
    )


async def test_docker_backend_builds_hardened_fixed_argv(tmp_path):
    backend = _InspectableDockerBackend()
    process = _FakeProcess()
    with patch("khaos.coding.execution.docker.asyncio.create_subprocess_exec", new=AsyncMock(return_value=process)) as spawn:
        result = await backend.execute_resolved(_resolved(tmp_path))
    argv = spawn.await_args.args
    assert argv[:2] == ("docker", "run")
    assert "--read-only" in argv
    assert "--tmpfs" in argv and any(str(item).startswith("/tmp:rw,noexec,nosuid,nodev") for item in argv)
    assert argv[argv.index("--user") + 1] == "65534:65534"
    assert argv[argv.index("--cap-drop") + 1] == "ALL"
    assert argv[argv.index("--security-opt") + 1] == "no-new-privileges"
    assert argv[argv.index("--network") + 1] == "none"
    assert argv[argv.index("--pull") + 1] == "never"
    assert "--init" in argv
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
        (
            f"type=bind,src={tmp_path / 'worktree' / '.git'},"
            "dst=/workspace/.git,readonly"
        ),
    ]
    assert str(tmp_path / "repo") not in " ".join(argv)
    assert "/var/run/docker.sock" not in " ".join(argv)
    assert argv[-3:] == ("--", "python", "-V")
    assert result.diagnostics["cleanup"] == "removed"


async def test_docker_deleted_open_file_watchdog_maps_to_resource_violation(tmp_path):
    backend = _InspectableDockerBackend()
    process = _FakeProcess(returncode=173)
    with patch(
        "khaos.coding.execution.docker.asyncio.create_subprocess_exec",
        new=AsyncMock(return_value=process),
    ):
        result = await backend.execute_resolved(_resolved(tmp_path))

    assert result.status == "resource-exhausted"
    assert result.diagnostics["resource_violation"]["kind"] == "workspace-bytes"


async def test_docker_backend_rejects_unavailable_or_unapproved_image_without_pull(tmp_path):
    backend = _InspectableDockerBackend()
    with pytest.raises(PermissionError, match="allowlist"):
        await backend.execute_resolved(_resolved(tmp_path, image="evil/latest"))
    missing = "example.invalid/khaos@sha256:" + "1" * 64
    backend.allowed_images = frozenset({missing})

    async def missing_cli(args, *, timeout):
        backend.cli_calls.append(args)
        return 1, "", "missing"

    backend._run_cli = missing_cli
    with pytest.raises(PermissionError, match="automatic pull"):
        await backend.execute_resolved(_resolved(tmp_path, image=missing))
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
            await backend.execute_resolved(_resolved(tmp_path))

    destructive = {"stop", "kill", "rm"}
    assert not any(call[0] in destructive for call in backend.cli_calls)
    assert backend._active == {}


async def test_docker_backend_rejects_mount_option_injection_path(tmp_path):
    backend = _InspectableDockerBackend()
    context = _resolved(tmp_path)
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
    context = _resolved(tmp_path)
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
        result = await backend.execute_resolved(_resolved(tmp_path, budget=budget))
    assert result.status == "timed-out"
    assert process.returncode in {-15, -9}
    assert result.diagnostics["process_group_terminated"] is True
    assert any(call[:1] == ("rm",) for call in backend.cli_calls)
    assert result.diagnostics["cleanup"] == "removed"

    backend._active["active"] = _ContainerLease("khaos-active", "owner")
    await backend.shutdown()
    assert any(call[-1:] == ("khaos-active",) for call in backend.cli_calls)


async def test_docker_backend_truncates_output_without_unbounded_artifact(tmp_path):
    backend = _InspectableDockerBackend()
    process = _FakeProcess(stdout=b"0123456789", stderr=b"abcdefghij")
    with patch("khaos.coding.execution.docker.asyncio.create_subprocess_exec", new=AsyncMock(return_value=process)):
        result = await backend.execute_resolved(
            _resolved(tmp_path, budget=ResourceBudget(output_bytes=8))
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
    worktree.chmod(0o777)
    workspace = SimpleNamespace(
        task_id="task", worktree_path=worktree, repository_root=repository,
        state=WorkspaceState.RUNNING,
    )
    manager = SimpleNamespace(
        get=lambda workspace_id: workspace if workspace_id == "workspace" else None,
        verify_git_identity=AsyncMock(),
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
    context = _resolved(
        tmp_path,
        budget=ResourceBudget(
            workspace_bytes=4096,
            file_bytes=1024 * 1024,
            timeout_seconds=10,
        ),
    )
    context.worktree_path.chmod(0o777)
    command = (
        "import os,time; "
        "fd=os.open('/workspace/deleted.bin', os.O_CREAT|os.O_RDWR, 0o600); "
        "os.unlink('/workspace/deleted.bin'); os.write(fd, b'x'*16384); "
        "os.fsync(fd); time.sleep(30)"
    )
    context = ResolvedExecutionContext(
        **{**context.__dict__, "argv": ("python", "-c", command)}
    )
    backend = DockerBackend(allowed_images={DEFAULT_DOCKER_IMAGE})

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
    worktree.chmod(0o777)
    workspace = SimpleNamespace(
        task_id="task", worktree_path=worktree, repository_root=repository,
        state=WorkspaceState.RUNNING,
    )
    manager = SimpleNamespace(
        get=lambda workspace_id: workspace if workspace_id == "workspace" else None,
        verify_git_identity=AsyncMock(),
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
    leftovers = subprocess.run(
        ["docker", "ps", "-aq", "--filter", "name=khaos-"],
        check=True, capture_output=True, text=True,
    ).stdout.strip()
    assert leftovers == ""
    await service.shutdown()
