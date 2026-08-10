"""Linux kernel-resource ownership and native executable authority tests."""

from __future__ import annotations

import asyncio
import hashlib
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

from khaos.coding.execution import ExecutionService, LinuxBubblewrapBackend
from khaos.coding.execution import platform as platform_module
from khaos.coding.execution.identity import (
    container_command_identity,
    executable_identity,
    open_executable_authority,
)
from khaos.coding.execution.models import (
    ExecutionRequest,
    FileSystemAccess,
    PermissionProfile,
    ResourceBudget,
)
from khaos.coding.execution.native_launcher import build_process_launch
from khaos.coding.execution.native_launcher_runtime import _parse
from khaos.coding.execution.platform import KernelResourceLease
from khaos.coding.execution.service import ExecutionServiceShutdownError


def test_linux_cgroup_populated_timeout_retains_external_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    group = tmp_path / "populated-cgroup"
    group.mkdir()
    (group / "cgroup.kill").write_text("", encoding="ascii")
    (group / "cgroup.events").write_text("populated 1\n", encoding="ascii")
    ticks = iter((0.0, 6.0))
    monkeypatch.setattr(time, "monotonic", lambda: next(ticks, 6.0))

    with pytest.raises(TimeoutError, match="remained populated"):
        platform_module._remove_linux_cgroup(group)

    assert group.exists()


@pytest.mark.asyncio
async def test_linux_owner_requires_external_path_absence_before_release(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    backend = LinuxBubblewrapBackend()
    cgroup = tmp_path / "oracle-cgroup"
    cgroup.mkdir()
    backend._cgroup_leases["oracle"] = KernelResourceLease("oracle", cgroup)

    monkeypatch.setattr(platform_module, "_remove_linux_cgroup", lambda _path: None)
    with pytest.raises(RuntimeError, match="disappearance was not proven"):
        await backend.terminate("oracle")

    assert backend.owns_execution("oracle")
    assert backend.is_quarantined

    monkeypatch.setattr(platform_module, "_remove_linux_cgroup", lambda path: path.rmdir())
    await backend.close()
    assert not backend.owns_execution("oracle")
    assert backend.terminal_postcondition()
    assert not cgroup.exists()


@pytest.mark.asyncio
async def test_linux_backend_retains_failed_cgroup_cleanup_for_retry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    backend = LinuxBubblewrapBackend()
    cgroup = tmp_path / "cgroup-exec"
    cgroup.mkdir()
    backend._cgroup_leases["exec-1"] = KernelResourceLease("exec-1", cgroup)
    attempts = 0

    def flaky_remove(path: Path) -> None:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise OSError("transient cgroup removal failure")
        path.rmdir()

    monkeypatch.setattr(platform_module, "_remove_linux_cgroup", flaky_remove)

    with pytest.raises(OSError, match="transient cgroup"):
        await backend.terminate("exec-1")

    assert backend.is_quarantined
    assert not backend.terminal_closed
    assert backend.owns_execution("exec-1")
    assert backend.owned_resources()

    await backend.close()
    assert attempts == 2
    assert backend.terminal_closed
    assert backend.terminal_postcondition()
    assert backend.owned_resources() == ()
    assert not cgroup.exists()


@pytest.mark.asyncio
async def test_linux_backend_retains_cancelled_cleanup_for_retry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    backend = LinuxBubblewrapBackend()
    cgroup = tmp_path / "cancelled-cgroup"
    cgroup.mkdir()
    backend._cgroup_leases["exec-cancel"] = KernelResourceLease(
        "exec-cancel", cgroup
    )

    def cancel_remove(_path: Path) -> None:
        raise asyncio.CancelledError()

    monkeypatch.setattr(platform_module, "_remove_linux_cgroup", cancel_remove)
    with pytest.raises(asyncio.CancelledError):
        await backend.terminate("exec-cancel")

    assert backend.is_quarantined
    assert backend.owns_execution("exec-cancel")
    assert not backend.terminal_closed

    monkeypatch.setattr(platform_module, "_remove_linux_cgroup", lambda path: path.rmdir())
    await backend.close()
    assert backend.terminal_closed
    assert backend.owned_resources() == ()
    assert not cgroup.exists()


@pytest.mark.asyncio
async def test_execution_service_closes_transitive_linux_owner_on_retry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    backend = LinuxBubblewrapBackend()
    cgroup = tmp_path / "cgroup-exec"
    cgroup.mkdir()
    backend._cgroup_leases["exec-2"] = KernelResourceLease("exec-2", cgroup)
    service = ExecutionService(backend)
    service._active["exec-2"] = ("task", "workspace", backend)
    attempts = 0

    def fail_twice(path: Path) -> None:
        nonlocal attempts
        attempts += 1
        if attempts <= 2:
            raise OSError("cgroup cleanup temporarily unavailable")
        path.rmdir()

    monkeypatch.setattr(platform_module, "_remove_linux_cgroup", fail_twice)

    with pytest.raises(ExecutionServiceShutdownError):
        await service.shutdown()

    assert service.is_quarantined
    assert not service.terminal_closed
    assert service.owns_execution("exec-2")
    assert backend.is_quarantined
    assert backend.owns_execution("exec-2")

    await service.shutdown()
    assert service.terminal_closed
    assert service.terminal_postcondition()
    assert service.owned_resources() == ()
    assert backend.terminal_closed
    assert not cgroup.exists()


@pytest.mark.asyncio
async def test_linux_backend_releases_cgroup_when_setup_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    cgroup = tmp_path / "setup-failure-cgroup"
    cgroup.mkdir()
    backend = LinuxBubblewrapBackend()

    monkeypatch.setattr(
        platform_module, "_create_linux_cgroup", lambda *_: cgroup
    )
    monkeypatch.setattr(
        platform_module, "_resolve_bwrap_path", lambda: "/usr/bin/bwrap"
    )
    monkeypatch.setattr(platform_module, "_linux_sandbox_launcher", lambda: None)
    monkeypatch.setattr(
        platform_module, "_remove_linux_cgroup", lambda path: path.rmdir()
    )

    request = ExecutionRequest(
        ("/bin/echo", "ok"),
        workspace,
        correlation_id="setup-failure",
        permission_profile=PermissionProfile(
            filesystem=FileSystemAccess.WORKSPACE_WRITE,
        ).bind_workspace(workspace),
    )
    with pytest.raises(PermissionError, match="launcher unavailable"):
        await backend.execute(request)

    assert not cgroup.exists()
    assert backend.owned_resources() == ()


@pytest.mark.asyncio
async def test_linux_backend_cleans_unregistered_duplicate_cgroup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    retained = tmp_path / "retained-cgroup"
    retained.mkdir()
    duplicate = tmp_path / "duplicate-cgroup"
    duplicate.mkdir()
    backend = LinuxBubblewrapBackend()
    backend._cgroup_leases["duplicate"] = KernelResourceLease(
        "duplicate", retained
    )

    monkeypatch.setattr(
        platform_module, "_create_linux_cgroup", lambda *_: duplicate
    )
    monkeypatch.setattr(
        platform_module, "_remove_linux_cgroup", lambda path: path.rmdir()
    )

    request = ExecutionRequest(
        ("/bin/echo", "ok"),
        workspace,
        correlation_id="duplicate",
        permission_profile=PermissionProfile(
            filesystem=FileSystemAccess.WORKSPACE_WRITE,
        ).bind_workspace(workspace),
    )
    with pytest.raises(RuntimeError, match="duplicate Linux cgroup"):
        await backend.execute(request)

    assert not duplicate.exists()
    assert backend.owns_execution("duplicate")
    await backend.close()
    assert not retained.exists()


def test_descriptor_authority_survives_path_replacement(tmp_path: Path) -> None:
    executable = tmp_path / "tool"
    original = b"#!/bin/sh\nprintf original\n"
    executable.write_bytes(original)
    executable.chmod(0o700)
    argv = (str(executable),)
    expected = executable_identity(argv)
    authority = open_executable_authority(argv, expected_identity=expected)
    try:
        original_stat = os.fstat(authority.executable_fd)
        executable.unlink()
        executable.write_bytes(b"#!/bin/sh\nprintf replaced\n")
        executable.chmod(0o700)
        assert os.fstat(authority.executable_fd).st_ino == original_stat.st_ino
        assert executable.stat().st_ino != original_stat.st_ino
        os.lseek(authority.executable_fd, 0, os.SEEK_SET)
        assert os.read(authority.executable_fd, len(original)) == original
        assert authority.executable_digest == hashlib.sha256(original).hexdigest()
    finally:
        authority.close()


def test_descriptor_authority_binds_script_interpreter(tmp_path: Path) -> None:
    script = tmp_path / "script"
    script.write_text(f"#!{sys.executable}\nprint('ok')\n", encoding="utf-8")
    script.chmod(0o700)
    argv = (str(script),)
    authority = open_executable_authority(
        argv,
        {"PATH": os.environ.get("PATH", os.defpath)},
        expected_identity=executable_identity(argv),
    )
    try:
        assert authority.interpreter_fd is not None
        assert authority.interpreter_digest
        assert authority.interpreter_args == ()
        assert authority.interpreter_argv0 == str(Path(sys.executable).resolve())
    finally:
        authority.close()


def test_container_command_identity_is_not_host_executable_identity() -> None:
    argv = ("/bin/sh", "-c", "echo isolated")
    first = container_command_identity("example.test/khaos@sha256:" + "a" * 64, argv)
    second = container_command_identity("example.test/khaos@sha256:" + "b" * 64, argv)
    assert first != second
    assert first != executable_identity(argv)


def test_python_launcher_parses_descriptor_digest_and_interpreter_args() -> None:
    options, command = _parse(
        [
            "--exec-fd",
            "7",
            "--exec-digest",
            "a" * 64,
            "--interpreter-fd",
            "8",
            "--interpreter-digest",
            "b" * 64,
            "--interpreter-argv0",
            "/usr/bin/python3",
            "--interpreter-arg",
            "-S",
            "--",
            "/tmp/script",
            "arg",
        ]
    )
    assert options["exec_fd"] == 7
    assert options["exec_digest"] == "a" * 64
    assert options["interpreter_argv0"] == "/usr/bin/python3"
    assert options["interpreter_args"] == ["-S"]
    assert command == ["/tmp/script", "arg"]


def test_native_launcher_executes_pinned_script_after_path_replacement(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    script = tmp_path / "pinned-script"
    script.write_text(f"#!{sys.executable}\nprint('original')\n", encoding="utf-8")
    script.chmod(0o700)
    argv = (str(script),)
    environment = {
        "PATH": os.environ.get("PATH", os.defpath),
        "PYTHONPATH": str(Path(__file__).resolve().parents[3] / "python"),
    }
    expected = executable_identity(argv, environment)
    monkeypatch.setenv("KHAOS_DEV_MODE", "1")
    monkeypatch.setattr(
        "khaos.coding.execution.native_launcher._find_launcher", lambda: None
    )
    launch = build_process_launch(
        argv,
        cwd=tmp_path,
        directory_binding=None,
        budget=ResourceBudget(),
        enforce_resource_limits=False,
        environment=environment,
        expected_identity=expected,
    )
    try:
        script.unlink()
        script.write_text(f"#!{sys.executable}\nprint('replaced')\n", encoding="utf-8")
        script.chmod(0o700)
        completed = subprocess.run(
            launch.argv,
            cwd=launch.cwd,
            env=environment,
            pass_fds=launch.pass_fds,
            capture_output=True,
            text=True,
            check=False,
        )
    finally:
        launch.close_owned_fds()
    assert completed.returncode == 0, completed.stderr
    assert completed.stdout.strip() == "original"
