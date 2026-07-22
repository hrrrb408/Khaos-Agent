import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

from khaos.coding.execution import (
    ExecutionRequest,
    FileSystemAccess,
    NetworkPolicy,
    PermissionProfile,
    ResourceBudget,
)
from khaos.coding.execution.platform import (
    BackendSelector,
    LinuxBubblewrapBackend,
    MacOSSandboxBackend,
    UnsupportedBackend,
    _runtime_read_roots,
)


@pytest.fixture(autouse=True)
def _reset_bwrap_cache():
    """Ensure each test probes bwrap capability fresh (no cross-test leakage)."""
    LinuxBubblewrapBackend._capability_cache = None
    MacOSSandboxBackend._capability_cache = None
    yield
    LinuxBubblewrapBackend._capability_cache = None
    MacOSSandboxBackend._capability_cache = None


@pytest.mark.asyncio
async def test_unsupported_backend_refuses_writable_execution():
    with pytest.raises(PermissionError):
        await UnsupportedBackend().execute(object())


def test_platform_profiles_are_network_denying(tmp_path: Path):
    assert "deny network" in MacOSSandboxBackend().profile(tmp_path)
    assert "--unshare-net" in LinuxBubblewrapBackend().argv_prefix(tmp_path)


def test_writable_platform_profiles_protect_git_pointer(tmp_path: Path):
    pointer = tmp_path / ".git"
    pointer.write_text("gitdir: /not-used\n", encoding="utf-8")

    mac_profile = MacOSSandboxBackend().profile(tmp_path)
    assert (
        f'(deny file-write* (literal "{pointer.resolve()}"))'
        in mac_profile
    )
    linux_argv = LinuxBubblewrapBackend().argv_prefix(tmp_path)
    mounts = tuple(
        linux_argv[index:index + 3]
        for index in range(len(linux_argv) - 2)
    )
    assert ("--ro-bind", str(pointer.resolve()), "/workspace/.git") in mounts


def test_read_only_platform_profiles_do_not_mount_workspace_writable(tmp_path: Path):
    mac_profile = MacOSSandboxBackend().profile(tmp_path, writable=False)
    assert f'(allow file-write* (subpath "{tmp_path.resolve()}"))' not in mac_profile
    linux_argv = LinuxBubblewrapBackend().argv_prefix(tmp_path, writable=False)
    worktree_index = linux_argv.index(str(tmp_path.resolve()))
    assert linux_argv[worktree_index - 1] == "--ro-bind"


def test_linux_profile_isolates_proc_ipc_uts_and_parent_lifetime(tmp_path: Path):
    argv = LinuxBubblewrapBackend().argv_prefix(tmp_path)

    assert ("--proc", "/proc") == argv[
        argv.index("--proc"):argv.index("--proc") + 2
    ]
    assert "--unshare-pid" in argv
    assert "--unshare-ipc" in argv
    assert "--unshare-uts" in argv
    assert "--unshare-net" in argv
    assert "--new-session" in argv
    assert "--die-with-parent" in argv
    assert ("--ro-bind", "/", "/") not in tuple(
        argv[index:index + 3] for index in range(len(argv) - 2)
    )
    assert argv.count("--size") == 2
    assert argv.count(str(ResourceBudget().tmpfs_bytes)) == 2
    assert ("--tmpfs", "/home/khaos") in tuple(
        argv[index:index + 2] for index in range(len(argv) - 1)
    )
    assert ("--bind", str((tmp_path / ".khaos-home").resolve()), "/home/khaos") not in tuple(
        argv[index:index + 3] for index in range(len(argv) - 2)
    )
    assert "--clearenv" in argv


def test_macos_profile_uses_positive_read_allowlist(tmp_path: Path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    profile = MacOSSandboxBackend().profile(workspace)

    assert "(deny default)" in profile
    assert "(allow file-read*)" not in profile
    assert str(workspace.resolve()) in profile
    assert str(Path.home()) not in profile
    assert "(allow mach-lookup)" not in profile
    assert "com.apple.pboard" not in profile
    assert "com.apple.securityd" not in profile
    assert "com.apple.system.opendirectoryd.libinfo" in profile


def test_user_home_executable_never_exposes_entire_home(tmp_path: Path):
    executable = Path.home() / "bin" / "custom-tool"

    roots = _runtime_read_roots((str(executable),), tmp_path)

    assert Path.home().resolve() not in roots
    assert roots == (executable.resolve(),)


def test_runtime_roots_include_lexical_virtualenv(tmp_path: Path):
    base = tmp_path / "base" / "bin" / "python"
    base.parent.mkdir(parents=True)
    base.write_text("", encoding="utf-8")
    virtualenv = tmp_path / "venv"
    (virtualenv / "bin").mkdir(parents=True)
    (virtualenv / "pyvenv.cfg").write_text("home = /test\n", encoding="utf-8")
    executable = virtualenv / "bin" / "python"
    executable.symlink_to(base)

    roots = _runtime_read_roots((str(executable),), tmp_path / "workspace")

    assert virtualenv.resolve() in roots


def test_linux_profile_preserves_cwd_relative_to_workspace(tmp_path: Path):
    workspace = tmp_path / "workspace"
    cwd = workspace / "src" / "pkg"
    cwd.mkdir(parents=True)

    argv = LinuxBubblewrapBackend().argv_prefix(workspace, cwd=cwd)
    chdir_index = argv.index("--chdir")

    assert argv[chdir_index + 1] == "/workspace/src/pkg"


def test_linux_profile_rejects_cwd_outside_workspace(tmp_path: Path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()

    with pytest.raises(PermissionError, match="cwd"):
        LinuxBubblewrapBackend().argv_prefix(
            workspace, cwd=tmp_path / "outside"
        )


def test_platform_profiles_hide_explicit_secret_roots(tmp_path: Path):
    workspace = tmp_path / "workspace"
    secret_root = tmp_path / "host-secrets"
    workspace.mkdir()
    secret_root.mkdir()

    mac_profile = MacOSSandboxBackend().profile(
        workspace, unreadable_roots=(secret_root,)
    )
    assert str(secret_root) not in mac_profile
    assert "(allow file-read*)" not in mac_profile
    assert '(allow file-write* (subpath "/tmp"))' not in mac_profile

    linux_argv = LinuxBubblewrapBackend().argv_prefix(
        workspace, unreadable_roots=(secret_root,)
    )
    assert str(secret_root) not in linux_argv
    assert ("--ro-bind", "/", "/") not in tuple(
        linux_argv[index:index + 3]
        for index in range(len(linux_argv) - 2)
    )


def _require_or_skip(binary: str) -> None:
    if shutil.which(binary):
        return
    if os.environ.get("KHAOS_REQUIRE_PLATFORM_SANDBOX") == "1":
        pytest.fail(f"required platform sandbox binary is unavailable: {binary}")
    pytest.skip(f"platform sandbox binary is unavailable: {binary}")


@pytest.mark.asyncio
@pytest.mark.platform_sandbox_real
@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux bubblewrap evidence")
async def test_real_bwrap_enforces_full_isolation_matrix(tmp_path: Path, request):
    """Real bwrap execution verifying all 9 isolation requirements.

    1. actually executed through bwrap (not argv-only);
    2. worktree is writable;
    3. main repository is read-only / not writable;
    4. outside-worktree write fails;
    5. network access truly fails;
    6. /tmp is a controlled tmpfs;
    7. PID/process isolation is in effect;
    8. no residual processes after teardown;
    9. no capability → infrastructure-unsupported (covered by a separate test).
    """
    _require_or_skip("bwrap")

    # Probe real capability — if the platform cannot create the network
    # namespace (e.g. GitHub-hosted runner EPERM on RTM_NEWADDR), fail with
    # proof rather than degrading to host subprocess or marking an argv-only
    # test as passed.
    availability = LinuxBubblewrapBackend().probe_capability()
    if not (availability.available and availability.network_enforced):
        if os.environ.get("KHAOS_REQUIRE_PLATFORM_SANDBOX") == "1":
            pytest.fail(
                f"bwrap cannot enforce isolation on this platform: {availability.reason}"
            )
        pytest.skip(f"bwrap cannot enforce isolation: {availability.reason}")

    # /tmp is intentionally a writable tmpfs inside bwrap, so negative host
    # write evidence must live under a ro-bound host path such as $HOME.
    host_root = Path(tempfile.mkdtemp(prefix=".khaos-bwrap-e2e-", dir=Path.home()))
    request.addfinalizer(lambda: shutil.rmtree(host_root, ignore_errors=True))
    workspace = tmp_path / "workspace"
    secret_root = host_root / "host-secrets"
    secret_file = secret_root / "token"
    outside = host_root / "outside.txt"
    main_repo = host_root / "repository"
    workspace.mkdir()
    (workspace / ".git").write_text(
        "gitdir: /host/repository/.git/worktrees/task\n", encoding="utf-8"
    )
    secret_root.mkdir()
    secret_file.write_text("host-secret", encoding="utf-8")
    main_repo.mkdir()
    (main_repo / "README.txt").write_text("main\n", encoding="utf-8")

    command = "\n".join([
        "import os, socket",
        "from pathlib import Path",
        # 2. Worktree writable
        "Path('inside.txt').write_text('ok')",
        "try: Path('.git').write_text('tampered')",
        "except OSError: pass",
        "else: raise SystemExit('.git pointer writable')",
        # 6. /tmp is a fresh controlled tmpfs — writable
        "assert Path('/tmp').is_dir()",
        "Path('/tmp/sandbox.tmp').write_text('tmp-ok')",
        # 4. Outside-worktree write fails (read-only root bind)
        f"try: Path({str(outside)!r}).write_text('no')",
        "except OSError: pass",
        "else: raise SystemExit('outside write allowed')",
        # 3. Main repository is read-only
        f"try: Path({str(main_repo / 'README.txt')!r}).write_text('tampered')",
        "except OSError: pass",
        "else: raise SystemExit('main repo write allowed')",
        # 5. Network access truly fails
        "try: socket.create_connection(('1.1.1.1', 53), timeout=1)",
        "except OSError: pass",
        "else: raise SystemExit('network allowed')",
        # Host credential roots are not merely read-only; they are hidden.
        f"try: Path({str(secret_file)!r}).read_text()",
        "except OSError: pass",
        "else: raise SystemExit('host secret readable')",
        # 7. PID isolation — new PID namespace yields a low namespace-local PID
        "pid = os.getpid()",
        "assert pid < 100, f'unexpected host PID {pid}'",
        # 8. Background child — bwrap waits for ALL processes in the PID
        #    namespace to exit before returning (it does NOT SIGKILL them
        #    when PID 1 exits).  A short-lived sleep (3s < 15s budget) lets
        #    bwrap return within the test budget while still exercising the
        #    teardown path.  os.system with shell background (&) and full
        #    stdio redirection to /dev/null avoids subprocess.Popen's fd
        #    bookkeeping which previously caused teardown hangs.
        "os.system('sleep 3 </dev/null >/dev/null 2>&1 &')",
    ])

    # 1. Real bwrap execution
    result = await LinuxBubblewrapBackend().execute(
        ExecutionRequest(
            (sys.executable, "-c", command), workspace,
            permission_profile=PermissionProfile(
                filesystem=FileSystemAccess.WORKSPACE_WRITE,
                unreadable_roots=(secret_root,),
                resources=ResourceBudget(timeout_seconds=15),
            ).bind_workspace(workspace),
        )
    )
    assert result.status == "passed", result.stderr

    # 2. Worktree writable — evidence
    assert (workspace / "inside.txt").read_text(encoding="utf-8") == "ok"
    assert (workspace / ".git").read_text(encoding="utf-8").startswith("gitdir: ")
    # 4. Outside write blocked
    assert not outside.exists()
    # 3. Main repo untouched
    assert (main_repo / "README.txt").read_text(encoding="utf-8") == "main\n"

    # 8. No residual processes — the background sleep must have been killed
    # when the bwrap PID namespace was torn down.
    ps = subprocess.run(
        ["pgrep", "-f", "sleep 3"], capture_output=True, text=True,
    )
    assert ps.stdout.strip() == "", f"residual process survived bwrap teardown: {ps.stdout}"


@pytest.mark.asyncio
@pytest.mark.platform_sandbox_real
@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux bubblewrap evidence")
async def test_real_bwrap_home_capacity_and_inode_budget(tmp_path: Path):
    _require_or_skip("bwrap")
    backend = LinuxBubblewrapBackend()
    availability = backend.probe_capability()
    if not (availability.available and availability.network_enforced):
        if os.environ.get("KHAOS_REQUIRE_PLATFORM_SANDBOX") == "1":
            pytest.fail(availability.reason)
        pytest.skip(availability.reason)
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    command = (
        "from pathlib import Path; import time; "
        "home=Path.home(); "
        "[(home / f'entry-{i}').write_bytes(b'x' * 4096) for i in range(20)]; "
        "time.sleep(30)"
    )

    result = await backend.execute(ExecutionRequest(
        (sys.executable, "-c", command),
        workspace,
        permission_profile=PermissionProfile(
            filesystem=FileSystemAccess.WORKSPACE_WRITE,
            resources=ResourceBudget(
                timeout_seconds=10,
                tmpfs_bytes=1024 * 1024,
                filesystem_entries=10,
            ),
        ).bind_workspace(workspace),
    ))

    assert result.status == "resource-exhausted", result.diagnostics
    assert result.diagnostics["resource_violation"]["kind"] == "filesystem-entries"


@pytest.mark.asyncio
@pytest.mark.platform_sandbox_real
@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux bubblewrap evidence")
async def test_real_bwrap_workspace_relative_entry_budget(tmp_path: Path):
    _require_or_skip("bwrap")
    backend = LinuxBubblewrapBackend()
    availability = backend.probe_capability()
    if not (availability.available and availability.network_enforced):
        if os.environ.get("KHAOS_REQUIRE_PLATFORM_SANDBOX") == "1":
            pytest.fail(availability.reason)
        pytest.skip(availability.reason)
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    command = (
        "from pathlib import Path; import time; "
        "[(Path('.') / f'entry-{i}').touch() for i in range(12)]; "
        "time.sleep(30)"
    )

    result = await backend.execute(ExecutionRequest(
        (sys.executable, "-c", command),
        workspace,
        permission_profile=PermissionProfile(
            filesystem=FileSystemAccess.WORKSPACE_WRITE,
            resources=ResourceBudget(
                timeout_seconds=10,
                workspace_entries=10,
            ),
        ).bind_workspace(workspace),
    ))

    assert result.status == "resource-exhausted", result.diagnostics
    assert result.diagnostics["resource_violation"] == {
        "kind": "workspace-entries", "observed": 12, "limit": 10,
    }


@pytest.mark.asyncio
async def test_backend_selector_returns_unsupported_when_bwrap_probe_fails(monkeypatch):
    """Req 9: no security capability → infrastructure-unsupported, not host fallback."""
    from khaos.coding.execution.platform import BackendAvailability

    def _fail_probe(self):
        return BackendAvailability("linux-bwrap", False, False, "EPERM on RTM_NEWADDR")

    monkeypatch.setattr(LinuxBubblewrapBackend, "probe_capability", _fail_probe)
    monkeypatch.setattr("khaos.coding.execution.platform.sys.platform", "linux")
    monkeypatch.setattr("khaos.coding.execution.platform.shutil.which", lambda _: "/usr/bin/bwrap")

    writable_backend = BackendSelector().select(writable=True)
    assert isinstance(writable_backend, UnsupportedBackend), (
        "writable execution must fail closed when bwrap cannot isolate, "
        "not degrade to a host subprocess"
    )
    with pytest.raises(PermissionError):
        await writable_backend.execute(object())

    # Agent-originated read-only execution also fails closed: command labels
    # are not an OS isolation boundary.
    readonly_backend = BackendSelector().select(writable=False)
    assert isinstance(readonly_backend, UnsupportedBackend)


@pytest.mark.asyncio
async def test_backend_selector_fails_closed_when_bwrap_probe_raises(monkeypatch):
    def _raise_probe(self):
        raise subprocess.TimeoutExpired("bwrap", 10)

    monkeypatch.setattr(LinuxBubblewrapBackend, "probe_capability", _raise_probe)
    monkeypatch.setattr("khaos.coding.execution.platform.sys.platform", "linux")
    monkeypatch.setattr(
        "khaos.coding.execution.platform.shutil.which",
        lambda _: "/usr/bin/bwrap",
    )

    backend = BackendSelector().select(writable=False)
    assert isinstance(backend, UnsupportedBackend)
    with pytest.raises(PermissionError):
        await backend.execute(object())


@pytest.mark.asyncio
async def test_backend_selector_fails_closed_when_macos_probe_fails(monkeypatch):
    from khaos.coding.execution.platform import BackendAvailability

    monkeypatch.setattr(
        MacOSSandboxBackend,
        "probe_capability",
        lambda self: BackendAvailability(
            self.name, False, False, "seatbelt probe denied"
        ),
    )
    monkeypatch.setattr("khaos.coding.execution.platform.sys.platform", "darwin")
    monkeypatch.setattr(
        "khaos.coding.execution.platform.shutil.which",
        lambda _: "/usr/bin/sandbox-exec",
    )

    backend = BackendSelector().select(writable=True)

    assert isinstance(backend, UnsupportedBackend)
    with pytest.raises(PermissionError):
        await backend.execute(object())


@pytest.mark.asyncio
async def test_backend_selector_fails_closed_when_macos_probe_raises(monkeypatch):
    monkeypatch.setattr(
        MacOSSandboxBackend,
        "probe_capability",
        lambda self: (_ for _ in ()).throw(RuntimeError("probe crashed")),
    )
    monkeypatch.setattr("khaos.coding.execution.platform.sys.platform", "darwin")
    monkeypatch.setattr(
        "khaos.coding.execution.platform.shutil.which",
        lambda _: "/usr/bin/sandbox-exec",
    )

    assert isinstance(
        BackendSelector().select(writable=False), UnsupportedBackend
    )


@pytest.mark.asyncio
@pytest.mark.platform_sandbox_real
@pytest.mark.skipif(sys.platform != "darwin", reason="macOS sandbox-exec evidence")
async def test_real_macos_sandbox_blocks_network_and_external_writes(tmp_path: Path):
    """Run sandbox-exec against an actual process, with no host fallback."""
    _require_or_skip("sandbox-exec")
    availability = MacOSSandboxBackend().probe_capability()
    if (
        not availability.available
        and os.environ.get("KHAOS_REQUIRE_PLATFORM_SANDBOX") != "1"
    ):
        pytest.skip(availability.reason)
    assert availability.available, availability.reason
    assert availability.network_enforced, availability.reason
    workspace = tmp_path / "workspace"
    secret_root = tmp_path / "host-secrets"
    secret_file = secret_root / "token"
    outside = tmp_path / "outside.txt"
    workspace.mkdir()
    (workspace / ".git").write_text(
        "gitdir: /host/repository/.git/worktrees/task\n", encoding="utf-8"
    )
    secret_root.mkdir()
    secret_file.write_text("host-secret", encoding="utf-8")
    protected_pointer_names = (
        (".git", ".GIT")
        if (workspace / ".GIT").exists()
        else (".git",)
    )
    command = (
        "from pathlib import Path; import socket, subprocess; "
        "Path('inside.txt').write_text('ok'); "
        f"\nfor pointer in tuple(Path(name) for name in {protected_pointer_names!r}):"
        "\n try: pointer.write_text('tampered')"
        "\n except OSError: pass"
        "\n else: raise SystemExit(f'Git pointer writable: {pointer}')"
        f"\ntry: Path({str(outside)!r}).write_text('no')\nexcept OSError: pass\nelse: raise SystemExit('outside write allowed'); "
        "\ntry: socket.create_connection(('1.1.1.1', 53), timeout=1)\nexcept OSError: pass\nelse: raise SystemExit('network allowed')"
        f"\ntry: Path({str(secret_file)!r}).read_text()\nexcept OSError: pass\nelse: raise SystemExit('host secret readable')"
        "\nfor ipc_command in (('/usr/bin/pbpaste',), ('/usr/bin/security', 'list-keychains')):"
        "\n result = subprocess.run(ipc_command, capture_output=True)"
        "\n if result.returncode == 0: raise SystemExit(f'host IPC allowed: {ipc_command[0]}')"
    )
    result = await MacOSSandboxBackend().execute(
        ExecutionRequest(
            (sys.executable, "-c", command), workspace,
            permission_profile=PermissionProfile(
                filesystem=FileSystemAccess.WORKSPACE_WRITE,
                unreadable_roots=(secret_root,),
                resources=ResourceBudget(timeout_seconds=15),
            ).bind_workspace(workspace),
        )
    )
    if (
        result.status != "passed"
        and "Operation not permitted" in result.stderr
        and os.environ.get("KHAOS_REQUIRE_PLATFORM_SANDBOX") != "1"
    ):
        pytest.skip("current execution sandbox cannot invoke host sandbox-exec")
    assert result.status == "passed", result.stderr
    assert (workspace / "inside.txt").read_text(encoding="utf-8") == "ok"
    assert (workspace / ".git").read_text(encoding="utf-8").startswith("gitdir: ")
    assert not outside.exists()


@pytest.mark.asyncio
@pytest.mark.platform_sandbox_real
@pytest.mark.skipif(sys.platform != "darwin", reason="macOS sandbox-exec evidence")
async def test_real_macos_synthetic_home_capacity_is_enforced(tmp_path: Path):
    _require_or_skip("sandbox-exec")
    backend = MacOSSandboxBackend()
    availability = backend.probe_capability()
    if (
        not availability.available
        and os.environ.get("KHAOS_REQUIRE_PLATFORM_SANDBOX") != "1"
    ):
        pytest.skip(availability.reason)
    assert availability.available, availability.reason
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    command = (
        "from pathlib import Path; import time; "
        "home=Path.home(); "
        "[(home / f'payload-{i}').write_bytes(b'x' * 4096) for i in range(4)]; "
        "time.sleep(30)"
    )
    result = await backend.execute(ExecutionRequest(
        (sys.executable, "-c", command),
        workspace,
        permission_profile=PermissionProfile(
            filesystem=FileSystemAccess.WORKSPACE_WRITE,
            resources=ResourceBudget(
                timeout_seconds=10,
                tmpfs_bytes=10_000,
                file_bytes=8192,
            ),
        ).bind_workspace(workspace),
    ))
    if (
        result.status != "resource-exhausted"
        and "Operation not permitted" in result.stderr
        and os.environ.get("KHAOS_REQUIRE_PLATFORM_SANDBOX") != "1"
    ):
        pytest.skip("current execution sandbox cannot invoke host sandbox-exec")
    assert result.status == "resource-exhausted", result.diagnostics
    assert result.diagnostics["resource_violation"] == {
        "kind": "tmpfs", "observed": 16_384, "limit": 10_000,
    }


@pytest.mark.asyncio
@pytest.mark.platform_sandbox_real
@pytest.mark.skipif(sys.platform != "darwin", reason="macOS sandbox-exec evidence")
async def test_real_macos_workspace_relative_byte_budget(tmp_path: Path):
    _require_or_skip("sandbox-exec")
    backend = MacOSSandboxBackend()
    availability = backend.probe_capability()
    if (
        not availability.available
        and os.environ.get("KHAOS_REQUIRE_PLATFORM_SANDBOX") != "1"
    ):
        pytest.skip(availability.reason)
    assert availability.available, availability.reason
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    command = (
        "from pathlib import Path; import time; "
        "[(Path('.') / f'payload-{i}').write_bytes(b'x' * 4096) "
        "for i in range(4)]; time.sleep(30)"
    )
    result = await backend.execute(ExecutionRequest(
        (sys.executable, "-c", command),
        workspace,
        permission_profile=PermissionProfile(
            filesystem=FileSystemAccess.WORKSPACE_WRITE,
            resources=ResourceBudget(
                timeout_seconds=10,
                workspace_bytes=10_000,
            ),
        ).bind_workspace(workspace),
    ))
    if (
        result.status != "resource-exhausted"
        and "Operation not permitted" in result.stderr
        and os.environ.get("KHAOS_REQUIRE_PLATFORM_SANDBOX") != "1"
    ):
        pytest.skip("current execution sandbox cannot invoke host sandbox-exec")
    assert result.status == "resource-exhausted", result.diagnostics
    assert result.diagnostics["resource_violation"]["kind"] == "workspace-bytes"
    # The watchdog is intentionally allowed to terminate as soon as the
    # aggregate allocation crosses the configured boundary.  It need not wait
    # for every write in the child process to complete.
    assert result.diagnostics["resource_violation"]["observed"] > 10_000
    assert result.diagnostics["resource_violation"]["limit"] == 10_000
