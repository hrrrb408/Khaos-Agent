import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from khaos.coding.execution import ExecutionRequest, NetworkPolicy, ResourceBudget
from khaos.coding.execution.platform import (
    BackendSelector,
    LinuxBubblewrapBackend,
    MacOSSandboxBackend,
    UnsupportedBackend,
)


@pytest.fixture(autouse=True)
def _reset_bwrap_cache():
    """Ensure each test probes bwrap capability fresh (no cross-test leakage)."""
    LinuxBubblewrapBackend._capability_cache = None
    yield
    LinuxBubblewrapBackend._capability_cache = None


@pytest.mark.asyncio
async def test_unsupported_backend_refuses_writable_execution():
    with pytest.raises(PermissionError):
        await UnsupportedBackend().execute(object())


def test_platform_profiles_are_network_denying(tmp_path: Path):
    assert "deny network" in MacOSSandboxBackend().profile(tmp_path)
    assert "--unshare-net" in LinuxBubblewrapBackend().argv_prefix(tmp_path)


def _require_or_skip(binary: str) -> None:
    if shutil.which(binary):
        return
    if os.environ.get("KHAOS_REQUIRE_PLATFORM_SANDBOX") == "1":
        pytest.fail(f"required platform sandbox binary is unavailable: {binary}")
    pytest.skip(f"platform sandbox binary is unavailable: {binary}")


@pytest.mark.asyncio
@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux bubblewrap evidence")
async def test_real_bwrap_enforces_full_isolation_matrix(tmp_path: Path):
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

    workspace = tmp_path / "workspace"
    outside = tmp_path / "outside.txt"
    main_repo = tmp_path / "repository"
    workspace.mkdir()
    main_repo.mkdir()
    (main_repo / "README.txt").write_text("main\n", encoding="utf-8")

    command = "\n".join([
        "import os, socket, subprocess, time",
        "from pathlib import Path",
        "_log = open('debug.log', 'w')",
        "_log.write('start: %s\\n' % time.time()); _log.flush()",
        # 2. Worktree writable
        "Path('inside.txt').write_text('ok')",
        "_log.write('wrote inside.txt\\n'); _log.flush()",
        # 6. /tmp is a fresh controlled tmpfs — writable
        "assert Path('/tmp').is_dir()",
        "Path('/tmp/sandbox.tmp').write_text('tmp-ok')",
        "_log.write('wrote /tmp/sandbox.tmp\\n'); _log.flush()",
        # 4. Outside-worktree write fails (read-only root bind)
        f"try: Path({str(outside)!r}).write_text('no')",
        "except OSError: pass",
        "else: raise SystemExit('outside write allowed')",
        "_log.write('outside write blocked\\n'); _log.flush()",
        # 3. Main repository is read-only
        f"try: Path({str(main_repo / 'README.txt')!r}).write_text('tampered')",
        "except OSError: pass",
        "else: raise SystemExit('main repo write allowed')",
        "_log.write('main repo write blocked\\n'); _log.flush()",
        # 5. Network access truly fails
        "try: socket.create_connection(('1.1.1.1', 53), timeout=1)",
        "except OSError: pass",
        "else: raise SystemExit('network allowed')",
        "_log.write('network blocked\\n'); _log.flush()",
        # 7. PID isolation — new PID namespace yields a low namespace-local PID
        "pid = os.getpid()",
        "assert pid < 100, f'unexpected host PID {pid}'",
        "_log.write('pid ok: %s\\n' % pid); _log.flush()",
        # 8. Background child — must be killed when bwrap tears down the namespace.
        #    Use os.system with shell background (&) and full stdio redirection to
        #    /dev/null.  This avoids subprocess.Popen's internal pipe/fd bookkeeping
        #    which was causing bwrap to hang on teardown.  The shell starts sleep in
        #    the background and exits immediately; os.system returns.  Python then
        #    exits normally.  When PID 1 exits, the kernel SIGKILLs the orphaned sleep.
        "os.system('sleep 30 </dev/null >/dev/null 2>&1 &')",
        "_log.write('spawned sleep via shell\\n'); _log.flush()",
    ])

    # 1. Real bwrap execution
    result = await LinuxBubblewrapBackend().execute(
        ExecutionRequest(
            (sys.executable, "-c", command), workspace, (workspace,),
            network_policy=NetworkPolicy.NONE,
            budget=ResourceBudget(timeout_seconds=15),
        )
    )
    # Read debug log from workspace (persists even on timeout because the
    # worktree is bind-mounted on the host).
    debug_log = ""
    debug_path = workspace / "debug.log"
    if debug_path.exists():
        debug_log = debug_path.read_text(encoding="utf-8")
    assert result.status == "passed", (
        f"status={result.status} stderr={result.stderr!r} debug_log={debug_log!r}"
    )

    # 2. Worktree writable — evidence
    assert (workspace / "inside.txt").read_text(encoding="utf-8") == "ok"
    # 4. Outside write blocked
    assert not outside.exists()
    # 3. Main repo untouched
    assert (main_repo / "README.txt").read_text(encoding="utf-8") == "main\n"

    # 8. No residual processes — the background sleep must have been killed
    # when the bwrap PID namespace was torn down.
    ps = subprocess.run(
        ["pgrep", "-f", "sleep 30"], capture_output=True, text=True,
    )
    assert ps.stdout.strip() == "", f"residual process survived bwrap teardown: {ps.stdout}"


@pytest.mark.asyncio
async def test_backend_selector_returns_unsupported_when_bwrap_probe_fails(monkeypatch):
    """Req 9: no security capability → infrastructure-unsupported, not host fallback."""
    from khaos.coding.execution.host import HostExecutionBackend
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

    # Read-only execution may still use host — only writable is fail-closed.
    readonly_backend = BackendSelector().select(writable=False)
    assert isinstance(readonly_backend, HostExecutionBackend)


@pytest.mark.asyncio
@pytest.mark.skipif(sys.platform != "darwin", reason="macOS sandbox-exec evidence")
async def test_real_macos_sandbox_blocks_network_and_external_writes(tmp_path: Path):
    """Run sandbox-exec against an actual process, with no host fallback."""
    _require_or_skip("sandbox-exec")
    workspace = tmp_path / "workspace"
    outside = tmp_path / "outside.txt"
    workspace.mkdir()
    command = (
        "from pathlib import Path; import socket; "
        "Path('inside.txt').write_text('ok'); "
        f"\ntry: Path({str(outside)!r}).write_text('no')\nexcept OSError: pass\nelse: raise SystemExit('outside write allowed'); "
        "\ntry: socket.create_connection(('1.1.1.1', 53), timeout=1)\nexcept OSError: pass\nelse: raise SystemExit('network allowed')"
    )
    result = await MacOSSandboxBackend().execute(
        ExecutionRequest(
            (sys.executable, "-c", command), workspace, (workspace,),
            network_policy=NetworkPolicy.NONE,
            budget=ResourceBudget(timeout_seconds=15),
        )
    )
    if result.status != "passed" and "Operation not permitted" in result.stderr and os.environ.get("KHAOS_REQUIRE_PLATFORM_SANDBOX") != "1":
        pytest.skip("current execution sandbox cannot invoke host sandbox-exec")
    assert result.status == "passed", result.stderr
    assert (workspace / "inside.txt").read_text(encoding="utf-8") == "ok"
    assert not outside.exists()
