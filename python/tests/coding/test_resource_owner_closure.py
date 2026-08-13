"""Round-17 review §十五: Resource Ownership Closure E2E suite.

This module applies the shared lifecycle assertions plus owner-specific fault
matrices to every ``ResourceOwner`` implementation (:class:`~khaos.coding.execution.service.ExecutionService`,
:class:`~khaos.coding.execution.docker.DockerBackend`,
:class:`~khaos.coding.execution.managed.ManagedProcessHandle`,
:class:`~khaos.coding.execution.supervisor.ProcessSupervisor`,
:class:`~khaos.coding.intelligence.lsp.client.LspClient`,
:class:`~khaos.security.browser_egress_proxy.BrowserEgressProxy`,
:class:`~khaos.tools.browser_tools.BrowserManager`, and
:class:`~khaos.runtime.factory.RuntimeResult`).

The review identified that LSP, Supervisor, and BrowserEgressProxy each
had their own ad-hoc notion of "CLOSED" — with different state
combinations, different cleanup semantics, and different (or missing)
postcondition proofs.  This suite verifies the unified lifecycle theorem:

    CLOSED ⇔
      1. future resource admission is impossible
      2. every resource acquired by this owner has a recorded terminal
         postcondition
      3. no initializing/acquiring transaction remains
      4. no child owner remains non-terminal
    5. all resource registries are empty (or contain only explicitly
       detached non-owned resources)
    6. independent external oracles (process returncode, temp paths,
       supervisor registration, and child-owner inventories) agree with the
       owner's terminal claim

Concretely the behavior matrix is:

| Fault                      | Must satisfy                    |
| -------------------------- | ------------------------------- |
| start after close          | reject                          |
| concurrent close           | all callers await same result   |
| first close failure        | second close retry → CLOSED     |
| cleanup ordinary exception | QUARANTINED (not CLOSED)        |
| cleanup CancelledError     | QUARANTINED (not CLOSED)        |
| CLOSED                     | no live/owned resource          |

The common assertions are applied through the
:class:`~khaos.coding.execution.resource_owner.ResourceOwner` protocol, while
the fault injection remains owner-specific.  DockerBackend is covered by a
complete matrix in ``test_sandbox_tools.py`` because its container and
finalizer oracles are different from process/socket owners.
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock
from urllib.parse import urlsplit

import pytest

from khaos.coding.execution import (
    ExecutionRequest,
    ExecutionService,
    HostExecutionBackend,
    ResourceBudget,
)
from khaos.coding.execution.supervisor import (
    ProcessSupervisor,
    SupervisorClosedError,
)
from khaos.coding.intelligence.lsp.client import LspClient, LspCloseError
from khaos.security.browser_egress_proxy import (
    BrowserEgressProxy,
    _ProxyState,
    _RelayLease,
)
from khaos.security.host_network import ValidatedTarget
from khaos.tools.browser_tools import BrowserManager
from khaos.runtime.factory import RuntimeResult
from khaos.runtime.lifecycle import CloseState

# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

#: A short grace period so termination tests run quickly.
_SHORT_GRACE = 0.1


class _MockProcess:
    """Duck-typed stand-in for ``asyncio.subprocess.Process``.

    Used by both ProcessSupervisor and LspClient fault-injection tests.
    The process starts alive (``returncode is None``) and transitions to
    a terminal state only after ``terminate()`` or ``kill()`` is called.
    ``pid`` is ``None`` so ``_signal_process_group`` falls through to
    the sync ``process.terminate()`` / ``process.kill()`` methods instead
    of calling ``os.killpg`` on a real process group.
    """

    def __init__(self) -> None:
        self.pid = None
        self.returncode: int | None = None
        self._waiters: list[asyncio.Future[int]] = []

    async def wait(self) -> int:
        if self.returncode is not None:
            return self.returncode
        fut: asyncio.Future[int] = asyncio.get_running_loop().create_future()
        self._waiters.append(fut)
        return await fut

    def _set_returncode(self, code: int) -> None:
        self.returncode = code
        for fut in self._waiters:
            if not fut.done():
                fut.set_result(code)
        self._waiters.clear()

    def terminate(self) -> None:
        self._set_returncode(-15)

    def kill(self) -> None:
        self._set_returncode(-9)


# ---------------------------------------------------------------------------
# ProcessSupervisor closure tests
# ---------------------------------------------------------------------------


def _supervisor_request(cwd: Path, *, correlation_id: str = "task-closure") -> ExecutionRequest:
    return ExecutionRequest(
        (sys.executable, "-c", "import time; time.sleep(30)"),
        cwd,
        budget=ResourceBudget(timeout_seconds=30, output_bytes=65536),
        correlation_id=correlation_id,
    )


async def test_supervisor_close_then_start_rejected(tmp_path: str) -> None:
    """start after close ⇒ reject (admission fence)."""
    supervisor = ProcessSupervisor(termination_grace_seconds=_SHORT_GRACE)
    await supervisor.shutdown()
    assert supervisor.terminal_closed
    # run() must reject because the supervisor is CLOSED.
    with pytest.raises(SupervisorClosedError):
        await supervisor.run(_supervisor_request(Path(tmp_path)))


async def test_supervisor_concurrent_close_joins_same_task() -> None:
    """concurrent close ⇒ all callers observe the same result."""
    supervisor = ProcessSupervisor(termination_grace_seconds=_SHORT_GRACE)
    # Launch two concurrent shutdowns — both must succeed (no exception)
    # and both must see terminal_closed after.
    results = await asyncio.gather(
        supervisor.shutdown(),
        supervisor.shutdown(),
        return_exceptions=True,
    )
    assert all(not isinstance(r, Exception) for r in results), results
    assert supervisor.terminal_closed
    assert supervisor.owned_resources() == ()


async def test_supervisor_first_close_failure_second_retry() -> None:
    """first close failure → QUARANTINED; second close retry → CLOSED."""
    supervisor = ProcessSupervisor(termination_grace_seconds=_SHORT_GRACE)
    mock_proc = _MockProcess()
    await supervisor.register_process("quarantine-retry", mock_proc)  # type: ignore[arg-type]
    # Inject a terminate that fails the first time, succeeds the second.
    original = supervisor._terminate_active
    call_count = 0

    async def failing_terminate(active: object) -> None:
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            raise RuntimeError("transient failure")
        await original(active)  # type: ignore[arg-type]

    supervisor._terminate_active = failing_terminate  # type: ignore[assignment]

    # First shutdown fails → QUARANTINED.
    with pytest.raises(SupervisorClosedError, match="1 error"):
        await supervisor.shutdown()
    assert supervisor.is_quarantined
    assert not supervisor.terminal_closed
    # Resources are retained — the process is still registered.
    assert supervisor.owned_resources() != ()

    # Second shutdown succeeds → CLOSED.
    await supervisor.shutdown()
    assert supervisor.terminal_closed
    assert supervisor.owned_resources() == ()


async def test_supervisor_cleanup_exception_enters_quarantine_not_closed() -> None:
    """cleanup ordinary exception ⇒ QUARANTINED (not CLOSED)."""
    supervisor = ProcessSupervisor(termination_grace_seconds=_SHORT_GRACE)
    mock_proc = _MockProcess()
    await supervisor.register_process("quarantine-exc", mock_proc)  # type: ignore[arg-type]

    async def always_failing(active: object) -> None:
        raise RuntimeError("permanent failure")

    supervisor._terminate_active = always_failing  # type: ignore[assignment]

    with pytest.raises(SupervisorClosedError):
        await supervisor.shutdown()
    assert supervisor.is_quarantined
    assert not supervisor.terminal_closed
    # CLOSED invariant violated — resources remain.
    assert supervisor.owned_resources() != ()


async def test_supervisor_cancelled_error_enters_quarantine_not_closed() -> None:
    """cleanup CancelledError ⇒ QUARANTINED (not CLOSED).

    Round-17 review §四: CancelledError during terminate must not be
    swallowed into a false CLOSED.  The process may still be alive —
    ownership release is unproven.  The supervisor records the
    cancellation as an error and enters QUARANTINED.
    """
    supervisor = ProcessSupervisor(termination_grace_seconds=_SHORT_GRACE)
    mock_proc = _MockProcess()
    await supervisor.register_process("quarantine-cancel", mock_proc)  # type: ignore[arg-type]

    async def cancelling_terminate(active: object) -> None:
        raise asyncio.CancelledError()

    supervisor._terminate_active = cancelling_terminate  # type: ignore[assignment]

    # CancelledError is recorded as an error and re-raised as
    # SupervisorClosedError (QUARANTINED, not CLOSED).
    with pytest.raises(SupervisorClosedError):
        await supervisor.shutdown()
    # The supervisor must NOT be CLOSED — CancelledError means ownership
    # release is unproven.  It should be QUARANTINED.
    assert supervisor.is_quarantined
    assert not supervisor.terminal_closed


@pytest.mark.posix_host
async def test_supervisor_closed_implies_no_owned_resources(tmp_path: str) -> None:
    """CLOSED ⇒ no live/owned resource."""
    supervisor = ProcessSupervisor(termination_grace_seconds=_SHORT_GRACE)
    request = ExecutionRequest(
        (sys.executable, "-c", "pass"),
        Path(tmp_path),
        budget=ResourceBudget(timeout_seconds=5, output_bytes=65536),
        correlation_id="closure-happy",
    )
    await supervisor.run(request)
    await supervisor.shutdown()
    assert supervisor.terminal_closed
    assert supervisor.terminal_postcondition()
    assert supervisor.owned_resources() == ()


async def test_supervisor_shutdown_settles_watchdog_before_unregister() -> None:
    """CLOSED must not hide a still-pending child watchdog task."""
    supervisor = ProcessSupervisor(termination_grace_seconds=_SHORT_GRACE)
    mock_proc = _MockProcess()
    await supervisor.register_process("watchdog-owner", mock_proc)
    watchdog = asyncio.create_task(asyncio.sleep(30))
    active = supervisor._active["watchdog-owner"]
    active.watchdog_task = watchdog

    await supervisor.shutdown()
    assert watchdog.done()
    assert supervisor.terminal_closed
    assert supervisor.terminal_postcondition()
    assert supervisor.owned_resources() == ()


async def test_execution_service_closed_has_independent_owner_proof() -> None:
    """ExecutionService CLOSED is backed by supervisor and registry oracles."""
    service = ExecutionService(HostExecutionBackend())
    await service.shutdown()
    assert service.terminal_closed
    assert service.terminal_postcondition()
    assert service.owned_resources() == ()
    assert service.process_supervisor.active_execution_ids == ()


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX process cleanup oracle")
async def test_managed_handle_closed_proves_pid_and_temp_home_cleanup(
    tmp_path: Path,
) -> None:
    """ManagedProcessHandle proves the real child and temporary HOME are gone."""
    temporary_home = tmp_path / "managed-home"
    temporary_home.mkdir()
    process = await asyncio.create_subprocess_exec(
        sys.executable,
        "-c",
        "import time; time.sleep(30)",
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        start_new_session=True,
    )
    from khaos.coding.execution.managed import ManagedProcessHandle

    handle = ManagedProcessHandle(
        "matrix-managed-handle",
        process,
        temporary_home=temporary_home,
    )
    await handle.aclose()
    assert process.returncode is not None
    assert not temporary_home.exists()
    assert handle.terminal_closed
    assert handle.terminal_postcondition()
    assert handle.owned_resources() == ()


# ---------------------------------------------------------------------------
# LspClient closure tests
# ---------------------------------------------------------------------------

_FAKE_SERVER = r'''
import sys, json
def read_msg():
    headers = {}
    while True:
        line = sys.stdin.buffer.readline()
        if line in (b"\r\n", b"\n", b""):
            break
        k, _, v = line.decode("ascii").partition(":")
        headers[k.strip().lower()] = v.strip()
    n = int(headers.get("content-length", "0"))
    return json.loads(sys.stdin.buffer.read(n).decode("utf-8"))

def write_msg(msg):
    payload = json.dumps(msg).encode("utf-8")
    sys.stdout.buffer.write(f"Content-Length: {len(payload)}\r\n\r\n".encode("ascii"))
    sys.stdout.buffer.write(payload)
    sys.stdout.buffer.flush()

initialized = False
while True:
    try:
        msg = read_msg()
    except Exception:
        break
    if msg.get("method") == "initialize":
        write_msg({"jsonrpc": "2.0", "id": msg["id"], "result": {"capabilities": {}}})
    elif msg.get("method") == "initialized":
        initialized = True
    elif msg.get("method") == "shutdown":
        write_msg({"jsonrpc": "2.0", "id": msg["id"], "result": None})
    elif msg.get("method") == "exit":
        break
'''


def _lsp_runtime(tmp_path: Path):
    from khaos.coding.execution.managed import ManagedProcessHandle

    server = tmp_path / "server.py"
    server.write_text(_FAKE_SERVER)

    workspace = SimpleNamespace(
        task_id="task",
        workspace_id="workspace",
        worktree_path=tmp_path,
        state="running",
    )
    manager = SimpleNamespace(
        get=lambda wid, **kw: workspace if wid == "workspace" else None,
        require=lambda wid, **kw: workspace if wid == "workspace" else None,
        verify_git_identity=AsyncMock(return_value=True),
        verify_execution_root=AsyncMock(return_value=True),
    )

    spawned: list[object] = []

    async def factory(request, backend):
        proc = await asyncio.create_subprocess_exec(
            *request.argv,
            cwd=str(request.cwd),
            env=request.environment or None,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            stdin=asyncio.subprocess.PIPE,
            start_new_session=True,
        )
        handle = ManagedProcessHandle(
            execution_id=request.correlation_id,
            process=proc,
            request=request,
            temporary_home=None,
        )
        spawned.append(handle)
        return handle

    service = ExecutionService(
        HostExecutionBackend(),
        manager,  # type: ignore[arg-type]
        managed_process_factory=factory,
    )
    return service, workspace, server


def _lsp_client(service, workspace, server, *, timeout: float = 2.0) -> LspClient:
    argv = (sys.executable, str(server))
    return LspClient(
        argv,
        execution_service=service,
        task_id="task",
        workspace_id="workspace",
        trusted_argv=argv,
        timeout=timeout,
    )


class _FakeLspProcess:
    """Fully fake ManagedProcess for LSP fault injection."""

    def __init__(self) -> None:
        self.execution_id = "fake-exec"
        self.returncode: int | None = None
        self.stderr_text = ""
        self.stderr_truncated = False
        self.stdin = SimpleNamespace()
        self._stdout = asyncio.StreamReader()
        self._closed = False

    @property
    def stdout(self):
        return self._stdout

    async def write_stdin(self, payload: bytes) -> None:
        if self._closed:
            raise RuntimeError("process closed")

    async def wait(self) -> int:
        if self.returncode is not None:
            return self.returncode
        await asyncio.sleep(0.05)
        return self.returncode or 0

    async def terminate(self) -> None:
        self.returncode = -15
        self._closed = True
        self._stdout.feed_eof()

    async def kill(self) -> None:
        self.returncode = -9
        self._closed = True
        self._stdout.feed_eof()

    def feed_response(self, request_id: int, result: object = None) -> None:
        """Feed a JSON-RPC response into the stdout StreamReader."""
        import json as _json
        msg = {"jsonrpc": "2.0", "id": request_id, "result": result}
        payload = _json.dumps(msg).encode("utf-8")
        header = f"Content-Length: {len(payload)}\r\n\r\n".encode("ascii")
        self._stdout.feed_data(header + payload)


async def test_lsp_close_then_start_rejected(tmp_path: Path) -> None:
    """start after close ⇒ reject."""
    service, workspace, server = _lsp_runtime(tmp_path)
    client = _lsp_client(service, workspace, server)
    await client.close()
    assert client.terminal_closed
    result = await client.start("file:///")
    assert result["ok"] is False
    assert result["diagnostic"].code == "closed"


async def test_lsp_concurrent_close_joins_same_task(tmp_path: Path) -> None:
    """concurrent close ⇒ all callers observe the same result."""
    service, workspace, server = _lsp_runtime(tmp_path)
    client = _lsp_client(service, workspace, server)
    # Start then concurrently close twice.
    await client.start(f"file://{workspace.worktree_path}")
    results = await asyncio.gather(
        client.close(),
        client.close(),
        return_exceptions=True,
    )
    assert all(not isinstance(r, Exception) for r in results), results
    assert client.terminal_closed
    assert client.owned_resources() == ()


async def test_lsp_first_close_failure_second_retry(tmp_path: Path) -> None:
    """first close failure → QUARANTINED; second close retry → CLOSED."""
    service, workspace, server = _lsp_runtime(tmp_path)
    client = _lsp_client(service, workspace, server)
    # Inject a fake process whose terminate fails on the first call.
    fake = _FakeLspProcess()
    service.start_managed_process = AsyncMock(return_value=fake)  # type: ignore[assignment]
    service.terminate = AsyncMock()  # type: ignore[assignment]
    # Pre-feed the initialize response so start() succeeds.
    fake.feed_response(1, {"capabilities": {}})
    await client.start(f"file://{workspace.worktree_path}")
    # Replace the real process with a fake whose terminate fails once.
    original_terminate = fake.terminate
    call_count = 0

    async def failing_terminate() -> None:
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            raise RuntimeError("transient terminate failure")
        await original_terminate()

    fake.terminate = failing_terminate  # type: ignore[assignment]

    # First close fails → QUARANTINED.
    with pytest.raises(LspCloseError):
        await client.close()
    assert client.is_quarantined
    assert not client.terminal_closed

    # Second close succeeds → CLOSED.
    await client.close()
    assert client.terminal_closed
    assert client.owned_resources() == ()


async def test_lsp_exec_terminate_failure_enters_quarantine(tmp_path: Path) -> None:
    """cleanup ordinary exception (exec_terminate) ⇒ QUARANTINED."""
    service, workspace, server = _lsp_runtime(tmp_path)
    client = _lsp_client(service, workspace, server)
    fake = _FakeLspProcess()
    service.start_managed_process = AsyncMock(return_value=fake)  # type: ignore[assignment]
    service.terminate = AsyncMock(side_effect=RuntimeError("exec terminate failed"))  # type: ignore[assignment]
    # Pre-feed the initialize response so start() succeeds.
    fake.feed_response(1, {"capabilities": {}})
    await client.start(f"file://{workspace.worktree_path}")

    with pytest.raises(LspCloseError):
        await client.close()
    assert client.is_quarantined
    assert not client.terminal_closed
    # process_terminate may be done, but exec_terminate is not.
    assert not client._cleanup_ledger.is_done("exec_terminate")


async def test_lsp_closed_implies_no_owned_resources(tmp_path: Path) -> None:
    """CLOSED ⇒ no live/owned resource."""
    service, workspace, server = _lsp_runtime(tmp_path)
    client = _lsp_client(service, workspace, server)
    await client.start(f"file://{workspace.worktree_path}")
    await client.close()
    assert client.terminal_closed
    assert client.terminal_postcondition()
    assert client.owned_resources() == ()


# ---------------------------------------------------------------------------
# BrowserEgressProxy closure tests
# ---------------------------------------------------------------------------


class _PinnedGuard:
    """Fake NetworkGuard that pins to a configurable address."""

    def __init__(self, address: str = "127.0.0.1") -> None:
        self.address = address
        self.urls: list[str] = []

    async def authorize_url(self, url: str) -> ValidatedTarget:
        self.urls.append(url)
        parsed = urlsplit(url)
        return ValidatedTarget(
            url=url,
            parsed=parsed,
            hostname=parsed.hostname or "",
            addresses=(self.address,),
        )


def _proxy_auth_header(proxy: BrowserEgressProxy) -> str:
    import base64

    credentials = f"{proxy.proxy_username}:{proxy.proxy_password}"
    encoded = base64.b64encode(credentials.encode("ascii")).decode("ascii")
    return f"Proxy-Authorization: Basic {encoded}\r\n"


async def test_proxy_start_after_close_rejected() -> None:
    """start after close ⇒ reject (admission fence)."""
    guard = _PinnedGuard()
    proxy = BrowserEgressProxy(guard)  # type: ignore[arg-type]
    await proxy.start()
    await proxy.close()
    assert proxy.terminal_closed
    # start() after close must raise — the admission fence is permanent.
    with pytest.raises(RuntimeError, match="cannot start"):
        await proxy.start()


async def test_proxy_concurrent_close_joins_same_task() -> None:
    """concurrent close ⇒ all callers observe the same result."""
    guard = _PinnedGuard()
    proxy = BrowserEgressProxy(guard)  # type: ignore[arg-type]
    await proxy.start()
    results = await asyncio.gather(
        proxy.close(),
        proxy.close(),
        return_exceptions=True,
    )
    assert all(not isinstance(r, Exception) for r in results), results
    assert proxy.terminal_closed
    assert proxy.owned_resources() == ()


async def test_proxy_start_during_close_rejected() -> None:
    """start during close (QUARANTINED) ⇒ reject.

    Once close() has begun and failed (QUARANTINED), start() is
    permanently forbidden — the admission fence is permanent.  This
    eliminates the spawn-after-close window even when close fails.

    Note: the lifecycle lock serializes concurrent start() and close(),
    so "start during close" is practically "start after close failed".
    The key invariant is that once ``admission_closed`` becomes True
    (CLOSING/QUARANTINED/CLOSED), start() is rejected.
    """
    guard = _PinnedGuard()
    proxy = BrowserEgressProxy(guard)  # type: ignore[arg-type]
    await proxy.start()
    # Manually transition to QUARANTINED to simulate a failed close.
    proxy._state = _ProxyState.QUARANTINED
    assert proxy.admission_closed
    assert not proxy.terminal_closed
    # start() must be rejected even in QUARANTINED.
    with pytest.raises(RuntimeError, match="cannot start"):
        await proxy.start()
    # Clean up — close the listener manually since close() would retry.
    if proxy._server is not None:
        proxy._server.close()
        try:
            await proxy._server.wait_closed()
        except Exception:  # noqa: BLE001
            pass
        proxy._server = None
    proxy._state = _ProxyState.CLOSED


async def test_proxy_first_close_failure_second_retry() -> None:
    """first close failure → QUARANTINED; second close retry → CLOSED.

    Injects a stale (already-done) task into ``_client_tasks`` that
    won't be removed by the ``_tracked_handler`` finally block.  The
    close code checks ``if self._client_tasks:`` after gather and
    records an error because the set is non-empty — simulating a
    handler that wasn't properly cleaned up.
    """
    guard = _PinnedGuard()
    proxy = BrowserEgressProxy(guard)  # type: ignore[arg-type]
    await proxy.start()

    # Create a done task and add it to _client_tasks.  It won't be
    # removed by the tracked_handler finally block (because it's not a
    # real tracked handler), so _client_tasks remains non-empty after
    # gather → handlers_drain fails → QUARANTINED.
    async def _noop() -> None:
        pass

    stale_task = asyncio.create_task(_noop())
    await stale_task  # ensure it's done
    proxy._client_tasks.add(stale_task)

    # First close fails → QUARANTINED (handlers_drain postcondition).
    with pytest.raises(RuntimeError, match="partially failed"):
        await proxy.close()
    assert proxy.is_quarantined
    assert not proxy.terminal_closed

    # Remove the stale task so the retry can succeed.
    proxy._client_tasks.discard(stale_task)

    # Second close succeeds → CLOSED.
    await proxy.close()
    assert proxy.terminal_closed
    assert proxy.owned_resources() == ()


async def test_proxy_closed_implies_no_owned_resources() -> None:
    """CLOSED ⇒ no live/owned resource."""
    guard = _PinnedGuard()
    proxy = BrowserEgressProxy(guard)  # type: ignore[arg-type]
    await proxy.start()
    await proxy.close()
    assert proxy.terminal_closed
    assert proxy.terminal_postcondition()
    assert proxy.owned_resources() == ()


async def test_browser_manager_closed_has_empty_external_inventory() -> None:
    """BrowserManager is a first-class owner even when no browser was launched."""
    manager = BrowserManager()
    result = await manager.close()
    assert result["ok"] is True
    assert manager.terminal_closed
    assert manager.terminal_postcondition()
    assert manager.owned_resources() == ()


def test_runtime_result_terminal_proof_requires_child_owner_oracle() -> None:
    """RuntimeResult cannot claim CLOSED while a child owner retains state."""

    class ChildOwner:
        terminal_closed = True

        def __init__(self) -> None:
            self.resources = ("child:live",)

        def owned_resources(self) -> tuple[str, ...]:
            return self.resources

        def terminal_postcondition(self) -> bool:
            return self.terminal_closed and not self.resources

    child = ChildOwner()
    runtime = RuntimeResult(
        loop=SimpleNamespace(),
        mode_manager=SimpleNamespace(),
        task_manager=None,
        skill_generator=None,
        tool_scheduler=SimpleNamespace(),
        memory_manager=SimpleNamespace(),
        skill_manager=SimpleNamespace(),
        new_verify_fix_loop=None,
        execution_service=child,
    )
    runtime._close_state = CloseState.CLOSED
    runtime._closed = True
    assert not runtime.terminal_closed
    assert runtime.owned_resources() == ("execution_service:child:live",)
    child.resources = ()
    assert runtime.terminal_closed
    assert runtime.terminal_postcondition()
    assert runtime.owned_resources() == ()


class _RetryableRelayWriter:
    """Writer oracle that fails once, then proves terminal on retry."""

    def __init__(self) -> None:
        self.close_calls = 0
        self.wait_closed_calls = 0

    def close(self) -> None:
        self.close_calls += 1

    async def wait_closed(self) -> None:
        self.wait_closed_calls += 1
        if self.wait_closed_calls == 1:
            raise OSError("upstream close transient failure")


async def test_proxy_retries_retained_relay_lease_after_handler_failure() -> None:
    """A failed handler lease remains owned and is retried by proxy.close()."""
    guard = _PinnedGuard()
    proxy = BrowserEgressProxy(guard)  # type: ignore[arg-type]
    writer = _RetryableRelayWriter()
    lease = _RelayLease(writer)  # type: ignore[arg-type]
    proxy._relay_leases.add(lease)
    proxy._upstream_writers.add(writer)  # type: ignore[arg-type]

    with pytest.raises(RuntimeError, match="partially failed"):
        await proxy.close()
    assert proxy.is_quarantined
    assert not proxy.terminal_closed
    assert lease in proxy._relay_leases
    assert proxy.owned_resources()

    await proxy.close()
    assert proxy.terminal_closed
    assert proxy.terminal_postcondition()
    assert proxy.owned_resources() == ()
    assert writer.wait_closed_calls >= 2


async def test_proxy_new_state_admission_open() -> None:
    """NEW state: admission NOT closed, terminal NOT closed."""
    guard = _PinnedGuard()
    proxy = BrowserEgressProxy(guard)  # type: ignore[arg-type]
    assert not proxy.admission_closed
    assert not proxy.terminal_closed
    assert not proxy.is_quarantined


async def test_proxy_open_state_admission_closed() -> None:
    """OPEN state: admission closed (no re-start), terminal NOT closed."""
    guard = _PinnedGuard()
    proxy = BrowserEgressProxy(guard)  # type: ignore[arg-type]
    await proxy.start()
    assert proxy.admission_closed  # start() is now forbidden
    assert not proxy.terminal_closed  # but not CLOSED yet
    assert not proxy.is_quarantined
    await proxy.close()
