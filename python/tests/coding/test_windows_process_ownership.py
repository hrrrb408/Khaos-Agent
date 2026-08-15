"""Deterministic lifecycle tests for the Windows native helper owner."""

from __future__ import annotations

import asyncio
from contextlib import suppress

import pytest
from khaos.coding.execution import platform as platform_module
from khaos.coding.execution.platform import (
    WindowsSandboxBackend,
    _WindowsOwnedProcess,
)


class _FakeStdin:
    def __init__(self) -> None:
        self.closed = False
        self.writes: list[bytes] = []

    def write(self, data: bytes) -> None:
        self.writes.append(data)

    async def drain(self) -> None:
        return None

    def close(self) -> None:
        self.closed = True


class _FakeProcess:
    def __init__(
        self,
        *,
        result: int = 0,
        wait_error: BaseException | None = None,
        wait_gate: asyncio.Event | None = None,
        kill_error: BaseException | None = None,
    ) -> None:
        self.returncode: int | None = None
        self.stdin = _FakeStdin()
        self._result = result
        self._wait_error = wait_error
        self._wait_gate = wait_gate
        self._kill_error = kill_error
        self.kill_calls = 0

    async def wait(self) -> int:
        if self._wait_gate is not None:
            await self._wait_gate.wait()
        if self._wait_error is not None:
            raise self._wait_error
        self.returncode = self._result
        return self._result

    def kill(self) -> None:
        self.kill_calls += 1
        if self._kill_error is not None:
            raise self._kill_error
        if self._wait_gate is not None:
            self._wait_gate.set()


async def _publish(
    backend: WindowsSandboxBackend,
    execution_id: str,
    process: _FakeProcess,
) -> _WindowsOwnedProcess:
    pending = await backend._reserve_spawn(execution_id)
    return await backend._publish_process(execution_id, pending, process)


@pytest.mark.asyncio
async def test_spawn_cancellation_keeps_pending_owner_until_process_is_adopted():
    backend = WindowsSandboxBackend()
    pending = await backend._reserve_spawn("cancel-before-publish")
    gate = asyncio.Event()
    process = _FakeProcess(wait_gate=gate)

    async def spawn() -> _FakeProcess:
        await asyncio.sleep(0)
        await gate.wait()
        return process

    pending.spawn_task = asyncio.create_task(spawn())
    adoption = asyncio.create_task(backend._await_spawn_result(pending))
    await asyncio.sleep(0)
    adoption.cancel()
    gate.set()

    assert await adoption is process
    assert pending.termination_requested is True
    owner = await backend._publish_process("cancel-before-publish", pending, process)
    await backend._terminate_process("cancel-before-publish")

    assert owner.reaped_return_code == 0
    assert backend.owned_resources() == ()


@pytest.mark.asyncio
async def test_failed_wait_retains_orphan_instead_of_false_closed_state():
    backend = WindowsSandboxBackend()
    owner = await _publish(
        backend,
        "wait-fails",
        _FakeProcess(wait_error=RuntimeError("wait proof failed")),
    )

    with pytest.raises(RuntimeError, match="wait proof failed"):
        await backend._terminate_process("wait-fails")

    assert backend.owned_resources() == ("windows-helper-orphan:wait-fails",)
    assert backend.is_quarantined is True
    assert backend.terminal_closed is False
    assert owner.process.returncode is None


@pytest.mark.asyncio
async def test_kill_then_wait_proves_terminal_owner_and_allows_close(monkeypatch):
    backend = WindowsSandboxBackend()
    process = _FakeProcess(result=137, wait_gate=asyncio.Event())
    owner = await _publish(backend, "kill-wait", process)
    original_wait_for = platform_module.asyncio.wait_for
    wait_for_calls = 0

    async def timeout_once(awaitable, timeout):
        nonlocal wait_for_calls
        wait_for_calls += 1
        if wait_for_calls == 1:
            raise TimeoutError()
        return await original_wait_for(awaitable, timeout)

    monkeypatch.setattr(platform_module.asyncio, "wait_for", timeout_once)
    await backend._terminate_process("kill-wait")
    await backend.close()

    assert process.kill_calls == 1
    assert owner.reaped_return_code == 137
    assert backend.state == "closed"
    assert backend.terminal_closed is True


@pytest.mark.asyncio
async def test_pending_owner_disappearance_retains_late_process_as_orphan():
    backend = WindowsSandboxBackend()
    pending = await backend._reserve_spawn("late-process")
    await backend._finish_pending_spawn(
        "late-process", pending, error=RuntimeError("pending owner closed")
    )

    with pytest.raises(RuntimeError, match="pending owner disappeared"):
        await backend._publish_process(
            "late-process", pending, _FakeProcess(result=0)
        )

    assert backend.owned_resources() == ("windows-helper-orphan:late-process",)
    await backend._terminate_process("late-process")
    assert backend.owned_resources() == ()
    assert backend.terminal_closed is False


@pytest.mark.asyncio
async def test_close_closes_admission_before_cleanup_and_rejects_new_spawn():
    backend = WindowsSandboxBackend()
    await backend.close()

    assert backend.state == "closed"
    with pytest.raises(PermissionError, match="spawn refused"):
        await backend._reserve_spawn("after-close")


@pytest.mark.asyncio
async def test_failed_kill_keeps_wait_task_and_orphan_for_retry():
    backend = WindowsSandboxBackend()
    gate = asyncio.Event()
    owner = await _publish(
        backend,
        "kill-fails",
        _FakeProcess(
            wait_gate=gate,
            kill_error=RuntimeError("kill failed"),
        ),
    )
    original_wait_for = platform_module.asyncio.wait_for

    async def always_timeout(awaitable, timeout):
        del timeout
        raise TimeoutError()

    monkeypatch = pytest.MonkeyPatch()
    monkeypatch.setattr(platform_module.asyncio, "wait_for", always_timeout)
    try:
        with pytest.raises(RuntimeError, match="kill failed"):
            await backend._terminate_process("kill-fails")
    finally:
        monkeypatch.setattr(platform_module.asyncio, "wait_for", original_wait_for)
        assert owner.wait_task is not None
        owner.wait_task.cancel()
        with suppress(asyncio.CancelledError):
            await owner.wait_task

    assert backend.owned_resources() == ("windows-helper-orphan:kill-fails",)
    assert backend.terminal_closed is False
