import asyncio
import time

import pytest
from khaos.coding.execution import BackendSelector, UnsupportedBackend


@pytest.mark.asyncio
async def test_selector_never_uses_host_for_write_without_platform_sandbox(monkeypatch):
    monkeypatch.setattr("khaos.coding.execution.platform.sys.platform", "unknown")
    assert isinstance(BackendSelector().select(writable=True), UnsupportedBackend)


@pytest.mark.asyncio
async def test_async_selector_does_not_block_event_loop(monkeypatch):
    selector = BackendSelector()
    monkeypatch.setattr(
        selector,
        "select",
        lambda *, writable: (time.sleep(0.08), UnsupportedBackend())[1],
    )
    ticks: list[float] = []

    async def heartbeat() -> None:
        await asyncio.sleep(0.01)
        ticks.append(time.monotonic())

    await asyncio.gather(selector.select_async(writable=True), heartbeat())
    assert ticks


def test_selector_never_uses_host_for_read_without_platform_sandbox(monkeypatch):
    monkeypatch.setattr("khaos.coding.execution.platform.sys.platform", "unknown")
    assert isinstance(BackendSelector().select(writable=False), UnsupportedBackend)


@pytest.mark.asyncio
@pytest.mark.windows_fail_closed
async def test_windows_never_falls_back_to_host(monkeypatch):
    monkeypatch.setattr("khaos.coding.execution.platform.sys.platform", "win32")

    backend = BackendSelector().select(writable=True)
    availability = await backend.probe()

    if isinstance(backend, UnsupportedBackend):
        assert "Windows" in availability.reason
        assert availability.available is False
        assert availability.network_enforced is False
        with pytest.raises(PermissionError, match="Windows"):
            await backend.execute(object())
    else:
        from khaos.coding.execution import WindowsSandboxBackend

        assert isinstance(backend, WindowsSandboxBackend)
        assert availability.available is True
        assert availability.network_enforced is True
