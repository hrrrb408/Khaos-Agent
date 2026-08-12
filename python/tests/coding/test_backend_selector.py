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


def test_windows_missing_native_helper_is_unsupported(monkeypatch):
    monkeypatch.setattr("khaos.coding.execution.platform.sys.platform", "win32")
    monkeypatch.setattr(
        "khaos.coding.execution.platform._windows_sandbox_helper",
        lambda: None,
    )

    backend = BackendSelector().select(writable=True)

    assert isinstance(backend, UnsupportedBackend)
    assert "Host fallback is forbidden" in backend.reason


def test_windows_failed_native_probe_is_unsupported(monkeypatch):
    from khaos.coding.execution.platform import (
        BackendAvailability,
        WindowsSandboxBackend,
    )

    monkeypatch.setattr("khaos.coding.execution.platform.sys.platform", "win32")
    monkeypatch.setattr(
        "khaos.coding.execution.platform._windows_sandbox_helper",
        lambda: object(),
    )
    monkeypatch.setattr(
        WindowsSandboxBackend,
        "probe_capability",
        lambda self: BackendAvailability(
            self.name,
            False,
            False,
            "native Windows probe failed",
        ),
    )

    backend = BackendSelector().select(writable=True)

    assert isinstance(backend, UnsupportedBackend)
    assert "native Windows probe failed" in backend.reason


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
