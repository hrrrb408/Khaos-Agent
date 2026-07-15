import pytest

from khaos.coding.execution import BackendSelector, UnsupportedBackend


@pytest.mark.asyncio
async def test_selector_never_uses_host_for_write_without_platform_sandbox(monkeypatch):
    monkeypatch.setattr("khaos.coding.execution.platform.sys.platform", "unknown")
    assert isinstance(BackendSelector().select(writable=True), UnsupportedBackend)


def test_selector_never_uses_host_for_read_without_platform_sandbox(monkeypatch):
    monkeypatch.setattr("khaos.coding.execution.platform.sys.platform", "unknown")
    assert isinstance(BackendSelector().select(writable=False), UnsupportedBackend)


@pytest.mark.asyncio
@pytest.mark.windows_fail_closed
async def test_windows_is_explicitly_unsupported_and_fails_closed(monkeypatch):
    monkeypatch.setattr("khaos.coding.execution.platform.sys.platform", "win32")

    backend = BackendSelector().select(writable=True)
    availability = await backend.probe()

    assert isinstance(backend, UnsupportedBackend)
    assert "Windows" in availability.reason
    with pytest.raises(PermissionError, match="Windows"):
        await backend.execute(object())
