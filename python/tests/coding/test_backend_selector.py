import pytest

from khaos.coding.execution import BackendSelector, UnsupportedBackend


@pytest.mark.asyncio
async def test_selector_never_uses_host_for_write_without_platform_sandbox(monkeypatch):
    monkeypatch.setattr("khaos.coding.execution.platform.sys.platform", "unknown")
    assert isinstance(BackendSelector().select(writable=True), UnsupportedBackend)
