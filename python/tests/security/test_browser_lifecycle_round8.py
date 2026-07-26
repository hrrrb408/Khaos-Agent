"""Round 8 browser launch and cleanup transaction regressions."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from khaos.security.browser_sandbox import CleanupResult, EnforcementStatus
from khaos.tools import browser_tools
from khaos.tools.browser_tools import BrowserManager


@pytest.mark.asyncio
async def test_failed_sandbox_setup_permanently_blocks_generation(monkeypatch) -> None:
    launches = {"count": 0}

    class FailedSandbox:
        enforcement_status = EnforcementStatus(failure_reason="setup failed")
        is_active = False

        def __init__(self, **_: object) -> None:
            pass

        @staticmethod
        def startup_reaper() -> dict[str, int]:
            return {}

        def setup(self) -> None:
            raise RuntimeError("injected setup failure")

        def teardown(self) -> CleanupResult:
            return CleanupResult(fully_closed=True)

    class Chromium:
        executable_path = "/chromium"

        async def launch(self, **_: object) -> object:
            launches["count"] += 1
            return object()

    class Starter:
        async def start(self) -> object:
            return SimpleNamespace(chromium=Chromium())

    monkeypatch.setattr(browser_tools, "_HAS_PLAYWRIGHT", True)
    monkeypatch.setattr(browser_tools, "BrowserNetworkSandbox", FailedSandbox)
    monkeypatch.setattr(browser_tools, "async_playwright", lambda: Starter())
    monkeypatch.delenv("KHAOS_BROWSER_DEV_MODE", raising=False)

    manager = BrowserManager()
    first = await manager.launch()
    second = await manager.launch()
    assert not first["ok"] and "injected setup failure" in first["error"]
    assert not second["ok"] and "quarantined" in second["error"]
    assert manager._browser_sandbox is None
    assert launches["count"] == 0


@pytest.mark.asyncio
async def test_manager_retains_sandbox_when_cleanup_is_partial() -> None:
    class ResidualSandbox:
        def teardown(self) -> CleanupResult:
            return CleanupResult(
                nft_removed=False,
                registry_retained=True,
                fully_closed=False,
            )

    manager = BrowserManager()
    sandbox = ResidualSandbox()
    manager._browser_sandbox = sandbox  # type: ignore[assignment]
    result = await manager.close()
    assert result["ok"] is False
    assert result["cleanup"]["fully_closed"] is False
    assert manager._browser_sandbox is sandbox
    assert manager._closed is False


@pytest.mark.asyncio
async def test_context_revokes_nft_before_proxy_and_context_close() -> None:
    events: list[str] = []

    class Sandbox:
        is_active = True

        def remove_egress_port(self, port: int) -> None:
            assert port == 43210
            events.append("nft")

    class Proxy:
        async def close(self) -> None:
            events.append("proxy")

    class Context:
        async def close(self) -> None:
            events.append("context")

    manager = BrowserManager()
    manager._browser_sandbox = Sandbox()  # type: ignore[assignment]
    manager._contexts["owner"] = {
        "context": Context(),
        "egress_proxy": Proxy(),
        "egress_port": 43210,
        "refcount": 1,
    }
    await manager._close_one_context("owner", force=True)
    assert events == ["nft", "proxy", "context"]
    assert "owner" not in manager._contexts


@pytest.mark.asyncio
async def test_browser_process_generation_rejects_second_principal() -> None:
    manager = BrowserManager()
    manager._process_principal = "alice"

    page = await manager.ensure_page(
        "bob", session_id="s", runtime_id="r",
    )

    assert page is None
    assert "cross-principal process sharing" in manager._last_ensure_error
