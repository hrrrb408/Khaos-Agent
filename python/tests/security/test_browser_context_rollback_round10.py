"""Batch 10.2 (round-10 §五): context creation nft pin rollback regressions.

Context creation installs an nft egress pin (kernel authority) BEFORE
``new_context`` / route guard / ``new_page``.  If any of those later steps
fail, the pin must be revoked — otherwise a host process can rebind the
freed port and become reachable from the browser netns.

These tests inject failures at each step and verify the rollback runs the
proven order (remove_egress_port → proxy.close → context.close) and leaves
no residual kernel authority or context entry.
"""

from __future__ import annotations

import asyncio
from typing import Any

import pytest

from khaos.tools import browser_tools
from khaos.tools.browser_tools import BrowserManager


class _FakeProxy:
    """Minimal egress proxy stub that records close() calls."""

    def __init__(self) -> None:
        self.server_url = "http://127.0.0.1:43210"
        self.proxy_username = "u"
        self.proxy_password = "p"
        self.closed = False

    async def start(self) -> None:
        pass

    async def close(self) -> None:
        self.closed = True


class _FakeContext:
    def __init__(self, *, new_page_raises: bool = False) -> None:
        self._new_page_raises = new_page_raises
        self.closed = False

    async def close(self) -> None:
        self.closed = True

    async def new_page(self) -> Any:
        if self._new_page_raises:
            raise RuntimeError("injected new_page failure")
        return object()


class _FakeBrowser:
    def __init__(self, *, new_context_raises: bool = False) -> None:
        self._new_context_raises = new_context_raises
        self._context = _FakeContext()

    async def new_context(self, **_: object) -> _FakeContext:
        if self._new_context_raises:
            raise RuntimeError("injected new_context failure")
        return self._context


def _manager_with_active_sandbox(monkeypatch) -> BrowserManager:
    """A BrowserManager with an active sandbox whose remove_egress_port is
    a no-op stub (tests assert it was called)."""
    manager = BrowserManager()

    class _Sandbox:
        is_active = True
        proxy_bind_host = "127.0.0.1"

        def install_egress_pin(self, port: int) -> None:
            pass

        def remove_egress_port(self, port: int) -> None:
            pass

    sandbox = _Sandbox()
    manager._browser_sandbox = sandbox  # type: ignore[assignment]
    manager._browser = _FakeBrowser()  # type: ignore[assignment]
    # Spy on remove_egress_port so tests can assert it was called.
    calls: list[int] = []
    original_remove = sandbox.remove_egress_port

    def tracking_remove(port: int) -> None:
        calls.append(port)
        original_remove(port)

    sandbox.remove_egress_port = tracking_remove  # type: ignore[method-assign]
    manager._rollback_test_calls = calls  # type: ignore[attr-defined]
    return manager


@pytest.mark.asyncio
async def test_new_context_failure_rolls_back_nft_pin(monkeypatch) -> None:
    """new_context() failure after install_egress_pin → pin revoked."""
    manager = _manager_with_active_sandbox(monkeypatch)
    manager._browser = _FakeBrowser(new_context_raises=True)  # type: ignore[assignment]
    # Patch BrowserEgressProxy so we can observe close().
    fake_proxy = _FakeProxy()
    monkeypatch.setattr(
        browser_tools, "BrowserEgressProxy", lambda *a, **k: fake_proxy
    )

    with pytest.raises(RuntimeError, match="new_context"):
        await manager._ensure_page_locked(
            "p:s:r",
            principal_id="p",
            runtime_id="r",
            network_guard=None,
        )

    assert manager._rollback_test_calls == [43210], (
        "remove_egress_port must be called on new_context failure"
    )
    assert fake_proxy.closed, "proxy must be closed on rollback"
    assert "p:s:r" not in manager._contexts


@pytest.mark.asyncio
async def test_new_page_failure_rolls_back_nft_pin(monkeypatch) -> None:
    """new_page() failure → full rollback including nft pin."""
    manager = _manager_with_active_sandbox(monkeypatch)
    manager._browser = _FakeBrowser()  # type: ignore[assignment]
    manager._browser._context = _FakeContext(new_page_raises=True)  # type: ignore[attr-defined]
    fake_proxy = _FakeProxy()
    monkeypatch.setattr(
        browser_tools, "BrowserEgressProxy", lambda *a, **k: fake_proxy
    )

    result = await manager._ensure_page_locked(
        "p:s:r",
        principal_id="p",
        runtime_id="r",
        network_guard=None,
    )

    assert result is None, "new_page failure must return None"
    assert manager._last_ensure_error == "Browser page creation failed"
    assert manager._rollback_test_calls == [43210], (
        "remove_egress_port must be called on new_page failure"
    )
    assert fake_proxy.closed, "proxy must be closed on rollback"
    assert manager._browser._context.closed, "context must be closed"  # type: ignore[attr-defined]
    assert "p:s:r" not in manager._contexts


@pytest.mark.asyncio
async def test_failed_pin_rollback_quarantines_generation(monkeypatch) -> None:
    """If remove_egress_port raises during rollback, the proxy socket is
    RETAINED (not closed) and the generation is quarantined."""
    manager = _manager_with_active_sandbox(monkeypatch)

    class _FailingSandbox:
        is_active = True
        proxy_bind_host = "127.0.0.1"

        def install_egress_pin(self, port: int) -> None:
            pass

        def remove_egress_port(self, port: int) -> None:
            raise RuntimeError("injected nft rollback failure")

    manager._browser_sandbox = _FailingSandbox()  # type: ignore[assignment]
    manager._browser = _FakeBrowser(new_context_raises=True)  # type: ignore[assignment]
    fake_proxy = _FakeProxy()
    monkeypatch.setattr(
        browser_tools, "BrowserEgressProxy", lambda *a, **k: fake_proxy
    )

    with pytest.raises(RuntimeError, match="new_context"):
        await manager._ensure_page_locked(
            "p:s:r",
            principal_id="p",
            runtime_id="r",
            network_guard=None,
        )

    assert manager._sandbox_generation_failed is True, (
        "rollback failure must quarantine the generation"
    )
    assert not fake_proxy.closed, (
        "proxy socket must be RETAINED when remove_egress_port fails "
        "(stale-open kernel rule is safer than a stale-closed one)"
    )
