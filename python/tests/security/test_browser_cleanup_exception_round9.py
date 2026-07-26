"""Batch 9.4 (round-9 §十三): cleanup exception closure regressions.

Round-8 correctly propagated PARTIAL cleanup results (CleanupResult with
fully_closed=False), but if ``teardown()`` itself RAISED an unexpected
exception, both ``close()`` and ``_force_close_browser_locked()`` would
log the error and then continue to:

* drop the sandbox reference (``_browser_sandbox = None``);
* clear the context authority map;
* return ``{"ok": True}`` (close) or fall through to ``ok: True`` (force).

This is a fail-open result: the kernel resource state is unknown, yet the
caller is told the manager is closed.  These tests verify teardown
exceptions now produce a fail-closed result with the sandbox reference
and context map retained.
"""

from __future__ import annotations

import pytest

from khaos.tools.browser_tools import BrowserManager


class _RaisingSandbox:
    """A sandbox whose teardown() always raises."""

    is_active = True

    def teardown(self):
        raise RuntimeError("injected teardown failure")


class _RaisingContext:
    async def close(self) -> None:
        pass


class _RaisingProxy:
    async def close(self) -> None:
        pass


@pytest.mark.asyncio
async def test_normal_close_retains_sandbox_when_teardown_raises() -> None:
    """close() must return ok=False and keep _browser_sandbox when teardown raises."""
    manager = BrowserManager()
    sandbox = _RaisingSandbox()
    manager._browser_sandbox = sandbox  # type: ignore[assignment]
    # Give it a context so the close path has something to enumerate.
    manager._contexts["owner"] = {
        "context": _RaisingContext(),
        "egress_proxy": _RaisingProxy(),
        "egress_port": None,
        "refcount": 1,
    }

    result = await manager.close()

    assert result["ok"] is False, (
        "close() must NOT report success when teardown raises"
    )
    assert "teardown raised" in result["error"], result
    assert result.get("quarantined") is True, (
        "close() must mark the sandbox quarantined on teardown exception"
    )
    # The sandbox reference MUST be retained so the startup Reaper can
    # recover the residual netns/veth/cgroup/nft on next launch.
    assert manager._browser_sandbox is sandbox, (
        "close() must NOT drop _browser_sandbox when teardown raises"
    )
    # _closed must stay False so the next close() retries.
    assert manager._closed is False, (
        "close() must NOT set _closed when teardown raises"
    )
    assert manager._close_failed is True


@pytest.mark.asyncio
async def test_force_close_returns_failure_when_teardown_raises() -> None:
    """_force_close_browser_locked() must return ok=False when teardown raises.

    Note: force-close first best-effort closes every context's proxy+port
    (via _close_all_contexts), THEN attempts sandbox teardown.  So when
    teardown raises, the per-context proxies are already gone — the
    critical invariant is that the SANDBOX reference is retained and the
    result reports failure, NOT that the context map is preserved.
    """
    manager = BrowserManager()
    sandbox = _RaisingSandbox()
    manager._browser_sandbox = sandbox  # type: ignore[assignment]
    # Give it a context so the force-close path has something to close.
    manager._contexts["owner"] = {
        "context": _RaisingContext(),
        "egress_proxy": _RaisingProxy(),
        "egress_port": None,
        "refcount": 1,
    }

    result = await manager._force_close_browser_locked()

    assert result["ok"] is False, (
        "force-close must NOT report success when teardown raises"
    )
    assert "teardown raised" in result["error"], result
    assert result.get("quarantined") is True
    # The sandbox reference MUST be retained so the startup Reaper can
    # recover the residual netns/veth/cgroup/nft on next launch.
    assert manager._browser_sandbox is sandbox, (
        "force-close must NOT drop _browser_sandbox when teardown raises"
    )
    assert manager._close_failed is True


@pytest.mark.asyncio
async def test_normal_close_succeeds_when_teardown_is_clean() -> None:
    """Regression guard: a clean teardown still reports ok=True and _closed."""
    from khaos.security.browser_sandbox import CleanupResult

    class CleanSandbox:
        is_active = True

        def teardown(self) -> CleanupResult:
            return CleanupResult(fully_closed=True)

    manager = BrowserManager()
    manager._browser_sandbox = CleanSandbox()  # type: ignore[assignment]

    result = await manager.close()

    assert result["ok"] is True
    assert manager._closed is True
    assert manager._browser_sandbox is None
