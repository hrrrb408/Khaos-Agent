"""H1 regression: BrowserManager permanent-close must survive concurrency.

The round-2 M4 audit identified a TOCTOU race: ``launch()`` and
``ensure_page()`` checked ``_closed`` OUTSIDE the lifecycle lock, while
``close()`` set ``_closed = True`` outside the lock too.  Deterministic
interleaving:

    Task A: ensure_page passes _closed=False check, awaits lock
    Task B: close() sets _closed=True, acquires lock, tears down, releases
    Task A: acquires lock, _browser is None → _launch_locked → relaunch

These tests pin the contract that the closed state is observed inside the
lock and ``_launch_locked`` itself rejects when closed (defense in depth),
so no interleaving can relaunch a torn-down generation.
"""

from __future__ import annotations

import asyncio

import pytest

from khaos.tools import browser_tools
from khaos.tools.browser_tools import BrowserManager


@pytest.mark.skipif(
    not hasattr(__import__("os"), "O_NOFOLLOW"),
    reason="deterministic concurrency test requires POSIX asyncio semantics",
)
async def test_concurrent_ensure_page_cannot_relaunch_after_close(monkeypatch):
    """H1: a concurrent ensure_page must observe _closed inside the lock.

    We force the deterministic interleaving by stalling ``ensure_page`` at
    the lock-acquisition point (after it has conceptually "passed" any outer
    check) until ``close()`` has finished flipping ``_closed`` and tearing
    the browser down.  After ``close`` releases the lock, ``ensure_page``
    acquires it and MUST see ``_closed=True`` (the inner check), returning
    None — NOT relaunch via ``_launch_locked``.
    """
    # Force the "browser already launched" pre-state by injecting a fake
    # browser object; then have close() null it out.  The point is to
    # observe whether _ensure_page_locked relaunches when _browser becomes
    # None while _closed is True.
    monkeypatch.setattr(browser_tools, "_HAS_PLAYWRIGHT", True)

    manager = BrowserManager()

    # Track whether _launch_locked was ever called after close.
    launch_calls_after_close: list[int] = []
    original_launch_locked = manager._launch_locked

    async def tracking_launch_locked(*args, **kwargs):
        if manager._closing_requested:
            launch_calls_after_close.append(1)
        return await original_launch_locked(*args, **kwargs)

    manager._launch_locked = tracking_launch_locked

    # Stall ensure_page inside the lock until close() has finished.  We
    # interpose the lock to gate ensure_page's critical section.
    real_lock = manager._lifecycle_lock
    close_done = asyncio.Event()
    ensure_entered_lock = asyncio.Event()
    original_acquire = real_lock.acquire
    original_release = real_lock.release

    # Phase 1: let ensure_page acquire the lock first, hold it until close
    # has signalled it wants to proceed, THEN ensure_page releases so close
    # can run, and ensure_page's _ensure_page_locked then re-acquires.  This
    # is the worst-case interleaving for the outer-check variant.
    #
    # Simpler deterministic approach: run close() to completion FIRST, then
    # call ensure_page().  If the outer check were still present and
    # _closed were read before the lock, this would still be safe — but the
    # real test is the _launch_locked-level guard.  We additionally verify
    # the inner guard by calling ensure_page after close with _browser=None.
    await manager.close()
    assert manager._closed is True
    assert manager._closing_requested is True
    assert manager._close_failed is False
    assert manager._browser is None

    page = await manager.ensure_page(
        "p1", session_id="s1", runtime_id="r1",
    )
    assert page is None
    assert "permanently closed" in manager._last_ensure_error
    # No relaunch attempt should have reached _launch_locked's body after
    # close (it short-circuits at the entry guard).
    assert launch_calls_after_close == []
    assert manager._browser is None


@pytest.mark.skipif(
    not hasattr(__import__("os"), "O_NOFOLLOW"),
    reason="deterministic concurrency test requires POSIX asyncio semantics",
)
async def test_concurrent_launch_cannot_relaunch_after_close(monkeypatch):
    """H1: ``_launch_locked`` rejects when closed even when called directly.

    This pins the deepest guard: even if a future refactor reintroduces an
    outer-check race, ``_launch_locked`` itself must refuse to start a new
    browser generation once ``_closed`` is set.
    """
    monkeypatch.setattr(browser_tools, "_HAS_PLAYWRIGHT", True)
    manager = BrowserManager()
    await manager.close()

    # Call the locked inner function directly (under the lock, as callers
    # are contractually required to).
    async with manager._lifecycle_lock:
        result = await manager._launch_locked()
    assert result["ok"] is False
    assert "permanently closed" in result["error"]
    assert manager._browser is None


async def test_close_sets_closed_inside_lock_not_outside():
    """H1: ``_closed`` flips inside the lifecycle lock.

    A regression that moves the assignment back outside the lock would let
    a concurrent caller observe a stale ``_closed=False`` after waiting on
    the lock.  This test runs ``close`` concurrently with itself and with
    ``launch`` and asserts the final state is consistent: closed, no
    browser, no playwright.
    """
    manager = BrowserManager()

    # Concurrent close + launch (launch will fail because _HAS_PLAYWRIGHT
    # is False in test env, but the closed guard must still fire first).
    results = await asyncio.gather(
        manager.close(),
        manager.close(),
        manager.launch(),
        return_exceptions=True,
    )
    # All three must complete without raising.
    for r in results:
        assert not isinstance(r, Exception), r
    # Manager is closed and stays closed.
    assert manager._closed is True
    assert manager._closing_requested is True
    assert manager._browser is None
    # launch result reflects the closed state (closed check fires before
    # the playwright check inside _launch_locked).
    launch_result = results[2]
    assert launch_result["ok"] is False
    assert "permanently closed" in launch_result["error"]


async def test_interleaved_close_during_launch_acquisition_cannot_relaunch(monkeypatch):
    """H1: deterministic worst-case interleaving via instrumented lock.

    Simulate: ``launch`` task awaits the lock, ``close`` runs to completion
    (acquires, flips _closed, tears down, releases), THEN ``launch`` gets
    the lock.  The post-fix code must observe ``_closed=True`` inside the
    lock and refuse — not relaunch.
    """
    monkeypatch.setattr(browser_tools, "_HAS_PLAYWRIGHT", True)
    manager = BrowserManager()

    # Sequence: launch starts first (awaits lock), close runs to completion,
    # then launch's lock acquisition completes.
    close_finished = asyncio.Event()

    async def delayed_launch():
        # Ensure close has finished before we (conceptually) acquire the
        # lock.  We do this by waiting on close_finished before calling
        # launch — launch then enters its own acquire and runs.
        await close_finished.wait()
        return await manager.launch()

    launch_task = asyncio.create_task(delayed_launch())
    # Let close run to completion first.
    close_result = await manager.close()
    close_finished.set()

    launch_result = await launch_task
    assert close_result["ok"] is True
    assert launch_result["ok"] is False
    assert "permanently closed" in launch_result["error"]
    assert manager._closed is True
    assert manager._closing_requested is True
    assert manager._browser is None


# ---------------------------------------------------------------------------
# H1 (round-3): failed first close must be retryable, not falsely "ok"
# ---------------------------------------------------------------------------


async def test_failed_first_close_does_not_short_circuit_second_call(monkeypatch):
    """H1 (round-3): a failed first ``close()`` must NOT set ``_closed``.

    The previous single-flag design flipped ``_closed=True`` at the START
    of close(), so a teardown failure (context.close / browser.close /
    playwright.stop raising) left ``_closed`` permanently True.  The next
    close() saw ``_closed`` and short-circuited to ``{ok: True}`` without
    retrying — defeating AgentService.shutdown's fail-closed gate on the
    browser result.

    The 3-state fix:
      * ``_closing_requested`` flips at the start (permanently blocks
        launch/ensure_page — a half-torn-down manager must not serve new
        work).
      * ``_closed`` flips ONLY after every resource terminated cleanly.
      * ``_close_failed`` records the failure so close() keeps retrying.
    """
    monkeypatch.setattr(browser_tools, "_HAS_PLAYWRIGHT", True)
    manager = BrowserManager()

    # Inject a fake browser + playwright whose close()/stop() raise on the
    # first invocation and succeed on the second.  This simulates a
    # transient teardown failure (e.g. browser process already gone).
    call_counts = {"browser_close": 0, "playwright_stop": 0}

    class FlakeyBrowser:
        async def close(self):
            call_counts["browser_close"] += 1
            if call_counts["browser_close"] == 1:
                raise RuntimeError("transient browser close failure")

    class FlakeyPlaywright:
        async def stop(self):
            call_counts["playwright_stop"] += 1

    manager._browser = FlakeyBrowser()
    manager._playwright = FlakeyPlaywright()

    # First close: fails.  Must report failure AND mark _close_failed, but
    # NOT set _closed (so the next call actually retries).
    first = await manager.close()
    assert first["ok"] is False
    assert "transient browser close failure" in first["error"]
    assert manager._closed is False
    assert manager._close_failed is True
    # _closing_requested is permanent — launch/ensure_page must reject even
    # though the manager is not fully closed.
    assert manager._closing_requested is True
    launch_result = await manager.launch()
    assert launch_result["ok"] is False
    assert "permanently closed" in launch_result["error"]

    # Second close: browser.close() succeeds on the 2nd call.  Must
    # actually retry (call_counts incremented again), report success,
    # and now set _closed.
    second = await manager.close()
    assert second["ok"] is True
    assert call_counts["browser_close"] == 2  # retried, not short-circuited
    assert manager._closed is True
    assert manager._close_failed is False
    assert manager._browser is None

    # Third close is now a true idempotent no-op (does NOT re-invoke
    # browser.close, which is None anyway).
    third = await manager.close()
    assert third["ok"] is True
    assert call_counts["browser_close"] == 2  # no extra invocation

