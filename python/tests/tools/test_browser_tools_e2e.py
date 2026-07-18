"""M2: real Playwright security E2E tests.

The mock-only tests in ``test_browser_tools.py`` pin the JSON contract
and the structural guarantees of ``BrowserManager``.  They do NOT
exercise the live Playwright path — the route guard registration, the
``context.route("**/*", ...)`` interception, the refcount / close
lifecycle, or the per-session isolation against a real Chromium
instance.  This file fills that gap.

Every test here is marked ``browser_real`` and is skipped unless BOTH:

* Playwright is importable (``browser_tools._HAS_PLAYWRIGHT is True``);
* the ``KHAOS_RUN_BROWSER_E2E`` env var is set to a truthy value.

This mirrors the gating pattern used by ``docker_sandbox_real`` and
``platform_sandbox_real`` so local ``pytest`` runs stay fast and
dependency-free, while CI runs the full E2E matrix in a dedicated job
(``.github/workflows/browser-e2e.yml``).

Covered regressions:

* H2 — ``context.route`` installation success path: an allowlisted
  domain loads, a blocked domain is aborted with ``blockedbyclient``.
* H2 — ``context.route`` installation failure is fail-closed: the
  context is closed and ``ensure_page`` returns ``None``.
* H2 — scheme allowlist: ``file:`` and unknown schemes are aborted
  even when the NetworkGuard would otherwise permit the host.
* H1 — refcount semantics: a sequence of ``ensure_page`` calls under
  the SAME ``runtime_id`` (navigate / snapshot / click pattern) does
  NOT bump refcount beyond 1, so a single ``close_runtime`` releases
  the context.
* H1 — ``close_runtime`` releases ALL contexts a runtime acquired
  across different principal / session keys.
* H5 — concurrent sessions under the same principal get independent
  contexts (different cookies / DOM).
"""

from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import pytest

from khaos.security.network_guard import NetworkGuard
from khaos.tools import browser_tools
from khaos.tools.browser_tools import BrowserManager


# Every test in this file is a real-browser E2E test.  The marker also
# lets the CI workflow select just this file with ``-m browser_real``.
pytestmark = [
    pytest.mark.browser_real,
    # The route guard + refcount lifecycle are POSIX-agnostic, but
    # Windows has a long history of Playwright flakiness in CI; pin to
    # POSIX for now (the mock tests still cover Windows).
    pytest.mark.skipif(
        sys.platform == "win32",
        reason="real Playwright E2E is POSIX-only for now",
    ),
]


def _browser_e2e_enabled() -> bool:
    """Gate the whole module on Playwright + env var + browser binary.

    The env var (``KHAOS_RUN_BROWSER_E2E=1``) is set by the CI workflow
    so local ``pytest`` runs skip this file unless the developer
    explicitly opts in.
    """
    if not browser_tools._HAS_PLAYWRIGHT:
        return False
    return os.environ.get("KHAOS_RUN_BROWSER_E2E", "").lower() in (
        "1", "true", "yes",
    )


_SKIP_REASON = (
    "set KHAOS_RUN_BROWSER_E2E=1 and install playwright + "
    "``playwright install chromium`` to run real browser E2E tests"
)


# Module-level skip: if the gate isn't satisfied, skip every test in
# this file with a clear reason.  Using ``pytestmark`` alone would let
# pytest attempt collection and fail at import time on environments
# without Playwright.
if not _browser_e2e_enabled():
    pytestmark.append(
        pytest.mark.skip(reason=_SKIP_REASON)
    )


@pytest.fixture
async def manager():
    """Yield a fresh ``BrowserManager`` and tear it down after each test.

    A per-test manager (instead of the module-level ``_manager``
    singleton) keeps tests independent: a leaked context in test N
    cannot affect test N+1.  ``close()`` is idempotent so the
    ``try/finally`` is safe even if the test already closed it.
    """
    mgr = BrowserManager()
    try:
        yield mgr
    finally:
        try:
            await asyncio.wait_for(mgr.close(), timeout=10)
        except asyncio.TimeoutError:
            # Best-effort — don't mask the original test failure.
            pass


@pytest.fixture
def http_server(tmp_path):
    """Spin up a tiny ``http.server`` on a free port for the route
    guard tests.

    Returns a ``BaseUrl`` namedtuple-ish with ``.url`` (the
    ``http://127.0.0.1:<port>/`` root) and ``.stop()``.  The server
    serves ``tmp_path`` so the test can drop an ``index.html`` and a
    ``secret.txt`` and verify the route guard lets the page load but
    blocks cross-origin requests.
    """
    import http.server
    import socketserver
    import threading

    (tmp_path / "index.html").write_text(
        "<html><body><h1 id='greeting'>hello</h1></body></html>",
        encoding="utf-8",
    )

    class _Handler(http.server.SimpleHTTPRequestHandler):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, directory=str(tmp_path), **kwargs)

        def log_message(self, *args, **kwargs):  # silence
            pass

    # Find a free port.
    with socketserver.TCPServer(("127.0.0.1", 0), _Handler) as httpd:
        port = httpd.server_address[1]
        thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        thread.start()
        try:
            yield type(
                "BaseUrl",
                (),
                {"url": f"http://127.0.0.1:{port}/", "stop": httpd.shutdown},
            )()
        finally:
            httpd.shutdown()
            thread.join(timeout=5)


# ───────────────────────── H2: route guard success path ────────────────────


async def test_route_guard_allows_listed_domain(manager, http_server):
    """H2: when ``allowed_domains`` lists the test server's host, the
    route guard lets the navigation through and the page actually loads.
    """
    host = urlparse(http_server.url).hostname or "127.0.0.1"
    guard = NetworkGuard(network_enabled=True, allowed_domains=[host])
    page = await manager.ensure_page(
        principal_id="test-allow",
        session_id="s1",
        runtime_id="r1",
        network_guard=guard,
    )
    assert page is not None, "ensure_page must succeed with route guard installed"
    try:
        response = await page.goto(http_server.url, wait_until="domcontentloaded")
        assert response is not None
        assert response.ok, f"navigation should succeed, got {response.status}"
        # The page actually rendered the greeting.
        text = await page.text_content("#greeting")
        assert text == "hello"
    finally:
        await manager.close_runtime("r1")


async def test_route_guard_blocks_unlisted_domain(manager, http_server):
    """H2: when ``allowed_domains`` does NOT list the test server's
    host, the route guard aborts the navigation with
    ``blockedbyclient`` and the page never loads the content.
    """
    # Allowlist a DIFFERENT host — the test server is not on it.
    guard = NetworkGuard(network_enabled=True, allowed_domains=["example.invalid"])
    page = await manager.ensure_page(
        principal_id="test-block",
        session_id="s1",
        runtime_id="r1",
        network_guard=guard,
    )
    assert page is not None
    try:
        # The navigation must be aborted by the route guard.  Playwright
        # surfaces this as a net::ERR_BLOCKED_BY_CLIENT exception from
        # ``page.goto()`` — so we expect the goto to raise.
        blocked = False
        try:
            await page.goto(http_server.url, wait_until="domcontentloaded", timeout=5000)
        except Exception as exc:
            # The route guard aborted the request — exactly what we want.
            blocked = "blocked" in str(exc).lower() or "ERR_BLOCKED" in str(exc)
        assert blocked, (
            "navigation to an unlisted domain should have been aborted "
            "by the route guard, but goto did not raise a blocked error"
        )
        # The page must still be on about:blank (or some non-test URL)
        # — never the test server's content.
        assert "127.0.0.1" not in page.url, (
            "the page URL must not point at the blocked test server"
        )
    finally:
        await manager.close_runtime("r1")


# ───────────────────────── H2: route guard fail-closed ─────────────────────


async def test_route_guard_installation_failure_is_fail_closed(manager, monkeypatch):
    """H2: when ``context.route(...)`` raises, the context is closed
    immediately and ``ensure_page`` returns ``None`` — never continue
    with an unguarded context.
    """
    guard = NetworkGuard(network_enabled=True, allowed_domains=["example.com"])

    # Force ``context.route`` to raise.  We patch the NetworkGuard into
    # a real guard, then monkeypatch the Playwright ``BrowserContext``
    # class so any ``route()`` call blows up.  This is the closest we
    # can get to a real installation failure without a broken
    # Playwright build.
    from playwright.async_api import BrowserContext as _RealCtx

    original_route = _RealCtx.route

    async def _boom_route(self, url, handler, **kwargs):
        raise RuntimeError("simulated route registration failure")

    monkeypatch.setattr(_RealCtx, "route", _boom_route)
    try:
        page = await manager.ensure_page(
            principal_id="test-fail-closed",
            session_id="s1",
            runtime_id="r1",
            network_guard=guard,
        )
        assert page is None, (
            "ensure_page must return None when route guard installation "
            "fails — never continue with an unguarded context"
        )
        # The failure reason must be surfaced so callers can tell the
        # difference between "Playwright missing" and "guard failed".
        assert "guard installation failed" in manager._last_ensure_error.lower()
        # No context should be left in the manager — it was closed.
        assert manager._contexts == {}, (
            "the half-created context must be closed, not leaked"
        )
    finally:
        monkeypatch.setattr(_RealCtx, "route", original_route)


# ───────────────────────── H2: scheme allowlist ────────────────────────────


async def test_route_guard_blocks_file_scheme(manager, tmp_path):
    """H2: ``file:`` URLs are blocked even when the NetworkGuard would
    otherwise permit the host.  A page that tries to read a local file
    via ``file:///`` must be aborted.
    """
    secret = tmp_path / "secret.txt"
    secret.write_text("top-secret-content", encoding="utf-8")

    # NetworkGuard with no allowlist → all hosts permitted.  The scheme
    # check must STILL block file: because it's not in the allowed set.
    guard = NetworkGuard(network_enabled=True, allowed_domains=[])
    page = await manager.ensure_page(
        principal_id="test-scheme",
        session_id="s1",
        runtime_id="r1",
        network_guard=guard,
    )
    assert page is not None
    try:
        # Navigate to a file:// URL — the route guard must abort it.
        blocked = False
        try:
            await page.goto(f"file://{secret}", wait_until="domcontentloaded", timeout=5000)
        except Exception as exc:
            blocked = "blocked" in str(exc).lower() or "ERR_BLOCKED" in str(exc)
        assert blocked, (
            "file:// navigation should have been aborted by the route "
            "guard's scheme allowlist, but goto did not raise"
        )
        # The page must NOT be on the file:// URL.
        assert not page.url.startswith("file:"), (
            f"page must not have navigated to file://, got url={page.url!r}"
        )
    finally:
        await manager.close_runtime("r1")


# ───────────────────────── H1: refcount lifecycle ─────────────────────────


async def test_refcount_does_not_bump_on_reentry_under_same_runtime(manager, http_server):
    """H1 (lifecycle): a sequence of ``ensure_page`` calls under the
    SAME ``runtime_id`` (mimicking navigate → snapshot → click) must
    NOT bump refcount beyond 1.  Otherwise ``close_runtime`` would
    only decrement once and the context would leak.
    """
    host = urlparse(http_server.url).hostname or "127.0.0.1"
    guard = NetworkGuard(network_enabled=True, allowed_domains=[host])

    page1 = await manager.ensure_page(
        principal_id="p1", session_id="s1", runtime_id="r1",
        network_guard=guard,
    )
    page2 = await manager.ensure_page(
        principal_id="p1", session_id="s1", runtime_id="r1",
        network_guard=guard,
    )
    page3 = await manager.ensure_page(
        principal_id="p1", session_id="s1", runtime_id="r1",
        network_guard=guard,
    )
    assert page1 is page2 is page3, "same runtime_id must return the same page"
    # Refcount must still be 1 — three calls, but only one NEW runtime.
    key = manager._context_key("p1", "s1", "r1")
    assert manager._contexts[key]["refcount"] == 1, (
        "refcount must only bump for NEW runtime_ids, not every tool call"
    )
    # And the owner set contains exactly this one runtime.
    assert manager._contexts[key]["_runtime_owners"] == {"r1"}

    # close_runtime(r1) must release the context entirely.
    await manager.close_runtime("r1")
    assert key not in manager._contexts, (
        "close_runtime must release the context when the sole owner "
        "releases — refcount should have reached 0"
    )


async def test_close_runtime_releases_all_contexts_across_sessions(manager, http_server):
    """H1: ``close_runtime(runtime_id)`` closes ALL contexts that
    runtime acquired, even across different principal / session keys.
    This is the robust alternative to ``close_context`` which can only
    guess a single key.
    """
    host = urlparse(http_server.url).hostname or "127.0.0.1"
    guard = NetworkGuard(network_enabled=True, allowed_domains=[host])

    # One runtime acquires contexts under three different sessions.
    await manager.ensure_page("p1", session_id="s1", runtime_id="r1", network_guard=guard)
    await manager.ensure_page("p1", session_id="s2", runtime_id="r1", network_guard=guard)
    await manager.ensure_page("p2", session_id="s3", runtime_id="r1", network_guard=guard)

    assert len(manager._contexts) == 3
    # close_runtime(r1) must release every context r1 touched.
    await manager.close_runtime("r1")
    assert manager._contexts == {}, (
        "close_runtime must release ALL contexts the runtime acquired, "
        "not just one — otherwise cookies / DOM leak into the next run"
    )


# ───────────────────────── H5: concurrent session isolation ───────────────


async def test_concurrent_sessions_get_independent_contexts(manager, http_server):
    """H5: two concurrent sessions under the SAME principal get
    independent ``BrowserContext`` instances — different cookies, DOM
    and current page.  A cookie set in session A must NOT be visible
    to session B.
    """
    host = urlparse(http_server.url).hostname or "127.0.0.1"
    guard = NetworkGuard(network_enabled=True, allowed_domains=[host])

    page_a = await manager.ensure_page(
        principal_id="p1", session_id="session-A", runtime_id="rA",
        network_guard=guard,
    )
    page_b = await manager.ensure_page(
        principal_id="p1", session_id="session-B", runtime_id="rB",
        network_guard=guard,
    )
    assert page_a is not page_b, "different sessions must get different pages"

    try:
        # Session A sets a cookie; session B must not see it.
        await page_a.goto(http_server.url, wait_until="domcontentloaded")
        await page_a.context.add_cookies([{
            "name": "session-marker",
            "value": "A",
            "url": http_server.url,
        }])
        cookies_a = await page_a.context.cookies()
        assert any(c["name"] == "session-marker" and c["value"] == "A" for c in cookies_a)

        # Session B navigates to the same URL — its cookie jar is empty.
        await page_b.goto(http_server.url, wait_until="domcontentloaded")
        cookies_b = await page_b.context.cookies()
        assert not any(c["name"] == "session-marker" for c in cookies_b), (
            "session-A's cookie leaked into session-B — contexts are not isolated"
        )
    finally:
        await manager.close_runtime("rA")
        await manager.close_runtime("rB")


# ───────────────────────── H1: route guard on subresource ─────────────────


async def test_route_guard_blocks_subresource_fetch(manager, http_server, tmp_path):
    """H2: the route guard intercepts not just the main navigation but
    also subresource requests (fetch / XHR / images).  A page that
    tries to ``fetch()`` a blocked domain must fail.

    This pins the contract that ``context.route("**/*", ...)`` covers
    every request Playwright sees — closing the bypass where
    ``browser_navigate`` passed the initial URL check but a subsequent
    ``browser_evaluate`` could ``fetch('http://evil.example/...')``.
    """
    host = urlparse(http_server.url).hostname or "127.0.0.1"
    # Allowlist ONLY the test server — every other host is blocked.
    guard = NetworkGuard(network_enabled=True, allowed_domains=[host])

    # Drop a page that attempts a fetch to a different host.
    (tmp_path / "index.html").write_text(
        """
        <html><body>
          <h1 id="greeting">hello</h1>
          <script>
            window.__fetch_result = 'pending';
            fetch('http://blocked.example.invalid/leak')
              .then(() => { window.__fetch_result = 'succeeded'; })
              .catch(() => { window.__fetch_result = 'failed'; });
          </script>
        </body></html>
        """,
        encoding="utf-8",
    )

    page = await manager.ensure_page(
        principal_id="test-subresource",
        session_id="s1",
        runtime_id="r1",
        network_guard=guard,
    )
    assert page is not None
    try:
        await page.goto(http_server.url, wait_until="domcontentloaded")
        # The fetch must have failed (blocked by the route guard).
        # Poll briefly because fetch is async.
        result = await page.evaluate(
            """
            () => new Promise(resolve => {
                const start = Date.now();
                const tick = () => {
                    if (window.__fetch_result !== 'pending' || Date.now() - start > 3000) {
                        resolve(window.__fetch_result);
                    } else {
                        setTimeout(tick, 50);
                    }
                };
                tick();
            })
            """
        )
        assert result == "failed", (
            "the fetch to blocked.example.invalid should have been aborted "
            f"by the route guard, but got result={result!r}"
        )
    finally:
        await manager.close_runtime("r1")
