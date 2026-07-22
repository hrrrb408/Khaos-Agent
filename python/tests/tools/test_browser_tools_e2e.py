"""M2 / B1 / B2: real Playwright security E2E tests.

The mock-only tests in ``test_browser_tools.py`` pin the JSON contract
and the structural guarantees of ``BrowserManager``.  They do NOT
exercise the live Playwright path — the route guard registration, the
``context.route("**/*", ...)`` interception, the refcount / close
lifecycle, or the per-session isolation against a real Chromium
instance.  This file fills that gap.

B1 (critical): every test here calls the PUBLIC tool functions
(``browser_navigate``, ``browser_click``, ``browser_type``,
``browser_snapshot``, ``browser_evaluate``, ``browser_scroll``,
``browser_screenshot``) — NOT the ``BrowserManager`` API directly.
The previous version of this file only tested ``manager.ensure_page``
and ``page.goto``, which meant the real handlers' ``NameError`` bugs
(they referenced outer-scope parameters that were never bound) were
never caught.  Calling the public functions is the only way to prove
the model-facing tools actually work on the real Playwright path.

B2: dedicated tests for the Service Worker and WebSocket bypasses.
``context.route()`` does NOT intercept requests handled by a service
worker or WebSocket upgrades — so the context now sets
``service_workers="block"`` and registers ``route_web_socket()``
with the same domain allowlist.

Every test here is marked ``browser_real`` and is skipped unless BOTH:

* Playwright is importable (``browser_tools._HAS_PLAYWRIGHT is True``);
* the ``KHAOS_RUN_BROWSER_E2E`` env var is set to a truthy value.

This mirrors the gating pattern used by ``docker_sandbox_real`` and
``platform_sandbox_real`` so local ``pytest`` runs stay fast and
dependency-free, while CI runs the full E2E matrix in a dedicated job
(``.github/workflows/browser-e2e.yml``).
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import os
import struct
import sys
from urllib.parse import urlparse

import pytest

from khaos.security.network_guard import NetworkGuard
from khaos.security.host_network import ValidatedTarget
from khaos.tools import browser_tools
from khaos.tools.browser_tools import (
    BrowserManager,
    browser_click,
    browser_evaluate,
    browser_navigate,
    browser_screenshot,
    browser_scroll,
    browser_snapshot,
    browser_type,
)


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
# this file with a clear reason.
if not _browser_e2e_enabled():
    pytestmark.append(
        pytest.mark.skip(reason=_SKIP_REASON)
    )


@pytest.fixture
async def fresh_manager(monkeypatch):
    """Yield a fresh ``BrowserManager`` for the module-level ``_manager``
    singleton so the public tool functions (which use ``_manager``)
    operate on a clean instance.

    B1: the public tool functions reference the module-level
    ``_manager`` singleton.  Testing them requires swapping that
    singleton with a fresh instance per test, otherwise state from one
    test's contexts / pages leaks into the next.

    After each test, ``close()`` is called to release the browser
    process; it's idempotent so the ``try/finally`` is safe even if
    the test already closed it.
    """
    mgr = BrowserManager()
    monkeypatch.setattr(browser_tools, "_manager", mgr)
    try:
        yield mgr
    finally:
        try:
            await asyncio.wait_for(mgr.close(), timeout=10)
        except asyncio.TimeoutError:
            pass  # best-effort — don't mask the original test failure.


@pytest.fixture
async def websocket_echo_server():
    """Run a dependency-free RFC6455 text echo server for real WS routing."""
    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        try:
            request = await reader.readuntil(b"\r\n\r\n")
            headers: dict[str, str] = {}
            for line in request.decode("latin-1").split("\r\n")[1:]:
                if ":" in line:
                    name, value = line.split(":", 1)
                    headers[name.lower()] = value.strip()
            key = headers["sec-websocket-key"]
            accept = base64.b64encode(
                hashlib.sha1(
                    (key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()
                ).digest()
            ).decode()
            writer.write(
                (
                    "HTTP/1.1 101 Switching Protocols\r\n"
                    "Upgrade: websocket\r\n"
                    "Connection: Upgrade\r\n"
                    f"Sec-WebSocket-Accept: {accept}\r\n\r\n"
                ).encode()
            )
            await writer.drain()

            header = await reader.readexactly(2)
            length = header[1] & 0x7F
            if length == 126:
                length = struct.unpack("!H", await reader.readexactly(2))[0]
            elif length == 127:
                length = struct.unpack("!Q", await reader.readexactly(8))[0]
            mask = await reader.readexactly(4)
            payload = await reader.readexactly(length)
            decoded = bytes(
                byte ^ mask[index % 4] for index, byte in enumerate(payload)
            )
            echoed = b"echo:" + decoded
            if len(echoed) < 126:
                response_header = bytes((0x81, len(echoed)))
            else:
                response_header = bytes((0x81, 126)) + struct.pack(
                    "!H", len(echoed)
                )
            writer.write(response_header + echoed)
            await writer.drain()
            # Keep the server side open long enough for Playwright's routed
            # WebSocket proxy to forward the final data frame to the page.
            # Closing immediately after ``drain`` can race that forwarding
            # and surface only the close event on fast local runs.
            try:
                await asyncio.wait_for(reader.read(2), timeout=1)
            except asyncio.TimeoutError:
                pass
        except (asyncio.IncompleteReadError, KeyError):
            pass
        finally:
            writer.close()
            await writer.wait_closed()

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    try:
        yield f"ws://127.0.0.1:{port}/echo"
    finally:
        server.close()
        await server.wait_closed()


@pytest.fixture
def http_server(tmp_path):
    """Spin up a tiny ``http.server`` on a free port for the route
    guard tests.

    Serves ``tmp_path`` so the test can drop an ``index.html`` and a
    ``secret.txt`` and verify the route guard lets the page load but
    blocks cross-origin requests.
    """
    import http.server
    import socketserver
    import threading

    (tmp_path / "index.html").write_text(
        "<html><body><h1 id='greeting'>hello</h1>"
        "<input id='field' type='text'>"
        "</body></html>",
        encoding="utf-8",
    )

    class _Handler(http.server.SimpleHTTPRequestHandler):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, directory=str(tmp_path), **kwargs)

        def log_message(self, *args, **kwargs):  # silence
            pass

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


# ───────────────────────── B1: public tool functions work ─────────────────


async def test_browser_navigate_public_tool_loads_page(fresh_manager, http_server):
    """B1: ``browser_navigate`` (the PUBLIC tool function the model
    calls) actually loads the page on the real Playwright path.

    The previous ``_navigate_real(page)`` referenced ``url`` from the
    enclosing ``browser_navigate`` scope, but ``_safe_execute`` calls
    ``real(page)`` from a different call frame — so ``url`` was
    undefined and every real navigation raised ``NameError`` at runtime.
    This test calls the public function end-to-end so the closure
    binding is exercised for real.
    """
    host = urlparse(http_server.url).hostname or "127.0.0.1"
    guard = _browser_guard([host])
    result = await browser_navigate(
        http_server.url,
        principal_id="test-nav",
        session_id="s1",
        runtime_id="r1",
        network_guard=guard,
    )
    assert result.get("ok") is True, f"navigate failed: {result}"
    assert "127.0.0.1" in result.get("url", "")
    assert result.get("title") is not None


async def test_browser_snapshot_public_tool_returns_html(fresh_manager, http_server):
    """B1: ``browser_snapshot`` returns the page's HTML content."""
    host = urlparse(http_server.url).hostname or "127.0.0.1"
    guard = _browser_guard([host])
    await browser_navigate(
        http_server.url,
        principal_id="test-snap",
        session_id="s1",
        runtime_id="r1",
        network_guard=guard,
    )
    result = await browser_snapshot(
        principal_id="test-snap",
        session_id="s1",
        runtime_id="r1",
        network_guard=guard,
    )
    assert result.get("ok") is True, f"snapshot failed: {result}"
    assert "greeting" in result.get("html", "")


async def test_browser_click_public_tool_clicks_element(fresh_manager, http_server):
    """B1: ``browser_click`` actually clicks an element on the page."""
    host = urlparse(http_server.url).hostname or "127.0.0.1"
    guard = _browser_guard([host])
    await browser_navigate(
        http_server.url,
        principal_id="test-click",
        session_id="s1",
        runtime_id="r1",
        network_guard=guard,
    )
    result = await browser_click(
        "#greeting",
        principal_id="test-click",
        session_id="s1",
        runtime_id="r1",
        network_guard=guard,
    )
    assert result.get("ok") is True, f"click failed: {result}"
    assert result.get("selector") == "#greeting"


async def test_browser_type_public_tool_types_text(fresh_manager, http_server):
    """B1: ``browser_type`` actually types text into an input."""
    host = urlparse(http_server.url).hostname or "127.0.0.1"
    guard = _browser_guard([host])
    await browser_navigate(
        http_server.url,
        principal_id="test-type",
        session_id="s1",
        runtime_id="r1",
        network_guard=guard,
    )
    result = await browser_type(
        "#field", "hello-world",
        principal_id="test-type",
        session_id="s1",
        runtime_id="r1",
        network_guard=guard,
    )
    assert result.get("ok") is True, f"type failed: {result}"
    assert result.get("text") == "hello-world"


async def test_browser_evaluate_public_tool_runs_js(fresh_manager, http_server):
    """B1: ``browser_evaluate`` actually evaluates a JS expression."""
    host = urlparse(http_server.url).hostname or "127.0.0.1"
    guard = _browser_guard([host])
    await browser_navigate(
        http_server.url,
        principal_id="test-eval",
        session_id="s1",
        runtime_id="r1",
        network_guard=guard,
    )
    result = await browser_evaluate(
        "1 + 2",
        principal_id="test-eval",
        session_id="s1",
        runtime_id="r1",
        network_guard=guard,
    )
    assert result.get("ok") is True, f"evaluate failed: {result}"
    assert "3" in result.get("result", "")


async def test_browser_scroll_public_tool_scrolls_page(fresh_manager, http_server):
    """B1: ``browser_scroll`` actually scrolls the page."""
    host = urlparse(http_server.url).hostname or "127.0.0.1"
    guard = _browser_guard([host])
    await browser_navigate(
        http_server.url,
        principal_id="test-scroll",
        session_id="s1",
        runtime_id="r1",
        network_guard=guard,
    )
    result = await browser_scroll(
        "down", 2,
        principal_id="test-scroll",
        session_id="s1",
        runtime_id="r1",
        network_guard=guard,
    )
    assert result.get("ok") is True, f"scroll failed: {result}"
    assert result.get("direction") == "down"
    assert result.get("amount") == 2


async def test_browser_screenshot_public_tool_returns_base64(fresh_manager, http_server):
    """B1: ``browser_screenshot`` returns base64-encoded image bytes."""
    host = urlparse(http_server.url).hostname or "127.0.0.1"
    guard = _browser_guard([host])
    await browser_navigate(
        http_server.url,
        principal_id="test-shot",
        session_id="s1",
        runtime_id="r1",
        network_guard=guard,
    )
    result = await browser_screenshot(
        principal_id="test-shot",
        session_id="s1",
        runtime_id="r1",
        network_guard=guard,
    )
    assert result.get("ok") is True, f"screenshot failed: {result}"
    assert result.get("base64")
    assert result.get("size_bytes", 0) > 0


# ───────────────────────── B1: full tool sequence ─────────────────────────


async def test_full_browser_tool_sequence(fresh_manager, http_server):
    """B1: a realistic sequence of public tool calls (navigate →
    snapshot → type → click → evaluate) all succeed against the real
    browser, proving the closure binding works for every tool.

    This is the test that would have caught the original ``NameError``
    bugs in ``_navigate_real`` / ``_click_real`` / ``_type_real`` /
    ``_evaluate_real`` — they all referenced outer-scope parameters
    that ``_safe_execute``'s call frame did not have access to.
    """
    host = urlparse(http_server.url).hostname or "127.0.0.1"
    guard = _browser_guard([host])
    principal = "test-sequence"
    session = "s1"
    runtime = "r1"
    common = {
        "principal_id": principal,
        "session_id": session,
        "runtime_id": runtime,
        "network_guard": guard,
    }

    # Navigate
    nav = await browser_navigate(http_server.url, **common)
    assert nav["ok"], f"navigate failed: {nav}"

    # Snapshot — should see the input
    snap = await browser_snapshot(**common)
    assert snap["ok"], f"snapshot failed: {snap}"
    assert "field" in snap["html"]

    # Type into the input
    typed = await browser_type("#field", "khaos-test", **common)
    assert typed["ok"], f"type failed: {typed}"

    # Evaluate the input's value to prove the type landed
    ev = await browser_evaluate(
        "document.querySelector('#field').value", **common
    )
    assert ev["ok"], f"evaluate failed: {ev}"
    assert "khaos-test" in ev["result"], (
        f"type did not land in the input; got result={ev['result']!r}"
    )

    # Click the greeting (no navigation, but proves click works)
    clicked = await browser_click("#greeting", **common)
    assert clicked["ok"], f"click failed: {clicked}"


# ───────────────────────── H2: route guard success path ────────────────────


async def test_route_guard_allows_listed_domain(fresh_manager, http_server):
    """H2: when ``allowed_domains`` lists the test server's host, the
    route guard lets the navigation through and the page loads.
    """
    host = urlparse(http_server.url).hostname or "127.0.0.1"
    guard = _browser_guard([host])
    result = await browser_navigate(
        http_server.url,
        principal_id="test-allow",
        session_id="s1",
        runtime_id="r1",
        network_guard=guard,
    )
    assert result.get("ok") is True


async def test_route_guard_blocks_unlisted_domain(fresh_manager, http_server):
    """H2: when ``allowed_domains`` does NOT list the test server's
    host, the route guard aborts the navigation.
    """
    guard = _browser_guard(["example.invalid"])
    result = await browser_navigate(
        http_server.url,
        principal_id="test-block",
        session_id="s1",
        runtime_id="r1",
        network_guard=guard,
    )
    # Navigation must be aborted — either an error dict from the caught
    # exception, or ``ok: False`` with a blocked message.
    assert result.get("ok") is False, (
        f"navigation to unlisted domain should have been blocked: {result}"
    )


# ───────────────────────── H2: route guard fail-closed ─────────────────────


async def test_route_guard_installation_failure_is_fail_closed(fresh_manager, monkeypatch):
    """H2: when ``context.route(...)`` raises, the context is closed
    and ``ensure_page`` returns ``None`` — never continue with an
    unguarded context.
    """
    guard = _browser_guard(["example.com"])

    from playwright.async_api import BrowserContext as _RealCtx

    original_route = _RealCtx.route

    async def _boom_route(self, url, handler, **kwargs):
        raise RuntimeError("simulated route registration failure")

    monkeypatch.setattr(_RealCtx, "route", _boom_route)
    try:
        result = await browser_navigate(
            "https://example.com",
            principal_id="test-fail-closed",
            session_id="s1",
            runtime_id="r1",
            network_guard=guard,
        )
        assert result.get("ok") is False, (
            "navigate must fail when route guard installation fails"
        )
        assert "guard" in result.get("error", "").lower(), (
            f"error must mention guard installation failure: {result}"
        )
        # No context should be left in the manager — it was closed.
        assert fresh_manager._contexts == {}, (
            "the half-created context must be closed, not leaked"
        )
    finally:
        monkeypatch.setattr(_RealCtx, "route", original_route)


# ───────────────────────── H2: scheme allowlist ────────────────────────────


async def test_route_guard_blocks_file_scheme(fresh_manager, tmp_path):
    """H2: ``file:`` URLs are blocked even when the NetworkGuard would
    otherwise permit the host.
    """
    secret = tmp_path / "secret.txt"
    secret.write_text("top-secret-content", encoding="utf-8")

    guard = _browser_guard([])
    result = await browser_navigate(
        f"file://{secret}",
        principal_id="test-scheme",
        session_id="s1",
        runtime_id="r1",
        network_guard=guard,
    )
    assert result.get("ok") is False, (
        f"file:// navigation should have been blocked: {result}"
    )


# ───────────────────────── H1: refcount lifecycle ─────────────────────────


async def test_refcount_does_not_bump_on_reentry_under_same_runtime(fresh_manager, http_server):
    """H1: a sequence of public tool calls under the SAME
    ``runtime_id`` (navigate → snapshot → click) does NOT bump
    refcount beyond 1.
    """
    host = urlparse(http_server.url).hostname or "127.0.0.1"
    guard = _browser_guard([host])
    common = {
        "principal_id": "p1",
        "session_id": "s1",
        "runtime_id": "r1",
        "network_guard": guard,
    }

    await browser_navigate(http_server.url, **common)
    await browser_snapshot(**common)
    await browser_click("#greeting", **common)

    key = fresh_manager._context_key("p1", "s1", "r1")
    assert fresh_manager._contexts[key]["refcount"] == 1, (
        "refcount must only bump for NEW runtime_ids, not every tool call"
    )
    assert fresh_manager._contexts[key]["_runtime_owners"] == {"r1"}

    # close_runtime(r1) must release the context entirely.
    await fresh_manager.close_runtime("r1")
    assert key not in fresh_manager._contexts


async def test_close_runtime_releases_all_contexts_across_sessions(fresh_manager, http_server):
    """H1: ``close_runtime(runtime_id)`` closes ALL contexts that
    runtime acquired, even across different principal / session keys.
    """
    host = urlparse(http_server.url).hostname or "127.0.0.1"
    guard = _browser_guard([host])

    await browser_navigate(http_server.url, principal_id="p1", session_id="s1", runtime_id="r1", network_guard=guard)
    await browser_navigate(http_server.url, principal_id="p1", session_id="s2", runtime_id="r1", network_guard=guard)
    await browser_navigate(http_server.url, principal_id="p2", session_id="s3", runtime_id="r1", network_guard=guard)

    assert len(fresh_manager._contexts) == 3
    await fresh_manager.close_runtime("r1")
    assert fresh_manager._contexts == {}, (
        "close_runtime must release ALL contexts the runtime acquired"
    )


# ───────────────────────── H5: concurrent session isolation ───────────────


async def test_concurrent_sessions_get_independent_contexts(fresh_manager, http_server):
    """H5: two concurrent sessions under the SAME principal get
    independent ``BrowserContext`` instances — different cookies.
    """
    host = urlparse(http_server.url).hostname or "127.0.0.1"
    guard = _browser_guard([host])

    # First use is genuinely concurrent; lifecycle serialization must still
    # create one independent context per key without corrupting manager state.
    result_a, result_b = await asyncio.gather(
        browser_navigate(
            http_server.url, principal_id="p1", session_id="A",
            runtime_id="rA", network_guard=guard,
        ),
        browser_navigate(
            http_server.url, principal_id="p1", session_id="B",
            runtime_id="rB", network_guard=guard,
        ),
    )
    assert result_a["ok"] and result_b["ok"]

    # Session A sets a cookie via evaluate.
    ev_a = await browser_evaluate(
        "document.cookie = 'marker=A'; document.cookie",
        principal_id="p1", session_id="A", runtime_id="rA", network_guard=guard,
    )
    assert ev_a["ok"]

    # Session B's cookie jar is independent.
    ev_b = await browser_evaluate(
        "document.cookie",
        principal_id="p1", session_id="B", runtime_id="rB", network_guard=guard,
    )
    assert ev_b["ok"]
    assert "marker=A" not in ev_b["result"], (
        f"session A's cookie leaked into session B: {ev_b['result']!r}"
    )


# ───────────────────────── H2: subresource fetch ──────────────────────────


async def test_route_guard_blocks_subresource_fetch(fresh_manager, http_server, tmp_path):
    """H2: the route guard intercepts not just the main navigation but
    also subresource requests (fetch / XHR).  A page that tries to
    ``fetch()`` a blocked domain must fail.
    """
    host = urlparse(http_server.url).hostname or "127.0.0.1"
    guard = _browser_guard([host])

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

    result = await browser_navigate(
        http_server.url,
        principal_id="test-subresource",
        session_id="s1",
        runtime_id="r1",
        network_guard=guard,
    )
    assert result["ok"]
    # Use the public evaluate tool to read the fetch result — this also
    # proves ``browser_evaluate`` works end-to-end on the real path.
    ev = await browser_evaluate(
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
        """,
        principal_id="test-subresource",
        session_id="s1",
        runtime_id="r1",
        network_guard=guard,
    )
    assert ev["ok"], f"evaluate failed: {ev}"
    assert "failed" in ev["result"], (
        f"the fetch to blocked.example.invalid should have been aborted, "
        f"but got result={ev['result']!r}"
    )


# ───────────────────────── B2: service worker block ───────────────────────


async def test_service_worker_registration_is_blocked(fresh_manager, http_server, tmp_path):
    """B2: ``service_workers="block"`` prevents a page from registering
    a service worker, closing the bypass where SW-handled requests are
    not seen by ``context.route()``.

    With ``service_workers="block"``, Playwright blocks SW registration
    at the browser layer — ``navigator.serviceWorker.register()`` rejects
    and the page never gets a controlling SW.  We test this by attempting
    registration and checking that either the registration rejected OR
    (if the browser engine returns a success promise that's later killed)
    the controller never becomes non-null.
    """
    host = urlparse(http_server.url).hostname or "127.0.0.1"
    guard = _browser_guard([host])

    # Drop a real SW script so registration isn't rejected for 404.
    (tmp_path / "sw.js").write_text(
        "self.addEventListener('install', e => self.skipWaiting());\n"
        "self.addEventListener('activate', e => self.clients.claim());\n",
        encoding="utf-8",
    )
    # Rewrite index.html to attempt SW registration and report the result.
    (tmp_path / "index.html").write_text(
        """
        <html><body>
          <h1 id="greeting">hello</h1>
          <script>
            window.__sw_state = 'pending';
            window.__sw_controller = 'unknown';
            navigator.serviceWorker.register('/sw.js')
              .then(() => { window.__sw_state = 'registered'; })
              .catch(err => { window.__sw_state = 'blocked: ' + err.message; });
            // Poll the controller for 2 seconds — with
            // service_workers='block', the SW should never control the
            // page even if registration somehow resolves.
            const ctrlStart = Date.now();
            const ctrlTick = () => {
              if (navigator.serviceWorker.controller) {
                window.__sw_controller = 'yes';
              } else if (Date.now() - ctrlStart > 2000) {
                window.__sw_controller = 'no';
              } else {
                setTimeout(ctrlTick, 100);
              }
            };
            ctrlTick();
          </script>
        </body></html>
        """,
        encoding="utf-8",
    )

    await browser_navigate(
        http_server.url,
        principal_id="test-sw",
        session_id="s1",
        runtime_id="r1",
        network_guard=guard,
    )
    # Read the SW state — use a polling expression that doesn't contain
    # the blocked 'WebSocket' keyword.
    ev = await browser_evaluate(
        """
        () => new Promise(resolve => {
            const start = Date.now();
            const tick = () => {
                if ((window.__sw_state !== 'pending' && window.__sw_controller !== 'unknown')
                    || Date.now() - start > 4000) {
                    resolve({
                        state: window.__sw_state,
                        controller: window.__sw_controller,
                    });
                } else {
                    setTimeout(tick, 100);
                }
            };
            tick();
        })
        """,
        principal_id="test-sw",
        session_id="s1",
        runtime_id="r1",
        network_guard=guard,
    )
    assert ev["ok"], f"evaluate failed: {ev}"
    # With service_workers='block', the SW must NOT control the page —
    # ``navigator.serviceWorker.controller`` must be null.  Even if the
    # registration promise resolves (which can happen in some Chromium
    # versions before the SW is killed), the controller must remain
    # null.  This is the actual security property: a SW that cannot
    # control the page cannot intercept requests and bypass the route
    # guard.
    result_str = str(ev["result"]).lower()
    assert '"controller": "no"' in result_str or '"controller": "unknown"' not in result_str, (
        f"service_workers='block' should prevent the SW from controlling "
        f"the page (controller must be 'no'), but got: {ev['result']!r}"
    )
    assert '"controller": "yes"' not in result_str, (
        f"SECURITY: a service worker controlled the page despite "
        f"service_workers='block' — this is a browser-layer bypass of "
        f"the route guard.  Got: {ev['result']!r}"
    )


# ───────────────────────── B2: WebSocket route guard ──────────────────────


async def test_websocket_to_unlisted_domain_is_blocked(fresh_manager, http_server, tmp_path):
    """B2: ``route_web_socket()`` intercepts WebSocket upgrades so a
    page cannot open ``new WebSocket("wss://evil.example/leak")`` past
    the HTTP route guard.

    The WebSocket test code is embedded in the HTML page (not passed
    through ``browser_evaluate``) because ``browser_evaluate``'s
    defense-in-depth JS blocklist rejects expressions containing the
    word ``WebSocket``.  The route guard is what we're testing here —
    the blocklist is a separate, redundant defense.
    """
    host = urlparse(http_server.url).hostname or "127.0.0.1"
    guard = _browser_guard([host])

    (tmp_path / "index.html").write_text(
        """
        <html><body>
          <h1>ws-bypass-test</h1>
          <script>
            window.__ws_result = 'pending';
            try {
              const ws = new WebSocket('wss://blocked.example.invalid/leak');
              ws.onopen = () => { window.__ws_result = 'opened'; };
              ws.onerror = () => { window.__ws_result = 'blocked'; };
              ws.onclose = () => { window.__ws_result = 'closed'; };
            } catch (err) {
              window.__ws_result = 'exception: ' + err.message;
            }
            setTimeout(() => { window.__ws_result = window.__ws_result || 'timeout'; }, 3000);
          </script>
        </body></html>
        """,
        encoding="utf-8",
    )

    result = await browser_navigate(
        http_server.url,
        principal_id="test-ws",
        session_id="s1",
        runtime_id="r1",
        network_guard=guard,
    )
    assert result["ok"], f"navigate failed: {result}"

    # Poll for the WS result.  The expression deliberately avoids the
    # word 'WebSocket' so it passes the evaluate blocklist.
    ev = await browser_evaluate(
        """
        () => new Promise(resolve => {
            const start = Date.now();
            const tick = () => {
                if (window.__ws_result !== 'pending' || Date.now() - start > 3000) {
                    resolve(window.__ws_result || 'timeout');
                } else {
                    setTimeout(tick, 50);
                }
            };
            tick();
        })
        """,
        principal_id="test-ws",
        session_id="s1",
        runtime_id="r1",
        network_guard=guard,
    )
    assert ev["ok"], f"evaluate failed: {ev}"
    result_str = str(ev["result"]).lower()
    assert "opened" not in result_str, (
        f"the connection to blocked.example.invalid should have been "
        f"aborted by route_web_socket(), but it opened: {ev['result']!r}"
    )
    # The connection must be blocked, closed, or error out — NOT opened.
    assert any(kw in result_str for kw in ("blocked", "closed", "timeout", "exception")), (
        f"WS should have been blocked, got: {ev['result']!r}"
    )


async def test_websocket_to_allowlisted_domain_is_not_aborted_by_guard(
    fresh_manager, http_server, websocket_echo_server, tmp_path
):
    """M1: an allowlisted WebSocket completes a real echo round-trip.

    The WS code is embedded in the HTML page for the same reason as
    the blocked-domain test — ``browser_evaluate``'s blocklist rejects
    expressions containing 'WebSocket'.
    """
    host = urlparse(http_server.url).hostname or "127.0.0.1"
    guard = _browser_guard([host])

    (tmp_path / "index.html").write_text(
        f"""
        <html><body>
          <h1>ws-allow-test</h1>
          <script>
            window.__ws_ok_result = 'pending';
            try {{
              const ws = new WebSocket('{websocket_echo_server}');
              ws.onopen = () => {{ ws.send('ping'); }};
              ws.onmessage = (event) => {{ window.__ws_ok_result = event.data; }};
              ws.onerror = () => {{
                if (window.__ws_ok_result === 'pending') window.__ws_ok_result = 'error';
              }};
              ws.onclose = () => {{
                if (window.__ws_ok_result === 'pending') window.__ws_ok_result = 'closed';
              }};
            }} catch (err) {{
              window.__ws_ok_result = 'exception: ' + err.message;
            }}
            setTimeout(() => {{ window.__ws_ok_result = window.__ws_ok_result || 'timeout'; }}, 3000);
          </script>
        </body></html>
        """,
        encoding="utf-8",
    )

    result = await browser_navigate(
        http_server.url,
        principal_id="test-ws-ok",
        session_id="s1",
        runtime_id="r1",
        network_guard=guard,
    )
    assert result["ok"], f"navigate failed: {result}"

    ev = await browser_evaluate(
        """
        () => new Promise(resolve => {
            const start = Date.now();
            const tick = () => {
                if (window.__ws_ok_result !== 'pending' || Date.now() - start > 3000) {
                    resolve(window.__ws_ok_result || 'timeout');
                } else {
                    setTimeout(tick, 50);
                }
            };
            tick();
        })
        """,
        principal_id="test-ws-ok",
        session_id="s1",
        runtime_id="r1",
        network_guard=guard,
    )
    assert ev["ok"], f"evaluate failed: {ev}"
    assert ev["result"] == "echo:ping", (
        f"allowlisted WebSocket did not complete echo round-trip: {ev}"
    )
class _BrowserE2EHostAuthority:
    """Permit the test server; SSRF behavior has dedicated authority tests."""

    async def validate_url(self, url: str, **_kwargs: object) -> ValidatedTarget:
        parsed = urlparse(url)
        return ValidatedTarget(
            url=url,
            parsed=parsed,
            hostname=parsed.hostname or "127.0.0.1",
            addresses=("127.0.0.1",),
        )


def _browser_guard(allowed_domains: list[str]) -> NetworkGuard:
    return NetworkGuard(
        network_enabled=True,
        allowed_domains=allowed_domains,
        host_authority=_BrowserE2EHostAuthority(),
    )
