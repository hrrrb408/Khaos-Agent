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

H6: ``browser_file_upload`` validates the file's identity (inode + size +
dev) at ``open()`` time, copies the bytes into a runtime-private temp file
owned by the current user (0600), and hands Playwright the temp path — so a
TOCTOU swap between validation and upload cannot substitute different bytes.
"""

from __future__ import annotations

import base64
import logging
import os
import re
import tempfile
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Optional
from urllib.parse import urlparse

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
        """启动浏览器。

        Returns:
            ``{"ok": True, "browser_type": ..., "headless": ...}`` 成功；
            ``{"ok": False, "error": "..."}`` 失败（Playwright 缺失或启动报错）。
        """
        if not _HAS_PLAYWRIGHT:
            return {
                "ok": False,
                "error": (
                    "playwright not installed. Install with: "
                    "pip install playwright && playwright install chromium"
                ),
            }
        try:
            self._headless = headless
            self._browser_type = browser_type
            if self._playwright is None:
                self._playwright = await async_playwright().start()
            pw = self._playwright
            if browser_type == "firefox":
                browser = await pw.firefox.launch(headless=headless)
            elif browser_type == "webkit":
                browser = await pw.webkit.launch(headless=headless)
            else:
                browser = await pw.chromium.launch(headless=headless)
            # 关闭旧的 browser 和所有 per-session contexts（若切换了引擎）。
            await self._close_all_contexts()
            if self._browser is not None:
                try:
                    await self._browser.close()
                except Exception:  # noqa: BLE001 — best-effort cleanup
                    pass
            self._browser = browser
            logger.info("Browser launched: %s (headless=%s)", browser_type, headless)
            return {"ok": True, "browser_type": browser_type, "headless": headless}
        except Exception as exc:  # noqa: BLE001 — surfaced as error dict
            logger.error("Failed to launch browser: %s", exc)
            return {"ok": False, "error": str(exc)}

    async def _close_all_contexts(self) -> None:
        """Close every per-session BrowserContext (best-effort)."""
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
        self._contexts.pop(key, None)
        ctx = entry.get("context")
        if ctx is not None:
            try:
                await ctx.close()
            except Exception:  # noqa: BLE001 — best-effort cleanup
                pass

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
        for key in list(self._contexts.keys()):
            entry = self._contexts.get(key)
            if entry is None:
                continue
            owners = entry.get("_runtime_owners", set())
            if runtime_id not in owners:
                continue
            owners.discard(runtime_id)
            # Decrement refcount and close if it reaches zero.  We
            # already removed ``runtime_id`` from the owner set above so
            # a subsequent ``close_runtime`` for the same runtime is a
            # no-op for this entry.
            await self._close_one_context(key, force=False)
        return {"ok": True, "runtime_id": runtime_id}

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
        """关闭浏览器和 Playwright runtime（幂等）。"""
        try:
            await self._close_all_contexts()
            if self._browser:
                await self._browser.close()
            if self._playwright:
                await self._playwright.stop()
            self._browser = None
            self._playwright = None
            return {"ok": True}
        except Exception as exc:  # noqa: BLE001 — surfaced as error dict
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
        # H2: reset per-call failure reason so a transient failure on a
        # previous call doesn't poison this one.
        self._last_ensure_error = ""
        key = self._context_key(principal_id, session_id, runtime_id)
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
            result = await self.launch()
            if not result.get("ok"):
                return None
        if self._browser is None:
            return None
        context = await self._browser.new_context(
            viewport={"width": 1280, "height": 720},
            user_agent="KhaosBrowser/1.0",
        )
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
        if network_guard is not None:
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
                    # Use the guard's domain check (handles blocked /
                    # allowed / network_enabled priority).
                    result = guard._check_domain(domain)
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
        real=_navigate_real,
        mock=lambda: _navigate_mock(url),
        principal_id=principal_id,
        session_id=session_id,
        runtime_id=runtime_id,
        network_guard=network_guard,
    )


def _navigate_real(page: Page) -> Any:
    async def _run() -> dict[str, Any]:
        await page.goto(url, wait_until="domcontentloaded", timeout=30000)
        title = await page.title()
        return {"ok": True, "url": page.url, "title": title}

    return _run()


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
        real=_click_real,
        mock=lambda: _click_mock(selector),
        principal_id=principal_id,
        session_id=session_id,
        runtime_id=runtime_id,
        network_guard=network_guard,
    )


def _click_real(page: Page) -> Any:
    async def _run() -> dict[str, Any]:
        await page.click(selector, timeout=10000)
        try:
            await page.wait_for_load_state("domcontentloaded", timeout=5000)
        except Exception:  # noqa: BLE001 — 点击可能不触发导航，忽略超时
            pass
        return {"ok": True, "selector": selector, "url": page.url}

    return _run()


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
        real=_type_real,
        mock=lambda: _type_mock(selector, text),
        principal_id=principal_id,
        session_id=session_id,
        runtime_id=runtime_id,
        network_guard=network_guard,
    )


def _type_real(page: Page) -> Any:
    async def _run() -> dict[str, Any]:
        await page.fill(selector, text)
        if press_enter:
            await page.press(selector, "Enter")
        return {"ok": True, "selector": selector, "text": text}

    return _run()


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
    save_path: str = "", *, principal_id: str = "",
    session_id: str = "", runtime_id: str = "", network_guard: Any = None,
) -> dict[str, Any]:
    """截图。``save_path`` 非空时存盘，否则返回 base64 编码。

    H1: ``principal_id`` selects the per-principal ``BrowserContext``.
    H5: ``session_id`` + ``runtime_id`` extend the context key.
    B2: ``network_guard`` is installed on the context.
    """
    return await _manager._safe_execute(
        real=_screenshot_real,
        mock=_screenshot_mock,
        principal_id=principal_id,
        session_id=session_id,
        runtime_id=runtime_id,
        network_guard=network_guard,
    )


def _screenshot_real(page: Page) -> Any:
    async def _run() -> dict[str, Any]:
        if save_path:
            await page.screenshot(path=save_path, full_page=False)
            import os

            size = os.path.getsize(save_path)
            return {"ok": True, "path": save_path, "size_bytes": size}
        image_bytes = await page.screenshot(full_page=False)
        encoded = base64.b64encode(image_bytes).decode("ascii")
        return {"ok": True, "base64": encoded, "size_bytes": len(image_bytes)}

    return _run()


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
        real=_scroll_real,
        mock=lambda: _scroll_mock(direction, amount),
        principal_id=principal_id,
        session_id=session_id,
        runtime_id=runtime_id,
        network_guard=network_guard,
    )


def _scroll_real(page: Page) -> Any:
    async def _run() -> dict[str, Any]:
        pixels = amount * 500
        if direction == "up":
            pixels = -pixels
        await page.evaluate(f"window.scrollBy(0, {pixels})")
        return {"ok": True, "direction": direction, "amount": amount}

    return _run()


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
        real=_evaluate_real,
        mock=lambda: {"ok": False, "error": "JS evaluation not available in mock mode"},
        principal_id=principal_id,
        session_id=session_id,
        runtime_id=runtime_id,
        network_guard=network_guard,
    )


def _evaluate_real(page: Page) -> Any:
    async def _run() -> dict[str, Any]:
        result = await page.evaluate(expression)
        return {"ok": True, "result": str(result)}

    return _run()


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

    H6: the file is opened with ``O_RDONLY | O_NOFOLLOW`` and its bytes
    are copied into a runtime-private temp file (0600, fixed inode).
    Playwright receives the temp path, NOT the original — so a TOCTOU
    swap of the original file between validation and upload cannot
    substitute different bytes.  The temp file is unlinked after the
    upload completes (success or failure).

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
    # H6: materialize a runtime-private copy with fd-based identity
    # binding.  Returns an error dict on failure or the temp Path on
    # success.  The temp file has a fixed inode — Playwright reads from
    # it, not the original, so a TOCTOU swap of the original cannot
    # substitute different bytes.
    materialized = _materialize_upload(file_path, workspace_root)
    if isinstance(materialized, dict):
        return materialized
    temp_path = materialized
    try:
        return await _manager._safe_execute(
            real=_make_file_upload_real(selector, str(temp_path), file_path),
            mock=lambda: _file_upload_mock(selector, file_path),
            principal_id=principal_id,
            session_id=session_id,
            runtime_id=runtime_id,
            network_guard=network_guard,
        )
    finally:
        # H6: best-effort cleanup of the runtime-private temp copy.
        try:
            temp_path.unlink(missing_ok=True)
        except Exception:  # noqa: BLE001 — best-effort cleanup
            pass


# B1: maximum upload file size — 10 MiB.  Large enough for documents and
# images, small enough to prevent using the browser as a bulk exfiltration
# channel.
_UPLOAD_MAX_BYTES = 10 * 1024 * 1024

# M1: runtime-private directory for materialized upload temp files.
# ``tempfile.mkstemp()`` defaults to the system ``/tmp`` which is
# world-writable on the same UID — a same-UID process can swap the file
# between ``close(temp_fd)`` and Playwright's ``open()`` (TOCTOU).  Using
# a 0700 dir under the user's home closes that window: only the current
# user can access the temp file.  ``_ensure_upload_trusted_dir`` validates
# this directory (not a symlink, owned by current UID, mode 0700) before
# any temp file is created in it.
UPLOAD_TRUSTED_DIR = Path.home() / ".khaos" / "uploads"


def _ensure_upload_trusted_dir() -> Path:
    """M1: ensure ``UPLOAD_TRUSTED_DIR`` exists and is a 0700 directory
    owned by the current user.

    Validates the directory is:

    * not a symlink (so an attacker cannot point ``~/.khaos/uploads`` at
      ``/etc`` or another world-readable location);
    * a real directory (not a regular file, device, etc.);
    * owned by the current UID (so another user's directory cannot be
      used to leak or substitute temp files);
    * mode 0700 (no group / other access — only the owner can read,
      write or list the directory).

    The directory is created with mode 0700 if it does not exist, and
    ``chmod(0o700)`` is applied unconditionally (idempotent) to close
    any umask leak (e.g. ``mkdir`` under umask 022 would create 0755).
    Returns the validated ``Path`` on success; raises ``OSError`` on
    validation failure.
    """
    import os as _os
    import stat as _stat

    path = UPLOAD_TRUSTED_DIR
    path.mkdir(parents=True, exist_ok=True)
    # lstat (not stat / follow) so a symlink at ``path`` is detected
    # rather than transparently followed.
    st = path.lstat()
    if _stat.S_ISLNK(st.st_mode):
        raise OSError(f"upload trusted dir is a symlink: {path}")
    if not _stat.S_ISDIR(st.st_mode):
        raise OSError(f"upload trusted dir is not a directory: {path}")
    if st.st_uid != _os.getuid():
        raise OSError(
            f"upload trusted dir not owned by current user (uid="
            f"{_os.getuid()}): {path}"
        )
    # Force 0700 (idempotent) — closes any umask leak from a prior
    # ``mkdir`` under a permissive umask.  This is safe because chmod
    # follows symlinks and we already rejected symlinks above.
    _os.chmod(path, 0o700)
    return path


def _validate_upload_path(file_path: str, workspace_root: str) -> dict[str, Any] | None:
    """Validate ``file_path`` is within ``workspace_root`` and within size limit.

    B1: returns an error dict when validation fails, or ``None`` when the
    path is safe to upload.  Uses ``Path.resolve(strict=True)`` so symlink
    escape is rejected — the resolved path must be a real file inside the
    resolved workspace root.  This is the *fast* validation path used by
    tests; the actual upload path uses ``_materialize_upload`` (H6) which
    re-validates AND copies the bytes into a runtime-private temp file
    with fd-based identity binding.
    """
    from pathlib import Path

    try:
        root_resolved = Path(workspace_root).expanduser().resolve(strict=True)
        target_resolved = Path(file_path).expanduser().resolve(strict=True)
    except (OSError, ValueError) as exc:
        return {
            "ok": False,
            "error": f"file path validation failed: {exc}",
            "file": file_path,
        }
    # Containment check: target must be the root itself or a descendant.
    try:
        target_resolved.relative_to(root_resolved)
    except ValueError:
        return {
            "ok": False,
            "error": (
                "file_path is outside the workspace root; "
                "browser_file_upload may only upload files within the workspace"
            ),
            "file": file_path,
            "workspace_root": str(root_resolved),
        }
    # B1: file must be a regular file (no dirs, devices, pipes).
    if not target_resolved.is_file():
        return {
            "ok": False,
            "error": "file_path is not a regular file",
            "file": file_path,
        }
    # B1: size limit + identity capture.
    stat = target_resolved.stat()
    if stat.st_size > _UPLOAD_MAX_BYTES:
        return {
            "ok": False,
            "error": (
                f"file size {stat.st_size} exceeds the upload limit "
                f"of {_UPLOAD_MAX_BYTES} bytes"
            ),
            "file": file_path,
            "size": stat.st_size,
        }
    return None


def _materialize_upload(
    file_path: str, workspace_root: str
) -> "Path | dict[str, Any]":
    """H6: validate the upload path AND materialize a runtime-private copy.

    The previous ``_validate_upload_path`` → ``page.set_input_files(path)``
    flow had a TOCTOU window: between ``Path.resolve(strict=True)`` /
    ``is_file()`` / ``stat()`` returning and Playwright opening the path,
    a same-UID concurrent process could replace the file with different
    bytes (or a symlink, on kernels where the path was not opened with
    ``O_NOFOLLOW``).

    This function closes that window by:

    * opening the resolved target with ``O_RDONLY | O_NOFOLLOW`` so a
      symlink at the target is rejected and the file's identity (inode +
      dev) is pinned for the duration of the copy;
    * validating with ``fstat`` that it is a regular file owned by the
      current user and under the size limit;
    * copying the bytes (from the open fd, NOT from the path) into a
      runtime-private temp file created with ``mkstemp`` and ``fchmod 0600``;
    * returning the temp ``Path`` — Playwright reads from this temp file,
      so a subsequent swap of the original cannot affect the upload.

    M1: the temp file is created inside ``UPLOAD_TRUSTED_DIR`` (a 0700
    directory under ``~/.khaos/uploads/``), NOT the system ``/tmp``.
    ``/tmp`` is world-writable on the same UID, so a same-UID process
    could swap the temp file between ``close(temp_fd)`` and Playwright's
    ``open()``.  The 0700 dir closes that window: only the current user
    can access the temp file.

    M1: on ANY error path that returns a dict (after the temp file has
    been created), the temp file is unlinked in the ``finally`` block so
    partial / failed materializations do not leak runtime-private temp
    files into ``~/.khaos/uploads/``.  On the success path the caller is
    responsible for unlinking after Playwright finishes.

    Returns the temp ``Path`` on success, or an error dict on failure.
    """
    import os as _os
    import stat as _stat
    import tempfile as _tempfile

    # Reuse the fast validation path for the early containment / size
    # checks (so the error dicts match the test expectations).
    fast_error = _validate_upload_path(file_path, workspace_root)
    if fast_error is not None:
        return fast_error

    # Re-resolve the target path (the fast path already validated it, but
    # we need the resolved Path to open it).
    try:
        target_resolved = Path(file_path).expanduser().resolve(strict=True)
    except (OSError, ValueError) as exc:
        return {
            "ok": False,
            "error": f"file path re-resolution failed: {exc}",
            "file": file_path,
        }

    # H6: open with O_RDONLY | O_NOFOLLOW so a symlink at the target is
    # rejected and the file's identity is pinned for the copy.
    try:
        src_fd = _os.open(str(target_resolved), _os.O_RDONLY | _os.O_NOFOLLOW)
    except OSError as exc:
        return {
            "ok": False,
            "error": f"failed to open file for upload: {exc}",
            "file": file_path,
        }

    temp_path_str: str | None = None
    # M1: ``temp_handed_off`` is set to True ONLY on the success path,
    # so the ``finally`` block can unlink the temp file when we are
    # about to return an error dict (i.e. the temp file was created but
    # is partial / failed validation and the caller will never receive
    # the Path to clean up themselves).
    temp_handed_off = False
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
        # M1: validate the trusted upload dir before creating any temp
        # file in it.  Raises OSError on validation failure — propagated
        # to the caller as an error dict below.
        try:
            trusted_dir = _ensure_upload_trusted_dir()
        except OSError as exc:
            return {
                "ok": False,
                "error": f"upload trusted dir validation failed: {exc}",
                "file": file_path,
            }
        # Create the runtime-private temp file (0600, current user) in
        # the validated 0700 trusted dir.  mkstemp opens the file with
        # O_RDWR | O_CREAT | O_EXCL, so the temp path is unique and not
        # pre-existing.  M1: passing ``dir=str(trusted_dir)`` ensures
        # the temp file lands in the 0700 dir, NOT in the world-writable
        # system /tmp.
        temp_fd, temp_path_str = _tempfile.mkstemp(
            prefix="khaos_upload_",
            suffix=target_resolved.suffix or ".bin",
            dir=str(trusted_dir),
        )
        try:
            _os.fchmod(temp_fd, 0o600)
            # Copy from src_fd to temp_fd in chunks.  We read from the
            # OPEN FD, not from the path — so a concurrent swap of the
            # original file cannot substitute different bytes.
            chunk_size = 64 * 1024
            remaining = st.st_size
            while remaining > 0:
                chunk = _os.read(src_fd, min(chunk_size, remaining))
                if not chunk:
                    # File shrank between fstat and read — abort.  The
                    # temp file is partial; ``temp_handed_off`` is still
                    # False so the ``finally`` block below will unlink it.
                    return {
                        "ok": False,
                        "error": "file shrank during upload materialization",
                        "file": file_path,
                    }
                _os.write(temp_fd, chunk)
                remaining -= len(chunk)
            # Verify the temp file's identity before handing to Playwright.
            temp_st = _os.fstat(temp_fd)
            if not _stat.S_ISREG(temp_st.st_mode):
                return {
                    "ok": False,
                    "error": "temp file is not a regular file",
                    "file": file_path,
                }
            if temp_st.st_uid != _os.getuid():
                return {
                    "ok": False,
                    "error": "temp file is not owned by the current user",
                    "file": file_path,
                }
            if temp_st.st_mode & 0o077:
                return {
                    "ok": False,
                    "error": "temp file has unsafe permissions",
                    "file": file_path,
                }
        finally:
            _os.close(temp_fd)
        # Success — mark the temp file as handed off so the outer
        # ``finally`` does NOT unlink it (the caller unlinks after
        # Playwright finishes).
        temp_handed_off = True
        return Path(temp_path_str)
    finally:
        _os.close(src_fd)
        # M1: unlink the temp file on EVERY error path.  If we created a
        # temp file but returned an error dict (validation failure mid-
        # copy, identity check failure, etc.), the caller never received
        # the Path and cannot clean it up themselves — so we unlink here.
        # On the success path ``temp_handed_off`` is True and the temp
        # file is left for the caller to unlink after Playwright finishes.
        if temp_path_str is not None and not temp_handed_off:
            try:
                _os.unlink(temp_path_str)
            except OSError:  # noqa: BLE001 — best-effort cleanup
                pass


def _make_file_upload_real(
    selector: str, upload_path: str, original_path: str
) -> Callable[[Page], Any]:
    """Build a ``real`` closure for ``browser_file_upload`` that uploads
    from the materialized temp path (H6) but reports the original path
    in the result dict (so the caller sees what they asked to upload,
    not the runtime-private temp copy).
    """
    def _real(page: Page) -> Any:
        async def _run() -> dict[str, Any]:
            await page.set_input_files(selector, upload_path)
            return {
                "ok": True,
                "selector": selector,
                "file": original_path,
                # H6: include the temp path for auditability.
                "materialized_path": upload_path,
            }
        return _run()
    return _real


def _file_upload_real(page: Page) -> Any:  # pragma: no cover - legacy
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
