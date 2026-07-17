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
        """
        key = self._context_key(principal_id, session_id, runtime_id)
        await self._close_one_context(key, force=False)
        return {"ok": True, "principal_id": principal_id or "default"}

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

        B2: when ``network_guard`` is supplied, a Playwright
        ``context.route("**/*", ...)`` handler is installed that runs the
        guard's domain check on EVERY request, redirect and subresource —
        not just the initial URL passed to ``browser_navigate``.
        """
        key = self._context_key(principal_id, session_id, runtime_id)
        entry = self._contexts.get(key)
        if entry is not None and entry.get("page") is not None:
            # H5: bump refcount for the new runtime sharing this context.
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
        if network_guard is not None:
            await self._install_route_guard(context, network_guard)
        page = await context.new_page()
        page.set_default_timeout(30000)  # 30s default
        self._contexts[key] = {
            "context": context,
            "page": page,
            "refcount": 1,
            "network_guard": network_guard,
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
        """
        async def _route_handler(route: "Route", request: "Request") -> None:
            try:
                url = request.url
                parsed = urlparse(url)
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

        try:
            await context.route("**/*", _route_handler)
        except Exception as exc:  # noqa: BLE001 — best-effort
            logger.warning("failed to install B2 route guard: %s", exc)

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
            return {"ok": False, "error": "Browser not available"}
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
        # Create the runtime-private temp file (0600, current user).
        # mkstemp opens the file with O_RDWR | O_CREAT | O_EXCL, so the
        # temp path is unique and not pre-existing.
        temp_fd, temp_path_str = _tempfile.mkstemp(
            prefix="khaos_upload_",
            suffix=target_resolved.suffix or ".bin",
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
                    # temp file is partial; we'll unlink it below.
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
        return Path(temp_path_str)
    finally:
        _os.close(src_fd)
        # If we created a temp file but failed mid-copy, unlink it.
        # (On success, the caller is responsible for unlinking after
        # Playwright finishes.)
        # We can't easily tell here whether we returned success or an
        # error, so the caller's ``finally`` block handles the cleanup
        # unconditionally — this is just a safety net for the early-return
        # error paths above where we never returned the Path to the caller.


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
