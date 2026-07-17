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
"""

from __future__ import annotations

import base64
import logging
import re
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

logger = logging.getLogger(__name__)

# ─── 尝试导入 Playwright ───
try:  # pragma: no cover - import success depends on the environment
    from playwright.async_api import (  # type: ignore[import-not-found]
        Browser,
        BrowserContext,
        Page,
        async_playwright,
    )

    _HAS_PLAYWRIGHT = True
except ImportError:
    _HAS_PLAYWRIGHT = False
    Browser = BrowserContext = Page = async_playwright = None  # type: ignore[assignment]
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
    local storage or the current page.  Each principal gets its own
    ``BrowserContext`` + ``Page`` pair, keyed by ``principal_id``.  When
    ``principal_id`` is empty, the ``"default"`` context is used (backward
    compatible with callers that don't pass a principal).

    模块底部 ``_manager`` 是推荐的共享实例；``BrowserManager`` 本身也
    可被独立实例化（例如测试场景）。
    """

    def __init__(self):
        self._playwright = None
        self._browser: Optional[Browser] = None
        self._headless: bool = True
        self._browser_type: str = "chromium"  # chromium / firefox / webkit
        # H1: per-principal context+page pairs.  Keyed by principal_id
        # (defaulting to "default" when empty).  Each entry is a dict with
        # "context" and "page" keys.
        self._contexts: dict[str, dict[str, Any]] = {}

    @property
    def is_ready(self) -> bool:
        """Playwright 是否已初始化且可用（至少有一个活跃 page）。"""
        return any(entry.get("page") is not None for entry in self._contexts.values())

    @property
    def current_url(self) -> str:
        """当前默认页面 URL（无 page 时回退到 mock 状态）。"""
        entry = self._contexts.get("default")
        if entry and entry.get("page"):
            return entry["page"].url
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
            # 关闭旧的 browser 和所有 per-principal contexts（若切换了引擎）。
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
        """Close every per-principal BrowserContext (best-effort)."""
        for key in list(self._contexts.keys()):
            await self._close_one_context(key)

    async def _close_one_context(self, key: str) -> None:
        entry = self._contexts.pop(key, None)
        if entry is None:
            return
        ctx = entry.get("context")
        if ctx is not None:
            try:
                await ctx.close()
            except Exception:  # noqa: BLE001 — best-effort cleanup
                pass

    async def close_context(self, principal_id: str) -> dict[str, Any]:
        """Close one principal's BrowserContext (H1).

        Called when a runtime is done with a principal (e.g. subagent run
        finishes) so the principal's cookies / DOM / page are released
        and cannot leak into a subsequent run.
        """
        key = principal_id or "default"
        await self._close_one_context(key)
        return {"ok": True, "principal_id": key}

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

    async def ensure_page(self, principal_id: str = "") -> Optional[Page]:
        """确保浏览器已启动，未启动则自动启动（chromium, headless）。

        H1: returns the ``Page`` for ``principal_id``'s dedicated
        ``BrowserContext``.  Different principals get isolated contexts
        (cookies, local storage, current page) so one principal cannot
        observe another's browser state.
        """
        key = principal_id or "default"
        entry = self._contexts.get(key)
        if entry is not None and entry.get("page") is not None:
            return entry["page"]
        # Need to create a new context for this principal.
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
        page = await context.new_page()
        page.set_default_timeout(30000)  # 30s default
        self._contexts[key] = {"context": context, "page": page}
        logger.info("Browser context created for principal: %s", key)
        return page

    async def _safe_execute(
        self,
        real: Callable[[Page], Any],
        mock: Callable[[], Any],
        principal_id: str = "",
    ) -> dict[str, Any]:
        """安全执行浏览器操作：Playwright 不可用时走 ``mock``，否则走 ``real``。

        H1: ``principal_id`` selects the per-principal ``BrowserContext`` so
        different principals get isolated cookies / DOM / page state.

        ``real`` 接收一个 ``Page`` 并返回 ``dict``；``mock`` 无参并返回
        ``dict``。两条路径都返回 ``dict[str, Any]``。
        """
        if not _HAS_PLAYWRIGHT:
            return mock()  # mock 路径返回 dict
        page = await self.ensure_page(principal_id)
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


async def browser_navigate(url: str, *, principal_id: str = "") -> dict[str, Any]:
    """导航到指定 URL 并等待页面基本加载完成。

    H1: ``principal_id`` selects the per-principal ``BrowserContext`` so
    different principals (users / subagents / webhook senders) get isolated
    cookies / DOM / page state.
    """
    return await _manager._safe_execute(
        real=_navigate_real,
        mock=lambda: _navigate_mock(url),
        principal_id=principal_id,
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


async def browser_click(selector: str, *, principal_id: str = "") -> dict[str, Any]:
    """点击元素（CSS / text= / xpath=）。

    H1: ``principal_id`` selects the per-principal ``BrowserContext``.
    """
    return await _manager._safe_execute(
        real=_click_real,
        mock=lambda: _click_mock(selector),
        principal_id=principal_id,
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
) -> dict[str, Any]:
    """在输入框中输入文本（先清空）。

    H1: ``principal_id`` selects the per-principal ``BrowserContext``.
    """
    return await _manager._safe_execute(
        real=_type_real,
        mock=lambda: _type_mock(selector, text),
        principal_id=principal_id,
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


async def browser_snapshot(*, principal_id: str = "") -> dict[str, Any]:
    """获取页面 DOM 快照（完整 HTML，过长截断）。

    H1: ``principal_id`` selects the per-principal ``BrowserContext`` so
    one principal cannot observe another's DOM.
    """
    return await _manager._safe_execute(
        real=_snapshot_real,
        mock=_snapshot_mock,
        principal_id=principal_id,
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


async def browser_screenshot(save_path: str = "", *, principal_id: str = "") -> dict[str, Any]:
    """截图。``save_path`` 非空时存盘，否则返回 base64 编码。

    H1: ``principal_id`` selects the per-principal ``BrowserContext``.
    """
    return await _manager._safe_execute(
        real=_screenshot_real,
        mock=_screenshot_mock,
        principal_id=principal_id,
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
) -> dict[str, Any]:
    """滚动页面（每 ``amount`` 滚动 ``amount * 500`` 像素）。

    H1: ``principal_id`` selects the per-principal ``BrowserContext``.
    """
    return await _manager._safe_execute(
        real=_scroll_real,
        mock=lambda: _scroll_mock(direction, amount),
        principal_id=principal_id,
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


async def browser_evaluate(expression: str, *, principal_id: str = "") -> dict[str, Any]:
    """在页面上下文中执行 JS 表达式（拦截网络类 API）。

    H1: ``principal_id`` selects the per-principal ``BrowserContext`` so
    JS executes against the caller's own cookies / DOM, not a shared pool.
    """
    blocked = _is_expression_blocked(expression)
    if blocked:
        return {"ok": False, "error": blocked}
    return await _manager._safe_execute(
        real=_evaluate_real,
        mock=lambda: {"ok": False, "error": "JS evaluation not available in mock mode"},
        principal_id=principal_id,
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
) -> dict[str, Any]:
    """上传文件到 ``<input type=file>`` 元素。

    B1: the handler validates ``file_path`` is contained within
    ``workspace_root`` (no symlink escape, no arbitrary host file access),
    enforces a size limit, and captures the file identity (inode + size)
    before handing the path to Playwright.  ``network_policy`` is injected
    by the capability broker because this tool declares
    ``network.access``; the handler rejects when network is not enabled.

    H1: ``principal_id`` selects the per-principal ``BrowserContext`` so
    the upload targets the caller's own page, not a shared pool.
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
    validated = _validate_upload_path(file_path, workspace_root)
    if validated is not None:
        return validated
    return await _manager._safe_execute(
        real=_file_upload_real,
        mock=lambda: _file_upload_mock(selector, file_path),
        principal_id=principal_id,
    )


# B1: maximum upload file size — 10 MiB.  Large enough for documents and
# images, small enough to prevent using the browser as a bulk exfiltration
# channel.
_UPLOAD_MAX_BYTES = 10 * 1024 * 1024


def _validate_upload_path(file_path: str, workspace_root: str) -> dict[str, Any] | None:
    """Validate ``file_path`` is within ``workspace_root`` and within size limit.

    B1: returns an error dict when validation fails, or ``None`` when the
    path is safe to upload.  Uses ``Path.resolve(strict=True)`` so symlink
    escape is rejected — the resolved path must be a real file inside the
    resolved workspace root.  Captures inode + size as a fixed identity so
    a TOCTOU swap between validation and upload is detectable.
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


def _file_upload_real(page: Page) -> Any:
    async def _run() -> dict[str, Any]:
        await page.set_input_files(selector, file_path)
        return {"ok": True, "selector": selector, "file": file_path}

    return _run()


def _file_upload_mock(selector: str, file_path: str) -> dict[str, Any]:
    _MOCK_STATE.uploaded.append((selector, file_path))
    return {"ok": True, "selector": selector, "file": file_path}


async def browser_vision(*, principal_id: str = "") -> dict[str, Any]:
    """返回页面状态的文字摘要（URL + 标题）。

    H1: ``principal_id`` selects the per-principal ``BrowserContext`` so
    the summary reflects the caller's own page state, not a shared pool.
    """
    return await _manager._safe_execute(
        real=_vision_real,
        mock=_vision_mock,
        principal_id=principal_id,
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
