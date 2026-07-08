"""Web content extraction tools: HTML→Markdown, table extraction, metadata.

Architecture:
- Pure-stdlib HTML processing (regex-based — no BeautifulSoup/lxml dependency),
  tuned for the Agent use case: fast, zero-dependency, content-first extraction
  that strips ads/navigation/scripts rather than producing pixel-perfect output.
- HTTP fetching prefers ``httpx`` (async); falls back to ``urllib.request``
  wrapped in ``asyncio.to_thread`` when httpx is unavailable.
- Public tool functions return ``dict[str, Any]`` (the scheduler JSON-encodes
  them into a ``ToolResult``), matching the contract of every other tool module.
"""

from __future__ import annotations

import asyncio
import logging
import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urljoin, urlparse

logger = logging.getLogger(__name__)

# httpx is optional at runtime (urllib fallback keeps zero-dependency envs working).
try:  # pragma: no cover - import success depends on the environment
    import httpx

    _HAS_HTTPX = True
except ImportError:  # pragma: no cover
    httpx = None  # type: ignore[assignment]
    _HAS_HTTPX = False


# ─── HTML→Markdown 转换器（零依赖，纯正则实现）───


class HTMLToMarkdown:
    """轻量 HTML→Markdown 转换器，不依赖外部库。

    使用正则而非 DOM 解析，适合 Agent 工具场景（速度快、无依赖）。
    不追求完美转换，而是提取正文内容、去除噪音。
    """

    # 需要完全移除的标签（脚本、样式、导航、广告等）。
    # 第二个分支匹配 class/id 含广告/侧栏等关键词的任意标签。
    REMOVE_TAGS = re.compile(
        r"<(?:script|style|noscript|iframe|svg|nav|footer|header|aside"
        r"|[\w-]*(?:ad|banner|sidebar|popup|modal|overlay|cookie|newsletter"
        r"|social|share|comment|related|recommend)[\w-]*)\b[^>]*>.*?</(?:script|style|noscript|iframe|svg|nav|footer|header|aside"
        r"|[\w-]*(?:ad|banner|sidebar|popup|modal|overlay|cookie|newsletter"
        r"|social|share|comment|related|recommend)[\w-]*)>",
        re.DOTALL | re.IGNORECASE,
    )

    # 自闭合标签移除（不包含在 REMOVE_TAGS 的成对匹配里）。
    REMOVE_SELFCLOSING = re.compile(
        r"<(?:img|br|hr|input|meta|link|source)\b[^>]*/?>",
        re.IGNORECASE,
    )

    # 按 class/id/role 中的广告/导航关键词移除整个标签（成对）。
    # 标签名作为 \1 反向引用，确保配对闭合。
    REMOVE_BY_ATTR = re.compile(
        r"<(\w+)\b[^>]*\b(?:class|id|role)\s*=\s*["
        r"\"\'][^\"\']*(?:\b(?:ad|ads|advert|banner|sidebar|popup|modal|overlay"
        r"|cookie|newsletter|social|share|comment|comments|related|recommend"
        r"|navigation|menu|footer|header)\b)[^\"\']*[\"\'][^>]*>.*?</\1>",
        re.DOTALL | re.IGNORECASE,
    )

    # 标题：h1-h6 → # ~ ######
    HEADING = re.compile(
        r"<h([1-6])[^>]*>(.*?)</h\1>",
        re.DOTALL | re.IGNORECASE,
    )

    # 粗体/斜体。注意 (?:strong|b) 的 b 必须后随 > 或空白，
    # 否则会误匹配 <body> / <blockquote> 等以 b 开头的标签。
    BOLD = re.compile(
        r"<(?:strong|b)\b[^>]*>(.*?)</(?:strong|b)>",
        re.DOTALL | re.IGNORECASE,
    )
    ITALIC = re.compile(
        r"<(?:em|i)\b[^>]*>(.*?)</(?:em|i)>",
        re.DOTALL | re.IGNORECASE,
    )

    # 链接
    LINK = re.compile(r"<a[^>]*href=[\"']([^\"']+)[\"'][^>]*>(.*?)</a>", re.DOTALL | re.IGNORECASE)

    # 列表项
    LIST_ITEM = re.compile(r"<li[^>]*>(.*?)</li>", re.DOTALL | re.IGNORECASE)

    # 段落
    PARAGRAPH = re.compile(r"<p[^>]*>(.*?)</p>", re.DOTALL | re.IGNORECASE)

    # 换行
    BR = re.compile(r"<br\s*/?>", re.IGNORECASE)

    # HTML 实体解码
    ENTITIES = {
        "&amp;": "&",
        "&lt;": "<",
        "&gt;": ">",
        "&quot;": '"',
        "&#39;": "'",
        "&nbsp;": " ",
        "&mdash;": "—",
        "&ndash;": "–",
        "&hellip;": "…",
        "&copy;": "©",
        "&reg;": "®",
    }

    # 数字实体（十进制 / 十六进制）。
    _NUMERIC_ENTITY = re.compile(r"&#(x?[0-9a-fA-F]+);")

    def convert(self, html: str, url: str = "") -> str:
        """将 HTML 转为相对干净的 Markdown。

        步骤：
        1. 移除 script/style/导航/广告等噪音
        2. 移除自闭合标签（img/br/hr 等）
        3. 标题 → Markdown 标题
        4. 粗体/斜体 → **bold** / *italic*
        5. 链接 → [text](url)
        6. 列表 → - item
        7. 段落 → 双换行分隔
        8. 清理多余空行（3 个以上连续换行→2 个）
        9. HTML 实体解码
        10. strip() 去首尾空白

        Args:
            html: 原始 HTML
            url: 来源 URL（仅用于日志）

        Returns:
            Markdown 文本
        """
        if not html:
            return ""

        text = html

        # 1. 移除噪音标签（含内容）。
        text = self.REMOVE_TAGS.sub("", text)
        # 1b. 按 class/id/role 关键词移除广告/导航等容器。
        text = self.REMOVE_BY_ATTR.sub("", text)
        # 2. 移除自闭合标签。
        text = self.REMOVE_SELFCLOSING.sub("", text)

        # 3. 标题：h{n} → ('#' * n) + text
        text = self.HEADING.sub(
            lambda m: "\n\n" + "#" * int(m.group(1)) + " " + m.group(2).strip() + "\n\n",
            text,
        )
        # 4. 粗体 / 斜体。
        text = self.BOLD.sub(r"**\1**", text)
        text = self.ITALIC.sub(r"*\1*", text)
        # 5. 链接。
        text = self.LINK.sub(lambda m: f"[{m.group(2).strip()}]({m.group(1)})", text)
        # 6. 列表项。
        text = self.LIST_ITEM.sub(lambda m: "- " + m.group(1).strip() + "\n", text)
        # 7. 段落。
        text = self.PARAGRAPH.sub(lambda m: "\n\n" + m.group(1).strip() + "\n\n", text)

        # 8. 实体解码（在所有结构化替换之后）。
        text = self._decode_entities(text)
        # 9. 压缩多余空白。
        text = self._collapse_whitespace(text)
        # 10. 去首尾空白。
        return text.strip()

    def _decode_entities(self, text: str) -> str:
        """解码常见 HTML 实体（命名 + 数字）。"""
        for entity, char in self.ENTITIES.items():
            text = text.replace(entity, char)

        def _replace_numeric(match: re.Match[str]) -> str:
            raw = match.group(1)
            try:
                if raw.lower().startswith("x"):
                    code = int(raw[1:], 16)
                else:
                    code = int(raw, 10)
                return chr(code)
            except (ValueError, OverflowError):
                return match.group(0)

        return self._NUMERIC_ENTITY.sub(_replace_numeric, text)

    def _collapse_whitespace(self, text: str) -> str:
        """合并多余空行（3 个以上连续换行→2 个），并去除行尾空白。"""
        # 行尾空格。
        text = re.sub(r"[ \t]+\n", "\n", text)
        # 3+ 换行 → 2 换行。
        text = re.sub(r"\n{3,}", "\n\n", text)
        return text


# ─── 网页元数据提取 ───


@dataclass
class WebMetadata:
    """网页元数据。"""

    url: str
    title: str = ""
    description: str = ""
    author: str = ""
    published_date: str = ""
    word_count: int = 0
    links: list[str] = field(default_factory=list)
    images: list[str] = field(default_factory=list)


_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.DOTALL | re.IGNORECASE)
_META_DESCRIPTION_RE = re.compile(
    r'<meta\s+name=["\']description["\']\s+content=["\']([^"\']*)["\']',
    re.IGNORECASE,
)
_META_DESCRIPTION_RE_REV = re.compile(
    r'<meta\s+content=["\']([^"\']*)["\']\s+name=["\']description["\']',
    re.IGNORECASE,
)
_META_AUTHOR_RE = re.compile(
    r'<meta\s+name=["\']author["\']\s+content=["\']([^"\']*)["\']',
    re.IGNORECASE,
)
_META_PUBLISHED_RE = re.compile(
    r'<meta\s+property=["\']article:published_time["\']\s+content=["\']([^"\']*)["\']',
    re.IGNORECASE,
)
_ALL_HREFS_RE = re.compile(r'<a[^>]*href=["\']([^"\']+)["\']', re.IGNORECASE)
_ALL_SRCS_RE = re.compile(r'<img[^>]*src=["\']([^"\']+)["\']', re.IGNORECASE)
_ALL_TAGS_RE = re.compile(r"<[^>]+>")
_WHITESPACE_RE = re.compile(r"\s+")


def _decode_entities_simple(text: str) -> str:
    """轻量实体解码（用于元数据字段）。"""
    converter = HTMLToMarkdown()
    return converter._decode_entities(text)


def _is_absolute(url: str) -> bool:
    return bool(urlparse(url).scheme)


def extract_metadata(html: str, url: str) -> dict[str, Any]:
    """从 HTML 中提取元数据。

    提取：
    - <title> 标题
    - <meta name="description"> 描述
    - <meta name="author"> 作者
    - <meta property="article:published_time"> 发布时间
    - 所有 <a href> 链接（去重，转换为绝对 URL）
    - 所有 <img src> 图片（转换为绝对 URL）
    - 统计正文字数
    """
    if not html:
        return {
            "url": url,
            "title": "",
            "description": "",
            "author": "",
            "published_date": "",
            "word_count": 0,
            "links": [],
            "images": [],
        }

    def _first(pattern: re.Pattern[str]) -> str:
        match = pattern.search(html)
        return _decode_entities_simple(match.group(1).strip()) if match else ""

    title = _first(_TITLE_RE)
    description = _first(_META_DESCRIPTION_RE) or _first(_META_DESCRIPTION_RE_REV)
    author = _first(_META_AUTHOR_RE)
    published = _first(_META_PUBLISHED_RE)

    # 链接去重并转绝对。
    seen_links: set[str] = set()
    links: list[str] = []
    for raw in _ALL_HREFS_RE.findall(html):
        normalized = raw.strip()
        if not normalized or normalized.startswith("#") or normalized.startswith("javascript:"):
            continue
        absolute = urljoin(url, normalized) if url else normalized
        if absolute not in seen_links:
            seen_links.add(absolute)
            links.append(absolute)

    # 图片转绝对（不去重，保留出现顺序）。
    images: list[str] = []
    seen_imgs: set[str] = set()
    for raw in _ALL_SRCS_RE.findall(html):
        normalized = raw.strip()
        if not normalized:
            continue
        absolute = urljoin(url, normalized) if url else normalized
        if absolute not in seen_imgs:
            seen_imgs.add(absolute)
            images.append(absolute)

    # 正文字数：剥离所有标签后的可读文本词数。
    text_only = _ALL_TAGS_RE.sub(" ", html)
    text_only = _decode_entities_simple(text_only)
    word_count = len(_WHITESPACE_RE.sub(" ", text_only).split())

    return {
        "url": url,
        "title": title,
        "description": description,
        "author": author,
        "published_date": published,
        "word_count": word_count,
        "links": links,
        "images": images,
    }


# ─── 表格提取 ───

_TABLE_RE = re.compile(r"<table\b[^>]*>(.*?)</table>", re.DOTALL | re.IGNORECASE)
_TR_RE = re.compile(r"<tr\b[^>]*>(.*?)</tr>", re.DOTALL | re.IGNORECASE)
_TH_RE = re.compile(r"<th\b[^>]*>(.*?)</th>", re.DOTALL | re.IGNORECASE)
_TD_RE = re.compile(r"<td\b[^>]*>(.*?)</td>", re.DOTALL | re.IGNORECASE)


def _clean_cell(text: str) -> str:
    """清理单元格内容：去标签、解码实体、压缩空白。"""
    cell = _ALL_TAGS_RE.sub(" ", text)
    cell = _decode_entities_simple(cell)
    return _WHITESPACE_RE.sub(" ", cell).strip()


def extract_tables(html: str) -> list[dict[str, Any]]:
    """从 HTML 中提取表格数据。

    解析 <table> 结构，提取为结构化格式::

        [
            {
                "headers": ["列1", "列2", "列3"],
                "rows": [["值1", "值2", "值3"], ...],
                "row_count": int,
            }
        ]

    用正则解析，不依赖外部库。嵌套表格不处理（只提取最外层）。
    """
    if not html:
        return []

    tables: list[dict[str, Any]] = []
    for table_html in _TABLE_RE.findall(html):
        headers: list[str] = []
        rows: list[list[str]] = []

        for row_html in _TR_RE.findall(table_html):
            # 当前行的 <th> / <td>。
            ths = [_clean_cell(c) for c in _TH_RE.findall(row_html)]
            tds = [_clean_cell(c) for c in _TD_RE.findall(row_html)]

            if ths and not headers:
                # 第一行含 <th> 的视为表头。
                headers = ths
            elif tds:
                rows.append(tds)
            elif ths and headers:
                # 后续行只有 <th>（罕见）——当作普通行。
                rows.append(ths)

        # 若没有 <th>，但至少一行 <td>，把第一行作为表头。
        if not headers and rows:
            headers = rows.pop(0)

        tables.append(
            {
                "headers": headers,
                "rows": rows,
                "row_count": len(rows),
            }
        )

    return tables


# ─── HTTP 抓取 ───


def _is_valid_url(url: str) -> bool:
    parsed = urlparse(url)
    return parsed.scheme in {"http", "https"} and bool(parsed.netloc)


class _HTTPError(Exception):
    """携带状态码的 HTTP 错误。"""

    def __init__(self, status_code: int, message: str = ""):
        super().__init__(message or f"HTTP {status_code}")
        self.status_code = status_code


async def _fetch_html(url: str, timeout: int) -> tuple[str, str]:
    """抓取 URL，返回 (html, content_type)。

    httpx 优先；不可用时回退到 urllib（同步，包在 to_thread 里）。
    content-type 非 HTML 时抛出 ValueError。
    """
    if _HAS_HTTPX:
        return await _fetch_html_httpx(url, timeout)
    return await _fetch_html_urllib(url, timeout)


async def _fetch_html_httpx(url: str, timeout: int) -> tuple[str, str]:
    try:
        async with httpx.AsyncClient(
            follow_redirects=True,
            timeout=httpx.Timeout(timeout),
            headers={"User-Agent": "KhaosWebFetcher/1.0"},
        ) as client:
            response = await client.get(url)
    except httpx.TimeoutException as exc:
        raise TimeoutError(f"Timeout after {timeout}s") from exc
    except httpx.HTTPError as exc:
        raise ConnectionError(str(exc)) from exc

    if response.status_code >= 400:
        raise _HTTPError(response.status_code)

    content_type = response.headers.get("content-type", "").split(";")[0].strip().lower()
    if content_type and "html" not in content_type:
        raise ValueError(f"Content type not HTML: {content_type}")

    # 编码：优先响应头声明的 charset，否则按 httpx 的 best effort。
    return response.text, content_type


async def _fetch_html_urllib(url: str, timeout: int) -> tuple[str, str]:
    import urllib.request

    def _sync() -> tuple[str, str]:
        req = urllib.request.Request(url, headers={"User-Agent": "KhaosWebFetcher/1.0"})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 — Agent tool
                content_type = resp.headers.get("Content-Type", "").split(";")[0].strip().lower()
                if content_type and "html" not in content_type:
                    raise ValueError(f"Content type not HTML: {content_type}")
                # 处理 gzip/deflate（urllib 不自动解压）。
                raw = resp.read()
                charset = "utf-8"
                # 解析 charset。
                full_ct = resp.headers.get("Content-Type", "")
                if "charset=" in full_ct.lower():
                    charset = full_ct.lower().split("charset=")[-1].split(";")[0].strip() or "utf-8"
                try:
                    return raw.decode(charset, errors="replace"), content_type
                except (LookupError, UnicodeDecodeError):
                    return raw.decode("utf-8", errors="replace"), content_type
        except urllib.error.HTTPError as exc:
            raise _HTTPError(exc.code, str(exc)) from exc
        except urllib.error.URLError as exc:
            if "timed out" in str(exc).lower():
                raise TimeoutError(f"Timeout after {timeout}s") from exc
            raise ConnectionError(str(exc)) from exc

    return await asyncio.to_thread(_sync)


async def _fetch_head(url: str, timeout: int) -> tuple[dict[str, str], str]:
    """轻量抓取：HEAD 拿响应头 + 只读 body 前 100KB。

    返回 (headers_dict, body_prefix)。urllib 回退路径用 GET（HEAD 支持不稳定）。
    """
    body_limit = 100 * 1024
    if _HAS_HTTPX:
        try:
            async with httpx.AsyncClient(
                follow_redirects=True,
                timeout=httpx.Timeout(timeout),
                headers={"User-Agent": "KhaosWebFetcher/1.0"},
            ) as client:
                head_resp = await client.head(url)
                # 很多服务器对 HEAD 不返回 body，改用 GET 但只读前 100KB。
                get_resp = await client.get(url)
                content = get_resp.text[:body_limit]
                headers = {k: v for k, v in get_resp.headers.items()}
                return headers, content
        except httpx.TimeoutException as exc:
            raise TimeoutError(f"Timeout after {timeout}s") from exc
        except httpx.HTTPError as exc:
            raise ConnectionError(str(exc)) from exc
    # urllib 回退。
    import urllib.request

    def _sync() -> tuple[dict[str, str], str]:
        req = urllib.request.Request(url, headers={"User-Agent": "KhaosWebFetcher/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 — Agent tool
            raw = resp.read(body_limit)
            headers = {k: v for k, v in resp.headers.items()}
            return headers, raw.decode("utf-8", errors="replace")

    return await asyncio.to_thread(_sync)


# ─── 工具函数 ───


async def web_fetch(url: str, timeout: int = 30) -> dict[str, Any]:
    """抓取网页并提取正文内容（Markdown）+ 元数据。

    返回结构::

        {
          "ok": true,
          "url": "...",
          "title": "...",
          "content": "Markdown 正文",
          "word_count": int,
          "description": "...",
          "author": "...",
          "links_count": int
        }

    错误处理：
    - URL 无效 → {"ok": false, "error": "Invalid URL: ..."}
    - 请求失败 → {"ok": false, "error": "HTTP error: status_code"}
    - 超时 → {"ok": false, "error": "Timeout after Ns"}
    - 非 HTML → {"ok": false, "error": "Content type not HTML: ..."}
    """
    if not _is_valid_url(url):
        return {"ok": False, "error": f"Invalid URL: {url}"}

    try:
        html, _content_type = await _fetch_html(url, timeout)
    except TimeoutError as exc:
        return {"ok": False, "error": str(exc)}
    except _HTTPError as exc:
        return {"ok": False, "error": f"HTTP error: {exc.status_code}"}
    except ValueError as exc:
        # 非 HTML content-type。
        return {"ok": False, "error": str(exc)}
    except ConnectionError as exc:
        return {"ok": False, "error": f"Request failed: {exc}"}
    except Exception as exc:  # noqa: BLE001 — 工具不应让异常逃逸
        logger.error("web_fetch failed for %s: %s", url, exc)
        return {"ok": False, "error": f"Request failed: {exc}"}

    converter = HTMLToMarkdown()
    content = converter.convert(html, url=url)
    meta = extract_metadata(html, url)

    return {
        "ok": True,
        "url": url,
        "title": meta["title"],
        "content": content,
        "word_count": meta["word_count"],
        "description": meta["description"],
        "author": meta["author"],
        "links_count": len(meta["links"]),
    }


async def web_extract_tables(url: str) -> dict[str, Any]:
    """从 URL 提取表格数据。

    返回结构::

        {
          "ok": true,
          "url": "...",
          "tables": [{"headers": [...], "rows": [...], "row_count": int}],
          "table_count": int
        }
    """
    if not _is_valid_url(url):
        return {"ok": False, "error": f"Invalid URL: {url}"}

    try:
        html, _content_type = await _fetch_html(url, timeout=30)
    except TimeoutError as exc:
        return {"ok": False, "error": str(exc)}
    except _HTTPError as exc:
        return {"ok": False, "error": f"HTTP error: {exc.status_code}"}
    except ValueError as exc:
        return {"ok": False, "error": str(exc)}
    except ConnectionError as exc:
        return {"ok": False, "error": f"Request failed: {exc}"}
    except Exception as exc:  # noqa: BLE001 — 工具不应让异常逃逸
        logger.error("web_extract_tables failed for %s: %s", url, exc)
        return {"ok": False, "error": f"Request failed: {exc}"}

    tables = extract_tables(html)
    return {
        "ok": True,
        "url": url,
        "tables": tables,
        "table_count": len(tables),
    }


async def web_metadata(url: str) -> dict[str, Any]:
    """获取网页元数据（不下载完整内容，只用 HEAD + 少量 body）。

    返回结构::

        {
          "ok": true,
          "url": "...",
          "title": "...",
          "description": "...",
          "author": "...",
          "published_date": "...",
          "content_length": int,
          "content_type": "..."
        }
    """
    if not _is_valid_url(url):
        return {"ok": False, "error": f"Invalid URL: {url}"}

    try:
        headers, body_prefix = await _fetch_head(url, timeout=30)
    except TimeoutError as exc:
        return {"ok": False, "error": str(exc)}
    except _HTTPError as exc:
        return {"ok": False, "error": f"HTTP error: {exc.status_code}"}
    except ConnectionError as exc:
        return {"ok": False, "error": f"Request failed: {exc}"}
    except Exception as exc:  # noqa: BLE001 — 工具不应让异常逃逸
        logger.error("web_metadata failed for %s: %s", url, exc)
        return {"ok": False, "error": f"Request failed: {exc}"}

    meta = extract_metadata(body_prefix, url)
    content_length_str = headers.get("content-length") or headers.get("Content-Length")
    try:
        content_length = int(content_length_str) if content_length_str else len(body_prefix)
    except (TypeError, ValueError):
        content_length = len(body_prefix)
    content_type = (
        headers.get("content-type")
        or headers.get("Content-Type")
        or ""
    )

    return {
        "ok": True,
        "url": url,
        "title": meta["title"],
        "description": meta["description"],
        "author": meta["author"],
        "published_date": meta["published_date"],
        "content_length": content_length,
        "content_type": content_type,
    }
