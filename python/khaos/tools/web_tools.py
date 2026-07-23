"""Web content extraction tools: HTML→Markdown, table extraction, metadata.

Architecture:
- Pure-stdlib HTML processing (regex-based — no BeautifulSoup/lxml dependency),
  tuned for the Agent use case: fast, zero-dependency, content-first extraction
  that strips ads/navigation/scripts rather than producing pixel-perfect output.
- HTTP fetching requires ``httpx``/``httpcore`` so DNS can be validated and
  pinned.  Missing secure transport support fails closed.
- Public tool functions return ``dict[str, Any]`` (the scheduler JSON-encodes
  them into a ``ToolResult``), matching the contract of every other tool module.
"""

from __future__ import annotations

import ipaddress
import logging
import re
from dataclasses import dataclass, field
from typing import Any, Protocol
from urllib.parse import urljoin, urlparse

from khaos.security.host_network import (
    HostNetworkAuthority,
    HostNetworkDeniedError,
    ValidatedTarget,
)

logger = logging.getLogger(__name__)
_SECURITY_ENABLED = True
_HOST_NETWORK_AUTHORITY = HostNetworkAuthority()
_MAX_REDIRECTS = 5
_MAX_HEADER_BYTES = 64 * 1024
_MAX_HTML_BYTES = 2 * 1024 * 1024
_MAX_METADATA_BYTES = 100 * 1024
_MAX_HTML_LINE_CHARS = 256 * 1024
_MAX_LINKS = 1000
_MAX_IMAGES = 500
_MAX_TABLES = 32
_MAX_TABLE_CELLS = 4096
_MAX_CELL_CHARS = 16 * 1024
_MAX_COMPRESSION_RATIO = 100

# httpx is optional at runtime (urllib fallback keeps zero-dependency envs working).
try:  # pragma: no cover - import success depends on the environment
    import httpcore
    import httpx

    _HAS_HTTPX = True
except ImportError:  # pragma: no cover
    httpcore = None  # type: ignore[assignment]
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
    for match in _ALL_HREFS_RE.finditer(html):
        if len(links) >= _MAX_LINKS:
            break
        raw = match.group(1)
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
    for match in _ALL_SRCS_RE.finditer(html):
        if len(images) >= _MAX_IMAGES:
            break
        raw = match.group(1)
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
    cell_count = 0
    for table_match in _TABLE_RE.finditer(html):
        if len(tables) >= _MAX_TABLES:
            break
        table_html = table_match.group(1)
        headers: list[str] = []
        rows: list[list[str]] = []

        for row_match in _TR_RE.finditer(table_html):
            row_html = row_match.group(1)
            # 当前行的 <th> / <td>。
            ths = [
                _clean_cell(match.group(1))[:_MAX_CELL_CHARS]
                for match in _TH_RE.finditer(row_html)
            ]
            tds = [
                _clean_cell(match.group(1))[:_MAX_CELL_CHARS]
                for match in _TD_RE.finditer(row_html)
            ]
            if cell_count + len(ths) + len(tds) > _MAX_TABLE_CELLS:
                raise ValueError(
                    f"table cell count exceeds {_MAX_TABLE_CELLS}"
                )
            cell_count += len(ths) + len(tds)

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
    return parsed.scheme in {"http", "https"} and bool(parsed.netloc) and _is_safe_url(parsed)


def enable_security(enabled: bool = True) -> None:
    """启用/禁用 URL 安全检查（测试用）。"""
    global _SECURITY_ENABLED
    _SECURITY_ENABLED = enabled


def _is_safe_url(parsed) -> bool:
    if not _SECURITY_ENABLED:
        return True
    hostname = (parsed.hostname or "").strip().lower().rstrip(".")
    if not hostname:
        return False
    if hostname == "localhost" or hostname.endswith(".localhost"):
        return False
    try:
        ip = ipaddress.ip_address(hostname.strip("[]"))
    except ValueError:
        return True
    return not (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


class _HTTPError(Exception):
    """携带状态码的 HTTP 错误。"""

    def __init__(self, status_code: int, message: str = ""):
        super().__init__(message or f"HTTP {status_code}")
        self.status_code = status_code


class _ResponseLimitError(ValueError):
    """Raised before a host response can exceed its configured hard bound."""


class _EgressAuthority(Protocol):
    async def authorize_url(
        self,
        url: str,
        *,
        previous_scheme: str | None = None,
    ) -> ValidatedTarget: ...


@dataclass(frozen=True)
class _BufferedResponse:
    status_code: int
    headers: dict[str, str]
    content: bytes
    encoding: str = "utf-8"

    @property
    def text(self) -> str:
        return self.content.decode(self.encoding, errors="replace")


class _DefaultEgressAuthority:
    """Public-address-only authority used by direct library callers."""

    async def authorize_url(
        self,
        url: str,
        *,
        previous_scheme: str | None = None,
    ) -> ValidatedTarget:
        return await _HOST_NETWORK_AUTHORITY.validate_url(
            url,
            previous_scheme=previous_scheme,
        )


async def _fetch_html(
    url: str,
    timeout: int,
    *,
    network_guard: _EgressAuthority | None = None,
) -> tuple[str, str]:
    """抓取 URL，返回 (html, content_type)。

    httpx 优先；不可用时回退到 urllib（同步，包在 to_thread 里）。
    content-type 非 HTML 时抛出 ValueError。
    """
    if not _HAS_HTTPX:
        raise ConnectionError(
            "secure host fetching requires httpx/httpcore; refusing insecure fallback"
        )
    return await _fetch_html_httpx(url, timeout, network_guard=network_guard)


class _PinnedNetworkBackend:
    """httpcore backend that connects to an authority-approved DNS snapshot."""

    def __init__(self, target: ValidatedTarget) -> None:
        self._hostname = target.hostname
        self._addresses = target.addresses
        self._backend = httpcore.AnyIOBackend()

    async def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options=None,
    ):
        normalized = host.decode("ascii") if isinstance(host, bytes) else host
        if normalized.lower().rstrip(".") != self._hostname:
            raise HostNetworkDeniedError("transport attempted an unvalidated hostname")
        last_error: Exception | None = None
        for address in self._addresses:
            try:
                return await self._backend.connect_tcp(
                    address,
                    port,
                    timeout=timeout,
                    local_address=local_address,
                    socket_options=socket_options,
                )
            except Exception as exc:  # network backend errors vary by runtime
                last_error = exc
        if last_error is not None:
            raise last_error
        raise HostNetworkDeniedError("validated target has no pinned addresses")

    async def connect_unix_socket(self, path: str, timeout=None, socket_options=None):
        raise HostNetworkDeniedError("Unix sockets are prohibited for host web tools")

    async def sleep(self, seconds: float) -> None:
        await self._backend.sleep(seconds)


def _pinned_transport(target: ValidatedTarget):
    transport = httpx.AsyncHTTPTransport(trust_env=False, retries=0)
    # HTTPX does not expose a public resolver hook.  Its supported transport
    # is backed by httpcore, whose network backend is explicitly pluggable.
    # Replacing it before the first request pins connect_tcp while preserving
    # the original hostname for HTTP Host and TLS SNI/certificate validation.
    transport._pool._network_backend = _PinnedNetworkBackend(target)
    return transport


def _header_size(headers: Any) -> int:
    return sum(len(str(key)) + len(str(value)) + 4 for key, value in headers.items())


async def _read_bounded_response(response: Any, body_limit: int) -> bytes:
    if _header_size(response.headers) > _MAX_HEADER_BYTES:
        raise _ResponseLimitError(
            f"response headers exceed {_MAX_HEADER_BYTES} bytes"
        )
    content_length = response.headers.get("content-length")
    if content_length is not None:
        try:
            declared_length = int(content_length)
        except ValueError as exc:
            raise _ResponseLimitError("invalid Content-Length header") from exc
        if declared_length < 0 or declared_length > body_limit:
            raise _ResponseLimitError(f"response body exceeds {body_limit} bytes")

    body = bytearray()
    async for chunk in response.aiter_bytes():
        if len(body) + len(chunk) > body_limit:
            raise _ResponseLimitError(f"response body exceeds {body_limit} bytes")
        body.extend(chunk)
    if (
        response.headers.get("content-encoding")
        and content_length is not None
        and declared_length > 0
        and len(body) > declared_length * _MAX_COMPRESSION_RATIO
    ):
        raise _ResponseLimitError(
            f"response compression ratio exceeds {_MAX_COMPRESSION_RATIO}:1"
        )
    return bytes(body)


async def _request_httpx(
    method: str,
    url: str,
    timeout: int,
    *,
    network_guard: _EgressAuthority | None = None,
    body_limit: int = _MAX_HTML_BYTES,
) -> _BufferedResponse:
    current = url
    previous_scheme: str | None = None
    authority = network_guard or _DefaultEgressAuthority()
    for hop in range(_MAX_REDIRECTS + 1):
        target = await authority.authorize_url(
            current, previous_scheme=previous_scheme
        )
        try:
            async with httpx.AsyncClient(
                transport=_pinned_transport(target),
                follow_redirects=False,
                trust_env=False,
                timeout=httpx.Timeout(timeout),
                headers={"User-Agent": "KhaosWebFetcher/1.0"},
            ) as client:
                async with client.stream(method, current) as response:
                    status_code = response.status_code
                    headers = dict(response.headers)
                    if status_code not in {301, 302, 303, 307, 308}:
                        content = (
                            b""
                            if method == "HEAD"
                            else await _read_bounded_response(response, body_limit)
                        )
                        return _BufferedResponse(
                            status_code=status_code,
                            headers=headers,
                            content=content,
                            encoding=getattr(response, "encoding", None) or "utf-8",
                        )
        except httpx.TimeoutException as exc:
            raise TimeoutError(f"Timeout after {timeout}s") from exc
        except httpx.HTTPError as exc:
            raise ConnectionError(str(exc)) from exc
        location = headers.get("location")
        if not location:
            raise ConnectionError("redirect response omitted Location")
        if hop >= _MAX_REDIRECTS:
            raise ConnectionError(f"too many redirects (maximum {_MAX_REDIRECTS})")
        previous_scheme = target.parsed.scheme.lower()
        current = urljoin(current, location)
        if status_code == 303 and method != "HEAD":
            method = "GET"
    raise ConnectionError("redirect processing failed")


async def _fetch_html_httpx(
    url: str,
    timeout: int,
    *,
    network_guard: _EgressAuthority | None = None,
) -> tuple[str, str]:
    try:
        response = await _request_httpx(
            "GET",
            url,
            timeout,
            network_guard=network_guard,
            body_limit=_MAX_HTML_BYTES,
        )
    except HostNetworkDeniedError:
        raise

    if response.status_code >= 400:
        raise _HTTPError(response.status_code)

    content_type = response.headers.get("content-type", "").split(";")[0].strip().lower()
    if content_type and "html" not in content_type:
        raise ValueError(f"Content type not HTML: {content_type}")

    # 编码：优先响应头声明的 charset，否则按 httpx 的 best effort。
    text = response.text
    if any(len(line) > _MAX_HTML_LINE_CHARS for line in text.splitlines()):
        raise _ResponseLimitError(
            f"HTML line exceeds {_MAX_HTML_LINE_CHARS} characters"
        )
    return text, content_type


async def _fetch_html_urllib(url: str, timeout: int) -> tuple[str, str]:
    raise ConnectionError(
        "urllib fallback is disabled because it cannot pin validated DNS safely"
    )


async def _fetch_head(
    url: str,
    timeout: int,
    *,
    network_guard: _EgressAuthority | None = None,
) -> tuple[dict[str, str], str]:
    """轻量抓取：HEAD 拿响应头 + 只读 body 前 100KB。

    返回 (headers_dict, body_prefix)。urllib 回退路径用 GET（HEAD 支持不稳定）。
    """
    body_limit = _MAX_METADATA_BYTES
    if _HAS_HTTPX:
        try:
            # Keep HEAD for status/protocol coverage, then use a separately
            # validated and pinned GET for the body prefix.
            await _request_httpx(
                "HEAD", url, timeout, network_guard=network_guard, body_limit=0
            )
            get_resp = await _request_httpx(
                "GET",
                url,
                timeout,
                network_guard=network_guard,
                body_limit=body_limit,
            )
            if get_resp.status_code >= 400:
                raise _HTTPError(get_resp.status_code)
            return dict(get_resp.headers), get_resp.text
        except HostNetworkDeniedError:
            raise
    raise ConnectionError(
        "secure host fetching requires httpx/httpcore; refusing insecure fallback"
    )


# ─── 工具函数 ───


async def web_fetch(
    url: str,
    timeout: int = 30,
    *,
    network_guard: _EgressAuthority | None = None,
    network_policy: str = "none",
    credential_context: Any = None,
    principal_id: str = "",
) -> dict[str, Any]:
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
        html, _content_type = await _fetch_html(
            url, timeout, network_guard=network_guard
        )
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


async def web_extract_tables(
    url: str,
    *,
    network_guard: _EgressAuthority | None = None,
    network_policy: str = "none",
    credential_context: Any = None,
    principal_id: str = "",
) -> dict[str, Any]:
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
        html, _content_type = await _fetch_html(
            url, timeout=30, network_guard=network_guard
        )
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


async def web_metadata(
    url: str,
    *,
    network_guard: _EgressAuthority | None = None,
    network_policy: str = "none",
    credential_context: Any = None,
    principal_id: str = "",
) -> dict[str, Any]:
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
        headers, body_prefix = await _fetch_head(
            url, timeout=30, network_guard=network_guard
        )
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
