"""Tests for web content extraction tools (HTML→Markdown, metadata, tables, fetch)."""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock, patch
from urllib.parse import urlparse

import pytest

from khaos.tools import web_tools
from khaos.tools.web_tools import (
    HTMLToMarkdown,
    extract_metadata,
    extract_tables,
    web_extract_tables,
    web_fetch,
    web_metadata,
)
from khaos.tools.registry import create_runtime_registry


# ===========================================================================
# 1. HTMLToMarkdown
# ===========================================================================


class TestHTMLToMarkdown:
    def setup_method(self):
        self.converter = HTMLToMarkdown()

    def test_heading_conversion(self):
        assert self.converter.convert("<h1>Title</h1>") == "# Title"
        assert self.converter.convert("<h2>Sub</h2>") == "## Sub"
        assert self.converter.convert("<h3>Deep</h3>") == "### Deep"
        assert self.converter.convert("<h6>Deepest</h6>") == "###### Deepest"

    def test_heading_strips_surrounding_whitespace(self):
        assert self.converter.convert("<h1>  Spaced  </h1>") == "# Spaced"

    def test_bold_italic(self):
        assert self.converter.convert("<b>bold</b>") == "**bold**"
        assert self.converter.convert("<strong>strong</strong>") == "**strong**"
        assert self.converter.convert("<em>italic</em>") == "*italic*"
        assert self.converter.convert("<i>italic</i>") == "*italic*"

    def test_bold_and_italic_together(self):
        result = self.converter.convert("<b>bold</b> and <em>italic</em>")
        assert "**bold**" in result
        assert "*italic*" in result

    def test_link_conversion(self):
        result = self.converter.convert('<a href="https://x.test">link text</a>')
        assert result == "[link text](https://x.test)"

    def test_link_with_single_quotes(self):
        result = self.converter.convert("<a href='https://x.test'>link text</a>")
        assert result == "[link text](https://x.test)"

    def test_list_conversion(self):
        result = self.converter.convert("<ul><li>first</li><li>second</li></ul>")
        assert "- first" in result
        assert "- second" in result

    def test_script_removal(self):
        result = self.converter.convert("<script>alert(1)</script><p>kept</p>")
        assert "alert" not in result
        assert "kept" in result

    def test_style_removal(self):
        result = self.converter.convert("<style>body { color: red; }</style><p>kept</p>")
        assert "color" not in result
        assert "kept" in result

    def test_ad_removal_by_class(self):
        result = self.converter.convert('<div class="ad-banner">BUY NOW</div><p>kept</p>')
        assert "BUY NOW" not in result
        assert "kept" in result

    def test_sidebar_removal_by_class(self):
        result = self.converter.convert('<aside class="sidebar">menu</aside><p>kept</p>')
        assert "menu" not in result
        assert "kept" in result

    def test_navigation_removal_by_class(self):
        result = self.converter.convert('<nav class="navigation">nav links</nav><p>kept</p>')
        assert "nav links" not in result
        assert "kept" in result

    def test_real_content_class_is_preserved(self):
        # 'content' is not in the ad/nav blocklist — must survive.
        result = self.converter.convert('<div class="content">real article</div><p>kept</p>')
        assert "real article" in result

    def test_paragraph_double_newline(self):
        result = self.converter.convert("<p>one</p><p>two</p>")
        assert "one" in result
        assert "two" in result
        # Paragraphs separated by a blank line (double newline).
        assert "\n\n" in result

    def test_entity_decode_named(self):
        assert self.converter.convert("<p>a &amp; b</p>").strip() == "a & b"
        assert "&" in self.converter.convert("&amp;")
        assert "<" in self.converter.convert("&lt;")
        assert ">" in self.converter.convert("&gt;")

    def test_entity_decode_nbsp(self):
        result = self.converter.convert("a&nbsp;&nbsp;b")
        assert "  " in result  # nbsp → space

    def test_entity_decode_numeric(self):
        # Decimal &#65; → 'A', hex &#x41; → 'A'.
        assert self.converter.convert("&#65;") == "A"
        assert self.converter.convert("&#x41;") == "A"

    def test_entity_decode_mdash_ndash(self):
        assert "—" in self.converter.convert("&mdash;")
        assert "–" in self.converter.convert("&ndash;")

    def test_collapse_whitespace(self):
        result = self.converter.convert("<p>a</p>\n\n\n\n\n<p>b</p>")
        # No more than two consecutive newlines after collapse.
        assert "\n\n\n" not in result

    def test_complex_html(self):
        html = """
        <html><head><title>Ignored</title><script>bad()</script></head>
        <body>
            <header class="navigation">nav</header>
            <h1>Article Title</h1>
            <p>This is the <strong>first</strong> paragraph with a
            <a href="https://example.com">link</a>.</p>
            <div class="ad-banner">ADVERTISEMENT</div>
            <h2>Section</h2>
            <ul><li>Item one</li><li>Item two</li></ul>
            <p>Final paragraph.</p>
        </body></html>
        """
        result = self.converter.convert(html)
        assert "# Article Title" in result
        assert "## Section" in result
        assert "**first**" in result
        assert "[link](https://example.com)" in result
        assert "- Item one" in result
        assert "- Item two" in result
        assert "Final paragraph." in result
        # Noise removed.
        assert "bad()" not in result
        assert "ADVERTISEMENT" not in result
        assert "navigation" not in result.lower() or "nav" not in result

    def test_empty_html(self):
        assert self.converter.convert("") == ""

    def test_whitespace_only_html(self):
        assert self.converter.convert("   \n\t  ") == ""


# ===========================================================================
# 2. extract_metadata
# ===========================================================================


class TestExtractMetadata:
    def test_title_extraction(self):
        html = "<html><head><title>My Page</title></head><body>x</body></html>"
        meta = extract_metadata(html, "https://example.com")
        assert meta["title"] == "My Page"

    def test_title_with_entities(self):
        meta = extract_metadata("<title>A &amp; B</title>", "https://x.test")
        assert meta["title"] == "A & B"

    def test_meta_description(self):
        html = '<meta name="description" content="A great page about cats">'
        meta = extract_metadata(html, "https://example.com")
        assert meta["description"] == "A great page about cats"

    def test_meta_description_reversed_attr_order(self):
        html = '<meta content="Reversed order" name="description">'
        meta = extract_metadata(html, "https://example.com")
        assert meta["description"] == "Reversed order"

    def test_meta_author(self):
        html = '<meta name="author" content="Jane Doe">'
        meta = extract_metadata(html, "https://example.com")
        assert meta["author"] == "Jane Doe"

    def test_meta_published_time(self):
        html = '<meta property="article:published_time" content="2026-07-08T10:00:00Z">'
        meta = extract_metadata(html, "https://example.com")
        assert meta["published_date"] == "2026-07-08T10:00:00Z"

    def test_links_extraction_dedup(self):
        html = """
        <a href="/a">A</a>
        <a href="https://example.com/a">dup</a>
        <a href="/b">B</a>
        <a href="/a">dup again</a>
        """
        meta = extract_metadata(html, "https://example.com")
        # /a resolved to https://example.com/a, deduped with the absolute one.
        assert "https://example.com/a" in meta["links"]
        assert "https://example.com/b" in meta["links"]
        # No duplicates.
        assert meta["links"].count("https://example.com/a") == 1

    def test_links_skip_anchors_and_javascript(self):
        html = '<a href="#section">anchor</a><a href="javascript:void(0)">js</a><a href="/real">real</a>'
        meta = extract_metadata(html, "https://example.com")
        assert meta["links"] == ["https://example.com/real"]

    def test_links_relative_to_absolute(self):
        html = '<a href="../parent">up</a><a href="/root">root</a>'
        meta = extract_metadata(html, "https://example.com/sub/page")
        assert "https://example.com/parent" in meta["links"]
        assert "https://example.com/root" in meta["links"]

    def test_images_extraction(self):
        html = '<img src="/img/a.png"><img src="https://cdn.com/b.jpg">'
        meta = extract_metadata(html, "https://example.com")
        assert "https://example.com/img/a.png" in meta["images"]
        assert "https://cdn.com/b.jpg" in meta["images"]

    def test_word_count_positive(self):
        html = "<p>one two three four five</p>"
        meta = extract_metadata(html, "https://example.com")
        assert meta["word_count"] == 5

    def test_word_count_strips_tags(self):
        html = "<p><b>bold</b> <i>italic</i></p>"
        meta = extract_metadata(html, "https://example.com")
        assert meta["word_count"] == 2

    def test_url_returned(self):
        meta = extract_metadata("<title>x</title>", "https://example.com")
        assert meta["url"] == "https://example.com"

    def test_empty_html_returns_empty_metadata(self):
        meta = extract_metadata("", "https://example.com")
        assert meta["title"] == ""
        assert meta["description"] == ""
        assert meta["links"] == []
        assert meta["images"] == []
        assert meta["word_count"] == 0
        assert meta["url"] == "https://example.com"


# ===========================================================================
# 3. extract_tables
# ===========================================================================


class TestExtractTables:
    def test_single_table(self):
        html = """
        <table>
          <tr><th>Name</th><th>Age</th></tr>
          <tr><td>Alice</td><td>30</td></tr>
          <tr><td>Bob</td><td>25</td></tr>
        </table>
        """
        tables = extract_tables(html)
        assert len(tables) == 1
        table = tables[0]
        assert table["headers"] == ["Name", "Age"]
        assert table["rows"] == [["Alice", "30"], ["Bob", "25"]]
        assert table["row_count"] == 2

    def test_table_without_th_uses_first_row_as_header(self):
        html = """
        <table>
          <tr><td>H1</td><td>H2</td></tr>
          <tr><td>v1</td><td>v2</td></tr>
        </table>
        """
        tables = extract_tables(html)
        assert tables[0]["headers"] == ["H1", "H2"]
        assert tables[0]["rows"] == [["v1", "v2"]]

    def test_multiple_tables(self):
        html = """
        <table><tr><th>A</th></tr><tr><td>1</td></tr></table>
        <table><tr><th>B</th></tr><tr><td>2</td></tr></table>
        """
        tables = extract_tables(html)
        assert len(tables) == 2
        assert tables[0]["headers"] == ["A"]
        assert tables[1]["headers"] == ["B"]

    def test_no_tables(self):
        assert extract_tables("<p>no tables here</p>") == []

    def test_empty_html_no_tables(self):
        assert extract_tables("") == []

    def test_table_cell_html_stripped(self):
        html = '<table><tr><th>H</th></tr><tr><td><b>bold</b> text</td></tr></table>'
        tables = extract_tables(html)
        assert tables[0]["rows"] == [["bold text"]]

    def test_table_cell_entities_decoded(self):
        html = '<table><tr><th>H</th></tr><tr><td>a &amp; b</td></tr></table>'
        tables = extract_tables(html)
        assert tables[0]["rows"] == [["a & b"]]


# ===========================================================================
# 4. web_fetch / web_extract_tables / web_metadata (mocked HTTP)
# ===========================================================================


def _mock_httpx_response(*, text="", status_code=200, headers=None):
    """Build a fake httpx.Response-like object."""
    resp = MagicMock()
    resp.text = text
    resp.status_code = status_code
    resp.headers = headers or {"content-type": "text/html; charset=utf-8"}
    return resp


@pytest.fixture
def mock_httpx_client(monkeypatch):
    """Patch httpx.AsyncClient to return scripted responses.

    Tests configure ``client.get_response`` / ``client.head_response`` before
    calling the tool.
    """
    if not web_tools._HAS_HTTPX:
        pytest.skip("httpx not installed — HTTP path tests require httpx")

    class _FakeAsyncClient:
        def __init__(self, *args, **kwargs):
            self.get_response = _fake_state["get_response"]
            self.head_response = _fake_state["head_response"]

        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc):
            return False

        async def request(self, method, url):
            response = self.head_response if method == "HEAD" else self.get_response
            if isinstance(response, Exception):
                raise response
            return response

    class _FakeAuthority:
        async def validate_url(self, url, **_kwargs):
            parsed = urlparse(url)
            return web_tools.ValidatedTarget(
                url=url,
                parsed=parsed,
                hostname=parsed.hostname or "",
                addresses=("93.184.216.34",),
            )

    _fake_state = {
        "get_response": _mock_httpx_response(text="<html></html>"),
        "head_response": _mock_httpx_response(text="<html></html>"),
    }
    monkeypatch.setattr(web_tools.httpx, "AsyncClient", _FakeAsyncClient)
    monkeypatch.setattr(web_tools, "_HOST_NETWORK_AUTHORITY", _FakeAuthority())
    return _fake_state


class TestWebFetch:
    async def test_valid_html(self, mock_httpx_client):
        mock_httpx_client["get_response"] = _mock_httpx_response(
            text="<html><head><title>Hello</title></head><body><h1>Title</h1><p>Body text here</p></body></html>"
        )
        result = await web_fetch("https://example.com")
        assert result["ok"] is True
        assert result["url"] == "https://example.com"
        assert result["title"] == "Hello"
        assert "# Title" in result["content"]
        assert "Body text here" in result["content"]
        assert result["word_count"] > 0

    async def test_non_html_content_type(self, mock_httpx_client):
        mock_httpx_client["get_response"] = _mock_httpx_response(
            text='{"key": "value"}',
            headers={"content-type": "application/json"},
        )
        result = await web_fetch("https://example.com/api")
        assert result["ok"] is False
        assert "not HTML" in result["error"]

    async def test_http_error(self, mock_httpx_client):
        mock_httpx_client["get_response"] = _mock_httpx_response(status_code=404)
        result = await web_fetch("https://example.com/missing")
        assert result["ok"] is False
        assert "404" in result["error"]

    async def test_http_500_error(self, mock_httpx_client):
        mock_httpx_client["get_response"] = _mock_httpx_response(status_code=500)
        result = await web_fetch("https://example.com")
        assert result["ok"] is False
        assert "500" in result["error"]

    async def test_timeout(self, mock_httpx_client):
        mock_httpx_client["get_response"] = web_tools.httpx.TimeoutException("timed out")
        result = await web_fetch("https://slow.example.com", timeout=5)
        assert result["ok"] is False
        assert "Timeout after 5s" in result["error"]

    async def test_connection_error(self, mock_httpx_client):
        mock_httpx_client["get_response"] = web_tools.httpx.ConnectError("connection refused")
        result = await web_fetch("https://unreachable.example.com")
        assert result["ok"] is False
        assert "Request failed" in result["error"]

    async def test_invalid_url(self):
        result = await web_fetch("not a url")
        assert result["ok"] is False
        assert "Invalid URL" in result["error"]

    async def test_invalid_url_missing_scheme(self):
        result = await web_fetch("example.com/page")
        assert result["ok"] is False
        assert "Invalid URL" in result["error"]

    async def test_blocks_localhost_url(self):
        result = await web_fetch("http://localhost:8080")

        assert result["ok"] is False
        assert "Invalid URL" in result["error"]

    async def test_blocks_private_ip_url(self):
        result = await web_fetch("http://192.168.1.10")

        assert result["ok"] is False
        assert "Invalid URL" in result["error"]


class TestWebExtractTables:
    async def test_extracts_tables_from_url(self, mock_httpx_client):
        html = """
        <table><tr><th>A</th><th>B</th></tr><tr><td>1</td><td>2</td></tr></table>
        """
        mock_httpx_client["get_response"] = _mock_httpx_response(text=html)
        result = await web_extract_tables("https://example.com/table")
        assert result["ok"] is True
        assert result["table_count"] == 1
        assert result["tables"][0]["headers"] == ["A", "B"]
        assert result["tables"][0]["rows"] == [["1", "2"]]

    async def test_no_tables_in_page(self, mock_httpx_client):
        mock_httpx_client["get_response"] = _mock_httpx_response(text="<p>just text</p>")
        result = await web_extract_tables("https://example.com")
        assert result["ok"] is True
        assert result["table_count"] == 0
        assert result["tables"] == []

    async def test_http_error(self, mock_httpx_client):
        mock_httpx_client["get_response"] = _mock_httpx_response(status_code=403)
        result = await web_extract_tables("https://example.com")
        assert result["ok"] is False
        assert "403" in result["error"]

    async def test_invalid_url(self):
        result = await web_extract_tables("ftp://bad")
        assert result["ok"] is False
        assert "Invalid URL" in result["error"]


class TestWebMetadata:
    async def test_returns_metadata(self, mock_httpx_client):
        html = """
        <html><head>
          <title>Page Title</title>
          <meta name="description" content="A desc">
          <meta name="author" content="Author">
          <meta property="article:published_time" content="2026-07-08">
        </head><body>content</body></html>
        """
        mock_httpx_client["get_response"] = _mock_httpx_response(
            text=html,
            headers={"content-type": "text/html", "content-length": "100"},
        )
        mock_httpx_client["head_response"] = _mock_httpx_response(
            headers={"content-type": "text/html", "content-length": "100"},
        )
        result = await web_metadata("https://example.com")
        assert result["ok"] is True
        assert result["title"] == "Page Title"
        assert result["description"] == "A desc"
        assert result["author"] == "Author"
        assert result["published_date"] == "2026-07-08"
        assert result["content_type"] == "text/html"

    async def test_invalid_url(self):
        result = await web_metadata("nope")
        assert result["ok"] is False
        assert "Invalid URL" in result["error"]

    async def test_timeout(self, mock_httpx_client):
        mock_httpx_client["get_response"] = web_tools.httpx.TimeoutException("timed out")
        mock_httpx_client["head_response"] = web_tools.httpx.TimeoutException("timed out")
        result = await web_metadata("https://slow.example.com")
        assert result["ok"] is False
        assert "Timeout" in result["error"]


# ===========================================================================
# All tool functions return JSON-serialisable dicts
# ===========================================================================


async def test_all_tool_results_are_json_serialisable(mock_httpx_client):
    mock_httpx_client["get_response"] = _mock_httpx_response(text="<title>x</title><p>hi</p>")
    mock_httpx_client["head_response"] = _mock_httpx_response(
        headers={"content-type": "text/html", "content-length": "10"}
    )
    for result in (
        await web_fetch("https://example.com"),
        await web_extract_tables("https://example.com"),
        await web_metadata("https://example.com"),
    ):
        assert isinstance(result, dict)
        json.dumps(result)  # must not raise


# ===========================================================================
# Registry wiring
# ===========================================================================


def test_runtime_registry_binds_web_tools():
    registry = create_runtime_registry()
    for name in ("web_fetch", "web_extract_tables", "web_metadata"):
        tool = registry.get(name)
        assert tool.handler is not None, f"{name} has no handler"
        assert "office" in tool.modes
        assert "coding" in tool.modes
        assert tool.permission_level == "read"
