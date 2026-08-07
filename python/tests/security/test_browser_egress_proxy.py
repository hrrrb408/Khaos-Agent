from __future__ import annotations

import asyncio
import base64
from urllib.parse import urlsplit

from khaos.security.browser_egress_proxy import BrowserEgressProxy
from khaos.security.browser_egress_proxy import _parse_tls_sni
from khaos.security.host_network import ValidatedTarget


def _proxy_auth_header(proxy: BrowserEgressProxy) -> str:
    """C-07: build the ``Proxy-Authorization`` header for a proxy instance."""
    credentials = f"{proxy.proxy_username}:{proxy.proxy_password}"
    encoded = base64.b64encode(credentials.encode("ascii")).decode("ascii")
    return f"Proxy-Authorization: Basic {encoded}\r\n"


class _PinnedGuard:
    def __init__(self, address: str = "127.0.0.1") -> None:
        self.address = address
        self.urls: list[str] = []

    async def authorize_url(self, url: str) -> ValidatedTarget:
        self.urls.append(url)
        parsed = urlsplit(url)
        return ValidatedTarget(
            url=url,
            parsed=parsed,
            hostname=parsed.hostname or "",
            addresses=(self.address,),
        )


def _build_tls_client_hello(sni: str | None = None) -> bytes:
    """Build a minimal TLS 1.2 ClientHello record for tests.

    If ``sni`` is provided the SNI extension carries that hostname.  If
    ``sni`` is ``None`` the ClientHello has no extensions (no SNI).
    The structure follows RFC 5246 §7.4.1.2 and RFC 6066 §3.
    """
    # --- ClientHello body ---
    body = bytearray()
    body += b"\x03\x03"          # client_version (TLS 1.2)
    body += b"\x00" * 32         # random (32 bytes)
    body += b"\x00"              # session_id length = 0
    body += b"\x00\x02\x00\xff"  # cipher_suites: 1 suite (TLS_EMPTY_RENEGOTIATION_INFO_SCSV)
    body += b"\x01\x00"          # compression_methods: 1 method (null)
    if sni is not None:
        sni_bytes = sni.encode("ascii")
        # ServerName entry: name_type(1)=host_name + length(2) + name
        server_name = b"\x00" + len(sni_bytes).to_bytes(2, "big") + sni_bytes
        # server_name_list: length(2) + entries
        ext_data = len(server_name).to_bytes(2, "big") + server_name
        # Extension: type(2)=0x0000 (SNI) + length(2) + data
        extension = b"\x00\x00" + len(ext_data).to_bytes(2, "big") + ext_data
        body += len(extension).to_bytes(2, "big") + extension
    else:
        body += b"\x00\x00"  # extensions length = 0
    # --- Handshake header ---
    handshake = b"\x01" + len(body).to_bytes(3, "big") + bytes(body)
    # --- TLS record header ---
    record = b"\x16\x03\x01" + len(handshake).to_bytes(2, "big") + handshake
    return record


async def test_http_proxy_uses_authorized_ip_not_browser_dns():
    async def origin(_reader, writer):
        await _reader.readuntil(b"\r\n\r\n")
        writer.write(
            b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\n"
            b"Connection: close\r\n\r\npinned"
        )
        await writer.drain()
        writer.close()

    server = await asyncio.start_server(origin, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    guard = _PinnedGuard()
    proxy = BrowserEgressProxy(guard)  # type: ignore[arg-type]
    await proxy.start()
    try:
        proxy_port = int(urlsplit(proxy.server_url).port or 0)
        reader, writer = await asyncio.open_connection("127.0.0.1", proxy_port)
        writer.write(
            f"GET http://browser.attacker.invalid:{port}/ HTTP/1.1\r\n"
            f"Host: browser.attacker.invalid:{port}\r\n"
            f"{_proxy_auth_header(proxy)}\r\n".encode("ascii")
        )
        await writer.drain()
        response = await reader.read()
        writer.close()
        await writer.wait_closed()
        assert response.endswith(b"pinned")
        assert guard.urls == [f"http://browser.attacker.invalid:{port}/"]
    finally:
        await proxy.close()
        server.close()
        await server.wait_closed()


async def test_connect_tunnel_is_authorized_and_dns_pinned():
    async def echo(reader, writer):
        # Read whatever the proxy forwards (the ClientHello) and echo it
        # back, then keep the connection open until the client closes.
        data = await reader.read(4096)
        if data:
            writer.write(data)
            await writer.drain()
        await reader.read()  # wait for client close
        writer.close()

    server = await asyncio.start_server(echo, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    guard = _PinnedGuard()
    proxy = BrowserEgressProxy(guard)  # type: ignore[arg-type]
    await proxy.start()
    try:
        proxy_port = int(urlsplit(proxy.server_url).port or 0)
        reader, writer = await asyncio.open_connection("127.0.0.1", proxy_port)
        writer.write(
            f"CONNECT websocket.attacker.invalid:{port} HTTP/1.1\r\n"
            f"{_proxy_auth_header(proxy)}\r\n".encode("ascii")
        )
        await writer.drain()
        assert await reader.readuntil(b"\r\n\r\n") == (
            b"HTTP/1.1 200 Connection Established\r\n\r\n"
        )
        # Batch 15.5: CONNECT tunnels now validate TLS SNI.  Send a
        # ClientHello whose SNI matches the CONNECT authority so the
        # proxy forwards it to upstream.
        client_hello = _build_tls_client_hello("websocket.attacker.invalid")
        writer.write(client_hello)
        await writer.drain()
        echoed = await asyncio.wait_for(
            reader.readexactly(len(client_hello)), timeout=5.0,
        )
        assert echoed == client_hello
        writer.close()
        await writer.wait_closed()
        assert guard.urls == [
            f"https://websocket.attacker.invalid:{port}"
        ]
    finally:
        await proxy.close()
        server.close()
        await server.wait_closed()


# ---------------------------------------------------------------------------
# Batch 15.5: TLS SNI ↔ CONNECT authority binding regression tests
# ---------------------------------------------------------------------------


def test_parse_tls_sni_extracts_hostname():
    """Unit test: ``_parse_tls_sni`` returns the SNI from a ClientHello."""
    hello = _build_tls_client_hello("allowed.example")
    assert _parse_tls_sni(hello) == "allowed.example"


def test_parse_tls_sni_returns_none_when_absent():
    """Unit test: no SNI extension → ``None`` (fail closed)."""
    hello = _build_tls_client_hello(sni=None)
    assert _parse_tls_sni(hello) is None


def test_parse_tls_sni_returns_none_for_non_tls():
    """Unit test: non-TLS data → ``None``."""
    assert _parse_tls_sni(b"GET / HTTP/1.1\r\n\r\n") is None
    assert _parse_tls_sni(b"") is None
    assert _parse_tls_sni(b"\x00" * 64) is None


def test_parse_tls_sni_returns_none_for_truncated():
    """Unit test: truncated ClientHello → ``None`` (never raises)."""
    hello = _build_tls_client_hello("allowed.example")
    assert _parse_tls_sni(hello[:5]) is None
    assert _parse_tls_sni(hello[:20]) is None


async def test_connect_sni_match_is_allowed():
    """CONNECT allowed.example + SNI=allowed.example → relayed."""
    async def echo(reader, writer):
        data = await reader.read(4096)
        if data:
            writer.write(data)
            await writer.drain()
        await reader.read()
        writer.close()

    server = await asyncio.start_server(echo, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    guard = _PinnedGuard()
    proxy = BrowserEgressProxy(guard)  # type: ignore[arg-type]
    await proxy.start()
    try:
        proxy_port = int(urlsplit(proxy.server_url).port or 0)
        reader, writer = await asyncio.open_connection("127.0.0.1", proxy_port)
        writer.write(
            f"CONNECT allowed.example:{port} HTTP/1.1\r\n"
            f"{_proxy_auth_header(proxy)}\r\n".encode("ascii")
        )
        await writer.drain()
        assert await reader.readuntil(b"\r\n\r\n") == (
            b"HTTP/1.1 200 Connection Established\r\n\r\n"
        )
        client_hello = _build_tls_client_hello("allowed.example")
        writer.write(client_hello)
        await writer.drain()
        # SNI matches → the ClientHello is forwarded and echoed back.
        echoed = await asyncio.wait_for(
            reader.readexactly(len(client_hello)), timeout=5.0,
        )
        assert echoed == client_hello
        writer.close()
        await writer.wait_closed()
        assert guard.urls == [f"https://allowed.example:{port}"]
    finally:
        await proxy.close()
        server.close()
        await server.wait_closed()


async def test_connect_sni_mismatch_is_rejected():
    """CONNECT allowed.example + SNI=blocked.example → rejected."""
    async def echo(reader, writer):
        # Should never be reached — SNI mismatch aborts before relay.
        data = await reader.read(4096)
        if data:
            writer.write(data)
            await writer.drain()
        writer.close()

    server = await asyncio.start_server(echo, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    guard = _PinnedGuard()
    proxy = BrowserEgressProxy(guard)  # type: ignore[arg-type]
    await proxy.start()
    try:
        proxy_port = int(urlsplit(proxy.server_url).port or 0)
        reader, writer = await asyncio.open_connection("127.0.0.1", proxy_port)
        writer.write(
            f"CONNECT allowed.example:{port} HTTP/1.1\r\n"
            f"{_proxy_auth_header(proxy)}\r\n".encode("ascii")
        )
        await writer.drain()
        assert await reader.readuntil(b"\r\n\r\n") == (
            b"HTTP/1.1 200 Connection Established\r\n\r\n"
        )
        # Send a ClientHello whose SNI does NOT match the authority.
        writer.write(_build_tls_client_hello("blocked.example"))
        await writer.drain()
        # The proxy must reject — either a 403 body or connection close.
        response = await asyncio.wait_for(reader.read(), timeout=5.0)
        assert response == b"" or b"403" in response
        writer.close()
        await writer.wait_closed()
        assert guard.urls == [f"https://allowed.example:{port}"]
    finally:
        await proxy.close()
        server.close()
        await server.wait_closed()


async def test_connect_sni_missing_is_rejected():
    """CONNECT allowed.example + no SNI extension → rejected (fail closed)."""
    async def echo(reader, writer):
        data = await reader.read(4096)
        if data:
            writer.write(data)
            await writer.drain()
        writer.close()

    server = await asyncio.start_server(echo, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    guard = _PinnedGuard()
    proxy = BrowserEgressProxy(guard)  # type: ignore[arg-type]
    await proxy.start()
    try:
        proxy_port = int(urlsplit(proxy.server_url).port or 0)
        reader, writer = await asyncio.open_connection("127.0.0.1", proxy_port)
        writer.write(
            f"CONNECT allowed.example:{port} HTTP/1.1\r\n"
            f"{_proxy_auth_header(proxy)}\r\n".encode("ascii")
        )
        await writer.drain()
        assert await reader.readuntil(b"\r\n\r\n") == (
            b"HTTP/1.1 200 Connection Established\r\n\r\n"
        )
        # Send a ClientHello with NO SNI extension.
        writer.write(_build_tls_client_hello(sni=None))
        await writer.drain()
        response = await asyncio.wait_for(reader.read(), timeout=5.0)
        assert response == b"" or b"403" in response
        writer.close()
        await writer.wait_closed()
    finally:
        await proxy.close()
        server.close()
        await server.wait_closed()


async def test_connect_non_tls_tunnel_is_forwarded():
    """CONNECT allowed.example + non-TLS data (plain TCP) → forwarded.

    Batch 15.5 revision: CONNECT tunnels that carry plain TCP (e.g.
    ``ws://`` WebSocket upgrades) are forwarded without SNI validation —
    the SNI check only applies when the first byte is 0x16 (TLS
    Handshake).  The CONNECT authority was already validated by
    ``authorize_url``, so the destination is authorized regardless of
    whether TLS is used.
    """
    async def echo(reader, writer):
        data = await reader.read(4096)
        if data:
            writer.write(data)
            await writer.drain()
        writer.close()

    server = await asyncio.start_server(echo, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    guard = _PinnedGuard()
    proxy = BrowserEgressProxy(guard)  # type: ignore[arg-type]
    await proxy.start()
    try:
        proxy_port = int(urlsplit(proxy.server_url).port or 0)
        reader, writer = await asyncio.open_connection("127.0.0.1", proxy_port)
        writer.write(
            f"CONNECT allowed.example:{port} HTTP/1.1\r\n"
            f"{_proxy_auth_header(proxy)}\r\n".encode("ascii")
        )
        await writer.drain()
        assert await reader.readuntil(b"\r\n\r\n") == (
            b"HTTP/1.1 200 Connection Established\r\n\r\n"
        )
        # Send non-TLS data (plain HTTP GET — e.g. a WebSocket upgrade).
        plain_request = b"GET / HTTP/1.1\r\nHost: allowed.example\r\n\r\n"
        writer.write(plain_request)
        await writer.drain()
        # Non-TLS data is forwarded (not rejected) — the echo server
        # returns it.
        echoed = await asyncio.wait_for(
            reader.readexactly(len(plain_request)), timeout=5.0,
        )
        assert echoed == plain_request
        writer.close()
        await writer.wait_closed()
    finally:
        await proxy.close()
        server.close()
        await server.wait_closed()
