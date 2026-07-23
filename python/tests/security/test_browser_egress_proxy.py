from __future__ import annotations

import asyncio
import base64
from urllib.parse import urlsplit

from khaos.security.browser_egress_proxy import BrowserEgressProxy
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
        writer.write(await reader.readexactly(4))
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
            f"CONNECT websocket.attacker.invalid:{port} HTTP/1.1\r\n"
            f"{_proxy_auth_header(proxy)}\r\n".encode("ascii")
        )
        await writer.drain()
        assert await reader.readuntil(b"\r\n\r\n") == (
            b"HTTP/1.1 200 Connection Established\r\n\r\n"
        )
        writer.write(b"ping")
        await writer.drain()
        assert await reader.readexactly(4) == b"ping"
        writer.close()
        await writer.wait_closed()
        assert guard.urls == [
            f"https://websocket.attacker.invalid:{port}"
        ]
    finally:
        await proxy.close()
        server.close()
        await server.wait_closed()
