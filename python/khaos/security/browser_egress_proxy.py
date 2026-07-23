"""Mandatory DNS-pinning egress proxy for Playwright browser contexts."""

from __future__ import annotations

import asyncio
import contextlib
import logging
from urllib.parse import urlsplit, urlunsplit

from khaos.security.network_guard import NetworkGuard

logger = logging.getLogger(__name__)

_MAX_HEADER_BYTES = 64 * 1024
_CONNECT_TIMEOUT = 15.0


class BrowserEgressProxy:
    """A loopback-only proxy that authorizes and pins every connection."""

    def __init__(self, guard: NetworkGuard) -> None:
        self._guard = guard
        self._server: asyncio.AbstractServer | None = None

    @property
    def server_url(self) -> str:
        if self._server is None or not self._server.sockets:
            raise RuntimeError("browser egress proxy is not running")
        port = int(self._server.sockets[0].getsockname()[1])
        return f"http://127.0.0.1:{port}"

    async def start(self) -> None:
        if self._server is not None:
            return
        self._server = await asyncio.start_server(
            self._handle_client, host="127.0.0.1", port=0, limit=_MAX_HEADER_BYTES,
        )

    async def close(self) -> None:
        if self._server is None:
            return
        self._server.close()
        await self._server.wait_closed()
        self._server = None

    async def _handle_client(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
    ) -> None:
        try:
            header = await asyncio.wait_for(
                reader.readuntil(b"\r\n\r\n"), timeout=_CONNECT_TIMEOUT,
            )
            if len(header) > _MAX_HEADER_BYTES:
                raise ValueError("proxy request header exceeds limit")
            head, _, _ = header.partition(b"\r\n")
            method, target, version = head.decode("latin-1").split(" ", 2)
            if method.upper() == "CONNECT":
                await self._tunnel_connect(target, reader, writer)
            else:
                await self._forward_http(
                    method, target, version, header, reader, writer,
                )
        except (asyncio.IncompleteReadError, asyncio.LimitOverrunError):
            await self._reject(writer, 400, "Bad Request")
        except Exception as exc:  # noqa: BLE001 - deny and audit every failure
            logger.warning("browser egress denied: %s", exc)
            await self._reject(writer, 403, "Forbidden")
        finally:
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()

    async def _tunnel_connect(
        self,
        authority: str,
        client_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
    ) -> None:
        host, port = _split_authority(authority, 443)
        target = await self._guard.authorize_url(f"https://{host}:{port}")
        upstream_reader, upstream_writer = await _open_pinned(
            target.addresses, port,
        )
        client_writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        await client_writer.drain()
        await _relay_bidirectional(
            client_reader, client_writer, upstream_reader, upstream_writer,
        )

    async def _forward_http(
        self,
        method: str,
        raw_target: str,
        version: str,
        header: bytes,
        client_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
    ) -> None:
        parsed = urlsplit(raw_target)
        if parsed.scheme.lower() not in {"http", "ws"} or not parsed.hostname:
            raise ValueError("proxy requires an absolute HTTP URL")
        target = await self._guard.authorize_url(raw_target)
        port = parsed.port or 80
        upstream_reader, upstream_writer = await _open_pinned(
            target.addresses, port,
        )
        origin_target = urlunsplit(("", "", parsed.path or "/", parsed.query, ""))
        lines = header.decode("latin-1").split("\r\n")
        forwarded = [f"{method} {origin_target} {version}"]
        for line in lines[1:]:
            if not line:
                continue
            name = line.split(":", 1)[0].strip().lower()
            if name in {"proxy-authorization", "proxy-connection", "connection"}:
                continue
            forwarded.append(line)
        forwarded.extend(("Connection: close", "", ""))
        upstream_writer.write("\r\n".join(forwarded).encode("latin-1"))
        await upstream_writer.drain()
        await _relay_bidirectional(
            client_reader, client_writer, upstream_reader, upstream_writer,
        )

    @staticmethod
    async def _reject(
        writer: asyncio.StreamWriter, status: int, reason: str,
    ) -> None:
        if writer.is_closing():
            return
        writer.write(
            f"HTTP/1.1 {status} {reason}\r\nConnection: close\r\n"
            "Content-Length: 0\r\n\r\n".encode("ascii")
        )
        with contextlib.suppress(Exception):
            await writer.drain()


def _split_authority(authority: str, default_port: int) -> tuple[str, int]:
    parsed = urlsplit(f"//{authority}")
    if not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("invalid CONNECT authority")
    return parsed.hostname, parsed.port or default_port


async def _open_pinned(
    addresses: tuple[str, ...], port: int,
) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    last_error: OSError | None = None
    for address in addresses:
        try:
            return await asyncio.wait_for(
                asyncio.open_connection(address, port), timeout=_CONNECT_TIMEOUT,
            )
        except OSError as exc:
            last_error = exc
    raise last_error or OSError("no authorized destination address")


async def _copy_stream(
    reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
) -> None:
    while data := await reader.read(64 * 1024):
        writer.write(data)
        await writer.drain()


async def _relay_bidirectional(
    client_reader: asyncio.StreamReader,
    client_writer: asyncio.StreamWriter,
    upstream_reader: asyncio.StreamReader,
    upstream_writer: asyncio.StreamWriter,
) -> None:
    async def upload() -> None:
        try:
            await _copy_stream(client_reader, upstream_writer)
        finally:
            upstream_writer.close()

    async def download() -> None:
        await _copy_stream(upstream_reader, client_writer)

    tasks = (asyncio.create_task(upload()), asyncio.create_task(download()))
    done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
    for task in pending:
        task.cancel()
    await asyncio.gather(*done, *pending, return_exceptions=True)
    upstream_writer.close()
    with contextlib.suppress(Exception):
        await upstream_writer.wait_closed()
