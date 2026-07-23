"""Mandatory DNS-pinning egress proxy for Playwright browser contexts.

F-05 (third-round review §5.3): the proxy now enforces per-connection
resource limits so a compromised or runaway page cannot exhaust host
resources:

  - **idle timeout** — connections with no data transfer for
    ``_IDLE_TIMEOUT`` seconds are closed;
  - **upload byte cap** — uploads beyond ``_MAX_UPLOAD_BYTES`` are
    aborted;
  - **download byte cap** — downloads beyond ``_MAX_DOWNLOAD_BYTES``
    are aborted;
  - **connection quota** — at most ``_MAX_CONCURRENT_CONNECTIONS``
    concurrent connections per proxy instance (per browser context);
  - **audit logging** — every authorize / reject / limit event is
    logged at WARNING (rejects) or INFO (authorized + closed).
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import hmac
import logging
import secrets
import time
from dataclasses import dataclass, field
from urllib.parse import urlsplit, urlunsplit

from khaos.security.network_guard import NetworkGuard

logger = logging.getLogger(__name__)

_MAX_HEADER_BYTES = 64 * 1024
_CONNECT_TIMEOUT = 15.0
# F-05: per-connection resource limits.
_IDLE_TIMEOUT = 60.0  # seconds with no data transfer → close
_MAX_UPLOAD_BYTES = 50 * 1024 * 1024  # 50 MiB upload per connection
_MAX_DOWNLOAD_BYTES = 200 * 1024 * 1024  # 200 MiB download per connection
_MAX_CONCURRENT_CONNECTIONS = 20  # per proxy instance (per browser context)


@dataclass
class _ConnectionStats:
    """Per-connection accounting for audit logging."""

    method: str = ""
    host: str = ""
    port: int = 0
    uploaded: int = 0
    downloaded: int = 0
    started_at: float = field(default_factory=time.monotonic)

    def summary(self) -> str:
        duration = time.monotonic() - self.started_at
        return (
            f"method={self.method} host={self.host}:{self.port} "
            f"uploaded={self.uploaded} downloaded={self.downloaded} "
            f"duration={duration:.1f}s"
        )


class _ByteLimitExceeded(Exception):
    """Raised when a connection exceeds its upload or download byte cap."""

    def __init__(self, direction: str, transferred: int, limit: int) -> None:
        super().__init__(
            f"{direction} byte limit exceeded: {transferred} > {limit}"
        )
        self.direction = direction
        self.transferred = transferred
        self.limit = limit


class _ProxyAuthError(Exception):
    """C-07: raised when a client fails proxy authentication.

    The proxy binds to a veth host IP that is reachable from inside the
    browser network namespace.  Without per-client authentication any
    process in that namespace (or any host process that can reach the
    bind address) could use the proxy.  ``_ProxyAuthError`` triggers a
    ``407 Proxy Authentication Required`` response carrying a
    ``Proxy-Authenticate`` challenge so only the browser context that
    received ``proxy_username``/``proxy_password`` can relay traffic.
    """


class BrowserEgressProxy:
    """A loopback-only proxy that authorizes and pins every connection.

    F-05: enforces idle timeout, upload/download byte caps, a concurrent
    connection quota, and audit logging on every connection lifecycle
    event.

    C-07 (round-4): generates a random auth token so only the intended
    browser context can use the proxy.  The token is validated on every
    request (including CONNECT) via ``Proxy-Authorization: Basic …``.

    C-11 (round-4): policy-violation exceptions (byte-limit, idle-timeout)
    are now re-raised from ``_relay_bidirectional`` instead of being
    silently swallowed by ``gather(return_exceptions=True)``.
    """

    def __init__(
        self,
        guard: NetworkGuard,
        *,
        max_concurrent: int = _MAX_CONCURRENT_CONNECTIONS,
        idle_timeout: float = _IDLE_TIMEOUT,
        max_upload: int = _MAX_UPLOAD_BYTES,
        max_download: int = _MAX_DOWNLOAD_BYTES,
        bind_host: str = "127.0.0.1",
    ) -> None:
        self._guard = guard
        self._server: asyncio.AbstractServer | None = None
        self._max_concurrent = max_concurrent
        self._idle_timeout = idle_timeout
        self._max_upload = max_upload
        self._max_download = max_download
        self._bind_host = bind_host
        self._active_connections = 0
        self._connection_semaphore = asyncio.Semaphore(max_concurrent)
        # C-07: random auth token — only the browser that receives this
        # token can use the proxy.  Other host processes that can reach
        # the bind address are rejected with 407.
        self._auth_token = secrets.token_urlsafe(32)

    @property
    def proxy_username(self) -> str:
        """Username for Playwright's ``proxy.username`` field."""
        return "khaos"

    @property
    def proxy_password(self) -> str:
        """Password for Playwright's ``proxy.password`` field."""
        return self._auth_token

    @property
    def server_url(self) -> str:
        if self._server is None or not self._server.sockets:
            raise RuntimeError("browser egress proxy is not running")
        port = int(self._server.sockets[0].getsockname()[1])
        return f"http://{self._bind_host}:{port}"

    async def start(self) -> None:
        if self._server is not None:
            return
        self._server = await asyncio.start_server(
            self._handle_client,
            host=self._bind_host,
            port=0,
            limit=_MAX_HEADER_BYTES,
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
        # F-05: enforce concurrent connection quota.  If the quota is
        # exhausted, reject immediately so a compromised page cannot
        # exhaust file descriptors.
        try:
            await asyncio.wait_for(
                self._connection_semaphore.acquire(), timeout=_CONNECT_TIMEOUT,
            )
        except asyncio.TimeoutError:
            logger.warning(
                "browser egress rejected: connection quota exhausted "
                "(%d/%d concurrent)",
                self._active_connections,
                self._max_concurrent,
            )
            await self._reject(writer, 503, "Too Many Connections")
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()
            return

        self._active_connections += 1
        stats = _ConnectionStats()
        try:
            header = await asyncio.wait_for(
                reader.readuntil(b"\r\n\r\n"), timeout=_CONNECT_TIMEOUT,
            )
            if len(header) > _MAX_HEADER_BYTES:
                raise ValueError("proxy request header exceeds limit")
            # C-07: validate Proxy-Authorization before dispatching.
            # Every request — CONNECT or plain HTTP — must carry the
            # per-proxy auth token so only the intended browser context
            # can relay traffic through this proxy.
            self._validate_proxy_auth(header)
            head, _, _ = header.partition(b"\r\n")
            method, target, version = head.decode("latin-1").split(" ", 2)
            stats.method = method.upper()
            if stats.method == "CONNECT":
                await self._tunnel_connect(
                    target, reader, writer, stats,
                )
            else:
                await self._forward_http(
                    method, target, version, header, reader, writer, stats,
                )
        except (asyncio.IncompleteReadError, asyncio.LimitOverrunError):
            await self._reject(writer, 400, "Bad Request")
        except _ProxyAuthError as exc:
            logger.warning(
                "browser egress rejected: %s (%s)", exc, stats.summary(),
            )
            await self._reject_unauthorized(writer)
        except _ByteLimitExceeded as exc:
            logger.warning(
                "browser egress byte limit exceeded: %s (%s)",
                exc, stats.summary(),
            )
            await self._reject(writer, 413, "Payload Too Large")
        except Exception as exc:  # noqa: BLE001 - deny and audit every failure
            logger.warning(
                "browser egress denied: %s (%s)", exc, stats.summary(),
            )
            await self._reject(writer, 403, "Forbidden")
        else:
            logger.info("browser egress closed: %s", stats.summary())
        finally:
            self._active_connections -= 1
            self._connection_semaphore.release()
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()

    def _validate_proxy_auth(self, header: bytes) -> None:
        """C-07: enforce per-proxy authentication on every request.

        The browser context receives ``proxy_username``/``proxy_password``
        and sends them as ``Proxy-Authorization: Basic <b64>``.  We parse
        the header (case-insensitive header name), decode the Basic
        credentials, and use ``hmac.compare_digest`` so a wrong token is
        rejected in constant time.  Missing or malformed credentials
        raise ``_ProxyAuthError`` which maps to a ``407`` response.
        """
        expected = f"{self.proxy_username}:{self._auth_token}".encode("ascii")
        auth_header: str | None = None
        for line in header.split(b"\r\n")[1:]:
            if not line:
                continue
            name, sep, value = line.partition(b":")
            if not sep:
                continue
            if name.strip().lower() == b"proxy-authorization":
                auth_header = value.decode("latin-1").strip()
                break
        if auth_header is None:
            raise _ProxyAuthError("missing Proxy-Authorization header")
        scheme, _, credentials = auth_header.partition(" ")
        if scheme.lower() != "basic" or not credentials:
            raise _ProxyAuthError("invalid Proxy-Authorization scheme")
        try:
            decoded = base64.b64decode(credentials, validate=True)
        except ValueError as exc:
            # binascii.Error is a subclass of ValueError
            raise _ProxyAuthError("malformed Basic credentials") from exc
        if not hmac.compare_digest(decoded, expected):
            raise _ProxyAuthError("invalid proxy credentials")

    @staticmethod
    async def _reject_unauthorized(writer: asyncio.StreamWriter) -> None:
        """C-07: send a 407 with a ``Proxy-Authenticate`` challenge."""
        if writer.is_closing():
            return
        writer.write(
            b"HTTP/1.1 407 Proxy Authentication Required\r\n"
            b"Proxy-Authenticate: Basic realm=\"khaos-browser-egress\"\r\n"
            b"Connection: close\r\n"
            b"Content-Length: 0\r\n\r\n"
        )
        with contextlib.suppress(Exception):
            await writer.drain()

    async def _tunnel_connect(
        self,
        authority: str,
        client_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
        stats: _ConnectionStats,
    ) -> None:
        host, port = _split_authority(authority, 443)
        target = await self._guard.authorize_url(f"https://{host}:{port}")
        stats.host = host
        stats.port = port
        logger.info(
            "browser egress authorized: CONNECT %s:%d", host, port,
        )
        upstream_reader, upstream_writer = await _open_pinned(
            target.addresses, port,
        )
        client_writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        await client_writer.drain()
        await _relay_bidirectional(
            client_reader, client_writer,
            upstream_reader, upstream_writer,
            stats, self._idle_timeout,
            self._max_upload, self._max_download,
        )

    async def _forward_http(
        self,
        method: str,
        raw_target: str,
        version: str,
        header: bytes,
        client_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
        stats: _ConnectionStats,
    ) -> None:
        parsed = urlsplit(raw_target)
        if parsed.scheme.lower() not in {"http", "ws"} or not parsed.hostname:
            raise ValueError("proxy requires an absolute HTTP URL")
        target = await self._guard.authorize_url(raw_target)
        port = parsed.port or 80
        stats.host = parsed.hostname
        stats.port = port
        logger.info(
            "browser egress authorized: %s %s:%d",
            method.upper(), parsed.hostname, port,
        )
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
            client_reader, client_writer,
            upstream_reader, upstream_writer,
            stats, self._idle_timeout,
            self._max_upload, self._max_download,
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
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    *,
    direction: str,
    byte_limit: int,
    stats: _ConnectionStats,
    idle_timeout: float,
) -> None:
    """Copy bytes from ``reader`` to ``writer`` with idle + byte limits.

    F-05: raises ``_ByteLimitExceeded`` when ``byte_limit`` is exceeded,
    and raises ``asyncio.TimeoutError`` when no data arrives for
    ``idle_timeout`` seconds.
    """
    transferred = 0
    while True:
        try:
            data = await asyncio.wait_for(reader.read(64 * 1024), timeout=idle_timeout)
        except asyncio.TimeoutError:
            logger.warning(
                "browser egress idle timeout (%.0fs) on %s (%s)",
                idle_timeout, direction, stats.summary(),
            )
            raise
        if not data:
            break
        transferred += len(data)
        if transferred > byte_limit:
            raise _ByteLimitExceeded(direction, transferred, byte_limit)
        if direction == "upload":
            stats.uploaded = transferred
        else:
            stats.downloaded = transferred
        writer.write(data)
        await writer.drain()


async def _relay_bidirectional(
    client_reader: asyncio.StreamReader,
    client_writer: asyncio.StreamWriter,
    upstream_reader: asyncio.StreamReader,
    upstream_writer: asyncio.StreamWriter,
    stats: _ConnectionStats,
    idle_timeout: float,
    max_upload: int,
    max_download: int,
) -> None:
    async def upload() -> None:
        try:
            await _copy_stream(
                client_reader, upstream_writer,
                direction="upload",
                byte_limit=max_upload,
                stats=stats,
                idle_timeout=idle_timeout,
            )
        finally:
            upstream_writer.close()

    async def download() -> None:
        await _copy_stream(
            upstream_reader, client_writer,
            direction="download",
            byte_limit=max_download,
            stats=stats,
            idle_timeout=idle_timeout,
        )

    tasks = (asyncio.create_task(upload()), asyncio.create_task(download()))
    done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
    for task in pending:
        task.cancel()
    # C-11: re-raise the first policy-violation exception instead of
    # silently swallowing it via ``gather(return_exceptions=True)``.
    # ``_ByteLimitExceeded`` (upload/download cap) and
    # ``asyncio.TimeoutError`` (idle timeout) are the policy signals
    # that ``_handle_client`` maps to 413 / 408 responses; if we swallow
    # them here the audit log lies about why the connection was closed
    # and the 413 branch becomes dead code.  We only swallow exceptions
    # from the *cancelled* pending tasks (CancelledError / connection
    # reset), which are expected side-effects of tearing down a relay.
    for task in done:
        exc = task.exception()
        if isinstance(exc, (_ByteLimitExceeded, asyncio.TimeoutError)):
            # Let the pending tasks finish cancelling before propagating.
            await asyncio.gather(*pending, return_exceptions=True)
            raise exc
    await asyncio.gather(*done, *pending, return_exceptions=True)
    upstream_writer.close()
    with contextlib.suppress(Exception):
        await upstream_writer.wait_closed()
