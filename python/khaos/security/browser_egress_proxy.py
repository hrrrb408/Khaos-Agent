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

from khaos.coding.execution.cleanup_ledger import CleanupLedger
from khaos.security.network_guard import NetworkGuard

logger = logging.getLogger(__name__)

_MAX_HEADER_BYTES = 64 * 1024
_CONNECT_TIMEOUT = 15.0
# F-05: per-connection resource limits.
_IDLE_TIMEOUT = 60.0  # seconds with no data transfer → close
_MAX_UPLOAD_BYTES = 50 * 1024 * 1024  # 50 MiB upload per connection
_MAX_DOWNLOAD_BYTES = 200 * 1024 * 1024  # 200 MiB download per connection
_MAX_CONCURRENT_CONNECTIONS = 20  # per proxy instance (per browser context)
# Batch 16.4: incremental TLS ClientHello parser bounds.  The record body
# is bounded so a malicious client cannot stream unlimited data during the
# SNI validation phase.
_MAX_TLS_RECORD_BYTES = 16 * 1024
_TLS_READ_TIMEOUT = 10.0
# Batch 16.4: bounded wait for handler tasks during close().  Previously
# close() used ``asyncio.gather(*tasks, return_exceptions=True)`` without a
# timeout — if a handler was stuck in a future that swallowed cancellation,
# shutdown could block indefinitely.  Now a timeout enters QUARANTINED
# (retryable) instead of hanging.
_HANDLER_DRAIN_TIMEOUT = 10.0


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


class _SniMismatchError(Exception):
    """Batch 15.5: raised when the TLS ClientHello SNI does not match the
    CONNECT authority.

    A compromised Chromium can send ``CONNECT allowed.example:443`` (which
    the proxy authorizes) but then emit a TLS ClientHello whose SNI is
    ``blocked.example``.  If both domains share a CDN / ALB, the upstream
    would serve the blocked virtual host.  The proxy must prove the TLS
    layer matches the authorized CONNECT authority before relaying.
    """

    def __init__(self, expected: str, actual: str | None) -> None:
        actual_repr = actual if actual is not None else "<absent>"
        super().__init__(
            f"SNI mismatch: CONNECT authority={expected!r} "
            f"but TLS SNI={actual_repr!r}"
        )
        self.expected = expected
        self.actual = actual


class _NonTlsConnectError(Exception):
    """Batch 16.3: raised when a CONNECT tunnel receives non-TLS data.

    Production CONNECT is restricted to TLS traffic only (https:// and
    wss://).  A compromised Chromium can send ``CONNECT allowed.example:80``
    (which the proxy authorizes at the domain level) and then emit a plain
    HTTP request whose ``Host`` header is ``blocked.example`` — if both
    domains share a CDN / ALB, the upstream would serve the blocked
    virtual host.  By requiring the first bytes to be a TLS ClientHello,
    the proxy proves the application-layer identity matches the authorized
    CONNECT authority.  Plain HTTP (http://, ws://) must use the normal
    HTTP proxy absolute-form request path, not CONNECT.
    """

    def __init__(self, first_byte: int) -> None:
        super().__init__(
            f"CONNECT tunnel requires TLS; first byte=0x{first_byte:02x} "
            f"is not Handshake (0x16)"
        )
        self.first_byte = first_byte


class _ProxyState:
    """Round-17 review §五: BrowserEgressProxy lifecycle state machine.

    NEW → OPEN → CLOSING → CLOSED (or CLOSING → QUARANTINED → CLOSING).

    Once close() begins (CLOSING), ``start()`` is permanently forbidden —
    even if close() fails and enters QUARANTINED, a new listener cannot be
    created.  This eliminates the spawn-after-close / stale-ledger
    generation bug where a partial close + reopen produced a new listener
    that the retry's ledger skipped (it had already marked ``listener_close``
    as done for the old listener).
    """

    NEW = "new"
    OPEN = "open"
    CLOSING = "closing"
    QUARANTINED = "quarantined"
    CLOSED = "closed"


class BrowserEgressProxy:
    """A loopback-only proxy that authorizes and pins every connection.

    F-05: enforces idle timeout, upload/download byte caps, a concurrent
    connection quota, and audit logging on every connection lifecycle
    event.

    C-07 (round-4): generates a random auth token so only the intended
    browser context can use the proxy.  The token is validated on every
    request (including CONNECT) via ``Proxy-Authorization: Basic …``.

    Round-17 review §五: full state machine (NEW/OPEN/CLOSING/QUARANTINED/
    CLOSED) with a lifecycle lock so: (1) close permanently forbids start,
    (2) concurrent start is serialized, (3) concurrent close callers join
    the same shared task.
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
        local_service_endpoints: frozenset[tuple[str, int]] = frozenset(),
    ) -> None:
        self._guard = guard
        self._server: asyncio.Server | None = None
        self._max_concurrent = max_concurrent
        self._idle_timeout = idle_timeout
        self._max_upload = max_upload
        self._max_download = max_download
        self._bind_host = bind_host
        self._active_connections = 0
        self._connection_semaphore = asyncio.Semaphore(max_concurrent)
        self._client_tasks: set[asyncio.Task] = set()
        self._client_writers: set[asyncio.StreamWriter] = set()
        self._cleanup_ledger = CleanupLedger()
        self._auth_token = secrets.token_urlsafe(32)
        # Round-17 review §五: typed lifecycle state + lock + shared task.
        self._state = _ProxyState.NEW
        self._lifecycle_lock = asyncio.Lock()
        self._close_task: asyncio.Task | None = None
        # Round-17 review §七: policy-based local-service exception for
        # non-TLS CONNECT.  Previously the proxy used an IP-based check
        # (``all(addr.is_loopback for addr in target.addresses)``) to
        # permit non-TLS CONNECT.  This was unsound: a loopback address
        # can host a reverse proxy (nginx/Caddy) that routes by Host
        # header to different virtual hosts — the same bypass risk as
        # remote CONNECT.  The fix replaces the IP check with an
        # explicit policy: each ``(host, port)`` pair in this set is a
        # declared local-service endpoint that the operator has
        # authorized for plain (non-TLS) CONNECT.  The host is matched
        # case-insensitively against the CONNECT authority host.
        self._local_service_endpoints = frozenset(
            (h.lower(), p) for h, p in local_service_endpoints
        )

    @property
    def _closed(self) -> bool:
        """Backward-compat: True only when cleanly CLOSED."""
        return self._state is _ProxyState.CLOSED

    @property
    def _closing(self) -> bool:
        """Backward-compat: True when CLOSING or QUARANTINED."""
        return self._state in (_ProxyState.CLOSING, _ProxyState.QUARANTINED)

    @property
    def admission_closed(self) -> bool:
        """Round-17: True when new start() is permanently rejected."""
        return self._state is not _ProxyState.NEW

    @property
    def terminal_closed(self) -> bool:
        """Round-17: True only when CLOSED (all resources proven terminated)."""
        return self._state is _ProxyState.CLOSED

    @property
    def is_quarantined(self) -> bool:
        """Round-17: True when QUARANTINED (resources may still be alive)."""
        return self._state is _ProxyState.QUARANTINED

    def owned_resources(self) -> tuple[str, ...]:
        """Round-17 review §十四: descriptors of currently-held resources.

        Returns one descriptor per live listener, in-flight handler task,
        and open client writer.  The CLOSED invariant requires this to
        be empty.
        """
        resources: list[str] = []
        if self._server is not None:
            resources.append("listener")
        for task in self._client_tasks:
            if not task.done():
                resources.append(f"handler:{id(task)}")
        for writer in self._client_writers:
            if not writer.is_closing():
                resources.append(f"writer:{id(writer)}")
        return tuple(resources)

    def terminal_postcondition(self) -> bool:
        """Round-17 review §十四: True when listener is closed, all
        handler tasks are done, and all client writers are closed."""
        return (
            self._server is None
            and all(t.done() for t in self._client_tasks)
            and all(w.is_closing() for w in self._client_writers)
        )

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
        """Start the listening socket.

        Round-17 review §五: only NEW → OPEN is allowed.  Once close()
        begins (CLOSING/QUARANTINED/CLOSED), start() is permanently
        forbidden — a partial close + reopen can no longer produce a new
        listener that the retry's ledger skips.  The lifecycle lock
        serializes concurrent start() calls so two tasks cannot both
        pass the ``_server is None`` check and create two listeners.
        """
        async with self._lifecycle_lock:
            if self._state is not _ProxyState.NEW:
                # Already started, or close() has begun — permanently
                # forbidden.  Silently return for OPEN (idempotent),
                # raise for terminal states.
                if self._state is _ProxyState.OPEN:
                    return
                raise RuntimeError(
                    f"BrowserEgressProxy cannot start: state is {self._state}"
                )

            async def _tracked_handler(
                reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
            ) -> None:
                if self._state is not _ProxyState.OPEN:
                    writer.close()
                    return
                current_task = asyncio.current_task()
                if current_task is not None:
                    self._client_tasks.add(current_task)
                self._client_writers.add(writer)
                try:
                    await self._handle_client(reader, writer)
                finally:
                    self._client_writers.discard(writer)
                    if current_task is not None:
                        self._client_tasks.discard(current_task)

            self._server = await asyncio.start_server(
                _tracked_handler,
                host=self._bind_host,
                port=0,
                limit=_MAX_HEADER_BYTES,
            )
            self._state = _ProxyState.OPEN

    async def close(self) -> None:
        """Close the listener AND terminate all active relay connections.

        Round-17 review §五: close() now uses a shared ``_close_task`` so
        concurrent callers observe the same result.  The state machine
        ensures: (1) close permanently forbids start, (2) QUARANTINED is
        retryable, (3) CLOSED is only reached when all resources are
        proven terminated.
        """
        if self._state is _ProxyState.CLOSED:
            return
        if self._close_task is not None and not self._close_task.done():
            await asyncio.shield(self._close_task)
            return
        self._close_task = asyncio.ensure_future(self._run_close())
        await asyncio.shield(self._close_task)

    async def _run_close(self) -> None:
        """The actual cleanup sequence — may run multiple times via retry."""
        async with self._lifecycle_lock:
            if self._state is _ProxyState.CLOSED:
                return
            if self._state is _ProxyState.QUARANTINED:
                # Retryable — transition to CLOSING.
                pass
            elif self._state is _ProxyState.CLOSING:
                return
            self._state = _ProxyState.CLOSING
            self._cleanup_ledger.reset_errors()

            # Step 1: close the listener so no new connections are accepted.
            if not self._cleanup_ledger.is_done("listener_close"):
                if self._server is not None:
                    self._server.close()
                    try:
                        await self._server.wait_closed()
                    except Exception:  # noqa: BLE001 — best-effort
                        pass
                    self._server = None
                self._cleanup_ledger.mark_done("listener_close")

            # Step 2: close all client writers to break relay read loops.
            if not self._cleanup_ledger.is_done("writers_close"):
                for w in tuple(self._client_writers):
                    try:
                        w.close()
                    except Exception:  # noqa: BLE001
                        pass
                self._client_writers.clear()
                self._cleanup_ledger.mark_done("writers_close")

            # Step 3: cancel and bounded-await all handler tasks.
            if not self._cleanup_ledger.is_done("handlers_drain"):
                tasks = tuple(self._client_tasks)
                for t in tasks:
                    if not t.done():
                        t.cancel()
                if tasks:
                    try:
                        await asyncio.wait_for(
                            asyncio.gather(*tasks, return_exceptions=True),
                            timeout=_HANDLER_DRAIN_TIMEOUT,
                        )
                    except TimeoutError:
                        self._cleanup_ledger.record_error(
                            "handlers_drain",
                            TimeoutError(
                                f"BrowserEgressProxy close() timed out after "
                                f"{_HANDLER_DRAIN_TIMEOUT}s: "
                                f"{len(self._client_tasks)} handler task(s) still active"
                            ),
                        )
                if self._client_tasks:
                    if not self._cleanup_ledger.has_errors():
                        self._cleanup_ledger.record_error(
                            "handlers_drain",
                            RuntimeError(
                                f"BrowserEgressProxy close() did not fully drain: "
                                f"{len(self._client_tasks)} handler task(s) still active"
                            ),
                        )
                else:
                    self._client_tasks.clear()
                    self._cleanup_ledger.mark_done("handlers_drain")

            if self._cleanup_ledger.has_errors():
                self._state = _ProxyState.QUARANTINED
                errors = self._cleanup_ledger.errors
                raise RuntimeError(
                    f"BrowserEgressProxy close() partially failed: "
                    + "; ".join(type(e).__name__ for e in errors)
                ) from errors[0]
            self._state = _ProxyState.CLOSED

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
        except TimeoutError:
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
        # Batch 16.3 (round-16 review §十三–§十五): CONNECT is TLS-only
        # for remote hosts.  A compromised Chromium can send
        # ``CONNECT allowed.example:80`` (which the proxy authorizes at the
        # domain level) and then emit a plain HTTP request whose ``Host``
        # header is ``blocked.example`` — if both domains share a CDN / ALB,
        # the upstream would serve the blocked virtual host.  By requiring
        # the first bytes to be a TLS ClientHello and validating SNI ==
        # authority, the proxy proves the application-layer identity matches
        # the authorized CONNECT authority.
        #
        # Round-17 review §七: policy-based local-service exception.
        # Chromium sends CONNECT for ``ws://`` (non-TLS WebSocket) through
        # a proxy — it does NOT fall back to absolute-form.  The previous
        # loopback exception (``all(addr.is_loopback for addr in
        # target.addresses)``) was unsound: a loopback address can host a
        # reverse proxy (nginx/Caddy) that routes by ``Host`` header to
        # different virtual hosts — the same bypass risk as remote
        # CONNECT.  The fix replaces the IP check with an explicit
        # operator-declared policy: each ``(host, port)`` pair in
        # ``_local_service_endpoints`` is a declared local-service endpoint
        # that the operator has authorized for plain (non-TLS) CONNECT.
        # The host is matched case-insensitively against the CONNECT
        # authority host.  Endpoints NOT in the policy must use TLS.
        if (host.lower(), port) in self._local_service_endpoints:
            await _relay_bidirectional(
                client_reader, client_writer,
                upstream_reader, upstream_writer,
                stats, self._idle_timeout,
                self._max_upload, self._max_download,
            )
            return
        # Batch 16.4 (round-16 review §十六): the TLS ClientHello is now
        # read incrementally via ``readexactly(5)`` (record header) +
        # ``readexactly(record_length)`` (record body) instead of a single
        # bare ``read(n)``.  ``StreamReader.read(n)`` does not guarantee
        # that a complete TLS record is returned in one call — TCP may
        # fragment it, causing the parser to see a truncated record and
        # fail-closed (false-deny).  ``readexactly`` blocks until the
        # exact number of bytes is available, correctly handling split
        # ClientHellos.
        try:
            first_bytes = await _read_tls_client_hello(client_reader)
            sni = _parse_tls_sni(first_bytes)
            if sni is None or sni.lower() != host.lower():
                raise _SniMismatchError(host, sni)
            logger.debug(
                "browser egress SNI validated: %s for CONNECT %s:%d",
                sni, host, port,
            )
        except Exception:
            # Non-TLS data, SNI mismatch, timeout, or parse error —
            # close the upstream connection before propagating so we do
            # not leak it.  _relay_bidirectional owns cleanup on the
            # success path.
            upstream_writer.close()
            with contextlib.suppress(Exception):
                await upstream_writer.wait_closed()
            raise
        # Forward the buffered ClientHello to upstream so the TLS
        # handshake proceeds normally, then start the blind relay.
        upstream_writer.write(first_bytes)
        await upstream_writer.drain()
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
        # Round-15 review P1 (Host header authority binding): the proxy
        # does NOT trust the client's Host header.  A compromised Chromium
        # in the browser netns can craft a proxy request with an allowed
        # absolute target but a different (or missing) Host header — if
        # both domains share a CDN/IP, the upstream virtual host would
        # serve the blocked domain.  Instead of validating the client
        # Host (which still allowed a missing Host to pass through), the
        # proxy now STRIPS all client Host headers and generates a
        # canonical ``Host: <authorized-host>[:<port>]`` from the
        # absolute target.  Protocol interpretation authority is entirely
        # in the security proxy, not the compromised browser.
        canonical_host = parsed.hostname.lower()
        if parsed.port is not None:
            canonical_host = f"{canonical_host}:{parsed.port}"
        elif port != 80:
            canonical_host = f"{canonical_host}:{port}"
        forwarded = [f"{method} {origin_target} {version}"]
        for line in lines[1:]:
            if not line:
                continue
            name = line.split(":", 1)[0].strip().lower()
            # Strip ALL client Host headers — the proxy owns the canonical
            # Host.  Also strip hop-by-hop headers.
            if name in {"host", "proxy-authorization", "proxy-connection", "connection"}:
                continue
            forwarded.append(line)
        forwarded.append(f"Host: {canonical_host}")
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


async def _read_tls_client_hello(reader: asyncio.StreamReader) -> bytes:
    """Batch 16.4: incrementally read a TLS ClientHello record.

    Uses ``readexactly`` to read the record header (5 bytes) and body
    separately, so a ClientHello split across TCP segments is handled
    correctly.  ``StreamReader.read(n)`` does not guarantee that a
    complete TLS record is returned in one call — TCP may fragment it,
    causing the parser to see a truncated record and fail-closed
    (false-deny on legitimate HTTPS).  ``readexactly`` blocks until the
    exact number of bytes is available.

    Batch 16.3: the first byte must be ``0x16`` (TLS Handshake).  If it
    is not, the tunnel is carrying non-TLS data (e.g. plain HTTP) and
    is rejected — production CONNECT is TLS-only.

    Returns the complete TLS record (header + body) on success.
    Raises ``_NonTlsConnectError`` if the first byte is not 0x16,
    ``ValueError`` if the record body exceeds the bound, or
    ``asyncio.IncompleteReadError`` / ``TimeoutError`` on read failure.
    """
    header = await asyncio.wait_for(
        reader.readexactly(5), timeout=_TLS_READ_TIMEOUT,
    )
    if header[0] != 0x16:  # ContentType: Handshake
        raise _NonTlsConnectError(header[0])
    record_length = int.from_bytes(header[3:5], "big")
    if record_length > _MAX_TLS_RECORD_BYTES:
        raise ValueError(
            f"TLS record body exceeds limit: {record_length} > "
            f"{_MAX_TLS_RECORD_BYTES}"
        )
    body = await asyncio.wait_for(
        reader.readexactly(record_length), timeout=_TLS_READ_TIMEOUT,
    )
    return header + body


def _parse_tls_sni(data: bytes) -> str | None:
    """Extract the SNI host_name from a TLS ClientHello record.

    Batch 15.5: parses the TLS record header (type=0x16 Handshake), the
    Handshake header (type=0x01 ClientHello), and the ClientHello fields
    to locate the SNI extension (extension type 0x0000).  Returns the
    first ``host_name`` (name_type=0) decoded as ASCII, or ``None`` if
    the data is not a valid TLS ClientHello, the SNI extension is absent,
    or any parse error occurs.  Never raises — callers rely on ``None``
    to signal "reject (fail-closed)".
    """
    try:
        # --- TLS record header (RFC 5246 §6.2.1) ---
        # ContentType(1) + ProtocolVersion(2) + length(2)
        if len(data) < 5:
            return None
        if data[0] != 0x16:  # handshake
            return None
        record_length = int.from_bytes(data[3:5], "big")
        if record_length + 5 > len(data):
            # Fragment does not contain the full record — the
            # ClientHello may have been split, but a real ClientHello
            # fits in one record on loopback.  Fail closed.
            return None
        # --- Handshake header (RFC 5246 §7.4) ---
        # HandshakeType(1) + length(3)
        if len(data) < 9:
            return None
        if data[5] != 0x01:  # ClientHello
            return None
        offset = 9  # start of ClientHello body
        # --- ClientHello body (RFC 5246 §7.4.1.2) ---
        # client_version(2)
        if offset + 2 > len(data):
            return None
        offset += 2
        # random(32)
        if offset + 32 > len(data):
            return None
        offset += 32
        # session_id(1-byte length + variable)
        if offset + 1 > len(data):
            return None
        session_id_len = data[offset]
        offset += 1
        if offset + session_id_len > len(data):
            return None
        offset += session_id_len
        # cipher_suites(2-byte length + variable)
        if offset + 2 > len(data):
            return None
        cipher_suites_len = int.from_bytes(data[offset:offset + 2], "big")
        offset += 2
        if offset + cipher_suites_len > len(data):
            return None
        offset += cipher_suites_len
        # compression_methods(1-byte length + variable)
        if offset + 1 > len(data):
            return None
        compression_len = data[offset]
        offset += 1
        if offset + compression_len > len(data):
            return None
        offset += compression_len
        # extensions(2-byte total length + variable) — optional
        if offset + 2 > len(data):
            return None
        extensions_len = int.from_bytes(data[offset:offset + 2], "big")
        offset += 2
        if extensions_len == 0:
            return None  # no extensions → no SNI → fail closed
        if offset + extensions_len > len(data):
            return None
        extensions_end = offset + extensions_len
        # --- Extension loop ---
        # Each: ExtensionType(2) + extension_data(2-byte length + variable)
        while offset + 4 <= extensions_end:
            ext_type = int.from_bytes(data[offset:offset + 2], "big")
            ext_len = int.from_bytes(data[offset + 2:offset + 4], "big")
            offset += 4
            if offset + ext_len > extensions_end:
                return None
            if ext_type == 0x0000:  # server_name (RFC 6066 §3)
                # server_name_list(2-byte length) + entries
                if ext_len < 2:
                    return None
                list_len = int.from_bytes(
                    data[offset:offset + 2], "big",
                )
                list_start = offset + 2
                list_end = list_start + list_len
                if list_end > offset + ext_len:
                    return None
                pos = list_start
                # Each entry: name_type(1) + host_name(2-byte length + bytes)
                while pos + 3 <= list_end:
                    name_type = data[pos]
                    name_len = int.from_bytes(
                        data[pos + 1:pos + 3], "big",
                    )
                    pos += 3
                    if pos + name_len > list_end:
                        return None
                    if name_type == 0x00:  # host_name
                        return data[pos:pos + name_len].decode("ascii")
                    pos += name_len
            offset += ext_len
        return None
    except (IndexError, ValueError, UnicodeDecodeError):
        return None


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
        except TimeoutError:
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
