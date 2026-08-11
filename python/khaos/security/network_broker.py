"""Managed network egress for terminal and tool subprocesses.

The worker receives only a loopback proxy endpoint and a short-lived lease.
It never supplies a destination IP, DNS answer, or upstream socket to the
broker.  The broker parses the request, validates the broker-issued authority
capability, resolves DNS, rejects unsafe addresses, and opens the pinned
upstream connection itself.  ``HTTP_PROXY`` is therefore only a transport
hint; the proxy authentication and target checks are the actual authority.
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import hashlib
import hmac
import ipaddress
import logging
import secrets
import socket
import sys
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from urllib.parse import quote, urlsplit, urlunsplit

from khaos.security.authority_broker import (
    AuthorityBroker,
    AuthorityBrokerError,
    EffectCapability,
)

logger = logging.getLogger(__name__)

_MAX_HEADER_BYTES = 64 * 1024
_MAX_CONNECTIONS = 32
_MAX_UPLOAD_BYTES = 64 * 1024 * 1024
_MAX_DOWNLOAD_BYTES = 256 * 1024 * 1024
_IDLE_TIMEOUT = 60.0
_CONNECT_TIMEOUT = 15.0


class NetworkBrokerError(PermissionError):
    """Raised when a brokered network request is not authorized."""


@dataclass(frozen=True, slots=True)
class NetworkLease:
    """The only network material a managed child may receive."""

    endpoint: str
    username: str
    password: str
    capability_digest: str
    allowed_domains: frozenset[str]
    blocked_domains: frozenset[str]
    allowed_ports: frozenset[int]
    protocols: frozenset[str]
    namespace_environment: tuple[tuple[str, str], ...] = ()
    _capability: EffectCapability | None = field(
        default=None, init=False, repr=False, compare=False
    )
    _authority_broker: AuthorityBroker | None = field(
        default=None, init=False, repr=False, compare=False
    )

    @classmethod
    def _from_broker(
        cls,
        *,
        capability: EffectCapability,
        authority_broker: AuthorityBroker,
        **fields: object,
    ) -> NetworkLease:
        """Create a lease only after NetworkBroker has bound its authority."""
        lease = cls(**fields)
        object.__setattr__(lease, "_capability", capability)
        object.__setattr__(lease, "_authority_broker", authority_broker)
        lease.validate()
        return lease

    @property
    def configuration_digest(self) -> str:
        """Digest every transport and policy field except its attestation."""
        payload = (
            self.endpoint,
            self.username,
            self.password,
            tuple(sorted(self.allowed_domains)),
            tuple(sorted(self.blocked_domains)),
            tuple(sorted(self.allowed_ports)),
            tuple(sorted(self.protocols)),
            self.namespace_environment,
        )
        return hashlib.sha256(repr(payload).encode("utf-8")).hexdigest()

    def validate(self) -> None:
        """Validate the live broker attestation before a child is launched."""
        capability = self._capability
        authority_broker = self._authority_broker
        if capability is None or authority_broker is None:
            raise NetworkBrokerError("network lease was not issued by NetworkBroker")
        if capability.digest != self.capability_digest:
            raise NetworkBrokerError("network lease capability digest does not match")
        try:
            authority_broker.validate(
                capability,
                expected_operation="network.connect",
                expected_resource_digest=self.configuration_digest,
            )
        except AuthorityBrokerError as exc:
            raise NetworkBrokerError(f"network lease attestation rejected: {exc}") from exc

    @property
    def identity_digest(self) -> str:
        payload = "|".join(
            (
                self.endpoint,
                self.username,
                self.capability_digest,
                self.configuration_digest,
                ",".join(sorted(self.allowed_domains)),
                ",".join(sorted(self.blocked_domains)),
                ",".join(str(port) for port in sorted(self.allowed_ports)),
                ",".join(sorted(self.protocols)),
                hashlib.sha256(repr(self.namespace_environment).encode("utf-8")).hexdigest(),
            )
        )
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    @property
    def uses_network_namespace(self) -> bool:
        """Return whether the lease requires a trusted namespace join."""
        return bool(self.namespace_environment)

    @property
    def host(self) -> str:
        parsed = urlsplit(self.endpoint)
        if parsed.hostname is None:
            raise NetworkBrokerError("network lease endpoint has no host")
        return parsed.hostname

    @property
    def port(self) -> int:
        parsed = urlsplit(self.endpoint)
        if parsed.port is None:
            raise NetworkBrokerError("network lease endpoint has no port")
        return parsed.port

    def proxy_environment(self) -> dict[str, str]:
        """Return proxy variables for a trusted backend to inject."""
        parsed = urlsplit(self.endpoint)
        display_host = _endpoint_host(parsed.hostname or "")
        authenticated = (
            f"{parsed.scheme}://{quote(self.username, safe='')}:{quote(self.password, safe='')}@"
            f"{display_host}:{parsed.port}"
        )
        return {
            "HTTP_PROXY": authenticated,
            "HTTPS_PROXY": authenticated,
            "ALL_PROXY": authenticated,
            # An empty NO_PROXY is deliberate: direct bypasses are not an
            # allowed interpretation of a brokered profile.
            "NO_PROXY": "",
        }


@dataclass
class _ConnectionStats:
    method: str = ""
    host: str = ""
    port: int = 0
    uploaded: int = 0
    downloaded: int = 0
    started_at: float = field(default_factory=time.monotonic)


class NetworkBroker:
    """Capability-bound HTTP CONNECT/absolute-form proxy.

    The default endpoint is loopback-only.  ``linux_namespace=True`` creates a
    separate kernel network namespace through the existing authenticated
    kernel authority, binds the broker to the host side of its veth, and gives
    the worker an outer-launcher join contract.  The worker therefore cannot
    reach the host network unless it first crosses this broker.
    """

    def __init__(
        self,
        capability: EffectCapability,
        *,
        authority_broker: AuthorityBroker | None = None,
        allowed_domains: frozenset[str] = frozenset(),
        blocked_domains: frozenset[str] = frozenset(),
        allowed_ports: frozenset[int] = frozenset({80, 443}),
        protocols: frozenset[str] = frozenset({"http", "https"}),
        local_endpoints: frozenset[tuple[str, int]] = frozenset(),
        bind_host: str = "127.0.0.1",
        max_connections: int = _MAX_CONNECTIONS,
        idle_timeout: float = _IDLE_TIMEOUT,
        max_upload: int = _MAX_UPLOAD_BYTES,
        max_download: int = _MAX_DOWNLOAD_BYTES,
        audit: Callable[[dict[str, object]], None] | None = None,
        linux_namespace: bool = False,
    ) -> None:
        if not isinstance(capability, EffectCapability):
            raise NetworkBrokerError("network broker requires a broker-issued capability")
        if not capability.authority.operation_class.startswith("network."):
            raise NetworkBrokerError("capability is not a network authority")
        if not _is_loopback(bind_host):
            raise NetworkBrokerError("network broker bind_host must be loopback")
        if linux_namespace and not sys.platform.startswith("linux"):
            raise NetworkBrokerError("Linux network namespace broker used on non-Linux")
        if not allowed_domains:
            raise NetworkBrokerError("network broker requires a non-empty domain allowlist")
        if not allowed_ports or any(type(port) is not int or not 1 <= port <= 65535 for port in allowed_ports):
            raise NetworkBrokerError("network broker port allowlist is invalid")
        normalized_allowed = frozenset(_normalize_domain(domain) for domain in allowed_domains)
        normalized_blocked = frozenset(_normalize_domain(domain) for domain in blocked_domains)
        self._capability = capability
        self._authority_broker = authority_broker or AuthorityBroker.default()
        self._allowed_domains = normalized_allowed
        self._blocked_domains = normalized_blocked
        self._allowed_ports = frozenset(allowed_ports)
        self._protocols = frozenset(protocol.lower() for protocol in protocols)
        self._local_endpoints = frozenset(
            (_normalize_domain(host), port) for host, port in local_endpoints
        )
        self._bind_host = bind_host
        self._max_connections = max_connections
        self._idle_timeout = idle_timeout
        self._max_upload = max_upload
        self._max_download = max_download
        self._audit_callback = audit
        self._server: asyncio.Server | None = None
        self._tasks: set[asyncio.Task[None]] = set()
        self._writers: set[asyncio.StreamWriter] = set()
        self._semaphore = asyncio.Semaphore(max_connections)
        self._auth_username = "khaos"
        self._auth_password = secrets.token_urlsafe(32)
        self._state = "new"
        self._lease: NetworkLease | None = None
        self._linux_namespace = linux_namespace
        self._network_sandbox = None

    @property
    def lease(self) -> NetworkLease:
        if self._lease is None:
            raise NetworkBrokerError("network broker is not started")
        return self._lease

    @property
    def endpoint(self) -> str:
        return self.lease.endpoint

    @property
    def terminal_closed(self) -> bool:
        return self._state == "closed" and self._server is None and not self._tasks and not self._writers

    async def start(self) -> NetworkLease:
        if self._state == "open":
            return self.lease
        if self._state != "new":
            raise NetworkBrokerError(f"network broker cannot start in state {self._state}")
        try:
            self._authority_broker.validate(
                self._capability,
                expected_operation="network.connect",
            )
        except AuthorityBrokerError as exc:
            raise NetworkBrokerError(f"network capability rejected: {exc}") from exc

        namespace_environment: tuple[tuple[str, str], ...] = ()
        if self._linux_namespace:
            sandbox = None
            try:
                from khaos.security.browser_sandbox import BrowserNetworkSandbox

                authority = self._capability.authority
                sandbox = BrowserNetworkSandbox(
                    require_os_sandbox=True,
                    principal_id=authority.principal_id,
                    project_id=authority.project_id,
                    runtime_id=authority.runtime_id,
                    task_id=authority.task_id,
                )
                await asyncio.to_thread(sandbox.setup)
                if not sandbox.network_namespace_active:
                    raise NetworkBrokerError(
                        "Linux network namespace setup returned incomplete evidence"
                    )
                self._network_sandbox = sandbox
                self._bind_host = sandbox.proxy_bind_host
                namespace_environment = tuple(
                    sorted(sandbox.authority_environment().items())
                )
            except NetworkBrokerError:
                owner = self._network_sandbox or sandbox
                if owner is not None:
                    teardown = await asyncio.to_thread(owner.teardown)
                    self._network_sandbox = None
                    if not teardown.fully_closed:
                        self._network_sandbox = owner
                        self._state = "quarantined"
                        raise NetworkBrokerError(
                            "network namespace setup failed and teardown is unproven"
                        )
                raise
            except Exception as exc:
                if sandbox is not None:
                    teardown = await asyncio.to_thread(sandbox.teardown)
                    if not teardown.fully_closed:
                        self._network_sandbox = sandbox
                        self._state = "quarantined"
                        raise NetworkBrokerError(
                            "Linux network namespace setup failed and teardown is unproven"
                        ) from exc
                raise NetworkBrokerError(
                    f"Linux network namespace setup failed: {type(exc).__name__}: {exc}"
                ) from exc

        async def handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            task = asyncio.current_task()
            if task is not None:
                self._tasks.add(task)
            self._writers.add(writer)
            try:
                await self._handle_client(reader, writer)
            finally:
                self._writers.discard(writer)
                if task is not None:
                    self._tasks.discard(task)

        try:
            self._server = await asyncio.start_server(
                handler,
                host=self._bind_host,
                port=0,
                limit=_MAX_HEADER_BYTES,
            )
        except OSError as exc:
            if self._network_sandbox is not None:
                teardown = await asyncio.to_thread(self._network_sandbox.teardown)
                self._network_sandbox = None
                if not teardown.fully_closed:
                    self._state = "quarantined"
                    raise NetworkBrokerError(
                        "network broker listener failed and namespace teardown is unproven"
                    ) from exc
            raise NetworkBrokerError(f"network broker listener unavailable: {exc}") from exc
        socket_info = self._server.sockets[0].getsockname()
        port = int(socket_info[1])
        if self._network_sandbox is not None:
            try:
                await asyncio.to_thread(self._network_sandbox.install_egress_pin, port)
            except Exception as exc:
                self._server.close()
                await self._server.wait_closed()
                self._server = None
                teardown = await asyncio.to_thread(self._network_sandbox.teardown)
                self._network_sandbox = None
                if not teardown.fully_closed:
                    self._state = "quarantined"
                    raise NetworkBrokerError(
                        "network namespace egress pin failed and teardown is unproven"
                    ) from exc
                raise NetworkBrokerError(
                    f"network namespace egress pin failed: {exc}"
                ) from exc
        try:
            lease_fields = {
                "endpoint": f"http://{_endpoint_host(self._bind_host)}:{port}",
                "username": self._auth_username,
                "password": self._auth_password,
                "capability_digest": "pending",
                "allowed_domains": self._allowed_domains,
                "blocked_domains": self._blocked_domains,
                "allowed_ports": self._allowed_ports,
                "protocols": self._protocols,
                "namespace_environment": namespace_environment,
            }
            candidate = NetworkLease(**lease_fields)
            network_authority = self._capability.authority.derive(
                operation_class="network.connect",
                resource_digest=candidate.configuration_digest,
            )
            lease_capability = self._authority_broker.issue(
                network_authority,
                allowed_operation="network.connect",
            )
            lease_fields["capability_digest"] = lease_capability.digest
            self._lease = NetworkLease._from_broker(
                capability=lease_capability,
                authority_broker=self._authority_broker,
                **lease_fields,
            )
        except (AuthorityBrokerError, NetworkBrokerError, TypeError, ValueError) as exc:
            self._server.close()
            await self._server.wait_closed()
            self._server = None
            if self._network_sandbox is not None:
                teardown = await asyncio.to_thread(self._network_sandbox.teardown)
                self._network_sandbox = None
                if not teardown.fully_closed:
                    self._state = "quarantined"
                    raise NetworkBrokerError(
                        "network lease issuance failed and namespace teardown is unproven"
                    ) from exc
            raise NetworkBrokerError(f"network lease issuance failed: {exc}") from exc
        self._state = "open"
        self._audit({"event": "network-broker-open", "endpoint": self.endpoint})
        return self.lease

    async def close(self) -> None:
        if self._state == "closed":
            return
        self._state = "closing"
        server = self._server
        if server is not None:
            server.close()
            await server.wait_closed()
            self._server = None
        for writer in tuple(self._writers):
            writer.close()
        if self._writers:
            await asyncio.gather(
                *(writer.wait_closed() for writer in tuple(self._writers)),
                return_exceptions=True,
            )
        for task in tuple(self._tasks):
            if not task.done():
                task.cancel()
        if self._tasks:
            await asyncio.gather(*tuple(self._tasks), return_exceptions=True)
        self._tasks.clear()
        self._writers.clear()
        if self._network_sandbox is not None:
            result = await asyncio.to_thread(self._network_sandbox.teardown)
            if not result.fully_closed:
                self._state = "quarantined"
                raise NetworkBrokerError(
                    "network namespace teardown is unproven; broker quarantined"
                )
            self._network_sandbox = None
        if self._lease is not None and self._lease._capability is not None:
            try:
                self._authority_broker.revoke(self._lease._capability)
            except AuthorityBrokerError as exc:
                self._state = "quarantined"
                raise NetworkBrokerError(
                    "network lease revocation is unproven; broker quarantined"
                ) from exc
        self._state = "closed"
        self._audit({"event": "network-broker-closed"})

    async def _handle_client(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        stats = _ConnectionStats()
        try:
            await asyncio.wait_for(self._semaphore.acquire(), timeout=_CONNECT_TIMEOUT)
        except TimeoutError:
            await self._reject(writer, 503, "Too Many Connections")
            return
        try:
            if self._lease is None:
                raise NetworkBrokerError("network broker lease is missing")
            # Revalidate the live capability for every connection, not just at
            # startup, so revocation/expiry immediately closes egress.
            self._lease.validate()
            header = await asyncio.wait_for(
                reader.readuntil(b"\r\n\r\n"), timeout=_CONNECT_TIMEOUT
            )
            if len(header) > _MAX_HEADER_BYTES:
                raise NetworkBrokerError("proxy request header exceeds limit")
            self._validate_proxy_auth(header)
            first_line = header.split(b"\r\n", 1)[0].decode("latin-1")
            parts = first_line.split(" ", 2)
            if len(parts) != 3:
                raise NetworkBrokerError("proxy request line is invalid")
            method, target, version = parts
            stats.method = method.upper()
            if stats.method == "CONNECT":
                await self._handle_connect(target, reader, writer, stats)
            else:
                await self._handle_http(method, target, version, header, reader, writer, stats)
            self._audit({"event": "network-authorized", **stats.__dict__})
        except Exception as exc:  # noqa: BLE001 - every egress error is denied
            self._audit({"event": "network-denied", "reason": str(exc), **stats.__dict__})
            with contextlib.suppress(Exception):
                await self._reject(writer, 403, "Forbidden")
        finally:
            self._semaphore.release()
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()
            self._writers.discard(writer)

    def _validate_proxy_auth(self, header: bytes) -> None:
        value: str | None = None
        for line in header.split(b"\r\n")[1:]:
            name, separator, raw = line.partition(b":")
            if separator and name.strip().lower() == b"proxy-authorization":
                value = raw.decode("latin-1").strip()
                break
        if value is None:
            raise NetworkBrokerError("missing proxy authentication")
        scheme, _, encoded = value.partition(" ")
        if scheme.lower() != "basic" or not encoded:
            raise NetworkBrokerError("invalid proxy authentication scheme")
        try:
            credentials = base64.b64decode(encoded, validate=True)
        except ValueError as exc:
            raise NetworkBrokerError("malformed proxy authentication") from exc
        expected = f"{self._auth_username}:{self._auth_password}".encode("ascii")
        if not hmac.compare_digest(credentials, expected):
            raise NetworkBrokerError("invalid proxy authentication")

    async def _handle_http(
        self,
        method: str,
        raw_target: str,
        version: str,
        header: bytes,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        stats: _ConnectionStats,
    ) -> None:
        parsed = urlsplit(raw_target)
        scheme = parsed.scheme.lower()
        if scheme not in self._protocols or scheme not in {"http", "ws"} or not parsed.hostname:
            raise NetworkBrokerError("proxy requires an absolute HTTP target")
        host = _normalize_domain(parsed.hostname)
        port = parsed.port or 80
        self._authorize_target(host, port, scheme)
        upstream_reader, upstream_writer, _ = await self._open_pinned(host, port)
        stats.host, stats.port = host, port
        path = urlunsplit(("", "", parsed.path or "/", parsed.query, ""))
        lines = header.decode("latin-1").split("\r\n")
        forwarded = [f"{method} {path} {version}"]
        for line in lines[1:]:
            if not line:
                continue
            name = line.split(":", 1)[0].strip().lower()
            if name in {"host", "proxy-authorization", "proxy-connection", "connection"}:
                continue
            forwarded.append(line)
        host_header = host if port == 80 else f"{host}:{port}"
        forwarded.extend((f"Host: {host_header}", "Connection: close", "", ""))
        try:
            upstream_writer.write("\r\n".join(forwarded).encode("latin-1"))
            await upstream_writer.drain()
            await self._relay(reader, writer, upstream_reader, upstream_writer, stats)
        finally:
            upstream_writer.close()
            with contextlib.suppress(Exception):
                await upstream_writer.wait_closed()

    async def _handle_connect(
        self,
        authority: str,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        stats: _ConnectionStats,
    ) -> None:
        # Lazy import avoids coupling the execution model import graph to the
        # browser execution package.  The parser is shared, but the broker
        # remains independently usable in terminal-only deployments.
        from khaos.security.browser_egress_proxy import (
            _parse_tls_sni,
            _read_tls_client_hello,
        )

        parsed = urlsplit(f"//{authority}")
        if not parsed.hostname or parsed.username or parsed.password:
            raise NetworkBrokerError("invalid CONNECT authority")
        host = _normalize_domain(parsed.hostname)
        port = parsed.port or 443
        self._authorize_target(host, port, "https")
        upstream_reader, upstream_writer, _ = await self._open_pinned(host, port)
        stats.host, stats.port = host, port
        try:
            writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            await writer.drain()
            client_hello = await _read_tls_client_hello(reader)
            sni = _parse_tls_sni(client_hello)
            if sni is None or _normalize_domain(sni) != host:
                raise NetworkBrokerError("TLS SNI does not match CONNECT authority")
            upstream_writer.write(client_hello)
            await upstream_writer.drain()
            await self._relay(reader, writer, upstream_reader, upstream_writer, stats)
        finally:
            upstream_writer.close()
            with contextlib.suppress(Exception):
                await upstream_writer.wait_closed()

    def _authorize_target(self, host: str, port: int, protocol: str) -> None:
        if protocol not in self._protocols:
            raise NetworkBrokerError("network protocol is not authorized")
        if port not in self._allowed_ports:
            raise NetworkBrokerError("network port is not authorized")
        if any(_domain_matches(host, blocked) for blocked in self._blocked_domains):
            raise NetworkBrokerError("network domain is blocked")
        if not any(_domain_matches(host, allowed) for allowed in self._allowed_domains):
            raise NetworkBrokerError("network domain is not allowlisted")

    async def _open_pinned(
        self, host: str, port: int
    ) -> tuple[asyncio.StreamReader, asyncio.StreamWriter, str]:
        try:
            infos = await asyncio.to_thread(
                socket.getaddrinfo,
                host,
                port,
                socket.AF_UNSPEC,
                socket.SOCK_STREAM,
            )
        except OSError as exc:
            raise NetworkBrokerError("broker DNS resolution failed") from exc
        addresses: list[tuple[int, str]] = []
        for family, socktype, _proto, _canonname, sockaddr in infos:
            address = str(sockaddr[0])
            parsed = ipaddress.ip_address(address)
            if not parsed.is_global and (host, port) not in self._local_endpoints:
                raise NetworkBrokerError("broker resolved a non-public address")
            if (family, address) not in addresses:
                addresses.append((family, address))
        if not addresses:
            raise NetworkBrokerError("broker DNS returned no safe address")
        errors: list[BaseException] = []
        for family, address in addresses:
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(address, port, family=family),
                    timeout=_CONNECT_TIMEOUT,
                )
                return reader, writer, address
            except (OSError, TimeoutError) as exc:
                errors.append(exc)
        raise NetworkBrokerError("broker could not connect to a pinned address") from errors[-1]

    async def _relay(
        self,
        client_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
        upstream_reader: asyncio.StreamReader,
        upstream_writer: asyncio.StreamWriter,
        stats: _ConnectionStats,
    ) -> None:
        async def copy_stream(
            source: asyncio.StreamReader,
            destination: asyncio.StreamWriter,
            direction: str,
            limit: int,
        ) -> None:
            total = 0
            while True:
                chunk = await asyncio.wait_for(
                    source.read(64 * 1024), timeout=self._idle_timeout
                )
                if not chunk:
                    return
                total += len(chunk)
                if total > limit:
                    raise NetworkBrokerError(f"network {direction} byte limit exceeded")
                destination.write(chunk)
                await destination.drain()
                if direction == "upload":
                    stats.uploaded = total
                else:
                    stats.downloaded = total

        tasks = (
            asyncio.create_task(copy_stream(client_reader, upstream_writer, "upload", self._max_upload)),
            asyncio.create_task(copy_stream(upstream_reader, client_writer, "download", self._max_download)),
        )
        # HTTP/1.1 ``Connection: close`` is a normal terminal signal from
        # either side.  Stop the opposite relay as soon as one direction
        # reaches EOF; waiting for an exception would keep the client side
        # open until the idle timeout and incorrectly turn a successful
        # response into a 403.
        done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        for task in pending:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        for task in done:
            error = task.exception()
            if error is not None:
                raise error

    @staticmethod
    async def _reject(writer: asyncio.StreamWriter, status: int, reason: str) -> None:
        if writer.is_closing():
            return
        writer.write(
            f"HTTP/1.1 {status} {reason}\r\nConnection: close\r\n"
            "Content-Length: 0\r\n\r\n".encode("ascii")
        )
        with contextlib.suppress(Exception):
            await writer.drain()

    def _audit(self, event: dict[str, object]) -> None:
        if self._audit_callback is not None:
            self._audit_callback(event)
        else:
            logger.info("network broker event: %s", event)


def _is_loopback(value: str) -> bool:
    try:
        return ipaddress.ip_address(value).is_loopback
    except ValueError:
        return False


def _endpoint_host(value: str) -> str:
    """Format an IP literal for a URL without accepting a new host value."""
    return f"[{value}]" if ":" in value and not value.startswith("[") else value


def _normalize_domain(value: str) -> str:
    value = value.strip().rstrip(".").lower()
    if not value or len(value) > 253 or "\x00" in value:
        raise NetworkBrokerError("network hostname is invalid")
    try:
        return value.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise NetworkBrokerError("network hostname is invalid") from exc


def _domain_matches(host: str, rule: str) -> bool:
    return host == rule or host.endswith(f".{rule}")


__all__ = ["NetworkBroker", "NetworkBrokerError", "NetworkLease"]
