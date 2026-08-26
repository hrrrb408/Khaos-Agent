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
from typing import TYPE_CHECKING, TypedDict
from urllib.parse import quote, urlsplit, urlunsplit

from khaos.runtime_profile import RuntimeProfile, resolve_runtime_profile
from khaos.security.authority import AuthorityEnvelope
from khaos.security.authority_broker import (
    AuthorityBroker,
    AuthorityBrokerError,
    EffectCapability,
)

if TYPE_CHECKING:
    from khaos.security.resource_scope import TypedResourcePartialOrder

logger = logging.getLogger(__name__)
_NETWORK_LEASE_ISSUER = object()

_MAX_HEADER_BYTES = 64 * 1024
_MAX_CONNECTIONS = 32
_MAX_UPLOAD_BYTES = 64 * 1024 * 1024
_MAX_DOWNLOAD_BYTES = 256 * 1024 * 1024
_IDLE_TIMEOUT = 60.0
_CONNECT_TIMEOUT = 15.0
_HANDLER_DRAIN_TIMEOUT = 10.0


class _NetworkConfigurationFields(TypedDict):
    endpoint: str
    username: str
    password: str
    allowed_domains: frozenset[str]
    blocked_domains: frozenset[str]
    allowed_ports: frozenset[int]
    protocols: frozenset[str]
    namespace_environment: tuple[tuple[str, str], ...]


class _NetworkLeaseFields(_NetworkConfigurationFields):
    capability_digest: str


class NetworkBrokerError(PermissionError):
    """Raised when a brokered network request is not authorized."""


@dataclass(frozen=True, slots=True, init=False)
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
    _authority_grant: AuthorityEnvelope | None = field(
        default=None, init=False, repr=False, compare=False
    )

    def __init__(
        self,
        *,
        endpoint: str,
        username: str,
        password: str,
        capability_digest: str,
        allowed_domains: frozenset[str],
        blocked_domains: frozenset[str],
        allowed_ports: frozenset[int],
        protocols: frozenset[str],
        namespace_environment: tuple[tuple[str, str], ...] = (),
        _issuer: object | None = None,
    ) -> None:
        if _issuer is not _NETWORK_LEASE_ISSUER:
            raise TypeError(
                "NetworkLease instances can only be created by NetworkBroker"
            )
        for name, value in (
            ("endpoint", endpoint),
            ("username", username),
            ("password", password),
            ("capability_digest", capability_digest),
            ("allowed_domains", allowed_domains),
            ("blocked_domains", blocked_domains),
            ("allowed_ports", allowed_ports),
            ("protocols", protocols),
            ("namespace_environment", namespace_environment),
        ):
            object.__setattr__(self, name, value)
        object.__setattr__(self, "_capability", None)
        object.__setattr__(self, "_authority_broker", None)
        object.__setattr__(self, "_authority_grant", None)

    @classmethod
    def _from_broker(
        cls,
        *,
        capability: EffectCapability,
        authority_broker: AuthorityBroker,
        endpoint: str,
        username: str,
        password: str,
        capability_digest: str,
        allowed_domains: frozenset[str],
        blocked_domains: frozenset[str],
        allowed_ports: frozenset[int],
        protocols: frozenset[str],
        namespace_environment: tuple[tuple[str, str], ...] = (),
    ) -> NetworkLease:
        """Create a lease only after NetworkBroker has bound its authority."""
        lease = cls(
            endpoint=endpoint,
            username=username,
            password=password,
            capability_digest=capability_digest,
            allowed_domains=allowed_domains,
            blocked_domains=blocked_domains,
            allowed_ports=allowed_ports,
            protocols=protocols,
            namespace_environment=namespace_environment,
            _issuer=_NETWORK_LEASE_ISSUER,
        )
        object.__setattr__(lease, "_capability", capability)
        object.__setattr__(lease, "_authority_broker", authority_broker)
        object.__setattr__(lease, "_authority_grant", capability.authority)
        lease.validate()
        return lease

    @staticmethod
    def _configuration_digest_for_fields(
        fields: _NetworkConfigurationFields,
    ) -> str:
        """Digest lease configuration before the attested object exists."""
        payload = (
            fields["endpoint"],
            fields["username"],
            fields["password"],
            tuple(sorted(fields["allowed_domains"])),
            tuple(sorted(fields["blocked_domains"])),
            tuple(sorted(fields["allowed_ports"])),
            tuple(sorted(fields["protocols"])),
            fields["namespace_environment"],
        )
        return hashlib.sha256(repr(payload).encode("utf-8")).hexdigest()

    @property
    def configuration_digest(self) -> str:
        """Digest every transport and policy field except its attestation."""
        return self._configuration_digest_for_fields(
            {
                "endpoint": self.endpoint,
                "username": self.username,
                "password": self.password,
                "allowed_domains": self.allowed_domains,
                "blocked_domains": self.blocked_domains,
                "allowed_ports": self.allowed_ports,
                "protocols": self.protocols,
                "namespace_environment": self.namespace_environment,
            }
        )

    def validate(self) -> None:
        """Validate the live broker attestation before a child is launched."""
        capability = self._capability
        authority_broker = self._authority_broker
        if capability is None or authority_broker is None:
            raise NetworkBrokerError("network lease was not broker-issued by NetworkBroker")
        if capability.expires_at <= time.time():
            grant = self._authority_grant
            if grant is None:
                raise NetworkBrokerError("network lease renewal grant is missing")
            try:
                capability = authority_broker.issue(
                    grant,
                    allowed_operation=grant.operation_class,
                    resource_digest=grant.resource_digest,
                )
            except AuthorityBrokerError as exc:
                raise NetworkBrokerError(
                    f"network lease renewal was rejected: {exc}"
                ) from exc
            object.__setattr__(self, "_capability", capability)
            object.__setattr__(self, "capability_digest", capability.digest)
        if capability.digest != self.capability_digest:
            raise NetworkBrokerError("network lease capability digest does not match")
        try:
            authority_broker.validate(
                capability,
                expected_operation="network.connect",
                expected_resource_digest=capability.resource_digest,
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


@dataclass(eq=False)
class _NetworkRelayLease:
    """Own one generic proxy upstream and both relay child tasks."""

    upstream_writer: asyncio.StreamWriter
    tasks: set[asyncio.Task[None]] = field(default_factory=set)
    terminal: bool = False
    _close_error: BaseException | None = None
    _close_lock: asyncio.Lock = field(default_factory=asyncio.Lock, repr=False)
    _close_task: asyncio.Task[None] | None = field(default=None, repr=False)

    def create_task(self, coroutine) -> asyncio.Task[None]:
        """Publish a relay child before the next cancellable await."""
        task = asyncio.create_task(coroutine)
        self.tasks.add(task)
        return task

    async def close(self) -> None:
        """Cancel, await, and close the upstream transport with retry proof."""
        async with self._close_lock:
            if self.terminal:
                return
            close_task = self._close_task
            if close_task is None or close_task.done():
                close_task = asyncio.ensure_future(self._run_close())
                self._close_task = close_task
        await asyncio.shield(close_task)

    async def _run_close(self) -> None:
        for task in tuple(self.tasks):
            if not task.done():
                task.cancel()
        if self.tasks:
            await asyncio.gather(*tuple(self.tasks), return_exceptions=True)
        self.tasks = {task for task in self.tasks if not task.done()}
        try:
            self.upstream_writer.close()
            await self.upstream_writer.wait_closed()
        except BaseException as exc:
            self._close_error = exc
            self.terminal = False
            raise NetworkBrokerError(
                "network relay upstream transport did not reach terminal state"
            ) from exc
        self.tasks.clear()
        self.terminal = True


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
        resource_digest: str | None = None,
        runtime_profile: RuntimeProfile | str | None = None,
    ) -> None:
        if not isinstance(capability, EffectCapability):
            raise NetworkBrokerError("network broker requires a broker-issued capability")
        if not capability.authority.operation_class.startswith("network."):
            raise NetworkBrokerError("capability is not a network authority")
        if resource_digest is not None and resource_digest != capability.resource_digest:
            raise NetworkBrokerError(
                "network broker resource digest does not match its capability"
            )
        if not _is_loopback(bind_host):
            raise NetworkBrokerError("network broker bind_host must be loopback")
        if linux_namespace and not sys.platform.startswith("linux"):
            raise NetworkBrokerError("Linux network namespace broker used on non-Linux")
        if not allowed_domains:
            raise NetworkBrokerError("network broker requires a non-empty domain allowlist")
        if not allowed_ports or any(type(port) is not int or not 1 <= port <= 65535 for port in allowed_ports):
            raise NetworkBrokerError("network broker port allowlist is invalid")
        normalized_allowed = frozenset(
            "*" if str(domain).strip() == "*" else _normalize_domain(str(domain))
            for domain in allowed_domains
        )
        normalized_blocked = frozenset(_normalize_domain(domain) for domain in blocked_domains)
        self._capability = capability
        self.runtime_profile = resolve_runtime_profile(runtime_profile)
        self._authority_broker = authority_broker or AuthorityBroker.default(
            runtime_profile=self.runtime_profile
        )
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
        self._relay_leases: set[_NetworkRelayLease] = set()
        self._upstream_writers: set[asyncio.StreamWriter] = set()
        self._semaphore = asyncio.Semaphore(max_connections)
        self._auth_username = "khaos"
        self._auth_password = secrets.token_urlsafe(32)
        self._state = "new"
        self._lifecycle_lock = asyncio.Lock()
        self._close_task: asyncio.Task[None] | None = None
        self._lease: NetworkLease | None = None
        self._linux_namespace = linux_namespace
        self._network_sandbox = None
        self._resource_digest = resource_digest

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
        return (
            self._state == "closed"
            and self._server is None
            and not self._tasks
            and not self._writers
            and not self._upstream_writers
            and not self._relay_leases
            and self._lease is None
            and self._capability is None
        )

    @property
    def is_quarantined(self) -> bool:
        """Return whether cleanup failed and the broker remains retryable."""
        return self._state == "quarantined"

    def owned_resources(self) -> tuple[str, ...]:
        """Return non-secret resources that still require owner-level cleanup."""
        resources: list[str] = []
        if self._server is not None:
            resources.append("listener")
        if self._tasks:
            resources.append(f"handlers:{len(self._tasks)}")
        if self._writers:
            resources.append(f"client-writers:{len(self._writers)}")
        if self._relay_leases:
            resources.append(f"relay-leases:{len(self._relay_leases)}")
        if self._upstream_writers:
            resources.append(f"upstream-writers:{len(self._upstream_writers)}")
        if self._network_sandbox is not None:
            resources.append("network-namespace")
        if self._lease is not None:
            resources.append("network-lease")
        if self._capability is not None:
            resources.append("authority-capability")
        return tuple(resources)

    async def start(self) -> NetworkLease:
        if self._state == "open":
            return self.lease
        if self._state != "new":
            raise NetworkBrokerError(f"network broker cannot start in state {self._state}")
        try:
            if self._capability.expires_at <= time.time():
                self._capability = self._authority_broker.issue(
                    self._capability.authority,
                    allowed_operation=self._capability.authority.operation_class,
                    resource_digest=self._capability.authority.resource_digest,
                )
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
            lease_fields: _NetworkLeaseFields = {
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
            lease_capability = self._authority_broker.reissue(
                self._capability,
                operation_class="network.connect",
                resource_digest=(
                    self._resource_digest
                    or NetworkLease._configuration_digest_for_fields(lease_fields)
                ),
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
        async with self._lifecycle_lock:
            if self._state == "closed":
                return
            self._state = "closing"
            if self._close_task is None or self._close_task.done():
                self._close_task = asyncio.ensure_future(self._run_close())
            close_task = self._close_task
        await asyncio.shield(close_task)

    async def _run_close(self) -> None:
        """Close all transitive resources, retaining any failed owner for retry."""
        errors: list[BaseException] = []
        server = self._server
        if server is not None:
            server.close()

        tasks = tuple(self._tasks)
        pending: set[asyncio.Task[None]] = set()
        for task in tasks:
            if not task.done():
                task.cancel()
        if tasks:
            _done, pending = await asyncio.wait(
                tasks,
                timeout=_HANDLER_DRAIN_TIMEOUT,
            )
            if _done:
                await asyncio.gather(*_done, return_exceptions=True)
            self._tasks.difference_update(_done)
            if pending:
                errors.append(
                    NetworkBrokerError(
                        "network broker handler drain is unproven"
                    )
                )
        self._tasks.difference_update(
            {task for task in self._tasks if task.done()}
        )

        for relay in tuple(self._relay_leases):
            try:
                await relay.close()
            except asyncio.CancelledError:
                raise
            except BaseException as exc:  # noqa: BLE001 - retain failed lease
                errors.append(exc)
            else:
                if relay.terminal:
                    self._relay_leases.discard(relay)
                    self._upstream_writers.discard(relay.upstream_writer)
                else:
                    errors.append(
                        NetworkBrokerError(
                            f"network relay {id(relay)} lacks terminal proof"
                        )
                    )

        if server is not None and not pending:
            try:
                await server.wait_closed()
            except asyncio.CancelledError:
                raise
            except BaseException as exc:  # noqa: BLE001 - retain failed server
                errors.append(exc)
            else:
                self._server = None

        for writer in tuple(self._writers):
            try:
                writer.close()
                await writer.wait_closed()
            except asyncio.CancelledError:
                raise
            except BaseException as exc:  # noqa: BLE001 - retain failed client writer
                errors.append(exc)
            else:
                self._writers.discard(writer)

        for writer in tuple(self._upstream_writers):
            try:
                writer.close()
                await writer.wait_closed()
            except asyncio.CancelledError:
                raise
            except BaseException as exc:  # noqa: BLE001 - retain failed upstream writer
                errors.append(exc)
            else:
                self._upstream_writers.discard(writer)

        if self._network_sandbox is not None:
            try:
                result = await asyncio.to_thread(self._network_sandbox.teardown)
            except asyncio.CancelledError:
                raise
            except BaseException as exc:  # noqa: BLE001 - retain failed namespace
                errors.append(exc)
            else:
                if result.fully_closed:
                    self._network_sandbox = None
                else:
                    errors.append(
                        NetworkBrokerError(
                            "network namespace teardown is unproven"
                        )
                    )

        if self._lease is not None and self._lease._capability is not None:
            try:
                self._authority_broker.revoke(self._lease._capability)
            except AuthorityBrokerError as exc:
                errors.append(exc)
            else:
                self._lease = None

        if self._capability is not None:
            try:
                self._authority_broker.revoke(self._capability)
            except AuthorityBrokerError as exc:
                errors.append(exc)
            else:
                self._capability = None

        if errors:
            self._state = "quarantined"
            raise NetworkBrokerError(
                "network broker cleanup is unproven; broker quarantined"
            ) from errors[0]
        self._close_task = None
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
            try:
                await writer.wait_closed()
            except asyncio.CancelledError:
                raise
            except BaseException as exc:
                # Keep failed transports registered for owner-level retry.
                logger.debug("network client writer did not close", exc_info=exc)
            else:
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
        self._upstream_writers.add(upstream_writer)
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
            try:
                await upstream_writer.wait_closed()
            except asyncio.CancelledError:
                raise
            except BaseException as exc:
                # Retain an unproven transport for NetworkBroker.close().
                logger.debug("network HTTP upstream writer did not close", exc_info=exc)
            else:
                self._upstream_writers.discard(upstream_writer)

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
        self._upstream_writers.add(upstream_writer)
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
            try:
                await upstream_writer.wait_closed()
            except asyncio.CancelledError:
                raise
            except BaseException as exc:
                # Retain an unproven transport for NetworkBroker.close().
                logger.debug("network CONNECT upstream writer did not close", exc_info=exc)
            else:
                self._upstream_writers.discard(upstream_writer)

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

        lease = _NetworkRelayLease(upstream_writer)
        self._relay_leases.add(lease)
        self._upstream_writers.add(upstream_writer)
        tasks = (
            lease.create_task(
                copy_stream(client_reader, upstream_writer, "upload", self._max_upload)
            ),
            lease.create_task(
                copy_stream(upstream_reader, client_writer, "download", self._max_download)
            ),
        )
        try:
            # HTTP/1.1 ``Connection: close`` is a normal terminal signal from
            # either side.  Stop the opposite relay as soon as one direction
            # reaches EOF; waiting for an exception would keep the client side
            # open until the idle timeout and incorrectly turn a successful
            # response into a 403.
            done, pending = await asyncio.wait(
                tasks, return_when=asyncio.FIRST_COMPLETED
            )
            for task in pending:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            for task in done:
                error = task.exception()
                if error is not None:
                    raise error
        finally:
            cleanup = asyncio.create_task(lease.close())
            try:
                await asyncio.shield(cleanup)
            except asyncio.CancelledError:
                result = await asyncio.gather(cleanup, return_exceptions=True)
                if result and isinstance(result[0], BaseException):
                    logger.warning(
                        "network relay cleanup retained for broker retry: %s",
                        type(result[0]).__name__,
                    )
                raise
            if lease.terminal:
                self._relay_leases.discard(lease)
                self._upstream_writers.discard(upstream_writer)

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


class NetworkBrokerFactory:
    """Create a managed broker and lease for one execution authority.

    The factory is the production bridge between the scheduler's approved
    network policy and the transport consumed by an execution backend. It
    starts the broker before the step authority is frozen, so the lease
    identity is part of the approval-bound permission profile rather than an
    untracked environment mutation at spawn time.
    """

    def __init__(
        self,
        *,
        authority_broker: AuthorityBroker | None = None,
        linux_namespace: bool | None = None,
        audit: Callable[[dict[str, object]], None] | None = None,
        resource_order: TypedResourcePartialOrder | None = None,
        runtime_profile: RuntimeProfile | str | None = None,
    ) -> None:
        self.runtime_profile = resolve_runtime_profile(runtime_profile)
        self.authority_broker = authority_broker or AuthorityBroker.default(
            runtime_profile=self.runtime_profile
        )
        self.resource_order = resource_order
        self.linux_namespace = (
            sys.platform.startswith("linux")
            if linux_namespace is None
            else linux_namespace
        )
        self.audit = audit
        self._quarantined: set[NetworkBroker] = set()

    async def start(
        self,
        *,
        principal_id: str,
        project_id: str,
        runtime_id: str,
        task_id: str,
        workspace_id: str,
        workspace_generation: int,
        policy_digest: str,
        authorization_epoch: int,
        allowed_domains: frozenset[str] | None,
        blocked_domains: frozenset[str],
    ) -> tuple[NetworkBroker, NetworkLease]:
        """Start one capability-bound broker for an execution step."""
        if allowed_domains is not None and not allowed_domains:
            raise NetworkBrokerError(
                "network policy has an explicit empty allowlist; broker denied"
            )
        broker_domains = (
            frozenset({"*"}) if allowed_domains is None else frozenset(allowed_domains)
        )
        policy_resource = self._resource_digest(broker_domains, blocked_domains)
        authority = self.authority_broker.envelope(
            principal_id=principal_id,
            project_id=project_id,
            runtime_id=runtime_id,
            task_id=task_id,
            workspace_id=workspace_id,
            workspace_generation=workspace_generation,
            policy_digest=policy_digest or "policy:unspecified",
            operation_class="network.connect",
            resource_digest=policy_resource,
            authorization_epoch=authorization_epoch,
        )
        capability = self.authority_broker.issue(
            authority,
            allowed_operation="network.connect",
            resource_digest=policy_resource,
        )
        broker = NetworkBroker(
            capability,
            authority_broker=self.authority_broker,
            allowed_domains=broker_domains,
            blocked_domains=frozenset(blocked_domains),
            audit=self.audit,
            linux_namespace=self.linux_namespace,
            resource_digest=policy_resource,
            runtime_profile=self.runtime_profile,
        )
        try:
            lease = await broker.start()
        except BaseException:
            # A failed start may retain a namespace or listener transaction;
            # close is the broker's proof-producing cleanup path.  Retain the
            # broker when that proof cannot be completed so the runtime can
            # retry cleanup during its final close instead of losing ownership
            # at the factory boundary.
            cleanup = asyncio.create_task(broker.close())
            try:
                await asyncio.shield(cleanup)
            except asyncio.CancelledError:
                try:
                    await cleanup
                except BaseException as cleanup_error:
                    self._quarantined.add(broker)
                    raise NetworkBrokerError(
                        "network broker start was cancelled and cleanup is unproven"
                    ) from cleanup_error
                raise
            except BaseException as cleanup_error:
                self._quarantined.add(broker)
                raise NetworkBrokerError(
                    "network broker start failed and cleanup is unproven"
                ) from cleanup_error
            raise
        return broker, lease

    def _resource_digest(
        self,
        broker_domains: frozenset[str],
        blocked_domains: frozenset[str],
    ) -> str:
        """Resolve the network authority through the typed catalog when bound."""
        if self.resource_order is None:
            return hashlib.sha256(
                repr(
                    (
                        tuple(sorted(broker_domains)),
                        tuple(sorted(blocked_domains)),
                        (80, 443),
                        ("http", "https"),
                    )
                ).encode("utf-8")
            ).hexdigest()
        if "*" in broker_domains:
            raise NetworkBrokerError(
                "typed network authority requires an explicit host allowlist"
            )
        from khaos.security.resource_scope import NetworkScope, ResourceScopeError

        try:
            scope = NetworkScope(
                schemes=frozenset({"http", "https"}),
                hosts=broker_domains,
                ports=frozenset({80, 443}),
                path_prefixes=frozenset({"/"}),
                operations=frozenset({"connect"}),
                blocked_hosts=frozenset(blocked_domains),
            )
            return self.resource_order.require_scope(scope)
        except ResourceScopeError as exc:
            raise NetworkBrokerError(
                "network policy is not represented by the typed authority catalog"
            ) from exc

    async def close(self) -> None:
        """Retry cleanup for brokers whose start transaction was unproven."""
        errors: list[BaseException] = []
        for broker in tuple(self._quarantined):
            try:
                await broker.close()
            except BaseException as exc:  # noqa: BLE001 - cleanup must survive cancellation
                errors.append(exc)
            else:
                self._quarantined.discard(broker)
        if errors:
            raise NetworkBrokerError(
                "network broker factory cleanup was not proven"
            ) from errors[0]


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
    return rule == "*" or host == rule or host.endswith(f".{rule}")


def _validate_network_lease_or_close(lease: object) -> None:
    """Deterministically validate network authority or fail closed."""
    if lease is None:
        raise NetworkBrokerError(
            "managed network lease is required before credential materialization"
        )
    validate = getattr(lease, "validate", None)
    if not callable(validate):
        raise NetworkBrokerError(
            "network authority state is malformed and must fail closed"
        )
    try:
        validate()
    except NetworkBrokerError:
        raise
    except Exception as exc:
        raise NetworkBrokerError(
            f"network authority preflight rejected the lease: {exc}"
        ) from exc


def preflight_network_lease(lease: object) -> None:
    """Deterministically validate network authority before any secret load.

    Implements *No Secret Materialization Before Deterministic Authority
    Preflight*: if the network lease is missing, malformed, expired, or its
    broker attestation no longer validates, the caller must fail closed
    before touching a credential provider.  The check is read-only — it
    renews an expired lease through the broker's own grant path exactly like
    ``NetworkLease.validate`` does, but never claims or consumes the effect
    capability reserved for the final operation.
    """
    _validate_network_lease_or_close(lease)


class NetworkReservation:
    """One-shot *prerequisite fence* over the exact network authority.

    State machine: ``PREPARED → RESERVED → CLAIMED → TERMINAL``.

    ``reserve_network_lease`` validates the lease (renewal semantics
    identical to ``NetworkLease.validate``) and holds the reservation;
    ``ensure_live`` re-validates without consuming so callers can prove
    *prerequisite authority exists* immediately before claiming a
    credential — if the authority was revoked, the secret provider is
    never invoked; ``claim`` consumes the fence one-shot right before the
    effect executes.

    Scope (deliberate): this is a local prerequisite fence, **not** a
    broker-owned one-shot authority token.  ``claimed`` is Python object
    state — it does not consume the underlying network capability, and it
    must never be presented as proof that the capability was used exactly
    once.  The enforcement points remain ``NetworkLease.validate`` at
    every brokered connection and the AuthorityBroker capability
    lifecycle; this fence exists so that *secret materialization* cannot
    happen after prerequisite authority has disappeared.
    """

    _PREPARED = "prepared"
    _RESERVED = "reserved"
    _CLAIMED = "claimed"
    _TERMINAL = "terminal"

    def __init__(self, lease: object) -> None:
        _validate_network_lease_or_close(lease)
        self._lease = lease
        self._state = self._RESERVED
        self._reserved_at = time.time()

    @property
    def state(self) -> str:
        return self._state

    @property
    def is_terminal(self) -> bool:
        return self._state == self._TERMINAL

    def ensure_live(self) -> None:
        """Re-validate the reserved authority without consuming it.

        Used as the prerequisite gate directly before credential
        materialization: a revoked or expired lease raises here, so the
        provider loader invocation count stays zero.
        """
        if self._state != self._RESERVED:
            raise NetworkBrokerError(
                f"network reservation is {self._state}, not live"
            )
        _validate_network_lease_or_close(self._lease)

    def claim(self) -> None:
        """Consume the reservation one-shot for the exact effect."""
        if self._state != self._RESERVED:
            raise NetworkBrokerError(
                f"network reservation is {self._state} and cannot be claimed"
            )
        try:
            _validate_network_lease_or_close(self._lease)
        except NetworkBrokerError:
            self._state = self._TERMINAL
            raise
        self._state = self._CLAIMED

    def terminalize(self) -> None:
        """Mark the reservation terminal; idempotent and always safe."""
        self._state = self._TERMINAL

    def __repr__(self) -> str:  # pragma: no cover - diagnostic only
        return f"<NetworkReservation state={self._state}>"


def reserve_network_lease(lease: object) -> NetworkReservation:
    """Reserve the exact network authority as a claimable prerequisite."""
    return NetworkReservation(lease)


__all__ = [
    "NetworkBroker",
    "NetworkBrokerError",
    "NetworkBrokerFactory",
    "NetworkLease",
    "NetworkReservation",
    "preflight_network_lease",
    "reserve_network_lease",
]
