from __future__ import annotations

import asyncio
import base64
import contextlib

import khaos.security.network_broker as network_broker_module
import pytest
from khaos.security.authority import AuthorityEnvelope
from khaos.security.authority_broker import AuthorityBroker
from khaos.security.network_broker import (
    NetworkBroker,
    NetworkBrokerError,
    NetworkBrokerFactory,
    NetworkLease,
    _NetworkRelayLease,
)


def _authority(broker: AuthorityBroker) -> AuthorityEnvelope:
    return broker.envelope(
        principal_id="principal",
        project_id="project",
        runtime_id="runtime",
        task_id="task",
        workspace_id="workspace",
        workspace_generation=1,
        policy_digest="policy",
        operation_class="network.connect",
        resource_digest="resource",
    )


def _proxy_header(broker: NetworkBroker) -> bytes:
    credentials = base64.b64encode(
        f"{broker.lease.username}:{broker.lease.password}".encode("ascii")
    ).decode("ascii")
    return f"Proxy-Authorization: Basic {credentials}\r\n".encode("ascii")


def _tamper(capability, **changes):
    clone = object.__new__(type(capability))
    for field_name in capability.__dataclass_fields__:
        object.__setattr__(
            clone,
            field_name,
            changes.get(field_name, getattr(capability, field_name)),
        )
    return clone


def test_network_lease_constructor_is_not_an_authority_boundary() -> None:
    with pytest.raises(TypeError, match="only be created"):
        NetworkLease(
            endpoint="http://127.0.0.1:49152",
            username="khaos",
            password="secret",
            capability_digest="forged",
            allowed_domains=frozenset({"allowed.example"}),
            blocked_domains=frozenset(),
            allowed_ports=frozenset({443}),
            protocols=frozenset({"https"}),
        )


def test_network_lease_renews_from_grant_after_effect_ttl(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    authority_broker = AuthorityBroker()
    try:
        authority = _authority(authority_broker)
        capability = authority_broker.issue(authority, allowed_operation="network.connect")
        lease = NetworkLease._from_broker(
            capability=capability,
            authority_broker=authority_broker,
            endpoint="http://127.0.0.1:49152",
            username="khaos",
            password="secret",
            capability_digest=capability.digest,
            allowed_domains=frozenset({"allowed.example"}),
            blocked_domains=frozenset(),
            allowed_ports=frozenset({443}),
            protocols=frozenset({"https"}),
        )
        monkeypatch.setattr(
            network_broker_module.time,
            "time",
            lambda: capability.expires_at + 1,
        )
        lease.validate()
        assert lease._capability is not capability
        assert lease.capability_digest == lease._capability.digest
    finally:
        authority_broker.close()


class _RetryableRelayWriter:
    def __init__(self) -> None:
        self.wait_closed_calls = 0

    def close(self) -> None:
        return None

    async def wait_closed(self) -> None:
        self.wait_closed_calls += 1
        if self.wait_closed_calls == 1:
            raise OSError("upstream close transient failure")


@pytest.mark.asyncio
async def test_network_broker_retries_retained_relay_after_close_failure() -> None:
    authority_broker = AuthorityBroker()
    try:
        capability = authority_broker.issue(
            _authority(authority_broker),
            allowed_operation="network.*",
        )
        broker = NetworkBroker(
            capability,
            authority_broker=authority_broker,
            allowed_domains=frozenset({"allowed.example"}),
        )
        writer = _RetryableRelayWriter()
        lease = _NetworkRelayLease(writer)  # type: ignore[arg-type]
        broker._relay_leases.add(lease)
        broker._upstream_writers.add(writer)  # type: ignore[arg-type]

        with pytest.raises(NetworkBrokerError, match="cleanup"):
            await broker.close()
        assert lease in broker._relay_leases
        assert not broker.terminal_closed

        await broker.close()
        assert writer.wait_closed_calls >= 2
        assert broker.terminal_closed
    finally:
        authority_broker.close()


@pytest.mark.asyncio
async def test_broker_resolves_and_pins_allowlisted_target() -> None:
    received: list[bytes] = []

    async def service(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        received.append(await reader.readuntil(b"\r\n\r\n"))
        writer.write(
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n"
            b"Connection: close\r\n\r\nOK"
        )
        await writer.drain()
        writer.close()
        await writer.wait_closed()

    server = await asyncio.start_server(service, "127.0.0.1", 0)
    target_port = int(server.sockets[0].getsockname()[1])
    authority_broker = AuthorityBroker()
    broker: NetworkBroker | None = None
    try:
        capability = authority_broker.issue(_authority(authority_broker), allowed_operation="network.*")
        broker = NetworkBroker(
            capability,
            authority_broker=authority_broker,
            allowed_domains=frozenset({"localhost"}),
            allowed_ports=frozenset({target_port}),
            protocols=frozenset({"http"}),
            local_endpoints=frozenset({("localhost", target_port)}),
        )
        await broker.start()
        reader, writer = await asyncio.open_connection("127.0.0.1", broker.lease.port)
        writer.write(
            f"GET http://localhost:{target_port}/ok HTTP/1.1\r\n".encode("ascii")
            + _proxy_header(broker)
            + b"Connection: close\r\n\r\n"
        )
        await writer.drain()
        response = await reader.read()
        writer.close()
        await writer.wait_closed()
        assert b"200 OK" in response
        assert response.endswith(b"OK")
        assert received and b"Host: localhost:" in received[0]
    finally:
        if broker is not None:
            await broker.close()
        authority_broker.close()
        server.close()
        await server.wait_closed()


@pytest.mark.asyncio
async def test_broker_rejects_wrong_domain_and_forged_capability() -> None:
    authority_broker = AuthorityBroker()
    try:
        capability = authority_broker.issue(_authority(authority_broker), allowed_operation="network.*")
        broker = NetworkBroker(
            capability,
            authority_broker=authority_broker,
            allowed_domains=frozenset({"allowed.example"}),
        )
        await broker.start()
        reader, writer = await asyncio.open_connection("127.0.0.1", broker.lease.port)
        writer.write(
            b"GET http://blocked.example/ HTTP/1.1\r\n"
            + _proxy_header(broker)
            + b"Connection: close\r\n\r\n"
        )
        await writer.drain()
        response = await reader.read()
        writer.close()
        await writer.wait_closed()
        assert b"403 Forbidden" in response
        await broker.close()

        with pytest.raises(TypeError, match="only be created"):
            capability.__class__(
                authority=capability.authority,
                allowed_operation=capability.allowed_operation,
                resource_digest=capability.resource_digest,
                generation=capability.generation,
                authorization_epoch=capability.authorization_epoch,
                issued_at=capability.issued_at,
                expires_at=capability.expires_at,
                nonce=capability.nonce,
                token="forged",
                seal=capability.seal,
            )
        forged = _tamper(capability, token="forged")
        forged_broker = NetworkBroker(
            forged,
            authority_broker=authority_broker,
            allowed_domains=frozenset({"allowed.example"}),
        )
        with pytest.raises(NetworkBrokerError):
            await forged_broker.start()
    finally:
        authority_broker.close()


@pytest.mark.asyncio
async def test_broker_revalidates_lease_after_revocation() -> None:
    authority_broker = AuthorityBroker()
    broker: NetworkBroker | None = None
    try:
        capability = authority_broker.issue(_authority(authority_broker), allowed_operation="network.*")
        broker = NetworkBroker(
            capability,
            authority_broker=authority_broker,
            allowed_domains=frozenset({"allowed.example"}),
        )
        lease = await broker.start()
        issued_capability = lease._capability
        authority_broker.revoke(issued_capability)
        reader, writer = await asyncio.open_connection("127.0.0.1", lease.port)
        writer.write(
            b"GET http://allowed.example/ HTTP/1.1\r\n"
            + _proxy_header(broker)
            + b"Connection: close\r\n\r\n"
        )
        await writer.drain()
        try:
            response = await reader.read()
        except ConnectionResetError:
            response = b""
        writer.close()
        with contextlib.suppress(ConnectionResetError):
            await writer.wait_closed()
        assert b"200 OK" not in response
    finally:
        if broker is not None:
            await broker.close()
        authority_broker.close()


@pytest.mark.asyncio
async def test_factory_binds_policy_to_lease_and_revokes_on_close() -> None:
    authority_broker = AuthorityBroker()
    broker: NetworkBroker | None = None
    try:
        factory = NetworkBrokerFactory(
            authority_broker=authority_broker,
            linux_namespace=False,
        )
        broker, lease = await factory.start(
            principal_id="principal",
            project_id="project",
            runtime_id="runtime",
            task_id="task",
            workspace_id="workspace",
            workspace_generation=1,
            policy_digest="policy",
            authorization_epoch=7,
            allowed_domains=frozenset({"allowed.example"}),
            blocked_domains=frozenset({"blocked.example"}),
        )
        assert lease.allowed_domains == frozenset({"allowed.example"})
        assert lease.blocked_domains == frozenset({"blocked.example"})
        lease.validate()

        await broker.close()
        assert broker.terminal_closed
        with pytest.raises(NetworkBrokerError, match="attestation"):
            lease.validate()
        broker = None
    finally:
        if broker is not None:
            await broker.close()
        authority_broker.close()
