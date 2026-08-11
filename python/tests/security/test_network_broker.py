from __future__ import annotations

import asyncio
import base64
import contextlib

import pytest
from khaos.security.authority import AuthorityEnvelope
from khaos.security.authority_broker import AuthorityBroker
from khaos.security.network_broker import NetworkBroker, NetworkBrokerError


def _authority() -> AuthorityEnvelope:
    return AuthorityEnvelope(
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
        capability = authority_broker.issue(_authority(), allowed_operation="network.*")
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
        capability = authority_broker.issue(_authority(), allowed_operation="network.*")
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
        capability = authority_broker.issue(_authority(), allowed_operation="network.*")
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
