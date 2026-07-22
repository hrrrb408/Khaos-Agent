"""Host-side network egress authority.

Repository tools execute in a trusted host process, outside the command
sandbox.  This authority normalizes hostnames, resolves every A/AAAA result,
rejects special-use addresses, and returns an immutable DNS snapshot that a
transport can pin for the lifetime of one request hop.
"""

from __future__ import annotations

import asyncio
import ipaddress
import socket
from dataclasses import dataclass
from typing import Awaitable, Callable
from urllib.parse import ParseResult, urlparse


class HostNetworkDeniedError(ValueError):
    """Raised when a host request cannot be proven public and safe."""


@dataclass(frozen=True)
class ValidatedTarget:
    """Normalized URL plus the public DNS addresses approved for one hop."""

    url: str
    parsed: ParseResult
    hostname: str
    addresses: tuple[str, ...]


Resolver = Callable[[str, int], Awaitable[list[tuple]]]


class HostNetworkAuthority:
    """Validate URLs and freeze DNS results before a host connection."""

    def __init__(self, resolver: Resolver | None = None) -> None:
        self._resolver = resolver or self._resolve

    async def validate_url(
        self,
        url: str,
        *,
        previous_scheme: str | None = None,
        allowed_schemes: frozenset[str] = frozenset({"http", "https"}),
    ) -> ValidatedTarget:
        parsed = urlparse(url)
        scheme = parsed.scheme.lower()
        if scheme not in allowed_schemes or not parsed.netloc:
            raise HostNetworkDeniedError("URL must use an allowed network scheme")
        if parsed.username is not None or parsed.password is not None:
            raise HostNetworkDeniedError("URL userinfo is not allowed")
        if previous_scheme == "https" and scheme == "http":
            raise HostNetworkDeniedError("HTTPS redirect downgrade is not allowed")

        raw_hostname = (parsed.hostname or "").strip().rstrip(".")
        if not raw_hostname:
            raise HostNetworkDeniedError("URL hostname is required")
        try:
            hostname = raw_hostname.encode("idna").decode("ascii").lower()
        except UnicodeError as exc:
            raise HostNetworkDeniedError("URL hostname is not valid IDNA") from exc
        if hostname == "localhost" or hostname.endswith(".localhost"):
            raise HostNetworkDeniedError("localhost is not a public destination")

        port = parsed.port or (443 if scheme in {"https", "wss"} else 80)
        try:
            literal = ipaddress.ip_address(hostname.strip("[]"))
        except ValueError:
            try:
                records = await self._resolver(hostname, port)
            except OSError as exc:
                raise HostNetworkDeniedError(
                    f"DNS resolution failed for {hostname}: {exc}"
                ) from exc
            addresses = tuple(
                sorted({str(record[4][0]) for record in records if record[4]})
            )
            if not addresses:
                raise HostNetworkDeniedError(
                    f"DNS resolution returned no addresses for {hostname}"
                )
        else:
            addresses = (str(literal),)

        for address in addresses:
            if not _is_public_address(address):
                raise HostNetworkDeniedError(
                    f"destination {hostname} resolved to prohibited address {address}"
                )
        return ValidatedTarget(
            url=url,
            parsed=parsed,
            hostname=hostname,
            addresses=addresses,
        )

    @staticmethod
    async def _resolve(hostname: str, port: int) -> list[tuple]:
        loop = asyncio.get_running_loop()
        return await loop.getaddrinfo(
            hostname,
            port,
            family=socket.AF_UNSPEC,
            type=socket.SOCK_STREAM,
        )


def _is_public_address(address: str) -> bool:
    ip = ipaddress.ip_address(address)
    # is_global also excludes private, loopback, link-local, multicast,
    # unspecified, reserved and documentation/special-use ranges.  Keep the
    # explicit checks as defense against interpreter classification drift.
    return bool(
        ip.is_global
        and not ip.is_private
        and not ip.is_loopback
        and not ip.is_link_local
        and not ip.is_multicast
        and not ip.is_reserved
        and not ip.is_unspecified
    )
