from __future__ import annotations

import socket

import pytest
from unittest.mock import MagicMock
from urllib.parse import urlparse

from khaos.security.host_network import HostNetworkAuthority, HostNetworkDeniedError
from khaos.tools import web_tools


def _records(*addresses: str) -> list[tuple]:
    return [
        (socket.AF_INET6 if ":" in address else socket.AF_INET,
         socket.SOCK_STREAM, 6, "", (address, 443))
        for address in addresses
    ]


async def test_rejects_domain_when_any_dns_answer_is_private() -> None:
    async def resolver(_host: str, _port: int) -> list[tuple]:
        return _records("93.184.216.34", "127.0.0.1")

    with pytest.raises(HostNetworkDeniedError, match="127.0.0.1"):
        await HostNetworkAuthority(resolver).validate_url("https://example.test/")


async def test_rejects_cloud_metadata_and_private_literals() -> None:
    authority = HostNetworkAuthority()
    for url in (
        "http://169.254.169.254/latest/meta-data",
        "http://127.0.0.1:8080/api/config",
        "http://10.0.0.5/",
        "http://[::1]/",
    ):
        with pytest.raises(HostNetworkDeniedError):
            await authority.validate_url(url)


async def test_normalizes_idna_and_freezes_public_dns_snapshot() -> None:
    seen: list[str] = []

    async def resolver(host: str, _port: int) -> list[tuple]:
        seen.append(host)
        return _records("93.184.216.34")

    target = await HostNetworkAuthority(resolver).validate_url(
        "https://bücher.example/path"
    )
    assert seen == ["xn--bcher-kva.example"]
    assert target.addresses == ("93.184.216.34",)


async def test_rejects_https_redirect_downgrade() -> None:
    async def resolver(_host: str, _port: int) -> list[tuple]:
        return _records("93.184.216.34")

    with pytest.raises(HostNetworkDeniedError, match="downgrade"):
        await HostNetworkAuthority(resolver).validate_url(
            "http://example.test/", previous_scheme="https"
        )


async def test_web_transport_revalidates_redirect_and_disables_proxy(monkeypatch) -> None:
    calls: list[tuple[str, str | None]] = []
    client_options: list[dict] = []

    class Authority:
        async def validate_url(self, url: str, *, previous_scheme=None, **_kwargs):
            calls.append((url, previous_scheme))
            if "127.0.0.1" in url:
                raise HostNetworkDeniedError("prohibited redirect target")
            parsed = urlparse(url)
            return web_tools.ValidatedTarget(
                url, parsed, parsed.hostname or "", ("93.184.216.34",)
            )

    class Client:
        def __init__(self, **kwargs):
            client_options.append(kwargs)

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return False

        async def request(self, _method: str, _url: str):
            response = MagicMock()
            response.status_code = 302
            response.headers = {"location": "http://127.0.0.1:8080/private"}
            return response

    monkeypatch.setattr(web_tools, "_HOST_NETWORK_AUTHORITY", Authority())
    monkeypatch.setattr(web_tools.httpx, "AsyncClient", Client)
    with pytest.raises(HostNetworkDeniedError, match="prohibited redirect"):
        await web_tools._request_httpx("GET", "https://public.example/start", 5)
    assert calls == [
        ("https://public.example/start", None),
        ("http://127.0.0.1:8080/private", "https"),
    ]
    assert client_options[0]["trust_env"] is False
    assert client_options[0]["follow_redirects"] is False
