"""Explicit authority profile and transport contract tests."""

from __future__ import annotations

from pathlib import Path
from typing import Self

import pytest
from khaos.security import authorityd_protocol
from khaos.security.authority_transport import (
    AuthorityProfile,
    AuthorityTransport,
    AuthorityTransportConfig,
    AuthorityTransportError,
)
from khaos.security.authorityd_protocol import AuthorityDaemonClient
from khaos.security.identity_isolation import AuthorityIdentityContract


def test_macos_defaults_to_community_unix_transport(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("KHAOS_AUTHORITY_PROFILE", raising=False)

    config = AuthorityTransportConfig.from_environment(
        platform_name="darwin", os_name="posix"
    )

    assert config.profile is AuthorityProfile.COMMUNITY
    assert config.transport is AuthorityTransport.UNIX


def test_macos_native_profile_remains_explicit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("KHAOS_AUTHORITY_PROFILE", "native-production")

    config = AuthorityTransportConfig.from_environment(
        platform_name="darwin", os_name="posix"
    )

    assert config.profile is AuthorityProfile.NATIVE_PRODUCTION
    assert config.transport is AuthorityTransport.NATIVE


def test_unknown_profile_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("KHAOS_AUTHORITY_PROFILE", "automatic")

    with pytest.raises(AuthorityTransportError, match="must be one of"):
        AuthorityTransportConfig.from_environment(
            platform_name="darwin", os_name="posix"
        )


def test_windows_cannot_select_same_user_community_transport(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("KHAOS_AUTHORITY_PROFILE", "community")

    with pytest.raises(AuthorityTransportError, match="Windows must use"):
        AuthorityTransportConfig.from_environment(
            platform_name="win32", os_name="nt"
        )


def test_unknown_platform_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("KHAOS_AUTHORITY_PROFILE", raising=False)

    with pytest.raises(AuthorityTransportError, match="unsupported"):
        AuthorityTransportConfig.from_environment(
            platform_name="freebsd", os_name="posix"
        )


def test_linux_default_preserves_dedicated_uid_unix_transport(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("KHAOS_AUTHORITY_PROFILE", raising=False)

    config = AuthorityTransportConfig.from_environment(
        platform_name="linux", os_name="posix"
    )

    assert config.profile is AuthorityProfile.NATIVE_PRODUCTION
    assert config.transport is AuthorityTransport.UNIX


def test_community_contract_does_not_require_apple_identity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "khaos.security.identity_isolation.sys_platform", lambda: "darwin"
    )
    contract = AuthorityIdentityContract(501, 501, 501)

    contract.validate(
        production=True,
        transport="unix",
        profile="community",
    )


def test_windows_native_contract_uses_platform_identity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "khaos.security.identity_isolation.sys_platform", lambda: "win32"
    )
    contract = AuthorityIdentityContract(501, 501, 501)

    with pytest.raises(
        PermissionError, match="service_sid, agent_sid, named_pipe"
    ):
        contract.validate(
            production=True,
            transport="native",
            profile="native-production",
        )


def test_broker_factory_uses_unix_for_macos_community_profile(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from khaos.security.authority_broker import AuthorityBroker, AuthorityDaemonBroker

    monkeypatch.setattr("khaos.security.authority_transport.sys.platform", "darwin")
    monkeypatch.setattr(
        "khaos.security.identity_isolation.sys_platform", lambda: "darwin"
    )
    monkeypatch.setenv("KHAOS_DEV_MODE", "0")
    monkeypatch.delenv("KHAOS_AUTHORITY_PROFILE", raising=False)
    monkeypatch.setenv("KHAOS_AUTHORITYD_SOCKET", str(tmp_path / "authorityd.sock"))
    # The test simulates macOS on Windows, where ``os.geteuid`` does not
    # exist; provide the simulated same-user authority UID explicitly.
    monkeypatch.setenv("KHAOS_AUTHORITYD_UID", "501")
    AuthorityBroker._default = None
    broker = AuthorityBroker.default()
    try:
        assert isinstance(broker, AuthorityDaemonBroker)
        assert broker._authorityd.transport == "unix"
    finally:
        broker.close()
        AuthorityBroker._default = None


def test_darwin_unix_client_does_not_infer_xpc(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Explicitly model the macOS platform so the test remains portable to
    # Windows runners; the transport must be selected by the caller rather
    # than inferred from the host's native backend.
    monkeypatch.setattr(authorityd_protocol.sys, "platform", "darwin")

    class FakeSocket:
        def __enter__(self) -> Self:
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def settimeout(self, _timeout: float) -> None:
            return None

        def connect(self, _path: str) -> None:
            return None

        def sendall(self, _body: bytes) -> None:
            return None

        def recv(self, _size: int) -> bytes:
            return b'{"ok":true,"transport":"unix"}\n'

    monkeypatch.setattr(
        authorityd_protocol,
        "validate_private_unix_socket",
        lambda _path, expected_uid: None,
    )
    monkeypatch.setattr(
        authorityd_protocol.socket,
        "socket",
        lambda *_args: FakeSocket(),
    )
    # ``Path('/tmp/...')`` is not absolute under Windows path semantics even
    # though this test is explicitly simulating macOS.  Use a portable
    # absolute placeholder; the socket and validator are both mocked.
    client = AuthorityDaemonClient(
        Path.cwd() / "authorityd.sock",
        expected_authority_uid=0,
        transport="unix",
    )
    assert client.request({"operation": "ping"})["transport"] == "unix"
