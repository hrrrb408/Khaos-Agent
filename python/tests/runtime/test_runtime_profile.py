"""Regression contracts for explicit runtime security profiles."""

from __future__ import annotations

from pathlib import Path

import pytest

from khaos.runtime_profile import RuntimeProfile, resolve_runtime_profile


@pytest.mark.asyncio
async def test_build_production_runtime_ignores_dev_mode_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("KHAOS_DEV_MODE", "1")
    from khaos.runtime import factory

    seen: list[object] = []

    async def capture(config: object) -> object:
        seen.append(config)
        return object()

    monkeypatch.setattr(factory, "build_runtime", capture)
    config = factory.ProductionRuntimeConfig()

    await factory.build_production_runtime(config)

    assert seen == [config]
    assert config.profile is RuntimeProfile.PRODUCTION


@pytest.mark.asyncio
async def test_production_runtime_cannot_disable_security_injection_checks(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("KHAOS_DEV_MODE", "1")
    from khaos.runtime import RuntimeConfig, build_runtime

    with pytest.raises(PermissionError, match="tool_scheduler must not be injected"):
        await build_runtime(
            RuntimeConfig(
                project_root=tmp_path,
                db=object(),
                principal_id="profile-test",
                profile=RuntimeProfile.PRODUCTION,
                tool_scheduler=object(),
            )
        )


def test_production_runtime_cannot_enable_host_fallback(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("KHAOS_DEV_MODE", "1")
    from khaos.coding.execution.native_launcher import build_process_launch

    with pytest.raises(
        PermissionError, match="cannot disable authority receipts"
    ):
        build_process_launch(
            ("/bin/echo",),
            cwd=tmp_path,
            directory_binding=None,
            budget=None,
            enforce_resource_limits=False,
            require_authority_receipt=False,
            runtime_profile=RuntimeProfile.PRODUCTION,
        )


def test_production_rpc_still_requires_protocol_metadata_when_dev_env_is_set(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("KHAOS_DEV_MODE", "1")
    from khaos.rpc.protocol import GatewayRPCAuthenticator, RPCProtocolError

    authenticator = GatewayRPCAuthenticator(
        "k" * 32,
        runtime_profile=RuntimeProfile.PRODUCTION,
    )
    with pytest.raises(RPCProtocolError, match="protocol metadata is required"):
        authenticator.authenticate(
            {
                "method": "Bootstrap.Health",
                "protocol_version": 2,
                "payload": {},
                "auth": {},
            }
        )


@pytest.mark.posix_host
def test_community_local_production_still_validates_trusted_root_when_dev_env_is_set(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("KHAOS_DEV_MODE", "1")
    monkeypatch.setenv("KHAOS_AUTHORITY_PROFILE", "community")
    trusted_root = tmp_path / "home" / ".khaos" / "authorityd"
    trusted_root.mkdir(parents=True)
    monkeypatch.setattr(
        "khaos.security.authority_transport.local_authority_root",
        lambda: trusted_root,
    )
    monkeypatch.setenv(
        "KHAOS_AUTHORITYD_SOCKET",
        str(tmp_path / "repository" / "authorityd.sock"),
    )

    from khaos.security.authority_transport import (
        AuthorityTransportConfig,
        AuthorityTransportError,
    )

    config = AuthorityTransportConfig.from_environment(
        platform_name="darwin",
        os_name="posix",
        runtime_profile=RuntimeProfile.PRODUCTION,
    )
    with pytest.raises(AuthorityTransportError, match="trusted authority directory"):
        config.socket_path()


def test_testing_runtime_can_explicitly_use_testing_profile(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("KHAOS_DEV_MODE", raising=False)

    assert resolve_runtime_profile(RuntimeProfile.TESTING) is RuntimeProfile.TESTING


def test_legacy_runtime_config_is_not_production_reachable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("KHAOS_DEV_MODE", "1")
    from khaos.runtime import RuntimeConfig

    config = RuntimeConfig()

    assert config.profile is None
    assert resolve_runtime_profile(config.profile) is RuntimeProfile.TESTING
