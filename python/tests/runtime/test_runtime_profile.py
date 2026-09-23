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


@pytest.mark.asyncio
async def test_local_runtime_builder_pins_local_profile(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from khaos.runtime import factory

    seen: list[object] = []

    async def capture(config: object) -> object:
        seen.append(config)
        return object()

    monkeypatch.setattr(factory, "build_runtime", capture)

    await factory.build_local_runtime(factory.RuntimeConfig())

    assert len(seen) == 1
    assert isinstance(seen[0], factory.RuntimeConfig)
    assert seen[0].profile is RuntimeProfile.LOCAL
    assert RuntimeProfile.LOCAL.is_local is True
    assert RuntimeProfile.LOCAL.is_production is False


@pytest.mark.asyncio
@pytest.mark.posix_host
async def test_local_runtime_composes_typed_identity_without_browser_authority(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("KHAOS_NO_CONFIG", "1")
    from khaos.db import Database
    from khaos.runtime import (
        RuntimeConfig,
        build_local_runtime,
        close_runtime_or_register,
    )

    db = Database(tmp_path / "runtime.db")
    await db.connect()
    await db.run_migrations()
    runtime = await build_local_runtime(
        RuntimeConfig(
            db=db,
            project_root=tmp_path,
            mode_override="coding",
            principal_id="local-uid:local-test",
            source_transport="cli",
            session_id="local-session",
        )
    )
    try:
        assert runtime.profile is RuntimeProfile.LOCAL
        assert runtime.browser_manager is None
        assert runtime.browser_coding_service is None
        assert runtime.loop.principal_kind == "human"
        assert runtime.loop.parent_principal_id == "human:local-uid:local-test"
        assert len(runtime.loop.delegation_digest) == 64
    finally:
        await close_runtime_or_register(runtime)
        await db.close()


def test_legacy_runtime_config_is_not_production_reachable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("KHAOS_DEV_MODE", "1")
    from khaos.runtime import RuntimeConfig

    config = RuntimeConfig()

    assert config.profile is None
    assert resolve_runtime_profile(config.profile) is RuntimeProfile.TESTING


def test_production_transport_binding_is_derived_from_complete_runtime_identity() -> None:
    from khaos.runtime.factory import _complete_production_principal_binding
    from khaos.security.principals import transport_root_delegation_digest

    kind, parent, digest = _complete_production_principal_binding(
        principal_id="local-uid:501",
        principal_kind="",
        parent_principal_id="",
        delegation_digest="",
        source_transport="cli",
        session_id="session-1",
        project_id="project-1",
        runtime_id="runtime-1",
        policy_digest="a" * 64,
    )

    assert kind == "human"
    assert parent == "human:local-uid:501"
    assert digest == transport_root_delegation_digest(
        principal_id="local-uid:501",
        principal_kind="human",
        parent_principal_id=parent,
        project_id="project-1",
        session_id="session-1",
        runtime_id="runtime-1",
        source_transport="cli",
        policy_digest="a" * 64,
    )


def test_production_transport_binding_rejects_partial_identity() -> None:
    from khaos.runtime.factory import _complete_production_principal_binding

    with pytest.raises(ValueError, match="known.*session_id"):
        _complete_production_principal_binding(
            principal_id="local-uid:501",
            principal_kind="human",
            parent_principal_id="human:local-uid:501",
            delegation_digest="",
            source_transport="unknown",
            session_id="",
            project_id="project-1",
            runtime_id="runtime-1",
            policy_digest="a" * 64,
        )


def test_untyped_local_fixture_does_not_receive_partial_principal_binding() -> None:
    from khaos.runtime.factory import _complete_production_principal_binding

    assert _complete_production_principal_binding(
        principal_id="local-uid:501",
        principal_kind="",
        parent_principal_id="",
        delegation_digest="",
        source_transport="unknown",
        session_id="",
        project_id="project-1",
        runtime_id="runtime-1",
        policy_digest="a" * 64,
    ) == ("", "", "")
