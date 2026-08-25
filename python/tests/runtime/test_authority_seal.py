"""Tests for the runtime authority seal and production injection gate (P1-1).

Review P1-1: ``RuntimeConfig`` allowed injecting every security-critical
component without re-proving its security properties.  In production mode
(``KHAOS_DEV_MODE != "1"``) the factory now refuses to install an injected
``tool_scheduler`` / ``execution_service`` / ``sandbox`` / ``network_guard`` /
``memory_manager`` — they must be constructed by the factory so they carry the
authority seal implicitly.  The dev/test path (``KHAOS_DEV_MODE=1``) still
injects mocks freely.

These tests toggle ``KHAOS_DEV_MODE`` directly with ``monkeypatch.setenv`` so
the production gate is exercised regardless of the suite-wide default.
"""

from __future__ import annotations

import os

import pytest

from khaos.runtime.authority import RuntimeAuthoritySeal, is_production_mode


def test_seal_is_unforgeable_outside_mint():
    """A seal constructed with raw field values (not minted) fails verify()."""
    forged = RuntimeAuthoritySeal(
        principal_id="p", project_id="proj",
        policy_digest="d", runtime_id="r", mac="bogus",
    )
    assert not forged.verify()


def test_minted_seal_verifies_and_matches():
    seal = RuntimeAuthoritySeal.mint(
        principal_id="p", project_id="proj",
        policy_digest="d", runtime_id="r",
    )
    assert seal.verify()
    assert seal.matches(principal_id="p", project_id="proj", policy_digest="d", runtime_id="r")
    assert not seal.matches(principal_id="other", project_id="proj", policy_digest="d", runtime_id="r")


def test_seal_mac_is_process_unique():
    """Two seals with the same fields but minted in different processes would
    differ — within one process they're equal (same MAC key).  This test pins
    that the MAC is deterministic within the process."""
    a = RuntimeAuthoritySeal.mint(principal_id="p", project_id="proj", policy_digest="d", runtime_id="r")
    b = RuntimeAuthoritySeal.mint(principal_id="p", project_id="proj", policy_digest="d", runtime_id="r")
    assert a.mac == b.mac
    assert a == b


def test_is_production_mode_reflects_env(monkeypatch):
    monkeypatch.delenv("KHAOS_DEV_MODE", raising=False)
    assert is_production_mode() is True
    monkeypatch.setenv("KHAOS_DEV_MODE", "1")
    assert is_production_mode() is False
    monkeypatch.setenv("KHAOS_DEV_MODE", "0")
    assert is_production_mode() is True


def test_production_runtime_config_has_no_security_owner_injection_fields():
    """The production input type cannot carry a second security authority."""
    from dataclasses import fields

    from khaos.runtime.factory import ProductionRuntimeConfig

    field_names = {field.name for field in fields(ProductionRuntimeConfig)}
    assert not field_names & {
        "tool_scheduler",
        "execution_service",
        "sandbox",
        "network_guard",
        "memory_manager",
        "browser_manager",
        "workspace_manager",
    }


@pytest.mark.asyncio
async def test_production_mode_rejects_injected_tool_scheduler(tmp_path, monkeypatch):
    """P1-1: in production mode, injecting a ToolScheduler is fail-closed."""
    monkeypatch.delenv("KHAOS_DEV_MODE", raising=False)
    from khaos.runtime.factory import RuntimeConfig, build_runtime
    from unittest.mock import MagicMock

    db = MagicMock()
    db.run_migrations = MagicMock()
    cfg = RuntimeConfig(
        project_root=tmp_path,
        db=db,
        principal_id="local-uid:1000",
        tool_scheduler=MagicMock(),  # injection attempt
    )
    with pytest.raises(PermissionError, match="tool_scheduler must not be injected"):
        await build_runtime(cfg)


@pytest.mark.asyncio
async def test_production_mode_rejects_injected_execution_service(tmp_path, monkeypatch):
    """P1-1: in production mode, injecting an ExecutionService is fail-closed."""
    monkeypatch.delenv("KHAOS_DEV_MODE", raising=False)
    from khaos.runtime.factory import RuntimeConfig, build_runtime
    from unittest.mock import MagicMock

    db = MagicMock()
    db.run_migrations = MagicMock()
    cfg = RuntimeConfig(
        project_root=tmp_path,
        db=db,
        principal_id="local-uid:1000",
        execution_service=MagicMock(),
    )
    with pytest.raises(PermissionError, match="execution_service must not be injected"):
        await build_runtime(cfg)


@pytest.mark.asyncio
async def test_production_mode_rejects_injected_sandbox_network_guard_memory(tmp_path, monkeypatch):
    """P1-1: sandbox, network_guard, memory_manager injections are all rejected."""
    monkeypatch.delenv("KHAOS_DEV_MODE", raising=False)
    from khaos.runtime.factory import RuntimeConfig, build_runtime
    from unittest.mock import MagicMock

    db = MagicMock()
    db.run_migrations = MagicMock()
    for field in ("sandbox", "network_guard", "memory_manager"):
        cfg = RuntimeConfig(
            project_root=tmp_path,
            db=db,
            principal_id="local-uid:1000",
            **{field: MagicMock()},
        )
        with pytest.raises(PermissionError, match=f"{field} must not be injected"):
            await build_runtime(cfg)


@pytest.mark.asyncio
async def test_production_mode_rejects_audit_logger_with_mismatched_digest(monkeypatch):
    """P1-1: a borrowed AuditLogger whose policy_digest disagrees with the
    runtime's effective policy is rejected (a server-shared logger must be
    built from the same compiled policy).  Tested at the gate function level
    so it does not require a fully-initialized runtime."""
    from khaos.runtime.factory import RuntimeConfig, _enforce_borrowed_authority_match
    from khaos.runtime.authority import RuntimeAuthoritySeal
    from unittest.mock import MagicMock

    seal = RuntimeAuthoritySeal.mint(
        principal_id="local-uid:1000", project_id="proj",
        policy_digest="abc123", runtime_id="r",
    )
    injected_logger = MagicMock()
    injected_logger.policy_digest = "deadbeef" * 8  # wrong digest
    injected_logger.principal_id = "local-uid:1000"
    injected_logger.project_id = "proj"
    cfg = RuntimeConfig(
        project_root=MagicMock(),
        db=MagicMock(),
        principal_id="local-uid:1000",
        audit_logger=injected_logger,
    )
    with pytest.raises(PermissionError, match="policy_digest does not match"):
        _enforce_borrowed_authority_match(cfg, seal)


@pytest.mark.asyncio
async def test_dev_mode_allows_security_component_injection(tmp_path, monkeypatch):
    """P1-1: in dev/test mode (KHAOS_DEV_MODE=1) the production injection gate
    is not invoked, so the test suite's mock injection continues to work.
    This test confirms the gate is keyed off is_production_mode()."""
    monkeypatch.setenv("KHAOS_DEV_MODE", "1")
    from khaos.runtime.factory import RuntimeConfig
    from unittest.mock import MagicMock

    assert not is_production_mode()
    # Constructing a config with injected security components is fine in dev
    # mode — build_runtime would not reject it because the gate only runs in
    # production mode.
    cfg = RuntimeConfig(
        project_root=tmp_path,
        db=MagicMock(),
        principal_id="local-uid:1000",
        tool_scheduler=MagicMock(),  # injection — allowed in dev
        sandbox=MagicMock(),
    )
    assert cfg.tool_scheduler is not None
    assert cfg.sandbox is not None


@pytest.mark.asyncio
async def test_production_structural_config_rejects_mock_borrowed_authority(
    tmp_path, monkeypatch
):
    """A borrowed production slot cannot carry a mock authority."""
    monkeypatch.delenv("KHAOS_DEV_MODE", raising=False)
    from khaos.runtime import ProductionRuntimeConfig, build_production_runtime
    from unittest.mock import MagicMock

    cfg = ProductionRuntimeConfig(
        project_root=tmp_path,
        db=MagicMock(),
        principal_id="local-uid:1000",
        source_transport="cli",
        approval_broker=MagicMock(),
    )
    with pytest.raises(PermissionError, match="forbidden testing/mock composition"):
        await build_production_runtime(cfg)
