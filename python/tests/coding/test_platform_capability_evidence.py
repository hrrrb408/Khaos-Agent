"""Secure-default platform selection and capability-cache evidence tests."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from khaos.coding.execution.platform import (
    BackendAvailability,
    CapabilityEvidence,
    LinuxBubblewrapBackend,
    MacOSSandboxBackend,
    _CapabilityCacheEntry,
    _cached_availability,
    _development_mode,
)
from khaos.coding.execution.capability import SandboxDecision


def _evidence() -> CapabilityEvidence:
    return CapabilityEvidence(
        boot_id="boot-a",
        uid=1001,
        mount_namespace_inode=10,
        user_namespace_inode=11,
        binary_device=12,
        binary_inode=13,
        binary_digest="a" * 64,
        cgroup_root_device=14,
        cgroup_root_inode=15,
        probe_timestamp=1_000_000_000.0,
    )


def test_secure_mode_is_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("KHAOS_DEV_MODE", raising=False)
    assert not _development_mode()
    monkeypatch.setenv("KHAOS_DEV_MODE", "0")
    assert not _development_mode()
    monkeypatch.setenv("KHAOS_DEV_MODE", "1")
    assert _development_mode()


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("boot_id", "boot-b"),
        ("uid", 2002),
        ("mount_namespace_inode", 20),
        ("user_namespace_inode", 21),
        ("binary_device", 22),
        ("binary_inode", 23),
        ("binary_digest", "b" * 64),
        ("cgroup_root_device", 24),
        ("cgroup_root_inode", 25),
    ],
)
def test_cache_invalidates_on_every_system_or_tcb_identity_change(
    monkeypatch: pytest.MonkeyPatch, field: str, value: object
) -> None:
    original = _evidence()
    monkeypatch.setattr(
        "khaos.coding.execution.capability.time.time",
        lambda: 1_000_000_001.0,
    )
    availability = BackendAvailability("linux-bwrap", True, True, evidence=original)
    entry = _CapabilityCacheEntry(availability, original)
    assert _cached_availability(entry, original) is availability
    assert _cached_availability(entry, replace(original, **{field: value})) is None


def test_cache_is_runtime_instance_owned() -> None:
    first = LinuxBubblewrapBackend()
    second = LinuxBubblewrapBackend()
    first._capability_cache = _CapabilityCacheEntry(
        BackendAvailability("linux-bwrap", True, True, evidence=_evidence()),
        _evidence(),
    )
    assert second._capability_cache is None


def test_sandbox_decision_binds_concrete_backend_and_evidence() -> None:
    backend = type("ConcreteBackend", (), {"name": "linux-bwrap"})()
    availability = BackendAvailability(
        "linux-bwrap", True, True, evidence=_evidence()
    )
    decision = SandboxDecision.from_backend(
        backend,
        availability,
        writable=True,
        network_mode="none",
        platform="linux",
    )
    changed = replace(decision, launcher_digest="b" * 64)
    assert decision.backend_name == "linux-bwrap"
    assert decision.filesystem_mode == "workspace-write"
    assert decision.kernel_enforced is True
    assert decision.digest() != changed.digest()


def test_sandbox_decision_rejects_unenforced_probe() -> None:
    backend = type("ConcreteBackend", (), {"name": "unsupported"})()
    availability = BackendAvailability(
        "unsupported", False, False, "missing", evidence=_evidence()
    )
    with pytest.raises(PermissionError, match="kernel-enforced"):
        SandboxDecision.from_backend(backend, availability, writable=False)


def test_macos_profile_does_not_grant_global_metadata_visibility(tmp_path: Path) -> None:
    profile = MacOSSandboxBackend().profile(tmp_path)
    assert "(allow file-read-metadata)" not in profile
