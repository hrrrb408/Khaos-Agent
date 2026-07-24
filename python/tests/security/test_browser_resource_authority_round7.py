"""Batch 7.3 (round-7): Browser Resource Authority Transaction.

Closes review §六 (Critical: Registry Confused Deputy), §七 (Resource
creation no transaction state machine), §八 (Teardown swallows failures),
§九 (Egress port set not transactional).

These tests exercise the LOGIC (name derivation/validation, registry
format, CleanupResult, port rollback) without needing a privileged Linux
kernel — they run everywhere.  The real-kernel teardown/reaper behavior
is additionally covered by the ``kernel_real`` tests in
``test_browser_kernel_isolation_round6.py``.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from khaos.security.browser_sandbox import (
    BrowserNetworkSandbox,
    CleanupResult,
    _derive_cgroup_name,
    _derive_netns_name,
    _derive_nft_table,
    _derive_veth_host,
    _is_valid_derived_name,
)


# ===========================================================================
# §六 — Name derivation + validation (the Confused Deputy defense)
# ===========================================================================


class TestNameDerivation:
    def test_derive_netns_name(self):
        assert _derive_netns_name("a1b2c3d4e5f6a1b2") == "khaos-br-a1b2c3"

    def test_derive_veth_host(self):
        assert _derive_veth_host("a1b2c3d4e5f6a1b2") == "khbrh-a1b2c3"

    def test_derive_nft_table(self):
        assert _derive_nft_table("a1b2c3d4e5f6a1b2") == "khaos_browser_a1b2c3d4e5f6a1b2"

    def test_derive_cgroup_name(self):
        assert _derive_cgroup_name("a1b2c3d4e5f6a1b2") == "browser-a1b2c3d4"


class TestNameValidation:
    """§六: derived names must pass strict regex; forged names rejected."""

    def test_valid_derived_names_pass(self):
        assert _is_valid_derived_name(
            netns="khaos-br-a1b2c3",
            veth="khbrh-a1b2c3",
            nft_table="khaos_browser_a1b2c3d4e5f6a1b2",
        )

    def test_forged_netns_rejected(self):
        # A forged registry entry naming "production-vpn" must fail.
        assert not _is_valid_derived_name(netns="production-vpn")

    def test_forged_veth_rejected(self):
        assert not _is_valid_derived_name(veth="docker0")

    def test_forged_nft_table_rejected(self):
        assert not _is_valid_derived_name(nft_table="important_host_table")

    def test_short_token_netns_rejected(self):
        assert not _is_valid_derived_name(netns="khaos-br-short")

    def test_empty_names_pass(self):
        # No names to validate → vacuously valid.
        assert _is_valid_derived_name()


# ===========================================================================
# §六 — Registry no longer stores resource names
# ===========================================================================


class TestRegistryFormat:
    """§六: the registry entry must NOT contain netns/veth/cgroup/nft
    names — only token/pid/process_start_time/creation_stage."""

    def test_registry_entry_has_no_resource_names(self, tmp_path, monkeypatch):
        # Point the registry at a temp dir.
        monkeypatch.setattr(
            "khaos.security.browser_sandbox._RESOURCE_REGISTRY",
            tmp_path / "reg",
        )
        sb = BrowserNetworkSandbox(require_os_sandbox=False)
        sb._token = "a1b2c3d4e5f6a1b2"
        sb._creation_stage = "INTENT"
        sb._write_registry_entry()
        assert sb._registry_file is not None
        entry = json.loads(sb._registry_file.read_text())
        # Allowed fields only.
        assert set(entry.keys()) == {
            "token", "pid", "process_start_time", "creation_stage",
        }
        # Forbidden resource-name fields.
        for forbidden in (
            "netns_name", "veth_host", "veth_ns", "cgroup_path", "nft_table",
        ):
            assert forbidden not in entry, (
                f"registry still stores {forbidden!r} — Confused Deputy surface"
            )


# ===========================================================================
# §六/§七 — Production refuses startup on registry write failure
# ===========================================================================


class TestRegistryProductionRefusal:
    def test_production_refuses_when_registry_dir_unwritable(self, tmp_path, monkeypatch):
        """§六: when require_os_sandbox=True, a registry write failure must
        RAISE (not best-effort debug log) — an un-trackable sandbox must
        not start."""
        # Force mkdir to fail.
        monkeypatch.setattr(
            "khaos.security.browser_sandbox._RESOURCE_REGISTRY",
            tmp_path / "reg",
        )
        sb = BrowserNetworkSandbox(require_os_sandbox=True)
        sb._token = "a1b2c3d4e5f6a1b2"
        sb._creation_stage = "INTENT"
        with patch("pathlib.Path.mkdir", side_effect=OSError("denied")):
            from khaos.security.browser_sandbox import BrowserSandboxError
            with pytest.raises(BrowserSandboxError, match="registry"):
                sb._write_registry_entry()

    def test_dev_mode_tolerates_registry_failure(self, tmp_path, monkeypatch):
        """§六: in dev mode (require_os_sandbox=False), a registry failure
        is still best-effort (no raise) — preserves the dev escape hatch."""
        monkeypatch.setattr(
            "khaos.security.browser_sandbox._RESOURCE_REGISTRY",
            tmp_path / "reg",
        )
        sb = BrowserNetworkSandbox(require_os_sandbox=False)
        sb._token = "a1b2c3d4e5f6a1b2"
        sb._creation_stage = "INTENT"
        with patch("pathlib.Path.mkdir", side_effect=OSError("denied")):
            sb._write_registry_entry()  # must NOT raise
        assert sb._registry_file is None


# ===========================================================================
# §七 — Stage state machine
# ===========================================================================


class TestCreationStage:
    def test_stage_starts_empty(self):
        sb = BrowserNetworkSandbox(require_os_sandbox=False)
        assert sb._creation_stage == ""

    def test_update_registry_stage_writes_stage(self, tmp_path, monkeypatch):
        monkeypatch.setattr(
            "khaos.security.browser_sandbox._RESOURCE_REGISTRY",
            tmp_path / "reg",
        )
        sb = BrowserNetworkSandbox(require_os_sandbox=False)
        sb._token = "a1b2c3d4e5f6a1b2"
        sb._creation_stage = "INTENT"
        sb._write_registry_entry()
        sb._update_registry_stage("NETNS")
        entry = json.loads(sb._registry_file.read_text())
        assert entry["creation_stage"] == "NETNS"

    def test_update_registry_stage_atomic(self, tmp_path, monkeypatch):
        """§七: the stage update uses temp-file + os.replace (atomic)."""
        monkeypatch.setattr(
            "khaos.security.browser_sandbox._RESOURCE_REGISTRY",
            tmp_path / "reg",
        )
        sb = BrowserNetworkSandbox(require_os_sandbox=False)
        sb._token = "a1b2c3d4e5f6a1b2"
        sb._creation_stage = "INTENT"
        sb._write_registry_entry()
        sb._update_registry_stage("BROWSER_ACTIVE")
        # No leftover .tmp file.
        tmp = sb._registry_file.with_suffix(".tmp")
        assert not tmp.exists()
        entry = json.loads(sb._registry_file.read_text())
        assert entry["creation_stage"] == "BROWSER_ACTIVE"


# ===========================================================================
# §八 — CleanupResult
# ===========================================================================


class TestCleanupResult:
    def test_fully_closed_when_all_removed(self):
        r = CleanupResult(
            nft_removed=True, veth_removed=True, netns_removed=True,
            cgroup_removed=True, wrapper_removed=True, run_dir_removed=True,
            registry_retained=False, fully_closed=True,
        )
        assert r.fully_closed

    def test_not_closed_when_nft_fails(self):
        r = CleanupResult(
            nft_removed=False, veth_removed=True, netns_removed=True,
            cgroup_removed=True, registry_retained=True, fully_closed=False,
        )
        assert not r.fully_closed
        assert r.registry_retained


class TestTeardownResult:
    """§八: teardown returns a CleanupResult; on a clean teardown
    fully_closed=True; the dev-mode sandbox (inactive) returns a clean
    result without touching the kernel."""

    def test_teardown_returns_cleanup_result(self):
        sb = BrowserNetworkSandbox(require_os_sandbox=False)
        # Inactive sandbox → teardown is a no-op that returns fully_closed.
        result = sb.teardown()
        assert isinstance(result, CleanupResult)
        # Nothing was active, so nothing failed → fully closed (vacuously).
        assert result.fully_closed

    def test_teardown_retains_registry_on_kernel_failure(self, tmp_path, monkeypatch):
        """§八: if a kernel-resource deletion fails, the registry is
        RETAINED and fully_closed=False."""
        monkeypatch.setattr(
            "khaos.security.browser_sandbox._RESOURCE_REGISTRY",
            tmp_path / "reg",
        )
        sb = BrowserNetworkSandbox(require_os_sandbox=False)
        sb._token = "a1b2c3d4e5f6a1b2"
        sb._creation_stage = "INTENT"
        sb._write_registry_entry()
        reg = sb._registry_file
        assert reg is not None and reg.exists()
        # Simulate an active sandbox with an nft table that fails to delete.
        sb._active = True
        sb._nft_table = "khaos_browser_a1b2c3d4e5f6a1b2"
        sb._netns_name = "khaos-br-a1b2c3"
        sb._veth_host = "khbrh-a1b2c3"
        sb._cgroup_path = None  # no cgroup → cgroup_removed True (vacuous)
        # Make _run_command raise for nft delete but succeed for others.
        from khaos.security.browser_sandbox import _run_command as real_rc

        def fake_rc(cmd, desc):
            if "nft" in " ".join(cmd):
                raise OSError("nft delete failed")

        with patch("khaos.security.browser_sandbox._run_command", fake_rc):
            result = sb.teardown()
        assert not result.nft_removed
        assert not result.fully_closed
        assert result.registry_retained
        # Registry file still exists (retained for the reaper).
        assert reg.exists()


# ===========================================================================
# §九 — Egress port transaction (rollback on failure)
# ===========================================================================


class TestEgressPortTransaction:
    """§九: install_egress_pin / remove_egress_port are transactional —
    the in-memory _egress_ports set only commits on a successful nft apply."""

    def test_install_commits_on_success(self):
        sb = BrowserNetworkSandbox(require_os_sandbox=False)
        sb._active = True
        sb._veth_host = "khbrh-a1b2c3"
        sb._nft_table = "khaos_browser_a1b2c3d4e5f6a1b2"
        with patch.object(sb, "_apply_nft_script", return_value=True):
            sb.install_egress_pin(40001)
        assert 40001 in sb._egress_ports

    def test_install_rolls_back_on_soft_failure(self):
        """§九: if _apply_nft_script returns False (dev-mode soft fail),
        the port is NOT added to the set (no stale port)."""
        sb = BrowserNetworkSandbox(require_os_sandbox=False)
        sb._active = True
        sb._veth_host = "khbrh-a1b2c3"
        sb._nft_table = "khaos_browser_a1b2c3d4e5f6a1b2"
        with patch.object(sb, "_apply_nft_script", return_value=False):
            sb.install_egress_pin(40001)
        assert 40001 not in sb._egress_ports, (
            "install left a stale port after a soft nft failure"
        )

    def test_install_rolls_back_on_exception(self):
        """§九: if _apply_nft_script raises, the port is rolled back."""
        sb = BrowserNetworkSandbox(require_os_sandbox=False)
        sb._active = True
        sb._veth_host = "khbrh-a1b2c3"
        sb._nft_table = "khaos_browser_a1b2c3d4e5f6a1b2"
        from khaos.security.browser_sandbox import BrowserSandboxError
        with patch.object(
            sb, "_apply_nft_script", side_effect=BrowserSandboxError("nft boom")
        ):
            with pytest.raises(BrowserSandboxError):
                sb.install_egress_pin(40001)
        assert 40001 not in sb._egress_ports

    def test_install_preserves_existing_ports_on_rollback(self):
        """§九: a failed install must not disturb already-pinned ports."""
        sb = BrowserNetworkSandbox(require_os_sandbox=False)
        sb._active = True
        sb._veth_host = "khbrh-a1b2c3"
        sb._nft_table = "khaos_browser_a1b2c3d4e5f6a1b2"
        sb._egress_ports = {40001}
        with patch.object(sb, "_apply_nft_script", return_value=False):
            sb.install_egress_pin(40002)
        assert sb._egress_ports == {40001}, (
            "rollback disturbed the existing pin set"
        )

    def test_remove_commits_on_success(self):
        sb = BrowserNetworkSandbox(require_os_sandbox=False)
        sb._active = True
        sb._veth_host = "khbrh-a1b2c3"
        sb._nft_table = "khaos_browser_a1b2c3d4e5f6a1b2"
        sb._egress_ports = {40001}
        with patch.object(sb, "_apply_nft_script", return_value=True):
            sb.remove_egress_port(40001)
        assert 40001 not in sb._egress_ports

    def test_remove_keeps_port_on_soft_failure(self):
        """§九: if the re-apply after removal fails, the port is KEPT
        (stale-open is safer than stale-closed — the proxy may still be
        running, so the kernel allowing it is correct)."""
        sb = BrowserNetworkSandbox(require_os_sandbox=False)
        sb._active = True
        sb._veth_host = "khbrh-a1b2c3"
        sb._nft_table = "khaos_browser_a1b2c3d4e5f6a1b2"
        sb._egress_ports = {40001}
        with patch.object(sb, "_apply_nft_script", return_value=False):
            sb.remove_egress_port(40001)
        assert 40001 in sb._egress_ports, (
            "remove dropped the port on failure (stale-closed is unsafe)"
        )

    def test_remove_keeps_port_on_exception(self):
        sb = BrowserNetworkSandbox(require_os_sandbox=False)
        sb._active = True
        sb._veth_host = "khbrh-a1b2c3"
        sb._nft_table = "khaos_browser_a1b2c3d4e5f6a1b2"
        sb._egress_ports = {40001}
        from khaos.security.browser_sandbox import BrowserSandboxError
        with patch.object(
            sb, "_apply_nft_script", side_effect=BrowserSandboxError("nft boom")
        ):
            with pytest.raises(BrowserSandboxError):
                sb.remove_egress_port(40001)
        assert 40001 in sb._egress_ports
