"""Independent M6 postcondition-oriented adversarial matrix.

These tests intentionally assert what must remain impossible or physically
proven after an operation.  A return code or an in-memory success flag is not
treated as a security postcondition.
"""

from __future__ import annotations

import asyncio
import importlib.util
import os
import signal
import socket
import sys
from pathlib import Path

import pytest
from khaos.coding.workspace.boundary import SafeWorkspaceFS, WorkspaceBoundaryError
from khaos.security.authority import AuthorityEnvelope
from khaos.security.authority_broker import AuthorityBroker, AuthorityBrokerError
from khaos.security.credential_provider_host import (
    CredentialProviderHost,
    CredentialProviderHostError,
)
from khaos.security.credential_provider_worker import (
    ProviderSpecError,
    validate_provider_spec,
)
from khaos.security.native_authority import NativeAuthorityError
from khaos.security.network_broker import NetworkBrokerError
from khaos.security.protocol_boundary import (
    EffectBinding,
    OwnerState,
    ProtocolBoundaryError,
    require_owner_transition,
)
from khaos.security.shell_semantics import ShellSemanticStatus, analyze_shell_script

ROOT = Path(__file__).resolve().parents[3]


def _authority(broker: AuthorityBroker, *, principal: str = "human:alice", session: str = "s1") -> AuthorityEnvelope:
    return broker.envelope(
        principal_id=principal,
        project_id="project-1",
        runtime_id="runtime-1",
        task_id="task-1",
        workspace_id="workspace-1",
        workspace_generation=1,
        policy_digest="policy-1",
        operation_class="terminal.exec",
        resource_digest="resource-1",
        principal_kind="human",
        parent_principal_id="human:alice-parent",
        session_id=session,
        delegation_digest="a" * 64,
    )


def test_shell_semantic_bypass_is_not_read_only():
    result = analyze_shell_script("printf '%s' $(cat secret.txt)")
    assert result.status is ShellSemanticStatus.SEMANTIC_UNKNOWN
    assert result.requires_approval is True
    assert result.read_only is False


def test_approval_replay_is_rejected_after_revoke():
    broker = AuthorityBroker()
    try:
        capability = broker.issue(_authority(broker))
        broker.revoke(capability)
        with pytest.raises(AuthorityBrokerError):
            broker.validate(capability)
    finally:
        broker.close()


def test_effect_mutation_after_approval_is_rejected():
    binding = EffectBinding.create(
        operation="terminal.exec",
        resource={"workspace": "workspace-1"},
        effect={"argv": ["/bin/echo", "approved"]},
    )
    assert binding.matches(
        operation="terminal.exec",
        resource={"workspace": "workspace-1"},
        effect={"argv": ["/bin/echo", "approved"]},
    )
    assert not binding.matches(
        operation="terminal.exec",
        resource={"workspace": "workspace-1"},
        effect={"argv": ["/bin/rm", "approved"]},
    )


def test_workspace_symlink_and_hardlink_escape_has_no_external_effect(tmp_path: Path):
    outside = tmp_path.parent / f"{tmp_path.name}-outside"
    outside.mkdir()
    secret = outside / "secret.txt"
    secret.write_text("unchanged", encoding="utf-8")
    (tmp_path / "escape").symlink_to(outside, target_is_directory=True)
    original = tmp_path / "original.txt"
    original.write_text("original", encoding="utf-8")
    os.link(original, tmp_path / "alias.txt")
    with SafeWorkspaceFS(tmp_path) as filesystem:
        with pytest.raises(WorkspaceBoundaryError):
            filesystem.write_bytes("escape/secret.txt", b"mutated")
        with pytest.raises(WorkspaceBoundaryError):
            filesystem.write_bytes("alias.txt", b"mutated")
    assert secret.read_text(encoding="utf-8") == "unchanged"
    assert original.read_text(encoding="utf-8") == "original"


def test_executable_path_poisoning_fails_closed(tmp_path: Path):
    real = tmp_path / "real-helper"
    real.write_text("#!/bin/sh\n", encoding="utf-8")
    real.chmod(0o755)
    link = tmp_path / "helper"
    link.symlink_to(real)
    host = CredentialProviderHost(untrusted_roots=(tmp_path,))
    with pytest.raises(CredentialProviderHostError, match="untrusted root"):
        asyncio.run(host.materialize({"type": "command", "argv": [str(link)]}, deadline=2.0))
    assert not host.alive


def test_credential_provider_relative_and_malformed_specs_are_rejected():
    with pytest.raises(ProviderSpecError):
        validate_provider_spec({"type": "command", "argv": ["helper"]})
    with pytest.raises(ProviderSpecError):
        validate_provider_spec(
            {"type": "env", "variables": {"NOT A VARIABLE": "SOURCE"}}
        )


def test_windows_domain_signal_does_not_require_killpg(monkeypatch):
    """Windows termination uses direct PIDs because ``os.killpg`` is POSIX-only."""
    import khaos.security.credential_provider_host as host_module

    signals: list[tuple[int, signal.Signals]] = []
    monkeypatch.setattr(host_module.os, "name", "nt")
    monkeypatch.delattr(host_module.os, "killpg", raising=False)
    monkeypatch.setattr(
        host_module.os,
        "kill",
        lambda pid, sig: signals.append((pid, sig)),
    )

    host_module._signal_domain(101, {102}, signal.SIGTERM)

    assert {pid for pid, _sig in signals} == {101, 102}
    assert all(sig is signal.SIGTERM for _pid, sig in signals)


@pytest.mark.asyncio
async def test_cancellation_during_spawn_has_no_live_provider_domain():
    host = CredentialProviderHost(termination_grace=0.2, kill_grace=1.0)
    task = asyncio.create_task(
        host.materialize({"type": "sleep", "seconds": 3600}, deadline=30.0)
    )
    await asyncio.sleep(0.2)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert not host.alive


def test_cgroup_cleanup_without_kernel_controls_is_not_reported_closed(tmp_path: Path):
    from khaos.coding.execution.platform import _remove_linux_cgroup

    group = tmp_path / "cgroup"
    group.mkdir()
    with pytest.raises(OSError, match="cgroup.kill"):
        _remove_linux_cgroup(group)
    assert group.exists()


@pytest.mark.asyncio
async def test_broker_dns_loopback_rebind_is_rejected(monkeypatch: pytest.MonkeyPatch):
    import khaos.security.network_broker as network_module

    async def fake_open_connection(*_args, **_kwargs):
        raise AssertionError("unsafe DNS result must be rejected before connect")

    monkeypatch.setattr(
        network_module.socket,
        "getaddrinfo",
        lambda *_args, **_kwargs: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 443))],
    )
    monkeypatch.setattr(network_module.asyncio, "open_connection", fake_open_connection)
    broker = object.__new__(network_module.NetworkBroker)
    broker._local_endpoints = frozenset()
    with pytest.raises(NetworkBrokerError, match="non-public"):
        await broker._open_pinned("public.example", 443)


def test_network_namespace_boundary_is_explicitly_denying(tmp_path: Path):
    from khaos.coding.execution.platform import LinuxBubblewrapBackend

    argv = LinuxBubblewrapBackend().argv_prefix(tmp_path)
    assert "--unshare-net" in argv
    assert "--share-net" not in argv


def test_shutdown_admission_cannot_skip_owner_terminal_proof():
    with pytest.raises(ProtocolBoundaryError):
        require_owner_transition(OwnerState.OPEN, OwnerState.CLOSED, terminal_proven=True)
    with pytest.raises(ProtocolBoundaryError):
        require_owner_transition(
            OwnerState.CLOSING,
            OwnerState.CLOSED,
            terminal_proven=True,
            owned_resources=("process:still-live",),
        )


def test_cross_principal_capability_reuse_is_rejected():
    broker = AuthorityBroker()
    try:
        capability = broker.issue(_authority(broker, principal="human:alice"))
        changed_authority = object.__new__(AuthorityEnvelope)
        for field_name in capability.authority.__dataclass_fields__:
            object.__setattr__(
                changed_authority,
                field_name,
                "human:bob" if field_name == "principal_id" else getattr(capability.authority, field_name),
            )
        forged = object.__new__(type(capability))
        for field_name in capability.__dataclass_fields__:
            object.__setattr__(
                forged,
                field_name,
                changed_authority if field_name == "authority" else getattr(capability, field_name),
            )
        with pytest.raises(AuthorityBrokerError):
            broker.validate(forged)
    finally:
        broker.close()


def test_production_graph_has_no_dev_or_host_fallback_reachability():
    script = ROOT / "scripts" / "generate_production_reachability.py"
    spec = importlib.util.spec_from_file_location("production_graph", script)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    modules, edges, unresolved = module.build_graph()
    assert not unresolved
    assert not module.forbidden_edges(modules, edges)
    assert "khaos.coding.execution.host" not in modules
    assert "khaos.security.test_broker" not in modules


def test_native_missing_proof_is_not_success():
    from khaos.security.native_authority import NativeAuthorityProof

    with pytest.raises(NativeAuthorityError):
        NativeAuthorityProof.from_payload(
            {"platform": "darwin"},
            expected_platform="darwin",
            expected_transport="xpc",
            expected_service_id="authorityd",
            expected_key_ref="key",
        )
