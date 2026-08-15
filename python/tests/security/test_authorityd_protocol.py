"""Authorityd receipt, independent-audit, and production fail-closed tests."""

from __future__ import annotations

import json
import subprocess
import sys
import threading
import time
from dataclasses import replace
from pathlib import Path
from socket import socketpair

import khaos.security.authorityd as authorityd_module
import khaos.security.authorityd_protocol as authorityd_protocol_module
import pytest
from khaos.coding.execution.identity import (
    executable_identity,
    open_executable_authority,
)
from khaos.coding.execution.models import ResourceBudget
from khaos.coding.execution.native_launcher import build_process_launch
from khaos.coding.execution.receipt_binding import execution_binding_digest
from khaos.security.authority_broker import (
    AuthorityBrokerError,
    AuthorityDaemonBroker,
)
from khaos.security.authorityd import (
    AuthorityDaemon,
    AuthorityPolicyKernel,
    _dispatch,
    _serve_connection,
    build_production_daemon,
)
from khaos.security.authorityd_protocol import (
    AUTHORITYD_PROTOCOL,
    AuthorityControlPlaneError,
    AuthorizationIntent,
    Ed25519KeyStore,
    RemoteAuditUnavailableError,
    SignedAuthorizationReceipt,
    derive_resource_digest,
)
from khaos.security.network_broker import NetworkBroker, NetworkBrokerError


class _MemoryWorm:
    def __init__(self) -> None:
        self.records: list[dict[str, object]] = []

    def append(self, record: dict[str, object]) -> None:
        self.records.append(record)


class _BlockingWorm(_MemoryWorm):
    def __init__(self) -> None:
        super().__init__()
        self.entered = threading.Event()
        self.release = threading.Event()

    def append(self, record: dict[str, object]) -> None:
        self.entered.set()
        if not self.release.wait(timeout=2):
            raise TimeoutError("test WORM did not release")
        super().append(record)


class _SelectiveWorm(_MemoryWorm):
    def __init__(self, failing_kind: str) -> None:
        super().__init__()
        self.failing_kind = failing_kind
        self.fail = True

    def append(self, record: dict[str, object]) -> None:
        if self.fail and record.get("kind") == self.failing_kind:
            raise RemoteAuditUnavailableError(
                f"test WORM rejected {self.failing_kind}"
            )
        super().append(record)


def _intent() -> AuthorizationIntent:
    return AuthorizationIntent(
        principal_id="agent",
        project_id="project",
        runtime_id="runtime",
        task_id="task",
        workspace_id="workspace",
        operation="git.workspace",
        resource_digest="workspace-digest",
        policy_digest="policy-digest",
        nonce="nonce-1",
        authorization_epoch=2,
    )


@pytest.mark.posix_host
def test_authorityd_prepare_and_complete_are_two_phase(tmp_path: Path) -> None:
    key = Ed25519KeyStore.load_or_create(
        tmp_path / "khaos-authorityd-test-key.pem", create=True
    )
    worm = _MemoryWorm()
    daemon = AuthorityDaemon(
        socket_path=Path("/tmp/khaos-authorityd-test.sock"),
        signing_key=key,
        audit_writer=worm,
        issuer_id="test-authorityd",
        policy=lambda _intent: None,
    )
    receipt = daemon.prepare(_intent())
    receipt.verify(key.public_key())
    daemon.complete(receipt, result="success", result_digest="result-digest")
    assert [record["kind"] for record in worm.records] == [
        "execution.prepare",
        "execution.success",
    ]
    with pytest.raises(AuthorityControlPlaneError):
        daemon.complete(receipt, result="success", result_digest="again")


def test_receipt_wire_timestamps_are_integer_milliseconds(tmp_path: Path) -> None:
    key = Ed25519KeyStore.load_or_create(
        tmp_path / "khaos-authorityd-wire-key.pem", create=True
    )
    daemon = AuthorityDaemon(
        socket_path=tmp_path / "authorityd.sock",
        signing_key=key,
        audit_writer=_MemoryWorm(),
        issuer_id="test-authorityd",
        policy=lambda _intent: None,
    )

    receipt = daemon.prepare(_intent())
    wire = receipt.to_dict()
    assert type(wire["issued_at"]) is int
    assert type(wire["expires_at"]) is int
    assert wire["expires_at"] - wire["issued_at"] == 300_000

    decoded = SignedAuthorizationReceipt.from_dict(wire)
    decoded.verify(key.public_key())

    malformed = dict(wire)
    malformed["issued_at"] = float(wire["issued_at"])
    with pytest.raises(AuthorityControlPlaneError, match="issued_at"):
        SignedAuthorizationReceipt.from_dict(malformed)


def test_claimed_receipt_can_commit_after_launch_ttl(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    clock = [100.0]
    monkeypatch.setattr(authorityd_module.time, "time", lambda: clock[0])
    monkeypatch.setattr(authorityd_protocol_module.time, "time", lambda: clock[0])
    worm = _MemoryWorm()
    daemon = AuthorityDaemon(
        socket_path=tmp_path / "authorityd.sock",
        signing_key=Ed25519KeyStore.load_or_create(tmp_path / "key.pem", create=True),
        audit_writer=worm,
        issuer_id="test-authorityd",
        policy=lambda _intent: None,
    )
    receipt = daemon.prepare(_intent())
    daemon.claim(receipt)
    clock[0] = 401.0
    daemon.complete(receipt, result="success", result_digest="late-result")
    assert daemon.pending_count == 0
    assert [record["kind"] for record in worm.records] == [
        "execution.prepare",
        "execution.claimed",
        "execution.success",
    ]


def test_expired_prepared_receipts_are_gc_bounded_and_cannot_launch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    clock = [100.0]
    monkeypatch.setattr(authorityd_module.time, "time", lambda: clock[0])
    monkeypatch.setattr(authorityd_protocol_module.time, "time", lambda: clock[0])
    daemon = AuthorityDaemon(
        socket_path=tmp_path / "authorityd.sock",
        signing_key=Ed25519KeyStore.load_or_create(tmp_path / "key.pem", create=True),
        audit_writer=_MemoryWorm(),
        issuer_id="test-authorityd",
        policy=lambda _intent: None,
        max_pending_receipts=4,
        max_pending_per_principal=4,
        terminal_tombstone_limit=2,
    )
    receipts = [
        daemon.prepare(replace(_intent(), nonce=f"nonce-{index}"))
        for index in range(4)
    ]
    with pytest.raises(AuthorityControlPlaneError, match="quota"):
        daemon.prepare(replace(_intent(), nonce="nonce-over-quota"))
    clock[0] = 401.0
    assert daemon.pending_count == 0
    with pytest.raises(AuthorityControlPlaneError, match="expired|unknown"):
        daemon.validate(receipts[-1])
    assert len(daemon._terminal) <= 2


def test_expiry_keeps_unprocessed_receipts_when_worm_quota_is_full(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    clock = [100.0]
    monkeypatch.setattr(authorityd_module.time, "time", lambda: clock[0])
    monkeypatch.setattr(authorityd_protocol_module.time, "time", lambda: clock[0])
    worm = _SelectiveWorm("execution.expired")
    daemon = AuthorityDaemon(
        socket_path=tmp_path / "authorityd.sock",
        signing_key=Ed25519KeyStore.load_or_create(tmp_path / "key.pem", create=True),
        audit_writer=worm,
        issuer_id="test-authorityd",
        policy=lambda _intent: None,
        max_pending_receipts=3,
        max_pending_per_principal=3,
        max_audit_obligations=1,
    )
    receipts = [
        daemon.prepare(replace(_intent(), nonce=f"expiry-{index}"))
        for index in range(3)
    ]
    clock[0] = 401.0

    assert daemon.pending_count == 2
    assert daemon.audit_obligation_count == 1
    with pytest.raises(AuthorityControlPlaneError, match="expired|unknown"):
        daemon.validate(receipts[0])
    with pytest.raises(AuthorityControlPlaneError):
        daemon.validate(receipts[1])

    worm.fail = False
    assert daemon.reconcile_audit_obligations() == 0
    assert daemon.pending_count == 0


def test_narrow_refuses_without_two_bounded_audit_slots(tmp_path: Path) -> None:
    daemon = AuthorityDaemon(
        socket_path=tmp_path / "authorityd.sock",
        signing_key=Ed25519KeyStore.load_or_create(tmp_path / "key.pem", create=True),
        audit_writer=_MemoryWorm(),
        issuer_id="test-authorityd",
        policy=lambda _intent: None,
        max_audit_obligations=1,
    )
    parent = daemon.prepare(_intent())

    with pytest.raises(AuthorityControlPlaneError, match="quota"):
        daemon.narrow(parent, operation="git.hash", resource_digest="scope")

    assert daemon.pending_count == 1
    daemon.validate(parent)


def test_slow_worm_does_not_hold_receipt_state_lock(tmp_path: Path) -> None:
    worm = _BlockingWorm()
    daemon = AuthorityDaemon(
        socket_path=tmp_path / "authorityd.sock",
        signing_key=Ed25519KeyStore.load_or_create(tmp_path / "key.pem", create=True),
        audit_writer=worm,
        issuer_id="test-authorityd",
        policy=lambda _intent: None,
    )
    errors: list[BaseException] = []

    def prepare() -> None:
        try:
            daemon.prepare(_intent())
        except BaseException as exc:  # noqa: BLE001 - test thread transports failures
            errors.append(exc)

    worker = threading.Thread(target=prepare)
    worker.start()
    assert worm.entered.wait(timeout=1)
    started = time.monotonic()
    assert daemon.pending_count == 1
    assert time.monotonic() - started < 0.5
    worm.release.set()
    worker.join(timeout=2)
    assert not worker.is_alive()
    assert errors == []


def test_incomplete_authorityd_connection_is_bounded(tmp_path: Path) -> None:
    daemon = AuthorityDaemon(
        socket_path=tmp_path / "authorityd.sock",
        signing_key=Ed25519KeyStore.load_or_create(tmp_path / "key.pem", create=True),
        audit_writer=_MemoryWorm(),
        issuer_id="test-authorityd",
        policy=lambda _intent: None,
    )
    client, server = socketpair()
    worker = threading.Thread(
        target=_serve_connection,
        args=(daemon, server, None, 0.05),
    )
    worker.start()
    try:
        response = client.recv(4096)
    finally:
        client.close()
        worker.join(timeout=1)
    assert not worker.is_alive()
    assert b'"ok":false' in response


def test_authorityd_socket_round_trip_accepts_versioned_intent_payload(
    tmp_path: Path,
) -> None:
    daemon = AuthorityDaemon(
        socket_path=tmp_path / "authorityd.sock",
        signing_key=Ed25519KeyStore.load_or_create(tmp_path / "key.pem", create=True),
        audit_writer=_MemoryWorm(),
        issuer_id="test-authorityd",
        policy=lambda _intent: None,
    )
    client, server = socketpair()
    worker = threading.Thread(
        target=_serve_connection,
        args=(daemon, server, None, 1.0),
    )
    worker.start()
    try:
        request = {
            "protocol": AUTHORITYD_PROTOCOL,
            "operation": "prepare",
            "intent": _intent().payload(),
        }
        client.sendall((json.dumps(request, separators=(",", ":")) + "\n").encode())
        response = json.loads(client.recv(4096).decode())
    finally:
        client.close()
        worker.join(timeout=1)
    assert not worker.is_alive()
    assert response["ok"] is True
    assert response["receipt"]["schema_version"] == 1


def test_authorityd_socket_receipt_wire_round_trip_supports_claim_and_complete(
    tmp_path: Path,
) -> None:
    """A receipt reconstructed from JSON must remain lifecycle-addressable."""
    daemon = AuthorityDaemon(
        socket_path=tmp_path / "authorityd.sock",
        signing_key=Ed25519KeyStore.load_or_create(tmp_path / "key.pem", create=True),
        audit_writer=_MemoryWorm(),
        issuer_id="test-authorityd",
        policy=lambda _intent: None,
    )
    prepared = _dispatch(
        daemon,
        {
            "protocol": AUTHORITYD_PROTOCOL,
            "operation": "prepare",
            "intent": _intent().payload(),
        },
    )
    wire_receipt = json.loads(json.dumps(prepared["receipt"]))

    claimed = _dispatch(
        daemon,
        {
            "protocol": AUTHORITYD_PROTOCOL,
            "operation": "claim",
            "receipt": wire_receipt,
        },
    )
    completed = _dispatch(
        daemon,
        {
            "protocol": AUTHORITYD_PROTOCOL,
            "operation": "complete",
            "receipt": wire_receipt,
            "result": "success",
            "result_digest": "wire-round-trip-result",
        },
    )

    assert claimed == {"ok": True}
    assert completed == {"ok": True}
    assert daemon.pending_count == 0


def test_authorization_intent_rejects_unknown_schema_version() -> None:
    with pytest.raises(AuthorityControlPlaneError, match="schema"):
        replace(_intent(), schema_version=2)


def test_production_daemon_requires_independent_audit_writer(tmp_path: Path) -> None:
    with pytest.raises(AuthorityControlPlaneError, match="independent.*audit"):
        build_production_daemon(
            socket_path=tmp_path / "authorityd.sock",
            key_path=tmp_path / "authorityd.pem",
            audit_writer=None,
        )


@pytest.mark.posix_host
def test_production_daemon_requires_its_compiled_policy_digest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    key_path = tmp_path / "authorityd.pem"
    Ed25519KeyStore.load_or_create(key_path, create=True)
    monkeypatch.delenv("KHAOS_EFFECTIVE_POLICY_DIGEST", raising=False)
    with pytest.raises(AuthorityControlPlaneError, match="EFFECTIVE_POLICY_DIGEST"):
        build_production_daemon(
            socket_path=tmp_path / "authorityd.sock",
            key_path=key_path,
            audit_writer=_MemoryWorm(),
        )
    monkeypatch.setenv("KHAOS_EFFECTIVE_POLICY_DIGEST", "policy-digest")
    daemon = build_production_daemon(
        socket_path=tmp_path / "authorityd.sock",
        key_path=key_path,
        audit_writer=_MemoryWorm(),
    )
    with pytest.raises(AuthorityControlPlaneError, match="compiled policy"):
        daemon.prepare(replace(_intent(), policy_digest="other-policy"))


@pytest.mark.posix_host
def test_production_daemon_requires_live_grant_and_same_operation_family(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    key_path = tmp_path / "authorityd.pem"
    Ed25519KeyStore.load_or_create(key_path, create=True)
    monkeypatch.setenv("KHAOS_EFFECTIVE_POLICY_DIGEST", "policy-digest")
    worm = _MemoryWorm()
    daemon = build_production_daemon(
        socket_path=tmp_path / "authorityd.sock",
        key_path=key_path,
        audit_writer=worm,
    )
    grant_id, _expires_at = daemon.grant(
        principal_id="agent",
        project_id="project",
        runtime_id="runtime",
        task_id="task",
        workspace_id="workspace",
        workspace_generation=1,
        policy_digest="policy-digest",
        operation_class="git.workspace",
        resource_digest="grant-resource",
        authorization_epoch=2,
    )
    context_digest = authorityd_module._digest(
        {
            "schema_version": 1,
            "principal_id": "agent",
            "project_id": "project",
            "runtime_id": "runtime",
            "task_id": "task",
            "workspace_id": "workspace",
            "workspace_generation": 1,
            "policy_digest": "policy-digest",
            "authorization_epoch": 2,
        }
    )
    intent = AuthorizationIntent(
        principal_id="agent",
        project_id="project",
        runtime_id="runtime",
        task_id="task",
        workspace_id="workspace",
        operation="git.hash",
        resource_digest="grant-resource",
        policy_digest="policy-digest",
        nonce="live-grant-nonce",
        authorization_epoch=2,
        workspace_generation=1,
        grant_id=grant_id,
        grant_context_digest=context_digest,
    )
    with pytest.raises(AuthorityControlPlaneError, match="resource"):
        daemon.prepare(replace(intent, resource_digest="unrelated-resource"))
    parent = daemon.prepare(intent)
    receipt = daemon.narrow(
        parent,
        operation="git.hash",
        resource_digest="child-resource",
    )
    daemon.complete(receipt, result="success", result_digest="result")

    with pytest.raises(AuthorityControlPlaneError, match="operation family"):
        daemon.prepare(replace(intent, operation="network.connect", nonce="cross-family"))

    daemon.revoke_grant(grant_id)
    with pytest.raises(AuthorityControlPlaneError, match="unknown|revoked"):
        daemon.prepare(replace(intent, nonce="revoked-grant"))


def test_expired_live_grant_is_terminally_audited_before_rejection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    clock = [100.0]
    monkeypatch.setattr(authorityd_module.time, "time", lambda: clock[0])
    worm = _MemoryWorm()
    daemon = AuthorityDaemon(
        socket_path=tmp_path / "authorityd.sock",
        signing_key=Ed25519KeyStore.load_or_create(tmp_path / "key.pem", create=True),
        audit_writer=worm,
        issuer_id="test-authorityd",
        policy=lambda _intent: None,
        require_live_grants=True,
    )
    grant_id, _expires_at = daemon.grant(
        principal_id="agent",
        project_id="project",
        runtime_id="runtime",
        task_id="task",
        workspace_id="workspace",
        workspace_generation=1,
        policy_digest="policy-digest",
        operation_class="git.workspace",
        resource_digest="grant-resource",
        authorization_epoch=2,
        ttl_seconds=1.0,
    )
    context_digest = authorityd_module._digest(
        {
            "schema_version": 1,
            "principal_id": "agent",
            "project_id": "project",
            "runtime_id": "runtime",
            "task_id": "task",
            "workspace_id": "workspace",
            "workspace_generation": 1,
            "policy_digest": "policy-digest",
            "authorization_epoch": 2,
        }
    )
    clock[0] = 102.0
    with pytest.raises(AuthorityControlPlaneError, match="expired"):
        daemon.prepare(
            replace(
                _intent(),
                nonce="expired-grant",
                policy_digest="policy-digest",
                grant_id=grant_id,
                grant_context_digest=context_digest,
            )
        )
    assert daemon.pending_count == 0
    assert daemon.audit_obligation_count == 0
    assert [record["kind"] for record in worm.records] == [
        "authority.grant",
        "authority.grant.expired",
    ]


def test_grant_revoke_invalidates_prepared_receipts_but_not_claimed_receipts(
    tmp_path: Path,
) -> None:
    worm = _MemoryWorm()
    daemon = AuthorityDaemon(
        socket_path=tmp_path / "authorityd.sock",
        signing_key=Ed25519KeyStore.load_or_create(tmp_path / "key.pem", create=True),
        audit_writer=worm,
        issuer_id="test-authorityd",
        policy=lambda _intent: None,
        require_live_grants=True,
    )

    def issue_grant(nonce: str) -> tuple[str, SignedAuthorizationReceipt]:
        grant_id, _ = daemon.grant(
            principal_id="agent",
            project_id="project",
            runtime_id="runtime",
            task_id="task",
            workspace_id="workspace",
            workspace_generation=1,
            policy_digest="policy-digest",
            operation_class="git.workspace",
            resource_digest="workspace-digest",
            authorization_epoch=2,
        )
        context_digest = authorityd_module._digest(
            {
                "schema_version": 1,
                "principal_id": "agent",
                "project_id": "project",
                "runtime_id": "runtime",
                "task_id": "task",
                "workspace_id": "workspace",
                "workspace_generation": 1,
                "policy_digest": "policy-digest",
                "authorization_epoch": 2,
            }
        )
        receipt = daemon.prepare(
            replace(
                _intent(),
                nonce=nonce,
                grant_id=grant_id,
                grant_context_digest=context_digest,
                workspace_generation=1,
            )
        )
        return grant_id, receipt

    grant_id, prepared = issue_grant("prepared-before-revoke")
    daemon.revoke_grant(grant_id)
    assert daemon.pending_count == 0
    assert daemon._terminal[prepared.nonce] == "revoked-by-grant"
    with pytest.raises(AuthorityControlPlaneError, match="revoked"):
        daemon.claim(prepared)

    claimed_grant, claimed = issue_grant("claimed-before-revoke")
    daemon.claim(claimed)
    daemon.revoke_grant(claimed_grant)
    daemon.complete(claimed, result="success", result_digest="claimed-result")
    assert daemon.pending_count == 0
    assert any(
        record["kind"] == "execution.revoked-by-grant"
        and record.get("receipt_nonce") == prepared.nonce
        for record in worm.records
    )


def test_epoch_rotation_invalidates_prepared_grant_receipts(
    tmp_path: Path,
) -> None:
    worm = _MemoryWorm()
    daemon = AuthorityDaemon(
        socket_path=tmp_path / "authorityd.sock",
        signing_key=Ed25519KeyStore.load_or_create(tmp_path / "key.pem", create=True),
        audit_writer=worm,
        issuer_id="test-authorityd",
        policy=lambda _intent: None,
        require_live_grants=True,
    )
    grant_id, _ = daemon.grant(
        principal_id="agent",
        project_id="project",
        runtime_id="runtime",
        task_id="task",
        workspace_id="workspace",
        workspace_generation=1,
        policy_digest="policy-digest",
        operation_class="git.workspace",
        resource_digest="workspace-digest",
        authorization_epoch=2,
    )
    context_digest = authorityd_module._digest(
        {
            "schema_version": 1,
            "principal_id": "agent",
            "project_id": "project",
            "runtime_id": "runtime",
            "task_id": "task",
            "workspace_id": "workspace",
            "workspace_generation": 1,
            "policy_digest": "policy-digest",
            "authorization_epoch": 2,
        }
    )
    receipt = daemon.prepare(
        replace(
            _intent(),
            nonce="epoch-rotated-before-claim",
            grant_id=grant_id,
            grant_context_digest=context_digest,
            workspace_generation=1,
        )
    )
    daemon.rotate_authorization_epoch(
        principal_id="agent",
        project_id="project",
        workspace_id="workspace",
        authorization_epoch=3,
    )
    with pytest.raises(AuthorityControlPlaneError, match="revoked"):
        daemon.claim(receipt)
    assert daemon._terminal[receipt.nonce] == "revoked-by-grant"


def test_workspace_generation_rotation_invalidates_prepared_grant_receipts(
    tmp_path: Path,
) -> None:
    worm = _MemoryWorm()
    daemon = AuthorityDaemon(
        socket_path=tmp_path / "authorityd.sock",
        signing_key=Ed25519KeyStore.load_or_create(tmp_path / "key.pem", create=True),
        audit_writer=worm,
        issuer_id="test-authorityd",
        policy=lambda _intent: None,
        require_live_grants=True,
    )
    grant_id, _ = daemon.grant(
        principal_id="agent",
        project_id="project",
        runtime_id="runtime",
        task_id="task",
        workspace_id="workspace",
        workspace_generation=1,
        policy_digest="policy-digest",
        operation_class="git.workspace",
        resource_digest="workspace-digest",
        authorization_epoch=2,
    )
    context_digest = authorityd_module._digest(
        {
            "schema_version": 1,
            "principal_id": "agent",
            "project_id": "project",
            "runtime_id": "runtime",
            "task_id": "task",
            "workspace_id": "workspace",
            "workspace_generation": 1,
            "policy_digest": "policy-digest",
            "authorization_epoch": 2,
        }
    )
    receipt = daemon.prepare(
        replace(
            _intent(),
            nonce="generation-rotated-before-claim",
            grant_id=grant_id,
            grant_context_digest=context_digest,
            workspace_generation=1,
        )
    )
    daemon.rotate_workspace_generation(
        principal_id="agent",
        project_id="project",
        workspace_id="workspace",
        workspace_generation=2,
    )
    with pytest.raises(AuthorityControlPlaneError, match="revoked"):
        daemon.claim(receipt)
    assert daemon._terminal[receipt.nonce] == "revoked-by-grant"
    assert any(
        record["kind"] == "authority.grant.revoked"
        and record.get("workspace_generation") == 2
        for record in worm.records
    )


def test_grant_expiry_invalidates_prepared_receipt_before_claim(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = [100.0]
    monkeypatch.setattr(authorityd_module.time, "time", lambda: clock[0])
    worm = _MemoryWorm()
    daemon = AuthorityDaemon(
        socket_path=tmp_path / "authorityd.sock",
        signing_key=Ed25519KeyStore.load_or_create(tmp_path / "key.pem", create=True),
        audit_writer=worm,
        issuer_id="test-authorityd",
        policy=lambda _intent: None,
        require_live_grants=True,
    )
    grant_id, _ = daemon.grant(
        principal_id="agent",
        project_id="project",
        runtime_id="runtime",
        task_id="task",
        workspace_id="workspace",
        workspace_generation=1,
        policy_digest="policy-digest",
        operation_class="git.workspace",
        resource_digest="workspace-digest",
        authorization_epoch=2,
        ttl_seconds=1.0,
    )
    context_digest = authorityd_module._digest(
        {
            "schema_version": 1,
            "principal_id": "agent",
            "project_id": "project",
            "runtime_id": "runtime",
            "task_id": "task",
            "workspace_id": "workspace",
            "workspace_generation": 1,
            "policy_digest": "policy-digest",
            "authorization_epoch": 2,
        }
    )
    receipt = daemon.prepare(
        replace(
            _intent(),
            nonce="expired-grant-prepared",
            grant_id=grant_id,
            grant_context_digest=context_digest,
            workspace_generation=1,
        )
    )
    clock[0] = 102.0
    with pytest.raises(AuthorityControlPlaneError, match="expired|revoked"):
        daemon.claim(receipt)
    assert daemon._terminal[receipt.nonce] in {"expired-grant", "revoked-by-grant"}
    assert any(
        record["kind"] == "execution.revoked-by-grant"
        and record.get("receipt_nonce") == receipt.nonce
        for record in worm.records
    )


def test_authority_policy_kernel_closes_unregistered_and_cross_family_narrowing() -> None:
    kernel = AuthorityPolicyKernel()
    intent = _intent()
    kernel(intent)
    with pytest.raises(AuthorityControlPlaneError):
        kernel(
            replace(intent, operation="admin.delete")
        )
    with pytest.raises(AuthorityControlPlaneError):
        kernel.check_narrow("git.workspace", "network.connect")


def test_authority_policy_kernel_binds_compiled_policy_digest() -> None:
    kernel = AuthorityPolicyKernel(expected_policy_digest="policy-digest")
    kernel(_intent())
    with pytest.raises(AuthorityControlPlaneError, match="compiled policy"):
        kernel(replace(_intent(), policy_digest="other-policy"))


def test_daemon_broker_uses_signed_receipts_and_reissues_narrowly(tmp_path: Path) -> None:
    key = Ed25519KeyStore.load_or_create(tmp_path / "authorityd.pem", create=True)
    daemon = AuthorityDaemon(
        socket_path=tmp_path / "authorityd.sock",
        signing_key=key,
        audit_writer=_MemoryWorm(),
        issuer_id="test-authorityd",
        policy=lambda _intent: None,
    )

    class _Client:
        def prepare(self, intent: AuthorizationIntent) -> SignedAuthorizationReceipt:
            return daemon.prepare(intent)

        def validate(self, receipt: SignedAuthorizationReceipt, **kwargs: object) -> None:
            daemon.validate(receipt, **kwargs)

        def narrow(self, receipt: SignedAuthorizationReceipt, **kwargs: str) -> SignedAuthorizationReceipt:
            return daemon.narrow(receipt, operation=kwargs["operation"], resource_digest=kwargs["resource_digest"])

        def revoke(self, receipt: SignedAuthorizationReceipt) -> None:
            daemon.revoke(receipt)

    broker = AuthorityDaemonBroker(_Client())  # type: ignore[arg-type]
    authority = broker.envelope(
        principal_id="agent",
        project_id="project",
        runtime_id="runtime",
        task_id="task",
        workspace_id="workspace",
        workspace_generation=1,
        policy_digest="policy",
        operation_class="git.workspace",
        resource_digest="resource",
    )
    capability = broker.issue(authority, allowed_operation="git.*")
    assert capability.receipt is not None
    assert capability.receipt.operation == "git.workspace"
    narrowed = capability.derive(
        operation_class="git.hash",
        resource_digest="resource-hash",
    )
    assert narrowed.receipt is not None
    assert narrowed.receipt.operation == "git.hash"
    assert narrowed.resource_digest == derive_resource_digest(
        "resource", "git.hash", "resource-hash"
    )
    broker.validate(narrowed, expected_operation="git.hash")
    with pytest.raises(AuthorityBrokerError):
        broker.validate(narrowed, expected_operation="git.update-ref")


@pytest.mark.asyncio
async def test_network_broker_close_consumes_parent_and_child_authority(
    tmp_path: Path,
) -> None:
    daemon = AuthorityDaemon(
        socket_path=tmp_path / "authorityd.sock",
        signing_key=Ed25519KeyStore.load_or_create(tmp_path / "key.pem", create=True),
        audit_writer=_MemoryWorm(),
        issuer_id="test-authorityd",
        policy=lambda _intent: None,
    )

    class _Client:
        def grant(self, **kwargs: object) -> tuple[str, float]:
            return daemon.grant(**kwargs)  # type: ignore[arg-type]

        def revoke_grant(self, grant_id: str) -> None:
            daemon.revoke_grant(grant_id)

        def prepare(self, intent: AuthorizationIntent) -> SignedAuthorizationReceipt:
            return daemon.prepare(intent)

        def validate(self, receipt: SignedAuthorizationReceipt, **kwargs: object) -> None:
            daemon.validate(receipt, **kwargs)

        def narrow(
            self, receipt: SignedAuthorizationReceipt, **kwargs: str
        ) -> SignedAuthorizationReceipt:
            return daemon.narrow(
                receipt,
                operation=kwargs["operation"],
                resource_digest=kwargs["resource_digest"],
            )

        def revoke(self, receipt: SignedAuthorizationReceipt) -> None:
            daemon.revoke(receipt)

        def complete(
            self,
            receipt: SignedAuthorizationReceipt,
            *,
            result: str,
            result_digest: str,
        ) -> None:
            daemon.complete(receipt, result=result, result_digest=result_digest)

    authority_broker = AuthorityDaemonBroker(_Client())  # type: ignore[arg-type]
    authority = authority_broker.envelope(
        principal_id="agent",
        project_id="project",
        runtime_id="runtime",
        task_id="network-task",
        workspace_id="workspace",
        workspace_generation=1,
        policy_digest="policy",
        operation_class="network.connect",
        resource_digest="network-parent",
    )
    capability = authority_broker.issue(authority, allowed_operation="network.*")
    network = NetworkBroker(
        capability,
        authority_broker=authority_broker,
        allowed_domains=frozenset({"example.com"}),
    )

    try:
        await network.start()
    except NetworkBrokerError as exc:
        if "operation not permitted" in str(exc).lower():
            await network.close()
            pytest.skip("sandbox forbids loopback bind; rerun with host network permission")
        raise
    assert daemon.pending_count == 1
    await network.close()

    assert network.terminal_closed
    assert network.owned_resources() == ()
    assert daemon.pending_count == 0


def test_narrow_consumes_parent_and_keeps_pending_quota_bounded(
    tmp_path: Path,
) -> None:
    daemon = AuthorityDaemon(
        socket_path=tmp_path / "authorityd.sock",
        signing_key=Ed25519KeyStore.load_or_create(tmp_path / "key.pem", create=True),
        audit_writer=_MemoryWorm(),
        issuer_id="test-authorityd",
        policy=lambda _intent: None,
        max_pending_receipts=2,
        max_pending_per_principal=2,
    )
    for index in range(1000):
        parent = daemon.prepare(replace(_intent(), nonce=f"parent-{index}"))
        child = daemon.narrow(
            parent,
            operation="git.hash",
            resource_digest=f"scope-{index}",
        )
        daemon.complete(child, result="success", result_digest=f"result-{index}")
        assert daemon.pending_count == 0
        with pytest.raises(AuthorityControlPlaneError, match="narrowed"):
            daemon.validate(parent)
        # NetworkBroker.close() may retry the consumed parent; that cleanup
        # is an idempotent no-op, never a false live-parent error.
        daemon.revoke(parent)


def test_narrow_terminalizes_parent_when_worm_append_is_uncertain(
    tmp_path: Path,
) -> None:
    worm = _SelectiveWorm("execution.narrowed")
    daemon = AuthorityDaemon(
        socket_path=tmp_path / "authorityd.sock",
        signing_key=Ed25519KeyStore.load_or_create(tmp_path / "key.pem", create=True),
        audit_writer=worm,
        issuer_id="test-authorityd",
        policy=lambda _intent: None,
    )
    parent = daemon.prepare(_intent())
    child = daemon.narrow(
        parent,
        operation="git.hash",
        resource_digest="hash-scope",
    )
    assert daemon.pending_count == 1
    assert daemon.audit_obligation_count == 1
    with pytest.raises(AuthorityControlPlaneError, match="narrowed"):
        daemon.validate(parent)

    worm.fail = False
    assert daemon.reconcile_audit_obligations() == 0
    daemon.complete(child, result="success", result_digest="result")
    assert daemon.pending_count == 0
    assert any(record["kind"] == "execution.narrowed" for record in worm.records)


def test_narrow_child_prepare_failure_rolls_parent_back_without_narrowing_state(
    tmp_path: Path,
) -> None:
    worm = _SelectiveWorm("execution.prepare")
    daemon = AuthorityDaemon(
        socket_path=tmp_path / "authorityd.sock",
        signing_key=Ed25519KeyStore.load_or_create(tmp_path / "key.pem", create=True),
        audit_writer=worm,
        issuer_id="test-authorityd",
        policy=lambda _intent: None,
    )
    worm.fail = False
    parent = daemon.prepare(_intent())
    worm.fail = True
    with pytest.raises(RemoteAuditUnavailableError):
        daemon.narrow(parent, operation="git.hash", resource_digest="scope")
    assert daemon.pending_count == 1
    daemon.validate(parent)
    assert daemon._states[parent.nonce].state == "prepared"

    worm.fail = False
    assert daemon.reconcile_audit_obligations() == 0


@pytest.mark.posix_host
def test_native_launcher_receives_only_verified_receipt_fds(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    key = Ed25519KeyStore.load_or_create(tmp_path / "authorityd.pem", create=True)
    public_key_path = tmp_path / "authorityd.pub"
    public_key_path.write_bytes(key.public_key().public_bytes_raw())
    public_key_path.chmod(0o600)
    worm = _MemoryWorm()
    daemon = AuthorityDaemon(
        socket_path=tmp_path / "authorityd.sock",
        signing_key=key,
        audit_writer=worm,
        issuer_id="test-authorityd",
        policy=lambda _intent: None,
    )

    class _Client:
        def prepare(self, intent: AuthorizationIntent) -> SignedAuthorizationReceipt:
            return daemon.prepare(intent)

        def validate(self, receipt: SignedAuthorizationReceipt, **kwargs: object) -> None:
            daemon.validate(receipt, **kwargs)

        def narrow(
            self, receipt: SignedAuthorizationReceipt, **kwargs: str
        ) -> SignedAuthorizationReceipt:
            return daemon.narrow(
                receipt,
                operation=kwargs["operation"],
                resource_digest=kwargs["resource_digest"],
            )

        def revoke(self, receipt: SignedAuthorizationReceipt) -> None:
            daemon.revoke(receipt)

        def complete(
            self,
            receipt: SignedAuthorizationReceipt,
            *,
            result: str,
            result_digest: str,
        ) -> None:
            daemon.complete(receipt, result=result, result_digest=result_digest)

    broker = AuthorityDaemonBroker(_Client())  # type: ignore[arg-type]
    command = (sys.executable, "-c", "print('receipt-ok')")
    environment = {
        "PATH": "/usr/bin:/bin",
        "PYTHONPATH": str(Path(__file__).resolve().parents[3] / "python"),
    }
    executable_authority = open_executable_authority(
        command,
        environment,
        expected_identity=executable_identity(command, environment),
    )
    resource_digest = execution_binding_digest(
        command,
        directory_binding=None,
        budget=None,
        enforce_resource_limits=False,
        preserve_directory_fds=False,
        environment=environment,
        executable_authority=executable_authority,
    )
    authority = broker.envelope(
        principal_id="agent",
        project_id="project",
        runtime_id="runtime",
        task_id="task",
        workspace_id="workspace",
        workspace_generation=1,
        policy_digest="policy",
        operation_class="exec.host",
        resource_digest=resource_digest,
    )
    capability = broker.issue(authority, allowed_operation="exec.*")
    monkeypatch.setenv("KHAOS_DEV_MODE", "1")
    monkeypatch.setattr(
        "khaos.coding.execution.native_launcher._find_launcher", lambda: None
    )
    launch = build_process_launch(
        command,
        cwd=tmp_path,
        directory_binding=None,
        budget=ResourceBudget(),
        enforce_resource_limits=False,
        environment=environment,
        expected_identity=executable_identity(command, environment),
        executable_authority=executable_authority,
        authority_capability=capability,
        authority_public_key_path=public_key_path,
    )
    try:
        completed = subprocess.run(
            launch.argv,
            cwd=launch.cwd,
            env=environment,
            pass_fds=launch.pass_fds,
            capture_output=True,
            text=True,
            check=False,
        )
    finally:
        launch.close_owned_fds()
    assert completed.returncode == 0, completed.stderr
    assert completed.stdout.strip() == "receipt-ok"

    changed_command = (sys.executable, "-c", "print('receipt-changed')")
    changed_authority = open_executable_authority(
        changed_command,
        environment,
        expected_identity=executable_identity(changed_command, environment),
    )
    with pytest.raises(PermissionError, match="exact launch"):
        build_process_launch(
            changed_command,
            cwd=tmp_path,
            directory_binding=None,
            budget=ResourceBudget(),
            enforce_resource_limits=False,
            environment=environment,
            expected_identity=executable_identity(changed_command, environment),
            executable_authority=changed_authority,
            authority_capability=capability,
            authority_public_key_path=public_key_path,
        )
    broker.complete(capability, result="success", result_digest="result")
