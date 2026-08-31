"""Authorityd receipt, independent-audit, and production fail-closed tests."""

from __future__ import annotations

import hashlib
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
from cryptography.hazmat.primitives import serialization
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
from khaos.security.authority_context import AuthorityContextV1
from khaos.security.authorityd import (
    AuthorityDaemon,
    AuthorityPolicyKernel,
    _dispatch,
    _serve_connection,
    build_local_daemon,
    build_production_daemon,
)
from khaos.security.authorityd_protocol import (
    AUTHORITYD_PROTOCOL,
    MAX_MESSAGE_BYTES,
    AuthorityControlPlaneError,
    AuthorizationIntent,
    Ed25519KeyStore,
    RemoteAuditUnavailableError,
    SignedAuthorizationReceipt,
    derive_resource_digest,
)
from khaos.security.local_trust import ensure_local_authority_root
from khaos.security.network_broker import NetworkBroker, NetworkBrokerError
from khaos.security.principals import transport_root_delegation_digest
from khaos.security.production_trust import (
    ProductionTrustBinding,
    public_key_fingerprint,
)
from khaos.security.protocol_boundary import canonical_json_bytes
from khaos.security.resource_scope import GitRefScope, TypedResourcePartialOrder

TEST_POLICY_DIGEST = "a" * 64

# Canonical transport-root commitment for the standard typed-principal test
# context: grants must recompute and match exactly this (an arbitrary
# 64-hex string is no longer an acceptable delegation provenance).
_TEST_TRANSPORT_DELEGATION = transport_root_delegation_digest(
    principal_id="agent",
    principal_kind="human",
    parent_principal_id="human:agent",
    project_id="project",
    session_id="session",
    runtime_id="runtime",
    source_transport="pytest",
    policy_digest=TEST_POLICY_DIGEST,
)


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


def _typed_git_order(
    policy_digest: str = TEST_POLICY_DIGEST,
) -> tuple[TypedResourcePartialOrder, GitRefScope, GitRefScope]:
    parent = GitRefScope(
        repository="khaos",
        refs=frozenset({"HEAD"}),
        operations=frozenset({"hash", "workspace"}),
    )
    child = GitRefScope(
        repository="khaos",
        refs=frozenset({"HEAD"}),
        operations=frozenset({"hash"}),
    )
    return (
        TypedResourcePartialOrder(
            {parent.digest(): parent, child.digest(): child},
            policy_digest=policy_digest,
        ),
        parent,
        child,
    )


def _intent() -> AuthorizationIntent:
    return AuthorizationIntent(
        principal_id="agent",
        project_id="project",
        runtime_id="runtime",
        task_id="task",
        workspace_id="workspace",
        operation="git.workspace",
        resource_digest="workspace-digest",
        policy_digest=TEST_POLICY_DIGEST,
        nonce="nonce-1",
        authorization_epoch=2,
    )


def _authority_context_digest(
    *,
    principal_kind: str = "",
    parent_principal_id: str = "",
    session_id: str = "",
    delegation_digest: str = "",
    source_transport: str = "",
) -> str:
    """Build the same canonical owner binding that ``AuthorityDaemon.grant`` stores."""
    return AuthorityContextV1(
        principal_id="agent",
        principal_kind=principal_kind,
        parent_principal_id=parent_principal_id,
        project_id="project",
        session_id=session_id,
        runtime_id="runtime",
        source_transport=source_transport,
        task_id="task",
        workspace_id="workspace",
        workspace_generation=1,
        policy_digest=TEST_POLICY_DIGEST,
        authorization_epoch=2,
        delegation_digest=delegation_digest,
    ).digest()


def _live_grant_parent(
    daemon: AuthorityDaemon,
    *,
    grant_ttl_seconds: float = 900.0,
    nonce: str = "narrow-race-parent",
) -> tuple[str, SignedAuthorizationReceipt]:
    """Issue one live grant and a prepared parent for narrow race tests."""
    grant_id, _expires_at = daemon.grant(
        principal_id="agent",
        project_id="project",
        runtime_id="runtime",
        task_id="task",
        workspace_id="workspace",
        workspace_generation=1,
        policy_digest=TEST_POLICY_DIGEST,
        operation_class="git.workspace",
        resource_digest="workspace-digest",
        authorization_epoch=2,
        ttl_seconds=grant_ttl_seconds,
    )
    context_digest = _authority_context_digest()
    parent = daemon.prepare(
        replace(
            _intent(),
            nonce=nonce,
            grant_id=grant_id,
            grant_context_digest=context_digest,
            workspace_generation=1,
        )
    )
    return grant_id, parent


def _start_gated_narrow(
    daemon: AuthorityDaemon,
    parent: SignedAuthorizationReceipt,
    *,
    block_phase: str,
) -> tuple[threading.Thread, threading.Event, dict[str, BaseException | object]]:
    """Pause child preparation either before or after it enters authorityd."""
    entered = threading.Event()
    release = threading.Event()
    outcome: dict[str, BaseException | object] = {}
    original_prepare = daemon.prepare

    def gated_prepare(
        intent: AuthorizationIntent,
        **kwargs: object,
    ) -> SignedAuthorizationReceipt:
        if kwargs.get("_parent_receipt") is None:
            return original_prepare(intent, **kwargs)  # type: ignore[arg-type]
        if block_phase == "before-child":
            entered.set()
            assert release.wait(timeout=2)
            return original_prepare(intent, **kwargs)  # type: ignore[arg-type]
        child = original_prepare(intent, **kwargs)  # type: ignore[arg-type]
        entered.set()
        assert release.wait(timeout=2)
        return child

    daemon.prepare = gated_prepare  # type: ignore[method-assign]

    def run() -> None:
        try:
            outcome["child"] = daemon.narrow(
                parent,
                operation="git.hash",
                resource_digest="narrow-race-scope",
            )
        except BaseException as exc:  # noqa: BLE001 - test captures the boundary
            outcome["error"] = exc

    thread = threading.Thread(target=run)
    thread.start()
    assert entered.wait(timeout=2)
    return thread, release, outcome


def test_public_key_load_is_binary_safe(tmp_path: Path) -> None:
    """A raw Ed25519 public key containing 0x1A / CRLF must load verbatim.

    Windows ``os.open`` without ``O_BINARY`` opens descriptors in CRT text
    mode: 0x1A acts as EOF and CRLF pairs collapse, so ~12% of randomly
    generated 32-byte keys were truncated and rejected as "malformed" (the
    2026-08-19 Windows Product Suite flakes).  POSIX has no text mode, so the
    deterministic repro payload below only distinguishes fixed from broken on
    Windows — where it failed before the ``_O_BINARY`` fix.
    """
    payload = b"\x00\x1a\r\n" + bytes(range(4, 32))
    assert len(payload) == 32 and b"\x1a" in payload and b"\r\n" in payload
    path = tmp_path / "authorityd.pub"
    path.write_bytes(payload)
    key = Ed25519KeyStore.load_public_key(path)
    assert (
        key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        == payload
    )


def test_native_business_rejection_preserves_ready_trust_channel(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    key = Ed25519KeyStore.load_or_create(tmp_path / "authorityd.pem", create=True)
    public_key_path = tmp_path / "authorityd.pub"
    public_key_path.write_bytes(key.public_key().public_bytes_raw())
    binding = ProductionTrustBinding.create(
        protocol_version=AUTHORITYD_PROTOCOL,
        authority_id="test-authorityd",
        policy_digest=TEST_POLICY_DIGEST,
        catalog_digest="b" * 64,
        public_key_fingerprint=public_key_fingerprint(
            key.public_key().public_bytes_raw()
        ),
        environment_digest="c" * 64,
    )

    class FakeNativeAdapter:
        def request(self, payload: dict[str, object]) -> dict[str, object]:
            if payload["operation"] == "handshake":
                return {
                    "ok": True,
                    "ready": "READY",
                    "issuer_id": binding.authority_id,
                    "channel_nonce": "d" * 64,
                    "runtime_identity": payload["runtime_identity"],
                    "trust_binding": binding.to_payload(),
                }
            return {"ok": False, "error": "authority grant is revoked"}

    # This test uses an in-process adapter to isolate the protocol state
    # machine.  The deployed Windows ACL trust-anchor contract is covered by
    # the native production E2E, so retain the real key reader but omit only
    # its deployment ACL check for this pytest temp file.  The assertion below
    # still proves that production requests that check.
    original_load_public_key = authorityd_protocol_module.Ed25519KeyStore.load_public_key

    def load_test_public_key(
        path: Path, *, require_windows_acl: bool = False
    ):
        assert path == public_key_path
        assert require_windows_acl is True
        return original_load_public_key(path, require_windows_acl=False)

    monkeypatch.setattr(
        authorityd_protocol_module.Ed25519KeyStore,
        "load_public_key",
        staticmethod(load_test_public_key),
    )
    client = authorityd_protocol_module.AuthorityDaemonClient(
        transport="native",
        native_adapter=FakeNativeAdapter(),
        runtime_profile="production",
        public_key_path=public_key_path,
        trust_binding=binding,
    )
    client.handshake(
        runtime_id="runtime",
        principal_id="agent",
        project_id="project",
        principal_kind="human",
    )

    with pytest.raises(AuthorityControlPlaneError, match="grant is revoked"):
        client.request({"operation": "prepare"})
    assert client.ready


def test_native_attestation_keeps_business_rejection_inside_signed_envelope(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    key = Ed25519KeyStore.load_or_create(tmp_path / "authorityd.pem", create=True)
    daemon = AuthorityDaemon(
        socket_path=tmp_path / "authorityd.sock",
        signing_key=key,
        audit_writer=_MemoryWorm(),
        issuer_id="test-authorityd",
        policy=lambda _intent: None,
    )

    def reject_dispatch(*_args: object, **_kwargs: object) -> dict[str, object]:
        raise AuthorityControlPlaneError("authority grant is revoked")

    monkeypatch.setattr(authorityd_module, "_dispatch", reject_dispatch)
    raw_request = canonical_json_bytes(
        {"protocol": AUTHORITYD_PROTOCOL, "operation": "ping"}
    )
    response = daemon.attest(
        proof_fields={
            "platform": "win32",
            "transport": "named-pipe",
            "service_id": "KhaosAuthorityD",
            "service_pid": "1",
            "service_identity": "S-1-5-18",
            "peer_identity": "S-1-5-21-test",
            "peer_team_id": "S-1-5-21-test",
            "peer_cdhash": "",
            "designated_requirement_digest": "a" * 64,
            "service_instance_id": "b" * 32,
            "protected_key_ref": "test-key",
        },
        challenge_nonce="c" * 64,
        request_raw_hex=raw_request.hex(),
        request_digest=hashlib.sha256(raw_request).hexdigest(),
    )

    assert response["ok"] is True
    assert response["response"] == {
        "ok": False,
        "error": "authority grant is revoked",
    }
    assert isinstance(response["attestation"], dict)


@pytest.mark.posix_host
def test_community_client_verifies_receipts_against_local_trust_anchor(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "home" / ".khaos" / "authorityd"
    root.parent.parent.mkdir()
    ensure_local_authority_root(root)
    monkeypatch.setattr(
        authorityd_protocol_module, "local_authority_root", lambda: root
    )
    key_path = root / "authorityd.pem"
    public_key_path = root / "authorityd.pub"
    key = Ed25519KeyStore.load_or_create(key_path, create=True)
    public_key_path.write_bytes(
        key.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
    )
    daemon = AuthorityDaemon(
        socket_path=root / "authorityd.sock",
        signing_key=key,
        audit_writer=_MemoryWorm(),
        issuer_id="test-community-authorityd",
        policy=lambda _intent: None,
    )
    receipt = daemon.prepare(_intent())
    client = authorityd_protocol_module.AuthorityDaemonClient(
        root / "authorityd.sock",
        public_key_path=public_key_path,
        trusted_local_root=root,
        transport="unix",
        community_local=True,
    )

    assert client._verify_receipt(receipt.to_dict()).signature == receipt.signature
    with pytest.raises(
        AuthorityControlPlaneError,
        match="trusted local authority key",
    ):
        client._verify_receipt(replace(receipt, operation="network.connect").to_dict())


def test_typed_kernel_keeps_native_execution_binding_exact() -> None:
    order, _parent_scope, _child_scope = _typed_git_order()
    kernel = AuthorityPolicyKernel(
        expected_policy_digest=TEST_POLICY_DIGEST,
        resource_order=order,
    )
    binding = "a" * 64
    kernel.check_prepare(
        replace(
            _intent(),
            operation="exec.host",
            resource_digest=binding,
        )
    )
    kernel.check_narrow(
        "exec.host",
        "exec.host",
        parent_resource_digest=binding,
        requested_resource_scope=binding,
    )
    with pytest.raises(AuthorityControlPlaneError, match="exact launch binding"):
        kernel.check_prepare(
            replace(
                _intent(),
                operation="exec.host",
                resource_digest="not-a-binding",
            )
        )
    with pytest.raises(AuthorityControlPlaneError, match="cannot change"):
        kernel.check_narrow(
            "exec.host",
            "exec.host",
            parent_resource_digest=binding,
            requested_resource_scope="b" * 64,
        )
    with pytest.raises(AuthorityControlPlaneError, match="not in the typed catalog"):
        kernel.check_prepare(
            replace(
                _intent(),
                operation="exec.shell",
                resource_digest=binding,
            )
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


def test_claim_is_one_shot_and_a_second_claim_is_rejected(tmp_path: Path) -> None:
    daemon = AuthorityDaemon(
        socket_path=tmp_path / "authorityd.sock",
        signing_key=Ed25519KeyStore.load_or_create(tmp_path / "key.pem", create=True),
        audit_writer=_MemoryWorm(),
        issuer_id="test-authorityd",
        policy=lambda _intent: None,
    )
    receipt = daemon.prepare(_intent())

    daemon.claim(receipt)
    with pytest.raises(AuthorityControlPlaneError, match="not claimable"):
        daemon.claim(receipt)


def test_tampered_receipt_is_rejected_at_the_daemon_boundary(tmp_path: Path) -> None:
    daemon = AuthorityDaemon(
        socket_path=tmp_path / "authorityd.sock",
        signing_key=Ed25519KeyStore.load_or_create(tmp_path / "key.pem", create=True),
        audit_writer=_MemoryWorm(),
        issuer_id="test-authorityd",
        policy=lambda _intent: None,
    )
    receipt = daemon.prepare(_intent())
    tampered = replace(receipt, operation="network.connect")

    with pytest.raises(AuthorityControlPlaneError, match="unknown or revoked"):
        daemon.claim(tampered)
    assert daemon.pending_count == 1


def test_unknown_grant_revoke_is_not_reported_as_success(tmp_path: Path) -> None:
    daemon = AuthorityDaemon(
        socket_path=tmp_path / "authorityd.sock",
        signing_key=Ed25519KeyStore.load_or_create(tmp_path / "key.pem", create=True),
        audit_writer=_MemoryWorm(),
        issuer_id="test-authorityd",
        policy=lambda _intent: None,
        require_live_grants=True,
    )

    with pytest.raises(AuthorityControlPlaneError, match="grant is unknown"):
        daemon.revoke_grant("missing-grant")

    grant_id, _parent = _live_grant_parent(daemon, nonce="revoke-idempotency-parent")
    daemon.revoke_grant(grant_id)
    # A tombstoned grant is intentionally idempotent for retrying callers.
    daemon.revoke_grant(grant_id)


@pytest.mark.parametrize(
    "payload",
    [
        None,
        {"protocol": 99, "operation": "ping"},
        {"protocol": AUTHORITYD_PROTOCOL, "operation": "unknown"},
        {
            "protocol": AUTHORITYD_PROTOCOL,
            "operation": "prepare",
            "intent": [],
        },
        {
            "protocol": AUTHORITYD_PROTOCOL,
            "operation": "claim",
            "receipt": "not-a-mapping",
        },
        {
            "protocol": AUTHORITYD_PROTOCOL,
            "operation": "attest",
            "proof_fields": [],
            "challenge_nonce": "x",
            "request_raw_hex": "00",
            "request_digest": "0" * 64,
        },
    ],
)
def test_malformed_authority_requests_fail_closed(
    tmp_path: Path, payload: object
) -> None:
    daemon = AuthorityDaemon(
        socket_path=tmp_path / "authorityd.sock",
        signing_key=Ed25519KeyStore.load_or_create(tmp_path / "key.pem", create=True),
        audit_writer=_MemoryWorm(),
        issuer_id="test-authorityd",
        policy=lambda _intent: None,
    )

    with pytest.raises(AuthorityControlPlaneError):
        _dispatch(daemon, payload)


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


def test_transport_root_provenance_is_not_consumed_as_child_delegation(
    tmp_path: Path,
) -> None:
    """A transport identity commitment must remain usable at the claim edge."""
    daemon = AuthorityDaemon(
        socket_path=tmp_path / "authorityd.sock",
        signing_key=Ed25519KeyStore.load_or_create(tmp_path / "key.pem", create=True),
        audit_writer=_MemoryWorm(),
        issuer_id="test-authorityd",
        policy=lambda _intent: None,
    )
    grant_id, _ = daemon.grant(
        principal_id="agent",
        project_id="project",
        runtime_id="runtime",
        task_id="task",
        workspace_id="workspace",
        workspace_generation=1,
        policy_digest=TEST_POLICY_DIGEST,
        operation_class="git.workspace",
        resource_digest="workspace-digest",
        authorization_epoch=2,
        principal_kind="human",
        parent_principal_id="human:agent",
        session_id="session",
        delegation_digest=_TEST_TRANSPORT_DELEGATION,
        source_transport="pytest",
        delegation_resource="git.workspace",
    )
    receipt = daemon.prepare(
        replace(
            _intent(),
            grant_id=grant_id,
            grant_context_digest=_authority_context_digest(
                principal_kind="human",
                parent_principal_id="human:agent",
                session_id="session",
                delegation_digest=_TEST_TRANSPORT_DELEGATION,
                source_transport="pytest",
            ),
            principal_kind="human",
            parent_principal_id="human:agent",
            session_id="session",
            delegation_digest=_TEST_TRANSPORT_DELEGATION,
            source_transport="pytest",
            delegation_resource="git.workspace",
            workspace_generation=1,
        )
    )
    daemon.claim(receipt)


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


@pytest.mark.parametrize(
    "frame",
    [
        b"\xff\n",
        b"x" * MAX_MESSAGE_BYTES,
    ],
    ids=["invalid-utf8", "oversized-frame"],
)
def test_authorityd_connection_rejects_malformed_frames(
    tmp_path: Path, frame: bytes
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
        client.sendall(frame)
        response = json.loads(client.recv(4096).decode("utf-8"))
    finally:
        client.close()
        worker.join(timeout=1)
    assert not worker.is_alive()
    assert response["ok"] is False


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
def test_community_daemon_keeps_policy_boundary_without_remote_worm(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    key_path = tmp_path / "authorityd.pem"
    Ed25519KeyStore.load_or_create(key_path, create=True)
    monkeypatch.setenv("KHAOS_EFFECTIVE_POLICY_DIGEST", TEST_POLICY_DIGEST)
    resource_order, _parent_scope, _child_scope = _typed_git_order()

    daemon = build_local_daemon(
        socket_path=tmp_path / "authorityd.sock",
        key_path=key_path,
        audit_writer=_MemoryWorm(),
        resource_order=resource_order,
    )

    assert daemon.issuer_id == "khaos-authorityd-community"


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
    monkeypatch.setenv("KHAOS_EFFECTIVE_POLICY_DIGEST", TEST_POLICY_DIGEST)
    resource_order, _parent_scope, _child_scope = _typed_git_order()
    daemon = build_production_daemon(
        socket_path=tmp_path / "authorityd.sock",
        key_path=key_path,
        audit_writer=_MemoryWorm(),
        resource_order=resource_order,
    )
    with pytest.raises(AuthorityControlPlaneError, match="compiled policy"):
        daemon.prepare(replace(_intent(), policy_digest="other-policy"))


@pytest.mark.posix_host
def test_authorityd_builders_reject_symbolic_trust_material(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    key_path = tmp_path / "authorityd.pem"
    Ed25519KeyStore.load_or_create(key_path, create=True)
    monkeypatch.setenv("KHAOS_EFFECTIVE_POLICY_DIGEST", "policy-digest")
    resource_order, _parent_scope, _child_scope = _typed_git_order("policy-digest")

    with pytest.raises(AuthorityControlPlaneError, match="canonical SHA-256"):
        build_local_daemon(
            socket_path=tmp_path / "community.sock",
            key_path=key_path,
            audit_writer=_MemoryWorm(),
            resource_order=resource_order,
        )
    with pytest.raises(AuthorityControlPlaneError, match="canonical SHA-256"):
        build_production_daemon(
            socket_path=tmp_path / "production.sock",
            key_path=key_path,
            audit_writer=_MemoryWorm(),
            resource_order=resource_order,
        )


@pytest.mark.posix_host
def test_production_daemon_requires_live_grant_and_same_operation_family(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    key_path = tmp_path / "authorityd.pem"
    Ed25519KeyStore.load_or_create(key_path, create=True)
    monkeypatch.setenv("KHAOS_EFFECTIVE_POLICY_DIGEST", TEST_POLICY_DIGEST)
    worm = _MemoryWorm()
    resource_order, parent_scope, child_scope = _typed_git_order()
    daemon = build_production_daemon(
        socket_path=tmp_path / "authorityd.sock",
        key_path=key_path,
        audit_writer=worm,
        resource_order=resource_order,
    )
    grant_id, _expires_at = daemon.grant(
        principal_id="agent",
        project_id="project",
        runtime_id="runtime",
        task_id="task",
        workspace_id="workspace",
        workspace_generation=1,
        policy_digest=TEST_POLICY_DIGEST,
        operation_class="git.workspace",
        resource_digest=parent_scope.digest(),
        authorization_epoch=2,
        principal_kind="human",
        parent_principal_id="human:agent",
        session_id="session",
        delegation_digest=_TEST_TRANSPORT_DELEGATION,
        source_transport="pytest",
    )
    context_digest = _authority_context_digest(
        principal_kind="human",
        parent_principal_id="human:agent",
        session_id="session",
        delegation_digest=_TEST_TRANSPORT_DELEGATION,
        source_transport="pytest",
    )
    intent = AuthorizationIntent(
        principal_id="agent",
        project_id="project",
        runtime_id="runtime",
        task_id="task",
        workspace_id="workspace",
        operation="git.hash",
        resource_digest=parent_scope.digest(),
        policy_digest=TEST_POLICY_DIGEST,
        nonce="live-grant-nonce",
        authorization_epoch=2,
        workspace_generation=1,
        grant_id=grant_id,
        grant_context_digest=context_digest,
        principal_kind="human",
        parent_principal_id="human:agent",
        session_id="session",
        delegation_digest=_TEST_TRANSPORT_DELEGATION,
        source_transport="pytest",
    )
    with pytest.raises(AuthorityControlPlaneError, match="resource"):
        daemon.prepare(replace(intent, resource_digest="unrelated-resource"))
    parent = daemon.prepare(intent)
    receipt = daemon.narrow(
        parent,
        operation="git.hash",
        resource_digest=child_scope.digest(),
    )
    daemon.complete(receipt, result="success", result_digest="result")

    with pytest.raises(AuthorityControlPlaneError, match="operation family"):
        daemon.prepare(replace(intent, operation="network.connect", nonce="cross-family"))

    daemon.revoke_grant(grant_id)
    with pytest.raises(AuthorityControlPlaneError, match="unknown|revoked"):
        daemon.prepare(replace(intent, nonce="revoked-grant"))


@pytest.mark.posix_host
def test_expired_typed_child_receipt_renews_only_issued_action_and_scope(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    clock = [100.0]
    monkeypatch.setattr(authorityd_module.time, "time", lambda: clock[0])
    monkeypatch.setattr(authorityd_protocol_module.time, "time", lambda: clock[0])
    key_path = tmp_path / "authorityd.pem"
    Ed25519KeyStore.load_or_create(key_path, create=True)
    monkeypatch.setenv("KHAOS_EFFECTIVE_POLICY_DIGEST", TEST_POLICY_DIGEST)
    resource_order, parent_scope, child_scope = _typed_git_order()
    unrelated_scope = GitRefScope(
        repository="other-repository",
        refs=frozenset({"HEAD"}),
        operations=frozenset({"hash"}),
    )
    resource_order = TypedResourcePartialOrder(
        {
            parent_scope.digest(): parent_scope,
            child_scope.digest(): child_scope,
            unrelated_scope.digest(): unrelated_scope,
        },
        policy_digest=TEST_POLICY_DIGEST,
    )
    daemon = build_production_daemon(
        socket_path=tmp_path / "authorityd.sock",
        key_path=key_path,
        audit_writer=_MemoryWorm(),
        resource_order=resource_order,
    )
    grant_id, _expires_at = daemon.grant(
        principal_id="agent",
        project_id="project",
        runtime_id="runtime",
        task_id="task",
        workspace_id="workspace",
        workspace_generation=1,
        policy_digest=TEST_POLICY_DIGEST,
        operation_class="git.workspace",
        resource_digest=parent_scope.digest(),
        authorization_epoch=2,
        ttl_seconds=900.0,
        principal_kind="human",
        parent_principal_id="human:agent",
        session_id="session",
        delegation_digest=_TEST_TRANSPORT_DELEGATION,
        source_transport="pytest",
    )
    context_digest = _authority_context_digest(
        principal_kind="human",
        parent_principal_id="human:agent",
        session_id="session",
        delegation_digest=_TEST_TRANSPORT_DELEGATION,
        source_transport="pytest",
    )
    parent_intent = AuthorizationIntent(
        principal_id="agent",
        project_id="project",
        runtime_id="runtime",
        task_id="task",
        workspace_id="workspace",
        operation="git.workspace",
        resource_digest=parent_scope.digest(),
        policy_digest=TEST_POLICY_DIGEST,
        nonce="typed-parent",
        authorization_epoch=2,
        workspace_generation=1,
        grant_id=grant_id,
        grant_context_digest=context_digest,
        principal_kind="human",
        parent_principal_id="human:agent",
        session_id="session",
        delegation_digest=_TEST_TRANSPORT_DELEGATION,
        source_transport="pytest",
    )
    parent_receipt = daemon.prepare(parent_intent)
    child_receipt = daemon.narrow(
        parent_receipt,
        operation="git.hash",
        resource_digest=child_scope.digest(),
    )

    clock[0] = 401.0
    renewed = daemon.prepare(
        replace(
            parent_intent,
            operation="git.hash",
            resource_digest=child_scope.digest(),
            nonce="typed-child-renewal",
        )
    )
    assert renewed.resource_digest == child_receipt.resource_digest
    daemon.complete(renewed, result="success", result_digest="renewed-result")

    with pytest.raises(AuthorityControlPlaneError, match="typed resource prepare"):
        daemon.prepare(
            replace(
                parent_intent,
                operation="git.workspace",
                resource_digest=child_scope.digest(),
                nonce="forbidden-child-action",
            )
        )
    with pytest.raises(AuthorityControlPlaneError, match="outside its live scope"):
        daemon.prepare(
            replace(
                parent_intent,
                operation="git.hash",
                resource_digest=unrelated_scope.digest(),
                nonce="unissued-scope",
            )
        )


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
        policy_digest=TEST_POLICY_DIGEST,
        operation_class="git.workspace",
        resource_digest="grant-resource",
        authorization_epoch=2,
        ttl_seconds=1.0,
    )
    context_digest = _authority_context_digest()
    clock[0] = 102.0
    with pytest.raises(AuthorityControlPlaneError, match="expired"):
        daemon.prepare(
            replace(
                _intent(),
                nonce="expired-grant",
                policy_digest=TEST_POLICY_DIGEST,
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
            policy_digest=TEST_POLICY_DIGEST,
            operation_class="git.workspace",
            resource_digest="workspace-digest",
            authorization_epoch=2,
        )
        context_digest = _authority_context_digest()
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
        policy_digest=TEST_POLICY_DIGEST,
        operation_class="git.workspace",
        resource_digest="workspace-digest",
        authorization_epoch=2,
    )
    context_digest = _authority_context_digest()
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
        policy_digest=TEST_POLICY_DIGEST,
        operation_class="git.workspace",
        resource_digest="workspace-digest",
        authorization_epoch=2,
    )
    context_digest = _authority_context_digest()
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
        policy_digest=TEST_POLICY_DIGEST,
        operation_class="git.workspace",
        resource_digest="workspace-digest",
        authorization_epoch=2,
        ttl_seconds=1.0,
    )
    context_digest = _authority_context_digest()
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
    kernel = AuthorityPolicyKernel(expected_policy_digest=TEST_POLICY_DIGEST)
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


@pytest.mark.parametrize("block_phase", ["before-child", "after-child"])
@pytest.mark.parametrize(
    "invalidation",
    ["revoke", "epoch", "generation", "expiry"],
)
def test_narrow_transaction_aborts_without_leaking_audit_or_descendant_slots(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    block_phase: str,
    invalidation: str,
) -> None:
    """Every grant invalidation path must close an in-flight narrow exactly once."""
    clock = [100.0]
    if invalidation == "expiry":
        monkeypatch.setattr(authorityd_module.time, "time", lambda: clock[0])
    daemon = AuthorityDaemon(
        socket_path=tmp_path / "authorityd.sock",
        signing_key=Ed25519KeyStore.load_or_create(tmp_path / "key.pem", create=True),
        audit_writer=_MemoryWorm(),
        issuer_id="test-authorityd",
        policy=lambda _intent: None,
        require_live_grants=True,
        max_audit_obligations=32,
    )
    grant_id, parent = _live_grant_parent(
        daemon,
        grant_ttl_seconds=1.0 if invalidation == "expiry" else 900.0,
        nonce=f"{invalidation}-{block_phase}-parent",
    )
    thread, release, outcome = _start_gated_narrow(
        daemon,
        parent,
        block_phase=block_phase,
    )

    invalidation_error: BaseException | None = None
    try:
        if invalidation == "revoke":
            daemon.revoke_grant(grant_id)
        elif invalidation == "epoch":
            daemon.rotate_authorization_epoch(
                principal_id="agent",
                project_id="project",
                workspace_id="workspace",
                authorization_epoch=3,
            )
        elif invalidation == "generation":
            daemon.rotate_workspace_generation(
                principal_id="agent",
                project_id="project",
                workspace_id="workspace",
                workspace_generation=2,
            )
        else:
            clock[0] = 102.0
            daemon._expire_grants()
    except BaseException as exc:  # noqa: BLE001 - audit append may be uncertain
        invalidation_error = exc
    finally:
        release.set()
        thread.join(timeout=2)

    assert not thread.is_alive()
    assert isinstance(outcome.get("error"), AuthorityControlPlaneError)
    assert invalidation_error is None
    assert daemon._audit_reservations == set()
    assert daemon._grant_descendant_reservations == {}
    assert daemon._narrow_transactions == {}
    assert daemon.pending_count == 0
    abort_events = [
        record
        for record in daemon.audit_writer.records  # type: ignore[union-attr]
        if record["kind"] == "execution.narrow-aborted-by-grant"
    ]
    assert abort_events
    assert abort_events[-1]["reason"] == {
        "revoke": "explicit-revoke",
        "epoch": "authorization-epoch-rotated",
        "generation": "workspace-generation-rotated",
        "expiry": "expired",
    }[invalidation]


def test_aborted_narrow_audit_failure_is_reconciled_and_second_revoke_is_idempotent(
    tmp_path: Path,
) -> None:
    """An uncertain abort append retains evidence, not an anonymous token."""
    worm = _SelectiveWorm("execution.narrow-aborted-by-grant")
    daemon = AuthorityDaemon(
        socket_path=tmp_path / "authorityd.sock",
        signing_key=Ed25519KeyStore.load_or_create(tmp_path / "key.pem", create=True),
        audit_writer=worm,
        issuer_id="test-authorityd",
        policy=lambda _intent: None,
        require_live_grants=True,
        max_audit_obligations=8,
    )
    grant_id, parent = _live_grant_parent(daemon, nonce="audit-failure-parent")
    thread, release, outcome = _start_gated_narrow(
        daemon,
        parent,
        block_phase="after-child",
    )

    with pytest.raises(RemoteAuditUnavailableError):
        daemon.revoke_grant(grant_id)
    assert daemon._audit_reservations == set()
    assert daemon.audit_obligation_count == 1

    # A repeated revoke sees the terminal grant and cannot create another
    # reservation or duplicate abort ownership while reconciliation is active.
    daemon.revoke_grant(grant_id)
    release.set()
    thread.join(timeout=2)
    assert not thread.is_alive()
    assert isinstance(outcome.get("error"), AuthorityControlPlaneError)
    assert daemon._narrow_transactions == {}

    worm.fail = False
    assert daemon.reconcile_audit_obligations() == 0
    assert daemon._audit_reservations == set()

    # The bounded quota is reusable after the evidence owner is reconciled.
    next_grant, next_parent = _live_grant_parent(
        daemon,
        nonce="audit-failure-reusable-parent",
    )
    daemon.revoke(next_parent)
    daemon.revoke_grant(next_grant)


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
