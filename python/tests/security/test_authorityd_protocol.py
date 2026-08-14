"""Authorityd receipt, independent-audit, and production fail-closed tests."""

from __future__ import annotations

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
    _serve_connection,
    build_production_daemon,
)
from khaos.security.authorityd_protocol import (
    AuthorityControlPlaneError,
    AuthorizationIntent,
    Ed25519KeyStore,
    SignedAuthorizationReceipt,
    derive_resource_digest,
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
