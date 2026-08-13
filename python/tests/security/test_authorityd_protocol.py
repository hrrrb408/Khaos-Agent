"""Authorityd receipt, independent-audit, and production fail-closed tests."""

from __future__ import annotations

import subprocess
import sys
from dataclasses import replace
from pathlib import Path

import pytest
from khaos.coding.execution.identity import executable_identity
from khaos.coding.execution.models import ResourceBudget
from khaos.coding.execution.native_launcher import build_process_launch
from khaos.security.authority_broker import (
    AuthorityBrokerError,
    AuthorityDaemonBroker,
)
from khaos.security.authorityd import (
    AuthorityDaemon,
    AuthorityPolicyKernel,
    build_production_daemon,
)
from khaos.security.authorityd_protocol import (
    AuthorityControlPlaneError,
    AuthorizationIntent,
    Ed25519KeyStore,
    SignedAuthorizationReceipt,
)


class _MemoryWorm:
    def __init__(self) -> None:
        self.records: list[dict[str, object]] = []

    def append(self, record: dict[str, object]) -> None:
        self.records.append(record)


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
    authority = broker.envelope(
        principal_id="agent",
        project_id="project",
        runtime_id="runtime",
        task_id="task",
        workspace_id="workspace",
        workspace_generation=1,
        policy_digest="policy",
        operation_class="exec.host",
        resource_digest="exec-resource",
    )
    capability = broker.issue(authority, allowed_operation="exec.*")
    command = (sys.executable, "-c", "print('receipt-ok')")
    environment = {
        "PATH": "/usr/bin:/bin",
        "PYTHONPATH": str(Path(__file__).resolve().parents[3] / "python"),
    }
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
    broker.complete(capability, result="success", result_digest="result")
