"""Post-M7 production trust material and authorityd integration evidence."""

from __future__ import annotations

import copy
import hashlib
import json
import multiprocessing
import os
import secrets
import shutil
import signal
import socket
import sys
import time
from pathlib import Path

import khaos.security.authorityd_protocol as authorityd_protocol_module
import pytest
from khaos.runtime_profile import RuntimeProfile
from khaos.security.authority_broker import (
    AuthorityBroker,
    AuthorityBrokerError,
    AuthorityDaemonBroker,
)
from khaos.security.authorityd import (
    AuthorityDaemon,
    AuthorityPolicyKernel,
    JsonlAuditWriter,
    _dispatch,
    serve_unix,
)
from khaos.security.authorityd_protocol import (
    AUTHORITYD_PROTOCOL,
    AuthorityControlPlaneError,
    AuthorityDaemonClient,
    Ed25519KeyStore,
)
from khaos.security.network_broker import NetworkBrokerError, NetworkBrokerFactory
from khaos.security.principals import transport_root_delegation_digest
from khaos.security.production_trust import (
    ProductionTrustBinding,
    ProductionTrustError,
    compare_trust_bindings,
    public_key_fingerprint,
)
from khaos.security.protocol_boundary import canonical_json_bytes, strict_json_loads
from khaos.security.resource_scope import (
    MAX_TYPED_RESOURCE_CATALOG_BYTES,
    NetworkScope,
    ResourceScopeError,
    TypedResourcePartialOrder,
)

POLICY_DIGEST = "a" * 64
AUTHORITY_ID = "test-authorityd"
ENVIRONMENT_DIGEST = "e" * 64


class _MemoryAudit:
    def __init__(self) -> None:
        self.records: list[dict[str, object]] = []

    def append(self, record: dict[str, object]) -> None:
        self.records.append(record)


def _network_catalog() -> TypedResourcePartialOrder:
    scope = NetworkScope(
        schemes=frozenset({"https"}),
        hosts=frozenset({"allowed.example"}),
        ports=frozenset({443}),
        path_prefixes=frozenset({"/"}),
        operations=frozenset({"connect"}),
    )
    return TypedResourcePartialOrder(
        {scope.digest(): scope}, policy_digest=POLICY_DIGEST
    )


def _binding(key_path: Path, catalog: TypedResourcePartialOrder) -> ProductionTrustBinding:
    key = Ed25519KeyStore.load_or_create(key_path, create=False)
    return ProductionTrustBinding.create(
        protocol_version=AUTHORITYD_PROTOCOL,
        authority_id=AUTHORITY_ID,
        policy_digest=POLICY_DIGEST,
        catalog_digest=catalog.catalog_semantic_digest,
        public_key_fingerprint=public_key_fingerprint(
            key.public_key().public_bytes_raw()
        ),
        environment_digest=ENVIRONMENT_DIGEST,
    )


def _write_catalog(path: Path, catalog: TypedResourcePartialOrder) -> None:
    path.write_text(
        json.dumps(catalog.manifest(), sort_keys=True, separators=(",", ":")),
        encoding="utf-8",
    )
    path.chmod(0o640)


def test_production_binding_is_closed_and_self_digesting(tmp_path: Path) -> None:
    key_path = tmp_path / "authorityd.pem"
    Ed25519KeyStore.load_or_create(key_path, create=True)
    catalog = _network_catalog()
    binding = _binding(key_path, catalog)

    restored = ProductionTrustBinding.from_payload(binding.to_payload())
    assert restored.matches(binding)
    assert restored.digest == binding.digest
    assert restored.catalog_semantic_digest == catalog.catalog_semantic_digest

    tampered = copy.deepcopy(binding.to_payload())
    tampered["policy_digest"] = "b" * 64
    with pytest.raises(ProductionTrustError, match="digest"):
        ProductionTrustBinding.from_payload(tampered)

    changed = ProductionTrustBinding.create(
        protocol_version=binding.protocol_version,
        authority_id=binding.authority_id,
        policy_digest="b" * 64,
        catalog_digest=binding.catalog_digest,
        public_key_fingerprint=binding.public_key_fingerprint,
        environment_digest=binding.environment_digest,
    )
    with pytest.raises(ProductionTrustError, match="mismatch"):
        compare_trust_bindings(binding, changed)


def test_security_boundary_json_rejects_duplicate_keys() -> None:
    with pytest.raises(ValueError, match="duplicate"):
        strict_json_loads(b'{"operation":"ping","operation":"grant"}')


def test_security_boundary_json_bounds_bytes_before_decode_and_rejects_extensions() -> None:
    with pytest.raises(ValueError, match="size bound"):
        strict_json_loads(b"\xff" * 8, max_bytes=4)
    with pytest.raises(ValueError, match="non-standard number"):
        strict_json_loads(b'{"value":NaN}')
    with pytest.raises(ValueError, match="non-standard number"):
        strict_json_loads(b'{"value":Infinity}')


@pytest.mark.posix_host
def test_typed_catalog_loader_rejects_untrusted_paths_and_material(
    tmp_path: Path,
) -> None:
    catalog = _network_catalog()
    valid_path = tmp_path / "catalog.json"
    _write_catalog(valid_path, catalog)
    assert (
        TypedResourcePartialOrder.from_json_file(
            valid_path, expected_policy_digest=POLICY_DIGEST
        ).catalog_semantic_digest
        == catalog.catalog_semantic_digest
    )

    with pytest.raises(ResourceScopeError, match="parent traversal"):
        TypedResourcePartialOrder.from_json_file(
            tmp_path / ".." / "catalog.json",
            expected_policy_digest=POLICY_DIGEST,
        )

    symlink_path = tmp_path / "catalog-link.json"
    symlink_path.symlink_to(valid_path)
    with pytest.raises(ResourceScopeError, match="symlink"):
        TypedResourcePartialOrder.from_json_file(
            symlink_path, expected_policy_digest=POLICY_DIGEST
        )

    symlink_parent = tmp_path / "parent-link"
    real_parent = tmp_path / "real-parent"
    real_parent.mkdir()
    _write_catalog(real_parent / "catalog.json", catalog)
    symlink_parent.symlink_to(real_parent, target_is_directory=True)
    with pytest.raises(ResourceScopeError, match="symlink"):
        TypedResourcePartialOrder.from_json_file(
            symlink_parent / "catalog.json", expected_policy_digest=POLICY_DIGEST
        )

    writable_parent = tmp_path / "writable-parent"
    writable_parent.mkdir()
    _write_catalog(writable_parent / "catalog.json", catalog)
    writable_parent.chmod(0o777)
    try:
        with pytest.raises(ResourceScopeError, match="non-writable"):
            TypedResourcePartialOrder.from_json_file(
                writable_parent / "catalog.json",
                expected_policy_digest=POLICY_DIGEST,
            )
    finally:
        writable_parent.chmod(0o700)

    writable_file = tmp_path / "writable-file.json"
    _write_catalog(writable_file, catalog)
    writable_file.chmod(0o666)
    try:
        with pytest.raises(ResourceScopeError, match="trusted non-writable"):
            TypedResourcePartialOrder.from_json_file(
                writable_file, expected_policy_digest=POLICY_DIGEST
            )
    finally:
        writable_file.chmod(0o640)

    duplicate_path = tmp_path / "duplicate.json"
    duplicate_path.write_bytes(b'{"schema_version":1,"schema_version":1}')
    duplicate_path.chmod(0o640)
    with pytest.raises(ResourceScopeError, match="malformed JSON"):
        TypedResourcePartialOrder.from_json_file(
            duplicate_path, expected_policy_digest=POLICY_DIGEST
        )

    unknown_kind = copy.deepcopy(catalog.manifest())
    unknown_kind["scopes"][0]["kind"] = "unknown"
    unknown_path = tmp_path / "unknown-kind.json"
    unknown_path.write_text(json.dumps(unknown_kind), encoding="utf-8")
    unknown_path.chmod(0o640)
    with pytest.raises(ResourceScopeError, match="scope kind is invalid"):
        TypedResourcePartialOrder.from_json_file(
            unknown_path, expected_policy_digest=POLICY_DIGEST
        )

    oversized_path = tmp_path / "oversized.json"
    oversized_path.write_bytes(b" " * (MAX_TYPED_RESOURCE_CATALOG_BYTES + 1))
    oversized_path.chmod(0o640)
    with pytest.raises(ResourceScopeError, match="regular file"):
        TypedResourcePartialOrder.from_json_file(
            oversized_path, expected_policy_digest=POLICY_DIGEST
        )


@pytest.mark.posix_host
def test_production_catalog_can_be_loaded_before_policy_binding(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The first startup gate validates catalog semantics without policy state."""
    from khaos.runtime.factory import _load_production_resource_order

    catalog = _network_catalog()
    catalog_path = tmp_path / "catalog.json"
    _write_catalog(catalog_path, catalog)
    monkeypatch.setenv("KHAOS_TYPED_RESOURCE_CATALOG_PATH", str(catalog_path))
    monkeypatch.setenv("KHAOS_AUTHORITY_PROFILE", "native-production")

    independent = _load_production_resource_order(None, RuntimeProfile.PRODUCTION)
    assert independent is not None
    assert independent.catalog_semantic_digest == catalog.catalog_semantic_digest
    assert independent.policy_digest == POLICY_DIGEST


def _daemon_for_binding(
    tmp_path: Path,
) -> tuple[AuthorityDaemon, TypedResourcePartialOrder, ProductionTrustBinding]:
    catalog = _network_catalog()
    key_path = tmp_path / "authorityd.pem"
    key = Ed25519KeyStore.load_or_create(key_path, create=True)
    binding = _binding(key_path, catalog)
    daemon = AuthorityDaemon(
        socket_path=tmp_path / "authorityd.sock",
        signing_key=key,
        audit_writer=_MemoryAudit(),
        issuer_id=AUTHORITY_ID,
        policy=AuthorityPolicyKernel(
            expected_policy_digest=POLICY_DIGEST,
            resource_order=catalog,
        ),
        trust_binding=binding,
        require_live_grants=True,
        require_typed_principals=True,
    )
    return daemon, catalog, binding


def _handshake_request(binding: ProductionTrustBinding) -> dict[str, object]:
    return {
        "protocol": AUTHORITYD_PROTOCOL,
        "operation": "handshake",
        "handshake_schema_version": 1,
        "protocol_version": AUTHORITYD_PROTOCOL,
        "runtime_identity": {
            "runtime_id": "runtime",
            "principal_id": "agent",
            "project_id": "project",
            "principal_kind": "human",
        },
        "trust_binding": binding.to_payload(),
    }


def test_authorityd_handshake_binds_effect_requests_and_key(
    tmp_path: Path,
) -> None:
    daemon, _catalog, binding = _daemon_for_binding(tmp_path)

    with pytest.raises(AuthorityControlPlaneError, match="trust binding"):
        _dispatch(daemon, {"protocol": AUTHORITYD_PROTOCOL, "operation": "ping"})

    response = _dispatch(daemon, _handshake_request(binding))
    assert response["ready"] == "READY"
    channel_nonce = response["channel_nonce"]
    assert isinstance(channel_nonce, str) and len(channel_nonce) == 64

    ping = _dispatch(
        daemon,
        {
            "protocol": AUTHORITYD_PROTOCOL,
            "operation": "ping",
            "trust_binding": binding.to_payload(),
            "channel_nonce": channel_nonce,
            "runtime_identity": _handshake_request(binding)["runtime_identity"],
        },
    )
    assert ping == {"ok": True, "issuer_id": AUTHORITY_ID}

    wrong_identity = {
        **_handshake_request(binding)["runtime_identity"],
        "runtime_id": "other-runtime",
    }
    with pytest.raises(AuthorityControlPlaneError, match="runtime identity"):
        _dispatch(
            daemon,
            {
                "protocol": AUTHORITYD_PROTOCOL,
                "operation": "ping",
                "trust_binding": binding.to_payload(),
                "channel_nonce": channel_nonce,
                "runtime_identity": wrong_identity,
            },
        )

    changed = ProductionTrustBinding.create(
        protocol_version=binding.protocol_version,
        authority_id=binding.authority_id,
        policy_digest="b" * 64,
        catalog_digest=binding.catalog_digest,
        public_key_fingerprint=binding.public_key_fingerprint,
        environment_digest=binding.environment_digest,
    )
    with pytest.raises(AuthorityControlPlaneError, match="mismatch"):
        _dispatch(
            daemon,
            {
                "protocol": AUTHORITYD_PROTOCOL,
                "operation": "ping",
                "trust_binding": changed.to_payload(),
                "channel_nonce": channel_nonce,
            },
        )
    with pytest.raises(AuthorityControlPlaneError, match="unknown"):
        _dispatch(
            daemon,
            {
                "protocol": AUTHORITYD_PROTOCOL,
                "operation": "ping",
                "trust_binding": binding.to_payload(),
                "channel_nonce": "f" * 64,
            },
        )

    other_key = Ed25519KeyStore.load_or_create(tmp_path / "other.pem", create=True)
    wrong_key_binding = ProductionTrustBinding.create(
        protocol_version=binding.protocol_version,
        authority_id=binding.authority_id,
        policy_digest=binding.policy_digest,
        catalog_digest=binding.catalog_digest,
        public_key_fingerprint=public_key_fingerprint(
            other_key.public_key().public_bytes_raw()
        ),
        environment_digest=binding.environment_digest,
    )
    with pytest.raises(AuthorityControlPlaneError, match="key fingerprint"):
        AuthorityDaemon(
            socket_path=tmp_path / "wrong-key.sock",
            signing_key=other_key,
            audit_writer=_MemoryAudit(),
            issuer_id=AUTHORITY_ID,
            policy=lambda _intent: None,
            trust_binding=binding,
        )
    assert wrong_key_binding.public_key_fingerprint != binding.public_key_fingerprint


def test_bound_authorityd_limits_native_probe_to_non_effect_ping(
    tmp_path: Path,
) -> None:
    daemon, _catalog, _binding = _daemon_for_binding(tmp_path)
    request = b'{"operation":"ping","protocol":1}'
    attestation = _dispatch(
        daemon,
        {
            "protocol": AUTHORITYD_PROTOCOL,
            "operation": "attest",
            "challenge_nonce": "a" * 64,
            "request_raw_hex": request.hex(),
            "request_digest": hashlib.sha256(request).hexdigest(),
            "proof_fields": {
                "platform": "darwin",
                "transport": "xpc",
                "service_id": "com.khaos.authorityd",
                "service_pid": "4242",
                "service_identity": "com.khaos.authorityd",
                "peer_identity": "com.khaos.agent",
                "peer_team_id": "TEAMID123",
                "peer_cdhash": "ab" * 20,
                "designated_requirement_digest": "c" * 64,
                "service_instance_id": "d" * 32,
                "protected_key_ref": "khaos-authority-signing-key",
            },
        },
    )
    assert attestation["response"] == {"ok": True, "issuer_id": AUTHORITY_ID}

    effect_request = b'{"operation":"grant","protocol":1}'
    with pytest.raises(AuthorityControlPlaneError, match="trust binding"):
        _dispatch(
            daemon,
            {
                "protocol": AUTHORITYD_PROTOCOL,
                "operation": "attest",
                "challenge_nonce": "b" * 64,
                "request_raw_hex": effect_request.hex(),
                "request_digest": hashlib.sha256(effect_request).hexdigest(),
                "proof_fields": {
                    "platform": "darwin",
                    "transport": "xpc",
                    "service_id": "com.khaos.authorityd",
                    "service_pid": "4242",
                    "service_identity": "com.khaos.authorityd",
                    "peer_identity": "com.khaos.agent",
                    "peer_team_id": "TEAMID123",
                    "peer_cdhash": "ab" * 20,
                    "designated_requirement_digest": "c" * 64,
                    "service_instance_id": "d" * 32,
                    "protected_key_ref": "khaos-authority-signing-key",
                },
            },
        )


def test_production_effect_consumers_cannot_create_default_authority() -> None:
    with pytest.raises(NetworkBrokerError, match="requires the runtime authority broker"):
        NetworkBrokerFactory(runtime_profile=RuntimeProfile.PRODUCTION)
    with pytest.raises(AuthorityBrokerError, match="explicit catalog/policy handshake"):
        AuthorityBroker.default(runtime_profile=RuntimeProfile.PRODUCTION)
    with pytest.raises(ValueError, match="explicit trust binding"):
        AuthorityDaemonClient(
            Path("/tmp/khaos-authorityd.sock"),
            runtime_profile=RuntimeProfile.PRODUCTION,
        )


def _serve_authority_process(
    socket_path: str,
    key_path: str,
    catalog_path: str,
    audit_path: str,
    binding_payload: dict[str, object],
    trusted_root: str,
) -> None:
    import khaos.security.authorityd as authorityd_module
    import khaos.security.authorityd_protocol as authorityd_protocol_module

    authority_root = Path(trusted_root)
    authorityd_module.local_authority_root = lambda: authority_root
    authorityd_protocol_module.local_authority_root = lambda: authority_root
    catalog = TypedResourcePartialOrder.from_json_file(
        Path(catalog_path), expected_policy_digest=POLICY_DIGEST
    )
    key = Ed25519KeyStore.load_or_create(Path(key_path), create=False)
    binding = ProductionTrustBinding.from_payload(binding_payload)
    daemon = AuthorityDaemon(
        socket_path=Path(socket_path),
        signing_key=key,
        audit_writer=JsonlAuditWriter(Path(audit_path)),
        issuer_id=AUTHORITY_ID,
        policy=AuthorityPolicyKernel(
            expected_policy_digest=POLICY_DIGEST,
            resource_order=catalog,
        ),
        trust_binding=binding,
        require_live_grants=True,
        require_typed_principals=True,
    )
    serve_unix(daemon, production=True, transport="unix", profile="community")


def _start_authority_process(
    *,
    socket_path: Path,
    key_path: Path,
    catalog_path: Path,
    audit_path: Path,
    binding: ProductionTrustBinding,
    trusted_root: Path,
) -> multiprocessing.Process:
    context = multiprocessing.get_context("spawn")
    process = context.Process(
        target=_serve_authority_process,
        args=(
            str(socket_path),
            str(key_path),
            str(catalog_path),
            str(audit_path),
            binding.to_payload(),
            str(trusted_root),
        ),
        daemon=True,
    )
    process.start()
    deadline = time.monotonic() + 5
    while not socket_path.exists() and time.monotonic() < deadline:
        if not process.is_alive():
            break
        time.sleep(0.02)
    assert socket_path.exists(), f"authorityd process exited with {process.exitcode}"
    return process


def _stop_authority_process(process: multiprocessing.Process, socket_path: Path) -> None:
    if process.is_alive() and process.pid is not None:
        os.kill(process.pid, signal.SIGINT)
        process.join(timeout=5)
    if process.is_alive():
        process.terminate()
        process.join(timeout=2)
    assert not process.is_alive()
    deadline = time.monotonic() + 2
    while socket_path.exists() and time.monotonic() < deadline:
        time.sleep(0.02)
    assert not socket_path.exists()


def _raw_uds_request(socket_path: Path, payload: dict[str, object]) -> dict[str, object]:
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(3)
        connection.connect(str(socket_path))
        connection.sendall(canonical_json_bytes(payload) + b"\n")
        chunks: list[bytes] = []
        while True:
            chunk = connection.recv(65536)
            if not chunk:
                break
            chunks.append(chunk)
            if b"\n" in chunk:
                break
    response = b"".join(chunks).split(b"\n", 1)[0]
    value = strict_json_loads(response, max_bytes=1024 * 1024)
    assert isinstance(value, dict)
    return value


@pytest.mark.posix_host
def test_real_multiprocess_uds_catalog_key_handshake_and_restart(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    short_parent = Path("/private/tmp") if sys.platform == "darwin" else Path("/tmp")
    short_root = short_parent / f"khaos-p7-root-{os.getpid()}-{secrets.token_hex(4)}"
    trusted_root = short_root / ".khaos" / "authorityd"
    trusted_root.mkdir(mode=0o700, parents=True)
    monkeypatch.setattr(
        authorityd_protocol_module, "local_authority_root", lambda: trusted_root
    )
    catalog = _network_catalog()
    catalog_path = trusted_root / "typed-resource-catalog.json"
    _write_catalog(catalog_path, catalog)
    key_path = trusted_root / "authorityd.pem"
    key = Ed25519KeyStore.load_or_create(key_path, create=True)
    public_key_path = trusted_root / "authorityd.pub"
    public_key_path.write_bytes(key.public_key().public_bytes_raw())
    public_key_path.chmod(0o640)
    binding = _binding(key_path, catalog)
    socket_path = trusted_root / "authorityd.sock"
    audit_path = trusted_root / "authorityd.audit.jsonl"
    process = _start_authority_process(
        socket_path=socket_path,
        key_path=key_path,
        catalog_path=catalog_path,
        audit_path=audit_path,
        binding=binding,
        trusted_root=trusted_root,
    )
    client = AuthorityDaemonClient(
        socket_path,
        transport="unix",
        runtime_profile=RuntimeProfile.PRODUCTION,
        public_key_path=public_key_path,
        trusted_local_root=trusted_root,
        trust_binding=binding,
    )
    second_process: multiprocessing.Process | None = None
    try:
        with pytest.raises(AuthorityControlPlaneError, match="handshake"):
            client.request({"operation": "ping"})

        observed = client.handshake(
            runtime_id="runtime",
            principal_id="agent",
            project_id="project",
            principal_kind="human",
        )
        assert observed.matches(binding)
        assert client.request({"operation": "ping"})["issuer_id"] == AUTHORITY_ID

        raw_without_binding = _raw_uds_request(
            socket_path,
            {"protocol": AUTHORITYD_PROTOCOL, "operation": "ping"},
        )
        assert raw_without_binding["ok"] is False
        assert "trust binding" in str(raw_without_binding["error"])

        wrong_binding = ProductionTrustBinding.create(
            protocol_version=binding.protocol_version,
            authority_id=binding.authority_id,
            policy_digest="b" * 64,
            catalog_digest=binding.catalog_digest,
            public_key_fingerprint=binding.public_key_fingerprint,
            environment_digest=binding.environment_digest,
        )
        raw_mismatch = _raw_uds_request(
            socket_path,
            {
                "protocol": AUTHORITYD_PROTOCOL,
                "operation": "ping",
                "trust_binding": wrong_binding.to_payload(),
                "channel_nonce": client._channel_nonce,
            },
        )
        assert raw_mismatch["ok"] is False
        assert "mismatch" in str(raw_mismatch["error"])

        delegation_digest = transport_root_delegation_digest(
            principal_id="agent",
            principal_kind="human",
            parent_principal_id="human:agent",
            project_id="project",
            session_id="session",
            runtime_id="runtime",
            source_transport="pytest",
            policy_digest=POLICY_DIGEST,
        )
        broker = AuthorityDaemonBroker(client)
        channel_nonce = client._channel_nonce
        assert channel_nonce is not None
        authority = broker.envelope(
            principal_id="agent",
            project_id="project",
            runtime_id="runtime",
            task_id="task",
            workspace_id="workspace",
            workspace_generation=1,
            policy_digest=POLICY_DIGEST,
            operation_class="network.connect",
            resource_digest=next(iter(catalog.scopes)),
            authorization_epoch=1,
            principal_kind="human",
            parent_principal_id="human:agent",
            session_id="session",
            delegation_digest=delegation_digest,
            source_transport="pytest",
        )
        capability = broker.issue(authority)
        broker.validate(capability, expected_operation="network.connect")
        broker.revoke(capability)
        broker.revoke_grant(authority)

        with pytest.raises(AuthorityControlPlaneError, match="typed resource"):
            client.grant(
                principal_id="agent",
                project_id="project",
                runtime_id="runtime",
                task_id="task",
                workspace_id="workspace",
                workspace_generation=1,
                policy_digest=POLICY_DIGEST,
                operation_class="network.connect",
                resource_digest="f" * 64,
                authorization_epoch=1,
                principal_kind="human",
                parent_principal_id="human:agent",
                session_id="session",
                delegation_digest=delegation_digest,
                source_transport="pytest",
            )

        broker.close()
        closed_channel = _raw_uds_request(
            socket_path,
            {
                "protocol": AUTHORITYD_PROTOCOL,
                "operation": "ping",
                "trust_binding": binding.to_payload(),
                "channel_nonce": channel_nonce,
            },
        )
        assert closed_channel["ok"] is False
        assert "unknown" in str(closed_channel["error"])

        _stop_authority_process(process, socket_path)
        with pytest.raises(AuthorityControlPlaneError):
            client.request({"operation": "ping"})
        assert not client.ready

        second_process = _start_authority_process(
            socket_path=socket_path,
            key_path=key_path,
            catalog_path=catalog_path,
            audit_path=audit_path,
            binding=binding,
            trusted_root=trusted_root,
        )
        restarted = AuthorityDaemonClient(
            socket_path,
            transport="unix",
            runtime_profile=RuntimeProfile.PRODUCTION,
            public_key_path=public_key_path,
            trust_binding=binding,
        )
        restarted.handshake(
            runtime_id="runtime",
            principal_id="agent",
            project_id="project",
            principal_kind="human",
        )
        assert restarted.request({"operation": "ping"})["issuer_id"] == AUTHORITY_ID
    finally:
        if second_process is not None:
            _stop_authority_process(second_process, socket_path)
        elif process.is_alive():
            _stop_authority_process(process, socket_path)
        shutil.rmtree(short_root, ignore_errors=True)
