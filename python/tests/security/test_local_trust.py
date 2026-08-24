"""Community Local Trust Root path-boundary regressions."""

from __future__ import annotations

import os
import socket
import stat
import tempfile
import threading
import time
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from khaos.security import authorityd as authorityd_module
from khaos.security import authorityd_protocol as authorityd_protocol_module
from khaos.security.authorityd import AuthorityDaemon, serve_unix
from khaos.security.authorityd_protocol import (
    AuthorityDaemonClient,
    AuthorizationIntent,
    Ed25519KeyStore,
)
from khaos.security.local_trust import (
    LocalTrustRootError,
    ensure_local_authority_root,
    local_authority_root,
    validate_trusted_local_path,
)

pytestmark = pytest.mark.posix_host


def _root(tmp_path: Path) -> Path:
    root = tmp_path / "home" / ".khaos" / "authorityd"
    root.parent.parent.mkdir()
    return root


class _MemoryAuditWriter:
    def append(self, _record: dict[str, object]) -> None:
        return None


def test_local_authority_root_is_owner_only_and_not_a_symlink(tmp_path: Path) -> None:
    root = _root(tmp_path)
    ensure_local_authority_root(root)
    assert root.stat().st_uid == os.getuid()
    assert root.stat().st_mode & 0o077 == 0

    os.chmod(root, 0o700)
    root.rename(root.parent / "real-authorityd")
    (root.parent / "authorityd").symlink_to(root.parent / "real-authorityd")
    with pytest.raises(LocalTrustRootError, match="must not be a symlink"):
        ensure_local_authority_root(root)


def test_local_authority_root_rejects_world_writable_parent(tmp_path: Path) -> None:
    root = _root(tmp_path)
    root.parent.mkdir(mode=0o700)
    os.chmod(root.parent, 0o777)
    with pytest.raises(LocalTrustRootError, match="group/world writable"):
        ensure_local_authority_root(root)


def test_local_authority_root_does_not_follow_home_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    if os.name != "posix":
        pytest.skip("the Community profile uses POSIX account home metadata")
    import pwd

    monkeypatch.setenv("HOME", str(tmp_path / "repository"))

    assert local_authority_root() == (
        Path(pwd.getpwuid(os.getuid()).pw_dir) / ".khaos" / "authorityd"
    )


def test_local_authority_path_rejects_symlink_and_escape(
    tmp_path: Path,
) -> None:
    root = _root(tmp_path)
    ensure_local_authority_root(root)
    outside = tmp_path / "outside"
    outside.write_text("not trusted", encoding="utf-8")

    with pytest.raises(LocalTrustRootError, match="must stay under"):
        validate_trusted_local_path(outside, kind="file", root=root)

    link = root / "catalog.json"
    link.symlink_to(outside)
    with pytest.raises(LocalTrustRootError, match="must not be a symlink"):
        validate_trusted_local_path(link, kind="file", root=root)


def test_local_socket_must_be_exactly_private(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _root(tmp_path)
    ensure_local_authority_root(root)
    path = root / "authorityd.sock"

    original_lstat = Path.lstat

    def fake_lstat(candidate: Path) -> os.stat_result:
        if candidate == path:
            return os.stat_result(
                (
                    stat.S_IFSOCK | 0o660,
                    1,
                    1,
                    1,
                    os.getuid(),
                    os.getgid(),
                    0,
                    0,
                    0,
                    0,
                )
            )
        return original_lstat(candidate)

    monkeypatch.setattr(Path, "lstat", fake_lstat)
    with pytest.raises(LocalTrustRootError, match="exactly 0600"):
        validate_trusted_local_path(path, kind="socket", root=root)


def test_community_local_profile_round_trip_uses_real_authorityd(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Exercise the non-signing Community transport through a real UDS."""
    if os.name == "nt" or not hasattr(socket, "AF_UNIX"):
        pytest.skip("Community Local Profile requires POSIX AF_UNIX")

    with tempfile.TemporaryDirectory(prefix="khaos-community-", dir="/tmp") as directory:
        root = Path(directory) / ".khaos" / "authorityd"
        root.parent.mkdir()
        ensure_local_authority_root(root)
        monkeypatch.setattr(authorityd_module, "local_authority_root", lambda: root)
        monkeypatch.setattr(
            authorityd_protocol_module, "local_authority_root", lambda: root
        )
        monkeypatch.setenv("KHAOS_AUTHORITYD_SOCKET_MODE", "0600")
        monkeypatch.delenv("KHAOS_AUTHORITY_PROFILE", raising=False)
        key_path = root / "authorityd.pem"
        public_key_path = root / "authorityd.pub"
        key = Ed25519KeyStore.load_or_create(key_path, create=True)
        public_key_path.write_bytes(
            key.public_key().public_bytes(
                serialization.Encoding.Raw,
                serialization.PublicFormat.Raw,
            )
        )
        socket_path = root / "authorityd.sock"
        daemon = AuthorityDaemon(
            socket_path=socket_path,
            signing_key=key,
            audit_writer=_MemoryAuditWriter(),
            issuer_id="test-community-authorityd",
            policy=lambda _intent: None,
        )
        errors: list[BaseException] = []

        def serve() -> None:
            try:
                serve_unix(
                    daemon,
                    production=True,
                    transport="unix",
                    profile="community",
                )
            except BaseException as exc:  # noqa: BLE001 - surface thread failure
                errors.append(exc)

        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        try:
            deadline = time.monotonic() + 5
            while not socket_path.exists() and time.monotonic() < deadline:
                time.sleep(0.02)
            assert socket_path.exists(), errors
            client = AuthorityDaemonClient(
                socket_path,
                expected_authority_uid=os.geteuid(),
                public_key_path=public_key_path,
                trusted_local_root=root,
                transport="unix",
            )
            intent = AuthorizationIntent(
                principal_id="agent",
                project_id="project",
                runtime_id="runtime",
                task_id="task",
                workspace_id="workspace",
                operation="git.workspace",
                resource_digest="workspace-digest",
                policy_digest="policy-digest",
                nonce="community-round-trip",
                authorization_epoch=2,
            )
            receipt = client.prepare(intent)
            client.claim(receipt)
            client.complete(receipt, result="success", result_digest="round-trip")
            assert not errors
        finally:
            daemon._closed = True
            if socket_path.exists():
                try:
                    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as wakeup:
                        wakeup.connect(str(socket_path))
                except OSError:
                    pass
            thread.join(timeout=5)
        assert not thread.is_alive()
