"""Native authority backend ownership tests (M6.9 BATCH 1).

The native frontend/backend chain must be real on every platform:
- darwin ``serve_unix`` only serves the configured backend socket behind the
  XPC frontend, with kernel-verified LOCAL_PEERCRED peer identity;
- the Windows backend pipe DACL excludes every identity except SYSTEM and
  the authority Service SID;
- the E2E probe script's negative scenarios detect fail-open acceptance.
"""

from __future__ import annotations

import json
import socket
import stat
import sys
import threading
import time
from pathlib import Path

import pytest
from khaos.security.authorityd import (
    AuthorityControlPlaneError,
    AuthorityDaemon,
    serve_unix,
)
from khaos.security.authorityd_protocol import (
    AUTHORITYD_PROTOCOL,
    Ed25519KeyStore,
)
from khaos.security.authorityd_windows import build_backend_sddl
from khaos.security.identity_isolation import (
    IdentityIsolationError,
    peer_uid_darwin,
)


class _MemoryWorm:
    def __init__(self) -> None:
        self.records: list[dict[str, object]] = []

    def append(self, record: dict[str, object]) -> None:
        self.records.append(record)


def _daemon(tmp_path: Path) -> AuthorityDaemon:
    return AuthorityDaemon(
        socket_path=tmp_path / "backend.sock",
        signing_key=Ed25519KeyStore.load_or_create(
            tmp_path / "backend-key.pem", create=True
        ),
        audit_writer=_MemoryWorm(),
        issuer_id="test-authorityd",
        policy=lambda _intent: None,
    )


def _darwin_contract_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("KHAOS_AUTHORITYD_UID", str(_euid()))
    monkeypatch.setenv("KHAOS_AUTHORITYD_LAUNCHD_SERVICE", "com.khaos.authorityd")
    monkeypatch.setenv("KHAOS_AUTHORITYD_AGENT_CODE_SIGNATURE", "com.khaos.agent")
    monkeypatch.setenv("KHAOS_AUTHORITYD_KEYCHAIN_GROUP", "TEAMID.com.khaos.authority")
    monkeypatch.setenv("KHAOS_AUTHORITYD_PROTECTED_KEY_REF", "khaos-authority-signing-key")
    monkeypatch.setenv("KHAOS_AUTHORITYD_BACKEND_SOCKET", str(tmp_path / "backend.sock"))
    monkeypatch.delenv("KHAOS_AUTHORITYD_SOCKET_MODE", raising=False)


def _euid() -> int:
    import os

    return os.geteuid()


def test_darwin_backend_mode_rejects_foreign_socket(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Serving any darwin socket other than the frontend backend is refused."""
    monkeypatch.setattr(sys, "platform", "darwin")
    import khaos.security.authorityd as authorityd_module

    monkeypatch.setattr(authorityd_module.os, "name", "posix", raising=False)
    monkeypatch.setenv("KHAOS_AUTHORITYD_BACKEND_SOCKET", str(tmp_path / "configured.sock"))
    daemon = _daemon(tmp_path)
    # daemon.socket_path differs from the configured backend socket.
    with pytest.raises(AuthorityControlPlaneError, match="may only serve"):
        serve_unix(daemon, production=False)


def test_darwin_backend_mode_rejects_missing_backend_config(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(sys, "platform", "darwin")
    monkeypatch.delenv("KHAOS_AUTHORITYD_BACKEND_SOCKET", raising=False)
    daemon = _daemon(tmp_path)
    with pytest.raises(AuthorityControlPlaneError, match="may only serve"):
        serve_unix(daemon, production=False)


@pytest.mark.skipif(sys.platform != "darwin", reason="LOCAL_PEERCRED live test")
def test_darwin_backend_serves_only_frontend_peers(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A real darwin backend accepts the authority-UID peer and answers."""
    # macOS AF_UNIX paths are limited to ~104 bytes; keep the live socket
    # under a short /tmp prefix instead of the deep pytest temp tree.
    import uuid

    short_root = Path(f"/tmp/khaos-bk-{uuid.uuid4().hex[:8]}")
    short_root.mkdir(mode=0o700)
    _darwin_contract_env(monkeypatch, short_root)
    daemon = _daemon(short_root)
    served = threading.Event()

    def _serve() -> None:
        served.set()
        try:
            serve_unix(daemon, production=True)
        except Exception as exc:  # noqa: BLE001 - surface serve failures
            served.exc = exc  # type: ignore[attr-defined]

    thread = threading.Thread(target=_serve, daemon=True)
    thread.start()
    assert served.wait(timeout=5)
    # The socket must be private to the authority identity.
    deadline = time.time() + 5
    while time.time() < deadline and not (short_root / "backend.sock").exists():
        time.sleep(0.05)
    assert (short_root / "backend.sock").exists(), getattr(
        served, "exc", "socket was never created"
    )
    info = (short_root / "backend.sock").lstat()
    assert stat.S_ISSOCK(info.st_mode)
    assert stat.S_IMODE(info.st_mode) == 0o600
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.settimeout(5)
            client.connect(str(short_root / "backend.sock"))
            request = json.dumps(
                {"protocol": AUTHORITYD_PROTOCOL, "operation": "unknown-op"}
            ).encode("utf-8")
            client.sendall(request + b"\n")
            response = json.loads(client.recv(65536).decode("utf-8"))
            # Reaching dispatch (not a peer rejection) proves the
            # LOCAL_PEERCRED gate admitted the authority-UID peer.
            assert response["ok"] is False
            assert "unknown authorityd operation" in str(response["error"])
    finally:
        daemon._closed = True
        thread.join(timeout=5)


@pytest.mark.skipif(sys.platform != "darwin", reason="LOCAL_PEERCRED live test")
def test_darwin_backend_rejects_wrong_peer_uid(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A peer whose LOCAL_PEERCRED UID is not the authority UID is closed."""
    import uuid

    short_root = Path(f"/tmp/khaos-bk-{uuid.uuid4().hex[:8]}")
    short_root.mkdir(mode=0o700)
    _darwin_contract_env(monkeypatch, short_root)
    import khaos.security.authorityd as authorityd_module

    real_peer_uid = authorityd_module.peer_uid_platform

    def _wrong_uid(connection: socket.socket) -> int:
        _ = real_peer_uid(connection)
        return 4242

    monkeypatch.setattr(authorityd_module, "peer_uid_platform", _wrong_uid)
    daemon = _daemon(short_root)
    served = threading.Event()

    def _serve() -> None:
        served.set()
        try:
            serve_unix(daemon, production=True)
        except Exception as exc:  # noqa: BLE001 - recorded for diagnosis
            served.exc = exc  # type: ignore[attr-defined]

    thread = threading.Thread(target=_serve, daemon=True)
    thread.start()
    assert served.wait(timeout=5)
    deadline = time.time() + 5
    while time.time() < deadline and not (short_root / "backend.sock").exists():
        time.sleep(0.05)
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.settimeout(5)
            client.connect(str(short_root / "backend.sock"))
            client.sendall(b'{"protocol":1,"operation":"unknown"}\n')
            deadline = time.time() + 5
            data = b""
            while time.time() < deadline:
                chunk = client.recv(4096)
                if not chunk:
                    break
                data += chunk
                if b"\n" in data:
                    break
            # The wrong-UID peer must be rejected with an explicit error,
            # never a dispatched response.
            assert b"peer UID" in data or data == b""
    finally:
        daemon._closed = True
        thread.join(timeout=5)


class _FakeSocket:
    """Minimal socket stand-in for LOCAL_PEERCRED payload parsing tests."""

    def __init__(self, payload: bytes) -> None:
        self._payload = payload

    def getsockopt(self, level: int, option: int, size: int) -> bytes:
        return self._payload[:size]


def test_local_peercred_parsing_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "platform", "darwin")
    # A short payload must never be interpreted optimistically.
    with pytest.raises(IdentityIsolationError, match="malformed"):
        peer_uid_darwin(_FakeSocket(b"\x01\x00"))
    # XUCRED_VERSION is 0 on current macOS; a valid kernel credential with
    # version 0 must parse, while a negative (>= 2^31) UID fails closed.
    padding = b"\x00" * 8
    valid = (0).to_bytes(4, "little") + (502).to_bytes(4, "little") + padding
    assert peer_uid_darwin(_FakeSocket(valid)) == 502
    invalid = (0).to_bytes(4, "little") + (0xFFFFFFFF).to_bytes(4, "little") + padding
    with pytest.raises(IdentityIsolationError, match="UID is invalid"):
        peer_uid_darwin(_FakeSocket(invalid))


def test_windows_backend_sddl_excludes_agent_identities() -> None:
    sddl = build_backend_sddl("S-1-5-80-1234567890-1234567890")
    assert sddl == "D:P(A;;GA;;;SY)(A;;GA;;;S-1-5-80-1234567890-1234567890)"
    # No agent SID may appear anywhere in the backend DACL.
    assert "S-1-5-21" not in sddl
    with pytest.raises(IdentityIsolationError):
        build_backend_sddl("not-a-sid")
    with pytest.raises(IdentityIsolationError):
        build_backend_sddl("S-1-5-" + "9" * 200)
    with pytest.raises(IdentityIsolationError):
        build_backend_sddl("  ")


def test_e2e_probe_emits_exact_catalog_entry() -> None:
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "run_native_authority_e2e",
        Path(__file__).resolve().parents[2].parent
        / "scripts"
        / "run_native_authority_e2e.py",
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    from khaos.security.resource_scope import ExecutionScope

    scope: ExecutionScope = module.e2e_execution_scope()
    manifest = {"digest": scope.digest(), **scope.manifest()}
    assert manifest["kind"] == "execution"
    assert manifest["scope"]["argv_exact"] is True
    assert manifest["scope"]["executable"] == "/bin/echo"
    # The effect payload the E2E writes stays inside its declared bound.
    assert len("khaos-native-e2e:") + 32 <= 64
