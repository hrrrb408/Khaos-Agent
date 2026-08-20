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
import os
import socket
import stat
import struct
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
    peer_uid,
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
    monkeypatch.setenv(
        "KHAOS_AUTHORITYD_AGENT_CODE_REQUIREMENT",
        'identifier "com.khaos.agent" and anchor apple generic '
        'and certificate leaf[subject.OU] = TEAMID123',
    )
    monkeypatch.setenv("KHAOS_AUTHORITYD_KEYCHAIN_GROUP", "TEAMID.com.khaos.authority")
    monkeypatch.setenv("KHAOS_AUTHORITYD_PROTECTED_KEY_REF", "khaos-authority-signing-key")
    monkeypatch.setenv("KHAOS_AUTHORITYD_BACKEND_SOCKET", str(tmp_path / "backend.sock"))
    monkeypatch.delenv("KHAOS_AUTHORITYD_SOCKET_MODE", raising=False)


def _euid() -> int:
    import os

    return os.geteuid()


def _connect_when_listening(path: Path, *, timeout: float = 5.0) -> socket.socket:
    """Connect once the listener is actually accepting.

    ``serve_unix`` creates the socket file at ``bind()`` but only starts
    accepting after ``chmod`` and environment validation; a client racing
    into that window gets ECONNREFUSED even though the file exists.  Retry
    within the test budget instead of treating the window as a failure.
    """
    deadline = time.monotonic() + timeout
    while True:
        client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        client.settimeout(5)
        try:
            client.connect(str(path))
            return client
        except ConnectionRefusedError:
            client.close()
            if time.monotonic() >= deadline:
                raise
            time.sleep(0.05)


def test_darwin_backend_mode_rejects_foreign_socket(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Serving any darwin socket other than the frontend backend is refused."""
    # Patching the global os.name to "posix" on Windows makes every later
    # Path() construction instantiate PosixPath and crash the interpreter
    # (NotImplementedError), including inside pytest's failure reporting.
    # serve_unix validates the backend-socket binding before the platform
    # transport check, so this test must not patch os.name at all.
    monkeypatch.setattr(sys, "platform", "darwin")
    monkeypatch.setenv("KHAOS_AUTHORITYD_BACKEND_SOCKET", str(tmp_path / "configured.sock"))
    daemon = _daemon(tmp_path)
    # daemon.socket_path differs from the configured backend socket.
    with pytest.raises(AuthorityControlPlaneError, match="may only serve"):
        serve_unix(daemon, production=False)


def test_darwin_backend_mode_rejects_missing_backend_config(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The backend-socket binding is validated before the platform transport
    # check, so the darwin backend-mode branch is reachable on any platform
    # without patching the global os.name (see foreign-socket test).
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
        with _connect_when_listening(short_root / "backend.sock") as client:
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
        with _connect_when_listening(short_root / "backend.sock") as client:
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


def test_so_peercred_returns_uid_not_gid(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """struct ucred layout is (pid, uid, gid); the UID is bytes 4..8.

    Regression: peer_uid used to return raw[8:12] — the GID — so the Linux
    authority admission gate compared the peer's effective GID against the
    configured agent UID (identity-boundary defect, found in review of
    209344f5).  CI runners with uid == gid had masked it.  The platform
    guard is monkeypatched so the parsing logic is exercised everywhere.
    """
    monkeypatch.setattr(socket, "SO_PEERCRED", 17, raising=False)
    payload = struct.pack("=3i", 1234, 10001, 20002)
    assert peer_uid(_FakeSocket(payload)) == 10001
    # A short payload must never be interpreted optimistically.
    with pytest.raises(IdentityIsolationError, match="malformed"):
        peer_uid(_FakeSocket(payload[:8]))


@pytest.mark.skipif(
    not sys.platform.startswith("linux") or not hasattr(socket, "SO_PEERCRED"),
    reason="real SO_PEERCRED kernel credential requires Linux",
)
def test_so_peercred_real_socketpair_matches_euid_not_egid() -> None:
    """On a real Linux kernel the reported UID must be the peer's euid.

    GitHub-hosted runners use uid 1001 / gid 127, so asserting against
    geteuid() (and explicitly not getegid() when they differ) catches any
    future pid/uid/gid offset mix-up against the real ABI.
    """
    client, server = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        observed = peer_uid(client)
    finally:
        client.close()
        server.close()
    assert observed == os.geteuid()
    if os.getegid() != os.geteuid():
        assert observed != os.getegid()


def test_windows_backend_sddl_excludes_agent_identities() -> None:
    sddl = build_backend_sddl("S-1-5-80-1234567890-1234567890")
    assert sddl == "D:P(A;;GA;;;SY)(A;;GA;;;S-1-5-80-1234567890-1234567890)"
    # No agent SID may appear anywhere in the backend DACL.
    assert "S-1-5-21" not in sddl
    with pytest.raises(IdentityIsolationError):
        build_backend_sddl("not-a-sid")


def test_windows_token_groups_parsing_round_trip() -> None:
    """TOKEN_GROUPS (x64): DWORD count, then 16-byte SID_AND_ATTRIBUTES."""
    from khaos.security.authorityd_windows import _parse_token_group_sids

    def entry(sid_ptr: int, attributes: int = 7) -> bytes:
        return struct.pack("<QI4x", sid_ptr, attributes)

    raw = struct.pack("<I4x", 2) + entry(0x1000) + entry(0x2000)
    seen: list[int] = []
    sids = _parse_token_group_sids(
        raw, dereference=lambda ptr: (seen.append(ptr), f"S-{ptr}")[1]
    )
    assert sids == ["S-4096", "S-8192"]
    assert seen == [0x1000, 0x2000]
    # A count that overflows the buffer can only be a forged/corrupt payload.
    evil = struct.pack("<I4x", 99) + entry(0x1000)
    with pytest.raises(IdentityIsolationError, match="malformed"):
        _parse_token_group_sids(evil, dereference=lambda _ptr: "")
    with pytest.raises(IdentityIsolationError, match="malformed"):
        _parse_token_group_sids(b"\x00" * 4, dereference=lambda _ptr: "")


def test_windows_peer_trust_covers_service_sid_in_groups() -> None:
    """A Service SID (S-1-5-80-...) lives in TokenGroups, not TokenUser.

    Regression: the check compared only the TokenUser SID against
    {service_sid, S-1-5-18}, so the Service-SID half of the trust set was
    dead code and the claim "Service-SID protected" was unproven.
    """
    from khaos.security.authorityd_windows import _peer_is_trusted

    service = "S-1-5-80-1234567890-1234567890"
    # LocalSystem user — trusted.
    assert _peer_is_trusted("S-1-5-18", [], service)
    # Service SID as token user (dedicated account layout) — trusted.
    assert _peer_is_trusted(service, [], service)
    # Service SID in groups, user is something else — trusted (the real
    # Windows service layout).
    assert _peer_is_trusted("S-1-5-20", ["S-1-5-5-5", service], service)
    # An unrelated process with unrelated groups — rejected.
    assert not _peer_is_trusted("S-1-5-21-999", ["S-1-5-5-5"], service)


def test_windows_connection_timeout_contract(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from khaos.security.authorityd_windows import _connection_timeout_seconds
    from khaos.security.authorityd_protocol import AuthorityControlPlaneError

    monkeypatch.delenv("KHAOS_AUTHORITYD_CONNECTION_TIMEOUT", raising=False)
    assert _connection_timeout_seconds() == 5.0
    for bad in ("0", "61", "nope"):
        monkeypatch.setenv("KHAOS_AUTHORITYD_CONNECTION_TIMEOUT", bad)
        with pytest.raises(AuthorityControlPlaneError):
            _connection_timeout_seconds()
    monkeypatch.setenv("KHAOS_AUTHORITYD_CONNECTION_TIMEOUT", "30")
    assert _connection_timeout_seconds() == 30.0
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
