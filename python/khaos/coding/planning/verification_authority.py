"""Boot-scoped write authority for the trusted-verification database.

The authority is a boot-scoped production boundary.  Before filesystem modes
are reduced it acquires and retains SQLite's EXCLUSIVE database lock, so a
connection opened before startup cannot keep writing through an already-open
file descriptor.  It also pins database/parent/WAL/SHM identities and issues
opaque capabilities to the verification store.  It does not claim to defend
hostile Python executing in the Khaos runtime process or an OS administrator.
Those principals can inspect process memory or change owner-controlled
permissions and are outside this boundary.
"""
from __future__ import annotations

import hashlib
import json
import multiprocessing
import os
import secrets
import sqlite3
import stat
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator


PROTECTED_SCHEMA_OBJECTS: dict[str, str] = {
    "plan_execution_runs": "table",
    "plan_verification_runs": "table",
    "plan_verification_steps": "table",
    "plan_verification_audit_events": "table",
    "plan_verification_artifacts": "table",
    "plan_execution_phase_leases": "table",
    "verification_sandbox_instances": "table",
    "toolchain_attestations": "table",
    "disposable_verification_workspaces": "table",
    "approved_verification_plan_snapshots": "table",
    "verification_cleanup_proofs": "table",
    "verification_success_evidence": "table",
    "ux_active_verification_phase_lease": "index",
    "ix_vsi_boot_state": "index",
    "ix_vsi_run": "index",
    "ix_ta_boot": "index",
    "ix_dvw_boot_state": "index",
    "ix_dvw_run": "index",
    "ix_avps_plan": "index",
    "ux_avps_snapshot_digest": "index",
    "ix_vcp_run": "index",
    "ux_vcp_run": "index",
    "ix_vsi_kind_state": "index",
    "trg_avps_referenced_update": "trigger",
    "trg_avps_referenced_delete": "trigger",
    "trg_vcp_immutable_update": "trigger",
    "trg_vcp_immutable_delete": "trigger",
    "trg_verification_passed_guard": "trigger",
    "trg_verification_passed_insert_guard": "trigger",
    "trg_execution_verified_guard": "trigger",
    "trg_execution_verified_insert_guard": "trigger",
    "trg_vse_immutable_update": "trigger",
    "trg_vse_immutable_delete": "trigger",
}


def canonical_success_payload_digest(
    *, verification_run_id: str, execution_run_id: str,
    cleanup_proof_id: str, cleanup_digest: str,
    authority_instance_id: str, runtime_id: str, boot_id: str,
) -> str:
    payload = json.dumps({
        "authority_instance_id": authority_instance_id,
        "boot_id": boot_id,
        "cleanup_digest": cleanup_digest,
        "cleanup_proof_id": cleanup_proof_id,
        "execution_run_id": execution_run_id,
        "runtime_id": runtime_id,
        "verification_run_id": verification_run_id,
    }, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def require_canonical_success(
    connection: sqlite3.Connection,
    authority: Any,
    *,
    verification_run_id: str,
    execution_run_id: str | None = None,
) -> None:
    """Reload and verify every success binding before returning trusted state."""
    authority.verify_storage()
    run = connection.execute(
        "SELECT verification_run_id,execution_run_id,status "
        "FROM plan_verification_runs WHERE verification_run_id=?",
        (verification_run_id,),
    ).fetchone()
    if run is None or str(run[2]) != "passed":
        raise PermissionError("trusted success requires a persisted PASSED run")
    persisted_execution_id = str(run[1])
    if execution_run_id is not None and persisted_execution_id != execution_run_id:
        raise PermissionError("verification success execution binding mismatch")
    evidence = connection.execute(
        "SELECT verification_run_id,execution_run_id,cleanup_proof_id,"
        "cleanup_digest,authority_instance_id,runtime_id,boot_id,payload_digest "
        "FROM verification_success_evidence WHERE verification_run_id=?",
        (verification_run_id,),
    ).fetchone()
    if evidence is None:
        raise PermissionError("persisted PASSED status lacks authority evidence")
    if str(evidence[0]) != verification_run_id or str(evidence[1]) != persisted_execution_id:
        raise PermissionError("verification success evidence identity mismatch")
    recomputed = canonical_success_payload_digest(
        verification_run_id=str(evidence[0]),
        execution_run_id=str(evidence[1]),
        cleanup_proof_id=str(evidence[2]),
        cleanup_digest=str(evidence[3]),
        authority_instance_id=str(evidence[4]),
        runtime_id=str(evidence[5]),
        boot_id=str(evidence[6]),
    )
    if recomputed != str(evidence[7]):
        raise PermissionError("verification success evidence digest mismatch")
    authority.require_success(verification_run_id, recomputed)


def _authority_event_payload(
    runtime_id: str, boot_id: str, event_type: str,
    detail: dict[str, Any], created_at: float,
) -> str:
    return json.dumps({
        "runtime_id": runtime_id,
        "boot_id": boot_id,
        "event_type": event_type,
        "detail": detail,
        "created_at": created_at,
    }, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _append_authority_event(
    ledger: sqlite3.Connection, runtime_id: str, boot_id: str,
    event_type: str, detail: dict[str, Any],
) -> None:
    row = ledger.execute(
        "SELECT event_hash FROM authority_events ORDER BY sequence DESC LIMIT 1"
    ).fetchone()
    previous_hash = str(row[0]) if row is not None else "0" * 64
    created_at = time.time()
    payload = _authority_event_payload(
        runtime_id, boot_id, event_type, detail, created_at
    )
    event_hash = hashlib.sha256(
        f"{previous_hash}\n{payload}".encode("utf-8")
    ).hexdigest()
    ledger.execute(
        "INSERT INTO authority_events(runtime_id,boot_id,event_type,payload_json,"
        "previous_hash,event_hash,created_at) VALUES(?,?,?,?,?,?,?)",
        (runtime_id, boot_id, event_type, payload, previous_hash, event_hash, created_at),
    )


def _verify_authority_event_chain(ledger: sqlite3.Connection) -> None:
    previous_hash = "0" * 64
    rows = ledger.execute(
        "SELECT payload_json,previous_hash,event_hash FROM authority_events "
        "ORDER BY sequence"
    ).fetchall()
    for payload, stored_previous, stored_hash in rows:
        expected = hashlib.sha256(
            f"{previous_hash}\n{payload}".encode("utf-8")
        ).hexdigest()
        if stored_previous != previous_hash or stored_hash != expected:
            raise PermissionError("verification authority ledger hash chain is corrupt")
        previous_hash = str(stored_hash)


@dataclass(frozen=True)
class AuthorityLedgerObjectIdentity:
    path: Path
    dev: int
    ino: int
    uid: int
    gid: int
    mode: int
    nlink: int


def _identity_from_path(path: Path) -> AuthorityLedgerObjectIdentity:
    value = path.lstat()
    if not stat.S_ISREG(value.st_mode) and not stat.S_ISDIR(value.st_mode):
        raise PermissionError("verification authority ledger storage has unsafe type")
    return AuthorityLedgerObjectIdentity(
        path=path,
        dev=value.st_dev,
        ino=value.st_ino,
        uid=value.st_uid,
        gid=value.st_gid,
        mode=stat.S_IMODE(value.st_mode),
        nlink=value.st_nlink,
    )


def _create_exclusive_ledger_file(path: Path) -> AuthorityLedgerObjectIdentity:
    flags = (
        os.O_CREAT | os.O_EXCL | os.O_RDWR | os.O_NOFOLLOW
        | getattr(os, "O_CLOEXEC", 0)
    )
    fd = os.open(path, flags, 0o600)
    try:
        value = os.fstat(fd)
        if (
            not stat.S_ISREG(value.st_mode)
            or value.st_uid != os.getuid()
            or stat.S_IMODE(value.st_mode) != 0o600
            or value.st_nlink != 1
        ):
            raise PermissionError("verification authority ledger file is unsafe")
        return AuthorityLedgerObjectIdentity(
            path=path,
            dev=value.st_dev,
            ino=value.st_ino,
            uid=value.st_uid,
            gid=value.st_gid,
            mode=stat.S_IMODE(value.st_mode),
            nlink=value.st_nlink,
        )
    finally:
        os.close(fd)


def _prepare_authority_ledger(
    database_parent: Path,
) -> tuple[Path, AuthorityLedgerObjectIdentity, AuthorityLedgerObjectIdentity]:
    directory = database_parent / (
        f".khaos-verification-authority-{secrets.token_hex(24)}"
    )
    os.mkdir(directory, 0o700)
    database = directory / "authority-ledger.sqlite"
    database_identity = _create_exclusive_ledger_file(database)
    directory_identity = _identity_from_path(directory)
    if directory_identity.uid != os.getuid() or directory_identity.mode != 0o700:
        raise PermissionError("verification authority ledger directory is unsafe")
    return database, directory_identity, database_identity


def _verify_ledger_identity(
    expected: AuthorityLedgerObjectIdentity,
    *,
    required_mode: int,
    check_nlink: bool = True,
) -> None:
    actual = _identity_from_path(expected.path)
    if (
        actual.dev,
        actual.ino,
        actual.uid,
        actual.gid,
        actual.mode,
    ) != (
        expected.dev,
        expected.ino,
        expected.uid,
        expected.gid,
        required_mode,
    ) or (check_nlink and actual.nlink != expected.nlink):
        raise PermissionError("verification authority ledger identity drift")


def _open_locked_authority_ledger(
    database: Path,
    directory_identity: AuthorityLedgerObjectIdentity,
    database_identity: AuthorityLedgerObjectIdentity,
) -> sqlite3.Connection:
    _verify_ledger_identity(
        directory_identity, required_mode=0o700, check_nlink=False
    )
    _verify_ledger_identity(database_identity, required_mode=0o600)
    ledger = sqlite3.connect(f"file:{database}?mode=rw", uri=True, timeout=0.1)
    try:
        journal_mode = str(ledger.execute("PRAGMA journal_mode=WAL").fetchone()[0])
        if journal_mode.casefold() != "wal":
            raise PermissionError("verification authority ledger requires WAL mode")
        locking_mode = str(
            ledger.execute("PRAGMA locking_mode=EXCLUSIVE").fetchone()[0]
        )
        if locking_mode.casefold() != "exclusive":
            raise PermissionError("verification authority ledger requires exclusive locking")
        ledger.execute("PRAGMA synchronous=FULL")
        ledger.execute("BEGIN EXCLUSIVE")
        ledger.execute(
            "CREATE TABLE IF NOT EXISTS _authority_ledger_bootstrap(id INTEGER)"
        )
        ledger.commit()
        ledger.execute("BEGIN EXCLUSIVE")
        ledger.execute("DROP TABLE _authority_ledger_bootstrap")
        ledger.commit()
        return ledger
    except Exception:
        ledger.rollback()
        ledger.close()
        raise


def _pin_authority_ledger_objects(
    database: Path,
) -> tuple[int, dict[str, tuple[int, AuthorityLedgerObjectIdentity]], set[str]]:
    directory_fd = os.open(
        database.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    )
    objects: dict[str, tuple[int, AuthorityLedgerObjectIdentity]] = {}
    absent: set[str] = set()
    try:
        for suffix in ("", "-wal", "-shm"):
            path = Path(f"{database}{suffix}")
            try:
                fd = os.open(
                    path.name,
                    os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
                    dir_fd=directory_fd,
                )
            except FileNotFoundError:
                absent.add(suffix)
                continue
            value = os.fstat(fd)
            if (
                not stat.S_ISREG(value.st_mode)
                or value.st_uid != os.getuid()
                or value.st_nlink != 1
            ):
                os.close(fd)
                raise PermissionError("verification authority ledger object is unsafe")
            os.fchmod(fd, 0o400)
            objects[suffix] = (
                fd,
                AuthorityLedgerObjectIdentity(
                    path, value.st_dev, value.st_ino, value.st_uid, value.st_gid,
                    0o400, value.st_nlink,
                ),
            )
        return directory_fd, objects, absent
    except Exception:
        for fd, _identity in objects.values():
            os.close(fd)
        os.close(directory_fd)
        raise


def _verify_pinned_authority_ledger(
    database: Path,
    directory_identity: AuthorityLedgerObjectIdentity,
    directory_fd: int,
    objects: dict[str, tuple[int, AuthorityLedgerObjectIdentity]],
    absent: set[str],
) -> None:
    _verify_ledger_identity(
        directory_identity, required_mode=0o700, check_nlink=False
    )
    opened_directory = os.fstat(directory_fd)
    if (
        opened_directory.st_dev,
        opened_directory.st_ino,
        opened_directory.st_uid,
        opened_directory.st_gid,
        stat.S_IMODE(opened_directory.st_mode),
    ) != (
        directory_identity.dev,
        directory_identity.ino,
        directory_identity.uid,
        directory_identity.gid,
        0o700,
    ):
        raise PermissionError("verification authority ledger directory drift")
    for suffix, (fd, expected) in objects.items():
        opened = os.fstat(fd)
        entry = os.stat(
            expected.path.name, dir_fd=directory_fd, follow_symlinks=False
        )
        if (
            not stat.S_ISREG(opened.st_mode)
            or not stat.S_ISREG(entry.st_mode)
            or entry.st_nlink != 1
            or (
                opened.st_dev, opened.st_ino, opened.st_uid, opened.st_gid,
                entry.st_dev, entry.st_ino, stat.S_IMODE(entry.st_mode),
            ) != (
                expected.dev, expected.ino, expected.uid, expected.gid,
                expected.dev, expected.ino, 0o400,
            )
        ):
            raise PermissionError(
                f"verification authority ledger {suffix or 'database'} identity drift"
            )
    for suffix in absent:
        try:
            os.stat(
                f"{database.name}{suffix}",
                dir_fd=directory_fd,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            continue
        raise PermissionError("verification authority ledger sidecar appeared")


def _authority_process_main(
    connection: Any,
    capability: str,
    ledger_path: str,
    runtime_id: str,
    boot_id: str,
    directory_identity: AuthorityLedgerObjectIdentity,
    database_identity: AuthorityLedgerObjectIdentity,
) -> None:
    """Own the authoritative proof/success ledger behind an inherited pipe."""
    database = Path(ledger_path)
    try:
        ledger = _open_locked_authority_ledger(
            database, directory_identity, database_identity
        )
        ledger.executescript(
        "CREATE TABLE IF NOT EXISTS proofs(boot_id TEXT NOT NULL,proof_id TEXT NOT NULL,"
        "run_id TEXT NOT NULL,digest TEXT NOT NULL,PRIMARY KEY(boot_id,proof_id),"
        "UNIQUE(boot_id,run_id));"
        "CREATE TABLE IF NOT EXISTS successes(boot_id TEXT NOT NULL,run_id TEXT NOT NULL,"
        "digest TEXT NOT NULL,PRIMARY KEY(boot_id,run_id));"
        "CREATE TABLE IF NOT EXISTS authority_events(sequence INTEGER PRIMARY KEY AUTOINCREMENT,"
        "runtime_id TEXT NOT NULL,boot_id TEXT NOT NULL,event_type TEXT NOT NULL,"
        "payload_json TEXT NOT NULL,previous_hash TEXT NOT NULL,event_hash TEXT NOT NULL UNIQUE,"
        "created_at REAL NOT NULL);"
        )
        _verify_authority_event_chain(ledger)
        _append_authority_event(
            ledger, runtime_id, boot_id, "boot-started", {"pid": os.getpid()}
        )
        ledger.commit()
        directory_fd, objects, absent = _pin_authority_ledger_objects(database)
        pinned_database = objects.get("")
        if pinned_database is None or (
            pinned_database[1].dev,
            pinned_database[1].ino,
            pinned_database[1].uid,
            pinned_database[1].gid,
            pinned_database[1].nlink,
        ) != (
            database_identity.dev,
            database_identity.ino,
            database_identity.uid,
            database_identity.gid,
            database_identity.nlink,
        ):
            raise PermissionError("verification authority ledger database replaced")
        _verify_pinned_authority_ledger(
            database, directory_identity, directory_fd, objects, absent
        )
    except Exception as exc:
        connection.send(("error", f"{type(exc).__name__}: {exc}"))
        connection.close()
        return
    connection.send(("ready", os.getpid()))
    expected_sequence = 1
    try:
        while True:
            try:
                request = connection.recv()
            except EOFError:
                break
            token, sequence, operation, arguments = request
            _verify_pinned_authority_ledger(
                database, directory_identity, directory_fd, objects, absent
            )
            if token != capability or sequence != expected_sequence:
                _append_authority_event(
                    ledger, runtime_id, boot_id, "request-rejected",
                    {"operation": str(operation), "reason": "capability-or-sequence"},
                )
                ledger.commit()
                _verify_pinned_authority_ledger(
                    database, directory_identity, directory_fd, objects, absent
                )
                connection.send((False, "invalid authority capability or replay"))
                continue
            expected_sequence += 1
            if operation == "shutdown":
                _append_authority_event(
                    ledger, runtime_id, boot_id, "boot-stopped", {}
                )
                ledger.commit()
                _verify_pinned_authority_ledger(
                    database, directory_identity, directory_fd, objects, absent
                )
                connection.send((True, None))
                break
            try:
                if operation == "authorize-proof":
                    proof_id, run_id, digest = arguments
                    row = ledger.execute(
                        "SELECT run_id,digest FROM proofs WHERE boot_id=? AND proof_id=?",
                        (boot_id, proof_id),
                    ).fetchone()
                    if row is None:
                        ledger.execute(
                            "INSERT INTO proofs VALUES (?,?,?,?)",
                            (boot_id, proof_id, run_id, digest),
                        )
                    elif tuple(row) != (run_id, digest):
                        raise PermissionError("cleanup proof authority conflict")
                elif operation == "require-proof":
                    proof_id, run_id, digest = arguments
                    row = ledger.execute(
                        "SELECT run_id,digest FROM proofs WHERE boot_id=? AND proof_id=?",
                        (boot_id, proof_id),
                    ).fetchone()
                    if row is None or tuple(row) != (run_id, digest):
                        raise PermissionError("cleanup proof is not authority-issued")
                elif operation == "record-success":
                    run_id, digest = arguments
                    row = ledger.execute(
                        "SELECT digest FROM successes WHERE boot_id=? AND run_id=?",
                        (boot_id, run_id),
                    ).fetchone()
                    if row is None:
                        ledger.execute(
                            "INSERT INTO successes VALUES (?,?,?)",
                            (boot_id, run_id, digest),
                        )
                    elif row[0] != digest:
                        raise PermissionError("success authority conflict")
                elif operation == "require-success":
                    run_id, digest = arguments
                    row = ledger.execute(
                        "SELECT digest FROM successes WHERE boot_id=? AND run_id=?",
                        (boot_id, run_id),
                    ).fetchone()
                    if row is None or row[0] != digest:
                        raise PermissionError("success lacks authority evidence")
                else:
                    raise PermissionError("unknown verification authority command")
                _append_authority_event(
                    ledger, runtime_id, boot_id, "request-accepted",
                    {"operation": operation, "arguments_digest": hashlib.sha256(
                        json.dumps(arguments, separators=(",", ":")).encode("utf-8")
                    ).hexdigest()},
                )
                ledger.commit()
                _verify_pinned_authority_ledger(
                    database, directory_identity, directory_fd, objects, absent
                )
                connection.send((True, None))
            except Exception as exc:
                ledger.rollback()
                _append_authority_event(
                    ledger, runtime_id, boot_id, "request-rejected",
                    {"operation": str(operation), "reason": type(exc).__name__},
                )
                ledger.commit()
                _verify_pinned_authority_ledger(
                    database, directory_identity, directory_fd, objects, absent
                )
                connection.send((False, f"{type(exc).__name__}: {exc}"))
    finally:
        ledger.close()
        for fd, _identity in objects.values():
            os.close(fd)
        os.close(directory_fd)
        connection.close()


@dataclass(frozen=True)
class VerificationDatabaseObjectIdentity:
    path: Path
    dev: int
    ino: int
    uid: int
    gid: int
    mode: int


class VerificationWriteCapability:
    """Opaque capability; only the registry can construct instances."""

    __slots__ = ("_capability_id",)

    def __init__(self, *_: Any, **__: Any) -> None:
        raise TypeError("VerificationWriteCapability cannot be constructed")


class VerificationReadHandle:
    """Fixed-query read facade; it never returns its SQLite connection."""

    __slots__ = ("__connection", "__authority", "__owns_connection")

    def __init__(
        self, connection: sqlite3.Connection, authority: Any,
        *, owns_connection: bool = True,
    ) -> None:
        self.__connection = connection
        self.__authority = authority
        self.__owns_connection = owns_connection

    def verification_status(self, verification_run_id: str) -> str | None:
        self.__authority.verify_storage()
        row = self.__connection.execute(
            "SELECT status FROM plan_verification_runs "
            "WHERE verification_run_id=?", (verification_run_id,),
        ).fetchone()
        if row is None:
            return None
        status = str(row[0])
        if status == "passed":
            require_canonical_success(
                self.__connection, self.__authority,
                verification_run_id=verification_run_id,
            )
        return status

    def execution_status(self, execution_run_id: str) -> str | None:
        self.__authority.verify_storage()
        row = self.__connection.execute(
            "SELECT status FROM plan_execution_runs WHERE execution_run_id=?",
            (execution_run_id,),
        ).fetchone()
        if row is None:
            return None
        status = str(row[0])
        if status == "verified":
            run = self.__connection.execute(
                "SELECT verification_run_id FROM plan_verification_runs "
                "WHERE execution_run_id=?",
                (execution_run_id,),
            ).fetchone()
            if run is None:
                raise PermissionError("persisted VERIFIED status lacks authority evidence")
            require_canonical_success(
                self.__connection, self.__authority,
                verification_run_id=str(run[0]),
                execution_run_id=execution_run_id,
            )
        return status

    def close(self) -> None:
        if self.__owns_connection:
            self.__connection.close()


class VerificationWriteAuthority:
    """Single boot-scoped owner of the existing writable SQLite handle."""

    def __init__(self, *_: Any, **__: Any) -> None:
        raise TypeError("VerificationWriteAuthority must be runtime-issued")

    @classmethod
    def _activate(
        cls, connection: sqlite3.Connection, *, runtime_id: str, boot_id: str,
    ) -> "VerificationWriteAuthority":
        row = connection.execute("PRAGMA database_list").fetchone()
        database_path = str(row[2]) if row is not None else ""
        if not database_path:
            raise PermissionError(
                "production verification authority requires a file SQLite database"
            )
        authority = object.__new__(cls)
        authority._connection = connection
        authority._runtime_id = runtime_id
        authority._boot_id = boot_id
        authority._authority_id = os.urandom(32).hex()
        authority._lock = threading.RLock()
        authority._active = True
        authority._ipc_capability = secrets.token_hex(32)
        authority._ipc_sequence = 0
        authority._database_path = Path(os.path.abspath(database_path))
        journal_mode = str(connection.execute("PRAGMA journal_mode=WAL").fetchone()[0])
        if journal_mode.casefold() != "wal":
            raise PermissionError("verification authority requires SQLite WAL mode")
        locking_mode = str(
            connection.execute("PRAGMA locking_mode=EXCLUSIVE").fetchone()[0]
        )
        if locking_mode.casefold() != "exclusive":
            raise PermissionError("verification authority requires exclusive locking")
        # A committed write is required for EXCLUSIVE locking_mode to acquire
        # and retain the OS lock.  If another pre-opened writer currently owns
        # a transaction this fails closed before the authority becomes ready.
        connection.execute("BEGIN EXCLUSIVE")
        try:
            connection.execute(
                "CREATE TABLE IF NOT EXISTS _verification_authority_bootstrap "
                "(id INTEGER)"
            )
            connection.commit()
            connection.execute("BEGIN EXCLUSIVE")
            connection.execute(
                "INSERT INTO _verification_authority_bootstrap VALUES (1)"
            )
            connection.commit()
            connection.execute("BEGIN EXCLUSIVE")
            connection.execute("DROP TABLE _verification_authority_bootstrap")
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        (
            authority._ledger_path,
            authority._ledger_directory_identity,
            authority._ledger_database_identity,
        ) = _prepare_authority_ledger(authority._database_path.parent)
        process_context = multiprocessing.get_context("spawn")
        parent_connection, child_connection = process_context.Pipe()
        authority._ipc_connection = parent_connection
        authority._authority_process = process_context.Process(
            target=_authority_process_main,
            args=(
                child_connection,
                authority._ipc_capability,
                str(authority._ledger_path),
                runtime_id,
                boot_id,
                authority._ledger_directory_identity,
                authority._ledger_database_identity,
            ),
            name="khaos-verification-authority",
            daemon=True,
        )
        authority._authority_process.start()
        child_connection.close()
        if not parent_connection.poll(10):
            authority._authority_process.terminate()
            raise RuntimeError("verification authority process did not start")
        ready, ready_detail = parent_connection.recv()
        if ready != "ready":
            authority._authority_process.join(timeout=5)
            raise RuntimeError(
                f"verification authority process startup failed: {ready_detail}"
            )
        authority._authority_process_id = ready_detail
        authority._schema_digest = authority._compute_schema_digest()
        authority._parent_fd = authority._open_directory_chain(
            authority._database_path.parent,
        )
        authority._parent_identity = authority._identity_from_fd(
            authority._parent_fd, authority._database_path.parent,
        )
        authority._objects: dict[str, tuple[int, VerificationDatabaseObjectIdentity]] = {}
        authority._absent_objects: set[str] = set()
        for suffix in ("", "-wal", "-shm"):
            path = Path(f"{authority._database_path}{suffix}")
            try:
                fd = os.open(
                    path.name,
                    os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
                    dir_fd=authority._parent_fd,
                )
            except FileNotFoundError as exc:
                if suffix == "-shm" and locking_mode.casefold() == "exclusive":
                    # SQLite may keep WAL-index state in process memory under
                    # EXCLUSIVE locking mode.  Pin the absence just as strictly
                    # as an inode: a later sidecar appearance is drift.
                    authority._absent_objects.add(suffix)
                    continue
                raise PermissionError(
                    f"verification authority storage missing: {suffix or 'database'}"
                ) from exc
            os.fchmod(fd, 0o400)
            authority._objects[suffix] = (fd, authority._identity_from_fd(fd, path))
        authority.verify_storage()
        return authority

    @staticmethod
    def _open_directory_chain(path: Path) -> int:
        current = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            for part in path.parts[1:]:
                next_fd = os.open(
                    part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                    dir_fd=current,
                )
                os.close(current)
                current = next_fd
            return current
        except Exception:
            os.close(current)
            raise

    @staticmethod
    def _identity_from_fd(fd: int, path: Path) -> VerificationDatabaseObjectIdentity:
        value = os.fstat(fd)
        if not stat.S_ISREG(value.st_mode) and not stat.S_ISDIR(value.st_mode):
            raise PermissionError("verification authority storage has unsafe type")
        return VerificationDatabaseObjectIdentity(
            path, value.st_dev, value.st_ino, value.st_uid, value.st_gid,
            stat.S_IMODE(value.st_mode),
        )

    def _compute_schema_digest(self) -> str:
        protected_tables = tuple(
            name for name, object_type in PROTECTED_SCHEMA_OBJECTS.items()
            if object_type == "table"
        )
        placeholders = ",".join("?" for _ in protected_tables)
        rows = self._connection.execute(
            "SELECT type,name,tbl_name,sql FROM sqlite_master "
            "WHERE name NOT LIKE 'sqlite_%' AND "
            f"(name IN ({placeholders}) OR tbl_name IN ({placeholders})) "
            "ORDER BY type,name",
            protected_tables + protected_tables,
        ).fetchall()
        actual = {str(row[1]): str(row[0]) for row in rows}
        if actual != PROTECTED_SCHEMA_OBJECTS:
            missing = sorted(set(PROTECTED_SCHEMA_OBJECTS) - set(actual))
            extra_or_wrong = sorted(
                name for name, object_type in actual.items()
                if PROTECTED_SCHEMA_OBJECTS.get(name) != object_type
            )
            raise PermissionError(
                "verification database schema/trigger digest drift; "
                "protected manifest mismatch: "
                f"missing={missing}, wrong_type={extra_or_wrong}"
            )
        canonical = "\n".join(
            "|".join("" if item is None else str(item) for item in row)
            for row in rows
        )
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    @property
    def authority_id(self) -> str:
        return self._authority_id

    @property
    def boot_id(self) -> str:
        return self._boot_id

    @property
    def runtime_id(self) -> str:
        return self._runtime_id

    @property
    def authority_process_id(self) -> int:
        return self._authority_process_id

    @property
    def ledger_path(self) -> Path:
        return self._ledger_path

    def _rpc(self, operation: str, *arguments: str) -> None:
        if not self._active or not self._authority_process.is_alive():
            raise PermissionError("verification write authority is revoked")
        self._ipc_sequence += 1
        self._ipc_connection.send((
            self._ipc_capability, self._ipc_sequence, operation, arguments,
        ))
        if not self._ipc_connection.poll(10):
            raise RuntimeError("verification authority IPC timed out")
        accepted, error = self._ipc_connection.recv()
        if not accepted:
            raise PermissionError(error)

    def verify_storage(self) -> None:
        if not self._active:
            raise PermissionError("verification write authority is revoked")
        current_parent = os.fstat(self._parent_fd)
        expected_parent = self._parent_identity
        if (
            current_parent.st_dev, current_parent.st_ino, current_parent.st_uid,
            current_parent.st_gid, stat.S_IMODE(current_parent.st_mode),
        ) != (
            expected_parent.dev, expected_parent.ino, expected_parent.uid,
            expected_parent.gid, expected_parent.mode,
        ):
            raise PermissionError("verification database parent identity drift")
        ancestor_fd = os.open(
            str(self._database_path.parent.parent),
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
        )
        try:
            parent_entry = os.stat(
                self._database_path.parent.name, dir_fd=ancestor_fd,
                follow_symlinks=False,
            )
        finally:
            os.close(ancestor_fd)
        if (
            parent_entry.st_dev, parent_entry.st_ino, parent_entry.st_uid,
            parent_entry.st_gid, stat.S_IMODE(parent_entry.st_mode),
        ) != (
            expected_parent.dev, expected_parent.ino, expected_parent.uid,
            expected_parent.gid, expected_parent.mode,
        ):
            raise PermissionError("verification database parent directory replaced")
        for suffix, (fd, expected) in self._objects.items():
            opened = os.fstat(fd)
            entry = os.stat(
                expected.path.name, dir_fd=self._parent_fd,
                follow_symlinks=False,
            )
            if not stat.S_ISREG(opened.st_mode) or not stat.S_ISREG(entry.st_mode):
                raise PermissionError("verification database object is not regular")
            actual = (
                opened.st_dev, opened.st_ino, opened.st_uid, opened.st_gid,
                stat.S_IMODE(entry.st_mode), entry.st_dev, entry.st_ino,
            )
            wanted = (
                expected.dev, expected.ino, expected.uid, expected.gid,
                0o400, expected.dev, expected.ino,
            )
            if actual != wanted:
                raise PermissionError(
                    f"verification database {suffix or 'file'} identity drift"
                )
        for suffix in self._absent_objects:
            try:
                os.stat(
                    f"{self._database_path.name}{suffix}",
                    dir_fd=self._parent_fd, follow_symlinks=False,
                )
            except FileNotFoundError:
                continue
            raise PermissionError(
                f"verification database {suffix} unexpected sidecar appeared"
            )
        if self._compute_schema_digest() != self._schema_digest:
            raise PermissionError("verification database schema/trigger digest drift")

    @contextmanager
    def write_scope(self) -> Iterator[None]:
        with self._lock:
            self.verify_storage()
            yield
            self.verify_storage()

    def authorize_cleanup_proof(
        self, proof_id: str, verification_run_id: str, cleanup_digest: str,
    ) -> None:
        with self._lock:
            self.verify_storage()
            self._rpc(
                "authorize-proof", proof_id, verification_run_id,
                cleanup_digest,
            )

    def require_cleanup_proof(
        self, proof_id: str, verification_run_id: str, cleanup_digest: str,
    ) -> None:
        self.verify_storage()
        self._rpc("require-proof", proof_id, verification_run_id, cleanup_digest)

    def record_success(self, verification_run_id: str, payload_digest: str) -> None:
        self.verify_storage()
        self._rpc("record-success", verification_run_id, payload_digest)

    def require_success(self, verification_run_id: str, payload_digest: str) -> None:
        self.verify_storage()
        self._rpc("require-success", verification_run_id, payload_digest)

    def open_readonly(self) -> VerificationReadHandle:
        self.verify_storage()
        # EXCLUSIVE mode intentionally prevents opening a second SQLite
        # connection.  The fixed-query facade shares the authority-owned
        # handle but never exposes execute/cursor and never closes the owner.
        return VerificationReadHandle(
            self._connection, self, owns_connection=False,
        )

    def close(self) -> None:
        with self._lock:
            if not self._active:
                return
            shutdown_error: Exception | None = None
            try:
                self._rpc("shutdown")
            except Exception as exc:
                shutdown_error = exc
            finally:
                self._active = False
                self._ipc_connection.close()
                self._authority_process.join(timeout=5)
                if self._authority_process.is_alive():
                    self._authority_process.terminate()
                    self._authority_process.join(timeout=5)
            for fd, identity in self._objects.values():
                try:
                    os.fchmod(fd, 0o600)
                finally:
                    os.close(fd)
            try:
                self._connection.execute("PRAGMA locking_mode=NORMAL")
            except sqlite3.Error:
                pass
            self._connection.close()
            os.close(self._parent_fd)
            if shutdown_error is not None:
                raise shutdown_error


class VerificationAuthorityRegistry:
    """Issues one authority per Runtime boot and rejects reuse."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._authorities: dict[str, VerificationWriteAuthority] = {}

    def issue(
        self, connection: sqlite3.Connection, *, runtime_id: str, boot_id: str,
    ) -> VerificationWriteAuthority:
        key = f"{runtime_id}:{boot_id}"
        with self._lock:
            if key in self._authorities:
                raise PermissionError("verification write authority already issued")
            authority = VerificationWriteAuthority._activate(
                connection, runtime_id=runtime_id, boot_id=boot_id,
            )
            self._authorities[key] = authority
            return authority

    def revoke(self, runtime_id: str, boot_id: str) -> None:
        key = f"{runtime_id}:{boot_id}"
        with self._lock:
            authority = self._authorities.pop(key, None)
        if authority is not None:
            authority.close()


VERIFICATION_AUTHORITIES = VerificationAuthorityRegistry()
