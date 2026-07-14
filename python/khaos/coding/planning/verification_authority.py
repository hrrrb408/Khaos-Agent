"""Boot-scoped write authority for the trusted-verification database.

The authority is an in-process production boundary: it protects an already
opened SQLite writer with file permissions, pins database/parent/WAL/SHM
identities, and issues opaque boot-scoped capabilities to the verification
store.  It does not claim to defend hostile Python executing in the Khaos
runtime process or an OS administrator.  Those principals can inspect process
memory or change owner-controlled permissions and are outside this boundary.
"""
from __future__ import annotations

import hashlib
import multiprocessing
import os
import secrets
import shutil
import sqlite3
import stat
import tempfile
import threading
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator
from urllib.parse import quote


def _authority_process_main(connection: Any, capability: str) -> None:
    """Own the authoritative proof/success ledger behind an inherited pipe."""
    root = Path(tempfile.mkdtemp(prefix="khaos-verification-authority-"))
    database = root / "authority.sqlite"
    ledger = sqlite3.connect(database)
    ledger.executescript(
        "CREATE TABLE proofs(proof_id TEXT PRIMARY KEY,run_id TEXT NOT NULL,"
        "digest TEXT NOT NULL,UNIQUE(run_id));"
        "CREATE TABLE successes(run_id TEXT PRIMARY KEY,digest TEXT NOT NULL);"
    )
    ledger.execute("PRAGMA journal_mode=WAL")
    ledger.commit()
    ledger.execute("CREATE TABLE bootstrap(value INTEGER)")
    ledger.commit()
    ledger.execute("DROP TABLE bootstrap")
    ledger.commit()
    for path in root.iterdir():
        os.chmod(path, 0o400)
    os.chmod(root, 0o500)
    connection.send(("ready", os.getpid()))
    expected_sequence = 1
    try:
        while True:
            request = connection.recv()
            token, sequence, operation, arguments = request
            if token != capability or sequence != expected_sequence:
                connection.send((False, "invalid authority capability or replay"))
                continue
            expected_sequence += 1
            if operation == "shutdown":
                connection.send((True, None))
                break
            try:
                if operation == "authorize-proof":
                    proof_id, run_id, digest = arguments
                    row = ledger.execute(
                        "SELECT run_id,digest FROM proofs WHERE proof_id=?",
                        (proof_id,),
                    ).fetchone()
                    if row is None:
                        ledger.execute(
                            "INSERT INTO proofs VALUES (?,?,?)",
                            (proof_id, run_id, digest),
                        )
                        ledger.commit()
                    elif tuple(row) != (run_id, digest):
                        raise PermissionError("cleanup proof authority conflict")
                    connection.send((True, None))
                elif operation == "require-proof":
                    proof_id, run_id, digest = arguments
                    row = ledger.execute(
                        "SELECT run_id,digest FROM proofs WHERE proof_id=?",
                        (proof_id,),
                    ).fetchone()
                    if row is None or tuple(row) != (run_id, digest):
                        raise PermissionError("cleanup proof is not authority-issued")
                    connection.send((True, None))
                elif operation == "record-success":
                    run_id, digest = arguments
                    row = ledger.execute(
                        "SELECT digest FROM successes WHERE run_id=?", (run_id,),
                    ).fetchone()
                    if row is None:
                        ledger.execute(
                            "INSERT INTO successes VALUES (?,?)", (run_id, digest),
                        )
                        ledger.commit()
                    elif row[0] != digest:
                        raise PermissionError("success authority conflict")
                    connection.send((True, None))
                elif operation == "require-success":
                    run_id, digest = arguments
                    row = ledger.execute(
                        "SELECT digest FROM successes WHERE run_id=?", (run_id,),
                    ).fetchone()
                    if row is None or row[0] != digest:
                        raise PermissionError("success lacks authority evidence")
                    connection.send((True, None))
                else:
                    raise PermissionError("unknown verification authority command")
            except Exception as exc:
                ledger.rollback()
                connection.send((False, f"{type(exc).__name__}: {exc}"))
    finally:
        ledger.close()
        connection.close()
        try:
            os.chmod(root, 0o700)
            for path in root.iterdir():
                os.chmod(path, 0o600)
            shutil.rmtree(root)
        except OSError:
            pass


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

    __slots__ = ("__connection", "__authority")

    def __init__(self, connection: sqlite3.Connection, authority: Any) -> None:
        self.__connection = connection
        self.__authority = authority

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
            evidence = self.__connection.execute(
                "SELECT payload_digest FROM verification_success_evidence "
                "WHERE verification_run_id=?", (verification_run_id,),
            ).fetchone()
            if evidence is None:
                raise PermissionError("persisted PASSED status lacks authority evidence")
            self.__authority.require_success(verification_run_id, str(evidence[0]))
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
            evidence = self.__connection.execute(
                "SELECT verification_run_id,payload_digest "
                "FROM verification_success_evidence WHERE execution_run_id=?",
                (execution_run_id,),
            ).fetchone()
            if evidence is None:
                raise PermissionError("persisted VERIFIED status lacks authority evidence")
            self.__authority.require_success(str(evidence[0]), str(evidence[1]))
        return status

    def close(self) -> None:
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
        process_context = multiprocessing.get_context("spawn")
        parent_connection, child_connection = process_context.Pipe()
        authority._ipc_connection = parent_connection
        authority._authority_process = process_context.Process(
            target=_authority_process_main,
            args=(child_connection, authority._ipc_capability),
            name="khaos-verification-authority",
            daemon=True,
        )
        authority._authority_process.start()
        child_connection.close()
        if not parent_connection.poll(10):
            authority._authority_process.terminate()
            raise RuntimeError("verification authority process did not start")
        ready, authority._authority_process_id = parent_connection.recv()
        if ready != "ready":
            raise RuntimeError("verification authority process startup failed")
        authority._database_path = Path(os.path.abspath(database_path))
        journal_mode = str(connection.execute("PRAGMA journal_mode=WAL").fetchone()[0])
        if journal_mode.casefold() != "wal":
            raise PermissionError("verification authority requires SQLite WAL mode")
        connection.execute("CREATE TABLE IF NOT EXISTS _verification_authority_bootstrap (id INTEGER)")
        connection.commit()
        connection.execute("DROP TABLE _verification_authority_bootstrap")
        connection.commit()
        authority._schema_digest = authority._compute_schema_digest()
        authority._parent_fd = authority._open_directory_chain(
            authority._database_path.parent,
        )
        authority._parent_identity = authority._identity_from_fd(
            authority._parent_fd, authority._database_path.parent,
        )
        authority._objects: dict[str, tuple[int, VerificationDatabaseObjectIdentity]] = {}
        for suffix in ("", "-wal", "-shm"):
            path = Path(f"{authority._database_path}{suffix}")
            try:
                fd = os.open(
                    path.name,
                    os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
                    dir_fd=authority._parent_fd,
                )
            except FileNotFoundError as exc:
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
        rows = self._connection.execute(
            "SELECT type,name,tbl_name,sql FROM sqlite_master "
            "WHERE name LIKE 'plan_verification_%' "
            "OR name LIKE 'verification_%' OR name LIKE 'trg_verification_%' "
            "ORDER BY type,name"
        ).fetchall()
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
        uri = f"file:{quote(str(self._database_path))}?mode=ro"
        connection = sqlite3.connect(uri, uri=True)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA query_only=ON")
        denied = {
            sqlite3.SQLITE_ATTACH, sqlite3.SQLITE_DETACH,
            sqlite3.SQLITE_INSERT, sqlite3.SQLITE_UPDATE, sqlite3.SQLITE_DELETE,
            sqlite3.SQLITE_ALTER_TABLE, sqlite3.SQLITE_DROP_TABLE,
            sqlite3.SQLITE_DROP_TRIGGER, sqlite3.SQLITE_DROP_INDEX,
            sqlite3.SQLITE_CREATE_TABLE, sqlite3.SQLITE_CREATE_TRIGGER,
            sqlite3.SQLITE_CREATE_INDEX, sqlite3.SQLITE_PRAGMA,
        }
        connection.set_authorizer(
            lambda action, _one, _two, _db, _source: (
                sqlite3.SQLITE_DENY if action in denied else sqlite3.SQLITE_OK
            )
        )
        return VerificationReadHandle(connection, self)

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
