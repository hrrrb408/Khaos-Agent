"""Structured audit logger backed by SQLite.

AuditLogger is a thin async wrapper over Database.insert_audit_log /
query_audit_logs that normalizes the ``detail`` field to JSON and gives the
rest of Khaos one stable place to record observable events:

- permission decisions (approved / denied / expired)
- tool executions (success / error, with duration)
- API requests (when wired from the Go gateway)

The ``result`` vocabulary is intentionally small and shared across event kinds
so a single ``GET /api/audit?result=denied`` query surfaces every denial
regardless of source.

M1: when ``log_path`` is configured (from the effective policy's
``audit_log_path``), every record is *also* appended as one JSON line to that
file so an operator has a path-stable secondary trail outside the SQLite
database.  The long-lived fd prevents path/symlink substitution, but this is
not cryptographic tamper evidence against another process running as the same
UID.  The
file write is best-effort — a failure to append to the file does NOT suppress
the database write or break the calling flow.

H2: ``resolve_safe_audit_log_path`` only validates the configured filename.
It deliberately performs no filesystem I/O.  ``AuditLogger`` is the single
filesystem authority: it creates/opens the trusted directory chain with
dirfd-relative, no-follow operations and holds the final append fd for its
entire lifetime.
"""

from __future__ import annotations

import asyncio
import gzip
import hashlib
import hmac
import json
import logging
import os
import stat as _stat
import threading
import time
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from khaos.audit.anchor import AuditAnchorError, AuditChainAnchor, anchor_filename
from khaos.time_utils import utc_now_naive

logger = logging.getLogger(__name__)

# Canonical result values. Producers should prefer these; arbitrary strings are
# still accepted for forward compatibility.
RESULT_SUCCESS = "success"
RESULT_DENIED = "denied"
RESULT_ERROR = "error"
RESULT_APPROVED = "approved"
RESULT_EXPIRED = "expired"


# H2: trusted directory for audit log files.  Project-supplied
# ``audit.log_path`` values MUST resolve under this directory (after symlink
# resolution) or they are rejected — an untrusted repo cannot point audit at
# an arbitrary host file (``~/.ssh/authorized_keys``, a FIFO that blocks the
# event loop, a device file, …).  Only the user layer (``~/.khaos/policy.yaml``)
# is allowed to set ``audit.log_path``; the effective policy compiler drops
# the project layer's ``audit_log_path`` entirely.
AUDIT_LOG_TRUSTED_DIR = Path.home() / ".khaos" / "audit"
# The SQLite hash chain remains the authoritative ordered record.  The file
# trail is segmented before it becomes an operationally dangerous append-only
# blob; segments are retained in the same trusted directory for export/archive
# and are never deleted by the logger.
AUDIT_FILE_SEGMENT_BYTES = 64 * 1024 * 1024
# A secondary file trail must not grow without an operator action.  Reaching
# this limit fails only the secondary append (SQLite remains authoritative)
# and tells the operator to run ``archive_segments`` explicitly.
AUDIT_FILE_MAX_BYTES = 512 * 1024 * 1024
AUDIT_ARCHIVE_TOMBSTONE = "audit-archive-tombstones.jsonl"


def resolve_safe_audit_log_path(
    log_path: str | os.PathLike[str] | None,
) -> Path | None:
    """Validate ``log_path`` and return only its safe basename (H2).

    Rules:

    * ``None`` / empty → ``None`` (no file audit; db-only audit remains).
    * Relative paths must be a single basename (no parent components).
    * Absolute paths are accepted only when their lexical parent is exactly
      ``~/.khaos/audit``; symlinks are not resolved here.
    * No directory or file is created/opened.  All filesystem effects belong
      exclusively to :class:`AuditLogger`'s dirfd authority.

    Returns a one-component relative ``Path`` on success, otherwise ``None``.
    """
    if not log_path:
        return None
    raw = Path(str(log_path)).expanduser()
    trusted = AUDIT_LOG_TRUSTED_DIR.expanduser()
    if raw.is_absolute():
        if raw.parent != trusted:
            logger.warning(
                "audit log path %s is not directly under trusted dir %s; "
                "falling back to db-only audit", log_path, trusted,
            )
            return None
        filename = raw.name
    else:
        if len(raw.parts) != 1:
            logger.warning(
                "audit log path %s contains parent components; "
                "falling back to db-only audit", log_path,
            )
            return None
        filename = raw.name
    if not filename or filename in {".", ".."}:
        logger.warning(
            "audit log path %s has no safe basename; falling back to db-only audit",
            log_path,
        )
        return None
    return Path(filename)


def resolve_safe_audit_anchor_path(project_id: str) -> Path:
    """Return the trusted basename used by the local audit chain anchor."""
    return anchor_filename(project_id)


@dataclass
class AuditEntry:
    """One audit record as returned from a query."""

    id: int | None
    action: str
    target: str
    result: str
    detail: dict[str, Any]
    session_id: str | None
    created_at: str | None = None
    # A2-6: principal attribution + context fields.  Older rows (and
    # older callers) leave these as None.
    principal_id: str | None = None
    runtime_id: str | None = None
    task_id: str | None = None
    operation_id: str | None = None
    policy_digest: str | None = None
    project_id: str | None = None
    authority_generation: int | None = None
    source_transport: str | None = None

    @classmethod
    def from_row(cls, row: dict[str, Any]) -> AuditEntry:
        return cls(
            id=int(row["id"]) if row.get("id") is not None else None,
            action=str(row.get("action", "")),
            target=str(row.get("target", "")),
            result=str(row.get("result", "")),
            detail=parse_detail(row.get("detail")),
            session_id=row.get("session_id"),
            created_at=row.get("created_at"),
            principal_id=row.get("principal_id"),
            runtime_id=row.get("runtime_id"),
            task_id=row.get("task_id"),
            operation_id=row.get("operation_id"),
            policy_digest=row.get("policy_digest"),
            project_id=row.get("project_id"),
            authority_generation=row.get("authority_generation"),
            source_transport=row.get("source_transport"),
        )

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        return data


@dataclass(frozen=True, slots=True)
class AuditBinding:
    """Immutable identity attached to one request-scoped audit sink.

    The shared :class:`AuditLogger` remains the only owner of the SQLite
    chain, file descriptor, and anchor.  A binding only carries attribution;
    it cannot close or replace the underlying writer.
    """

    principal_id: str
    project_id: str
    policy_digest: str | None = None
    runtime_id: str | None = None
    source_transport: str | None = None


class BoundAuditLogger:
    """Request-scoped audit facade backed by one shared ``AuditLogger``.

    This object deliberately exposes only logging/query operations.  ``close``
    is a no-op because lifecycle belongs to the shared root logger; allowing a
    request handler to close that logger would race unrelated requests.
    """

    def __init__(self, root: AuditLogger, binding: AuditBinding) -> None:
        self._root = root
        self._binding = binding

    @property
    def principal_id(self) -> str:
        return self._binding.principal_id

    @property
    def project_id(self) -> str:
        return self._binding.project_id

    @property
    def policy_digest(self) -> str | None:
        return self._binding.policy_digest

    @property
    def runtime_id(self) -> str | None:
        return self._binding.runtime_id

    async def log(
        self,
        action: str,
        target: str,
        result: str,
        detail: dict[str, Any] | None = None,
        session_id: str | None = None,
        *,
        task_id: str | None = None,
        operation_id: str | None = None,
        authority_generation: int | None = None,
        source_transport: str | None = None,
    ) -> int:
        """Persist an event with this request's immutable attribution."""
        return await self._root._log_for_binding(
            self._binding,
            action,
            target,
            result,
            detail,
            session_id,
            task_id=task_id,
            operation_id=operation_id,
            authority_generation=authority_generation,
            source_transport=(
                source_transport
                if source_transport is not None
                else self._binding.source_transport
            ),
        )

    async def log_permission(
        self,
        tool_name: str,
        target: str,
        approved: bool,
        reason: str = "",
        session_id: str | None = None,
        *,
        task_id: str | None = None,
        operation_id: str | None = None,
        authority_generation: int | None = None,
        source_transport: str | None = None,
    ) -> int:
        return await self.log(
            tool_name,
            target,
            RESULT_APPROVED if approved else RESULT_DENIED,
            {"reason": reason},
            session_id,
            task_id=task_id,
            operation_id=operation_id,
            authority_generation=authority_generation,
            source_transport=source_transport,
        )

    async def log_tool(
        self,
        tool_name: str,
        target: str,
        success: bool,
        duration_ms: int = 0,
        error: str = "",
        session_id: str | None = None,
        *,
        task_id: str | None = None,
        operation_id: str | None = None,
        authority_generation: int | None = None,
        source_transport: str | None = None,
    ) -> int:
        return await self.log(
            tool_name,
            target,
            RESULT_SUCCESS if success else RESULT_ERROR,
            {"duration_ms": duration_ms, "error": error},
            session_id,
            task_id=task_id,
            operation_id=operation_id,
            authority_generation=authority_generation,
            source_transport=source_transport,
        )

    async def log_security_event(
        self,
        event_type: str,
        tool_name: str,
        reason: str,
        detail: dict[str, Any] | None = None,
        session_id: str | None = None,
        *,
        task_id: str | None = None,
        operation_id: str | None = None,
        authority_generation: int | None = None,
        source_transport: str | None = None,
    ) -> int:
        return await self.log(
            f"security:{event_type}",
            f"{tool_name}:{reason}",
            RESULT_DENIED,
            detail,
            session_id,
            task_id=task_id,
            operation_id=operation_id,
            authority_generation=authority_generation,
            source_transport=source_transport,
        )

    async def query(
        self,
        action: str | None = None,
        result: str | None = None,
        since: str | datetime | None = None,
        until: str | datetime | None = None,
        limit: int = 100,
    ) -> list[AuditEntry]:
        """Query only this binding's principal/project rows."""
        return await self._root._query_for_binding(
            self._binding,
            action=action,
            result=result,
            since=since,
            until=until,
            limit=limit,
        )

    async def verify_anchor(self) -> None:
        """Verify the shared chain without taking lifecycle ownership."""
        await self._root.verify_anchor()

    def close(self) -> None:
        """Keep the shared logger alive; ownership remains at the server."""


class AuditLogger:
    """Write and query audit records.

    M1: ``log_path`` is the optional file path from the effective policy's
    ``audit_log_path``.  When set, every record is appended as one JSON
    line to that file (in addition to the SQLite database) so an operator
    has a path-stable secondary trail outside the database.  This protects
    the writer from path substitution; it is not cryptographic tamper
    evidence against the same UID.  The file write is best-effort.

    H3: the log file is opened ONCE at construction time with
    ``O_WRONLY | O_CREAT | O_APPEND | O_NOFOLLOW`` and the fd is held for
    the logger's lifetime.  Every ``_append_to_file`` call writes via
    ``os.write(self._fd, ...)`` — no per-event path resolution, no
    ``open(path, "a")`` that could follow a symlink substituted after
    startup.  The trusted directory is also validated (not a symlink,
    owned by the current UID, mode 0700) before the file is opened.

    M4 batch 3.1.16A-2: AuditLogger is principal-scoped, mirroring
    PermissionEngine / MemoryStore / ModeManager.  ``principal_id`` is
    bound at construction and stamped on every persisted row; ``query()``
    filters by it by default so one principal cannot read another's
    audit trail.  ``runtime_id`` and ``policy_digest`` are likewise
    runtime-bound and stamped on every row for attribution.  Per-event
    context (``task_id``, ``operation_id``, ``authority_generation``,
    ``source_transport``) flows through ``log()`` and the typed helpers.

    M4 batch 3.1.16A-5-1b (CRITICAL): ``project_id`` is bound at
    construction and stamped on every persisted row so an audit record
    is cryptographically tied to the project that produced it.  This
    closes the cross-project drift path where a runtime booted under
    one ``project_root`` could write audit rows attributed to another
    project (because the DB layer had no column to bind against).  The
    RPC dispatcher's drift check (``ctx.project_id !=
    agent._bound_project_id``) is the sole authority — when the
    AuditLogger is constructed via ``build_runtime`` the
    ``project_id`` comes from ``RuntimeConfig.project_id`` (set by
    ``AgentService`` from the verified RPC payload), NOT from
    ``compute_project_id(root)``.
    """

    def __init__(
        self,
        db,
        *,
        log_path: str | os.PathLike[str] | None = None,
        anchor_path: str | os.PathLike[str] | None = None,
        principal_id: str = "legacy",
        runtime_id: str | None = None,
        policy_digest: str | None = None,
        project_id: str = "",
    ):
        self.db = db
        self.log_path: Path | None = None
        # A2-6: principal attribution bound at construction.  Stamped on
        # every insert; used as the default ``query()`` filter so a
        # principal cannot read another principal's audit trail.
        self._principal_id = principal_id
        self._runtime_id = runtime_id
        self._policy_digest = policy_digest
        # M4 batch 3.1.16A-5-1b: project identity bound at construction
        # and stamped on every persisted row.  Default ``''`` ("unbound")
        # matches the schema column default — legacy callers / tests that
        # omit it produce ``project_id=''`` rows which are still visible
        # (no filter is applied on this column yet) but distinguishable
        # from rows stamped by a project-bound runtime.
        self._project_id = project_id
        # H3: long-lived fd opened at construction; None when file audit
        # is disabled or the path failed safety validation.
        self._fd: int | None = None
        self._audit_dir_fd: int | None = None
        self._log_filename: str | None = None
        self._file_lock = threading.RLock()
        if log_path is not None:
            self._open_log_fd(log_path)
        self._anchor: AuditChainAnchor | None = None
        if anchor_path is not None:
            try:
                self._anchor = AuditChainAnchor(
                    anchor_path,
                    project_id=self._project_id,
                    database_path=str(getattr(db, "path", "")),
                    trusted_dir=AUDIT_LOG_TRUSTED_DIR.expanduser(),
                )
            except AuditAnchorError:
                # An enabled production anchor must not silently downgrade to
                # SQLite-only evidence.  Construction fails closed so the
                # caller can refuse to start the runtime.
                logger.exception("failed to open audit chain anchor")
                raise

    @property
    def principal_id(self) -> str:
        """Return the root logger's default principal binding."""
        return self._principal_id

    @property
    def runtime_id(self) -> str | None:
        """Return the root logger's default runtime binding."""
        return self._runtime_id

    @property
    def policy_digest(self) -> str | None:
        """Return the policy digest sealed into the root logger."""
        return self._policy_digest

    @property
    def project_id(self) -> str:
        """Return the project scope sealed into the root logger."""
        return self._project_id

    def bind(
        self,
        *,
        principal_id: str,
        project_id: str,
        policy_digest: str | None = None,
        runtime_id: str | None = None,
        source_transport: str | None = None,
    ) -> BoundAuditLogger:
        """Create a request-scoped sink without duplicating the writer.

        A binding may change the principal and runtime attribution, but it
        may never change the project or effective policy owned by this root
        logger.  This is the fail-closed seam used by RPC services.
        """
        if not isinstance(principal_id, str) or not principal_id.strip():
            raise ValueError("audit binding requires a non-empty principal_id")
        if project_id != self._project_id:
            raise ValueError("audit binding project_id does not match root logger")
        if (
            policy_digest is not None
            and self._policy_digest is not None
            and policy_digest != self._policy_digest
        ):
            raise ValueError("audit binding policy_digest does not match root logger")
        return BoundAuditLogger(
            self,
            AuditBinding(
                principal_id=principal_id,
                project_id=project_id,
                policy_digest=(
                    self._policy_digest
                    if policy_digest is None
                    else policy_digest
                ),
                runtime_id=runtime_id,
                source_transport=source_transport,
            ),
        )

    def _open_log_fd(self, log_path: str | os.PathLike[str]) -> None:
        """H1: open and validate the audit log file via an ``openat``
        dirfd chain that does NOT follow symlinks at any component.

        * Starts from ``Path.home()`` opened with
          ``O_DIRECTORY | O_NOFOLLOW``.
        * Opens ``.khaos`` and ``audit`` relative to their parent dirfd
          using ``openat(dirfd, name, O_DIRECTORY | O_NOFOLLOW)`` so a
          symlink at ANY level is rejected.  The previous implementation
          called ``AUDIT_LOG_TRUSTED_DIR.expanduser().resolve()`` which
          FOLLOWED symlinks before the ``O_NOFOLLOW`` check — an
          attacker who replaced ``~/.khaos/audit`` with a symlink to
          ``/attacker-controlled-directory`` had the resolve follow it
          to the real directory, then ``O_NOFOLLOW`` checked the real
          directory (not the symlink), so validation passed.
        * For each directory, validates via ``fstat(dirfd)``: must be a
          regular directory (``S_ISDIR``), owned by the current UID,
          mode 0700 (no group/other access).
        * Opens the log file relative to the ``audit`` dirfd using
          ``openat(dirfd, filename, O_WRONLY | O_CREAT | O_APPEND |
          O_NOFOLLOW, 0o600)``.  Only the basename of ``log_path`` is
          used so an absolute path supplied by the caller cannot escape
          the trusted directory.
        * Validates the file fd via ``fstat``: must be a regular file
          (``S_ISREG``), owned by the current UID, mode 0600.
        * Holds the fd for the logger's lifetime; ``_append_to_file``
          uses ``os.write(self._fd, ...)`` — no per-event
          ``open(path, "a")`` that could follow a symlink substituted
          after startup.

        H1: CPython exposes openat semantics as ``os.open(..., dir_fd=...)``.
        If the platform does not advertise dirfd support for both ``open``
        and ``mkdir``, file audit fails closed to db-only mode.
        """
        if (
            os.open not in os.supports_dir_fd
            or os.mkdir not in os.supports_dir_fd
            or not hasattr(os, "O_DIRECTORY")
            or not hasattr(os, "O_NOFOLLOW")
        ):
            logger.warning(
                "dirfd/no-follow operations unavailable on this platform; "
                "falling back to db-only audit"
            )
            return
        # Use only the basename so an absolute path (or one with
        # subdirectory components) supplied by the caller cannot escape
        # the trusted audit directory via the openat call.
        filename = Path(str(log_path)).name
        if not filename or filename in (".", ".."):
            logger.warning(
                "audit log path %s has no usable filename component; "
                "db-only audit", log_path,
            )
            return
        # Track every open dirfd so we can close them on every exit path.
        dirfds: list[int] = []
        try:
            # 1. Start from Path.home() opened with O_DIRECTORY | O_NOFOLLOW.
            #    O_NOFOLLOW on the home path rejects a symlink at the home
            #    level (defense in depth).
            try:
                trusted = AUDIT_LOG_TRUSTED_DIR.expanduser()
                if trusted.name != "audit" or trusted.parent.name != ".khaos":
                    raise OSError("invalid trusted audit directory layout")
                home_fd = os.open(
                    str(trusted.parent.parent),
                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                )
            except OSError:
                logger.warning(
                    "failed to open home directory for audit; db-only audit",
                    exc_info=True,
                )
                return
            dirfds.append(home_fd)

            # 2. Open ".khaos" relative to the home dirfd (NO symlink
            #    following — openat with O_NOFOLLOW rejects a symlink).
            khaos_fd = self._openat_dir_component(
                home_fd, ".khaos", parent_label="home",
            )
            if khaos_fd is None:
                return
            dirfds.append(khaos_fd)

            # 3. Open "audit" relative to the .khaos dirfd.
            audit_fd = self._openat_dir_component(
                khaos_fd, "audit", parent_label=".khaos",
            )
            if audit_fd is None:
                return
            dirfds.append(audit_fd)

            # 4. Open the log file relative to the audit dirfd.
            try:
                fd = self._open_regular_log_fd(audit_fd, filename)
            except OSError:
                logger.warning(
                    "failed to open audit log file %s; db-only audit",
                    filename, exc_info=True,
                )
                return
            # Success — hold the fd for the logger's lifetime.  Reconstruct
            # ``log_path`` as the audit dir + filename for logging / display
            # (the original input may have been an absolute path).
            self._fd = fd
            self._audit_dir_fd = audit_fd
            self._log_filename = filename
            self.log_path = AUDIT_LOG_TRUSTED_DIR.expanduser() / filename
            logger.info("audit log file opened (fd=%d): %s", fd, self.log_path)
        finally:
            # Close every directory fd in reverse order; the held file fd
            # (``self._fd``) is NOT closed here — it is held for the
            # logger's lifetime and closed in ``close()``.
            for dfd in reversed(dirfds):
                if dfd == self._audit_dir_fd:
                    continue
                try:
                    os.close(dfd)
                except OSError:
                    pass

    def _openat_dir_component(
        self, parent_fd: int, name: str, *, parent_label: str,
    ) -> int | None:
        """H1: open a directory component via ``openat`` with
        ``O_DIRECTORY | O_NOFOLLOW`` (no symlink following), creating it
        0700 if missing.  Validates via ``fstat`` that the result is a
        regular directory owned by the current UID with mode 0700.

        Returns the opened dirfd on success, or ``None`` on any failure
        (a warning is logged and the caller falls back to db-only audit).
        """
        try:
            fd = os.open(
                name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                dir_fd=parent_fd,
            )
        except OSError:
            # Component may not exist yet — create it 0700 (mkdirat
            # semantics: the new directory is created relative to
            # ``parent_fd`` so a concurrent symlink swap cannot win the
            # race between mkdir and openat).  Then retry the openat.
            try:
                os.mkdir(name, 0o700, dir_fd=parent_fd)
            except OSError:
                logger.warning(
                    "failed to create %s under %s for audit; db-only audit",
                    name, parent_label, exc_info=True,
                )
                return None
            try:
                fd = os.open(
                    name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                    dir_fd=parent_fd,
                )
            except OSError:
                logger.warning(
                    "failed to open %s under %s for audit; db-only audit",
                    name, parent_label, exc_info=True,
                )
                return None
        try:
            st = os.fstat(fd)
        except OSError:
            logger.warning(
                "fstat failed on %s under %s; db-only audit",
                name, parent_label, exc_info=True,
            )
            try:
                os.close(fd)
            except OSError:
                pass
            return None
        if not _stat.S_ISDIR(st.st_mode):
            logger.warning(
                "%s under %s is not a directory; db-only audit",
                name, parent_label,
            )
            os.close(fd)
            return None
        if st.st_uid != os.getuid():
            logger.warning(
                "%s under %s not owned by current UID; db-only audit",
                name, parent_label,
            )
            os.close(fd)
            return None
        if st.st_mode & 0o077:
            # A normal first-run config created by an older Khaos build may
            # have inherited umask 022 and produced ~/.khaos as 0755.  The
            # directory is already pinned by fd, is a real directory, and is
            # owned by this UID, so tightening that exact inode is safe.
            try:
                os.fchmod(fd, 0o700)
                st = os.fstat(fd)
            except OSError:
                logger.warning(
                    "failed to tighten %s under %s; db-only audit",
                    name, parent_label, exc_info=True,
                )
                os.close(fd)
                return None
            if _stat.S_IMODE(st.st_mode) != 0o700:
                logger.warning(
                    "%s under %s remains unsafe mode %o; db-only audit",
                    name, parent_label, _stat.S_IMODE(st.st_mode),
                )
                os.close(fd)
                return None
        return fd

    def _open_regular_log_fd(self, directory_fd: int, filename: str) -> int:
        """Open one trusted JSONL segment and validate its inode."""
        fd = os.open(
            filename,
            os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW,
            0o600,
            dir_fd=directory_fd,
        )
        try:
            st = os.fstat(fd)
            if not _stat.S_ISREG(st.st_mode):
                raise OSError("audit log segment is not a regular file")
            if st.st_uid != os.getuid():
                raise OSError("audit log segment is not owned by current UID")
            if st.st_mode & 0o077:
                raise OSError("audit log segment has unsafe permissions")
            return fd
        except Exception:
            try:
                os.close(fd)
            except OSError:
                pass
            raise

    def close(self) -> None:
        """Close the held audit log fd (idempotent)."""
        with self._file_lock:
            if self._fd is not None:
                try:
                    os.close(self._fd)
                except OSError:
                    pass
                self._fd = None
            if self._audit_dir_fd is not None:
                try:
                    os.close(self._audit_dir_fd)
                except OSError:
                    pass
                self._audit_dir_fd = None
        if self._anchor is not None:
            self._anchor.close()

    async def verify_anchor(self) -> None:
        """Replay the SQLite audit chain against the independent anchor."""
        if self._anchor is not None:
            await self._anchor.verify(self.db)

    async def log(
        self,
        action: str,
        target: str,
        result: str,
        detail: dict[str, Any] | None = None,
        session_id: str | None = None,
        *,
        task_id: str | None = None,
        operation_id: str | None = None,
        authority_generation: int | None = None,
        source_transport: str | None = None,
    ) -> int:
        """Persist one audit row; return its id.

        ``detail`` is JSON-serialized. Pass a plain dict; primitives are kept
        readable for direct SQLite inspection.

        M1: when ``log_path`` is configured, the record is also appended as
        one JSON line to that file.  The file write is best-effort — a
        failure does NOT suppress the database write.

        A2-6: ``principal_id`` / ``runtime_id`` / ``policy_digest`` come
        from the logger's construction (they are properties of the runtime
        that owns this logger).  The per-event keyword args
        (``task_id`` / ``operation_id`` / ``authority_generation`` /
        ``source_transport``) describe the immediate caller and are
        stamped on this row only.

        M4 batch 3.1.16A-5-1b: ``project_id`` likewise comes from the
        logger's construction — it is a runtime property, not per-event.
        """
        return await self._log_for_binding(
            AuditBinding(
                principal_id=self._principal_id,
                project_id=self._project_id,
                policy_digest=self._policy_digest,
                runtime_id=self._runtime_id,
                source_transport=source_transport,
            ),
            action,
            target,
            result,
            detail,
            session_id,
            task_id=task_id,
            operation_id=operation_id,
            authority_generation=authority_generation,
            source_transport=source_transport,
        )

    async def _log_for_binding(
        self,
        binding: AuditBinding,
        action: str,
        target: str,
        result: str,
        detail: dict[str, Any] | None = None,
        session_id: str | None = None,
        *,
        task_id: str | None = None,
        operation_id: str | None = None,
        authority_generation: int | None = None,
        source_transport: str | None = None,
    ) -> int:
        """Write one event under a validated identity binding."""
        detail_json = json.dumps(detail or {}, ensure_ascii=False, sort_keys=True)
        if self._anchor is not None:
            try:
                # Verify before accepting a new event, so a database that was
                # edited after startup cannot advance the trusted head.
                await self._anchor.verify(self.db)
            except AuditAnchorError:
                logger.exception(
                    "audit chain anchor verification failed; refusing to "
                    "record a trusted audit event"
                )
                return -1
        # M1: append a copy to the configured file path (best-effort).
        if self.log_path is not None:
            try:
                self._append_to_file(
                    action=action,
                    target=target,
                    result=result,
                    detail_json=detail_json,
                    session_id=session_id,
                    principal_id=binding.principal_id,
                    runtime_id=binding.runtime_id,
                    policy_digest=binding.policy_digest,
                    project_id=binding.project_id,
                    task_id=task_id,
                    operation_id=operation_id,
                    authority_generation=authority_generation,
                    source_transport=(
                        source_transport
                        if source_transport is not None
                        else binding.source_transport
                    ),
                )
            except Exception:
                logger.debug(
                    "audit log file append failed for path=%s",
                    self.log_path,
                    exc_info=True,
                )
        try:
            row_id = await self.db.insert_audit_log(
                action=action,
                target=target,
                result=result,
                detail=detail_json,
                session_id=session_id,
                principal_id=binding.principal_id,
                runtime_id=binding.runtime_id,
                task_id=task_id,
                operation_id=operation_id,
                policy_digest=binding.policy_digest,
                authority_generation=authority_generation,
                source_transport=(
                    source_transport
                    if source_transport is not None
                    else binding.source_transport
                ),
                project_id=binding.project_id,
            )
            if self._anchor is not None:
                try:
                    await self._anchor.observe(self.db)
                except AuditAnchorError:
                    logger.exception(
                        "audit chain anchor update failed after row %s",
                        row_id
                    )
                    return -1
            return row_id
        except Exception:
            # Audit must never break the calling flow; log and continue.
            logger.exception("audit log write failed for action=%s", action)
            return -1

    def _append_to_file(
        self,
        *,
        action: str,
        target: str,
        result: str,
        detail_json: str,
        session_id: str | None,
        principal_id: str,
        runtime_id: str | None,
        policy_digest: str | None,
        project_id: str,
        task_id: str | None = None,
        operation_id: str | None = None,
        authority_generation: int | None = None,
        source_transport: str | None = None,
    ) -> None:
        """Append one audit record as a JSON line to the held fd.

        H3: writes via ``os.write(self._fd, ...)`` using the fd opened at
        construction time — no per-event ``open(path, "a")`` that could
        follow a symlink substituted after startup.  The fd was validated
        (regular file, owner, mode) when opened and is held for the
        logger's lifetime, so the write target cannot be swapped.

        A2-6: the JSON line carries the principal / runtime / policy
        attribution plus the per-event context fields so the file trail
        matches the DB row 1:1.
        """
        if self._fd is None:
            return  # file audit disabled or path failed validation
        record: dict[str, Any] = {
            "ts": utc_now_naive().strftime("%Y-%m-%dT%H:%M:%SZ"),
            "action": action,
            "target": target,
            "result": result,
            "detail": json.loads(detail_json),
            "session_id": session_id,
            "principal_id": principal_id,
            "runtime_id": runtime_id,
            "policy_digest": policy_digest,
            # M4 batch 3.1.16A-5-1b: project identity stamp so the file
            # audit trail matches the DB row 1:1.
            "project_id": project_id,
        }
        # Only include per-event context when set, so the file line stays
        # compact for the common case (no task / operation / transport).
        if task_id is not None:
            record["task_id"] = task_id
        if operation_id is not None:
            record["operation_id"] = operation_id
        if authority_generation is not None:
            record["authority_generation"] = authority_generation
        if source_transport is not None:
            record["source_transport"] = source_transport
        line = (json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n").encode(
            "utf-8"
        )
        with self._file_lock:
            try:
                self._enforce_file_storage_limit(len(line))
                self._rotate_file_if_needed(len(line))
                view = memoryview(line)
                while view:
                    written = os.write(self._fd, view)
                    if written <= 0:
                        raise OSError("audit log write made no progress")
                    view = view[written:]
            except OSError as exc:
                if "storage limit" in str(exc):
                    logger.error("%s", exc)
                else:
                    logger.debug(
                        "audit log fd write failed (fd=%s)", self._fd, exc_info=True
                    )

    def _segment_files(self) -> list[tuple[str, int]]:
        """Return trusted rotated segment names and sizes."""
        if self._audit_dir_fd is None or self._log_filename is None:
            return []
        prefix = f"{self._log_filename}.segment-"
        entries: list[tuple[str, int]] = []
        for name in os.listdir(self._audit_dir_fd):
            if not name.startswith(prefix) or "/" in name:
                continue
            try:
                stat_result = os.stat(
                    name, dir_fd=self._audit_dir_fd, follow_symlinks=False
                )
            except OSError:
                continue
            if _stat.S_ISREG(stat_result.st_mode):
                entries.append((name, int(stat_result.st_size)))
        return sorted(entries)

    def _enforce_file_storage_limit(self, incoming_bytes: int) -> None:
        """Reject secondary writes that exceed the explicit disk budget."""
        if AUDIT_FILE_MAX_BYTES <= 0 or self._fd is None:
            return
        current = int(os.fstat(self._fd).st_size)
        rotated = sum(size for _, size in self._segment_files())
        if rotated + current + incoming_bytes > AUDIT_FILE_MAX_BYTES:
            raise OSError(
                "audit file storage limit reached; run explicit archive_segments"
            )

    async def archive_segments(
        self,
        destination: str | os.PathLike[str],
        *,
        signing_key: bytes,
        remove_source: bool = False,
    ) -> dict[str, Any]:
        """Explicitly archive rotated JSONL segments.

        The logger never deletes segments during rotation or maintenance.
        An operator may call this method with an out-of-band signing key to
        create gzip members plus a signed manifest.  A tombstone is appended
        to the trusted audit directory before optional source removal, so a
        later audit can distinguish an explicit archive from silent loss.
        The active JSONL file is never archived or removed by this method.
        """
        if not isinstance(signing_key, bytes) or len(signing_key) < 16:
            raise ValueError("archive signing_key must contain at least 16 bytes")
        return await asyncio.to_thread(
            self._archive_segments_sync,
            Path(destination),
            signing_key,
            remove_source,
        )

    async def archive_audit_chain(
        self,
        destination: str | os.PathLike[str],
        *,
        signing_key: bytes,
    ) -> dict[str, Any]:
        """Export the SQLite audit chain as signed compressed evidence.

        This is an explicit operator action.  It verifies the complete chain
        first, writes an immutable gzip export plus an HMAC manifest, and
        records a trusted tombstone.  It deliberately does not delete rows:
        the SQLite table and its independent anchor remain authoritative until
        an operator performs a separately approved database rotation.
        """
        if not isinstance(signing_key, bytes) or len(signing_key) < 16:
            raise ValueError("archive signing_key must contain at least 16 bytes")
        if self._audit_dir_fd is None:
            raise RuntimeError(
                "SQLite audit archive requires the trusted file-audit directory"
            )
        breaks = await self.db.verify_audit_chain()
        if breaks:
            raise AuditAnchorError(
                "cannot archive a broken SQLite audit chain: "
                + ", ".join(str(item.get("id")) for item in breaks)
            )
        if self._anchor is not None:
            await self._anchor.verify(self.db)
        rows = await self.db.list_audit_logs()
        return await asyncio.to_thread(
            self._archive_audit_chain_sync,
            Path(destination),
            signing_key,
            rows,
        )

    def _archive_audit_chain_sync(
        self,
        destination: Path,
        signing_key: bytes,
        rows: list[dict[str, Any]],
    ) -> dict[str, Any]:
        with self._file_lock:
            if self._audit_dir_fd is None:
                raise RuntimeError("trusted audit directory is closed")
            destination = destination.expanduser()
            destination.mkdir(parents=True, exist_ok=True, mode=0o700)
            destination_stat = destination.stat()
            if not _stat.S_ISDIR(destination_stat.st_mode):
                raise ValueError("archive destination is not a directory")
            if destination_stat.st_uid != os.getuid():
                raise PermissionError("archive destination is not owned by current UID")
            if destination_stat.st_mode & 0o077:
                destination.chmod(0o700)
            archive_id = f"{os.getpid()}-{time.time_ns()}"
            archive_dir = destination / f"sqlite-audit.archive-{archive_id}"
            archive_dir.mkdir(mode=0o700)
            ordered_rows = sorted(rows, key=lambda row: int(row.get("id") or 0))
            archive_path = archive_dir / "audit-chain.jsonl.gz"
            source_hash = hashlib.sha256()
            with open(archive_path, "xb") as raw_target:
                with gzip.GzipFile(
                    filename=archive_path.name,
                    mode="wb",
                    fileobj=raw_target,
                    mtime=0,
                ) as compressed:
                    for row in ordered_rows:
                        line = (
                            json.dumps(
                                row,
                                ensure_ascii=False,
                                sort_keys=True,
                                separators=(",", ":"),
                            )
                            + "\n"
                        ).encode("utf-8")
                        source_hash.update(line)
                        compressed.write(line)
                raw_target.flush()
                os.fsync(raw_target.fileno())
            compressed_hash = hashlib.sha256(archive_path.read_bytes()).hexdigest()
            first_id = int(ordered_rows[0]["id"]) if ordered_rows else 0
            last_id = int(ordered_rows[-1]["id"]) if ordered_rows else 0
            head_hash = str(ordered_rows[-1].get("prev_hash") or "") if ordered_rows else ""
            body: dict[str, Any] = {
                "format": "khaos-sqlite-audit-archive-v1",
                "archive_id": archive_id,
                "created_at": utc_now_naive().isoformat(),
                "project_id": self._project_id,
                "database_id": hashlib.sha256(
                    str(Path(getattr(self.db, "path", "")).expanduser().resolve())
                    .encode("utf-8")
                ).hexdigest(),
                "first_id": first_id,
                "last_id": last_id,
                "row_count": len(ordered_rows),
                "head_hash": head_hash,
                "source_sha256": source_hash.hexdigest(),
                "archive_name": archive_path.name,
                "archive_bytes": archive_path.stat().st_size,
                "archive_sha256": compressed_hash,
                "source_delete_requested": False,
            }
            body_bytes = json.dumps(
                body, ensure_ascii=False, sort_keys=True, separators=(",", ":")
            ).encode("utf-8")
            manifest_hash = hashlib.sha256(body_bytes).hexdigest()
            manifest = {
                **body,
                "manifest_sha256": manifest_hash,
                "manifest_hmac_sha256": hmac.new(
                    signing_key, body_bytes, hashlib.sha256
                ).hexdigest(),
            }
            manifest_path = archive_dir / "manifest.json"
            with open(manifest_path, "xb") as manifest_file:
                manifest_file.write(
                    (json.dumps(manifest, ensure_ascii=False, sort_keys=True) + "\n")
                    .encode("utf-8")
                )
                manifest_file.flush()
                os.fsync(manifest_file.fileno())
            manifest_path.chmod(0o600)
            tombstone = {
                "format": "khaos-audit-archive-tombstone-v1",
                "archive_id": archive_id,
                "created_at": body["created_at"],
                "source": "sqlite:audit_log",
                "manifest_sha256": manifest_hash,
                "first_id": first_id,
                "last_id": last_id,
                "row_count": len(ordered_rows),
                "source_delete_requested": False,
            }
            tombstone_line = (
                json.dumps(tombstone, ensure_ascii=False, sort_keys=True) + "\n"
            ).encode("utf-8")
            tombstone_fd = os.open(
                AUDIT_ARCHIVE_TOMBSTONE,
                os.O_WRONLY
                | os.O_CREAT
                | os.O_APPEND
                | getattr(os, "O_NOFOLLOW", 0),
                0o600,
                dir_fd=self._audit_dir_fd,
            )
            try:
                view = memoryview(tombstone_line)
                while view:
                    written = os.write(tombstone_fd, view)
                    if written <= 0:
                        raise OSError("audit archive tombstone write made no progress")
                    view = view[written:]
                os.fsync(tombstone_fd)
            finally:
                os.close(tombstone_fd)
            return {
                "archive_id": archive_id,
                "archive_directory": str(archive_dir),
                "manifest": str(manifest_path),
                "manifest_sha256": manifest_hash,
                "row_count": len(ordered_rows),
                "source_deleted": False,
            }

    def _archive_segments_sync(
        self,
        destination: Path,
        signing_key: bytes,
        remove_source: bool,
    ) -> dict[str, Any]:
        with self._file_lock:
            return self._archive_segments_locked(
                destination, signing_key, remove_source
            )

    def _archive_segments_locked(
        self,
        destination: Path,
        signing_key: bytes,
        remove_source: bool,
    ) -> dict[str, Any]:
        if self._audit_dir_fd is None or self._log_filename is None:
            raise RuntimeError("file audit is not enabled")
        destination = destination.expanduser()
        destination.mkdir(parents=True, exist_ok=True, mode=0o700)
        destination_stat = destination.stat()
        if not _stat.S_ISDIR(destination_stat.st_mode):
            raise ValueError("archive destination is not a directory")
        if destination_stat.st_uid != os.getuid():
            raise PermissionError("archive destination is not owned by current UID")
        if destination_stat.st_mode & 0o077:
            destination.chmod(0o700)

        source_entries = self._segment_files()
        archive_id = f"{os.getpid()}-{time.time_ns()}"
        archive_dir = destination / f"{self._log_filename}.archive-{archive_id}"
        archive_dir.mkdir(mode=0o700)
        entries: list[dict[str, Any]] = []
        for source_name, source_size in source_entries:
            target = archive_dir / f"{source_name}.gz"
            source_hash = hashlib.sha256()
            source_fd = os.open(
                source_name,
                os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=self._audit_dir_fd,
            )
            try:
                with os.fdopen(source_fd, "rb", closefd=True) as source, open(
                    target, "xb"
                ) as raw_target:
                    with gzip.GzipFile(
                        filename=target.name,
                        mode="wb",
                        fileobj=raw_target,
                        mtime=0,
                    ) as compressed:
                        while True:
                            chunk = source.read(1024 * 1024)
                            if not chunk:
                                break
                            source_hash.update(chunk)
                            compressed.write(chunk)
                    raw_target.flush()
                    os.fsync(raw_target.fileno())
            except Exception:
                try:
                    os.close(source_fd)
                except OSError:
                    pass
                raise
            compressed_hash = hashlib.sha256(target.read_bytes()).hexdigest()
            entries.append({
                "source_name": source_name,
                "source_bytes": source_size,
                "source_sha256": source_hash.hexdigest(),
                "archive_name": target.name,
                "archive_bytes": target.stat().st_size,
                "archive_sha256": compressed_hash,
            })

        body: dict[str, Any] = {
            "format": "khaos-audit-archive-v1",
            "archive_id": archive_id,
            "created_at": utc_now_naive().isoformat(),
            "log_filename": self._log_filename,
            "project_id": self._project_id,
            "entries": entries,
            "source_delete_requested": remove_source,
        }
        body_bytes = json.dumps(
            body, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        manifest_hash = hashlib.sha256(body_bytes).hexdigest()
        signature = hmac.new(signing_key, body_bytes, hashlib.sha256).hexdigest()
        manifest = {
            **body,
            "manifest_sha256": manifest_hash,
            "manifest_hmac_sha256": signature,
        }
        manifest_path = archive_dir / "manifest.json"
        with open(manifest_path, "xb") as manifest_file:
            manifest_file.write(
                (json.dumps(manifest, ensure_ascii=False, sort_keys=True) + "\n")
                .encode("utf-8")
            )
            manifest_file.flush()
            os.fsync(manifest_file.fileno())
        manifest_path.chmod(0o600)

        tombstone = {
            "format": "khaos-audit-archive-tombstone-v1",
            "archive_id": archive_id,
            "created_at": body["created_at"],
            "manifest_sha256": manifest_hash,
            "segments": [name for name, _ in source_entries],
            "source_delete_requested": remove_source,
        }
        tombstone_line = (
            json.dumps(tombstone, ensure_ascii=False, sort_keys=True) + "\n"
        ).encode("utf-8")
        tombstone_fd = os.open(
            AUDIT_ARCHIVE_TOMBSTONE,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_APPEND
            | getattr(os, "O_NOFOLLOW", 0),
            0o600,
            dir_fd=self._audit_dir_fd,
        )
        try:
            view = memoryview(tombstone_line)
            while view:
                written = os.write(tombstone_fd, view)
                if written <= 0:
                    raise OSError("audit archive tombstone write made no progress")
                view = view[written:]
            os.fsync(tombstone_fd)
        finally:
            os.close(tombstone_fd)

        if remove_source:
            for source_name, _ in source_entries:
                os.unlink(source_name, dir_fd=self._audit_dir_fd)
            os.fsync(self._audit_dir_fd)

        return {
            "archive_id": archive_id,
            "archive_directory": str(archive_dir),
            "manifest": str(manifest_path),
            "manifest_sha256": manifest_hash,
            "segments": [name for name, _ in source_entries],
            "source_deleted": remove_source,
        }

    def _rotate_file_if_needed(self, incoming_bytes: int) -> None:
        """Rotate the secondary trail under the already-pinned directory fd."""
        if (
            self._fd is None
            or self._audit_dir_fd is None
            or self._log_filename is None
            or AUDIT_FILE_SEGMENT_BYTES <= 0
        ):
            return
        current = os.fstat(self._fd)
        if current.st_size == 0 or current.st_size + incoming_bytes <= AUDIT_FILE_SEGMENT_BYTES:
            return
        segment_name = self._next_segment_name()
        os.fsync(self._fd)
        os.close(self._fd)
        self._fd = None
        try:
            os.rename(
                self._log_filename,
                segment_name,
                src_dir_fd=self._audit_dir_fd,
                dst_dir_fd=self._audit_dir_fd,
            )
            # Persist the directory entry update before accepting new rows;
            # otherwise a power loss could lose the segment rename even
            # though the old file contents were already fsynced.
            os.fsync(self._audit_dir_fd)
            self._fd = self._open_regular_log_fd(
                self._audit_dir_fd, self._log_filename
            )
            logger.info("rotated audit log segment to %s", segment_name)
        except Exception:
            # Reopen the base file if rotation failed.  The DB audit row still
            # remains authoritative; file append is deliberately best-effort.
            try:
                self._fd = self._open_regular_log_fd(
                    self._audit_dir_fd, self._log_filename
                )
            except OSError:
                self._fd = None
            raise

    def _next_segment_name(self) -> str:
        """Return a collision-resistant basename inside the trusted directory."""
        if self._log_filename is None:
            raise OSError("audit log filename is unavailable")
        stem = f"{self._log_filename}.segment-{os.getpid()}-{time.time_ns()}"
        candidate = stem
        counter = 0
        while self._audit_dir_fd is not None:
            try:
                os.stat(candidate, dir_fd=self._audit_dir_fd, follow_symlinks=False)
            except FileNotFoundError:
                return candidate
            except OSError:
                raise
            counter += 1
            candidate = f"{stem}-{counter}"
        raise OSError("audit directory fd is unavailable")

    async def log_permission(
        self,
        tool_name: str,
        target: str,
        approved: bool,
        reason: str = "",
        session_id: str | None = None,
        *,
        task_id: str | None = None,
        operation_id: str | None = None,
        authority_generation: int | None = None,
        source_transport: str | None = None,
    ) -> int:
        """Record a permission decision (approved/denied)."""
        return await self.log(
            action=tool_name,
            target=target,
            result=RESULT_APPROVED if approved else RESULT_DENIED,
            detail={"reason": reason},
            session_id=session_id,
            task_id=task_id,
            operation_id=operation_id,
            authority_generation=authority_generation,
            source_transport=source_transport,
        )

    async def log_tool(
        self,
        tool_name: str,
        target: str,
        success: bool,
        duration_ms: int = 0,
        error: str = "",
        session_id: str | None = None,
        *,
        task_id: str | None = None,
        operation_id: str | None = None,
        authority_generation: int | None = None,
        source_transport: str | None = None,
    ) -> int:
        """Record a tool execution outcome."""
        return await self.log(
            action=tool_name,
            target=target,
            result=RESULT_SUCCESS if success else RESULT_ERROR,
            detail={"duration_ms": duration_ms, "error": error},
            session_id=session_id,
            task_id=task_id,
            operation_id=operation_id,
            authority_generation=authority_generation,
            source_transport=source_transport,
        )

    async def log_security_event(
        self,
        event_type: str,
        tool_name: str,
        reason: str,
        detail: dict[str, Any] | None = None,
        session_id: str | None = None,
        *,
        task_id: str | None = None,
        operation_id: str | None = None,
        authority_generation: int | None = None,
        source_transport: str | None = None,
    ) -> int:
        """记录安全事件到审计日志。

        ``event_type`` 是分类标签，例如 ``"command_blocked"`` /
        ``"path_denied"`` / ``"network_blocked"`` / ``"sandbox_violation"``。
        事件以 ``action="security:<event_type>"``、``result="blocked"`` 写入，
        因此一次 ``query(result="blocked")`` 就能覆盖所有安全拦截。
        """
        return await self.log(
            action=f"security:{event_type}",
            target=f"{tool_name}:{reason}",
            result=RESULT_DENIED,
            detail=detail,
            session_id=session_id,
            task_id=task_id,
            operation_id=operation_id,
            authority_generation=authority_generation,
            source_transport=source_transport,
        )

    async def query(
        self,
        action: str | None = None,
        result: str | None = None,
        since: str | datetime | None = None,
        until: str | datetime | None = None,
        limit: int = 100,
        *,
        principal_id: str | None = "__default__",
    ) -> list[AuditEntry]:
        """Query audit records, newest first, with optional filters.

        A2-6: by default the query is scoped to this logger's bound
        ``principal_id`` so one principal cannot read another's audit
        trail.  Callers that legitimately need a cross-principal view
        (e.g. a future admin operator) may pass ``principal_id=None`` to
        disable the filter, or pass an explicit principal id to query a
        different principal's events.  Both are explicit opt-ins; the
        default is fail-closed isolation.
        """
        binding = AuditBinding(
            principal_id=self._principal_id,
            project_id=self._project_id,
            policy_digest=self._policy_digest,
            runtime_id=self._runtime_id,
        )
        if principal_id not in {"__default__", self._principal_id}:
            # Preserve the explicit administrative query escape hatch on the
            # root logger.  Request-bound sinks never expose this parameter.
            return await self._query_for_binding(
                binding,
                action=action,
                result=result,
                since=since,
                until=until,
                limit=limit,
                principal_override=principal_id,
                principal_override_set=True,
            )
        return await self._query_for_binding(
            binding,
            action=action,
            result=result,
            since=since,
            until=until,
            limit=limit,
        )

    async def _query_for_binding(
        self,
        binding: AuditBinding,
        *,
        action: str | None = None,
        result: str | None = None,
        since: str | datetime | None = None,
        until: str | datetime | None = None,
        limit: int = 100,
        principal_override: str | None = None,
        principal_override_set: bool = False,
    ) -> list[AuditEntry]:
        """Query rows for one binding; never widen a bound project."""
        effective_principal = (
            binding.principal_id
            if not principal_override_set
            else principal_override
        )
        rows = await self.db.query_audit_logs(
            action=action,
            result=result,
            since=_normalize_time(since),
            until=_normalize_time(until),
            limit=limit,
            principal_id=effective_principal,
            project_id=binding.project_id,
        )
        return [AuditEntry.from_row(row) for row in rows]


def parse_detail(raw: Any) -> dict[str, Any]:
    """Best-effort parse of the ``detail`` JSON column into a dict."""
    if raw is None or raw == "":
        return {}
    if isinstance(raw, dict):
        return raw
    try:
        loaded = json.loads(str(raw))
        return loaded if isinstance(loaded, dict) else {"value": loaded}
    except (json.JSONDecodeError, TypeError):
        return {"raw": str(raw)}


def _normalize_time(value: str | datetime | None) -> str | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value.strftime("%Y-%m-%d %H:%M:%S")
    return str(value)
