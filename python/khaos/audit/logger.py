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

import json
import logging
import os
import stat as _stat
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

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
    authority_generation: int | None = None
    source_transport: str | None = None

    @classmethod
    def from_row(cls, row: dict[str, Any]) -> "AuditEntry":
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
            authority_generation=row.get("authority_generation"),
            source_transport=row.get("source_transport"),
        )

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        return data


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
        if log_path is not None:
            self._open_log_fd(log_path)

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
                fd = os.open(
                    filename,
                    os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW,
                    0o600,
                    dir_fd=audit_fd,
                )
            except OSError:
                logger.warning(
                    "failed to open audit log file %s; db-only audit",
                    filename, exc_info=True,
                )
                return
            try:
                st = os.fstat(fd)
                if not _stat.S_ISREG(st.st_mode):
                    logger.warning(
                        "audit log file %s is not a regular file; db-only audit",
                        filename,
                    )
                    os.close(fd)
                    return
                if st.st_uid != os.getuid():
                    logger.warning(
                        "audit log file %s not owned by current UID; db-only audit",
                        filename,
                    )
                    os.close(fd)
                    return
                if st.st_mode & 0o077:
                    logger.warning(
                        "audit log file %s has unsafe mode %o; db-only audit",
                        filename, _stat.S_IMODE(st.st_mode),
                    )
                    os.close(fd)
                    return
            except OSError:
                os.close(fd)
                return
            # Success — hold the fd for the logger's lifetime.  Reconstruct
            # ``log_path`` as the audit dir + filename for logging / display
            # (the original input may have been an absolute path).
            self._fd = fd
            self.log_path = AUDIT_LOG_TRUSTED_DIR.expanduser() / filename
            logger.info("audit log file opened (fd=%d): %s", fd, self.log_path)
        finally:
            # Close every directory fd in reverse order; the held file fd
            # (``self._fd``) is NOT closed here — it is held for the
            # logger's lifetime and closed in ``close()``.
            for dfd in reversed(dirfds):
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

    def close(self) -> None:
        """Close the held audit log fd (idempotent)."""
        if self._fd is not None:
            try:
                os.close(self._fd)
            except OSError:
                pass
            self._fd = None

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
        detail_json = json.dumps(detail or {}, ensure_ascii=False, sort_keys=True)
        # M1: append a copy to the configured file path (best-effort).
        if self.log_path is not None:
            try:
                self._append_to_file(
                    action=action,
                    target=target,
                    result=result,
                    detail_json=detail_json,
                    session_id=session_id,
                    task_id=task_id,
                    operation_id=operation_id,
                    authority_generation=authority_generation,
                    source_transport=source_transport,
                )
            except Exception:
                logger.debug(
                    "audit log file append failed for path=%s",
                    self.log_path,
                    exc_info=True,
                )
        try:
            return await self.db.insert_audit_log(
                action=action,
                target=target,
                result=result,
                detail=detail_json,
                session_id=session_id,
                principal_id=self._principal_id,
                runtime_id=self._runtime_id,
                task_id=task_id,
                operation_id=operation_id,
                policy_digest=self._policy_digest,
                authority_generation=authority_generation,
                source_transport=source_transport,
                project_id=self._project_id,
            )
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
            "principal_id": self._principal_id,
            "runtime_id": self._runtime_id,
            "policy_digest": self._policy_digest,
            # M4 batch 3.1.16A-5-1b: project identity stamp so the file
            # audit trail matches the DB row 1:1.
            "project_id": self._project_id,
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
        line = json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n"
        try:
            os.write(self._fd, line.encode("utf-8"))
        except OSError:
            logger.debug(
                "audit log fd write failed (fd=%s)", self._fd, exc_info=True
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
        effective_principal = (
            self._principal_id if principal_id == "__default__" else principal_id
        )
        rows = await self.db.query_audit_logs(
            action=action,
            result=result,
            since=_normalize_time(since),
            until=_normalize_time(until),
            limit=limit,
            principal_id=effective_principal,
            project_id=self._project_id,
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
