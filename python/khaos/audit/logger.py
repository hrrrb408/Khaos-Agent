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
file so an operator has an append-only, tamper-evident trail outside the
SQLite database (which a compromised process could otherwise rewrite).  The
file write is best-effort — a failure to append to the file does NOT suppress
the database write or break the calling flow.

H2: ``resolve_safe_audit_log_path`` (exported below) is the single trusted
resolver for ``audit_log_path`` — it constrains the path to
``~/.khaos/audit/``, opens it with ``O_APPEND | O_CREAT | O_NOFOLLOW`` and
validates owner / mode / regular-file.  Both the gRPC server path and the
runtime factory (used by CLI / TUI / tests) call it so the audit trust
boundary is uniform across every entry point (M1).
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
    """Resolve ``log_path`` to a safe, trusted-directory audit file (H2).

    Rules:

    * ``None`` / empty → ``None`` (no file audit; db-only audit remains).
    * Path resolves outside ``~/.khaos/audit/`` → rejected (``None``).
    * The trusted directory is created 0700 (best-effort).
    * The final path is opened ``O_APPEND | O_CREAT | O_NOFOLLOW`` and its
      ``(st_dev, st_ino, st_mode, st_uid)`` are validated: must be a regular
      file owned by the current user with no group/other write bits.

    Returns the resolved ``Path`` (inside the trusted dir) when safe, or
    ``None`` when the input was empty / unsafe (in which case audit falls
    back to db-only — never raises, because audit must never block startup).
    """
    if not log_path:
        return None
    trusted = AUDIT_LOG_TRUSTED_DIR.expanduser().resolve()
    try:
        trusted.mkdir(parents=True, exist_ok=True, mode=0o700)
    except OSError:
        # If we can't create the trusted dir, fall back to db-only audit
        # rather than disabling audit entirely.
        logger.warning(
            "failed to create trusted audit dir %s; falling back to db-only audit",
            trusted, exc_info=True,
        )
        return None
    raw = Path(str(log_path)).expanduser()
    # If the caller gave a relative path, anchor it under the trusted dir.
    if not raw.is_absolute():
        candidate = trusted / raw
    else:
        candidate = raw
    try:
        # ``resolve(strict=False)`` follows symlinks; if the resolved path
        # is outside the trusted dir, reject.
        resolved = candidate.resolve(strict=False)
        resolved.relative_to(trusted)
    except (OSError, ValueError):
        logger.warning(
            "audit log path %s resolves outside the trusted dir %s; "
            "falling back to db-only audit", log_path, trusted,
        )
        return None
    # Open with O_NOFOLLOW so a symlink at the target is rejected; create
    # if missing.  Validate owner / mode / regular-file after open.
    try:
        fd = os.open(
            resolved,
            os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW,
            0o600,
        )
    except OSError:
        logger.warning(
            "failed to open audit log path %s; falling back to db-only audit",
            resolved, exc_info=True,
        )
        return None
    try:
        st = os.fstat(fd)
    finally:
        os.close(fd)
    if not _stat.S_ISREG(st.st_mode):
        logger.warning(
            "audit log path %s is not a regular file; falling back to db-only audit",
            resolved,
        )
        return None
    if st.st_uid != os.getuid():
        logger.warning(
            "audit log path %s is not owned by the current user; "
            "falling back to db-only audit", resolved,
        )
        return None
    if st.st_mode & 0o077:
        logger.warning(
            "audit log path %s has unsafe permissions %o; "
            "falling back to db-only audit", resolved, _stat.S_IMODE(st.st_mode),
        )
        return None
    return resolved


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
        )

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        return data


class AuditLogger:
    """Write and query audit records.

    M1: ``log_path`` is the optional file path from the effective policy's
    ``audit_log_path``.  When set, every record is appended as one JSON
    line to that file (in addition to the SQLite database) so an operator
    has an append-only trail outside the database.  The file write is
    best-effort.
    """

    def __init__(self, db, *, log_path: str | os.PathLike[str] | None = None):
        self.db = db
        self.log_path: Path | None = (
            Path(log_path).expanduser() if log_path else None
        )

    async def log(
        self,
        action: str,
        target: str,
        result: str,
        detail: dict[str, Any] | None = None,
        session_id: str | None = None,
    ) -> int:
        """Persist one audit row; return its id.

        ``detail`` is JSON-serialized. Pass a plain dict; primitives are kept
        readable for direct SQLite inspection.

        M1: when ``log_path`` is configured, the record is also appended as
        one JSON line to that file.  The file write is best-effort — a
        failure does NOT suppress the database write.
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
    ) -> None:
        """Append one audit record as a JSON line to ``self.log_path``.

        M1: synchronous file I/O is acceptable here because audit is on the
        hot path of every tool call but the write is a single small append;
        using ``aiofiles`` would add a dependency for negligible gain.  The
        file is opened in append mode so concurrent processes can safely
        append.
        """
        assert self.log_path is not None
        record = {
            "ts": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
            "action": action,
            "target": target,
            "result": result,
            "detail": json.loads(detail_json),
            "session_id": session_id,
        }
        line = json.dumps(record, ensure_ascii=False, sort_keys=True)
        # Ensure parent directory exists (best-effort).
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.log_path, "a", encoding="utf-8") as handle:
            handle.write(line + "\n")

    async def log_permission(
        self,
        tool_name: str,
        target: str,
        approved: bool,
        reason: str = "",
        session_id: str | None = None,
    ) -> int:
        """Record a permission decision (approved/denied)."""
        return await self.log(
            action=tool_name,
            target=target,
            result=RESULT_APPROVED if approved else RESULT_DENIED,
            detail={"reason": reason},
            session_id=session_id,
        )

    async def log_tool(
        self,
        tool_name: str,
        target: str,
        success: bool,
        duration_ms: int = 0,
        error: str = "",
        session_id: str | None = None,
    ) -> int:
        """Record a tool execution outcome."""
        return await self.log(
            action=tool_name,
            target=target,
            result=RESULT_SUCCESS if success else RESULT_ERROR,
            detail={"duration_ms": duration_ms, "error": error},
            session_id=session_id,
        )

    async def log_security_event(
        self,
        event_type: str,
        tool_name: str,
        reason: str,
        detail: dict[str, Any] | None = None,
        session_id: str | None = None,
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
        )

    async def query(
        self,
        action: str | None = None,
        result: str | None = None,
        since: str | datetime | None = None,
        until: str | datetime | None = None,
        limit: int = 100,
    ) -> list[AuditEntry]:
        """Query audit records, newest first, with optional filters."""
        rows = await self.db.query_audit_logs(
            action=action,
            result=result,
            since=_normalize_time(since),
            until=_normalize_time(until),
            limit=limit,
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
