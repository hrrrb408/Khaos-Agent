"""Independent local anchor for the SQLite audit hash chain.

The SQLite ``prev_hash`` chain is useful evidence, but a process that can
rewrite the database can also rewrite the chain head.  This module keeps a
small, separately opened chain-head file in the trusted audit directory.  It
detects rollback, truncation, and edits to the anchored prefix on the next
startup or write.

This is deliberately described as a *local independent anchor*: it is not a
remote WORM store and does not defend against an attacker who can rewrite both
the database and the user's trusted audit directory.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import stat
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


class AuditAnchorError(RuntimeError):
    """Raised when the independent audit anchor cannot be trusted."""


def anchor_filename(project_id: str) -> Path:
    """Return a safe, deterministic anchor basename for a project."""
    identity = str(project_id or "legacy").encode("utf-8")
    digest = hashlib.sha256(identity).hexdigest()[:32]
    return Path(f"chain-head-{digest}.json")


def _validate_directory(fd: int, label: str) -> None:
    stat_result = os.fstat(fd)
    if not stat.S_ISDIR(stat_result.st_mode):
        raise AuditAnchorError(f"trusted audit {label} is not a directory")
    if stat_result.st_uid != os.getuid():
        raise AuditAnchorError(
            f"trusted audit {label} is not owned by the current UID"
        )
    if stat.S_IMODE(stat_result.st_mode) != 0o700:
        raise AuditAnchorError(
            f"trusted audit {label} must have mode 0700, got "
            f"{stat.S_IMODE(stat_result.st_mode):o}"
        )


def _open_directory_component(parent_fd: int, name: str, label: str) -> int:
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    try:
        fd = os.open(name, flags, dir_fd=parent_fd)
    except FileNotFoundError:
        try:
            os.mkdir(name, 0o700, dir_fd=parent_fd)
            fd = os.open(name, flags, dir_fd=parent_fd)
        except OSError as exc:
            raise AuditAnchorError(
                f"cannot create trusted audit {label}: {exc}"
            ) from exc
    except OSError as exc:
        raise AuditAnchorError(f"cannot open trusted audit {label}: {exc}") from exc
    try:
        os.fchmod(fd, 0o700)
        _validate_directory(fd, label)
    except Exception:
        os.close(fd)
        raise
    return fd


def _open_anchor_file(trusted_dir: Path, filename: str) -> tuple[int, int]:
    """Open the anchor with dirfd-relative no-follow semantics."""
    if (
        os.open not in os.supports_dir_fd
        or os.mkdir not in os.supports_dir_fd
        or not hasattr(os, "O_DIRECTORY")
        or not hasattr(os, "O_NOFOLLOW")
    ):
        raise AuditAnchorError("dirfd/no-follow anchor operations are unavailable")
    if (
        trusted_dir.name != "audit"
        or trusted_dir.parent.name != ".khaos"
        or not filename
        or Path(filename).name != filename
        or filename in {".", ".."}
    ):
        raise AuditAnchorError("invalid trusted audit anchor path")

    directory_fds: list[int] = []
    keep_audit_fd = False
    audit_fd: int | None = None
    try:
        home_fd = os.open(
            str(trusted_dir.parent.parent),
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
        )
        directory_fds.append(home_fd)
        khaos_fd = _open_directory_component(home_fd, ".khaos", ".khaos")
        directory_fds.append(khaos_fd)
        audit_fd = _open_directory_component(khaos_fd, "audit", "audit")
        directory_fds.append(audit_fd)
        try:
            fd = os.open(
                filename, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW,
                0o600,
                dir_fd=audit_fd,
            )
        except OSError as exc:
            raise AuditAnchorError(f"cannot open audit chain anchor: {exc}") from exc
        try:
            stat_result = os.fstat(fd)
            if not stat.S_ISREG(stat_result.st_mode):
                raise AuditAnchorError("audit chain anchor is not a regular file")
            if stat_result.st_uid != os.getuid():
                raise AuditAnchorError("audit chain anchor is not owned by the current UID")
            if stat.S_IMODE(stat_result.st_mode) != 0o600:
                raise AuditAnchorError(
                    "audit chain anchor must have mode 0600, got "
                    f"{stat.S_IMODE(stat_result.st_mode):o}"
                )
        except Exception:
            os.close(fd)
            raise
        keep_audit_fd = True
        return fd, audit_fd
    except OSError as exc:
        raise AuditAnchorError(f"cannot open trusted audit home: {exc}") from exc
    finally:
        for fd in reversed(directory_fds):
            if keep_audit_fd and fd == audit_fd:
                continue
            try:
                os.close(fd)
            except OSError:
                pass


class AuditChainAnchor:
    """Persist and verify the latest SQLite audit-chain head."""

    def __init__(
        self,
        path: str | os.PathLike[str],
        *,
        project_id: str,
        database_path: str,
        trusted_dir: Path,
    ) -> None:
        anchor_path = Path(path)
        filename = anchor_path.name
        if anchor_path.parent not in {Path("."), trusted_dir}:
            raise AuditAnchorError("audit chain anchor must be a trusted basename")
        self.path = trusted_dir / filename
        self._fd, self._dir_fd = _open_anchor_file(trusted_dir, filename)
        self._project_id = str(project_id or "")
        self._database_id = hashlib.sha256(
            str(Path(database_path).expanduser().resolve()).encode("utf-8")
        ).hexdigest()
        self._lock = asyncio.Lock()
        self._verified = False

    def _read_state(self) -> dict[str, Any] | None:
        raw = os.pread(self._fd, 64 * 1024, 0)
        if len(raw) >= 64 * 1024:
            raise AuditAnchorError("audit chain anchor exceeds its size limit")
        lines = [line for line in raw.splitlines() if line.strip()]
        if not lines:
            return None
        try:
            value = json.loads(lines[-1].decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise AuditAnchorError("audit chain anchor is not valid JSON") from exc
        if not isinstance(value, dict):
            raise AuditAnchorError("audit chain anchor must contain a JSON object")
        return value

    def _write_state(self, head: dict[str, Any] | None) -> None:
        head_id = 0 if head is None else int(head["id"])
        head_hash = "" if head is None else str(head["hash"])
        state = {
            "format": 1,
            "project_id": self._project_id,
            "database_id": self._database_id,
            "head_id": head_id,
            "head_hash": head_hash,
            "updated_at": datetime.now(UTC).isoformat(),
        }
        raw = (json.dumps(state, ensure_ascii=False, sort_keys=True) + "\n").encode(
            "utf-8"
        )
        temporary_name = (
            f".{self.path.name}.{os.getpid()}.{id(self):x}.tmp"
        )
        temporary_fd: int | None = None
        replaced = False
        try:
            temporary_fd = os.open(
                temporary_name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                0o600,
                dir_fd=self._dir_fd,
            )
            view = memoryview(raw)
            while view:
                written = os.write(temporary_fd, view)
                if written <= 0:
                    raise AuditAnchorError("audit chain anchor write made no progress")
                view = view[written:]
            os.fsync(temporary_fd)
            os.close(temporary_fd)
            temporary_fd = None
            os.replace(
                temporary_name,
                self.path.name,
                src_dir_fd=self._dir_fd,
                dst_dir_fd=self._dir_fd,
            )
            replaced = True
            os.fsync(self._dir_fd)
            replacement_fd = os.open(
                self.path.name,
                os.O_RDWR | os.O_NOFOLLOW,
                dir_fd=self._dir_fd,
            )
            old_fd = self._fd
            self._fd = replacement_fd
            os.close(old_fd)
        except OSError as exc:
            raise AuditAnchorError("cannot atomically replace audit chain anchor") from exc
        finally:
            if temporary_fd is not None:
                try:
                    os.close(temporary_fd)
                except OSError:
                    pass
            if not replaced:
                try:
                    os.unlink(temporary_name, dir_fd=self._dir_fd)
                except OSError:
                    pass

    def _validate_state(self, state: dict[str, Any]) -> tuple[int, str]:
        if state.get("format") != 1:
            raise AuditAnchorError("unsupported audit chain anchor format")
        if state.get("project_id") != self._project_id:
            raise AuditAnchorError("audit chain anchor project identity mismatch")
        if state.get("database_id") != self._database_id:
            raise AuditAnchorError("audit chain anchor database identity mismatch")
        head_id = state.get("head_id")
        head_hash = state.get("head_hash")
        if type(head_id) is not int or head_id < 0:
            raise AuditAnchorError("audit chain anchor head_id is invalid")
        if type(head_hash) is not str:
            raise AuditAnchorError("audit chain anchor head_hash is invalid")
        if head_id == 0 and head_hash != "":
            raise AuditAnchorError("empty audit chain anchor has a non-empty hash")
        if head_id > 0 and len(head_hash) != 64:
            raise AuditAnchorError("audit chain anchor head_hash is malformed")
        return head_id, head_hash

    async def _check(self, database: Any, *, replay: bool) -> None:
        if replay:
            breaks = await database.verify_audit_chain()
            if breaks:
                raise AuditAnchorError(
                    "SQLite audit hash chain is broken: "
                    + ", ".join(str(item.get("id")) for item in breaks)
                )
        state = self._read_state()
        current = await database.get_audit_chain_head()
        if state is None:
            self._write_state(current)
            return
        anchor_id, anchor_hash = self._validate_state(state)
        anchored_row = (
            await database.get_audit_chain_head(anchor_id)
            if anchor_id > 0
            else None
        )
        if anchor_id > 0 and (
            anchored_row is None or anchored_row["hash"] != anchor_hash
        ):
            raise AuditAnchorError(
                "audit chain anchor does not match the persisted database prefix"
            )
        if anchor_id > 0 and not replay:
            breaks = await database.verify_audit_chain_since(anchor_id)
            if breaks:
                raise AuditAnchorError(
                    "SQLite audit hash chain suffix is broken: "
                    + ", ".join(str(item.get("id")) for item in breaks)
                )
        current_id = 0 if current is None else int(current["id"])
        if current_id < anchor_id:
            raise AuditAnchorError(
                "database audit chain rolled back behind the independent anchor"
            )
        if current_id != anchor_id or (current is not None and current["hash"] != anchor_hash):
            self._write_state(current)

    async def verify(self, database: Any) -> None:
        """Validate the chain, replaying it once per anchor lifecycle."""
        async with self._lock:
            await self._check(database, replay=not self._verified)
            self._verified = True

    async def observe(self, database: Any) -> None:
        """Verify the anchored prefix and advance the head after an insert."""
        async with self._lock:
            # Keep the anchor update fail-closed: a forged row must not become
            # the new trusted head merely because it was appended after the
            # last startup replay.
            await self._check(database, replay=False)
            self._verified = True

    def close(self) -> None:
        """Close the anchor descriptor (idempotent)."""
        if self._fd >= 0:
            try:
                os.close(self._fd)
            except OSError:
                pass
            self._fd = -1
        if self._dir_fd >= 0:
            try:
                os.close(self._dir_fd)
            except OSError:
                pass
            self._dir_fd = -1
