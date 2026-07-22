"""Python AgentService and MemoryService.

The service classes mirror the LLD gRPC surface. The JSON-line Unix socket
server keeps the control plane local without generated protobuf dependencies.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import hmac
import json
import logging
import os
import socket
import stat
import struct
import sys
import time
import uuid
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import AsyncIterator

# M4 batch 3.1.13 (CRITICAL-3): fcntl-based process-level exclusive
# lock to enforce the single-instance model.  Without this, a second
# process could ``unlink`` the live first process's UDS socket, open
# the same DB, and mark all RUNNING tasks as FAILED via
# ``recover_all_running_tasks`` — while the first process's executors
# kept running and producing side effects.  The lock is acquired
# BEFORE socket unlink / migration / recovery and held for the
# process lifetime.  fcntl is Unix-only; on Windows the UDS server
# itself is unavailable (``asyncio.start_unix_server`` doesn't exist),
# so the lock is a no-op there.
try:
    import fcntl as _fcntl
except ImportError:  # pragma: no cover — Windows
    _fcntl = None

from khaos.agent import AgentConfig, AgentLoop
from khaos.agent.approval import ApprovalBroker
from khaos.agent.compressor import ContextCompressor
from khaos.agent.error_handler import ErrorHandler
from khaos.audit import AuditLogger, resolve_safe_audit_log_path
from khaos.coding.task_manager import TaskManager
from khaos.coding.verify_fix import VerifyFixLoop
from khaos.coding.workspace.office_authority import OfficeMutationAuthority
from khaos.channels import (
    ChannelRegistry,
    ChannelType,
    PlatformMessage,
    WebhookHandler,
    WebhookRateLimiter,
    WebhookReplayGuard,
)
from khaos.db import Database
from khaos.exceptions import ServiceShutdownError
from khaos.memory import (
    Memory,
    MemoryBudget,
    MemoryConfidence,
    MemoryManager,
    MemoryScope,
    MemoryStore,
)
from khaos.modes import ModeManager
from khaos.permissions import PermissionEngine
from khaos.rust_bridge import get_token_engine
from khaos.routing.router import create_default_router
from khaos.routing import ModelRouter
from khaos.runtime import RequestContext
from khaos.scheduler import CronEngine
from khaos.security.middleware import SecurityMiddleware
from khaos.skills import SkillGenerator, SkillManager
from khaos.subagents import SubAgentConfig, SubAgentRunner, SubAgentService, SubAgentSpawner
from khaos.tools import create_runtime_registry
from khaos.tools.cron_tools import set_cron_engine
from khaos.tools.scheduler import ToolScheduler

logger = logging.getLogger(__name__)


RPC_MAX_REQUEST_BYTES = 1024 * 1024
RPC_AUTH_WINDOW_SECONDS = 30
# M2: bounded shutdown deadlines so a stuck handler / chat / detached
# subagent task cannot wedge server teardown.  These are fail-safe
# ceilings — the underlying close/orphan-drain phases still enforce the
# real terminal-state contracts (``ServiceShutdownError`` surfaces a
# quarantined runtime; the caller never observes a silent partial close).
SERVER_HANDLER_DRAIN_TIMEOUT = 5.0   # connection handler tasks
CHAT_DRAIN_TIMEOUT = 10.0            # active AgentService chat tasks
SUBAGENT_SHUTDOWN_TIMEOUT = 30.0     # detached SubAgent background tasks


def _instance_lockfile_path(db_path: str) -> Path:
    """M4 batch 3.1.14 (CRITICAL-2): compute the instance lockfile
    path in a TRUSTED directory (``~/.khaos/run/``).

    Previously the lockfile lived next to the DB (``<db_path>
    .instance.lock``).  When the DB was in a project directory (the
    default — ``khaos.db`` in the CWD), a malicious repository could
    pre-place a symlink at ``khaos.db.instance.lock`` pointing to
    e.g. ``~/.ssh/authorized_keys``.  The old code ``os.open``-ed
    WITHOUT ``O_NOFOLLOW`` (following the symlink), then
    ``ftruncate(fd, 0)`` — truncating the symlink target's content.

    The lockfile is now keyed by ``sha256(realpath(db_path))`` so
    different DB paths get different lockfiles, but the lockfiles all
    live under ``~/.khaos/run/`` which the user controls.
    """
    import hashlib
    real_db = str(Path(db_path).resolve())
    digest = hashlib.sha256(real_db.encode("utf-8")).hexdigest()[:32]
    return Path.home() / ".khaos" / "run" / f"{digest}.instance.lock"


def _ensure_safe_run_dir(run_dir: Path) -> None:
    """M4 batch 3.1.14 (CRITICAL-2): ensure ``~/.khaos/run/`` exists
    and is safe (owner-only, not a symlink).

    ``~/.khaos/`` (the parent) is a shared user config dir used by
    memory, audit, and other Khaos components.  It may legitimately
    have mode 0755 (default for user dirs).  We only require it to be
    owned by the current UID and not a symlink — an attacker who
    doesn't own the UID can't replace the ``run/`` subdir.

    ``~/.khaos/run/`` (the lockfile dir) MUST be owned by the current
    UID with mode ``0700`` — this is where lockfiles are created, and
    an attacker with write access here could pre-place a symlink.
    If the directory doesn't exist, create it with ``0700``.  If it
    exists but is a symlink, refuse.
    """
    khaos_dir = run_dir.parent
    # Check the parent ``~/.khaos/``: owned by us, not a symlink, is
    # a directory.  Mode is NOT checked — other Khaos components may
    # have created it with 0755.
    if not khaos_dir.exists():
        khaos_dir.mkdir(mode=0o755, parents=False, exist_ok=True)
    try:
        parent_st = khaos_dir.lstat()
    except OSError as exc:
        raise PermissionError(
            f"cannot stat trusted khaos dir {khaos_dir}: {exc}"
        ) from exc
    if stat.S_ISLNK(parent_st.st_mode):
        raise PermissionError(
            f"refusing to use symlinked khaos dir: {khaos_dir} "
            f"(CRITICAL-2: lockfile safety)"
        )
    if not stat.S_ISDIR(parent_st.st_mode):
        raise PermissionError(
            f"khaos dir is not a directory: {khaos_dir}"
        )
    if parent_st.st_uid != os.getuid():
        raise PermissionError(
            f"khaos dir {khaos_dir} is owned by uid "
            f"{parent_st.st_uid}, not the current uid {os.getuid()} "
            f"(CRITICAL-2: lockfile safety)"
        )
    # M4 batch 3.1.15 (HIGH-2): reject group/other-writable parent.
    # Even though ``~/.khaos/run/`` itself is 0700, a group/other-
    # writable ``~/.khaos/`` lets another user rename/replace the
    # ``run/`` directory itself — subsequent path-based ``os.open``
    # would enter the replacement directory.  Allow 0755/0700 (no
    # group/other write); reject 0775/0777.
    parent_mode = stat.S_IMODE(parent_st.st_mode)
    if parent_mode & 0o022:
        raise PermissionError(
            f"khaos dir {khaos_dir} has unsafe mode {parent_mode:o} "
            f"(group or other writable; expected no group/other write "
            f"bits) — refusing to use it for lockfile creation "
            f"(HIGH-2: lockfile parent dir safety)"
        )
    # Check / create the run dir with strict 0700.
    if not run_dir.exists():
        run_dir.mkdir(mode=0o700, parents=False, exist_ok=True)
    try:
        st = run_dir.lstat()
    except OSError as exc:
        raise PermissionError(
            f"cannot stat trusted run directory {run_dir}: {exc}"
        ) from exc
    if stat.S_ISLNK(st.st_mode):
        raise PermissionError(
            f"refusing to use symlinked trusted directory: {run_dir} "
            f"(CRITICAL-2: lockfile safety — a symlink could "
            f"redirect lockfile creation to an attacker-controlled "
            f"path)"
        )
    if not stat.S_ISDIR(st.st_mode):
        raise PermissionError(
            f"trusted run path is not a directory: {run_dir}"
        )
    if st.st_uid != os.getuid():
        raise PermissionError(
            f"trusted run directory {run_dir} is owned by uid "
            f"{st.st_uid}, not the current uid {os.getuid()} "
            f"(CRITICAL-2: lockfile safety)"
        )
    mode = stat.S_IMODE(st.st_mode)
    if mode & 0o077:
        raise PermissionError(
            f"trusted run directory {run_dir} has unsafe mode "
            f"{mode:o} (group/other bits set; expected 0700) — "
            f"refusing to use it for lockfile creation "
            f"(CRITICAL-2: lockfile safety)"
        )


def _acquire_instance_lock(db_path: str) -> int | None:
    """M4 batch 3.1.13 (CRITICAL-3) + 3.1.14 (CRITICAL-2) + 3.1.15
    (HIGH-2): acquire a process-level exclusive lock on a lockfile in
    a TRUSTED directory.

    The lock prevents a second Khaos process from opening the same DB
    and running ``recover_all_running_tasks`` (which marks ALL running
    tasks as FAILED) while the first process's executors are still
    alive.  Without this, the "single-instance model" was just a
    comment assumption — not an enforced safety constraint.

    M4 batch 3.1.14 (CRITICAL-2) — symlink truncation fix:
      Previously the lockfile lived next to the DB.  When the DB was
      in a project directory (the default), a malicious repo could
      pre-place a symlink at that path pointing to e.g.
      ``~/.ssh/authorized_keys``.  The old code ``os.open``-ed WITHOUT
      ``O_NOFOLLOW`` (following the symlink), then ``ftruncate(fd, 0)``
      — truncating the symlink target.

      The lockfile now lives under ``~/.khaos/run/<sha256(db_path)>
      .instance.lock``.  The run dir is verified to be owner-only
      (0700) and not a symlink.  The lockfile itself is opened with
      ``O_NOFOLLOW`` (refuses to follow symlinks), and we verify
      (lstat vs fstat) that the file we opened is the same file on
      disk (no inode swap race), is a regular file, is owned by the
      current UID, and has mode ``0600``.  Only AFTER all these
      checks pass do we ``ftruncate`` and write the PID.

    M4 batch 3.1.15 (HIGH-2) — path-based identity re-verification:
      The previous post-flock re-check only called ``fstat(fd)`` and
      compared it to the PRE-flock ``fstat(fd)``.  Since ``flock``
      locks the fd (not the path), an attacker who replaced the path
      between ``open`` and ``flock`` would leave us holding a lock on
      the OLD inode while the path points to a NEW inode — and a
      second process opening the path would get a different fd with
      no lock contention.  The old re-check (fstat-vs-fstat) could
      NOT detect this because both fstats hit the same fd.

      The fix opens the trusted run directory as a ``dir_fd`` and
      uses ``openat`` (``os.open(..., dir_fd=run_dir_fd)``) to open
      the lockfile relative to it.  After ``flock``, we re-``lstat``
      the path via ``dir_fd`` and compare its ``(st_dev, st_ino)``
      with the lock fd's ``fstat``.  If they differ, the path was
      replaced after we opened it — the lock fd points to a stale
      inode while the path points elsewhere, and a second process
      could acquire a separate lock.  Refuse.

    The lock is ``fcntl.LOCK_EX | fcntl.LOCK_NB`` (non-blocking): if
    another process holds it, we fail immediately with
    ``PermissionError``.  The lock is released automatically when the
    process exits (the fd is closed by the OS).

    Returns the lock fd (which MUST be kept open for the process
    lifetime), or ``None`` on platforms without fcntl (Windows — the
    UDS server itself is unavailable there).
    """
    if _fcntl is None:
        return None
    lockfile_path = _instance_lockfile_path(db_path)
    run_dir = lockfile_path.parent
    _ensure_safe_run_dir(run_dir)
    lockfile_name = lockfile_path.name  # relative to run_dir
    # M4 batch 3.1.15 (HIGH-2): open the trusted run directory as a
    # dir_fd so we can use ``openat`` for the lockfile and re-lstat
    # the path via the same dir_fd after flock.
    run_dir_fd = os.open(
        str(run_dir),
        os.O_DIRECTORY | os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
    )
    try:
        return _acquire_instance_lock_via_dir_fd(
            run_dir_fd, lockfile_name, lockfile_path,
        )
    finally:
        os.close(run_dir_fd)


def _acquire_instance_lock_via_dir_fd(
    run_dir_fd: int, lockfile_name: str, lockfile_path: Path,
) -> int:
    """M4 batch 3.1.15 (HIGH-2): inner lockfile acquisition using
    ``openat(dir_fd)``.  Separated from ``_acquire_instance_lock`` so
    the ``run_dir_fd`` lifecycle is clean (caller closes it).
    """
    # M4 batch 3.1.14 (CRITICAL-2): open with O_NOFOLLOW so a symlink
    # at the lockfile path is NOT followed (raises ELOOP).  O_CLOEXEC
    # so the fd doesn't leak into child processes (exec / subagents).
    flags = os.O_CREAT | os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW
    # lstat BEFORE open to detect a symlink (O_NOFOLLOW already
    # refuses symlinks, but we lstat first for a clearer error
    # message and to detect the race where the file is replaced
    # between lstat and open).  Use dir_fd for the lstat.
    try:
        pre_lstat = os.lstat(lockfile_name, dir_fd=run_dir_fd)
        if stat.S_ISLNK(pre_lstat.st_mode):
            raise PermissionError(
                f"refusing to open symlinked lockfile: {lockfile_path} "
                f"(CRITICAL-2: lockfile symlink truncation defense)"
            )
    except FileNotFoundError:
        pre_lstat = None  # Will be created by open.
    # M4 batch 3.1.15 (HIGH-2): openat — lockfile is relative to run_dir_fd.
    fd = os.open(lockfile_name, flags, 0o600, dir_fd=run_dir_fd)
    try:
        # M4 batch 3.1.14 (CRITICAL-2): validate the fd we just
        # opened.  fstat the fd and compare (st_dev, st_ino) with the
        # lstat we did before open — if they differ, someone swapped
        # the file between lstat and open (TOCTOU race).  Also verify
        # it's a regular file, owned by us, with mode <= 0600.
        fstat_info = os.fstat(fd)
        if not stat.S_ISREG(fstat_info.st_mode):
            raise PermissionError(
                f"lockfile {lockfile_path} is not a regular file "
                f"(CRITICAL-2: lockfile safety)"
            )
        if fstat_info.st_uid != os.getuid():
            raise PermissionError(
                f"lockfile {lockfile_path} is owned by uid "
                f"{fstat_info.st_uid}, not the current uid "
                f"{os.getuid()} (CRITICAL-2: lockfile safety)"
            )
        fstat_mode = stat.S_IMODE(fstat_info.st_mode)
        if fstat_mode & 0o077:
            raise PermissionError(
                f"lockfile {lockfile_path} has unsafe mode "
                f"{fstat_mode:o} (group/other bits set; expected "
                f"0600) — refusing to truncate (CRITICAL-2: "
                f"lockfile safety)"
            )
        if pre_lstat is not None:
            if (fstat_info.st_dev, fstat_info.st_ino) != (
                pre_lstat.st_dev, pre_lstat.st_ino,
            ):
                raise PermissionError(
                    f"lockfile {lockfile_path} changed identity "
                    f"between lstat and open (TOCTOU race; "
                    f"CRITICAL-2: lockfile safety)"
                )
        # All checks passed — acquire the flock.
        try:
            _fcntl.flock(fd, _fcntl.LOCK_EX | _fcntl.LOCK_NB)
        except OSError as exc:
            # Another process holds the lock — convert to
            # PermissionError for a clearer error message.
            raise PermissionError(
                f"another Khaos instance holds the exclusive lock on "
                f"{lockfile_path}; refusing to start (single-instance "
                f"model enforced — CRITICAL-3)"
            ) from exc
    except BaseException:
        # On ANY failure (including PermissionError from the checks
        # above, or OSError from flock), close the fd so we don't
        # leak it.  The caller will see the raised exception.
        os.close(fd)
        raise
    # M4 batch 3.1.15 (HIGH-2): re-verify PATH identity after flock.
    # ``flock`` locks the fd, not the path.  If an attacker replaced
    # the path between ``open`` and ``flock``, our fd locks the OLD
    # inode while the path points to a NEW inode.  A second process
    # opening the path would get a different fd with no contention.
    # The old re-check (fstat-vs-fstat) could NOT detect this because
    # both fstats hit the same fd.  The fix: re-lstat the PATH via
    # ``dir_fd`` and compare its ``(st_dev, st_ino)`` with the lock
    # fd's ``fstat``.  If they differ, the path was replaced — refuse.
    post_fstat = os.fstat(fd)
    try:
        post_path_lstat = os.lstat(lockfile_name, dir_fd=run_dir_fd)
    except FileNotFoundError:
        # The path was unlinked after we opened it.  Our fd still
        # points to the old inode (now unlinked).  A second process
        # creating the path would get a NEW inode with no contention.
        # Refuse — the lock is not protecting the path anymore.
        os.close(fd)
        raise PermissionError(
            f"lockfile {lockfile_path} was unlinked after flock; the "
            f"path no longer matches the locked inode — refusing to "
            f"start (HIGH-2: lockfile path identity)"
        )
    if (post_path_lstat.st_dev, post_path_lstat.st_ino) != (
        post_fstat.st_dev, post_fstat.st_ino,
    ):
        os.close(fd)
        raise PermissionError(
            f"lockfile {lockfile_path} path identity changed after "
            f"flock (path inode != locked inode); a second process "
            f"could acquire a separate lock — refusing to start "
            f"(HIGH-2: lockfile path identity)"
        )
    # Write the current PID for diagnostics (not used for locking —
    # the flock is the authoritative lock).
    try:
        os.ftruncate(fd, 0)
        os.write(fd, f"{os.getpid()}\n".encode("utf-8"))
        os.fsync(fd)
    except OSError:
        pass  # non-fatal — the lock itself is what matters
    return fd


def _probe_uds_liveness(uds_path: Path) -> bool:
    """M4 batch 3.1.13 (CRITICAL-3): probe whether a live process is
    listening on the given UDS path.

    Attempts a non-blocking ``connect`` to the socket.  If the connect
    succeeds (or raises ``EINPROGRESS`` then completes), a live server
    is listening → return ``True``.  If the connect fails with
    ``ECONNREFUSED``, the socket is stale (the server process died
    without unlinking) → return ``False``.  Other errors are
    treated conservatively as "alive" (fail-closed — don't unlink a
    socket we're not sure about).

    This is called BEFORE ``uds_path.unlink()`` so a live first
    process's socket is NOT replaced by a second process.
    """
    probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    probe.setblocking(False)
    try:
        probe.connect(str(uds_path))
        # Non-blocking connect returns EINPROGRESS on Unix; the socket
        # is writable when the connect completes.  A successful connect
        # means a server accepted it — the instance is alive.
        #
        # M4 batch 3.1.16B-4: use ``selectors.DefaultSelector``
        # instead of ``select.select``.  ``select.select`` has a hard
        # fd-number ceiling of 1024 on macOS (FD_SETSIZE), which
        # causes ``ValueError: filedescriptor out of range in select()``
        # when the test suite has accumulated many open fds.  The
        # ``selectors`` module auto-selects ``poll`` / ``kqueue`` /
        # ``epoll`` on platforms that support them, none of which have
        # the 1024 fd limit.  This is the standard library's
        # recommended replacement for ``select.select``.
        import selectors
        with selectors.DefaultSelector() as sel:
            sel.register(probe, selectors.EVENT_WRITE)
            ready = sel.select(timeout=0.5)
            if ready:
                # Check SO_ERROR — 0 means connected successfully.
                err = probe.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
                return err == 0
            # Timeout — assume alive (conservative).
            return True
    except ConnectionRefusedError:
        # Stale socket — no process is listening.
        return False
    except FileNotFoundError:
        # Socket doesn't exist (race — already unlinked).
        return False
    except OSError:
        # Other errors (EACCES, ENOTSOCK, etc.) — be conservative.
        return True
    finally:
        probe.close()


# M4 batch 3.1.15 (CRITICAL-1): process-level retained instance lock.
# When ``serve_json_lines`` cannot complete a clean shutdown (live cron
# executors resist cancellation, or emergency cleanup fails), the
# instance lock fd is parked here so it is NOT closed by the outer
# ``finally`` block.  The OS reaps the fd when the process exits,
# preventing a second instance from starting against the same DB while
# the first process's live owners are still producing side effects.
# See ``serve_json_lines`` for the full rationale.
_retained_instance_lock_fd: int | None = None


async def _emergency_instance_cleanup(
    agent: AgentService | None,
    db: Database | None,
    subagent_service: SubAgentService | None,
) -> bool:
    """M4 batch 3.1.15 (CRITICAL-1 + HIGH-1): attempt to clean up
    partially-initialized or partially-torn-down resources.

    Called by the ``serve_json_lines`` outer ``finally`` when the inner
    cleanup did NOT complete cleanly (either init failed after
    ``agent.start()``, or the inner ``finally`` raised during
    teardown).  Returns ``True`` only if ALL cleanups succeed — in
    that case the instance lock can be safely released.  Returns
    ``False`` if ANY cleanup fails (live owners remain) — the caller
    must RETAIN the instance lock.

    Each cleanup is best-effort and idempotent:
      - ``subagent_service.shutdown()`` — bounded by SUBAGENT_SHUTDOWN_TIMEOUT.
      - ``agent.shutdown()`` — idempotent via ``_shutdown_completed`` flag.
      - ``db.close()`` — idempotent (sets ``_conn = None``).
    """
    ok = True
    if subagent_service is not None:
        try:
            await subagent_service.shutdown(timeout=SUBAGENT_SHUTDOWN_TIMEOUT)
        except Exception:  # noqa: BLE001 — best-effort cleanup
            logger.error(
                "emergency cleanup: subagent_service.shutdown() failed; "
                "live subagent owners may remain",
                exc_info=True,
            )
            ok = False
    if agent is not None:
        try:
            await agent.shutdown()
        except Exception:  # noqa: BLE001 — best-effort cleanup
            logger.error(
                "emergency cleanup: agent.shutdown() failed; live cron "
                "executors or chat owners may remain",
                exc_info=True,
            )
            ok = False
    if db is not None:
        try:
            await db.close()
        except Exception:  # noqa: BLE001 — best-effort cleanup
            logger.error(
                "emergency cleanup: db.close() failed",
                exc_info=True,
            )
            ok = False
    return ok


def _load_rpc_capability() -> str:
    path_value = os.environ.get("KHAOS_PYTHON_CAPABILITY_FILE", "").strip()
    if path_value:
        path = Path(path_value).expanduser()
        if not path.is_absolute():
            raise PermissionError("RPC capability file path must be absolute")
        entry = path.lstat()
        if stat.S_ISLNK(entry.st_mode):
            raise PermissionError("RPC capability file must not be a symlink")
        if not stat.S_ISREG(entry.st_mode) or entry.st_uid != os.getuid():
            raise PermissionError("RPC capability file must be an owner-held regular file")
        mode = stat.S_IMODE(entry.st_mode)
        is_container_secret = str(path).startswith("/run/secrets/")
        if (is_container_secret and mode & 0o222) or (
            not is_container_secret and mode & 0o077
        ):
            raise PermissionError("RPC capability file permissions are unsafe")
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            opened = os.fstat(fd)
            if (opened.st_dev, opened.st_ino) != (entry.st_dev, entry.st_ino):
                raise PermissionError("RPC capability file identity changed")
            content = os.read(fd, 4097)
        finally:
            os.close(fd)
        final = path.lstat()
        if (final.st_dev, final.st_ino) != (entry.st_dev, entry.st_ino):
            raise PermissionError("RPC capability file identity changed")
        if len(content) > 4096:
            raise PermissionError("RPC capability file is too large")
        capability = content.decode("utf-8").strip()
    elif os.environ.get("KHAOS_ALLOW_LEGACY_CAPABILITY_ENV") == "1":
        capability = os.environ.get("KHAOS_PYTHON_CAPABILITY", "")
    else:
        raise PermissionError(
            "RPC capability requires an inherited value or protected capability file"
        )
    if len(capability) < 32:
        raise PermissionError("RPC capability must contain at least 32 characters")
    return capability


# H2: ``resolve_safe_audit_log_path`` and ``AUDIT_LOG_TRUSTED_DIR`` live in
# ``khaos.audit`` so the runtime factory (used by CLI / TUI / tests) shares
# the same trust boundary as the gRPC server path (M1).  The effective
# policy compiler drops the project layer's ``audit_log_path`` entirely;
# only the user layer may set it, and even then it MUST resolve under
# ``~/.khaos/audit/`` (validated with ``O_NOFOLLOW`` + owner/mode checks).


class GatewayRPCAuthenticator:
    """Verify peer UID and one-shot, method-scoped Gateway capabilities."""

    def __init__(
        self,
        capability: str,
        *,
        expected_uid: int | None = None,
        expected_pid: int | None = None,
    ) -> None:
        if len(capability) < 32:
            raise ValueError("Gateway RPC capability must contain at least 32 characters")
        self._key = capability.encode("utf-8")
        self._expected_uid = os.getuid() if expected_uid is None else expected_uid
        self._expected_pid = expected_pid
        self._bound_pid: int | None = None
        self._used_nonces: dict[str, float] = {}

    def verify_peer(self, writer: asyncio.StreamWriter) -> int:
        peer = writer.get_extra_info("socket")
        if peer is None:
            raise PermissionError("RPC peer socket identity is unavailable")
        peer = getattr(peer, "_sock", peer)
        peer_pid: int | None = None
        try:
            if hasattr(peer, "getpeereid"):
                peer_uid, _peer_gid = peer.getpeereid()
                if sys.platform == "darwin":
                    peer_pid = struct.unpack(
                        "=i",
                        peer.getsockopt(getattr(socket, "SOL_LOCAL", 0), 2, 4),
                    )[0]
            elif hasattr(socket, "LOCAL_PEERCRED"):
                credentials = peer.getsockopt(
                    getattr(socket, "SOL_LOCAL", 0), socket.LOCAL_PEERCRED, 128
                )
                if len(credentials) < 8:
                    raise PermissionError("RPC peer credentials are truncated")
                _version, peer_uid = struct.unpack_from("=II", credentials)
                if sys.platform == "darwin":
                    peer_pid = struct.unpack(
                        "=i",
                        peer.getsockopt(getattr(socket, "SOL_LOCAL", 0), 2, 4),
                    )[0]
            elif hasattr(socket, "SO_PEERCRED"):
                credentials = peer.getsockopt(
                    socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")
                )
                peer_pid, peer_uid, _peer_gid = struct.unpack("3i", credentials)
            else:
                raise PermissionError("RPC peer credentials are unsupported")
        except PermissionError:
            raise
        except OSError as exc:
            # M4 batch 3.1.16B-4: macOS ``getsockopt(SOL_LOCAL,
            # LOCAL_PEERPID)`` raises ``OSError(57, ENOTCONN)`` when
            # the peer has already half-closed the connection (common
            # in test suites that open + close rapidly).  Previously
            # this propagated as an unhandled OSError, crashed the
            # ``handle`` coroutine, and left the client with an empty
            # event stream (causing ``KeyError: 'event'`` in
            # ``test_triad_smoke``).  Treat it as "peer identity
            # unavailable" — fail-closed (reject the connection).
            raise PermissionError(
                f"RPC peer socket is not connected: {exc} "
                f"(fail-closed — peer identity unavailable)"
            ) from exc
        if peer_uid != self._expected_uid:
            raise PermissionError("RPC peer UID is not the configured Gateway UID")
        if peer_pid is None or peer_pid <= 0:
            raise PermissionError("RPC peer PID is unavailable")
        if self._expected_pid is not None and peer_pid != self._expected_pid:
            raise PermissionError("RPC peer PID is not the configured Gateway PID")
        return peer_pid

    def authenticate(self, request: dict, *, peer_pid: int | None = None) -> str:
        method = str(request.get("method") or "")
        payload = request.get("payload", {})
        auth = request.get("auth")
        if not isinstance(auth, dict) or not isinstance(payload, dict):
            raise PermissionError("RPC authentication envelope is required")
        nonce = str(auth.get("nonce") or "")
        principal_id = str(auth.get("principal_id") or "")
        payload_digest = str(auth.get("payload_digest") or "")
        mac = str(auth.get("mac") or "")
        try:
            issued_at = int(auth.get("issued_at"))
        except (TypeError, ValueError) as exc:
            raise PermissionError("RPC issued_at is invalid") from exc
        now = int(time.time())
        if abs(now - issued_at) > RPC_AUTH_WINDOW_SECONDS:
            raise PermissionError("RPC capability has expired")
        if len(nonce) < 32 or nonce in self._used_nonces:
            raise PermissionError("RPC nonce is invalid or replayed")
        canonical_payload = json.dumps(
            payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        ).encode("utf-8")
        expected_digest = hashlib.sha256(canonical_payload).hexdigest()
        if not hmac.compare_digest(payload_digest, expected_digest):
            raise PermissionError("RPC payload digest mismatch")
        signed = (
            f"{method}\n{nonce}\n{issued_at}\n{principal_id}\n{payload_digest}"
        ).encode("utf-8")
        method_key = hmac.new(
            self._key,
            f"khaos-rpc-method-v1\n{method}".encode("utf-8"),
            hashlib.sha256,
        ).digest()
        expected_mac = hmac.new(method_key, signed, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(mac, expected_mac):
            raise PermissionError("RPC method capability is invalid")
        claimed_principal = str(payload.get("principal_id") or "")
        if claimed_principal and claimed_principal != principal_id:
            raise PermissionError("RPC payload principal is not transport-bound")
        if peer_pid is not None:
            if self._bound_pid is None:
                self._bound_pid = peer_pid
            elif peer_pid != self._bound_pid:
                raise PermissionError("RPC peer PID does not match the bound Gateway")
        self._used_nonces[nonce] = float(issued_at)
        cutoff = now - RPC_AUTH_WINDOW_SECONDS
        self._used_nonces = {
            key: value for key, value in self._used_nonces.items()
            if value >= cutoff
        }
        return principal_id


@dataclass
class ChatRequest:
    session_id: str
    message: str
    mode: str = ""
    principal_id: str = ""


@dataclass
class ConfirmRequest:
    session_id: str
    tool_call_id: str
    approved: bool
    remember: bool = False
    principal_id: str = ""
    binding_digest: str = ""


class AgentService:
    """Agent RPC service backed by AgentLoop."""

    def __init__(self, db: Database, project_root: Path | None = None, config_path: Path | None = None, router=None):
        self.db = db
        self.project_root = project_root or Path.cwd()
        self.config_path = config_path or self.project_root / "config.yaml"
        self._router = router
        self.pending_confirmations: dict[str, dict] = {}
        self.approval_broker = ApprovalBroker(db=db)
        # Shared coding-task tracker so the TUI / TaskService can observe
        # long-running coding turns alongside the AgentLoop.
        # A3-6: bind the server-lifecycle TaskManager to the local-uid
        # principal (matching the server-lifecycle AuditLogger / MemoryService
        # above) so tasks created via the JSON-line RPC path are owned by
        # the local user and invisible to any other authenticated principal.
        # Per-turn runtimes constructed by ``build_runtime`` carry their own
        # principal-scoped TaskManager via ``RuntimeConfig.principal_id``.
        #
        # C-1-5a: the server-level ``TaskManager(local-uid)`` singleton
        # is REMOVED.  ``TaskService`` now holds ``db`` and constructs
        # per-principal ``TaskManager`` instances on demand (cached for
        # the process lifetime).  This allows API principals to
        # ``create`` / ``list`` / ``get`` / ``cancel`` their own tasks
        # (previously ``create`` was rejected and ``list``/``get``
        # returned empty for API principals).  ``_build_runtime`` no
        # longer passes a shared task_manager — ``build_runtime``
        # constructs a per-turn manager from ``cfg.principal_id``
        # (factory.py:502-517).
        # H2: compile the *layered* effective policy (user ∩ project ∩
        # platform) once at startup — never consult the raw project policy
        # for enforcement decisions.  An untrusted repo can no longer
        # silently disable audit by setting ``audit.enabled: false`` in
        # its ``khaos_policy.yaml``: the effective policy's ``audit_enabled``
        # uses OR semantics (if the user layer requires audit, the project
        # cannot disable it).
        from khaos.security.effective_policy import load_effective_policy
        self._effective_policy = load_effective_policy(self.project_root)
        logger.info(
            "effective security policy digest: %s (audit_enabled=%s)",
            self._effective_policy.digest,
            self._effective_policy.audit_enabled,
        )
        # M4 batch 3.1.16B-1 (CRITICAL): bind the CronEngine to the
        # effective policy digest + project_id so every scheduled task
        # captures the security-context snapshot at creation time.  B-2
        # will compare these against the live values at ``start()`` and
        # ``_execute_task`` claim time to detect policy/project drift.
        # ``project_id`` is derived from the project root via
        # ``state_root.project_id`` (sha256(realpath(root))[:32]).
        from khaos.db.state_root import project_id as _compute_project_id
        # M4 batch 3.1.16A-4-1: store as a member so the RPC dispatcher
        # can build RequestContext with the correct project_id without
        # recomputing it per request.
        self._bound_project_id = _compute_project_id(self.project_root)
        _bound_project_id = self._bound_project_id
        # H1: a single server-lifecycle AuditLogger shared by the main runtime
        # AND every SubAgent run, so security events from both paths land in
        # the same audit trail.  ``log_path`` comes from the effective policy
        # (user ∩ project, OR semantics — an untrusted project cannot disable
        # audit).  H2: ``resolve_safe_audit_log_path`` constrains the path
        # to a trusted directory so an untrusted project cannot point audit
        # at an arbitrary host file (symlink / FIFO / device attacks).
        # M4 batch 3.1.16B-3: constructed BEFORE CronEngine so it can be
        # injected into the engine for drift-quarantine audit logging.
        self._audit_logger = (
            AuditLogger(
                self.db,
                log_path=resolve_safe_audit_log_path(
                    self._effective_policy.audit_log_path
                ),
                # A2-6: bind the server-lifecycle AuditLogger to the
                # local-uid principal (matching MemoryService / ModeManager
                # above) and stamp the effective policy digest on every row
                # so audit attribution matches the runtime that produced it.
                # ``runtime_id`` is left None at the server level; per-runtime
                # AuditLoggers constructed by ``build_runtime`` carry it.
                principal_id=f"local-uid:{os.getuid()}",
                policy_digest=self._effective_policy.digest,
                # M4 batch 3.1.16A-5-1b: stamp the server-bound project
                # identity on every audit row.  The dispatcher's drift
                # check guarantees every RPC reaching a service method
                # has ``ctx.project_id == self._bound_project_id``, so
                # this is the canonical project identity for all server-
                # lifecycle audit events (webhook / cron / channel
                # mutations).  Per-runtime AuditLoggers constructed by
                # ``build_runtime`` get the same value via
                # ``RuntimeConfig.project_id``.
                project_id=_bound_project_id,
            )
            if self._effective_policy.audit_enabled
            else None
        )
        self.cron_engine = CronEngine(
            db=db,
            executor=self._execute_scheduled_prompt,
            project_id=_bound_project_id,
            policy_digest=self._effective_policy.digest,
            # M4 batch 3.1.16B-3: inject the server-lifecycle AuditLogger
            # so drift quarantine events land in the audit trail.
            audit_logger=self._audit_logger,
        )
        set_cron_engine(self.cron_engine)
        self.channel_registry = ChannelRegistry()
        self._webhook_replay_guard = WebhookReplayGuard(
            consumer=self.db.consume_webhook_event
        )
        self._verified_webhook_limiter = WebhookRateLimiter()
        # M4 batch 3.1.16A-4-4-3: the module-global ``set_channel_registry``
        # call has been removed.  The four channel tools now receive
        # ``channel_registry`` + ``principal_id`` (+ ``channel_admins`` for
        # mutations) per-call via the ``channel.read`` / ``channel.manage``
        # broker injection from ``tool_context`` (assembled by
        # ``AgentLoop`` from ``self.channel_registry`` and
        # ``self._effective_policy.channel_admins``).  See
        # ``channel_tools.py`` docstring for the cross-principal mutation
        # risk that the holder posed.
        # B1: the OfficeMutationAuthority is a server-lifecycle object shared
        # across every chat / webhook / cron turn.  Reusing one instance keeps
        # the aggregate storage baseline stable across turns (closing the
        # cross-turn quota bypass).  Per-turn runtimes borrow it (via
        # RuntimeConfig.office_authority); RuntimeResult.aclose does NOT close
        # it — AgentService.shutdown does.
        self._office_authority = OfficeMutationAuthority()
        self._accepting_work = True
        self._active_chat_tasks: set[asyncio.Task] = set()
        self._active_runtimes: dict[int, object] = {}
        self._office_shutdown_task: asyncio.Task | None = None
        self.shutdown_failed = False
        # M4 batch 3.1.15 (CRITICAL-1): idempotency flag for shutdown().
        # Set to True only on clean completion.  Allows the outer
        # emergency-cleanup path to safely re-call shutdown() without
        # double-closing shared authorities.
        self._shutdown_completed = False
        # M2 (round-3): admission lock serialises ``chat``'s admission
        # decision + owner reservation against ``shutdown``'s
        # ``_accepting_work = False`` flip + owner snapshot.  Without it,
        # a chat that passed the accepting_work check could be mid-await
        # in ``_build_runtime`` while shutdown snapshotted an empty
        # ``_active_chat_tasks`` and proceeded to dismantle shared
        # authorities — the chat would then resume and register a runtime
        # after shutdown believed all owners were drained.  The JSON-line
        # server's connection-handler registry is an outer guard for the
        # production RPC path, but ``AgentService`` is also a direct
        # caller (cron / webhook) and its lifecycle contract must hold
        # independently.
        self._admission_lock = asyncio.Lock()

    async def start(self) -> None:
        """Start process-scoped background services."""
        # C-1-5a: ``TaskService`` now lazily constructs per-principal
        # TaskManagers on first use (``_manager(ctx)``), so there's no
        # server-level ``task_manager.load()`` at startup.
        await self.cron_engine.start()

    async def stop_producers(self) -> None:
        """Reject new turns and stop background producers before teardown."""
        self._accepting_work = False
        await self.cron_engine.stop()

    async def shutdown(self) -> None:
        """Stop process-scoped background services."""
        # M4 batch 3.1.15 (CRITICAL-1): idempotency guard.  If a previous
        # shutdown() completed cleanly, this is a no-op.  If a previous
        # call raised, the flag is NOT set and re-entry is allowed (each
        # internal step is itself idempotent — cron stop via state machine,
        # chat drain via fresh snapshot, runtime drain via registry scan).
        if self._shutdown_completed:
            return
        # Stop producers, then cancel/wait every active turn while shared
        # authorities and the database are still available.
        await self.stop_producers()
        # Take the admission lock for the accepting_work flip and owner
        # snapshot so a concurrent ``chat`` cannot publish a runtime AFTER
        # this snapshot.  This lock acquisition is bounded: chat only holds
        # the lock for cheap dict mutations (reserve / publish), NOT across
        # ``_build_runtime`` (which is slow DB I/O) — so a wedged build
        # cannot block this shutdown from reaching the bounded drain below.
        # See ``chat()``'s reservation pattern.
        async with self._admission_lock:
            # stop_producers already set _accepting_work=False outside the
            # lock; re-assert it under the lock so chat's admission check
            # (under the same lock) cannot observe a stale True here.
            self._accepting_work = False
            current = asyncio.current_task()
            active_tasks = [
                task for task in self._active_chat_tasks
                if task is not current and not task.done()
            ]
        for task in active_tasks:
            task.cancel()
        if active_tasks:
            # M1: bounded drain with hard ownership semantics.  A task that
            # swallows CancelledError used to make ``wait_for(gather)``
            # raise TimeoutError, which the previous code only logged before
            # continuing to dismantle Office/Browser/Audit/DB — while the
            # swallowing task was still running and borrowing exactly those
            # authorities.  ``asyncio.wait`` returns the pending set so we
            # can fail closed: if any chat is still running at the deadline,
            # refuse teardown by raising ``ServiceShutdownError``.  The
            # residual runtime is still registered in ``_active_runtimes``
            # and will be closed or quarantined by the next owner.
            done, pending = await asyncio.wait(
                active_tasks, timeout=CHAT_DRAIN_TIMEOUT,
            )
            if pending:
                logger.error(
                    "agent shutdown: %d chat task(s) did not terminate within "
                    "%.2fs (swallowed cancellation or wedged); refusing to "
                    "tear down shared authorities",
                    len(pending), CHAT_DRAIN_TIMEOUT,
                )
                self.shutdown_failed = True
                raise ServiceShutdownError(
                    f"{len(pending)} chat task(s) did not terminate within "
                    f"{CHAT_DRAIN_TIMEOUT}s; shared authorities cannot be "
                    f"torn down safely"
                )

        # Defensive ownership pass: a handler cancellation must normally run
        # chat's finally block, but retain/close anything still registered.
        from khaos.runtime import close_runtime_or_register
        for runtime in list(self._active_runtimes.values()):
            try:
                await close_runtime_or_register(runtime)
            except Exception:
                # close_runtime_or_register already quarantines terminal
                # failures.  Continue so drain can retry all retained owners.
                logger.error("active runtime teardown failed", exc_info=True)

        from khaos.runtime import drain_orphan_runtimes
        remaining = await drain_orphan_runtimes(timeout_seconds=5.0)
        if remaining:
            logger.error(
                "server shutdown retaining %d quarantined runtime(s)", remaining
            )
            self.shutdown_failed = True
            raise ServiceShutdownError(
                f"{remaining} runtime(s) did not reach a terminal state"
            )
        # Fence every in-flight Office mutation after runtimes have settled.
        await self._shutdown_office_authority()
        # BrowserManager is process-scoped.  Its close contract retains
        # failed Context owners and returns an observable error; do not close
        # Audit/DB state if the browser generation is still live.
        from khaos.tools.browser_tools import _manager as browser_manager
        browser_result = await browser_manager.close()
        if not browser_result.get("ok"):
            self.shutdown_failed = True
            raise ServiceShutdownError(
                f"shared BrowserManager shutdown failed: "
                f"{browser_result.get('error', 'unknown error')}"
            )
        # The shared AuditLogger is process-owned and is closed exactly once,
        # after all runtime/authority shutdown events had a chance to log.
        if self._audit_logger is not None:
            self._audit_logger.close()
        self.shutdown_failed = False
        # M4 batch 3.1.15 (CRITICAL-1): mark shutdown as completed so
        # subsequent calls are no-ops.  Set ONLY on the clean exit path.
        self._shutdown_completed = True

    async def _shutdown_office_authority(
        self, *, attempts: int = 3, timeout_seconds: float = 5.0,
    ) -> None:
        """Close the shared mutation authority with bounded observable retry."""
        last_error: BaseException | None = None
        for attempt in range(1, attempts + 1):
            if self._office_shutdown_task is None:
                self._office_shutdown_task = asyncio.create_task(
                    self._office_authority.shutdown()
                )
            try:
                await asyncio.wait_for(
                    asyncio.shield(self._office_shutdown_task),
                    timeout=timeout_seconds,
                )
                self._office_shutdown_task = None
                return
            except asyncio.TimeoutError as exc:
                # The shielded task still owns the mutation fence.  Do not
                # start a concurrent retry or tear down audit/database state.
                last_error = exc
                break
            except Exception as exc:
                last_error = exc
                self._office_shutdown_task = None
                logger.warning(
                    "office authority shutdown attempt %d/%d failed",
                    attempt, attempts, exc_info=True,
                )
        self.shutdown_failed = True
        logger.error("shared Office authority did not reach terminal state")
        raise ServiceShutdownError(
            "shared Office mutation authority shutdown failed"
        ) from last_error

    async def _execute_scheduled_prompt(
        self, task_id: str, prompt: str, principal_id: str = ""
    ) -> str:
        """Run a scheduled prompt through the normal office-mode agent path.

        M4 batch 3.1.10 (CRITICAL): the executor signature now accepts
        the task's ``principal_id`` so the scheduled prompt runs as the
        creator (not the server UID).  Without this, ``chat()`` would
        fall back to ``local-uid:{os.getuid()}`` and:

          * Memory writes would be attributed to the wrong principal.
          * BrowserContext / permission / audit decisions would bind
            to the local server identity instead of the creator.
          * A low-privilege remote principal could schedule a future
            execution that runs as a higher-privilege local user.

        ``CronEngine._execute_task`` calls this as a 3-arg executor;
        the engine keeps a 2-arg fallback for older test executors.
        """
        # M4 batch 3.1.16A-4-1: build a cron-sourced RequestContext
        # for this chat turn.  The ctx is constructed from the task's
        # bound principal_id (stamped at creation time) — not the
        # server's local-uid.
        cron_ctx = RequestContext.for_cron(
            principal_id,
            project_id=self._bound_project_id,
            policy_digest=self._effective_policy.digest,
        )
        contents: list[str] = []
        async for event in self.chat(
            cron_ctx,
            ChatRequest(f"cron:{task_id}", prompt, "office", principal_id=principal_id)
        ):
            if event.get("event") == "message":
                content = event.get("data", {}).get("content")
                if content:
                    contents.append(str(content))
        return "\n".join(contents)

    async def chat(self, ctx: RequestContext, request: ChatRequest) -> AsyncIterator[dict]:
        """Stream chat events.

        B1: hold the full RuntimeResult and close it in ``finally`` so the
        per-turn ExecutionService / MemoryManager are released even when
        ``loop.run`` raises or the client disconnects.  The shared
        OfficeMutationAuthority is borrowed (not owned), so ``aclose`` does
        NOT shut it down — ``AgentService.shutdown`` does.

        Reservation lifecycle (round-4 audit closure):

        The previous round-3 fix held ``_admission_lock`` across the whole
        ``_build_runtime`` await.  That closed the owner-snapshot race but
        introduced a worse problem: ``_build_runtime`` does real DB I/O
        (mode_manager.load / switch, permission_engine.load_rules,
        task_manager.load), so a slow or wedged build held the lock
        indefinitely and shutdown's ``CHAT_DRAIN_TIMEOUT`` deadline never
        started — shutdown blocked on lock acquisition before it could
        even begin the bounded wait.

        The reservation pattern splits admission from the build:

          1. Under ``_admission_lock`` (cheap): check ``_accepting_work``,
             register ``owner_task`` in ``_active_chat_tasks``.  This is
             the reservation — shutdown's snapshot WILL see it.
          2. OUTSIDE the lock: ``await _build_runtime(...)``.  A slow or
             wedged build no longer blocks shutdown; the owner task is
             already registered, so shutdown's cancel + bounded drain
             applies to it directly.
          3. Under ``_admission_lock`` again: if shutdown flipped
             ``_accepting_work`` during the build, abort (the owner task
             is about to be or has already been cancelled by shutdown).
             Otherwise publish the runtime in ``_active_runtimes``.

        The ``finally`` wraps the whole body — including the build — so a
        build failure or cancellation still discards the owner task from
        ``_active_chat_tasks`` (closing the round-3 M3 leak where the
        reservation was only cleaned up after a successful build).
        """
        owner_task = asyncio.current_task()
        runtime = None
        # Register the reservation BEFORE any await so shutdown's snapshot
        # cannot miss this chat.  Cheap dict mutation under the lock; the
        # expensive build is outside.
        async with self._admission_lock:
            if not self._accepting_work:
                raise ServiceShutdownError("AgentService is shutting down")
            if owner_task is not None:
                self._active_chat_tasks.add(owner_task)
        try:
            session_id = request.session_id or str(uuid.uuid4())
            # Build OUTSIDE the lock — a slow / wedged build no longer
            # blocks shutdown from acquiring the lock and running its
            # bounded drain.  Cancellation from shutdown propagates here.
            # M4 batch 3.1.16A-4-1: bind session_id into ctx so
            # downstream ModeManager / AgentLoop see the correct
            # (principal, session) pair.
            runtime = await self._build_runtime(
                ctx.with_session(session_id),
                session_id,
                request.mode,
            )
            # Publish under the lock so shutdown's snapshot of
            # _active_runtimes is consistent.  If shutdown closed
            # admission while we were building, abort — the owner task
            # has already been cancelled (or is about to be) and any
            # runtime we built must be torn down.
            async with self._admission_lock:
                if not self._accepting_work:
                    # shutdown began during the build; do not serve.  The
                    # finally block below closes/quarantines the runtime
                    # and discards the owner reservation.
                    raise ServiceShutdownError(
                        "AgentService began shutting down during runtime build"
                    )
                self._active_runtimes[id(runtime)] = runtime
            async for message in runtime.loop.run(request.message, session_id):
                yield _message_to_event(message)
        finally:
            # Covers build failure, build cancellation, and normal exit.
            # Without this wrap, a _build_runtime raise would leak the
            # owner_task reference in _active_chat_tasks forever.
            from khaos.runtime import close_runtime_or_register
            if runtime is not None:
                try:
                    await close_runtime_or_register(runtime)
                finally:
                    self._active_runtimes.pop(id(runtime), None)
            if owner_task is not None:
                self._active_chat_tasks.discard(owner_task)

    async def switch_mode(self, ctx: RequestContext, session_id: str, target_mode: str) -> dict:
        # M4 batch 3.1.16A-4-1: use ctx.principal_id (transport-
        # authenticated) instead of the hardcoded ``local-uid``.
        # Previously a remote API principal A calling SwitchMode would
        # modify the local-uid's mode, then A's Chat runtime would
        # load A's principal — producing inconsistent authority and
        # UI state.  Now the switch is scoped to (ctx.principal_id,
        # session_id), matching the Chat runtime's principal binding.
        mode_manager = ModeManager(
            self.db,
            project_root=self.project_root,
            principal_id=ctx.principal_id,
            session_id=session_id,
        )
        await mode_manager.load()
        mode = ModeManager.parse(target_mode)
        await mode_manager.switch(mode)
        if session_id:
            await self.db.create_session(
                session_id, mode.value,
                principal_id=ctx.principal_id,
                # M4 batch 3.1.16A-5-1b: stamp the RPC-verified project
                # identity (owner-preserving ON CONFLICT — see
                # ``_build_runtime`` for the rationale).
                project_id=ctx.project_id,
            )
        return {"current_mode": mode.value}

    async def confirm_permission(self, ctx: RequestContext, request: ConfirmRequest) -> dict:
        # M4 batch 3.1.16A-4-1: ctx is the authoritative principal.
        # ConfirmRequest.principal_id is still populated by the
        # dispatcher (backward compat) but ctx.principal_id is the
        # verified transport principal.  A-4-2 will switch the
        # ApprovalBroker call to use ctx.principal_id directly.
        if not request.principal_id or not request.binding_digest:
            return {"ok": False, "error": "approval principal/binding required"}
        return {
            "ok": await self.approval_broker.resolve(
                request.tool_call_id,
                request.approved,
                request.remember,
                principal_id=request.principal_id,
                session_id=request.session_id,
                binding_digest=request.binding_digest,
            )
        }

    async def handle_webhook(
        self,
        ctx: RequestContext,
        platform: str,
        channel_id: str,
        headers: dict[str, str],
        body: str,
        query: dict[str, str] | None = None,
    ) -> dict[str, str]:
        """Validate and process one inbound platform webhook."""
        channel = self.channel_registry.get(channel_id)
        if channel is None or not channel.is_enabled:
            return {"status": "channel_not_found_or_disabled"}
        try:
            channel_type = ChannelType.WEBHOOK_IN if platform == "generic" else ChannelType(platform)
        except ValueError:
            return {"status": "unsupported_platform"}
        if channel.channel_type != channel_type:
            return {"status": "channel_type_mismatch"}
        handler = WebhookHandler(
            channel_type,
            secret=channel.config.secret,
            on_message=lambda message: self._on_webhook_message(channel_id, message),
            channel_id=channel_id,
            replay_guard=self._webhook_replay_guard,
            verified_limiter=self._verified_webhook_limiter,
        )
        return await handler.handle(headers, body.encode("utf-8"), query)

    async def _on_webhook_message(self, channel_id: str, message: PlatformMessage) -> None:
        identity = {
            "channel_id": channel_id,
            "platform": message.channel.value,
            "sender": message.sender.platform_id or message.sender.id,
            "target": message.target,
        }
        identity_digest = hashlib.sha256(
            json.dumps(
                identity, sort_keys=True, separators=(",", ":"), ensure_ascii=False
            ).encode("utf-8")
        ).hexdigest()[:24]
        session_id = f"webhook:{channel_id}:{message.channel.value}:{identity_digest}"
        principal_id = (
            f"webhook:{channel_id}:{message.channel.value}:"
            f"{identity['sender'] or 'unknown'}"
        )
        # M4 batch 3.1.16A-4-1: build a webhook-sourced RequestContext
        # for this chat turn.  The ctx is constructed from the derived
        # webhook principal (not the original RPC caller's principal —
        # webhook turns belong to the webhook sender, not the Gateway
        # operator who dispatched the webhook event).
        webhook_ctx = RequestContext.for_webhook(
            principal_id,
            project_id=self._bound_project_id,
            policy_digest=self._effective_policy.digest,
        )
        async for _event in self.chat(webhook_ctx, ChatRequest(
            session_id,
            message.to_agent_input(),
            principal_id=principal_id,
        )):
            pass
        self.channel_registry.record_success(channel_id, received=True)

    def list_channels(self, ctx: RequestContext) -> dict[str, object]:
        return {"channels": self.channel_registry.get_health_report()}

    def set_channel_enabled(self, ctx: RequestContext, channel_id: str, enabled: bool) -> dict[str, object]:
        changed = self.channel_registry.enable(channel_id) if enabled else self.channel_registry.disable(channel_id)
        return {"ok": changed, "channel_id": channel_id}

    async def _build_runtime(
        self, ctx: RequestContext, session_id: str, mode: str,
    ):
        """Build a per-turn runtime that borrows the shared Office authority.

        B1: returns the full ``RuntimeResult`` so ``chat`` can ``aclose`` it
        in ``finally``.  The shared ``self._office_authority`` is injected so
        the aggregate storage baseline persists across turns (closing the
        cross-turn quota bypass).

        H1: reuses the server-lifecycle ``self._audit_logger`` so security
        events from the main AgentLoop and every SubAgent run land in the
        SAME audit trail (no parallel unsupervised audit path).

        M4 batch 3.1.16A-4-1: takes a :class:`RequestContext` instead of
        a bare ``principal_id`` string.  The context is the sole
        authority for principal identity; ``RuntimeConfig`` now
        receives ``session_id`` from ``ctx.session_id`` (previously
        always ``""``, which broke ModeManager's (principal, session)
        binding).  ``principal_id`` still falls back to ``local-uid``
        for legacy callers that construct ctx via
        :meth:`RequestContext.for_cli` without a session_id — but the
        RPC path always provides a non-empty ctx.principal_id.
        """
        await self.db.create_session(
            session_id, mode or "office",
            principal_id=ctx.principal_id,
            # M4 batch 3.1.16A-5-1b: stamp the RPC-verified project
            # identity on the session row.  ``create_session``'s
            # ``ON CONFLICT`` clause does NOT touch ``project_id``
            # (owner-preserving), so once a session is bound to a
            # (principal, project) pair a later ``create_session``
            # call from a different project cannot re-stamp it.
            project_id=ctx.project_id,
        )
        from khaos.runtime import RuntimeConfig, build_runtime

        return await build_runtime(RuntimeConfig(
            project_root=self.project_root, config_path=self.config_path,
            mode_override=mode or None, confirm_callback=self._wait_for_confirmation,
            db=self.db, audit_logger=self._audit_logger,
            # C-1-5a: do NOT pass a shared task_manager — let
            # ``build_runtime`` construct a per-turn TaskManager from
            # ``cfg.principal_id`` (factory.py:502-517).  Previously
            # this passed the server-level ``TaskManager(local-uid)``
            # singleton, which meant per-turn coding tasks landed in
            # the local-uid cache — invisible to the API principal's
            # ``TaskService.list``.
            approval_broker=self.approval_broker,
            router=self._router,
            office_authority=self._office_authority,
            principal_id=ctx.principal_id,
            session_id=session_id,
            # M4 batch 3.1.16A-5-1b (CRITICAL): inject the RPC-verified
            # project identity so ``AgentLoop._bound_project_id`` (and
            # every component constructed by ``build_runtime``:
            # PermissionEngine, MemoryStore, AuditLogger, TaskManager)
            # comes from ``ctx.project_id`` (server-bound) instead of
            # being recomputed from ``project_root``.  The dispatcher's
            # drift check above guarantees ``ctx.project_id ==
            # agent._bound_project_id`` here.
            project_id=ctx.project_id,
            # M4 batch 3.1.16A-4-4-3: inject the server-lifecycle
            # ChannelRegistry + the effective policy's compiled
            # ``channel_admins`` allowlist so the four channel tools
            # receive them via the ``channel.read`` / ``channel.manage``
            # broker injection (no module-global holder, no
            # cross-principal mutation).
            channel_registry=self.channel_registry,
            channel_admins=self._effective_policy.channel_admins,
        ))

    async def _wait_for_confirmation(self, request: dict) -> dict:
        return await self.approval_broker.wait(
            request["id"],
            timeout=120.0,
            binding_digest=request["binding_digest"],
        )

    def _build_security_middleware(self) -> SecurityMiddleware:
        """Build the full security stack from the effective policy.

        Wiring chain (see 批次 5 of the Codex-alignment doc):
        policy → Sandbox(mode) + NetworkGuard(network_*) + policy-extended
        guards + audit_logger → SecurityMiddleware → ToolScheduler.pre_check.

        H2: every enforcement decision is made from the *effective* policy
        (user ∩ project ∩ platform), not the raw project policy — an
        untrusted repo can no longer disable audit or relax network by
        editing its own ``khaos_policy.yaml``.

        Components are optional and imported lazily so the server starts even
        before all batches are present; a missing class simply means that
        layer is not enforced yet.
        """
        eff = self._effective_policy
        sandbox = None
        network_guard = None
        # Sandbox: capability constraint layer.
        try:
            from khaos.security.sandbox import Sandbox

            sandbox = Sandbox(
                mode=eff.mode,
                workspace_root=self.project_root,
                root_capabilities=eff.root_capabilities,
            )
        except ImportError:
            pass
        # NetworkGuard: network access control.
        try:
            from khaos.security.network_guard import NetworkGuard

            network_guard = NetworkGuard(
                network_enabled=eff.network_enabled,
                # H3: three-state — pass None through so NetworkGuard
                # distinguishes "no allowlist" (unrestricted) from "empty
                # allowlist" (deny all).
                allowed_domains=(
                    list(eff.network_allowed_domains)
                    if eff.network_allowed_domains is not None
                    else None
                ),
                blocked_domains=list(eff.network_blocked_domains),
            )
        except ImportError:
            pass
        audit_logger = self._audit_logger
        return SecurityMiddleware(
            effective_policy=eff,
            sandbox=sandbox,
            network_guard=network_guard,
            audit_logger=audit_logger,
        )


class MemoryService:
    """Memory RPC service backed by a per-request :class:`MemoryStore`.

    M4 batch 3.1.16A-4-2: the service holds the ``db`` handle and
    constructs a fresh ``MemoryStore`` scoped to ``ctx.principal_id``
    on every call.  Previously the service was bound to a server-level
    ``MemoryStore(local-uid)`` singleton, so an API principal could
    read/write the local-uid's memories.  Each principal now sees only
    their own private memories plus project-shared memories
    (``namespace='shared'``).
    """

    def __init__(self, db: Database):
        self.db = db

    def _store(self, ctx: RequestContext) -> MemoryStore:
        return MemoryStore(self.db, principal_id=ctx.principal_id)

    async def get_memory(self, ctx: RequestContext, scope: str, key: str) -> dict:
        store = self._store(ctx)
        memory = await store.get(MemoryScope(scope), key)
        if memory is None:
            raise KeyError(key)
        return _memory_to_dict(memory)

    async def set_memory(
        self,
        ctx: RequestContext,
        scope: str,
        key: str,
        value: str,
        ttl: int = 604800,
        confidence: int = 2,
    ) -> dict:
        store = self._store(ctx)
        memory = await store.set(
            Memory(
                id=None,
                scope=MemoryScope(scope),
                key=key,
                value=value,
                ttl=ttl,
                confidence=MemoryConfidence(confidence),
            )
        )
        return {"ok": True, "id": memory.id}

    async def delete_memory(self, ctx: RequestContext, memory_id: int) -> dict:
        # M4 batch 3.1.16A-4-2: principal-scoped deletion.  Previously
        # ``delete_memory_by_id`` had no principal filter, so any
        # principal could delete any other principal's memory by id.
        # Now the DELETE is scoped to ``ctx.principal_id`` (or
        # project-shared rows with ``principal_id=''``).
        await self.db.delete_memory_by_id(
            memory_id, principal_id=ctx.principal_id,
        )
        return {"ok": True}

    async def search_memory(self, ctx: RequestContext, query: str, top_k: int = 5) -> list[dict]:
        store = self._store(ctx)
        return [_memory_to_dict(memory) for memory in await store.search(query, top_k)]


class AuditService:
    """Audit RPC service backed by AuditLogger."""

    def __init__(self, logger: AuditLogger):
        self.logger = logger

    async def query(
        self,
        ctx: RequestContext,
        action: str | None = None,
        result: str | None = None,
        since: str | None = None,
        until: str | None = None,
        limit: int = 100,
    ) -> list[dict]:
        # M4 batch 3.1.16A-4-2: scope audit queries to the transport
        # principal.  Previously the query used the server-level
        # AuditLogger's bound principal (``local-uid``), so an API
        # principal could read the local-uid's audit trail.  The
        # underlying ``AuditLogger.query`` already supports a
        # ``principal_id`` parameter; we now pass ``ctx.principal_id``
        # explicitly so each principal sees only their own audit events.
        entries = await self.logger.query(
            action=action,
            result=result,
            since=since,
            until=until,
            limit=limit,
            principal_id=ctx.principal_id,
        )
        return [entry.to_dict() for entry in entries]


class TaskService:
    """Coding-task RPC service with per-principal TaskManager.

    C-1-5a: previously this service held a server-level
    ``TaskManager(local-uid)`` singleton, which (a) rejected ``create``
    from API principals (fail-closed with a "deferred to A-4-3/A-4-4"
    error) and (b) returned empty ``list``/``get``/``cancel`` results
    for API principals because the cache only held local-uid tasks.

    Now the service holds ``db`` + ``approval_broker`` and constructs
    a per-principal ``TaskManager`` on demand (cached for the
    process lifetime).  Each principal gets an isolated cache loaded
    from the DB, so ``create``/``list``/``get``/``cancel`` all work
    correctly for any authenticated principal.  Cross-principal
    isolation is enforced both by the manager's principal-scoped cache
    AND by the explicit ``task.principal_id != ctx.principal_id``
    checks (defense in depth).
    """

    def __init__(self, db, approval_broker: ApprovalBroker | None = None):
        self.db = db
        self.approval_broker = approval_broker
        # C-1-5a: per-principal TaskManager cache.  Each principal
        # gets its own manager with its own in-memory cache loaded
        # from the DB.  The cache is keyed by principal_id and lives
        # for the process lifetime — a principal that connects, goes
        # away, and comes back reuses the same manager.
        self._managers: dict[str, TaskManager] = {}

    async def _manager(self, ctx: RequestContext) -> TaskManager:
        """Get or create the per-principal TaskManager."""
        manager = self._managers.get(ctx.principal_id)
        if manager is None:
            manager = TaskManager(
                db=self.db, principal_id=ctx.principal_id,
                project_id=ctx.project_id,
            )
            await manager.load()
            self._managers[ctx.principal_id] = manager
        return manager

    async def list(self, ctx: RequestContext, active_only: bool = False) -> list[dict]:
        """List tasks — active ones by default, all when ``active_only`` is set.

        C-1-5a: the per-principal TaskManager's cache only contains
        tasks owned by ``ctx.principal_id``, so the caller sees exactly
        their own tasks.  The explicit ``principal_id`` filter is
        defense in depth.
        """
        manager = await self._manager(ctx)
        if active_only:
            return await manager.list_active(
                principal_id=ctx.principal_id,
            )
        return await manager.list_all(
            principal_id=ctx.principal_id,
        )

    async def get(self, ctx: RequestContext, task_id: str) -> dict:
        """Return one task's state, or ``{"error": "not found"}``.

        C-1-5a: a task owned by a different principal is treated as
        ``not found`` — existence is hidden to avoid leaking that
        another principal has work in flight.  (Defense in depth: the
        per-principal cache already excludes foreign tasks.)
        """
        manager = await self._manager(ctx)
        task = await manager.get(task_id)
        if task is None or task.principal_id != ctx.principal_id:
            return {"error": "task not found", "task_id": task_id}
        return task.to_dict()

    async def create(self, ctx: RequestContext, goal: str) -> dict:
        """Create a task owned by ``ctx.principal_id``.

        C-1-5a: the per-principal TaskManager stamps
        ``ctx.principal_id`` on the new task and stores it in the
        caller's cache.  Previously this rejected API principals with
        a "per-principal TaskManager required" error (deferred to
        A-4-3/A-4-4) — C-1-5a fulfills that deferral.
        """
        manager = await self._manager(ctx)
        return (await manager.create(goal)).to_dict()

    async def cancel(self, ctx: RequestContext, task_id: str) -> dict:
        from khaos.coding.task_manager import TransitionResult

        # C-1-5a: hide cross-principal tasks (treat as not found) so
        # an API principal cannot enumerate or cancel another
        # principal's tasks.  (Defense in depth.)
        manager = await self._manager(ctx)
        task = await manager.get(task_id)
        if task is None or task.principal_id != ctx.principal_id:
            return {"ok": False, "error": "task not found", "task_id": task_id}
        result = await manager.cancel(task_id)
        if result == TransitionResult.NOT_FOUND:
            return {"ok": False, "error": "task not found", "task_id": task_id}
        if result == TransitionResult.INVALID_TRANSITION:
            return {"ok": False, "error": "task already terminal", "task_id": task_id}
        return {"ok": True, "task_id": task_id}

    async def approve(
        self,
        ctx: RequestContext,
        task_id: str,
        principal_id: str = "",
        session_id: str = "",
        binding_digest: str = "",
    ) -> dict:
        from khaos.coding.task_manager import TaskStatus, TransitionResult

        # M4 batch 3.1.16A-4-2: a compromised Gateway could forge the
        # payload's ``principal_id`` to match the task's pending
        # approval principal.  The transport ``ctx.principal_id`` is
        # the authority — reject if the payload principal disagrees.
        # Also hide cross-principal tasks (treat as not found).
        if principal_id and principal_id != ctx.principal_id:
            return {
                "ok": False,
                "error": "payload principal_id does not match transport principal",
                "task_id": task_id,
            }
        manager = await self._manager(ctx)
        task = await manager.get(task_id)
        if task is None or task.principal_id != ctx.principal_id:
            return {"ok": False, "error": "task not found", "task_id": task_id}
        if task.status != TaskStatus.BLOCKED:
            return {"ok": False, "error": f"task is {task.status.value}, not blocked", "task_id": task_id}
        pending = task.metadata.get("pending_approval") or {}
        if (
            not self.approval_broker
            or principal_id != pending.get("principal_id")
            or session_id != pending.get("session_id")
            or binding_digest != pending.get("binding_digest")
        ):
            return {
                "ok": False,
                "error": "approval principal/session/binding mismatch",
                "task_id": task_id,
            }
        async def commit() -> bool:
            result = await manager.transition(
                task_id, expected={TaskStatus.BLOCKED},
                target=TaskStatus.RUNNING, pending_approval=None,
                approval_consumption={
                    "tool_call_id": pending.get("tool_call_id", ""),
                    "binding_digest": binding_digest,
                    "principal_id": principal_id,
                    "session_id": session_id,
                    "decision": "approved",
                    "consumed_at": time.time(),
                },
            )
            return result == TransitionResult.UPDATED

        resolved = await self.approval_broker.consume_task_decision_and_commit(
            pending.get("tool_call_id", ""),
            True,
            principal_id=principal_id,
            session_id=session_id,
            binding_digest=binding_digest,
            commit=commit,
        )
        return {"ok": resolved, "task_id": task_id}

    async def reject(
        self,
        ctx: RequestContext,
        task_id: str,
        principal_id: str = "",
        session_id: str = "",
        binding_digest: str = "",
    ) -> dict:
        from khaos.coding.task_manager import TaskStatus, TransitionResult

        # M4 batch 3.1.16A-4-2: see ``approve`` — payload principal
        # must agree with transport principal, and cross-principal
        # tasks are hidden.
        if principal_id and principal_id != ctx.principal_id:
            return {
                "ok": False,
                "error": "payload principal_id does not match transport principal",
                "task_id": task_id,
            }
        manager = await self._manager(ctx)
        task = await manager.get(task_id)
        if task is None or task.principal_id != ctx.principal_id:
            return {"ok": False, "error": "task not found", "task_id": task_id}
        if task.status != TaskStatus.BLOCKED:
            return {"ok": False, "error": f"task is {task.status.value}, not blocked", "task_id": task_id}
        pending = task.metadata.get("pending_approval") or {}
        if (
            not self.approval_broker
            or principal_id != pending.get("principal_id")
            or session_id != pending.get("session_id")
            or binding_digest != pending.get("binding_digest")
        ):
            return {
                "ok": False,
                "error": "approval principal/session/binding mismatch",
                "task_id": task_id,
            }
        async def commit() -> bool:
            result = await manager.transition(
                task_id, expected={TaskStatus.BLOCKED}, target=TaskStatus.FAILED,
                error="rejected by user", pending_approval=None,
                approval_consumption={
                    "tool_call_id": pending.get("tool_call_id", ""),
                    "binding_digest": binding_digest,
                    "principal_id": principal_id,
                    "session_id": session_id,
                    "decision": "rejected",
                    "consumed_at": time.time(),
                },
            )
            return result == TransitionResult.UPDATED

        resolved = await self.approval_broker.consume_task_decision_and_commit(
            pending.get("tool_call_id", ""),
            False,
            principal_id=principal_id,
            session_id=session_id,
            binding_digest=binding_digest,
            commit=commit,
        )
        return {"ok": resolved, "task_id": task_id}

    async def artifacts(self, ctx: RequestContext, task_id: str) -> list[dict]:
        """Return a task's produced artifacts (files + test results).

        M4 batch 3.1.16A-4-2: cross-principal tasks return an empty
        list (existence hidden) — symmetric with ``get`` / ``cancel``.
        """
        manager = await self._manager(ctx)
        task = await manager.get(task_id)
        if task is None or task.principal_id != ctx.principal_id:
            return []
        return ([{"type": "file", "path": path} for path in task.files_modified] + [{"type": "test_result", "data": result} for result in task.test_results])

    async def events(self, ctx: RequestContext, task_id: str):
        """Subscribe to a task's event stream.

        M4 batch 3.1.16A-4-2: previously the dispatcher reached into
        ``task_manager.subscribe`` directly, bypassing the service
        layer — so the principal check on ``ctx`` was never enforced.
        This wrapper hides cross-principal tasks (yields nothing) so
        an API principal cannot subscribe to another principal's
        task events.
        """
        manager = await self._manager(ctx)
        task = await manager.get(task_id)
        if task is None or task.principal_id != ctx.principal_id:
            return
        async for event in manager.subscribe(task_id):
            yield event


async def serve_json_lines(
    socket_path: str,
    db_path: str,
    project_root: Path | None = None,
    config_path: Path | None = None,
    enable_subagents: bool = False,
    router=None,
    gateway_capability: str | None = None,
    gateway_uid: int | None = None,
    gateway_pid: int | None = None,
) -> None:
    """Serve the privileged JSON-line control plane over a mode-0600 UDS.

    M4 batch 3.1.13 (CRITICAL-3): the server now enforces the
    single-instance model with a process-level exclusive lock
    (``fcntl.flock``) on a lockfile bound to the DB path.  The lock is
    acquired BEFORE socket unlink / migration / recovery.  A second
    process that tries to start against the same DB fails immediately
    with ``PermissionError`` — it cannot ``unlink`` the live first
    process's UDS socket, open the DB, and mark all RUNNING tasks as
    FAILED while the first process's executors are still running.

    Additionally, when an existing UDS socket is found, a liveness
    probe (non-blocking ``connect``) is performed BEFORE ``unlink``.
    If the probe succeeds, a live server is listening → refuse to
    start.  If the probe gets ``ECONNREFUSED``, the socket is stale
    (the previous process died without unlinking) → safe to replace.
    Previously the code unconditionally ``unlink``-ed any existing
    socket, which let a second process replace the first process's
    live socket.

    M4 batch 3.1.16A-1 (CRITICAL-1): the caller is expected to have
    resolved ``db_path`` via ``state_root.resolve_state_db_path`` +
    ``state_root.open_state_db_safely``.  When ``KHAOS_ALLOW_PROJECT_DB=1``
    is set (tests), the safety checks are bypassed so the test suite
    can pass ``tmp_path / "khaos.db"`` directly.  Production callers
    (CLI ``cmd_start``, ``serve_json_lines.main``) MUST resolve the
    state root path before calling this function.
    """
    uds_path = Path(socket_path).expanduser().resolve()
    capability = gateway_capability or _load_rpc_capability()
    authenticator = GatewayRPCAuthenticator(
        capability, expected_uid=gateway_uid, expected_pid=gateway_pid
    )
    uds_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    parent_stat = uds_path.parent.stat()
    if parent_stat.st_uid != os.getuid() or stat.S_IMODE(parent_stat.st_mode) != 0o700:
        raise PermissionError("RPC socket parent must be owned by Runtime and mode 0700")
    # M4 batch 3.1.13 (CRITICAL-3): acquire the process-level
    # exclusive lock BEFORE touching the UDS socket or the DB.  This
    # must happen BEFORE the liveness probe below — even if the probe
    # gets lucky and the socket looks stale, we MUST NOT start a
    # second instance against the same DB.  The lock fd is kept in a
    # local variable and released when the process exits (the OS
    # closes the fd).
    instance_lock_fd = _acquire_instance_lock(db_path)
    # M4 batch 3.1.15 (CRITICAL-1 + HIGH-1): track partially-initialized
    # resources so the outer ``finally`` can attempt emergency cleanup.
    # ``inner_cleanup_completed`` is set to True ONLY at the end of the
    # inner ``finally`` — if the inner cleanup raises (e.g. cron executor
    # resists cancellation), it stays False and the outer finally retains
    # the instance lock instead of releasing it.
    agent: AgentService | None = None
    db: Database | None = None
    subagent_service: SubAgentService | None = None
    inner_cleanup_completed = False
    try:
        if uds_path.exists() or uds_path.is_symlink():
            mode = uds_path.lstat().st_mode
            if not stat.S_ISSOCK(mode):
                raise PermissionError(f"refusing to replace non-socket RPC path: {uds_path}")
            # M4 batch 3.1.13 (CRITICAL-3): probe liveness BEFORE unlink.
            # If a live server is listening, refuse to start.  Only
            # ``ECONNREFUSED`` (stale socket) is safe to replace.
            if _probe_uds_liveness(uds_path):
                raise PermissionError(
                    f"refusing to replace live UDS socket: {uds_path} — "
                    f"another Khaos instance is listening (CRITICAL-3: "
                    f"single-instance model enforced)"
                )
            uds_path.unlink()

        db = Database(db_path)
        await db.connect()
        await db.run_migrations()
        agent = AgentService(db, project_root=project_root, config_path=config_path, router=router)
        await agent.start()
        # M4 batch 3.1.16A-4-2: MemoryService now holds ``db`` and
        # constructs a per-request ``MemoryStore`` scoped to
        # ``ctx.principal_id``.  Previously it was bound to a
        # server-level ``MemoryStore(local-uid)`` singleton, so an API
        # principal could read/write the local-uid's memories.
        memory = MemoryService(db)
        audit_service = AuditService(agent._audit_logger or AuditLogger(db))
        # C-1-5a: TaskService now takes ``db`` (not a TaskManager) and
        # constructs per-principal managers on demand.
        task_service = TaskService(db, agent.approval_broker)
        subagent_service: SubAgentService | None = None
        if enable_subagents:
            # B1: share the AgentService's office authority AND approval broker so
            # subagent runs reuse the same aggregate storage baseline (no
            # cross-run quota bypass) and the same approval authority (no parallel
            # unsupervised permission path).  The runtime borrows these instead of
            # creating fresh instances; build_runtime constructs the per-run
            # ToolScheduler with the full SecurityMiddleware stack.
            subagent_service = await _build_subagent_service(
                db, project_root, config_path,
                office_authority=agent._office_authority,
                approval_broker=agent.approval_broker,
                # C-1-5b: no server-level principal_id — the subagent's
                # ModeManager / MemoryManager are constructed per-turn by
                # ``build_runtime`` from ``task.principal_id`` (set from
                # ``ctx.principal_id``).  Previously this passed
                # ``f"local-uid:{os.getuid()}"`` which bound the subagent's
                # mode / memory scope to the local OS user.
                # H1: inherit the server-lifecycle AuditLogger so SubAgent
                # security events land in the SAME audit trail as the main
                # AgentLoop — no parallel unsupervised audit path.
                audit_logger=agent._audit_logger,
            )

        async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            try:
                try:
                    peer_pid = authenticator.verify_peer(writer)
                except PermissionError:
                    return
                line = await reader.readline()
                if not line:
                    return
                try:
                    request = _parse_json_line(line)
                except ValueError as exc:
                    writer.write(
                        (
                            json.dumps(
                                {
                                    "event": "error",
                                    "data": {
                                        "code": "INVALID_JSON",
                                        "message": str(exc),
                                        "recoverable": True,
                                    },
                                },
                                ensure_ascii=False,
                            )
                            + "\n"
                        ).encode("utf-8")
                    )
                    await writer.drain()
                    return
                try:
                    principal_id = authenticator.authenticate(request, peer_pid=peer_pid)
                except PermissionError as exc:
                    writer.write((json.dumps({
                        "error": "unauthenticated", "message": str(exc),
                    }) + "\n").encode("utf-8"))
                    await writer.drain()
                    return
                method = request.get("method")
                payload = request.get("payload", {})
                # C-1-4: Bootstrap.GetPolicyDigest — Gateway startup
                # handshake.  Returns the server-bound policy_digest so
                # the Gateway can stamp it on all subsequent RPC payloads
                # for drift detection.  This must run BEFORE ctx creation
                # and BEFORE any drift detection — the bootstrap call
                # itself carries no policy_digest claim (it's fetching
                # the digest).  Python is the sole authority for
                # policy_digest; Go never computes it independently.
                if method == "Bootstrap.GetPolicyDigest":
                    writer.write((json.dumps({
                        "policy_digest": agent._effective_policy.digest,
                    }) + "\n").encode("utf-8"))
                    await writer.drain()
                    return
                # M4 batch 3.1.16A-4-1: build an immutable RequestContext
                # from the transport-authenticated principal.  This is
                # the SOLE authority for principal identity — payload
                # ``principal_id`` is no longer trusted (a compromised
                # Gateway could forge it).  All service methods receive
                # ``ctx`` as their first parameter.
                #
                # Backward compat: methods that historically read
                # ``principal_id`` from the payload (ChatRequest,
                # ConfirmRequest, TaskService.approve/reject, SubAgent
                # handlers) still work — we inject ctx.principal_id
                # into the payload so ``**payload`` unpacking picks it
                # up.  A-4-2 will remove this crutch and read directly
                # from ctx.
                #
                # CONDITIONAL injection (M4 batch 3.1.16A-4-1): only
                # overwrite when the Go side already sent
                # ``principal_id``.  Methods whose signatures don't
                # accept ``principal_id`` (TaskService.list/get/create/
                # cancel/artifacts, MemoryService.*, AuditService.query,
                # AgentService.switch_mode/list_channels/
                # set_channel_enabled/handle_webhook) would raise
                # TypeError on ``**payload`` unpacking if we injected
                # unconditionally.  SubAgent handlers get their
                # principal stamped inside ``_handle_optional_subagent``
                # so they don't depend on this branch.
                ctx = RequestContext.for_rpc(
                    principal_id,
                    project_id=agent._bound_project_id,
                    policy_digest=agent._effective_policy.digest,
                )
                if "principal_id" in payload:
                    payload["principal_id"] = ctx.principal_id
                # M4 batch 3.1.16A-5-1b (CRITICAL): project identity
                # drift detection.  The Go side may claim a
                # ``project_id`` in the payload (caller-asserted).
                # Compare it against ``agent._bound_project_id`` (the
                # server-computed identity of this AgentService's
                # ``project_root``).  A mismatch means the Gateway
                # routed a request for project A to a server booted
                # under project B — either a misconfiguration or an
                # attempt to cross-contaminate project state (e.g.
                # write audit rows / memories / coding tasks attributed
                # to the wrong project).  Fail-closed: reject before
                # any service method runs.  An empty claim (Go side
                # didn't send ``project_id``) is accepted — backward
                # compat with older Gateways — and ``ctx.project_id``
                # remains the server-bound value.
                claimed_project_id = payload.get("project_id", "")
                if (
                    claimed_project_id
                    and claimed_project_id != agent._bound_project_id
                ):
                    writer.write((json.dumps({
                        "error": "project_drift",
                        "message": (
                            f"payload project_id {claimed_project_id!r} "
                            f"does not match server-bound project_id "
                            f"{agent._bound_project_id!r}"
                        ),
                    }) + "\n").encode("utf-8"))
                    await writer.drain()
                    return
                # Pop ``project_id`` from the payload so downstream
                # ``ChatRequest(**payload)`` / ``ConfirmRequest(**payload)``
                # etc. don't receive an unexpected keyword.  The
                # verified value lives on ``ctx.project_id`` (always
                # equal to ``agent._bound_project_id`` here).
                payload.pop("project_id", None)
                # M4 batch 3.1.16C-1-4 (CRITICAL): policy identity drift
                # detection — symmetric to project_id drift detection
                # above.  The Go side may claim a ``policy_digest`` in
                # the payload (Gateway-asserted, sourced from the
                # Bootstrap.GetPolicyDigest handshake at startup).
                # Compare it against ``agent._effective_policy.digest``
                # (the server-computed digest of this AgentService's
                # compiled EffectiveSecurityPolicy).  A mismatch means
                # the Gateway booted against a Python server with policy
                # A, then routed a request to a Python server with
                # policy B — either a restart with a different
                # khaos_policy.yaml, or a misconfigured multi-server
                # deployment.  Fail-closed: reject before any service
                # method runs.  An empty claim (Go side didn't send
                # ``policy_digest``, e.g. older Gateway or bootstrap
                # handshake failed) is accepted — backward compat — and
                # ``ctx.policy_digest`` remains the server-bound value.
                claimed_policy_digest = payload.get("policy_digest", "")
                if (
                    claimed_policy_digest
                    and claimed_policy_digest != agent._effective_policy.digest
                ):
                    writer.write((json.dumps({
                        "error": "policy_drift",
                        "message": (
                            f"payload policy_digest {claimed_policy_digest!r} "
                            f"does not match server-bound policy_digest "
                            f"{agent._effective_policy.digest!r}"
                        ),
                    }) + "\n").encode("utf-8"))
                    await writer.drain()
                    return
                # Pop ``policy_digest`` from the payload so downstream
                # ``ChatRequest(**payload)`` / ``ConfirmRequest(**payload)``
                # etc. don't receive an unexpected keyword.  The
                # verified value lives on ``ctx.policy_digest`` (always
                # equal to ``agent._effective_policy.digest`` here).
                payload.pop("policy_digest", None)
                if method == "AgentService.Chat":
                    try:
                        async for event in agent.chat(ctx, ChatRequest(**payload)):
                            writer.write((json.dumps(event, ensure_ascii=False) + "\n").encode("utf-8"))
                            await writer.drain()
                    except Exception as exc:
                        writer.write(
                            (
                                json.dumps(
                                    {
                                        "event": "error",
                                        "data": {
                                            "code": exc.__class__.__name__,
                                            "message": str(exc),
                                            "recoverable": False,
                                        },
                                    },
                                    ensure_ascii=False,
                                )
                                + "\n"
                            ).encode("utf-8")
                        )
                elif method == "AgentService.SwitchMode":
                    response = await agent.switch_mode(ctx, payload.get("session_id", ""), payload["target_mode"])
                    writer.write((json.dumps(response, ensure_ascii=False) + "\n").encode("utf-8"))
                elif method == "AgentService.ConfirmPermission":
                    response = await agent.confirm_permission(ctx, ConfirmRequest(**payload))
                    writer.write((json.dumps(response, ensure_ascii=False) + "\n").encode("utf-8"))
                elif method == "AgentService.HandleWebhook":
                    response = await agent.handle_webhook(ctx, **payload)
                    writer.write((json.dumps(response, ensure_ascii=False) + "\n").encode("utf-8"))
                elif method in {"ChannelService.List", "ChannelService.Health"}:
                    writer.write((json.dumps(agent.list_channels(ctx), ensure_ascii=False) + "\n").encode("utf-8"))
                elif method in {"ChannelService.Enable", "ChannelService.Disable"}:
                    response = agent.set_channel_enabled(ctx, payload["channel_id"], method.endswith("Enable"))
                    writer.write((json.dumps(response, ensure_ascii=False) + "\n").encode("utf-8"))
                elif method == "MemoryService.SetMemory":
                    response = await memory.set_memory(ctx, **payload)
                    writer.write((json.dumps(response, ensure_ascii=False) + "\n").encode("utf-8"))
                elif method == "MemoryService.GetMemory":
                    response = await memory.get_memory(ctx, **payload)
                    writer.write((json.dumps(response, ensure_ascii=False) + "\n").encode("utf-8"))
                elif method == "MemoryService.SearchMemory":
                    response = await memory.search_memory(ctx, **payload)
                    writer.write((json.dumps(response, ensure_ascii=False) + "\n").encode("utf-8"))
                elif method == "AuditService.Query":
                    response = await audit_service.query(ctx, **payload)
                    writer.write((json.dumps(response, ensure_ascii=False) + "\n").encode("utf-8"))
                elif method == "TaskService.List":
                    response = await task_service.list(ctx, **payload)
                    writer.write((json.dumps(response, ensure_ascii=False) + "\n").encode("utf-8"))
                elif method == "TaskService.Get":
                    response = await task_service.get(ctx, **payload)
                    writer.write((json.dumps(response, ensure_ascii=False) + "\n").encode("utf-8"))
                elif method == "TaskService.Create":
                    writer.write((json.dumps(await task_service.create(ctx, **payload), ensure_ascii=False) + "\n").encode("utf-8"))
                elif method in {"TaskService.Cancel", "TaskService.Approve", "TaskService.Reject"}:
                    action = method.rsplit(".", 1)[-1].lower()
                    writer.write((json.dumps(await getattr(task_service, action)(ctx, **payload), ensure_ascii=False) + "\n").encode("utf-8"))
                elif method == "TaskService.Artifacts":
                    writer.write((json.dumps(await task_service.artifacts(ctx, payload["task_id"]), ensure_ascii=False) + "\n").encode("utf-8"))
                elif method == "TaskService.Events":
                    # M4 batch 3.1.16A-4-2: route through the service
                    # layer so ``ctx.principal_id`` is enforced (cross-
                    # principal subscriptions yield nothing).
                    async for event in task_service.events(ctx, payload["task_id"]):
                        writer.write((json.dumps(event, ensure_ascii=False) + "\n").encode("utf-8"))
                        await writer.drain()
                elif method == "SubAgentService.Spawn":
                    response = await _handle_optional_subagent(subagent_service, "spawn", ctx, payload)
                    writer.write((json.dumps(response, ensure_ascii=False) + "\n").encode("utf-8"))
                elif method == "SubAgentService.Collect":
                    response = await _handle_optional_subagent(subagent_service, "collect", ctx, payload)
                    writer.write((json.dumps(response, ensure_ascii=False) + "\n").encode("utf-8"))
                elif method == "SubAgentService.Status":
                    response = await _handle_optional_subagent(subagent_service, "status", ctx, payload)
                    writer.write((json.dumps(response, ensure_ascii=False) + "\n").encode("utf-8"))
                else:
                    writer.write(json.dumps({"error": "unknown method"}).encode("utf-8") + b"\n")
                await writer.drain()
            finally:
                writer.close()
                try:
                    await asyncio.wait_for(writer.wait_closed(), timeout=1.0)
                except (asyncio.TimeoutError, ConnectionError, OSError):
                    pass

        # ``asyncio.start_unix_server`` otherwise creates handler tasks without
        # giving the application an ownership registry.  Keep every connection
        # task so shutdown can cancel and await it before shared authorities and
        # the database are dismantled.
        handler_tasks: set[asyncio.Task] = set()

        def accept_connection(
            reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
        ) -> None:
            task = asyncio.create_task(handle(reader, writer))
            handler_tasks.add(task)
            task.add_done_callback(handler_tasks.discard)

        try:
            server = await asyncio.start_unix_server(
                accept_connection, path=str(uds_path), limit=RPC_MAX_REQUEST_BYTES,
            )
            os.chmod(uds_path, 0o600)
            socket_stat = uds_path.lstat()
            if socket_stat.st_uid != os.getuid() or not stat.S_ISSOCK(socket_stat.st_mode):
                raise PermissionError("RPC socket inode ownership/type validation failed")
            # Wait until the owner cancels this service.  Do not use
            # ``Server.serve_forever()`` here: on Python 3.13 its cancellation
            # path waits for active client connections before returning, while
            # Khaos must cancel those handlers itself before shared-authority
            # teardown.  That ordering forms a shutdown deadlock.
            await asyncio.Future()
        finally:
            if "server" in locals():
                server.close()
            if uds_path.exists() and stat.S_ISSOCK(uds_path.lstat().st_mode):
                uds_path.unlink()
            # 1. Server context has stopped accepting new connections.
            # 2. Stop cron/webhook producers before cancelling active handlers.
            # 3. Await handler cancellation; Chat finally blocks close/quarantine
            #    their RuntimeResult while shared authorities are still alive.
            await agent.stop_producers()
            current = asyncio.current_task()
            active_handlers = [
                task for task in handler_tasks
                if task is not current and not task.done()
            ]
            for task in active_handlers:
                task.cancel()
            if active_handlers:
                # M1: bounded drain with hard ownership semantics — same
                # rationale as the chat drain in ``AgentService.shutdown``.  A
                # handler that swallows CancelledError would have left
                # ``wait_for(gather)`` to log+continue, dismantling shared
                # state under a live handler.  Fail closed: pending handlers at
                # the deadline refuse teardown.
                done, pending = await asyncio.wait(
                    active_handlers, timeout=SERVER_HANDLER_DRAIN_TIMEOUT,
                )
                if pending:
                    logger.error(
                        "server shutdown: %d handler task(s) did not terminate "
                        "within %.2fs (swallowed cancellation or wedged); "
                        "refusing to tear down shared authorities",
                        len(pending), SERVER_HANDLER_DRAIN_TIMEOUT,
                    )
                    raise ServiceShutdownError(
                        f"{len(pending)} handler task(s) did not terminate within "
                        f"{SERVER_HANDLER_DRAIN_TIMEOUT}s; shared authorities "
                        f"cannot be torn down safely"
                    )
            if "server" in locals():
                await server.wait_closed()
            # H1: detached SubAgent background tasks must be torn down BEFORE
            # the shared Office / Browser / Audit / DB authorities.  SubAgent
            # runs borrow all four; without this gate the server could close
            # them under a live task.  ``SubAgentRunner.run`` finally-block
            # already calls ``close_runtime_or_register``, so the cancelled
            # runtimes land in the orphan registry for the bounded drain inside
            # ``AgentService.shutdown``.
            if subagent_service is not None:
                await subagent_service.shutdown(timeout=SUBAGENT_SHUTDOWN_TIMEOUT)
            # Only after every handler/runtime is terminal may the service close
            # Office/Audit ownership.  A shutdown failure intentionally prevents
            # premature database close and remains observable to the caller.
            await agent.shutdown()
            await db.close()
            # M4 batch 3.1.15 (CRITICAL-1): mark the inner cleanup as
            # completed.  If ANY step above raised, this line is NOT
            # reached, and the outer ``finally`` will attempt emergency
            # cleanup and potentially retain the instance lock.
            inner_cleanup_completed = True
    finally:
        # M4 batch 3.1.15 (CRITICAL-1 + HIGH-1): the instance lock is
        # released ONLY on a clean shutdown.  If the inner cleanup raised
        # (cron executor resisted cancellation, chat drain timed out,
        # etc.) OR init failed after ``agent.start()`` (HIGH-1), we
        # attempt emergency cleanup.  If emergency cleanup succeeds, the
        # lock is released.  If it fails (live owners remain), the lock
        # fd is RETAINED in the module-level ``_retained_instance_lock_fd``
        # so a second instance cannot start against the same DB while the
        # first process's live executors are still producing side effects.
        # The OS reaps the fd when the process exits.
        if instance_lock_fd is not None:
            if inner_cleanup_completed:
                # Clean shutdown — release the lock.
                try:
                    os.close(instance_lock_fd)
                except OSError:
                    pass
            else:
                # Inner cleanup did NOT complete.  Attempt emergency
                # cleanup (HIGH-1: init failed after agent.start(); or
                # CRITICAL-1: inner finally raised during teardown).
                cleanup_ok = await _emergency_instance_cleanup(
                    agent, db, subagent_service,
                )
                if cleanup_ok:
                    try:
                        os.close(instance_lock_fd)
                    except OSError:
                        pass
                    logger.info(
                        "serve_json_lines: emergency cleanup succeeded; "
                        "instance lock released"
                    )
                else:
                    # RETAIN the lock — live owners remain.  Park the fd
                    # in the module-level holder so it is NOT garbage-
                    # collected (which would close it) and NOT closed by
                    # any other finally block.  The OS reaps it when the
                    # process exits.
                    global _retained_instance_lock_fd
                    _retained_instance_lock_fd = instance_lock_fd
                    logger.error(
                        "serve_json_lines: shutdown did NOT complete cleanly "
                        "and emergency cleanup failed (live cron executors / "
                        "chat owners / subagent runs remain); RETAINING "
                        "instance lock fd=%d to prevent a second instance "
                        "from starting against the same DB while live "
                        "owners remain.  The lock will be released when "
                        "the process exits. (CRITICAL-1)",
                        instance_lock_fd,
                    )


def _parse_json_line(line: bytes) -> dict:
    """Decode one JSON-line request into a dict.

    Empty connection probes are handled before this function. Malformed payloads get a
    structured error response instead of bubbling into asyncio's
    client_connected_cb exception logger.
    """
    try:
        request = json.loads(line.decode("utf-8"))
    except UnicodeDecodeError as exc:
        raise ValueError("request must be UTF-8 JSON") from exc
    except json.JSONDecodeError as exc:
        raise ValueError("request must be a JSON object line") from exc
    if not isinstance(request, dict):
        raise ValueError("request must be a JSON object")
    return request


async def _build_subagent_service(
    db: Database,
    project_root: Path | None,
    config_path: Path | None,
    *,
    office_authority: OfficeMutationAuthority | None = None,
    approval_broker: Any = None,
    audit_logger: Any = None,
) -> SubAgentService:
    """Build the SubAgent service bound to the server's shared security stack.

    B1: previously this function constructed a *bare* ``ToolScheduler(
    create_runtime_registry(), permission_engine)`` with no
    ``SecurityMiddleware`` — so the subagent ran on a parallel, unsupervised
    execution path that bypassed EffectivePolicy / Sandbox / NetworkGuard /
    AuditLogger.  Now the runner receives ``tool_scheduler=None`` and
    ``build_runtime`` constructs a fresh scheduler per run with the full
    security stack compiled from the same layered effective policy as the
    main AgentLoop.  The server-level ``approval_broker`` /
    ``audit_logger`` / ``office_authority`` are inherited so approvals,
    audit events and the Office storage baseline are shared with the main
    runtime, not forked.

    C-1-5b: the server-level ``ModeManager(local-uid)`` /
    ``MemoryStore(local-uid)`` / ``MemoryManager`` singletons are REMOVED.
    Previously they were bound to ``principal_id=f"local-uid:{os.getuid()}"``
    and passed to ``SubAgentRunner``, which forwarded them to
    ``RuntimeConfig`` — so ``build_runtime`` reused the local-uid-bound
    instances instead of constructing per-turn ones scoped to
    ``task.principal_id``.  Now ``SubAgentRunner`` receives ``None`` for
    both, and ``build_runtime`` constructs a per-turn ``ModeManager`` +
    ``MemoryManager`` from ``cfg.principal_id`` (= ``task.principal_id``,
    set from the authenticated RPC payload).  This guarantees the
    subagent's mode switches / memory scope are bound to the CALLING
    principal, not the server's local UID.
    """
    root = project_root or Path.cwd()
    resolved_config = config_path or root / "config.yaml"
    router = load_router_from_config(resolved_config, project_root=root)
    skill_manager = SkillManager()
    skills_dir = root / "skills"
    if skills_dir.is_dir():
        skill_manager.load_from_dir(skills_dir)
    runner = SubAgentRunner(
        router=router,
        db=db,
        # C-1-5b: do NOT pass server-level ModeManager / MemoryManager —
        # let ``build_runtime`` construct per-turn instances from
        # ``cfg.principal_id`` (= ``task.principal_id``).  Previously
        # these were bound to ``local-uid`` and reused across every
        # subagent run, so an API principal's subagent saw the local
        # user's mode state and memories.
        mode_manager=None,
        # B1: do NOT pass a bare ToolScheduler — let build_runtime construct
        # one per run with the full SecurityMiddleware stack and a registry
        # pruned to ``task.tools``.
        tool_scheduler=None,
        memory_manager=None,
        skill_manager=skill_manager if len(skill_manager.registry) > 0 else None,
        token_engine=get_token_engine(),
        office_authority=office_authority,
        approval_broker=approval_broker,
        # C-1-5b: no server-level principal_id — the runner relies on
        # ``task.principal_id`` (set from ``ctx.principal_id`` by
        # ``SubAgentService.handle_spawn``) and ``build_runtime``'s
        # fail-closed gate on empty principal_id.
        principal_id="",
        audit_logger=audit_logger,
        # B1: inherit the server's project_root / config_path so the subagent
        # loads the SAME ``khaos_policy.yaml`` and compiles the SAME
        # EffectivePolicy as the main AgentLoop — no second security
        # authority rooted at the process cwd.
        project_root=root,
        config_path=resolved_config,
    )
    spawner = SubAgentSpawner(
        SubAgentConfig(max_concurrent=3, max_spawn_depth=1, allow_nesting=False),
        db,
        runner=runner.run,
        registry=create_runtime_registry(),
    )
    # MEDIUM (batch 3.1.8): wire the orchestrator tool handlers
    # (``spawn_subagent`` / ``collect_results`` / ``execute_plan`` /
    # ``subagent_status``) with the real spawner + runner so they no
    # longer return ``"Orchestrator not initialized"`` in production.
    # The four handlers are registered in ``register_builtin_tools``
    # with a placeholder handler; ``create_runtime_registry`` rebinds
    # them to ``orchestrator_tools.{spawn_subagent,collect_results,...}``
    # but those module-level globals stay ``None`` until this call.
    from khaos.tools.orchestrator_tools import init_orchestrator
    init_orchestrator(spawner, runner)
    return SubAgentService(spawner, runner)


async def _handle_optional_subagent(
    subagent_service: SubAgentService | None,
    action: str,
    ctx: RequestContext,
    payload: dict,
) -> dict:
    """Dispatch a SubAgent RPC action with the transport ``ctx``.

    M4 batch 3.1.16A-4-2: ``ctx`` is passed directly to the SubAgent
    handler — no longer stamped onto the payload.  The SubAgentService
    reads ``ctx.principal_id`` directly, so a compromised Gateway that
    sends ``principal_id: 'admin'`` in the payload cannot win.
    """
    if subagent_service is None:
        return {"ok": False, "error": "subagents not enabled"}
    if action == "spawn":
        return await subagent_service.handle_spawn(ctx, payload)
    if action == "collect":
        return await subagent_service.handle_collect(ctx, payload)
    if action == "status":
        return await subagent_service.handle_status(ctx, payload)
    return {"ok": False, "error": "unknown subagent action"}


def load_router_from_config(config_path: Path, project_root: Path | None = None) -> ModelRouter:
    """Load model router, merging user config for the project template path."""
    expanded_config = config_path.expanduser()
    if not expanded_config.exists():
        return create_default_router(str(expanded_config), honor_no_config=False)
    root = project_root or Path.cwd()
    project_config = (root / "config.yaml").resolve()
    resolved_config = expanded_config.resolve()
    if resolved_config == project_config:
        return create_default_router(honor_no_config=False)
    return create_default_router(str(expanded_config), honor_no_config=False)


def _message_to_event(message) -> dict:
    event = message.event or ("done" if message.content == "done" and message.role == "system" else "message")
    if event in {"tool_call", "permission_request", "tool_result", "error"}:
        data = message.metadata
    elif event == "done":
        data = {"total_tokens": message.token_count, "stop_reason": message.stop_reason}
    else:
        data = {"role": message.role, "content": message.content, "token_count": message.token_count}
    return {"event": event, "data": data}


def _memory_to_dict(memory: Memory) -> dict:
    data = asdict(memory)
    data["scope"] = memory.scope.value
    data["confidence"] = memory.confidence.value
    data["created_at"] = memory.created_at.isoformat() if memory.created_at else ""
    data["updated_at"] = memory.updated_at.isoformat() if memory.updated_at else ""
    return data


def main() -> None:
    from khaos.db.state_root import open_state_db_safely, resolve_state_db_path

    parser = argparse.ArgumentParser()
    parser.add_argument("--socket", default="/tmp/khaos-agent.sock")
    parser.add_argument(
        "--db",
        default=None,
        help="SQLite database path (default: ~/.khaos/state/<project-id>/state.db)",
    )
    parser.add_argument("--config", default="config.yaml")
    parser.add_argument("--subagents", action="store_true")
    args = parser.parse_args()
    db_path = open_state_db_safely(
        resolve_state_db_path(Path.cwd(), args.db)
    )
    asyncio.run(
        serve_json_lines(
            args.socket,
            str(db_path),
            project_root=Path.cwd(),
            config_path=Path(args.config),
            enable_subagents=args.subagents,
        )
    )


if __name__ == "__main__":
    main()
