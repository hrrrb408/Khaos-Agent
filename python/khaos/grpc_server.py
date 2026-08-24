"""Python RPC transport and composition server.

The service classes mirror the LLD gRPC surface. The JSON-line Unix socket
server keeps the control plane local without generated protobuf dependencies.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import logging
import os
import socket
import stat
import time
import uuid
from pathlib import Path

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

from khaos.audit import (
    AuditLogger,
)
from khaos.db import Database
from khaos.exceptions import ServiceShutdownError
from khaos.maintenance import MaintenanceService
from khaos.rpc import AuditService as _AuditService
from khaos.rpc import MemoryService as _MemoryService
from khaos.rpc import SessionService as _SessionService
from khaos.rpc.agent_service import AgentService as _AgentService
from khaos.rpc.composition import _build_subagent_service, _handle_optional_subagent
from khaos.rpc.models import ChatRequest as _ChatRequest
from khaos.rpc.models import ConfirmRequest as _ConfirmRequest
from khaos.rpc.task_service import TaskService as _TaskService
from khaos.runtime import RequestContext
from khaos.subagents import SubAgentService
from khaos.tools import create_runtime_registry

logger = logging.getLogger(__name__)

import khaos.rpc.protocol as _rpc_protocol

# M2: bounded shutdown deadlines so a stuck handler / chat / detached
# subagent task cannot wedge server teardown.  These are fail-safe ceilings;
# the underlying close/orphan-drain phases still enforce terminal-state
# contracts and surface ``ServiceShutdownError`` on failure.
SERVER_HANDLER_DRAIN_TIMEOUT = 5.0
SUBAGENT_SHUTDOWN_TIMEOUT = 30.0


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
        if pre_lstat is not None and (fstat_info.st_dev, fstat_info.st_ino) != (
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
        os.write(fd, f"{os.getpid()}\n".encode())
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
    agent: _AgentService | None,
    db: Database | None,
    subagent_service: SubAgentService | None,
    maintenance: MaintenanceService | None = None,
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
      - ``maintenance.stop()`` — cancels the periodic GC loop.
      - ``subagent_service.shutdown()`` — bounded by SUBAGENT_SHUTDOWN_TIMEOUT.
      - ``agent.shutdown()`` — idempotent via ``_shutdown_completed`` flag.
      - ``db.close()`` — idempotent (sets ``_conn = None``).

    Round-5 Batch 5.4 (Shutdown Quarantine): if ``agent.shutdown()`` or
    ``subagent_service.shutdown()`` fails (live cron executors, chat
    owners, or subagent owners may still be running), the DB is NOT
    closed.  Closing the DB while live owners still hold references
    would cause them to hit ``_require_*_conn()`` which silently
    re-opens the database outside the normal service lifecycle —
    defeating the shutdown ordering invariant.  Instead the DB is
    quarantined (left open) and the instance lock is retained so no
    second process can start against it; the OS reaps everything when
    the process exits.  Only when ALL upstream owners have shut down
    cleanly is the DB closed.

    Batch 6.5 (round-6 §十六): FAIL-STOP dependency chain.  The shutdown
    topology is maintenance → subagent → agent → db, where each lower
    layer borrows the layer above's shared authorities.  If an upstream
    layer fails to shut down, its live owners may still be using those
    borrowed authorities — closing them would leave the live owner
    half-quarantined (alive but with Office/Browser/Audit already gone).
    Therefore a failure at ANY layer now stops the whole chain: it does
    NOT fall through to close downstream borrowed authorities.  Each
    step returns ``False`` (quarantine + retain lock) on failure rather
    than logging and continuing.
    """
    ok = True
    # Round-5 Batch 5.2 (C-05): stop the maintenance loop FIRST so it
    # does not race with agent.shutdown() / db.close() — e.g. a prune
    # cycle touching chat_streams while the DB is being closed.
    if maintenance is not None:
        try:
            await maintenance.stop()
        except Exception:
            logger.exception(
                "emergency cleanup: maintenance.stop() failed",
            )
            ok = False
    # Batch 6.5 (round-6 §十六): FAIL-STOP dependency chain.  The shutdown
    # topology is maintenance → subagent → agent → db, where each lower
    # layer BORROWS the layer above's shared authorities (Subagent borrows
    # Agent's OfficeMutationAuthority / BrowserManager / AuditLogger /
    # ApprovalBroker / DB; Agent borrows the DB).  If an upstream layer
    # fails to shut down, its live owners may still be using those borrowed
    # authorities — closing them would leave the live owner half-quarantined
    # (alive but its authorities gone).  Therefore a failure at any layer
    # MUST NOT proceed to close the downstream borrowed authorities.  Each
    # step checks ``ok`` and returns early (quarantine + retain lock) on
    # failure, instead of the old "log + continue" fall-through.
    if not ok:
        logger.error(
            "emergency cleanup: maintenance.stop() failed; NOT shutting "
            "down subagent/agent/db — borrowed authorities retained to "
            "avoid half-quarantine; instance lock must be retained",
        )
        return False
    if subagent_service is not None:
        try:
            await subagent_service.shutdown(timeout=SUBAGENT_SHUTDOWN_TIMEOUT)
        except Exception:
            logger.exception(
                "emergency cleanup: subagent_service.shutdown() failed; "
                "live subagent owners may remain — NOT shutting down "
                "agent/db (Subagent borrows Agent's Office/Browser/Audit)",
            )
            ok = False
    if not ok:
        logger.error(
            "emergency cleanup: subagent shutdown failed; QUARANTINING "
            "agent + database (not closing borrowed authorities) — live "
            "subagent owners may still be active; instance lock retained",
        )
        return False
    if agent is not None:
        try:
            await agent.shutdown()
        except Exception:
            logger.exception(
                "emergency cleanup: agent.shutdown() failed; live cron "
                "executors or chat owners may remain",
            )
            ok = False
    # Round-5 Batch 5.4 (Shutdown Quarantine): only close the DB when
    # every upstream owner has shut down cleanly.  If any shutdown
    # failed, live owners may still be accessing the DB — closing it
    # would either crash them or trigger a silent re-open outside the
    # service lifecycle.  Quarantine (leave open) + retain lock instead.
    if not ok:
        logger.error(
            "emergency cleanup: agent shutdown failed; QUARANTINING "
            "the database (not closing) — live cron/chat owners may "
            "still be active; instance lock must be retained",
        )
        return False
    if db is not None:
        try:
            await db.close()
        except Exception:
            logger.exception(
                "emergency cleanup: db.close() failed",
            )
            ok = False
    return ok


def _load_rpc_capability() -> str:
    path_value = os.environ.get("KHAOS_PYTHON_CAPABILITY_FILE", "").strip()
    if path_value:
        if os.name != "posix" or not hasattr(os, "O_NOFOLLOW"):
            raise PermissionError(
                "protected RPC capability files require POSIX no-follow support"
            )
        path = Path(path_value).expanduser()
        if not path.is_absolute():
            raise PermissionError("RPC capability file path must be absolute")
        entry = path.lstat()
        if stat.S_ISLNK(entry.st_mode):
            raise PermissionError("RPC capability file must not be a symlink")
        if not stat.S_ISREG(entry.st_mode):
            raise PermissionError("RPC capability file must be an owner-held regular file")
        mode = stat.S_IMODE(entry.st_mode)
        is_container_secret = str(path).startswith("/run/secrets/")
        # Docker Compose file-backed secrets are mounted root-owned and the
        # local Docker Desktop engine ignores the long-syntax uid/gid fields.
        # The container-secret contract is therefore non-writable rather than
        # current-UID-owned; ordinary host files remain owner-held below.
        if not is_container_secret and entry.st_uid != os.getuid():
            raise PermissionError("RPC capability file must be an owner-held regular file")
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
    gateway_gid: int | None = None,
) -> None:
    """Serve the privileged JSON-line control plane over a protected UDS.

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
    if gateway_gid is not None and gateway_gid < 0:
        raise ValueError("gateway GID must be non-negative")
    if gateway_gid is not None and gateway_uid is None:
        raise ValueError("gateway GID requires an explicit gateway UID")
    parent_mode = 0o2750 if gateway_gid is not None else 0o700
    socket_mode = 0o660 if gateway_gid is not None else 0o600
    authenticator = _rpc_protocol.GatewayRPCAuthenticator(
        capability,
        expected_uid=gateway_uid,
        expected_pid=gateway_pid,
        require_protocol_metadata=os.environ.get("KHAOS_DEV_MODE") != "1",
    )
    uds_path.parent.mkdir(mode=parent_mode, parents=True, exist_ok=True)
    parent_stat = uds_path.parent.stat()
    if parent_stat.st_uid != os.getuid():
        raise PermissionError("RPC socket parent must be owned by Runtime")
    if gateway_gid is None:
        if stat.S_IMODE(parent_stat.st_mode) != 0o700:
            raise PermissionError("RPC socket parent must have mode 0700")
    elif (
        parent_stat.st_gid != gateway_gid
        or stat.S_IMODE(parent_stat.st_mode) != 0o2750
    ):
        raise PermissionError(
            "RPC socket parent must be a Runtime-owned setgid directory "
            f"with group {gateway_gid} and mode 02750"
        )
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
    agent: _AgentService | None = None
    db: Database | None = None
    subagent_service: SubAgentService | None = None
    # Round-5 Batch 5.2 (C-05): track maintenance so both the inner
    # shutdown path and the outer emergency-cleanup path can stop the
    # periodic GC loop before tearing down shared authorities / DB.
    maintenance: MaintenanceService | None = None
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
        # Round-5 Batch 5.2 (C-05): chat stream recovery is now a
        # STARTUP-ONLY operation that passes a per-process ``boot_id``.
        # Previously ``recover_inflight_chat_streams`` was called both at
        # startup AND hourly by ``MaintenanceService``; the hourly call
        # terminated active chats that were waiting on long tool calls
        # because their lease had expired between heartbeat renewals.
        # The ``boot_id`` ensures the current process never recovers its
        # OWN active streams — only streams left by a PREVIOUS crashed
        # process or streams whose lease has genuinely expired.
        boot_id = uuid.uuid4().hex
        recovered = await db.recover_inflight_chat_streams(
            now=time.time(), boot_id=boot_id,
        )
        if recovered > 0:
            logger.info(
                "serve_json_lines: recovered %d crash-left chat stream(s) "
                "at startup (boot_id=%s)", recovered, boot_id,
            )
        agent = _AgentService(
            db, project_root=project_root, config_path=config_path, router=router,
            boot_id=boot_id,
        )
        await agent.start()
        # Round-4 review Batch 4 (§11.2 + §13.1): start the periodic
        # maintenance service so ``prune_terminal_chat_streams`` and
        # ``ApprovalBroker.sweep_expired`` run hourly in production.
        # Previously these GC methods existed but had no production
        # caller, causing unbounded chat ledger and approval growth.
        #
        # Round-5 Batch 5.2 (C-05): ``recover_inflight_chat_streams``
        # was REMOVED from the periodic loop — recovery is now
        # startup-only (see the call above).  Calling recovery
        # periodically was the C-05 bug.
        maintenance = MaintenanceService(
            db,
            approval_broker=agent.approval_broker,
            operation_repository=db.tool_operation_repository,
        )
        maintenance.start()
        # _MemoryService receives explicit repository and audit ports.  The
        # service binds both to each authenticated RequestContext; it never
        # shares the server logger's local-uid attribution with API callers.
        from khaos.memory import SqliteMemoryRepository

        memory = _MemoryService(
            SqliteMemoryRepository(db),
            audit_logger=agent._audit_logger,
            memory_host=agent.memory_host,
            broker=agent.memory_host.broker if agent.memory_host is not None else None,
            require_host=True,
        )
        # C-2-3: _SessionService proxies REST /api/sessions list/detail
        # reads to the durable ``sessions`` table, scoped to
        # ``ctx.principal_id``.  Previously the Go Gateway served these
        # from its in-memory ``sessions`` + ``sessionOwners`` maps
        # (lost on restart, blind to Python-side sessions).
        sessions = _SessionService(db)
        audit_service = _AuditService(agent._audit_logger or AuditLogger(db))
        # C-1-5a: _TaskService now takes ``db`` (not a TaskManager) and
        # constructs per-principal managers on demand.
        task_service = _TaskService(db, agent.approval_broker)
        subagent_service: SubAgentService | None = None
        if enable_subagents:
            # B1: share the _AgentService's office authority AND approval broker so
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
                cleanup_authority=agent.runtime_cleanup_authority,
                memory_host=agent.memory_host,
            )
            agent.subagent_spawner = subagent_service.spawner

        async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            try:
                try:
                    peer_pid = authenticator.verify_peer(writer)
                except PermissionError as exc:
                    logger.warning("RPC peer rejected before request framing: %s", exc)
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
                except _rpc_protocol.RPCProtocolError as exc:
                    writer.write((json.dumps({
                        "error": exc.code, "message": str(exc),
                    }) + "\n").encode("utf-8"))
                    await writer.drain()
                    return
                except PermissionError as exc:
                    writer.write((json.dumps({
                        "error": "unauthenticated", "message": str(exc),
                    }) + "\n").encode("utf-8"))
                    await writer.drain()
                    return
                method = request.get("method")
                payload = request.get("payload", {})
                require_initialize = os.environ.get("KHAOS_DEV_MODE") != "1"
                if (
                    require_initialize
                    and method != _rpc_protocol.RPC_INITIALIZE_METHOD
                ):
                    writer.write((json.dumps({
                        "error": "rpc_negotiation_required",
                        "message": (
                            "RPC.Initialize must complete before service requests"
                        ),
                    }) + "\n").encode("utf-8"))
                    await writer.drain()
                    return
                if method == _rpc_protocol.RPC_INITIALIZE_METHOD:
                    try:
                        if not isinstance(payload, dict):
                            raise _rpc_protocol.RPCProtocolError(
                                "rpc_schema_unsupported",
                                "RPC initialize payload must be an object",
                            )
                        initialize_response = _rpc_protocol.rpc_initialize_response(
                            payload
                        )
                    except _rpc_protocol.RPCProtocolError as exc:
                        writer.write((json.dumps({
                            "error": exc.code,
                            "message": str(exc),
                        }) + "\n").encode("utf-8"))
                        await writer.drain()
                        return
                    writer.write(
                        (json.dumps(initialize_response, ensure_ascii=False) + "\n")
                        .encode("utf-8")
                    )
                    await writer.drain()
                    # Production clients reuse the negotiated connection for
                    # exactly one authenticated service request.  The
                    # initialize frame is never treated as a service call.
                    line = await reader.readline()
                    if not line:
                        return
                    try:
                        request = _parse_json_line(line)
                    except ValueError as exc:
                        writer.write((json.dumps({
                            "error": "invalid_json",
                            "message": str(exc),
                        }) + "\n").encode("utf-8"))
                        await writer.drain()
                        return
                    try:
                        principal_id = authenticator.authenticate(
                            request, peer_pid=peer_pid,
                        )
                    except _rpc_protocol.RPCProtocolError as exc:
                        writer.write((json.dumps({
                            "error": exc.code,
                            "message": str(exc),
                        }) + "\n").encode("utf-8"))
                        await writer.drain()
                        return
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
                # P1-2 (tool descriptor drift): Bootstrap.GetToolSchemas —
                # Gateway startup handshake returning the Python production
                # registry's model-visible tool catalogue so /api/tools is
                # the runtime fact, not a hard-coded three-tool literal that
                # silently drifts.  Python is the sole authority for which
                # tools exist; Go never re-declares them.
                if method == "Bootstrap.GetToolSchemas":
                    writer.write((json.dumps({
                        "tools": create_runtime_registry().gateway_view(),
                    }) + "\n").encode("utf-8"))
                    await writer.drain()
                    return
                # Bootstrap.Health is an authenticated control-plane probe.
                # Unlike GetPolicyDigest it must carry the deployment claims,
                # so a Gateway pointed at the wrong project/policy cannot
                # receive a misleading ready response.  It has no user
                # principal and therefore does not enter a service context.
                if method == "Bootstrap.Health":
                    claim_error = _rpc_protocol.rpc_binding_claim_error(
                        payload,
                        bound_project_id=agent._bound_project_id,
                        bound_policy_digest=agent._effective_policy.digest,
                        require_claims=os.environ.get("KHAOS_DEV_MODE") != "1",
                    )
                    if claim_error is not None:
                        error_code, error_message = claim_error
                        writer.write((json.dumps({
                            "error": error_code,
                            "message": error_message,
                        }) + "\n").encode("utf-8"))
                    else:
                        writer.write(
                            (json.dumps(await agent.health(), ensure_ascii=False) + "\n")
                            .encode("utf-8")
                        )
                    await writer.drain()
                    return
                # Internal RPC v2 is the production contract. The Gateway
                # must complete the bootstrap handshake and carry both
                # server-bound claims on every non-bootstrap request. Empty
                # claims remain available only under the explicit test/dev
                # mode, never as a production compatibility default.
                claim_error = _rpc_protocol.rpc_binding_claim_error(
                    payload,
                    bound_project_id=agent._bound_project_id,
                    bound_policy_digest=agent._effective_policy.digest,
                    require_claims=os.environ.get("KHAOS_DEV_MODE") != "1",
                )
                if claim_error is not None:
                    error_code, error_message = claim_error
                    writer.write((json.dumps({
                        "error": error_code,
                        "message": error_message,
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
                # ``principal_id`` from the payload (_ChatRequest,
                # _ConfirmRequest, _TaskService.approve/reject, SubAgent
                # handlers) still work — we inject ctx.principal_id
                # into the payload so ``**payload`` unpacking picks it
                # up.  A-4-2 will remove this crutch and read directly
                # from ctx.
                #
                # CONDITIONAL injection (M4 batch 3.1.16A-4-1): only
                # overwrite when the Go side already sent
                # ``principal_id``.  Methods whose signatures don't
                # accept ``principal_id`` (_TaskService.list/get/create/
                # cancel/artifacts, _MemoryService.*, _AuditService.query,
                # _AgentService.switch_mode/list_channels/
                # set_channel_enabled/handle_webhook) would raise
                # TypeError on ``**payload`` unpacking if we injected
                # unconditionally.  SubAgent handlers get their
                # principal stamped inside ``_handle_optional_subagent``
                # so they don't depend on this branch.
                if principal_id:
                    ctx = RequestContext.for_rpc(
                        principal_id,
                        project_id=agent._bound_project_id,
                        policy_digest=agent._effective_policy.digest,
                    )
                elif method == "AgentService.HandleWebhook":
                    # Round-15 B-3: the Go gateway forwards inbound platform
                    # webhooks with ``principal_id=""`` (the webhook has no
                    # API-key principal; ``handle_webhook`` derives its own
                    # ``webhook:<channel>:<platform>:<sender>`` principal for
                    # the resulting turn).  ``for_rpc`` rejects an empty
                    # principal, which previously made the production webhook
                    # path die at context construction.  Use the local-uid
                    # context for the webhook handler only — it does not use
                    # ``ctx.principal_id`` for authorization (the platform
                    # signature is verified inside ``handle_webhook``).
                    ctx = RequestContext.for_cli(
                        project_id=agent._bound_project_id,
                        policy_digest=agent._effective_policy.digest,
                    )
                else:
                    writer.write((json.dumps({
                        "error": "unauthenticated", "message": "principal_id is required",
                    }) + "\n").encode("utf-8"))
                    await writer.drain()
                    return
                if "principal_id" in payload:
                    payload["principal_id"] = ctx.principal_id
                # M4 batch 3.1.16A-5-1b (CRITICAL): project identity
                # drift detection.  The Go side may claim a
                # ``project_id`` in the payload (caller-asserted).
                # Compare it against ``agent._bound_project_id`` (the
                # server-computed identity of this _AgentService's
                # ``project_root``).  A mismatch means the Gateway
                # routed a request for project A to a server booted
                # under project B — either a misconfiguration or an
                # attempt to cross-contaminate project state (e.g.
                # write audit rows / memories / coding tasks attributed
                # to the wrong project).  Fail-closed: reject before
                # any service method runs. Empty claims are accepted only
                # under explicit development mode; production v2 rejects
                # them before this point, and ``ctx.project_id`` remains
                # the server-bound value.
                # Pop ``project_id`` from the payload so downstream
                # ``_ChatRequest(**payload)`` / ``_ConfirmRequest(**payload)``
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
                # (the server-computed digest of this _AgentService's
                # compiled EffectiveSecurityPolicy).  A mismatch means
                # the Gateway booted against a Python server with policy
                # A, then routed a request to a Python server with
                # policy B — either a restart with a different
                # khaos_policy.yaml, or a misconfigured multi-server
                # deployment. Fail-closed: reject before any service
                # method runs. Empty claims are accepted only under
                # explicit development mode; production v2 rejects them
                # before this point, and ``ctx.policy_digest`` remains
                # the server-bound value.
                # Pop ``policy_digest`` from the payload so downstream
                # ``_ChatRequest(**payload)`` / ``_ConfirmRequest(**payload)``
                # etc. don't receive an unexpected keyword.  The
                # verified value lives on ``ctx.policy_digest`` (always
                # equal to ``agent._effective_policy.digest`` here).
                payload.pop("policy_digest", None)
                if method == "AgentService.Chat":
                    try:
                        async for event in agent.chat(ctx, _ChatRequest(**payload)):
                            writer.write((json.dumps(event, ensure_ascii=False) + "\n").encode("utf-8"))
                            await writer.drain()
                    except Exception as exc:  # noqa: BLE001 - RPC errors must be framed
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
                elif method == "AgentService.ChatEvents":
                    # Batch 7.2 §十四: forward stream_id so a caller can
                    # request a stream-specific tail (previously dropped).
                    legacy_cursor_present = "after_sequence" in payload
                    event_cursor_present = "after_event_id" in payload
                    if legacy_cursor_present and event_cursor_present:
                        raise ValueError("ambiguous replay cursor fields")
                    async for event in agent.chat_events(
                        ctx,
                        str(payload.get("session_id", "")),
                        int(payload.get("after_sequence", 0)),
                        str(payload.get("stream_id", "")),
                        (
                            int(payload["after_event_id"])
                            if event_cursor_present
                            else None
                        ),
                    ):
                        writer.write(
                            (json.dumps(event, ensure_ascii=False) + "\n").encode(
                                "utf-8"
                            )
                        )
                        await writer.drain()
                elif method == "AgentService.SwitchMode":
                    response = await agent.switch_mode(ctx, payload.get("session_id", ""), payload["target_mode"])
                    writer.write((json.dumps(response, ensure_ascii=False) + "\n").encode("utf-8"))
                elif method == "AgentService.ConfirmPermission":
                    response = await agent.confirm_permission(ctx, _ConfirmRequest(**payload))
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
                elif method == "MemoryService.DeleteMemory":
                    # C-2-2: route DELETE through the service layer so
                    # ``ctx.principal_id`` is enforced (cross-principal
                    # deletion yields ``{"ok": True}`` but only affects
                    # rows owned by the caller or project-shared rows).
                    # Previously the dispatcher had no DeleteMemory branch,
                    # so Go REST ``DELETE /api/memory/{id}`` could never
                    # reach Python — the in-memory Gateway ``MemoryMap``
                    # silently swallowed the call and the durable row
                    # survived in the DB.
                    response = await memory.delete_memory(ctx, **payload)
                    writer.write((json.dumps(response, ensure_ascii=False) + "\n").encode("utf-8"))
                elif method == "SessionService.List":
                    # C-2-3: REST ``GET /api/sessions`` proxies here so
                    # the list is sourced from the durable ``sessions``
                    # table (not the Go in-memory map, which is lost on
                    # restart and blind to Python-side sessions).
                    response = await sessions.list(ctx, **payload)
                    writer.write((json.dumps(response, ensure_ascii=False) + "\n").encode("utf-8"))
                elif method == "SessionService.Get":
                    # C-2-3: REST ``GET /api/sessions/{id}`` proxies
                    # here; cross-principal access is hidden as
                    # ``{"ok": false, "error": "session not found"}``.
                    response = await sessions.get(ctx, **payload)
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
                    writer.write(json.dumps({
                        "error": "unknown_method",
                        "message": "unknown method",
                    }).encode("utf-8") + b"\n")
                await writer.drain()
            except Exception as exc:  # noqa: BLE001 - service errors must be framed
                # A service-level miss or validation error must remain a
                # framed RPC response. Letting it escape silently closes the
                # one-request UDS connection, producing an empty JSON line and
                # an unowned handler-task exception on the server.
                try:
                    writer.write((json.dumps({
                        "error": exc.__class__.__name__,
                        "message": str(exc),
                    }, ensure_ascii=False) + "\n").encode("utf-8"))
                    await writer.drain()
                except (ConnectionError, OSError):
                    pass
            finally:
                writer.close()
                try:
                    await asyncio.wait_for(writer.wait_closed(), timeout=1.0)
                except (TimeoutError, ConnectionError, OSError):
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
                accept_connection,
                path=str(uds_path),
                limit=_rpc_protocol.RPC_MAX_REQUEST_BYTES,
            )
            os.chmod(uds_path, socket_mode)
            socket_stat = uds_path.lstat()
            if socket_stat.st_uid != os.getuid() or not stat.S_ISSOCK(socket_stat.st_mode):
                raise PermissionError("RPC socket inode ownership/type validation failed")
            if gateway_gid is not None and (
                socket_stat.st_gid != gateway_gid
                or stat.S_IMODE(socket_stat.st_mode) != socket_mode
            ):
                raise PermissionError(
                    "RPC socket inode did not inherit the configured Gateway group"
                )
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
                # rationale as the chat drain in ``_AgentService.shutdown``.  A
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
            # Round-5 Batch 5.2 (C-05): stop the periodic maintenance
            # loop BEFORE tearing down shared authorities / DB, so a GC
            # cycle does not race with agent.shutdown() / db.close().
            if maintenance is not None:
                await maintenance.stop()
            # H1: detached SubAgent background tasks must be torn down BEFORE
            # the shared Office / Browser / Audit / DB authorities.  SubAgent
            # runs borrow all four; without this gate the server could close
            # them under a live task.  ``SubAgentRunner.run`` finally-block
            # already calls ``close_runtime_or_register``, so the cancelled
            # runtimes land in the orphan registry for the bounded drain inside
            # ``_AgentService.shutdown``.
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
                    agent, db, subagent_service, maintenance,
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
        raise ValueError("request must be a JSON object")  # noqa: TRY004 - wire compatibility
    return request


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
