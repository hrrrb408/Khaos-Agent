"""M4 batch 3.1.16A-1 — Trusted State Root.

The trusted state database (permissions, memories, audit, cron,
coding tasks, scheduled tasks) MUST NOT live in the project
directory.  The project directory is controlled by the repository
and cannot be trusted as the root of security state:

  * a malicious repo can pre-place a ``khaos.db`` symlink pointing
    at an arbitrary host file (migrations would then write to that
    file);
  * a malicious repo can pre-place a constructed ``khaos.db``
    containing auto-approve permissions, global system-prompt
    memories, or pending cron tasks with an attacker-chosen
    ``principal_id``;
  * in workspace-write mode, the Agent itself can modify the DB
    that holds its own permission and audit state;
  * hardlinks to the same SQLite inode from different project
    paths produce different lockfile hashes, defeating the
    single-instance model.

The state DB now lives at::

    ~/.khaos/state/<project-id>/state.db

where ``<project-id> = sha256(realpath(project_root))[:32]``.

This module is the single authority for resolving and safety-
checking the state DB path.  ``Database`` itself stays a thin
low-level wrapper — tests that instantiate ``Database(tmp_path /
"khaos.db")`` directly bypass this module and are unaffected.

Production entry points (CLI commands, ``serve_json_lines``,
``khaos migrate``) MUST call ``resolve_state_db_path`` and
``open_state_db_safely`` before constructing ``Database``.

Tests set ``KHAOS_ALLOW_PROJECT_DB=1`` (see ``conftest.py``) to
bypass the state-root enforcement — the test suite legitimately
needs to create DBs in ``tmp_path``.
"""

from __future__ import annotations

import hashlib
import os
import stat
from pathlib import Path

from khaos.exceptions import KhaosError


class StateRootError(KhaosError):
    """Raised when the trusted state root cannot be established."""


# Trusted root for all per-project state databases.
STATE_ROOT = Path.home() / ".khaos" / "state"

# The old default DB filename.  If a file with this name exists in
# the project directory, the runtime refuses to start and prompts
# the user to migrate — see ``check_no_project_dir_db``.
PROJECT_DB_SENTINEL = "khaos.db"

# Environment variable that disables state-root enforcement.
# Set to ``"1"`` in ``conftest.py`` so the test suite can use
# ``Database(tmp_path / "khaos.db")`` without modification.
_ALLOW_PROJECT_DB_ENV = "KHAOS_ALLOW_PROJECT_DB"


def is_project_db_allowed() -> bool:
    """Return True when state-root enforcement is bypassed.

    The test suite sets ``KHAOS_ALLOW_PROJECT_DB=1`` so it can
    create databases in ``tmp_path`` without each test having to
    construct a ``~/.khaos/state/<id>/state.db`` path.  Production
    code never sets this variable.
    """
    return os.environ.get(_ALLOW_PROJECT_DB_ENV, "") == "1"


def project_id(project_root: Path) -> str:
    """Compute a stable project identifier from the project root path.

    The identifier is ``sha256(realpath(project_root))[:32]``.  Two
    different project paths produce different identifiers, so each
    project gets its own state DB.  Symlinks in the project path are
    resolved first, so a project reached via different symlink paths
    maps to the same state DB.
    """
    real = str(Path(project_root).resolve())
    return hashlib.sha256(real.encode("utf-8")).hexdigest()[:32]


def state_db_path(project_root: Path) -> Path:
    """Compute the trusted state DB path for a project.

    Returns ``~/.khaos/state/<project-id>/state.db``.  The path is
    not yet created or validated — call ``open_state_db_safely``
    to ensure the directory chain and file are safe before opening.
    """
    return STATE_ROOT / project_id(project_root) / "state.db"


def check_no_project_dir_db(project_root: Path) -> None:
    """Refuse to start if a ``khaos.db`` exists in the project dir.

    A ``khaos.db`` in the project directory is either:
      * a legitimate DB from a pre-3.1.16A Khaos version → the user
        must explicitly migrate it (we refuse auto-migration because
        the old DB might be malicious);
      * a malicious pre-placed DB → must be refused;
      * a symlink → must be refused.

    Raises ``StateRootError`` with a migration prompt if the file
    exists.  Bypassed when ``KHAOS_ALLOW_PROJECT_DB=1`` (tests).
    """
    if is_project_db_allowed():
        return
    legacy = project_root / PROJECT_DB_SENTINEL
    if legacy.exists() or legacy.is_symlink():
        state_path = state_db_path(project_root)
        raise StateRootError(
            f"A '{PROJECT_DB_SENTINEL}' file exists in the project "
            f"directory:\n\n"
            f"  {legacy}\n\n"
            f"Khaos no longer stores its trusted state database in "
            f"the project directory (M4 batch 3.1.16A-1: trusted "
            f"state root isolation).  The project directory is "
            f"controlled by the repository and cannot be trusted as "
            f"the root of security state — a malicious repo can "
            f"pre-place a symlink, a constructed DB with auto-approve "
            f"permissions, or global system-prompt memories.\n\n"
            f"To migrate:\n\n"
            f"  1. Export trusted data from the old DB:\n"
            f"       sqlite3 {legacy} .dump > /tmp/khaos-export.sql\n\n"
            f"  2. Initialize the new state DB:\n"
            f"       khaos migrate\n"
            f"     (creates {state_path})\n\n"
            f"  3. Review the SQL export, then import:\n"
            f"       sqlite3 {state_path} < /tmp/khaos-export.sql\n\n"
            f"  4. Remove or rename the old DB:\n"
            f"       mv {legacy} {legacy}.bak\n\n"
            f"  5. Restart Khaos.\n\n"
            f"If the old DB was created by a malicious repository, "
            f"DO NOT import its contents — start fresh with "
            f"`khaos migrate` and let Khaos rebuild its state.\n"
        )


def resolve_state_db_path(
    project_root: Path | None,
    explicit_db: str | Path | None = None,
) -> Path:
    """Resolve the DB path, enforcing state root for the default case.

    Resolution rules:

    1. ``explicit_db`` is ``None`` or equal to ``"khaos.db"`` (the
       old default sentinel) → use the state root:
       ``~/.khaos/state/<project-id>/state.db``.  Also calls
       ``check_no_project_dir_db`` to refuse legacy DBs.

    2. ``explicit_db`` is provided as a non-sentinel path → the user
       is taking responsibility for the location.  If the resolved
       path is inside the project directory, refuse unless
       ``KHAOS_ALLOW_PROJECT_DB=1`` (tests).  Otherwise accept.

    The returned path is NOT yet safety-checked.  Call
    ``open_state_db_safely`` to ensure the directory chain and file
    are safe before constructing ``Database``.
    """
    root = project_root or Path.cwd()

    # Case 1: no explicit DB, or the old "khaos.db" sentinel.
    if explicit_db is None or str(explicit_db) == PROJECT_DB_SENTINEL:
        check_no_project_dir_db(root)
        return state_db_path(root)

    # Case 2: user provided an explicit path.
    path = Path(explicit_db)
    if not is_project_db_allowed():
        # Refuse if the resolved path is inside the project dir.
        try:
            resolved = path.resolve()
            proj_resolved = root.resolve()
            try:
                resolved.relative_to(proj_resolved)
                in_project = True
            except ValueError:
                in_project = False
        except OSError:
            in_project = False
        if in_project:
            raise StateRootError(
                f"explicit --db path {path} resolves inside the "
                f"project directory {root}; Khaos no longer accepts "
                f"project-directory databases as trusted state "
                f"(M4 batch 3.1.16A-1).  Either omit --db to use "
                f"the trusted state root, or set "
                f"KHAOS_ALLOW_PROJECT_DB=1 for tests."
            )
    return path


def _ensure_safe_dir(
    dir_path: Path,
    *,
    expected_mode: int,
    label: str,
) -> None:
    """Ensure a trusted directory exists and is safe.

    Safety properties:
      * not a symlink (lstat before any open);
      * is a directory;
      * owned by the current UID;
      * mode has no group/other bits set (``expected_mode`` is
        typically ``0o700``).

    If the directory doesn't exist, create it with ``expected_mode``.
    """
    if not dir_path.exists():
        dir_path.mkdir(mode=expected_mode, parents=False, exist_ok=True)
    try:
        st = dir_path.lstat()
    except OSError as exc:
        raise StateRootError(
            f"cannot stat trusted {label} {dir_path}: {exc}"
        ) from exc
    if stat.S_ISLNK(st.st_mode):
        raise StateRootError(
            f"refusing to use symlinked {label}: {dir_path} "
            f"(3.1.16A-1: a symlink could redirect state DB "
            f"creation to an attacker-controlled path)"
        )
    if not stat.S_ISDIR(st.st_mode):
        raise StateRootError(
            f"trusted {label} is not a directory: {dir_path}"
        )
    if st.st_uid != os.getuid():
        raise StateRootError(
            f"trusted {label} {dir_path} is owned by uid "
            f"{st.st_uid}, not the current uid {os.getuid()} "
            f"(3.1.16A-1: state root ownership)"
        )
    mode = stat.S_IMODE(st.st_mode)
    if mode & ~expected_mode:
        raise StateRootError(
            f"trusted {label} {dir_path} has unsafe mode "
            f"{mode:o} (extra bits set; expected {expected_mode:o}) "
            f"— refusing to use it for state DB storage "
            f"(3.1.16A-1: state root safety)"
        )


def _ensure_safe_parent_khaos_dir(khaos_dir: Path) -> None:
    """Ensure ``~/.khaos/`` is safe (parent of state root).

    Same rules as ``_ensure_safe_run_dir`` in ``grpc_server.py``:
    owned by current UID, not a symlink, is a directory, no
    group/other write bits.  Mode 0755 is allowed (shared with
    other Khaos components); 0775/0777 are rejected.
    """
    if not khaos_dir.exists():
        khaos_dir.mkdir(mode=0o755, parents=False, exist_ok=True)
    try:
        st = khaos_dir.lstat()
    except OSError as exc:
        raise StateRootError(
            f"cannot stat trusted khaos dir {khaos_dir}: {exc}"
        ) from exc
    if stat.S_ISLNK(st.st_mode):
        raise StateRootError(
            f"refusing to use symlinked khaos dir: {khaos_dir} "
            f"(3.1.16A-1: state root safety)"
        )
    if not stat.S_ISDIR(st.st_mode):
        raise StateRootError(
            f"khaos dir is not a directory: {khaos_dir}"
        )
    if st.st_uid != os.getuid():
        raise StateRootError(
            f"khaos dir {khaos_dir} is owned by uid "
            f"{st.st_uid}, not the current uid {os.getuid()} "
            f"(3.1.16A-1: state root ownership)"
        )
    mode = stat.S_IMODE(st.st_mode)
    if mode & 0o022:
        raise StateRootError(
            f"khaos dir {khaos_dir} has unsafe mode {mode:o} "
            f"(group or other writable; expected no group/other "
            f"write bits) — refusing to use it for state root "
            f"(3.1.16A-1: state root parent dir safety)"
        )


def ensure_safe_state_dir(state_dir: Path) -> None:
    """Ensure the full directory chain for a state DB is safe.

    Validates, from top to bottom:
      * ``~/.khaos/`` — owned by UID, not symlink, mode & 0o022 == 0
      * ``~/.khaos/state/`` — 0700, owned by UID, not symlink
      * ``~/.khaos/state/<project-id>/`` — 0700, owned by UID, not symlink

    Creates missing directories with the strict mode.  WAL and SHM
    files (created by SQLite alongside ``state.db``) live in the
    same directory and are protected by the directory permissions.
    """
    project_dir = state_dir  # e.g. ~/.khaos/state/<project-id>/
    state_root = project_dir.parent  # ~/.khaos/state/
    khaos_dir = state_root.parent  # ~/.khaos/

    _ensure_safe_parent_khaos_dir(khaos_dir)
    _ensure_safe_dir(state_root, expected_mode=0o700, label="state root")
    _ensure_safe_dir(project_dir, expected_mode=0o700, label="project state dir")


def ensure_safe_state_db_file(db_path: Path) -> None:
    """Ensure the state DB file itself is safe to open.

    If the file exists:
      * must be a regular file (not symlink, not device, not dir);
      * must be owned by the current UID;
      * must have mode 0600 (no group/other access).

    If the file doesn't exist, it will be created by SQLite with
    the process umask; the directory is already 0700, so the file
    is only accessible to the owner.  We ``os.chmod`` it to 0600
    after creation if needed (handled by the caller via SQLite's
    default behavior + the 0700 directory).
    """
    if not db_path.exists():
        return  # SQLite will create it; directory is 0700.
    if db_path.is_symlink():
        raise StateRootError(
            f"refusing to open symlinked state DB: {db_path} "
            f"(3.1.16A-1: a symlink could redirect DB access to "
            f"an attacker-controlled file)"
        )
    try:
        st = db_path.lstat()
    except OSError as exc:
        raise StateRootError(
            f"cannot stat state DB {db_path}: {exc}"
        ) from exc
    if not stat.S_ISREG(st.st_mode):
        raise StateRootError(
            f"state DB {db_path} is not a regular file "
            f"(3.1.16A-1: state root safety)"
        )
    if st.st_uid != os.getuid():
        raise StateRootError(
            f"state DB {db_path} is owned by uid {st.st_uid}, "
            f"not the current uid {os.getuid()} "
            f"(3.1.16A-1: state root ownership)"
        )
    mode = stat.S_IMODE(st.st_mode)
    if mode & 0o077:
        raise StateRootError(
            f"state DB {db_path} has unsafe mode {mode:o} "
            f"(group/other bits set; expected 0600) — refusing "
            f"to open (3.1.16A-1: state root safety)"
        )


def open_state_db_safely(db_path: Path) -> Path:
    """Top-level safety gate for the state DB.

    For state-root paths (under ``~/.khaos/state/``): run the full
    directory chain check + file check.

    For non-state-root paths (only allowed when
    ``KHAOS_ALLOW_PROJECT_DB=1``): skip safety checks — tests take
    responsibility for their ``tmp_path`` databases.

    Returns the validated ``db_path`` (unchanged).  The caller can
    then construct ``Database(db_path)`` safely.
    """
    if is_project_db_allowed():
        return db_path
    # Determine if this is a state-root path.
    try:
        resolved = db_path.resolve()
        state_root_resolved = STATE_ROOT.resolve()
        resolved.relative_to(state_root_resolved)
    except (ValueError, OSError):
        raise StateRootError(
            f"state DB path {db_path} is not under the trusted "
            f"state root {STATE_ROOT}; refusing to open.  Either "
            f"omit --db to use the state root, or set "
            f"KHAOS_ALLOW_PROJECT_DB=1 for tests."
        )
    # Full safety checks for state-root paths.
    ensure_safe_state_dir(db_path.parent)
    ensure_safe_state_db_file(db_path)
    return db_path
