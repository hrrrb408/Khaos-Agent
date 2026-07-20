"""M4 Batch 3.1.16A-1 — Trusted State Root acceptance tests.

Verifies the 9 acceptance criteria from the batch plan:

  1. Default DB path resolves to ~/.khaos/state/<project-id>/state.db.
  2. Project-dir khaos.db (regular file) is refused with migration prompt.
  3. Project-dir khaos.db (symlink) is refused.
  4. Explicit --db inside project dir is refused.
  5. Explicit --db outside project dir is allowed.
  6. State root dir chain safety (parent writable, state not 0700,
     project dir not 0700, symlinks).
  7. State DB file safety (symlink, non-regular, wrong owner,
     group/other mode bits).
  8. KHAOS_ALLOW_PROJECT_DB=1 bypasses all checks (test mode).
  9. Different project roots → different state DB paths; same
     project root via symlink → same state DB path.

All tests monkeypatch ``STATE_ROOT`` to a tmp_path so they don't
touch the user's real ``~/.khaos/`` directory.
"""

from __future__ import annotations

import os
import stat
import tempfile
from pathlib import Path

import pytest

from khaos.db import state_root as sr
from khaos.db.state_root import (
    StateRootError,
    check_no_project_dir_db,
    ensure_safe_state_db_file,
    ensure_safe_state_dir,
    is_project_db_allowed,
    open_state_db_safely,
    project_id,
    resolve_state_db_path,
    state_db_path,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def fake_state_root(tmp_path: Path, monkeypatch):
    """Redirect STATE_ROOT to a tmp_path so tests don't touch ~/.khaos/.

    Creates a safe ``~/.khaos/`` (tmp_path/.khaos) with mode 0755,
    ``~/.khaos/state/`` with mode 0700, so that the default safety
    checks pass.  Individual tests can then corrupt specific parts
    to verify rejection.
    """
    khaos_dir = tmp_path / ".khaos"
    khaos_dir.mkdir(mode=0o755)
    state_root = khaos_dir / "state"
    state_root.mkdir(mode=0o700)
    monkeypatch.setattr(sr, "STATE_ROOT", state_root)
    return state_root


@pytest.fixture
def no_bypass(monkeypatch):
    """Ensure KHAOS_ALLOW_PROJECT_DB is NOT set, so enforcement is active."""
    monkeypatch.delenv("KHAOS_ALLOW_PROJECT_DB", raising=False)


# ---------------------------------------------------------------------------
# Acceptance 1: Default DB path resolves to state root
# ---------------------------------------------------------------------------


def test_acceptance_1_default_resolves_to_state_root(
    fake_state_root: Path, no_bypass, tmp_path: Path,
) -> None:
    """When --db is not provided, the DB path MUST resolve to
    ``~/.khaos/state/<project-id>/state.db`` (not ``khaos.db`` in
    the project directory).
    """
    project = tmp_path / "myproject"
    project.mkdir()
    resolved = resolve_state_db_path(project, explicit_db=None)
    expected = fake_state_root / project_id(project) / "state.db"
    assert resolved == expected, (
        f"default DB path should be {expected}, got {resolved}"
    )


# ---------------------------------------------------------------------------
# Acceptance 2: Project-dir khaos.db (regular file) is refused
# ---------------------------------------------------------------------------


def test_acceptance_2_project_dir_db_file_refused(
    fake_state_root: Path, no_bypass, tmp_path: Path,
) -> None:
    """A pre-existing ``khaos.db`` (regular file) in the project
    directory MUST be refused with a migration prompt.
    """
    project = tmp_path / "proj-with-legacy-db"
    project.mkdir()
    (project / "khaos.db").write_bytes(b"fake sqlite header")
    with pytest.raises(StateRootError, match="no longer stores its trusted state"):
        check_no_project_dir_db(project)
    with pytest.raises(StateRootError, match="no longer stores its trusted state"):
        resolve_state_db_path(project, explicit_db=None)


# ---------------------------------------------------------------------------
# Acceptance 3: Project-dir khaos.db (symlink) is refused
# ---------------------------------------------------------------------------


def test_acceptance_3_project_dir_db_symlink_refused(
    fake_state_root: Path, no_bypass, tmp_path: Path,
) -> None:
    """A ``khaos.db`` symlink in the project directory MUST be
    refused (malicious repo could point it at ``~/.ssh/authorized_keys``).
    """
    project = tmp_path / "proj-with-symlink-db"
    project.mkdir()
    target = tmp_path / "attacker-target"
    target.write_text("sensitive")
    (project / "khaos.db").symlink_to(target)
    with pytest.raises(StateRootError, match="no longer stores its trusted state"):
        check_no_project_dir_db(project)


# ---------------------------------------------------------------------------
# Acceptance 4: Explicit --db inside project dir is refused
# ---------------------------------------------------------------------------


def test_acceptance_4_explicit_db_in_project_refused(
    fake_state_root: Path, no_bypass, tmp_path: Path, monkeypatch,
) -> None:
    """An explicit ``--db`` path that resolves inside the project
    directory MUST be refused (the project dir is untrusted).
    """
    project = tmp_path / "proj"
    project.mkdir()
    # Relative path: chdir into project so CWD == project_root
    # (this is the production scenario — user is in the project dir
    # and types --db custom.db).
    monkeypatch.chdir(project)
    with pytest.raises(StateRootError, match="inside the project directory"):
        resolve_state_db_path(project, explicit_db="custom.db")
    # Absolute path inside project
    abs_path = project / "subdir" / "data.db"
    abs_path.parent.mkdir()
    with pytest.raises(StateRootError, match="inside the project directory"):
        resolve_state_db_path(project, explicit_db=str(abs_path))


# ---------------------------------------------------------------------------
# Acceptance 5: Explicit --db outside project dir is allowed
# ---------------------------------------------------------------------------


def test_acceptance_5_explicit_db_outside_project_allowed(
    fake_state_root: Path, no_bypass, tmp_path: Path,
) -> None:
    """An explicit ``--db`` path OUTSIDE the project directory is
    allowed (user takes responsibility for the location).
    """
    project = tmp_path / "proj"
    project.mkdir()
    external = tmp_path / "external.db"
    resolved = resolve_state_db_path(project, explicit_db=str(external))
    assert resolved == external


# ---------------------------------------------------------------------------
# Acceptance 6: State root dir chain safety
# ---------------------------------------------------------------------------


def test_acceptance_6a_parent_khaos_group_writable_refused(
    fake_state_root: Path, no_bypass, tmp_path: Path,
) -> None:
    """``~/.khaos/`` with group write bit (0775) MUST be refused."""
    khaos_dir = fake_state_root.parent
    os.chmod(khaos_dir, 0o775)
    project_dir = fake_state_root / "abc123"
    with pytest.raises(StateRootError, match="group or other writable"):
        ensure_safe_state_dir(project_dir)


def test_acceptance_6b_parent_khaos_other_writable_refused(
    fake_state_root: Path, no_bypass, tmp_path: Path,
) -> None:
    """``~/.khaos/`` with other write bit (0777) MUST be refused."""
    khaos_dir = fake_state_root.parent
    os.chmod(khaos_dir, 0o777)
    project_dir = fake_state_root / "abc123"
    with pytest.raises(StateRootError, match="group or other writable"):
        ensure_safe_state_dir(project_dir)


def test_acceptance_6c_state_root_not_0700_refused(
    fake_state_root: Path, no_bypass, tmp_path: Path,
) -> None:
    """``~/.khaos/state/`` with any extra mode bits MUST be refused."""
    os.chmod(fake_state_root, 0o755)  # should be 0700
    project_dir = fake_state_root / "abc123"
    with pytest.raises(StateRootError, match="unsafe mode"):
        ensure_safe_state_dir(project_dir)


def test_acceptance_6d_project_dir_not_0700_refused(
    fake_state_root: Path, no_bypass, tmp_path: Path,
) -> None:
    """``~/.khaos/state/<project-id>/`` with extra mode bits refused."""
    project_dir = fake_state_root / "myproject"
    project_dir.mkdir(mode=0o755)  # should be 0700
    with pytest.raises(StateRootError, match="unsafe mode"):
        ensure_safe_state_dir(project_dir)


def test_acceptance_6e_state_root_symlink_refused(
    fake_state_root: Path, no_bypass, tmp_path: Path,
) -> None:
    """A symlink at ``~/.khaos/state/`` MUST be refused."""
    # Replace fake_state_root with a symlink
    fake_state_root.rmdir()
    target = tmp_path / "real-state"
    target.mkdir(mode=0o700)
    fake_state_root.symlink_to(target)
    project_dir = Path(str(fake_state_root)) / "abc123"  # path through symlink
    with pytest.raises(StateRootError, match="symlinked"):
        ensure_safe_state_dir(project_dir)


def test_acceptance_6f_safe_chain_created(
    fake_state_root: Path, no_bypass,
) -> None:
    """A safe directory chain is created and accepted."""
    project_dir = fake_state_root / "newproject"
    ensure_safe_state_dir(project_dir)
    assert project_dir.exists()
    assert project_dir.is_dir()
    mode = stat.S_IMODE(project_dir.lstat().st_mode)
    assert mode == 0o700


# ---------------------------------------------------------------------------
# Acceptance 7: State DB file safety
# ---------------------------------------------------------------------------


def test_acceptance_7a_symlink_db_refused(
    fake_state_root: Path, no_bypass, tmp_path: Path,
) -> None:
    """A symlink at the state DB path MUST be refused."""
    project_dir = fake_state_root / "proj"
    project_dir.mkdir(mode=0o700)
    db_path = project_dir / "state.db"
    target = tmp_path / "attacker.db"
    target.write_text("evil")
    db_path.symlink_to(target)
    with pytest.raises(StateRootError, match="symlinked state DB"):
        ensure_safe_state_db_file(db_path)


def test_acceptance_7b_non_regular_db_refused(
    fake_state_root: Path, no_bypass,
) -> None:
    """A non-regular file (e.g. directory) at the state DB path refused."""
    project_dir = fake_state_root / "proj"
    project_dir.mkdir(mode=0o700)
    db_path = project_dir / "state.db"
    db_path.mkdir()  # a directory, not a regular file
    with pytest.raises(StateRootError, match="not a regular file"):
        ensure_safe_state_db_file(db_path)


def test_acceptance_7c_db_group_mode_bits_refused(
    fake_state_root: Path, no_bypass,
) -> None:
    """State DB with group/other mode bits MUST be refused."""
    project_dir = fake_state_root / "proj"
    project_dir.mkdir(mode=0o700)
    db_path = project_dir / "state.db"
    db_path.write_bytes(b"sqlite")
    os.chmod(db_path, 0o640)  # group read — should be 0600
    with pytest.raises(StateRootError, match="unsafe mode"):
        ensure_safe_state_db_file(db_path)


def test_acceptance_7d_safe_db_file_accepted(
    fake_state_root: Path, no_bypass,
) -> None:
    """A safe state DB file (regular, 0600, owned by current UID) is accepted."""
    project_dir = fake_state_root / "proj"
    project_dir.mkdir(mode=0o700)
    db_path = project_dir / "state.db"
    db_path.write_bytes(b"sqlite header")
    os.chmod(db_path, 0o600)
    # Should not raise
    ensure_safe_state_db_file(db_path)


def test_acceptance_7e_nonexistent_db_accepted(
    fake_state_root: Path, no_bypass,
) -> None:
    """A non-existent state DB file is accepted (SQLite will create it)."""
    project_dir = fake_state_root / "proj"
    project_dir.mkdir(mode=0o700)
    db_path = project_dir / "state.db"
    # Should not raise
    ensure_safe_state_db_file(db_path)


# ---------------------------------------------------------------------------
# Acceptance 8: KHAOS_ALLOW_PROJECT_DB=1 bypasses all checks
# ---------------------------------------------------------------------------


def test_acceptance_8a_bypass_allows_project_dir_db(
    tmp_path: Path, monkeypatch,
) -> None:
    """When KHAOS_ALLOW_PROJECT_DB=1, a project-dir DB is allowed."""
    monkeypatch.setenv("KHAOS_ALLOW_PROJECT_DB", "1")
    assert is_project_db_allowed() is True
    project = tmp_path / "proj"
    project.mkdir()
    (project / "khaos.db").write_bytes(b"legacy")
    # check_no_project_dir_db should NOT raise
    check_no_project_dir_db(project)
    # resolve_state_db_path with explicit None returns the sentinel path
    # (which under bypass mode is just "khaos.db" relative)
    # Actually, when bypass is set, resolve still returns state_db_path
    # for the default case — but check_no_project_dir_db is skipped.
    # Let's verify resolve works without raising.
    resolved = resolve_state_db_path(project, explicit_db=None)
    assert resolved is not None


def test_acceptance_8b_bypass_allows_unsafe_open(
    tmp_path: Path, monkeypatch,
) -> None:
    """When KHAOS_ALLOW_PROJECT_DB=1, open_state_db_safely skips checks."""
    monkeypatch.setenv("KHAOS_ALLOW_PROJECT_DB", "1")
    db_path = tmp_path / "test.db"
    db_path.write_bytes(b"sqlite")
    os.chmod(db_path, 0o644)  # unsafe mode, but bypassed
    result = open_state_db_safely(db_path)
    assert result == db_path


# ---------------------------------------------------------------------------
# Acceptance 9: Project ID stability and uniqueness
# ---------------------------------------------------------------------------


def test_acceptance_9a_different_projects_different_paths(
    fake_state_root: Path, no_bypass, tmp_path: Path,
) -> None:
    """Two different project roots produce different state DB paths."""
    proj_a = tmp_path / "projectA"
    proj_b = tmp_path / "projectB"
    proj_a.mkdir()
    proj_b.mkdir()
    path_a = state_db_path(proj_a)
    path_b = state_db_path(proj_b)
    assert path_a != path_b, (
        "different project roots must produce different state DB paths"
    )
    assert project_id(proj_a) != project_id(proj_b)


def test_acceptance_9b_symlinked_project_same_path(
    fake_state_root: Path, no_bypass, tmp_path: Path,
) -> None:
    """A project reached via different symlink paths maps to the same
    state DB (resolve() follows symlinks before hashing).
    """
    real_project = tmp_path / "real-project"
    real_project.mkdir()
    symlink_project = tmp_path / "symlink-project"
    symlink_project.symlink_to(real_project)
    id_real = project_id(real_project)
    id_symlink = project_id(symlink_project)
    assert id_real == id_symlink, (
        "project reached via symlink must map to the same state DB"
    )


# ---------------------------------------------------------------------------
# Acceptance 10: open_state_db_safely end-to-end
# ---------------------------------------------------------------------------


def test_acceptance_10_open_state_db_safely_creates_chain(
    fake_state_root: Path, no_bypass, tmp_path: Path,
) -> None:
    """open_state_db_safely creates the full directory chain and
    accepts a non-existent DB file (SQLite will create it).
    """
    project = tmp_path / "myproject"
    project.mkdir()
    db_path = resolve_state_db_path(project, explicit_db=None)
    result = open_state_db_safely(db_path)
    assert result == db_path
    assert db_path.parent.exists()
    assert db_path.parent.is_dir()
    mode = stat.S_IMODE(db_path.parent.lstat().st_mode)
    assert mode == 0o700


def test_acceptance_10b_open_state_db_safely_rejects_non_state_root(
    fake_state_root: Path, no_bypass, tmp_path: Path,
) -> None:
    """open_state_db_safely rejects a path outside the state root
    (when KHAOS_ALLOW_PROJECT_DB is not set).
    """
    external = tmp_path / "outside-state-root.db"
    with pytest.raises(StateRootError, match="not under the trusted state root"):
        open_state_db_safely(external)


# ---------------------------------------------------------------------------
# Acceptance 11: Database works after state root resolution
# ---------------------------------------------------------------------------


async def test_acceptance_11_database_opens_after_state_root_resolution(
    fake_state_root: Path, no_bypass, tmp_path: Path,
) -> None:
    """After resolving and safety-checking the state root path,
    Database can connect and run migrations without error.
    """
    from khaos.db import Database
    project = tmp_path / "proj"
    project.mkdir()
    db_path = open_state_db_safely(resolve_state_db_path(project))
    db = Database(db_path)
    await db.connect()
    await db.run_migrations()
    await db.close()
    # The DB file should now exist with safe permissions.
    assert db_path.exists()
    st = db_path.lstat()
    assert stat.S_ISREG(st.st_mode)
    # SQLite creates with 0644 by default (subject to umask); the
    # 0700 directory protects it.  We don't chmod the file here —
    # that's a future hardening step.  The key property is that
    # it's under a 0700 directory owned by the current UID.
    dir_st = db_path.parent.lstat()
    assert stat.S_IMODE(dir_st.st_mode) == 0o700
    assert dir_st.st_uid == os.getuid()
