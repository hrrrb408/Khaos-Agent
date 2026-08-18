"""M5.5 Batch A — approval evidence is bounded, race-safe, and complete.

Covers the two Git-evidence security theorems:

* Approval Evidence Is Bounded TCB Input: untracked-content hashing has
  per-file / total / count / wall-clock budgets and rejects oversized
  files before reading a single byte.
* Security Evidence Must Prove Completeness: truncated supervisor output
  can never be accepted as approval evidence.

Race determinism: swap-in attacks (regular → symlink / FIFO / socket /
vanished path / structural escape) are verified through their final
filesystem state, because the snapshotter opens each entry with
``O_NOFOLLOW`` on every component and ``fstat``s the same descriptor it
reads — the validated and read kernel objects are identical by
construction, so the only observable is "the attack state fails closed".
"""

from __future__ import annotations

import os
import shutil
import socket
import stat
import tempfile
from pathlib import Path

import pytest

from khaos.security.git_evidence import (
    EvidenceSnapshotBudgets,
    GitEvidenceError,
    require_complete_git_output,
    snapshot_untracked_files,
)

pytestmark = pytest.mark.posix_host


def _budgets(**overrides: object) -> EvidenceSnapshotBudgets:
    defaults: dict[str, object] = {
        "max_file_bytes": 64 * 1024,
        "max_total_bytes": 128 * 1024,
        "max_file_count": 8,
        "max_wall_clock_seconds": 5.0,
    }
    defaults.update(overrides)
    return EvidenceSnapshotBudgets(**defaults)  # type: ignore[arg-type]


# ─── Completeness gate ────────────────────────────────────────────────────


def test_complete_output_passes_the_gate():
    require_complete_git_output(
        {"stdout": "ok", "diagnostics": {"output_truncated": False}},
        source="git status",
    )


def test_truncated_output_fails_closed():
    result = {"stdout": "partial", "diagnostics": {"output_truncated": True}}
    with pytest.raises(GitEvidenceError, match="must be complete"):
        require_complete_git_output(result, source="git status")


@pytest.mark.parametrize("key", ["stdout_truncated", "stderr_truncated"])
def test_stream_level_truncation_flags_also_fail_closed(key):
    result = {"stdout": "partial", "diagnostics": {key: True}}
    with pytest.raises(GitEvidenceError, match="must be complete"):
        require_complete_git_output(result, source="git diff")


def test_result_without_diagnostics_fails_closed():
    with pytest.raises(GitEvidenceError, match="diagnostics are missing"):
        require_complete_git_output({"stdout": "ok"}, source="git status")


def test_result_with_empty_diagnostics_fails_closed():
    # Completeness must be positively proven: an empty diagnostics mapping
    # carries no truncation bits, so it is malformed evidence, not proof.
    with pytest.raises(GitEvidenceError, match="diagnostics are malformed"):
        require_complete_git_output(
            {"stdout": "ok", "diagnostics": {}}, source="git status"
        )


# ─── Bounded snapshot: happy path and determinism ─────────────────────────


def test_snapshot_hashes_regular_files_deterministically(tmp_path: Path):
    (tmp_path / "a.txt").write_bytes(b"alpha")
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "b.txt").write_bytes(b"beta")

    first = snapshot_untracked_files(
        tmp_path, ["a.txt", "sub/b.txt"], budgets=_budgets()
    )
    second = snapshot_untracked_files(
        tmp_path, ["a.txt", "sub/b.txt"], budgets=_budgets()
    )

    assert first == second
    assert len(first) == 64


def test_snapshot_binding_includes_the_path(tmp_path: Path):
    (tmp_path / "one").write_bytes(b"same")
    (tmp_path / "two").write_bytes(b"same")

    one = snapshot_untracked_files(tmp_path, ["one"], budgets=_budgets())
    two = snapshot_untracked_files(tmp_path, ["two"], budgets=_budgets())

    assert one != two


def test_snapshot_frames_paths_so_concatenation_cannot_alias(tmp_path: Path):
    # "ab" as one file must not produce the same manifest as "a" + "b",
    # even though the raw byte streams are identical.
    (tmp_path / "ab").write_bytes(b"XY")
    (tmp_path / "a").write_bytes(b"X")
    (tmp_path / "b").write_bytes(b"Y")

    joined = snapshot_untracked_files(tmp_path, ["ab"], budgets=_budgets())
    split = snapshot_untracked_files(tmp_path, ["a", "b"], budgets=_budgets())

    assert joined != split


def test_snapshot_of_no_entries_is_stable(tmp_path: Path):
    first = snapshot_untracked_files(tmp_path, [], budgets=_budgets())
    second = snapshot_untracked_files(tmp_path, [], budgets=_budgets())
    assert first == second


# ─── Bounded snapshot: budget enforcement ─────────────────────────────────


def test_oversized_declared_file_fails_closed_before_any_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    huge = tmp_path / "huge.bin"
    # A sparse file: st_size is enormous, disk usage is not.
    with open(huge, "wb") as handle:
        handle.truncate(100 * 1024 * 1024 * 1024)
    assert huge.stat().st_size == 100 * 1024 * 1024 * 1024

    def _no_reads(*args: object, **kwargs: object):
        raise AssertionError("evidence snapshot read file bytes for an oversized file")

    monkeypatch.setattr(os, "read", _no_reads)

    with pytest.raises(GitEvidenceError, match="per-file evidence budget"):
        snapshot_untracked_files(tmp_path, ["huge.bin"], budgets=_budgets())


def test_per_file_growth_during_hash_fails_closed(tmp_path: Path):
    payload = tmp_path / "growing.bin"
    payload.write_bytes(b"x" * 1024)

    # A size that fits the budget at fstat time but where content appended
    # between chunks would cross the per-file bound.  We simulate the
    # mid-hash growth with a small budget instead of a real race.
    with pytest.raises(GitEvidenceError, match="per-file evidence budget"):
        snapshot_untracked_files(
            tmp_path,
            ["growing.bin"],
            budgets=_budgets(max_file_bytes=16),
        )


def test_total_byte_budget_fails_closed(tmp_path: Path):
    (tmp_path / "one").write_bytes(b"x" * (60 * 1024))
    (tmp_path / "two").write_bytes(b"y" * (60 * 1024))

    with pytest.raises(GitEvidenceError, match="total-byte budget"):
        snapshot_untracked_files(
            tmp_path, ["one", "two"], budgets=_budgets(max_total_bytes=64 * 1024)
        )


def test_file_count_budget_fails_closed(tmp_path: Path):
    for index in range(4):
        (tmp_path / f"f{index}").write_bytes(b"data")

    with pytest.raises(GitEvidenceError, match="file-count budget"):
        snapshot_untracked_files(
            tmp_path, ["f0", "f1", "f2", "f3"], budgets=_budgets(max_file_count=2)
        )


def test_wall_clock_budget_fails_closed(tmp_path: Path):
    (tmp_path / "slow").write_bytes(b"x" * 4096)

    # The open + fstat already cost more than this budget, so the first
    # chunk check must fail closed instead of hashing unbounded content.
    with pytest.raises(GitEvidenceError, match="wall-clock budget"):
        snapshot_untracked_files(
            tmp_path,
            ["slow"],
            budgets=_budgets(max_file_bytes=64 * 1024, max_wall_clock_seconds=1e-9),
        )


def test_invalid_budgets_are_rejected():
    with pytest.raises(GitEvidenceError, match="budgets"):
        EvidenceSnapshotBudgets(max_total_bytes=1, max_file_bytes=4096)


# ─── Race-safe open: replacement attacks fail closed ─────────────────────


def test_symlink_replacement_fails_closed(tmp_path: Path):
    target = tmp_path / "outside"
    target.write_bytes(b"secret")
    link = tmp_path / "entry"
    link.symlink_to(target)

    with pytest.raises(GitEvidenceError, match="could not be opened"):
        snapshot_untracked_files(tmp_path, ["entry"], budgets=_budgets())


def test_symlinked_directory_component_fails_closed(tmp_path: Path):
    (tmp_path / "real").mkdir()
    (tmp_path / "real" / "file.txt").write_bytes(b"data")
    (tmp_path / "link").symlink_to("real", target_is_directory=True)

    with pytest.raises(GitEvidenceError, match="could not be opened"):
        snapshot_untracked_files(tmp_path, ["link/file.txt"], budgets=_budgets())


def test_fifo_replacement_fails_closed_without_blocking(tmp_path: Path):
    fifo = tmp_path / "pipe"
    os.mkfifo(fifo)

    with pytest.raises(GitEvidenceError, match="not a regular file"):
        snapshot_untracked_files(tmp_path, ["pipe"], budgets=_budgets())


def test_socket_replacement_fails_closed(tmp_path: Path):
    # macOS caps AF_UNIX paths at ~104 bytes, far below pytest's tmp_path;
    # bind the socket in a short-lived directory instead.
    short_root = Path(tempfile.mkdtemp(prefix="kx-", dir="/tmp"))
    sock_path = short_root / "s"
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        server.bind(str(sock_path))
        assert stat.S_ISSOCK(sock_path.stat().st_mode)
        # POSIX ``open`` on a unix socket fails outright (ENXIO); either
        # failure shape — open rejection or non-regular fstat — is closed.
        with pytest.raises(GitEvidenceError):
            snapshot_untracked_files(short_root, ["s"], budgets=_budgets())
    finally:
        server.close()
        shutil.rmtree(short_root, ignore_errors=True)


def test_vanished_entry_fails_closed(tmp_path: Path):
    with pytest.raises(GitEvidenceError, match="could not be opened"):
        snapshot_untracked_files(tmp_path, ["vanished.txt"], budgets=_budgets())


def test_directory_entry_fails_closed(tmp_path: Path):
    (tmp_path / "adir").mkdir()

    with pytest.raises(GitEvidenceError, match="not a regular file"):
        snapshot_untracked_files(tmp_path, ["adir"], budgets=_budgets())


@pytest.mark.parametrize("entry", ["../escape", "/etc/passwd", "a/../b", "./here"])
def test_structural_path_escapes_fail_closed(tmp_path: Path, entry: str):
    with pytest.raises(GitEvidenceError):
        snapshot_untracked_files(tmp_path, [entry], budgets=_budgets())
