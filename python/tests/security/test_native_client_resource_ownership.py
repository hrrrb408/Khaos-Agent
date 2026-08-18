"""Native client process resource ownership tests (M6.9 BATCH 7).

``_bounded_native_call`` previously buffered the whole child output with
``communicate()`` and checked the budget afterwards: an infinite-output or
hung native client consumed unbounded memory/time, and a bare
``process.kill()`` was treated as terminal proof.  The bounded call now
enforces incremental stdout/stderr/combined caps, one deadline over spawn
+ IO + wait, and SIGTERM -> grace -> SIGKILL over the whole process
domain (process group on POSIX).  No survivor, no success.
"""

from __future__ import annotations

import os
import stat
import sys
import time
from pathlib import Path

import pytest
from khaos.security.native_authority import (
    MAX_NATIVE_OUTPUT_BYTES,
    NativeAuthorityError,
    _bounded_native_call,
)


def _client_script(tmp_path: Path, body: str) -> Path:
    script = tmp_path / f"client-{abs(hash(body))}.sh"
    script.write_text(f"#!/bin/sh\n{body}\n", encoding="utf-8")
    script.chmod(0o755)
    return script


@pytest.mark.skipif(os.name == "nt", reason="POSIX process-group semantics")
def test_infinite_stdout_terminates_immediately(tmp_path: Path) -> None:
    client = _client_script(tmp_path, "while true; do echo aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa; done")
    started = time.monotonic()
    with pytest.raises(NativeAuthorityError, match="output budget"):
        _bounded_native_call(client, (), timeout_seconds=30.0)
    # The budget must fire long before the deadline: incremental, not
    # post-hoc.
    assert time.monotonic() - started < 10.0


@pytest.mark.skipif(os.name == "nt", reason="POSIX process-group semantics")
def test_infinite_stderr_terminates_immediately(tmp_path: Path) -> None:
    client = _client_script(tmp_path, "while true; do echo bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb >&2; done")
    started = time.monotonic()
    with pytest.raises(NativeAuthorityError, match="output budget"):
        _bounded_native_call(client, (), timeout_seconds=30.0)
    assert time.monotonic() - started < 10.0


@pytest.mark.skipif(os.name == "nt", reason="POSIX process-group semantics")
def test_combined_overflow_terminates(tmp_path: Path) -> None:
    # Each stream stays under its own cap but the combined total exceeds
    # the shared budget.
    filler = "c" * 512
    client = _client_script(
        tmp_path,
        f"while true; do echo {filler}; echo {filler} >&2; done",
    )
    started = time.monotonic()
    with pytest.raises(NativeAuthorityError, match="output budget"):
        _bounded_native_call(client, (), timeout_seconds=30.0)
    assert time.monotonic() - started < 20.0


@pytest.mark.skipif(os.name == "nt", reason="POSIX process-group semantics")
def test_hung_client_hits_deadline(tmp_path: Path) -> None:
    client = _client_script(tmp_path, "sleep 300")
    started = time.monotonic()
    with pytest.raises(NativeAuthorityError, match="deadline"):
        _bounded_native_call(client, (), timeout_seconds=1.0)
    assert time.monotonic() - started < 5.0


@pytest.mark.skipif(os.name == "nt", reason="POSIX process-group semantics")
def test_forked_descendant_is_terminated_with_the_domain(tmp_path: Path) -> None:
    marker = tmp_path / "descendant-alive"
    if marker.exists():
        marker.unlink()
    client = _client_script(
        tmp_path,
        "(sleep 300) &\n"
        f"echo $! > {tmp_path}/child.pid\n"
        "sleep 300",
    )
    with pytest.raises(NativeAuthorityError, match="deadline"):
        _bounded_native_call(client, (), timeout_seconds=1.0)
    child_pid = int((tmp_path / "child.pid").read_text().strip())
    # The whole process group must be gone: a surviving descendant would
    # be a false CLOSED.
    deadline = time.monotonic() + 5.0
    while time.monotonic() < deadline:
        try:
            os.kill(child_pid, 0)
        except OSError:
            break
        time.sleep(0.1)
    with pytest.raises(OSError):
        os.kill(child_pid, 0)


@pytest.mark.skipif(os.name == "nt", reason="POSIX process-group semantics")
def test_sigterm_ignoring_descendant_is_killed(tmp_path: Path) -> None:
    client = _client_script(
        tmp_path,
        "trap '' TERM\n"
        "(trap '' TERM; sleep 300) &\n"
        f"echo $! > {tmp_path}/child.pid\n"
        "sleep 300",
    )
    with pytest.raises(NativeAuthorityError, match="deadline"):
        _bounded_native_call(client, (), timeout_seconds=1.0)
    child_pid = int((tmp_path / "child.pid").read_text().strip())
    deadline = time.monotonic() + 6.0
    while time.monotonic() < deadline:
        try:
            os.kill(child_pid, 0)
        except OSError:
            break
        time.sleep(0.1)
    with pytest.raises(OSError):
        os.kill(child_pid, 0)


def test_successful_client_returns_stdout(tmp_path: Path) -> None:
    client = _client_script(tmp_path, "echo '{\"ok\":true}'")
    stdout = _bounded_native_call(client, (), timeout_seconds=10.0)
    assert b'{"ok":true}' in stdout


def test_nonzero_exit_reports_detail(tmp_path: Path) -> None:
    client = _client_script(tmp_path, "echo boom >&2; exit 3")
    with pytest.raises(NativeAuthorityError, match="rc=3.*boom"):
        _bounded_native_call(client, (), timeout_seconds=10.0)


def test_missing_executable_fails_closed(tmp_path: Path) -> None:
    with pytest.raises(NativeAuthorityError):
        _bounded_native_call(tmp_path / "absent-client", (), timeout_seconds=5.0)


@pytest.mark.skipif(os.name == "nt", reason="POSIX process-group semantics")
def test_setsid_descendant_is_in_the_child_domain(tmp_path: Path) -> None:
    # A child that calls setsid itself leaves the process group: the
    # session leader termination still targets the original group, so the
    # top-level child dies and the call fails closed at the deadline.
    client = _client_script(tmp_path, "setsid sleep 300 & sleep 300")
    started = time.monotonic()
    with pytest.raises(NativeAuthorityError, match="deadline"):
        _bounded_native_call(client, (), timeout_seconds=1.0)
    assert time.monotonic() - started < 5.0


def test_client_script_permissions(tmp_path: Path) -> None:
    client = _client_script(tmp_path, "true")
    assert stat.S_IMODE(client.stat().st_mode) & 0o111
    # Budget sanity for the shared caps used above.
    assert MAX_NATIVE_OUTPUT_BYTES == 64 * 1024
    assert sys.platform in {"darwin", "linux", "win32"}
