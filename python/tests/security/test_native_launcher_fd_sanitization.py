"""Native launcher authority-FD inheritance checks."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[3]


def test_rust_launcher_has_stdio_only_fd_policy() -> None:
    source = (
        ROOT / "rust/khaos-core/src/bin/khaos-exec-launcher.rs"
    ).read_text(encoding="utf-8")

    assert "close_authority_fds(options.root_fd, options.cwd_fd)" in source
    assert "SYS_close_range" in source
    assert "for fd in 3..maximum" in source
    assert "explicit whitelist of 0/1/2" in source


@pytest.mark.skipif(
    not Path("/proc/self/fd").is_dir(),
    reason="child FD inspection requires /proc/self/fd",
)
def test_python_development_launcher_closes_authority_fds(tmp_path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    cwd = root / "cwd"
    cwd.mkdir()
    root_fd = os.open(root, os.O_RDONLY)
    cwd_fd = os.open(cwd, os.O_RDONLY)
    extra_fd = os.open(root / "extra", os.O_CREAT | os.O_RDWR, 0o600)
    try:
        root_stat = os.fstat(root_fd)
        cwd_stat = os.fstat(cwd_fd)
        command = [
            sys.executable,
            "-m",
            "khaos.coding.execution.native_launcher_runtime",
            "--root-fd",
            str(root_fd),
            "--root-device",
            str(root_stat.st_dev),
            "--root-inode",
            str(root_stat.st_ino),
            "--cwd-fd",
            str(cwd_fd),
            "--cwd-device",
            str(cwd_stat.st_dev),
            "--cwd-inode",
            str(cwd_stat.st_ino),
            "--",
            sys.executable,
            "-c",
            "import json, os; print(json.dumps(sorted(int(x) for x in os.listdir('/proc/self/fd') if x.isdigit())))",
        ]
        completed = subprocess.run(
            command,
            pass_fds=(root_fd, cwd_fd, extra_fd),
            capture_output=True,
            text=True,
            check=False,
            env={**os.environ, "PYTHONPATH": str(ROOT / "python")},
        )
    finally:
        for fd in (root_fd, cwd_fd, extra_fd):
            try:
                os.close(fd)
            except OSError:
                pass

    if completed.returncode != 0 and sys.platform == "win32":
        pytest.skip("the explicit development launcher is POSIX-only")
    assert completed.returncode == 0, completed.stderr
    inherited = json.loads(completed.stdout.strip())
    assert all(fd <= 2 for fd in inherited)


@pytest.mark.skipif(
    sys.platform != "linux", reason="the Rust integration check inspects /proc"
)
def test_rust_launcher_closes_authority_fds_when_binary_is_provided(tmp_path) -> None:
    launcher = os.environ.get("KHAOS_EXEC_LAUNCHER_FD_TEST", "")
    if not launcher or not Path(launcher).is_file():
        pytest.skip("set KHAOS_EXEC_LAUNCHER_FD_TEST to a built Rust launcher")

    root = tmp_path / "root"
    root.mkdir()
    cwd = root / "cwd"
    cwd.mkdir()
    root_fd = os.open(root, os.O_RDONLY)
    cwd_fd = os.open(cwd, os.O_RDONLY)
    extra_fd = os.open(root / "extra", os.O_CREAT | os.O_RDWR, 0o600)
    try:
        root_stat = os.fstat(root_fd)
        cwd_stat = os.fstat(cwd_fd)
        completed = subprocess.run(
            [
                launcher,
                "--root-fd",
                str(root_fd),
                "--root-device",
                str(root_stat.st_dev),
                "--root-inode",
                str(root_stat.st_ino),
                "--cwd-fd",
                str(cwd_fd),
                "--cwd-device",
                str(cwd_stat.st_dev),
                "--cwd-inode",
                str(cwd_stat.st_ino),
                "--",
                sys.executable,
                "-c",
                "import json, os; print(json.dumps(sorted(int(x) for x in os.listdir('/proc/self/fd') if x.isdigit())))",
            ],
            pass_fds=(root_fd, cwd_fd, extra_fd),
            capture_output=True,
            text=True,
            check=False,
        )
    finally:
        for fd in (root_fd, cwd_fd, extra_fd):
            try:
                os.close(fd)
            except OSError:
                pass

    assert completed.returncode == 0, completed.stderr
    inherited = json.loads(completed.stdout.strip())
    assert all(fd <= 2 for fd in inherited)
