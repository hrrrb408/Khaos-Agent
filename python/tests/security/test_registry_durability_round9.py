"""Batch 9.5 (round-9 §十五): registry durability regressions.

The registry entry, stage-update rename and MAC key file are written via
``write → close → replace``.  Round-8 had no ``fsync`` of the file data or
the parent directory, so the crash-recovery claim only held for process
crashes (page cache survives), not host power loss (page cache is lost).

These tests verify every persistent registry write path now calls
``os.fsync`` on the file AND ``_fsync_dir`` on the parent directory.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from unittest.mock import patch

import pytest

pytestmark = pytest.mark.posix_host

from khaos.security import browser_sandbox as bs
from khaos.security.browser_sandbox import BrowserNetworkSandbox


def _make_sandbox(tmp_path: Path, monkeypatch) -> BrowserNetworkSandbox:
    """Return a sandbox wired to a tmp_path registry root."""
    reg_dir = tmp_path / "registry"
    monkeypatch.setattr(bs, "_RESOURCE_REGISTRY", reg_dir)
    sandbox = BrowserNetworkSandbox.__new__(BrowserNetworkSandbox)
    sandbox._token = "testtoken123456"
    sandbox._creation_stage = "INTENT"
    sandbox._registry_file = None
    sandbox._run_dir = tmp_path
    sandbox._require_os_sandbox = True
    return sandbox


def test_write_registry_entry_fsyncs_file_and_dir(tmp_path, monkeypatch) -> None:
    """_write_registry_entry must fsync the file + parent directory."""
    sandbox = _make_sandbox(tmp_path, monkeypatch)
    fsync_calls: list[int] = []  # fds passed to os.fsync
    dir_fds: list[str] = []  # paths opened by _fsync_dir

    real_fsync = os.fsync
    real_open = os.open

    def tracking_fsync(fd: int) -> None:
        fsync_calls.append(fd)
        real_fsync(fd)

    def tracking_fsync_dir(path) -> None:
        dir_fds.append(str(path))
        # Actually perform the fsync so the test is realistic.
        flags = os.O_RDONLY
        if hasattr(os, "O_DIRECTORY"):
            flags |= os.O_DIRECTORY
        try:
            d = real_open(str(path), flags)
            try:
                real_fsync(d)
            finally:
                os.close(d)
        except OSError:
            pass

    monkeypatch.setattr(os, "fsync", tracking_fsync)
    monkeypatch.setattr(bs, "_fsync_dir", tracking_fsync_dir)

    sandbox._write_registry_entry()

    # File fsync happened.
    assert len(fsync_calls) >= 1, "registry entry file was not fsynced"
    # Parent directory fsync happened.
    assert any("registry" in p for p in dir_fds), (
        "registry parent directory was not fsynced"
    )
    # The entry actually landed.
    reg_file = bs._RESOURCE_REGISTRY / f"{sandbox._token}.json"
    assert reg_file.exists()
    entry = json.loads(reg_file.read_text())
    assert entry["token"] == sandbox._token
    assert entry["creation_stage"] == "INTENT"


def test_update_registry_stage_fsyncs_file_and_dir(tmp_path, monkeypatch) -> None:
    """_update_registry_stage must fsync the temp file + parent dir after rename."""
    sandbox = _make_sandbox(tmp_path, monkeypatch)
    # First write the initial entry so _registry_file is set.
    sandbox._write_registry_entry()
    assert sandbox._registry_file is not None

    fsync_calls: list[int] = []
    dir_fds: list[str] = []
    real_fsync = os.fsync
    real_open = os.open

    def tracking_fsync(fd: int) -> None:
        fsync_calls.append(fd)
        real_fsync(fd)

    def tracking_fsync_dir(path) -> None:
        dir_fds.append(str(path))
        flags = os.O_RDONLY
        if hasattr(os, "O_DIRECTORY"):
            flags |= os.O_DIRECTORY
        try:
            d = real_open(str(path), flags)
            try:
                real_fsync(d)
            finally:
                os.close(d)
        except OSError:
            pass

    monkeypatch.setattr(os, "fsync", tracking_fsync)
    monkeypatch.setattr(bs, "_fsync_dir", tracking_fsync_dir)

    sandbox._update_registry_stage("NETNS")

    assert len(fsync_calls) >= 1, "stage-update temp file was not fsynced"
    assert any("registry" in p for p in dir_fds), (
        "stage-update parent directory was not fsynced after rename"
    )
    entry = json.loads(sandbox._registry_file.read_text())
    assert entry["creation_stage"] == "NETNS"


def test_registry_key_create_fsyncs_dir(tmp_path, monkeypatch) -> None:
    """_registry_key(create=True) must fsync the parent dir after creating the key."""
    key_dir = tmp_path / "runroot"
    monkeypatch.setattr(bs, "_RESOURCE_REGISTRY", key_dir / "browser_registry")
    dir_fds: list[str] = []
    real_fsync = os.fsync
    real_open = os.open

    def tracking_fsync_dir(path) -> None:
        dir_fds.append(str(path))
        flags = os.O_RDONLY
        if hasattr(os, "O_DIRECTORY"):
            flags |= os.O_DIRECTORY
        try:
            d = real_open(str(path), flags)
            try:
                real_fsync(d)
            finally:
                os.close(d)
        except OSError:
            pass

    monkeypatch.setattr(bs, "_fsync_dir", tracking_fsync_dir)

    bs._registry_key(create=True)

    # The parent of browser-registry.key is the runroot (the .parent of
    # _RESOURCE_REGISTRY which is browser_registry's parent).
    assert any(str(key_dir) in p or "runroot" in p for p in dir_fds), (
        f"registry key parent dir was not fsynced; saw {dir_fds}"
    )


def test_fsync_dir_is_safe_on_nonexistent(tmp_path) -> None:
    """_fsync_dir must not raise on a nonexistent or unreadable directory."""
    # Should not raise.
    bs._fsync_dir(tmp_path / "does-not-exist")
    bs._fsync_dir(tmp_path)  # real dir — should also not raise.
