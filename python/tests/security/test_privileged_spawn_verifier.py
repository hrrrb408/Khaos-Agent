"""Adversarial syntax coverage for the privileged-spawn inventory verifier."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
SPEC = importlib.util.spec_from_file_location(
    "check_privileged_spawn_sites",
    ROOT / "scripts" / "check_privileged_spawn_sites.py",
)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


def test_python_import_aliases_and_os_spawn_primitives(tmp_path: Path) -> None:
    source = tmp_path / "aliases.py"
    source.write_text(
        """
import asyncio as aio
import os as operating_system
import subprocess as sp
import pty as terminal
from os import posix_spawn as spawn
from subprocess import Popen as Launch

async def run():
    await aio.create_subprocess_exec('x')
    sp.run(['x'])
    Launch(['x'])
    operating_system.system('x')
    spawn('x', ['x'], {})
    terminal.spawn('x')
""",
        encoding="utf-8",
    )

    sites = MODULE._python_sites(source)
    symbols = {symbol for _, symbol, _ in sites}
    assert {
        "asyncio.create_subprocess_exec",
        "subprocess.run",
        "subprocess.Popen",
        "os.system",
        "os.posix_spawn",
        "pty.spawn",
    } <= symbols


def test_go_package_aliases_and_comments_are_scanned(tmp_path: Path) -> None:
    source = tmp_path / "aliases.go"
    source.write_text(
        r'''
package main

import (
    command "os/exec"
    operatingSystem "os"
    "syscall"
)

func run() {
    // command.Command("comment") must not count.
    _ = "operatingSystem.StartProcess('string')"
    command.CommandContext(nil, "x")
    operatingSystem.StartProcess("x", nil, nil)
    syscall.Exec("x", nil, nil)
}
''',
        encoding="utf-8",
    )

    sites = MODULE._go_sites(source)
    symbols = {symbol for _, symbol, _ in sites}
    assert {"exec.CommandContext", "os.StartProcess", "syscall.Exec"} <= symbols


def test_rust_command_alias_is_scanned(tmp_path: Path) -> None:
    source = tmp_path / "aliases.rs"
    source.write_text(
        """
use std::process::Command as SpawnCommand;

fn run() {
    let _child = SpawnCommand::new("x");
}
""",
        encoding="utf-8",
    )

    sites = MODULE._rust_sites(source)
    assert any(symbol == "SpawnCommand::new" for _, symbol, _ in sites)
