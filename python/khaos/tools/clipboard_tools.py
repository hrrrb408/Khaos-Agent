"""Clipboard tools for macOS/Linux."""

from __future__ import annotations

import asyncio
import logging
import subprocess
import sys
from typing import Any

logger = logging.getLogger(__name__)


async def clipboard_read() -> dict[str, Any]:
    """Read text from the system clipboard."""
    return await asyncio.to_thread(_clipboard_read_sync)


def _clipboard_read_sync() -> dict[str, Any]:
    commands = _read_commands()
    for command in commands:
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                check=True,
                text=True,
            )
        except (FileNotFoundError, subprocess.CalledProcessError) as exc:
            logger.debug("Clipboard read command failed: %s", exc)
            continue
        return {
            "ok": True,
            "content": result.stdout,
            "length": len(result.stdout),
        }
    return {"ok": False, "error": "Clipboard not accessible"}


async def clipboard_write(text: str) -> dict[str, Any]:
    """Write text to the system clipboard."""
    return await asyncio.to_thread(_clipboard_write_sync, text)


def _clipboard_write_sync(text: str) -> dict[str, Any]:
    commands = _write_commands()
    for command in commands:
        try:
            subprocess.run(
                command,
                input=text,
                capture_output=True,
                check=True,
                text=True,
            )
        except (FileNotFoundError, subprocess.CalledProcessError) as exc:
            logger.debug("Clipboard write command failed: %s", exc)
            continue
        return {"ok": True, "length": len(text)}
    return {"ok": False, "error": "Clipboard not accessible"}


def _read_commands() -> list[list[str]]:
    if sys.platform == "darwin":
        return [
            ["pbpaste"],
            ["xclip", "-selection", "clipboard", "-o"],
            ["xsel", "--clipboard", "--output"],
        ]
    return [
        ["xclip", "-selection", "clipboard", "-o"],
        ["xsel", "--clipboard", "--output"],
        ["pbpaste"],
    ]


def _write_commands() -> list[list[str]]:
    if sys.platform == "darwin":
        return [
            ["pbcopy"],
            ["xclip", "-selection", "clipboard", "-i"],
            ["xsel", "--clipboard", "--input"],
        ]
    return [
        ["xclip", "-selection", "clipboard", "-i"],
        ["xsel", "--clipboard", "--input"],
        ["pbcopy"],
    ]
