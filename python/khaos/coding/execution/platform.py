"""Platform sandbox capability probes and command builders."""

from __future__ import annotations

import shutil
import sys
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class BackendAvailability:
    name: str
    available: bool
    network_enforced: bool
    reason: str = ""


class UnsupportedBackend:
    name = "unsupported"

    async def probe(self) -> BackendAvailability:
        return BackendAvailability(self.name, False, False, "no supported sandbox backend")

    async def execute(self, request):
        raise PermissionError("workspace-write refused: no safe execution backend")

    async def terminate(self, execution_id: str) -> None:
        return None


class MacOSSandboxBackend:
    name = "macos-sandbox-exec"

    async def probe(self) -> BackendAvailability:
        available = sys.platform == "darwin" and shutil.which("sandbox-exec") is not None
        return BackendAvailability(self.name, available, available, "sandbox-exec unavailable" if not available else "")

    def profile(self, worktree: Path) -> str:
        escaped = str(worktree.resolve()).replace("\\", "\\\\").replace('"', '\\"')
        return f'(version 1)(deny default)(allow process*)(allow file-read*)(allow file-write* (subpath "{escaped}"))(allow file-write* (subpath "/tmp"))(deny network*)'


class LinuxBubblewrapBackend:
    name = "linux-bwrap"

    async def probe(self) -> BackendAvailability:
        available = sys.platform.startswith("linux") and shutil.which("bwrap") is not None
        return BackendAvailability(self.name, available, available, "bwrap unavailable" if not available else "")

    def argv_prefix(self, worktree: Path) -> tuple[str, ...]:
        return ("bwrap", "--ro-bind", "/", "/", "--bind", str(worktree.resolve()), str(worktree.resolve()), "--tmpfs", "/tmp", "--unshare-net", "--unshare-pid")
