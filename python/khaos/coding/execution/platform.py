"""Platform sandbox capability probes and command builders."""

from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
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
        raise PermissionError("workspace-write refused: no safe execution backend (infrastructure unsupported)")

    async def terminate(self, execution_id: str) -> None:
        return None


class BackendSelector:
    """Select a platform backend; writable execution never falls back to host."""

    def select(self, *, writable: bool):
        if sys.platform == "darwin":
            backend = MacOSSandboxBackend()
            if shutil.which("sandbox-exec"):
                return backend
        elif sys.platform.startswith("linux"):
            backend = LinuxBubblewrapBackend()
            availability = backend.probe_capability()
            if availability.available and availability.network_enforced:
                return backend
            # bwrap present but cannot enforce isolation (e.g. GitHub-hosted
            # runner blocks network namespace creation).  Writable execution
            # must fail closed as infrastructure-unsupported, never degrade to
            # a plain host subprocess.
            if writable:
                return UnsupportedBackend()
        if writable:
            return UnsupportedBackend()
        from khaos.coding.execution.host import HostExecutionBackend

        return HostExecutionBackend()


class MacOSSandboxBackend:
    name = "macos-sandbox-exec"

    async def probe(self) -> BackendAvailability:
        available = sys.platform == "darwin" and shutil.which("sandbox-exec") is not None
        return BackendAvailability(self.name, available, available, "sandbox-exec unavailable" if not available else "")

    def profile(self, worktree: Path) -> str:
        escaped = str(worktree.resolve()).replace("\\", "\\\\").replace('"', '\\"')
        return f'(version 1)(deny default)(allow process*)(allow file-read*)(allow file-write* (subpath "{escaped}"))(allow file-write* (subpath "/tmp"))(deny network*)'

    async def execute(self, request):
        from khaos.coding.execution.host import HostExecutionBackend
        from dataclasses import replace
        worktree = request.writable_roots[0] if request.writable_roots else request.cwd
        return await HostExecutionBackend().execute(replace(request, argv=("sandbox-exec", "-p", self.profile(worktree), *request.argv)))

    async def terminate(self, execution_id: str) -> None:
        return None


class LinuxBubblewrapBackend:
    name = "linux-bwrap"
    _capability_cache: "BackendAvailability | None" = None

    async def probe(self) -> BackendAvailability:
        return self.probe_capability()

    def probe_capability(self) -> BackendAvailability:
        """Actually execute bwrap to verify --unshare-net/--unshare-pid work.

        A ``shutil.which`` check is not sufficient: some platforms (notably
        GitHub-hosted ubuntu-latest) ship bwrap but block the network
        namespace creation with EPERM on RTM_NEWADDR.  This probe runs the
        real sandbox and reports the platform limitation so the
        BackendSelector can fail closed as infrastructure-unsupported instead
        of degrading to a plain host subprocess.
        """
        if not sys.platform.startswith("linux") or shutil.which("bwrap") is None:
            return BackendAvailability(self.name, False, False, "bwrap unavailable on this platform")
        if LinuxBubblewrapBackend._capability_cache is not None:
            return LinuxBubblewrapBackend._capability_cache
        with tempfile.TemporaryDirectory() as tmp:
            completed = subprocess.run(
                ("bwrap", "--ro-bind", "/", "/", "--bind", tmp, tmp,
                 "--tmpfs", "/tmp", "--unshare-net", "--unshare-pid",
                 "--", "/bin/true"),
                capture_output=True, timeout=10,
            )
        if completed.returncode == 0:
            availability = BackendAvailability(self.name, True, True)
        else:
            stderr = completed.stderr.decode("utf-8", errors="replace").strip()
            availability = BackendAvailability(
                self.name, False, False,
                f"bwrap isolation probe failed (rc={completed.returncode}): {stderr}",
            )
        LinuxBubblewrapBackend._capability_cache = availability
        return availability

    def argv_prefix(self, worktree: Path) -> tuple[str, ...]:
        return ("bwrap", "--ro-bind", "/", "/", "--bind", str(worktree.resolve()), str(worktree.resolve()), "--tmpfs", "/tmp", "--unshare-net", "--unshare-pid")

    async def execute(self, request):
        from khaos.coding.execution.host import HostExecutionBackend
        from dataclasses import replace
        worktree = request.writable_roots[0] if request.writable_roots else request.cwd
        return await HostExecutionBackend().execute(replace(request, argv=(*self.argv_prefix(worktree), *request.argv)))

    async def terminate(self, execution_id: str) -> None:
        return None
