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

    def __init__(
        self, reason: str = "no supported sandbox backend"
    ) -> None:
        self.reason = reason

    async def probe(self) -> BackendAvailability:
        return BackendAvailability(self.name, False, False, self.reason)

    async def execute(self, request):
        raise PermissionError(
            "execution refused: no safe execution backend "
            f"(infrastructure unsupported: {self.reason})"
        )

    async def terminate(self, execution_id: str) -> None:
        return None


class BackendSelector:
    """Select an OS-enforced backend; Agent execution never falls back to host."""

    def __init__(self, supervisor=None) -> None:
        self.supervisor = supervisor

    def set_supervisor(self, supervisor) -> None:
        self.supervisor = supervisor

    def select(self, *, writable: bool):
        if sys.platform == "darwin":
            backend = MacOSSandboxBackend(self.supervisor)
            try:
                availability = backend.probe_capability()
            except Exception:
                availability = BackendAvailability(
                    backend.name,
                    False,
                    False,
                    "sandbox-exec capability probe raised an exception",
                )
            if availability.available and availability.network_enforced:
                return backend
        elif sys.platform.startswith("linux"):
            backend = LinuxBubblewrapBackend(self.supervisor)
            try:
                availability = backend.probe_capability()
            except Exception as exc:
                availability = BackendAvailability(
                    backend.name,
                    False,
                    False,
                    f"bwrap isolation probe raised {type(exc).__name__}: {exc}",
                )
            if availability.available and availability.network_enforced:
                return backend
            # bwrap present but cannot enforce isolation (e.g. GitHub-hosted
            # runner blocks network namespace creation).  Writable execution
            # must fail closed as infrastructure-unsupported, never degrade to
            # a plain host subprocess.
            if writable:
                return UnsupportedBackend()
        if sys.platform.startswith("win"):
            return UnsupportedBackend(
                "Windows sandbox backend is not implemented; Host fallback is forbidden"
            )
        return UnsupportedBackend()


class MacOSSandboxBackend:
    name = "macos-sandbox-exec"
    _capability_cache: "BackendAvailability | None" = None

    def __init__(self, supervisor=None) -> None:
        self.supervisor = supervisor

    async def probe(self) -> BackendAvailability:
        return self.probe_capability()

    def probe_capability(self) -> BackendAvailability:
        """Execute Seatbelt and prove write and network denial before use."""
        if (
            sys.platform != "darwin"
            or shutil.which("sandbox-exec") is None
        ):
            return BackendAvailability(
                self.name, False, False, "sandbox-exec unavailable"
            )
        if MacOSSandboxBackend._capability_cache is not None:
            return MacOSSandboxBackend._capability_cache
        try:
            with tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                workspace = root / "workspace"
                outside = root / "outside.txt"
                workspace.mkdir()
                script = "\n".join(
                    (
                        "from pathlib import Path",
                        "import socket",
                        "Path('inside.txt').write_text('ok')",
                        f"try: Path({str(outside)!r}).write_text('denied')",
                        "except OSError: pass",
                        "else: raise SystemExit('outside write allowed')",
                        "try: socket.create_connection(('1.1.1.1', 53), timeout=0.2)",
                        "except OSError: pass",
                        "else: raise SystemExit('network allowed')",
                    )
                )
                completed = subprocess.run(
                    (
                        "/usr/bin/sandbox-exec",
                        "-p",
                        self.profile(workspace),
                        sys.executable,
                        "-c",
                        script,
                    ),
                    cwd=workspace,
                    capture_output=True,
                    timeout=5,
                )
                passed = (
                    completed.returncode == 0
                    and (workspace / "inside.txt").is_file()
                    and not outside.exists()
                )
                stderr = completed.stderr.decode(
                    "utf-8", errors="replace"
                ).strip()[:500]
        except (OSError, subprocess.SubprocessError) as exc:
            availability = BackendAvailability(
                self.name,
                False,
                False,
                f"sandbox-exec probe could not run: {type(exc).__name__}: {exc}",
            )
        else:
            availability = BackendAvailability(
                self.name,
                passed,
                passed,
                "" if passed else (
                    "sandbox-exec isolation probe failed "
                    f"(rc={completed.returncode}): {stderr}"
                ),
            )
        MacOSSandboxBackend._capability_cache = availability
        return availability

    def profile(
        self,
        worktree: Path,
        *,
        writable: bool = True,
        unreadable_roots: tuple[Path, ...] = (),
    ) -> str:
        escaped = str(worktree.resolve()).replace("\\", "\\\\").replace('"', '\\"')
        workspace_write = f'(allow file-write* (subpath "{escaped}"))' if writable else ""
        deny_reads = "".join(
            f'(deny file-read* (subpath "{_seatbelt_escape(path)}"))'
            for path in unreadable_roots
        )
        return (
            "(version 1)(deny default)(allow process*)(allow file-read*)"
            f"{workspace_write}{deny_reads}(deny network*)"
        )

    async def execute(self, request):
        from khaos.coding.execution.host import HostExecutionBackend
        from dataclasses import replace
        profile = _validated_profile(request)
        writable = profile.filesystem.value == "workspace-write"
        worktree = profile.workspace_roots[0]
        sandbox_profile = self.profile(
            worktree,
            writable=writable,
            unreadable_roots=profile.unreadable_roots,
        )
        sandboxed = replace(
            request,
            argv=("/usr/bin/sandbox-exec", "-p", sandbox_profile, *request.argv),
        )
        return await HostExecutionBackend(self.supervisor).execute(sandboxed)

    async def terminate(self, execution_id: str) -> None:
        if self.supervisor is not None:
            await self.supervisor.terminate(execution_id)


class LinuxBubblewrapBackend:
    name = "linux-bwrap"
    _capability_cache: "BackendAvailability | None" = None

    def __init__(self, supervisor=None) -> None:
        self.supervisor = supervisor

    async def probe(self) -> BackendAvailability:
        return self.probe_capability()

    def probe_capability(self) -> BackendAvailability:
        """Actually execute bwrap to verify --unshare-net/--unshare-pid AND
        the writable workspace bind actually work.

        A ``shutil.which`` check is not sufficient: some platforms (notably
        GitHub-hosted ubuntu-latest) ship bwrap but block the network
        namespace creation with EPERM on RTM_NEWADDR.  Additionally, a
        ``--tmpfs /tmp`` can shadow a worktree that lives under ``/tmp``
        (the default pytest tmp_path location), making the writable bind
        invisible and the sandboxed process fall back to read-only ``/``.

        Mount topology: ``--ro-bind / /`` first (read-only root), then
        ``--dev /dev`` (fresh devtmpfs so /dev/null etc. are accessible),
        then ``--tmpfs /tmp`` (fresh writable tmpfs), then ``--bind
        <worktree> /tmp/workspace``.  The tmpfs must precede the bind so
        that bwrap can ``mkdir /tmp/workspace`` inside the writable tmpfs
        — a ``--bind`` to a top-level path that does not exist on the
        host (e.g. ``/workspace``) fails because ``--ro-bind / /`` makes
        the root read-only and bwrap cannot create the mount point.

        Without ``--dev /dev``, the read-only root bind exposes the
        host's /dev/null as a read-only device node, and subprocess
        redirection (subprocess.DEVNULL) fails with EACCES.

        This probe runs the real sandbox with the same mount topology as
        ``argv_prefix`` and actually writes a probe file, so it catches
        both the namespace failure and the bind-shadow failure.
        """
        if not sys.platform.startswith("linux") or shutil.which("bwrap") is None:
            return BackendAvailability(self.name, False, False, "bwrap unavailable on this platform")
        if LinuxBubblewrapBackend._capability_cache is not None:
            return LinuxBubblewrapBackend._capability_cache
        try:
            with tempfile.TemporaryDirectory() as tmp:
                prefix = self.argv_prefix(Path(tmp), cwd=Path(tmp))
                completed = subprocess.run(
                    (*prefix, "--", "/bin/sh", "-c", "echo probe > .probe && cat .probe"),
                    capture_output=True,
                    timeout=10,
                )
        except (OSError, subprocess.SubprocessError) as exc:
            availability = BackendAvailability(
                self.name,
                False,
                False,
                f"bwrap isolation probe could not run: {type(exc).__name__}: {exc}",
            )
            LinuxBubblewrapBackend._capability_cache = availability
            return availability
        if completed.returncode == 0 and b"probe" in completed.stdout:
            availability = BackendAvailability(self.name, True, True)
        else:
            stderr = completed.stderr.decode("utf-8", errors="replace").strip()
            availability = BackendAvailability(
                self.name, False, False,
                f"bwrap isolation probe failed (rc={completed.returncode}): {stderr}",
            )
        LinuxBubblewrapBackend._capability_cache = availability
        return availability

    # The worktree is bound to /tmp/workspace inside the sandbox.  --tmpfs /tmp
    # is applied BEFORE the bind so that /tmp is a fresh writable tmpfs; bwrap
    # can then mkdir /tmp/workspace (inside the tmpfs) and mount the worktree
    # there.  Binding to a path under /tmp avoids the tmpfs-shadow problem
    # (host worktree under /tmp being shadowed by --tmpfs /tmp) AND avoids the
    # read-only-root problem (bwrap cannot create a top-level path like
    # /workspace because --ro-bind / / makes the root read-only).
    SANDBOX_WORKDIR = "/tmp/workspace"

    def argv_prefix(
        self,
        worktree: Path,
        *,
        cwd: Path | None = None,
        writable: bool = True,
        unreadable_roots: tuple[Path, ...] = (),
    ) -> tuple[str, ...]:
        canonical_worktree = worktree.expanduser().resolve()
        canonical_cwd = (cwd or canonical_worktree).expanduser().resolve()
        if (
            canonical_cwd != canonical_worktree
            and canonical_worktree not in canonical_cwd.parents
        ):
            raise PermissionError("sandbox cwd is outside the active workspace")
        relative_cwd = canonical_cwd.relative_to(canonical_worktree)
        sandbox_cwd = Path(self.SANDBOX_WORKDIR) / relative_cwd
        prefix = [
            "bwrap",
            "--ro-bind", "/", "/",
            "--dev", "/dev",
            "--proc", "/proc",
            "--tmpfs", "/tmp",
            "--bind" if writable else "--ro-bind", str(canonical_worktree), self.SANDBOX_WORKDIR,
        ]
        for denied in unreadable_roots:
            if denied.is_dir():
                prefix.extend(("--tmpfs", str(denied)))
            elif denied.exists():
                prefix.extend(("--ro-bind", "/dev/null", str(denied)))
        prefix.extend((
            "--unshare-net", "--unshare-pid", "--unshare-ipc", "--unshare-uts",
            "--new-session", "--die-with-parent",
            "--chdir", str(sandbox_cwd),
        ))
        return tuple(prefix)

    async def execute(self, request):
        from khaos.coding.execution.host import HostExecutionBackend
        from dataclasses import replace
        profile = _validated_profile(request)
        writable = profile.filesystem.value == "workspace-write"
        worktree = profile.workspace_roots[0]
        prefix = self.argv_prefix(
            worktree,
            cwd=request.cwd,
            writable=writable,
            unreadable_roots=profile.unreadable_roots,
        )
        return await HostExecutionBackend(self.supervisor).execute(
            replace(request, argv=(*prefix, *request.argv))
        )

    async def terminate(self, execution_id: str) -> None:
        if self.supervisor is not None:
            await self.supervisor.terminate(execution_id)


def _validated_profile(request):
    profile = request.permission_profile
    if profile is None:
        raise PermissionError("execution request has no permission profile")
    profile.validate_resolved()
    if profile.network.value != "none":
        raise PermissionError(
            f"platform backend cannot enforce requested network policy: {profile.network.value}"
        )
    return profile


def _seatbelt_escape(path: Path) -> str:
    return str(path).replace("\\", "\\\\").replace('"', '\\"')
