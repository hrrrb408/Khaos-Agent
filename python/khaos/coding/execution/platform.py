"""Platform sandbox capability probes and command builders."""

from __future__ import annotations

import os
import shutil
import secrets
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

from khaos.coding.execution.models import ResourceBudget
from khaos.coding.execution.supervisor import ProcessSupervisor


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

    @staticmethod
    def runtime_read_roots(
        command: tuple[str, ...], workspace: Path
    ) -> tuple[Path, ...]:
        return _runtime_read_roots(command, workspace)

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
                        "import socket, subprocess",
                        "Path('inside.txt').write_text('ok')",
                        f"try: Path({str(outside)!r}).write_text('denied')",
                        "except OSError: pass",
                        "else: raise SystemExit('outside write allowed')",
                        "try: socket.create_connection(('1.1.1.1', 53), timeout=0.2)",
                        "except OSError: pass",
                        "else: raise SystemExit('network allowed')",
                        "for command in (('/usr/bin/pbpaste',), "
                        "('/usr/bin/security', 'list-keychains')):",
                        "    result = subprocess.run(command, capture_output=True)",
                        "    if result.returncode == 0:",
                        "        raise SystemExit(f'host IPC allowed: {command[0]}')",
                    )
                )
                completed = subprocess.run(
                    (
                        "/usr/bin/sandbox-exec",
                        "-p",
                        self.profile(
                            workspace,
                            runtime_roots=_runtime_read_roots(
                                (sys.executable,), workspace
                            ),
                        ),
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
        runtime_roots: tuple[Path, ...] = (),
        synthetic_home: Path | None = None,
        synthetic_tmp: Path | None = None,
    ) -> str:
        workspace = worktree.resolve()
        read_roots = _deduplicate_paths(
            (
                workspace,
                *_macos_system_read_roots(),
                *runtime_roots,
                *(() if synthetic_home is None else (synthetic_home.resolve(),)),
                *(() if synthetic_tmp is None else (synthetic_tmp.resolve(),)),
            )
        )
        read_rules = "".join(
            f'(allow file-read* (subpath "{_seatbelt_escape(path)}"))'
            for path in read_roots if path.exists()
        )
        literal_reads = "".join(
            f'(allow file-read* (literal "{_seatbelt_escape(path)}"))'
            for path in _macos_literal_read_files() if path.exists()
        )
        executable_map_rules = "".join(
            f'(allow file-map-executable (subpath "{_seatbelt_escape(path)}"))'
            for path in read_roots if path.exists()
        )
        write_roots = tuple(
            path for path in (
                workspace if writable else None,
                synthetic_home.resolve() if synthetic_home else None,
                synthetic_tmp.resolve() if synthetic_tmp else None,
            ) if path is not None
        )
        write_rules = "".join(
            f'(allow file-write* (subpath "{_seatbelt_escape(path)}"))'
            for path in write_roots
        )
        git_pointer = workspace / ".git"
        protected_write_rules = (
            f'(deny file-write* (literal "{_seatbelt_escape(git_pointer)}"))'
            if git_pointer.exists()
            else ""
        )
        mach_lookup_rules = "".join(
            f'(allow mach-lookup (global-name "{service}"))'
            for service in _macos_runtime_mach_services()
        )
        # unreadable_roots are deliberately not represented as deny exceptions:
        # deny-default plus the positive allowlist makes all non-runtime host
        # paths invisible, including credential roots not known in advance.
        _ = unreadable_roots
        return "".join((
            "(version 1)(deny default)(allow process-exec process-fork)",
            "(allow signal (target same-sandbox))",
            "(allow process-info* (target same-sandbox))",
            "(allow sysctl-read)(allow file-read-metadata)",
            '(allow file-read* (literal "/"))',
            '(allow file-read* file-write-data (literal "/dev/null"))',
            '(allow file-read* (literal "/dev/random"))',
            '(allow file-read* (literal "/dev/urandom"))',
            read_rules, literal_reads, executable_map_rules, write_rules,
            protected_write_rules,
            mach_lookup_rules,
            "(deny network*)",
        ))

    async def execute(self, request):
        from dataclasses import replace
        profile = _validated_profile(request)
        writable = profile.filesystem.value == "workspace-write"
        worktree = profile.workspace_roots[0]
        with tempfile.TemporaryDirectory(prefix="khaos-home-") as home_value:
            home = Path(home_value)
            sandbox_tmp = home / "tmp"
            sandbox_tmp.mkdir(mode=0o700)
            sandbox_profile = self.profile(
                worktree,
                writable=writable,
                unreadable_roots=profile.unreadable_roots,
                runtime_roots=_runtime_read_roots(request.argv, worktree),
                synthetic_home=home,
                synthetic_tmp=sandbox_tmp,
            )
            sandboxed = replace(
                request,
                argv=(
                    "/usr/bin/sandbox-exec", "-p", sandbox_profile,
                    *request.argv,
                ),
            )
            environment = _sandbox_environment(
                profile, request.environment,
                home=str(home), tmpdir=str(sandbox_tmp),
            )
            supervisor = self.supervisor or ProcessSupervisor()
            self.supervisor = supervisor
            return await supervisor.run(
                sandboxed,
                cwd=request.cwd.resolve(),
                env=environment,
                tmp_root=home,
                workspace_root=worktree if writable else None,
                workspace_baseline=request.workspace_baseline,
            )

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

        The probe uses the same empty-root topology as production: a tmpfs
        root, explicitly mounted runtime directories, a synthetic HOME,
        bounded /tmp, and exactly one workspace bind.  It therefore catches
        accidental regressions to a host-root bind as well as namespace
        failures.
        """
        if not sys.platform.startswith("linux") or shutil.which("bwrap") is None:
            return BackendAvailability(self.name, False, False, "bwrap unavailable on this platform")
        launcher = _linux_sandbox_launcher()
        if launcher is None:
            return BackendAvailability(
                self.name, False, False,
                "khaos-sandbox-launcher unavailable; no_new_privs/seccomp TCB is required",
            )
        if LinuxBubblewrapBackend._capability_cache is not None:
            return LinuxBubblewrapBackend._capability_cache
        cgroup: Path | None = None
        try:
            with tempfile.TemporaryDirectory() as tmp, \
                    tempfile.TemporaryDirectory(prefix="khaos-home-") as home:
                budget = ResourceBudget()
                cgroup = _create_linux_cgroup(budget, Path(tmp))
                if cgroup is None:
                    return BackendAvailability(
                        self.name, False, False,
                        "delegated cgroup v2 root unavailable; hard resource limits are required",
                    )
                prefix = self.argv_prefix(
                    Path(tmp), cwd=Path(tmp), synthetic_home=Path(home),
                    resources=budget, command=("/bin/sh",),
                    cgroup_procs=cgroup / "cgroup.procs",
                )
                completed = subprocess.run(
                    (
                        *prefix, "--", str(launcher), "--cgroup-procs",
                        "/run/khaos-cgroup.procs", "--", "/bin/sh", "-c",
                        "echo probe > .probe && cat .probe",
                    ),
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
            if cgroup is not None:
                _remove_linux_cgroup(cgroup)
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
        if cgroup is not None:
            _remove_linux_cgroup(cgroup)
        return availability

    SANDBOX_WORKDIR = "/workspace"

    def argv_prefix(
        self,
        worktree: Path,
        *,
        cwd: Path | None = None,
        writable: bool = True,
        unreadable_roots: tuple[Path, ...] = (),
        synthetic_home: Path | None = None,
        resources: ResourceBudget | None = None,
        command: tuple[str, ...] = (),
        environment: dict[str, str] | None = None,
        cgroup_procs: Path | None = None,
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
        budget = resources or ResourceBudget()
        home = (synthetic_home or canonical_worktree / ".khaos-home").resolve()
        home.mkdir(mode=0o700, parents=True, exist_ok=True)
        prefix = [
            "bwrap",
            "--tmpfs", "/",
            "--dir", "/home",
            "--dir", "/etc",
            "--dev", "/dev",
            "--proc", "/proc",
            "--size", str(budget.tmpfs_bytes),
            "--tmpfs", "/home/khaos",
            "--size", str(budget.tmpfs_bytes),
            "--tmpfs", "/tmp",
            "--bind" if writable else "--ro-bind", str(canonical_worktree), self.SANDBOX_WORKDIR,
        ]
        git_pointer = canonical_worktree / ".git"
        if writable and git_pointer.is_file():
            prefix.extend(
                ("--ro-bind", str(git_pointer), f"{self.SANDBOX_WORKDIR}/.git")
            )
        for link in (Path("/bin"), Path("/sbin"), Path("/lib"), Path("/lib64")):
            if link.is_symlink():
                prefix.extend(("--symlink", os.readlink(link), str(link)))
        runtime_roots = _linux_runtime_read_roots(command, canonical_worktree)
        for runtime_root in runtime_roots:
            prefix.extend(("--ro-bind", str(runtime_root), str(runtime_root)))
        for literal in _linux_literal_read_files():
            if literal.is_file():
                prefix.extend(("--ro-bind", str(literal), str(literal)))
        launcher = _linux_sandbox_launcher()
        if launcher is not None:
            prefix.extend(("--ro-bind", str(launcher), str(launcher)))
        if cgroup_procs is not None:
            prefix.extend((
                "--bind", str(cgroup_procs), "/run/khaos-cgroup.procs",
            ))
        safe_environment = _sandbox_environment(
            None, environment or {}, home="/home/khaos", tmpdir="/tmp"
        )
        prefix.append("--clearenv")
        for key, value in sorted(safe_environment.items()):
            prefix.extend(("--setenv", key, value))
        # deny-default mount construction makes unreadable roots absent.  They
        # must never be mounted merely to cover them with another mount.
        _ = unreadable_roots
        prefix.extend((
            "--unshare-net", "--unshare-pid", "--unshare-ipc", "--unshare-uts",
            "--new-session", "--die-with-parent",
            "--chdir", str(sandbox_cwd),
        ))
        return tuple(prefix)

    async def execute(self, request):
        from dataclasses import replace
        profile = _validated_profile(request)
        writable = profile.filesystem.value == "workspace-write"
        worktree = profile.workspace_roots[0]
        with tempfile.TemporaryDirectory(prefix="khaos-home-") as home_value:
            cgroup = _create_linux_cgroup(profile.resources, worktree)
            if cgroup is None:
                raise PermissionError(
                    "execution refused: delegated cgroup v2 limits unavailable"
                )
            prefix = self.argv_prefix(
                worktree,
                cwd=request.cwd,
                writable=writable,
                unreadable_roots=profile.unreadable_roots,
                synthetic_home=Path(home_value),
                resources=profile.resources,
                command=request.argv,
                environment=request.environment,
                cgroup_procs=cgroup / "cgroup.procs",
            )
            launcher = _linux_sandbox_launcher()
            if launcher is None:
                raise PermissionError(
                    "execution refused: no_new_privs/seccomp launcher unavailable"
                )
            sandboxed = replace(request, argv=(
                *prefix, "--", str(launcher), "--cgroup-procs",
                "/run/khaos-cgroup.procs", "--", *request.argv,
            ))
            supervisor = self.supervisor or ProcessSupervisor()
            self.supervisor = supervisor
            try:
                return await supervisor.run(
                    sandboxed,
                    cwd=request.cwd.resolve(),
                    sandbox_storage_paths=("/home/khaos", "/tmp"),
                    workspace_root=worktree if writable else None,
                    workspace_baseline=request.workspace_baseline,
                )
            finally:
                _remove_linux_cgroup(cgroup)

    async def terminate(self, execution_id: str) -> None:
        if self.supervisor is not None:
            await self.supervisor.terminate(execution_id)


def _linux_sandbox_launcher() -> Path | None:
    """Resolve the reviewed Rust inner TCB; never fall back to raw exec."""
    configured = os.environ.get("KHAOS_SANDBOX_LAUNCHER", "").strip()
    candidates: list[Path] = []
    if configured:
        candidates.append(Path(configured).expanduser())
    repository_root = Path(__file__).resolve().parents[4]
    candidates.extend((
        repository_root / "rust" / "khaos-core" / "target" / "release"
        / "khaos-sandbox-launcher",
        repository_root / "rust" / "khaos-core" / "target" / "debug"
        / "khaos-sandbox-launcher",
    ))
    located = shutil.which("khaos-sandbox-launcher")
    if located:
        candidates.append(Path(located))
    for candidate in candidates:
        canonical = candidate.resolve()
        if canonical.is_file() and os.access(canonical, os.X_OK):
            return canonical
    return None


def _linux_cgroup_root() -> Path | None:
    """Return a writable delegated cgroup-v2 subtree, if available."""
    if not sys.platform.startswith("linux"):
        return None
    unified = Path("/sys/fs/cgroup/cgroup.controllers")
    if not unified.is_file():
        return None
    configured = os.environ.get("KHAOS_CGROUP_ROOT", "").strip()
    root = Path(configured) if configured else Path("/sys/fs/cgroup/khaos")
    try:
        root.mkdir(mode=0o700, parents=True, exist_ok=True)
        canonical = root.resolve()
        if Path("/sys/fs/cgroup") not in (canonical, *canonical.parents):
            return None
        if not os.access(canonical, os.W_OK):
            return None
        return canonical
    except OSError:
        return None


def _create_linux_cgroup(
    budget: ResourceBudget, workspace: Path,
) -> Path | None:
    """Create and fully configure a per-execution cgroup-v2 leaf."""
    root = _linux_cgroup_root()
    if root is None:
        return None
    group = root / f"exec-{os.getpid()}-{secrets.token_hex(8)}"
    try:
        group.mkdir(mode=0o700)
        period = 100_000
        quota = max(1_000, int(budget.cpu_count * period))
        io_rate = max(
            1024 * 1024,
            min(
                256 * 1024 * 1024,
                int(budget.workspace_bytes / max(1.0, budget.timeout_seconds)),
            ),
        )
        device = workspace.resolve().stat().st_dev
        limits = {
            "pids.max": str(budget.pids),
            "memory.max": str(budget.memory_bytes),
            "memory.swap.max": "0",
            "cpu.max": f"{quota} {period}",
            "io.max": (
                f"{os.major(device)}:{os.minor(device)} "
                f"rbps={io_rate} wbps={io_rate}"
            ),
        }
        for name, value in limits.items():
            (group / name).write_text(value, encoding="ascii")
        return group
    except OSError:
        _remove_linux_cgroup(group)
        return None


def _remove_linux_cgroup(group: Path) -> None:
    """Best-effort removal; a live payload keeps the leaf non-empty."""
    try:
        group.rmdir()
    except OSError:
        pass


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


def _deduplicate_paths(paths: tuple[Path, ...]) -> tuple[Path, ...]:
    result: list[Path] = []
    seen: set[Path] = set()
    for path in paths:
        canonical = path.expanduser().resolve()
        if canonical not in seen:
            result.append(canonical)
            seen.add(canonical)
    return tuple(result)


def _runtime_read_roots(
    command: tuple[str, ...], workspace: Path
) -> tuple[Path, ...]:
    """Return the narrow installation root needed to launch argv[0]."""
    if not command:
        return ()
    executable = command[0]
    located = shutil.which(executable) if not Path(executable).is_absolute() else executable
    if not located:
        return ()
    lexical = Path(located).expanduser().absolute()
    resolved = Path(located).expanduser().resolve()
    canonical_workspace = workspace.expanduser().resolve()
    venv_roots: tuple[Path, ...] = ()
    if len(lexical.parents) >= 2:
        possible_venv = lexical.parents[1]
        if (
            (possible_venv / "pyvenv.cfg").is_file()
            and possible_venv != canonical_workspace
            and canonical_workspace not in possible_venv.parents
        ):
            # Python resolves the executable symlink to its base install, but
            # ``site.py`` still reads pyvenv.cfg through the lexical venv
            # path. Both narrow roots are therefore required.
            venv_roots = (possible_venv.resolve(),)
    if resolved == canonical_workspace or canonical_workspace in resolved.parents:
        return venv_roots
    for root in _macos_system_read_roots():
        if resolved == root or root in resolved.parents:
            return venv_roots
    parents = resolved.parents
    if len(parents) < 2:
        return (*venv_roots, resolved)
    # /opt/homebrew/bin/python -> /opt/homebrew; framework and application
    # binaries receive their product root rather than the user's whole HOME.
    if resolved.parts[:3] == ("/", "opt", "homebrew"):
        return (*venv_roots, Path("/opt/homebrew"))
    if "Library" in resolved.parts and "Frameworks" in resolved.parts:
        index = resolved.parts.index("Frameworks")
        return (*venv_roots, Path(*resolved.parts[: index + 2]))
    if ".app" in "".join(resolved.parts):
        for index, part in enumerate(resolved.parts):
            if part.endswith(".app"):
                return (*venv_roots, Path(*resolved.parts[: index + 1]))
    candidate = parents[1]
    home = Path.home().resolve()
    if candidate == home or candidate in home.parents:
        return (*venv_roots, resolved)
    return (*venv_roots, candidate)


def _macos_system_read_roots() -> tuple[Path, ...]:
    return tuple(
        path for path in (
            Path("/System"), Path("/usr"), Path("/bin"), Path("/sbin"),
            Path("/Library/Apple"),
            Path("/private/var/db/dyld"),
            Path("/System/Volumes/Preboot/Cryptexes/OS"),
        ) if path.exists()
    )


def _macos_literal_read_files() -> tuple[Path, ...]:
    return tuple(
        path for path in (
            Path("/etc/hosts"), Path("/etc/passwd"), Path("/etc/group"),
            Path("/etc/localtime"),
        ) if path.exists()
    )


def _macos_runtime_mach_services() -> tuple[str, ...]:
    """Minimal lookup needed for libc account/group resolution."""
    return ("com.apple.system.opendirectoryd.libinfo",)


def _linux_runtime_read_roots(
    command: tuple[str, ...], workspace: Path
) -> tuple[Path, ...]:
    roots = [
        path for path in (
            Path("/usr"), Path("/bin"), Path("/sbin"), Path("/lib"),
            Path("/lib64"),
        ) if path.exists() and not path.is_symlink()
    ]
    roots.extend(_runtime_read_roots(command, workspace))
    return _deduplicate_paths(tuple(roots))


def _linux_literal_read_files() -> tuple[Path, ...]:
    return tuple(
        path for path in (
            Path("/etc/ld.so.cache"), Path("/etc/ld.so.conf"),
            Path("/etc/nsswitch.conf"), Path("/etc/passwd"),
            Path("/etc/group"), Path("/etc/localtime"),
        ) if path.exists()
    )


def _sandbox_environment(
    profile,
    requested: dict[str, str],
    *,
    home: str,
    tmpdir: str,
) -> dict[str, str]:
    allowed_keys = (
        profile.environment_keys if profile is not None
        else frozenset({"PATH", "LANG", "LC_ALL", "TERM"})
    )
    environment = {
        key: value for key, value in requested.items() if key in allowed_keys
    }
    environment.setdefault("PATH", os.defpath)
    environment.setdefault("LANG", "C.UTF-8")
    environment.update({"HOME": home, "TMPDIR": tmpdir, "TMP": tmpdir, "TEMP": tmpdir})
    return environment
