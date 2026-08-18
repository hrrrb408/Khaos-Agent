# KHAOS-PRIVILEGED-SPAWN owner=CredentialProviderHost threat-model=contained-blocking-provider boundary=killable-worker-domain
"""Killable subprocess containment for blocking credential providers.

A synchronous provider loader that hangs forever cannot be reclaimed at
Python thread level — ``Thread.terminate`` does not exist and the broker
correctly refuses to report a false terminal state while the thread lives.
This host moves one provider materialization into a dedicated child
process (``python -I -S <canonical credential_provider_worker.py>``) and
owns the full termination ladder::

    deadline breach / close request
        → SIGTERM to the provider execution domain
        → grace period
        → SIGKILL to the domain + descendant sweep
        → waitpid terminal proof

so logical cancellation becomes physical resource reclamation with a
bounded wall-clock cost and without exiting the trusted runtime process.

M5.6 hardens two boundaries the ladder previously assumed:

* **No Untrusted Resolution Before Privileged Spawn** — the worker is
  launched from an absolute canonical script path with ``-I -S`` (no
  ``PYTHONPATH``, no cwd on ``sys.path``), a trusted fixed cwd, and a
  minimal fixed environment.  A malicious repository cwd cannot poison
  worker imports, and helper ``argv[0]`` never resolves through ``PATH``.
* **Provider Terminal Means Process-Tree Terminal** — the worker runs in
  its own session; termination signals the process group *and* every
  enumerated descendant, and the host only claims the domain terminal when
  no collected pid remains alive.  If proof cannot be established the host
  stays alive from the broker's perspective (quarantine), never a false
  CLOSED.

The parent never trusts the child blindly: the response is one bounded
JSON line, and the returned environment still passes the broker's schema
validation in the parent before any fence settles.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import signal
import stat as stat_module
import subprocess
import sys
from collections.abc import Mapping
from pathlib import Path

from khaos.security.credential_provider_worker import (
    environment_passthrough_names,
)

logger = logging.getLogger(__name__)

_WORKER_SCRIPT = Path(__file__).resolve().parent / "credential_provider_worker.py"
_TRUSTED_CWD = Path(__file__).resolve().parent
_FIXED_POSIX_PATH = "/usr/bin:/bin"
_DEFAULT_TERMINATION_GRACE = 2.0
_DEFAULT_KILL_GRACE = 5.0
_MAX_RESPONSE_BYTES = 1 * 1024 * 1024
_DESCENDANT_POLL_INTERVAL = 0.05


class CredentialProviderHostError(PermissionError):
    """Raised when a contained provider host cannot deliver material."""


class CredentialProviderHost:
    """Own one child process executing exactly one provider spec."""

    def __init__(
        self,
        *,
        python_executable: str | None = None,
        startup_deadline: float | None = None,
        termination_grace: float = _DEFAULT_TERMINATION_GRACE,
        kill_grace: float = _DEFAULT_KILL_GRACE,
        untrusted_roots: tuple[Path, ...] = (),
    ) -> None:
        if termination_grace < 0 or kill_grace <= 0:
            raise ValueError("credential provider host deadlines must be positive")
        if startup_deadline is not None:
            logger.debug(
                "startup_deadline is folded into the materialization deadline"
            )
        self._python = python_executable or sys.executable or "python3"
        self._termination_grace = termination_grace
        self._kill_grace = kill_grace
        self._untrusted_roots = tuple(Path(root) for root in untrusted_roots)
        self._process: asyncio.subprocess.Process | None = None
        self._domain_pids: set[int] = set()
        self._worker_identity: dict[str, object] | None = None

    @property
    def pid(self) -> int | None:
        process = self._process
        if process is None:
            return None
        return process.pid

    @property
    def worker_identity(self) -> dict[str, object] | None:
        """Canonical path/dev/inode identity of the launched worker script."""
        return dict(self._worker_identity) if self._worker_identity else None

    @property
    def alive(self) -> bool:
        """True while any process of the provider execution domain lives.

        Terminal means *process-tree* terminal: the direct worker plus
        every descendant pid collected during termination must be gone
        (zombies excluded — they hold no execution state).
        """
        if self._process is not None and self._process.returncode is None:
            return True
        return any(
            _pid_alive(pid) and not _pid_is_zombie(pid)
            for pid in self._domain_pids
        )

    async def materialize(
        self, spec: Mapping[str, object], *, deadline: float
    ) -> dict[str, str]:
        """Run one spec in a fresh child and return its environment material.

        ``deadline`` bounds spawn, request, and response combined — a spawn
        that never completes fails closed at the deadline like a hung
        provider.  Any breach — or a caller-side task cancellation —
        escalates the termination ladder over the whole execution domain,
        so this coroutine never returns or raises while a domain process
        is still alive unless termination itself is unproven (in which
        case the error says so and the host stays alive for quarantine).
        """
        if deadline <= 0:
            raise CredentialProviderHostError(
                "credential provider host deadline must be positive"
            )
        request = json.dumps(
            {
                "spec": dict(spec),
                "untrusted_roots": [
                    str(Path(root).resolve()) for root in self._untrusted_roots
                ],
            },
            ensure_ascii=False,
        )
        try:
            try:
                material = await asyncio.wait_for(
                    self._spawn_and_exchange(request, spec), timeout=deadline
                )
            except TimeoutError as exc:
                raise CredentialProviderHostError(
                    "credential provider host exceeded its materialization deadline"
                ) from exc
            except asyncio.CancelledError:
                raise
            except CredentialProviderHostError:
                raise
            except Exception as exc:  # noqa: BLE001 - the host boundary fails closed
                raise CredentialProviderHostError(
                    f"credential provider host failed: {type(exc).__name__}: {exc}"
                ) from exc
            return material
        finally:
            # The ladder must complete even under cancellation, and an
            # unproven termination must not mask the original failure.
            try:
                await asyncio.shield(self._terminate())
            except asyncio.CancelledError:
                raise
            except CredentialProviderHostError as exc:
                if sys.exc_info()[0] is None:
                    raise
                logger.error("provider host termination is unproven: %s", exc)

    def request_termination(self) -> None:
        """Ask the domain to stop without waiting; thread-safe for close().

        Signals the owned process group directly.  The pgid equals the
        worker pid (session leader via ``start_new_session``) and cannot
        be reused while the host still owns the un-reaped child.
        """
        process = self._process
        if process is None or process.returncode is not None:
            return
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except (ProcessLookupError, PermissionError, OSError) as exc:
            if isinstance(exc, ProcessLookupError):
                return
            logger.warning(
                "credential provider host termination signal failed: %s", exc
            )

    # ─── spawn identity ─────────────────────────────────────────────────

    def _worker_script_identity(self) -> Path:
        """Verify and return the canonical absolute worker script path."""
        canonical = _WORKER_SCRIPT.resolve()
        try:
            info = canonical.stat()
        except OSError as exc:
            raise CredentialProviderHostError(
                f"credential provider worker script is unavailable: {exc}"
            ) from exc
        if not stat_module.S_ISREG(info.st_mode):
            raise CredentialProviderHostError(
                "credential provider worker script is not a regular file"
            )
        self._worker_identity = {
            "path": str(canonical),
            "device": info.st_dev,
            "inode": info.st_ino,
            "mode": oct(stat_module.S_IMODE(info.st_mode)),
        }
        return canonical

    def _worker_environment(self, spec: Mapping[str, object]) -> dict[str, str]:
        """Give the worker a minimal fixed environment plus spec variables.

        No ``PYTHONPATH`` is passed (and ``-I`` ignores it anyway), PATH is
        a fixed system allowlist rather than the caller's, and only the
        variables an ``env`` spec explicitly reads cross the boundary.
        """
        environment: dict[str, str] = {}
        if os.name == "posix":
            environment["PATH"] = _FIXED_POSIX_PATH
        else:
            environment["PATH"] = os.environ.get("PATH", "")
            if "SYSTEMROOT" in os.environ:
                environment["SYSTEMROOT"] = os.environ["SYSTEMROOT"]
        for name in sorted(environment_passthrough_names(spec)):
            value = os.environ.get(name)
            if value is not None:
                environment[name] = value
        return environment

    # ─── request/response exchange ──────────────────────────────────────

    async def _spawn_and_exchange(
        self, request: str, spec: Mapping[str, object]
    ) -> dict[str, str]:
        script = self._worker_script_identity()
        self._process = await asyncio.create_subprocess_exec(
            self._python,
            # -I: isolated mode (implies -E/-P/-s): no PYTHONPATH, no cwd or
            # script dir on sys.path, no user site.  -S: no site packages —
            # the worker is standard-library only.
            "-I",
            "-S",
            str(script),
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
            cwd=str(_TRUSTED_CWD),
            env=self._worker_environment(spec),
            start_new_session=os.name == "posix",
            limit=_MAX_RESPONSE_BYTES,
        )
        return await self._exchange(request)

    async def _exchange(self, request: str) -> dict[str, str]:
        process = self._process
        if process is None or process.stdin is None or process.stdout is None:
            raise CredentialProviderHostError(
                "credential provider host pipes are missing"
            )
        process.stdin.write(request.encode("utf-8") + b"\n")
        await process.stdin.drain()
        process.stdin.close()
        line = await process.stdout.readline()
        if not line:
            code = process.returncode
            raise CredentialProviderHostError(
                "credential provider host exited before responding"
                + (f" (status {code})" if code is not None else "")
            )
        try:
            payload = json.loads(line.decode("utf-8"))
        except (UnicodeError, ValueError) as exc:
            raise CredentialProviderHostError(
                "credential provider host response is not valid JSON"
            ) from exc
        if not isinstance(payload, dict) or "ok" not in payload:
            raise CredentialProviderHostError(
                "credential provider host response is malformed"
            )
        if payload.get("ok") is not True:
            raise CredentialProviderHostError(
                f"credential provider failed: {payload.get('error', 'unknown error')}"
            )
        environment = payload.get("environment")
        if not isinstance(environment, dict):
            raise CredentialProviderHostError(
                "credential provider returned no material"
            )
        return {str(key): str(value) for key, value in environment.items()}

    # ─── process-domain termination ─────────────────────────────────────

    async def _terminate(self) -> None:
        """Run the domain-wide TERM → grace → KILL ladder with proof.

        Signals the worker's whole process group and every enumerated
        descendant pid; the domain is terminal only when the worker is
        reaped AND no collected descendant remains alive.
        """
        process = self._process
        if process is None:
            return
        if process.returncode is None:
            self._domain_pids |= await asyncio.to_thread(_collect_descendants, process.pid)
            await asyncio.to_thread(_signal_domain, process.pid, self._domain_pids, signal.SIGTERM)
            try:
                await asyncio.wait_for(
                    process.wait(), timeout=self._termination_grace
                )
            except TimeoutError:
                self._domain_pids |= await asyncio.to_thread(
                    _collect_descendants, process.pid
                )
                await asyncio.to_thread(
                    _signal_domain, process.pid, self._domain_pids, signal.SIGKILL
                )
                try:
                    await asyncio.wait_for(
                        process.wait(), timeout=self._kill_grace
                    )
                except TimeoutError:
                    raise CredentialProviderHostError(
                        "credential provider host could not prove child termination"
                    )
        if process.returncode is None:
            raise CredentialProviderHostError(
                "credential provider host child termination is unproven"
            )
        try:
            survivors = await asyncio.wait_for(
                self._wait_domain_gone(), timeout=self._kill_grace
            )
        except TimeoutError:
            # The worker is reaped but descendants survived the group TERM
            # (e.g. a SIGTERM-ignoring helper): escalate to SIGKILL over the
            # whole collected domain before declaring anything terminal.
            await asyncio.to_thread(
                _signal_domain, process.pid, self._domain_pids, signal.SIGKILL
            )
            try:
                survivors = await asyncio.wait_for(
                    self._wait_domain_gone(), timeout=self._kill_grace
                )
            except TimeoutError as exc:
                raise CredentialProviderHostError(
                    "credential provider execution domain termination is unproven"
                ) from exc
        if survivors:
            raise CredentialProviderHostError(
                "credential provider execution domain has surviving processes"
            )

    async def _wait_domain_gone(self) -> set[int]:
        """Poll collected descendants until none remains alive (zombies ok)."""
        while True:
            survivors = {
                pid
                for pid in self._domain_pids
                if _pid_alive(pid) and not _pid_is_zombie(pid)
            }
            if not survivors:
                return set()
            await asyncio.sleep(_DESCENDANT_POLL_INTERVAL)


def _signal_domain(
    worker_pid: int, domain_pids: set[int], sig: signal.Signals
) -> None:
    """Signal the worker's process group and each enumerated descendant."""
    try:
        os.killpg(worker_pid, sig)
    except (ProcessLookupError, PermissionError):
        pass
    except OSError as exc:
        logger.debug("provider domain group signal failed: %s", exc)
    for pid in domain_pids:
        if pid == worker_pid:
            continue
        try:
            os.kill(pid, sig)
        except (ProcessLookupError, PermissionError):
            pass
        except OSError as exc:
            logger.debug("provider domain signal for %d failed: %s", pid, exc)


def _collect_descendants(worker_pid: int) -> set[int]:
    """Enumerate live descendants of the worker (best effort, bounded).

    On Linux this walks /proc parent links; elsewhere it falls back to
    ``ps``.  Descendants that escape the process group via setsid are
    still reachable here while the worker lives, which is exactly the
    window the ladder signals in.
    """
    parents: dict[int, int] = {}
    zombie: set[int] = set()
    try:
        if sys.platform.startswith("linux"):
            for entry in os.listdir("/proc"):
                if not entry.isdigit():
                    continue
                pid = int(entry)
                try:
                    with open(f"/proc/{pid}/stat", "rb") as handle:
                        fields = handle.read().rsplit(b")", 1)[-1].split()
                    # fields[0] is state, fields[1] is ppid after the ')'.
                    state = fields[0][:1]
                    ppid = int(fields[1])
                except (OSError, IndexError, ValueError):
                    continue
                parents[pid] = ppid
                if state == b"Z":
                    zombie.add(pid)
        else:
            completed = subprocess.run(
                ["ps", "-axo", "pid=,ppid=,state="],
                capture_output=True,
                timeout=5,
                check=False,
            )
            for line in completed.stdout.decode("utf-8", errors="replace").splitlines():
                parts = line.split()
                if len(parts) < 3:
                    continue
                try:
                    pid, ppid = int(parts[0]), int(parts[1])
                except ValueError:
                    continue
                parents[pid] = ppid
                if parts[2].startswith("Z"):
                    zombie.add(pid)
    except (OSError, subprocess.SubprocessError):
        return set()
    descendants: set[int] = set()
    frontier = {worker_pid}
    while frontier:
        current = frontier.pop()
        for pid, ppid in parents.items():
            if ppid == current and pid not in descendants:
                descendants.add(pid)
                if pid not in zombie:
                    frontier.add(pid)
    return descendants


def _pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return False
    return True


def _pid_is_zombie(pid: int) -> bool:
    try:
        if sys.platform.startswith("linux"):
            with open(f"/proc/{pid}/stat", "rb") as handle:
                state = handle.read().rsplit(b")", 1)[-1].split()[0][:1]
            return state == b"Z"
        completed = subprocess.run(
            ["ps", "-o", "state=", "-p", str(pid)],
            capture_output=True,
            timeout=2,
            check=False,
        )
        return completed.stdout.decode("utf-8", errors="replace").strip().startswith("Z")
    except (OSError, IndexError, subprocess.SubprocessError):
        return False


__all__ = [
    "CredentialProviderHost",
    "CredentialProviderHostError",
]
