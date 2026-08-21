"""Owned subprocess lifecycle for trusted Git operations.

The process owner proves spawn adoption, bounded pipe draining, process-domain
termination, and quarantine. Git command allowlists and authority effects
remain in the trusted_git module.
"""

# KHAOS-PRIVILEGED-SPAWN owner=TrustedGitProcessOwner threat-model=untrusted-repository-config boundary=workspace-control-plane

from __future__ import annotations

import asyncio
import os
import signal
import subprocess
from enum import Enum

_MAX_GIT_ERROR_BYTES = 64 * 1024
_MAX_GIT_CHUNK_BYTES = 1024 * 1024
class TrustedGitError(RuntimeError):
    """Raised when a host-side Git authority or invocation is not trusted."""


class TrustedGitProcessState(str, Enum):
    """Terminal ownership state for one host-side Git process."""

    NEW = "new"
    SPAWNED = "spawned"
    RUNNING = "running"
    COMPLETED = "completed"
    CANCELLED = "cancelled"
    FAILED = "failed"
    QUARANTINED = "quarantined"


class TrustedGitProcessOwner:
    """Own a Git subprocess from spawn through a proved terminal state.

    ``asyncio.create_subprocess_exec`` is launched in a task and shielded so a
    caller cancellation cannot abandon the process between kernel spawn and
    assignment to the owner.  Once a process exists, cancellation and error
    cleanup are themselves shielded and operate on the whole POSIX process
    group.  If exit cannot be proved, the owner remains quarantined and the
    caller receives a hard failure instead of a false success.
    """

    def __init__(
        self,
        label: str,
        *,
        terminate_grace_seconds: float = 0.75,
        spawn_adoption_seconds: float = 5.0,
    ) -> None:
        if not label or terminate_grace_seconds <= 0 or spawn_adoption_seconds <= 0:
            raise ValueError("invalid TrustedGitProcessOwner limits")
        self.label = label
        self.terminate_grace_seconds = terminate_grace_seconds
        self.spawn_adoption_seconds = spawn_adoption_seconds
        self.state = TrustedGitProcessState.NEW
        self.process: asyncio.subprocess.Process | None = None
        self.quarantine_reason: str | None = None
        self._late_spawn_task: asyncio.Task[None] | None = None

    @property
    def terminal(self) -> bool:
        return self.state in {
            TrustedGitProcessState.COMPLETED,
            TrustedGitProcessState.CANCELLED,
            TrustedGitProcessState.FAILED,
        }

    @property
    def terminal_postcondition(self) -> bool:
        """Prove that no late spawn task or live Git child remains."""
        return (
            (self.process is None or self.process.returncode is not None)
            and (self._late_spawn_task is None or self._late_spawn_task.done())
            and self.state is not TrustedGitProcessState.QUARANTINED
        )

    @staticmethod
    def _spawn_options() -> dict[str, object]:
        if os.name == "nt":
            return {"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP}
        return {"start_new_session": True}

    async def spawn(self, *argv: str, **kwargs: object) -> asyncio.subprocess.Process:
        """Spawn and publish the child, adopting it if the caller is cancelled."""
        if self.state is not TrustedGitProcessState.NEW:
            raise TrustedGitError(f"Git process owner {self.label} was reused")
        spawn_task = asyncio.create_task(
            asyncio.create_subprocess_exec(*argv, **self._spawn_options(), **kwargs)
        )
        try:
            process = await asyncio.shield(spawn_task)
        except asyncio.CancelledError:
            try:
                process = await asyncio.shield(
                    asyncio.wait_for(
                        asyncio.shield(spawn_task), self.spawn_adoption_seconds
                    )
                )
            except TimeoutError as exc:
                self.state = TrustedGitProcessState.QUARANTINED
                self.quarantine_reason = "spawn could not be adopted after cancellation"
                # ``wait_for(spawn_task)`` would cancel the spawn coroutine,
                # but cancellation of subprocess creation does not prove
                # that a kernel child was not created. Keep the original task
                # alive and attach an owner-side reaper that adopts and
                # terminates a child if it appears later.
                self._late_spawn_task = asyncio.create_task(
                    self._adopt_late_spawn(spawn_task),
                    name=f"khaos-git-reaper:{self.label}",
                )
                raise TrustedGitError(
                    f"Git process {self.label} could not be adopted after cancellation"
                ) from exc
            self.process = process
            self.state = TrustedGitProcessState.SPAWNED
            await asyncio.shield(self.abort(cancelled=True))
            raise
        except Exception:
            if not spawn_task.done():
                spawn_task.cancel()
                try:
                    await spawn_task
                except asyncio.CancelledError:
                    pass
            self.state = TrustedGitProcessState.FAILED
            raise
        self.process = process
        self.state = TrustedGitProcessState.RUNNING
        return process

    async def _adopt_late_spawn(
        self, spawn_task: asyncio.Task[asyncio.subprocess.Process]
    ) -> None:
        """Reap a spawn that outlived the caller's bounded adoption window."""
        try:
            process = await spawn_task
        except BaseException:  # noqa: BLE001 - reaper must consume late spawn failures
            # A failed/cancelled spawn proves that no process was published.
            self.state = TrustedGitProcessState.CANCELLED
            return
        self.process = process
        self.state = TrustedGitProcessState.SPAWNED
        try:
            await self.abort(cancelled=True)
        except TrustedGitError as exc:
            self.state = TrustedGitProcessState.QUARANTINED
            self.quarantine_reason = str(exc) or "late Git process cleanup failed"

    async def close(self) -> None:
        """Retry late adoption/termination and retain failure as quarantine."""
        late_spawn = self._late_spawn_task
        if late_spawn is not None and not late_spawn.done():
            await asyncio.shield(late_spawn)
        if self.process is not None and self.process.returncode is None:
            await asyncio.shield(self.abort(cancelled=True))
        if self.state is TrustedGitProcessState.QUARANTINED:
            if self.process is None or self.process.returncode is not None:
                self.state = TrustedGitProcessState.CANCELLED
            else:
                raise TrustedGitError(
                    f"Git process {self.label} remains quarantined: "
                    f"{self.quarantine_reason or 'terminal proof is missing'}"
                )
        if not self.terminal_postcondition:
            raise TrustedGitError(
                f"Git process {self.label} terminal ownership proof is missing"
            )

    async def communicate_after_spawn(
        self,
        *argv: str,
        input_bytes: bytes | None = None,
        **kwargs: object,
    ) -> tuple[bytes, bytes]:
        """Spawn one command and communicate under the same owner."""
        await self.spawn(*argv, **kwargs)
        return await self.communicate(input_bytes)

    async def communicate_bounded_after_spawn(
        self,
        *argv: str,
        input_bytes: bytes | None = None,
        max_stdout_bytes: int = 64 * 1024,
        max_stderr_bytes: int = _MAX_GIT_ERROR_BYTES,
        **kwargs: object,
    ) -> tuple[bytes, bytes, int]:
        """Spawn and drain one Git process under explicit output bounds."""
        await self.spawn(*argv, **kwargs)
        return await self.communicate_bounded(
            input_bytes=input_bytes,
            max_stdout_bytes=max_stdout_bytes,
            max_stderr_bytes=max_stderr_bytes,
        )

    async def communicate(
        self, input_bytes: bytes | None = None
    ) -> tuple[bytes, bytes]:
        """Communicate with cancellation-safe, bounded output ownership."""
        stdout, stderr, _ = await self.communicate_bounded(input_bytes=input_bytes)
        return stdout, stderr

    async def communicate_bounded(
        self,
        *,
        input_bytes: bytes | None = None,
        max_stdout_bytes: int = 64 * 1024,
        max_stderr_bytes: int = _MAX_GIT_ERROR_BYTES,
    ) -> tuple[bytes, bytes, int]:
        """Drain both pipes under hard bounds before publishing termination.

        ``Process.communicate`` buffers untrusted Git output until the child
        exits.  This owner-level primitive reads both pipes concurrently,
        aborts the whole process domain as soon as either bound is exceeded,
        and only returns after the child has a proven terminal state.
        """
        if max_stdout_bytes <= 0 or max_stderr_bytes <= 0:
            raise ValueError("Git output limits must be positive")
        process = self._require_process()
        if process.stdout is None or process.stderr is None:
            raise TrustedGitError(f"Git process {self.label} has no output pipes")

        async def read_bounded(
            stream: asyncio.StreamReader,
            stream_name: str,
            limit: int,
        ) -> bytes:
            output = bytearray()
            while True:
                remaining = max(limit + 1 - len(output), 1)
                chunk = await stream.read(min(_MAX_GIT_CHUNK_BYTES, remaining))
                if not chunk:
                    return bytes(output)
                output.extend(chunk)
                if len(output) > limit:
                    raise TrustedGitError(
                        f"trusted Git {stream_name} output exceeds its bound"
                    )

        async def write_input() -> None:
            if input_bytes is None:
                return
            if process.stdin is None:
                raise TrustedGitError(f"Git process {self.label} has no input pipe")
            try:
                process.stdin.write(input_bytes)
                await process.stdin.drain()
            except (BrokenPipeError, ConnectionResetError) as exc:
                raise TrustedGitError("trusted Git stdin could not be written") from exc
            finally:
                process.stdin.close()
                wait_closed = getattr(process.stdin, "wait_closed", None)
                if callable(wait_closed):
                    await wait_closed()

        tasks: list[asyncio.Task[object]] = [
            asyncio.create_task(
                read_bounded(process.stdout, "stdout", max_stdout_bytes)
            ),
            asyncio.create_task(
                read_bounded(process.stderr, "stderr", max_stderr_bytes)
            ),
        ]
        if input_bytes is not None:
            tasks.append(asyncio.create_task(write_input()))
        try:
            done, pending = await asyncio.wait(
                tasks, return_when=asyncio.FIRST_EXCEPTION
            )
            failure: BaseException | None = None
            for task in done:
                if not task.cancelled():
                    failure = task.exception()
                    if failure is not None:
                        break
            if failure is not None:
                await asyncio.shield(self.abort(cancelled=False))
                for task in pending:
                    task.cancel()
                await asyncio.gather(*pending, return_exceptions=True)
                raise failure
            await asyncio.gather(*pending)
            stdout = tasks[0].result()
            stderr = tasks[1].result()
            returncode = await self.wait()
        except asyncio.CancelledError:
            await asyncio.shield(self.abort(cancelled=True))
            for task in tasks:
                if not task.done():
                    task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            raise
        except Exception:
            await asyncio.shield(self.abort(cancelled=False))
            raise
        return stdout, stderr, returncode

    async def wait(self) -> int:
        """Wait for a process that has already had its pipes drained."""
        process = self._require_process()
        try:
            returncode = await process.wait()
        except asyncio.CancelledError:
            await asyncio.shield(self.abort(cancelled=True))
            raise
        except Exception:
            await asyncio.shield(self.abort(cancelled=False))
            raise
        self.state = (
            TrustedGitProcessState.COMPLETED
            if returncode == 0
            else TrustedGitProcessState.FAILED
        )
        return returncode

    async def abort(self, *, cancelled: bool) -> None:
        """Terminate the child and prove that it is no longer running."""
        process = self.process
        target_state = (
            TrustedGitProcessState.CANCELLED
            if cancelled
            else TrustedGitProcessState.FAILED
        )
        if process is None:
            self.state = target_state
            return
        try:
            if process.returncode is None:
                self._signal(process, force=False)
                try:
                    await asyncio.wait_for(
                        process.wait(), self.terminate_grace_seconds
                    )
                except TimeoutError:
                    self._signal(process, force=True)
                    await asyncio.wait_for(
                        process.wait(), self.terminate_grace_seconds
                    )
            if process.returncode is None:
                raise TrustedGitError("Git process exit could not be proved")
        except Exception as exc:
            self.state = TrustedGitProcessState.QUARANTINED
            self.quarantine_reason = str(exc) or "Git process cleanup failed"
            raise TrustedGitError(
                f"Git process {self.label} is quarantined: {self.quarantine_reason}"
            ) from exc
        self.state = target_state

    def _require_process(self) -> asyncio.subprocess.Process:
        if self.process is None:
            raise TrustedGitError(f"Git process {self.label} was not spawned")
        return self.process

    @staticmethod
    def _signal(process: asyncio.subprocess.Process, *, force: bool) -> None:
        if process.returncode is not None:
            return
        if os.name == "nt":
            process.kill() if force else process.terminate()
            return
        signum = signal.SIGKILL if force else signal.SIGTERM
        try:
            os.killpg(process.pid, signum)
        except ProcessLookupError:
            return
        except OSError:
            if force:
                process.kill()
            else:
                process.terminate()


__all__ = ["TrustedGitError", "TrustedGitProcessOwner", "TrustedGitProcessState"]
