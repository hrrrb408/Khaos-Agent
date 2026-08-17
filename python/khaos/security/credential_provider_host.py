# KHAOS-PRIVILEGED-SPAWN owner=CredentialProviderHost threat-model=contained-blocking-provider boundary=killable-worker-child
"""Killable subprocess containment for blocking credential providers.

A synchronous provider loader that hangs forever cannot be reclaimed at
Python thread level — ``Thread.terminate`` does not exist and the broker
correctly refuses to report a false terminal state while the thread lives.
This host moves one provider materialization into a dedicated child
process (``python -m khaos.security.credential_provider_worker``) and owns
the full termination ladder::

    deadline breach / close request
        → SIGTERM
        → grace period
        → SIGKILL
        → wait()            (waitpid terminal proof)

so logical cancellation becomes physical resource reclamation with a
bounded wall-clock cost and without exiting the trusted runtime process.

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
import sys
from collections.abc import Mapping

from khaos.security.credential_provider_worker import (
    environment_passthrough_names,
)

logger = logging.getLogger(__name__)

_WORKER_MODULE = "khaos.security.credential_provider_worker"
_DEFAULT_STARTUP_DEADLINE = 10.0
_DEFAULT_TERMINATION_GRACE = 2.0
_DEFAULT_KILL_GRACE = 5.0
_MAX_RESPONSE_BYTES = 1 * 1024 * 1024


class CredentialProviderHostError(PermissionError):
    """Raised when a contained provider host cannot deliver material."""


class CredentialProviderHost:
    """Own one child process executing exactly one provider spec."""

    def __init__(
        self,
        *,
        python_executable: str | None = None,
        startup_deadline: float = _DEFAULT_STARTUP_DEADLINE,
        termination_grace: float = _DEFAULT_TERMINATION_GRACE,
        kill_grace: float = _DEFAULT_KILL_GRACE,
    ) -> None:
        if startup_deadline <= 0 or termination_grace < 0 or kill_grace <= 0:
            raise ValueError("credential provider host deadlines must be positive")
        self._python = python_executable or sys.executable or "python3"
        self._startup_deadline = startup_deadline
        self._termination_grace = termination_grace
        self._kill_grace = kill_grace
        self._process: asyncio.subprocess.Process | None = None

    @property
    def pid(self) -> int | None:
        process = self._process
        if process is None:
            return None
        return process.pid

    @property
    def alive(self) -> bool:
        """True while the owned child has not been proven terminal."""
        process = self._process
        return process is not None and process.returncode is None

    async def materialize(
        self, spec: Mapping[str, object], *, deadline: float
    ) -> dict[str, str]:
        """Run one spec in a fresh child and return its environment material.

        ``deadline`` bounds spawn, request, and response combined.  Any
        breach — or a caller-side task cancellation — escalates the
        termination ladder, so this coroutine never returns or raises
        while the child is still alive.
        """
        if deadline <= 0:
            raise CredentialProviderHostError(
                "credential provider host deadline must be positive"
            )
        request = json.dumps({"spec": dict(spec)}, ensure_ascii=False)
        environment = self._worker_environment(spec)
        try:
            self._process = await asyncio.create_subprocess_exec(
                self._python,
                "-m",
                _WORKER_MODULE,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
                env=environment,
                limit=_MAX_RESPONSE_BYTES,
            )
        except OSError as exc:
            raise CredentialProviderHostError(
                f"credential provider host could not start: {exc}"
            ) from exc
        try:
            try:
                material = await asyncio.wait_for(
                    self._exchange(request), timeout=deadline
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
        """Ask the child to stop without waiting; thread-safe for close().

        Signals the owned pid directly.  The pid cannot be reused while
        the host still owns the un-reaped child, so a late signal can only
        reach this child (or its zombie, where it is a no-op).
        """
        process = self._process
        if process is None or process.returncode is not None:
            return
        try:
            os.kill(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        except OSError as exc:
            logger.warning(
                "credential provider host termination signal failed: %s", exc
            )

    def _worker_environment(self, spec: Mapping[str, object]) -> dict[str, str]:
        """Give the worker only PATH plus the variables its spec reads."""
        environment = {"PATH": os.environ.get("PATH", "")}
        for name in sorted(environment_passthrough_names(spec)):
            value = os.environ.get(name)
            if value is not None:
                environment[name] = value
        return environment

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

    async def _terminate(self) -> None:
        """Run the full TERM → grace → KILL ladder and prove termination."""
        process = self._process
        if process is None:
            return
        if process.returncode is None:
            try:
                process.terminate()
            except ProcessLookupError:
                pass
            try:
                await asyncio.wait_for(
                    process.wait(), timeout=self._termination_grace
                )
            except TimeoutError:
                try:
                    process.kill()
                except ProcessLookupError:
                    pass
                try:
                    await asyncio.wait_for(process.wait(), timeout=self._kill_grace)
                except TimeoutError:
                    # The child ignored SIGKILL-equivalent escalation; only
                    # kernel-level stop can hold a pid past this point.  The
                    # host must not claim terminal proof it does not have.
                    raise CredentialProviderHostError(
                        "credential provider host could not prove child termination"
                    )
        if process.returncode is None:
            raise CredentialProviderHostError(
                "credential provider host child termination is unproven"
            )


__all__ = [
    "CredentialProviderHost",
    "CredentialProviderHostError",
]
