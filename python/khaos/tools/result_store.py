"""Runtime-owned idempotent tool-result storage.

The durable operation row remains the restart authority. This store only
owns the bounded in-process cache used by callers that share one scheduler
runtime, including the result hand-off for a completed effect. It does not
claim operations, execute handlers, or decide whether a result is safe to
replay.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field

from khaos.exceptions import PermissionDeniedError
from khaos.security.protocol_boundary import canonical_digest
from khaos.tools.scheduler_models import ToolResult

DEFAULT_CACHE_LIMIT = 1024


@dataclass(slots=True)
class _CachedResult:
    """One bounded runtime result and the argument identity it represents."""

    arguments_digest: str
    result: ToolResult
    stored_at: float = field(default_factory=time.monotonic)


class ToolResultStore:
    """Own runtime-scoped idempotent result cache and synchronization."""

    def __init__(self, *, max_entries: int = DEFAULT_CACHE_LIMIT) -> None:
        if type(max_entries) is not int or max_entries <= 0:
            raise ValueError("max_entries must be a positive integer")
        self._max_entries = max_entries
        self._lock = asyncio.Lock()
        self._results: dict[str, _CachedResult] = {}

    @staticmethod
    def digest_arguments(arguments: object) -> str:
        """Return the canonical digest used to detect argument reuse."""
        return canonical_digest(arguments)

    async def get(self, operation_id: str, arguments_digest: str) -> ToolResult | None:
        """Return a cached result or reject a conflicting argument reuse."""
        if not operation_id:
            return None
        async with self._lock:
            cached = self._results.get(operation_id)
            if cached is None:
                return None
            if cached.arguments_digest != arguments_digest:
                raise PermissionDeniedError(
                    "idempotency key was reused with different tool arguments"
                )
            return cached.result

    async def put(
        self,
        operation_id: str,
        arguments_digest: str,
        result: ToolResult,
    ) -> None:
        """Store a result, evicting only the oldest unrelated cache entry."""
        if not operation_id:
            return
        async with self._lock:
            if (
                operation_id not in self._results
                and len(self._results) >= self._max_entries
            ):
                oldest = min(
                    self._results,
                    key=lambda item: self._results[item].stored_at,
                )
                self._results.pop(oldest, None)
            self._results[operation_id] = _CachedResult(
                arguments_digest=arguments_digest,
                result=result,
            )


__all__ = ["DEFAULT_CACHE_LIMIT", "ToolResultStore"]
