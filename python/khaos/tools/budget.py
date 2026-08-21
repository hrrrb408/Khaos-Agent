"""Hard budgets used by tool admission and execution.

Budgets are a concurrency boundary, not a scheduler policy detail.  This
module owns reservation/commit semantics so serial and parallel dispatch share
one implementation and cannot accidentally oversubscribe the same limits.
"""

from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class ToolBudget:
    """Atomic hard budget shared by serial and parallel tool dispatch."""

    max_calls: int = 50
    max_output_chars: int = 100000
    max_batch_calls: int = 16
    max_parallel_calls: int = 8
    max_output_per_tool: int = 65536
    max_total_output: int = 100000
    max_background_processes: int = 4
    max_processes_per_workspace: int = 2
    max_browser_contexts: int = 4
    _call_count: int = 0
    _output_chars: int = 0
    _reserved_calls: int = 0
    _reserved_output: int = 0
    _parallel_active: int = 0
    _lock: asyncio.Lock = field(default_factory=asyncio.Lock, repr=False)

    @property
    def is_exhausted(self) -> bool:
        """Return true once call or output budget is exhausted."""
        return (
            self._call_count + self._reserved_calls >= self.max_calls
            or self._output_chars + self._reserved_output >= self._total_output_limit
        )

    @property
    def _total_output_limit(self) -> int:
        return min(self.max_output_chars, self.max_total_output)

    def validate_batch(self, size: int) -> bool:
        """Return whether a batch size is within the configured hard limit."""
        return 0 <= size <= self.max_batch_calls

    async def reserve(self, *, parallel: bool = False) -> ToolBudgetReservation | None:
        """Reserve one call and its maximum possible output.

        Reservation is atomic with respect to all other callers.  A caller
        must either ``commit`` with the measured output size or ``release``
        when dispatch never crosses the handler boundary.
        """
        async with self._lock:
            if self._call_count + self._reserved_calls >= self.max_calls:
                return None
            if parallel and self._parallel_active >= self.max_parallel_calls:
                return None
            remaining = (
                self._total_output_limit
                - self._output_chars
                - self._reserved_output
            )
            if remaining <= 0:
                return None
            output_limit = min(self.max_output_per_tool, remaining)
            self._reserved_calls += 1
            self._reserved_output += output_limit
            if parallel:
                self._parallel_active += 1
            return ToolBudgetReservation(self, output_limit, parallel)

    async def _finish(
        self, reservation: ToolBudgetReservation, *, output_chars: int | None
    ) -> None:
        async with self._lock:
            if not reservation.active:
                return
            reservation.active = False
            self._reserved_calls -= 1
            self._reserved_output -= reservation.output_limit
            if reservation.parallel:
                self._parallel_active -= 1
            if output_chars is not None:
                if output_chars > reservation.output_limit:
                    raise RuntimeError("tool output exceeded reserved hard budget")
                self._call_count += 1
                self._output_chars += output_chars

    def record(self, output_chars: int) -> None:
        """Compatibility hook for trusted single-threaded callers."""
        self._call_count += 1
        self._output_chars += output_chars


@dataclass
class ToolBudgetReservation:
    """One active reservation held by a dispatch task."""

    budget: ToolBudget
    output_limit: int
    parallel: bool
    active: bool = True

    async def commit(self, output_chars: int) -> None:
        await self.budget._finish(self, output_chars=output_chars)

    async def release(self) -> None:
        await self.budget._finish(self, output_chars=None)


class ToolOutputBudgetExceeded(RuntimeError):
    """Raised without materializing an output larger than its reservation."""


def measure_tool_output(
    value: Any,
    limit: int,
    *,
    _depth: int = 0,
    _seen: set[int] | None = None,
) -> int:
    """Measure JSON-compatible output incrementally and stop at ``limit``.

    The function deliberately accepts only JSON-compatible values.  It keeps
    output accounting bounded before serialization, detects cycles, and
    rejects excessive nesting instead of relying on an unbounded ``str`` or
    ``json.dumps`` allocation.
    """
    if _depth > 64:
        raise ToolOutputBudgetExceeded("tool output nesting exceeds 64 levels")
    if value is None:
        size = 4
    elif isinstance(value, bool):
        size = 4 if value else 5
    elif isinstance(value, (int, float)):
        size = len(json.dumps(value, allow_nan=False))
    elif isinstance(value, str):
        # json.dumps would allocate an escaped copy.  Reject obviously large
        # strings first; accepted strings are at most one reservation.
        if len(value) > limit:
            raise ToolOutputBudgetExceeded(
                "tool output exceeded reserved hard budget"
            )
        size = len(json.dumps(value, ensure_ascii=False))
    elif isinstance(value, Path):
        path_text = str(value)
        if len(path_text) > limit:
            raise ToolOutputBudgetExceeded(
                "tool output exceeded reserved hard budget"
            )
        size = len(json.dumps(path_text, ensure_ascii=False))
    elif isinstance(value, (list, tuple, dict)):
        seen = _seen if _seen is not None else set()
        identity = id(value)
        if identity in seen:
            raise ToolOutputBudgetExceeded("tool output contains a cycle")
        seen.add(identity)
        try:
            size = 2
            if isinstance(value, dict):
                iterator = value.items()
                for index, (key, item) in enumerate(iterator):
                    if not isinstance(key, str):
                        raise ToolOutputBudgetExceeded(
                            "tool output object keys must be strings"
                        )
                    size += (1 if index else 0) + len(
                        json.dumps(key, ensure_ascii=False)
                    ) + 1
                    if size > limit:
                        raise ToolOutputBudgetExceeded(
                            "tool output exceeded reserved hard budget"
                        )
                    size += measure_tool_output(
                        item,
                        limit - size,
                        _depth=_depth + 1,
                        _seen=seen,
                    )
            else:
                for index, item in enumerate(value):
                    size += 1 if index else 0
                    if size > limit:
                        raise ToolOutputBudgetExceeded(
                            "tool output exceeded reserved hard budget"
                        )
                    size += measure_tool_output(
                        item,
                        limit - size,
                        _depth=_depth + 1,
                        _seen=seen,
                    )
        finally:
            seen.remove(identity)
    else:
        raise ToolOutputBudgetExceeded(
            f"tool output type is not JSON-compatible: {type(value).__name__}"
        )
    if size > limit:
        raise ToolOutputBudgetExceeded("tool output exceeded reserved hard budget")
    return size


# Private compatibility spelling used by the pre-refactor scheduler.
_measure_tool_output = measure_tool_output
