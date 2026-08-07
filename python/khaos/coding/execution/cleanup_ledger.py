"""Per-step completion ledger for retryable cleanup sequences.

Batch 15.3 (round-15 review §八/§九/§十/§十二): ``QUARANTINED`` was previously
a permanent failure state — a second cleanup call re-raised the original
error and never attempted the remaining steps.  The ledger records which
steps have completed successfully so a retry only runs the incomplete ones.

This converts ``QUARANTINED`` from a "permanent graveyard" into a "retained
resource owner" that can make forward progress on retry, aligning with the
Browser threat model: *"Partial cleanup remains registered and makes
shutdown fail until a retry succeeds; it is never reported as closed."*

The ledger is intentionally minimal: a set of completed step names plus a
map of step → last error.  Callers name their own steps; the ledger does
not impose a schema.  This keeps it usable across ExecutionService,
ManagedProcessHandle, LspClient, and BrowserEgressProxy without those
modules needing to know about each other's step taxonomy.
"""

from __future__ import annotations


class CleanupLedger:
    """Tracks per-step completion so retryable cleanup only runs failed steps.

    Invariants:
      - ``is_done(step)`` is sticky: once ``True`` it stays ``True`` across
        retries (a successfully-completed step is never redone).
      - ``record_error(step, exc)`` is NOT sticky across attempts: a
        successful retry clears the prior error via ``mark_done``.
      - The ledger is not thread-safe; it is intended for single-loop
        asyncio cleanup sequences that are already serialised by a shared
        shutdown/finalize task.
    """

    __slots__ = ("_completed", "_errors")

    def __init__(self) -> None:
        self._completed: set[str] = set()
        self._errors: dict[str, BaseException] = {}

    def is_done(self, step: str) -> bool:
        """True iff ``step`` completed successfully on a prior attempt."""
        return step in self._completed

    def mark_done(self, step: str) -> None:
        """Record that ``step`` completed successfully.

        Clears any prior error for this step so ``has_errors`` reflects
        only the current attempt's failures.
        """
        self._completed.add(step)
        self._errors.pop(step, None)

    def record_error(self, step: str, error: BaseException) -> None:
        """Record that ``step`` failed (without raising).

        The error is kept so the caller can build a typed aggregate error
        after all steps have been attempted.  A subsequent successful
        retry of the same step clears the error via ``mark_done``.
        """
        self._errors[step] = error

    def clear_error(self, step: str) -> None:
        """Clear a prior error for ``step`` (e.g., before a retry)."""
        self._errors.pop(step, None)

    @property
    def errors(self) -> tuple[BaseException, ...]:
        """The errors from the most recent attempt, in insertion order."""
        return tuple(self._errors.values())

    @property
    def failed_steps(self) -> tuple[str, ...]:
        """The steps that failed on the most recent attempt."""
        return tuple(self._errors.keys())

    def has_errors(self) -> bool:
        """True iff any step failed on the most recent attempt."""
        return bool(self._errors)

    def pending(self, all_steps: tuple[str, ...]) -> tuple[str, ...]:
        """Return the subset of ``all_steps`` not yet completed."""
        return tuple(s for s in all_steps if s not in self._completed)

    def reset_errors(self) -> None:
        """Clear all recorded errors (called at the start of a retry)."""
        self._errors.clear()
