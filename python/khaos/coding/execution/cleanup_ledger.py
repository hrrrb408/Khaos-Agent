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

Round-17 review §六: the ledger now also offers :meth:`run_step` — a
unified ``action → verify → mark_done`` abstraction that owns the
postcondition check, generation tracking, and CancelledError semantics.
Callers that adopt ``run_step`` can no longer forget a postcondition or
swallow a CancelledError into a false ``mark_done``.  Existing callers
that use ``mark_done`` / ``record_error`` directly remain supported
(backward compatible); ``run_step`` is the recommended abstraction for
new cleanup sequences.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from typing import Any


class CleanupInvariantError(RuntimeError):
    """Round-17 review §六: raised/recorded when a cleanup step's action
    returned successfully but the verified postcondition does not hold.

    This is a contract violation: the action claimed success, but the
    resource is NOT proven terminal.  The step must NOT be marked done —
    the owner must enter QUARANTINED and retry.  ``CleanupInvariantError``
    makes "action returned but resource still alive" visible instead of
    silently transitioning to CLOSED.
    """


class CleanupLedger:
    """Tracks per-step completion so retryable cleanup only runs failed steps.

    Invariants:
      - ``is_done(step)`` is sticky: once ``True`` it stays ``True`` across
        retries (a successfully-completed step is never redone) — UNLESS
        the resource generation changed (see ``run_step``), in which case
        the prior completion is invalidated because it referenced a
        different resource instance.
      - ``record_error(step, exc)`` is NOT sticky across attempts: a
        successful retry clears the prior error via ``mark_done``.
      - The ledger is not thread-safe; it is intended for single-loop
        asyncio cleanup sequences that are already serialised by a shared
        shutdown/finalize task.
    """

    __slots__ = ("_completed", "_errors", "_generations")

    def __init__(self) -> None:
        self._completed: set[str] = set()
        self._errors: dict[str, BaseException] = {}
        # Round-17 review §六: per-step resource generation.  When a step
        # is marked done, the generation passed to ``run_step`` (or
        # ``mark_done_with_generation``) is recorded.  On a subsequent
        # ``run_step`` call, if the current generation differs from the
        # recorded one, the prior DONE is invalidated — the step referenced
        # a resource instance (e.g., a listener) that has since been
        # replaced, so the DONE must not cause the new instance to be
        # skipped.  This closes the "stale DONE" bug identified in
        # round-17 review §五 for BrowserEgressProxy.
        self._generations: dict[str, Any] = {}

    def is_done(self, step: str) -> bool:
        """True iff ``step`` completed successfully on a prior attempt."""
        return step in self._completed

    def mark_done(self, step: str) -> None:
        """Record that ``step`` completed successfully.

        Clears any prior error for this step so ``has_errors`` reflects
        only the current attempt's failures.  Does NOT clear a recorded
        generation — use ``mark_done_with_generation`` to also record the
        resource generation, or ``run_step`` which does both.
        """
        self._completed.add(step)
        self._errors.pop(step, None)

    def mark_done_with_generation(
        self, step: str, generation: Any | None,
    ) -> None:
        """Record ``step`` done AND bind the completion to ``generation``.

        Round-17 review §六: a subsequent ``run_step`` call with a
        different ``resource_generation`` invalidates this DONE so the
        step is re-run for the new resource instance.
        """
        self._completed.add(step)
        self._errors.pop(step, None)
        if generation is not None:
            self._generations[step] = generation
        else:
            self._generations.pop(step, None)

    def generation_of(self, step: str) -> Any | None:
        """Return the resource generation recorded for ``step``, or None."""
        return self._generations.get(step)

    def invalidate(self, step: str) -> None:
        """Force ``step`` to be re-run on the next attempt.

        Removes ``step`` from the completed set and clears its recorded
        generation.  Callers use this when they know the resource has
        changed independently of ``run_step`` (e.g., a listener was
        reopened directly).
        """
        self._completed.discard(step)
        self._generations.pop(step, None)
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

    async def run_step(
        self,
        step: str,
        *,
        action: Callable[[], Awaitable[None]],
        verify: Callable[[], bool] | None = None,
        resource_generation: Any | None = None,
    ) -> bool:
        """Run one cleanup step with postcondition verification.

        Round-17 review §六: the unified ``action → verify → mark_done``
        abstraction.  The ledger owns the sequence so callers cannot
        forget a postcondition, swallow a CancelledError into a false
        ``mark_done``, or skip a step whose prior DONE referenced a
        different resource instance.

        Semantics:

        - **Skip**: if ``step`` is already done AND (no generation
          tracking is used OR the recorded generation equals
          ``resource_generation``), return ``True`` immediately without
          calling ``action``.

        - **Stale DONE**: if ``step`` is already done BUT the recorded
          generation differs from ``resource_generation``, the prior
          completion is invalidated (the resource instance it referenced
          has been replaced).  The step is re-run from scratch.

        - **CancelledError**: recorded as an error (ownership release is
          unproven → the caller must enter QUARANTINED), then re-raised
          so the caller's cleanup loop can abort.  Callers that want to
          attempt remaining steps despite cancellation must wrap each
          ``run_step`` call in ``asyncio.shield`` — but note that a
          shielded step whose own internals raise CancelledError will
          still record+re-raise.  The ledger NEVER marks the step done
          on CancelledError.

        - **Other Exception**: recorded as an error; returns ``False``
          so the caller can continue to the next step and collect all
          errors.

        - **Success + ``verify`` True**: ``mark_done`` (with generation);
          returns ``True``.

        - **Success + ``verify`` False (or ``verify`` raises)**:
          ``CleanupInvariantError`` is recorded; returns ``False``.  The
          step is NOT marked done — "action returned but resource still
          alive" is a contract violation that must enter QUARANTINED,
          not CLOSED.

        Returns ``True`` iff the step is now done (either it was already
        done for the same generation, or this call completed it
        successfully and the postcondition held).
        """
        # Skip if already done for the same (or untracked) generation.
        if step in self._completed:
            if resource_generation is not None:
                recorded = self._generations.get(step)
                if recorded is not None and recorded != resource_generation:
                    # Stale DONE — the resource instance has changed.
                    # Invalidate so the step is re-run for the new
                    # instance.  This closes the round-17 review §五
                    # "stale DONE" bug where a partial close + reopen
                    # produced a new listener that the retry's ledger
                    # skipped.
                    self._completed.discard(step)
                    self._generations.pop(step, None)
                    self._errors.pop(step, None)
                else:
                    return True
            else:
                return True

        try:
            await action()
        except asyncio.CancelledError:
            # Ownership release unproven — record and re-raise so the
            # caller enters QUARANTINED.  The ledger does NOT mark done.
            self._errors[step] = RuntimeError(
                f"{step} cancelled — ownership release unproven"
            )
            raise
        except Exception as exc:  # noqa: BLE001 — collect, don't abort
            self._errors[step] = exc
            return False

        # Action succeeded — verify the postcondition if provided.
        if verify is not None:
            try:
                verified = verify()
            except Exception as exc:  # noqa: BLE001 — verify contract error
                self._errors[step] = CleanupInvariantError(
                    f"{step} verify() raised: {exc!r}"
                )
                return False
            if not verified:
                self._errors[step] = CleanupInvariantError(
                    f"{step} postcondition not met after successful action"
                )
                return False

        self._completed.add(step)
        self._errors.pop(step, None)
        if resource_generation is not None:
            self._generations[step] = resource_generation
        else:
            self._generations.pop(step, None)
        return True
