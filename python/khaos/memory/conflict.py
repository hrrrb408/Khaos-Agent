"""Pure conflict-resolution policy for memory assertions."""

from __future__ import annotations

from dataclasses import dataclass

from khaos.memory.models import Memory


@dataclass(frozen=True, slots=True)
class ConflictDecision:
    """The result of comparing two assertions."""

    winner: Memory | None
    reason: str


class ConflictResolver:
    """Resolve memory conflicts without touching persistence."""

    @staticmethod
    def decide(new: Memory, existing: Memory) -> ConflictDecision:
        """Choose a winner using confidence, then explicit recency.

        An equal-confidence and equal-timestamp pair is intentionally
        unresolved.  If timestamps are absent, the incoming assertion is the
        current user statement and wins by the newest-information rule.
        """

        if new.confidence.value > existing.confidence.value:
            return ConflictDecision(new, "new_higher_confidence")
        if existing.confidence.value > new.confidence.value:
            return ConflictDecision(existing, "existing_higher_confidence")

        new_ts = new.updated_at
        existing_ts = existing.updated_at
        if new_ts is not None and existing_ts is not None:
            if new_ts < existing_ts:
                return ConflictDecision(existing, "new_explicitly_stale")
            if new_ts > existing_ts:
                return ConflictDecision(new, "newer_explicit_timestamp")
            return ConflictDecision(None, "equal_confidence_and_timestamp")
        return ConflictDecision(new, "new_current_assertion")


def resolve_conflict(new: Memory, existing: Memory) -> Memory | None:
    """Compatibility function for callers that only need the winner."""

    return ConflictResolver.decide(new, existing).winner


__all__ = ["ConflictDecision", "ConflictResolver", "resolve_conflict"]
