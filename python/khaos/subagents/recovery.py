"""Restart reconciliation for M8.5 child and merge projections."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from khaos.subagents.contracts import ChildWorkspaceState


@dataclass(frozen=True, slots=True)
class ParallelRecoveryReport:
    """Bounded recovery evidence; it never asserts successful completion."""

    inspected: int
    marked_unknown: int
    quarantined: int
    reasons: tuple[str, ...] = ()


class ParallelSubagentRecovery:
    """Reconcile unfinished durable state after a process restart."""

    def __init__(self, repository: Any) -> None:
        self.repository = repository

    async def reconcile(self) -> ParallelRecoveryReport:
        """Mark every unfinished child/merge unknown until re-proven."""
        records = await self.repository.incomplete()
        reasons: list[str] = []
        marked = 0
        quarantined = 0
        for record in records:
            identifier = str(record.get("assignment_id", ""))
            kind = str(record.get("kind", ""))
            state = str(record.get("state", ""))
            reason = "restart interrupted an unfinished M8.5 operation"
            if state in {"quarantined", "published-quarantined"}:
                # Quarantine is already the durable fail-closed projection.
                # Do not downgrade it to UNKNOWN or attempt an invalid
                # QUARANTINED -> UNKNOWN child transition on restart.
                quarantined += 1
                reasons.append(f"{kind}:{identifier}:quarantined")
                continue
            if kind == "child":
                if state != ChildWorkspaceState.UNKNOWN.value:
                    await self.repository.update_child_state(
                        identifier,
                        ChildWorkspaceState.UNKNOWN,
                        reason=reason,
                    )
            elif kind == "merge":
                await self.repository.mark_merge_recovery(identifier, reason)
            else:
                reasons.append(f"unknown recovery record kind: {kind}")
                quarantined += 1
                continue
            marked += 1
            reasons.append(f"{kind}:{identifier}:unknown")
        return ParallelRecoveryReport(
            inspected=len(records),
            marked_unknown=marked,
            quarantined=quarantined,
            reasons=tuple(reasons[:128]),
        )


__all__ = ["ParallelRecoveryReport", "ParallelSubagentRecovery"]
