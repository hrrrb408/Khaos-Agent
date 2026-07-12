"""Authoritative plan snapshot source (spec §5).

The execution gate must validate against the server-authoritative plan
snapshot — never against a caller-supplied :class:`ImplementationPlan`
object. A caller can construct a frozen dataclass copy with mutated fields,
but that copy has no entry in the :class:`PlanSnapshotStore` and so the gate
cannot resolve it by ``plan_id``.

In production this will be backed by a persisted plan store; for Batch 2.1
an in-memory implementation is sufficient and keeps the contract honest.
"""
from __future__ import annotations

from typing import Protocol, TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover - typing only
    from khaos.coding.planning.contracts import ImplementationPlan


class PlanRepository(Protocol):
    """Read-only authoritative source of plan snapshots by plan_id."""

    def get(self, plan_id: str) -> "ImplementationPlan | None":  # pragma: no cover
        ...


class PlanSnapshotStore:
    """In-memory authoritative plan registry.

    Plans are registered by the planning service / approval service when a
    request is created. The gate resolves plans exclusively through this
    store so a caller cannot influence validation by passing a mutated plan.
    """

    def __init__(self) -> None:
        self._snapshots: dict[str, "ImplementationPlan"] = {}

    def register(self, plan: "ImplementationPlan") -> None:
        """Register (or replace) the authoritative snapshot for a plan_id."""
        self._snapshots[plan.plan_id] = plan

    def get(self, plan_id: str) -> "ImplementationPlan | None":
        return self._snapshots.get(plan_id)

    def require(self, plan_id: str) -> "ImplementationPlan":
        """Return the snapshot or raise KeyError (caller surfaces as a refusal)."""
        plan = self._snapshots.get(plan_id)
        if plan is None:
            raise KeyError(plan_id)
        return plan

    def clear(self) -> None:
        self._snapshots.clear()
