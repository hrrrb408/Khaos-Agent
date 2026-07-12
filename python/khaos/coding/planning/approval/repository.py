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

from typing import Any, Protocol, TYPE_CHECKING

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

    NOTE (Batch 2.2): for restart durability use :class:`PersistedPlanRepository`
    instead — this in-memory store loses its snapshots on process restart.
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


class PersistedPlanRepository:
    """Durable authoritative plan registry backed by ``plan_snapshots``.

    Survives process restart. A plan_id cannot be silently replaced with
    different content (``register`` refuses and returns False if a snapshot
    with the same plan_id and a different content_hash already exists).

    The canonical JSON is a deterministic serialization of the plan body
    (no source code, no absolute host paths) that can be deserialized back
    into an :class:`ImplementationPlan` for re-validation.
    """

    SCHEMA_VERSION = "khaos.planning.v1"

    def __init__(self, store: Any) -> None:
        self._store = store
        # Cache deserialized plans so repeated lookups don't re-parse JSON.
        self._cache: dict[str, "ImplementationPlan"] = {}

    def register(self, plan: "ImplementationPlan") -> bool:
        """Persist the authoritative snapshot. Returns False if a snapshot
        with the same plan_id but DIFFERENT content_hash already exists
        (refused — use a new plan_id)."""
        from khaos.coding.planning.approval.models import compute_plan_binding_digest

        canonical = self._canonicalize(plan)
        binding_digest = compute_plan_binding_digest(plan)
        ok = self._store.save_plan_snapshot(
            plan_id=plan.plan_id,
            content_hash=plan.content_hash,
            binding_digest=binding_digest,
            repository_id=plan.repository_id,
            task_id=plan.task_id,
            workspace_id=plan.workspace_id,
            canonical_plan_json=canonical,
            schema_version=self.SCHEMA_VERSION,
        )
        if ok:
            self._cache[plan.plan_id] = plan
        return ok

    def get(self, plan_id: str) -> "ImplementationPlan | None":
        if plan_id in self._cache:
            return self._cache[plan_id]
        row = self._store.load_plan_snapshot(plan_id)
        if row is None:
            return None
        canonical_json, _content_hash, _binding = row
        plan = self._deserialize(canonical_json)
        if plan is not None:
            self._cache[plan.plan_id] = plan
        return plan

    def require(self, plan_id: str) -> "ImplementationPlan":
        plan = self.get(plan_id)
        if plan is None:
            raise KeyError(plan_id)
        return plan

    @staticmethod
    def _canonicalize(plan: "ImplementationPlan") -> str:
        """Deterministic JSON serialization of the plan body.

        Only includes the fields needed for binding/identity — NEVER source
        code text, credentials, or absolute host paths. The full dataclass
        is serialized so deserialize() can reconstruct it.
        """
        import json
        from dataclasses import asdict

        return json.dumps(asdict(plan), default=str, sort_keys=True, separators=(",", ":"))

    @staticmethod
    def _deserialize(canonical_json: str) -> "ImplementationPlan | None":
        """Reconstruct an ImplementationPlan from its canonical JSON."""
        import json

        from khaos.coding.planning.contracts import (
            AffectedFile,
            AffectedSymbol,
            DependencyImpact,
            ImplementationPlan,
            PlanDiagnostic,
            PlanEvidence,
            PlanOperation,
            PlanStatus,
            PlanStep,
            RiskAssessment,
            VerificationRequirement,
        )

        try:
            data = json.loads(canonical_json)
        except Exception:
            return None

        def _tuple_of(cls, items):
            out = []
            for item in items or ():
                if cls is PlanStep:
                    risk = RiskAssessment(**item["risk"])
                    out.append(PlanStep(
                        step_id=item["step_id"], title=item["title"],
                        description=item["description"],
                        operation=PlanOperation(item["operation"]),
                        target_files=tuple(item.get("target_files", ())),
                        target_symbols=tuple(item.get("target_symbols", ())),
                        depends_on=tuple(item.get("depends_on", ())),
                        expected_outcome=item["expected_outcome"],
                        verification_requirements=tuple(
                            VerificationRequirement(
                                command=tuple(v["command"]) if v.get("command") else None,
                                verification_type=v["verification_type"],
                                scope=v["scope"], expected_result=v["expected_result"],
                                required=v["required"], risk_level=v["risk_level"],
                                evidence=tuple(PlanEvidence(**e) for e in v.get("evidence", ())),
                            ) for v in item.get("verification_requirements", ())
                        ),
                        risk=risk, requires_approval=item["requires_approval"],
                        evidence=tuple(PlanEvidence(**e) for e in item.get("evidence", ())),
                    ))
                elif cls is AffectedFile:
                    out.append(AffectedFile(
                        path=item["path"],
                        operation=PlanOperation(item["operation"]),
                        reason=item["reason"], confidence=item["confidence"],
                        exists=item["exists"], language=item.get("language"),
                        evidence=tuple(PlanEvidence(**e) for e in item.get("evidence", ())),
                        source_path=item.get("source_path"),
                        destination_path=item.get("destination_path"),
                    ))
                elif cls is AffectedSymbol:
                    out.append(AffectedSymbol(
                        stable_symbol_id=item.get("stable_symbol_id"),
                        qualified_name=item["qualified_name"], kind=item["kind"],
                        path=item["path"], impact_type=item["impact_type"],
                        confidence=item["confidence"],
                        evidence=tuple(PlanEvidence(**e) for e in item.get("evidence", ())),
                        requested_new_name=item.get("requested_new_name"),
                    ))
                elif cls is DependencyImpact:
                    out.append(DependencyImpact(**item))
                elif cls is PlanDiagnostic:
                    out.append(PlanDiagnostic(
                        code=item["code"], severity=item["severity"],
                        message=item["message"], recoverable=item["recoverable"],
                        evidence=tuple(PlanEvidence(**e) for e in item.get("evidence", ())),
                    ))
                elif cls is RiskAssessment:
                    out.append(RiskAssessment(**item))
                elif cls is VerificationRequirement:
                    out.append(VerificationRequirement(
                        command=tuple(item["command"]) if item.get("command") else None,
                        verification_type=item["verification_type"],
                        scope=item["scope"], expected_result=item["expected_result"],
                        required=item["required"], risk_level=item["risk_level"],
                        evidence=tuple(PlanEvidence(**e) for e in item.get("evidence", ())),
                    ))
                elif cls is PlanEvidence:
                    out.append(PlanEvidence(**item))
            return out

        try:
            return ImplementationPlan(
                plan_id=data["plan_id"], repository_id=data["repository_id"],
                task_id=data["task_id"], workspace_id=data["workspace_id"],
                user_goal=data["user_goal"], normalized_goal=data["normalized_goal"],
                base_sha=data["base_sha"],
                repository_generation=int(data["repository_generation"]),
                status=PlanStatus(data["status"]),
                summary=data["summary"],
                steps=tuple(_tuple_of(PlanStep, data.get("steps", ()))),
                affected_files=tuple(_tuple_of(AffectedFile, data.get("affected_files", ()))),
                affected_symbols=tuple(_tuple_of(AffectedSymbol, data.get("affected_symbols", ()))),
                dependency_impacts=tuple(_tuple_of(DependencyImpact, data.get("dependency_impacts", ()))),
                verification_requirements=tuple(_tuple_of(VerificationRequirement, data.get("verification_requirements", ()))),
                risks=tuple(_tuple_of(RiskAssessment, data.get("risks", ()))),
                diagnostics=tuple(_tuple_of(PlanDiagnostic, data.get("diagnostics", ()))),
                evidence=tuple(_tuple_of(PlanEvidence, data.get("evidence", ()))),
                content_hash=data.get("content_hash", ""),
                created_at=float(data.get("created_at", 0.0)),
            )
        except Exception:
            return None
