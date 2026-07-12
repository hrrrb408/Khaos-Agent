"""Server-side evaluation of whether a plan needs human approval.

The client can NEVER short-circuit approval. Whatever the client sends in
``approved``, ``requires_approval``, ``risk`` or ``status`` is ignored — this
module recomputes the authoritative decision from the final
:class:`ImplementationPlan` produced by the deterministic planning service.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

from khaos.coding.planning.approval.models import ApprovalRequirementOutcome

if TYPE_CHECKING:  # pragma: no cover - typing only
    from khaos.coding.planning.contracts import ImplementationPlan


# Risk levels that MUST trigger human approval regardless of other factors.
_HIGH_RISK_LEVELS = {"high", "critical"}

# Operations that are inherently destructive and require approval.
_DESTRUCTIVE_OPERATIONS = {"delete", "rename", "move"}

# Goal intents that always require approval (security/schema/credential/etc.).
_HIGH_RISK_INTENTS = {
    "security_change",
    "schema_change",
    "update_configuration",  # config / sandbox / network policy changes
}

# Risk categories that imply approval is mandatory.
_HIGH_RISK_CATEGORIES = {
    "security",
    "auth",
    "approval",
    "credential",
    "network",
    "sandbox",
    "schema",
    "migration",
}


def evaluate_approval_requirement(plan: "ImplementationPlan") -> ApprovalRequirementOutcome:
    """Recompute the authoritative approval requirement for a plan.

    Decision rules (a plan requires human approval if ANY is true):

    1. Any :class:`RiskAssessment` carries ``requires_approval=True``.
    2. Any risk ``level`` is ``high`` or ``critical``.
    3. Any risk ``category`` is in the mandatory-approval set
       (security/auth/credential/network/sandbox/schema/migration).
    4. Any affected file uses a destructive operation (delete/rename/move).
    5. Any plan step carries ``requires_approval=True``.
    6. The impact graph was truncated (incomplete blast radius).
    7. Any impact edge has a high-risk status (``ambiguous`` / ``dynamic``)
       that could hide a destructive downstream effect.

    A plan that does not require approval is still bound by the same digest
    and must still obtain a server-issued authorization before execution —
    the authorization just does not need a prior pending→approved round trip.
    """
    reason_codes: list[str] = []
    requires_approval = False

    # 1 & 2 & 3 — risk assessments
    for risk in plan.risks:
        if getattr(risk, "requires_approval", False):
            requires_approval = True
            reason_codes.append("risk.requires_approval")
        if str(risk.level).lower() in _HIGH_RISK_LEVELS:
            requires_approval = True
            reason_codes.append(f"risk.level:{risk.level}")
        if str(risk.category).lower() in _HIGH_RISK_CATEGORIES:
            requires_approval = True
            reason_codes.append(f"risk.category:{risk.category}")

    # 4 — destructive operations on affected files
    destructive_ops: set[str] = set()
    for affected in plan.affected_files:
        op_value = getattr(affected.operation, "value", str(affected.operation)).lower()
        if op_value in _DESTRUCTIVE_OPERATIONS:
            destructive_ops.add(op_value)
            requires_approval = True
            reason_codes.append(f"operation.destructive:{op_value}")

    # 5 — per-step approval flags
    for step in plan.steps:
        if getattr(step, "requires_approval", False):
            requires_approval = True
            reason_codes.append("step.requires_approval")

    # 6 — truncated impact graph
    for diagnostic in plan.diagnostics:
        # The planning service records impact-truncated diagnostics when the
        # traversal budget is exhausted.
        if getattr(diagnostic, "code", "") == "impact-truncated":
            requires_approval = True
            reason_codes.append("impact.truncated")

    # 7 — ambiguous / dynamic high-risk impact edges
    for impact in plan.dependency_impacts:
        status = str(getattr(impact, "status", "")).lower()
        if status in {"ambiguous", "dynamic"}:
            requires_approval = True
            reason_codes.append(f"impact.status:{status}")

    # Compute the authoritative risk level (highest across the plan).
    risk_level = _aggregate_risk_level(plan)

    requested_operations = tuple(
        sorted(
            {
                getattr(f.operation, "value", str(f.operation))
                for f in plan.affected_files
            }
        )
    )

    # De-duplicate reason codes while keeping them stable-sorted for audit.
    seen: set[str] = set()
    unique_codes: list[str] = []
    for code in sorted(reason_codes):
        if code not in seen:
            seen.add(code)
            unique_codes.append(code)

    if not requires_approval and not unique_codes:
        unique_codes = ["policy.low-risk-not-required"]

    return ApprovalRequirementOutcome(
        requires_approval=requires_approval,
        risk_level=risk_level,
        reason_codes=tuple(unique_codes),
        requested_operations=requested_operations,
    )


# Risk-level ordering used to aggregate the highest level across a plan.
_RISK_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}


def _aggregate_risk_level(plan: "ImplementationPlan") -> str:
    """Return the highest risk level present anywhere in the plan."""
    levels: list[str] = []
    for risk in plan.risks:
        levels.append(str(risk.level).lower())
    # Default to low when the planner produced no explicit risk assessments.
    if not levels:
        return "low"
    return max(levels, key=lambda lv: _RISK_RANK.get(lv, 0))
