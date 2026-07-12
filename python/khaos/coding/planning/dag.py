"""Deterministic validation and sorting for implementation-plan step DAGs."""
from __future__ import annotations

from khaos.coding.planning.contracts import PlanDiagnostic, PlanOperation, PlanStep

MODIFICATION_OPERATIONS = {
    PlanOperation.MODIFY, PlanOperation.CREATE, PlanOperation.DELETE,
    PlanOperation.RENAME, PlanOperation.CONFIGURE, PlanOperation.DOCUMENT,
}

class InvalidPlanDagError(ValueError):
    def __init__(self, diagnostics: tuple[PlanDiagnostic, ...]) -> None:
        super().__init__("invalid implementation-plan DAG")
        self.diagnostics = diagnostics

def _inspection_ancestor(step_id: str, by_id: dict[str, PlanStep]) -> bool:
    pending = sorted(by_id[step_id].depends_on); seen: set[str] = set()
    while pending:
        current = pending.pop(0)
        if current in seen or current not in by_id: continue
        seen.add(current)
        if by_id[current].operation is PlanOperation.INSPECT: return True
        pending.extend(sorted(by_id[current].depends_on))
    return False

def _ancestors(step_id: str, by_id: dict[str, PlanStep]) -> tuple[PlanStep, ...]:
    pending = sorted(by_id[step_id].depends_on); seen: set[str] = set(); result=[]
    while pending:
        current = pending.pop(0)
        if current in seen or current not in by_id: continue
        seen.add(current); result.append(by_id[current]); pending.extend(sorted(by_id[current].depends_on))
    return tuple(sorted(result, key=lambda item: item.step_id))

def validate_steps(steps: tuple[PlanStep, ...]) -> tuple[PlanDiagnostic, ...]:
    diagnostics: list[PlanDiagnostic] = []
    counts: dict[str, int] = {}
    for step in steps: counts[step.step_id] = counts.get(step.step_id, 0) + 1
    for step_id in sorted(key for key, count in counts.items() if count > 1):
        diagnostics.append(PlanDiagnostic("duplicate-step-id", "error", step_id, False))
    unique = {step.step_id: step for step in sorted(steps, key=lambda item: item.step_id) if counts[step.step_id] == 1}
    valid_edges: dict[str, set[str]] = {step_id: set() for step_id in unique}
    for step_id in sorted(unique):
        step = unique[step_id]
        for dependency in sorted(set(step.depends_on)):
            if dependency not in unique:
                diagnostics.append(PlanDiagnostic("missing-step-dependency", "error", f"{step_id}:{dependency}", False))
            elif dependency == step_id:
                diagnostics.append(PlanDiagnostic("self-step-dependency", "error", step_id, False))
            else:
                valid_edges[step_id].add(dependency)
        if step.operation in MODIFICATION_OPERATIONS and not _inspection_ancestor(step_id, unique):
            code = "destructive-without-inspection" if step.operation in (PlanOperation.DELETE, PlanOperation.RENAME) else "invalid-operation-order"
            diagnostics.append(PlanDiagnostic(code, "error", step_id, False))
        ancestors = _ancestors(step_id, unique)
        is_verification = step.step_id.startswith("verify") or bool(step.verification_requirements)
        if is_verification:
            modifications = [item for item in ancestors if item.operation in MODIFICATION_OPERATIONS or (item.operation is PlanOperation.TEST and not item.step_id.startswith("verify"))]
            if not modifications:
                diagnostics.append(PlanDiagnostic("invalid-operation-order", "error", step_id, False))
            elif not any(set(step.target_files) & set(item.target_files) or set(step.target_symbols) & set(item.target_symbols) for item in modifications):
                diagnostics.append(PlanDiagnostic("unrelated-verification-target", "error", step_id, False))
        if step.operation in MODIFICATION_OPERATIONS and any(item.operation is PlanOperation.TEST and (item.step_id.startswith("verify") or item.verification_requirements) for item in ancestors):
            diagnostics.append(PlanDiagnostic("invalid-operation-order", "error", step_id, False))
    graph = {key: set(value) for key, value in valid_edges.items()}
    while graph:
        ready = sorted(key for key, value in graph.items() if not value)
        if not ready:
            diagnostics.append(PlanDiagnostic("step-cycle", "error", ",".join(sorted(graph)), False)); break
        for key in ready: graph.pop(key)
        for value in graph.values(): value.difference_update(ready)
    return tuple(sorted(diagnostics, key=lambda item: (item.code, item.message)))

def topologically_sort_steps(steps: tuple[PlanStep, ...]) -> tuple[PlanStep, ...]:
    diagnostics = validate_steps(steps)
    if diagnostics: raise InvalidPlanDagError(diagnostics)
    by_id = {step.step_id: step for step in steps}
    graph = {key: set(step.depends_on) for key, step in by_id.items()}; result=[]
    while graph:
        ready = sorted(key for key, value in graph.items() if not value)
        for key in ready: result.append(by_id[key]); graph.pop(key)
        for value in graph.values(): value.difference_update(ready)
    return tuple(result)
