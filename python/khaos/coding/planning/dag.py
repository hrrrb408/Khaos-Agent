"""Deterministic, read-only validation for implementation-plan step DAGs."""
from __future__ import annotations
from khaos.coding.planning.contracts import PlanDiagnostic, PlanOperation, PlanStep

def validate_steps(steps: tuple[PlanStep, ...]) -> tuple[PlanDiagnostic, ...]:
    seen=set(); diagnostics=[]; ids={step.step_id for step in steps}
    for step in steps:
        if step.step_id in seen: diagnostics.append(PlanDiagnostic("duplicate-step-id","error",step.step_id,False))
        seen.add(step.step_id)
        for dependency in step.depends_on:
            if dependency not in ids: diagnostics.append(PlanDiagnostic("missing-step-dependency","error",dependency,False))
            if dependency == step.step_id: diagnostics.append(PlanDiagnostic("self-step-dependency","error",dependency,False))
        if step.operation in (PlanOperation.DELETE, PlanOperation.RENAME) and not step.depends_on:
            diagnostics.append(PlanDiagnostic("destructive-without-inspection","error",step.step_id,False))
    graph={step.step_id:set(step.depends_on) for step in steps}
    while graph:
        ready=sorted(key for key,value in graph.items() if not value)
        if not ready:
            diagnostics.append(PlanDiagnostic("step-cycle","error","cycle detected",False)); break
        for key in ready: graph.pop(key)
        for value in graph.values(): value.difference_update(ready)
    return tuple(diagnostics)
