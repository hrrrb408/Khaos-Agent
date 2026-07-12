"""Deterministic implementation-plan risk propagation."""
from __future__ import annotations
from khaos.coding.planning.contracts import ImpactAnalysis, PlanOperation, RiskAssessment

_LEVELS=("low","medium","high","critical")
class RiskEvaluator:
    def evaluate(self, operation: PlanOperation, goal: str, impact: ImpactAnalysis, *, public: bool, has_tests: bool, paths: tuple[str, ...]) -> RiskAssessment:
        text=goal.casefold(); level=0; categories=[]
        if public: level=max(level,2); categories.append("public-api")
        if public and len({x.source_file for x in impact.direct_impacts}) > 1: level=max(level,2)
        if operation in (PlanOperation.DELETE, PlanOperation.RENAME): level=max(level,2); categories.append("destructive")
        if impact.dynamic_impacts: level=max(level,1); categories.append("dynamic")
        if impact.truncated: level=max(level,2 if public else 1); categories.append("truncated")
        if not has_tests: level=max(level,1); categories.append("test-gap")
        if any(word in text for word in ("schema","migration")): level=max(level,2); categories.append("schema")
        if any(word in text for word in ("security","auth","approval","credential","network","sandbox")): level=3; categories.append("security")
        if len({x.source_file for x in impact.direct_impacts + impact.indirect_impacts}) > 10: level=max(level,2); categories.append("broad-impact")
        return RiskAssessment(_LEVELS[level], "+".join(sorted(set(categories))) or "local", "deterministic propagated planning risk", paths, "inspect evidence and satisfy verification", level >= 2)
