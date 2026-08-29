"""Canonical machine-readable and concise human capability reports."""

from __future__ import annotations

from dataclasses import dataclass

from khaos.evaluation.benchmark import CapabilityBenchmarkResult
from khaos.evaluation.models import CapabilityEvaluation
from khaos.security.protocol_boundary import canonical_json_bytes


@dataclass(frozen=True, slots=True)
class CapabilityEvaluationReport:
    """Derived presentation; it is never written as authority state."""

    evaluation: CapabilityEvaluation
    source_sha: str | None = None
    benchmark_result: CapabilityBenchmarkResult | None = None

    def to_payload(self) -> dict[str, object]:
        payload: dict[str, object] = {
            "schema_version": 1,
            "source_sha": self.source_sha,
            "evaluation": self.evaluation.to_payload(),
            "evaluation_digest": self.evaluation.evaluation_digest,
            "security_integrity": self.evaluation.security_integrity.value,
        }
        if self.benchmark_result is not None:
            payload["benchmark"] = self.benchmark_result.to_payload()
        return payload

    def canonical_json(self) -> str:
        return canonical_json_bytes(self.to_payload()).decode("utf-8")

    def human_summary(self) -> str:
        outcome = self.evaluation.outcome_metrics
        recovery = self.evaluation.recovery_metrics
        execution = self.evaluation.execution_metrics
        delegation = self.evaluation.delegation_metrics
        return "\n".join(
            (
                f"Outcome: {outcome.terminal_status or 'UNKNOWN'}",
                f"Evaluation: {self.evaluation.disposition.value}",
                f"Trusted Verification: {self.evaluation.verification_metrics.current_disposition or 'UNKNOWN'}",
                f"Replans: {recovery.replan_count if recovery.replan_count is not None else 'UNKNOWN'}",
                f"Recovery cycles: {recovery.recovery_cycles if recovery.recovery_cycles is not None else 'UNKNOWN'}",
                f"Applied effects: {execution.applied_effects if execution.applied_effects is not None else 'UNKNOWN'}",
                f"Uncertain effects: {execution.unknown_effects if execution.unknown_effects is not None else 'UNKNOWN'}",
                f"Sub-Agent delegated steps: {delegation.delegated_steps_executed if delegation.delegated_steps_executed is not None else 'UNKNOWN'}",
                f"Security integrity: {self.evaluation.security_integrity.value}",
            )
        )


__all__ = ["CapabilityEvaluationReport"]
