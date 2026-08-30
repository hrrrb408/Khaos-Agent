"""Trusted benchmark execution boundary.

The harness is deliberately downstream of the control plane.  It accepts a
frozen snapshot produced by a trusted fixture, evaluates it, and invokes the
typed benchmark oracle.  No production agent, router, approval, completion,
or policy component imports this module.
"""

from __future__ import annotations

from dataclasses import dataclass

from khaos.evaluation.benchmark import (
    BenchmarkExecutionEvidence,
    CapabilityBenchmarkManifest,
    CapabilityBenchmarkResult,
    CapabilityBenchmarkScenario,
    default_capability_benchmark_manifest,
    judge_benchmark,
)
from khaos.evaluation.evaluator import CapabilityEvaluator
from khaos.evaluation.models import (
    CapabilityEvaluation,
    CapabilityEvaluationPolicy,
    CapabilityEvidenceSnapshot,
)


@dataclass(frozen=True, slots=True)
class BenchmarkScenarioFixture:
    """Trusted fixture output consumed by :class:`CapabilityBenchmarkHarness`.

    Fixture construction belongs to tests or a separately trusted benchmark
    runner.  The tested model cannot write this object, and its evidence is
    bound to the exact snapshot before judging.
    """

    scenario: CapabilityBenchmarkScenario
    snapshot: CapabilityEvidenceSnapshot
    execution_evidence: BenchmarkExecutionEvidence


class CapabilityBenchmarkHarness:
    """Run one immutable fixture through the real M7.9 evaluator and oracle."""

    def __init__(
        self,
        manifest: CapabilityBenchmarkManifest | None = None,
        policy: CapabilityEvaluationPolicy | None = None,
    ) -> None:
        self.manifest = manifest or default_capability_benchmark_manifest()
        self.policy = policy or CapabilityEvaluationPolicy.production()
        self._evaluator = CapabilityEvaluator()

    def evaluate_fixture(
        self, fixture: BenchmarkScenarioFixture
    ) -> tuple[CapabilityEvaluation, CapabilityBenchmarkResult]:
        """Evaluate and judge a trusted scenario fixture without side effects."""

        if fixture.scenario not in self.manifest.scenarios:
            raise ValueError("fixture scenario is not part of the trusted manifest")
        evaluation = self._evaluator.evaluate(fixture.snapshot, self.policy)
        result = judge_benchmark(
            self.manifest,
            fixture.scenario,
            evaluation,
            fixture.execution_evidence,
        )
        return evaluation, result


__all__ = [
    "BenchmarkScenarioFixture",
    "CapabilityBenchmarkHarness",
]
