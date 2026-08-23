"""Reproducible retrieval, temporal, and poisoning benchmarks.

The harness deliberately uses the live Broker rather than a provider directly.
This makes security filtering part of the measured result and prevents a
benchmark from accidentally becoming an authority bypass.  It is deterministic
apart from measured wall-clock latency and requires at least three repetitions
so a single lucky run cannot be reported as production evidence.
"""

from __future__ import annotations

import hashlib
import json
import statistics
import uuid
from dataclasses import dataclass
from time import monotonic
from typing import Any

from khaos.memory.core.broker import MemoryBroker
from khaos.memory.core.contracts import MemoryBudget, RuntimeMemoryContext


@dataclass(frozen=True, slots=True)
class BenchmarkCase:
    """One query with expected and forbidden retrieval signals."""

    case_id: str
    query: str
    expected_terms: tuple[str, ...] = ()
    forbidden_terms: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class BenchmarkRun:
    """One independent case execution."""

    run_id: str
    case_id: str
    backend: str
    order_variant: str
    repetition: int
    latency_ms: float
    recall: float
    security_violations: int
    result_count: int


@dataclass(frozen=True, slots=True)
class BenchmarkReport:
    """Aggregate benchmark evidence suitable for audit and comparison."""

    benchmark_name: str
    backend: str
    repetitions: int
    order_variants: tuple[str, ...]
    runs: tuple[BenchmarkRun, ...]
    metrics: dict[str, float]
    variance: dict[str, float]
    security_violations: int


class MemoryBenchmarkHarness:
    """Run chronological/shuffled/adversarial retrieval comparisons."""

    def __init__(
        self,
        broker: MemoryBroker,
        *,
        benchmark_name: str = "memory-v2",
        backend: str = "native-v2",
    ) -> None:
        if not benchmark_name.strip() or not backend.strip():
            raise ValueError("benchmark name and backend are required")
        self._broker = broker
        self._name = benchmark_name
        self._backend = backend

    async def run(
        self,
        cases: tuple[BenchmarkCase, ...] | list[BenchmarkCase],
        runtime: RuntimeMemoryContext,
        *,
        repetitions: int = 3,
        order_variants: tuple[str, ...] = (
            "chronological",
            "shuffled",
            "adversarial",
        ),
        limit: int = 32,
    ) -> BenchmarkReport:
        """Execute independent repetitions and persist bounded run evidence."""

        if repetitions < 3 or repetitions > 100:
            raise ValueError("benchmark repetitions must be between 3 and 100")
        if not cases or len(cases) > 10_000:
            raise ValueError("benchmark requires 1 to 10000 cases")
        allowed_variants = {"chronological", "shuffled", "adversarial"}
        if not order_variants or any(value not in allowed_variants for value in order_variants):
            raise ValueError("benchmark order variant is unsupported")
        if limit <= 0 or limit > 256:
            raise ValueError("benchmark limit is outside the bounded range")
        ordered = tuple(cases)
        runs: list[BenchmarkRun] = []
        for repetition in range(repetitions):
            for variant in order_variants:
                for case in _ordered_cases(ordered, variant, repetition):
                    started = monotonic()
                    resolution = await self._broker.search(
                        case.query,
                        runtime,
                        MemoryBudget(max_hits=limit),
                        include_historical=variant == "adversarial",
                    )
                    hits = (*resolution.primary_hits, *resolution.supporting_hits)
                    content = "\n".join(hit.content.casefold() for hit in hits)
                    expected = _term_recall(content, case.expected_terms)
                    violations = sum(
                        1 for term in case.forbidden_terms if term.casefold() in content
                    )
                    runs.append(
                        BenchmarkRun(
                            run_id=uuid.uuid4().hex,
                            case_id=case.case_id,
                            backend=self._backend,
                            order_variant=variant,
                            repetition=repetition,
                            latency_ms=(monotonic() - started) * 1000,
                            recall=expected,
                            security_violations=violations,
                            result_count=len(hits),
                        )
                    )
        report = _aggregate(self._name, self._backend, repetitions, order_variants, runs)
        await self._persist(runtime, report)
        return report

    async def compare_backends(
        self,
        cases: tuple[BenchmarkCase, ...] | list[BenchmarkCase],
        runtime: RuntimeMemoryContext,
        *,
        backends: tuple[str, ...] = (
            "no-memory",
            "v1",
            "native-v2",
            "mem0",
            "graphiti",
        ),
        repetitions: int = 3,
    ) -> dict[str, BenchmarkReport]:
        """Produce comparable labels; non-live backends are explicit baselines.

        Only the live Broker backend executes here.  Other labels are reported
        as zero baselines rather than pretending an external SDK was queried.
        Callers can run this method once per configured provider and merge the
        resulting reports without conflating unavailable infrastructure with a
        passing result.
        """

        result: dict[str, BenchmarkReport] = {}
        for backend in backends:
            if backend == self._backend:
                result[backend] = await self.run(
                    cases,
                    runtime,
                    repetitions=repetitions,
                )
                continue
            result[backend] = _baseline_report(self._name, backend, repetitions)
        return result

    async def _persist(self, runtime: RuntimeMemoryContext, report: BenchmarkReport) -> None:
        db = self._broker.ledger.database
        async with db.transaction() as conn:
            for run in report.runs:
                await conn.execute(
                    "INSERT INTO memory_benchmark_runs ("
                    "run_id, benchmark_name, provider_id, profile_id, order_variant, "
                    "repetition, started_at, finished_at, status, metrics_json, "
                    "principal_id, project_id"
                    ") VALUES (?, ?, ?, ?, ?, ?, datetime('now'), datetime('now'), ?, ?, ?, ?)",
                    (
                        run.run_id,
                        report.benchmark_name,
                        self._broker.provider.provider_id,
                        self._broker.profile.profile_id if self._broker.profile else "",
                        run.order_variant,
                        run.repetition,
                        "completed",
                        json.dumps(
                            {
                                "case_id": run.case_id,
                                "latency_ms": run.latency_ms,
                                "recall": run.recall,
                                "security_violations": run.security_violations,
                                "result_count": run.result_count,
                            },
                            sort_keys=True,
                        ),
                        runtime.principal_id,
                        runtime.project_id,
                    ),
                )


def _ordered_cases(
    cases: tuple[BenchmarkCase, ...],
    variant: str,
    repetition: int,
) -> tuple[BenchmarkCase, ...]:
    if variant == "chronological":
        return cases
    if variant == "shuffled":
        return tuple(sorted(cases, key=lambda case: _stable_order(case.case_id, repetition)))
    # Adversarial order is deterministic reverse-hash order and asks the
    # Broker for historical evidence, exercising conflict/temporal gates.
    return tuple(sorted(cases, key=lambda case: _stable_order(case.case_id, repetition), reverse=True))


def _stable_order(case_id: str, repetition: int) -> str:
    return hashlib.sha256(f"{case_id}:{repetition}".encode()).hexdigest()


def _term_recall(content: str, terms: tuple[str, ...]) -> float:
    if not terms:
        return 1.0
    return sum(term.casefold() in content for term in terms) / len(terms)


def _aggregate(
    name: str,
    backend: str,
    repetitions: int,
    variants: tuple[str, ...],
    runs: list[BenchmarkRun],
) -> BenchmarkReport:
    latencies = [run.latency_ms for run in runs]
    recalls = [run.recall for run in runs]
    metrics = {
        "recall": statistics.fmean(recalls) if recalls else 0.0,
        "latency_p50_ms": _percentile(latencies, 0.50),
        "latency_p95_ms": _percentile(latencies, 0.95),
        "result_count": statistics.fmean(run.result_count for run in runs) if runs else 0.0,
    }
    variance = {
        "recall": statistics.pvariance(recalls) if len(recalls) > 1 else 0.0,
        "latency_ms": statistics.pvariance(latencies) if len(latencies) > 1 else 0.0,
    }
    return BenchmarkReport(
        benchmark_name=name,
        backend=backend,
        repetitions=repetitions,
        order_variants=variants,
        runs=tuple(runs),
        metrics=metrics,
        variance=variance,
        security_violations=sum(run.security_violations for run in runs),
    )


def _baseline_report(name: str, backend: str, repetitions: int) -> BenchmarkReport:
    return BenchmarkReport(
        benchmark_name=name,
        backend=backend,
        repetitions=repetitions,
        order_variants=(),
        runs=(),
        metrics={"recall": 0.0, "latency_p50_ms": 0.0, "latency_p95_ms": 0.0},
        variance={"recall": 0.0, "latency_ms": 0.0},
        security_violations=0,
    )


def _percentile(values: list[float], quantile: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, int(round((len(ordered) - 1) * quantile))))
    return float(ordered[index])


__all__ = [
    "BenchmarkCase",
    "BenchmarkReport",
    "BenchmarkRun",
    "MemoryBenchmarkHarness",
]
