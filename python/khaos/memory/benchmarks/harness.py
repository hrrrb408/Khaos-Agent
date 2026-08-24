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
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from time import monotonic
from typing import Any, cast

from khaos.memory.core.broker import MemoryBroker
from khaos.memory.core.contracts import MemoryBudget, RuntimeMemoryContext, enum_value


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
    status: str = "COMPLETED"
    error: str = ""
    task_order: tuple[str, ...] = ()
    initial_state_digest: str = ""
    mutation_digest: str = ""
    final_state_digest: str = ""
    promotion_count: int = 0
    false_promotion_count: int = 0


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
    status: str = "COMPLETED"
    error: str = ""
    state_isolated: bool = False
    promotion_count: int = 0
    false_promotion_count: int = 0
    initial_state_digests: tuple[str, ...] = ()
    final_state_digests: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class OnlineMemoryTask:
    """One state-mutating task used by the online-learning benchmark."""

    task_id: str
    query: str
    mutate: Callable[[MemoryBroker, RuntimeMemoryContext], Awaitable[None]]
    expected_terms: tuple[str, ...] = ()
    forbidden_terms: tuple[str, ...] = ()


class OnlineMemoryBenchmark:
    """Run task-order experiments against independent fresh Broker states."""

    def __init__(
        self,
        fresh_state: Callable[
            [], Awaitable[tuple[MemoryBroker, RuntimeMemoryContext]]
        ],
        *,
        benchmark_name: str = "memory-online-v2",
        backend: str = "native-v2",
    ) -> None:
        if not callable(fresh_state):
            raise TypeError("fresh_state factory is required")
        self._fresh_state = fresh_state
        self._name = benchmark_name
        self._backend = backend

    async def run(
        self,
        tasks: tuple[OnlineMemoryTask, ...] | list[OnlineMemoryTask],
        *,
        repetitions: int = 3,
        order_variants: tuple[str, ...] = (
            "chronological",
            "shuffled",
            "adversarial",
        ),
        limit: int = 32,
    ) -> BenchmarkReport:
        """Execute real mutations on a fresh state for every run."""

        if repetitions < 3 or repetitions > 100:
            raise ValueError("benchmark repetitions must be between 3 and 100")
        if not tasks or len(tasks) > 10_000:
            raise ValueError("online benchmark requires 1 to 10000 tasks")
        allowed_variants = {"chronological", "shuffled", "adversarial"}
        if not order_variants or any(value not in allowed_variants for value in order_variants):
            raise ValueError("benchmark order variant is unsupported")
        if limit <= 0 or limit > 256:
            raise ValueError("benchmark limit is outside the bounded range")

        runs: list[BenchmarkRun] = []
        initial_digests: list[str] = []
        final_digests: list[str] = []
        for repetition in range(repetitions):
            for variant in order_variants:
                broker, runtime = await self._fresh_state()
                if not isinstance(broker, MemoryBroker):
                    raise TypeError("fresh_state must return a MemoryBroker")
                ordered = _ordered_online_tasks(tuple(tasks), variant, repetition)
                task_order = tuple(task.task_id for task in ordered)
                initial_digest = await _state_digest(broker, runtime, limit=limit)
                initial_digests.append(initial_digest)
                mutation_digests: list[str] = []
                promotion_count = 0
                false_promotion_count = 0
                for task in ordered:
                    started = monotonic()
                    status = "COMPLETED"
                    error = ""
                    recall = 0.0
                    violations = 0
                    result_count = 0
                    before = await _state_digest(broker, runtime, limit=limit)
                    try:
                        await task.mutate(broker, runtime)
                        resolution = await broker.search(
                            task.query,
                            runtime,
                            MemoryBudget(max_hits=limit),
                        )
                        hits = [*resolution.primary_hits, *resolution.supporting_hits]
                        content = "\n".join(hit.content.casefold() for hit in hits)
                        recall = _term_recall(content, task.expected_terms)
                        violations = sum(
                            1 for term in task.forbidden_terms if term.casefold() in content
                        )
                        result_count = len(hits)
                        promotion_count += sum(
                            1
                            for hit in hits
                            if enum_value(hit.status) == "VERIFIED"
                        )
                        false_promotion_count += sum(
                            1
                            for hit in hits
                            if enum_value(hit.status) == "VERIFIED"
                            and str(hit.authority_hint)
                            not in {"USER_STATED", "VERIFICATION_CONFIRMED"}
                        )
                    except Exception as exc:  # noqa: BLE001 - benchmark records state errors
                        status = "ERROR"
                        error = type(exc).__name__
                    after = await _state_digest(broker, runtime, limit=limit)
                    mutation_digests.append(
                        hashlib.sha256(f"{before}:{after}".encode()).hexdigest()
                    )
                    runs.append(
                        BenchmarkRun(
                            run_id=uuid.uuid4().hex,
                            case_id=task.task_id,
                            backend=self._backend,
                            order_variant=variant,
                            repetition=repetition,
                            latency_ms=(monotonic() - started) * 1000,
                            recall=recall,
                            security_violations=violations,
                            result_count=result_count,
                            status=status,
                            error=error,
                            task_order=task_order,
                            initial_state_digest=initial_digest,
                            mutation_digest=mutation_digests[-1],
                            promotion_count=promotion_count,
                            false_promotion_count=false_promotion_count,
                        )
                    )
                final_digest = await _state_digest(broker, runtime, limit=limit)
                final_digests.append(final_digest)
                close = getattr(broker, "close", None)
                if callable(close):
                    await cast(Callable[..., Awaitable[Any]], close)()

        report = _aggregate(
            self._name,
            self._backend,
            repetitions,
            order_variants,
            runs,
            state_isolated=True,
            initial_state_digests=tuple(initial_digests),
            final_state_digests=tuple(final_digests),
        )
        return report


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
        prepare_case: Callable[[BenchmarkCase, str, int], Awaitable[None]] | None = None,
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
                    if prepare_case is not None:
                        await prepare_case(case, variant, repetition)
                    started = monotonic()
                    error = ""
                    status = "COMPLETED"
                    hits: tuple[Any, ...] = ()
                    expected = 0.0
                    violations = 0
                    try:
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
                    except Exception as exc:  # noqa: BLE001 - benchmark records failures
                        status = "ERROR"
                        error = type(exc).__name__
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
                            status=status,
                            error=error,
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
                        run.status.lower(),
                        json.dumps(
                            {
                                "case_id": run.case_id,
                                "task_order": list(run.task_order),
                                "initial_state_digest": run.initial_state_digest,
                                "mutation_digest": run.mutation_digest,
                                "final_state_digest": run.final_state_digest,
                                "latency_ms": run.latency_ms,
                                "recall": run.recall,
                                "security_violations": run.security_violations,
                                "result_count": run.result_count,
                                "promotion_count": run.promotion_count,
                                "false_promotion_count": run.false_promotion_count,
                                "status": run.status,
                                "error": run.error,
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
    *,
    state_isolated: bool = False,
    initial_state_digests: tuple[str, ...] = (),
    final_state_digests: tuple[str, ...] = (),
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
        status="FAILED" if any(run.status != "COMPLETED" for run in runs) else "COMPLETED",
        error=next((run.error for run in runs if run.error), ""),
        state_isolated=state_isolated,
        promotion_count=sum(run.promotion_count for run in runs),
        false_promotion_count=sum(run.false_promotion_count for run in runs),
        initial_state_digests=initial_state_digests,
        final_state_digests=final_state_digests,
    )


def _baseline_report(name: str, backend: str, repetitions: int) -> BenchmarkReport:
    return BenchmarkReport(
        benchmark_name=name,
        backend=backend,
        repetitions=repetitions,
        order_variants=(),
        runs=(),
        metrics={},
        variance={"recall": 0.0, "latency_ms": 0.0},
        security_violations=0,
        status="NOT_RUN",
        error="backend is not configured in this process",
    )


def _percentile(values: list[float], quantile: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, round((len(ordered) - 1) * quantile)))
    return float(ordered[index])


def _ordered_online_tasks(
    tasks: tuple[OnlineMemoryTask, ...],
    variant: str,
    repetition: int,
) -> tuple[OnlineMemoryTask, ...]:
    if variant == "chronological":
        return tasks
    ordered = sorted(tasks, key=lambda task: _stable_order(task.task_id, repetition))
    return tuple(ordered if variant == "shuffled" else reversed(ordered))


async def _state_digest(
    broker: MemoryBroker,
    runtime: RuntimeMemoryContext,
    *,
    limit: int,
) -> str:
    """Hash Broker-visible state without querying provider tables directly."""

    resolution = await broker.search(
        "",
        runtime,
        MemoryBudget(max_hits=limit),
        include_historical=True,
    )
    rows = [
        {
            "id": hit.memory_id or hit.external_id,
            "status": str(hit.status),
            "authority": str(hit.authority_hint),
            "content_hash": hashlib.sha256(hit.content.encode("utf-8")).hexdigest(),
            "valid_from": hit.valid_from.isoformat() if hit.valid_from else "",
        }
        for hit in (*resolution.primary_hits, *resolution.supporting_hits, *resolution.conflicts)
    ]
    return hashlib.sha256(
        json.dumps(rows, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


__all__ = [
    "BenchmarkCase",
    "BenchmarkReport",
    "BenchmarkRun",
    "MemoryBenchmarkHarness",
    "OnlineMemoryBenchmark",
    "OnlineMemoryTask",
]
