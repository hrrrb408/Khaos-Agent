"""Bounded Memory V2 metrics persisted outside the truth ledger."""

from __future__ import annotations

import json
import math
import statistics
from dataclasses import dataclass
from typing import Any

from khaos.memory.core.contracts import RuntimeMemoryContext, utc_now


@dataclass(frozen=True, slots=True)
class MetricSummary:
    """Aggregate view of one metric family."""

    metric_name: str
    count: int
    p50: float
    p95: float
    average: float


class MemoryObservability:
    """Record provider/retrieval/rebuild timings with explicit bounds."""

    def __init__(self, db: Any, *, max_metadata_bytes: int = 8192) -> None:
        if max_metadata_bytes <= 0 or max_metadata_bytes > 64 * 1024:
            raise ValueError("max_metadata_bytes is outside the bounded range")
        self._db = db
        self._max_metadata_bytes = max_metadata_bytes

    async def record(
        self,
        metric_name: str,
        value: float,
        runtime: RuntimeMemoryContext,
        *,
        unit: str = "count",
        provider_id: str = "",
        profile_id: str = "",
        operation: str = "",
        metadata: dict[str, Any] | None = None,
    ) -> None:
        """Persist one bounded sample; metrics never become authority."""

        if not metric_name or len(metric_name) > 128:
            raise ValueError("metric_name is empty or oversized")
        if not unit or len(unit) > 32:
            raise ValueError("metric unit is empty or oversized")
        numeric_value = float(value)
        if not math.isfinite(numeric_value):
            raise ValueError("metric value must be finite")
        try:
            encoded = json.dumps(
                metadata or {},
                ensure_ascii=False,
                sort_keys=True,
                allow_nan=False,
            )
        except (TypeError, ValueError) as exc:
            raise ValueError("metric metadata must be JSON serializable") from exc
        if len(encoded.encode("utf-8")) > self._max_metadata_bytes:
            raise ValueError("metric metadata is oversized")
        async with self._db.transaction() as conn:
            await conn.execute(
                "INSERT INTO memory_metric_samples ("
                "metric_name, value, unit, provider_id, profile_id, operation, "
                "principal_id, project_id, recorded_at, metadata_json"
                ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    metric_name,
                    numeric_value,
                    unit,
                    provider_id,
                    profile_id,
                    operation,
                    runtime.principal_id,
                    runtime.project_id,
                    utc_now().isoformat(),
                    encoded,
                ),
            )

    async def summary(
        self,
        metric_name: str,
        runtime: RuntimeMemoryContext,
        *,
        limit: int = 10_000,
    ) -> MetricSummary:
        """Return p50/p95 evidence for one project/principal metric."""

        if limit <= 0 or limit > 100_000:
            raise ValueError("metric summary limit is outside the bounded range")
        async with self._db.read_connection() as conn:
            rows = await (
                await conn.execute(
                    "SELECT value FROM memory_metric_samples "
                    "WHERE metric_name = ? AND principal_id = ? AND project_id = ? "
                    "ORDER BY recorded_at DESC LIMIT ?",
                    (metric_name, runtime.principal_id, runtime.project_id, limit),
                )
            ).fetchall()
        values = sorted(float(row["value"]) for row in rows)
        return MetricSummary(
            metric_name=metric_name,
            count=len(values),
            p50=_percentile(values, 0.50),
            p95=_percentile(values, 0.95),
            average=statistics.fmean(values) if values else 0.0,
        )


def _percentile(values: list[float], quantile: float) -> float:
    if not values:
        return 0.0
    index = min(len(values) - 1, max(0, int(round((len(values) - 1) * quantile))))
    return values[index]


__all__ = ["MemoryObservability", "MetricSummary"]
