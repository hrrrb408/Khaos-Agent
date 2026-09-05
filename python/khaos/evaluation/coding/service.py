"""Application service for the ``khaos eval coding`` CLI surface."""

from __future__ import annotations

from dataclasses import dataclass

from khaos.evaluation.coding.contracts import CodingScenarioManifest
from khaos.evaluation.coding.report import CodingComparison, compare_runs, report_json, report_markdown
from khaos.evaluation.coding.repository import CodingEvaluationRepository
from khaos.evaluation.coding.results import CodingEvaluationRun
from khaos.evaluation.coding.runner import CodingEvaluationRunner


@dataclass(frozen=True, slots=True)
class CodingScenarioSummary:
    """CLI-safe scenario listing without oracle ground truth."""

    scenario_id: str
    version: int
    kind: str
    difficulty: str
    languages: tuple[str, ...]
    tags: tuple[str, ...]
    source_file_count: int

    def to_payload(self) -> dict[str, object]:
        return {
            "scenario_id": self.scenario_id,
            "version": self.version,
            "kind": self.kind,
            "difficulty": self.difficulty,
            "languages": list(self.languages),
            "tags": list(self.tags),
            "source_file_count": self.source_file_count,
        }


class CodingEvaluationService:
    """Coordinate selection, execution, and read-only report operations."""

    def __init__(
        self,
        manifest: CodingScenarioManifest,
        *,
        runner: CodingEvaluationRunner,
        repository: CodingEvaluationRepository | None = None,
    ) -> None:
        self.manifest = manifest
        self.runner = runner
        self.repository = repository

    def list_scenarios(self, *, tag: str | None = None) -> tuple[CodingScenarioSummary, ...]:
        values = self.manifest.select(tag=tag)
        return tuple(
            CodingScenarioSummary(
                scenario_id=scenario.scenario_id,
                version=scenario.version,
                kind=scenario.kind.value,
                difficulty=scenario.difficulty,
                languages=scenario.languages,
                tags=scenario.tags,
                source_file_count=len(scenario.expected_files),
            )
            for scenario in values
        )

    async def run(
        self,
        *,
        scenario_id: str | None = None,
        tag: str | None = None,
        all_scenarios: bool = False,
    ) -> tuple[CodingEvaluationRun, ...]:
        if sum(value is not None for value in (scenario_id, tag)) + int(all_scenarios) > 1:
            raise ValueError("choose one of scenario_id, tag, or all_scenarios")
        if scenario_id is not None:
            scenarios = self.manifest.select(scenario_id=scenario_id)
        elif tag is not None:
            scenarios = self.manifest.select(tag=tag)
        elif all_scenarios:
            scenarios = self.manifest.scenarios
        else:
            raise ValueError("coding run requires a scenario, tag, or --all")
        if not scenarios:
            raise ValueError("coding selection matched no scenarios")
        return await self.runner.run_many(scenarios)

    async def report(
        self,
        *,
        run_id: str | None = None,
        scenario_id: str | None = None,
        limit: int = 100,
        pretty: bool = False,
    ) -> str:
        if self.repository is None:
            raise RuntimeError("coding report requires a run repository")
        if run_id is not None:
            run = await self.repository.get_by_id(
                run_id,
                principal_id=self.runner.principal_id,
                project_id=self.runner.project_id,
            )
            runs = () if run is None else (run,)
        else:
            runs = await self.repository.list(
                principal_id=self.runner.principal_id,
                project_id=self.runner.project_id,
                scenario_id=scenario_id,
                limit=limit,
            )
        return report_json(runs, pretty=pretty)

    async def report_markdown(
        self,
        *,
        scenario_id: str | None = None,
        limit: int = 100,
    ) -> str:
        if self.repository is None:
            raise RuntimeError("coding report requires a run repository")
        runs = await self.repository.list(
            principal_id=self.runner.principal_id,
            project_id=self.runner.project_id,
            scenario_id=scenario_id,
            limit=limit,
        )
        return report_markdown(runs)

    async def compare(self, baseline_id: str, candidate_id: str) -> CodingComparison:
        if self.repository is None:
            raise RuntimeError("coding compare requires a run repository")
        baseline = await self.repository.get_by_id(
            baseline_id,
            principal_id=self.runner.principal_id,
            project_id=self.runner.project_id,
        )
        candidate = await self.repository.get_by_id(
            candidate_id,
            principal_id=self.runner.principal_id,
            project_id=self.runner.project_id,
        )
        if baseline is None or candidate is None:
            raise KeyError("coding evaluation run not found in owner scope")
        return compare_runs(baseline, candidate)


__all__ = ["CodingEvaluationService", "CodingScenarioSummary"]
