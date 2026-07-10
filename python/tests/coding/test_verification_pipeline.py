import sys
from pathlib import Path

import pytest

from khaos.coding.verification import ProjectDetector, VerificationPipeline, VerificationPlanner


def test_detector_and_planner_use_manifest_without_execution(tmp_path: Path):
    (tmp_path / "go.mod").write_text("module example.com/x\n", encoding="utf-8")
    project = ProjectDetector().detect(tmp_path)
    assert project.ecosystem == "go"
    plan = VerificationPlanner().plan(project)
    assert [step.stage for step in plan.steps] == ["lint", "unit-test"]


def test_unknown_project_has_no_plan(tmp_path: Path):
    assert VerificationPlanner().plan(ProjectDetector().detect(tmp_path)).diagnostics == ("no-safe-plan",)


@pytest.mark.asyncio
async def test_pipeline_runs_steps_through_execution_backend(tmp_path: Path):
    (tmp_path / "pyproject.toml").write_text("[project]\nname='x'\n", encoding="utf-8")
    pipeline = VerificationPipeline()
    plan = pipeline.plan(tmp_path)
    # Use an explicit tiny plan to keep this fixture independent of pytest installation.
    from khaos.coding.verification.models import VerificationPlan, VerificationStep
    tiny = VerificationPlan((VerificationStep("echo", "preflight", (sys.executable, "-c", "print('ok')"), tmp_path),))
    results = await pipeline.run(tiny)
    assert results[0].status == "passed"
