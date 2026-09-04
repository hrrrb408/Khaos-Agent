"""M8.3 orchestration seams for planning, execution, and repair observation."""

from __future__ import annotations

import inspect
from dataclasses import replace
from pathlib import Path
from typing import Any

from khaos.agent.control.completion_evaluator import (
    CompletionConstraint,
    CompletionConstraintCode,
    CompletionEvaluationSnapshot,
)
from khaos.agent.control.completion_flow import (
    CompletionFactBundle,
    CompletionProposal,
)
from khaos.agent.control.goal import GoalSpec
from khaos.coding.edit_transaction import EditTransactionResult
from khaos.coding.verification.contracts import (
    VerificationRunStatus,
)
from khaos.coding.verification.diagnostics import RepairContext
from khaos.coding.verification.evidence import (
    StoredVerificationRun,
    VerificationObservationStore,
    VerificationRun,
)
from khaos.coding.verification.executor import VerificationExecutor
from khaos.coding.verification.impact import (
    EditImpact,
    VerificationImpactAnalyzer,
)
from khaos.coding.verification.planner import AutonomousVerificationPlanner
from khaos.coding.verification.profile import VerificationProfileDetector
from khaos.security.protocol_boundary import canonical_digest


class AutonomousVerificationCoordinator:
    """Coordinate one post-edit plan/run without owning completion authority."""

    def __init__(
        self,
        *,
        execution_service: Any,
        repo_intelligence: Any | None = None,
        evidence_store: VerificationObservationStore | None = None,
        profile_detector: VerificationProfileDetector | None = None,
        impact_analyzer: VerificationImpactAnalyzer | None = None,
        planner: AutonomousVerificationPlanner | None = None,
        principal_id: str = "",
        project_id: str = "",
        repository_id: str = "",
    ) -> None:
        self.executor = VerificationExecutor(execution_service)
        self.repo_intelligence = repo_intelligence
        self.evidence_store = evidence_store or VerificationObservationStore()
        self.profile_detector = profile_detector or VerificationProfileDetector()
        self.impact_analyzer = impact_analyzer or VerificationImpactAnalyzer()
        self.planner = planner or AutonomousVerificationPlanner()
        self.principal_id = principal_id
        self.project_id = project_id
        self.repository_id = repository_id
        self._latest: dict[str, VerificationRun] = {}
        self._latest_impacts: dict[str, EditImpact] = {}
        self._invalidated: set[str] = set()

    async def verify_after_edit(
        self,
        result: EditTransactionResult,
        *,
        task_id: str,
        workspace: Any,
        transaction: Any | None = None,
        event_sink: Any | None = None,
        principal_id: str | None = None,
        project_id: str | None = None,
    ) -> VerificationRun:
        """Analyze, plan, execute, and persist one successful edit result."""
        if type(result) is not EditTransactionResult:
            raise TypeError("result must be an EditTransactionResult")
        if type(task_id) is not str or not task_id:
            raise ValueError("task_id must be non-empty")
        workspace_id = str(getattr(workspace, "id", ""))
        if workspace_id != result.workspace_id:
            raise PermissionError("edit result and active workspace are mismatched")
        workspace_task_id = getattr(workspace, "task_id", None)
        if workspace_task_id is not None and workspace_task_id != task_id:
            raise PermissionError("active workspace belongs to another task")
        root = Path(workspace.worktree_path).expanduser().resolve(strict=True)
        owner_principal = self.principal_id if principal_id is None else principal_id
        owner_project = self.project_id if project_id is None else project_id
        if not owner_principal:
            owner_principal = str(getattr(workspace, "principal_id", ""))
        if not owner_project:
            owner_project = str(getattr(workspace, "project_id", ""))
        workspace_principal = getattr(workspace, "principal_id", None)
        if workspace_principal not in (None, "", owner_principal):
            raise PermissionError("active workspace belongs to another principal")
        workspace_project = getattr(workspace, "project_id", None)
        if workspace_project not in (None, "", owner_project):
            raise PermissionError("active workspace belongs to another project")
        workspace_generation = getattr(workspace, "generation", None)
        if (
            type(workspace_generation) is not int
            or workspace_generation != result.resulting_generation
        ):
            raise PermissionError("edit result generation does not match active workspace")
        self._invalidated.add(task_id)
        impact = await self.impact_analyzer.analyze(
            result,
            repo_intelligence=self.repo_intelligence,
            task_id=task_id,
            principal_id=owner_principal,
            project_id=owner_project,
            transaction=transaction,
        )
        return await self._verify_impact(
            impact,
            task_id=task_id,
            workspace=workspace,
            root=root,
            principal_id=owner_principal,
            project_id=owner_project,
            event_sink=event_sink,
        )

    async def verify_after_merge(
        self,
        *,
        merge_id: str,
        task_id: str,
        workspace: Any,
        base_generation: int,
        resulting_generation: int,
        base_commit: str,
        resulting_commit: str,
        changed_paths: tuple[str, ...],
        phase: str = "parent",
        principal_id: str | None = None,
        project_id: str | None = None,
        event_sink: Any | None = None,
    ) -> VerificationRun:
        """Verify a committed integration or parent merge through M8.3.

        The merge coordinator supplies the actual commit and generation
        transition.  This method only derives bounded impact facts and
        delegates planning/execution to the existing verification owners; it
        never turns a child result into completion evidence.
        """
        if type(merge_id) is not str or not merge_id:
            raise ValueError("merge_id must be non-empty")
        if phase not in {"integration", "parent"}:
            raise ValueError("merge verification phase is invalid")
        if type(task_id) is not str or not task_id:
            raise ValueError("task_id must be non-empty")
        if type(base_generation) is not int or base_generation < 0:
            raise ValueError("base_generation must be non-negative")
        if type(resulting_generation) is not int or resulting_generation < 0:
            raise ValueError("resulting_generation must be non-negative")
        if resulting_generation < base_generation:
            raise ValueError("resulting_generation cannot go backwards")
        _validate_commit(base_commit, "base_commit")
        _validate_commit(resulting_commit, "resulting_commit")
        if type(changed_paths) is not tuple:
            raise TypeError("changed_paths must be an immutable tuple")
        workspace_id = str(getattr(workspace, "id", ""))
        if not workspace_id:
            raise PermissionError("merge workspace identity is missing")
        if getattr(workspace, "task_id", task_id) != task_id:
            raise PermissionError("merge workspace belongs to another task")
        workspace_generation = getattr(workspace, "generation", None)
        if type(workspace_generation) is not int or workspace_generation != resulting_generation:
            raise PermissionError("merge result generation does not match active workspace")
        workspace_head = getattr(workspace, "head_sha", None)
        if workspace_head is not None and workspace_head != resulting_commit:
            raise PermissionError("merge result commit does not match active workspace")
        root = Path(workspace.worktree_path).expanduser().resolve(strict=True)
        owner_principal = self.principal_id if principal_id is None else principal_id
        owner_project = self.project_id if project_id is None else project_id
        if not owner_principal:
            owner_principal = str(getattr(workspace, "principal_id", ""))
        if not owner_project:
            owner_project = str(getattr(workspace, "project_id", ""))
        workspace_principal = getattr(workspace, "principal_id", None)
        if workspace_principal not in (None, "", owner_principal):
            raise PermissionError("merge workspace belongs to another principal")
        workspace_project = getattr(workspace, "project_id", None)
        if workspace_project not in (None, "", owner_project):
            raise PermissionError("merge workspace belongs to another project")
        impact = EditImpact(
            workspace_id=workspace_id,
            transaction_id=f"merge:{merge_id}",
            transaction_digest=canonical_digest(
                {
                    "merge_id": merge_id,
                    "base_commit": base_commit,
                    "resulting_commit": resulting_commit,
                    "base_generation": base_generation,
                    "resulting_generation": resulting_generation,
                    "changed_paths": changed_paths,
                }
            ),
            base_generation=base_generation,
            resulting_generation=resulting_generation,
            repository_generation=0,
            changed_paths=changed_paths,
            operations=("merge",),
            uncertainty=("child-verification-is-not-parent-proof",),
        )
        self._invalidated.add(task_id)
        impact = await self.impact_analyzer.analyze_impact(
            impact,
            repo_intelligence=self.repo_intelligence,
            task_id=task_id,
            principal_id=owner_principal,
            project_id=owner_project,
        )
        return await self._verify_impact(
            impact,
            task_id=task_id,
            workspace=workspace,
            root=root,
            principal_id=owner_principal,
            project_id=owner_project,
            event_sink=event_sink,
        )

    async def _verify_impact(
        self,
        impact: EditImpact,
        *,
        task_id: str,
        workspace: Any,
        root: Path,
        principal_id: str,
        project_id: str,
        event_sink: Any | None,
    ) -> VerificationRun:
        """Run the shared M8.3 plan/execution/evidence pipeline."""
        workspace_id = impact.workspace_id
        self._latest_impacts[task_id] = impact
        overview = await self._overview(
            workspace_id=workspace_id,
            task_id=task_id,
            principal_id=principal_id,
            project_id=project_id,
        )
        overview_freshness = getattr(overview, "freshness", None)
        overview_is_current = (
            overview_freshness is None
            or getattr(overview_freshness, "value", overview_freshness) == "current"
        )
        profile_overview = (
            getattr(overview, "overview", overview) if overview_is_current else None
        )
        profile = self.profile_detector.detect(
            root,
            repository_id=self.repository_id,
            overview=profile_overview,
        )
        plan = self.planner.plan(
            impact,
            profile,
            workspace_generation=int(
                getattr(workspace, "generation", impact.resulting_generation)
            ),
        )
        await _emit(
            event_sink,
            "verification.plan_created",
            {
                "task_id": task_id,
                "workspace_id": workspace_id,
                "plan_id": plan.plan_id,
                "plan_digest": plan.plan_digest,
                "workspace_generation": plan.workspace_generation,
                "repository_generation": plan.repository_generation,
                "check_count": len(plan.checks),
                "required_check_count": len(plan.required_checks),
                "risk": plan.risk.value,
            },
        )
        async def current_repository_generation() -> int:
            current = await self._overview(
                workspace_id=workspace_id,
                task_id=task_id,
                principal_id=principal_id,
                project_id=project_id,
            )
            if current is None:
                return plan.repository_generation + 1
            freshness = getattr(current, "freshness", None)
            if freshness is not None and getattr(freshness, "value", freshness) != "current":
                return plan.repository_generation + 1
            return int(current.generation.generation)

        run = await self.executor.execute(
            plan,
            workspace_root=root,
            workspace=workspace,
            task_id=task_id,
            repository_generation_reader=(
                current_repository_generation
                if self.repo_intelligence is not None and overview is not None
                else None
            ),
            principal_id=principal_id,
            project_id=project_id,
            event_sink=event_sink,
        )
        await self.evidence_store.append(
            run,
            principal_id=principal_id,
            project_id=project_id,
            task_id=task_id,
        )
        self._latest[task_id] = run
        self._invalidated.discard(task_id)
        if run.status is VerificationRunStatus.STALE:
            await _emit(
                event_sink,
                "verification.plan_stale",
                {
                    "task_id": task_id,
                    "plan_id": run.plan.plan_id,
                    "plan_digest": run.plan.plan_digest,
                    "workspace_generation": run.plan.workspace_generation,
                    "repository_generation": run.plan.repository_generation,
                },
            )
        await _emit(
            event_sink,
            "verification.run_completed",
            {
                "task_id": task_id,
                "workspace_id": workspace_id,
                "run_id": run.run_id,
                "plan_id": run.plan.plan_id,
                "plan_digest": run.plan.plan_digest,
                "status": run.status.value,
                "required_check_count": run.required_count,
                "passed_check_count": run.passed_count,
                "diagnostic_count": len(run.diagnostics),
            },
        )
        await _emit(
            event_sink,
            "verification.completed",
            {
                "task_id": task_id,
                "workspace_id": workspace_id,
                "run_id": run.run_id,
                "plan_id": run.plan.plan_id,
                "plan_digest": run.plan.plan_digest,
                "status": run.status.value,
                "required_check_count": run.required_count,
                "passed_check_count": run.passed_count,
                "diagnostic_count": len(run.diagnostics),
            },
        )
        return run

    def invalidate(self, task_id: str) -> None:
        """Invalidate the in-process positive/negative observation on a new edit."""
        self._latest.pop(task_id, None)
        self._latest_impacts.pop(task_id, None)
        self._invalidated.add(task_id)

    def impact_for_task(self, task_id: str) -> EditImpact | None:
        """Return the current bounded impact used for the latest plan."""
        return self._latest_impacts.get(task_id)

    async def latest_for_task(self, task_id: str) -> StoredVerificationRun | VerificationRun | None:
        """Return the current runtime observation or the durable last run."""
        if task_id in self._invalidated and task_id not in self._latest:
            return None
        current = self._latest.get(task_id)
        if current is not None:
            return current
        return await self.evidence_store.latest_for_task(
            task_id,
            principal_id=self.principal_id,
            project_id=self.project_id,
        )

    @staticmethod
    def repair_context(run: VerificationRun, impact: EditImpact) -> RepairContext:
        """Build bounded diagnostic context; no mutation or completion effect."""
        return RepairContext(
            plan_id=run.plan.plan_id,
            workspace_id=run.plan.workspace_id,
            repository_generation=run.plan.repository_generation,
            status=run.status,
            changed_paths=impact.changed_paths,
            changed_symbols=impact.changed_symbols,
            related_tests=impact.related_tests,
            diagnostics=tuple(
                item
                for evidence in run.evidence
                for item in evidence.diagnostics
            )[:64],
        )

    async def _overview(
        self,
        *,
        workspace_id: str,
        task_id: str,
        principal_id: str,
        project_id: str,
    ) -> Any | None:
        if self.repo_intelligence is None:
            return None
        from khaos.coding.intelligence.repository import (
            FreshnessPolicy,
            RepoQueryKind,
            RepoQueryRequest,
        )

        try:
            return await self.repo_intelligence.query(
                RepoQueryRequest(
                    workspace_id=workspace_id,
                    task_id=task_id,
                    principal_id=principal_id,
                    project_id=project_id,
                    kind=RepoQueryKind.REPOSITORY_OVERVIEW,
                    freshness_policy=FreshnessPolicy.REQUIRE_CURRENT,
                    limit=64,
                )
            )
        except Exception:  # noqa: BLE001 - intelligence unavailability is fail-closed
            return None


class AutonomousVerificationFactProvider:
    """Add only negative M8.3 constraints to an existing fact provider."""

    def __init__(self, base_provider: Any, coordinator: AutonomousVerificationCoordinator) -> None:
        if base_provider is None or not callable(getattr(base_provider, "collect", None)):
            raise ValueError("base completion fact provider is required")
        self.base_provider = base_provider
        self.coordinator = coordinator

    async def collect(
        self,
        *,
        proposal: CompletionProposal,
        goal_spec: GoalSpec,
        snapshot: CompletionEvaluationSnapshot,
    ) -> CompletionFactBundle:
        """Project M8.3 failures as narrowing constraints only."""
        facts = await self.base_provider.collect(
            proposal=proposal,
            goal_spec=goal_spec,
            snapshot=snapshot,
        )
        if type(facts) is not CompletionFactBundle:
            raise TypeError("base completion fact provider returned an invalid bundle")
        observation = await self.coordinator.latest_for_task(proposal.task_id)
        if observation is None:
            return facts
        status = observation.status
        required_count = int(getattr(observation, "required_count", 0))
        passed_count = int(getattr(observation, "passed_count", 0))
        if status is VerificationRunStatus.PASSED and passed_count >= required_count:
            # A planner/executor observation is never a positive completion
            # fact.  The trusted M4 provider still has to supply that proof.
            return facts
        observation_plan_id = (
            observation.plan.plan_id
            if isinstance(observation, VerificationRun)
            else observation.plan_id
        )
        constraint = CompletionConstraint(
            code=(
                CompletionConstraintCode.VERIFICATION_FAILED
                if status in {
                    VerificationRunStatus.FAILED,
                    VerificationRunStatus.TIMED_OUT,
                    VerificationRunStatus.CANCELLED,
                    VerificationRunStatus.STALE,
                }
                else CompletionConstraintCode.VERIFICATION_MISSING
            ),
            subject_id=observation_plan_id,
        )
        return replace(facts, constraints=(*facts.constraints, constraint))


async def _emit(sink: Any | None, event: str, payload: dict[str, object]) -> None:
    if sink is None:
        return
    emitter = getattr(sink, "emit", None)
    if not callable(emitter):
        return
    try:
        result = emitter(event, payload)
        if inspect.isawaitable(result):
            await result
    except Exception:  # noqa: BLE001 - observability cannot affect authority
        # Observability must not grant an availability or authority bypass.
        return


def _validate_commit(value: str, label: str) -> None:
    """Validate a Git object id without resolving model-controlled input."""
    if (
        type(value) is not str
        or len(value) not in {40, 64}
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ValueError(f"{label} must be a lowercase Git object id")


__all__ = [
    "AutonomousVerificationCoordinator",
    "AutonomousVerificationFactProvider",
]
