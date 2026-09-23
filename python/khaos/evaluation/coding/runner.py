"""Run the real Coding runtime against isolated M8.0 scenarios."""

from __future__ import annotations

import asyncio
import inspect
import logging
import math
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Protocol, cast

from khaos.evaluation.coding.contracts import (
    REVIEW_CATEGORY_CONTRACT_V3,
    CodingContractError,
    CodingFailureReason,
    CodingRunIdentity,
    CodingScenario,
    CodingScenarioManifest,
    CodingVerdict,
    DiffOracleSpec,
    digest_payload,
)
from khaos.evaluation.coding.fixtures import (
    FixtureError,
    FixtureManager,
    MaterializedFixture,
)
from khaos.evaluation.coding.metrics import CodingMetrics, CodingTraceCollector
from khaos.evaluation.coding.oracle import (
    CodingOracle,
    DiffSummary,
    OracleCheckResult,
    OracleError,
    OracleEvaluation,
    OracleKind,
    snapshot_tree,
    summarize_diff,
)
from khaos.evaluation.coding.results import (
    AgentExecution,
    CodingEvaluationRun,
    new_run_id,
    utc_timestamp,
)

logger = logging.getLogger(__name__)


class CodingRunRepository(Protocol):
    async def append(self, run: CodingEvaluationRun) -> CodingEvaluationRun: ...


class CodingAgentInvoker(Protocol):
    async def run(
        self,
        scenario: CodingScenario,
        fixture: MaterializedFixture,
        trace: CodingTraceCollector,
    ) -> AgentExecution: ...


class AgentInvokerCallable:
    """Adapter for test and integration callables."""

    def __init__(self, callback: Callable[..., object]) -> None:
        self._callback = callback

    async def run(self, scenario: CodingScenario, fixture: MaterializedFixture, trace: CodingTraceCollector) -> AgentExecution:
        value = self._callback(scenario, fixture, trace)
        if inspect.isawaitable(value):
            value = await value
        if not isinstance(value, AgentExecution):
            raise TypeError("coding agent invoker must return AgentExecution")
        return value


class CodingEvaluationRunner:
    """Single-writer orchestration for fixture, runtime, oracle, and ledger."""

    def __init__(
        self,
        manifest: CodingScenarioManifest,
        *,
        fixture_manager: FixtureManager,
        oracle: CodingOracle,
        agent_invoker: CodingAgentInvoker | Callable[..., object],
        repository: CodingRunRepository | None = None,
        principal_id: str = "evaluation",
        project_id: str = "coding-evaluation",
        khaos_source_sha: str = "unknown",
        config_digest: str | None = None,
        model: str = "unknown",
        provider: str = "unknown",
        task_timeout_seconds: float | None = None,
        provider_observations: Sequence[object] | None = None,
    ) -> None:
        self.manifest = manifest
        self.fixture_manager = fixture_manager
        self.oracle = oracle
        if callable(getattr(agent_invoker, "run", None)):
            self.agent_invoker = cast(CodingAgentInvoker, agent_invoker)
        else:
            self.agent_invoker = AgentInvokerCallable(
                cast(Callable[..., object], agent_invoker)
            )
        self.repository = repository
        self.principal_id = principal_id
        self.project_id = project_id
        self.khaos_source_sha = khaos_source_sha or "unknown"
        self.config_digest = config_digest or digest_payload({"config": "unknown"})
        self.model = model or "unknown"
        self.provider = provider or "unknown"
        self.provider_observations = provider_observations
        if task_timeout_seconds is not None:
            if (
                isinstance(task_timeout_seconds, bool)
                or not isinstance(task_timeout_seconds, (int, float))
                or not math.isfinite(float(task_timeout_seconds))
                or not 0 < float(task_timeout_seconds) <= 3600
            ):
                raise ValueError("task_timeout_seconds is outside (0, 3600]")
            self.task_timeout_seconds = float(task_timeout_seconds)
        else:
            self.task_timeout_seconds = None
        if not principal_id or not project_id:
            raise ValueError("coding evaluation owner identity is required")

    async def run(self, scenario_id: str) -> CodingEvaluationRun:
        """Run one manifest scenario with bounded cleanup."""

        scenario = self.manifest.get(scenario_id)
        return await self.run_scenario(scenario)

    async def run_scenario(self, scenario: CodingScenario) -> CodingEvaluationRun:
        run_id = new_run_id()
        started_at = utc_timestamp()
        trace = CodingTraceCollector(
            max_events=scenario.limits.max_tool_events,
            max_model_turns=scenario.limits.max_model_turns,
            max_tool_calls=scenario.limits.max_tool_calls,
            run_id=run_id,
        )
        provider_observation_start = (
            len(self.provider_observations)
            if self.provider_observations is not None
            else None
        )
        fixture: MaterializedFixture | None = None
        agent: AgentExecution | None = None
        oracle_evaluation: OracleEvaluation | None = None
        final_root: Path | None = None
        before: dict[str, bytes] = {}
        after: dict[str, bytes] = {}
        error: str | None = None
        evidence_error: str | None = None
        verdict: CodingVerdict | None = None
        try:
            fixture = await self.fixture_manager.materialize(scenario)
            if scenario.base_revision is not None and fixture.base_revision != scenario.base_revision:
                raise FixtureError("materialized fixture base revision disagrees with scenario")
            fixture.assert_source_unchanged()
            before = snapshot_tree(
                fixture.agent_root,
                max_files=scenario.limits.max_source_files,
                max_bytes=scenario.limits.max_source_bytes,
            )
            trace.record("fixture", scenario.scenario_id, success=True)
            try:
                timeout_seconds = (
                    self.task_timeout_seconds
                    if self.task_timeout_seconds is not None
                    else scenario.limits.timeout_seconds
                )
                async with asyncio.timeout(timeout_seconds):
                    agent = await self.agent_invoker.run(scenario, fixture, trace)
            except TimeoutError:
                error = "agent runtime exceeded scenario timeout"
                verdict = CodingVerdict.TIMEOUT
                agent = AgentExecution(
                    status="TIMEOUT",
                    completion_status=None,
                    final_root=fixture.agent_root,
                    runtime_id="unknown",
                    model=self.model,
                    provider=self.provider,
                    error=error,
                )
                trace.record("agent", "timeout", success=False)
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # noqa: BLE001 - runtime boundary becomes typed evidence
                error = _safe_error(exc)
                verdict = CodingVerdict.AGENT_ERROR
                agent = AgentExecution(
                    status="ERROR",
                    completion_status=None,
                    final_root=fixture.agent_root,
                    runtime_id="unknown",
                    model=self.model,
                    provider=self.provider,
                    error=error,
                )
                trace.record("agent", "error", success=False)
            assert agent is not None
            # A failed runtime must not be allowed to nominate an arbitrary
            # path for post-failure inspection.  Some adapters retain a
            # partially constructed workspace even when model/provider
            # admission fails; that path is not successful-agent evidence.
            # Keep the failure typed as an agent/runtime result and inspect
            # only the fixture-owned baseline tree.
            final_root = (
                _validated_final_root(agent.final_root, fixture)
                if agent.completed
                else fixture.agent_root
            )
            after = snapshot_tree(
                final_root,
                max_files=scenario.limits.max_changed_files + scenario.limits.max_source_files,
                max_bytes=scenario.limits.max_diff_bytes,
            )
            diff = summarize_diff(
                before,
                after,
                max_diff_bytes=scenario.limits.max_diff_bytes,
            )
            if verdict in {CodingVerdict.AGENT_ERROR, CodingVerdict.TIMEOUT, CodingVerdict.INVALID_FIXTURE}:
                pass
            elif not agent.completed:
                verdict = CodingVerdict.AGENT_ERROR
                error = agent.error or "agent did not reach a terminal success status"
            else:
                oracle_evaluation = await self.oracle.evaluate(
                    scenario.oracle,
                    fixture=fixture,
                    evaluated_root=final_root,
                    diff=diff,
                    review_findings=agent.review_findings,
                    read_only=scenario.kind.value == "CODE_REVIEW",
                )
                oracle_evaluation = _apply_scenario_diff_bounds(
                    scenario,
                    diff,
                    oracle_evaluation,
                )
                verdict = oracle_evaluation.verdict
                error = oracle_evaluation.error
            fixture.assert_source_unchanged()
        except asyncio.CancelledError:
            try:
                if agent is not None and agent.cleanup is not None:
                    await asyncio.shield(agent.cleanup())
            finally:
                if fixture is not None:
                    await asyncio.shield(fixture.cleanup())
            raise
        except (CodingContractError, FixtureError) as exc:
            error = str(exc)
            verdict = CodingVerdict.INVALID_FIXTURE
            if fixture is not None:
                final_root = fixture.agent_root
            trace.record("fixture", "invalid", success=False)
        except (OracleError, OSError, ValueError) as exc:
            error = _safe_error(exc)
            verdict = CodingVerdict.ORACLE_ERROR if oracle_evaluation is None else CodingVerdict.AGENT_ERROR
            trace.record("evaluation", "error", success=False)
        finally:
            if fixture is not None and final_root is None:
                final_root = fixture.agent_root

        if fixture is None:
            return await self._record_invalid_fixture(
                scenario,
                trace=trace,
                error=error or "coding evaluation fixture was not materialized",
                started_at=started_at,
            )
        if not before:
            try:
                before = snapshot_tree(
                    fixture.agent_root,
                    max_files=scenario.limits.max_source_files,
                    max_bytes=scenario.limits.max_source_bytes,
                )
            except (OracleError, OSError, ValueError) as exc:
                evidence_error = _safe_error(exc)
        if not after:
            try:
                after = snapshot_tree(
                    final_root or fixture.agent_root,
                    max_files=scenario.limits.max_source_files + scenario.limits.max_changed_files,
                    max_bytes=scenario.limits.max_diff_bytes,
                )
            except (OracleError, OSError, ValueError) as exc:
                evidence_error = evidence_error or _safe_error(exc)
                # Do not fabricate a source diff when the final tree cannot be
                # inspected.  The terminal verdict below remains an oracle
                # error unless a higher-priority timeout/agent/fixture error
                # already explains the run.
                after = dict(before)
        try:
            diff = summarize_diff(
                before,
                after,
                max_diff_bytes=scenario.limits.max_diff_bytes,
            )
        except (OracleError, OSError, ValueError) as exc:
            evidence_error = evidence_error or _safe_error(exc)
            diff = _empty_diff(evidence_error)
        if evidence_error:
            error = error or evidence_error
            if verdict not in {
                CodingVerdict.TIMEOUT,
                CodingVerdict.AGENT_ERROR,
                CodingVerdict.INVALID_FIXTURE,
            }:
                verdict = CodingVerdict.ORACLE_ERROR
        if verdict is None:
            verdict = CodingVerdict.AGENT_ERROR
        if agent is None:
            agent = AgentExecution(
                status="ERROR",
                completion_status=None,
                final_root=final_root or fixture.agent_root,
                runtime_id="unknown",
                model="unknown",
                provider="unknown",
                error=error,
            )
        identity = CodingRunIdentity(
            run_id=run_id,
            scenario_id=scenario.scenario_id,
            scenario_version=scenario.version,
            scenario_digest=scenario.digest,
            oracle_spec_digest=digest_payload(scenario.oracle.to_payload()),
            fixture_digest=fixture.fixture_digest,
            source_sha=self.khaos_source_sha,
            model=agent.model or "unknown",
            provider=agent.provider or "unknown",
            config_digest=self.config_digest,
            runtime_profile="coding-evaluation",
            runtime_id=agent.runtime_id or "unknown",
        )
        try:
            evaluated_source_digest = fixture.digest_evaluated_tree(
                final_root or fixture.agent_root
            )
        except (FixtureError, OSError, ValueError) as exc:
            evaluated_source_digest = digest_payload(
                {"evaluated_source_unavailable": _safe_error(exc)}
            )
            error = error or _safe_error(exc)
            if verdict not in {
                CodingVerdict.TIMEOUT,
                CodingVerdict.AGENT_ERROR,
                CodingVerdict.INVALID_FIXTURE,
            }:
                verdict = CodingVerdict.ORACLE_ERROR
        if oracle_evaluation is not None:
            review_check = next(
                (
                    check
                    for check in oracle_evaluation.checks
                    if check.kind is OracleKind.REVIEW_FINDING
                ),
                None,
            )
            if review_check is not None:
                review_evidence = dict(review_check.evidence)
                review_evidence["passed"] = review_check.passed
                trace.record_semantic_review(review_evidence)
        if provider_observation_start is not None and self.provider_observations is not None:
            trace.record_provider_observations(
                self.provider_observations[provider_observation_start:]
            )
        metrics = trace.finish(
            verdict=verdict,
            agent_status=agent.status,
            completion_status=agent.completion_status,
            input_tokens=agent.input_tokens,
            output_tokens=agent.output_tokens,
            oracle_pass_count=(
                sum(check.passed for check in oracle_evaluation.checks)
                if oracle_evaluation is not None
                else 0
            ),
            oracle_fail_count=(
                sum(not check.passed for check in oracle_evaluation.checks)
                if oracle_evaluation is not None
                else 0
            ),
            diff_changed_files=len(diff.changed_files),
            diff_insertions=diff.insertions,
            diff_deletions=diff.deletions,
            unrelated_changed_files=len(
                set(diff.changed_files) - set(scenario.expected_files)
            ) if scenario.kind.value != "CODE_REVIEW" else len(diff.changed_files),
        )
        failure_reason = _classify_failure(
            verdict,
            scenario,
            agent=agent,
            oracle=oracle_evaluation,
            diff=diff,
            trace=trace,
            metrics=metrics,
        )
        run = CodingEvaluationRun.new(
            identity=identity,
            scenario_kind=scenario.kind,
            fixture_base_revision=fixture.base_revision,
            fixture_source_digest=fixture.source_digest,
            evaluated_source_digest=evaluated_source_digest,
            verdict=verdict,
            agent=AgentExecution(
                status=agent.status,
                completion_status=agent.completion_status,
                final_root=final_root or fixture.agent_root,
                runtime_id=agent.runtime_id,
                model=agent.model,
                provider=agent.provider,
                review_findings=agent.review_findings,
                input_tokens=agent.input_tokens,
                output_tokens=agent.output_tokens,
                error=error or agent.error,
                task_id=agent.task_id,
                workspace_id=agent.workspace_id,
            ),
            metrics=metrics,
            oracle=oracle_evaluation,
            diff=diff,
            trace=trace.events,
            started_at=started_at,
            finished_at=utc_timestamp(),
            task_id=agent.task_id,
            workspace_id=agent.workspace_id,
            failure_reason=failure_reason,
        )
        try:
            if self.repository is not None:
                await self.repository.append(run)
        finally:
            try:
                if agent.cleanup is not None:
                    await asyncio.shield(agent.cleanup())
            finally:
                await asyncio.shield(fixture.cleanup())
        return run

    async def _record_invalid_fixture(
        self,
        scenario: CodingScenario,
        *,
        trace: CodingTraceCollector,
        error: str,
        started_at: str,
    ) -> CodingEvaluationRun:
        """Persist an infrastructure-classified invalid-fixture result."""

        placeholder = digest_payload(
            {"invalid_fixture": scenario.scenario_id, "scenario_digest": scenario.digest}
        )
        diff = DiffSummary(
            changed_files=(),
            added_files=(),
            deleted_files=(),
            renamed_files=(),
            insertions=0,
            deletions=0,
            binary_files=(),
            digest=digest_payload({"changed_files": (), "error": error}),
        )
        agent = AgentExecution(
            status="INVALID_FIXTURE",
            completion_status=None,
            final_root=Path("<invalid-fixture>"),
            runtime_id="unknown",
            model="unknown",
            provider="unknown",
            error=error[:1024],
        )
        identity = CodingRunIdentity(
            run_id=trace.run_id,
            scenario_id=scenario.scenario_id,
            scenario_version=scenario.version,
            scenario_digest=scenario.digest,
            oracle_spec_digest=digest_payload(scenario.oracle.to_payload()),
            fixture_digest=placeholder,
            source_sha=self.khaos_source_sha,
            model="unknown",
            provider="unknown",
            config_digest=self.config_digest,
            runtime_profile="coding-evaluation",
            runtime_id="unknown",
        )
        metrics = trace.finish(
            verdict=CodingVerdict.INVALID_FIXTURE,
            agent_status=agent.status,
            completion_status=None,
            diff_changed_files=0,
            diff_insertions=0,
            diff_deletions=0,
        )
        run = CodingEvaluationRun.new(
            identity=identity,
            scenario_kind=scenario.kind,
            fixture_base_revision="unknown",
            fixture_source_digest=placeholder,
            evaluated_source_digest=placeholder,
            verdict=CodingVerdict.INVALID_FIXTURE,
            agent=agent,
            metrics=metrics,
            oracle=None,
            diff=diff,
            trace=trace.events,
            started_at=started_at,
            finished_at=utc_timestamp(),
            failure_reason=CodingFailureReason.INVALID_FIXTURE,
        )
        if self.repository is not None:
            await self.repository.append(run)
        return run

    async def run_many(self, scenarios: Sequence[CodingScenario]) -> tuple[CodingEvaluationRun, ...]:
        """Run selected scenarios serially so isolated resources do not overlap."""

        results: list[CodingEvaluationRun] = []
        for scenario in scenarios:
            results.append(await self.run_scenario(scenario))
        return tuple(results)


def _validated_final_root(value: object, fixture: MaterializedFixture) -> Path:
    if value is None:
        lexical_root = fixture.agent_root
    elif isinstance(value, (str, Path)):
        lexical_root = Path(value)
    else:
        raise FixtureError("agent final workspace path is invalid")
    lexical_root = lexical_root.expanduser().absolute()
    if lexical_root.is_symlink():
        raise FixtureError("agent final workspace must not be a symlink")
    try:
        # ``/tmp`` is a symlink to ``/private/tmp`` on macOS.  Compare the
        # Agent worktree and fixture authority root in the same canonical
        # namespace, while retaining the lexical symlink rejection above.
        root = lexical_root.resolve(strict=True)
        private = fixture._private_root.expanduser().resolve(strict=True)
    except OSError as exc:
        raise FixtureError("agent final workspace cannot be resolved") from exc
    oracle_root = private / "oracle"
    if root == oracle_root or oracle_root in root.parents:
        raise FixtureError("oracle-owned workspace cannot be used as agent output")
    if root != private and private not in root.parents:
        raise FixtureError("agent final workspace is outside the private fixture root")
    if not root.is_dir():
        raise FixtureError("agent final workspace is not a regular directory")
    return root


def _safe_error(exc: BaseException) -> str:
    message = str(exc).strip().replace("\n", " ")
    if not message:
        return type(exc).__name__
    return message[:1024]


def _empty_diff(error: str) -> DiffSummary:
    """Return explicit unavailable diff evidence without inventing changes."""

    return DiffSummary(
        changed_files=(),
        added_files=(),
        deleted_files=(),
        renamed_files=(),
        insertions=0,
        deletions=0,
        binary_files=(),
        digest=digest_payload({"diff_unavailable": error[:1024]}),
    )


def _apply_scenario_diff_bounds(
    scenario: CodingScenario,
    diff: DiffSummary,
    evaluation: OracleEvaluation,
) -> OracleEvaluation:
    """Apply scenario-level diff bounds without changing oracle ownership."""

    if evaluation.verdict is CodingVerdict.ORACLE_ERROR:
        return evaluation
    violations: list[str] = []
    if (
        scenario.max_changed_files is not None
        and len(diff.changed_files) > scenario.max_changed_files
    ):
        violations.append("changed_file_count_exceeded")
    changed_lines = diff.insertions + diff.deletions
    if scenario.max_diff_lines is not None and changed_lines > scenario.max_diff_lines:
        violations.append("diff_line_count_exceeded")
    if scenario.max_changed_files is None and scenario.max_diff_lines is None:
        return evaluation
    passed = not violations
    checks = tuple(evaluation.checks) + (
        OracleCheckResult(
            kind=OracleKind.DIFF,
            passed=passed,
            summary="scenario diff bounds matched" if passed else "scenario diff bounds exceeded",
            evidence={
                "changed_file_count": len(diff.changed_files),
                "changed_lines": changed_lines,
                "max_changed_files": scenario.max_changed_files,
                "max_diff_lines": scenario.max_diff_lines,
                "violations": violations,
            },
        ),
    )
    return OracleEvaluation(
        verdict=CodingVerdict.PASS if all(check.passed for check in checks) else CodingVerdict.FAIL,
        checks=checks,
        evidence_digest=digest_payload([check.to_payload() for check in checks]),
        error=evaluation.error,
    )


def _classify_failure(
    verdict: CodingVerdict,
    scenario: CodingScenario,
    *,
    agent: AgentExecution,
    oracle: OracleEvaluation | None,
    diff: DiffSummary,
    trace: CodingTraceCollector | None = None,
    metrics: CodingMetrics | None = None,
) -> CodingFailureReason | None:
    """Map a terminal observation to a stable, non-authoritative reason."""

    if verdict is CodingVerdict.PASS:
        return None
    direct = {
        CodingVerdict.ORACLE_ERROR: CodingFailureReason.ORACLE_ERROR,
        CodingVerdict.INVALID_FIXTURE: CodingFailureReason.INVALID_FIXTURE,
        CodingVerdict.INSUFFICIENT_EVIDENCE: CodingFailureReason.INSUFFICIENT_EVIDENCE,
    }
    if verdict is CodingVerdict.TIMEOUT:
        # An outer task deadline cancels the AgentLoop while ModelClient is
        # still waiting for the provider response.  That is a provider
        # failure, not a model reasoning limit.  Require the bounded
        # observation to show that no first response byte arrived and no
        # typed provider error was already projected; otherwise preserve the
        # ordinary task-timeout attribution.
        if _timed_out_during_provider_request(metrics):
            return CodingFailureReason.PROVIDER_FAILURE
        return CodingFailureReason.TIMEOUT
    if verdict is CodingVerdict.AGENT_ERROR:
        if agent.status == "TOOL_BUDGET_EXHAUSTED" or (
            agent.error is not None
            and "TOOL_BUDGET_EXHAUSTED" in agent.error
        ):
            return CodingFailureReason.TOOL_BUDGET_EXHAUSTED
        return (
            CodingFailureReason.PROVIDER_FAILURE
            if _looks_like_provider_failure(agent.error)
            else CodingFailureReason.AGENT_ERROR
        )
    if verdict in direct:
        return direct[verdict]
    if oracle is None:
        return CodingFailureReason.EDIT_FAILURE
    failed_kinds = {check.kind.value for check in oracle.checks if not check.passed}
    if "REVIEW_FINDING" in failed_kinds:
        if (
            scenario.review_category_contract == REVIEW_CATEGORY_CONTRACT_V3
            and _response_contract_failed(trace)
        ):
            return CodingFailureReason.OUTPUT_CONTRACT_FAILURE
        review_check = next(
            check for check in oracle.checks if check.kind.value == "REVIEW_FINDING"
        )
        unmatched_count = review_check.evidence.get("unmatched_count", 0)
        false_positive_count = review_check.evidence.get("false_positive_count", 0)
        duplicate_count = review_check.evidence.get("duplicate_count", 0)
        if scenario.review_category_contract == REVIEW_CATEGORY_CONTRACT_V3:
            return CodingFailureReason.SEMANTIC_REVIEW_FAILURE
        if isinstance(unmatched_count, int) and unmatched_count > 0:
            return CodingFailureReason.REVIEW_MISSED_FINDING
        if (
            isinstance(false_positive_count, int)
            and false_positive_count > 0
        ) or (
            isinstance(duplicate_count, int)
            and duplicate_count > 0
        ):
            return CodingFailureReason.REVIEW_FALSE_POSITIVE
        return CodingFailureReason.REVIEW_MISSED_FINDING
    if "DIFF" in failed_kinds:
        changed = set(diff.changed_files)
        if changed & set(scenario.forbidden_files):
            return CodingFailureReason.WRONG_FILES_CHANGED
        if not changed and scenario.kind.value != "CODE_REVIEW":
            return CodingFailureReason.NO_PROGRESS
        diff_spec = next(
            (item for item in _flatten_oracles(scenario.oracle) if isinstance(item, DiffOracleSpec)),
            None,
        )
        if diff_spec is not None and (
            len(changed) > diff_spec.max_changed_files
            or diff.insertions > diff_spec.max_insertions
            or diff.deletions > diff_spec.max_deletions
            or (
                diff_spec.max_diff_lines is not None
                and diff.insertions + diff.deletions > diff_spec.max_diff_lines
            )
        ):
            return CodingFailureReason.EXCESSIVE_DIFF
        if (
            scenario.max_changed_files is not None
            and len(changed) > scenario.max_changed_files
        ) or (
            scenario.max_diff_lines is not None
            and diff.insertions + diff.deletions > scenario.max_diff_lines
        ):
            return CodingFailureReason.EXCESSIVE_DIFF
        return CodingFailureReason.WRONG_FILES_CHANGED
    if "FILE_STATE" in failed_kinds:
        return CodingFailureReason.REGRESSION_FAILURE
    if "COMMAND" in failed_kinds:
        return CodingFailureReason.TEST_FAILURE
    return CodingFailureReason.EDIT_FAILURE


def _timed_out_during_provider_request(metrics: CodingMetrics | None) -> bool:
    """Detect a task deadline that interrupted an unresponsive provider call."""

    if metrics is None or not isinstance(metrics.observability, Mapping):
        return False
    provider = metrics.observability.get("provider")
    if not isinstance(provider, Mapping):
        return False
    requests = provider.get("requests")
    if not isinstance(requests, list) or not requests:
        return False
    latest = requests[-1]
    if not isinstance(latest, Mapping):
        return False
    return (
        latest.get("first_byte_latency_ms") is None
        and latest.get("provider_error_type") is None
    )


def _response_contract_failed(trace: CodingTraceCollector | None) -> bool:
    """Return whether the final response failed before semantic evaluation."""

    if trace is None:
        return False
    for event in reversed(trace.events):
        if event.event_type != "response_parse_evaluated":
            continue
        metadata = event.safe_event_metadata
        if not isinstance(metadata, Mapping):
            return False
        return any(
            metadata.get(name) == "FAIL"
            for name in (
                "json_decode_status",
                "schema_validation_status",
                "typed_parse_status",
            )
        )
    return False


def _looks_like_provider_failure(error: str | None) -> bool:
    """Classify provider/model admission failures without retaining raw text."""

    if not error:
        return False
    normalized = error.casefold()
    markers = (
        "no available model",
        "model unavailable",
        "provider",
        "rate limit",
        "authentication",
        "api key",
        "credential",
        "http 401",
        "http 403",
        "http 429",
        # ``ErrorHandler`` intentionally emits only a redacted exception
        # class when an HTTP timeout has no message.  Preserve the provider
        # failure boundary instead of turning that typed transport outcome
        # into a coding/tool failure.
        "readtimeout",
        "connecttimeout",
        "writetimeout",
        "pooltimeout",
        "model timeout",
        "model_timeout",
    )
    return any(marker in normalized for marker in markers)


def _flatten_oracles(spec):
    from khaos.evaluation.coding.contracts import CompositeOracleSpec

    if isinstance(spec, CompositeOracleSpec):
        for child in spec.children:
            yield from _flatten_oracles(child)
    else:
        yield spec


__all__ = [
    "AgentInvokerCallable",
    "CodingAgentInvoker",
    "CodingEvaluationRunner",
    "CodingRunRepository",
]
