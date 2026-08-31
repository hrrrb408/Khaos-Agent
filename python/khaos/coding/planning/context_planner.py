"""Context-bound adapter for the existing deterministic planning rules.

This module deliberately has no filesystem, database, model, or execution
dependency.  It turns the bounded M7.2 context projection into the legacy
planner's typed impact/risk/DAG inputs and then emits the immutable M7.3
``PlanRevision`` contract.  Current repository bytes never come from the old
path-oriented ``CodeQueryService``.
"""

from __future__ import annotations

from dataclasses import asdict
from typing import Any

from khaos.agent.control.goal import GoalSpec
from khaos.coding.intelligence.context import (
    ContextBundle,
    ContextEvidence,
    ContextEvidenceKind,
    ContextFreshness,
)
from khaos.coding.planning.contracts import (
    AffectedFile,
    AffectedSymbol,
    GoalIntent,
    ImpactAnalysis,
    ImpactEdge,
    ImpactStatus,
    ImplementationPlan,
    PlanDiagnostic,
    PlanEvidence,
    PlanOperation,
    PlanStep,
    VerificationRequirement,
)
from khaos.coding.planning.dag import validate_steps
from khaos.coding.planning.limits import PlanningLimits
from khaos.coding.planning.revision import (
    PlanDisposition,
    PlanningAffectedFile,
    PlanningAffectedSymbol,
    PlanningDependencyImpact,
    PlanningDiagnostic,
    PlanningEvidenceKind,
    PlanningEvidenceRef,
    PlanningInput,
    PlanningRisk,
    PlanningRiskLevel,
    PlanningStep,
    PlanningVerificationIntent,
    PlanRevision,
)
from khaos.coding.planning.risk import RiskEvaluator
from khaos.coding.planning.verification import TrustedVerificationSelector
from khaos.security.protocol_boundary import canonical_digest

_OPERATION_WORDS: tuple[tuple[PlanOperation, GoalIntent, tuple[str, ...]], ...] = (
    (
        PlanOperation.RENAME,
        GoalIntent.RENAME_SYMBOL,
        ("rename", "重命名", "改名", "移动", "move", "迁移文件"),
    ),
    (
        PlanOperation.DELETE,
        GoalIntent.DELETE_FILE,
        ("delete", "remove", "删除", "移除"),
    ),
    (
        PlanOperation.CREATE,
        GoalIntent.CREATE_FILE,
        ("create", "add", "新增", "新建", "添加"),
    ),
    (
        PlanOperation.DOCUMENT,
        GoalIntent.UPDATE_DOCUMENTATION,
        ("document", "docs", "documentation", "文档", "说明"),
    ),
    (
        PlanOperation.TEST,
        GoalIntent.UPDATE_TEST,
        ("test", "测试", "回归测试"),
    ),
    (
        PlanOperation.CONFIGURE,
        GoalIntent.UPDATE_CONFIGURATION,
        ("config", "configuration", "配置"),
    ),
    (
        PlanOperation.MODIFY,
        GoalIntent.SECURITY_CHANGE,
        ("security", "安全", "权限", "sandbox", "沙箱"),
    ),
    (
        PlanOperation.MODIFY,
        GoalIntent.SCHEMA_CHANGE,
        ("schema", "migration", "数据库迁移", "数据迁移"),
    ),
    (
        PlanOperation.MODIFY,
        GoalIntent.DEPENDENCY_CHANGE,
        ("dependency", "dependencies", "依赖"),
    ),
    (
        PlanOperation.MODIFY,
        GoalIntent.MODIFY_SYMBOL,
        ("modify", "fix", "update", "implement", "修复", "修改", "实现", "更新"),
    ),
)

_GLOBAL_SCOPE_WORDS = (
    "repository-wide",
    "repo-wide",
    "whole repository",
    "全仓",
    "全项目",
    "整个项目",
    "所有文件",
    "全局",
)


def _operation_for_goal(goal: str) -> tuple[PlanOperation, GoalIntent]:
    folded = goal.casefold()
    for operation, intent, words in _OPERATION_WORDS:
        if any(word.casefold() in folded for word in words):
            return operation, intent
    return PlanOperation.MODIFY, GoalIntent.UNKNOWN


def _legacy_evidence(
    evidence: PlanningEvidenceRef,
    *,
    repository_id: str,
) -> PlanEvidence:
    """Create a compatibility-only legacy evidence view for shared rules."""
    source = evidence.kind.value
    return PlanEvidence(
        source,
        repository_id,
        path=evidence.relative_path,
        symbol_id=evidence.symbol_id,
        content_hash=evidence.digest,
        confidence=1.0,
    )


def _planning_evidence(
    *,
    kind: PlanningEvidenceKind,
    ref_id: str,
    digest: str | None = None,
    relative_path: str | None = None,
    symbol_id: str | None = None,
) -> PlanningEvidenceRef:
    return PlanningEvidenceRef(
        kind=kind,
        ref_id=ref_id,
        digest=digest,
        relative_path=relative_path,
        symbol_id=symbol_id,
    )


def _context_evidence(
    value: ContextEvidence,
    *,
    bundle: ContextBundle,
) -> PlanningEvidenceRef:
    kind = (
        PlanningEvidenceKind.REPOSITORY_CONFIG
        if value.kind is ContextEvidenceKind.REPOSITORY_CONFIG
        else PlanningEvidenceKind.CONTEXT_RELATION
    )
    return _planning_evidence(
        kind=kind,
        ref_id=value.ref_id,
        digest=value.digest,
        relative_path=value.subject_path,
    )


def _risk_level(value: str) -> PlanningRiskLevel:
    try:
        return PlanningRiskLevel(value)
    except ValueError:
        return PlanningRiskLevel.MEDIUM


def _revision_diagnostic(
    diagnostic: PlanDiagnostic,
    *,
    evidence: tuple[PlanningEvidenceRef, ...] = (),
) -> PlanningDiagnostic:
    return PlanningDiagnostic(
        code=diagnostic.code,
        severity=diagnostic.severity,
        message=diagnostic.message[:16 * 1024],
        recoverable=diagnostic.recoverable,
        evidence=evidence,
    )


def _verification_intent(
    requirement: VerificationRequirement,
    *,
    evidence: tuple[PlanningEvidenceRef, ...],
) -> PlanningVerificationIntent:
    return PlanningVerificationIntent(
        verification_type=requirement.verification_type,
        scope=requirement.scope,
        expected_result=requirement.expected_result,
        required=requirement.required,
        risk_level=_risk_level(requirement.risk_level),
        command=requirement.command,
        evidence=evidence,
    )


class ContextBoundPlanningAdapter:
    """Build M7.3 plans from one already-captured ``ContextBundle``.

    ``RiskEvaluator``, ``TrustedVerificationSelector`` (descriptive only),
    and the legacy DAG validator are injected from
    ``DeterministicPlanningService``.  This keeps those existing deterministic
    rules as the authority while ensuring the production source of facts is
    the M7.2 workspace-bound context bundle.
    """

    def __init__(
        self,
        *,
        risk_evaluator: RiskEvaluator,
        verification_selector: TrustedVerificationSelector,
        limits: PlanningLimits,
    ) -> None:
        self._risk_evaluator = risk_evaluator
        self._verification_selector = verification_selector
        self._limits = limits

    def build(
        self,
        *,
        goal_spec: GoalSpec,
        planning_input: PlanningInput,
        context_bundle: ContextBundle,
    ) -> PlanRevision:
        """Produce one immutable plan revision without side effects."""
        _validate_bindings(goal_spec, planning_input, context_bundle)
        base_evidence = (
            _planning_evidence(
                kind=PlanningEvidenceKind.GOAL_SPEC,
                ref_id=goal_spec.goal_spec_id,
                digest=goal_spec.semantic_digest,
            ),
            _planning_evidence(
                kind=PlanningEvidenceKind.CONTEXT_BUNDLE,
                ref_id=context_bundle.bundle_id,
                digest=context_bundle.bundle_digest,
            ),
            _planning_evidence(
                kind=PlanningEvidenceKind.TASK_SNAPSHOT,
                ref_id=canonical_digest(
                    {
                        "task_id": planning_input.task_id,
                        "cognitive_state": planning_input.cognitive_state.value,
                        "control_state_version": planning_input.control_state_version,
                        "task_status": planning_input.task_status,
                    }
                ),
            ),
        )
        if context_bundle.freshness is not ContextFreshness.FRESH:
            diagnostic = PlanningDiagnostic(
                "stale-context",
                "error",
                "context bundle is not fresh",
                True,
                base_evidence,
            )
            return _build_revision(
                goal_spec=goal_spec,
                planning_input=planning_input,
                context_bundle=context_bundle,
                disposition=PlanDisposition.STALE,
                summary="planning context is stale",
                steps=(),
                diagnostics=(diagnostic,),
                evidence=base_evidence,
            )

        operation, intent = _operation_for_goal(goal_spec.normalized_goal)
        target_files, target_symbols, target_diagnostics = self._resolve_targets(
            planning_input=planning_input,
            context_bundle=context_bundle,
            evidence=base_evidence,
        )
        evidence = list(base_evidence)
        for document in context_bundle.documents:
            evidence.append(
                _planning_evidence(
                    kind=PlanningEvidenceKind.CONTEXT_DOCUMENT,
                    ref_id=canonical_digest(
                        {
                            "bundle_id": context_bundle.bundle_id,
                            "path": document.relative_path,
                        }
                    ),
                    digest=document.content_digest,
                    relative_path=document.relative_path,
                )
            )
            evidence.extend(
                _context_evidence(item, bundle=context_bundle)
                for item in document.evidence
            )
        evidence.extend(
            _context_evidence(item, bundle=context_bundle)
            for item in context_bundle.evidence
        )
        for symbol in context_bundle.symbols:
            evidence.append(
                _planning_evidence(
                    kind=PlanningEvidenceKind.CONTEXT_SYMBOL,
                    ref_id=symbol.symbol_id,
                    digest=symbol.content_digest,
                    relative_path=symbol.relative_path,
                    symbol_id=symbol.symbol_id,
                )
            )
        evidence_tuple = tuple(sorted(set(evidence), key=lambda item: (
            item.kind.value,
            item.ref_id,
            item.relative_path or "",
            item.symbol_id or "",
        )))

        selected_documents = tuple(
            document
            for document in context_bundle.documents
            if document.relative_path in target_files
        )
        selected_symbols = tuple(
            symbol
            for symbol in context_bundle.symbols
            if symbol.symbol_id in target_symbols
            or symbol.relative_path in target_files
        )
        affected_files = tuple(
            PlanningAffectedFile(
                path=document.relative_path,
                operation=operation,
                reason="fresh context document selected by deterministic ranking",
                confidence=min(
                    1.0,
                    max(0.0, document.relevance_score / 100_000.0),
                ),
                exists=True,
                language=document.language,
                evidence=tuple(
                    item
                    for item in evidence_tuple
                    if item.relative_path == document.relative_path
                )
                or base_evidence,
            )
            for document in selected_documents
        )
        affected_symbols = tuple(
            PlanningAffectedSymbol(
                symbol_id=symbol.symbol_id,
                relative_path=symbol.relative_path,
                language=symbol.language,
                qualified_name=symbol.qualified_name,
                kind=symbol.kind,
                evidence=tuple(
                    item
                    for item in evidence_tuple
                    if item.symbol_id == symbol.symbol_id
                    or item.relative_path == symbol.relative_path
                )
                or base_evidence,
            )
            for symbol in selected_symbols
            if symbol.symbol_id in target_symbols
        )

        dependency_impacts, legacy_edges = _relation_impacts(
            context_bundle=context_bundle,
            target_files=target_files,
            evidence=evidence_tuple,
        )
        impact = _impact_analysis(
            planning_input=planning_input,
            target_files=target_files,
            target_symbols=target_symbols,
            edges=legacy_edges,
            truncated=context_bundle.truncated,
        )
        diagnostics = list(target_diagnostics)
        if (
            _is_global_goal(goal_spec.normalized_goal)
            and not planning_input.target_files
            and not planning_input.target_symbols
        ):
            diagnostics.append(
                PlanningDiagnostic(
                    "global-target-unbound",
                    "error",
                    "repository-wide planning requires explicit target binding",
                    True,
                    evidence_tuple,
                )
            )
        if context_bundle.truncated:
            diagnostics.append(
                PlanningDiagnostic(
                    "context-truncated",
                    "warning",
                    "context bundle is bounded and may not cover the full repository",
                    True,
                    evidence_tuple,
                )
            )
        public = any(
            symbol.kind in {"class", "interface", "struct", "enum"}
            or not symbol.qualified_name.split(".")[-1].startswith("_")
            for symbol in affected_symbols
        )
        risk = self._risk_evaluator.evaluate(
            operation,
            goal_spec.normalized_goal,
            impact,
            public=public,
            # Context relations can identify possible tests, but M7.3 does
            # not mint verification authority from repository text.
            has_tests=False,
            paths=target_files,
        )
        planning_risk = PlanningRisk(
            level=_risk_level(risk.level),
            category=risk.category,
            description=risk.description,
            affected_scope=risk.affected_scope,
            mitigation=risk.mitigation,
            requires_approval=risk.requires_approval,
        )
        languages = {
            document.language
            for document in selected_documents
            if document.language and document.language != "text"
        }
        legacy_requirements = self._verification_selector.select(
            {"repository_id": planning_input.repository_id},
            languages,
            tuple(_legacy_evidence(item, repository_id=planning_input.repository_id) for item in evidence_tuple),
            catalog=None,
            security=intent is GoalIntent.SECURITY_CHANGE,
            schema=intent is GoalIntent.SCHEMA_CHANGE,
        )
        verification_intents = tuple(
            _verification_intent(item, evidence=evidence_tuple)
            for item in legacy_requirements
        )
        diagnostics.extend(
            PlanningDiagnostic(
                "global-context-incomplete",
                "error",
                "bounded context cannot establish repository-wide scope",
                True,
                evidence_tuple,
            )
            for _ in (
                1,
            )
            if context_bundle.truncated
            and _is_global_goal(goal_spec.normalized_goal)
        )
        if context_bundle.truncated and operation in {
            PlanOperation.DELETE,
            PlanOperation.RENAME,
        }:
            diagnostics.append(
                PlanningDiagnostic(
                    "destructive-context-incomplete",
                    "error",
                    "destructive planning requires complete target context",
                    True,
                    evidence_tuple,
                )
            )
        requires_complete_scope = (
            operation in {
                PlanOperation.DELETE,
                PlanOperation.RENAME,
                PlanOperation.CONFIGURE,
            }
            or intent
            in {
                GoalIntent.DEPENDENCY_CHANGE,
                GoalIntent.SCHEMA_CHANGE,
                GoalIntent.SECURITY_CHANGE,
            }
        )
        if context_bundle.truncated and (
            requires_complete_scope
            or planning_risk.level
            in {PlanningRiskLevel.HIGH, PlanningRiskLevel.CRITICAL}
        ):
            diagnostics.append(
                PlanningDiagnostic(
                    "high-risk-context-incomplete",
                    "error",
                    "high-risk planning requires complete affected-scope context",
                    True,
                    evidence_tuple,
                )
            )

        legacy_files = tuple(
            AffectedFile(
                path=item.path,
                operation=item.operation,
                reason=item.reason,
                confidence=item.confidence,
                exists=item.exists,
                language=item.language,
                evidence=tuple(
                    _legacy_evidence(ref, repository_id=planning_input.repository_id)
                    for ref in item.evidence
                ),
            )
            for item in affected_files
        )
        legacy_symbols = tuple(
            AffectedSymbol(
                stable_symbol_id=item.symbol_id,
                qualified_name=item.qualified_name,
                kind=item.kind,
                path=item.relative_path,
                impact_type=operation.value,
                confidence=1.0,
                evidence=tuple(
                    _legacy_evidence(ref, repository_id=planning_input.repository_id)
                    for ref in item.evidence
                ),
            )
            for item in affected_symbols
        )
        legacy_verification = tuple(
            VerificationRequirement(
                item.command,
                item.verification_type,
                item.scope,
                item.expected_result,
                item.required,
                item.risk_level.value,
                tuple(_legacy_evidence(ref, repository_id=planning_input.repository_id) for ref in item.evidence),
            )
            for item in verification_intents
        )
        legacy_steps = self._legacy_steps(
            operation=operation,
            goal=goal_spec.normalized_goal,
            files=legacy_files,
            symbols=legacy_symbols,
            requirements=legacy_verification,
            risk=risk,
            evidence=tuple(
                _legacy_evidence(ref, repository_id=planning_input.repository_id)
                for ref in evidence_tuple
            ),
            ready=bool(affected_files)
            and not any(item.severity == "error" for item in diagnostics),
        )
        for item in validate_steps(legacy_steps):
            diagnostics.append(
                PlanningDiagnostic(
                    item.code,
                    item.severity,
                    item.message,
                    item.recoverable,
                    evidence_tuple,
                )
            )
        hard_errors = any(item.severity == "error" for item in diagnostics)
        disposition = (
            PlanDisposition.BLOCKED
            if hard_errors or not affected_files
            else PlanDisposition.READY
        )
        steps = _new_steps(
            operation=operation,
            goal=goal_spec.normalized_goal,
            files=affected_files,
            symbols=affected_symbols,
            requirements=verification_intents,
            risk=planning_risk,
            evidence=evidence_tuple,
            ready=disposition is PlanDisposition.READY,
        )
        summary = _summary(disposition, operation, target_files)
        return _build_revision(
            goal_spec=goal_spec,
            planning_input=planning_input,
            context_bundle=context_bundle,
            disposition=disposition,
            summary=summary,
            steps=steps,
            affected_files=affected_files,
            affected_symbols=affected_symbols,
            dependency_impacts=dependency_impacts,
            verification_intents=verification_intents,
            risks=(planning_risk,),
            diagnostics=tuple(diagnostics),
            evidence=evidence_tuple,
        )

    def _resolve_targets(
        self,
        *,
        planning_input: PlanningInput,
        context_bundle: ContextBundle,
        evidence: tuple[PlanningEvidenceRef, ...],
    ) -> tuple[tuple[str, ...], tuple[str, ...], tuple[PlanningDiagnostic, ...]]:
        documents = tuple(sorted(context_bundle.documents, key=lambda item: (
            -item.relevance_score,
            item.relative_path,
            item.content_digest,
        )))
        symbols = tuple(sorted(context_bundle.symbols, key=lambda item: (
            item.relative_path,
            item.qualified_name,
            item.byte_start,
            item.byte_end,
            item.symbol_id,
        )))
        diagnostics: list[PlanningDiagnostic] = []
        files: tuple[str, ...]
        if planning_input.target_files:
            missing = tuple(
                path
                for path in planning_input.target_files
                if path not in {item.relative_path for item in documents}
            )
            if missing:
                diagnostics.append(
                    PlanningDiagnostic(
                        "target-not-in-context",
                        "error",
                        "explicit target file is absent from fresh context: "
                        + ",".join(missing),
                        True,
                        evidence,
                    )
                )
            files = tuple(
                path
                for path in planning_input.target_files
                if path not in missing
            )
        elif not planning_input.target_symbols:
            # Lexical relevance alone is evidence, not target authority.  The
            # coordinator may supply a conservative explicit path hint from
            # the GoalSpec; otherwise a human/model-visible ambiguity must be
            # surfaced as BLOCKED even when one file happened to match.
            files = ()
            diagnostics.append(
                PlanningDiagnostic(
                    "missing-explicit-target",
                    "error",
                    "planning requires an explicit workspace target binding",
                    True,
                    evidence,
                )
            )
        else:
            files = ()

        selected_symbols: list[str] = []
        matched_symbol_paths: set[str] = set()
        for requested in planning_input.target_symbols:
            matches = tuple(
                item
                for item in symbols
                if item.qualified_name == requested
                or item.qualified_name.endswith("." + requested)
                or item.symbol_id == requested
            )
            if len(matches) == 1:
                selected_symbols.append(matches[0].symbol_id)
                matched_symbol_paths.add(matches[0].relative_path)
            elif len(matches) == 0:
                diagnostics.append(
                    PlanningDiagnostic(
                        "symbol-not-in-context",
                        "error",
                        f"explicit target symbol is absent from fresh context: {requested}",
                        True,
                        evidence,
                    )
                )
            else:
                diagnostics.append(
                    PlanningDiagnostic(
                        "ambiguous-symbol",
                        "error",
                        f"multiple context symbols match explicit target: {requested}",
                        True,
                        evidence,
                    )
                )
        if matched_symbol_paths:
            files = tuple(sorted(set(files).union(matched_symbol_paths)))
        if planning_input.target_symbols:
            selected = set(selected_symbols)
            selected_symbols = [item.symbol_id for item in symbols if item.symbol_id in selected]
        else:
            selected_symbols = [
                item.symbol_id
                for item in symbols
                if item.relative_path in files
                and any(
                    evidence_item.kind is ContextEvidenceKind.SYMBOL_DEFINITION
                    for evidence_item in item.evidence
                )
            ][: self._limits.max_symbols]
        if not files and not selected_symbols and not diagnostics:
            diagnostics.append(
                PlanningDiagnostic(
                    "target-not-found",
                    "error",
                    "no deterministic context target is available",
                    True,
                    evidence,
                )
            )
        return tuple(sorted(files)), tuple(sorted(selected_symbols)), tuple(diagnostics)

    @staticmethod
    def _legacy_steps(
        *,
        operation: PlanOperation,
        goal: str,
        files: tuple[AffectedFile, ...],
        symbols: tuple[AffectedSymbol, ...],
        requirements: tuple[VerificationRequirement, ...],
        risk: Any,
        evidence: tuple[PlanEvidence, ...],
        ready: bool,
    ) -> tuple[PlanStep, ...]:
        if not files:
            return ()
        targets = tuple(item.path for item in files)
        symbol_ids = tuple(item.stable_symbol_id for item in symbols if item.stable_symbol_id)
        inspect = PlanStep(
            "inspect-1",
            "Inspect evidence",
            "confirm context-bound target and assumptions",
            PlanOperation.INSPECT,
            targets,
            symbol_ids,
            (),
            "confirmed scope",
            (),
            risk,
            risk.requires_approval,
            evidence,
        )
        if not ready:
            return (inspect,)
        modify = PlanStep(
            "modify-1",
            "Apply planned source update",
            goal,
            operation,
            targets,
            symbol_ids,
            ("inspect-1",),
            "source update prepared",
            (),
            risk,
            risk.requires_approval,
            evidence,
        )
        verify = PlanStep(
            "verify-1",
            "Verify affected scope",
            "run the selected verification intent later",
            PlanOperation.TEST,
            targets,
            (),
            ("modify-1",),
            "verification intent satisfied",
            requirements,
            risk,
            risk.requires_approval,
            evidence,
        )
        return inspect, modify, verify


def _validate_bindings(
    goal_spec: GoalSpec,
    planning_input: PlanningInput,
    context_bundle: ContextBundle,
) -> None:
    if planning_input.goal_spec_id != goal_spec.goal_spec_id:
        raise ValueError("planning input GoalSpec id does not match canonical GoalSpec")
    if planning_input.goal_spec_digest != goal_spec.semantic_digest:
        raise ValueError("planning input GoalSpec digest does not match canonical GoalSpec")
    pairs = (
        (context_bundle.task_id, planning_input.task_id, "task"),
        (context_bundle.principal_id, planning_input.principal_id, "principal"),
        (context_bundle.project_id, planning_input.project_id, "project"),
        (context_bundle.goal_spec_id, planning_input.goal_spec_id, "GoalSpec id"),
        (context_bundle.goal_spec_digest, planning_input.goal_spec_digest, "GoalSpec digest"),
        (context_bundle.workspace_id, planning_input.workspace_id, "workspace"),
        (context_bundle.repository_id, planning_input.repository_id, "repository"),
        (context_bundle.base_revision, planning_input.base_revision, "base revision"),
        (context_bundle.bundle_id, planning_input.context_bundle_id, "bundle"),
        (context_bundle.bundle_digest, planning_input.context_bundle_digest, "bundle digest"),
        (context_bundle.request_digest, planning_input.context_request_digest, "request digest"),
        (context_bundle.repository_generation, planning_input.repository_generation, "repository generation"),
        (context_bundle.index_generation, planning_input.index_generation, "index generation"),
        (context_bundle.freshness, planning_input.context_freshness, "freshness"),
    )
    for actual, expected, label in pairs:
        if actual != expected:
            raise ValueError(f"planning {label} binding does not match context bundle")


def _relation_impacts(
    *,
    context_bundle: ContextBundle,
    target_files: tuple[str, ...],
    evidence: tuple[PlanningEvidenceRef, ...],
) -> tuple[tuple[PlanningDependencyImpact, ...], tuple[ImpactEdge, ...]]:
    relation_values: list[PlanningDependencyImpact] = []
    edges: list[ImpactEdge] = []
    for document in context_bundle.documents:
        for relation in document.evidence:
            if relation.kind not in {
                ContextEvidenceKind.CALLER,
                ContextEvidenceKind.CALLEE,
                ContextEvidenceKind.IMPORT,
                ContextEvidenceKind.REVERSE_IMPORT,
                ContextEvidenceKind.RELATED_TEST,
            }:
                continue
            target = relation.subject_path or (target_files[0] if target_files else document.relative_path)
            relation_values.append(
                PlanningDependencyImpact(
                    source=document.relative_path,
                    target=target,
                    relation=relation.kind.value,
                    status="possible",
                    reason="context relation evidence; resolution remains descriptive",
                )
            )
            legacy_ref = _legacy_evidence(
                _context_evidence(relation, bundle=context_bundle),
                repository_id=context_bundle.repository_id,
            )
            status = ImpactStatus.POSSIBLE
            edges.append(
                ImpactEdge(
                    document.relative_path,
                    None,
                    target,
                    None,
                    relation.kind.value,
                    1,
                    status,
                    0.5,
                    "context relation evidence",
                    (legacy_ref,),
                )
            )
    return (
        tuple(sorted(set(relation_values), key=lambda item: (item.source, item.target, item.relation))),
        tuple(sorted(edges, key=lambda item: (item.source_file, item.target_file, item.relation))),
    )


def _impact_analysis(
    *,
    planning_input: PlanningInput,
    target_files: tuple[str, ...],
    target_symbols: tuple[str, ...],
    edges: tuple[ImpactEdge, ...],
    truncated: bool,
) -> ImpactAnalysis:
    direct = tuple(edges)
    digest = ImplementationPlan.digest(
        {
            "target_files": target_files,
            "target_symbols": target_symbols,
            "edges": [asdict(item) for item in direct],
            "truncated": truncated,
            "context_bundle_digest": planning_input.context_bundle_digest,
        }
    )
    return ImpactAnalysis(
        target_files,
        target_symbols,
        direct,
        (),
        (),
        (),
        (),
        (),
        1 if direct else 0,
        truncated,
        digest,
        visited_nodes=len(target_symbols),
        visited_files=len(target_files),
        visited_symbols=len(target_symbols),
        inspected_edges=len(direct),
        inspected_file_candidates=len(target_files),
        inspected_test_candidates=0,
        inspected_reverse_imports=sum(item.relation == "reverse_import" for item in direct),
        sql_rows_returned=0,
        sql_queries_issued=0,
        indexed_edge_rows_fetched=0,
        limit_code="context-bundle-truncated" if truncated else None,
        has_resolved_test_coverage=False,
    )


def _new_steps(
    *,
    operation: PlanOperation,
    goal: str,
    files: tuple[PlanningAffectedFile, ...],
    symbols: tuple[PlanningAffectedSymbol, ...],
    requirements: tuple[PlanningVerificationIntent, ...],
    risk: PlanningRisk,
    evidence: tuple[PlanningEvidenceRef, ...],
    ready: bool,
) -> tuple[PlanningStep, ...]:
    del goal
    if not files:
        return ()
    paths = tuple(item.path for item in files)
    symbol_ids = tuple(item.symbol_id for item in symbols)
    identity = canonical_digest(
        {"operation": operation.value, "files": paths, "symbols": symbol_ids}
    )[:12]
    inspect_id = f"inspect-{identity}"
    inspect = PlanningStep(
        step_id=inspect_id,
        title="Inspect context-bound evidence",
        description="confirm selected workspace targets and assumptions",
        operation=PlanOperation.INSPECT,
        target_files=paths,
        target_symbols=symbol_ids,
        dependencies=(),
        expected_outcome="target scope confirmed",
        verification_requirements=(),
        risk=risk,
        requires_approval=risk.requires_approval,
        evidence=evidence,
    )
    if not ready:
        return (inspect,)
    modify_id = f"modify-{identity}"
    verify_id = f"verify-{identity}"
    modify = PlanningStep(
        step_id=modify_id,
        title="Apply planned source update",
        description="prepare the deterministic change within the selected scope",
        operation=operation,
        target_files=paths,
        target_symbols=symbol_ids,
        dependencies=(inspect_id,),
        expected_outcome="planned source update prepared",
        verification_requirements=(),
        risk=risk,
        requires_approval=risk.requires_approval,
        evidence=evidence,
    )
    verify = PlanningStep(
        step_id=verify_id,
        title="Verify affected scope",
        description="apply the descriptive verification intent in a later phase",
        operation=PlanOperation.TEST,
        target_files=paths,
        target_symbols=(),
        dependencies=(modify_id,),
        expected_outcome="declared verification intent can be evaluated later",
        verification_requirements=requirements,
        risk=risk,
        requires_approval=risk.requires_approval,
        evidence=evidence,
    )
    return inspect, modify, verify


def _is_global_goal(goal: str) -> bool:
    folded = goal.casefold()
    return any(word.casefold() in folded for word in _GLOBAL_SCOPE_WORDS)


def _summary(disposition: PlanDisposition, operation: PlanOperation, files: tuple[str, ...]) -> str:
    if disposition is PlanDisposition.READY:
        return f"{operation.value} plan ready for {', '.join(files[:8])}"
    if disposition is PlanDisposition.STALE:
        return "planning context is stale"
    if disposition is PlanDisposition.INVALID:
        return "planning contract is invalid"
    return "planning requires deterministic clarification or additional context"


def _build_revision(
    *,
    goal_spec: GoalSpec,
    planning_input: PlanningInput,
    context_bundle: ContextBundle,
    disposition: PlanDisposition,
    summary: str,
    steps: tuple[PlanningStep, ...],
    diagnostics: tuple[PlanningDiagnostic, ...] = (),
    evidence: tuple[PlanningEvidenceRef, ...] = (),
    affected_files: tuple[PlanningAffectedFile, ...] = (),
    affected_symbols: tuple[PlanningAffectedSymbol, ...] = (),
    dependency_impacts: tuple[PlanningDependencyImpact, ...] = (),
    verification_intents: tuple[PlanningVerificationIntent, ...] = (),
    risks: tuple[PlanningRisk, ...] = (),
) -> PlanRevision:
    return PlanRevision(
        schema_version=planning_input.schema_version,
        plan_revision_id="",
        task_id=planning_input.task_id,
        principal_id=planning_input.principal_id,
        project_id=planning_input.project_id,
        revision_sequence=0,
        parent_revision_id=None,
        goal_spec_id=goal_spec.goal_spec_id,
        goal_spec_digest=goal_spec.semantic_digest,
        workspace_id=planning_input.workspace_id,
        repository_id=planning_input.repository_id,
        base_revision=planning_input.base_revision,
        context_bundle_id=context_bundle.bundle_id,
        context_bundle_digest=context_bundle.bundle_digest,
        context_request_digest=context_bundle.request_digest,
        repository_generation=context_bundle.repository_generation,
        index_generation=context_bundle.index_generation,
        context_freshness=context_bundle.freshness,
        cognitive_state=planning_input.cognitive_state,
        control_state_version=planning_input.control_state_version,
        task_status=planning_input.task_status,
        planner_schema_version=planning_input.planner_schema_version,
        planner_algorithm_version=planning_input.planner_algorithm_version,
        planning_input_digest=planning_input.input_digest,
        disposition=disposition,
        summary=summary,
        steps=steps,
        affected_files=affected_files,
        affected_symbols=affected_symbols,
        dependency_impacts=dependency_impacts,
        verification_intents=verification_intents,
        risks=risks,
        diagnostics=diagnostics,
        evidence=evidence,
    )


__all__ = ["ContextBoundPlanningAdapter"]
