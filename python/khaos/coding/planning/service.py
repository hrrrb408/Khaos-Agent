"""Conservative read-only planner backed exclusively by M3 repository evidence."""
from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from typing import Any

from khaos.coding.intelligence.query import CodeQueryService
from khaos.coding.planning.contracts import *  # noqa: F403
from khaos.coding.planning.dag import validate_steps
from khaos.coding.planning.risk import RiskEvaluator
from khaos.coding.planning.verification import TrustedVerificationSelector
from khaos.coding.planning.verification_catalog import VerificationCatalog

MAX_GOAL_LENGTH = 4096

@dataclass(frozen=True)
class ParsedGoalTarget:
    raw_token: str
    explicit_kind: str
    requested_path: str | None
    requested_symbol: str | None
    path_syntax: bool
    requested_destination: str | None = None
    diagnostics: tuple[PlanDiagnostic, ...] = ()

@dataclass(frozen=True)
class ParsedGoalAction:
    operation: PlanOperation
    intent: GoalIntent

@dataclass(frozen=True)
class ResolvedGoalTarget:
    parsed: ParsedGoalTarget
    action: ParsedGoalAction
    status: str
    file_candidate: dict[str, Any] | None
    symbol_candidates: tuple[dict[str, Any], ...]
    selected_file: str | None
    selected_symbol: dict[str, Any] | None
    diagnostics: tuple[PlanDiagnostic, ...]
    evidence: tuple[PlanEvidence, ...]


class DeterministicPlanningService:
    """No tools, shell, writes, ChangeSets, or approval transitions are exposed here."""
    def __init__(self, query: CodeQueryService, *, repositories: dict[str, dict[str, Any]], max_depth: int = 3, max_nodes: int = 200, max_files: int = 100, max_symbols: int = 100, max_edges: int = 500, max_reverse_imports: int = 50, max_test_candidates: int = 50) -> None:
        self._query, self._repositories = query, repositories
        self._limits=(max_depth,max_nodes,max_files,max_symbols,max_edges,max_reverse_imports,max_test_candidates); self._verification_selector=TrustedVerificationSelector(); self._risk_evaluator=RiskEvaluator()
        self._catalogs: dict[str, VerificationCatalog] = {}

    def _get_catalog(self, repository_id: str) -> VerificationCatalog:
        """Build (or refresh) a VerificationCatalog for the repository.

        The catalog is read-only — it scans config files (pyproject.toml,
        package.json, go.mod, Cargo.toml) from the repository root and server
        rules from the repository metadata. It never writes, executes, or
        modifies approval state.

        FRESHNESS: The cache is keyed by a fingerprint that binds repository_id,
        config file hashes, server rules hash, and catalog parser version.
        When any of these change, the cache entry is automatically invalidated
        and a fresh catalog is built. Callers never need to manually clear
        the cache — validate_plan() always sees the current state.
        """
        repo = self._repositories.get(repository_id, {})
        root = repo.get("root")
        server_rules = tuple(
            rule for rule in repo.get("trusted_verification", ())
            if isinstance(rule, dict) and rule.get("language")
        )
        from pathlib import Path
        root_path = Path(root) if root else None
        fingerprint = VerificationCatalog.compute_fingerprint(
            repository_id, root_path, server_rules,
        )
        cached = self._catalogs.get(repository_id)
        if cached is None or cached.fingerprint != fingerprint:
            catalog = VerificationCatalog(
                root_path, server_rules=server_rules, repository_id=repository_id,
            )
            self._catalogs[repository_id] = catalog
        return self._catalogs[repository_id]

    def classify_goal(self, *, repository_id: str, user_goal: str) -> GoalIntentResult:
        """Classify only explicit wording; it never guesses a target."""
        raw_goal = " ".join(user_goal.split())
        resolved = self._resolve_goal_target(repository_id, raw_goal)
        parsed = resolved.parsed
        return GoalIntentResult(raw_goal, (resolved.action.intent,), (GoalTarget(parsed.raw_token, parsed.explicit_kind, parsed.requested_symbol, parsed.requested_path, self._language(parsed.requested_path or ""), resolved.action.operation.value, resolved.status, (resolved.selected_file,) if resolved.selected_file else (), tuple(x.get("stable_symbol_id", "") for x in resolved.symbol_candidates), resolved.evidence, resolved.diagnostics),), 1.0 if resolved.status == "resolved" else 0.0, resolved.diagnostics)

    def analyze_impacts(self, *, repository_id: str, target_symbols: tuple[str, ...], target_files: tuple[str, ...] = (), max_depth: int | None = None, max_nodes: int | None = None, max_files: int | None = None, max_symbols: int | None = None, max_edges: int | None = None, max_reverse_imports: int | None = None, max_test_candidates: int | None = None) -> ImpactAnalysis:
        """Cycle-safe reverse call/reference traversal over persisted resolution edges.

        Uses a single :class:`ImpactTraversalBudget` shared across ALL impact
        sources: callers, references, reverse imports, re-exports, module
        dependencies, unresolved/dynamic candidates, and test associations.
        Never scans the entire repository — test association uses bounded
        :meth:`CodeQueryService.associated_tests` with indexed LIMIT queries.
        """
        budget = ImpactTraversalBudget(
            max_depth=max_depth if max_depth is not None else self._limits[0],
            max_nodes=max_nodes if max_nodes is not None else self._limits[1],
            max_files=max_files if max_files is not None else self._limits[2],
            max_symbols=max_symbols if max_symbols is not None else self._limits[3],
            max_edges=max_edges if max_edges is not None else self._limits[4],
            max_reverse_imports=max_reverse_imports if max_reverse_imports is not None else self._limits[5],
            max_test_candidates=max_test_candidates if max_test_candidates is not None else self._limits[6],
        )
        queue = [(sid, 0) for sid in sorted(target_symbols)]
        direct: list[ImpactEdge] = []
        indirect: list[ImpactEdge] = []
        dynamic: list[ImpactEdge] = []
        external: list[ImpactEdge] = []
        excluded: list[ImpactEdge] = []
        diagnostics: list[PlanDiagnostic] = []
        # Seed affected files with target files (bounded by budget)
        for tf in target_files:
            budget.add_affected_file(tf)

        # --- Phase 1: Reverse call/reference graph traversal (budgeted) ---
        while queue and not budget.truncated:
            sid, depth = queue.pop(0)
            if not budget.can_visit_node(sid, depth):
                continue
            budget.mark_visited(sid)
            budget.add_affected_symbol(sid)
            edges = sorted(
                self._query.callers_of(repository_id, sid) + self._query.references_to(repository_id, sid),
                key=lambda e: (e.get("source_file", ""), e.get("edge_id", "")),
            )
            for edge in edges:
                if not budget.can_inspect_edge():
                    break
                path = edge["source_file"]
                if not budget.add_affected_file(path):
                    break
                ev = PlanEvidence("resolution-graph", repository_id, path, sid, query=sid, confidence=float(edge.get("confidence", 0)))
                relation = "calls" if "call_callee" in edge else "references"
                item = ImpactEdge(path, edge.get("caller_symbol_id"), edge.get("target_file") or "", sid, relation, depth + 1,
                                  ImpactStatus.DIRECT if depth == 0 else ImpactStatus.INDIRECT,
                                  float(edge.get("confidence", 0)), edge.get("resolution_rule", "resolved"), (ev,))
                (direct if depth == 0 else indirect).append(item)
                caller = edge.get("caller_symbol_id")
                if caller:
                    queue.append((caller, depth + 1))

        # --- Phase 2: Reverse imports + semantic re-export evidence (budgeted) ---
        # HARD BUDGET: skip this entire phase if Phase 1 already triggered truncation.
        resolved_target_files = sorted(target_files or tuple(
            item.get("path", "") for sid in target_symbols
            for item in [self._query.symbol_by_stable_id(repository_id, sid) or {}] if item
        ))
        if not budget.truncated:
            for target_file in resolved_target_files:
                if budget.truncated:
                    break
                for import_edge in self._query.reverse_imports_to(repository_id, target_file):
                    if not budget.can_inspect_reverse_import():
                        break
                    source = str(import_edge["source_file"])
                    meta = import_edge.get("metadata", {})
                    is_semantic_reexport = bool(meta.get("reexport") or meta.get("pub_use"))
                    is_init_py = source.endswith("__init__.py")
                    if is_semantic_reexport:
                        relation = "re-export"
                        impact_status = ImpactStatus.DIRECT
                        confidence = 0.92
                        reason = "semantic re-export evidence"
                    elif is_init_py:
                        relation = "possible-reexport"
                        impact_status = ImpactStatus.POSSIBLE
                        confidence = 0.5
                        reason = "python __init__.py layout推测 — not semantic evidence"
                    else:
                        relation = "reverse-import"
                        impact_status = ImpactStatus.DIRECT
                        confidence = 0.9
                        reason = "resolved reverse dependency"
                    if source in budget.affected_files and any(item.source_file == source for item in direct + indirect):
                        continue
                    if not budget.add_affected_file(source):
                        break
                    record = self._query.file_evidence(repository_id, source) or {}
                    ev = PlanEvidence("resolution-graph", repository_id, source,
                                      generation=record.get("generation"),
                                      content_hash=record.get("content_hash"),
                                      query=target_file, confidence=confidence,
                                      metadata={"reexport": is_semantic_reexport, "possible_reexport": is_init_py})
                    edge_item = ImpactEdge(source, None, target_file, None, relation, 1,
                                           impact_status, confidence, reason, (ev,))
                    if impact_status is ImpactStatus.POSSIBLE:
                        dynamic.append(edge_item)
                    else:
                        direct.append(edge_item)

                # --- Phase 3: Unresolved/dynamic candidates (budgeted) ---
                if budget.truncated:
                    break
                for item in self._query.unresolved_candidates(repository_id, target_file):
                    if not budget.can_inspect_edge():
                        break
                    status = str(item.get("status", "unresolved"))
                    impact_status = (ImpactStatus.DYNAMIC if status == "dynamic"
                                     else ImpactStatus.EXTERNAL if status == "external"
                                     else ImpactStatus.AMBIGUOUS if status == "ambiguous"
                                     else ImpactStatus.POSSIBLE)
                    ev = PlanEvidence("resolution-graph", repository_id, target_file,
                                      query=str(item.get("callee") or item.get("name") or item.get("import_module") or ""),
                                      confidence=0.3)
                    edge_item = ImpactEdge(target_file, None, "", None, item.get("edge_type", "unknown"),
                                           1, impact_status, 0.3, status, (ev,))
                    (external if impact_status is ImpactStatus.EXTERNAL else dynamic).append(edge_item)

        # --- Phase 4: Bounded test association (NO full-repo scan) ---
        # HARD BUDGET: skip test association entirely if an earlier phase truncated.
        test_result = None
        if not budget.truncated:
            test_result = self._query.associated_tests(
                repository_id,
                target_files=tuple(resolved_target_files),
                target_symbols=target_symbols,
                max_results=budget.max_test_candidates,
                max_sql_queries=10,
                max_indexed_rows=budget.max_test_candidates * 4,
            )
            budget.record_sql_batch(
                queries_issued=test_result.sql_queries_issued,
                rows_returned=test_result.sql_rows_returned,
                indexed_rows_fetched=test_result.indexed_edge_rows_fetched,
            )
            for candidate in test_result.candidates:
                if not budget.can_inspect_test_candidate():
                    break
                path = candidate.get("path", "")
                if not budget.add_affected_file(path):
                    break
                record = self._query.file_evidence(repository_id, path) or {}
                ev = PlanEvidence("test-layout-rule", repository_id, path,
                                  generation=record.get("generation"),
                                  content_hash=record.get("content_hash"),
                                  query=",".join(resolved_target_files),
                                  confidence=candidate.get("confidence", 0.5),
                                  metadata={"source": candidate.get("source", "heuristic"),
                                            "edge_type": candidate.get("edge_type", "")})
                dynamic.append(ImpactEdge(path, None, ",".join(resolved_target_files), None,
                                          "associated-test", 1, ImpactStatus.POSSIBLE,
                                          candidate.get("confidence", 0.5),
                                          candidate.get("reason", "server test-layout heuristic"), (ev,)))

        # --- Finalize ---
        if budget.truncated:
            diagnostics.append(PlanDiagnostic("impact-truncated", "warning",
                                              f"budget limit reached: {budget.limit_code}", True))
        direct = sorted(direct, key=lambda x: (x.depth, x.source_file, x.relation, x.source_symbol or ""))
        indirect = sorted(indirect, key=lambda x: (x.depth, x.source_file, x.relation, x.source_symbol or ""))
        dynamic = sorted(dynamic, key=lambda x: (x.source_file, x.relation, x.reason))
        external = sorted(external, key=lambda x: (x.source_file, x.relation))
        digest = ImplementationPlan.digest({
            "target_files": sorted(target_files),
            "targets": sorted(target_symbols),
            "direct": [asdict(x) for x in direct],
            "indirect": [asdict(x) for x in indirect],
            "dynamic": [asdict(x) for x in dynamic],
            "external": [asdict(x) for x in external],
            "truncated": budget.truncated,
        })
        return ImpactAnalysis(
            tuple(sorted(target_files)), tuple(sorted(target_symbols)),
            tuple(direct), tuple(indirect), tuple(external), tuple(dynamic), tuple(excluded),
            tuple(diagnostics), max((x.depth for x in direct + indirect), default=0),
            budget.truncated, digest,
            budget.visited_nodes_count, budget.affected_files_count, budget.affected_symbols_count,
            budget.inspected_edges, budget.inspected_file_candidates, budget.inspected_test_candidates,
            budget.inspected_reverse_imports, budget.sql_rows_returned,
            budget.sql_queries_issued, budget.indexed_edge_rows_fetched, budget.limit_code,
            bool(test_result and test_result.has_resolved_test_coverage),
        )

    def plan(self, *, repository_id: str, task_id: str, workspace_id: str, user_goal: str, base_sha: str) -> ImplementationPlan:
        raw_goal = " ".join(user_goal.split())
        normalized = raw_goal
        diagnostics: list[PlanDiagnostic] = []
        repo = self._repositories.get(repository_id)
        if not normalized or len(normalized) > MAX_GOAL_LENGTH or repo is None or repo.get("workspace_id") != workspace_id or repo.get("head") != base_sha:
            code = "empty-goal" if not normalized else "goal-too-long" if len(normalized) > MAX_GOAL_LENGTH else "repository-not-found" if repo is None else "workspace-mismatch" if repo.get("workspace_id") != workspace_id else "base-sha-mismatch"
            diagnostics.append(PlanDiagnostic(code, "error", code.replace("-", " "), False))
            return self._build(repository_id, task_id, workspace_id, user_goal, normalized, base_sha, int(repo.get("generation", 0)) if repo else 0, PlanStatus.BLOCKED, (), (), (), (), (), (), diagnostics)
        resolved = self._resolve_goal_target(repository_id, raw_goal)
        operation = resolved.action.operation
        parsed = resolved.parsed
        diagnostics.extend(resolved.diagnostics)
        token = parsed.raw_token
        candidates = list(resolved.symbol_candidates)
        evidence: list[PlanEvidence] = []
        symbols: list[AffectedSymbol] = []
        files: list[AffectedFile] = []
        impacts: list[DependencyImpact] = []
        file_record = resolved.file_candidate
        if resolved.selected_file and file_record and operation is not PlanOperation.CREATE:
            path = resolved.selected_file
            ev = PlanEvidence("index-store", repository_id, path, generation=file_record["generation"], content_hash=file_record["content_hash"], query=token, confidence=1.0)
            evidence.append(ev); files.append(AffectedFile(path, operation, "indexed file target", 1.0, True, file_record["language"], (ev,), path if operation is PlanOperation.RENAME else None, parsed.requested_destination if operation is PlanOperation.RENAME else None))
        elif resolved.status == "resolved" and operation == PlanOperation.CREATE and parsed.requested_path:
            ev = PlanEvidence("goal", repository_id, path=parsed.requested_path, query=token, confidence=.5)
            evidence.append(ev); files.append(AffectedFile(parsed.requested_path, operation, "explicit new file target", .5, False, self._language(parsed.requested_path), (ev,)))
        elif resolved.selected_symbol:
            item = resolved.selected_symbol; path = item["path"]; sid = item.get("stable_symbol_id")
            record = self._query.file_evidence(repository_id, path) or {}
            ev = PlanEvidence("resolution-graph", repository_id, path, sid, record.get("generation", item.get("generation")), record.get("content_hash"), token, 1.0, {"kind": item.get("kind"),"qualified_name":item.get("qualified_name")})
            evidence.append(ev); symbols.append(AffectedSymbol(sid, item.get("qualified_name", item["name"]), item["kind"], path, operation.value, 1.0, (ev,), parsed.requested_destination if operation is PlanOperation.RENAME else None))
            files.append(AffectedFile(path, operation, "unique symbol match", 1.0, True, item.get("language"), (ev,)))
        impact=self.analyze_impacts(repository_id=repository_id,target_symbols=tuple(s.stable_symbol_id for s in symbols if s.stable_symbol_id),target_files=tuple(f.path for f in files if f.exists)) if files else ImpactAnalysis((),(),(),(),(),(),(),(),0,False,ImplementationPlan.digest({}))
        diagnostics.extend(impact.diagnostics)
        known_paths={f.path for f in files}
        for edge in impact.direct_impacts + impact.indirect_impacts + impact.dynamic_impacts + impact.external_impacts + impact.excluded_impacts:
            impacts.append(DependencyImpact(edge.source_file,edge.target_file,edge.relation,edge.status.value,edge.confidence,edge.reason))
            if edge.status in (ImpactStatus.DIRECT,ImpactStatus.INDIRECT) and edge.source_file and edge.source_file not in known_paths:
                record=self._query.file_evidence(repository_id,edge.source_file)
                if record:
                    files.append(AffectedFile(edge.source_file,PlanOperation.MODIFY,edge.reason,edge.confidence,True,record["language"],edge.evidence)); known_paths.add(edge.source_file); evidence.extend(edge.evidence)
        public=bool(symbols and symbols[0].kind in {"class","interface","struct","enum"}) or bool(symbols and not symbols[0].qualified_name.split(".")[-1].startswith("_"))
        # has_tests is ONLY triggered by resolved graph test edges or trusted
        # mapping — never by possible_test_coverage or path-name heuristics.
        has_tests = impact.has_resolved_test_coverage
        risk=self._risk_evaluator.evaluate(operation,raw_goal,impact,public=public,has_tests=has_tests,paths=tuple(sorted(f.path for f in files)))
        risks=(risk,)
        languages={f.language for f in files if f.language}; repo_metadata=dict(repo); repo_metadata["repository_id"]=repository_id
        catalog=self._get_catalog(repository_id)
        requirements=self._verification_selector.select(repo_metadata,languages,tuple(evidence),catalog=catalog,security=resolved.action.intent is GoalIntent.SECURITY_CHANGE,schema=resolved.action.intent is GoalIntent.SCHEMA_CHANGE)
        # Include config hash evidence so config file changes invalidate plans.
        config_hash=catalog.combined_config_hash()
        # Always add verification-config evidence (even when empty) so that
        # adding a new config file is detected as drift.
        evidence.append(PlanEvidence("verification-config",repository_id,query="config-hash",confidence=1.0,metadata={"config_hash":config_hash,"config_files":dict(catalog.config_hashes)}))
        status = PlanStatus.READY if resolved.status == "resolved" and files and not any(d.severity == "error" for d in diagnostics) else PlanStatus.BLOCKED
        step = self._steps(operation, raw_goal, files, symbols, requirements, risks[0], evidence, status, impact)
        diagnostics.extend(validate_steps(step))
        if any(d.severity == "error" for d in diagnostics): status = PlanStatus.BLOCKED
        diagnostics.append(PlanDiagnostic("impact-summary","info",f"visited_nodes={impact.visited_nodes};visited_files={impact.visited_files};visited_symbols={impact.visited_symbols};inspected_edges={impact.inspected_edges};inspected_file_candidates={impact.inspected_file_candidates};inspected_test_candidates={impact.inspected_test_candidates};inspected_reverse_imports={impact.inspected_reverse_imports};sql_rows_returned={impact.sql_rows_returned};sql_queries_issued={impact.sql_queries_issued};indexed_edge_rows_fetched={impact.indexed_edge_rows_fetched};truncated={impact.truncated};limit_code={impact.limit_code or 'none'};impact_hash={impact.content_hash}",True))
        return self._build(repository_id, task_id, workspace_id, user_goal, normalized, base_sha, int(repo["generation"]), status, step, files, symbols, impacts, requirements, risks, diagnostics, evidence)

    def validate_plan(self, plan: ImplementationPlan, *, current_head: str, current_repository_generation: int) -> PlanValidationResult:
        issues: list[PlanDiagnostic] = []
        if plan.base_sha != current_head: issues.append(PlanDiagnostic("head-drift", "error", "HEAD changed", False))
        if plan.repository_generation != current_repository_generation: issues.append(PlanDiagnostic("generation-drift", "error", "repository generation changed", False))
        # Rule 8: config file changes invalidate old plans.
        current_catalog = self._get_catalog(plan.repository_id)
        current_config_hash = current_catalog.combined_config_hash()
        for ev in plan.evidence:
            if ev.source == "verification-config":
                # Compare config hashes — detects modify, delete, AND add (empty → non-empty)
                plan_hash = ev.metadata.get("config_hash", "")
                if plan_hash != current_config_hash:
                    issues.append(PlanDiagnostic("config-hash-drift", "error", "verification config changed", False, (ev,)))
            if ev.path and ev.content_hash:
                record = self._query.file_evidence(plan.repository_id, ev.path)
                if not record or record["content_hash"] != ev.content_hash: issues.append(PlanDiagnostic("evidence-drift", "error", f"evidence changed: {ev.path}", False, (ev,)))
            if ev.symbol_id and ev.metadata.get("qualified_name"):
                current=self._query.symbol_by_stable_id(plan.repository_id,ev.symbol_id); expected=ev.metadata
                if not current or current.get("path") != ev.path or current.get("qualified_name") != expected.get("qualified_name") or current.get("kind") != expected.get("kind") or int(current.get("generation",-1)) != ev.generation:
                    issues.append(PlanDiagnostic("symbol-drift", "error", "exact symbol evidence changed", False, (ev,)))
        for affected in plan.affected_files:
            if affected.destination_path and self._query.file_evidence(plan.repository_id,affected.destination_path): issues.append(PlanDiagnostic("destination-drift","error",affected.destination_path,False,affected.evidence))
        return PlanValidationResult(not issues, PlanStatus.READY if not issues else PlanStatus.STALE, tuple(issues))

    def _build(self, repository_id, task_id, workspace_id, goal, normalized, sha, generation, status, steps, files, symbols, impacts, requirements, risks, diagnostics, evidence=()):
        body = {"repository_id": repository_id, "task_id": task_id, "workspace_id": workspace_id, "normalized_goal": normalized, "base_sha": sha, "repository_generation": generation, "status": status.value, "steps": [asdict(x) for x in steps], "affected_files": [asdict(x) for x in files], "affected_symbols": [asdict(x) for x in symbols], "dependency_impacts": [asdict(x) for x in impacts], "verification_requirements": [asdict(x) for x in requirements], "risks": [asdict(x) for x in risks], "diagnostics": [asdict(x) for x in diagnostics], "evidence": [asdict(x) for x in evidence]}
        digest = ImplementationPlan.digest(body); plan_id = ImplementationPlan.digest({"repository_id": repository_id, "task_id": task_id, "base_sha": sha, "normalized_goal": normalized, "content_hash": digest})
        return ImplementationPlan(plan_id, repository_id, task_id, workspace_id, goal, normalized, sha, generation, status, normalized, tuple(steps), tuple(files), tuple(symbols), tuple(impacts), tuple(requirements), tuple(risks), tuple(diagnostics), tuple(evidence), digest)

    @staticmethod
    def _parse_action(goal: str) -> ParsedGoalAction:
        text = goal.casefold()
        prefix = re.match(r"^\s*(update\s+import|inspect|modify|change|create|add|delete|remove|rename|move|test|document|configure|schema|migration|security|dependency)\b", text)
        word = prefix.group(1) if prefix else ""
        mapping = {
            "inspect": (PlanOperation.INSPECT, GoalIntent.INSPECT), "modify": (PlanOperation.MODIFY, GoalIntent.MODIFY_SYMBOL), "change": (PlanOperation.MODIFY, GoalIntent.MODIFY_SYMBOL),
            "create": (PlanOperation.CREATE, GoalIntent.CREATE_FILE), "add": (PlanOperation.CREATE, GoalIntent.CREATE_FILE), "delete": (PlanOperation.DELETE, GoalIntent.DELETE_FILE), "remove": (PlanOperation.DELETE, GoalIntent.DELETE_FILE),
            "rename": (PlanOperation.RENAME, GoalIntent.RENAME_SYMBOL), "move": (PlanOperation.RENAME, GoalIntent.MOVE_FILE), "test": (PlanOperation.TEST, GoalIntent.UPDATE_TEST), "document": (PlanOperation.DOCUMENT, GoalIntent.UPDATE_DOCUMENTATION),
            "configure": (PlanOperation.CONFIGURE, GoalIntent.UPDATE_CONFIGURATION), "update import": (PlanOperation.INSPECT, GoalIntent.UPDATE_IMPORT), "schema": (PlanOperation.INSPECT, GoalIntent.SCHEMA_CHANGE),
            "migration": (PlanOperation.INSPECT, GoalIntent.SCHEMA_CHANGE), "security": (PlanOperation.INSPECT, GoalIntent.SECURITY_CHANGE), "dependency": (PlanOperation.INSPECT, GoalIntent.DEPENDENCY_CHANGE),
        }
        operation, intent = mapping.get(word, (PlanOperation.INSPECT, GoalIntent.UNKNOWN))
        return ParsedGoalAction(operation, intent)

    @staticmethod
    def _operation(goal):
        return DeterministicPlanningService._parse_action(goal).operation
    @staticmethod
    def _parse_target(goal: str) -> ParsedGoalTarget:
        explicit = re.search(r"\b(file|function|symbol|type|module)\s+[`'\"]?([^\s`'\"]+)", goal, re.IGNORECASE)
        fallback = re.search(r"\b(?:rename|modify|change|delete|create|inspect)\s+[`'\"]?([^\s`'\"]+)", goal, re.IGNORECASE)
        kind = explicit.group(1).casefold() if explicit else "unknown"
        token = explicit.group(2) if explicit else fallback.group(1) if fallback else ""
        destination_match = re.search(r"\s+(?:to|into)\s+[`'\"]?([^\s`'\"]+)", goal, re.IGNORECASE)
        destination = destination_match.group(1) if destination_match else None
        if not token: return ParsedGoalTarget("", kind, None, None, False, destination)
        if kind == "file" or kind == "unknown":
            windows_absolute = bool(re.match(r"^[A-Za-z]:[\\/]", token))
            unc = token.startswith(("\\\\", "//"))
            normalized = token.replace("\\", "/")
            parts = normalized.split("/")
            unsafe = token.startswith("/") or windows_absolute or unc or any(part == ".." for part in parts)
            if unsafe:
                diagnostic = PlanDiagnostic("unsafe-path", "error", f"repository-external path rejected: {token}", False)
                return ParsedGoalTarget(token, kind, None, None, True, destination, (diagnostic,))
            normalized = "/".join(part for part in parts if part not in ("", "."))
            if destination:
                destination_normalized = destination.replace("\\", "/")
                destination_parts = destination_normalized.split("/")
                destination_unsafe = destination.startswith(("/", "\\\\", "//")) or bool(re.match(r"^[A-Za-z]:[\\/]", destination)) or any(part == ".." for part in destination_parts)
                if destination_unsafe:
                    diagnostic = PlanDiagnostic("unsafe-path", "error", f"repository-external destination rejected: {destination}", False)
                    return ParsedGoalTarget(token, kind, None, None, True, destination, (diagnostic,))
                destination = "/".join(part for part in destination_parts if part not in ("", "."))
            if kind == "file": return ParsedGoalTarget(token, kind, normalized, None, True, destination)
            return ParsedGoalTarget(token, kind, normalized, token, "/" in normalized, destination)
        return ParsedGoalTarget(token, kind, None, token, False, destination)

    def _resolve_goal_target(self, repository_id: str, raw_goal: str) -> ResolvedGoalTarget:
        parsed = self._parse_target(raw_goal)
        action = self._parse_action(raw_goal)
        diagnostics = list(parsed.diagnostics)
        file_candidate = self._query.file_evidence(repository_id, parsed.requested_path) if parsed.requested_path and not parsed.diagnostics else None
        if parsed.diagnostics:
            return ResolvedGoalTarget(parsed, action, "rejected", None, (), None, None, tuple(parsed.diagnostics), ())
        symbol_candidates: list[dict[str, Any]] = []
        if parsed.requested_symbol and parsed.explicit_kind != "file" and not parsed.diagnostics:
            symbol_candidates = self._query.find_qualified_symbol_targets(repository_id, parsed.requested_symbol)
            if not symbol_candidates and "." not in parsed.requested_symbol:
                symbol_candidates = self._query.find_symbol_targets(repository_id, parsed.requested_symbol)
            allowed = {
                "function": {"function", "method"}, "type": {"class", "interface", "struct", "enum", "type"},
                "module": {"module", "package"}, "symbol": None, "unknown": None,
            }.get(parsed.explicit_kind)
            if allowed is not None:
                matching = [item for item in symbol_candidates if item.get("kind") in allowed]
                if symbol_candidates and not matching:
                    diagnostics.append(PlanDiagnostic("kind-mismatch", "warning", f"no {parsed.explicit_kind} candidate matches {parsed.raw_token}", True))
                symbol_candidates = matching
        selected_file = None; selected_symbol = None
        if parsed.explicit_kind == "file":
            if action.operation is PlanOperation.CREATE:
                if file_candidate: diagnostics.append(PlanDiagnostic("target-already-exists", "error", parsed.raw_token, False))
                elif not diagnostics: selected_file = parsed.requested_path
            elif not file_candidate:
                diagnostics.append(PlanDiagnostic("target-not-found", "warning", parsed.raw_token, True))
            else: selected_file = parsed.requested_path
        elif parsed.explicit_kind in {"function", "symbol", "type", "module"}:
            if len(symbol_candidates) == 1: selected_symbol = symbol_candidates[0]
            elif len(symbol_candidates) > 1: diagnostics.append(PlanDiagnostic("ambiguous-symbol", "warning", parsed.raw_token, True))
            elif not any(item.code == "kind-mismatch" for item in diagnostics): diagnostics.append(PlanDiagnostic("target-not-found", "warning", parsed.raw_token, True))
        else:
            if action.operation is PlanOperation.CREATE and parsed.requested_path:
                if file_candidate: diagnostics.append(PlanDiagnostic("target-already-exists", "error", parsed.raw_token, False))
                else: selected_file = parsed.requested_path
            elif file_candidate and symbol_candidates:
                diagnostics.append(PlanDiagnostic("ambiguous-target", "warning", parsed.raw_token, True))
            elif file_candidate: selected_file = parsed.requested_path
            elif len(symbol_candidates) == 1: selected_symbol = symbol_candidates[0]
            elif len(symbol_candidates) > 1: diagnostics.append(PlanDiagnostic("ambiguous-symbol", "warning", parsed.raw_token, True))
            else: diagnostics.append(PlanDiagnostic("target-not-found", "warning", parsed.raw_token or "target", True))
        if action.operation is PlanOperation.RENAME and not parsed.requested_destination:
            diagnostics.append(PlanDiagnostic("missing-destination", "warning", parsed.raw_token, True))
        if action.operation is PlanOperation.RENAME and parsed.requested_destination:
            if parsed.requested_destination == parsed.requested_path:
                diagnostics.append(PlanDiagnostic("same-destination", "error", parsed.requested_destination, False))
            elif self._query.file_evidence(repository_id, parsed.requested_destination):
                diagnostics.append(PlanDiagnostic("destination-exists", "error", parsed.requested_destination, False))
        blocking = {"ambiguous-target", "ambiguous-symbol", "kind-mismatch", "target-not-found", "missing-destination", "unsafe-path", "target-already-exists", "same-destination", "destination-exists"}
        status = "resolved" if (selected_file or selected_symbol) and not any(item.code in blocking for item in diagnostics) else "rejected" if any(item.code == "unsafe-path" for item in diagnostics) else "ambiguous" if any(item.code.startswith("ambiguous") for item in diagnostics) else "unresolved"
        evidence: list[PlanEvidence] = []
        if selected_symbol: evidence.append(self._symbol_evidence(repository_id, parsed.raw_token, selected_symbol))
        if selected_file and file_candidate:
            evidence.append(PlanEvidence("index-store", repository_id, selected_file, generation=file_candidate["generation"], content_hash=file_candidate["content_hash"], query=parsed.raw_token, confidence=1.0))
        return ResolvedGoalTarget(parsed, action, status, file_candidate, tuple(sorted(symbol_candidates, key=lambda item: (item.get("path", ""), item.get("qualified_name", "")))), selected_file, selected_symbol, tuple(sorted(diagnostics, key=lambda item: (item.code, item.message))), tuple(evidence))

    def _symbol_evidence(self, repository_id: str, query: str, item: dict[str, Any]) -> PlanEvidence:
        record = self._query.file_evidence(repository_id, item["path"]) or {}
        return PlanEvidence("resolution-graph", repository_id, item["path"], item.get("stable_symbol_id"), record.get("generation", item.get("generation")), record.get("content_hash"), query, 1.0, {"kind": item.get("kind"),"qualified_name":item.get("qualified_name")})
    @staticmethod
    def _steps(operation, goal, files, symbols, requirements, risk, evidence, status, impact):
        if not files: return ()
        targets=tuple(f.path for f in files); symbols=tuple(s.stable_symbol_id for s in symbols if s.stable_symbol_id)
        inspect=PlanStep("inspect-1", "Inspect evidence", "confirm indexed target and assumptions", PlanOperation.INSPECT, targets, symbols, (), "confirmed scope", (), risk, risk.requires_approval, tuple(evidence))
        if status != PlanStatus.READY or operation is PlanOperation.INSPECT: return (inspect,)
        primary_targets=tuple(f.path for f in files if f.operation is operation) or (targets[0],)
        primary=PlanStep("modify-1", "Apply planned source update", goal, operation, primary_targets, symbols, ("inspect-1",), "source update prepared", (), risk, risk.requires_approval, tuple(evidence))
        steps=[inspect,primary]
        dependent=tuple(sorted(f.path for f in files if f.path not in primary_targets and "test" not in f.path.casefold()))
        if dependent: steps.append(PlanStep("dependent-1","Update resolved dependents","update direct and indirect resolved dependents",PlanOperation.MODIFY,dependent,(),("modify-1",),"dependents remain compatible",(),risk,risk.requires_approval,tuple(evidence)))
        modification_ids=tuple(step.step_id for step in steps if step.operation is not PlanOperation.INSPECT)
        steps.append(PlanStep("verify-1", "Verify affected scope", "run trusted verification later", PlanOperation.TEST, targets, (), modification_ids or ("modify-1",), "verification requirements satisfied", tuple(requirements), risk, risk.requires_approval, tuple(evidence)))
        return tuple(steps)
    @staticmethod
    def _language(path):
        return {"py":"python", "js":"javascript", "ts":"typescript", "tsx":"typescript", "go":"go", "rs":"rust"}.get(path.rsplit(".", 1)[-1]) if "." in path else None
    @staticmethod
    def _risks(operation, files, symbols, goal):
        destructive = operation in (PlanOperation.DELETE, PlanOperation.RENAME)
        critical = any(x in goal for x in ("migration", "credential", "security"))
        public = bool(symbols)
        level = "critical" if critical else "high" if destructive or public else "low"
        return (RiskAssessment(level, "security" if critical else "destructive" if destructive else "public-api" if public else "local", "conservative static assessment", tuple(f.path for f in files), "require review before implementation", level in ("high", "critical")),)
    @staticmethod
    def _verification(repo, files, evidence):
        commands = repo.get("verification", ())
        return tuple(VerificationRequirement(tuple(command), "repository-command", "repository", "exit 0", True, "medium", tuple(evidence)) for command in commands)
