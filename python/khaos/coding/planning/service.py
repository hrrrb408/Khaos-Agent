"""Conservative read-only planner backed exclusively by M3 repository evidence."""
from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from typing import Any

from khaos.coding.intelligence.query import CodeQueryService
from khaos.coding.planning.contracts import *  # noqa: F403
from khaos.coding.planning.dag import validate_steps

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
    def __init__(self, query: CodeQueryService, *, repositories: dict[str, dict[str, Any]]) -> None:
        self._query, self._repositories = query, repositories

    def classify_goal(self, *, repository_id: str, user_goal: str) -> GoalIntentResult:
        """Classify only explicit wording; it never guesses a target."""
        raw_goal = " ".join(user_goal.split())
        resolved = self._resolve_goal_target(repository_id, raw_goal)
        parsed = resolved.parsed
        return GoalIntentResult(raw_goal, (resolved.action.intent,), (GoalTarget(parsed.raw_token, parsed.explicit_kind, parsed.requested_symbol, parsed.requested_path, self._language(parsed.requested_path or ""), resolved.action.operation.value, resolved.status, (resolved.selected_file,) if resolved.selected_file else (), tuple(x.get("stable_symbol_id", "") for x in resolved.symbol_candidates), resolved.evidence, resolved.diagnostics),), 1.0 if resolved.status == "resolved" else 0.0, resolved.diagnostics)

    def analyze_impacts(self, *, repository_id: str, target_symbols: tuple[str, ...], max_depth: int = 3, max_nodes: int = 200, max_files: int = 100) -> ImpactAnalysis:
        """Cycle-safe reverse call/reference traversal over persisted resolution edges."""
        queue = [(sid, 0) for sid in sorted(target_symbols)]; seen: set[str] = set(); direct=[]; indirect=[]; dynamic=[]; diagnostics=[]; files=set(); truncated=False
        while queue:
            sid, depth = queue.pop(0)
            if sid in seen: continue
            seen.add(sid)
            if len(seen) > max_nodes or depth > max_depth: truncated=True; break
            edges = sorted(self._query.callers_of(repository_id, sid) + self._query.references_to(repository_id, sid), key=lambda e: (e.get("source_file", ""), e.get("edge_id", "")))
            for edge in edges:
                path=edge["source_file"]; files.add(path)
                ev=PlanEvidence("resolution-graph", repository_id, path, sid, query=sid, confidence=float(edge.get("confidence",0)))
                item=ImpactEdge(path, edge.get("caller_symbol_id"), edge.get("target_file") or "", sid, "calls" if "call_callee" in edge else "references", depth+1, ImpactStatus.DIRECT if depth==0 else ImpactStatus.INDIRECT, float(edge.get("confidence",0)), edge.get("resolution_rule", "resolved"), (ev,))
                (direct if depth==0 else indirect).append(item)
                caller=edge.get("caller_symbol_id")
                if caller: queue.append((caller, depth+1))
                if len(files) > max_files: truncated=True; break
            if truncated: break
        if truncated: diagnostics.append(PlanDiagnostic("impact-truncated", "warning", "fixed graph traversal limit reached", True))
        digest=ImplementationPlan.digest({"targets":sorted(target_symbols),"direct":[asdict(x) for x in direct],"indirect":[asdict(x) for x in indirect],"truncated":truncated})
        return ImpactAnalysis((), tuple(sorted(target_symbols)), tuple(direct), tuple(indirect), (), tuple(dynamic), (), tuple(diagnostics), max((x.depth for x in direct+indirect), default=0), truncated, digest)

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
            evidence.append(ev); files.append(AffectedFile(path, operation, "indexed file target", 1.0, True, file_record["language"], (ev,)))
        elif resolved.status == "resolved" and operation == PlanOperation.CREATE and parsed.requested_path:
            ev = PlanEvidence("goal", repository_id, path=parsed.requested_path, query=token, confidence=.5)
            evidence.append(ev); files.append(AffectedFile(parsed.requested_path, operation, "explicit new file target", .5, False, self._language(parsed.requested_path), (ev,)))
        elif resolved.selected_symbol:
            item = resolved.selected_symbol; path = item["path"]; sid = item.get("stable_symbol_id")
            record = self._query.file_evidence(repository_id, path) or {}
            ev = PlanEvidence("resolution-graph", repository_id, path, sid, record.get("generation", item.get("generation")), record.get("content_hash"), token, 1.0, {"kind": item.get("kind")})
            evidence.append(ev); symbols.append(AffectedSymbol(sid, item.get("qualified_name", item["name"]), item["kind"], path, operation.value, 1.0, (ev,)))
            files.append(AffectedFile(path, operation, "unique symbol match", 1.0, True, item.get("language"), (ev,)))
            for edge in self._query.callers_of(repository_id, sid) if sid else ():
                impacts.append(DependencyImpact(edge["source_file"], path, "calls", edge["status"], edge["confidence"], "direct caller of public symbol"))
        for item in self._query.unresolved_candidates(repository_id, files[0].path) if files else []:
            diagnostics.append(PlanDiagnostic("dynamic-or-unresolved-call", "warning", item["status"], True))
        risks = self._risks(operation, files, symbols, raw_goal.casefold())
        requirements = self._verification(repo, files, evidence)
        status = PlanStatus.READY if resolved.status == "resolved" and files and not any(d.severity == "error" for d in diagnostics) else PlanStatus.BLOCKED
        step = self._steps(operation, raw_goal, files, symbols, requirements, risks[0], evidence, status)
        diagnostics.extend(validate_steps(step))
        if any(d.severity == "error" for d in diagnostics): status = PlanStatus.BLOCKED
        return self._build(repository_id, task_id, workspace_id, user_goal, normalized, base_sha, int(repo["generation"]), status, step, files, symbols, impacts, requirements, risks, diagnostics, evidence)

    def validate_plan(self, plan: ImplementationPlan, *, current_head: str, current_repository_generation: int) -> PlanValidationResult:
        issues: list[PlanDiagnostic] = []
        if plan.base_sha != current_head: issues.append(PlanDiagnostic("head-drift", "error", "HEAD changed", False))
        if plan.repository_generation != current_repository_generation: issues.append(PlanDiagnostic("generation-drift", "error", "repository generation changed", False))
        for ev in plan.evidence:
            if ev.path and ev.content_hash:
                record = self._query.file_evidence(plan.repository_id, ev.path)
                if not record or record["content_hash"] != ev.content_hash: issues.append(PlanDiagnostic("evidence-drift", "error", f"evidence changed: {ev.path}", False, (ev,)))
            if ev.symbol_id and not self._query.find_symbol_targets(plan.repository_id, ev.query): issues.append(PlanDiagnostic("symbol-drift", "error", "symbol removed or moved", False, (ev,)))
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
        blocking = {"ambiguous-target", "ambiguous-symbol", "kind-mismatch", "target-not-found", "missing-destination", "unsafe-path", "target-already-exists"}
        status = "resolved" if (selected_file or selected_symbol) and not any(item.code in blocking for item in diagnostics) else "rejected" if any(item.code == "unsafe-path" for item in diagnostics) else "ambiguous" if any(item.code.startswith("ambiguous") for item in diagnostics) else "unresolved"
        evidence: list[PlanEvidence] = []
        if selected_symbol: evidence.append(self._symbol_evidence(repository_id, parsed.raw_token, selected_symbol))
        if selected_file and file_candidate:
            evidence.append(PlanEvidence("index-store", repository_id, selected_file, generation=file_candidate["generation"], content_hash=file_candidate["content_hash"], query=parsed.raw_token, confidence=1.0))
        return ResolvedGoalTarget(parsed, action, status, file_candidate, tuple(sorted(symbol_candidates, key=lambda item: (item.get("path", ""), item.get("qualified_name", "")))), selected_file, selected_symbol, tuple(sorted(diagnostics, key=lambda item: (item.code, item.message))), tuple(evidence))

    def _symbol_evidence(self, repository_id: str, query: str, item: dict[str, Any]) -> PlanEvidence:
        record = self._query.file_evidence(repository_id, item["path"]) or {}
        return PlanEvidence("resolution-graph", repository_id, item["path"], item.get("stable_symbol_id"), record.get("generation", item.get("generation")), record.get("content_hash"), query, 1.0, {"kind": item.get("kind")})
    @staticmethod
    def _steps(operation, goal, files, symbols, requirements, risk, evidence, status):
        if not files: return ()
        targets=tuple(f.path for f in files); symbols=tuple(s.stable_symbol_id for s in symbols if s.stable_symbol_id)
        inspect=PlanStep("inspect-1", "Inspect evidence", "confirm indexed target and assumptions", PlanOperation.INSPECT, targets, symbols, (), "confirmed scope", (), risk, risk.requires_approval, tuple(evidence))
        if status != PlanStatus.READY or operation is PlanOperation.INSPECT: return (inspect,)
        primary=PlanStep("modify-1", "Apply planned source update", goal, operation, targets, symbols, ("inspect-1",), "source update prepared", (), risk, risk.requires_approval, tuple(evidence))
        tests=PlanStep("verify-1", "Verify affected scope", "run trusted verification later", PlanOperation.TEST, targets, (), ("modify-1",), "verification requirements satisfied", tuple(requirements), risk, risk.requires_approval, tuple(evidence))
        return (inspect, primary, tests)
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
