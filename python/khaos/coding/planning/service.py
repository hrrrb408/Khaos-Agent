"""Conservative read-only planner backed exclusively by M3 repository evidence."""
from __future__ import annotations

import re
from dataclasses import asdict
from typing import Any

from khaos.coding.intelligence.query import CodeQueryService
from khaos.coding.planning.contracts import *  # noqa: F403

MAX_GOAL_LENGTH = 4096


class DeterministicPlanningService:
    """No tools, shell, writes, ChangeSets, or approval transitions are exposed here."""
    def __init__(self, query: CodeQueryService, *, repositories: dict[str, dict[str, Any]]) -> None:
        self._query, self._repositories = query, repositories

    def plan(self, *, repository_id: str, task_id: str, workspace_id: str, user_goal: str, base_sha: str) -> ImplementationPlan:
        normalized = " ".join(user_goal.split()).casefold()
        diagnostics: list[PlanDiagnostic] = []
        repo = self._repositories.get(repository_id)
        if not normalized or len(normalized) > MAX_GOAL_LENGTH or repo is None or repo.get("workspace_id") != workspace_id or repo.get("head") != base_sha:
            code = "empty-goal" if not normalized else "goal-too-long" if len(normalized) > MAX_GOAL_LENGTH else "repository-not-found" if repo is None else "workspace-mismatch" if repo.get("workspace_id") != workspace_id else "base-sha-mismatch"
            diagnostics.append(PlanDiagnostic(code, "error", code.replace("-", " "), False))
            return self._build(repository_id, task_id, workspace_id, user_goal, normalized, base_sha, int(repo.get("generation", 0)) if repo else 0, PlanStatus.BLOCKED, (), (), (), (), (), (), diagnostics)
        operation = self._operation(normalized)
        token = self._target(normalized)
        candidates = self._query.find_symbol_targets(repository_id, token) if token else []
        if not candidates and token:
            candidates = self._query.indexed_symbol_candidates(repository_id, token)
        evidence: list[PlanEvidence] = []
        symbols: list[AffectedSymbol] = []
        files: list[AffectedFile] = []
        impacts: list[DependencyImpact] = []
        file_record = self._query.file_evidence(repository_id, token) if "." in token else None
        if operation in (PlanOperation.DELETE, PlanOperation.RENAME) and file_record:
            ev = PlanEvidence("index-store", repository_id, token, generation=file_record["generation"], content_hash=file_record["content_hash"], query=token, confidence=1.0)
            evidence.append(ev); files.append(AffectedFile(token, operation, "indexed file target", 1.0, True, file_record["language"], (ev,)))
        elif operation == PlanOperation.CREATE and token:
            files.append(AffectedFile(token, operation, "goal names a new file", .5, False, self._language(token), (PlanEvidence("goal", repository_id, path=token, query=normalized, confidence=.5),)))
        elif len(candidates) == 1:
            item = candidates[0]; path = item["path"]; sid = item.get("stable_symbol_id")
            record = self._query.file_evidence(repository_id, path) or {}
            ev = PlanEvidence("resolution-graph", repository_id, path, sid, record.get("generation", item.get("generation")), record.get("content_hash"), token, 1.0, {"kind": item.get("kind")})
            evidence.append(ev); symbols.append(AffectedSymbol(sid, item.get("qualified_name", item["name"]), item["kind"], path, operation.value, 1.0, (ev,)))
            files.append(AffectedFile(path, operation, "unique symbol match", 1.0, True, item.get("language"), (ev,)))
            for edge in self._query.callers_of(repository_id, sid) if sid else ():
                impacts.append(DependencyImpact(edge["source_file"], path, "calls", edge["status"], edge["confidence"], "direct caller of public symbol"))
        elif candidates:
            diagnostics.append(PlanDiagnostic("ambiguous-symbol", "warning", f"multiple symbols match {token}", True))
        else:
            diagnostics.append(PlanDiagnostic("target-not-found", "warning", f"no evidence for {token or 'target'}", True))
        for item in self._query.unresolved_candidates(repository_id, files[0].path) if files else []:
            diagnostics.append(PlanDiagnostic("dynamic-or-unresolved-call", "warning", item["status"], True))
        risks = self._risks(operation, files, symbols, normalized)
        requirements = self._verification(repo, files, evidence)
        status = PlanStatus.READY if files and not any(d.code == "ambiguous-symbol" for d in diagnostics) else PlanStatus.BLOCKED
        step = () if not files else (PlanStep("step-1", "Plan repository change", normalized, operation, tuple(f.path for f in files), tuple(s.stable_symbol_id for s in symbols if s.stable_symbol_id), (), "reviewable implementation scope", tuple(requirements), risks[0], risks[0].requires_approval, tuple(evidence)),)
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
    def _operation(goal):
        return next((op for word, op in (("rename", PlanOperation.RENAME), ("delete", PlanOperation.DELETE), ("create", PlanOperation.CREATE), ("add", PlanOperation.CREATE), ("test", PlanOperation.TEST), ("config", PlanOperation.CONFIGURE), ("document", PlanOperation.DOCUMENT), ("modify", PlanOperation.MODIFY), ("change", PlanOperation.MODIFY)) if word in goal), PlanOperation.INSPECT)
    @staticmethod
    def _target(goal):
        match = re.search(r"(?:function|symbol|file)\s+[`'\"]?([\w./-]+)", goal)
        if not match:
            match = re.search(r"(?:rename|modify|change|delete|create)\s+[`'\"]?([\w./-]+)", goal)
        value = match.group(1) if match else ""
        return value if "." in value else value.split("/")[-1]
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
