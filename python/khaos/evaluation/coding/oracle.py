"""External, deterministic oracles for Coding evaluation runs.

The evaluated agent never receives this module's manifest, hidden fixture, or
ground truth.  Command execution is an injected ``ExecutionService`` adapter;
the oracle does not create an independent subprocess security mechanism.
"""

from __future__ import annotations

import asyncio
import difflib
import hashlib
import json
import os
import stat
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Protocol

from khaos.coding.execution import (
    ExecutionRequest,
    ExecutionResult,
    ExecutionService,
    NetworkPolicy,
    ResourceBudget,
)
from khaos.evaluation.coding.contracts import (
    CodingContractError,
    CodingVerdict,
    CommandOracleSpec,
    CompositeOracleSpec,
    DiffOracleSpec,
    FileStateOracleSpec,
    FindingMatchMode,
    OracleKind,
    OracleSpec,
    ReviewFindingExpectation,
    ReviewOracleSpec,
)
from khaos.evaluation.coding.fixtures import MaterializedFixture, OracleWorkspace
from khaos.security.protocol_boundary import canonical_digest, canonical_json_bytes


class OracleError(RuntimeError):
    """An oracle could not produce trusted evidence."""


@dataclass(frozen=True, slots=True)
class CommandExecution:
    """Bounded command outcome with digests instead of raw hidden output."""

    status: str
    return_code: int | None
    stdout_bytes: int
    stderr_bytes: int
    stdout_digest: str
    stderr_digest: str
    duration_ms: int
    output_truncated: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.status, str) or not self.status.strip():
            raise OracleError("oracle command status is invalid")
        if self.return_code is not None and (
            type(self.return_code) is not int or not -128 <= self.return_code <= 255
        ):
            raise OracleError("oracle command return code is invalid")
        for name in ("stdout_bytes", "stderr_bytes", "duration_ms"):
            value = getattr(self, name)
            if type(value) is not int or value < 0:
                raise OracleError(f"oracle command {name} is invalid")
        for name in ("stdout_digest", "stderr_digest"):
            value = getattr(self, name)
            if not isinstance(value, str) or len(value) != 64:
                raise OracleError(f"oracle command {name} is invalid")
        if type(self.output_truncated) is not bool:
            raise OracleError("oracle command truncation flag is invalid")

    @classmethod
    def from_execution_result(cls, result: ExecutionResult) -> CommandExecution:
        stdout = result.stdout.encode("utf-8", errors="replace")
        stderr = result.stderr.encode("utf-8", errors="replace")
        diagnostics = result.diagnostics
        if not isinstance(diagnostics, Mapping):
            raise OracleError("oracle command completeness diagnostics are missing")
        truncation_keys = ("output_truncated", "stdout_truncated", "stderr_truncated")
        present = [key for key in truncation_keys if key in diagnostics]
        if not present or any(type(diagnostics[key]) is not bool for key in present):
            raise OracleError("oracle command completeness diagnostics are malformed")
        output_truncated = any(bool(diagnostics[key]) for key in present)
        return cls(
            status=str(result.status),
            return_code=result.return_code,
            stdout_bytes=len(stdout),
            stderr_bytes=len(stderr),
            stdout_digest=hashlib.sha256(stdout).hexdigest(),
            stderr_digest=hashlib.sha256(stderr).hexdigest(),
            duration_ms=int(result.duration_ms),
            output_truncated=output_truncated,
        )

    def to_payload(self) -> dict[str, object]:
        return {
            "status": self.status,
            "return_code": self.return_code,
            "stdout_bytes": self.stdout_bytes,
            "stderr_bytes": self.stderr_bytes,
            "stdout_digest": self.stdout_digest,
            "stderr_digest": self.stderr_digest,
            "duration_ms": self.duration_ms,
            "output_truncated": self.output_truncated,
        }


class OracleCommandExecutor(Protocol):
    """Trusted command execution port owned by the existing execution plane."""

    async def execute(
        self,
        argv: tuple[str, ...],
        *,
        cwd: Path,
        timeout_seconds: float,
        max_output_bytes: int,
        environment: Mapping[str, str],
    ) -> CommandExecution: ...


class ExecutionServiceOracleExecutor:
    """Adapt the existing ExecutionService to the external oracle port."""

    def __init__(self, execution_service: ExecutionService) -> None:
        self.execution_service = execution_service

    async def execute(
        self,
        argv: tuple[str, ...],
        *,
        cwd: Path,
        timeout_seconds: float,
        max_output_bytes: int,
        environment: Mapping[str, str],
    ) -> CommandExecution:
        if not argv or any(not isinstance(arg, str) or not arg for arg in argv):
            raise OracleError("oracle argv is invalid")
        backend = getattr(self.execution_service, "backend", None)
        if backend is None or backend.__class__.__name__ in {
            "HostExecutionBackend",
            "UnsupportedBackend",
        }:
            raise OracleError("oracle requires a concrete OS-enforced execution backend")
        # ``python3`` is a logical manifest command.  Bind it to the trusted
        # interpreter running this evaluator so macOS does not resolve an
        # unavailable system shim (and so the sandbox can bind its exact
        # runtime root).  The manifest still owns the command shape; this is
        # not model-controlled command rewriting.
        command_argv = (
            (sys.executable, *argv[1:])
            if argv[0] in {"python", "python3"}
            else argv
        )
        result = await self.execution_service.execute(
            ExecutionRequest(
                argv=command_argv,
                cwd=cwd,
                writable_roots=(cwd,),
                environment=dict(environment),
                allowed_environment_keys=frozenset(
                    {"PATH", "LANG", "LC_ALL", "TMPDIR", *environment, "PYTHONDONTWRITEBYTECODE"}
                ),
                network_policy=NetworkPolicy.NONE,
                budget=ResourceBudget(
                    timeout_seconds=timeout_seconds,
                    output_bytes=max_output_bytes,
                ),
                access_mode="read-only",
            )
        )
        return CommandExecution.from_execution_result(result)


@dataclass(frozen=True, slots=True)
class DiffSummary:
    """Bounded source-tree diff evidence."""

    changed_files: tuple[str, ...]
    added_files: tuple[str, ...]
    deleted_files: tuple[str, ...]
    renamed_files: tuple[str, ...]
    insertions: int
    deletions: int
    binary_files: tuple[str, ...]
    digest: str

    def __post_init__(self) -> None:
        for name in (
            "changed_files",
            "added_files",
            "deleted_files",
            "renamed_files",
            "binary_files",
        ):
            value = getattr(self, name)
            if not isinstance(value, (list, tuple)) or any(
                not isinstance(item, str) or not item for item in value
            ):
                raise OracleError(f"diff {name} is invalid")
            if len(set(value)) != len(value):
                raise OracleError(f"diff {name} contains duplicates")
            object.__setattr__(self, name, tuple(value))
        for name in ("insertions", "deletions"):
            value = getattr(self, name)
            if type(value) is not int or value < 0:
                raise OracleError(f"diff {name} is invalid")
        if not isinstance(self.digest, str) or len(self.digest) != 64:
            raise OracleError("diff digest is invalid")

    def to_payload(self) -> dict[str, object]:
        return {
            "changed_files": list(self.changed_files),
            "added_files": list(self.added_files),
            "deleted_files": list(self.deleted_files),
            "renamed_files": list(self.renamed_files),
            "insertions": self.insertions,
            "deletions": self.deletions,
            "binary_files": list(self.binary_files),
            "digest": self.digest,
        }


@dataclass(frozen=True, slots=True)
class ReviewFinding:
    """Sanitized agent-provided structured review finding."""

    category: str
    file: str
    concepts: tuple[str, ...]
    line: int | None = None
    severity: str = "medium"

    def __post_init__(self) -> None:
        if not isinstance(self.category, str) or not self.category.strip():
            raise OracleError("review finding category is invalid")
        if (
            not isinstance(self.file, str)
            or not self.file.strip()
            or Path(self.file).is_absolute()
            or ".." in Path(self.file).parts
            or Path(self.file) == Path(".")
        ):
            raise OracleError("review finding file is invalid")
        if (
            not isinstance(self.concepts, tuple)
            or not self.concepts
            or any(not isinstance(item, str) or not item.strip() for item in self.concepts)
            or len(set(self.concepts)) != len(self.concepts)
        ):
            raise OracleError("review finding concepts are invalid")
        if self.line is not None and (type(self.line) is not int or self.line <= 0):
            raise OracleError("review finding line is invalid")
        if self.severity not in {"low", "medium", "high", "critical"}:
            raise OracleError("review finding severity is invalid")
        object.__setattr__(self, "category", self.category.strip())
        object.__setattr__(self, "file", Path(self.file).as_posix())
        object.__setattr__(self, "concepts", tuple(item.strip() for item in self.concepts))

    @classmethod
    def from_mapping(cls, value: Mapping[str, object]) -> ReviewFinding:
        allowed = {"category", "file", "concepts", "line", "severity", "summary"}
        if set(value) - allowed:
            raise OracleError("review finding contains unknown fields")
        category = value.get("category")
        file = value.get("file")
        concepts = value.get("concepts")
        if not isinstance(category, str) or not category.strip():
            raise OracleError("review finding category is invalid")
        if not isinstance(file, str) or not file.strip() or Path(file).is_absolute() or ".." in Path(file).parts:
            raise OracleError("review finding file is invalid")
        if not isinstance(concepts, (list, tuple)) or not concepts or any(
            not isinstance(item, str) or not item.strip() for item in concepts
        ):
            raise OracleError("review finding concepts are invalid")
        line = value.get("line")
        if line is not None and (type(line) is not int or line <= 0):
            raise OracleError("review finding line is invalid")
        severity = value.get("severity", "medium")
        if severity not in {"low", "medium", "high", "critical"}:
            raise OracleError("review finding severity is invalid")
        summary = value.get("summary")
        if summary is not None and (
            not isinstance(summary, str) or len(summary.encode("utf-8")) > 4 * 1024
        ):
            raise OracleError("review finding summary is invalid")
        normalized_concepts = tuple(item.strip() for item in concepts)
        if len(set(normalized_concepts)) != len(normalized_concepts):
            raise OracleError("review finding concepts contain duplicates")
        return cls(category.strip(), Path(file).as_posix(), normalized_concepts, line, str(severity))

    def to_payload(self) -> dict[str, object]:
        return {
            "category": self.category,
            "file": self.file,
            "concepts": list(self.concepts),
            "line": self.line,
            "severity": self.severity,
        }


@dataclass(frozen=True, slots=True)
class OracleCheckResult:
    """One oracle check with bounded, non-disclosing evidence."""

    kind: OracleKind
    passed: bool
    summary: str
    evidence: Mapping[str, object]

    def __post_init__(self) -> None:
        try:
            kind = OracleKind(self.kind)
        except (TypeError, ValueError) as exc:
            raise OracleError("oracle check kind is invalid") from exc
        if type(self.passed) is not bool:
            raise OracleError("oracle check passed flag is invalid")
        if not isinstance(self.summary, str) or not self.summary.strip() or len(self.summary) > 4096:
            raise OracleError("oracle check summary is invalid")
        if not isinstance(self.evidence, Mapping):
            raise OracleError("oracle check evidence is invalid")
        object.__setattr__(self, "kind", kind)
        object.__setattr__(self, "evidence", dict(self.evidence))

    def to_payload(self) -> dict[str, object]:
        return {
            "kind": self.kind.value,
            "passed": self.passed,
            "summary": self.summary,
            "evidence": dict(self.evidence),
        }


@dataclass(frozen=True, slots=True)
class OracleEvaluation:
    """Complete external oracle result."""

    verdict: CodingVerdict
    checks: tuple[OracleCheckResult, ...]
    evidence_digest: str
    error: str | None = None

    def __post_init__(self) -> None:
        try:
            verdict = CodingVerdict(self.verdict)
        except (TypeError, ValueError) as exc:
            raise OracleError("oracle evaluation verdict is invalid") from exc
        if not isinstance(self.checks, (list, tuple)) or any(
            not isinstance(check, OracleCheckResult) for check in self.checks
        ):
            raise OracleError("oracle evaluation checks are invalid")
        if not isinstance(self.evidence_digest, str) or len(self.evidence_digest) != 64:
            raise OracleError("oracle evaluation evidence digest is invalid")
        if self.error is not None and not isinstance(self.error, str):
            raise OracleError("oracle evaluation error is invalid")
        object.__setattr__(self, "verdict", verdict)
        object.__setattr__(self, "checks", tuple(self.checks))

    @property
    def passed(self) -> bool:
        return self.verdict is CodingVerdict.PASS

    def to_payload(self) -> dict[str, object]:
        return {
            "verdict": self.verdict.value,
            "checks": [check.to_payload() for check in self.checks],
            "evidence_digest": self.evidence_digest,
            "error": self.error,
        }


class CodingOracle:
    """Evaluate hidden/file/diff/review truth outside the agent workspace."""

    def __init__(self, command_executor: OracleCommandExecutor | None = None) -> None:
        self._command_executor = command_executor

    async def evaluate(
        self,
        spec: OracleSpec,
        *,
        fixture: MaterializedFixture,
        evaluated_root: Path,
        diff: DiffSummary,
        review_findings: tuple[ReviewFinding, ...] = (),
        read_only: bool = False,
    ) -> OracleEvaluation:
        checks: list[OracleCheckResult] = []
        try:
            await self._evaluate_spec(
                spec,
                fixture=fixture,
                evaluated_root=evaluated_root,
                diff=diff,
                review_findings=review_findings,
                checks=checks,
            )
            if read_only:
                checks.append(_read_only_diff_check(diff))
        except (OracleError, OSError, UnicodeError, ValueError) as exc:
            evidence = tuple(check.to_payload() for check in checks)
            return OracleEvaluation(
                verdict=CodingVerdict.ORACLE_ERROR,
                checks=tuple(checks),
                evidence_digest=canonical_digest(evidence),
                error=str(exc),
            )
        verdict = CodingVerdict.PASS if all(check.passed for check in checks) else CodingVerdict.FAIL
        evidence = tuple(check.to_payload() for check in checks)
        return OracleEvaluation(
            verdict=verdict,
            checks=tuple(checks),
            evidence_digest=canonical_digest(evidence),
        )

    async def _evaluate_spec(
        self,
        spec: OracleSpec,
        *,
        fixture: MaterializedFixture,
        evaluated_root: Path,
        diff: DiffSummary,
        review_findings: tuple[ReviewFinding, ...],
        checks: list[OracleCheckResult],
    ) -> None:
        if isinstance(spec, CompositeOracleSpec):
            for child in spec.children:
                await self._evaluate_spec(
                    child,
                    fixture=fixture,
                    evaluated_root=evaluated_root,
                    diff=diff,
                    review_findings=review_findings,
                    checks=checks,
                )
            return
        if isinstance(spec, CommandOracleSpec):
            checks.append(await self._command(spec, fixture=fixture, evaluated_root=evaluated_root))
            return
        if isinstance(spec, FileStateOracleSpec):
            checks.extend(_file_state(spec, evaluated_root))
            return
        if isinstance(spec, DiffOracleSpec):
            checks.append(_diff(spec, diff))
            return
        if isinstance(spec, ReviewOracleSpec):
            checks.append(_review(spec, review_findings))
            return
        raise OracleError("unsupported oracle type")

    async def _command(
        self,
        spec: CommandOracleSpec,
        *,
        fixture: MaterializedFixture,
        evaluated_root: Path,
    ) -> OracleCheckResult:
        executor = self._command_executor
        if executor is None:
            raise OracleError("oracle command has no trusted ExecutionService adapter")
        workspace: OracleWorkspace | None = None
        try:
            # The hidden directory exists only in this oracle-owned copy. It is
            # never materialized into the agent worktree or exposed as env.
            workspace = await fixture.create_oracle_workspace(evaluated_root)
            for hidden_file in spec.hidden_files:
                hidden_path = _under(workspace.hidden_root, hidden_file)
                if hidden_path.is_symlink() or not hidden_path.is_file():
                    raise OracleError("manifest hidden oracle file is unavailable")
            cwd = _under(workspace.root, spec.cwd)
            command_environment = dict(spec.environment)
            # Hidden Python verifiers must not mutate either the immutable
            # fixture package or the oracle copy with interpreter bytecode.
            command_environment.setdefault("PYTHONDONTWRITEBYTECODE", "1")
            result = await executor.execute(
                spec.argv,
                cwd=cwd,
                timeout_seconds=spec.timeout_seconds,
                max_output_bytes=spec.max_output_bytes,
                environment=command_environment,
            )
            if (
                result.output_truncated
                or result.stdout_bytes + result.stderr_bytes > spec.max_output_bytes
            ):
                raise OracleError("oracle command output exceeded its evidence bound")
            # The existing execution plane reports successful host processes as
            # ``passed``.  Keep the adapter tolerant of its older equivalent
            # spellings without treating an unknown status as success.
            passed = (
                result.status in {"passed", "completed", "success", "ok"}
                and result.return_code == spec.expected_exit_code
            )
            return OracleCheckResult(
                kind=OracleKind.COMMAND,
                passed=passed,
                summary="hidden command passed" if passed else "hidden command failed",
                evidence=result.to_payload(),
            )
        finally:
            if workspace is not None:
                await workspace.cleanup()


def _read_only_diff_check(diff: DiffSummary) -> OracleCheckResult:
    """Enforce the CODE_REVIEW no-mutation postcondition externally."""

    passed = not diff.changed_files
    return OracleCheckResult(
        kind=OracleKind.DIFF,
        passed=passed,
        summary=(
            "read-only workspace preserved"
            if passed
            else "read-only workspace was modified"
        ),
        evidence={
            "changed_files": list(diff.changed_files),
            "changed_file_count": len(diff.changed_files),
            "diff_digest": diff.digest,
        },
    )


def _file_state(spec: FileStateOracleSpec, root: Path) -> list[OracleCheckResult]:
    checks: list[OracleCheckResult] = []
    for item in spec.checks:
        path = _under(root, item.path)
        is_symlink = path.is_symlink()
        present = path.exists() or is_symlink
        exists = present and not is_symlink
        passed = (exists is item.exists) and not is_symlink
        evidence: dict[str, object] = {
            "path": item.path,
            "exists": exists,
        }
        if exists and item.exists:
            if not path.is_file():
                passed = False
                evidence["reason"] = "not_regular_file"
            else:
                data = path.read_bytes()
                if len(data) > 16 * 1024 * 1024:
                    raise OracleError("file-state target exceeds bound")
                digest = hashlib.sha256(data).hexdigest()
                evidence["sha256"] = digest
                text = data.decode("utf-8", errors="replace")
                evidence["bytes"] = len(data)
                if item.sha256 is not None and digest != item.sha256:
                    passed = False
                if any(needle not in text for needle in item.contains):
                    passed = False
                if any(needle in text for needle in item.not_contains):
                    passed = False
                if item.json_equals is not None:
                    try:
                        parsed = json.loads(text)
                    except (TypeError, ValueError, json.JSONDecodeError):
                        passed = False
                    else:
                        if parsed != dict(item.json_equals):
                            passed = False
        checks.append(
            OracleCheckResult(
                kind=OracleKind.FILE_STATE,
                passed=passed,
                summary="file state matched" if passed else "file state mismatch",
                evidence=evidence,
            )
        )
    return checks


def _diff(spec: DiffOracleSpec, diff: DiffSummary) -> OracleCheckResult:
    changed = set(diff.changed_files)
    required = set(spec.required_changed_files)
    forbidden = set(spec.forbidden_changed_files)
    passed = (
        required <= changed
        and not forbidden & changed
        and spec.min_changed_files <= len(changed) <= spec.max_changed_files
        and diff.insertions <= spec.max_insertions
        and diff.deletions <= spec.max_deletions
        and (
            spec.max_diff_lines is None
            or diff.insertions + diff.deletions <= spec.max_diff_lines
        )
        and (spec.allow_binary or not diff.binary_files)
    )
    return OracleCheckResult(
        kind=OracleKind.DIFF,
        passed=passed,
        summary="diff constraints matched" if passed else "diff constraints mismatch",
        evidence={
            "changed_files": list(diff.changed_files),
            "insertions": diff.insertions,
            "deletions": diff.deletions,
            "max_diff_lines": spec.max_diff_lines,
            "binary_files": list(diff.binary_files),
            "diff_digest": diff.digest,
        },
    )


def _review(spec: ReviewOracleSpec, findings: tuple[ReviewFinding, ...]) -> OracleCheckResult:
    matched: list[str] = []
    used: set[int] = set()
    duplicate_indices: set[int] = set()
    for expected in spec.required_findings:
        candidates = [
            (index, finding)
            for index, finding in enumerate(findings)
            if _finding_matches(expected, finding)
        ]
        if candidates:
            unused = [(index, finding) for index, finding in candidates if index not in used]
            if unused:
                index, _ = unused[0]
                used.add(index)
                matched.append(expected.finding_id)
                duplicate_indices.update(index for index, _ in unused[1:])
            else:
                duplicate_indices.update(index for index, _ in candidates)
        elif spec.match_mode is FindingMatchMode.ALL:
            continue
    all_required = len(matched) == len(spec.required_findings)
    any_required = bool(matched)
    passed = all_required if spec.match_mode is FindingMatchMode.ALL else any_required
    false_positive_indices = set(range(len(findings))) - used - duplicate_indices
    extra_count = len(duplicate_indices) + len(false_positive_indices)
    if not spec.allow_extra_findings and extra_count:
        passed = False
    return OracleCheckResult(
        kind=OracleKind.REVIEW_FINDING,
        passed=passed,
        summary="review findings matched" if passed else "review findings mismatch",
        evidence={
            "required_count": len(spec.required_findings),
            "matched_ids": matched,
            "submitted_count": len(findings),
            "unmatched_count": len(spec.required_findings) - len(matched),
            "duplicate_count": len(duplicate_indices),
            "false_positive_count": len(false_positive_indices),
            "extra_count": extra_count,
        },
    )


def _finding_matches(expected: ReviewFindingExpectation, actual: ReviewFinding) -> bool:
    if expected.category.casefold() != actual.category.casefold():
        return False
    if Path(expected.file).as_posix() != Path(actual.file).as_posix():
        return False
    expected_start = expected.line_start if expected.line_start is not None else expected.line
    expected_end = expected.line_end if expected.line_end is not None else expected.line
    if expected_start is not None:
        if actual.line is None or actual.line < expected_start - expected.line_tolerance:
            return False
        if expected_end is not None and actual.line > expected_end + expected.line_tolerance:
            return False
    concepts = {concept.casefold() for concept in actual.concepts}
    return all(concept.casefold() in concepts for concept in expected.concepts)


def snapshot_tree(root: Path, *, max_files: int = 256, max_bytes: int = 16 * 1024 * 1024) -> dict[str, bytes]:
    """Read a bounded regular-file snapshot without including Git metadata."""

    root = root.expanduser().absolute()
    if root.is_symlink() or not root.is_dir():
        raise OracleError("diff root is not a regular directory")
    root = root.resolve()
    result: dict[str, bytes] = {}
    total = 0
    for current, directories, files in os.walk(root, followlinks=False):
        current_path = Path(current)
        retained_directories: list[str] = []
        for directory in sorted(directories):
            directory_path = current_path / directory
            info = directory_path.lstat()
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
                raise OracleError("diff tree contains a symlink or special directory")
            if directory == ".oracle-hidden":
                raise OracleError("agent workspace contains reserved oracle directory")
            if directory not in {
                ".git",
                ".khaos",
                "__pycache__",
                ".pytest_cache",
                ".mypy_cache",
                ".ruff_cache",
                ".tox",
            }:
                retained_directories.append(directory)
        directories[:] = retained_directories
        for name in sorted(files):
            path = current_path / name
            info = path.lstat()
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
                raise OracleError("diff tree contains a symlink or special file")
            if name in {".git", ".khaos"}:
                # A Git worktree represents its control directory as a
                # regular ``.git`` pointer file.  It is runtime metadata, not
                # evaluated source, and must not turn a read-only review into
                # a false file mutation.
                continue
            if path.suffix in {".pyc", ".pyo"}:
                continue
            data = path.read_bytes()
            relative = path.relative_to(root).as_posix()
            result[relative] = data
            total += len(data)
            if len(result) > max_files or total > max_bytes:
                raise OracleError("diff tree exceeds bounds")
    return result


def summarize_diff(before: Mapping[str, bytes], after: Mapping[str, bytes], *, max_diff_bytes: int = 4 * 1024 * 1024) -> DiffSummary:
    """Compute deterministic file/change/line evidence from two snapshots."""

    names = sorted(set(before) | set(after))
    changed = tuple(name for name in names if before.get(name) != after.get(name))
    added_candidates = [name for name in names if name not in before]
    deleted_candidates = [name for name in names if name not in after]
    renamed_pairs: list[tuple[str, str]] = []
    remaining_added = set(added_candidates)
    for old_name in deleted_candidates:
        matches = sorted(
            name
            for name in remaining_added
            if before[old_name] == after[name]
        )
        if matches:
            new_name = matches[0]
            remaining_added.remove(new_name)
            renamed_pairs.append((old_name, new_name))
    renamed_pairs.sort()
    added = tuple(sorted(remaining_added))
    deleted = tuple(
        name for name in deleted_candidates
        if not any(old == name for old, _ in renamed_pairs)
    )
    renamed = tuple(f"{old} -> {new}" for old, new in renamed_pairs)
    binary = tuple(
        name
        for name in changed
        if b"\x00" in before.get(name, after.get(name, b""))
    )
    insertions = 0
    deletions = 0
    diff_size = 0
    for name in changed:
        if name in binary:
            diff_size += len(before.get(name, b"")) + len(after.get(name, b""))
            if diff_size > max_diff_bytes:
                raise OracleError("diff exceeds its byte bound")
            continue
        old = before.get(name, b"").decode("utf-8", errors="replace").splitlines()
        new = after.get(name, b"").decode("utf-8", errors="replace").splitlines()
        lines = tuple(difflib.ndiff(old, new))
        diff_size += sum(len(line.encode("utf-8")) + 1 for line in lines)
        if diff_size > max_diff_bytes:
            raise OracleError("diff exceeds its byte bound")
        insertions += sum(line.startswith("+ ") for line in lines)
        deletions += sum(line.startswith("- ") for line in lines)
    payload = {
        "changed_files": list(changed),
        "added_files": list(added),
        "deleted_files": list(deleted),
        "renamed_files": list(renamed),
        "insertions": insertions,
        "deletions": deletions,
        "binary_files": list(binary),
    }
    return DiffSummary(
        changed_files=changed,
        added_files=added,
        deleted_files=deleted,
        renamed_files=renamed,
        insertions=insertions,
        deletions=deletions,
        binary_files=binary,
        digest=canonical_digest(payload),
    )


def _under(root: Path, relative: str) -> Path:
    if not isinstance(relative, str) or "\x00" in relative:
        raise OracleError("oracle relative path is invalid")
    relative_path = Path(relative)
    if relative_path.is_absolute() or ".." in relative_path.parts:
        raise OracleError("oracle path escapes its private root")
    lexical_root = root.expanduser().absolute()
    if lexical_root.is_symlink() or not lexical_root.is_dir():
        raise OracleError("oracle root is not a regular directory")
    real_root = lexical_root.resolve()
    candidate = lexical_root / relative_path

    # Return the lexical path so callers can lstat the requested object.  A
    # prior implementation resolved the final component here, which turned a
    # symlink inside the evaluated root into its target and allowed FILE_STATE
    # to read it as if it were a regular file.  Every existing component is
    # checked before the containment proof; missing final paths remain valid
    # inputs for an ``exists: false`` assertion.
    cursor = lexical_root
    parts = relative_path.parts
    for index, part in enumerate(parts):
        cursor = cursor / part
        try:
            info = cursor.lstat()
        except FileNotFoundError:
            break
        except OSError as exc:
            raise OracleError("oracle path cannot be inspected") from exc
        if stat.S_ISLNK(info.st_mode):
            raise OracleError("oracle path contains a symlink")
        if index < len(parts) - 1 and not stat.S_ISDIR(info.st_mode):
            raise OracleError("oracle path contains a non-directory component")

    resolved_candidate = candidate.resolve(strict=False)
    if resolved_candidate != real_root and real_root not in resolved_candidate.parents:
        raise OracleError("oracle path escapes its private root")
    return candidate


__all__ = [
    "CodingOracle",
    "CommandExecution",
    "DiffSummary",
    "ExecutionServiceOracleExecutor",
    "OracleCheckResult",
    "OracleCommandExecutor",
    "OracleError",
    "OracleEvaluation",
    "ReviewFinding",
    "snapshot_tree",
    "summarize_diff",
]
