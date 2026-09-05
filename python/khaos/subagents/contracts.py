"""M8.5 parallel coding/subagent worktree contracts.

These contracts carry facts between the parent coordinator, an isolated child
workspace, and the deterministic merge coordinator.  They intentionally do
not contain shell commands, permissions, approval tokens, or completion
decisions.  Existing WorkspaceManager, EditTransaction, Verification, and
CompletionGate services remain the owners of those boundaries.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from enum import Enum
from pathlib import PurePosixPath

from khaos.security.protocol_boundary import canonical_digest

MAX_ASSIGNMENT_TEXT_BYTES = 16 * 1024
MAX_CONTEXT_ITEMS = 64
MAX_CONTEXT_BYTES = 64 * 1024
MAX_ASSIGNMENT_PATHS = 256
MAX_ASSIGNMENT_SYMBOLS = 256
MAX_RESULT_PATHS = 512
MAX_RESULT_EVIDENCE_REFS = 64
MAX_RESULT_TEXT_BYTES = 16 * 1024


class ParallelSubagentContractError(ValueError):
    """Raised when a parallel-subagent contract is malformed."""


class SubagentRole(str, Enum):
    """Child responsibility; a role never grants authority by itself."""

    RESEARCH = "research"
    IMPLEMENTATION = "implementation"
    TEST = "test"
    REVIEW = "review"


class SubagentAccessMode(str, Enum):
    """Whether a child may request mutating tools in its own workspace."""

    READ_ONLY = "read-only"
    MUTATING = "mutating"


class ChildWorkspaceState(str, Enum):
    """Lifecycle projection for one isolated child workspace."""

    STARTING = "starting"
    READY = "ready"
    RUNNING = "running"
    VERIFYING = "verifying"
    SUCCESS = "success"
    FAILED = "failed"
    CANCELLED = "cancelled"
    STALE = "stale"
    CONFLICT = "conflict"
    QUARANTINED = "quarantined"
    CLEANED = "cleaned"
    UNKNOWN = "unknown"


class SubagentResultStatus(str, Enum):
    """Terminal result statuses understood by the parent coordinator."""

    SUCCESS = "success"
    FAILED = "failed"
    CANCELLED = "cancelled"
    STALE = "stale"
    CONFLICT = "conflict"
    QUARANTINED = "quarantined"


class MergeResultStatus(str, Enum):
    """Deterministic merge outcome."""

    PUBLISHED = "published"
    PUBLISHED_UNVERIFIED = "published-unverified"
    PUBLISHED_QUARANTINED = "published-quarantined"
    REJECTED_STALE = "rejected-stale"
    CONFLICT = "conflict"
    VERIFICATION_FAILED = "verification-failed"
    CANCELLED = "cancelled"
    FAILED = "failed"
    QUARANTINED = "quarantined"


class MergeConflictKind(str, Enum):
    """Why two otherwise valid candidate changes cannot be merged safely."""

    PATH_OVERLAP = "path-overlap"
    SYMBOL_OVERLAP = "symbol-overlap"
    BASE_MISMATCH = "base-mismatch"
    ARTIFACT_MISSING = "artifact-missing"
    ASSIGNMENT_MISMATCH = "assignment-mismatch"
    CANDIDATE_DRIFT = "candidate-drift"


def _text(value: object, label: str, *, allow_empty: bool = False, limit: int = 1024) -> str:
    if type(value) is not str or (not allow_empty and not value) or "\x00" in value:
        raise ParallelSubagentContractError(f"{label} is invalid")
    if len(value.encode("utf-8")) > limit:
        raise ParallelSubagentContractError(f"{label} exceeds its bound")
    return value


def _digest(value: object, label: str, *, allow_empty: bool = False) -> str:
    if allow_empty and value == "":
        return ""
    if (
        type(value) is not str
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ParallelSubagentContractError(f"{label} must be a SHA-256 digest")
    return value


def _object_id(value: object, label: str) -> str:
    if (
        type(value) is not str
        or len(value) not in {40, 64}
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ParallelSubagentContractError(f"{label} must be a Git object id")
    return value


def _path(value: object, label: str, *, allow_root: bool = False) -> str:
    text = _text(value, label, limit=1024).replace("\\", "/")
    if text in {".", "./"}:
        if allow_root:
            return "."
        raise ParallelSubagentContractError(f"{label} must not be the workspace root")
    if text.startswith("/") or (len(text) > 1 and text[1] == ":"):
        raise ParallelSubagentContractError(f"{label} must be workspace-relative")
    candidate = PurePosixPath(text)
    if not candidate.parts or any(part in {"", ".", ".."} for part in candidate.parts):
        raise ParallelSubagentContractError(f"{label} is not normalized")
    if any(part.casefold() in {".git", ".agents", ".codex", ".khaos"} for part in candidate.parts):
        raise ParallelSubagentContractError(f"{label} reaches protected metadata")
    return candidate.as_posix()


def _paths(value: object, label: str, *, limit: int) -> tuple[str, ...]:
    if type(value) is not tuple:
        raise ParallelSubagentContractError(f"{label} must be an immutable tuple")
    if len(value) > limit:
        raise ParallelSubagentContractError(f"{label} exceeds its bound")
    normalized = tuple(sorted({_path(item, label, allow_root=True) for item in value}))
    if len(normalized) != len(value):
        raise ParallelSubagentContractError(f"{label} contains duplicates")
    return normalized


def _strings(value: object, label: str, *, limit: int, item_limit: int = 2048) -> tuple[str, ...]:
    if type(value) is not tuple:
        raise ParallelSubagentContractError(f"{label} must be an immutable tuple")
    if len(value) > limit:
        raise ParallelSubagentContractError(f"{label} exceeds its bound")
    result = tuple(_text(item, label, limit=item_limit) for item in value)
    if len(result) != len(set(result)):
        raise ParallelSubagentContractError(f"{label} contains duplicates")
    return result


def _total_bytes(values: tuple[str, ...]) -> int:
    return sum(len(value.encode("utf-8")) for value in values)


def _scope_contains(scope: str, candidate: str) -> bool:
    normalized_scope = scope.casefold()
    normalized_candidate = candidate.casefold()
    if normalized_scope == ".":
        return True
    return normalized_candidate == normalized_scope or normalized_candidate.startswith(
        f"{normalized_scope}/"
    )


@dataclass(frozen=True, slots=True)
class AssignmentContext:
    """Bounded context transfer facts selected by trusted parent code."""

    parent_task_id: str
    parent_workspace_id: str
    objective: str
    constraints: tuple[str, ...] = ()
    instructions: tuple[str, ...] = ()
    selected_paths: tuple[str, ...] = ()
    selected_symbols: tuple[str, ...] = ()
    diagnostics: tuple[str, ...] = ()
    decisions: tuple[str, ...] = ()
    base_generation: int = 1
    base_commit: str = ""

    def __post_init__(self) -> None:
        _text(self.parent_task_id, "parent_task_id")
        _text(self.parent_workspace_id, "parent_workspace_id")
        _text(self.objective, "objective", limit=MAX_ASSIGNMENT_TEXT_BYTES)
        for label, value in (
            ("constraints", self.constraints),
            ("instructions", self.instructions),
            ("diagnostics", self.diagnostics),
            ("decisions", self.decisions),
        ):
            object.__setattr__(self, label, _strings(value, label, limit=64))
        object.__setattr__(
            self,
            "selected_paths",
            _paths(self.selected_paths, "selected_paths", limit=MAX_ASSIGNMENT_PATHS),
        )
        object.__setattr__(
            self,
            "selected_symbols",
            _strings(self.selected_symbols, "selected_symbols", limit=MAX_ASSIGNMENT_SYMBOLS),
        )
        if type(self.base_generation) is not int or self.base_generation <= 0:
            raise ParallelSubagentContractError("base_generation must be positive")
        object.__setattr__(self, "base_commit", _object_id(self.base_commit, "base_commit"))
        if _total_bytes(
            (
                self.objective,
                *self.constraints,
                *self.instructions,
                *self.selected_paths,
                *self.selected_symbols,
                *self.diagnostics,
                *self.decisions,
            )
        ) > MAX_CONTEXT_BYTES:
            raise ParallelSubagentContractError("assignment context exceeds its byte bound")

    @property
    def context_digest(self) -> str:
        """Return the digest of only this bounded context package."""
        return canonical_digest(self.to_payload())

    def to_payload(self) -> dict[str, object]:
        return {
            "parent_task_id": self.parent_task_id,
            "parent_workspace_id": self.parent_workspace_id,
            "objective": self.objective,
            "constraints": self.constraints,
            "instructions": self.instructions,
            "selected_paths": self.selected_paths,
            "selected_symbols": self.selected_symbols,
            "diagnostics": self.diagnostics,
            "decisions": self.decisions,
            "base_generation": self.base_generation,
            "base_commit": self.base_commit,
        }


@dataclass(frozen=True, slots=True)
class ContextTransferItem:
    """One bounded, provenance-labelled context item."""

    kind: str
    source: str
    value: str

    def __post_init__(self) -> None:
        _text(self.kind, "context item kind", limit=128)
        _text(self.source, "context item source", limit=512)
        _text(self.value, "context item value", limit=16 * 1024)

    def to_payload(self) -> dict[str, str]:
        return {"kind": self.kind, "source": self.source, "value": self.value}


@dataclass(frozen=True, slots=True)
class ContextTransferPackage:
    """A digest-bound, bounded transfer package; no transcript is included."""

    assignment_id: str
    parent_task_id: str
    base_generation: int
    base_commit: str
    items: tuple[ContextTransferItem, ...] = ()
    transfer_digest: str = ""

    def __post_init__(self) -> None:
        _text(self.assignment_id, "assignment_id")
        _text(self.parent_task_id, "parent_task_id")
        if type(self.base_generation) is not int or self.base_generation <= 0:
            raise ParallelSubagentContractError("context base_generation must be positive")
        _object_id(self.base_commit, "context base_commit")
        if type(self.items) is not tuple or len(self.items) > MAX_CONTEXT_ITEMS:
            raise ParallelSubagentContractError("context item set exceeds its bound")
        if any(type(item) is not ContextTransferItem for item in self.items):
            raise ParallelSubagentContractError("context items are malformed")
        total = sum(len(item.value.encode("utf-8")) for item in self.items)
        if total > MAX_CONTEXT_BYTES:
            raise ParallelSubagentContractError("context transfer exceeds its byte bound")
        expected = canonical_digest(self._payload(include_digest=False))
        if self.transfer_digest and self.transfer_digest != expected:
            raise ParallelSubagentContractError("transfer_digest does not match package")
        object.__setattr__(self, "transfer_digest", expected)

    def _payload(self, *, include_digest: bool) -> dict[str, object]:
        payload: dict[str, object] = {
            "assignment_id": self.assignment_id,
            "parent_task_id": self.parent_task_id,
            "base_generation": self.base_generation,
            "base_commit": self.base_commit,
            "items": tuple(item.to_payload() for item in self.items),
        }
        if include_digest:
            payload["transfer_digest"] = self.transfer_digest
        return payload

    def to_payload(self) -> dict[str, object]:
        return self._payload(include_digest=True)


@dataclass(frozen=True, slots=True)
class SubagentAssignment:
    """Immutable authority-bounded assignment for one child."""

    parent_task_id: str
    parent_workspace_id: str
    role: SubagentRole
    objective: str
    allowed_paths: tuple[str, ...]
    allowed_symbols: tuple[str, ...]
    access_mode: SubagentAccessMode
    base_generation: int = 1
    base_commit: str = ""
    context_digest: str = ""
    assignment_digest: str = ""
    parent_principal_id: str = "parent"
    child_principal_id: str = ""
    child_runtime_id: str = ""
    project_id: str = ""
    assignment_id: str = ""
    dependencies: tuple[str, ...] = ()
    allowed_tools: tuple[str, ...] = ()
    policy_digest: str = ""
    depth: int = 1
    required: bool = True
    priority: int = 0
    base_repository_generation: int | None = None
    context: AssignmentContext | None = None

    def __post_init__(self) -> None:
        _text(self.parent_task_id, "parent_task_id")
        _text(self.parent_workspace_id, "parent_workspace_id")
        _text(self.objective, "objective", limit=MAX_ASSIGNMENT_TEXT_BYTES)
        role = self.role if isinstance(self.role, SubagentRole) else SubagentRole(self.role)
        access = (
            self.access_mode
            if isinstance(self.access_mode, SubagentAccessMode)
            else SubagentAccessMode(self.access_mode)
        )
        object.__setattr__(self, "role", role)
        object.__setattr__(self, "access_mode", access)
        if role in {SubagentRole.RESEARCH, SubagentRole.REVIEW} and access is not SubagentAccessMode.READ_ONLY:
            raise ParallelSubagentContractError("research and review assignments are read-only")
        object.__setattr__(
            self,
            "allowed_paths",
            _paths(self.allowed_paths, "allowed_paths", limit=MAX_ASSIGNMENT_PATHS),
        )
        object.__setattr__(
            self,
            "allowed_symbols",
            _strings(self.allowed_symbols, "allowed_symbols", limit=MAX_ASSIGNMENT_SYMBOLS),
        )
        for label, value in (
            ("parent_principal_id", self.parent_principal_id),
            ("project_id", self.project_id),
        ):
            _text(value, label, allow_empty=label == "project_id")
        assignment_id = self.assignment_id or uuid.uuid4().hex
        _text(assignment_id, "assignment_id", limit=128)
        object.__setattr__(self, "assignment_id", assignment_id)
        expected_principal = f"subagent:{self.parent_principal_id}:{assignment_id}"
        if self.child_principal_id and self.child_principal_id != expected_principal:
            raise ParallelSubagentContractError("child principal is not bound to this assignment")
        object.__setattr__(self, "child_principal_id", expected_principal)
        runtime_id = self.child_runtime_id or f"runtime:{assignment_id}"
        object.__setattr__(self, "child_runtime_id", _text(runtime_id, "child_runtime_id", limit=256))
        if type(self.depth) is not int or self.depth != 1:
            raise ParallelSubagentContractError("parallel child depth must be exactly one")
        if type(self.base_generation) is not int or self.base_generation <= 0:
            raise ParallelSubagentContractError("base_generation must be positive")
        if self.base_repository_generation is not None:
            if type(self.base_repository_generation) is not int or self.base_repository_generation <= 0:
                raise ParallelSubagentContractError("base_repository_generation is invalid")
            if self.base_generation != 1 and self.base_generation != self.base_repository_generation:
                raise ParallelSubagentContractError("base generation aliases disagree")
            object.__setattr__(self, "base_generation", self.base_repository_generation)
        object.__setattr__(self, "base_commit", _object_id(self.base_commit, "base_commit"))
        _digest(self.context_digest, "context_digest")
        if self.context is not None:
            if type(self.context) is not AssignmentContext:
                raise ParallelSubagentContractError("assignment context is malformed")
            if self.context.parent_task_id != self.parent_task_id or self.context.parent_workspace_id != self.parent_workspace_id:
                raise ParallelSubagentContractError("assignment context owner is mismatched")
            if self.context.base_generation != self.base_generation:
                raise ParallelSubagentContractError("assignment context generation is mismatched")
            if self.base_commit and self.context.base_commit and self.context.base_commit != self.base_commit:
                raise ParallelSubagentContractError("assignment context commit is mismatched")
            if self.context_digest != self.context.context_digest:
                raise ParallelSubagentContractError("assignment context digest is mismatched")
        object.__setattr__(self, "dependencies", _strings(self.dependencies, "dependencies", limit=32, item_limit=128))
        object.__setattr__(self, "allowed_tools", _strings(self.allowed_tools, "allowed_tools", limit=128, item_limit=256))
        if self.policy_digest:
            _digest(self.policy_digest, "policy_digest")
        if type(self.required) is not bool or type(self.priority) is not int:
            raise ParallelSubagentContractError("assignment scheduling fields are invalid")
        expected = canonical_digest(self._payload(include_digest=False))
        if self.assignment_digest and self.assignment_digest != expected:
            raise ParallelSubagentContractError("assignment_digest does not match assignment")
        object.__setattr__(self, "assignment_digest", expected)

    @property
    def base_repository_generation_value(self) -> int:
        """Compatibility name used by the M8.5 design document."""
        return self.base_generation

    @property
    def mutating(self) -> bool:
        """Whether this assignment requires a private writable Worktree."""
        return self.access_mode is SubagentAccessMode.MUTATING

    def path_allowed(self, path: str) -> bool:
        """Check a normalized workspace-relative path against the scope."""
        candidate = _path(path, "candidate path")
        return any(_scope_contains(scope, candidate) for scope in self.allowed_paths)

    def validate_changed_paths(self, paths: tuple[str, ...]) -> None:
        """Reject a result that claims changes outside the assignment scope."""
        normalized = _paths(paths, "changed_paths", limit=MAX_RESULT_PATHS)
        if any(not self.path_allowed(path) for path in normalized):
            raise ParallelSubagentContractError("child result changes a path outside its assignment")

    def _payload(self, *, include_digest: bool) -> dict[str, object]:
        payload: dict[str, object] = {
            "parent_task_id": self.parent_task_id,
            "parent_workspace_id": self.parent_workspace_id,
            "role": self.role.value,
            "objective": self.objective,
            "allowed_paths": self.allowed_paths,
            "allowed_symbols": self.allowed_symbols,
            "access_mode": self.access_mode.value,
            "base_generation": self.base_generation,
            "base_commit": self.base_commit,
            "context_digest": self.context_digest,
            "parent_principal_id": self.parent_principal_id,
            "child_principal_id": self.child_principal_id,
            "child_runtime_id": self.child_runtime_id,
            "project_id": self.project_id,
            "assignment_id": self.assignment_id,
            "dependencies": self.dependencies,
            "allowed_tools": self.allowed_tools,
            "policy_digest": self.policy_digest,
            "depth": self.depth,
            "required": self.required,
            "priority": self.priority,
        }
        if include_digest:
            payload["assignment_digest"] = self.assignment_digest
        return payload

    def to_payload(self) -> dict[str, object]:
        return self._payload(include_digest=True)


@dataclass(frozen=True, slots=True)
class ChildWorkspaceBinding:
    """Immutable parent/child workspace identity and base binding."""

    assignment_id: str
    parent_task_id: str
    parent_workspace_id: str
    child_task_id: str
    child_workspace_id: str
    child_worktree_path: str
    child_branch: str
    child_principal_id: str
    child_runtime_id: str
    base_generation: int
    base_commit: str
    binding_digest: str = ""

    def __post_init__(self) -> None:
        for label, value in (
            ("assignment_id", self.assignment_id),
            ("parent_task_id", self.parent_task_id),
            ("parent_workspace_id", self.parent_workspace_id),
            ("child_task_id", self.child_task_id),
            ("child_workspace_id", self.child_workspace_id),
            ("child_worktree_path", self.child_worktree_path),
            ("child_branch", self.child_branch),
            ("child_principal_id", self.child_principal_id),
            ("child_runtime_id", self.child_runtime_id),
        ):
            _text(value, label, limit=4096)
        if type(self.base_generation) is not int or self.base_generation <= 0:
            raise ParallelSubagentContractError("binding base_generation is invalid")
        _object_id(self.base_commit, "binding base_commit")
        expected = canonical_digest(self._payload(include_digest=False))
        if self.binding_digest and self.binding_digest != expected:
            raise ParallelSubagentContractError("binding_digest does not match binding")
        object.__setattr__(self, "binding_digest", expected)

    def _payload(self, *, include_digest: bool) -> dict[str, object]:
        payload: dict[str, object] = {
            "assignment_id": self.assignment_id,
            "parent_task_id": self.parent_task_id,
            "parent_workspace_id": self.parent_workspace_id,
            "child_task_id": self.child_task_id,
            "child_workspace_id": self.child_workspace_id,
            "child_worktree_path": self.child_worktree_path,
            "child_branch": self.child_branch,
            "child_principal_id": self.child_principal_id,
            "child_runtime_id": self.child_runtime_id,
            "base_generation": self.base_generation,
            "base_commit": self.base_commit,
        }
        if include_digest:
            payload["binding_digest"] = self.binding_digest
        return payload


@dataclass(frozen=True, slots=True)
class SubagentResult:
    """Bounded child outcome; model prose is never merge authority."""

    assignment_id: str
    parent_task_id: str
    parent_workspace_id: str
    status: SubagentResultStatus
    base_generation: int
    base_commit: str
    child_workspace_id: str
    child_final_commit: str | None = None
    changed_paths: tuple[str, ...] = ()
    change_digest: str = ""
    changeset_artifact_path: str = ""
    changeset_artifact_sha256: str = ""
    changeset_artifact_length: int = 0
    verification_status: str = "unknown"
    verification_evidence_digest: str = ""
    evidence_refs: tuple[str, ...] = ()
    summary: str = ""
    error_code: str = ""
    result_digest: str = ""

    def __post_init__(self) -> None:
        for label, value in (
            ("assignment_id", self.assignment_id),
            ("parent_task_id", self.parent_task_id),
            ("parent_workspace_id", self.parent_workspace_id),
            ("child_workspace_id", self.child_workspace_id),
            ("verification_status", self.verification_status),
        ):
            _text(value, label, allow_empty=False, limit=4096)
        status = self.status if isinstance(self.status, SubagentResultStatus) else SubagentResultStatus(self.status)
        object.__setattr__(self, "status", status)
        if type(self.base_generation) is not int or self.base_generation <= 0:
            raise ParallelSubagentContractError("result base_generation is invalid")
        _object_id(self.base_commit, "result base_commit")
        if self.child_final_commit is not None:
            _object_id(self.child_final_commit, "child_final_commit")
        object.__setattr__(self, "changed_paths", _paths(self.changed_paths, "changed_paths", limit=MAX_RESULT_PATHS))
        if self.change_digest:
            _digest(self.change_digest, "change_digest")
        if self.changeset_artifact_path:
            _text(self.changeset_artifact_path, "changeset_artifact_path", limit=4096)
        if self.changeset_artifact_sha256:
            _digest(self.changeset_artifact_sha256, "changeset_artifact_sha256")
        if type(self.changeset_artifact_length) is not int or self.changeset_artifact_length < 0:
            raise ParallelSubagentContractError("changeset_artifact_length is invalid")
        if self.changeset_artifact_path and not self.changeset_artifact_sha256:
            raise ParallelSubagentContractError("artifact path requires an artifact digest")
        object.__setattr__(self, "evidence_refs", _strings(self.evidence_refs, "evidence_refs", limit=MAX_RESULT_EVIDENCE_REFS, item_limit=1024))
        _text(self.summary, "summary", allow_empty=True, limit=MAX_RESULT_TEXT_BYTES)
        _text(self.error_code, "error_code", allow_empty=True, limit=512)
        if self.verification_evidence_digest:
            _digest(self.verification_evidence_digest, "verification_evidence_digest")
        expected = canonical_digest(self._payload(include_digest=False))
        if self.result_digest and self.result_digest != expected:
            raise ParallelSubagentContractError("result_digest does not match result")
        object.__setattr__(self, "result_digest", expected)

    def validate_against(self, assignment: SubagentAssignment) -> None:
        """Validate the result against its immutable assignment binding."""
        if self.assignment_id != assignment.assignment_id or self.parent_task_id != assignment.parent_task_id:
            raise ParallelSubagentContractError("result assignment identity is mismatched")
        if self.parent_workspace_id != assignment.parent_workspace_id:
            raise ParallelSubagentContractError("result parent workspace is mismatched")
        if self.base_generation != assignment.base_generation or self.base_commit != assignment.base_commit:
            raise ParallelSubagentContractError("result base binding is stale")
        assignment.validate_changed_paths(self.changed_paths)
        if self.status is SubagentResultStatus.SUCCESS:
            if self.child_final_commit is None or not self.changeset_artifact_path:
                raise ParallelSubagentContractError("successful child result lacks commit/artifact evidence")
            if not self.change_digest:
                raise ParallelSubagentContractError("successful child result lacks change digest")
            if self.verification_status.casefold() not in {"passed", "success", "verified"}:
                raise ParallelSubagentContractError("successful child result lacks passing verification")
            if not self.verification_evidence_digest:
                raise ParallelSubagentContractError(
                    "successful child result lacks verification evidence"
                )

    def _payload(self, *, include_digest: bool) -> dict[str, object]:
        payload: dict[str, object] = {
            "assignment_id": self.assignment_id,
            "parent_task_id": self.parent_task_id,
            "parent_workspace_id": self.parent_workspace_id,
            "status": self.status.value,
            "base_generation": self.base_generation,
            "base_commit": self.base_commit,
            "child_workspace_id": self.child_workspace_id,
            "child_final_commit": self.child_final_commit,
            "changed_paths": self.changed_paths,
            "change_digest": self.change_digest,
            "changeset_artifact_path": self.changeset_artifact_path,
            "changeset_artifact_sha256": self.changeset_artifact_sha256,
            "changeset_artifact_length": self.changeset_artifact_length,
            "verification_status": self.verification_status,
            "verification_evidence_digest": self.verification_evidence_digest,
            "evidence_refs": self.evidence_refs,
            "summary": self.summary,
            "error_code": self.error_code,
        }
        if include_digest:
            payload["result_digest"] = self.result_digest
        return payload

    def to_payload(self) -> dict[str, object]:
        return self._payload(include_digest=True)


@dataclass(frozen=True, slots=True)
class MergeCandidateBinding:
    """Immutable identity of the exact child result admitted to a merge.

    The binding is constructed from a validated assignment/result pair by the
    trusted merge planner.  An assignment id is only a readable lookup key;
    this complete binding is the merge authority identity.
    """

    assignment_id: str
    assignment_digest: str
    result_digest: str
    child_workspace_id: str
    child_final_commit: str
    change_digest: str
    changeset_artifact_sha256: str
    changeset_artifact_length: int
    changed_paths: tuple[str, ...]
    verification_evidence_digest: str
    changeset_artifact_path: str
    binding_digest: str = ""

    @classmethod
    def from_candidate(
        cls,
        assignment: SubagentAssignment,
        result: SubagentResult,
    ) -> MergeCandidateBinding:
        """Build a binding only from server-validated assignment/result state."""
        if type(assignment) is not SubagentAssignment or type(result) is not SubagentResult:
            raise ParallelSubagentContractError("candidate binding input is malformed")
        result.validate_against(assignment)
        if result.status is not SubagentResultStatus.SUCCESS:
            raise ParallelSubagentContractError("only successful results can be bound")
        if result.child_final_commit is None:
            raise ParallelSubagentContractError("candidate result has no final commit")
        if not result.change_digest:
            raise ParallelSubagentContractError("candidate result has no change digest")
        if not result.changeset_artifact_sha256:
            raise ParallelSubagentContractError("candidate result has no artifact digest")
        if not result.verification_evidence_digest:
            raise ParallelSubagentContractError(
                "candidate result has no verification evidence digest"
            )
        return cls(
            assignment_id=assignment.assignment_id,
            assignment_digest=assignment.assignment_digest,
            result_digest=result.result_digest,
            child_workspace_id=result.child_workspace_id,
            child_final_commit=result.child_final_commit,
            change_digest=result.change_digest,
            changeset_artifact_sha256=result.changeset_artifact_sha256,
            changeset_artifact_length=result.changeset_artifact_length,
            changed_paths=result.changed_paths,
            verification_evidence_digest=result.verification_evidence_digest,
            changeset_artifact_path=result.changeset_artifact_path,
        )

    def __post_init__(self) -> None:
        _text(self.assignment_id, "candidate assignment_id", limit=128)
        _digest(self.assignment_digest, "candidate assignment_digest")
        _digest(self.result_digest, "candidate result_digest")
        _text(self.child_workspace_id, "candidate child_workspace_id", limit=4096)
        _object_id(self.child_final_commit, "candidate child_final_commit")
        _digest(self.change_digest, "candidate change_digest")
        _digest(self.changeset_artifact_sha256, "candidate artifact digest")
        if type(self.changeset_artifact_length) is not int or self.changeset_artifact_length <= 0:
            raise ParallelSubagentContractError("candidate artifact length is invalid")
        object.__setattr__(
            self,
            "changed_paths",
            _paths(self.changed_paths, "candidate changed_paths", limit=MAX_RESULT_PATHS),
        )
        _digest(self.verification_evidence_digest, "candidate verification evidence digest")
        _text(
            self.changeset_artifact_path,
            "candidate changeset artifact path",
            limit=4096,
        )
        expected = canonical_digest(self._payload(include_digest=False))
        if self.binding_digest and self.binding_digest != expected:
            raise ParallelSubagentContractError("binding_digest does not match candidate binding")
        object.__setattr__(self, "binding_digest", expected)

    def _payload(self, *, include_digest: bool) -> dict[str, object]:
        payload: dict[str, object] = {
            "assignment_id": self.assignment_id,
            "assignment_digest": self.assignment_digest,
            "result_digest": self.result_digest,
            "child_workspace_id": self.child_workspace_id,
            "child_final_commit": self.child_final_commit,
            "change_digest": self.change_digest,
            "changeset_artifact_sha256": self.changeset_artifact_sha256,
            "changeset_artifact_length": self.changeset_artifact_length,
            "changed_paths": self.changed_paths,
            "verification_evidence_digest": self.verification_evidence_digest,
            "changeset_artifact_path": self.changeset_artifact_path,
        }
        if include_digest:
            payload["binding_digest"] = self.binding_digest
        return payload

    def to_payload(self) -> dict[str, object]:
        """Return the complete digest-bound candidate identity."""
        return self._payload(include_digest=True)


@dataclass(frozen=True, slots=True)
class MergeCandidate:
    """A result admitted to deterministic merge planning."""

    assignment: SubagentAssignment
    result: SubagentResult

    def __post_init__(self) -> None:
        if type(self.assignment) is not SubagentAssignment or type(self.result) is not SubagentResult:
            raise ParallelSubagentContractError("merge candidate is malformed")
        if not self.assignment.mutating:
            raise ParallelSubagentContractError("read-only child results cannot be merge candidates")
        self.result.validate_against(self.assignment)
        if self.result.status is not SubagentResultStatus.SUCCESS:
            raise ParallelSubagentContractError("only successful child results can be merge candidates")

    @property
    def assignment_id(self) -> str:
        return self.assignment.assignment_id

    @property
    def binding(self) -> MergeCandidateBinding:
        """Return the trusted immutable binding for this candidate."""
        return MergeCandidateBinding.from_candidate(self.assignment, self.result)


@dataclass(frozen=True, slots=True)
class MergePlan:
    """Digest-bound deterministic merge plan created before any publish."""

    merge_id: str
    parent_task_id: str
    parent_workspace_id: str
    parent_generation: int
    parent_base_commit: str
    candidate_ids: tuple[str, ...]
    ordered_candidate_ids: tuple[str, ...]
    parent_principal_id: str = ""
    parent_project_id: str = ""
    candidate_bindings: tuple[MergeCandidateBinding, ...] = ()
    conflicts: tuple[tuple[str, str, str], ...] = ()
    expected_result: str = "publish-parent"
    plan_digest: str = ""

    def __post_init__(self) -> None:
        _text(self.merge_id, "merge_id", limit=128)
        _text(self.parent_task_id, "parent_task_id")
        _text(self.parent_workspace_id, "parent_workspace_id")
        if type(self.parent_generation) is not int or self.parent_generation <= 0:
            raise ParallelSubagentContractError("merge parent_generation is invalid")
        _object_id(self.parent_base_commit, "parent_base_commit")
        object.__setattr__(self, "candidate_ids", _strings(self.candidate_ids, "candidate_ids", limit=64, item_limit=128))
        object.__setattr__(self, "ordered_candidate_ids", _strings(self.ordered_candidate_ids, "ordered_candidate_ids", limit=64, item_limit=128))
        _text(self.parent_principal_id, "parent_principal_id", allow_empty=True, limit=4096)
        _text(self.parent_project_id, "parent_project_id", allow_empty=True, limit=4096)
        if set(self.candidate_ids) != set(self.ordered_candidate_ids):
            raise ParallelSubagentContractError("merge candidate order is not a permutation")
        if type(self.candidate_bindings) is not tuple or len(self.candidate_bindings) > 64:
            raise ParallelSubagentContractError("merge candidate bindings exceed their bound")
        if any(type(binding) is not MergeCandidateBinding for binding in self.candidate_bindings):
            raise ParallelSubagentContractError("merge candidate binding is malformed")
        binding_ids = tuple(binding.assignment_id for binding in self.candidate_bindings)
        if binding_ids != self.ordered_candidate_ids:
            raise ParallelSubagentContractError(
                "merge candidate bindings do not match the deterministic order"
            )
        if type(self.conflicts) is not tuple or len(self.conflicts) > 256:
            raise ParallelSubagentContractError("merge conflict set exceeds its bound")
        for item in self.conflicts:
            if type(item) is not tuple or len(item) != 3:
                raise ParallelSubagentContractError("merge conflict entry is malformed")
            _text(item[0], "conflict kind", limit=128)
            _text(item[1], "conflict left", limit=128)
            _text(item[2], "conflict right", limit=128)
        _text(self.expected_result, "expected_result", limit=128)
        expected = canonical_digest(self._payload(include_digest=False))
        if self.plan_digest and self.plan_digest != expected:
            raise ParallelSubagentContractError("plan_digest does not match plan")
        object.__setattr__(self, "plan_digest", expected)

    def _payload(self, *, include_digest: bool) -> dict[str, object]:
        payload: dict[str, object] = {
            "merge_id": self.merge_id,
            "parent_task_id": self.parent_task_id,
            "parent_workspace_id": self.parent_workspace_id,
            "parent_generation": self.parent_generation,
            "parent_base_commit": self.parent_base_commit,
            "candidate_ids": self.candidate_ids,
            "ordered_candidate_ids": self.ordered_candidate_ids,
            "parent_principal_id": self.parent_principal_id,
            "parent_project_id": self.parent_project_id,
            "candidate_bindings": tuple(
                binding.to_payload() for binding in self.candidate_bindings
            ),
            "conflicts": self.conflicts,
            "expected_result": self.expected_result,
        }
        if include_digest:
            payload["plan_digest"] = self.plan_digest
        return payload

    def to_payload(self) -> dict[str, object]:
        """Return the complete immutable plan identity for durable storage."""
        return self._payload(include_digest=True)


@dataclass(frozen=True, slots=True)
class MergeResult:
    """Structured merge outcome and post-publish verification observation."""

    merge_id: str
    status: MergeResultStatus
    parent_task_id: str
    parent_workspace_id: str
    expected_parent_head: str
    expected_parent_generation: int
    candidate_ids: tuple[str, ...]
    published_head: str | None = None
    published_generation: int | None = None
    verification_status: str = "unknown"
    verification_evidence_digest: str = ""
    changed_paths: tuple[str, ...] = ()
    plan_digest: str = ""
    candidate_binding_digests: tuple[str, ...] = ()
    verified_integration_artifact_digest: str = ""
    publication_attestation_digest: str = ""
    parent_verification_evidence_digest: str = ""
    reason: str = ""
    result_digest: str = ""

    def __post_init__(self) -> None:
        _text(self.merge_id, "merge_id", limit=128)
        status = self.status if isinstance(self.status, MergeResultStatus) else MergeResultStatus(self.status)
        object.__setattr__(self, "status", status)
        _text(self.parent_task_id, "parent_task_id")
        _text(self.parent_workspace_id, "parent_workspace_id")
        _object_id(self.expected_parent_head, "expected_parent_head")
        if type(self.expected_parent_generation) is not int or self.expected_parent_generation <= 0:
            raise ParallelSubagentContractError("expected_parent_generation is invalid")
        object.__setattr__(self, "candidate_ids", _strings(self.candidate_ids, "candidate_ids", limit=64, item_limit=128))
        if self.published_head is not None:
            _object_id(self.published_head, "published_head")
        if self.published_generation is not None and (
            type(self.published_generation) is not int or self.published_generation <= 0
        ):
            raise ParallelSubagentContractError("published_generation is invalid")
        _text(self.verification_status, "verification_status")
        if self.verification_evidence_digest:
            _digest(self.verification_evidence_digest, "verification_evidence_digest")
        object.__setattr__(self, "changed_paths", _paths(self.changed_paths, "merge changed_paths", limit=MAX_RESULT_PATHS))
        if self.plan_digest:
            _digest(self.plan_digest, "merge plan_digest")
        if type(self.candidate_binding_digests) is not tuple or len(
            self.candidate_binding_digests
        ) > 64:
            raise ParallelSubagentContractError(
                "candidate binding digests exceed their bound"
            )
        object.__setattr__(
            self,
            "candidate_binding_digests",
            tuple(
                _digest(value, "candidate binding digest")
                for value in self.candidate_binding_digests
            ),
        )
        for label, value in (
            ("verified_integration_artifact_digest", self.verified_integration_artifact_digest),
            ("publication_attestation_digest", self.publication_attestation_digest),
            ("parent_verification_evidence_digest", self.parent_verification_evidence_digest),
        ):
            if value:
                _digest(value, label)
        _text(self.reason, "reason", allow_empty=True, limit=4096)
        expected = canonical_digest(self._payload(include_digest=False))
        if self.result_digest and self.result_digest != expected:
            raise ParallelSubagentContractError("merge result digest does not match result")
        object.__setattr__(self, "result_digest", expected)

    def _payload(self, *, include_digest: bool) -> dict[str, object]:
        payload: dict[str, object] = {
            "merge_id": self.merge_id,
            "status": self.status.value,
            "parent_task_id": self.parent_task_id,
            "parent_workspace_id": self.parent_workspace_id,
            "expected_parent_head": self.expected_parent_head,
            "expected_parent_generation": self.expected_parent_generation,
            "candidate_ids": self.candidate_ids,
            "published_head": self.published_head,
            "published_generation": self.published_generation,
            "verification_status": self.verification_status,
            "verification_evidence_digest": self.verification_evidence_digest,
            "changed_paths": self.changed_paths,
            "plan_digest": self.plan_digest,
            "candidate_binding_digests": self.candidate_binding_digests,
            "verified_integration_artifact_digest": self.verified_integration_artifact_digest,
            "publication_attestation_digest": self.publication_attestation_digest,
            "parent_verification_evidence_digest": self.parent_verification_evidence_digest,
            "reason": self.reason,
        }
        if include_digest:
            payload["result_digest"] = self.result_digest
        return payload

    def to_payload(self) -> dict[str, object]:
        """Return the complete digest-bound merge result."""
        return self._payload(include_digest=True)


@dataclass(frozen=True, slots=True)
class VerifiedIntegrationArtifact:
    """Frozen, manager-owned publication input produced after verification."""

    merge_id: str
    merge_plan_digest: str
    base_commit: str
    resulting_tree: str
    changeset_sha256: str
    changeset_length: int
    changed_paths: tuple[str, ...]
    verification_evidence_digest: str
    verification_plan_digest: str = ""
    artifact_storage_id: str = ""
    artifact_digest: str = ""

    def __post_init__(self) -> None:
        _text(self.merge_id, "verified artifact merge_id", limit=128)
        _digest(self.merge_plan_digest, "verified artifact merge_plan_digest")
        _object_id(self.base_commit, "verified artifact base_commit")
        _object_id(self.resulting_tree, "verified artifact resulting_tree")
        _digest(self.changeset_sha256, "verified artifact changeset_sha256")
        if type(self.changeset_length) is not int or self.changeset_length <= 0:
            raise ParallelSubagentContractError("verified artifact changeset_length is invalid")
        object.__setattr__(
            self,
            "changed_paths",
            _paths(self.changed_paths, "verified artifact changed_paths", limit=MAX_RESULT_PATHS),
        )
        _digest(
            self.verification_evidence_digest,
            "verified artifact verification_evidence_digest",
        )
        if self.verification_plan_digest:
            _digest(self.verification_plan_digest, "verified artifact verification_plan_digest")
        if self.artifact_storage_id:
            _text(self.artifact_storage_id, "verified artifact storage id", limit=256)
        expected = canonical_digest(self._payload(include_digest=False))
        if self.artifact_digest and self.artifact_digest != expected:
            raise ParallelSubagentContractError("artifact_digest does not match verified artifact")
        object.__setattr__(self, "artifact_digest", expected)

    def _payload(self, *, include_digest: bool) -> dict[str, object]:
        payload: dict[str, object] = {
            "merge_id": self.merge_id,
            "merge_plan_digest": self.merge_plan_digest,
            "base_commit": self.base_commit,
            "resulting_tree": self.resulting_tree,
            "changeset_sha256": self.changeset_sha256,
            "changeset_length": self.changeset_length,
            "changed_paths": self.changed_paths,
            "verification_evidence_digest": self.verification_evidence_digest,
            "verification_plan_digest": self.verification_plan_digest,
            "artifact_storage_id": self.artifact_storage_id,
        }
        if include_digest:
            payload["artifact_digest"] = self.artifact_digest
        return payload

    def to_payload(self) -> dict[str, object]:
        return self._payload(include_digest=True)


@dataclass(frozen=True, slots=True)
class PublicationAttestation:
    """Proof that the current Parent tree equals the verified integration tree."""

    merge_id: str
    integration_workspace_id: str
    integration_generation: int
    integration_commit: str
    integration_tree_digest: str
    parent_workspace_id: str
    parent_generation: int
    parent_commit: str
    parent_tree_digest: str
    source_verification_evidence_digest: str
    merge_plan_digest: str = ""
    verification_plan_digest: str = ""
    changed_paths: tuple[str, ...] = ()
    parent_task_id: str = ""
    project_id: str = ""
    attestation_digest: str = ""

    def __post_init__(self) -> None:
        _text(self.merge_id, "publication merge_id", limit=128)
        _text(self.integration_workspace_id, "integration_workspace_id", limit=4096)
        _text(self.parent_workspace_id, "parent_workspace_id", limit=4096)
        for label, value in (
            ("integration_generation", self.integration_generation),
            ("parent_generation", self.parent_generation),
        ):
            if type(value) is not int or value <= 0:
                raise ParallelSubagentContractError(f"publication {label} is invalid")
        _object_id(self.integration_commit, "integration_commit")
        _object_id(self.integration_tree_digest, "integration_tree_digest")
        _object_id(self.parent_commit, "parent_commit")
        _object_id(self.parent_tree_digest, "parent_tree_digest")
        if self.integration_tree_digest != self.parent_tree_digest:
            raise ParallelSubagentContractError(
                "publication attestation requires exact integration/Parent tree equality"
            )
        _digest(
            self.source_verification_evidence_digest,
            "source_verification_evidence_digest",
        )
        if self.merge_plan_digest:
            _digest(self.merge_plan_digest, "publication merge_plan_digest")
        if self.verification_plan_digest:
            _digest(self.verification_plan_digest, "publication verification_plan_digest")
        object.__setattr__(
            self,
            "changed_paths",
            _paths(self.changed_paths, "publication changed_paths", limit=MAX_RESULT_PATHS),
        )
        _text(self.parent_task_id, "publication parent_task_id", allow_empty=True, limit=4096)
        _text(self.project_id, "publication project_id", allow_empty=True, limit=4096)
        expected = canonical_digest(self._payload(include_digest=False))
        if self.attestation_digest and self.attestation_digest != expected:
            raise ParallelSubagentContractError(
                "attestation_digest does not match publication attestation"
            )
        object.__setattr__(self, "attestation_digest", expected)

    def _payload(self, *, include_digest: bool) -> dict[str, object]:
        payload: dict[str, object] = {
            "merge_id": self.merge_id,
            "integration_workspace_id": self.integration_workspace_id,
            "integration_generation": self.integration_generation,
            "integration_commit": self.integration_commit,
            "integration_tree_digest": self.integration_tree_digest,
            "parent_workspace_id": self.parent_workspace_id,
            "parent_generation": self.parent_generation,
            "parent_commit": self.parent_commit,
            "parent_tree_digest": self.parent_tree_digest,
            "source_verification_evidence_digest": self.source_verification_evidence_digest,
            "merge_plan_digest": self.merge_plan_digest,
            "verification_plan_digest": self.verification_plan_digest,
            "changed_paths": self.changed_paths,
            "parent_task_id": self.parent_task_id,
            "project_id": self.project_id,
        }
        if include_digest:
            payload["attestation_digest"] = self.attestation_digest
        return payload

    def to_payload(self) -> dict[str, object]:
        return self._payload(include_digest=True)


@dataclass(frozen=True, slots=True)
class SubagentParallelismPolicy:
    """Bounded scheduler policy; values are not model-controlled."""

    max_active_children: int = 4
    max_mutating_children: int = 2
    max_research_children: int = 4
    max_child_turns: int = 30
    max_child_tokens: int = 100_000
    max_child_tool_calls: int = 256
    max_child_duration_seconds: float = 300.0
    max_aggregate_tokens: int = 300_000
    max_aggregate_tool_calls: int = 1024
    max_child_storage_bytes: int = 256 * 1024 * 1024

    def __post_init__(self) -> None:
        for label in (
            "max_active_children",
            "max_mutating_children",
            "max_research_children",
            "max_child_turns",
            "max_child_tokens",
            "max_child_tool_calls",
            "max_aggregate_tokens",
            "max_aggregate_tool_calls",
            "max_child_storage_bytes",
        ):
            value = getattr(self, label)
            if type(value) is not int or value <= 0:
                raise ParallelSubagentContractError(f"{label} must be positive")
        if self.max_mutating_children > self.max_active_children:
            raise ParallelSubagentContractError("parallel child limits exceed max_active_children")
        if type(self.max_child_duration_seconds) not in {int, float} or self.max_child_duration_seconds <= 0:
            raise ParallelSubagentContractError("max_child_duration_seconds must be positive")


@dataclass(frozen=True, slots=True)
class ParallelMetrics:
    """Bounded descriptive counters; metrics never grant authority."""

    active_children: int = 0
    mutating_children: int = 0
    research_children: int = 0
    completed_children: int = 0
    failed_children: int = 0
    cancelled_children: int = 0
    stale_children: int = 0
    conflict_children: int = 0
    quarantined_children: int = 0
    aggregate_tokens: int = 0
    aggregate_tool_calls: int = 0


def validate_assignment_plan(assignments: tuple[SubagentAssignment, ...]) -> None:
    """Validate the deliberately small M8.5 dependency/overlap plan.

    This is not a general DAG engine.  It rejects cycles, missing references,
    duplicate assignments, and overlapping mutating path scopes before any
    child worktree is created.  A caller may still choose a serial fallback.
    """

    if type(assignments) is not tuple or len(assignments) > 64:
        raise ParallelSubagentContractError("assignment plan exceeds its bound")
    by_id = {assignment.assignment_id: assignment for assignment in assignments}
    if len(by_id) != len(assignments):
        raise ParallelSubagentContractError("assignment plan contains duplicate ids")
    for assignment in assignments:
        if any(dependency not in by_id for dependency in assignment.dependencies):
            raise ParallelSubagentContractError("assignment plan contains a missing dependency")
    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(assignment_id: str) -> None:
        if assignment_id in visiting:
            raise ParallelSubagentContractError("assignment dependency graph contains a cycle")
        if assignment_id in visited:
            return
        visiting.add(assignment_id)
        for dependency in by_id[assignment_id].dependencies:
            visit(dependency)
        visiting.remove(assignment_id)
        visited.add(assignment_id)

    for assignment in assignments:
        visit(assignment.assignment_id)
    mutating = [assignment for assignment in assignments if assignment.mutating]
    for index, left in enumerate(mutating):
        for right in mutating[index + 1 :]:
            if any(
                _scope_contains(left_scope, right_scope)
                or _scope_contains(right_scope, left_scope)
                for left_scope in left.allowed_paths
                for right_scope in right.allowed_paths
            ):
                raise ParallelSubagentContractError(
                    "overlapping mutating assignments require serial execution"
                )


__all__ = [
    "MAX_CONTEXT_BYTES",
    "MAX_CONTEXT_ITEMS",
    "AssignmentContext",
    "ChildWorkspaceBinding",
    "ChildWorkspaceState",
    "ContextTransferItem",
    "ContextTransferPackage",
    "MergeCandidate",
    "MergeCandidateBinding",
    "MergeConflictKind",
    "MergePlan",
    "MergeResult",
    "MergeResultStatus",
    "ParallelMetrics",
    "ParallelSubagentContractError",
    "PublicationAttestation",
    "SubagentAccessMode",
    "SubagentAssignment",
    "SubagentParallelismPolicy",
    "SubagentResult",
    "SubagentResultStatus",
    "SubagentRole",
    "VerifiedIntegrationArtifact",
    "validate_assignment_plan",
]
