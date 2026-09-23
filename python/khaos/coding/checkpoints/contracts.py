"""Typed immutable checkpoint and rewind-plan contracts."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum

from khaos.coding.edit_transaction import EditTransaction
from khaos.security.protocol_boundary import canonical_digest, canonical_json_bytes
from khaos.supervision.contracts import SupervisionCommandStatus
from khaos.time_utils import utc_now_naive

MAX_CHECKPOINT_LABEL_BYTES = 1024
MAX_CHECKPOINT_SNAPSHOT_BYTES = 16 * 1024 * 1024
MAX_REWIND_PATHS = 512
MAX_REWIND_CONFLICTS = 128


class CheckpointContractError(ValueError):
    """A checkpoint or rewind plan is malformed."""


class CheckpointKind(StrEnum):
    """The bounded set of automatic and user-created checkpoint reasons."""

    AUTOMATIC = "AUTOMATIC"
    USER_CREATED = "USER_CREATED"
    PRE_EDIT = "PRE_EDIT"
    POST_VERIFICATION = "POST_VERIFICATION"
    PRE_PARALLEL_MERGE = "PRE_PARALLEL_MERGE"
    POST_MERGE = "POST_MERGE"


def _text(value: object, label: str, *, allow_empty: bool = False, maximum: int = 256) -> str:
    if type(value) is not str or (not allow_empty and not value) or "\x00" in value:
        raise CheckpointContractError(f"{label} is invalid")
    if len(value.encode("utf-8")) > maximum:
        raise CheckpointContractError(f"{label} exceeds its bound")
    return value


def _digest(value: object, label: str, *, allow_empty: bool = False) -> str:
    if allow_empty and value == "":
        return ""
    if (
        type(value) is not str
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise CheckpointContractError(f"{label} must be a lowercase SHA-256 digest")
    return value


def _git_object(value: object, label: str) -> str:
    if (
        type(value) is not str
        or len(value) not in {40, 64}
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise CheckpointContractError(f"{label} must be a Git object id")
    return value


def _paths(value: object, label: str, *, maximum: int = MAX_REWIND_PATHS) -> tuple[str, ...]:
    if not isinstance(value, (tuple, list)) or len(value) > maximum:
        raise CheckpointContractError(f"{label} exceeds its bound")
    result: list[str] = []
    for item in value:
        if type(item) is not str or not item or "\x00" in item:
            raise CheckpointContractError(f"{label} contains an invalid path")
        if item.startswith("/") or "\\" in item or ".." in item.split("/"):
            raise CheckpointContractError(f"{label} contains an unsafe path")
        if any(part.casefold() in {".git", ".agents", ".codex", ".khaos"} for part in item.split("/")):
            raise CheckpointContractError(f"{label} reaches protected metadata")
        if item not in result:
            result.append(item)
    return tuple(result)


def _enum(value: object, cls: type[StrEnum], label: str) -> StrEnum:
    if isinstance(value, cls):
        return value
    try:
        return cls(str(value))
    except ValueError as exc:
        raise CheckpointContractError(f"{label} is invalid") from exc


@dataclass(frozen=True, slots=True)
class TaskCheckpoint:
    """An immutable exact workspace identity plus a bounded file snapshot."""

    checkpoint_id: str
    task_id: str
    workspace_id: str
    project_id: str
    repository_generation: int
    head_commit: str
    tree_digest: str
    task_revision: int
    plan_revision: int | None
    verification_evidence_digest: str | None
    checkpoint_kind: CheckpointKind | str
    label: str = ""
    snapshot_digest: str = ""
    snapshot: Mapping[str, Mapping[str, object]] = field(default_factory=dict, repr=False)
    created_at: str = field(default_factory=lambda: utc_now_naive().isoformat())
    checkpoint_digest: str = ""

    def __post_init__(self) -> None:
        _text(self.checkpoint_id, "checkpoint_id", maximum=128)
        _text(self.task_id, "task_id", maximum=128)
        _text(self.workspace_id, "workspace_id", maximum=128)
        _text(self.project_id, "project_id", maximum=256)
        if type(self.repository_generation) is not int or self.repository_generation <= 0:
            raise CheckpointContractError("repository_generation must be positive")
        _git_object(self.head_commit, "head_commit")
        _git_object(self.tree_digest, "tree_digest")
        if type(self.task_revision) is not int or self.task_revision < 0:
            raise CheckpointContractError("task_revision must be non-negative")
        if self.plan_revision is not None and (
            type(self.plan_revision) is not int or self.plan_revision < 0
        ):
            raise CheckpointContractError("plan_revision must be non-negative")
        if self.verification_evidence_digest is not None:
            _digest(self.verification_evidence_digest, "verification_evidence_digest")
        object.__setattr__(self, "checkpoint_kind", _enum(self.checkpoint_kind, CheckpointKind, "checkpoint_kind"))
        _text(self.label, "label", allow_empty=True, maximum=MAX_CHECKPOINT_LABEL_BYTES)
        snapshot = {
            str(path): dict(metadata)
            for path, metadata in dict(self.snapshot).items()
        }
        if len(canonical_json_bytes(snapshot)) > MAX_CHECKPOINT_SNAPSHOT_BYTES:
            raise CheckpointContractError("checkpoint snapshot exceeds its bound")
        for path, metadata in snapshot.items():
            _paths((path,), "snapshot.path", maximum=1)
            if not isinstance(metadata, dict):
                raise CheckpointContractError("snapshot metadata must be an object")
            _digest(metadata.get("digest"), "snapshot.digest")
            if type(metadata.get("size")) is not int or metadata["size"] < 0:
                raise CheckpointContractError("snapshot.size is invalid")
            if type(metadata.get("mode")) is not int or metadata["mode"] < 0:
                raise CheckpointContractError("snapshot.mode is invalid")
            content = metadata.get("content_b64")
            if type(content) is not str:
                raise CheckpointContractError("snapshot.content_b64 is invalid")
        object.__setattr__(self, "snapshot", snapshot)
        actual_snapshot_digest = canonical_digest(snapshot)
        if self.snapshot_digest and self.snapshot_digest != actual_snapshot_digest:
            raise CheckpointContractError("checkpoint snapshot digest mismatch")
        object.__setattr__(self, "snapshot_digest", actual_snapshot_digest)
        _text(self.created_at, "created_at", maximum=128)
        expected = canonical_digest(self._identity_payload())
        if self.checkpoint_digest and self.checkpoint_digest != expected:
            raise CheckpointContractError("checkpoint digest mismatch")
        object.__setattr__(self, "checkpoint_digest", expected)

    def _identity_payload(self) -> dict[str, object]:
        return {
            "checkpoint_id": self.checkpoint_id,
            "task_id": self.task_id,
            "workspace_id": self.workspace_id,
            "project_id": self.project_id,
            "repository_generation": self.repository_generation,
            "head_commit": self.head_commit,
            "tree_digest": self.tree_digest,
            "task_revision": self.task_revision,
            "plan_revision": self.plan_revision,
            "verification_evidence_digest": self.verification_evidence_digest,
            "checkpoint_kind": self.checkpoint_kind.value,
            "label": self.label,
            "snapshot_digest": self.snapshot_digest,
            "created_at": self.created_at,
        }

    def to_payload(self, *, include_snapshot: bool = True) -> dict[str, object]:
        payload = self._identity_payload()
        payload["checkpoint_digest"] = self.checkpoint_digest
        if include_snapshot:
            payload["snapshot"] = {path: dict(value) for path, value in self.snapshot.items()}
        return payload

    @classmethod
    def from_payload(cls, value: Mapping[str, object]) -> TaskCheckpoint:
        return cls(
            checkpoint_id=value.get("checkpoint_id", ""),
            task_id=value.get("task_id", ""),
            workspace_id=value.get("workspace_id", ""),
            project_id=value.get("project_id", ""),
            repository_generation=value.get("repository_generation", 0),
            head_commit=value.get("head_commit", ""),
            tree_digest=value.get("tree_digest", ""),
            task_revision=value.get("task_revision", 0),
            plan_revision=value.get("plan_revision"),
            verification_evidence_digest=value.get("verification_evidence_digest"),
            checkpoint_kind=value.get("checkpoint_kind", ""),
            label=value.get("label", ""),
            snapshot_digest=value.get("snapshot_digest", ""),
            snapshot=value.get("snapshot", {}),
            created_at=value.get("created_at", utc_now_naive().isoformat()),
            checkpoint_digest=value.get("checkpoint_digest", ""),
        )


@dataclass(frozen=True, slots=True)
class RewindPlan:
    """A fresh, generation-bound M8.2 transaction plan."""

    rewind_id: str
    task_id: str
    workspace_id: str
    project_id: str
    source_generation: int
    source_head: str
    source_tree: str
    target_checkpoint_id: str
    target_checkpoint_digest: str
    target_generation: int
    target_head: str
    target_tree: str
    affected_paths: tuple[str, ...]
    preserved_paths: tuple[str, ...]
    user_drift: tuple[str, ...]
    conflicts: tuple[str, ...]
    transaction: EditTransaction | None
    transaction_digest: str | None
    expected_resulting_generation: int
    status: str = "planned"
    created_at: str = field(default_factory=lambda: utc_now_naive().isoformat())
    plan_digest: str = ""
    # Git HEAD/tree identify committed state only.  This additional binding
    # covers the bounded workspace snapshot so an uncommitted edit cannot
    # slip through a stale-plan check merely because Git still reports the
    # same HEAD and tree.
    source_snapshot_digest: str = ""

    def __post_init__(self) -> None:
        _text(self.rewind_id, "rewind_id", maximum=128)
        _text(self.task_id, "task_id", maximum=128)
        _text(self.workspace_id, "workspace_id", maximum=128)
        _text(self.project_id, "project_id", maximum=256)
        for value, label in (
            (self.source_generation, "source_generation"),
            (self.target_generation, "target_generation"),
            (self.expected_resulting_generation, "expected_resulting_generation"),
        ):
            if type(value) is not int or value <= 0:
                raise CheckpointContractError(f"{label} must be positive")
        _git_object(self.source_head, "source_head")
        _git_object(self.source_tree, "source_tree")
        _digest(self.source_snapshot_digest, "source_snapshot_digest", allow_empty=True)
        _digest(self.target_checkpoint_digest, "target_checkpoint_digest")
        _git_object(self.target_head, "target_head")
        _git_object(self.target_tree, "target_tree")
        for value, label in (
            (self.affected_paths, "affected_paths"),
            (self.preserved_paths, "preserved_paths"),
            (self.user_drift, "user_drift"),
            (self.conflicts, "conflicts"),
        ):
            _paths(value, label, maximum=MAX_REWIND_CONFLICTS if label in {"user_drift", "conflicts"} else MAX_REWIND_PATHS)
        if self.transaction is not None and not isinstance(self.transaction, EditTransaction):
            raise CheckpointContractError("transaction is not an EditTransaction")
        expected_transaction_digest = self.transaction.transaction_digest if self.transaction else None
        if self.transaction_digest not in {None, expected_transaction_digest}:
            raise CheckpointContractError("transaction digest mismatch")
        object.__setattr__(self, "transaction_digest", expected_transaction_digest)
        _text(self.status, "status", maximum=64)
        _text(self.created_at, "created_at", maximum=128)
        expected = canonical_digest(self._digest_payload())
        if self.plan_digest and self.plan_digest != expected:
            raise CheckpointContractError("rewind plan digest mismatch")
        object.__setattr__(self, "plan_digest", expected)

    def _digest_payload(self) -> dict[str, object]:
        return {
            "rewind_id": self.rewind_id,
            "task_id": self.task_id,
            "workspace_id": self.workspace_id,
            "project_id": self.project_id,
            "source_generation": self.source_generation,
            "source_head": self.source_head,
            "source_tree": self.source_tree,
            "source_snapshot_digest": self.source_snapshot_digest,
            "target_checkpoint_id": self.target_checkpoint_id,
            "target_checkpoint_digest": self.target_checkpoint_digest,
            "target_generation": self.target_generation,
            "target_head": self.target_head,
            "target_tree": self.target_tree,
            "affected_paths": list(self.affected_paths),
            "preserved_paths": list(self.preserved_paths),
            "user_drift": list(self.user_drift),
            "conflicts": list(self.conflicts),
            "transaction": self.transaction.to_payload() if self.transaction else None,
            "transaction_digest": self.transaction_digest,
            "expected_resulting_generation": self.expected_resulting_generation,
            "status": self.status,
            "created_at": self.created_at,
        }

    def to_payload(self, *, include_transaction_content: bool = True) -> dict[str, object]:
        payload = self._digest_payload()
        if self.transaction is not None and not include_transaction_content:
            payload["transaction"] = self.transaction.to_payload()
            payload["transaction"]["operations"] = [
                {key: value for key, value in operation.items() if key != "content"}
                for operation in payload["transaction"]["operations"]
            ]
        payload["plan_digest"] = self.plan_digest
        return payload


@dataclass(frozen=True, slots=True)
class RewindExecutionResult:
    """Truthful result of one controlled rewind attempt."""

    rewind_id: str
    task_id: str
    status: SupervisionCommandStatus | str
    effect_applied: bool
    resulting_generation: int | None = None
    verification_status: str = "unknown"
    reason: str = ""
    result_digest: str = ""

    def __post_init__(self) -> None:
        _text(self.rewind_id, "rewind_id", maximum=128)
        _text(self.task_id, "task_id", maximum=128)
        object.__setattr__(self, "status", _enum(self.status, SupervisionCommandStatus, "status"))
        if type(self.effect_applied) is not bool:
            raise CheckpointContractError("effect_applied must be boolean")
        if self.resulting_generation is not None and (
            type(self.resulting_generation) is not int or self.resulting_generation <= 0
        ):
            raise CheckpointContractError("resulting_generation is invalid")
        _text(self.verification_status, "verification_status", maximum=128)
        _text(self.reason, "reason", allow_empty=True, maximum=2048)
        digest = canonical_digest(self._payload())
        if self.result_digest and self.result_digest != digest:
            raise CheckpointContractError("rewind result digest mismatch")
        object.__setattr__(self, "result_digest", digest)

    def _payload(self) -> dict[str, object]:
        return {
            "rewind_id": self.rewind_id,
            "task_id": self.task_id,
            "status": self.status.value,
            "effect_applied": self.effect_applied,
            "resulting_generation": self.resulting_generation,
            "verification_status": self.verification_status,
            "reason": self.reason,
        }

    def to_payload(self) -> dict[str, object]:
        payload = self._payload()
        payload["result_digest"] = self.result_digest
        return payload


__all__ = [
    "CheckpointContractError",
    "CheckpointKind",
    "RewindExecutionResult",
    "RewindPlan",
    "TaskCheckpoint",
]
