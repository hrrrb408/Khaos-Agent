"""Bounded, generation-bound edit transactions for Coding workspaces.

This module is the typed front door for multi-file model edits. It deliberately
reuses SafeWorkspaceFS, WorkspaceStorageAuthority and the WorkspaceManager
mutation lock; it does not introduce a second workspace store or recovery
authority.
"""

from __future__ import annotations

import asyncio
import difflib
import hashlib
import json
import unicodedata
from dataclasses import dataclass
from enum import Enum
from pathlib import PurePosixPath, PureWindowsPath
from typing import Any

from khaos.coding.planning.safe_workspace_path import MutationObjectIdentity
from khaos.coding.workspace.boundary import (
    SafeWorkspaceFS,
    WorkspaceBoundaryError,
    WorkspaceFileSnapshot,
)
from khaos.coding.workspace.models import TaskWorkspace, WorkspaceState
from khaos.coding.workspace.policy import (
    DEFAULT_FILE_TOOL_BYTES,
    DEFAULT_TREE_BYTES,
    DEFAULT_TREE_DEPTH,
    DEFAULT_TREE_ENTRIES,
    is_protected_workspace_name,
)
from khaos.coding.workspace.storage import (
    WorkspaceMutation,
    WorkspaceStorageViolation,
)

MAX_EDIT_OPERATIONS = 64
MAX_TRANSACTION_BYTES = 64 * 1024 * 1024
MAX_PREVIEW_BYTES = 64 * 1024
MAX_PREVIEW_SOURCE_BYTES = DEFAULT_FILE_TOOL_BYTES
MAX_TEXT_EDITS = 256
MAX_TEXT_REPLACEMENT_BYTES = DEFAULT_FILE_TOOL_BYTES
MAX_TRANSACTION_ID_LENGTH = 128
MAX_INTENT_LENGTH = 512


class EditTransactionError(ValueError):
    """Base error for malformed or unauthorized edit transactions."""


class EditTransactionPreconditionError(EditTransactionError):
    """The file or workspace state does not match the transaction contract."""


class EditTransactionStaleError(EditTransactionPreconditionError):
    """The transaction was built against an older workspace generation."""


class EditTransactionApplyError(EditTransactionError):
    """A transaction could not be applied or verified."""


class EditTransactionRecoveryError(EditTransactionApplyError):
    """A transaction could not be rolled back safely."""


class EditOperationKind(str, Enum):
    """Supported atomic file operations."""

    CREATE = "create"
    UPDATE = "update"
    DELETE = "delete"
    RENAME = "rename"


class EditTransactionStatus(str, Enum):
    """Terminal status values returned by the transaction service."""

    APPLIED = "applied"
    PREVIEWED = "previewed"


def _bounded_text(value: object, field_name: str, maximum: int) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise EditTransactionError(f"{field_name} must be a bounded non-empty string")
    if "\x00" in value:
        raise EditTransactionError(f"{field_name} contains a NUL byte")
    return value


def _optional_digest(value: object, field_name: str) -> str | None:
    if value is None:
        return None
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise EditTransactionError(f"{field_name} must be a lowercase SHA-256 digest")
    return value


def _normalize_relative_path(value: object, field_name: str) -> str:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise EditTransactionError(f"{field_name} must be a non-empty relative path")
    if "\\" in value or value.startswith("/") or value.endswith("/"):
        raise EditTransactionError(f"{field_name} must use normalized POSIX syntax")
    if len(value) >= 2 and value[1] == ":":
        raise EditTransactionError(f"{field_name} must not contain a drive prefix")
    windows = PureWindowsPath(value)
    if windows.is_absolute() or windows.drive:
        raise EditTransactionError(f"{field_name} must not be an absolute path")
    if any(part in {"", ".", ".."} for part in value.split("/")):
        raise EditTransactionError(f"{field_name} contains an unsafe path component")
    normalized = unicodedata.normalize("NFC", value)
    if normalized != value:
        value = normalized
    path = PurePosixPath(value)
    if path.is_absolute() or path.as_posix() != value:
        raise EditTransactionError(f"{field_name} is not canonically normalized")
    if any(is_protected_workspace_name(part) for part in path.parts):
        raise EditTransactionError(f"{field_name} reaches protected workspace metadata")
    return value


def _canonical_json_bytes(payload: object) -> bytes:
    return json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


@dataclass(frozen=True, slots=True)
class TextEdit:
    """A non-overlapping UTF-8 text edit expressed in Python string offsets."""

    start: int
    end: int
    replacement: str

    def __post_init__(self) -> None:
        if type(self.start) is not int or type(self.end) is not int:
            raise EditTransactionError("text edit offsets must be integers")
        if self.start < 0 or self.end < self.start:
            raise EditTransactionError("text edit offsets are invalid")
        if not isinstance(self.replacement, str) or "\x00" in self.replacement:
            raise EditTransactionError("text edit replacement must be text")
        if len(self.replacement.encode("utf-8")) > MAX_TEXT_REPLACEMENT_BYTES:
            raise EditTransactionError("text edit replacement exceeds its bound")


@dataclass(frozen=True, slots=True)
class EditOperation:
    """Immutable, typed description of one file edit."""

    operation: EditOperationKind | str
    path: str
    expected_exists: bool | None = None
    expected_digest: str | None = None
    content: str | None = None
    text_edits: tuple[TextEdit, ...] = ()
    destination_path: str | None = None

    def __post_init__(self) -> None:
        try:
            kind = (
                self.operation
                if isinstance(self.operation, EditOperationKind)
                else EditOperationKind(str(self.operation).lower())
            )
        except ValueError as exc:
            raise EditTransactionError("unsupported edit operation") from exc
        object.__setattr__(self, "operation", kind)
        object.__setattr__(
            self,
            "path",
            _normalize_relative_path(self.path, "operation.path"),
        )
        if self.destination_path is not None:
            object.__setattr__(
                self,
                "destination_path",
                _normalize_relative_path(
                    self.destination_path, "operation.destination_path"
                ),
            )
        if self.expected_exists is not None and type(self.expected_exists) is not bool:
            raise EditTransactionError("expected_exists must be a boolean")
        object.__setattr__(
            self,
            "expected_digest",
            _optional_digest(self.expected_digest, "expected_digest"),
        )
        if self.content is not None:
            if not isinstance(self.content, str) or "\x00" in self.content:
                raise EditTransactionError("operation.content must be text")
            if len(self.content.encode("utf-8")) > DEFAULT_FILE_TOOL_BYTES:
                raise EditTransactionError("operation.content exceeds the file bound")
        if not isinstance(self.text_edits, tuple) or any(
            not isinstance(edit, TextEdit) for edit in self.text_edits
        ):
            raise EditTransactionError("text_edits must be an immutable TextEdit tuple")
        if len(self.text_edits) > MAX_TEXT_EDITS:
            raise EditTransactionError("too many text edits")

        if kind is EditOperationKind.CREATE:
            if self.content is None or self.text_edits or self.destination_path is not None:
                raise EditTransactionError(
                    "create requires content and no destination or text edits"
                )
            if self.expected_exists is True or self.expected_digest is not None:
                raise EditTransactionError("create must be bound to an absent target")
        elif kind is EditOperationKind.UPDATE:
            if self.destination_path is not None:
                raise EditTransactionError("update cannot have a destination")
            if (self.content is None) == (not self.text_edits):
                raise EditTransactionError(
                    "update requires either content or text_edits, but not neither"
                )
        elif kind is EditOperationKind.DELETE:
            if (
                self.content is not None
                or self.text_edits
                or self.destination_path is not None
            ):
                raise EditTransactionError("delete cannot carry content or a destination")
        elif kind is EditOperationKind.RENAME:
            if (
                self.destination_path is None
                or self.content is not None
                or self.text_edits
            ):
                raise EditTransactionError(
                    "rename requires a destination and no content edits"
                )
            if self.destination_path == self.path:
                raise EditTransactionError("rename source and destination must differ")

    def to_payload(self, *, include_content: bool = True) -> dict[str, object]:
        payload: dict[str, object] = {
            "operation": self.operation.value,
            "path": self.path,
            "destination_path": self.destination_path,
            "expected_exists": self.expected_exists,
            "expected_digest": self.expected_digest,
            "text_edits": [
                {
                    "start": edit.start,
                    "end": edit.end,
                    "replacement": edit.replacement,
                }
                for edit in self.text_edits
            ],
        }
        payload["content"] = self.content if include_content else None
        return payload


@dataclass(frozen=True, slots=True)
class EditTransaction:
    """Immutable transaction envelope bound to one workspace generation."""

    transaction_id: str
    workspace_id: str
    base_generation: int
    operations: tuple[EditOperation, ...]
    expected_workspace_digest: str | None = None
    intent: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "transaction_id",
            _bounded_text(
                self.transaction_id,
                "transaction_id",
                MAX_TRANSACTION_ID_LENGTH,
            ),
        )
        object.__setattr__(
            self,
            "workspace_id",
            _bounded_text(self.workspace_id, "workspace_id", MAX_TRANSACTION_ID_LENGTH),
        )
        if type(self.base_generation) is not int or self.base_generation <= 0:
            raise EditTransactionError("base_generation must be a positive integer")
        if not isinstance(self.operations, tuple) or not self.operations:
            raise EditTransactionError("operations must be a non-empty immutable tuple")
        if len(self.operations) > MAX_EDIT_OPERATIONS or any(
            not isinstance(operation, EditOperation) for operation in self.operations
        ):
            raise EditTransactionError("operations exceed the transaction bound")
        object.__setattr__(
            self,
            "expected_workspace_digest",
            _optional_digest(
                self.expected_workspace_digest, "expected_workspace_digest"
            ),
        )
        if not isinstance(self.intent, str) or len(self.intent) > MAX_INTENT_LENGTH:
            raise EditTransactionError("intent exceeds its bound")
        if "\x00" in self.intent:
            raise EditTransactionError("intent contains a NUL byte")
        touched: set[str] = set()
        payload_bytes = 0
        for operation in self.operations:
            paths = [operation.path]
            if operation.destination_path is not None:
                paths.append(operation.destination_path)
            for path in paths:
                folded = path.casefold()
                if folded in touched:
                    raise EditTransactionError(
                        "a transaction cannot touch the same path twice"
                    )
                touched.add(folded)
            payload_bytes += len(_canonical_json_bytes(operation.to_payload()))
        if payload_bytes > MAX_TRANSACTION_BYTES:
            raise EditTransactionError("transaction payload exceeds its bound")

    @property
    def transaction_digest(self) -> str:
        """Return the stable digest used in audit, approval, and result bindings."""
        return hashlib.sha256(_canonical_json_bytes(self.to_payload())).hexdigest()

    def to_payload(self) -> dict[str, object]:
        return {
            "transaction_id": self.transaction_id,
            "workspace_id": self.workspace_id,
            "base_generation": self.base_generation,
            "expected_workspace_digest": self.expected_workspace_digest,
            "intent": self.intent,
            "operations": [
                operation.to_payload() for operation in self.operations
            ],
        }


@dataclass(frozen=True, slots=True)
class EditOperationPreview:
    """Bounded deterministic preview for one operation."""

    index: int
    operation: EditOperationKind
    path: str
    destination_path: str | None
    before_exists: bool
    after_exists: bool
    before_digest: str | None
    after_digest: str | None
    diff: str

    def to_payload(self) -> dict[str, object]:
        return {
            "index": self.index,
            "operation": self.operation.value,
            "path": self.path,
            "destination_path": self.destination_path,
            "before_exists": self.before_exists,
            "after_exists": self.after_exists,
            "before_digest": self.before_digest,
            "after_digest": self.after_digest,
            "diff": self.diff,
        }


@dataclass(frozen=True, slots=True)
class EditPreview:
    """Preview result that carries both workspace and transaction identity."""

    transaction_id: str
    workspace_id: str
    base_generation: int
    transaction_digest: str
    before_workspace_digest: str
    predicted_workspace_digest: str
    operations: tuple[EditOperationPreview, ...]

    def to_payload(self) -> dict[str, object]:
        return {
            "status": EditTransactionStatus.PREVIEWED.value,
            "transaction_id": self.transaction_id,
            "workspace_id": self.workspace_id,
            "base_generation": self.base_generation,
            "transaction_digest": self.transaction_digest,
            "before_workspace_digest": self.before_workspace_digest,
            "predicted_workspace_digest": self.predicted_workspace_digest,
            "operations": [operation.to_payload() for operation in self.operations],
        }


@dataclass(frozen=True, slots=True)
class EditOperationResult:
    """Bounded result for one applied operation."""

    index: int
    operation: EditOperationKind
    path: str
    destination_path: str | None
    before_exists: bool
    after_exists: bool
    before_digest: str | None
    after_digest: str | None

    def to_payload(self) -> dict[str, object]:
        return {
            "index": self.index,
            "operation": self.operation.value,
            "path": self.path,
            "destination_path": self.destination_path,
            "before_exists": self.before_exists,
            "after_exists": self.after_exists,
            "before_digest": self.before_digest,
            "after_digest": self.after_digest,
        }


@dataclass(frozen=True, slots=True)
class EditTransactionResult:
    """Successful transaction result."""

    transaction_id: str
    workspace_id: str
    base_generation: int
    resulting_generation: int
    transaction_digest: str
    before_workspace_digest: str
    after_workspace_digest: str
    operations: tuple[EditOperationResult, ...]

    def to_payload(self) -> dict[str, object]:
        return {
            "status": EditTransactionStatus.APPLIED.value,
            "transaction_id": self.transaction_id,
            "workspace_id": self.workspace_id,
            "base_generation": self.base_generation,
            "resulting_generation": self.resulting_generation,
            "transaction_digest": self.transaction_digest,
            "before_workspace_digest": self.before_workspace_digest,
            "after_workspace_digest": self.after_workspace_digest,
            "operations": [operation.to_payload() for operation in self.operations],
        }


@dataclass(slots=True)
class _PreparedEdit:
    operation: EditOperation
    before: WorkspaceFileSnapshot
    before_destination: WorkspaceFileSnapshot | None
    after_content: bytes | None


@dataclass(slots=True)
class _AppliedEdit:
    prepared: _PreparedEdit
    after: WorkspaceFileSnapshot
    after_destination: WorkspaceFileSnapshot | None


def _digest(snapshot: WorkspaceFileSnapshot) -> str | None:
    return snapshot.digest if snapshot.exists else None


def _validate_published_identity(
    snapshot: WorkspaceFileSnapshot,
    identity: object | None,
    path: str,
) -> None:
    """Prove that a post-publish snapshot still names the published object."""
    if not isinstance(identity, MutationObjectIdentity):
        raise EditTransactionRecoveryError(
            f"published identity is unavailable: {path}"
        )
    if identity.exists:
        if (
            not snapshot.exists
            or snapshot.identity != (identity.object_dev, identity.object_ino)
        ):
            raise EditTransactionRecoveryError(
                f"published identity changed: {path}"
            )
    elif snapshot.exists:
        raise EditTransactionRecoveryError(
            f"deleted target reappeared: {path}"
        )


def _validate_published_state(
    item: _PreparedEdit,
    after: WorkspaceFileSnapshot,
    after_destination: WorkspaceFileSnapshot | None,
    identity: object | None,
) -> None:
    """Validate identity and intended content at every publish boundary."""
    operation = item.operation
    if operation.operation in {
        EditOperationKind.CREATE,
        EditOperationKind.UPDATE,
    }:
        _validate_published_identity(after, identity, operation.path)
        if item.after_content is None or after.digest != hashlib.sha256(
            item.after_content
        ).hexdigest():
            raise EditTransactionRecoveryError(
                f"published content changed: {operation.path}"
            )
    elif operation.operation is EditOperationKind.DELETE:
        _validate_published_identity(after, identity, operation.path)
    else:
        destination = operation.destination_path
        if destination is None or after_destination is None:
            raise EditTransactionRecoveryError(
                f"published rename state is incomplete: {operation.path}"
            )
        _validate_published_identity(after_destination, identity, destination)
        if (
            after.exists
            or not after_destination.exists
            or after_destination.digest != item.before.digest
        ):
            raise EditTransactionRecoveryError(
                f"published rename content changed: {operation.path}"
            )


def _snapshot_payload(snapshot: WorkspaceFileSnapshot) -> dict[str, object]:
    return {
        "exists": snapshot.exists,
        "digest": _digest(snapshot),
        "size": snapshot.size if snapshot.exists else 0,
    }


def _workspace_digest(filesystem: SafeWorkspaceFS) -> str:
    """Hash the bounded regular-file view exposed by SafeWorkspaceFS."""
    entries = []
    total_bytes = 0
    for path in filesystem.iter_files(
        ".",
        max_entries=DEFAULT_TREE_ENTRIES,
        max_depth=DEFAULT_TREE_DEPTH,
    ):
        content = filesystem.read_bytes(path, max_bytes=DEFAULT_FILE_TOOL_BYTES)
        total_bytes += len(content)
        if total_bytes > DEFAULT_TREE_BYTES:
            raise EditTransactionApplyError(
                "workspace digest exceeds the aggregate byte limit"
            )
        entries.append(
            {
                "path": path,
                "size": len(content),
                "digest": hashlib.sha256(content).hexdigest(),
            }
        )
    return hashlib.sha256(_canonical_json_bytes(entries)).hexdigest()


def _workspace_digest_with_overrides(
    filesystem: SafeWorkspaceFS,
    overrides: dict[str, bytes | None],
) -> str:
    """Hash the current safe file view after applying an in-memory change set."""
    paths = set(
        filesystem.iter_files(
            ".",
            max_entries=DEFAULT_TREE_ENTRIES,
            max_depth=DEFAULT_TREE_DEPTH,
        )
    )
    paths.update(overrides)
    entries = []
    total_bytes = 0
    for path in sorted(paths):
        content = (
            overrides[path]
            if path in overrides
            else filesystem.read_bytes(path, max_bytes=DEFAULT_FILE_TOOL_BYTES)
        )
        if content is None:
            continue
        total_bytes += len(content)
        if total_bytes > DEFAULT_TREE_BYTES:
            raise EditTransactionApplyError(
                "workspace digest exceeds the aggregate byte limit"
            )
        entries.append(
            {
                "path": path,
                "size": len(content),
                "digest": hashlib.sha256(content).hexdigest(),
            }
        )
    return hashlib.sha256(_canonical_json_bytes(entries)).hexdigest()


def _decode_text(content: bytes, path: str) -> str:
    try:
        return content.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise EditTransactionApplyError(
            f"transaction target is not valid UTF-8 text: {path}"
        ) from exc


def _apply_text_edits(
    original: str,
    edits: tuple[TextEdit, ...],
    path: str,
) -> str:
    ordered = sorted(edits, key=lambda edit: (edit.start, edit.end))
    previous_end = 0
    for edit in ordered:
        if edit.end > len(original) or edit.start < previous_end:
            raise EditTransactionPreconditionError(
                f"text edit range is invalid or overlapping: {path}"
            )
        previous_end = edit.end
    updated = original
    for edit in reversed(ordered):
        updated = (
            updated[:edit.start]
            + edit.replacement
            + updated[edit.end:]
        )
    if len(updated.encode("utf-8")) > DEFAULT_FILE_TOOL_BYTES:
        raise EditTransactionApplyError("updated file exceeds the file-tool bound")
    return updated


def _require_apply_preconditions(transaction: EditTransaction) -> None:
    for operation in transaction.operations:
        if operation.operation is EditOperationKind.CREATE:
            if operation.expected_exists is not False:
                raise EditTransactionPreconditionError(
                    "create requires expected_exists=false"
                )
            continue
        if operation.expected_exists is not True:
            raise EditTransactionPreconditionError(
                f"{operation.operation.value} requires expected_exists=true"
            )
        if operation.expected_digest is None:
            raise EditTransactionPreconditionError(
                f"{operation.operation.value} requires expected_digest"
            )


def _snapshot(
    filesystem: SafeWorkspaceFS,
    path: str,
    *,
    recovery_root: Any = None,
) -> WorkspaceFileSnapshot:
    try:
        return filesystem.snapshot_file(
            path,
            recovery_root=recovery_root,
            max_bytes=DEFAULT_FILE_TOOL_BYTES,
        )
    except (WorkspaceBoundaryError, OSError) as exc:
        raise EditTransactionPreconditionError(
            f"cannot safely snapshot transaction path: {path}"
        ) from exc


def _validate_expected(
    operation: EditOperation,
    snapshot: WorkspaceFileSnapshot,
) -> None:
    if operation.expected_exists is not None and (
        snapshot.exists is not operation.expected_exists
    ):
        raise EditTransactionPreconditionError(
            f"expected existence does not match current state: {operation.path}"
        )
    if operation.expected_digest is not None and (
        not snapshot.exists or snapshot.digest != operation.expected_digest
    ):
        raise EditTransactionPreconditionError(
            f"expected digest does not match current state: {operation.path}"
        )


def _cleanup_prepared(prepared: list[_PreparedEdit]) -> None:
    seen: set[int] = set()
    for item in prepared:
        marker = id(item.before)
        if marker not in seen:
            item.before.cleanup()
            seen.add(marker)
        if item.before_destination is not None:
            marker = id(item.before_destination)
            if marker not in seen:
                item.before_destination.cleanup()
                seen.add(marker)


def _prepare_operations(
    filesystem: SafeWorkspaceFS,
    transaction: EditTransaction,
    *,
    recovery_root: Any = None,
    for_apply: bool,
) -> list[_PreparedEdit]:
    """Snapshot and validate every operation before the first publish."""
    if for_apply:
        _require_apply_preconditions(transaction)
    paths = sorted(
        {
            path
            for operation in transaction.operations
            for path in (operation.path, operation.destination_path)
            if path is not None
        }
    )
    snapshots: dict[str, WorkspaceFileSnapshot] = {}
    prepared: list[_PreparedEdit] = []
    try:
        for path in paths:
            snapshots[path] = _snapshot(
                filesystem,
                path,
                recovery_root=recovery_root,
            )
        for operation in transaction.operations:
            before = snapshots[operation.path]
            _validate_expected(operation, before)
            before_destination = (
                snapshots[operation.destination_path]
                if operation.destination_path is not None
                else None
            )
            if operation.operation is EditOperationKind.CREATE:
                if before.exists:
                    raise EditTransactionPreconditionError(
                        f"create target already exists: {operation.path}"
                    )
                after_content = operation.content.encode("utf-8")  # type: ignore[union-attr]
            elif operation.operation is EditOperationKind.UPDATE:
                if not before.exists:
                    raise EditTransactionPreconditionError(
                        f"update target does not exist: {operation.path}"
                    )
                original = _decode_text(
                    filesystem.read_bytes(
                        operation.path,
                        max_bytes=MAX_PREVIEW_SOURCE_BYTES,
                    ),
                    operation.path,
                )
                if operation.content is not None:
                    after_content = operation.content.encode("utf-8")
                else:
                    after_content = _apply_text_edits(
                        original,
                        operation.text_edits,
                        operation.path,
                    ).encode("utf-8")
            elif operation.operation is EditOperationKind.DELETE:
                if not before.exists:
                    raise EditTransactionPreconditionError(
                        f"delete target does not exist: {operation.path}"
                    )
                after_content = None
            else:
                if not before.exists:
                    raise EditTransactionPreconditionError(
                        f"rename source does not exist: {operation.path}"
                    )
                if before_destination is None or before_destination.exists:
                    raise EditTransactionPreconditionError(
                        f"rename destination already exists: "
                        f"{operation.destination_path}"
                    )
                after_content = None
            if (
                after_content is not None
                and len(after_content) > DEFAULT_FILE_TOOL_BYTES
            ):
                raise EditTransactionApplyError(
                    f"resulting file exceeds the file-tool bound: {operation.path}"
                )
            prepared.append(
                _PreparedEdit(
                    operation=operation,
                    before=before,
                    before_destination=before_destination,
                    after_content=after_content,
                )
            )
        # Revalidate every captured path after all content preparation and
        # before the caller is allowed to publish even the first operation.
        # This turns concurrent changes during a text read into a stale
        # precondition, rather than discovering them only after a prior file
        # in the transaction has already been published.
        for path, expected in snapshots.items():
            current = _snapshot(filesystem, path)
            if current != expected:
                raise EditTransactionPreconditionError(
                    f"transaction path changed during preparation: {path}"
                )
        return prepared
    except Exception:
        _cleanup_prepared(
            [
                _PreparedEdit(
                    operation=transaction.operations[0],
                    before=snapshot,
                    before_destination=None,
                    after_content=None,
                )
                for snapshot in snapshots.values()
            ]
        )
        raise


def _same_snapshot(
    filesystem: SafeWorkspaceFS,
    path: str,
    expected: WorkspaceFileSnapshot,
) -> WorkspaceFileSnapshot:
    current = _snapshot(filesystem, path)
    if current != expected:
        raise EditTransactionRecoveryError(
            f"transaction path changed during recovery: {path}"
        )
    return current


def _rollback_one(
    filesystem: SafeWorkspaceFS,
    prepared: _PreparedEdit,
    applied: _AppliedEdit,
) -> None:
    operation = prepared.operation
    if operation.operation in {
        EditOperationKind.CREATE,
        EditOperationKind.UPDATE,
    }:
        current = _same_snapshot(filesystem, operation.path, applied.after)
        if prepared.before.exists:
            filesystem.restore_file(
                operation.path,
                prepared.before,
                expected=current,
            )
        else:
            filesystem.delete_file(operation.path, expected=current)
        return
    if operation.operation is EditOperationKind.DELETE:
        current = _snapshot(filesystem, operation.path)
        if current.exists:
            raise EditTransactionRecoveryError(
                f"deleted target reappeared during recovery: {operation.path}"
            )
        filesystem.restore_file(
            operation.path,
            prepared.before,
            expected=current,
        )
        return

    destination = operation.destination_path
    if destination is None:
        raise EditTransactionRecoveryError("rename destination is missing")
    current_source = _snapshot(filesystem, operation.path)
    current_destination = _same_snapshot(
        filesystem,
        destination,
        applied.after_destination
        if applied.after_destination is not None
        else WorkspaceFileSnapshot(False),
    )
    if current_source.exists:
        raise EditTransactionRecoveryError(
            f"rename source reappeared during recovery: {operation.path}"
        )
    if not current_destination.exists:
        raise EditTransactionRecoveryError(
            f"rename destination disappeared during recovery: {destination}"
        )
    filesystem.move_published_back(
        destination,
        operation.path,
        (
            current_destination.identity[0],
            current_destination.identity[1],
            current_destination.mode,
        )
        if current_destination.identity is not None
        else None,
    )
    restored = _snapshot(filesystem, operation.path)
    removed = _snapshot(filesystem, destination)
    if restored != prepared.before or removed.exists:
        raise EditTransactionRecoveryError(
            f"rename recovery verification failed: {operation.path}"
        )


def _rollback_applied(
    filesystem: SafeWorkspaceFS,
    applied: list[_AppliedEdit],
) -> None:
    for item in reversed(applied):
        _rollback_one(filesystem, item.prepared, item)


def _capture_published_edit(
    filesystem: SafeWorkspaceFS,
    item: _PreparedEdit,
    transaction: EditTransaction,
    applied: list[_AppliedEdit],
    published_identity: object | None,
) -> None:
    """Record an effect observed before a lower-level mutation failed.

    SafeWorkspaceFS reports the ``filesystem-applied`` phase before its final
    directory revalidation/fsync. If that later phase raises, the transaction
    must still account for the published operation. A missing or unsafe
    post-state cannot be treated as an ordinary tool error: quarantine is the
    only safe outcome when the effect cannot be identity-bound for rollback.
    """
    operation = item.operation
    try:
        after = _snapshot(filesystem, operation.path)
        after_destination = (
            _snapshot(filesystem, operation.destination_path)
            if operation.destination_path is not None
            else None
        )
        _validate_published_state(
            item, after, after_destination, published_identity
        )
    except Exception as exc:
        raise _recovery_violation(transaction, exc) from exc
    changed = after != item.before
    if item.before_destination is not None:
        changed = changed or after_destination != item.before_destination
    if changed:
        applied.append(_AppliedEdit(item, after, after_destination))


def _verify_live_published_state(
    filesystem: SafeWorkspaceFS,
    applied: list[_AppliedEdit],
) -> None:
    """Re-read every published leaf immediately before reporting success.

    The workspace lock serializes Khaos mutations, but it cannot prevent an
    unrelated process from replacing a pathname.  The snapshots captured
    immediately after each publish therefore cannot by themselves serve as a
    final success claim.  A drift is an apply failure and is handled by the
    existing identity-bound rollback/quarantine path.
    """
    for item in applied:
        operation = item.prepared.operation
        current = _snapshot(filesystem, operation.path)
        if current != item.after:
            raise EditTransactionApplyError(
                f"published path changed before transaction completion: "
                f"{operation.path}"
            )
        if operation.destination_path is not None:
            current_destination = _snapshot(filesystem, operation.destination_path)
            expected_destination = item.after_destination
            if expected_destination is None or current_destination != expected_destination:
                raise EditTransactionApplyError(
                    "published destination changed before transaction completion: "
                    f"{operation.destination_path}"
                )


def _recovery_violation(
    transaction: EditTransaction,
    error: BaseException,
) -> WorkspaceStorageViolation:
    diagnostic = {
        "kind": "edit-transaction-recovery",
        "observed": "rollback-failed",
        "limit": "rollback-complete",
        "transaction_id": transaction.transaction_id,
        "transaction_digest": transaction.transaction_digest,
        "error": type(error).__name__,
    }
    return WorkspaceStorageViolation(
        diagnostic,
        rollback_attempted=True,
        rollback_succeeded=False,
        quarantine_required=True,
    )


def _bounded_diff(
    before: str,
    after: str,
    *,
    from_path: str,
    to_path: str,
) -> str:
    diff = "".join(
        difflib.unified_diff(
            before.splitlines(keepends=True),
            after.splitlines(keepends=True),
            fromfile=from_path,
            tofile=to_path,
            n=3,
        )
    )
    encoded = diff.encode("utf-8")
    if len(encoded) <= MAX_PREVIEW_BYTES:
        return diff
    marker = b"\n... [preview truncated]\n"
    prefix = max(0, MAX_PREVIEW_BYTES - len(marker))
    return encoded[:prefix].decode("utf-8", errors="ignore") + marker.decode()


def _read_touched_content(
    filesystem: SafeWorkspaceFS,
    transaction: EditTransaction,
    prepared: list[_PreparedEdit],
) -> dict[str, bytes]:
    content: dict[str, bytes] = {}
    for item in prepared:
        for path, snapshot in (
            (item.operation.path, item.before),
            (item.operation.destination_path, item.before_destination),
        ):
            if path is not None and snapshot is not None and snapshot.exists:
                current = _snapshot(filesystem, path)
                if current != snapshot:
                    raise EditTransactionPreconditionError(
                        f"transaction path changed while previewing: {path}"
                    )
                value = filesystem.read_bytes(
                    path,
                    max_bytes=MAX_PREVIEW_SOURCE_BYTES,
                )
                if hashlib.sha256(value).hexdigest() != snapshot.digest:
                    raise EditTransactionPreconditionError(
                        f"transaction content changed while previewing: {path}"
                    )
                if _snapshot(filesystem, path) != snapshot:
                    raise EditTransactionPreconditionError(
                        f"transaction path changed while previewing: {path}"
                    )
                content[path] = value
    return content


def _preview_sync(
    root: Any,
    transaction: EditTransaction,
) -> EditPreview:
    with SafeWorkspaceFS(root) as filesystem:
        before_workspace_digest = _workspace_digest(filesystem)
        if (
            transaction.expected_workspace_digest is not None
            and transaction.expected_workspace_digest != before_workspace_digest
        ):
            raise EditTransactionPreconditionError(
                "expected workspace digest does not match current state"
            )
        prepared = _prepare_operations(
            filesystem,
            transaction,
            for_apply=False,
        )
        try:
            before_content = _read_touched_content(
                filesystem,
                transaction,
                prepared,
            )
            overrides: dict[str, bytes | None] = {}
            operation_previews: list[EditOperationPreview] = []
            for index, item in enumerate(prepared):
                operation = item.operation
                before = item.before
                if operation.operation is EditOperationKind.RENAME:
                    destination = operation.destination_path
                    if destination is None:
                        raise EditTransactionApplyError(
                            "rename destination is missing"
                        )
                    source_content = before_content[operation.path]
                    overrides[operation.path] = None
                    overrides[destination] = source_content
                    diff = f"rename {operation.path} -> {destination}\n"
                    after_exists = False
                    after_digest = None
                else:
                    after_content = item.after_content
                    overrides[operation.path] = after_content
                    after_exists = after_content is not None
                    after_digest = (
                        hashlib.sha256(after_content).hexdigest()
                        if after_content is not None
                        else None
                    )
                    before_text = (
                        _decode_text(
                            before_content[operation.path],
                            operation.path,
                        )
                        if before.exists
                        else ""
                    )
                    after_text = (
                        _decode_text(after_content, operation.path)
                        if after_content is not None
                        else ""
                    )
                    diff = _bounded_diff(
                        before_text,
                        after_text,
                        from_path=operation.path,
                        to_path=operation.path,
                    )
                operation_previews.append(
                    EditOperationPreview(
                        index=index,
                        operation=operation.operation,
                        path=operation.path,
                        destination_path=operation.destination_path,
                        before_exists=before.exists,
                        after_exists=after_exists,
                        before_digest=_digest(before),
                        after_digest=after_digest,
                        diff=diff,
                    )
                )
            predicted_workspace_digest = _workspace_digest_with_overrides(
                filesystem,
                overrides,
            )
            if _workspace_digest(filesystem) != before_workspace_digest:
                raise EditTransactionPreconditionError(
                    "workspace changed while preview was being built"
                )
            return EditPreview(
                transaction_id=transaction.transaction_id,
                workspace_id=transaction.workspace_id,
                base_generation=transaction.base_generation,
                transaction_digest=transaction.transaction_digest,
                before_workspace_digest=before_workspace_digest,
                predicted_workspace_digest=predicted_workspace_digest,
                operations=tuple(operation_previews),
            )
        finally:
            _cleanup_prepared(prepared)


def _apply_sync(
    workspace: TaskWorkspace,
    transaction: EditTransaction,
    recovery_root: Any,
) -> WorkspaceMutation[EditTransactionResult]:
    """Apply under the manager's storage lock and return an all-or-rollback mutation."""
    root = workspace.worktree_path
    prepared: list[_PreparedEdit] = []
    applied: list[_AppliedEdit] = []
    committed = False
    with SafeWorkspaceFS(root) as filesystem:
        try:
            if workspace.generation != transaction.base_generation:
                raise EditTransactionStaleError(
                    "transaction base_generation is stale"
                )
            before_workspace_digest = _workspace_digest(filesystem)
            if (
                transaction.expected_workspace_digest is not None
                and transaction.expected_workspace_digest != before_workspace_digest
            ):
                raise EditTransactionPreconditionError(
                    "expected workspace digest does not match current state"
                )
            prepared = _prepare_operations(
                filesystem,
                transaction,
                recovery_root=recovery_root,
                for_apply=True,
            )
            for item in prepared:
                operation = item.operation
                published = False
                published_identity: object | None = None

                def mark_published(
                    identity: object | None = None,
                    *_args: object,
                    **_kwargs: object,
                ) -> None:
                    nonlocal published, published_identity
                    published = True
                    published_identity = identity

                try:
                    if operation.operation in {
                        EditOperationKind.CREATE,
                        EditOperationKind.UPDATE,
                    }:
                        current = _snapshot(filesystem, operation.path)
                        if current != item.before:
                            raise EditTransactionPreconditionError(
                                f"target changed before publish: {operation.path}"
                            )
                        if item.after_content is None:
                            raise EditTransactionApplyError(
                                f"prepared content is missing: {operation.path}"
                            )
                        filesystem.write_bytes(
                            operation.path,
                            item.after_content,
                            effect_callback=mark_published,
                        )
                        after = _snapshot(filesystem, operation.path)
                        _validate_published_state(
                            item, after, None, published_identity
                        )
                        applied.append(_AppliedEdit(item, after, None))
                    elif operation.operation is EditOperationKind.DELETE:
                        current = _snapshot(filesystem, operation.path)
                        if current != item.before:
                            raise EditTransactionPreconditionError(
                                f"target changed before delete: {operation.path}"
                            )
                        filesystem.delete_file(
                            operation.path,
                            expected=item.before,
                            effect_callback=mark_published,
                        )
                        after = _snapshot(filesystem, operation.path)
                        _validate_published_state(
                            item, after, None, published_identity
                        )
                        applied.append(_AppliedEdit(item, after, None))
                    else:
                        destination = operation.destination_path
                        if destination is None or item.before_destination is None:
                            raise EditTransactionApplyError(
                                "prepared rename is incomplete"
                            )
                        current_source = _snapshot(filesystem, operation.path)
                        current_destination = _snapshot(filesystem, destination)
                        if (
                            current_source != item.before
                            or current_destination != item.before_destination
                        ):
                            raise EditTransactionPreconditionError(
                                f"rename state changed before publish: {operation.path}"
                            )
                        filesystem.move_file(
                            operation.path,
                            destination,
                            effect_callback=mark_published,
                        )
                        after = _snapshot(filesystem, operation.path)
                        after_destination = _snapshot(filesystem, destination)
                        _validate_published_state(
                            item, after, after_destination, published_identity
                        )
                        applied.append(_AppliedEdit(item, after, after_destination))
                except Exception:
                    if published:
                        _capture_published_edit(
                            filesystem,
                            item,
                            transaction,
                            applied,
                            published_identity,
                        )
                    raise

            _verify_live_published_state(filesystem, applied)
            for item in applied:
                operation = item.prepared.operation
                if operation.operation in {
                    EditOperationKind.CREATE,
                    EditOperationKind.UPDATE,
                }:
                    if (
                        not item.after.exists
                        or item.prepared.after_content is None
                        or item.after.digest
                        != hashlib.sha256(item.prepared.after_content).hexdigest()
                    ):
                        raise EditTransactionApplyError(
                            f"resulting file verification failed: {operation.path}"
                        )
                elif operation.operation is EditOperationKind.DELETE:
                    if item.after.exists:
                        raise EditTransactionApplyError(
                            f"delete verification failed: {operation.path}"
                        )
                else:
                    destination = operation.destination_path
                    if (
                        item.after.exists
                        or destination is None
                        or item.after_destination is None
                        or not item.after_destination.exists
                        or item.after_destination.digest
                        != item.prepared.before.digest
                    ):
                        raise EditTransactionApplyError(
                            f"rename verification failed: {operation.path}"
                        )
            after_workspace_digest = _workspace_digest(filesystem)
            operation_results = tuple(
                EditOperationResult(
                    index=index,
                    operation=item.prepared.operation.operation,
                    path=item.prepared.operation.path,
                    destination_path=item.prepared.operation.destination_path,
                    before_exists=item.prepared.before.exists,
                    after_exists=(
                        item.after.exists
                        if item.prepared.operation.operation
                        is not EditOperationKind.RENAME
                        else item.after_destination is not None
                        and item.after_destination.exists
                    ),
                    before_digest=_digest(item.prepared.before),
                    after_digest=(
                        _digest(item.after)
                        if item.prepared.operation.operation
                        is not EditOperationKind.RENAME
                        else _digest(item.after_destination)
                    ),
                )
                for index, item in enumerate(applied)
            )
            result = EditTransactionResult(
                transaction_id=transaction.transaction_id,
                workspace_id=transaction.workspace_id,
                base_generation=transaction.base_generation,
                resulting_generation=transaction.base_generation + 1,
                transaction_digest=transaction.transaction_digest,
                before_workspace_digest=before_workspace_digest,
                after_workspace_digest=after_workspace_digest,
                operations=operation_results,
            )

            def rollback() -> None:
                try:
                    with SafeWorkspaceFS(root) as rollback_filesystem:
                        _rollback_applied(rollback_filesystem, applied)
                except WorkspaceStorageViolation:
                    raise
                except Exception as exc:
                    raise _recovery_violation(transaction, exc) from exc

            def finalize() -> None:
                _cleanup_prepared(prepared)

            committed = True
            return WorkspaceMutation(result, rollback, finalize)
        except Exception as exc:
            if applied:
                try:
                    _rollback_applied(filesystem, applied)
                except Exception as rollback_error:  # noqa: BLE001 - recovery must quarantine
                    raise _recovery_violation(transaction, rollback_error) from exc
            if isinstance(
                exc,
                (
                    EditTransactionError,
                    WorkspaceStorageViolation,
                ),
            ):
                raise
            raise EditTransactionApplyError(str(exc)) from exc
        finally:
            if not committed:
                _cleanup_prepared(prepared)


class EditTransactionService:
    """Workspace-bound preview/apply service used by Coding tools."""

    def _resolve_workspace(
        self,
        transaction: EditTransaction,
        *,
        workspace_manager: Any,
        task_id: str,
        workspace_id: str | None,
        principal_id: str | None,
        project_id: str | None,
        runtime_id: str | None,
    ) -> TaskWorkspace:
        if workspace_manager is None or not task_id:
            raise PermissionError("edit transactions require a TaskWorkspace owner")
        if workspace_id is not None and workspace_id != transaction.workspace_id:
            raise PermissionError("transaction workspace does not match the tool scope")
        if all(
            value is not None
            for value in (principal_id, project_id, runtime_id)
        ):
            workspace = workspace_manager.require(
                transaction.workspace_id,
                task_id=task_id,
                principal_id=principal_id,
                project_id=project_id,
                runtime_id=runtime_id,
            )
        else:
            runtime_profile = getattr(workspace_manager, "runtime_profile", None)
            if bool(getattr(runtime_profile, "is_production", False)):
                raise PermissionError(
                    "production edit transactions require complete owner identity"
                )
            workspace = workspace_manager.get(transaction.workspace_id)
            if workspace is None or workspace.task_id != task_id:
                raise PermissionError("transaction TaskWorkspace binding is invalid")
        if workspace.id != transaction.workspace_id:
            raise PermissionError("transaction workspace identity is invalid")
        if workspace.state in {
            WorkspaceState.FAILED,
            WorkspaceState.CANCELLED,
            WorkspaceState.CLEANING,
            WorkspaceState.CLEANED,
        }:
            raise PermissionError("transaction workspace is not active")
        if type(workspace.generation) is not int or workspace.generation <= 0:
            raise EditTransactionApplyError("workspace generation is invalid")
        if workspace.generation != transaction.base_generation:
            raise EditTransactionStaleError(
                "transaction base_generation is stale"
            )
        return workspace

    async def preview(
        self,
        transaction: EditTransaction,
        *,
        workspace_manager: Any,
        task_id: str,
        workspace_id: str | None = None,
        principal_id: str | None = None,
        project_id: str | None = None,
        runtime_id: str | None = None,
    ) -> EditPreview:
        workspace = self._resolve_workspace(
            transaction,
            workspace_manager=workspace_manager,
            task_id=task_id,
            workspace_id=workspace_id,
            principal_id=principal_id,
            project_id=project_id,
            runtime_id=runtime_id,
        )
        storage_scope = getattr(workspace_manager, "workspace_storage_scope", None)
        if callable(storage_scope):
            async with storage_scope(transaction.workspace_id, task_id) as locked:
                workspace = locked
                if workspace.generation != transaction.base_generation:
                    raise EditTransactionStaleError(
                        "transaction base_generation is stale"
                    )
                observed_generation = workspace.generation
                preview = await asyncio.to_thread(
                    _preview_sync,
                    workspace.worktree_path,
                    transaction,
                )
                if workspace.generation != observed_generation:
                    raise EditTransactionStaleError(
                        "workspace changed while preview was being built"
                    )
                return preview
        observed_generation = workspace.generation
        preview = await asyncio.to_thread(
            _preview_sync,
            workspace.worktree_path,
            transaction,
        )
        if workspace.generation != observed_generation:
            raise EditTransactionStaleError(
                "workspace changed while preview was being built"
            )
        return preview

    async def apply(
        self,
        transaction: EditTransaction,
        *,
        workspace_manager: Any,
        task_id: str,
        workspace_id: str | None = None,
        principal_id: str | None = None,
        project_id: str | None = None,
        runtime_id: str | None = None,
    ) -> EditTransactionResult:
        workspace = self._resolve_workspace(
            transaction,
            workspace_manager=workspace_manager,
            task_id=task_id,
            workspace_id=workspace_id,
            principal_id=principal_id,
            project_id=project_id,
            runtime_id=runtime_id,
        )
        mutate = getattr(
            workspace_manager,
            "mutate_with_storage_authority",
            None,
        )
        if mutate is None:
            raise PermissionError(
                "edit transactions require WorkspaceStorageAuthority"
            )
        recovery_root = workspace_manager.file_recovery_root(workspace.id)
        return await mutate(
            workspace.id,
            task_id,
            lambda: _apply_sync(workspace, transaction, recovery_root),
        )


# Keep the engine name available to callers that use the milestone vocabulary.
EditTransactionEngine = EditTransactionService


__all__ = [
    "EditOperation",
    "EditOperationKind",
    "EditOperationPreview",
    "EditOperationResult",
    "EditPreview",
    "EditTransaction",
    "EditTransactionApplyError",
    "EditTransactionEngine",
    "EditTransactionError",
    "EditTransactionPreconditionError",
    "EditTransactionRecoveryError",
    "EditTransactionResult",
    "EditTransactionService",
    "EditTransactionStaleError",
    "EditTransactionStatus",
    "TextEdit",
]
