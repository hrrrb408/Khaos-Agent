"""Typed, bounded contracts for the M8.4 context engine.

The context engine is a prompt assembly boundary.  It is deliberately not an
authority boundary: items may describe repository observations, tool output,
or memory, but none of those values can grant permission, approval, workspace
access, verification, or completion authority.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import asdict, dataclass, field
from enum import Enum
from types import MappingProxyType

from khaos.security.protocol_boundary import canonical_digest, canonical_json_bytes

CONTEXT_SCHEMA_VERSION = 1
MAX_CONTEXT_ITEM_BYTES = 256 * 1024
MAX_CONTEXT_METADATA_BYTES = 16 * 1024
MAX_CONTEXT_ITEMS = 1024
_HEX_DIGEST = re.compile(r"^[0-9a-f]{64}$")


class ContextContractError(ValueError):
    """Raised when a context contract is malformed or exceeds its bound."""


class ContextLayer(str, Enum):
    """The four bounded context layers.

    Aliases keep the terminology readable at call sites while the wire value
    remains the stable ``L0``-``L3`` vocabulary from the M8.4 contract.
    """

    L0 = "L0"
    PERSISTENT = "L0"  # noqa: PIE796 - readable alias for the wire layer
    L1 = "L1"
    TASK = "L1"  # noqa: PIE796 - readable alias for the wire layer
    L2 = "L2"
    STEP = "L2"  # noqa: PIE796 - readable alias for the wire layer
    L3 = "L3"
    EPHEMERAL = "L3"  # noqa: PIE796 - readable alias for the wire layer

    @property
    def rank(self) -> int:
        return int(self.value[1])


class ContextItemKind(str, Enum):
    """Stable item kinds accepted by the selector and serializer."""

    GOAL = "goal"
    PROJECT_INSTRUCTION = "project_instruction"
    PLAN = "plan"
    PLAN_STEP = "plan_step"
    FILE_REGION = "file_region"
    SYMBOL = "symbol"
    RELATION = "relation"
    DIAGNOSTIC = "diagnostic"
    EDIT_SUMMARY = "edit_summary"
    VERIFICATION_SUMMARY = "verification_summary"
    TOOL_RESULT = "tool_result"
    MEMORY = "memory"
    DECISION = "decision"
    HYPOTHESIS = "hypothesis"
    BLOCKER = "blocker"
    CONVERSATION = "conversation"
    TASK_STATE = "task_state"


class ContextSource(str, Enum):
    """Provenance of an item, independent from its trust tier."""

    SYSTEM = "system"
    PROJECT = "project"
    RUNTIME = "runtime"
    CONVERSATION = "conversation"
    REPO_INTELLIGENCE = "repo_intelligence"
    EDIT_TRANSACTION = "edit_transaction"
    VERIFICATION = "verification"
    TOOL = "tool"
    MEMORY = "memory"
    MODEL = "model"


# These sources describe code-state observations.  A workspace identifier
# without its corresponding generation is not enough to prove that such an
# observation is current after an edit or workspace refresh.
GENERATION_BOUND_SOURCES = frozenset(
    {
        ContextSource.REPO_INTELLIGENCE,
        ContextSource.EDIT_TRANSACTION,
        ContextSource.VERIFICATION,
    }
)


class ContextTrust(str, Enum):
    """Prompt provenance.  Compression and selection never elevate this."""

    TRUSTED_SYSTEM = "trusted_system"
    TRUSTED_PROJECT = "trusted_project"
    TRUSTED_RUNTIME = "trusted_runtime"
    TRUSTED_RUNTIME_STATE = "trusted_runtime"  # noqa: PIE796 - contract alias
    UNTRUSTED_REPO = "untrusted_repo"
    UNTRUSTED_REPOSITORY = "untrusted_repo"  # noqa: PIE796 - contract alias
    UNTRUSTED_TOOL = "untrusted_tool"
    UNTRUSTED_TOOL_OUTPUT = "untrusted_tool"  # noqa: PIE796 - contract alias
    UNTRUSTED_MEMORY = "untrusted_memory"
    UNTRUSTED_MODEL = "untrusted_model"
    UNTRUSTED_MODEL_SUMMARY = "untrusted_model"  # noqa: PIE796 - contract alias
    UNKNOWN = "unknown"


class ContextOperation(str, Enum):
    """Operation-aware context requirements."""

    GENERAL = "general"
    PLANNING = "planning"
    EDITING = "editing"
    VERIFICATION_REPAIR = "verification_repair"
    COMPLETION = "completion"


def _validate_text(value: object, *, label: str, max_length: int = 4096) -> str:
    if type(value) is not str or not value:
        raise ContextContractError(f"{label} must be a non-empty string")
    if len(value) > max_length or "\x00" in value:
        raise ContextContractError(f"{label} exceeds its bound or contains NUL")
    return value


def _validate_optional_text(
    value: object,
    *,
    label: str,
    max_length: int = 4096,
) -> str | None:
    if value is None:
        return None
    if type(value) is not str or len(value) > max_length or "\x00" in value:
        raise ContextContractError(f"{label} is malformed or exceeds its bound")
    return value


def _normalize_generation(value: object, *, label: str) -> str | None:
    """Normalize the runtime's integer-or-digest generation vocabulary."""

    if value is None:
        return None
    if type(value) is int:
        value = str(value)
    return _validate_optional_text(value, label=label, max_length=512)


def approximate_token_count(text: str) -> int:
    """Return a conservative, deterministic token estimate.

    The Rust tokenizer remains the authority for billing.  Context selection
    only needs a cheap upper-bound-ish estimate and records it as approximate.
    Taking the larger of word and UTF-8 byte estimates avoids treating
    minified JSON/code with no whitespace as one token.
    """

    if not text.strip():
        return 0
    byte_estimate = (len(text.encode("utf-8")) + 3) // 4
    return max(1, len(text.split()), byte_estimate)


def _approx_tokens(text: str) -> int:
    """Backward-compatible private spelling used by the item contract."""

    return approximate_token_count(text)


def _safe_text_prefix(text: str, max_bytes: int) -> str:
    if max_bytes <= 0:
        return ""
    raw = text.encode("utf-8")
    if len(raw) <= max_bytes:
        return text
    return raw[:max_bytes].decode("utf-8", errors="ignore")


@dataclass(frozen=True, slots=True)
class ContextItem:
    """One bounded, provenance-labelled context item."""

    kind: ContextItemKind
    payload: str
    layer: ContextLayer = ContextLayer.L1
    source: ContextSource = ContextSource.RUNTIME
    trust: ContextTrust = ContextTrust.TRUSTED_RUNTIME
    workspace_id: str = ""
    generation: str | None = None
    repository_generation: str | None = None
    priority: int = 0
    item_id: str = ""
    digest: str = ""
    token_count: int | None = None
    byte_count: int | None = None
    token_cost: int | None = None
    byte_size: int | None = None
    approximate: bool = True
    required: bool = False
    pinned: bool = False
    truncated: bool = False
    compressed: bool = False
    path: str | None = None
    symbol: str | None = None
    region_start: int | None = None
    region_end: int | None = None
    sequence: int = 0
    created_at: int = 0
    last_relevant_at: int = 0
    metadata: Mapping[str, object] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if type(self.kind) is not ContextItemKind:
            raise ContextContractError("context item kind is invalid")
        if type(self.layer) is not ContextLayer:
            raise ContextContractError("context item layer is invalid")
        if type(self.source) is not ContextSource:
            raise ContextContractError("context item source is invalid")
        if type(self.trust) is not ContextTrust:
            raise ContextContractError("context item trust is invalid")
        if type(self.payload) is not str or "\x00" in self.payload:
            raise ContextContractError("context item payload is invalid")
        byte_count = len(self.payload.encode("utf-8"))
        if byte_count > MAX_CONTEXT_ITEM_BYTES:
            raise ContextContractError("context item exceeds its byte bound")
        workspace_id = _validate_optional_text(
            self.workspace_id, label="workspace_id", max_length=512
        )
        if workspace_id is None:
            object.__setattr__(self, "workspace_id", "")
        generation = _normalize_generation(self.generation, label="generation")
        repository_generation = _normalize_generation(
            self.repository_generation,
            label="repository_generation",
        )
        # ``generation`` is the canonical field.  Prefer it when both names
        # are present so ``dataclasses.replace(item, generation=...)`` cannot
        # accidentally retain a stale alias value.
        generation = generation or repository_generation
        object.__setattr__(self, "generation", generation)
        object.__setattr__(self, "repository_generation", generation)
        if self.workspace_id and self.source in GENERATION_BOUND_SOURCES and generation is None:
            raise ContextContractError(
                "workspace-bound code-state context requires a generation"
            )
        path = _validate_optional_text(self.path, label="path", max_length=2048)
        symbol = _validate_optional_text(self.symbol, label="symbol", max_length=1024)
        object.__setattr__(self, "path", path)
        object.__setattr__(self, "symbol", symbol)
        if type(self.priority) is not int or self.priority < 0:
            raise ContextContractError("context item priority is invalid")
        if type(self.sequence) is not int or self.sequence < 0:
            raise ContextContractError("context item sequence is invalid")
        for name in ("created_at", "last_relevant_at"):
            value = getattr(self, name)
            if type(value) is not int or value < 0:
                raise ContextContractError(f"context item {name} is invalid")
        for name in ("required", "pinned", "truncated", "compressed", "approximate"):
            if type(getattr(self, name)) is not bool:
                raise ContextContractError(f"context item {name} is invalid")
        for name in ("region_start", "region_end"):
            value = getattr(self, name)
            if value is not None and (type(value) is not int or value < 0):
                raise ContextContractError(f"context item {name} is invalid")
        if (
            self.region_start is not None
            and self.region_end is not None
            and self.region_end < self.region_start
        ):
            raise ContextContractError("context item region is inverted")
        metadata = dict(self.metadata)
        try:
            encoded_metadata = canonical_json_bytes(metadata)
        except Exception as exc:
            raise ContextContractError("context item metadata is not JSON-safe") from exc
        if len(encoded_metadata) > MAX_CONTEXT_METADATA_BYTES:
            raise ContextContractError("context item metadata exceeds its bound")
        object.__setattr__(self, "metadata", MappingProxyType(metadata))
        if self.token_count is not None and (
            type(self.token_count) is not int or self.token_count < 0
        ):
            raise ContextContractError("context item token_count is invalid")
        if self.token_cost is not None and (
            type(self.token_cost) is not int or self.token_cost < 0
        ):
            raise ContextContractError("context item token_cost is invalid")
        if self.token_count is None:
            object.__setattr__(
                self,
                "token_count",
                self.token_cost if self.token_cost is not None else _approx_tokens(self.payload),
            )
        elif self.token_cost is not None and self.token_count != self.token_cost:
            raise ContextContractError("context item token aliases disagree")
        object.__setattr__(self, "token_cost", self.token_count)
        if self.byte_count is not None and (
            type(self.byte_count) is not int or self.byte_count < 0
        ):
            raise ContextContractError("context item byte_count is invalid")
        if self.byte_size is not None and (
            type(self.byte_size) is not int or self.byte_size < 0
        ):
            raise ContextContractError("context item byte_size is invalid")
        if self.byte_count is None:
            object.__setattr__(
                self,
                "byte_count",
                self.byte_size if self.byte_size is not None else byte_count,
            )
        elif self.byte_size is not None and self.byte_count != self.byte_size:
            raise ContextContractError("context item byte aliases disagree")
        object.__setattr__(self, "byte_size", self.byte_count)
        if self.digest:
            if type(self.digest) is not str or not _HEX_DIGEST.fullmatch(self.digest):
                raise ContextContractError("context item digest is invalid")
        else:
            object.__setattr__(
                self,
                "digest",
                hashlib.sha256(self.payload.encode("utf-8")).hexdigest(),
            )
        if self.item_id:
            if type(self.item_id) is not str or len(self.item_id) > 256:
                raise ContextContractError("context item id is invalid")
        else:
            identity = {
                "kind": self.kind.value,
                "layer": self.layer.value,
                "source": self.source.value,
                "workspace_id": self.workspace_id,
                "generation": self.generation,
                "path": self.path,
                "symbol": self.symbol,
                "region_start": self.region_start,
                "region_end": self.region_end,
                "sequence": self.sequence,
            }
            object.__setattr__(self, "item_id", canonical_digest(identity)[:32])

    @property
    def estimated_tokens(self) -> int:
        return int(self.token_count or 0)

    @property
    def estimated_bytes(self) -> int:
        return int(self.byte_count or 0)

    @property
    def identity_key(self) -> tuple[object, ...]:
        """Return the stable key used for de-duplication and overlap merging."""

        return (
            self.kind.value,
            self.source.value,
            self.workspace_id,
            self.generation or "",
            self.path or "",
            self.symbol or "",
            self.region_start,
            self.region_end,
            self.digest,
        )

    def reference(self) -> ContextItem:
        """Return a persistence-safe reference with content omitted."""

        return ContextItem(
            kind=self.kind,
            payload="",
            layer=self.layer,
            source=self.source,
            trust=self.trust,
            workspace_id=self.workspace_id,
            generation=self.generation,
            repository_generation=self.generation,
            priority=self.priority,
            item_id=self.item_id,
            digest=self.digest,
            token_count=0,
            byte_count=0,
            token_cost=0,
            byte_size=0,
            approximate=self.approximate,
            required=self.required,
            pinned=self.pinned,
            truncated=self.truncated,
            compressed=self.compressed,
            path=self.path,
            symbol=self.symbol,
            region_start=self.region_start,
            region_end=self.region_end,
            sequence=self.sequence,
            created_at=self.created_at,
            last_relevant_at=self.last_relevant_at,
            metadata={**dict(self.metadata), "content_omitted": True},
        )

    def truncated_to(self, *, max_bytes: int, max_tokens: int | None = None) -> ContextItem:
        """Bound content while retaining all provenance and authority labels."""

        text = _safe_text_prefix(self.payload, max(0, max_bytes))
        if max_tokens is not None and _approx_tokens(text) > max_tokens:
            words = text.split()
            text = " ".join(words[: max(0, max_tokens)])
        if text == self.payload:
            return self
        return ContextItem(
            kind=self.kind,
            payload=text,
            layer=self.layer,
            source=self.source,
            trust=self.trust,
            workspace_id=self.workspace_id,
            generation=self.generation,
            repository_generation=self.generation,
            priority=self.priority,
            item_id=self.item_id,
            approximate=True,
            required=self.required,
            pinned=self.pinned,
            truncated=True,
            compressed=self.compressed,
            path=self.path,
            symbol=self.symbol,
            region_start=self.region_start,
            region_end=self.region_end,
            sequence=self.sequence,
            created_at=self.created_at,
            last_relevant_at=self.last_relevant_at,
            metadata={**dict(self.metadata), "original_digest": self.digest},
        )

    def to_payload(self, *, include_content: bool = True) -> dict[str, object]:
        data: dict[str, object] = {
            "schema_version": CONTEXT_SCHEMA_VERSION,
            "item_id": self.item_id,
            "kind": self.kind.value,
            "layer": self.layer.value,
            "source": self.source.value,
            "trust": self.trust.value,
            "workspace_id": self.workspace_id,
            "generation": self.generation,
            "repository_generation": self.generation,
            "priority": self.priority,
            "digest": self.digest,
            "token_count": self.token_count,
            "byte_count": self.byte_count,
            "approximate": self.approximate,
            "required": self.required,
            "pinned": self.pinned,
            "truncated": self.truncated,
            "compressed": self.compressed,
            "path": self.path,
            "symbol": self.symbol,
            "region_start": self.region_start,
            "region_end": self.region_end,
            "sequence": self.sequence,
            "metadata": dict(self.metadata),
        }
        if include_content:
            data["payload"] = self.payload
        return data


@dataclass(frozen=True, slots=True)
class ContextBudget:
    """Hard context budgets, with an explicit output reserve."""

    total_tokens: int = 12_000
    total_bytes: int = 256 * 1024
    output_reserve_tokens: int | None = None
    output_reserve_bytes: int | None = None
    layer_token_budgets: tuple[int, int, int, int] = (2_048, 3_072, 5_120, 1_760)
    layer_byte_budgets: tuple[int, int, int, int] = (
        48 * 1024,
        64 * 1024,
        112 * 1024,
        32 * 1024,
    )
    # Named aliases mirror the design vocabulary while the tuple fields keep
    # the selector implementation compact.  When supplied, aliases normalize
    # into the tuple before validation.
    persistent_tokens: int | None = None
    task_tokens: int | None = None
    step_tokens: int | None = None
    ephemeral_tokens: int | None = None
    reserve_output_tokens: int | None = None

    def __post_init__(self) -> None:
        if self.reserve_output_tokens is not None and self.output_reserve_tokens is None:
            object.__setattr__(self, "output_reserve_tokens", self.reserve_output_tokens)
        if self.output_reserve_tokens is None:
            object.__setattr__(self, "output_reserve_tokens", max(1, min(2_048, self.total_tokens // 4)))
        if self.output_reserve_bytes is None:
            object.__setattr__(self, "output_reserve_bytes", max(1, min(32 * 1024, self.total_bytes // 4)))
        output_reserve_tokens = self.output_reserve_tokens
        output_reserve_bytes = self.output_reserve_bytes
        if output_reserve_tokens is None or output_reserve_bytes is None:
            raise ContextContractError("context output reserve is invalid")
        scalar_values = (
            self.total_tokens,
            self.total_bytes,
            output_reserve_tokens,
            output_reserve_bytes,
        )
        if any(type(value) is not int or value <= 0 for value in scalar_values):
            raise ContextContractError("context budget scalars must be positive")
        if type(self.layer_token_budgets) is not tuple or len(self.layer_token_budgets) != 4:
            raise ContextContractError("context token layer budget is invalid")
        if type(self.layer_byte_budgets) is not tuple or len(self.layer_byte_budgets) != 4:
            raise ContextContractError("context byte layer budget is invalid")
        if any(type(value) is not int or value < 0 for value in self.layer_token_budgets):
            raise ContextContractError("context token layer budget is invalid")
        if any(type(value) is not int or value < 0 for value in self.layer_byte_budgets):
            raise ContextContractError("context byte layer budget is invalid")
        aliases = (
            self.persistent_tokens,
            self.task_tokens,
            self.step_tokens,
            self.ephemeral_tokens,
        )
        if any(value is not None and (type(value) is not int or value < 0) for value in aliases):
            raise ContextContractError("named context token budget is invalid")
        if any(value is not None for value in aliases):
            normalized = list(self.layer_token_budgets)
            for index, value in enumerate(aliases):
                if value is not None:
                    normalized[index] = value
            object.__setattr__(self, "layer_token_budgets", tuple(normalized))
        object.__setattr__(self, "persistent_tokens", self.layer_token_budgets[0])
        object.__setattr__(self, "task_tokens", self.layer_token_budgets[1])
        object.__setattr__(self, "step_tokens", self.layer_token_budgets[2])
        object.__setattr__(self, "ephemeral_tokens", self.layer_token_budgets[3])
        object.__setattr__(self, "reserve_output_tokens", self.output_reserve_tokens)
        if output_reserve_tokens >= self.total_tokens:
            raise ContextContractError("output reserve consumes the whole token budget")
        if output_reserve_bytes >= self.total_bytes:
            raise ContextContractError("output reserve consumes the whole byte budget")

    @property
    def available_tokens(self) -> int:
        return self.total_tokens - int(self.output_reserve_tokens or 0)

    @property
    def available_bytes(self) -> int:
        return self.total_bytes - int(self.output_reserve_bytes or 0)

    def layer_tokens(self, layer: ContextLayer) -> int:
        return self.layer_token_budgets[layer.rank]

    def layer_bytes(self, layer: ContextLayer) -> int:
        return self.layer_byte_budgets[layer.rank]

    def digest(self) -> str:
        return canonical_digest(
            {
                "total_tokens": self.total_tokens,
                "total_bytes": self.total_bytes,
                "output_reserve_tokens": self.output_reserve_tokens,
                "output_reserve_bytes": self.output_reserve_bytes,
                "layer_token_budgets": self.layer_token_budgets,
                "layer_byte_budgets": self.layer_byte_budgets,
            }
        )


@dataclass(frozen=True, slots=True)
class ContextRequirements:
    """Operation-aware requirements used to construct one context snapshot."""

    operation: ContextOperation = ContextOperation.GENERAL
    task_id: str = ""
    step_id: str = ""
    workspace_id: str = ""
    generation: str | None = None
    plan_revision: str | None = None
    verification_state: str | None = None
    query: str = ""
    target_files: tuple[str, ...] = ()
    target_symbols: tuple[str, ...] = ()
    changed_files: tuple[str, ...] = ()
    current_step: str | None = None
    required_files: tuple[str, ...] = ()
    required_diagnostics: tuple[str, ...] = ()
    required_plan_state: bool = False
    required_verification_state: bool = False
    required_kinds: tuple[ContextItemKind, ...] = ()
    preferred_kinds: tuple[ContextItemKind, ...] = ()
    recent_message_count: int = 12
    max_items: int = MAX_CONTEXT_ITEMS
    include_memory: bool = True
    include_repo: bool = True
    include_diagnostics: bool = True
    budget: ContextBudget = field(default_factory=ContextBudget)

    def __post_init__(self) -> None:
        if type(self.operation) is not ContextOperation:
            raise ContextContractError("context operation is invalid")
        for name in ("task_id", "step_id", "workspace_id", "query"):
            value = getattr(self, name)
            if type(value) is not str or len(value) > 16 * 1024 or "\x00" in value:
                raise ContextContractError(f"context requirement {name} is invalid")
        object.__setattr__(
            self,
            "generation",
            _normalize_generation(self.generation, label="generation"),
        )
        for name in ("plan_revision", "verification_state"):
            _validate_optional_text(getattr(self, name), label=name, max_length=1024)
        _validate_optional_text(self.current_step, label="current_step", max_length=2048)
        if self.current_step is not None and not self.step_id:
            object.__setattr__(self, "step_id", self.current_step)
        for name in ("target_files", "target_symbols", "changed_files"):
            values = getattr(self, name)
            if type(values) is not tuple or len(values) > 256:
                raise ContextContractError(f"context requirement {name} is invalid")
            if any(type(value) is not str or not value or len(value) > 2048 for value in values):
                raise ContextContractError(f"context requirement {name} is invalid")
        for name in ("required_files", "required_diagnostics"):
            values = getattr(self, name)
            if type(values) is not tuple or len(values) > 256:
                raise ContextContractError(f"context requirement {name} is invalid")
            if any(type(value) is not str or not value or len(value) > 4096 for value in values):
                raise ContextContractError(f"context requirement {name} is invalid")
        if self.required_files:
            combined_files = tuple(sorted(set(self.target_files).union(self.required_files)))
            if len(combined_files) > 256:
                raise ContextContractError("context target_files exceed their bound")
            object.__setattr__(self, "target_files", combined_files)
        for name in ("required_plan_state", "required_verification_state"):
            if type(getattr(self, name)) is not bool:
                raise ContextContractError(f"context requirement {name} is invalid")
        for name in ("required_kinds", "preferred_kinds"):
            values = getattr(self, name)
            if type(values) is not tuple or any(type(value) is not ContextItemKind for value in values):
                raise ContextContractError(f"context requirement {name} is invalid")
        for name in ("recent_message_count", "max_items"):
            value = getattr(self, name)
            if type(value) is not int or value < 0:
                raise ContextContractError(f"context requirement {name} is invalid")
        if self.max_items > MAX_CONTEXT_ITEMS:
            raise ContextContractError("context requirement max_items exceeds its bound")
        for name in ("include_memory", "include_repo", "include_diagnostics"):
            if type(getattr(self, name)) is not bool:
                raise ContextContractError(f"context requirement {name} is invalid")
        if type(self.budget) is not ContextBudget:
            raise ContextContractError("context requirement budget is invalid")
        if not self.required_kinds:
            defaults = {
                ContextOperation.PLANNING: (ContextItemKind.GOAL, ContextItemKind.PLAN),
                ContextOperation.EDITING: (ContextItemKind.FILE_REGION, ContextItemKind.SYMBOL),
                ContextOperation.VERIFICATION_REPAIR: (
                    ContextItemKind.DIAGNOSTIC,
                    ContextItemKind.VERIFICATION_SUMMARY,
                ),
                ContextOperation.COMPLETION: (
                    ContextItemKind.PLAN,
                    ContextItemKind.VERIFICATION_SUMMARY,
                    ContextItemKind.BLOCKER,
                ),
            }
            if self.operation in defaults:
                object.__setattr__(self, "required_kinds", defaults[self.operation])
        if not self.preferred_kinds:
            preferred = {
                ContextOperation.PLANNING: (ContextItemKind.SYMBOL, ContextItemKind.RELATION),
                ContextOperation.EDITING: (ContextItemKind.RELATION, ContextItemKind.DIAGNOSTIC),
                ContextOperation.VERIFICATION_REPAIR: (
                    ContextItemKind.FILE_REGION,
                    ContextItemKind.SYMBOL,
                ),
                ContextOperation.COMPLETION: (
                    ContextItemKind.EDIT_SUMMARY,
                    ContextItemKind.BLOCKER,
                ),
            }
            if self.operation in preferred:
                object.__setattr__(self, "preferred_kinds", preferred[self.operation])

    def digest(self) -> str:
        return canonical_digest(
            {
                "schema_version": CONTEXT_SCHEMA_VERSION,
                "operation": self.operation.value,
                "task_id": self.task_id,
                "step_id": self.step_id,
                "workspace_id": self.workspace_id,
                "generation": self.generation,
                "plan_revision": self.plan_revision,
                "verification_state": self.verification_state,
                "query": self.query,
                "target_files": tuple(sorted(self.target_files)),
                "target_symbols": tuple(sorted(self.target_symbols)),
                "changed_files": tuple(sorted(self.changed_files)),
                "current_step": self.current_step,
                "required_files": tuple(sorted(self.required_files)),
                "required_diagnostics": tuple(sorted(self.required_diagnostics)),
                "required_plan_state": self.required_plan_state,
                "required_verification_state": self.required_verification_state,
                "required_kinds": tuple(item.value for item in self.required_kinds),
                "preferred_kinds": tuple(item.value for item in self.preferred_kinds),
                "recent_message_count": self.recent_message_count,
                "max_items": self.max_items,
                "include_memory": self.include_memory,
                "include_repo": self.include_repo,
                "include_diagnostics": self.include_diagnostics,
                "budget": self.budget.digest(),
            }
        )


@dataclass(frozen=True, slots=True)
class ContextMessage:
    """Provider-neutral message projection emitted by the engine."""

    role: str
    content: str
    tool_calls: tuple[Mapping[str, object], ...] = ()
    tool_call_id: str | None = None
    event: str | None = None
    metadata: Mapping[str, object] = field(default_factory=dict)
    item_ids: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.role not in {"system", "user", "assistant", "tool"}:
            raise ContextContractError("context message role is invalid")
        if type(self.content) is not str:
            raise ContextContractError("context message content is invalid")
        if len(self.content.encode("utf-8")) > MAX_CONTEXT_ITEM_BYTES:
            raise ContextContractError("context message exceeds its byte bound")
        if type(self.tool_calls) is not tuple:
            raise ContextContractError("context message tool_calls is invalid")
        if len(self.tool_calls) > 16:
            raise ContextContractError("context message tool_calls exceed their bound")
        try:
            encoded_metadata = canonical_json_bytes(dict(self.metadata))
        except Exception as exc:
            raise ContextContractError("context message metadata is not JSON-safe") from exc
        if len(encoded_metadata) > MAX_CONTEXT_METADATA_BYTES:
            raise ContextContractError("context message metadata exceeds its bound")
        for call in self.tool_calls:
            try:
                encoded_call = canonical_json_bytes(dict(call))
            except Exception as exc:
                raise ContextContractError("context message tool call is not JSON-safe") from exc
            if len(encoded_call) > MAX_CONTEXT_METADATA_BYTES:
                raise ContextContractError("context message tool call exceeds its bound")
        object.__setattr__(self, "metadata", MappingProxyType(dict(self.metadata)))


@dataclass(frozen=True, slots=True)
class ContextSelection:
    """Selector result and bounded accounting."""

    selected: tuple[ContextItem, ...]
    evicted: tuple[ContextItem, ...] = ()
    compressed: tuple[ContextItem, ...] = ()
    truncated_count: int = 0
    total_tokens: int = 0
    total_bytes: int = 0
    layer_tokens: Mapping[str, int] = field(default_factory=dict)
    layer_bytes: Mapping[str, int] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class TaskStateSummary:
    """Canonical compact state used after conversation compaction."""

    task_id: str = ""
    workspace_id: str = ""
    generation: str | None = None
    plan_revision: str | None = None
    active_step_id: str | None = None
    goal: str = ""
    constraints: tuple[str, ...] = ()
    changed_files: tuple[str, ...] = ()
    decisions: tuple[str, ...] = ()
    hypotheses: tuple[str, ...] = ()
    blockers: tuple[str, ...] = ()
    diagnostics: tuple[str, ...] = ()
    verification: tuple[str, ...] = ()
    event_sequence: int = 0
    schema_version: int = CONTEXT_SCHEMA_VERSION

    def __post_init__(self) -> None:
        for name in ("task_id", "workspace_id", "goal"):
            value = getattr(self, name)
            if type(value) is not str or len(value) > 16 * 1024 or "\x00" in value:
                raise ContextContractError(f"task summary {name} is invalid")
        object.__setattr__(
            self,
            "generation",
            _normalize_generation(self.generation, label="generation"),
        )
        for name in ("plan_revision", "active_step_id"):
            _validate_optional_text(getattr(self, name), label=name, max_length=2048)
        for name in (
            "constraints",
            "changed_files",
            "decisions",
            "hypotheses",
            "blockers",
            "diagnostics",
            "verification",
        ):
            values = getattr(self, name)
            if type(values) is not tuple or len(values) > 64:
                raise ContextContractError(f"task summary {name} is invalid")
            if any(
                type(value) is not str
                or not value
                or len(value.encode("utf-8")) > 8 * 1024
                or "\x00" in value
                for value in values
            ):
                raise ContextContractError(f"task summary {name} is invalid")
        if type(self.event_sequence) is not int or self.event_sequence < 0:
            raise ContextContractError("task summary event_sequence is invalid")
        if self.schema_version != CONTEXT_SCHEMA_VERSION:
            raise ContextContractError("task summary schema is unsupported")

    def digest(self) -> str:
        return canonical_digest(asdict(self))

    def to_text(self) -> str:
        data = {
            "task_id": self.task_id,
            "workspace_id": self.workspace_id,
            "generation": self.generation,
            "plan_revision": self.plan_revision,
            "active_step_id": self.active_step_id,
            "goal": self.goal,
            "constraints": self.constraints,
            "changed_files": self.changed_files,
            "decisions": self.decisions,
            "hypotheses": self.hypotheses,
            "blockers": self.blockers,
            "diagnostics": self.diagnostics,
            "verification": self.verification,
            "event_sequence": self.event_sequence,
            "summary_digest": self.digest(),
        }
        return json.dumps(data, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


@dataclass(frozen=True, slots=True)
class ModelContext:
    """Final bounded provider input and selection evidence."""

    messages: tuple[ContextMessage, ...]
    selection: ContextSelection
    requirements_digest: str
    context_digest: str
    cache_hit: bool = False
    partial: bool = False


@dataclass(frozen=True, slots=True)
class ContextMetricsSnapshot:
    """Stable M8.4 metrics vocabulary; unavailable values remain ``None``."""

    context_builds: int = 0
    context_input_tokens: int | None = None
    context_input_bytes: int | None = None
    context_l0_tokens: int | None = None
    context_l1_tokens: int | None = None
    context_l2_tokens: int | None = None
    context_l3_tokens: int | None = None
    context_items_selected: int = 0
    context_items_evicted: int = 0
    context_items_compressed: int = 0
    context_truncated_count: int = 0
    context_stale_retries: int = 0
    context_partial_builds: int = 0
    context_compactions: int = 0
    context_cache_hits: int = 0
    context_cache_misses: int = 0
    context_stable_prefix_tokens: int | None = None
    context_stable_prefix_bytes: int | None = None
    context_selected_file_count: int | None = None
    context_selected_symbol_count: int | None = None
    context_memory_items_selected: int | None = None
    context_repo_items_selected: int | None = None
    context_diagnostics_selected: int | None = None
    tool_schema_tokens: int | None = None
    tool_schema_bytes: int | None = None
    deferred_tool_discoveries: int = 0
    deferred_skill_discoveries: int = 0
    deferred_skill_loads: int = 0
    skill_tokens: int | None = None
    tool_output_tokens: int = 0
    tool_output_bytes: int = 0
    tool_output_truncated_count: int = 0

    @property
    def memory_items_selected(self) -> int | None:
        """M8.0 aggregate spelling for the context-prefixed counter."""

        return self.context_memory_items_selected

    @property
    def repo_items_selected(self) -> int | None:
        """M8.0 aggregate spelling for the context-prefixed counter."""

        return self.context_repo_items_selected

    @property
    def diagnostics_selected(self) -> int | None:
        """M8.0 aggregate spelling for the context-prefixed counter."""

        return self.context_diagnostics_selected

    @property
    def compaction_count(self) -> int | None:
        """M8.0 aggregate spelling for the context-prefixed counter."""

        return self.context_compactions

    def to_payload(self) -> dict[str, object]:
        payload = asdict(self)
        payload.update(
            {
                "memory_items_selected": self.memory_items_selected,
                "repo_items_selected": self.repo_items_selected,
                "diagnostics_selected": self.diagnostics_selected,
                "compaction_count": self.compaction_count,
            }
        )
        return payload
