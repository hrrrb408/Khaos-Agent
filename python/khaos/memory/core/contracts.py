"""Stable contracts for the Khaos Memory V2 boundary.

The contracts in this module are deliberately independent from SQLite and
from any particular provider.  A provider can implement storage and
retrieval, but it cannot replace these value objects or manufacture the
runtime scope that is passed to it by :class:`MemoryBroker`.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from typing import Any, Protocol


class MemoryEventType(str, Enum):
    """Canonical event kinds retained by the event ledger."""

    USER_MESSAGE = "USER_MESSAGE"
    ASSISTANT_MESSAGE = "ASSISTANT_MESSAGE"
    TOOL_CALL = "TOOL_CALL"
    TOOL_RESULT = "TOOL_RESULT"
    TASK_CREATED = "TASK_CREATED"
    TASK_TRANSITION = "TASK_TRANSITION"
    PLAN_CREATED = "PLAN_CREATED"
    APPROVAL_REQUESTED = "APPROVAL_REQUESTED"
    APPROVAL_DECIDED = "APPROVAL_DECIDED"
    WORKSPACE_CREATED = "WORKSPACE_CREATED"
    FILE_OBSERVED = "FILE_OBSERVED"
    PATCH_APPLIED = "PATCH_APPLIED"
    VERIFICATION_STARTED = "VERIFICATION_STARTED"
    VERIFICATION_RESULT = "VERIFICATION_RESULT"
    COMMIT_OBSERVED = "COMMIT_OBSERVED"
    MODE_CHANGED = "MODE_CHANGED"
    MEMORY_CANDIDATE_CREATED = "MEMORY_CANDIDATE_CREATED"
    MEMORY_PROMOTED = "MEMORY_PROMOTED"
    MEMORY_SUPERSEDED = "MEMORY_SUPERSEDED"
    MEMORY_REVOKED = "MEMORY_REVOKED"
    SKILL_CANDIDATE_CREATED = "SKILL_CANDIDATE_CREATED"
    SKILL_PROMOTED = "SKILL_PROMOTED"
    MEMORY_CONFLICT_DETECTED = "MEMORY_CONFLICT_DETECTED"
    MEMORY_REBUILD_STARTED = "MEMORY_REBUILD_STARTED"
    MEMORY_REBUILD_FINISHED = "MEMORY_REBUILD_FINISHED"
    MEMORY_REBUILD_FAILED = "MEMORY_REBUILD_FAILED"
    PROVIDER_CHANGED = "PROVIDER_CHANGED"
    PROVIDER_SWITCH_REQUESTED = "PROVIDER_SWITCH_REQUESTED"
    PROVIDER_SWITCH_COMMITTED = "PROVIDER_SWITCH_COMMITTED"
    PROVIDER_SWITCH_FAILED = "PROVIDER_SWITCH_FAILED"


class SourceType(str, Enum):
    """Origin class used for provenance and trust reclassification."""

    USER = "USER"
    TOOL = "TOOL"
    TASK = "TASK"
    VERIFICATION = "VERIFICATION"
    REPOSITORY = "REPOSITORY"
    EXTERNAL = "EXTERNAL"
    SYSTEM = "SYSTEM"
    PROVIDER = "PROVIDER"


class TrustHint(str, Enum):
    """Non-authoritative source hint attached to an event."""

    USER_STATED = "USER_STATED"
    TOOL_OBSERVED = "TOOL_OBSERVED"
    VERIFICATION_CONFIRMED = "VERIFICATION_CONFIRMED"
    REPOSITORY_OBSERVED = "REPOSITORY_OBSERVED"
    EXTERNAL_UNTRUSTED = "EXTERNAL_UNTRUSTED"
    AGENT_INFERRED = "AGENT_INFERRED"


class MemoryType(str, Enum):
    """Supported derived-memory classifications."""

    USER_MEMORY = "USER_MEMORY"
    PROJECT_FACT = "PROJECT_FACT"
    DECISION_MEMORY = "DECISION_MEMORY"
    FAILURE_MEMORY = "FAILURE_MEMORY"
    CODE_MEMORY = "CODE_MEMORY"
    EPISODIC_MEMORY = "EPISODIC_MEMORY"
    SKILL_MEMORY = "SKILL_MEMORY"
    CONSTRAINT_MEMORY = "CONSTRAINT_MEMORY"
    PROFILE_MEMORY = "PROFILE_MEMORY"
    NEGATIVE_MEMORY = "NEGATIVE_MEMORY"


class MemoryStatus(str, Enum):
    """Lifecycle state for a derived memory node."""

    OBSERVED = "OBSERVED"
    CANDIDATE = "CANDIDATE"
    QUARANTINED = "QUARANTINED"
    ACTIVE = "ACTIVE"
    VERIFIED = "VERIFIED"
    SUPERSEDED = "SUPERSEDED"
    REVOKED = "REVOKED"
    REJECTED = "REJECTED"


class MemoryAuthority(str, Enum):
    """Khaos authority level; provider hints never become authority alone."""

    SYSTEM_POLICY = "SYSTEM_POLICY"
    USER_STATED = "USER_STATED"
    VERIFICATION_CONFIRMED = "VERIFICATION_CONFIRMED"
    TOOL_OBSERVED = "TOOL_OBSERVED"
    REPOSITORY_OBSERVED = "REPOSITORY_OBSERVED"
    AGENT_INFERRED = "AGENT_INFERRED"
    EXTERNAL_UNTRUSTED = "EXTERNAL_UNTRUSTED"


class Sensitivity(str, Enum):
    """Sensitivity classification for storage and prompt admission."""

    PUBLIC = "PUBLIC"
    INTERNAL = "INTERNAL"
    PERSONAL = "PERSONAL"
    SENSITIVE = "SENSITIVE"
    SECRET_REFERENCE = "SECRET_REFERENCE"


class UsagePolicy(str, Enum):
    """Where a memory may be used after retrieval."""

    ALWAYS = "ALWAYS"
    PROJECT_ONLY = "PROJECT_ONLY"
    SESSION_ONLY = "SESSION_ONLY"
    EXPLICIT_QUERY_ONLY = "EXPLICIT_QUERY_ONLY"
    NEVER_PERSONALIZE = "NEVER_PERSONALIZE"
    HUMAN_APPROVAL_REQUIRED = "HUMAN_APPROVAL_REQUIRED"
    NO_MODEL_INJECTION = "NO_MODEL_INJECTION"


@dataclass(frozen=True, slots=True)
class MemoryObjectIdentity:
    """The complete identity of one memory object.

    A provider id or a database-local ``memory_id`` is never sufficient for
    an authority decision.  Every destructive, export, and provenance
    operation carries this tuple so a colliding id from another provider,
    project, principal, namespace, or session cannot be reused.
    """

    memory_id: str
    provider_id: str
    project_id: str
    namespace: str
    principal_id: str
    session_id: str | None = None

    def __post_init__(self) -> None:
        for name in ("memory_id", "provider_id", "project_id", "namespace"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"memory identity {name} must be non-empty")
        if self.namespace not in {"private", "session", "project", "shared"}:
            raise ValueError(f"unsupported memory identity namespace: {self.namespace}")
        if self.namespace in {"private", "session"} and not self.principal_id.strip():
            raise ValueError("private/session memory identity requires principal_id")
        if self.namespace == "session" and not self.session_id:
            raise ValueError("session memory identity requires session_id")

    @classmethod
    def from_hit(cls, hit: MemoryHit) -> MemoryObjectIdentity:
        """Build an identity from a Broker-normalized hit."""

        memory_id = hit.memory_id or hit.external_id
        if not memory_id:
            raise ValueError("memory hit has no canonical id")
        return cls(
            memory_id=memory_id,
            provider_id=hit.provider_id,
            project_id=hit.project_id,
            namespace=hit.namespace,
            principal_id=hit.principal_id,
            session_id=hit.session_id,
        )

    def matches_runtime(self, runtime: RuntimeMemoryContext) -> bool:
        """Return whether this identity is owned by the runtime scope."""

        if self.project_id != runtime.project_id:
            return False
        if self.namespace in {"private", "session"} and self.principal_id != runtime.principal_id:
            return False
        return self.namespace != "session" or self.session_id == runtime.session_id


def enum_value(value: Enum | str) -> str:
    """Return a stable string for an enum or already-normalized value."""

    return value.value if isinstance(value, Enum) else str(value)


def utc_now() -> datetime:
    """Return an aware UTC timestamp for new ledger records."""

    return datetime.now(UTC)


def as_utc(value: datetime) -> datetime:
    """Normalize naive legacy timestamps to UTC without changing wall time."""

    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def canonical_json(value: Mapping[str, Any] | Sequence[Any] | Any) -> str:
    """Serialize JSON deterministically for hashes and audit records."""

    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def payload_digest(payload: Mapping[str, Any]) -> str:
    """Hash an event payload using canonical JSON."""

    return hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class MemoryEvent:
    """One append-only fact in the canonical event ledger."""

    event_id: str
    event_type: MemoryEventType | str
    principal_id: str
    project_id: str
    session_id: str | None
    task_id: str | None
    workspace_id: str | None
    repo_id: str | None
    branch: str | None
    commit_sha: str | None
    source_type: SourceType | str
    source_ref: str | None
    occurred_at: datetime
    payload: Mapping[str, Any]
    payload_hash: str = ""
    trust_hint: TrustHint | str = TrustHint.AGENT_INFERRED
    sensitivity: Sensitivity | str = Sensitivity.INTERNAL
    observed_at: datetime | None = None
    recorded_at: datetime | None = None

    def __post_init__(self) -> None:
        """Validate identity and make the payload hash tamper-evident."""

        for name in ("event_id", "principal_id", "project_id"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"{name} must be a non-empty string")
        if not isinstance(self.payload, Mapping):
            raise TypeError("payload must be a mapping")
        normalized_hash = payload_digest(self.payload)
        if self.payload_hash and self.payload_hash != normalized_hash:
            raise ValueError("payload_hash does not match payload")
        object.__setattr__(self, "payload_hash", normalized_hash)
        occurred = as_utc(self.occurred_at)
        object.__setattr__(self, "occurred_at", occurred)
        object.__setattr__(
            self,
            "observed_at",
            as_utc(self.observed_at or occurred),
        )
        object.__setattr__(
            self,
            "recorded_at",
            as_utc(self.recorded_at or self.observed_at or occurred),
        )

    @classmethod
    def create(
        cls,
        event_type: MemoryEventType | str,
        *,
        principal_id: str,
        project_id: str,
        payload: Mapping[str, Any],
        session_id: str | None = None,
        task_id: str | None = None,
        workspace_id: str | None = None,
        repo_id: str | None = None,
        branch: str | None = None,
        commit_sha: str | None = None,
        source_type: SourceType | str = SourceType.SYSTEM,
        source_ref: str | None = None,
        occurred_at: datetime | None = None,
        trust_hint: TrustHint | str = TrustHint.AGENT_INFERRED,
        sensitivity: Sensitivity | str = Sensitivity.INTERNAL,
    ) -> MemoryEvent:
        """Construct a new event with a UUID and consistent timestamps."""

        moment = occurred_at or utc_now()
        return cls(
            event_id=uuid.uuid4().hex,
            event_type=event_type,
            principal_id=principal_id,
            project_id=project_id,
            session_id=session_id,
            task_id=task_id,
            workspace_id=workspace_id,
            repo_id=repo_id,
            branch=branch,
            commit_sha=commit_sha,
            source_type=source_type,
            source_ref=source_ref,
            occurred_at=moment,
            payload=payload,
            trust_hint=trust_hint,
            sensitivity=sensitivity,
        )


@dataclass(frozen=True, slots=True)
class RuntimeMemoryContext:
    """Host-bound context supplied to a provider by Khaos."""

    principal_id: str
    project_id: str
    session_id: str | None
    task_id: str | None
    workspace_id: str | None
    mode: str
    available_capabilities: frozenset[str] = frozenset()
    environment_fingerprint: str = ""
    repo_id: str | None = None
    commit_sha: str | None = None
    branch: str | None = None
    environment: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Reject an unbound runtime before it reaches a provider."""

        for name in ("principal_id", "project_id", "mode"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"{name} must be a non-empty string")
        if not isinstance(self.available_capabilities, frozenset):
            object.__setattr__(
                self,
                "available_capabilities",
                frozenset(self.available_capabilities),
            )


@dataclass(frozen=True, slots=True)
class MemoryBudget:
    """Bounded retrieval/context budget shared by manager and broker."""

    total_tokens: int = 2048
    l0_max_tokens: int = 512
    l1_max_tokens: int = 1024
    l2_max_tokens: int = 512
    max_hits: int = 32
    max_graph_hops: int = 2
    max_candidate_nodes: int = 64
    max_evidence_expansions: int = 64

    def __post_init__(self) -> None:
        values = {
            "total_tokens": self.total_tokens,
            "l0_max_tokens": self.l0_max_tokens,
            "l1_max_tokens": self.l1_max_tokens,
            "l2_max_tokens": self.l2_max_tokens,
            "max_hits": self.max_hits,
            "max_graph_hops": self.max_graph_hops,
            "max_candidate_nodes": self.max_candidate_nodes,
            "max_evidence_expansions": self.max_evidence_expansions,
        }
        invalid = [name for name, value in values.items() if value < 0]
        if invalid:
            raise ValueError(f"memory budgets must be non-negative: {invalid}")


@dataclass(frozen=True, slots=True)
class EntityRef:
    """Canonical entity reference attached to a candidate."""

    entity_type: str
    canonical_name: str
    entity_id: str | None = None


@dataclass(frozen=True, slots=True)
class EvidenceRef:
    """Reference to an event, verification run, file, or other evidence."""

    source_type: SourceType | str
    source_ref: str
    event_id: str | None = None
    verification_run_id: str | None = None
    commit_sha: str | None = None


@dataclass(frozen=True, slots=True)
class RelationCandidate:
    """Provider/extractor proposal for a graph relation."""

    relation: str
    target_kind: str
    target_id: str
    confidence: float = 0.5


@dataclass(frozen=True, slots=True)
class MemoryCandidate:
    """Untrusted derived-memory proposal awaiting Broker admission."""

    memory_type: MemoryType | str
    claim: str
    authority: MemoryAuthority | str
    confidence: float
    source_event_ids: tuple[str, ...] = ()
    evidence_refs: tuple[EvidenceRef, ...] = ()
    entities: tuple[EntityRef, ...] = ()
    relations: tuple[RelationCandidate, ...] = ()
    key: str | None = None
    scope: str = "global"
    namespace: str = "private"
    session_id: str | None = None
    valid_from: datetime | None = None
    valid_to: datetime | None = None
    preconditions: Mapping[str, Any] = field(default_factory=dict)
    environment: Mapping[str, Any] = field(default_factory=dict)
    sensitivity: Sensitivity | str = Sensitivity.INTERNAL
    usage_policy: UsagePolicy | str = UsagePolicy.PROJECT_ONLY
    verification_run_id: str | None = None
    verification_result_digest: str | None = None
    verification_proof: str | None = None

    def __post_init__(self) -> None:
        """Validate bounded candidate input before policy evaluation."""

        if not self.claim or len(self.claim) > 64 * 1024:
            raise ValueError("memory candidate claim is empty or oversized")
        if not 0.0 <= float(self.confidence) <= 1.0:
            raise ValueError("memory candidate confidence must be between 0 and 1")
        if self.namespace not in {"private", "session", "project", "shared"}:
            raise ValueError(f"unsupported memory namespace: {self.namespace}")
        if self.namespace == "session" and not self.session_id:
            raise ValueError("session memory candidates require session_id")
        for name, value in (
            ("preconditions", self.preconditions),
            ("environment", self.environment),
        ):
            if not isinstance(value, Mapping):
                raise TypeError(f"memory candidate {name} must be a mapping")
            try:
                canonical_json(value)
            except (TypeError, ValueError) as exc:
                raise ValueError(f"memory candidate {name} is not JSON serializable") from exc
        if self.valid_from is not None:
            object.__setattr__(self, "valid_from", as_utc(self.valid_from))
        if self.valid_to is not None:
            object.__setattr__(self, "valid_to", as_utc(self.valid_to))
        if (
            self.valid_from is not None
            and self.valid_to is not None
            and self.valid_to < self.valid_from
        ):
            raise ValueError("memory candidate valid_to must be after valid_from")


@dataclass(frozen=True, slots=True)
class MemoryWriteRequest:
    """Admitted write request handed from Broker to a provider."""

    candidate: MemoryCandidate
    runtime: RuntimeMemoryContext
    status: MemoryStatus
    authority: MemoryAuthority
    provider_id: str
    candidate_event_id: str | None = None
    supersede_memory_ids: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class MemoryWriteResult:
    """Provider write result; the provider does not make the admission decision."""

    memory_id: str
    status: MemoryStatus
    superseded_memory_ids: tuple[str, ...] = ()
    created: bool = True
    evidence_added: int = 0


@dataclass(frozen=True, slots=True)
class MemorySearchRequest:
    """Scoped search request built by the Broker."""

    query: str
    runtime: RuntimeMemoryContext
    limit: int = 32
    include_historical: bool = False
    profile_id: str = ""
    filters: Mapping[str, Any] = field(default_factory=dict)
    source_kinds: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class MemoryForgetRequest:
    """Scoped forget request for one or more canonical memory IDs."""

    memory_ids: tuple[str, ...]
    runtime: RuntimeMemoryContext
    mode: str = "soft"
    namespace: str | None = None
    scope: str | None = None
    identities: tuple[MemoryObjectIdentity, ...] = ()

    def __post_init__(self) -> None:
        """Reject ambiguous or unbounded forget requests at the boundary."""

        if self.mode not in {"soft", "hard", "compliance"}:
            raise ValueError("forget mode must be soft, hard, or compliance")
        if len(self.memory_ids) > 100:
            raise ValueError("forget request is oversized")
        if any(not isinstance(memory_id, str) or not memory_id for memory_id in self.memory_ids):
            raise ValueError("forget memory ids must be non-empty strings")
        if self.namespace is not None and self.namespace not in {"private", "session", "project", "shared"}:
            raise ValueError("forget namespace is unsupported")
        if self.scope is not None and not self.scope.strip():
            raise ValueError("forget scope must be non-empty when provided")
        if self.identities and len(self.identities) != len(self.memory_ids):
            raise ValueError("forget identities must align with memory_ids")


@dataclass(frozen=True, slots=True)
class ProviderHealth:
    """Bounded provider health snapshot."""

    provider_id: str
    healthy: bool
    detail: str = ""
    lifecycle: str = "healthy"
    generation: int = 0
    last_error: str = ""


@dataclass(frozen=True, slots=True)
class MemoryCapabilities:
    """Declared provider capabilities; absence is handled explicitly."""

    exact_search: bool = True
    keyword_search: bool = True
    semantic_search: bool = False
    entity_linking: bool = False
    graph_traversal: bool = False
    temporal_search: bool = True
    historical_query: bool = True
    profile: bool = False
    bulk_import: bool = False
    forget: bool = True
    update: bool = False
    graph_expand: bool = False
    vector_search: bool = False
    export_data: bool = False
    import_data: bool = False
    compact: bool = False
    bulk_rebuild: bool = False
    stream_events: bool = False


@dataclass(frozen=True, slots=True)
class MemoryHit:
    """Provider result that must be normalized by the Broker."""

    provider_id: str
    external_id: str | None
    content: str
    raw_score: float | None
    source_type: SourceType | str | None
    source_ref: str | None
    provider_metadata: Mapping[str, Any]
    authority_hint: str | None = None
    confidence_hint: float | None = None
    memory_id: str | None = None
    memory_type: MemoryType | str = MemoryType.PROJECT_FACT
    status: MemoryStatus | str = MemoryStatus.ACTIVE
    principal_id: str = ""
    project_id: str = ""
    namespace: str = "private"
    scope: str = "global"
    session_id: str | None = None
    key: str | None = None
    sensitivity: Sensitivity | str = Sensitivity.INTERNAL
    usage_policy: UsagePolicy | str = UsagePolicy.PROJECT_ONLY
    valid_from: datetime | None = None
    valid_to: datetime | None = None
    applicability: Mapping[str, Any] = field(default_factory=dict)
    environment: Mapping[str, Any] = field(default_factory=dict)
    event_ids: tuple[str, ...] = ()
    evidence_refs: tuple[EvidenceRef, ...] = ()
    source_rank: int = 0
    source_kind: str = "memory"
    retrieval_features: Mapping[str, float] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class EvidenceResolution:
    """Retrieval result separating localization from evidence completion."""

    primary_hits: tuple[MemoryHit, ...]
    supporting_hits: tuple[MemoryHit, ...] = ()
    conflicts: tuple[MemoryHit, ...] = ()
    missing_requirements: tuple[str, ...] = ()
    latest_valid_fact: MemoryHit | None = None
    provider_error: str | None = None


@dataclass(frozen=True, slots=True)
class MemoryDecision:
    """Broker decision returned for a candidate."""

    accepted: bool
    status: MemoryStatus
    reason: str
    memory_id: str | None = None
    event_id: str | None = None


@dataclass(frozen=True, slots=True)
class ForgetResult:
    """Forget operation result without leaking foreign-object existence."""

    forgotten_ids: tuple[str, ...]
    mode: str


# The design document uses ``MemoryForgetResult`` in its public SPI while the
# original V2 implementation exported the shorter ``ForgetResult`` name.
# Keeping one value object with both names avoids a compatibility fork.
MemoryForgetResult = ForgetResult


class MemoryProvider(Protocol):
    """Provider SPI implemented below the Khaos Broker."""

    provider_id: str

    async def add(self, request: MemoryWriteRequest) -> MemoryWriteResult:
        """Persist an already-admitted candidate."""

        ...

    async def search(self, request: MemorySearchRequest) -> list[MemoryHit]:
        """Return scoped evidence candidates."""

        ...

    async def forget(self, request: MemoryForgetRequest) -> ForgetResult:
        """Apply the provider's forget semantics."""

        ...

    async def health(self) -> ProviderHealth:
        """Return a bounded health snapshot."""

        ...

    def capabilities(self) -> MemoryCapabilities:
        """Return capability declarations without performing I/O."""

        ...


class MemoryAuditSink(Protocol):
    """Trust-Kernel audit port used by Broker safety decisions."""

    async def log(
        self,
        action: str,
        target: str,
        result: str,
        detail: dict[str, Any] | None = None,
        session_id: str | None = None,
        *,
        task_id: str | None = None,
        source_transport: str | None = None,
    ) -> int:
        """Persist one attributed decision in the canonical audit chain."""

        ...


__all__ = [
    "EntityRef",
    "EvidenceRef",
    "EvidenceResolution",
    "ForgetResult",
    "MemoryAuditSink",
    "MemoryAuthority",
    "MemoryBudget",
    "MemoryCandidate",
    "MemoryCapabilities",
    "MemoryDecision",
    "MemoryEvent",
    "MemoryEventType",
    "MemoryForgetRequest",
    "MemoryForgetResult",
    "MemoryHit",
    "MemoryObjectIdentity",
    "MemoryProvider",
    "MemorySearchRequest",
    "MemoryStatus",
    "MemoryType",
    "MemoryWriteRequest",
    "MemoryWriteResult",
    "ProviderHealth",
    "RelationCandidate",
    "RuntimeMemoryContext",
    "Sensitivity",
    "SourceType",
    "TrustHint",
    "UsagePolicy",
    "as_utc",
    "canonical_json",
    "enum_value",
    "payload_digest",
    "utc_now",
]
