"""Security and applicability policy for Memory Broker decisions."""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import Enum
from typing import Any, ClassVar

from khaos.memory.core.contracts import (
    MemoryAuthority,
    MemoryCandidate,
    MemoryHit,
    MemoryStatus,
    MemoryType,
    RuntimeMemoryContext,
    SourceType,
    UsagePolicy,
    enum_value,
)


class ScreeningAction(str, Enum):
    """Result of deterministic prompt-injection screening."""

    ALLOW = "allow"
    QUARANTINE = "quarantine"
    REJECT = "reject"


@dataclass(frozen=True, slots=True)
class ScreeningResult:
    """Bounded screening decision and a non-sensitive reason."""

    action: ScreeningAction
    reason: str = ""


@dataclass(frozen=True, slots=True)
class SupersessionDecision:
    """Broker-owned decision for replacing a temporal version."""

    allowed: bool
    reason: str


class SupersessionPolicy:
    """Compare authority and lifecycle before any version is superseded.

    Native and remote providers receive explicit ids only after this policy
    returns ``allowed``.  A provider's same-key behaviour is therefore never
    an implicit write authority.
    """

    _RANK: ClassVar[dict[str, int]] = {
        MemoryAuthority.EXTERNAL_UNTRUSTED.value: 0,
        MemoryAuthority.AGENT_INFERRED.value: 1,
        MemoryAuthority.REPOSITORY_OBSERVED.value: 2,
        MemoryAuthority.TOOL_OBSERVED.value: 3,
        MemoryAuthority.USER_STATED.value: 4,
        MemoryAuthority.VERIFICATION_CONFIRMED.value: 5,
        MemoryAuthority.SYSTEM_POLICY.value: 6,
    }

    _BLOCKED_CANDIDATE_STATUSES: ClassVar[set[str]] = {
        MemoryStatus.CANDIDATE.value,
        MemoryStatus.QUARANTINED.value,
        MemoryStatus.REJECTED.value,
    }

    def decide(
        self,
        existing: MemoryHit,
        *,
        candidate_authority: MemoryAuthority,
        candidate_status: MemoryStatus,
        user_correction: bool = False,
    ) -> SupersessionDecision:
        """Return a conservative temporal replacement decision."""

        if candidate_status.value in self._BLOCKED_CANDIDATE_STATUSES:
            return SupersessionDecision(False, "candidate_not_promotable")
        existing_status = enum_value(existing.status)
        if existing_status in {
            MemoryStatus.REVOKED.value,
            MemoryStatus.REJECTED.value,
            MemoryStatus.SUPERSEDED.value,
        }:
            return SupersessionDecision(False, "existing_not_current")
        incoming = candidate_authority.value
        current = enum_value(existing.authority_hint or MemoryAuthority.AGENT_INFERRED)
        # User correction is an explicit host decision, not an inference from
        # a matching key.  It is the only lower/equal-authority replacement.
        if incoming == MemoryAuthority.USER_STATED.value and user_correction:
            return SupersessionDecision(True, "explicit_user_correction")
        if incoming == MemoryAuthority.VERIFICATION_CONFIRMED.value:
            return SupersessionDecision(True, "trusted_verification")
        if current in {
            MemoryAuthority.USER_STATED.value,
            MemoryAuthority.VERIFICATION_CONFIRMED.value,
            MemoryAuthority.SYSTEM_POLICY.value,
        } and incoming in {
            MemoryAuthority.AGENT_INFERRED.value,
            MemoryAuthority.REPOSITORY_OBSERVED.value,
            MemoryAuthority.TOOL_OBSERVED.value,
        }:
            return SupersessionDecision(False, "lower_authority_cannot_supersede")
        if incoming == MemoryAuthority.REPOSITORY_OBSERVED.value and current in {
            MemoryAuthority.USER_STATED.value,
            MemoryAuthority.VERIFICATION_CONFIRMED.value,
        }:
            return SupersessionDecision(False, "repository_cannot_supersede_trusted_fact")
        if self._RANK.get(incoming, 0) < self._RANK.get(current, 0):
            return SupersessionDecision(False, "incoming_authority_is_lower")
        if incoming == MemoryAuthority.USER_STATED.value:
            return SupersessionDecision(True, "same_or_higher_user_authority")
        if incoming == current:
            return SupersessionDecision(True, "same_authority_temporal_update")
        return SupersessionDecision(False, "unresolved_conflict_preserved")


@dataclass(frozen=True, slots=True)
class MemoryPolicy:
    """Immutable policy compiled for one Broker instance."""

    max_candidate_bytes: int = 64 * 1024
    max_provider_content_bytes: int = 32 * 1024
    max_provider_metadata_bytes: int = 32 * 1024
    max_search_query_length: int = 4096
    max_search_hits: int = 100
    strict_prompt_injection: bool = True
    allow_system_policy_candidates: bool = False

    def __post_init__(self) -> None:
        values = (
            self.max_candidate_bytes,
            self.max_provider_content_bytes,
            self.max_provider_metadata_bytes,
            self.max_search_query_length,
            self.max_search_hits,
        )
        if any(value <= 0 for value in values):
            raise ValueError("memory policy limits must be positive")


_INSTRUCTION_PATTERNS = (
    re.compile(r"\bignore\s+(?:all\s+)?previous\s+(?:rules|instructions)\b", re.IGNORECASE),
    re.compile(r"\b(system|developer)\s+prompt\b", re.IGNORECASE),
    re.compile(r"\b(?:run|execute)\s+(?:curl|wget|bash|sh|powershell)\b", re.IGNORECASE),
    re.compile(r"\b(?:bypass|disable)\s+(?:sandbox|approval|security)\b", re.IGNORECASE),
    re.compile(r"\b(?:send|print|reveal|exfiltrate)\s+(?:the\s+)?(?:api\s+key|token|credential|secret)\b", re.IGNORECASE),
    re.compile(r"\bremember\s+this\s+permanently\b", re.IGNORECASE),
    re.compile(r"忽略(?:之前|先前|上面)的(?:指令|规则|要求)"),
    re.compile(r"无视(?:系统|开发者)?(?:指令|规则|提示)"),
    re.compile(r"(?:执行|运行)\s*(?:curl|wget|bash|sh|powershell)", re.IGNORECASE),
    re.compile(r"绕过(?:沙箱|审批|安全|权限)"),
    re.compile(r"(?:泄露|打印|输出|发送).{0,8}(?:API.?Key|密钥|令牌|凭证|秘密)", re.IGNORECASE),
    re.compile(r"永久(?:记住|保存)"),
)


def looks_like_instruction(text: str) -> bool:
    """Detect common persistent prompt-injection language."""

    normalized = unicodedata.normalize("NFKC", text).casefold()
    normalized = re.sub(r"[\u200b-\u200f\u2060\ufeff]", "", normalized)
    normalized = re.sub(r"\s+", " ", normalized)
    return any(pattern.search(normalized) for pattern in _INSTRUCTION_PATTERNS)


def screen_text(
    text: str,
    *,
    source_type: SourceType | str | None,
    policy: MemoryPolicy,
) -> ScreeningResult:
    """Screen untrusted content before it can become model-visible memory."""

    if not text or len(text.encode("utf-8")) > policy.max_provider_content_bytes:
        return ScreeningResult(ScreeningAction.REJECT, "content_empty_or_oversized")
    source = enum_value(source_type or SourceType.PROVIDER)
    if (
        policy.strict_prompt_injection
        and looks_like_instruction(text)
        and source in {SourceType.REPOSITORY.value, SourceType.EXTERNAL.value, SourceType.PROVIDER.value}
    ):
        return ScreeningResult(ScreeningAction.QUARANTINE, "instruction_like_untrusted_content")
    return ScreeningResult(ScreeningAction.ALLOW)


def reclassify_provider_authority(
    source_type: SourceType | str | None,
    authority_hint: str | None,
    *,
    canonical_record: bool,
    local_evidence: bool = False,
) -> MemoryAuthority:
    """Convert a provider hint into Khaos authority without escalation."""

    source = enum_value(source_type or SourceType.PROVIDER)
    if canonical_record and source == SourceType.SYSTEM.value:
        return MemoryAuthority.SYSTEM_POLICY
    if canonical_record and source == SourceType.VERIFICATION.value:
        return MemoryAuthority.VERIFICATION_CONFIRMED
    if local_evidence and source == SourceType.USER.value:
        return MemoryAuthority.USER_STATED
    if local_evidence and source == SourceType.TOOL.value:
        return MemoryAuthority.TOOL_OBSERVED
    if local_evidence and source == SourceType.REPOSITORY.value:
        return MemoryAuthority.REPOSITORY_OBSERVED
    if source == SourceType.EXTERNAL.value:
        return MemoryAuthority.EXTERNAL_UNTRUSTED
    del authority_hint
    return MemoryAuthority.AGENT_INFERRED


def scope_matches(hit: MemoryHit, runtime: RuntimeMemoryContext) -> bool:
    """Check project, principal, namespace, and session isolation."""

    if hit.project_id != runtime.project_id:
        return False
    namespace = hit.namespace
    if namespace in {"private", "session"} and hit.principal_id != runtime.principal_id:
        return False
    if namespace == "session" and hit.session_id != runtime.session_id:
        return False
    return namespace in {"private", "project", "shared", "session"}


def temporal_matches(
    hit: MemoryHit,
    *,
    now: datetime | None = None,
    include_historical: bool = False,
) -> bool:
    """Apply validity windows without treating stale facts as current."""

    if include_historical:
        return True
    moment = (now or datetime.now(UTC)).astimezone(UTC)
    if hit.valid_from is not None:
        valid_from = hit.valid_from.astimezone(UTC) if hit.valid_from.tzinfo else hit.valid_from.replace(tzinfo=UTC)
        if valid_from > moment:
            return False
    if hit.valid_to is not None:
        valid_to = hit.valid_to.astimezone(UTC) if hit.valid_to.tzinfo else hit.valid_to.replace(tzinfo=UTC)
        if valid_to <= moment:
            return False
    return True


def applicability_matches(
    hit: MemoryHit,
    runtime: RuntimeMemoryContext,
) -> bool:
    """Treat applicability as a hard gate rather than a ranking feature."""

    requirements: dict[str, Any] = dict(hit.applicability)
    required = set(requirements.get("required_capabilities", ()))
    forbidden = set(requirements.get("forbidden_capabilities", ()))
    if not required.issubset(runtime.available_capabilities):
        return False
    if forbidden.intersection(runtime.available_capabilities):
        return False
    if requirements.get("mode") and requirements["mode"] != runtime.mode:
        return False
    for key, expected in dict(hit.environment).items():
        if runtime.environment.get(key) != expected:
            return False
    return True


def usage_allows_injection(
    hit: MemoryHit,
    runtime: RuntimeMemoryContext,
    *,
    explicit_query: bool,
    include_historical: bool = False,
) -> bool:
    """Enforce UsagePolicy and sensitivity at the final model boundary."""

    usage = enum_value(hit.usage_policy)
    if usage in {UsagePolicy.NO_MODEL_INJECTION.value, UsagePolicy.HUMAN_APPROVAL_REQUIRED.value}:
        return False
    if usage == UsagePolicy.EXPLICIT_QUERY_ONLY.value and not explicit_query:
        return False
    if usage == UsagePolicy.SESSION_ONLY.value and hit.session_id != runtime.session_id:
        return False
    blocked_statuses = {
        MemoryStatus.OBSERVED.value,
        MemoryStatus.CANDIDATE.value,
        MemoryStatus.QUARANTINED.value,
        MemoryStatus.REVOKED.value,
        MemoryStatus.REJECTED.value,
    }
    if not include_historical:
        blocked_statuses.add(MemoryStatus.SUPERSEDED.value)
    if enum_value(hit.status) in blocked_statuses:
        return False
    return not (
        enum_value(hit.sensitivity) in {"SENSITIVE", "SECRET_REFERENCE"}
        and not explicit_query
    )


def candidate_status(
    candidate: MemoryCandidate,
    *,
    verified: bool,
    screened: ScreeningResult,
    policy: MemoryPolicy,
) -> tuple[MemoryStatus, str]:
    """Choose a conservative lifecycle status for a candidate."""

    authority = enum_value(candidate.authority)
    memory_type = enum_value(candidate.memory_type)
    if screened.action is ScreeningAction.REJECT:
        return MemoryStatus.REJECTED, screened.reason
    if screened.action is ScreeningAction.QUARANTINE:
        return MemoryStatus.QUARANTINED, screened.reason
    if authority == MemoryAuthority.SYSTEM_POLICY.value and not policy.allow_system_policy_candidates:
        return MemoryStatus.QUARANTINED, "system_policy_requires_trusted_bootstrap"
    if authority == MemoryAuthority.VERIFICATION_CONFIRMED.value and not verified:
        return MemoryStatus.QUARANTINED, "verification_authority_missing"
    if memory_type in {
        MemoryType.SKILL_MEMORY.value,
        MemoryType.FAILURE_MEMORY.value,
        MemoryType.NEGATIVE_MEMORY.value,
        MemoryType.DECISION_MEMORY.value,
        MemoryType.CONSTRAINT_MEMORY.value,
    } and not verified and authority != MemoryAuthority.USER_STATED.value:
        return MemoryStatus.CANDIDATE, "promotion_requires_verification_or_user_approval"
    if verified:
        return MemoryStatus.VERIFIED, "verification_receipt_valid"
    return MemoryStatus.ACTIVE, "trusted_candidate_source"


__all__ = [
    "MemoryPolicy",
    "ScreeningAction",
    "ScreeningResult",
    "SupersessionDecision",
    "SupersessionPolicy",
    "applicability_matches",
    "candidate_status",
    "looks_like_instruction",
    "reclassify_provider_authority",
    "scope_matches",
    "screen_text",
    "temporal_matches",
    "usage_allows_injection",
]
