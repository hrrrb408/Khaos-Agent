"""Verification authority for Memory V2.

The provider and the language model may suggest a verification result, but
only this small trust-kernel object can issue a receipt accepted by the
Broker.  The receipt is intentionally opaque and short-lived in memory; the
durable verification run remains an event/evidence record.
"""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass

from khaos.memory.core.contracts import MemoryCandidate, MemoryHit, canonical_json, enum_value


@dataclass(frozen=True, slots=True)
class VerificationReceipt:
    """Opaque proof that a trusted verification path confirmed a candidate."""

    token: str
    verification_run_id: str
    candidate_digest: str


def candidate_digest(candidate: MemoryCandidate) -> str:
    """Return a deterministic digest over the complete candidate contract."""

    payload = {
        "memory_type": enum_value(candidate.memory_type),
        "claim": candidate.claim,
        "authority": enum_value(candidate.authority),
        "confidence": candidate.confidence,
        "source_event_ids": candidate.source_event_ids,
        "evidence_refs": [
            {
                "source_type": enum_value(ref.source_type),
                "source_ref": ref.source_ref,
                "event_id": ref.event_id,
                "verification_run_id": ref.verification_run_id,
                "commit_sha": ref.commit_sha,
            }
            for ref in candidate.evidence_refs
        ],
        "entities": [
            {
                "entity_type": entity.entity_type,
                "canonical_name": entity.canonical_name,
                "entity_id": entity.entity_id,
            }
            for entity in candidate.entities
        ],
        "relations": [
            {
                "relation": relation.relation,
                "target_kind": relation.target_kind,
                "target_id": relation.target_id,
                "confidence": relation.confidence,
            }
            for relation in candidate.relations
        ],
        "key": candidate.key,
        "scope": candidate.scope,
        "namespace": candidate.namespace,
        "session_id": candidate.session_id,
        "valid_from": candidate.valid_from.isoformat() if candidate.valid_from else None,
        "valid_to": candidate.valid_to.isoformat() if candidate.valid_to else None,
        "preconditions": dict(candidate.preconditions),
        "environment": dict(candidate.environment),
        "sensitivity": enum_value(candidate.sensitivity),
        "usage_policy": enum_value(candidate.usage_policy),
        "verification_run_id": candidate.verification_run_id,
    }
    return hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()


def memory_digest(hit: MemoryHit) -> str:
    """Return a stable digest for a persisted memory promotion decision."""

    payload = {
        "memory_id": hit.memory_id,
        "external_id": hit.external_id,
        "content": hit.content,
        "memory_type": enum_value(hit.memory_type),
        "project_id": hit.project_id,
        "principal_id": hit.principal_id,
        "namespace": hit.namespace,
        "scope": hit.scope,
        "key": hit.key,
        "valid_from": hit.valid_from.isoformat() if hit.valid_from else None,
        "valid_to": hit.valid_to.isoformat() if hit.valid_to else None,
        "event_ids": hit.event_ids,
        "evidence_refs": [
            {
                "source_type": enum_value(ref.source_type),
                "source_ref": ref.source_ref,
                "event_id": ref.event_id,
                "verification_run_id": ref.verification_run_id,
                "commit_sha": ref.commit_sha,
            }
            for ref in hit.evidence_refs
        ],
    }
    return hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()


class VerificationAuthority:
    """Issue and validate process-local verification receipts."""

    def __init__(self, issuer_id: str = "khaos-verification") -> None:
        if not issuer_id:
            raise ValueError("issuer_id must be non-empty")
        self.issuer_id = issuer_id
        self._receipts: dict[str, VerificationReceipt] = {}

    def issue(
        self,
        candidate: MemoryCandidate,
        verification_run_id: str,
    ) -> VerificationReceipt:
        """Issue a receipt for a trusted verification pipeline result."""

        if not verification_run_id:
            raise ValueError("verification_run_id must be non-empty")
        receipt = VerificationReceipt(
            token=secrets.token_urlsafe(32),
            verification_run_id=verification_run_id,
            candidate_digest=candidate_digest(candidate),
        )
        self._receipts[receipt.token] = receipt
        return receipt

    def issue_memory(self, hit: MemoryHit, verification_run_id: str) -> VerificationReceipt:
        """Issue a receipt for a specific persisted memory representation."""

        if not verification_run_id:
            raise ValueError("verification_run_id must be non-empty")
        receipt = VerificationReceipt(
            token=secrets.token_urlsafe(32),
            verification_run_id=verification_run_id,
            candidate_digest=memory_digest(hit),
        )
        self._receipts[receipt.token] = receipt
        return receipt

    def validate(
        self,
        candidate: MemoryCandidate,
        *,
        token: str | None,
        verification_run_id: str | None,
    ) -> bool:
        """Return true only for a receipt issued for this exact candidate."""

        if not token or not verification_run_id:
            return False
        receipt = self._receipts.get(token)
        if receipt is None:
            return False
        return (
            receipt.verification_run_id == verification_run_id
            and receipt.candidate_digest == candidate_digest(candidate)
        )

    def validate_memory(
        self,
        hit: MemoryHit,
        *,
        token: str | None,
        verification_run_id: str | None,
    ) -> bool:
        """Validate a receipt issued for the exact scoped memory hit."""

        if not token or not verification_run_id:
            return False
        receipt = self._receipts.get(token)
        if receipt is None:
            return False
        return (
            receipt.verification_run_id == verification_run_id
            and receipt.candidate_digest == memory_digest(hit)
        )

    def revoke(self, token: str) -> None:
        """Revoke a receipt before it is consumed by a Broker."""

        self._receipts.pop(token, None)


__all__ = [
    "VerificationAuthority",
    "VerificationReceipt",
    "candidate_digest",
    "memory_digest",
]
