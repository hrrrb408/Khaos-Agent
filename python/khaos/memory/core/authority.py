"""Verification authority for Memory V2.

The provider and the language model may suggest a verification result, but
only this small trust-kernel object can issue a receipt accepted by the
Broker.  The receipt is intentionally opaque and short-lived in memory; the
durable verification run remains an event/evidence record.
"""

from __future__ import annotations

import hashlib
import secrets
import threading
from dataclasses import dataclass
from typing import Any

from khaos.memory.core.contracts import (
    MemoryCandidate,
    MemoryHit,
    canonical_json,
    enum_value,
)

_TRUSTED_ISSUER_CAPABILITY = object()


@dataclass(frozen=True, slots=True)
class VerificationReceipt:
    """Opaque proof that a trusted verification path confirmed a candidate."""

    token: str
    verification_run_id: str
    candidate_digest: str
    result_digest: str
    principal_id: str = ""
    project_id: str = ""
    session_id: str | None = None
    task_id: str | None = None
    workspace_id: str | None = None


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
        "verification_result_digest": candidate.verification_result_digest,
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


class VerificationReceiptVerifier:
    """Verifier-only port exposed to MemoryBroker."""

    def __init__(self) -> None:
        self._receipts: dict[str, VerificationReceipt] = {}
        self._lock = threading.RLock()

    def _register(self, receipt: VerificationReceipt) -> None:
        """Register a receipt through the trusted issuer seam."""

        with self._lock:
            self._receipts[receipt.token] = receipt

    def _validate_digest(
        self,
        digest: str,
        *,
        token: str | None,
        verification_run_id: str | None,
        principal_id: str = "",
        project_id: str = "",
        session_id: str | None = None,
        task_id: str | None = None,
        workspace_id: str | None = None,
        result_digest: str | None = None,
    ) -> bool:
        if not token or not verification_run_id:
            return False
        with self._lock:
            receipt = self._receipts.pop(token, None)
        if receipt is None:
            return False
        return (
            receipt.verification_run_id == verification_run_id
            and receipt.candidate_digest == digest
            and bool(result_digest)
            and receipt.result_digest == result_digest
            and (not receipt.principal_id or receipt.principal_id == principal_id)
            and (not receipt.project_id or receipt.project_id == project_id)
            and receipt.session_id in {None, session_id}
            and receipt.task_id in {None, task_id}
            and receipt.workspace_id in {None, workspace_id}
        )

    def validate(
        self,
        candidate: MemoryCandidate,
        *,
        token: str | None,
        verification_run_id: str | None,
        principal_id: str = "",
        project_id: str = "",
        session_id: str | None = None,
        task_id: str | None = None,
        workspace_id: str | None = None,
        result_digest: str | None = None,
    ) -> bool:
        """Consume a candidate receipt exactly once."""

        return self._validate_digest(
            candidate_digest(candidate),
            token=token,
            verification_run_id=verification_run_id,
            principal_id=principal_id,
            project_id=project_id,
            session_id=session_id,
            task_id=task_id,
            workspace_id=workspace_id,
            result_digest=result_digest,
        )

    def validate_memory(
        self,
        hit: MemoryHit,
        *,
        token: str | None,
        verification_run_id: str | None,
        principal_id: str = "",
        project_id: str = "",
        session_id: str | None = None,
        task_id: str | None = None,
        workspace_id: str | None = None,
        result_digest: str | None = None,
    ) -> bool:
        """Consume a persisted-memory receipt exactly once."""

        return self._validate_digest(
            memory_digest(hit),
            token=token,
            verification_run_id=verification_run_id,
            principal_id=principal_id,
            project_id=project_id,
            session_id=session_id,
            task_id=task_id,
            workspace_id=workspace_id,
            result_digest=result_digest,
        )

    def revoke(self, token: str) -> None:
        """Revoke an unconsumed receipt."""

        with self._lock:
            self._receipts.pop(token, None)


class VerificationReceiptIssuer:
    """Issuer owned by the trusted VerificationPipeline composition."""

    def __init__(
        self,
        verifier: VerificationReceiptVerifier,
        *,
        owner: Any,
        _capability: object | None = None,
    ) -> None:
        if _capability is not _TRUSTED_ISSUER_CAPABILITY:
            raise PermissionError("trusted verification pipeline capability is required")
        if owner is None or not getattr(owner, "__khaos_trusted_verification__", False):
            raise PermissionError("trusted verification pipeline owner is required")
        self._verifier = verifier
        self._owner = owner

    def issue(
        self,
        candidate: MemoryCandidate,
        verification_run_id: str,
        *,
        principal_id: str = "",
        project_id: str = "",
        session_id: str | None = None,
        task_id: str | None = None,
        workspace_id: str | None = None,
        result_digest: str | None = None,
    ) -> VerificationReceipt:
        """Mint a scope-bound candidate receipt."""

        if not verification_run_id:
            raise ValueError("verification_run_id must be non-empty")
        if not result_digest:
            raise ValueError("verification result digest is required")
        receipt = VerificationReceipt(
            token=secrets.token_urlsafe(32),
            verification_run_id=verification_run_id,
            candidate_digest=candidate_digest(candidate),
            result_digest=result_digest,
            principal_id=principal_id,
            project_id=project_id,
            session_id=session_id,
            task_id=task_id,
            workspace_id=workspace_id,
        )
        self._verifier._register(receipt)
        return receipt

    def issue_memory(
        self,
        hit: MemoryHit,
        verification_run_id: str,
        *,
        principal_id: str = "",
        project_id: str = "",
        session_id: str | None = None,
        task_id: str | None = None,
        workspace_id: str | None = None,
        result_digest: str | None = None,
    ) -> VerificationReceipt:
        """Mint a scope-bound persisted-memory receipt."""

        if not verification_run_id:
            raise ValueError("verification_run_id must be non-empty")
        if not result_digest:
            raise ValueError("verification result digest is required")
        receipt = VerificationReceipt(
            token=secrets.token_urlsafe(32),
            verification_run_id=verification_run_id,
            candidate_digest=memory_digest(hit),
            result_digest=result_digest,
            principal_id=principal_id,
            project_id=project_id,
            session_id=session_id,
            task_id=task_id,
            workspace_id=workspace_id,
        )
        self._verifier._register(receipt)
        return receipt


__all__ = [
    "VerificationReceipt",
    "VerificationReceiptIssuer",
    "VerificationReceiptVerifier",
    "candidate_digest",
    "memory_digest",
]
