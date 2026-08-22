"""Persistent store for plan approval state with atomic CAS transitions.

Backed by synchronous ``sqlite3`` (mirroring
``khaos.coding.intelligence.resolution.persistence``) so that every state
transition can be wrapped in a single ``BEGIN IMMEDIATE`` transaction — the
strongest concurrency primitive available without adding a new dependency.

The schema is appended idempotently to the project-wide ``schema.sql`` and is
also created here on first use (``ensure_schema``), so the store works against
both a fresh in-memory database and an existing project database.

Batch 2.1 hardening:

* :meth:`apply_authenticated_decision` — ONE ``BEGIN IMMEDIATE`` transitions
  the request, writes the decision, writes the audit, updates expiry AND
  consumes the broker receipt. Any step failing rolls the whole thing back.
* :meth:`mint_authorization_if_request_active` — atomic mint that refuses to
  create a second ACTIVE authorization for one request.
* :meth:`consume_authorization_with_request` — atomic consume that flips BOTH
  the authorization and its request to CONSUMED in one transaction.
* ``server_epoch`` column + :meth:`revoke_authorizations_outside_epoch` — the
  authoritative restart-invalidation mechanism (replaces "nonce lost in
  memory" as a safety property).
* ``plan_approval_receipts`` outbox — durable receipt token-hash registry so a
  forged dataclass receipt cannot pass validation.
"""
from __future__ import annotations

import json
import logging
import sqlite3
import threading
import time
import uuid
from enum import Enum
from pathlib import Path
from typing import Any

from khaos.coding.planning.approval.execution_journal_writer import (
    PlanExecutionJournalWriter,
)
from khaos.coding.planning.approval.execution_read_model import PlanExecutionReadModel
from khaos.coding.planning.approval.execution_writer import PlanExecutionWriter
from khaos.coding.planning.approval.models import (
    ALLOWED_APPROVAL_TRANSITIONS,
    AuthorizationStatus,
    PlanApprovalAuditEvent,
    PlanApprovalDecision,
    PlanApprovalRequest,
    PlanApprovalStatus,
    PlanExecutionAuthorization,
    verify_nonce,
)
from khaos.coding.planning.approval.read_model import PlanApprovalReadModel
from khaos.coding.planning.approval.schema import APPROVAL_SCHEMA, upgrade_schema
from khaos.coding.planning.security_identities import CanonicalWorkspaceId

logger = logging.getLogger(__name__)


class ApprovalTransitionResult(str, Enum):
    """Outcome of an atomic CAS approval transition."""

    UPDATED = "updated"
    UNCHANGED = "unchanged"  # idempotent same-decision
    INVALID_TRANSITION = "invalid_transition"
    CONFLICT = "conflict"  # opposite decision already applied
    NOT_FOUND = "not_found"
    STALE = "stale"  # binding digest drifted


class PlanApprovalStore:
    """Atomic, durable store for plan approval + authorization state.

    SQLite's ``BEGIN IMMEDIATE`` serializes separate connections. A
    ``sqlite3.Connection`` can also be intentionally shared between threads
    (the test/runtime contract uses ``check_same_thread=False``); in that
    case transaction state belongs to the connection, not to the calling
    thread. The store therefore serializes its atomic write paths with an
    ``RLock`` as well. Every mutating method opens a transaction, performs a
    Compare-And-Swap on the persisted status, and either commits or rolls back
    atomically.
    """

    def __init__(self, conn: sqlite3.Connection) -> None:
        self._conn = conn
        self._transaction_lock = threading.RLock()
        self._conn.row_factory = sqlite3.Row
        self._read_model = PlanApprovalReadModel(self._conn)
        self._execution_read_model = PlanExecutionReadModel(self._conn)
        self.ensure_schema()
        self._execution_writer = PlanExecutionWriter(
            self._conn,
            self._execution_read_model,
        )
        self._execution_journal_writer = PlanExecutionJournalWriter(self._conn)
        # Batch 2.6 §1: a name-mangled writer handle that ONLY the runtime
        # can install (via _install_runtime_receipt_writer). It is NOT a
        # sink closure and NOT exposed as a public attribute. Ordinary
        # callers cannot read or replace it.
        self.__runtime_receipt_writer = None  # type: ignore[assignment]
        self.__runtime_receipt_token = None
        # Public-only verifier registry. Unknown keys fail closed; prior-boot
        # public keys remain loadable across signing-key rotation.
        self.__receipt_verifiers: dict[str, Any] = {}
        try:
            for verifier in self.load_receipt_verifiers():
                self.__receipt_verifiers[verifier.key_id] = verifier
        except Exception as exc:
            logger.debug("could not load persisted receipt verifiers", exc_info=exc)

    @property
    def approval_read_model(self) -> PlanApprovalReadModel:
        """Return the read-only owner for approval ledger queries.

        The store deliberately exposes the owner object instead of forwarding
        query methods.  Callers must depend on the read boundary explicitly;
        approval CAS and lease mutations remain on this store.
        """
        return self._read_model

    @property
    def execution_read_model(self) -> PlanExecutionReadModel:
        """Return the read-only owner for planned-execution records."""
        return self._execution_read_model

    @property
    def execution_writer(self) -> PlanExecutionWriter:
        """Return the sole transactional writer for execution runs/proofs."""
        return self._execution_writer

    @property
    def execution_journal_writer(self) -> PlanExecutionJournalWriter:
        """Return the sole transactional writer for edit journals."""
        return self._execution_journal_writer

    def _install_runtime_receipt_writer(
        self, writer: Any, *, runtime_token: object, runtime_capability: Any = None
    ) -> None:
        """Install the runtime's receipt writer (name-mangled, token-gated).

        Batch 2.6 §1: replaces the old ``_create_receipt_sink`` /
        ``_bind_receipt_broker`` / ``broker._receipt_writer`` chain. The
        ``runtime_token`` is an opaque object that only
        :class:`ApprovalRuntime` possesses; a forged token is silently
        ignored. The writer is a plain callable that captures the broker's
        internal ``ReceiptSigner`` — it has no readable ``capability`` or
        ``signer`` attribute.
        """
        from khaos.coding.planning.approval.runtime import _consume_runtime_capability

        try:
            _consume_runtime_capability(runtime_capability, "receipt-store")
        except PermissionError as exc:
            raise PermissionError("runtime receipt authority required") from exc
        if runtime_token is None:
            raise PermissionError("runtime receipt token required")
        self.__runtime_receipt_writer = writer  # type: ignore[assignment]
        self.__runtime_receipt_token = runtime_token

    def _reset_runtime_receipt_writer(self) -> None:
        """Clear the runtime receipt writer (used by rollback/shutdown).

        Persisted public verifiers remain loaded so prior-boot receipts stay
        verifiable after signing-key rotation.
        Only the writer (mint path) is cleared.
        """
        self.__runtime_receipt_writer = None  # type: ignore[assignment]
        self.__runtime_receipt_token = None

    def _has_runtime_receipt_writer(self) -> bool:
        """Test-only introspection: does a writer exist?"""
        return self.__runtime_receipt_writer is not None  # type: ignore[attr-defined]

    def _install_verification_success_verifier(self, verifier: Any) -> None:
        """Install Runtime-owned validation for authoritative VERIFIED reads."""
        self._execution_read_model.install_verification_success_verifier(verifier)

    def _require_authoritative_verification_reads(self) -> None:
        self._execution_read_model.require_authoritative_verification_reads()

    def _reset_verification_success_verifier(self) -> None:
        self._execution_read_model.reset_verification_success_verifier()

    def _persist_receipt_verifier(self, verifier: Any, *, runtime_token: object) -> None:
        """Persist public verification material only."""
        if runtime_token is not self.__runtime_receipt_token:
            raise PermissionError("runtime authority required")
        import time as _time
        self._conn.execute(
            "INSERT OR REPLACE INTO receipt_verification_keys "
            "(key_id, public_key, key_version, boot_epoch, boot_id, created_at, active) "
            "VALUES (?, ?, ?, ?, ?, ?, 1)",
            (verifier.key_id, verifier.public_key, verifier.key_version,
             verifier.boot_epoch, verifier.boot_id, _time.time()),
        )
        self._conn.commit()
        self.__receipt_verifiers[verifier.key_id] = verifier

    def load_receipt_verifiers(self) -> list:
        """Return public-only verifier objects; legacy HMAC rows are ignored."""
        from khaos.coding.planning.approval.receipt_crypto import ReceiptPublicVerifier
        rows = self._conn.execute(
            "SELECT key_id,public_key,key_version,boot_epoch,boot_id "
            "FROM receipt_verification_keys WHERE active = 1"
        ).fetchall()
        return [ReceiptPublicVerifier(
            str(row["key_id"]), str(row["public_key"]), int(row["key_version"]),
            int(row["boot_epoch"]), str(row["boot_id"]),
        ) for row in rows]

    # ------------------------------------------------------------------
    # Schema bootstrap
    # ------------------------------------------------------------------

    def ensure_schema(self) -> None:
        """Create the approval tables if missing. Idempotent."""
        self._conn.executescript(APPROVAL_SCHEMA)
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            upgrade_schema(self._conn)
            self._conn.commit()
        except Exception:
            self._conn.rollback()
            raise

    # ------------------------------------------------------------------
    # Receipt outbox
    # ------------------------------------------------------------------

    def _insert_signed_receipt(
        self,
        *,
        runtime_token: object = None,
        receipt_id: str,
        token_hash: str,
        approval_request_id: str,
        broker_request_id: str,
        binding_digest: str,
        decision: str,
        namespace: str = "plan-execution",
        authenticated_actor_id: str = "",
        authenticated_actor_type: str = "",
        authenticated_source: str = "",
        session_request_id: str = "",
        server_capability: str = "",
        decided_at: float = 0.0,
        reason_digest: str = "",
        expires_at: float,
        canonical_payload_digest: str = "",
        broker_signature: str = "",
        signer_key_id: str = "",
        signer_epoch: int = 0,
        signer_boot_id: str = "",
        issued_at: float = 0.0,
        created_at: float | None = None,
        now: float | None = None,
    ) -> None:
        """Persist a SIGNED broker-decision receipt outbox row.

        Batch 2.6 §1: this method is called ONLY by the runtime-installed
        receipt writer (the broker's signed writer closure). It is NOT
        callable by ordinary store users — there is no capability token to
        forge. The writer closure is installed by the runtime via
        ``_install_runtime_receipt_writer`` and is name-mangled so it cannot
        be read or replaced from outside the store.

        The ``canonical_payload_digest``, ``broker_signature``, and
        ``signer_key_id`` are persisted alongside the row so
        ``apply_authenticated_decision`` can re-verify the Ed25519 signature
        against the persisted digest. Direct DB writes by ordinary code
        cannot produce a valid signature, so a forged outbox row is rejected
        even if it matches a known token hash.

        Uses plain INSERT (not INSERT OR REPLACE) so a receipt_id or
        token_hash conflict raises — a persisted decision cannot be rewritten.
        """
        if runtime_token is not self.__runtime_receipt_token:
            raise PermissionError("runtime receipt authority required")
        if not broker_signature or not signer_key_id or not canonical_payload_digest:
            raise PermissionError(
                "signed receipt requires broker_signature, signer_key_id, "
                "and canonical_payload_digest; unsigned receipts are refused"
            )
        ts = float(created_at if created_at is not None else (now if now is not None else time.time()))
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            if not self._verify_persisted_boot_context(
                server_epoch=signer_epoch, boot_id=signer_boot_id,
            ):
                raise PermissionError("receipt signer boot is no longer current")
            key = self._conn.execute(
                "SELECT boot_epoch,boot_id FROM receipt_verification_keys WHERE key_id=?",
                (signer_key_id,),
            ).fetchone()
            if key is None or int(key["boot_epoch"]) != int(signer_epoch) or str(key["boot_id"]) != signer_boot_id:
                raise PermissionError("receipt signer key is not bound to current boot")
            self._conn.execute(
            """
            INSERT INTO plan_approval_receipts (
                receipt_id, token_hash, approval_request_id, broker_request_id,
                binding_digest, decision, namespace, authenticated_actor_id,
                authenticated_actor_type, authenticated_source, session_request_id,
                server_capability, decided_at, reason_digest, consumed, created_at,
                expires_at, canonical_payload_digest, broker_signature, signer_key_id,
                signer_epoch, signer_boot_id, issued_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                receipt_id, token_hash, approval_request_id, broker_request_id,
                binding_digest, decision, namespace, authenticated_actor_id,
                authenticated_actor_type, authenticated_source, session_request_id,
                server_capability, float(decided_at), reason_digest, ts, float(expires_at),
                canonical_payload_digest, broker_signature, signer_key_id,
                int(signer_epoch), signer_boot_id, float(issued_at),
            ),
            )
            self._conn.commit()
        except Exception:
            self._conn.rollback()
            raise

    def get_receipt_by_token(self, token: str) -> sqlite3.Row | None:
        """Look up a receipt row by verifying a plaintext token.

        Constant-time: hashes the token and compares against stored hashes.
        """
        from khaos.coding.planning.approval.models import hash_receipt_token

        th = hash_receipt_token(token)
        return self._conn.execute(
            "SELECT * FROM plan_approval_receipts WHERE token_hash = ?",
            (th,),
        ).fetchone()

    # ------------------------------------------------------------------
    # Request persistence
    # ------------------------------------------------------------------

    def insert_request(self, request: PlanApprovalRequest) -> None:
        """Insert a brand new approval request (must not already exist)."""
        self._conn.execute(
            """
            INSERT INTO plan_approval_requests (
                approval_request_id, plan_id, plan_content_hash, repository_id,
                task_id, workspace_id, base_sha, repository_generation,
                risk_level, requested_operations, affected_files, affected_symbols,
                verification_digest, binding_digest, requested_at, expires_at,
                status, broker_request_id, reason, metadata,
                approved_verification_plan_id, approved_verification_plan_digest
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                request.approval_request_id,
                request.plan_id,
                request.plan_content_hash,
                request.repository_id,
                request.task_id,
                request.workspace_id,
                request.base_sha,
                int(request.repository_generation),
                request.risk_level,
                json.dumps(list(request.requested_operations)),
                json.dumps(list(request.affected_files)),
                json.dumps(list(request.affected_symbols)),
                request.verification_digest,
                request.binding_digest,
                float(request.requested_at),
                float(request.expires_at),
                request.status.value,
                request.broker_request_id,
                request.reason,
                json.dumps(request.metadata, default=str, sort_keys=True),
                getattr(request, "approved_verification_plan_id", "") or "",
                getattr(request, "approved_verification_plan_digest", "") or "",
            ),
        )
        self._conn.commit()

    # ------------------------------------------------------------------
    # Atomic status CAS (internal helper — does NOT write decision/audit)
    # ------------------------------------------------------------------

    def compare_and_set_status(
        self,
        approval_request_id: str,
        *,
        expected: set[PlanApprovalStatus],
        target: PlanApprovalStatus,
        current_binding_digest: str | None,
    ) -> ApprovalTransitionResult:
        """Atomically transition a request status under a CAS guard.

        NOTE (Batch 2.1): this method ONLY transitions the request status. It
        does NOT write a decision record or audit event — those belong to
        :meth:`apply_authenticated_decision`, which does everything in one
        transaction. This method is retained for non-decision transitions
        (revoke, invalidate, stale-on-drift).
        """
        if self._conn.in_transaction:
            self._conn.commit()
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            row = self._conn.execute(
                "SELECT status, binding_digest FROM plan_approval_requests "
                "WHERE approval_request_id = ?",
                (approval_request_id,),
            ).fetchone()
            if row is None:
                self._conn.rollback()
                return ApprovalTransitionResult.NOT_FOUND

            current = PlanApprovalStatus(row["status"])

            if current == target:
                self._conn.rollback()
                return ApprovalTransitionResult.UNCHANGED

            if current_binding_digest is not None and row["binding_digest"] != current_binding_digest:
                self._conn.execute(
                    "UPDATE plan_approval_requests SET status = ? WHERE approval_request_id = ?",
                    (PlanApprovalStatus.STALE.value, approval_request_id),
                )
                self._conn.commit()
                return ApprovalTransitionResult.STALE

            allowed = ALLOWED_APPROVAL_TRANSITIONS.get(current, frozenset())
            if target not in allowed:
                self._conn.rollback()
                return ApprovalTransitionResult.CONFLICT

            if current not in expected:
                self._conn.rollback()
                return ApprovalTransitionResult.CONFLICT

            self._conn.execute(
                "UPDATE plan_approval_requests SET status = ? WHERE approval_request_id = ?",
                (target.value, approval_request_id),
            )
            self._conn.commit()
            return ApprovalTransitionResult.UPDATED
        except Exception:
            self._conn.rollback()
            raise

    # ------------------------------------------------------------------
    # Atomic authenticated decision (§2) — the heart of the closure
    # ------------------------------------------------------------------

    def apply_authenticated_decision(
        self,
        *,
        approval_request_id: str,
        receipt,
        decision_record: PlanApprovalDecision,
        audit_event: PlanApprovalAuditEvent,
        new_expiry: float | None,
        now: float,
    ) -> ApprovalTransitionResult:
        """Apply a broker decision, the decision row, the audit row, the
        expiry update AND the receipt consumption in ONE ``BEGIN IMMEDIATE``.

        Failure of any step rolls back the entire transaction: the request
        status is unchanged, no decision row, no audit row, expiry unchanged,
        receipt not consumed.

        Full-field authenticity (Batch 2.2): the receipt's one-time token is
        hashed and matched against the ``plan_approval_receipts`` outbox row,
        AND EVERY authoritative field on the receipt (namespace, actor_id,
        actor_type, source, session_request_id, server_capability, decided_at,
        reason_digest, binding_digest, decision) is compared against that row.
        Tampering ANY field on a real receipt is detected and refused as
        CONFLICT. A forged dataclass receipt cannot supply a token whose hash
        matches an unconsumed outbox row in the first place.

        The idempotent path (request already in the decision state) STILL
        verifies the token + all fields before returning UNCHANGED — there is
        no early return that skips receipt verification.

        Returns:
            * ``UPDATED`` — decision applied atomically.
            * ``UNCHANGED`` — request already in ``decision`` (idempotent).
            * ``CONFLICT`` — receipt replay, cross-request, field tamper, or
              state conflict.
            * ``STALE`` — binding drift detected.
            * ``NOT_FOUND`` — request or receipt unknown.
        """
        decision = receipt.decision
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            # 1. Verify the receipt token against the outbox.
            receipt_row = self.get_receipt_by_token(receipt.one_time_token)
            if receipt_row is None:
                self._conn.rollback()
                return ApprovalTransitionResult.NOT_FOUND
            if int(receipt_row["consumed"]) == 1:
                # Replay attempt — refuse.
                self._conn.rollback()
                return ApprovalTransitionResult.CONFLICT
            if receipt_row["approval_request_id"] != approval_request_id:
                # Cross-request replay.
                self._conn.rollback()
                return ApprovalTransitionResult.CONFLICT
            if receipt_row["decision"] != decision.value:
                # Receipt's bound decision does not match the caller's claim.
                self._conn.rollback()
                return ApprovalTransitionResult.CONFLICT
            if now >= float(receipt_row["expires_at"]):
                self._conn.rollback()
                return ApprovalTransitionResult.CONFLICT

            # 1b. Verify EVERY authoritative field (Batch 2.2 §1). Tampering
            # any of these on a real receipt is a CONFLICT. We compare against
            # the durable outbox row, not the in-memory receipt object.
            field_checks = (
                ("namespace", receipt.namespace),
                ("authenticated_actor_id", receipt.authenticated_actor_id),
                ("authenticated_actor_type", receipt.authenticated_actor_type),
                ("authenticated_source", receipt.authenticated_source),
                ("session_request_id", receipt.session_request_id),
                ("server_capability", receipt.server_capability),
                ("reason_digest", receipt.reason_digest),
            )
            for col, expected in field_checks:
                if str(receipt_row[col]) != str(expected):
                    self._conn.rollback()
                    return ApprovalTransitionResult.CONFLICT
            # decided_at is a float; compare with small tolerance for JSON round-trip.
            if abs(float(receipt_row["decided_at"]) - float(receipt.decided_at)) > 1e-6:
                self._conn.rollback()
                return ApprovalTransitionResult.CONFLICT
            if str(receipt_row["binding_digest"]) != str(receipt.binding_digest):
                self._conn.rollback()
                return ApprovalTransitionResult.CONFLICT

            # 1c. Batch 2.6 §1: verify the broker signature. Even if an
            # attacker directly inserts a forged outbox row with a known
            # token_hash + matching fields, they cannot produce a valid
            # Ed25519 signature without the broker's private key. Old unsigned
            # receipts (broker_signature="") are rejected fail-closed.
            row_sig = str(receipt_row["broker_signature"]) if "broker_signature" in receipt_row.keys() else ""  # noqa: SIM118 - sqlite3.Row exposes keys explicitly
            row_signer_key_id = str(receipt_row["signer_key_id"]) if "signer_key_id" in receipt_row.keys() else ""  # noqa: SIM118 - sqlite3.Row exposes keys explicitly
            row_payload_digest = str(receipt_row["canonical_payload_digest"]) if "canonical_payload_digest" in receipt_row.keys() else ""  # noqa: SIM118 - sqlite3.Row exposes keys explicitly
            if not row_sig or not row_signer_key_id or not row_payload_digest:
                # Unsigned receipt — fail closed.
                self._conn.rollback()
                return ApprovalTransitionResult.CONFLICT
            # Look up the verifier by signer_key_id.
            verifier = self.__receipt_verifiers.get(row_signer_key_id)  # type: ignore[attr-defined]
            if verifier is None:
                # Unknown signer key — fail closed.
                self._conn.rollback()
                return ApprovalTransitionResult.CONFLICT
            signer_epoch = int(receipt_row["signer_epoch"])
            signer_boot_id = str(receipt_row["signer_boot_id"])
            issued_at = float(receipt_row["issued_at"])
            if (verifier.boot_epoch != signer_epoch
                    or verifier.boot_id != signer_boot_id):
                self._conn.rollback()
                return ApprovalTransitionResult.CONFLICT
            boot = self._conn.execute(
                "SELECT started_at,replaced_at FROM approval_runtime_boots "
                "WHERE server_epoch=? AND boot_id=?",
                (signer_epoch, signer_boot_id),
            ).fetchone()
            if (boot is None or issued_at < float(boot["started_at"])
                    or (boot["replaced_at"] is not None
                        and issued_at >= float(boot["replaced_at"]))
                    or abs(float(receipt_row["created_at"]) - issued_at) > 1e-6):
                self._conn.rollback()
                return ApprovalTransitionResult.CONFLICT
            # Recompute the canonical payload digest from the DURABLE ROW
            # fields (not the in-memory receipt) so a tampered in-memory
            # receipt is detected even if it claims the same signature.
            import hashlib as _hashlib
            canonical_from_row = "|".join([
                str(receipt_row["receipt_id"]),
                str(receipt_row["namespace"]),
                str(receipt_row["broker_request_id"]),
                str(receipt_row["approval_request_id"]),
                str(receipt_row["decision"]),
                str(receipt_row["authenticated_actor_id"]),
                str(receipt_row["authenticated_actor_type"]),
                str(receipt_row["authenticated_source"]),
                str(receipt_row["session_request_id"]),
                str(receipt_row["server_capability"]),
                str(receipt_row["binding_digest"]),
                f"{float(receipt_row['decided_at']):.6f}",
                f"{float(receipt_row['expires_at']):.6f}",
                str(receipt_row["reason_digest"]),
                str(receipt_row["token_hash"]),
                str(signer_epoch),
                signer_boot_id,
                f"{issued_at:.6f}",
            ])
            row_digest_recomputed = _hashlib.sha256(canonical_from_row.encode("utf-8")).hexdigest()
            if row_digest_recomputed != row_payload_digest:
                # Persisted payload digest doesn't match persisted fields — tampered row.
                self._conn.rollback()
                return ApprovalTransitionResult.CONFLICT
            if not verifier.verify_payload_digest(row_payload_digest, row_sig):
                self._conn.rollback()
                return ApprovalTransitionResult.CONFLICT
            # Also verify the in-memory receipt's signature matches (catches
            # a tampered in-memory receipt whose fields differ from the row).
            if (receipt.signer_key_id != verifier.key_id
                    or receipt.signer_epoch != signer_epoch
                    or receipt.signer_boot_id != signer_boot_id
                    or abs(receipt.issued_at - issued_at) > 1e-6
                    or not verifier.verify_payload_digest(
                        receipt.compute_canonical_payload_digest(),
                        receipt.broker_signature,
                    )):
                self._conn.rollback()
                return ApprovalTransitionResult.CONFLICT

            # 2. Verify the request status + binding.
            row = self._conn.execute(
                "SELECT status, binding_digest FROM plan_approval_requests "
                "WHERE approval_request_id = ?",
                (approval_request_id,),
            ).fetchone()
            if row is None:
                self._conn.rollback()
                return ApprovalTransitionResult.NOT_FOUND
            current = PlanApprovalStatus(row["status"])
            if current == decision:
                # Idempotent — STILL consume the receipt (after the full field
                # verification above passed) so it can't be reused.
                self._conn.execute(
                    "UPDATE plan_approval_receipts SET consumed = 1 WHERE receipt_id = ?",
                    (receipt_row["receipt_id"],),
                )
                self._conn.commit()
                return ApprovalTransitionResult.UNCHANGED
            if row["binding_digest"] != receipt_row["binding_digest"]:
                # Binding drift between request and receipt.
                self._conn.execute(
                    "UPDATE plan_approval_requests SET status = ? WHERE approval_request_id = ?",
                    (PlanApprovalStatus.STALE.value, approval_request_id),
                )
                self._conn.commit()
                return ApprovalTransitionResult.STALE
            allowed = ALLOWED_APPROVAL_TRANSITIONS.get(current, frozenset())
            if decision not in allowed:
                self._conn.rollback()
                return ApprovalTransitionResult.CONFLICT

            # 3. Transition request status.
            self._conn.execute(
                "UPDATE plan_approval_requests SET status = ? WHERE approval_request_id = ?",
                (decision.value, approval_request_id),
            )
            # 4. Update expiry (approved requests get the approved TTL).
            if new_expiry is not None:
                self._conn.execute(
                    "UPDATE plan_approval_requests SET expires_at = ? WHERE approval_request_id = ?",
                    (float(new_expiry), approval_request_id),
                )
            # 5. Insert decision record.
            self._conn.execute(
                """
                INSERT INTO plan_approval_decisions (
                    approval_request_id, decision, actor_id, actor_type, decided_at,
                    reason, authenticated_context, metadata
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    decision_record.approval_request_id,
                    decision_record.decision.value,
                    decision_record.actor_id,
                    decision_record.actor_type,
                    float(decision_record.decided_at),
                    decision_record.reason,
                    json.dumps(decision_record.authenticated_context, default=str, sort_keys=True),
                    json.dumps(decision_record.metadata, default=str, sort_keys=True),
                ),
            )
            # 6. Insert audit event.
            self._conn.execute(
                """
                INSERT INTO plan_approval_audit_events (
                    event_id, event_type, approval_request_id, plan_id, previous_status,
                    new_status, actor_id, actor_type, authenticated_source, timestamp,
                    reason_code, task_id, workspace_id, repository_id, correlation_id
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    audit_event.event_id,
                    audit_event.event_type,
                    audit_event.approval_request_id,
                    audit_event.plan_id,
                    audit_event.previous_status,
                    audit_event.new_status,
                    audit_event.actor_id,
                    audit_event.actor_type,
                    audit_event.authenticated_source,
                    float(audit_event.timestamp),
                    audit_event.reason_code,
                    audit_event.task_id,
                    audit_event.workspace_id,
                    audit_event.repository_id,
                    audit_event.correlation_id,
                ),
            )
            # 7. Consume the receipt.
            self._conn.execute(
                "UPDATE plan_approval_receipts SET consumed = 1 WHERE receipt_id = ?",
                (receipt_row["receipt_id"],),
            )
            self._conn.commit()
            return ApprovalTransitionResult.UPDATED
        except Exception:
            self._conn.rollback()
            raise

    # ------------------------------------------------------------------
    # Non-decision transitions (used by revoke / invalidate / registration)
    # ------------------------------------------------------------------

    def transition_request_status(
        self,
        approval_request_id: str,
        *,
        expected: set[PlanApprovalStatus],
        target: PlanApprovalStatus,
        audit_event: PlanApprovalAuditEvent | None = None,
    ) -> ApprovalTransitionResult:
        """Transition a request status (optionally with an audit row) in one tx."""
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            row = self._conn.execute(
                "SELECT status FROM plan_approval_requests WHERE approval_request_id = ?",
                (approval_request_id,),
            ).fetchone()
            if row is None:
                self._conn.rollback()
                return ApprovalTransitionResult.NOT_FOUND
            current = PlanApprovalStatus(row["status"])
            if current == target:
                self._conn.rollback()
                return ApprovalTransitionResult.UNCHANGED
            allowed = ALLOWED_APPROVAL_TRANSITIONS.get(current, frozenset())
            if target not in allowed or current not in expected:
                self._conn.rollback()
                return ApprovalTransitionResult.CONFLICT
            self._conn.execute(
                "UPDATE plan_approval_requests SET status = ? WHERE approval_request_id = ?",
                (target.value, approval_request_id),
            )
            if audit_event is not None:
                self._conn.execute(
                    """
                    INSERT INTO plan_approval_audit_events (
                        event_id, event_type, approval_request_id, plan_id, previous_status,
                        new_status, actor_id, actor_type, authenticated_source, timestamp,
                        reason_code, task_id, workspace_id, repository_id, correlation_id
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        audit_event.event_id, audit_event.event_type,
                        audit_event.approval_request_id, audit_event.plan_id,
                        audit_event.previous_status, audit_event.new_status,
                        audit_event.actor_id, audit_event.actor_type,
                        audit_event.authenticated_source, float(audit_event.timestamp),
                        audit_event.reason_code, audit_event.task_id,
                        audit_event.workspace_id, audit_event.repository_id,
                        audit_event.correlation_id,
                    ),
                )
            self._conn.commit()
            return ApprovalTransitionResult.UPDATED
        except Exception:
            self._conn.rollback()
            raise

    def set_request_broker(
        self, approval_request_id: str, broker_request_id: str, *, pending: bool = True
    ) -> bool:
        """Atomically attach a broker_request_id and flip registering→pending."""
        target = PlanApprovalStatus.PENDING if pending else PlanApprovalStatus.REGISTERING
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            row = self._conn.execute(
                "SELECT status FROM plan_approval_requests WHERE approval_request_id = ?",
                (approval_request_id,),
            ).fetchone()
            if row is None:
                self._conn.rollback()
                return False
            current = PlanApprovalStatus(row["status"])
            if pending and current != PlanApprovalStatus.REGISTERING:
                self._conn.rollback()
                return False
            self._conn.execute(
                "UPDATE plan_approval_requests SET broker_request_id = ?, status = ? "
                "WHERE approval_request_id = ?",
                (broker_request_id, target.value, approval_request_id),
            )
            self._conn.commit()
            return True
        except Exception:
            self._conn.rollback()
            raise

    def mark_expired(self, approval_request_id: str, *, now: float | None = None) -> ApprovalTransitionResult:
        """Move a request to ``expired`` if its TTL has elapsed."""
        now = time.time() if now is None else now
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            row = self._conn.execute(
                "SELECT status, expires_at FROM plan_approval_requests WHERE approval_request_id = ?",
                (approval_request_id,),
            ).fetchone()
            if row is None:
                self._conn.rollback()
                return ApprovalTransitionResult.NOT_FOUND
            current = PlanApprovalStatus(row["status"])
            if current.is_terminal and current != PlanApprovalStatus.EXPIRED:
                self._conn.rollback()
                return ApprovalTransitionResult.UNCHANGED
            if now < float(row["expires_at"]):
                self._conn.rollback()
                return ApprovalTransitionResult.UNCHANGED
            allowed = ALLOWED_APPROVAL_TRANSITIONS.get(current, frozenset())
            if PlanApprovalStatus.EXPIRED not in allowed:
                self._conn.rollback()
                return ApprovalTransitionResult.INVALID_TRANSITION
            self._conn.execute(
                "UPDATE plan_approval_requests SET status = ? WHERE approval_request_id = ?",
                (PlanApprovalStatus.EXPIRED.value, approval_request_id),
            )
            self._conn.commit()
            return ApprovalTransitionResult.UPDATED
        except Exception:
            self._conn.rollback()
            raise

    # ------------------------------------------------------------------
    # Decisions / Audit (read paths + standalone write for non-decision audit)
    # ------------------------------------------------------------------

    def insert_decision(self, decision: PlanApprovalDecision) -> None:
        self._conn.execute(
            """
            INSERT INTO plan_approval_decisions (
                approval_request_id, decision, actor_id, actor_type, decided_at,
                reason, authenticated_context, metadata
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                decision.approval_request_id,
                decision.decision.value,
                decision.actor_id,
                decision.actor_type,
                float(decision.decided_at),
                decision.reason,
                json.dumps(decision.authenticated_context, default=str, sort_keys=True),
                json.dumps(decision.metadata, default=str, sort_keys=True),
            ),
        )
        self._conn.commit()

    def insert_audit_event(self, event: PlanApprovalAuditEvent) -> None:
        self._conn.execute(
            """
            INSERT INTO plan_approval_audit_events (
                event_id, event_type, approval_request_id, plan_id, previous_status,
                new_status, actor_id, actor_type, authenticated_source, timestamp,
                reason_code, task_id, workspace_id, repository_id, correlation_id
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event.event_id, event.event_type, event.approval_request_id,
                event.plan_id, event.previous_status, event.new_status,
                event.actor_id, event.actor_type, event.authenticated_source,
                float(event.timestamp), event.reason_code, event.task_id,
                event.workspace_id, event.repository_id, event.correlation_id,
            ),
        )
        self._conn.commit()

    # ------------------------------------------------------------------
    # Execution authorizations
    # ------------------------------------------------------------------

    def insert_authorization(self, *args, **kwargs) -> None:
        """DISABLED (Batch 2.2 §2). Direct authorization insertion bypasses
        the gate's live validation + single-execution invariants.

        This public stub ALWAYS raises — it is retained only so accidental
        callers fail loudly instead of silently mutating the DB. The real
        mint path is :meth:`mint_authorization_if_request_active`, which is
        gate-internal and enforces all safety checks atomically.
        """
        raise PermissionError(
            "direct PlanApprovalStore.insert_authorization is disabled; "
            "use PlanExecutionGate.authorize_execution"
        )

    def consume_authorization(self, *args, **kwargs) -> bool:
        """DISABLED (Batch 2.2 §2). Direct authorization consumption bypasses
        the gate's live validation + request-consumption invariants.

        This public stub ALWAYS raises — retained so accidental callers fail
        loudly. The real consume path is
        :meth:`consume_authorization_with_request` (gate-internal) or the
        lease-based :meth:`PlanExecutionGate.acquire_lease`.
        """
        raise PermissionError(
            "direct PlanApprovalStore.consume_authorization is disabled; "
            "use PlanExecutionGate.acquire_lease / require_authorization"
        )

    def _verify_persisted_boot_context(
        self, *, server_epoch: int, boot_id: str,
    ) -> bool:
        """Verify the supplied epoch + boot_id match the persisted singleton.

        Batch 2.5 §2: must be called INSIDE a ``BEGIN IMMEDIATE`` transaction.
        Returns True if both match; False otherwise. This prevents a stale
        runtime (whose cached epoch/boot_id no longer matches the persisted
        state) from minting, consuming, or validating.
        """
        row = self._conn.execute(
            "SELECT current_epoch, boot_id FROM plan_execution_server_state "
            "WHERE singleton_key = 'global'"
        ).fetchone()
        if row is None:
            return False
        return int(row["current_epoch"]) == int(server_epoch) and str(row["boot_id"]) == boot_id

    def mint_authorization_if_request_active(
        self,
        auth: PlanExecutionAuthorization,
        *,
        server_epoch: int,
        boot_id: str = "",
        expected_binding_digest: str,
        audit_event: PlanApprovalAuditEvent | None = None,
        now: float,
    ) -> tuple[bool, PlanExecutionAuthorization | None]:
        """Serialize minting with invalidation on a shared connection.

        A ``CONSUMED`` request is never mintable; the locked implementation
        performs that authoritative check before any authorization insert.

        SQLite serializes ``BEGIN IMMEDIATE`` across connections, but a
        single ``sqlite3.Connection`` has one transaction state shared by all
        threads using it. The runtime and test harness may intentionally share
        a connection, so the lock closes that second concurrency boundary.
        """
        with self._transaction_lock:
            return self._mint_authorization_if_request_active(
                auth,
                server_epoch=server_epoch,
                boot_id=boot_id,
                expected_binding_digest=expected_binding_digest,
                audit_event=audit_event,
                now=now,
            )

    def _mint_authorization_if_request_active(
        self,
        auth: PlanExecutionAuthorization,
        *,
        server_epoch: int,
        boot_id: str = "",
        expected_binding_digest: str,
        audit_event: PlanApprovalAuditEvent | None = None,
        now: float,
    ) -> tuple[bool, PlanExecutionAuthorization | None]:
        """Atomically mint an authorization only if the request is still
        APPROVED/NOT_REQUIRED and no prior ACTIVE/CONSUMED authorization exists.

        Batch 2.5 §2: verifies the supplied ``server_epoch`` AND ``boot_id``
        match the persisted ``plan_execution_server_state`` singleton — a
        stale runtime whose cached epoch/boot_id no longer match cannot mint.

        Returns ``(True, auth)`` on a fresh mint, ``(True, existing)`` if an
        ACTIVE authorization already exists for this request (idempotent —
        returns the existing server handle, nonce blank because we no longer
        have it in scope), or ``(False, None)`` if the request state forbids
        a new authorization (already consumed / not approved / expired / etc).

        The partial unique index ``uq_plan_exec_auth_active_per_request``
        provides defense-in-depth at the DB level.
        """
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            # Batch 2.5 §2: verify persisted boot context first.
            if not self._verify_persisted_boot_context(
                server_epoch=server_epoch, boot_id=boot_id,
            ):
                self._conn.rollback()
                return False, None
            req = self._conn.execute(
                "SELECT status, expires_at, binding_digest FROM plan_approval_requests "
                "WHERE approval_request_id = ?",
                (auth.approval_request_id,),
            ).fetchone()
            if req is None:
                self._conn.rollback()
                return False, None
            status = PlanApprovalStatus(req["status"])
            if status not in (PlanApprovalStatus.APPROVED, PlanApprovalStatus.NOT_REQUIRED):
                self._conn.rollback()
                return False, None
            if now >= float(req["expires_at"]):
                self._conn.rollback()
                return False, None
            if req["binding_digest"] != expected_binding_digest:
                self._conn.rollback()
                return False, None

            # Is there an existing ACTIVE or CONSUMED authorization? A CONSUMED
            # one means this approval has already executed once → refuse.
            existing = self._conn.execute(
                "SELECT * FROM plan_execution_authorizations "
                "WHERE approval_request_id = ? AND status IN (?, ?) "
                "ORDER BY issued_at DESC LIMIT 1",
                (auth.approval_request_id, AuthorizationStatus.ACTIVE.value, AuthorizationStatus.CONSUMED.value),
            ).fetchone()
            if existing is not None:
                if existing["status"] == AuthorizationStatus.CONSUMED.value:
                    self._conn.rollback()
                    return False, None
                # ACTIVE — return the same handle (idempotent re-mint).
                self._conn.rollback()
                return True, self._read_model.row_to_authorization(existing)

            self._conn.execute(
                """
                INSERT INTO plan_execution_authorizations (
                    authorization_id, approval_request_id, plan_id, plan_content_hash,
                    repository_id, task_id, workspace_id, base_sha, repository_generation,
                    issued_at, expires_at, nonce_hash, binding_digest, status, server_epoch, boot_id
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    auth.authorization_id, auth.approval_request_id, auth.plan_id,
                    auth.plan_content_hash, auth.repository_id, auth.task_id,
                    auth.workspace_id, auth.base_sha, int(auth.repository_generation),
                    float(auth.issued_at), float(auth.expires_at), auth.nonce_hash,
                    auth.binding_digest, auth.status.value, int(server_epoch), boot_id,
                ),
            )
            if audit_event is not None:
                self._conn.execute(
                    """
                    INSERT INTO plan_approval_audit_events (
                        event_id, event_type, approval_request_id, plan_id, previous_status,
                        new_status, actor_id, actor_type, authenticated_source, timestamp,
                        reason_code, task_id, workspace_id, repository_id, correlation_id
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        audit_event.event_id, audit_event.event_type,
                        audit_event.approval_request_id, audit_event.plan_id,
                        audit_event.previous_status, audit_event.new_status,
                        audit_event.actor_id, audit_event.actor_type,
                        audit_event.authenticated_source, float(audit_event.timestamp),
                        audit_event.reason_code, audit_event.task_id,
                        audit_event.workspace_id, audit_event.repository_id,
                        audit_event.correlation_id,
                    ),
                )
            self._conn.commit()
            return True, auth
        except Exception:
            self._conn.rollback()
            raise

    def consume_authorization_with_request(
        self,
        authorization_id: str,
        *,
        nonce: str,
        expected_plan_id: str,
        expected_task_id: str,
        expected_workspace_id: str,
        expected_repository_id: str,
        expected_binding_digest: str,
        current_server_epoch: int,
        current_boot_id: str = "",
        audit_event: PlanApprovalAuditEvent | None = None,
        now: float,
    ) -> bool:
        """Atomically consume an authorization AND flip its request to CONSUMED.

        Verifies (all within one ``BEGIN IMMEDIATE``):
        1. Persisted boot context matches supplied epoch + boot_id (§2).
        2. Authorization exists, is ACTIVE, and belongs to the caller's scope.
        3. The nonce hashes to the stored ``nonce_hash``.
        4. The authorization has not expired and its ``server_epoch`` +
           ``boot_id`` match the current boot (restart-invalidation).
        5. The bound binding digest equals ``expected_binding_digest`` (drift
           check at consume time — §6).
        6. The request is still APPROVED/NOT_REQUIRED.

        On success: authorization → CONSUMED, request → CONSUMED, audit
        written, all committed atomically. Any mismatch rolls back.
        """
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            # Batch 2.5 §2: verify persisted boot context first.
            if not self._verify_persisted_boot_context(
                server_epoch=current_server_epoch, boot_id=current_boot_id,
            ):
                self._conn.rollback()
                return False
            row = self._conn.execute(
                "SELECT * FROM plan_execution_authorizations WHERE authorization_id = ?",
                (authorization_id,),
            ).fetchone()
            if row is None:
                self._conn.rollback()
                return False
            if row["status"] != AuthorizationStatus.ACTIVE.value:
                self._conn.rollback()
                return False
            if (
                row["plan_id"] != expected_plan_id
                or row["task_id"] != expected_task_id
                or row["workspace_id"] != expected_workspace_id
                or row["repository_id"] != expected_repository_id
            ):
                self._conn.rollback()
                return False
            if int(row["server_epoch"]) != int(current_server_epoch) or str(row["boot_id"]) != current_boot_id:
                # Restart-invalidation: authorization minted under a prior boot.
                self._conn.execute(
                    "UPDATE plan_execution_authorizations SET status = ? WHERE authorization_id = ?",
                    (AuthorizationStatus.REVOKED.value, authorization_id),
                )
                self._conn.commit()
                return False
            if not verify_nonce(nonce, row["nonce_hash"]):
                self._conn.rollback()
                return False
            if now >= float(row["expires_at"]):
                self._conn.execute(
                    "UPDATE plan_execution_authorizations SET status = ? WHERE authorization_id = ?",
                    (AuthorizationStatus.EXPIRED.value, authorization_id),
                )
                self._conn.commit()
                return False
            if row["binding_digest"] != expected_binding_digest:
                self._conn.rollback()
                return False

            # Request must still be in an executable state.
            req = self._conn.execute(
                "SELECT status FROM plan_approval_requests WHERE approval_request_id = ?",
                (row["approval_request_id"],),
            ).fetchone()
            if req is None:
                self._conn.rollback()
                return False
            req_status = PlanApprovalStatus(req["status"])
            if req_status not in (PlanApprovalStatus.APPROVED, PlanApprovalStatus.NOT_REQUIRED):
                self._conn.rollback()
                return False

            # Flip both atomically.
            self._conn.execute(
                "UPDATE plan_execution_authorizations SET status = ? WHERE authorization_id = ?",
                (AuthorizationStatus.CONSUMED.value, authorization_id),
            )
            self._conn.execute(
                "UPDATE plan_approval_requests SET status = ? WHERE approval_request_id = ?",
                (PlanApprovalStatus.CONSUMED.value, row["approval_request_id"]),
            )
            if audit_event is not None:
                self._conn.execute(
                    """
                    INSERT INTO plan_approval_audit_events (
                        event_id, event_type, approval_request_id, plan_id, previous_status,
                        new_status, actor_id, actor_type, authenticated_source, timestamp,
                        reason_code, task_id, workspace_id, repository_id, correlation_id
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        audit_event.event_id, audit_event.event_type,
                        audit_event.approval_request_id, audit_event.plan_id,
                        audit_event.previous_status, audit_event.new_status,
                        audit_event.actor_id, audit_event.actor_type,
                        audit_event.authenticated_source, float(audit_event.timestamp),
                        audit_event.reason_code, audit_event.task_id,
                        audit_event.workspace_id, audit_event.repository_id,
                        audit_event.correlation_id,
                    ),
                )
            self._conn.commit()
            return True
        except Exception:
            self._conn.rollback()
            raise

    def revoke_authorization(
        self, authorization_id: str, *,
        current_server_epoch: int = 0, current_boot_id: str = "",
    ) -> bool:
        """Externally invalidate an authorization (e.g. on Task cancel).

        Batch 2.5 §2: verifies the persisted boot context before revoking.
        A stale runtime cannot revoke authorizations from a newer boot.
        """
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            if not self._verify_persisted_boot_context(
                server_epoch=current_server_epoch, boot_id=current_boot_id,
            ):
                self._conn.rollback()
                return False
            row = self._conn.execute(
                "SELECT status FROM plan_execution_authorizations WHERE authorization_id = ?",
                (authorization_id,),
            ).fetchone()
            if row is None:
                self._conn.rollback()
                return False
            if row["status"] != AuthorizationStatus.ACTIVE.value:
                self._conn.rollback()
                return False
            self._conn.execute(
                "UPDATE plan_execution_authorizations SET status = ? WHERE authorization_id = ?",
                (AuthorizationStatus.REVOKED.value, authorization_id),
            )
            self._conn.commit()
            return True
        except Exception:
            self._conn.rollback()
            raise

    def revoke_authorizations_for_request(self, approval_request_id: str) -> int:
        """Revoke every still-active authorization tied to a request."""
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            cur = self._conn.execute(
                "UPDATE plan_execution_authorizations SET status = ? "
                "WHERE approval_request_id = ? AND status = ?",
                (AuthorizationStatus.REVOKED.value, approval_request_id, AuthorizationStatus.ACTIVE.value),
            )
            count = int(cur.rowcount or 0)
            self._conn.commit()
            return count
        except Exception:
            self._conn.rollback()
            raise

    def revoke_authorizations_outside_epoch(self, current_epoch: int) -> int:
        """Bulk-revoke every ACTIVE authorization minted under a prior epoch.

        Called at process startup once the gate has rotated its epoch. This is
        the authoritative restart-invalidation mechanism (§8) — it does NOT
        rely on the in-memory nonce being lost.
        """
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            cur = self._conn.execute(
                "UPDATE plan_execution_authorizations SET status = ? "
                "WHERE status = ? AND server_epoch != ?",
                (AuthorizationStatus.REVOKED.value, AuthorizationStatus.ACTIVE.value, int(current_epoch)),
            )
            count = int(cur.rowcount or 0)
            self._conn.commit()
            return count
        except Exception:
            self._conn.rollback()
            raise

    def refresh_expiry(self, approval_request_id: str, new_expiry: float) -> None:
        conn = self._conn
        conn.execute(
            "UPDATE plan_approval_requests SET expires_at = ? WHERE approval_request_id = ?",
            (float(new_expiry), approval_request_id),
        )
        conn.commit()

    # ------------------------------------------------------------------
    # Persisted server epoch (Batch 2.2 §3)
    # ------------------------------------------------------------------

    def get_current_epoch(self) -> tuple[int, str]:
        """Return ``(current_epoch, boot_id)`` from the persisted singleton.

        Initializes the row to epoch 0 / empty boot_id on first call.
        """
        row = self._conn.execute(
            "SELECT current_epoch, boot_id FROM plan_execution_server_state WHERE singleton_key = 'global'"
        ).fetchone()
        if row is None:
            self._conn.execute(
                "INSERT INTO plan_execution_server_state (singleton_key, current_epoch, boot_id, updated_at) "
                "VALUES ('global', 0, '', ?)",
                (time.time(),),
            )
            self._conn.commit()
            return 0, ""
        return int(row["current_epoch"]), str(row["boot_id"])

    def rotate_epoch(self, *, now: float | None = None) -> tuple[int, str, int]:
        """Atomically increment the persisted epoch and generate a fresh boot_id.

        ONE ``BEGIN IMMEDIATE``: read current epoch, increment, generate
        boot_id, persist, revoke all ACTIVE authorizations outside the new
        epoch → COMMIT. Returns ``(new_epoch, new_boot_id, revoked_count)``.

        Concurrent startup: two calls race on the singleton row; BEGIN
        IMMEDIATE serializes them so the epoch increments twice and only the
        latest boot_id can mint/consume.
        """
        now = time.time() if now is None else now
        new_boot_id = uuid.uuid4().hex
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            row = self._conn.execute(
                "SELECT current_epoch,boot_id FROM plan_execution_server_state WHERE singleton_key = 'global'"
            ).fetchone()
            if row is None:
                new_epoch = 1
                self._conn.execute(
                    "INSERT INTO plan_execution_server_state (singleton_key, current_epoch, boot_id, updated_at) "
                    "VALUES ('global', ?, ?, ?)",
                    (new_epoch, new_boot_id, now),
                )
            else:
                new_epoch = int(row["current_epoch"]) + 1
                self._conn.execute(
                    "UPDATE approval_runtime_boots SET replaced_at=? "
                    "WHERE boot_id=? AND replaced_at IS NULL",
                    (now, str(row["boot_id"])),
                )
                self._conn.execute(
                    "UPDATE plan_execution_server_state SET current_epoch = ?, boot_id = ?, updated_at = ? "
                    "WHERE singleton_key = 'global'",
                    (new_epoch, new_boot_id, now),
                )
            self._conn.execute(
                "INSERT INTO approval_runtime_boots "
                "(server_epoch,boot_id,started_at,replaced_at) VALUES (?,?,?,NULL)",
                (new_epoch, new_boot_id, now),
            )
            # Revoke all ACTIVE authorizations from prior epochs.
            cur = self._conn.execute(
                "UPDATE plan_execution_authorizations SET status = ? "
                "WHERE status = ? AND server_epoch != ?",
                (AuthorizationStatus.REVOKED.value, AuthorizationStatus.ACTIVE.value, new_epoch),
            )
            revoked = int(cur.rowcount or 0)
            # Batch 2.3: also release all ACTIVE leases from prior epochs so a
            # restart does not leave stale leases permanently blocking a workspace.
            self._conn.execute(
                "UPDATE plan_execution_leases SET status = 'expired' "
                "WHERE status = 'active' AND server_epoch != ?",
                (new_epoch,),
            )
            self._conn.commit()
            return new_epoch, new_boot_id, revoked
        except Exception:
            self._conn.rollback()
            raise

    # ------------------------------------------------------------------
    # Persisted plan snapshots (Batch 2.2 §4)
    # ------------------------------------------------------------------

    def save_plan_snapshot(
        self,
        *,
        plan_id: str,
        content_hash: str,
        binding_digest: str,
        repository_id: str,
        task_id: str,
        workspace_id: str,
        canonical_plan_json: str,
        schema_version: str = "khaos.planning.v1",
        now: float | None = None,
    ) -> bool:
        """Persist an authoritative plan snapshot.

        Returns True on insert, False if a snapshot with the SAME plan_id and
        DIFFERENT content_hash already existed (refused — a plan_id cannot be
        silently replaced with different content; use a new plan_id or
        explicit revision).
        """
        now = time.time() if now is None else now
        existing = self._conn.execute(
            "SELECT content_hash FROM plan_snapshots WHERE plan_id = ?",
            (plan_id,),
        ).fetchone()
        if existing is not None and existing["content_hash"] != content_hash:
            return False
        self._conn.execute(
            """
            INSERT INTO plan_snapshots (
                plan_id, content_hash, binding_digest, repository_id, task_id,
                workspace_id, schema_version, canonical_plan_json, created_at, status
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'active')
            ON CONFLICT(plan_id) DO UPDATE SET status = 'active'
            """,
            (
                plan_id, content_hash, binding_digest, repository_id, task_id,
                workspace_id, schema_version, canonical_plan_json, now,
            ),
        )
        self._conn.commit()
        return True

    def load_plan_snapshot(self, plan_id: str) -> tuple[str, str, str, str] | None:
        """Return canonical JSON, content hash, binding digest and schema for
        a plan_id, or None."""
        row = self._conn.execute(
            "SELECT canonical_plan_json, content_hash, binding_digest, schema_version FROM plan_snapshots "
            "WHERE plan_id = ? AND status = 'active'",
            (plan_id,),
        ).fetchone()
        if row is None:
            return None
        return str(row["canonical_plan_json"]), str(row["content_hash"]), str(row["binding_digest"]), str(row["schema_version"])

    # ------------------------------------------------------------------
    # Atomic request + authorization invalidation (Batch 2.2 §6)
    # ------------------------------------------------------------------

    def invalidate_request_authorizations_leases_and_receipt(
        self,
        request_id: str,
        *,
        target_status: PlanApprovalStatus,
        expected_statuses: set[PlanApprovalStatus],
        audit_event: PlanApprovalAuditEvent | None = None,
        now: float | None = None,
    ) -> ApprovalTransitionResult:
        """Serialize invalidation with concurrent authorization minting."""
        with self._transaction_lock:
            return self._invalidate_request_authorizations_leases_and_receipt(
                request_id,
                target_status=target_status,
                expected_statuses=expected_statuses,
                audit_event=audit_event,
                now=now,
            )

    def _invalidate_request_authorizations_leases_and_receipt(
        self,
        request_id: str,
        *,
        target_status: PlanApprovalStatus,
        expected_statuses: set[PlanApprovalStatus],
        audit_event: PlanApprovalAuditEvent | None = None,
        now: float | None = None,
    ) -> ApprovalTransitionResult:
        """Atomically transition a request AND revoke all its ACTIVE
        authorizations AND release all its ACTIVE leases in ONE
        ``BEGIN IMMEDIATE`` (Batch 2.3 §8).

        Replaces the non-atomic compositions in revoke / invalidate_for_task
        / _mark_authorization_stale. Guarantees no request=stale/revoked/
        expired can coexist with an active authorization OR an active lease.
        """
        if self._conn.in_transaction:
            self._conn.commit()
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            row = self._conn.execute(
                "SELECT status, workspace_id FROM plan_approval_requests WHERE approval_request_id = ?",
                (request_id,),
            ).fetchone()
            if row is None:
                self._conn.rollback()
                return ApprovalTransitionResult.NOT_FOUND
            workspace_id = row["workspace_id"]
            current = PlanApprovalStatus(row["status"])
            if current == target_status:
                # Still revoke any stray active authorizations (idempotent).
                self._conn.execute(
                    "UPDATE plan_execution_authorizations SET status = ? "
                    "WHERE approval_request_id = ? AND status = ?",
                    (AuthorizationStatus.REVOKED.value, request_id, AuthorizationStatus.ACTIVE.value),
                )
                # Batch 2.3: also release any active leases on this workspace.
                self._conn.execute(
                    "UPDATE plan_execution_leases SET status = 'expired' "
                    "WHERE workspace_id = ? AND status = 'active'",
                    (workspace_id,),
                )
                self._conn.execute("UPDATE plan_approval_receipts SET consumed=1 WHERE approval_request_id=?", (request_id,))
                if audit_event is not None:
                    self._conn.execute(
                        """
                        INSERT INTO plan_approval_audit_events (
                            event_id, event_type, approval_request_id, plan_id, previous_status,
                            new_status, actor_id, actor_type, authenticated_source, timestamp,
                            reason_code, task_id, workspace_id, repository_id, correlation_id
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            audit_event.event_id, audit_event.event_type,
                            audit_event.approval_request_id, audit_event.plan_id,
                            audit_event.previous_status, audit_event.new_status,
                            audit_event.actor_id, audit_event.actor_type,
                            audit_event.authenticated_source, float(audit_event.timestamp),
                            audit_event.reason_code, audit_event.task_id,
                            audit_event.workspace_id, audit_event.repository_id,
                            audit_event.correlation_id,
                        ),
                    )
                self._conn.commit()
                return ApprovalTransitionResult.UNCHANGED
            if current not in expected_statuses:
                self._conn.rollback()
                return ApprovalTransitionResult.CONFLICT
            allowed = ALLOWED_APPROVAL_TRANSITIONS.get(current, frozenset())
            if target_status not in allowed:
                self._conn.rollback()
                return ApprovalTransitionResult.CONFLICT
            self._conn.execute(
                "UPDATE plan_approval_requests SET status = ? WHERE approval_request_id = ?",
                (target_status.value, request_id),
            )
            self._conn.execute(
                "UPDATE plan_execution_authorizations SET status = ? "
                "WHERE approval_request_id = ? AND status = ?",
                (AuthorizationStatus.REVOKED.value, request_id, AuthorizationStatus.ACTIVE.value),
            )
            # Batch 2.3: release all active leases on this workspace too.
            self._conn.execute(
                "UPDATE plan_execution_leases SET status = 'expired' "
                "WHERE workspace_id = ? AND status = 'active'",
                (workspace_id,),
            )
            self._conn.execute("UPDATE plan_approval_receipts SET consumed=1 WHERE approval_request_id=?", (request_id,))
            if audit_event is not None:
                self._conn.execute(
                    """
                    INSERT INTO plan_approval_audit_events (
                        event_id, event_type, approval_request_id, plan_id, previous_status,
                        new_status, actor_id, actor_type, authenticated_source, timestamp,
                        reason_code, task_id, workspace_id, repository_id, correlation_id
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        audit_event.event_id, audit_event.event_type,
                        audit_event.approval_request_id, audit_event.plan_id,
                        audit_event.previous_status, audit_event.new_status,
                        audit_event.actor_id, audit_event.actor_type,
                        audit_event.authenticated_source, float(audit_event.timestamp),
                        audit_event.reason_code, audit_event.task_id,
                        audit_event.workspace_id, audit_event.repository_id,
                        audit_event.correlation_id,
                    ),
                )
            self._conn.commit()
            return ApprovalTransitionResult.UPDATED
        except Exception:
            self._conn.rollback()
            raise

    def invalidate_request_and_authorizations(self, *args: Any, **kwargs: Any) -> ApprovalTransitionResult:
        """Backward-compatible name delegating to the unified transaction."""
        return self.invalidate_request_authorizations_leases_and_receipt(*args, **kwargs)

    # ------------------------------------------------------------------
    # Execution leases (Batch 2.2 §7)
    # ------------------------------------------------------------------

    def acquire_lease(
        self,
        *,
        lease_id: str,
        task_id: str,
        workspace_id: str,
        repository_id: str,
        plan_id: str,
        head_sha: str,
        repository_generation: int,
        evidence_digest: str,
        binding_digest: str,
        authorization_id: str,
        owner_execution_id: str,
        expiry: float,
        server_epoch: int = 0,
        now: float | None = None,
    ) -> bool:
        """Atomically acquire an exclusive workspace execution lease.

        The partial unique index ``uq_plan_execution_leases_active_workspace``
        ensures at most one ACTIVE lease per workspace — a concurrent acquire
        on the same workspace fails with IntegrityError.
        """
        now = time.time() if now is None else now
        try:
            self._conn.execute(
                """
                INSERT INTO plan_execution_leases (
                    lease_id, task_id, workspace_id, repository_id, plan_id,
                    head_sha, repository_generation, evidence_digest, binding_digest,
                    authorization_id, expiry, owner_execution_id, status, server_epoch, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'active', ?, ?)
                """,
                (
                    lease_id, task_id, workspace_id, repository_id, plan_id,
                    head_sha, int(repository_generation), evidence_digest, binding_digest,
                    authorization_id, float(expiry), owner_execution_id, int(server_epoch), now,
                ),
            )
            self._conn.commit()
            return True
        except sqlite3.IntegrityError:
            # Another ACTIVE lease already holds this workspace.
            self._conn.rollback()
            return False

    def release_lease(
        self, lease_id: str, *,
        current_server_epoch: int = 0, current_boot_id: str = "",
    ) -> bool:
        """Release (mark released) an execution lease.

        Batch 2.5 §2: verifies the persisted boot context before releasing.
        A stale runtime cannot release leases from a newer boot.
        """
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            if not self._verify_persisted_boot_context(
                server_epoch=current_server_epoch, boot_id=current_boot_id,
            ):
                self._conn.rollback()
                return False
            cur = self._conn.execute(
                "UPDATE plan_execution_leases SET status = 'released' "
                "WHERE lease_id = ? AND status = 'active'",
                (lease_id,),
            )
            ok = int(cur.rowcount or 0) > 0
            if ok:
                lease = self._conn.execute(
                    "SELECT workspace_id FROM plan_execution_leases WHERE lease_id=?",
                    (lease_id,),
                ).fetchone()
                self._conn.execute(
                    "INSERT INTO workspace_mutation_audit "
                    "(event_id,workspace_id,lease_id,event_type,reason,created_at) "
                    "VALUES (?,?,?,?,?,?)",
                    (uuid.uuid4().hex, str(lease["workspace_id"]), lease_id,
                     "released", "context-exit", time.time()),
                )
            self._conn.commit()
            return ok
        except Exception:
            self._conn.rollback()
            raise

    def get_lease(self, lease_id: str) -> sqlite3.Row | None:
        return self._conn.execute(
            "SELECT * FROM plan_execution_leases WHERE lease_id = ?",
            (lease_id,),
        ).fetchone()

    def active_lease_scope_for_task(self, task_id: str) -> str | None:
        """Resolve a task's unique ACTIVE workspace from durable leases."""
        rows = self._conn.execute(
            "SELECT DISTINCT workspace_id FROM plan_execution_leases "
            "WHERE task_id=? AND status='active' ORDER BY workspace_id",
            (task_id,),
        ).fetchall()
        if len(rows) > 1:
            raise RuntimeError("task has ACTIVE leases in multiple workspaces")
        return None if not rows else str(rows[0]["workspace_id"])

    def validate_repository_workspace_scope(
        self, repository_id: str, workspace_id: str
    ) -> bool:
        """Reject ambiguity while validating an explicit mutation scope."""
        rows = self._conn.execute(
            "SELECT DISTINCT workspace_id FROM plan_execution_leases "
            "WHERE repository_id=? AND status='active' ORDER BY workspace_id",
            (repository_id,),
        ).fetchall()
        active = {str(row["workspace_id"]) for row in rows}
        return not active or workspace_id in active

    def poison_workspace(self, workspace_id: str, lease_id: str, *, reason: str) -> None:
        """Persist quarantine before a failed release exits the fence."""
        now = time.time()
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            self._conn.execute(
                "INSERT OR REPLACE INTO workspace_mutation_poison "
                "(workspace_id,lease_id,reason,poisoned_at) VALUES (?,?,?,?)",
                (workspace_id, lease_id, reason, now),
            )
            self._conn.execute(
                "INSERT INTO workspace_mutation_audit "
                "(event_id,workspace_id,lease_id,event_type,reason,created_at) "
                "VALUES (?,?,?,?,?,?)",
                (uuid.uuid4().hex, workspace_id, lease_id, "poisoned", reason, now),
            )
            self._conn.commit()
        except Exception:
            self._conn.rollback()
            raise

    def list_poisoned_workspaces(self) -> tuple[tuple[str, str], ...]:
        rows = self._conn.execute(
            "SELECT workspace_id,reason FROM workspace_mutation_poison "
            "ORDER BY workspace_id"
        ).fetchall()
        return tuple((str(row["workspace_id"]), str(row["reason"])) for row in rows)

    def add_workspace_poison_scope(
        self, workspace_id: CanonicalWorkspaceId, *, owner: str, reason: str
    ) -> None:
        self._conn.execute(
            "INSERT OR REPLACE INTO workspace_mutation_poison_scopes "
            "(workspace_id,poison_owner,reason,poisoned_at) VALUES (?,?,?,?)",
            (workspace_id, owner, reason, time.time()),
        )
        self._conn.commit()

    def clear_workspace_poison_scope(
        self, workspace_id: CanonicalWorkspaceId, *, owner: str
    ) -> bool:
        cur = self._conn.execute(
            "DELETE FROM workspace_mutation_poison_scopes "
            "WHERE workspace_id=? AND poison_owner=?",
            (workspace_id, owner),
        )
        self._conn.commit()
        return int(cur.rowcount or 0) == 1

    def list_workspace_poison_scopes(
        self, workspace_id: str | None = None
    ) -> tuple[tuple[str, str, str], ...]:
        if workspace_id is None:
            rows = self._conn.execute(
                "SELECT workspace_id,poison_owner,reason "
                "FROM workspace_mutation_poison_scopes "
                "ORDER BY workspace_id,poison_owner"
            ).fetchall()
        else:
            rows = self._conn.execute(
                "SELECT workspace_id,poison_owner,reason "
                "FROM workspace_mutation_poison_scopes WHERE workspace_id=? "
                "ORDER BY poison_owner", (workspace_id,),
            ).fetchall()
        return tuple(
            (str(row["workspace_id"]), str(row["poison_owner"]), str(row["reason"]))
            for row in rows
        )

    def reconcile_terminal_run_poison_scopes(self) -> tuple[tuple[str, str], ...]:
        rows = self._conn.execute(
            "SELECT p.workspace_id,p.poison_owner FROM workspace_mutation_poison_scopes p "
            "JOIN plan_execution_runs r ON p.poison_owner='run:' || r.execution_run_id "
            "WHERE r.status IN ('mutated','rolled-back','cancelled') "
            "AND r.terminal_tombstone_digest != ''"
        ).fetchall()
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            for row in rows:
                self._conn.execute(
                    "DELETE FROM workspace_mutation_poison_scopes WHERE workspace_id=? AND poison_owner=?",
                    (row["workspace_id"], row["poison_owner"]),
                )
            self._conn.commit()
        except Exception:
            self._conn.rollback()
            raise
        return tuple((str(row["workspace_id"]), str(row["poison_owner"])) for row in rows)

    def recover_poisoned_workspace(
        self, workspace_id: str, *, force: bool = False, now: float | None = None
    ) -> bool:
        """Expire the quarantined lease, clear poison, and write recovery audit."""
        now = time.time() if now is None else now
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            poison = self._conn.execute(
                "SELECT lease_id,reason FROM workspace_mutation_poison WHERE workspace_id=?",
                (workspace_id,),
            ).fetchone()
            if poison is None:
                self._conn.rollback()
                return False
            lease = self._conn.execute(
                "SELECT status,expiry FROM plan_execution_leases WHERE lease_id=?",
                (poison["lease_id"],),
            ).fetchone()
            if (lease is not None and lease["status"] == "active"
                    and float(lease["expiry"]) > now and not force):
                self._conn.rollback()
                raise RuntimeError("active poisoned lease has not expired")
            self._conn.execute(
                "UPDATE plan_execution_leases SET status='expired' "
                "WHERE lease_id=? AND status='active'",
                (poison["lease_id"],),
            )
            self._conn.execute(
                "DELETE FROM workspace_mutation_poison WHERE workspace_id=?",
                (workspace_id,),
            )
            self._conn.execute(
                "INSERT INTO workspace_mutation_audit "
                "(event_id,workspace_id,lease_id,event_type,reason,created_at) "
                "VALUES (?,?,?,?,?,?)",
                (uuid.uuid4().hex, workspace_id, poison["lease_id"],
                 "recovered", "forced" if force else "expired", now),
            )
            self._conn.commit()
            return True
        except Exception:
            self._conn.rollback()
            raise

    # ------------------------------------------------------------------
    # Lease-first atomic consume (Batch 2.3 §1) — the single transaction
    # ------------------------------------------------------------------

    def acquire_execution_lease_and_consume(
        self,
        *,
        authorization_id: str,
        nonce: str,
        expected_plan_id: str,
        expected_task_id: str,
        expected_workspace_id: str,
        expected_repository_id: str,
        expected_binding_digest: str,
        current_server_epoch: int,
        current_boot_id: str = "",
        lease_id: str,
        owner_execution_id: str,
        head_sha: str,
        repository_generation: int,
        evidence_digest: str,
        audit_event: PlanApprovalAuditEvent | None,
        now: float,
    ) -> bool:
        """Lease-first atomic consume: ONE ``BEGIN IMMEDIATE`` does ALL of:

        1. Verify persisted boot context matches supplied epoch + boot_id (§2).
        2. Read authorization; verify ACTIVE, scope, nonce, epoch, boot_id,
           expiry, binding.
        3. Read approval request; verify APPROVED/NOT_REQUIRED.
        4. Confirm workspace has NO existing ACTIVE lease (else rollback).
        5. Insert ACTIVE lease (stamped with current epoch + boot_id).
        6. Authorization → CONSUMED.
        7. Request → CONSUMED.
        8. Insert audit event.
        9. COMMIT.

        Any step failing rolls back the ENTIRE transaction: the authorization
        stays ACTIVE, the request stays APPROVED/NOT_REQUIRED, no lease row
        exists, no audit row exists. This closes the TOCTOU between consume
        and lease-acquire that the old two-step path had.
        """
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            # 1. Batch 2.5 §2: verify persisted boot context first.
            if not self._verify_persisted_boot_context(
                server_epoch=current_server_epoch, boot_id=current_boot_id,
            ):
                self._conn.rollback()
                return False
            # 2. Read + verify the authorization.
            auth_row = self._conn.execute(
                "SELECT * FROM plan_execution_authorizations WHERE authorization_id = ?",
                (authorization_id,),
            ).fetchone()
            if auth_row is None:
                self._conn.rollback()
                return False
            if auth_row["status"] != AuthorizationStatus.ACTIVE.value:
                self._conn.rollback()
                return False
            if (
                auth_row["plan_id"] != expected_plan_id
                or auth_row["task_id"] != expected_task_id
                or auth_row["workspace_id"] != expected_workspace_id
                or auth_row["repository_id"] != expected_repository_id
            ):
                self._conn.rollback()
                return False
            if int(auth_row["server_epoch"]) != int(current_server_epoch) or str(auth_row["boot_id"]) != current_boot_id:
                self._conn.rollback()
                return False
            if not verify_nonce(nonce, auth_row["nonce_hash"]):
                self._conn.rollback()
                return False
            if now >= float(auth_row["expires_at"]):
                self._conn.rollback()
                return False
            if auth_row["binding_digest"] != expected_binding_digest:
                self._conn.rollback()
                return False

            # 3. Read + verify the approval request.
            req_row = self._conn.execute(
                "SELECT status FROM plan_approval_requests WHERE approval_request_id = ?",
                (auth_row["approval_request_id"],),
            ).fetchone()
            if req_row is None:
                self._conn.rollback()
                return False
            req_status = PlanApprovalStatus(req_row["status"])
            if req_status not in (PlanApprovalStatus.APPROVED, PlanApprovalStatus.NOT_REQUIRED):
                self._conn.rollback()
                return False

            # 4 + 5. Insert the ACTIVE lease. The partial unique index
            # uq_plan_execution_leases_active_workspace makes a conflicting
            # ACTIVE lease raise IntegrityError → rollback (no consume).
            self._conn.execute(
                """
                INSERT INTO plan_execution_leases (
                    lease_id, task_id, workspace_id, repository_id, plan_id,
                    head_sha, repository_generation, evidence_digest, binding_digest,
                    authorization_id, expiry, owner_execution_id, status, server_epoch, boot_id, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'active', ?, ?, ?)
                """,
                (
                    lease_id, expected_task_id, expected_workspace_id, expected_repository_id,
                    expected_plan_id, head_sha, int(repository_generation),
                    evidence_digest, expected_binding_digest, authorization_id,
                    float(auth_row["expires_at"]), owner_execution_id,
                    int(current_server_epoch), current_boot_id, now,
                ),
            )

            # 5. Authorization → CONSUMED.
            self._conn.execute(
                "UPDATE plan_execution_authorizations SET status = ? WHERE authorization_id = ?",
                (AuthorizationStatus.CONSUMED.value, authorization_id),
            )
            # 6. Request → CONSUMED.
            self._conn.execute(
                "UPDATE plan_approval_requests SET status = ? WHERE approval_request_id = ?",
                (PlanApprovalStatus.CONSUMED.value, auth_row["approval_request_id"]),
            )
            # 7. Audit.
            if audit_event is not None:
                self._conn.execute(
                    """
                    INSERT INTO plan_approval_audit_events (
                        event_id, event_type, approval_request_id, plan_id, previous_status,
                        new_status, actor_id, actor_type, authenticated_source, timestamp,
                        reason_code, task_id, workspace_id, repository_id, correlation_id
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        audit_event.event_id, audit_event.event_type,
                        audit_event.approval_request_id, audit_event.plan_id,
                        audit_event.previous_status, audit_event.new_status,
                        audit_event.actor_id, audit_event.actor_type,
                        audit_event.authenticated_source, float(audit_event.timestamp),
                        audit_event.reason_code, audit_event.task_id,
                        audit_event.workspace_id, audit_event.repository_id,
                        audit_event.correlation_id,
                    ),
                )
            # 8. COMMIT.
            self._conn.commit()
            return True
        except sqlite3.IntegrityError:
            # A conflicting ACTIVE lease already holds this workspace.
            self._conn.rollback()
            return False
        except Exception:
            self._conn.rollback()
            raise

    def require_active_lease(
        self,
        lease_id: str,
        *,
        owner_execution_id: str,
        expected_task_id: str,
        expected_workspace_id: str,
        expected_repository_id: str,
        expected_plan_id: str,
        current_server_epoch: int,
        current_boot_id: str = "",
        now: float,
    ) -> bool:
        """Verify a lease is ACTIVE, owned by the caller, scope-correct,
        unexpired, and bound to the current boot epoch + boot_id.

        Batch 2.5 §2: verifies the persisted boot context matches the
        supplied epoch + boot_id BEFORE checking the lease. A stale runtime
        whose cached epoch/boot_id no longer match the persisted state
        cannot validate contexts.

        Every Batch 3 execution entry must call this BEFORE touching the
        workspace. Returns True if the lease is valid; False otherwise.
        """
        if self._conn.in_transaction:
            self._conn.commit()
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            # Batch 2.5 §2: verify persisted boot context first.
            if not self._verify_persisted_boot_context(
                server_epoch=current_server_epoch, boot_id=current_boot_id,
            ):
                self._conn.rollback()
                return False
            row = self._conn.execute(
                "SELECT * FROM plan_execution_leases WHERE lease_id = ?",
                (lease_id,),
            ).fetchone()
            if row is None:
                self._conn.rollback()
                return False
            if row["status"] != "active":
                self._conn.rollback()
                return False
            if now >= float(row["expiry"]):
                # Auto-expire the stale lease so it doesn't permanently block.
                self._conn.execute(
                    "UPDATE plan_execution_leases SET status = 'expired' WHERE lease_id = ?",
                    (lease_id,),
                )
                self._conn.commit()
                return False
            if row["owner_execution_id"] != owner_execution_id:
                self._conn.rollback()
                return False
            if (
                row["task_id"] != expected_task_id
                or row["workspace_id"] != expected_workspace_id
                or row["repository_id"] != expected_repository_id
                or row["plan_id"] != expected_plan_id
            ):
                self._conn.rollback()
                return False
            if int(row["server_epoch"]) != int(current_server_epoch) or str(row["boot_id"]) != current_boot_id:
                self._conn.rollback()
                return False
            auth = self._conn.execute(
                "SELECT status,binding_digest,approval_request_id,boot_id FROM plan_execution_authorizations WHERE authorization_id=?",
                (row["authorization_id"],),
            ).fetchone()
            if auth is None or auth["status"] != AuthorizationStatus.CONSUMED.value:
                self._conn.rollback()
                return False
            if auth["binding_digest"] != row["binding_digest"]:
                self._conn.rollback()
                return False
            request = self._conn.execute(
                "SELECT status,binding_digest FROM plan_approval_requests WHERE approval_request_id=?",
                (auth["approval_request_id"],),
            ).fetchone()
            if request is None or request["status"] != PlanApprovalStatus.CONSUMED.value:
                self._conn.rollback()
                return False
            if request["binding_digest"] != row["binding_digest"]:
                self._conn.rollback()
                return False
            self._conn.commit()
            return True
        except Exception:
            self._conn.rollback()
            raise

    def invalidate_active_execution_scope(
        self,
        *,
        task_id: str | None = None,
        workspace_id: str | None = None,
        owner_execution_id: str | None = None,
        boot_id: str | None = None,
        reason: str = "execution-cancelled",
        now: float | None = None,
    ) -> int:
        """Atomically invalidate all ACTIVE leases + authorizations matching
        the given scope, WITHOUT rolling back CONSUMED approval requests.

        Batch 2.5 §3: a Task cancel / Workspace cleanup / Runtime shutdown
        must be able to terminate the ACTIVE lease of a CONSUMED approval
        request. The old ``invalidate_request_authorizations_leases_and_receipt``
        tried to transition CONSUMED → REVOKED which is an illegal rollback.
        This method does NOT touch the approval request status at all — it
        only expires the lease and revokes still-ACTIVE authorizations.

        Batch 2.5 §7: when ``boot_id`` is supplied and all scope params are
        None, cancels ALL active leases for that boot (used by
        ``Runtime.shutdown``). When scope params are supplied, they filter
        within the matching set (optionally also filtered by boot_id).

        ONE ``BEGIN IMMEDIATE``:
        1. Find matching ACTIVE leases (by task_id and/or workspace_id and/or
           owner_execution_id, and/or boot_id).
        2. Each matching lease → 'cancelled'.
        3. For each lease's authorization_id: if the authorization is still
           ACTIVE, revoke it. (CONSUMED authorizations stay CONSUMED.)
        4. Write an execution-cancelled audit event per lease.
        5. COMMIT.

        Returns the count of invalidated leases.
        """
        if (task_id is None and workspace_id is None
                and owner_execution_id is None and boot_id is None):
            return 0
        now = time.time() if now is None else now
        if self._conn.in_transaction:
            self._conn.commit()
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            # Build the WHERE clause for matching ACTIVE leases.
            clauses = ["status = 'active'"]
            params: list[Any] = []
            if task_id is not None:
                clauses.append("task_id = ?")
                params.append(task_id)
            if workspace_id is not None:
                clauses.append("workspace_id = ?")
                params.append(workspace_id)
            if owner_execution_id is not None:
                clauses.append("owner_execution_id = ?")
                params.append(owner_execution_id)
            if boot_id is not None:
                clauses.append("boot_id = ?")
                params.append(boot_id)
            where = " AND ".join(clauses)
            leases = self._conn.execute(
                f"SELECT lease_id, task_id, workspace_id, repository_id, plan_id, "
                f"authorization_id, owner_execution_id FROM plan_execution_leases WHERE {where}",
                tuple(params),
            ).fetchall()
            invalidated = 0
            for lease in leases:
                # Expire the lease.
                self._conn.execute(
                    "UPDATE plan_execution_leases SET status = 'cancelled' WHERE lease_id = ?",
                    (lease["lease_id"],),
                )
                # Revoke the authorization if still ACTIVE (not CONSUMED).
                auth_row = self._conn.execute(
                    "SELECT status, approval_request_id, plan_id FROM plan_execution_authorizations "
                    "WHERE authorization_id = ?",
                    (lease["authorization_id"],),
                ).fetchone()
                if auth_row is not None and auth_row["status"] == AuthorizationStatus.ACTIVE.value:
                    self._conn.execute(
                        "UPDATE plan_execution_authorizations SET status = ? WHERE authorization_id = ?",
                        (AuthorizationStatus.REVOKED.value, lease["authorization_id"]),
                    )
                # Write execution-cancelled audit. Use the approval_request_id
                # from the auth row if available, else empty.
                req_id = auth_row["approval_request_id"] if auth_row is not None else ""
                plan_id = auth_row["plan_id"] if auth_row is not None else lease["plan_id"]
                audit_id = f"audit_{uuid.uuid4().hex}"
                self._conn.execute(
                    """
                    INSERT INTO plan_approval_audit_events (
                        event_id, event_type, approval_request_id, plan_id, previous_status,
                        new_status, actor_id, actor_type, authenticated_source, timestamp,
                        reason_code, task_id, workspace_id, repository_id, correlation_id
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        audit_id, "execution:cancelled", req_id, plan_id,
                        "active", "cancelled",
                        "system", "system", "runtime-shutdown",
                        float(now), reason,
                        lease["task_id"], lease["workspace_id"],
                        lease["repository_id"], lease["lease_id"],
                    ),
                )
                invalidated += 1
            self._conn.commit()
            return invalidated
        except Exception:
            self._conn.rollback()
            raise

    def count_active_leases_for_workspace(self, workspace_id: str) -> int:
        """Return the count of ACTIVE leases on a workspace (invariant check)."""
        row = self._conn.execute(
            "SELECT COUNT(*) AS c FROM plan_execution_leases WHERE workspace_id = ? AND status = 'active'",
            (workspace_id,),
        ).fetchone()
        return int(row["c"]) if row else 0

    def reap_expired_leases(self, *, now: float) -> int:
        """Expire every ACTIVE lease whose TTL has elapsed (§3 item 6/7).

        Returns the count reaped. Called periodically or before any lease
        acquire so an expired lease doesn't permanently block a workspace.
        """
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            cur = self._conn.execute(
                "UPDATE plan_execution_leases SET status = 'expired' "
                "WHERE status = 'active' AND expiry < ?",
                (float(now),),
            )
            count = int(cur.rowcount or 0)
            self._conn.commit()
            return count
        except Exception:
            self._conn.rollback()
            raise

    # ------------------------------------------------------------------
    # Batch 3 execution journal
    # ------------------------------------------------------------------


def new_authorization_id() -> str:
    """Generate a fresh opaque authorization identifier."""
    return f"pax_{uuid.uuid4().hex}"


def new_request_id() -> str:
    """Generate a fresh opaque approval request identifier."""
    return f"par_{uuid.uuid4().hex}"


def new_event_id() -> str:
    return f"pae_{uuid.uuid4().hex}"


def open_store(db_path: str | Path) -> PlanApprovalStore:
    """Open a :class:`PlanApprovalStore` against a file path."""
    conn = sqlite3.connect(str(db_path))
    return PlanApprovalStore(conn)
