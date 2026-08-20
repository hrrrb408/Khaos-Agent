"""Canonical authority-owner context shared by plans, receipts, and grants."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class AuthorityContextV1:
    """The complete non-secret owner binding for one effect authority.

    Effect-specific labels such as operation, argv, and resource digest do
    not belong here; they are bound by the effect capability.  Every object
    that carries owner identity embeds this exact payload and therefore cannot
    accidentally omit runtime or transport provenance from its digest.
    """

    principal_id: str
    principal_kind: str
    parent_principal_id: str
    project_id: str
    session_id: str
    runtime_id: str
    source_transport: str
    task_id: str
    workspace_id: str
    workspace_generation: int
    policy_digest: str
    authorization_epoch: int
    delegation_digest: str = ""
    schema_version: int = 1

    def __post_init__(self) -> None:
        if self.schema_version != 1:
            raise ValueError("unsupported authority context schema")
        fields = (
            self.principal_id,
            self.principal_kind,
            self.parent_principal_id,
            self.project_id,
            self.session_id,
            self.runtime_id,
            self.source_transport,
            self.task_id,
            self.workspace_id,
            self.policy_digest,
        )
        if any(not isinstance(value, str) for value in fields):
            raise ValueError("authority context fields must be strings")
        if self.workspace_generation < 0 or self.authorization_epoch < 0:
            raise ValueError("authority context counters must be non-negative")
        if self.delegation_digest and (
            len(self.delegation_digest) != 64
            or any(char not in "0123456789abcdef" for char in self.delegation_digest)
        ):
            raise ValueError("authority context delegation digest is malformed")

    def payload(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "principal_id": self.principal_id,
            "principal_kind": self.principal_kind,
            "parent_principal_id": self.parent_principal_id,
            "project_id": self.project_id,
            "session_id": self.session_id,
            "runtime_id": self.runtime_id,
            "source_transport": self.source_transport,
            "task_id": self.task_id,
            "workspace_id": self.workspace_id,
            "workspace_generation": self.workspace_generation,
            "policy_digest": self.policy_digest,
            "authorization_epoch": self.authorization_epoch,
            "delegation_digest": self.delegation_digest,
        }

    def digest(self) -> str:
        encoded = json.dumps(
            self.payload(), sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()


__all__ = ["AuthorityContextV1"]
