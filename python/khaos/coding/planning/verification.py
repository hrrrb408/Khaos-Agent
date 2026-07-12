"""Trusted, non-executing verification requirement selection."""
from __future__ import annotations

from typing import Any

from khaos.coding.planning.contracts import PlanEvidence, VerificationRequirement

_CONTROL = {";", "&&", "||", "|", ">", "<"}

class TrustedVerificationSelector:
    def select(self, metadata: dict[str, Any], languages: set[str], evidence: tuple[PlanEvidence, ...], *, security: bool = False, schema: bool = False) -> tuple[VerificationRequirement, ...]:
        requirements=[]
        for entry in metadata.get("trusted_verification", metadata.get("verification", ())):
            if isinstance(entry, dict):
                argv=tuple(entry.get("argv", ())); language=entry.get("language"); kind=entry.get("type", "unit-test"); source=entry.get("source", "server-rule")
            else:
                argv=tuple(entry); language=None; kind="unit-test"; source="server-rule"
            if not argv or any(part in _CONTROL or any(token in part for token in (";", "&&", "||", "`", "$(")) for part in argv): continue
            if language and language not in languages: continue
            ev = PlanEvidence("verification-config", metadata.get("repository_id", ""), query=source, confidence=1.0)
            requirements.append(VerificationRequirement(argv, kind, language or "repository", "exit 0", True, "high" if security or schema else "medium", evidence + (ev,)))
        if security: requirements.append(VerificationRequirement(None, "security-test", "affected-security-boundary", "security regression reviewed", True, "critical", evidence))
        if schema: requirements.append(VerificationRequirement(None, "migration-test", "schema-and-rollback", "migration and rollback reviewed", True, "high", evidence))
        if not requirements: requirements.append(VerificationRequirement(None, "manual-review", "affected-scope", "review completed", True, "medium", evidence))
        return tuple(sorted(requirements, key=lambda item: (item.verification_type, item.scope, item.command or ())))
