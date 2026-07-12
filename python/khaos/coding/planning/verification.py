"""Trusted, non-executing verification requirement selection.

Uses :class:`VerificationCatalog` — a read-only catalog built from repository
config files (pyproject.toml, package.json, go.mod, Cargo.toml) and server
rules. Every requirement is backed by catalog entries with provenance and
config hashes, ensuring:
- No language-less legacy command propagates across languages.
- Python pytest never becomes a Go/Rust/JS verification.
- npm scripts must actually exist.
- Unconfigured mypy/ruff/clippy are never generated.
- Config file changes invalidate old plans.
"""
from __future__ import annotations

from typing import Any

from khaos.coding.planning.contracts import PlanEvidence, VerificationRequirement
from khaos.coding.planning.verification_catalog import VerificationCatalog

_CONTROL = {";", "&&", "||", "|", ">", "<"}


class TrustedVerificationSelector:
    """Selects verification requirements from a trusted catalog.

    When no catalog is available (``catalog=None``), falls back to
    ``manual-review`` — it NEVER invents commands from user goal text or
    legacy language-less entries.
    """

    def select(
        self,
        metadata: dict[str, Any],
        languages: set[str],
        evidence: tuple[PlanEvidence, ...],
        *,
        catalog: VerificationCatalog | None = None,
        security: bool = False,
        schema: bool = False,
    ) -> tuple[VerificationRequirement, ...]:
        requirements: list[VerificationRequirement] = []
        repository_id = metadata.get("repository_id", "")

        if catalog is not None:
            # --- Catalog-driven selection (trusted, language-scoped) ---
            entries = catalog.entries_for_languages(languages)
            for entry in entries:
                # Rule 3: Python pytest never becomes Go/Rust/JS verification.
                # The catalog already filters by language — scope=repository
                # means "runs at repo root", NOT "applies to all languages".
                if entry.language not in languages:
                    continue
                # Rule 1: no language-less legacy command propagates.
                # (Catalog entries always have a language — this is structural.)
                ev = PlanEvidence(
                    "verification-config",
                    repository_id,
                    path=entry.config_path if entry.config_path.startswith("/") else None,
                    query=entry.provenance,
                    confidence=1.0 if entry.trust_level == "high" else 0.8,
                    metadata={
                        "language": entry.language,
                        "verification_type": entry.verification_type,
                        "scope": entry.scope,
                        "provenance": entry.provenance,
                        "config_hash": entry.config_hash,
                        "trust_level": entry.trust_level,
                    },
                )
                risk_level = "high" if security or schema else entry.trust_level
                requirements.append(VerificationRequirement(
                    entry.argv,
                    entry.verification_type,
                    entry.language,  # scope is the language, not "repository"
                    "exit 0",
                    True,
                    risk_level,
                    evidence + (ev,),
                ))
        else:
            # --- Legacy fallback: only use explicitly language-scoped server rules ---
            for entry in metadata.get("trusted_verification", ()):
                if not isinstance(entry, dict):
                    # Rule 1: language-less legacy tuples are NOT accepted.
                    continue
                language = entry.get("language")
                if not language:
                    # Rule 1: no language-less legacy command propagates.
                    continue
                argv = tuple(entry.get("argv", ()))
                if not argv or any(part in _CONTROL or any(token in part for token in (";", "&&", "||", "`", "$(")) for part in argv):
                    continue
                # Rule 3: Python pytest only for Python.
                if language not in languages:
                    continue
                kind = entry.get("type", "unit-test")
                source = entry.get("source", "server-rule")
                ev = PlanEvidence(
                    "verification-config",
                    repository_id,
                    query=source,
                    confidence=1.0,
                    metadata={"language": language, "provenance": source},
                )
                requirements.append(VerificationRequirement(
                    argv, kind, language, "exit 0", True,
                    "high" if security or schema else "medium",
                    evidence + (ev,),
                ))

        if security:
            requirements.append(VerificationRequirement(
                None, "security-test", "affected-security-boundary",
                "security regression reviewed", True, "critical", evidence,
            ))
        if schema:
            requirements.append(VerificationRequirement(
                None, "migration-test", "schema-and-rollback",
                "migration and rollback reviewed", True, "high", evidence,
            ))
        if not requirements:
            requirements.append(VerificationRequirement(
                None, "manual-review", "affected-scope",
                "review completed", True, "medium", evidence,
            ))
        return tuple(sorted(requirements, key=lambda item: (item.verification_type, item.scope, item.command or ())))
