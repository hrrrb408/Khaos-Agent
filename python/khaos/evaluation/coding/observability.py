"""Secret-free projections used by the coding qualification observer.

The functions in this module are deliberately downstream of parsing and
outside the evaluation decision.  They accept already-typed values and
produce bounded metadata only; they never receive or retain the raw model
response, finding summaries, repository contents, or the hidden oracle.
"""

from __future__ import annotations

import re
import unicodedata
from collections.abc import Iterable, Mapping
from itertools import islice
from typing import Final

from khaos.coding.intelligence.context import normalize_relative_path
from khaos.coding.planning.safe_identifiers import (
    SafeWorkspaceRelativePath,
    UnsafePersistedIdentifier,
)
from khaos.evaluation.coding.oracle import ReviewFinding
from khaos.security.protocol_boundary import canonical_digest
from khaos.security.secret_redaction import SecretRedactor

SEMANTIC_ATTRIBUTION_SCHEMA_VERSION: Final[int] = 1
MAX_REVIEW_FINDINGS: Final[int] = 128
MAX_REVIEW_CONCEPTS: Final[int] = 32
MAX_REVIEW_CONCEPT_BYTES: Final[int] = 256
MAX_REVIEW_CONCEPT_TOTAL_BYTES: Final[int] = 4 * 1024
MAX_REVIEW_CATEGORY_BYTES: Final[int] = 256
MAX_REVIEW_FILE_BYTES: Final[int] = 512

_REVIEW_IDENTIFIER_EXTRA = frozenset("_-.:/@$<>[]")
_CONTROL_OR_FORMAT = re.compile(r"[\x00-\x1f\x7f]|[\u0080-\u009f]")
_WINDOWS_DRIVE = re.compile(r"^[A-Za-z]:")
_SECRET_LIKE = re.compile(
    r"(?ix)"
    r"(?:authorization\s*[:=]\s*bearer\s+\S+)"
    r"|(?:(?:api[_ -]?key|access[_ -]?token|refresh[_ -]?token|"
    r"password|secret|private[_ -]?key|token)\s*[:=]\s*\S+)"
    r"|(?:\b(?:sk|rk|ghp|github_pat|xox[baprs]-|AIza)[A-Za-z0-9_-]{8,})"
    r"|(?:-----BEGIN\s+[A-Z ]+-----)"
)
_SECRET_PATH_PARTS = frozenset(
    {".ssh", "id_rsa", "id_ed25519", "id_dsa", "known_hosts"}
)
_HIDDEN_PATH_PARTS = frozenset(
    {
        ".oracle-hidden",
        "oracle",
        "gold",
        "golden",
        "expected",
        "hidden",
        "reference",
        "solution",
    }
)


def project_review_findings(
    findings: Iterable[ReviewFinding],
    *,
    redactor: SecretRedactor | None = None,
) -> dict[str, object]:
    """Project typed findings into bounded, ordered durable metadata.

    The input is never modified and the returned mapping contains no line,
    severity, summary, or other free-form finding prose.  Unsafe values are
    represented by sentinels while ordinal and finding counts remain visible
    so a later forensic tool can distinguish redaction from omission.
    """

    values, overflow = _bounded_values(findings, maximum=MAX_REVIEW_FINDINGS)
    rows: list[dict[str, object]] = []
    values_redacted = False
    for ordinal, finding in enumerate(values[:MAX_REVIEW_FINDINGS]):
        if not isinstance(finding, ReviewFinding):
            category = "[REDACTED_CATEGORY]"
            safe_file = "workspace:unsafe"
            concepts = ["[REDACTED_CONCEPT]"]
            category_redacted = True
            file_redacted = True
            concept_redacted = True
            original_concept_count = 0
            concepts_truncated = True
        else:
            category, category_redacted = _safe_identifier(
                finding.category,
                max_bytes=MAX_REVIEW_CATEGORY_BYTES,
                sentinel="[REDACTED_CATEGORY]",
                redactor=redactor,
            )
            safe_file, file_redacted = _safe_workspace_file(
                finding.file,
                redactor=redactor,
            )
            concepts, original_concept_count, concept_redacted, concepts_truncated = (
                _project_concepts(finding.concepts, redactor=redactor)
            )

        value_redacted = category_redacted or file_redacted or concept_redacted
        values_redacted = values_redacted or value_redacted
        canonical = {
            "category": category,
            "file": safe_file,
            "concepts": concepts,
        }
        rows.append(
            {
                "ordinal": ordinal,
                "category": category,
                "file": safe_file,
                "concepts": concepts,
                "safe_finding_digest": canonical_digest(canonical),
                "value_redacted": value_redacted,
                "concepts_original_count": original_concept_count,
                "concepts_persisted_count": len(concepts),
                "concepts_truncated": concepts_truncated,
            }
        )

    projection_truncated = overflow or len(values) > len(rows)
    return {
        "semantic_attribution_schema_version": SEMANTIC_ATTRIBUTION_SCHEMA_VERSION,
        "typed_finding_detail_status": "AVAILABLE",
        "typed_findings": rows,
        "typed_finding_original_count": (
            MAX_REVIEW_FINDINGS + 1 if overflow else len(values)
        ),
        "typed_finding_persisted_count": len(rows),
        "typed_finding_projection_truncated": projection_truncated,
        "typed_finding_values_redacted": values_redacted,
        "typed_finding_projection_digest": canonical_digest(rows),
    }


def unavailable_review_finding_detail() -> dict[str, object]:
    """Return the explicit state used when a legacy record lacks details."""

    return {
        "semantic_attribution_schema_version": SEMANTIC_ATTRIBUTION_SCHEMA_VERSION,
        "typed_finding_detail_status": "NOT_AVAILABLE_LEGACY_ARTIFACT",
        "typed_findings": "NOT_AVAILABLE_LEGACY_ARTIFACT",
        "typed_finding_original_count": None,
        "typed_finding_persisted_count": None,
        "typed_finding_projection_truncated": None,
        "typed_finding_values_redacted": None,
        "typed_finding_projection_digest": None,
    }


def _project_concepts(
    concepts: object,
    *,
    redactor: SecretRedactor | None,
) -> tuple[list[str], int, bool, bool]:
    values, overflow = _bounded_values(concepts, maximum=MAX_REVIEW_CONCEPTS)
    original_count = MAX_REVIEW_CONCEPTS + 1 if overflow else len(values)
    if not values:
        return ["[REDACTED_CONCEPT]"], original_count, True, True
    projected: list[str] = []
    total_bytes = 0
    value_redacted = False
    truncated = overflow or original_count > MAX_REVIEW_CONCEPTS
    for value in values:
        if len(projected) >= MAX_REVIEW_CONCEPTS:
            break
        safe, redacted = _safe_identifier(
            value,
            max_bytes=MAX_REVIEW_CONCEPT_BYTES,
            sentinel="[REDACTED_CONCEPT]",
            redactor=redactor,
        )
        encoded_size = len(safe.encode("utf-8"))
        if projected and total_bytes + encoded_size > MAX_REVIEW_CONCEPT_TOTAL_BYTES:
            truncated = True
            break
        if not projected and encoded_size > MAX_REVIEW_CONCEPT_TOTAL_BYTES:
            safe = "[REDACTED_CONCEPT]"
            encoded_size = len(safe.encode("utf-8"))
            redacted = True
        projected.append(safe)
        total_bytes += encoded_size
        value_redacted = value_redacted or redacted
    if len(projected) < original_count:
        truncated = True
    return projected, original_count, value_redacted, truncated


def _bounded_values(value: object, *, maximum: int) -> tuple[tuple[object, ...], bool]:
    """Read a typed collection without consuming an arbitrary iterator forever."""

    if isinstance(value, (list, tuple)):
        return tuple(value[: maximum + 1]), len(value) > maximum
    if isinstance(value, Iterable) and not isinstance(value, (str, bytes, Mapping)):
        values = tuple(islice(value, maximum + 1))
        return values, len(values) > maximum
    return (), False


def _safe_workspace_file(
    value: str,
    *,
    redactor: SecretRedactor | None,
) -> tuple[str, bool]:
    if not isinstance(value, str):
        return "workspace:unsafe", True
    sanitized = redactor.redact_text(value) if redactor is not None else value
    if (
        not sanitized
        or len(sanitized.encode("utf-8", errors="replace")) > MAX_REVIEW_FILE_BYTES
        or _CONTROL_OR_FORMAT.search(sanitized) is not None
        or "\\" in sanitized
        or _WINDOWS_DRIVE.match(sanitized) is not None
        or _SECRET_LIKE.search(sanitized) is not None
    ):
        return "workspace:unsafe", True
    try:
        normalized = normalize_relative_path(sanitized, label="finding.file")
        SafeWorkspaceRelativePath.parse(normalized)
    except (TypeError, ValueError, UnsafePersistedIdentifier):
        return "workspace:unsafe", True
    parts = {part.casefold() for part in normalized.split("/")}
    if parts.intersection(_SECRET_PATH_PARTS | _HIDDEN_PATH_PARTS):
        return "workspace:unsafe", True
    return normalized, sanitized != value


def _safe_identifier(
    value: object,
    *,
    max_bytes: int,
    sentinel: str,
    redactor: SecretRedactor | None,
) -> tuple[str, bool]:
    if not isinstance(value, str):
        return sentinel, True
    sanitized = redactor.redact_text(value) if redactor is not None else value
    normalized = unicodedata.normalize("NFKC", sanitized).strip()
    if (
        not normalized
        or len(normalized.encode("utf-8", errors="replace")) > max_bytes
        or _CONTROL_OR_FORMAT.search(normalized) is not None
        or _SECRET_LIKE.search(normalized) is not None
        or any(
            not (character.isalnum() or character in _REVIEW_IDENTIFIER_EXTRA)
            for character in normalized
        )
        or any(character.isspace() for character in normalized)
    ):
        return sentinel, True
    return normalized, sanitized != value


__all__ = [
    "MAX_REVIEW_CATEGORY_BYTES",
    "MAX_REVIEW_CONCEPTS",
    "MAX_REVIEW_CONCEPT_BYTES",
    "MAX_REVIEW_CONCEPT_TOTAL_BYTES",
    "MAX_REVIEW_FILE_BYTES",
    "MAX_REVIEW_FINDINGS",
    "SEMANTIC_ATTRIBUTION_SCHEMA_VERSION",
    "project_review_findings",
    "unavailable_review_finding_detail",
]
