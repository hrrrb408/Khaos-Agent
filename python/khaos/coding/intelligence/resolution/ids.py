"""Deterministic stable IDs for repository semantic objects.

IDs are reproducible: same repository + same file content + same position = same ID.
This enables incremental updates without full graph rebuilds.

All edge IDs bind repository_id so that two repositories with the same
file at the same byte range produce distinct edge IDs and can coexist
in the same database without collision.
"""
from __future__ import annotations

import hashlib


def symbol_id(
    repository_id: str,
    path: str,
    language: str,
    kind: str,
    qualified_name: str,
    byte_start: int,
    byte_end: int,
    generation: int,
) -> str:
    """Symbol revision ID binding repository, location, identity, and generation.

    Note: this ID changes when the file's generation changes. For a
    generation-independent stable identity, use ``stable_symbol_id``.
    """
    raw = f"sym|{repository_id}|{path}|{language}|{kind}|{qualified_name}|{byte_start}|{byte_end}|{generation}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]


def stable_symbol_id(
    repository_id: str,
    path: str,
    language: str,
    kind: str,
    qualified_name: str,
    byte_start: int,
    byte_end: int,
) -> str:
    """Generation-independent stable symbol identity.

    Same repository + same path + same definition position + same kind +
    same qualified name = same stable ID, regardless of generation.

    Used as the target of resolved edges so that incremental updates and
    full rebuilds produce identical stable IDs when the definition hasn't
    moved.
    """
    raw = f"ssym|{repository_id}|{path}|{language}|{kind}|{qualified_name}|{byte_start}|{byte_end}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]


def call_edge_id(
    repository_id: str,
    source_file: str,
    callee: str,
    byte_start: int,
    byte_end: int,
    source_generation: int,
) -> str:
    """Stable call edge ID binding repository, source location, and generation."""
    raw = f"call|{repository_id}|{source_file}|{callee}|{byte_start}|{byte_end}|{source_generation}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]


def reference_edge_id(
    repository_id: str,
    source_file: str,
    name: str,
    reference_kind: str,
    byte_start: int,
    byte_end: int,
    source_generation: int,
) -> str:
    """Stable reference edge ID binding repository, source location, and generation."""
    raw = f"ref|{repository_id}|{source_file}|{name}|{reference_kind}|{byte_start}|{byte_end}|{source_generation}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]


def import_id(
    repository_id: str,
    source_file: str,
    import_module: str,
    imported_name: str,
    alias: str | None,
    source_generation: int,
) -> str:
    """Stable import ID for deduplication, scoped by repository."""
    raw = f"imp|{repository_id}|{source_file}|{import_module}|{imported_name}|{alias or ''}|{source_generation}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]
