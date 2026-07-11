"""Deterministic stable IDs for repository semantic objects.

IDs are reproducible: same repository + same file content + same position = same ID.
This enables incremental updates without full graph rebuilds.
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
    """Stable symbol ID binding repository, location, identity, and generation."""
    raw = f"sym|{repository_id}|{path}|{language}|{kind}|{qualified_name}|{byte_start}|{byte_end}|{generation}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]


def call_edge_id(
    source_file: str,
    callee: str,
    byte_start: int,
    byte_end: int,
    source_generation: int,
) -> str:
    """Stable call edge ID binding source location and generation."""
    raw = f"call|{source_file}|{callee}|{byte_start}|{byte_end}|{source_generation}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]


def reference_edge_id(
    source_file: str,
    name: str,
    reference_kind: str,
    byte_start: int,
    byte_end: int,
    source_generation: int,
) -> str:
    """Stable reference edge ID binding source location and generation."""
    raw = f"ref|{source_file}|{name}|{reference_kind}|{byte_start}|{byte_end}|{source_generation}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]


def import_id(
    source_file: str,
    import_module: str,
    imported_name: str,
    alias: str | None,
    source_generation: int,
) -> str:
    """Stable import ID for deduplication."""
    raw = f"imp|{source_file}|{import_module}|{imported_name}|{alias or ''}|{source_generation}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]
