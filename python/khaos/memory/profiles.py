"""Workload profiles for the Memory V2 runtime.

Profiles are deliberately data-only.  They select a provider and bounded
feature switches, but they never carry authority, credentials, or a scope.
The Broker remains the owner of all security decisions after a profile is
resolved.
"""

from __future__ import annotations

import json
import tomllib
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from khaos.memory.core.contracts import MemoryBudget, canonical_json
from khaos.memory.core.policy import MemoryPolicy


class MemoryProfileError(ValueError):
    """Raised when a profile is malformed or references unknown fields."""


@dataclass(frozen=True, slots=True)
class MemoryProfile:
    """Bounded feature and policy selection for one workload."""

    profile_id: str
    provider: str = "khaos-native"
    codegraph: bool = False
    temporal: bool = True
    failure_memory: bool = True
    decision_memory: bool = True
    constraint_memory: bool = True
    skill_memory: bool = True
    user_profile: str = "light"
    fts: bool = True
    vector: bool = False
    graph: bool = True
    max_graph_hops: int = 2
    max_mutations_per_event: int = 16
    max_candidate_nodes: int = 64
    policy_overrides: Mapping[str, Any] = field(default_factory=dict)
    retrieval_overrides: Mapping[str, Any] = field(default_factory=dict)
    maintenance_overrides: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.profile_id or not self.profile_id.strip():
            raise MemoryProfileError("profile_id must be a non-empty string")
        if not self.provider or not self.provider.strip():
            raise MemoryProfileError("provider must be a non-empty string")
        for name in (
            "max_graph_hops",
            "max_mutations_per_event",
            "max_candidate_nodes",
        ):
            value = getattr(self, name)
            if type(value) is not int or value < 0:
                raise MemoryProfileError(f"{name} must be a non-negative integer")
        for name, value in (
            ("policy_overrides", self.policy_overrides),
            ("retrieval_overrides", self.retrieval_overrides),
            ("maintenance_overrides", self.maintenance_overrides),
        ):
            if not isinstance(value, Mapping):
                raise MemoryProfileError(f"{name} must be a mapping")
            try:
                canonical_json(value)
            except (TypeError, ValueError) as exc:
                raise MemoryProfileError(f"{name} must be JSON serializable") from exc
        if self.user_profile not in {"none", "light", "strong"}:
            raise MemoryProfileError("user_profile must be none, light, or strong")

    @classmethod
    def from_mapping(cls, profile_id: str, data: Mapping[str, Any]) -> MemoryProfile:
        """Build a profile while rejecting unknown top-level fields."""

        allowed = {
            "provider",
            "codegraph",
            "temporal",
            "failure_memory",
            "decision_memory",
            "constraint_memory",
            "skill_memory",
            "user_profile",
            "fts",
            "vector",
            "graph",
            "max_graph_hops",
            "max_mutations_per_event",
            "max_candidate_nodes",
            "policy_overrides",
            "retrieval_overrides",
            "maintenance_overrides",
        }
        unknown = set(data) - allowed
        if unknown:
            raise MemoryProfileError(
                f"unknown fields in memory profile {profile_id!r}: {sorted(unknown)}"
            )
        values = dict(data)
        return cls(profile_id=profile_id, **values)

    def policy(self, base: MemoryPolicy | None = None) -> MemoryPolicy:
        """Compile profile policy by tightening the supplied base policy."""

        current = base or MemoryPolicy()
        values = {field_name: getattr(current, field_name) for field_name in (
            "max_candidate_bytes",
            "max_provider_content_bytes",
            "max_provider_metadata_bytes",
            "max_search_query_length",
            "max_search_hits",
            "strict_prompt_injection",
            "allow_system_policy_candidates",
        )}
        for key, value in self.policy_overrides.items():
            if key not in values:
                raise MemoryProfileError(f"unknown policy override: {key}")
            values[key] = value
        # Profiles may tighten limits or enable strictness, but cannot widen
        # the Broker's safety defaults or admit SYSTEM_POLICY candidates.
        for key in (
            "max_candidate_bytes",
            "max_provider_content_bytes",
            "max_provider_metadata_bytes",
            "max_search_query_length",
            "max_search_hits",
        ):
            values[key] = min(int(values[key]), int(getattr(current, key)))
        values["strict_prompt_injection"] = bool(
            current.strict_prompt_injection or values["strict_prompt_injection"]
        )
        values["allow_system_policy_candidates"] = bool(
            current.allow_system_policy_candidates and values["allow_system_policy_candidates"]
        )
        return MemoryPolicy(**values)

    def budget(self, base: MemoryBudget | None = None) -> MemoryBudget:
        """Compile a bounded retrieval budget from profile overrides."""

        current = base or MemoryBudget()
        values = {
            name: getattr(current, name)
            for name in (
                "total_tokens",
                "l0_max_tokens",
                "l1_max_tokens",
                "l2_max_tokens",
                "max_hits",
                "max_graph_hops",
                "max_candidate_nodes",
                "max_evidence_expansions",
            )
        }
        for key, value in self.retrieval_overrides.items():
            if key not in values:
                raise MemoryProfileError(f"unknown retrieval override: {key}")
            values[key] = min(int(value), int(getattr(current, key)))
        values["max_graph_hops"] = min(values["max_graph_hops"], self.max_graph_hops)
        values["max_candidate_nodes"] = min(
            values["max_candidate_nodes"], self.max_candidate_nodes
        )
        values["max_evidence_expansions"] = min(
            values["max_evidence_expansions"],
            max(1, self.max_candidate_nodes),
        )
        return MemoryBudget(**values)

    def to_mapping(self) -> dict[str, Any]:
        """Return a stable JSON-compatible representation for persistence."""

        return {
            "profile_id": self.profile_id,
            "provider": self.provider,
            "codegraph": self.codegraph,
            "temporal": self.temporal,
            "failure_memory": self.failure_memory,
            "decision_memory": self.decision_memory,
            "constraint_memory": self.constraint_memory,
            "skill_memory": self.skill_memory,
            "user_profile": self.user_profile,
            "fts": self.fts,
            "vector": self.vector,
            "graph": self.graph,
            "max_graph_hops": self.max_graph_hops,
            "max_mutations_per_event": self.max_mutations_per_event,
            "max_candidate_nodes": self.max_candidate_nodes,
            "policy_overrides": dict(self.policy_overrides),
            "retrieval_overrides": dict(self.retrieval_overrides),
            "maintenance_overrides": dict(self.maintenance_overrides),
        }


CODING_PROFILE = MemoryProfile(
    profile_id="coding",
    codegraph=True,
    temporal=True,
    failure_memory=True,
    decision_memory=True,
    constraint_memory=True,
    skill_memory=True,
    user_profile="light",
    graph=True,
    max_graph_hops=2,
    max_mutations_per_event=16,
    max_candidate_nodes=64,
)

PERSONAL_PROFILE = MemoryProfile(
    profile_id="personal",
    codegraph=False,
    temporal=True,
    failure_memory=False,
    decision_memory=False,
    constraint_memory=True,
    skill_memory=False,
    user_profile="strong",
    graph=False,
    max_graph_hops=0,
    max_mutations_per_event=8,
    max_candidate_nodes=32,
)


class MemoryProfileRegistry:
    """Validated profile registry with deterministic built-in defaults."""

    def __init__(self, profiles: Mapping[str, MemoryProfile] | None = None) -> None:
        self._profiles: dict[str, MemoryProfile] = {
            "coding": CODING_PROFILE,
            "personal": PERSONAL_PROFILE,
        }
        if profiles:
            for profile in profiles.values():
                self.register(profile)

    def register(self, profile: MemoryProfile) -> None:
        """Register or replace one explicitly validated profile."""

        self._profiles[profile.profile_id] = profile

    def get(self, profile_id: str) -> MemoryProfile:
        """Resolve a profile or fail closed for unknown names."""

        try:
            return self._profiles[profile_id]
        except KeyError as exc:
            raise MemoryProfileError(f"unknown memory profile: {profile_id}") from exc

    def list(self) -> tuple[MemoryProfile, ...]:
        """Return profiles in stable identifier order."""

        return tuple(self._profiles[key] for key in sorted(self._profiles))

    @classmethod
    def from_config(cls, config: Mapping[str, Any] | None) -> MemoryProfileRegistry:
        """Load ``memory.profiles`` from YAML/TOML-shaped configuration."""

        registry = cls()
        if not config:
            return registry
        memory = config.get("memory", config)
        if not isinstance(memory, Mapping):
            raise MemoryProfileError("memory configuration must be a mapping")
        profiles = memory.get("profiles", {})
        if not isinstance(profiles, Mapping):
            raise MemoryProfileError("memory.profiles must be a mapping")
        for profile_id, raw in profiles.items():
            if not isinstance(profile_id, str) or not isinstance(raw, Mapping):
                raise MemoryProfileError("memory profile entries must be mappings")
            registry.register(MemoryProfile.from_mapping(profile_id, raw))
        return registry

    @classmethod
    def from_file(cls, path: Path) -> MemoryProfileRegistry:
        """Load a YAML or TOML configuration file without network access."""

        if not path.is_file():
            raise MemoryProfileError(f"profile configuration does not exist: {path}")
        if path.suffix.lower() == ".toml":
            data = tomllib.loads(path.read_text(encoding="utf-8"))
        else:
            import yaml

            data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        if not isinstance(data, Mapping):
            raise MemoryProfileError("profile configuration root must be a mapping")
        return cls.from_config(data)


class MemoryProfileStore:
    """Persist the active profile selection per principal and project."""

    def __init__(self, db: Any) -> None:
        self._db = db

    async def get(self, *, principal_id: str, project_id: str) -> str | None:
        async with self._db.read_connection() as conn:
            row = await (
                await conn.execute(
                    "SELECT profile_id FROM memory_profile_state "
                    "WHERE principal_id = ? AND project_id = ?",
                    (principal_id, project_id),
                )
            ).fetchone()
            return str(row["profile_id"]) if row is not None else None

    async def set(self, *, principal_id: str, project_id: str, profile: MemoryProfile) -> None:
        payload = json.dumps(profile.to_mapping(), ensure_ascii=False, sort_keys=True)
        async with self._db.transaction() as conn:
            await conn.execute(
                "INSERT INTO memory_profile_state "
                "(principal_id, project_id, profile_id, config_json, updated_at) "
                "VALUES (?, ?, ?, ?, datetime('now')) "
                "ON CONFLICT(principal_id, project_id) DO UPDATE SET "
                "profile_id = excluded.profile_id, config_json = excluded.config_json, "
                "updated_at = excluded.updated_at",
                (principal_id, project_id, profile.profile_id, payload),
            )


__all__ = [
    "CODING_PROFILE",
    "PERSONAL_PROFILE",
    "MemoryProfile",
    "MemoryProfileError",
    "MemoryProfileRegistry",
    "MemoryProfileStore",
]
