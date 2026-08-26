"""Immutable, non-authoritative declarations of a coding task's goal.

``GoalSpec`` is intentionally a value object.  It records what the user
declared, not whether the task has been completed and not what the runtime is
allowed to do.  Assessment, evidence, verification results, plan state, and
security authority are separate concerns owned by later control-plane
contracts.
"""

from __future__ import annotations

import json
import re
import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum

from khaos.security.protocol_boundary import canonical_digest, canonical_json_bytes

GOAL_SPEC_SCHEMA_VERSION = 1
GOAL_REQUIREMENT_SCHEMA_KEYS = frozenset(
    {"requirement_id", "description", "required", "source"}
)
ACCEPTANCE_CRITERION_SCHEMA_KEYS = frozenset(
    {"criterion_id", "description", "required", "source", "verification_kind"}
)
_GOAL_SPEC_SCHEMA_KEYS = frozenset(
    {
        "schema_version",
        "goal_spec_id",
        "raw_goal",
        "normalized_goal",
        "requirements",
        "acceptance_criteria",
        "constraints",
        "requested_artifacts",
        "verification_expectations",
        "semantic_digest",
    }
)
_HEX_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_EXPLICIT_REQUIREMENT_ID = "user_goal"


class GoalSpecValidationError(ValueError):
    """Raised when a GoalSpec or its canonical representation is invalid."""


class GoalSource(str, Enum):
    """Provenance vocabulary for declared or future derived goal facts."""

    EXPLICIT_USER = "explicit_user"
    INFERRED = "inferred"
    REPOSITORY_POLICY = "repository_policy"
    VERIFICATION_POLICY = "verification_policy"


def normalize_goal(raw_goal: str) -> str:
    """Apply only conservative, representation-safe goal normalization.

    Leading/trailing Unicode whitespace is removed and line endings are
    normalized.  Internal whitespace, Unicode text, paths, code symbols, and
    quoted content are preserved verbatim; this function does not interpret or
    expand the user's request.
    """
    if type(raw_goal) is not str:
        raise GoalSpecValidationError("raw_goal must be a string")
    normalized = raw_goal.strip()
    normalized = normalized.replace("\r\n", "\n").replace("\r", "\n")
    if not normalized:
        raise GoalSpecValidationError("raw_goal must not be empty")
    return normalized


def _require_text(value: object, *, label: str, allow_empty: bool = False) -> str:
    if type(value) is not str or (not allow_empty and not value):
        suffix = "" if allow_empty else " and must not be empty"
        raise GoalSpecValidationError(f"{label} must be a string{suffix}")
    return value


def _require_tuple(value: object, *, label: str) -> tuple[object, ...]:
    if type(value) is not tuple:
        raise GoalSpecValidationError(f"{label} must be a tuple")
    return value


def _require_string_tuple(value: object, *, label: str) -> tuple[str, ...]:
    values = _require_tuple(value, label=label)
    if any(type(item) is not str or not item for item in values):
        raise GoalSpecValidationError(f"{label} must contain non-empty strings")
    return values  # type: ignore[return-value]


@dataclass(frozen=True, slots=True)
class GoalRequirement:
    """One typed requirement declared by a goal source."""

    requirement_id: str
    description: str
    required: bool
    source: GoalSource

    def __post_init__(self) -> None:
        _require_text(self.requirement_id, label="requirement_id")
        _require_text(self.description, label="description")
        if type(self.required) is not bool:
            raise GoalSpecValidationError("required must be a bool")
        if type(self.source) is not GoalSource:
            raise GoalSpecValidationError("source must be a GoalSource")


@dataclass(frozen=True, slots=True)
class AcceptanceCriterion:
    """One typed acceptance declaration without mutable assessment state."""

    criterion_id: str
    description: str
    required: bool
    source: GoalSource
    verification_kind: str | None = None

    def __post_init__(self) -> None:
        _require_text(self.criterion_id, label="criterion_id")
        _require_text(self.description, label="description")
        if type(self.required) is not bool:
            raise GoalSpecValidationError("required must be a bool")
        if type(self.source) is not GoalSource:
            raise GoalSpecValidationError("source must be a GoalSource")
        if self.verification_kind is not None:
            _require_text(self.verification_kind, label="verification_kind")


def _require_typed_tuple(
    value: object,
    *,
    label: str,
    item_type: type[object],
) -> tuple[object, ...]:
    values = _require_tuple(value, label=label)
    if any(type(item) is not item_type for item in values):
        raise GoalSpecValidationError(
            f"{label} must contain only {item_type.__name__} values"
        )
    return values


def _semantic_payload(
    *,
    schema_version: int,
    raw_goal: str,
    normalized_goal: str,
    requirements: tuple[GoalRequirement, ...],
    acceptance_criteria: tuple[AcceptanceCriterion, ...],
    constraints: tuple[str, ...],
    requested_artifacts: tuple[str, ...],
    verification_expectations: tuple[str, ...],
) -> dict[str, object]:
    """Build the only payload covered by ``GoalSpec.semantic_digest``.

    Lists and mappings in this helper are serialization representations only;
    the canonical value object itself contains tuples and frozen dataclasses.
    Requirement and criterion collections are identity-keyed declarations, so
    their order is canonicalized by id.  Ordered scalar tuples retain their
    declared order.
    """
    return {
        "schema_version": schema_version,
        "raw_goal": raw_goal,
        "normalized_goal": normalized_goal,
        "requirements": [
            {
                "requirement_id": item.requirement_id,
                "description": item.description,
                "required": item.required,
                "source": item.source.value,
            }
            for item in sorted(requirements, key=lambda item: item.requirement_id)
        ],
        "acceptance_criteria": [
            {
                "criterion_id": item.criterion_id,
                "description": item.description,
                "required": item.required,
                "source": item.source.value,
                "verification_kind": item.verification_kind,
            }
            for item in sorted(
                acceptance_criteria, key=lambda item: item.criterion_id
            )
        ],
        "constraints": list(constraints),
        "requested_artifacts": list(requested_artifacts),
        "verification_expectations": list(verification_expectations),
    }


def _compute_semantic_digest(
    *,
    schema_version: int,
    raw_goal: str,
    normalized_goal: str,
    requirements: tuple[GoalRequirement, ...],
    acceptance_criteria: tuple[AcceptanceCriterion, ...],
    constraints: tuple[str, ...],
    requested_artifacts: tuple[str, ...],
    verification_expectations: tuple[str, ...],
) -> str:
    # ``from_parts`` computes the digest before the dataclass constructor runs.
    # Validate nested value types here too, so malformed list/dict inputs fail
    # as typed contract errors instead of reaching the encoder.
    _require_text(raw_goal, label="raw_goal")
    _require_text(normalized_goal, label="normalized_goal")
    _require_typed_tuple(
        requirements,
        label="requirements",
        item_type=GoalRequirement,
    )
    _require_typed_tuple(
        acceptance_criteria,
        label="acceptance_criteria",
        item_type=AcceptanceCriterion,
    )
    _require_string_tuple(constraints, label="constraints")
    _require_string_tuple(
        requested_artifacts,
        label="requested_artifacts",
    )
    _require_string_tuple(
        verification_expectations,
        label="verification_expectations",
    )
    return canonical_digest(
        _semantic_payload(
            schema_version=schema_version,
            raw_goal=raw_goal,
            normalized_goal=normalized_goal,
            requirements=requirements,
            acceptance_criteria=acceptance_criteria,
            constraints=constraints,
            requested_artifacts=requested_artifacts,
            verification_expectations=verification_expectations,
        )
    )


@dataclass(frozen=True, slots=True)
class GoalSpec:
    """Immutable canonical declaration of one user's coding goal.

    This contract intentionally has no status, evidence reference,
    verification result, or plan state.  It is not an authority token and
    cannot widen tool, approval, workspace, or sandbox capabilities.
    """

    schema_version: int
    goal_spec_id: str
    raw_goal: str
    normalized_goal: str
    requirements: tuple[GoalRequirement, ...]
    acceptance_criteria: tuple[AcceptanceCriterion, ...]
    constraints: tuple[str, ...]
    requested_artifacts: tuple[str, ...]
    verification_expectations: tuple[str, ...]
    semantic_digest: str

    def __post_init__(self) -> None:
        if type(self.schema_version) is not int:
            raise GoalSpecValidationError("schema_version must be an integer")
        if self.schema_version != GOAL_SPEC_SCHEMA_VERSION:
            raise GoalSpecValidationError(
                f"unsupported GoalSpec schema_version: {self.schema_version}"
            )
        _require_text(self.goal_spec_id, label="goal_spec_id")
        _require_text(self.raw_goal, label="raw_goal")
        if self.normalized_goal != normalize_goal(self.raw_goal):
            raise GoalSpecValidationError(
                "normalized_goal is not the deterministic normalization of raw_goal"
            )
        _require_typed_tuple(
            self.requirements,
            label="requirements",
            item_type=GoalRequirement,
        )
        _require_typed_tuple(
            self.acceptance_criteria,
            label="acceptance_criteria",
            item_type=AcceptanceCriterion,
        )
        _require_string_tuple(self.constraints, label="constraints")
        _require_string_tuple(
            self.requested_artifacts, label="requested_artifacts"
        )
        _require_string_tuple(
            self.verification_expectations,
            label="verification_expectations",
        )
        requirement_ids = [item.requirement_id for item in self.requirements]
        if len(requirement_ids) != len(set(requirement_ids)):
            raise GoalSpecValidationError("requirement_id values must be unique")
        criterion_ids = [item.criterion_id for item in self.acceptance_criteria]
        if len(criterion_ids) != len(set(criterion_ids)):
            raise GoalSpecValidationError("criterion_id values must be unique")
        if type(self.semantic_digest) is not str or not _HEX_DIGEST.fullmatch(
            self.semantic_digest
        ):
            raise GoalSpecValidationError("semantic_digest must be a SHA-256 hex digest")
        expected_digest = _compute_semantic_digest(
            schema_version=self.schema_version,
            raw_goal=self.raw_goal,
            normalized_goal=self.normalized_goal,
            requirements=self.requirements,
            acceptance_criteria=self.acceptance_criteria,
            constraints=self.constraints,
            requested_artifacts=self.requested_artifacts,
            verification_expectations=self.verification_expectations,
        )
        if self.semantic_digest != expected_digest:
            raise GoalSpecValidationError("semantic_digest does not match semantic payload")

    @classmethod
    def from_user_goal(
        cls,
        raw_goal: str,
        *,
        goal_spec_id: str | None = None,
    ) -> GoalSpec:
        """Create the minimal explicit-user GoalSpec used by M7.1.2."""
        normalized = normalize_goal(raw_goal)
        requirements = (
            GoalRequirement(
                requirement_id=_EXPLICIT_REQUIREMENT_ID,
                description=normalized,
                required=True,
                source=GoalSource.EXPLICIT_USER,
            ),
        )
        return cls.from_parts(
            goal_spec_id=(uuid.uuid4().hex if goal_spec_id is None else goal_spec_id),
            raw_goal=raw_goal,
            normalized_goal=normalized,
            requirements=requirements,
        )

    @classmethod
    def from_parts(
        cls,
        *,
        goal_spec_id: str,
        raw_goal: str,
        normalized_goal: str | None = None,
        requirements: tuple[GoalRequirement, ...] = (),
        acceptance_criteria: tuple[AcceptanceCriterion, ...] = (),
        constraints: tuple[str, ...] = (),
        requested_artifacts: tuple[str, ...] = (),
        verification_expectations: tuple[str, ...] = (),
        schema_version: int = GOAL_SPEC_SCHEMA_VERSION,
    ) -> GoalSpec:
        """Build a typed spec and calculate its digest from semantic fields."""
        resolved_normalized = (
            normalize_goal(raw_goal) if normalized_goal is None else normalized_goal
        )
        digest = _compute_semantic_digest(
            schema_version=schema_version,
            raw_goal=raw_goal,
            normalized_goal=resolved_normalized,
            requirements=requirements,
            acceptance_criteria=acceptance_criteria,
            constraints=constraints,
            requested_artifacts=requested_artifacts,
            verification_expectations=verification_expectations,
        )
        return cls(
            schema_version=schema_version,
            goal_spec_id=goal_spec_id,
            raw_goal=raw_goal,
            normalized_goal=resolved_normalized,
            requirements=requirements,
            acceptance_criteria=acceptance_criteria,
            constraints=constraints,
            requested_artifacts=requested_artifacts,
            verification_expectations=verification_expectations,
            semantic_digest=digest,
        )

    @property
    def semantic_payload(self) -> Mapping[str, object]:
        """Return a fresh serialization representation of semantic fields."""
        return _semantic_payload(
            schema_version=self.schema_version,
            raw_goal=self.raw_goal,
            normalized_goal=self.normalized_goal,
            requirements=self.requirements,
            acceptance_criteria=self.acceptance_criteria,
            constraints=self.constraints,
            requested_artifacts=self.requested_artifacts,
            verification_expectations=self.verification_expectations,
        )

    def to_canonical_mapping(self) -> dict[str, object]:
        """Return the closed canonical storage representation."""
        return {
            **self.semantic_payload,
            "goal_spec_id": self.goal_spec_id,
            "semantic_digest": self.semantic_digest,
        }

    def canonical_json(self) -> str:
        """Serialize the full GoalSpec in the shared canonical JSON format."""
        return canonical_json_bytes(self.to_canonical_mapping()).decode("utf-8")

    @classmethod
    def from_canonical_json(
        cls,
        payload: str,
        *,
        expected_digest: str | None = None,
    ) -> GoalSpec:
        """Parse and integrity-check one canonical stored GoalSpec."""
        if type(payload) is not str:
            raise GoalSpecValidationError("canonical GoalSpec payload must be a string")
        try:
            decoded = json.loads(payload)
        except (json.JSONDecodeError, TypeError, UnicodeDecodeError) as exc:
            raise GoalSpecValidationError("canonical GoalSpec JSON is malformed") from exc
        if type(decoded) is not dict:
            raise GoalSpecValidationError("canonical GoalSpec JSON must be an object")
        unknown = set(decoded) - _GOAL_SPEC_SCHEMA_KEYS
        missing = _GOAL_SPEC_SCHEMA_KEYS - set(decoded)
        if unknown:
            raise GoalSpecValidationError(
                f"canonical GoalSpec contains unknown fields: {sorted(unknown)}"
            )
        if missing:
            raise GoalSpecValidationError(
                f"canonical GoalSpec is missing fields: {sorted(missing)}"
            )

        requirements = _decode_requirements(decoded["requirements"])
        acceptance_criteria = _decode_acceptance_criteria(
            decoded["acceptance_criteria"]
        )
        spec = cls(
            schema_version=decoded["schema_version"],
            goal_spec_id=decoded["goal_spec_id"],
            raw_goal=decoded["raw_goal"],
            normalized_goal=decoded["normalized_goal"],
            requirements=requirements,
            acceptance_criteria=acceptance_criteria,
            constraints=_decode_strings(decoded["constraints"], label="constraints"),
            requested_artifacts=_decode_strings(
                decoded["requested_artifacts"], label="requested_artifacts"
            ),
            verification_expectations=_decode_strings(
                decoded["verification_expectations"],
                label="verification_expectations",
            ),
            semantic_digest=decoded["semantic_digest"],
        )
        if expected_digest is not None and spec.semantic_digest != expected_digest:
            raise GoalSpecValidationError(
                "stored semantic_digest does not match the GoalSpec payload"
            )
        if spec.canonical_json() != payload:
            raise GoalSpecValidationError(
                "stored GoalSpec JSON is not in canonical serialization form"
            )
        return spec


def _decode_strings(value: object, *, label: str) -> tuple[str, ...]:
    if type(value) is not list:
        raise GoalSpecValidationError(f"{label} must be a JSON array")
    if any(type(item) is not str or not item for item in value):
        raise GoalSpecValidationError(f"{label} must contain non-empty strings")
    return tuple(value)


def _decode_requirements(value: object) -> tuple[GoalRequirement, ...]:
    if type(value) is not list:
        raise GoalSpecValidationError("requirements must be a JSON array")
    decoded: list[GoalRequirement] = []
    for item in value:
        if type(item) is not dict:
            raise GoalSpecValidationError("each requirement must be an object")
        if set(item) != GOAL_REQUIREMENT_SCHEMA_KEYS:
            raise GoalSpecValidationError("requirement schema is not closed")
        try:
            decoded.append(
                GoalRequirement(
                    requirement_id=item["requirement_id"],
                    description=item["description"],
                    required=item["required"],
                    source=GoalSource(item["source"]),
                )
            )
        except (KeyError, ValueError, TypeError) as exc:
            raise GoalSpecValidationError("requirement value is invalid") from exc
    return tuple(decoded)


def _decode_acceptance_criteria(value: object) -> tuple[AcceptanceCriterion, ...]:
    if type(value) is not list:
        raise GoalSpecValidationError("acceptance_criteria must be a JSON array")
    decoded: list[AcceptanceCriterion] = []
    for item in value:
        if type(item) is not dict:
            raise GoalSpecValidationError("each acceptance criterion must be an object")
        if set(item) != ACCEPTANCE_CRITERION_SCHEMA_KEYS:
            raise GoalSpecValidationError("acceptance criterion schema is not closed")
        try:
            decoded.append(
                AcceptanceCriterion(
                    criterion_id=item["criterion_id"],
                    description=item["description"],
                    required=item["required"],
                    source=GoalSource(item["source"]),
                    verification_kind=item["verification_kind"],
                )
            )
        except (KeyError, ValueError, TypeError) as exc:
            raise GoalSpecValidationError(
                "acceptance criterion value is invalid"
            ) from exc
    return tuple(decoded)


__all__ = [
    "ACCEPTANCE_CRITERION_SCHEMA_KEYS",
    "GOAL_REQUIREMENT_SCHEMA_KEYS",
    "GOAL_SPEC_SCHEMA_VERSION",
    "AcceptanceCriterion",
    "GoalRequirement",
    "GoalSource",
    "GoalSpec",
    "GoalSpecValidationError",
    "normalize_goal",
]
