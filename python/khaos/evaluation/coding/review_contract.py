"""Public, versioned response contract for the P4 review qualification task.

The contract is intentionally independent from the fixture's hidden answer.
It defines the vocabulary and response shape visible to a model; the oracle
still keeps the mapping from a role to a repository entity private.
"""

from __future__ import annotations

from typing import Any

from khaos.evaluation.coding.contracts import (
    P4_V3_REQUIRED_FINDING_COUNT,
    REVIEW_CATEGORY_CONTRACT_V3,
    ReviewCategory,
)
from khaos.security.protocol_boundary import canonical_digest
from khaos.tools.schema import (
    production_schema,
    validate_json_schema,
    validate_schema_definition,
)

P4_V3_CATEGORY_ROLE_DEFINITIONS: dict[str, str] = {
    ReviewCategory.AUTHORITY_DEFINITION.value: (
        "the code location that establishes or defines the authority represented "
        "by the finding"
    ),
    ReviewCategory.CONSUMER.value: (
        "the code that consumes, depends on, or uses that authority"
    ),
    ReviewCategory.ENFORCEMENT_BOUNDARY.value: (
        "the code location that checks, enforces, or guards use of that authority"
    ),
}


def p4_v3_response_schema() -> dict[str, Any]:
    """Return the closed model-visible JSON Schema for P4-v3 findings."""

    return production_schema(
        {
            "type": "object",
            "additionalProperties": False,
            "required": ["findings"],
            "properties": {
                "findings": {
                    "type": "array",
                    "minItems": P4_V3_REQUIRED_FINDING_COUNT,
                    "maxItems": P4_V3_REQUIRED_FINDING_COUNT,
                    "items": {
                        "type": "object",
                        "additionalProperties": False,
                        "required": ["category", "file", "concepts"],
                        "properties": {
                            "category": {
                                "type": "string",
                                "enum": [
                                    category.value for category in ReviewCategory
                                ],
                            },
                            "file": {
                                "type": "string",
                                "minLength": 1,
                                "maxLength": 4096,
                            },
                            "concepts": {
                                "type": "array",
                                "minItems": 1,
                                "maxItems": 32,
                                "items": {
                                    "type": "string",
                                    "minLength": 1,
                                    "maxLength": 4096,
                                },
                            },
                            "line": {
                                "type": "integer",
                                "minimum": 1,
                                "maximum": 100_000,
                            },
                            "severity": {
                                "type": "string",
                                "enum": ["low", "medium", "high", "critical"],
                            },
                            "summary": {
                                "type": "string",
                                "maxLength": 4096,
                            },
                        },
                    },
                }
            },
        }
    )


def validate_p4_v3_response_schema() -> dict[str, Any]:
    """Validate and return the public P4-v3 response schema."""

    schema = p4_v3_response_schema()
    validate_schema_definition(schema, path="p4-v3.response")
    return schema


def validate_p4_v3_response(value: object) -> bool:
    """Validate one decoded response against the public P4-v3 contract."""

    return validate_json_schema(validate_p4_v3_response_schema(), value)


def p4_v3_schema_digest() -> str:
    """Return the stable digest of the model-visible response schema."""

    return canonical_digest(validate_p4_v3_response_schema())


__all__ = [
    "P4_V3_CATEGORY_ROLE_DEFINITIONS",
    "P4_V3_REQUIRED_FINDING_COUNT",
    "REVIEW_CATEGORY_CONTRACT_V3",
    "p4_v3_response_schema",
    "p4_v3_schema_digest",
    "validate_p4_v3_response",
    "validate_p4_v3_response_schema",
]
