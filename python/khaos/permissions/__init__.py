"""Permission engine."""

from khaos.permissions.engine import (
    ApprovalMode,
    GrantLifetime,
    PermissionDecision,
    PermissionEngine,
    PermissionRule,
    SourceTransport,
    TransportClass,
    is_interactive_transport,
    validate_rule_scope,
)
from khaos.permissions.resource import (
    AuthorizationResource,
    resolve_authorization_resource,
)
from khaos.permissions.rules import (
    PermissionResourceType,
    legacy_pattern_to_typed,
    match_typed_rule,
    typed_rule_from_authorization_resource,
    validate_typed_rule,
)

__all__ = [
    "ApprovalMode",
    "AuthorizationResource",
    "GrantLifetime",
    "PermissionDecision",
    "PermissionEngine",
    "PermissionRule",
    "PermissionResourceType",
    "SourceTransport",
    "TransportClass",
    "is_interactive_transport",
    "resolve_authorization_resource",
    "validate_rule_scope",
    "legacy_pattern_to_typed",
    "match_typed_rule",
    "typed_rule_from_authorization_resource",
    "validate_typed_rule",
]
