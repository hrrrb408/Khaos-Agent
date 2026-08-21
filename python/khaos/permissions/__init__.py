"""Permission engine and pure decision value types."""

from khaos.permissions.engine import (
    PermissionEngine,
    is_interactive_transport,
    validate_rule_scope,
)
from khaos.permissions.evaluator import PermissionEvaluator
from khaos.permissions.models import (
    ApprovalMode,
    GrantLifetime,
    PermissionDecision,
    PermissionRule,
    SourceTransport,
    TransportClass,
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
    "PermissionEvaluator",
    "PermissionResourceType",
    "PermissionRule",
    "SourceTransport",
    "TransportClass",
    "is_interactive_transport",
    "legacy_pattern_to_typed",
    "match_typed_rule",
    "resolve_authorization_resource",
    "typed_rule_from_authorization_resource",
    "validate_rule_scope",
    "validate_typed_rule",
]
