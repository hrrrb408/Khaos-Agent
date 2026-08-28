"""Stable value objects exchanged at the tool-scheduler boundary.

The scheduler is responsible for admission and execution orchestration.  The
objects emitted by that orchestration are a separate, deliberately boring
protocol: they describe a handler outcome, an effect state, a permission
request, or a streamed event.  Keeping those value objects in this module gives
callers a small import surface without making them depend on the scheduler's
implementation details.

The old ``khaos.tools.scheduler`` import path re-exports these names for one
migration cycle.  New code should import them from this module directly.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

EFFECT_NOT_STARTED = "not_started"
EFFECT_NOT_APPLIED = "not_applied"
EFFECT_APPLIED = "applied"
EFFECT_PARTIAL = "partial"
EFFECT_UNKNOWN = "unknown"

# Public spelling for callers that prefer outcome terminology.  Keep the
# historical value for wire compatibility with existing ToolResult clients.
EFFECT_NO_EFFECT = EFFECT_NOT_APPLIED

DELIVERY_COMPLETE = "complete"
DELIVERY_DEGRADED = "degraded"
DELIVERY_AUDIT_DEGRADED = "audit_degraded"


@dataclass
class ToolExecutionOutcome:
    """Complete handler outcome used at the scheduler boundary.

    A normal Python value is still treated as a successful payload for
    backwards compatibility.  Mutation handlers that can report a handled
    business failure must return this type instead of an error-shaped dict;
    otherwise the scheduler cannot distinguish ``forbidden`` from a successful
    mutation response.
    """

    ok: bool = True
    output: Any = ""
    error: str = ""
    error_code: str = ""
    effect_status: str = ""
    effect_id: str = ""
    reconciliation_hint: str = ""
    retry_safe: bool = True

    def _legacy_payload(self) -> dict[str, Any]:
        """Expose the old JSON-shaped payload to direct tool callers.

        Handlers are migrated independently of callers that invoke them in
        tests or integrations without a Scheduler.  Mapping-like access keeps
        that compatibility while the scheduler consumes the typed fields.
        """
        payload = dict(self.output) if isinstance(self.output, dict) else {}
        payload.setdefault("ok", self.ok)
        if self.error:
            payload.setdefault("error", self.error)
        return payload

    def __getitem__(self, key: str) -> Any:
        return self._legacy_payload()[key]

    def get(self, key: str, default: Any = None) -> Any:
        return self._legacy_payload().get(key, default)

    def __contains__(self, key: object) -> bool:
        return key in self._legacy_payload()

    def __eq__(self, other: object) -> bool:
        if isinstance(other, dict):
            return self._legacy_payload() == other
        return super().__eq__(other)


@dataclass
class EffectOutcome:
    """Backward-compatible effect-only outcome.

    Existing handlers use ``status=...``.  New handlers should prefer
    :class:`ToolExecutionOutcome`, which also carries explicit business
    failure state and an error code.
    """

    status: str
    effect_id: str = ""
    reconciliation_hint: str = ""
    output: Any = ""
    ok: bool = True
    error: str = ""
    error_code: str = ""
    retry_safe: bool = True


@dataclass
class ToolResult:
    """Normalized result for one tool call."""

    tool_call_id: str
    name: str
    success: bool
    output: Any = ""
    error: str = ""
    error_code: str = ""
    duration_ms: int = 0
    arguments: dict[str, Any] | None = None
    # Effect and delivery are deliberately separate.  A handler may have
    # completed a mutation even when projection, auditing, budget accounting,
    # or remember-rule persistence fails afterwards.  Callers must not turn
    # such a result into an ordinary retryable failure.
    effect_status: str = EFFECT_NOT_STARTED
    delivery_status: str = DELIVERY_COMPLETE
    warning: str = ""
    effect_id: str = ""
    reconciliation_hint: str = ""
    retry_safe: bool = True
    # Immutable ToolScheduler phase evidence.  Empty is retained only for
    # direct legacy helper calls that bypass ``stream_batch``.
    phase_digest: str = ""


@dataclass
class PermissionRequest:
    """Permission request emitted before an ask-every call can execute."""

    tool_call_id: str
    name: str
    arguments: dict
    level: str
    target: str
    reason: str
    binding_digest: str = ""
    expires_at: float = 0.0
    principal_id: str = ""
    session_id: str = ""
    task_id: str = ""
    workspace_id: str = ""
    arguments_digest: str = ""
    profile_digest: str = ""
    project_id: str = ""
    workspace_generation: int = 0
    authorization_resource_digest: str = ""
    authorization_epoch: int = 0
    policy_digest: str = ""
    tool_schema_digest: str = ""
    tool_security_digest: str = ""
    approval_id: str = ""
    # Final digest of the immutable authority consumed by execution.  The
    # binding itself carries the pre-receipt scope digest.
    step_execution_digest: str = ""
    plan_revision_id: str = ""
    plan_revision_digest: str = ""
    plan_step_id: str = ""
    plan_step_digest: str = ""
    plan_execution_epoch_digest: str = ""
    plan_route_id: str = ""
    plan_route_digest: str = ""


@dataclass
class SchedulerEvent:
    """Streaming scheduler event."""

    event: str
    result: ToolResult | None = None
    permission_request: PermissionRequest | None = None
