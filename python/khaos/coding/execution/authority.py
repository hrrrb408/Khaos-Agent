"""Single typed authority envelope for approved execution steps."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass

from khaos.agent.approval import StepExecutionAuthority
from khaos.coding.execution.models import ResolvedSpawnPlan


@dataclass(frozen=True)
class ExecutionAuthority:
    """Bind the approval snapshot and final spawn plan as one authority.

    The scheduler may keep the two immutable records for compatibility with
    existing approval storage, but the execution boundary receives this
    envelope and refuses a plan whose identity fields diverge from the
    approved step.  This prevents a caller from presenting a valid
    ``StepExecutionAuthority`` beside a different valid ``ResolvedSpawnPlan``.
    """

    step_authority: StepExecutionAuthority
    spawn_plan: ResolvedSpawnPlan

    def __post_init__(self) -> None:
        if not isinstance(self.step_authority, StepExecutionAuthority):
            raise TypeError("execution authority requires StepExecutionAuthority")
        if not isinstance(self.spawn_plan, ResolvedSpawnPlan):
            raise TypeError("execution authority requires ResolvedSpawnPlan")
        if self.step_authority.spawn_plan_digest != self.spawn_plan.digest():
            raise ValueError("execution authority plan digest does not match approval")
        if self.step_authority.authority_context().digest() != self.spawn_plan.authority_context().digest():
            raise ValueError("execution authority owner context diverged")
        pairs = (
            (self.step_authority.principal_id, self.spawn_plan.principal_id),
            (self.step_authority.principal_kind, self.spawn_plan.principal_kind),
            (self.step_authority.parent_principal_id, self.spawn_plan.parent_principal_id),
            (self.step_authority.delegation_digest, self.spawn_plan.delegation_digest),
            (self.step_authority.project_id, self.spawn_plan.project_id),
            (self.step_authority.session_id, self.spawn_plan.session_id),
            (self.step_authority.task_id, self.spawn_plan.task_id),
            (self.step_authority.turn_id, self.spawn_plan.turn_id),
            (self.step_authority.step_id, self.spawn_plan.step_id),
            (self.step_authority.workspace_generation, self.spawn_plan.workspace_generation),
            (
                self.step_authority.permission_profile_digest,
                self.spawn_plan.permission_profile_digest,
            ),
            (
                self.step_authority.sandbox_decision_digest,
                self.spawn_plan.sandbox_decision_digest,
            ),
            (self.step_authority.network_authority, self.spawn_plan.network_authority),
            (self.step_authority.executable_identity, self.spawn_plan.executable_identity),
            (self.step_authority.tool_name, self.spawn_plan.tool_name),
            (
                self.step_authority.authorization_resource_digest,
                self.spawn_plan.authorization_resource_digest,
            ),
            (self.step_authority.runtime_id, self.spawn_plan.runtime_id),
            (self.step_authority.source_transport, self.spawn_plan.source_transport),
            (self.step_authority.authorization_epoch, self.spawn_plan.authorization_epoch),
            (self.step_authority.workspace_id, self.spawn_plan.workspace_id),
            (self.step_authority.policy_digest, self.spawn_plan.policy_digest),
        )
        if any(left != right for left, right in pairs):
            raise ValueError("execution authority approval and spawn plan diverged")
        if tuple(self.step_authority.environment_keys) != tuple(
            key for key, _ in self.spawn_plan.environment
        ):
            raise ValueError("execution authority environment keys diverged")

    def _payload(self) -> dict[str, str]:
        return {
            "step_authority": self.step_authority.digest(),
            "spawn_plan": self.spawn_plan.digest(),
        }

    def digest(self) -> str:
        """Return the immutable combined authority digest."""
        encoded = json.dumps(
            self._payload(), sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

    def is_valid(self) -> bool:
        """Return whether both records and their cross-binding remain valid."""
        try:
            if not self.spawn_plan.is_valid():
                return False
            self.__post_init__()
        except (TypeError, ValueError):
            return False
        return True
