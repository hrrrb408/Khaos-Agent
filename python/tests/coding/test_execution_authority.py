"""Cross-binding tests for the single execution authority envelope."""

from __future__ import annotations

import pytest

from khaos.agent.approval import StepExecutionAuthority
from khaos.coding.execution import ExecutionAuthority, ResolvedSpawnPlan


def _authority() -> ExecutionAuthority:
    plan = ResolvedSpawnPlan(
        principal_id="principal",
        project_id="project",
        session_id="session",
        task_id="task",
        turn_id="turn",
        step_id="step",
        workspace_generation=1,
        workspace_root_device=1,
        workspace_root_inode=2,
        workspace_cwd_device=1,
        workspace_cwd_inode=3,
        permission_profile_digest="profile",
        sandbox_decision_digest="sandbox",
        network_authority="network",
        environment=(("PATH", "/bin"),),
        executable_identity="executable",
        argv=("/bin/echo", "ok"),
        budget_digest="budget",
    )
    step = StepExecutionAuthority(
        principal_id="principal",
        project_id="project",
        session_id="session",
        task_id="task",
        turn_id="turn",
        step_id="step",
        tool_call_id="call",
        tool_name="terminal",
        workspace_id="workspace",
        workspace_generation=1,
        cwd_identity="cwd",
        permission_profile_digest="profile",
        environment_keys=("PATH",),
        environment_digest="environment",
        sandbox_backend="sandbox",
        sandbox_decision_digest="sandbox",
        executable_identity="executable",
        network_authority="network",
        target="target",
        approval_target="approval",
        arguments_digest="arguments",
        authorization_resource_digest="resource",
        authorization_epoch=1,
        policy_digest="policy",
        tool_schema_digest="schema",
        tool_security_digest="security",
        spawn_plan_digest=plan.digest(),
    )
    return ExecutionAuthority(step_authority=step, spawn_plan=plan)


def test_execution_authority_binds_step_and_spawn_plan() -> None:
    authority = _authority()
    assert authority.is_valid()
    assert authority.digest()


def test_execution_authority_rejects_divergent_plan() -> None:
    authority = _authority()
    changed_plan = ResolvedSpawnPlan(
        **{
            **authority.spawn_plan.__dict__,
            "executable_identity": "different-executable",
            "plan_digest": "",
        }
    )
    with pytest.raises(ValueError, match="plan digest"):
        ExecutionAuthority(
            step_authority=authority.step_authority,
            spawn_plan=changed_plan,
        )
