"""Nominal security identities used at lifecycle and quarantine boundaries.

These aliases intentionally have the same runtime representation as ``str``.
They exist so static type checking can distinguish security resources that are
not interchangeable, even when their persistence layer stores text values.
"""
from __future__ import annotations

from typing import NewType

# These aliases deliberately remain ``NewType`` values for this migration
# step.  They preserve the string/int wire representation while making it
# impossible for the type checker to silently exchange identities from
# different security domains.  Runtime validation still belongs at the
# boundary that receives an untrusted value.
PrincipalId = NewType("PrincipalId", str)
ProjectId = NewType("ProjectId", str)
RuntimeId = NewType("RuntimeId", str)
TaskId = NewType("TaskId", str)
CanonicalWorkspaceId = NewType("CanonicalWorkspaceId", str)
WorkspaceGeneration = NewType("WorkspaceGeneration", int)
SessionId = NewType("SessionId", str)
ApprovalRequestId = NewType("ApprovalRequestId", str)
AuthorizationId = NewType("AuthorizationId", str)
GrantId = NewType("GrantId", str)
ReceiptNonce = NewType("ReceiptNonce", str)
ExecutionRunId = NewType("ExecutionRunId", str)
ExecutionContextId = NewType("ExecutionContextId", str)
LeaseId = NewType("LeaseId", str)
EffectId = NewType("EffectId", str)
VerificationRunId = NewType("VerificationRunId", str)
DisposableWorkspaceId = NewType("DisposableWorkspaceId", str)
SandboxInstanceId = NewType("SandboxInstanceId", str)

__all__ = [
    "ApprovalRequestId",
    "AuthorizationId",
    "CanonicalWorkspaceId",
    "DisposableWorkspaceId",
    "EffectId",
    "ExecutionContextId",
    "ExecutionRunId",
    "GrantId",
    "LeaseId",
    "PrincipalId",
    "ProjectId",
    "ReceiptNonce",
    "RuntimeId",
    "SandboxInstanceId",
    "SessionId",
    "TaskId",
    "VerificationRunId",
    "WorkspaceGeneration",
]
