"""Shared Khaos exception hierarchy."""


class KhaosError(Exception):
    """Base exception for Khaos runtime errors."""


class ModelUnavailableError(KhaosError):
    """Raised when no configured model can serve a function."""


class ToolNotFoundError(KhaosError):
    """Raised when a requested tool is not registered."""


class PermissionDeniedError(KhaosError):
    """Raised when a tool call is denied by policy."""


class SubAgentLimitError(KhaosError):
    """Raised when sub-agent nesting exceeds the configured limit."""


class CompressionCircuitOpenError(KhaosError):
    """Raised when repeated compression failures open the circuit."""


class RuntimeCloseError(KhaosError):
    """Raised when runtime cleanup fails after exhausting retries.

    H4: ``RuntimeResult.aclose`` raises this when safety-critical
    components (OfficeMutationAuthority, ExecutionService, MemoryManager)
    fail to reach a terminal state after 3 attempts.  The caller
    (AgentService / SubAgentRunner) must observe the failure and
    escalate — call ``register_orphan_runtime(runtime)`` so the
    orphan-cleanup registry retains the runtime's component references
    for a later retry via ``cleanup_orphan_runtimes()``.  Without this,
    the runtime's file descriptors / Office mutation fences /
    BrowserContexts would be silently leaked because the caller discarded
    the reference after the exception.
    """


class ServiceShutdownError(KhaosError):
    """Raised when a server-owned authority cannot reach a safe terminal state."""
