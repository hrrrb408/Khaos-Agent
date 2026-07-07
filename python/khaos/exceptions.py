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

