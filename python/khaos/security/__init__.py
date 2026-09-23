"""Security utilities: command guard, path guard, credentials, secret scanner."""

from khaos.security.authority import AuthorityEnvelope
from khaos.security.authority_broker import (
    AuthorityBroker,
    AuthorityBrokerError,
    EffectCapability,
)
from khaos.security.command_guard import CommandCheckResult, CommandGuard
from khaos.security.credential_broker import (
    CredentialSession,
    CredentialSessionError,
    CredentialSessionLease,
    CredentialSessionLocked,
    CredentialSessionMissing,
    CredentialUnlockCancelled,
)
from khaos.security.credentials import (
    CredentialAccessMode,
    CredentialHandle,
    CredentialNotFound,
    CredentialProvisioningCancelled,
    CredentialRef,
    CredentialReferenceError,
    CredentialStore,
    CredentialStoreDiagnostic,
    CredentialStoreError,
    CredentialStoreUnavailable,
    InMemoryCredentialStore,
    LinuxSecretServiceCredentialStore,
    MacOSKeychainCredentialStore,
    SecretValue,
    UnavailableCredentialStore,
    build_platform_credential_store,
    credential_store_backend_audit,
)
from khaos.security.middleware import SecurityCheckResult, SecurityMiddleware
from khaos.security.network_broker import (
    NetworkBroker,
    NetworkBrokerError,
    NetworkBrokerFactory,
    NetworkLease,
)
from khaos.security.orchestration_phases import (
    OrchestrationPhaseError,
    ToolPhase,
    ToolPhaseSnapshot,
    TurnPhase,
    TurnPhaseSnapshot,
)
from khaos.security.path_guard import PathCheckResult, PathGuard
from khaos.security.secret_redaction import SecretRedactor
from khaos.security.secret_scanner import ScanResult, SecretMatch, SecretScanner

__all__ = [
    "AuthorityBroker",
    "AuthorityBrokerError",
    "AuthorityEnvelope",
    "CommandCheckResult",
    "CommandGuard",
    "CredentialAccessMode",
    "CredentialHandle",
    "CredentialNotFound",
    "CredentialProvisioningCancelled",
    "CredentialRef",
    "CredentialReferenceError",
    "CredentialSession",
    "CredentialSessionError",
    "CredentialSessionLease",
    "CredentialSessionLocked",
    "CredentialSessionMissing",
    "CredentialStore",
    "CredentialStoreDiagnostic",
    "CredentialStoreError",
    "CredentialStoreUnavailable",
    "CredentialUnlockCancelled",
    "EffectCapability",
    "InMemoryCredentialStore",
    "LinuxSecretServiceCredentialStore",
    "MacOSKeychainCredentialStore",
    "NetworkBroker",
    "NetworkBrokerError",
    "NetworkBrokerFactory",
    "NetworkLease",
    "OrchestrationPhaseError",
    "PathCheckResult",
    "PathGuard",
    "ScanResult",
    "SecretMatch",
    "SecretRedactor",
    "SecretScanner",
    "SecretValue",
    "SecurityCheckResult",
    "SecurityMiddleware",
    "ToolPhase",
    "ToolPhaseSnapshot",
    "TurnPhase",
    "TurnPhaseSnapshot",
    "UnavailableCredentialStore",
    "build_platform_credential_store",
    "credential_store_backend_audit",
]
