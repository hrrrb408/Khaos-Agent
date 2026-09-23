"""Coding-mode browser/app contracts and the composed service."""

from khaos.coding.browser.artifacts import BrowserArtifactStore
from khaos.coding.browser.contracts import (
    AppHealth,
    AppInstance,
    AppInstanceState,
    AppLaunchProfile,
    BrowserAction,
    BrowserActionKind,
    BrowserActionResult,
    BrowserArtifactRef,
    BrowserAssertion,
    BrowserCheckAction,
    BrowserContractError,
    BrowserEffectClass,
    BrowserEffectStatus,
    BrowserObservation,
    BrowserResultStatus,
    BrowserRunResult,
    BrowserSessionBinding,
    BrowserSessionState,
    BrowserVerificationEvidence,
    BrowserVerificationSpec,
)
from khaos.coding.browser.metrics import BrowserMetrics
from khaos.coding.browser.service import (
    BrowserCodingService,
    BrowserEnvironmentBlocked,
    BrowserServiceError,
)
from khaos.coding.browser.state import BrowserStateJournalError, BrowserStateRepository

__all__ = [
    "AppHealth",
    "AppInstance",
    "AppInstanceState",
    "AppLaunchProfile",
    "BrowserAction",
    "BrowserActionKind",
    "BrowserActionResult",
    "BrowserArtifactRef",
    "BrowserArtifactStore",
    "BrowserAssertion",
    "BrowserCheckAction",
    "BrowserCodingService",
    "BrowserContractError",
    "BrowserEffectClass",
    "BrowserEffectStatus",
    "BrowserEnvironmentBlocked",
    "BrowserMetrics",
    "BrowserObservation",
    "BrowserResultStatus",
    "BrowserRunResult",
    "BrowserServiceError",
    "BrowserSessionBinding",
    "BrowserSessionState",
    "BrowserStateJournalError",
    "BrowserStateRepository",
    "BrowserVerificationEvidence",
    "BrowserVerificationSpec",
]
