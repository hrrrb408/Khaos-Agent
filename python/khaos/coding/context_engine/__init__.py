"""M8.4 Context Engine public API."""

from khaos.coding.context_engine.cache import ContextCache, ContextCacheKey
from khaos.coding.context_engine.compression import CompactionResult, ContextCompactor
from khaos.coding.context_engine.contracts import (
    CONTEXT_SCHEMA_VERSION,
    GENERATION_BOUND_SOURCES,
    ContextBudget,
    ContextContractError,
    ContextItem,
    ContextItemKind,
    ContextLayer,
    ContextMessage,
    ContextMetricsSnapshot,
    ContextOperation,
    ContextRequirements,
    ContextSelection,
    ContextSource,
    ContextTrust,
    ModelContext,
    TaskStateSummary,
    approximate_token_count,
)
from khaos.coding.context_engine.discovery import (
    CORE_TOOL_NAMES,
    DeferredToolDiscovery,
    LazySkillDiscovery,
    SkillMetadata,
    ToolDiscoveryResult,
)
from khaos.coding.context_engine.selector import ContextSelector
from khaos.coding.context_engine.serializer import ContextSerializer, SerializedContext
from khaos.coding.context_engine.service import ContextEngineService
from khaos.coding.context_engine.tools import (
    ToolOutputEnvelope,
    ToolOutputLimits,
    ToolOutputPolicy,
    bound_tool_result,
)
from khaos.coding.context_engine.working_set import (
    InMemoryWorkingSetStore,
    TaskWorkingSet,
    WorkingSetEvent,
)

# Short alias used by integrations that refer to the component as the
# Context Engine rather than its service implementation.
ContextEngine = ContextEngineService

__all__ = [
    "CONTEXT_SCHEMA_VERSION",
    "CORE_TOOL_NAMES",
    "GENERATION_BOUND_SOURCES",
    "CompactionResult",
    "ContextBudget",
    "ContextCache",
    "ContextCacheKey",
    "ContextCompactor",
    "ContextContractError",
    "ContextEngine",
    "ContextEngineService",
    "ContextItem",
    "ContextItemKind",
    "ContextLayer",
    "ContextMessage",
    "ContextMetricsSnapshot",
    "ContextOperation",
    "ContextRequirements",
    "ContextSelection",
    "ContextSelector",
    "ContextSerializer",
    "ContextSource",
    "ContextTrust",
    "DeferredToolDiscovery",
    "InMemoryWorkingSetStore",
    "LazySkillDiscovery",
    "ModelContext",
    "SerializedContext",
    "SkillMetadata",
    "TaskStateSummary",
    "TaskWorkingSet",
    "ToolDiscoveryResult",
    "ToolOutputEnvelope",
    "ToolOutputLimits",
    "ToolOutputPolicy",
    "WorkingSetEvent",
    "approximate_token_count",
    "bound_tool_result",
]
