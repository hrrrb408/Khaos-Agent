"""Coding-mode repository analysis helpers.

The public names are loaded lazily.  The native execution launcher imports a
small execution submodule from this package after it has scrubbed the child
environment; eager analysis imports would otherwise pull optional HTTP/model
dependencies into that security boundary.
"""

from importlib import import_module

_LAZY_EXPORTS = {
    "CodingContextBuilder": ("khaos.coding.context", "CodingContextBuilder"),
    "CostTracker": ("khaos.coding.cost_tracker", "CostTracker"),
    "SessionCostReport": ("khaos.coding.cost_tracker", "SessionCostReport"),
    "TurnCost": ("khaos.coding.cost_tracker", "TurnCost"),
    "FileFingerprintCache": ("khaos.coding.fingerprint", "FileFingerprintCache"),
    "RepoIndexer": ("khaos.coding.indexer", "RepoIndexer"),
    "CodeParser": ("khaos.coding.parser", "CodeParser"),
    "build_call_graph": ("khaos.coding.parser", "build_call_graph"),
    "build_dependency_graph": ("khaos.coding.parser", "build_dependency_graph"),
    "CodingTask": ("khaos.coding.task_manager", "CodingTask"),
    "TaskManager": ("khaos.coding.task_manager", "TaskManager"),
    "TaskStatus": ("khaos.coding.task_manager", "TaskStatus"),
    "VerifyFixLoop": ("khaos.coding.verify_fix", "VerifyFixLoop"),
    "EditOperation": ("khaos.coding.edit_transaction", "EditOperation"),
    "EditOperationKind": ("khaos.coding.edit_transaction", "EditOperationKind"),
    "EditTransaction": ("khaos.coding.edit_transaction", "EditTransaction"),
    "EditTransactionEngine": (
        "khaos.coding.edit_transaction",
        "EditTransactionEngine",
    ),
    "EditTransactionService": (
        "khaos.coding.edit_transaction",
        "EditTransactionService",
    ),
    "TextEdit": ("khaos.coding.edit_transaction", "TextEdit"),
    "ContextBudget": ("khaos.coding.context_engine", "ContextBudget"),
    "ContextCache": ("khaos.coding.context_engine", "ContextCache"),
    "ContextEngineService": ("khaos.coding.context_engine", "ContextEngineService"),
    "ContextEngine": ("khaos.coding.context_engine", "ContextEngine"),
    "ContextItem": ("khaos.coding.context_engine", "ContextItem"),
    "ContextItemKind": ("khaos.coding.context_engine", "ContextItemKind"),
    "ContextLayer": ("khaos.coding.context_engine", "ContextLayer"),
    "ContextMetricsSnapshot": ("khaos.coding.context_engine", "ContextMetricsSnapshot"),
    "ContextOperation": ("khaos.coding.context_engine", "ContextOperation"),
    "ContextRequirements": ("khaos.coding.context_engine", "ContextRequirements"),
    "ContextSelector": ("khaos.coding.context_engine", "ContextSelector"),
    "ContextSource": ("khaos.coding.context_engine", "ContextSource"),
    "ContextTrust": ("khaos.coding.context_engine", "ContextTrust"),
    "DeferredToolDiscovery": ("khaos.coding.context_engine", "DeferredToolDiscovery"),
    "TaskWorkingSet": ("khaos.coding.context_engine", "TaskWorkingSet"),
    "ToolOutputEnvelope": ("khaos.coding.context_engine", "ToolOutputEnvelope"),
}


def __getattr__(name: str):
    """Load one public coding helper on first access."""
    target = _LAZY_EXPORTS.get(name)
    if target is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    module = import_module(target[0])
    value = getattr(module, target[1])
    globals()[name] = value
    return value


def __dir__() -> list[str]:
    """Expose lazy public names to introspection and IDEs."""
    return sorted(set(globals()) | set(__all__))

__all__ = [
    "CodeParser",
    "CodingContextBuilder",
    "CodingTask",
    "ContextBudget",
    "ContextCache",
    "ContextEngine",
    "ContextEngineService",
    "ContextItem",
    "ContextItemKind",
    "ContextLayer",
    "ContextMetricsSnapshot",
    "ContextOperation",
    "ContextRequirements",
    "ContextSelector",
    "ContextSource",
    "ContextTrust",
    "CostTracker",
    "DeferredToolDiscovery",
    "EditOperation",
    "EditOperationKind",
    "EditTransaction",
    "EditTransactionEngine",
    "EditTransactionService",
    "FileFingerprintCache",
    "RepoIndexer",
    "SessionCostReport",
    "TaskManager",
    "TaskStatus",
    "TaskWorkingSet",
    "TextEdit",
    "ToolOutputEnvelope",
    "TurnCost",
    "VerifyFixLoop",
    "build_call_graph",
    "build_dependency_graph",
]
