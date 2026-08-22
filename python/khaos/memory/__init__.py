"""Public memory domain API.

Persistence and policy modules remain importable for composition and tests,
while the names historically imported from ``khaos.memory`` stay stable.
"""

from khaos.memory.conflict import ConflictDecision, ConflictResolver
from khaos.memory.decay import expired_memory_ids
from khaos.memory.extraction import (
    extract_memories_from_messages,
    extract_memories_from_text,
)
from khaos.memory.manager import MemoryBudget, MemoryManager
from khaos.memory.models import Memory, MemoryConfidence, MemoryScope
from khaos.memory.ownership import MemoryOwner, MemoryVisibility
from khaos.memory.repository import MemoryRepository, SqliteMemoryRepository
from khaos.memory.retrieval import MemoryLayers, MemoryRetriever
from khaos.memory.store import MemoryStore

__all__ = [
    "ConflictDecision",
    "ConflictResolver",
    "Memory",
    "MemoryBudget",
    "MemoryConfidence",
    "MemoryLayers",
    "MemoryManager",
    "MemoryOwner",
    "MemoryRepository",
    "MemoryRetriever",
    "MemoryScope",
    "MemoryStore",
    "MemoryVisibility",
    "SqliteMemoryRepository",
    "expired_memory_ids",
    "extract_memories_from_messages",
    "extract_memories_from_text",
]
