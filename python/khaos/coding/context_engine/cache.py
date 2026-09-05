"""Task/generation-scoped bounded context cache."""

from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass
from threading import RLock

from khaos.coding.context_engine.contracts import ModelContext
from khaos.security.protocol_boundary import canonical_digest


@dataclass(frozen=True, slots=True)
class ContextCacheKey:
    """All state that can make a context snapshot non-reusable."""

    workspace_id: str
    task_id: str
    generation: str | None
    plan_revision: str | None
    step_id: str | None
    requirements_digest: str
    candidate_digest: str
    verification_state: str | None = None
    scope_id: str = "parent"
    principal_id: str = ""
    project_id: str = ""

    @property
    def digest(self) -> str:
        return canonical_digest(
            {
                "workspace_id": self.workspace_id,
                "task_id": self.task_id,
                "generation": self.generation,
                "plan_revision": self.plan_revision,
                "step_id": self.step_id,
                "requirements_digest": self.requirements_digest,
                "candidate_digest": self.candidate_digest,
                "verification_state": self.verification_state,
                "scope_id": self.scope_id,
                "principal_id": self.principal_id,
                "project_id": self.project_id,
            }
        )


class ContextCache:
    """An LRU cache bounded by entry count and serialized bytes."""

    def __init__(self, *, max_entries: int = 128, max_bytes: int = 8 * 1024 * 1024) -> None:
        if type(max_entries) is not int or max_entries <= 0:
            raise ValueError("context cache max_entries must be positive")
        if type(max_bytes) is not int or max_bytes <= 0:
            raise ValueError("context cache max_bytes must be positive")
        self.max_entries = max_entries
        self.max_bytes = max_bytes
        self._values: OrderedDict[str, tuple[ModelContext, int, ContextCacheKey]] = OrderedDict()
        self._bytes = 0
        self._lock = RLock()

    def get(self, key: ContextCacheKey) -> ModelContext | None:
        with self._lock:
            entry = self._values.get(key.digest)
            if entry is None:
                return None
            self._values.move_to_end(key.digest)
            return entry[0]

    def put(self, key: ContextCacheKey, context: ModelContext) -> None:
        size = sum(len(message.content.encode("utf-8")) for message in context.messages)
        if size > self.max_bytes:
            return
        with self._lock:
            previous = self._values.pop(key.digest, None)
            if previous is not None:
                self._bytes -= previous[1]
            self._values[key.digest] = (context, size, key)
            self._bytes += size
            while len(self._values) > self.max_entries or self._bytes > self.max_bytes:
                _, (_, removed_size, _) = self._values.popitem(last=False)
                self._bytes -= removed_size

    def invalidate(
        self,
        *,
        workspace_id: str | None = None,
        task_id: str | None = None,
        generation: str | None = None,
        scope_id: str | None = None,
    ) -> int:
        """Remove matching entries and return the number removed."""

        with self._lock:
            removed = 0
            for digest, (_, size, key) in list(self._values.items()):
                if workspace_id is not None and key.workspace_id != workspace_id:
                    continue
                if task_id is not None and key.task_id != task_id:
                    continue
                if generation is not None and key.generation != generation:
                    continue
                if scope_id is not None and key.scope_id != scope_id:
                    continue
                self._values.pop(digest, None)
                self._bytes -= size
                removed += 1
            return removed

    def clear(self) -> None:
        with self._lock:
            self._values.clear()
            self._bytes = 0

    def snapshot(self) -> dict[str, object]:
        with self._lock:
            return {"entries": len(self._values), "bytes": self._bytes}
