"""Bounded copy-on-write task working sets for M8.4."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field, replace
from threading import RLock

from khaos.coding.context_engine.contracts import (
    CONTEXT_SCHEMA_VERSION,
    ContextContractError,
    ContextItem,
    ContextItemKind,
    ContextLayer,
    ContextSource,
    ContextTrust,
    TaskStateSummary,
    _normalize_generation,
)
from khaos.security.protocol_boundary import canonical_digest, canonical_json_bytes

MAX_WORKING_SET_ITEMS = 256
MAX_WORKING_SET_FILES = 128
MAX_WORKING_SET_TEXT_BYTES = 8 * 1024
WORKING_SET_METADATA_KEY = "context_working_set"


def _bounded_text(value: object, *, default: str = "") -> str:
    if value is None:
        return default
    text = str(value).strip()
    if not text:
        return default
    raw = text.encode("utf-8")
    if len(raw) <= MAX_WORKING_SET_TEXT_BYTES:
        return text
    return raw[:MAX_WORKING_SET_TEXT_BYTES].decode("utf-8", errors="ignore")


def _bounded_values(value: object, *, limit: int = MAX_WORKING_SET_FILES) -> tuple[str, ...]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        return ()
    values = {
        _bounded_text(item)
        for item in value
        if isinstance(item, str) and item.strip()
    }
    return tuple(sorted(values))[:limit]


@dataclass(frozen=True, slots=True)
class WorkingSetEvent:
    """One bounded runtime event projected into the working set."""

    kind: str
    payload: Mapping[str, object] = field(default_factory=dict)
    sequence: int = 0

    def __post_init__(self) -> None:
        if type(self.kind) is not str or not self.kind.strip() or len(self.kind) > 128:
            raise ContextContractError("working-set event kind is invalid")
        if type(self.payload) is not Mapping and not isinstance(self.payload, Mapping):
            raise ContextContractError("working-set event payload is invalid")
        if type(self.sequence) is not int or self.sequence < 0:
            raise ContextContractError("working-set event sequence is invalid")
        payload = dict(self.payload)
        try:
            if len(canonical_json_bytes(payload)) > 16 * 1024:
                raise ContextContractError("working-set event payload exceeds its bound")
        except ContextContractError:
            raise
        except (TypeError, ValueError) as exc:
            raise ContextContractError("working-set event payload is not JSON-safe") from exc
        object.__setattr__(self, "payload", payload)


@dataclass(frozen=True, slots=True)
class TaskWorkingSet:
    """Immutable task state projection with bounded durable references."""

    task_id: str
    principal_id: str = ""
    project_id: str = ""
    workspace_id: str = ""
    generation: str | None = None
    goal: str = ""
    constraints: tuple[str, ...] = ()
    goal_digest: str | None = None
    plan_revision: str | None = None
    active_step_id: str | None = None
    changed_files: tuple[str, ...] = ()
    viewed_files: tuple[str, ...] = ()
    important_paths: tuple[str, ...] = ()
    important_symbols: tuple[str, ...] = ()
    active_diagnostics: tuple[str, ...] = ()
    hypotheses: tuple[str, ...] = ()
    decisions: tuple[str, ...] = ()
    open_questions: tuple[str, ...] = ()
    verification_state: str | None = None
    items: tuple[ContextItem, ...] = ()
    event_sequence: int = 0
    schema_version: int = CONTEXT_SCHEMA_VERSION

    def __post_init__(self) -> None:
        for name in ("task_id", "principal_id", "project_id", "workspace_id", "goal"):
            value = getattr(self, name)
            if type(value) is not str or len(value) > 16 * 1024 or "\x00" in value:
                raise ContextContractError(f"working-set {name} is invalid")
        object.__setattr__(
            self,
            "generation",
            _normalize_generation(self.generation, label="generation"),
        )
        for name in ("goal_digest", "plan_revision", "active_step_id"):
            value = getattr(self, name)
            if value is not None and (type(value) is not str or len(value) > 2048 or "\x00" in value):
                raise ContextContractError(f"working-set {name} is invalid")
        for name in ("changed_files", "viewed_files"):
            value = getattr(self, name)
            if type(value) is not tuple or len(value) > MAX_WORKING_SET_FILES:
                raise ContextContractError(f"working-set {name} is invalid")
            if any(type(path) is not str or not path or len(path) > 2048 for path in value):
                raise ContextContractError(f"working-set {name} is invalid")
        for name in (
            "constraints",
            "important_paths",
            "important_symbols",
            "active_diagnostics",
            "hypotheses",
            "decisions",
            "open_questions",
        ):
            value = getattr(self, name)
            if type(value) is not tuple or len(value) > MAX_WORKING_SET_FILES:
                raise ContextContractError(f"working-set {name} is invalid")
            if any(type(item) is not str or not item or len(item) > MAX_WORKING_SET_TEXT_BYTES for item in value):
                raise ContextContractError(f"working-set {name} is invalid")
        if self.verification_state is not None and (
            type(self.verification_state) is not str
            or len(self.verification_state) > 256
            or "\x00" in self.verification_state
        ):
            raise ContextContractError("working-set verification state is invalid")
        if type(self.items) is not tuple or len(self.items) > MAX_WORKING_SET_ITEMS:
            raise ContextContractError("working-set items are invalid")
        if any(type(item) is not ContextItem for item in self.items):
            raise ContextContractError("working-set items are not typed")
        if type(self.event_sequence) is not int or self.event_sequence < 0:
            raise ContextContractError("working-set event sequence is invalid")
        if self.schema_version != CONTEXT_SCHEMA_VERSION:
            raise ContextContractError("working-set schema version is unsupported")

    @classmethod
    def empty(
        cls,
        task_id: str,
        *,
        principal_id: str = "",
        project_id: str = "",
        workspace_id: str = "",
        goal: str = "",
        constraints: tuple[str, ...] = (),
        generation: str | None = None,
    ) -> TaskWorkingSet:
        return cls(
            task_id=task_id,
            principal_id=principal_id,
            project_id=project_id,
            workspace_id=workspace_id,
            goal=goal,
            constraints=constraints,
            generation=generation,
        )

    @property
    def digest(self) -> str:
        return canonical_digest(self._payload_without_digest())

    def _add_item(self, item: ContextItem) -> TaskWorkingSet:
        # Durable state keeps repository content as references, while small
        # control summaries/diagnostics remain available for recovery and
        # compaction. Nothing can exceed the working-set text bound.
        bounded = (
            item.reference()
            if item.kind
            in {
                ContextItemKind.FILE_REGION,
                ContextItemKind.SYMBOL,
                ContextItemKind.RELATION,
                ContextItemKind.TOOL_RESULT,
            }
            else item.truncated_to(max_bytes=MAX_WORKING_SET_TEXT_BYTES)
        )
        by_key = {existing.identity_key: existing for existing in self.items}
        by_key[bounded.identity_key] = bounded
        values = sorted(
            by_key.values(),
            key=lambda value: (-int(value.required), -value.priority, value.sequence, value.item_id),
        )[:MAX_WORKING_SET_ITEMS]
        changes: dict[str, object] = {}
        if item.kind is ContextItemKind.FILE_REGION and item.path:
            changes["important_paths"] = tuple(sorted(set(self.important_paths) | {item.path}))[:MAX_WORKING_SET_FILES]
        if item.kind is ContextItemKind.SYMBOL and item.symbol:
            changes["important_symbols"] = tuple(sorted(set(self.important_symbols) | {item.symbol}))[:MAX_WORKING_SET_FILES]
        if item.kind is ContextItemKind.DIAGNOSTIC and bounded.payload:
            changes["active_diagnostics"] = tuple(
                dict.fromkeys((*self.active_diagnostics, bounded.payload))
            )[-64:]
        if item.kind is ContextItemKind.HYPOTHESIS and bounded.payload:
            changes["hypotheses"] = tuple(
                dict.fromkeys((*self.hypotheses, bounded.payload))
            )[-64:]
        if item.kind is ContextItemKind.DECISION and bounded.payload:
            changes["decisions"] = tuple(
                dict.fromkeys((*self.decisions, bounded.payload))
            )[-64:]
        if item.kind is ContextItemKind.BLOCKER and bounded.payload:
            changes["open_questions"] = tuple(
                dict.fromkeys((*self.open_questions, bounded.payload))
            )[-64:]
        if item.kind is ContextItemKind.VERIFICATION_SUMMARY and bounded.payload:
            changes["verification_state"] = bounded.payload[:256]
        return replace(self, items=tuple(values), **changes)

    def apply_event(
        self,
        event: WorkingSetEvent | str | Mapping[str, object],
        payload: Mapping[str, object] | None = None,
    ) -> TaskWorkingSet:
        """Project one runtime event without changing any authority state."""

        if isinstance(event, WorkingSetEvent):
            observed = event
        elif isinstance(event, Mapping):
            raw_payload = event.get("payload", event)
            event_payload = raw_payload if isinstance(raw_payload, Mapping) else {}
            raw_sequence = event.get("sequence", 0)
            event_sequence = raw_sequence if type(raw_sequence) is int else 0
            observed = WorkingSetEvent(
                kind=str(event.get("kind") or event.get("event") or "unknown"),
                payload=event_payload,
                sequence=event_sequence,
            )
        else:
            observed = WorkingSetEvent(kind=event, payload=payload or {})
        values = dict(observed.payload)
        normalized = observed.kind.casefold().replace(".", "_").replace("-", "_")
        sequence = max(self.event_sequence, observed.sequence)
        if observed.sequence == 0:
            sequence += 1

        workspace_id = _bounded_text(values.get("workspace_id"), default=self.workspace_id)
        generation = values.get("generation") or values.get("repository_generation")
        if generation is not None:
            generation = _bounded_text(generation, default=self.generation or "") or None
        changed = set(self.changed_files)
        changed.update(_bounded_values(values.get("changed_files")))
        viewed = set(self.viewed_files)
        viewed.update(_bounded_values(values.get("viewed_files")))
        important_paths = set(self.important_paths)
        important_paths.update(_bounded_values(values.get("important_paths")))
        important_symbols = set(self.important_symbols)
        important_symbols.update(_bounded_values(values.get("important_symbols")))
        constraints = set(self.constraints)
        constraints.update(_bounded_values(values.get("constraints"), limit=64))
        raw_constraint = values.get("constraint")
        if isinstance(raw_constraint, str) and raw_constraint.strip():
            constraints.add(_bounded_text(raw_constraint))
        current_items = self.items
        if generation and generation != self.generation:
            current_items = tuple(
                item
                for item in current_items
                if item.generation in (None, generation)
                or item.kind
                in {
                    ContextItemKind.GOAL,
                    ContextItemKind.PLAN,
                    ContextItemKind.PLAN_STEP,
                    ContextItemKind.DECISION,
                    ContextItemKind.HYPOTHESIS,
                    ContextItemKind.BLOCKER,
                }
            )
        current = replace(
            self,
            workspace_id=workspace_id,
            generation=generation or self.generation,
            goal=_bounded_text(values.get("goal"), default=self.goal),
            constraints=tuple(sorted(constraints))[:64],
            plan_revision=(
                _bounded_text(values.get("plan_revision"), default=self.plan_revision or "")
                or self.plan_revision
            ),
            active_step_id=(
                _bounded_text(values.get("step_id"), default=self.active_step_id or "")
                or self.active_step_id
            ),
            changed_files=tuple(sorted(changed))[:MAX_WORKING_SET_FILES],
            viewed_files=tuple(sorted(viewed))[:MAX_WORKING_SET_FILES],
            important_paths=tuple(sorted(important_paths))[:MAX_WORKING_SET_FILES],
            important_symbols=tuple(sorted(important_symbols))[:MAX_WORKING_SET_FILES],
            items=current_items,
            active_diagnostics=()
            if generation and generation != self.generation
            else self.active_diagnostics,
            verification_state=(
                None
                if generation and generation != self.generation
                else self.verification_state
            ),
            event_sequence=sequence,
        )

        if normalized in {"planrevision", "plan_revision", "plancreated", "plan_created"}:
            item = _event_item(
                current,
                kind=ContextItemKind.PLAN,
                source=ContextSource.RUNTIME,
                trust=ContextTrust.TRUSTED_RUNTIME,
                payload=values.get("plan") or values.get("summary") or values.get("plan_revision"),
                priority=90,
                required=True,
                sequence=sequence,
            )
            return current._add_item(item) if item is not None else current
        if normalized in {"planstepstarted", "plan_step_started", "step_started"}:
            current = replace(
                current,
                items=tuple(item for item in current.items if item.layer is not ContextLayer.L2 and item.layer is not ContextLayer.L3),
                active_diagnostics=(),
            )
            item = _event_item(
                current,
                kind=ContextItemKind.PLAN_STEP,
                source=ContextSource.RUNTIME,
                trust=ContextTrust.TRUSTED_RUNTIME,
                payload=values.get("step") or values.get("summary") or values.get("step_id"),
                priority=95,
                required=True,
                sequence=sequence,
            )
            return current._add_item(item) if item is not None else current
        if normalized in {"hypothesis", "hypothesisproposed", "hypothesis_proposed"}:
            item = _event_item(
                current,
                kind=ContextItemKind.HYPOTHESIS,
                source=ContextSource.MODEL,
                trust=ContextTrust.UNTRUSTED_MODEL,
                payload=values.get("hypothesis") or values.get("summary"),
                priority=35,
                sequence=sequence,
            )
            return current._add_item(item) if item is not None else current
        if normalized in {"hypothesisrejected", "hypothesis_rejected", "hypothesisconfirmed", "hypothesis_confirmed"}:
            raw_targets = values.get("hypotheses") or values.get("hypothesis") or values.get("summary")
            targets = set(_bounded_values(raw_targets))
            if isinstance(raw_targets, str) and raw_targets.strip():
                targets.add(_bounded_text(raw_targets))
            remaining_hypotheses = tuple(
                hypothesis for hypothesis in current.hypotheses if hypothesis not in targets
            )
            remaining_items = tuple(
                item
                for item in current.items
                if item.kind is not ContextItemKind.HYPOTHESIS or item.payload not in targets
            )
            current = replace(
                current,
                hypotheses=remaining_hypotheses,
                items=remaining_items,
            )
            if normalized in {"hypothesisconfirmed", "hypothesis_confirmed"}:
                item = _event_item(
                    current,
                    kind=ContextItemKind.DECISION,
                    source=ContextSource.RUNTIME,
                    trust=ContextTrust.TRUSTED_RUNTIME,
                    payload=values.get("confirmed") or values.get("hypothesis") or values.get("summary"),
                    priority=60,
                    sequence=sequence,
                )
                return current._add_item(item) if item is not None else current
            return current
        if normalized in {"contextitempinned", "context_item_pinned", "item_pinned", "pin"}:
            return _set_item_pin(current, values, pinned=True)
        if normalized in {"contextitemunpinned", "context_item_unpinned", "item_unpinned", "unpin"}:
            return _set_item_pin(current, values, pinned=False)
        if normalized in {"blockerresolved", "blocker_resolved"}:
            raw_blocker = values.get("blocker") or values.get("summary")
            blocker = _bounded_text(raw_blocker)
            if not blocker:
                return current
            return replace(
                current,
                open_questions=tuple(
                    value for value in current.open_questions if value != blocker
                ),
                items=tuple(
                    item
                    for item in current.items
                    if item.kind is not ContextItemKind.BLOCKER or item.payload != blocker
                ),
            )
        if normalized in {"edittransactionapplied", "edit_transaction_applied", "patch_applied"}:
            item = _event_item(
                current,
                kind=ContextItemKind.EDIT_SUMMARY,
                source=ContextSource.EDIT_TRANSACTION,
                trust=ContextTrust.TRUSTED_RUNTIME,
                payload=values.get("summary") or values.get("operation_digest") or "edit applied",
                priority=85,
                required=True,
                sequence=sequence,
            )
            return current._add_item(item) if item is not None else current
        if normalized in {
            "verificationplancreated",
            "verification_plan_created",
            "verificationresult",
            "verification_result",
            "verificationgreen",
            "verification_green",
        }:
            item = _event_item(
                current,
                kind=ContextItemKind.VERIFICATION_SUMMARY,
                source=ContextSource.VERIFICATION,
                trust=ContextTrust.UNTRUSTED_TOOL,
                payload=values.get("summary") or values.get("status") or "verification observed",
                priority=80,
                required=normalized in {
                    "verificationgreen",
                    "verification_green",
                },
                sequence=sequence,
            )
            if normalized in {"verificationgreen", "verification_green"}:
                current = replace(
                    current,
                    active_diagnostics=(),
                    items=tuple(
                        existing
                        for existing in current.items
                        if existing.kind is not ContextItemKind.DIAGNOSTIC
                    ),
                )
            return current._add_item(item) if item is not None else current
        if normalized in {"verificationdiagnostic", "verification_diagnostic", "diagnostic"}:
            item = _event_item(
                current,
                kind=ContextItemKind.DIAGNOSTIC,
                source=ContextSource.VERIFICATION,
                trust=ContextTrust.UNTRUSTED_TOOL,
                payload=values.get("summary") or values.get("message") or values.get("diagnostic"),
                priority=75,
                sequence=sequence,
            )
            return current._add_item(item) if item is not None else current
        if normalized in {"recoveryevent", "recovery_event", "completionrejected", "completion_rejected"}:
            item = _event_item(
                current,
                kind=ContextItemKind.BLOCKER,
                source=ContextSource.RUNTIME,
                trust=ContextTrust.TRUSTED_RUNTIME,
                payload=values.get("reason") or values.get("summary") or normalized,
                priority=88,
                required=normalized in {"completionrejected", "completion_rejected"},
                sequence=sequence,
            )
            return current._add_item(item) if item is not None else current

        # Repository query results are references only.  The actual bounded
        # evidence remains owned by Repo Intelligence and is selected per
        # request; the working set records that a query happened.
        if normalized in {"repoqueryresult", "repo_query_result", "contextqueryresult"}:
            item = _event_item(
                current,
                kind=ContextItemKind.RELATION,
                source=ContextSource.REPO_INTELLIGENCE,
                trust=ContextTrust.UNTRUSTED_REPO,
                payload=values.get("summary") or values.get("query_digest") or "repository context observed",
                priority=45,
                sequence=sequence,
            )
            return current._add_item(item) if item is not None else current
        if normalized in {"toolresult", "tool_result"}:
            item = _event_item(
                current,
                kind=ContextItemKind.TOOL_RESULT,
                source=ContextSource.TOOL,
                trust=ContextTrust.UNTRUSTED_TOOL,
                payload=values.get("summary") or values.get("tool_name") or "tool result observed",
                priority=25,
                sequence=sequence,
            )
            return current._add_item(item) if item is not None else current
        return current

    def summary(self) -> TaskStateSummary:
        decisions = self.decisions or _items_text(self.items, ContextItemKind.DECISION)
        hypotheses = self.hypotheses or _items_text(self.items, ContextItemKind.HYPOTHESIS)
        blockers = self.open_questions or _items_text(self.items, ContextItemKind.BLOCKER)
        verification = _items_text(self.items, ContextItemKind.VERIFICATION_SUMMARY)
        if self.verification_state and self.verification_state not in verification:
            verification = (*verification, self.verification_state)
        return TaskStateSummary(
            task_id=self.task_id,
            workspace_id=self.workspace_id,
            generation=self.generation,
            plan_revision=self.plan_revision,
            active_step_id=self.active_step_id,
            goal=self.goal,
            constraints=self.constraints[:64],
            changed_files=self.changed_files[:64],
            decisions=decisions[:64],
            hypotheses=hypotheses[:64],
            blockers=blockers[:64],
            diagnostics=self.active_diagnostics[:64],
            verification=verification[:64],
            event_sequence=self.event_sequence,
        )

    def to_payload(self) -> dict[str, object]:
        payload = self._payload_without_digest()
        payload["working_set_digest"] = self.digest
        return payload

    def _payload_without_digest(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "task_id": self.task_id,
            "principal_id": self.principal_id,
            "project_id": self.project_id,
            "workspace_id": self.workspace_id,
            "generation": self.generation,
            "goal": _bounded_text(self.goal),
            "constraints": self.constraints,
            "goal_digest": self.goal_digest,
            "plan_revision": self.plan_revision,
            "active_step_id": self.active_step_id,
            "changed_files": self.changed_files,
            "viewed_files": self.viewed_files,
            "important_paths": self.important_paths,
            "important_symbols": self.important_symbols,
            "active_diagnostics": self.active_diagnostics,
            "hypotheses": self.hypotheses,
            "decisions": self.decisions,
            "open_questions": self.open_questions,
            "verification_state": self.verification_state,
            "event_sequence": self.event_sequence,
            "items": [self._persistence_item(item).to_payload(include_content=True) for item in self.items],
        }

    @staticmethod
    def _persistence_item(item: ContextItem) -> ContextItem:
        if item.kind in {
            ContextItemKind.FILE_REGION,
            ContextItemKind.SYMBOL,
            ContextItemKind.RELATION,
            ContextItemKind.TOOL_RESULT,
        }:
            return item.reference()
        return item.truncated_to(max_bytes=MAX_WORKING_SET_TEXT_BYTES)

    @classmethod
    def from_payload(cls, payload: Mapping[str, object]) -> TaskWorkingSet:
        if type(payload) is not dict and not isinstance(payload, Mapping):
            raise ContextContractError("persisted working set is not an object")
        if payload.get("schema_version") != CONTEXT_SCHEMA_VERSION:
            raise ContextContractError("persisted working set schema is unsupported")
        raw_items = payload.get("items", ())
        if not isinstance(raw_items, Sequence) or isinstance(raw_items, (str, bytes, bytearray)):
            raise ContextContractError("persisted working-set items are invalid")
        items: list[ContextItem] = []
        for raw in list(raw_items)[:MAX_WORKING_SET_ITEMS]:
            if not isinstance(raw, Mapping):
                raise ContextContractError("persisted working-set item is invalid")
            try:
                items.append(
                    ContextItem(
                        kind=ContextItemKind(str(raw["kind"])),
                        payload=str(raw.get("payload", "")),
                        layer=ContextLayer(str(raw["layer"])),
                        source=ContextSource(str(raw["source"])),
                        trust=ContextTrust(str(raw["trust"])),
                        workspace_id=str(raw.get("workspace_id", "")),
                        generation=raw.get(
                            "generation", raw.get("repository_generation")
                        ),
                        priority=int(raw.get("priority", 0)),
                        item_id=str(raw.get("item_id", "")),
                        digest=str(raw.get("digest", "")),
                        token_count=int(raw.get("token_count", 0)),
                        byte_count=int(raw.get("byte_count", 0)),
                        approximate=bool(raw.get("approximate", True)),
                        required=bool(raw.get("required", False)),
                        pinned=bool(raw.get("pinned", False)),
                        truncated=bool(raw.get("truncated", False)),
                        compressed=bool(raw.get("compressed", False)),
                        path=raw.get("path"),
                        symbol=raw.get("symbol"),
                        region_start=raw.get("region_start"),
                        region_end=raw.get("region_end"),
                        sequence=int(raw.get("sequence", 0)),
                        metadata=raw.get("metadata", {}),
                    )
                )
            except (KeyError, TypeError, ValueError) as exc:
                raise ContextContractError("persisted working-set item is malformed") from exc
        def optional_text(name: str, max_length: int = 2048) -> str | None:
            value = payload.get(name)
            if value is None:
                return None
            if not isinstance(value, str):
                raise ContextContractError(f"persisted working-set {name} is invalid")
            return _bounded_text(value)[:max_length] or None

        def optional_generation() -> str | None:
            value = payload.get("generation", payload.get("repository_generation"))
            return _normalize_generation(value, label="generation")

        raw_event_sequence = payload.get("event_sequence", 0)
        event_sequence = raw_event_sequence if type(raw_event_sequence) is int else 0
        restored = cls(
            task_id=str(payload.get("task_id", "")),
            principal_id=str(payload.get("principal_id", "")),
            project_id=str(payload.get("project_id", "")),
            workspace_id=str(payload.get("workspace_id", "")),
            generation=optional_generation(),
            goal=str(payload.get("goal", "")),
            constraints=_bounded_values(payload.get("constraints"), limit=64),
            goal_digest=optional_text("goal_digest"),
            plan_revision=optional_text("plan_revision"),
            active_step_id=optional_text("active_step_id"),
            changed_files=_bounded_values(payload.get("changed_files")),
            viewed_files=_bounded_values(payload.get("viewed_files")),
            important_paths=_bounded_values(payload.get("important_paths")),
            important_symbols=_bounded_values(payload.get("important_symbols")),
            active_diagnostics=_bounded_values(payload.get("active_diagnostics"), limit=64),
            hypotheses=_bounded_values(payload.get("hypotheses"), limit=64),
            decisions=_bounded_values(payload.get("decisions"), limit=64),
            open_questions=_bounded_values(payload.get("open_questions"), limit=64),
            verification_state=optional_text("verification_state", max_length=256),
            items=tuple(items),
            event_sequence=event_sequence,
        )
        stored_digest = payload.get("working_set_digest")
        if stored_digest is not None and stored_digest != restored.digest:
            raise ContextContractError("working-set digest does not match payload")
        return restored


def _event_item(
    working_set: TaskWorkingSet,
    *,
    kind: ContextItemKind,
    source: ContextSource,
    trust: ContextTrust,
    payload: object,
    priority: int,
    sequence: int,
    required: bool = False,
) -> ContextItem | None:
    text = _bounded_text(payload)
    if not text:
        return None
    return ContextItem(
        kind=kind,
        payload=text,
        layer=ContextLayer.L1 if kind not in {ContextItemKind.RELATION} else ContextLayer.L2,
        source=source,
        trust=trust,
        workspace_id=working_set.workspace_id,
        generation=working_set.generation,
        priority=priority,
        required=required,
        sequence=sequence,
    )


def _set_item_pin(
    working_set: TaskWorkingSet,
    values: Mapping[str, object],
    *,
    pinned: bool,
) -> TaskWorkingSet:
    """Apply a bounded pin transition to an existing working-set item."""

    item_id = _bounded_text(values.get("item_id"))
    payload = _bounded_text(values.get("summary") or values.get("payload"))
    if not item_id and not payload:
        return working_set
    return replace(
        working_set,
        items=tuple(
            replace(item, pinned=pinned)
            if (item_id and item.item_id == item_id)
            or (payload and item.payload == payload)
            else item
            for item in working_set.items
        ),
    )


def _items_text(items: tuple[ContextItem, ...], kind: ContextItemKind) -> tuple[str, ...]:
    return tuple(item.payload for item in items if item.kind is kind and item.payload)[:32]


class InMemoryWorkingSetStore:
    """Small thread-safe store used by tests and non-durable adapters."""

    def __init__(self, *, max_tasks: int = 256) -> None:
        if type(max_tasks) is not int or max_tasks <= 0:
            raise ValueError("max_tasks must be positive")
        self.max_tasks = max_tasks
        self._values: dict[tuple[str, str, str], TaskWorkingSet] = {}
        self._lock = RLock()

    def get(self, key: tuple[str, str, str]) -> TaskWorkingSet | None:
        with self._lock:
            return self._values.get(key)

    def put(self, key: tuple[str, str, str], value: TaskWorkingSet) -> None:
        with self._lock:
            self._values[key] = value
            if len(self._values) > self.max_tasks:
                oldest = next(iter(self._values))
                self._values.pop(oldest, None)

    def delete(self, key: tuple[str, str, str]) -> None:
        with self._lock:
            self._values.pop(key, None)

    def snapshot(self) -> dict[tuple[str, str, str], TaskWorkingSet]:
        with self._lock:
            return dict(self._values)
