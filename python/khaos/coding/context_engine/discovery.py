"""Deferred model-visible tool and skill discovery."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from typing import cast

CORE_TOOL_NAMES = frozenset(
    {
        "read_file",
        "search_files",
        "list_directory",
        "file_info",
        "tree_view",
        "file_search_content",
        "code_search",
        "code_symbols",
        "git_diff",
        "git_log",
        "git_status",
        "preview_edit_transaction",
        "apply_edit_transaction",
        "write_file",
        "patch",
        "multi_edit",
        "terminal_argv",
        "terminal_shell",
        "process",
        "test_run",
        "todo_read",
        "todo_write",
        "todo_update",
    }
)


@dataclass(frozen=True, slots=True)
class ToolDiscoveryResult:
    definitions: tuple[object, ...]
    deferred_count: int
    loaded_count: int


class DeferredToolDiscovery:
    """Expose a small deterministic core schema and load specialists on intent."""

    def __init__(self, registry: object, *, mode: str = "coding") -> None:
        self.registry = registry
        self.mode = (mode or "coding").casefold()
        self.discovery_count = 0
        self.deferred_count = 0

    def discover(
        self,
        *,
        intent: str = "",
        allowlist: Iterable[str] | None = None,
    ) -> ToolDiscoveryResult:
        list_by_mode = getattr(self.registry, "list_by_mode", None)
        if not callable(list_by_mode):
            return ToolDiscoveryResult((), 0, 0)
        allowed = set(allowlist) if allowlist is not None else None
        raw_definitions = list_by_mode(self.mode)
        if not isinstance(raw_definitions, Iterable) or isinstance(
            raw_definitions, (str, bytes, bytearray)
        ):
            return ToolDiscoveryResult((), 0, 0)
        definitions = list(cast(Iterable[object], raw_definitions))
        visible: list[object] = []
        deferred = 0
        for definition in sorted(definitions, key=lambda item: str(getattr(item, "name", ""))):
            name = str(getattr(definition, "name", ""))
            if allowed is not None and name not in allowed:
                continue
            # M8.4's deferred specialist set is a Coding-mode optimization.
            # Office mode keeps its existing registered visibility (including
            # clipboard/browser/channel tools); visibility never changes the
            # registry's execution or permission authority.
            if (
                self.mode == "coding"
                and self._is_specialized(name)
                and not self._intent_requests(name, intent)
            ):
                deferred += 1
                continue
            visible.append(definition)
        self.discovery_count += 1
        self.deferred_count += deferred
        return ToolDiscoveryResult(tuple(visible), deferred, len(visible))

    def schemas(
        self,
        *,
        intent: str = "",
        allowlist: Iterable[str] | None = None,
    ) -> ToolDiscoveryResult:
        """Alias returning definitions for callers that render schemas."""

        return self.discover(intent=intent, allowlist=allowlist)

    @staticmethod
    def _is_specialized(name: str) -> bool:
        lowered = name.casefold()
        return (
            lowered.startswith(("browser", "web_", "mcp_", "remote_", "github_", "channel_", "cron_"))
            or lowered in {
                "git_commit",
                "git_push",
                "git_branch",
                "git_create_branch",
                "git_smart_commit",
                "git_undo",
                "spawn_subagent",
                "delegate_plan_step",
                "execute_plan",
                "subagent_status",
                "clipboard_read",
                "clipboard_write",
            }
        )

    @staticmethod
    def _intent_requests(name: str, intent: str) -> bool:
        haystack = (intent or "").casefold()
        lowered = name.casefold()
        terms = {
            "browser": (
                "browser",
                "web page",
                "website",
                "navigate",
                "click",
                "dom",
                "snapshot",
                "screenshot",
                "scroll",
                "upload",
            ),
            "web_": ("web", "http", "url", "online", "github"),
            "github_": ("github", "pull request", "issue", "repository"),
            "git_commit": ("commit", "save changes"),
            "git_push": ("push", "remote", "publish"),
            "git_branch": ("branch", "checkout"),
            "git_create_branch": (
                "create branch",
                "new branch",
                "checkout -b",
                "create a branch",
            ),
            "git_smart_commit": ("commit", "save changes"),
            "git_undo": ("undo", "revert", "restore"),
            "spawn_subagent": ("subagent", "delegate", "parallel"),
            "delegate_plan_step": ("delegate", "subagent"),
            "clipboard": ("clipboard", "copy", "paste"),
            "channel_": ("channel", "telegram", "discord", "slack", "wechat"),
            "cron_": ("cron", "schedule", "scheduled", "reminder"),
            "mcp_": ("mcp", "connector", "server"),
            "remote_": ("remote", "ssh", "cloud"),
        }
        for prefix, values in terms.items():
            if lowered.startswith(prefix) or lowered == prefix:
                return any(value in haystack for value in values)
        return any(token in haystack for token in ("remote", "browser", "web", "mcp", "skill"))


@dataclass(frozen=True, slots=True)
class SkillMetadata:
    name: str
    description: str
    category: str
    trust_tier: str
    triggers: tuple[str, ...]


class LazySkillDiscovery:
    """Match bounded metadata first; load a body only after selection."""

    def __init__(self, skill_manager: object | None) -> None:
        self.skill_manager = skill_manager
        self.metadata_count = 0
        self.full_load_count = 0

    def discover(self, mode: str, user_text: str, *, limit: int = 5) -> tuple[SkillMetadata, ...]:
        manager = self.skill_manager
        registry = getattr(manager, "registry", None)
        list_skills = getattr(registry, "list", None)
        if not callable(list_skills):
            return ()
        haystack = (user_text or "").casefold()
        mode_value = (mode or "").casefold()
        forced = set(getattr(manager, "forced", ()) or ())
        scored: list[tuple[int, object]] = []
        raw_skills = list_skills(only_enabled=True)
        if not isinstance(raw_skills, Iterable) or isinstance(
            raw_skills, (str, bytes, bytearray)
        ):
            return ()
        for skill in cast(Iterable[object], raw_skills):
            name = str(getattr(skill, "name", ""))
            triggers = tuple(str(value) for value in (getattr(skill, "triggers", ()) or ()))
            hits = sum(1 for trigger in triggers if trigger and trigger.casefold() in haystack)
            if name in forced:
                hits += 1000
            if mode_value and str(getattr(skill, "category", "")).casefold() == mode_value:
                hits += 1
            if hits:
                scored.append((hits, skill))
        scored.sort(key=lambda value: (-value[0], str(getattr(value[1], "name", ""))))
        result = tuple(
            SkillMetadata(
                name=str(getattr(skill, "name", "")),
                description=str(getattr(skill, "description", ""))[:1024],
                category=str(getattr(skill, "category", "general")),
                trust_tier=str(getattr(getattr(skill, "trust_tier", None), "value", getattr(skill, "trust_tier", "project"))),
                triggers=tuple(str(value) for value in (getattr(skill, "triggers", ()) or ()))[:32],
            )
            for _, skill in scored[: max(0, limit)]
        )
        self.metadata_count += len(result)
        return result

    def load_full(self, name: str) -> object | None:
        registry = getattr(self.skill_manager, "registry", None)
        getter = getattr(registry, "get", None)
        if not callable(getter):
            return None
        try:
            skill = getter(name)
        except Exception:  # noqa: BLE001 - lazy discovery is non-fatal
            return None
        self.full_load_count += 1
        return skill
