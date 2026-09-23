# KHAOS-PRIVILEGED-SPAWN owner=QualificationProvenance threat-model=trusted-source-git-provenance boundary=qualification-jsonl
"""Versioned, secret-free result artifacts for real-provider coding benchmarks.

This module is deliberately separate from the Khaos authority plane.  It
describes an experiment, records external evidence, and never authorizes a
task, completion, verification result, or recovery action.
"""

from __future__ import annotations

import asyncio
import hashlib
import math
import os
import platform as platform_module
import stat
import subprocess
import threading
from collections import Counter
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import cast

from khaos.evaluation.coding.contracts import (
    CodingFailureReason,
    CodingScenario,
    CodingScenarioKind,
    CodingVerdict,
    digest_payload,
)
from khaos.evaluation.coding.results import CodingEvaluationRun
from khaos.security.protocol_boundary import canonical_json_bytes
from khaos.security.secret_redaction import SecretRedactor

LEGACY_OBSERVABILITY_NOT_AVAILABLE = "NOT_AVAILABLE_LEGACY_ARTIFACT"


class CodingResultState(StrEnum):
    """Stable terminal state vocabulary for benchmark consumers."""

    SUCCESS = "SUCCESS"
    PARTIAL = "PARTIAL"
    FAILURE = "FAILURE"
    TIMEOUT = "TIMEOUT"
    MODEL_ERROR = "MODEL_ERROR"
    INFRASTRUCTURE_ERROR = "INFRASTRUCTURE_ERROR"
    ENVIRONMENT_BLOCKED = "ENVIRONMENT_BLOCKED"
    SECURITY_FAILURE = "SECURITY_FAILURE"
    QUARANTINED = "QUARANTINED"
    TOOL_BUDGET_EXHAUSTED = "TOOL_BUDGET_EXHAUSTED"


class CodingFailureTaxonomy(StrEnum):
    """Primary failure categories required by the M8 evaluation report."""

    PLANNING_FAILURE = "PLANNING_FAILURE"
    REPO_LOCALIZATION_FAILURE = "REPO_LOCALIZATION_FAILURE"
    CONTEXT_FAILURE = "CONTEXT_FAILURE"
    EDIT_FAILURE = "EDIT_FAILURE"
    EDIT_SCOPE_FAILURE = "EDIT_SCOPE_FAILURE"
    VERIFICATION_FAILURE = "VERIFICATION_FAILURE"
    REPAIR_FAILURE = "REPAIR_FAILURE"
    TOOL_SELECTION_FAILURE = "TOOL_SELECTION_FAILURE"
    TOOL_EXECUTION_FAILURE = "TOOL_EXECUTION_FAILURE"
    SUBAGENT_FAILURE = "SUBAGENT_FAILURE"
    MERGE_FAILURE = "MERGE_FAILURE"
    BROWSER_FAILURE = "BROWSER_FAILURE"
    APP_LAUNCH_FAILURE = "APP_LAUNCH_FAILURE"
    APPROVAL_FAILURE = "APPROVAL_FAILURE"
    PROVIDER_FAILURE = "PROVIDER_FAILURE"
    RESOURCE_LIMIT = "RESOURCE_LIMIT"
    NO_PROGRESS = "NO_PROGRESS"
    FALSE_COMPLETION = "FALSE_COMPLETION"
    OUTPUT_CONTRACT_FAILURE = "OUTPUT_CONTRACT_FAILURE"
    SEMANTIC_REVIEW_FAILURE = "SEMANTIC_REVIEW_FAILURE"
    ENVIRONMENT_FAILURE = "ENVIRONMENT_FAILURE"


class CodingRootCause(StrEnum):
    """Root-cause bucket kept separate from the observed failure category."""

    HARNESS_DEFECT = "HARNESS_DEFECT"
    MODEL_REASONING_LIMIT = "MODEL_REASONING_LIMIT"
    MODEL_TOOL_USE_LIMIT = "MODEL_TOOL_USE_LIMIT"
    PROVIDER_DEFECT = "PROVIDER_DEFECT"
    BENCHMARK_DEFECT = "BENCHMARK_DEFECT"
    ENVIRONMENT_DEFECT = "ENVIRONMENT_DEFECT"
    UNKNOWN = "UNKNOWN"


_SHA256_LENGTH = 64
_MAX_TEXT_BYTES = 4096
_MAX_RESULT_LINE_BYTES = 1024 * 1024
_MAX_RESULT_FILE_BYTES = 64 * 1024 * 1024
_APPEND_LOCK = threading.RLock()
_MAX_WORKTREE_PATH_OUTPUT_BYTES = 4 * 1024 * 1024
_MAX_WORKTREE_FILES = 16_384
_MAX_WORKTREE_FILE_BYTES = 16 * 1024 * 1024
_MAX_WORKTREE_TOTAL_BYTES = 256 * 1024 * 1024


def _bounded_text(value: str, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{label} must be non-empty text")
    if len(value.encode("utf-8")) > _MAX_TEXT_BYTES:
        raise ValueError(f"{label} exceeds its byte bound")
    return value


def _digest(value: str, label: str) -> str:
    value = _bounded_text(value, label)
    if len(value) != _SHA256_LENGTH or any(char not in "0123456789abcdef" for char in value):
        raise ValueError(f"{label} must be a lowercase SHA-256")
    return value


def _optional_digest(value: str | None, label: str) -> str | None:
    if value is None:
        return None
    return _digest(value, label)


def _public_sampling(value: Mapping[str, object]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, item in value.items():
        if not isinstance(key, str) or not key or len(key) > 128:
            raise ValueError("sampling keys are invalid")
        if any(secret in key.casefold() for secret in ("key", "token", "secret", "password", "cookie")):
            raise ValueError("sampling cannot contain credential-shaped keys")
        if item is not None and type(item) not in {bool, int, float, str}:
            raise ValueError("sampling values must be scalar and secret-free")
        if isinstance(item, str) and len(item.encode("utf-8")) > _MAX_TEXT_BYTES:
            raise ValueError("sampling string exceeds its bound")
        if isinstance(item, float) and not math.isfinite(item):
            raise ValueError("sampling float must be finite")
        result[key] = item
    return dict(sorted(result.items()))


@dataclass(frozen=True, slots=True)
class BenchmarkRunConfig:
    """Public, reproducibility-relevant configuration without raw secrets."""

    provider: str
    model: str
    khaos_sha: str
    scenario_manifest_digest: str
    config_digest: str
    task_seed: str = "default"
    model_version: str | None = None
    reasoning_effort: str | None = None
    sampling: Mapping[str, object] = field(default_factory=dict)
    max_turns: int = 128
    max_tokens: int | None = None
    task_timeout_seconds: float = 120.0
    tool_budget: int = 512
    subagent_policy: str = "runtime-default"
    browser_policy: str = "fixture-only"
    network_policy: str = "none"
    approval_policy: str = "benchmark-local-approved"
    context_budget_tokens: int | None = None
    policy_digest: str | None = None
    platform: str = ""
    working_tree_identity: str | None = None

    def __post_init__(self) -> None:
        _bounded_text(self.provider, "provider")
        _bounded_text(self.model, "model")
        _bounded_text(self.khaos_sha, "khaos_sha")
        _digest(self.scenario_manifest_digest, "scenario_manifest_digest")
        _digest(self.config_digest, "config_digest")
        _bounded_text(self.task_seed, "task_seed")
        if self.model_version is not None:
            _bounded_text(self.model_version, "model_version")
        if self.reasoning_effort is not None:
            _bounded_text(self.reasoning_effort, "reasoning_effort")
        object.__setattr__(self, "sampling", _public_sampling(self.sampling))
        if type(self.max_turns) is not int or self.max_turns <= 0:
            raise ValueError("max_turns must be positive")
        if self.max_tokens is not None and (type(self.max_tokens) is not int or self.max_tokens <= 0):
            raise ValueError("max_tokens must be positive when present")
        if (
            type(self.task_timeout_seconds) not in {int, float}
            or not math.isfinite(float(self.task_timeout_seconds))
            or self.task_timeout_seconds <= 0
        ):
            raise ValueError("task_timeout_seconds must be finite and positive")
        if type(self.tool_budget) is not int or self.tool_budget <= 0:
            raise ValueError("tool_budget must be positive")
        for name in ("subagent_policy", "browser_policy", "network_policy", "approval_policy"):
            _bounded_text(getattr(self, name), name)
        if self.context_budget_tokens is not None and (
            type(self.context_budget_tokens) is not int or self.context_budget_tokens <= 0
        ):
            raise ValueError("context_budget_tokens must be positive when present")
        _optional_digest(self.policy_digest, "policy_digest")
        _optional_digest(self.working_tree_identity, "working_tree_identity")
        object.__setattr__(
            self,
            "platform",
            self.platform or platform_module.system() or "unknown",
        )

    @property
    def digest(self) -> str:
        """Digest the public configuration fields for result binding."""

        return digest_payload(self.to_payload())

    def to_payload(self) -> dict[str, object]:
        return {
            "provider": self.provider,
            "model": self.model,
            "khaos_sha": self.khaos_sha,
            "scenario_manifest_digest": self.scenario_manifest_digest,
            "config_digest": self.config_digest,
            "task_seed": self.task_seed,
            "model_version": self.model_version,
            "reasoning_effort": self.reasoning_effort,
            "sampling": dict(self.sampling),
            "max_turns": self.max_turns,
            "max_tokens": self.max_tokens,
            "task_timeout_seconds": self.task_timeout_seconds,
            "tool_budget": self.tool_budget,
            "subagent_policy": self.subagent_policy,
            "browser_policy": self.browser_policy,
            "network_policy": self.network_policy,
            "approval_policy": self.approval_policy,
            "context_budget_tokens": self.context_budget_tokens,
            "policy_digest": self.policy_digest,
            "platform": self.platform,
            "working_tree_identity": self.working_tree_identity,
        }


_QUALIFICATION_SENSITIVE_KEY_MARKERS = (
    "api_key",
    "access_token",
    "authorization",
    "cookie",
    "password",
    "private_key",
)


def _safe_artifact(value: object, label: str, *, depth: int = 0) -> object:
    """Validate a bounded JSON-like artifact without accepting credentials."""

    if depth > 8:
        raise ValueError(f"{label} exceeds its nesting bound")
    if value is None or type(value) in {bool, int, float}:
        if isinstance(value, float) and not math.isfinite(value):
            raise ValueError(f"{label} contains a non-finite number")
        return value
    if isinstance(value, str):
        if len(value.encode("utf-8")) > _MAX_TEXT_BYTES:
            raise ValueError(f"{label} contains oversized text")
        return value
    if isinstance(value, Mapping):
        if len(value) > 256:
            raise ValueError(f"{label} contains too many fields")
        result: dict[str, object] = {}
        for key, item in value.items():
            if not isinstance(key, str) or not key or len(key) > 128:
                raise ValueError(f"{label} contains an invalid field name")
            lowered = key.casefold()
            if (
                any(marker in lowered for marker in _QUALIFICATION_SENSITIVE_KEY_MARKERS)
                or lowered in {"secret_value", "token_value"}
            ):
                raise ValueError(f"{label} contains a credential-shaped field")
            result[key] = _safe_artifact(item, f"{label}.{key}", depth=depth + 1)
        return dict(sorted(result.items()))
    if isinstance(value, (list, tuple)):
        if len(value) > 256:
            raise ValueError(f"{label} contains too many items")
        return [
            _safe_artifact(item, f"{label}[]", depth=depth + 1)
            for item in value
        ]
    raise ValueError(f"{label} contains an unsupported value")


def _optional_identifier(value: str | None, label: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise TypeError(f"{label} is not a bounded identifier")
    if "\n" in value or "\r" in value or len(value.encode("utf-8")) > 512:
        raise ValueError(f"{label} is not a bounded identifier")
    if not value.strip():
        return None
    return value


def capture_working_tree_identity(
    root: Path,
    *,
    excluded_paths: Iterable[str] = (),
) -> str:
    """Digest HEAD plus bounded worktree file identities.

    This is experiment provenance, not an approval or mutation authority.  A
    caller may exclude a protected local artifact whose contents it is not
    permitted to inspect; all other tracked, deleted, and non-ignored
    untracked paths are represented by path, mode, size, and content digest.
    """

    repository = root.expanduser().absolute()
    if repository.is_symlink() or not repository.is_dir():
        raise ValueError("working-tree root is not a regular directory")
    environment = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_TERMINAL_PROMPT": "0",
        "LC_ALL": "C",
    }
    try:
        head_result = subprocess.run(
            ["git", "rev-parse", "--verify", "HEAD"],
            cwd=str(repository),
            capture_output=True,
            check=False,
            timeout=10,
            env=environment,
        )
        paths_result = subprocess.run(
            [
                "git",
                "ls-files",
                "--cached",
                "--others",
                "--deleted",
                "--exclude-standard",
                "-z",
            ],
            cwd=str(repository),
            capture_output=True,
            check=False,
            timeout=10,
            env=environment,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise OSError("working-tree identity could not invoke Git") from exc
    if head_result.returncode != 0 or paths_result.returncode != 0:
        raise OSError("working-tree identity could not resolve Git state")
    if len(paths_result.stdout) > _MAX_WORKTREE_PATH_OUTPUT_BYTES:
        raise OSError("working-tree path inventory exceeds its bound")
    head = head_result.stdout.decode("utf-8", errors="strict").strip()
    if not head:
        raise OSError("working-tree HEAD is unavailable")
    excluded = {
        Path(path).as_posix()
        for path in excluded_paths
        if isinstance(path, str) and path
    }
    records: list[dict[str, object]] = []
    seen: set[str] = set()
    total_bytes = 0
    for raw_path in paths_result.stdout.split(b"\0"):
        if not raw_path:
            continue
        relative = Path(raw_path.decode("utf-8", errors="strict"))
        if relative.is_absolute() or ".." in relative.parts:
            raise OSError("working-tree inventory contains an unsafe path")
        name = relative.as_posix()
        if name in seen or name in excluded:
            continue
        seen.add(name)
        if len(seen) > _MAX_WORKTREE_FILES:
            raise OSError("working-tree file count exceeds its bound")
        candidate = repository / relative
        try:
            descriptor = os.open(
                candidate,
                os.O_RDONLY
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_BINARY", 0),
            )
        except FileNotFoundError:
            records.append({"path": name, "state": "MISSING"})
            continue
        try:
            before = os.fstat(descriptor)
            if not stat.S_ISREG(before.st_mode):
                raise OSError("working-tree inventory contains a non-regular file")
            digest = hashlib.sha256()
            file_bytes = 0
            while True:
                chunk = os.read(descriptor, 64 * 1024)
                if not chunk:
                    break
                file_bytes += len(chunk)
                total_bytes += len(chunk)
                if file_bytes > _MAX_WORKTREE_FILE_BYTES:
                    raise OSError("working-tree file exceeds its bound")
                if total_bytes > _MAX_WORKTREE_TOTAL_BYTES:
                    raise OSError("working-tree bytes exceed their bound")
                digest.update(chunk)
            after = os.fstat(descriptor)
            if (before.st_dev, before.st_ino, before.st_size) != (
                after.st_dev,
                after.st_ino,
                after.st_size,
            ):
                raise OSError("working-tree file changed while being hashed")
            records.append(
                {
                    "path": name,
                    "mode": stat.S_IMODE(before.st_mode),
                    "size": file_bytes,
                    "sha256": digest.hexdigest(),
                }
            )
        finally:
            os.close(descriptor)
    return digest_payload({"head": head, "files": records})


@dataclass(frozen=True, slots=True)
class CodingQualificationRecordV1:
    """One canonical, secret-free qualification JSONL record."""

    run_id: str
    result_state: CodingResultState
    provider: str
    model: str
    source_sha: str
    suite_id: str
    suite_version: int
    suite_digest: str
    scenario_id: str
    scenario_version: int
    scenario_digest: str | None
    working_tree_identity: str | None
    provider_config_digest: str | None
    fixture_digest: str | None
    prompt_digest: str | None
    system_prompt_digest: str | None
    tool_schema_digest: str | None
    policy_digest: str | None
    budgets: Mapping[str, object]
    timeout_seconds: float
    credential_ref: str | None
    reasoning_configuration: Mapping[str, object]
    metrics: Mapping[str, object]
    stages: tuple[Mapping[str, object], ...]
    started_at: str
    finished_at: str
    provider_returned_model_id: str | None = None
    observability_schema_version: int | None = None
    record_digest: str = ""

    def __post_init__(self) -> None:
        for name in (
            "run_id",
            "provider",
            "model",
            "source_sha",
            "suite_id",
            "scenario_id",
            "started_at",
            "finished_at",
        ):
            _bounded_text(getattr(self, name), name)
        if not isinstance(self.result_state, CodingResultState):
            raise TypeError("qualification result_state is invalid")
        if type(self.suite_version) is not int or self.suite_version <= 0:
            raise ValueError("qualification suite_version must be positive")
        if type(self.scenario_version) is not int or self.scenario_version <= 0:
            raise ValueError("qualification scenario_version must be positive")
        _digest(self.suite_digest, "qualification.suite_digest")
        for name in (
            "scenario_digest",
            "provider_config_digest",
            "fixture_digest",
            "prompt_digest",
            "system_prompt_digest",
            "tool_schema_digest",
            "policy_digest",
        ):
            _optional_digest(getattr(self, name), f"qualification.{name}")
        if (
            type(self.timeout_seconds) not in {int, float}
            or not math.isfinite(float(self.timeout_seconds))
            or self.timeout_seconds <= 0
        ):
            raise ValueError("qualification timeout_seconds is invalid")
        object.__setattr__(
            self,
            "working_tree_identity",
            _optional_identifier(self.working_tree_identity, "working_tree_identity"),
        )
        object.__setattr__(
            self,
            "credential_ref",
            _optional_identifier(self.credential_ref, "credential_ref"),
        )
        object.__setattr__(
            self,
            "provider_returned_model_id",
            _optional_identifier(
                self.provider_returned_model_id,
                "provider_returned_model_id",
            ),
        )
        if self.observability_schema_version is not None and (
            type(self.observability_schema_version) is not int
            or self.observability_schema_version != 1
        ):
            raise ValueError("qualification observability schema version is invalid")
        safe_budgets = _safe_artifact(self.budgets, "budgets")
        if not isinstance(safe_budgets, Mapping):
            raise TypeError("qualification budgets must be an object")
        object.__setattr__(self, "budgets", safe_budgets)
        safe_reasoning = _safe_artifact(
            self.reasoning_configuration,
            "reasoning_configuration",
        )
        if not isinstance(safe_reasoning, Mapping):
            raise TypeError("qualification reasoning configuration must be an object")
        object.__setattr__(
            self,
            "reasoning_configuration",
            safe_reasoning,
        )
        safe_metrics = _safe_artifact(self.metrics, "metrics")
        if not isinstance(safe_metrics, Mapping):
            raise TypeError("qualification metrics must be an object")
        object.__setattr__(self, "metrics", safe_metrics)
        safe_stages = _safe_artifact(self.stages, "stages")
        if not isinstance(safe_stages, list) or any(
            not isinstance(item, Mapping) for item in safe_stages
        ):
            raise ValueError("qualification stages must be a list")
        object.__setattr__(
            self,
            "stages",
            tuple(safe_stages),
        )
        expected = digest_payload(self._payload_without_digest())
        if self.record_digest and self.record_digest != expected:
            raise ValueError("qualification record digest does not match payload")
        object.__setattr__(self, "record_digest", expected)

    def _payload_without_digest(self) -> dict[str, object]:
        return {
            "schema_version": 1,
            "record_type": "coding_qualification",
            "run_id": self.run_id,
            "result_state": self.result_state.value,
            "provider": self.provider,
            "model": self.model,
            "provider_returned_model_id": self.provider_returned_model_id,
            "source_sha": self.source_sha,
            "working_tree_identity": self.working_tree_identity,
            "provider_config_digest": self.provider_config_digest,
            "suite_id": self.suite_id,
            "suite_version": self.suite_version,
            "suite_digest": self.suite_digest,
            "scenario_id": self.scenario_id,
            "scenario_version": self.scenario_version,
            "scenario_digest": self.scenario_digest,
            "fixture_digest": self.fixture_digest,
            "prompt_digest": self.prompt_digest,
            "system_prompt_digest": self.system_prompt_digest,
            "tool_schema_digest": self.tool_schema_digest,
            "policy_digest": self.policy_digest,
            "budgets": self.budgets,
            "timeout_seconds": self.timeout_seconds,
            "credential_ref": self.credential_ref,
            "reasoning_configuration": self.reasoning_configuration,
            "metrics": self.metrics,
            "stages": list(self.stages),
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            **(
                {"observability_schema_version": self.observability_schema_version}
                if self.observability_schema_version is not None
                else {}
            ),
        }

    def to_payload(self) -> dict[str, object]:
        return {**self._payload_without_digest(), "record_digest": self.record_digest}

    def to_sanitized_payload(self, redactor: SecretRedactor) -> dict[str, object]:
        candidate = redactor.redact_fail_closed(self._payload_without_digest())
        if not isinstance(candidate, Mapping):
            raise TypeError("qualification redaction did not preserve an object")
        payload = dict(candidate)
        payload["record_digest"] = digest_payload(payload)
        return payload

    def observability_field(self, section: str, field: str) -> object:
        """Read optional passive detail without rewriting historical records.

        V1 records predate typed-finding and exact-selection projections.  A
        missing field is intentionally distinct from a recorded empty list so
        forensic consumers cannot mistake legacy absence for an empty result.
        """

        if not isinstance(section, str) or not isinstance(field, str):
            return LEGACY_OBSERVABILITY_NOT_AVAILABLE
        section_names = _observability_section_names(section)
        containers: list[Mapping[str, object]] = []
        if isinstance(self.metrics, Mapping):
            containers.append(self.metrics)
        for stage in self.stages:
            if isinstance(stage, Mapping):
                containers.append(stage)
                nested = stage.get("observability")
                if isinstance(nested, Mapping):
                    containers.append(nested)
        for container in containers:
            for section_name in section_names:
                selected = container.get(section_name)
                if isinstance(selected, Mapping) and field in selected:
                    return selected[field]
        return LEGACY_OBSERVABILITY_NOT_AVAILABLE

    def typed_finding_detail(self) -> object:
        """Return typed finding detail or the explicit legacy sentinel."""

        return self.observability_field("response_observability", "typed_findings")

    def context_selection_detail(self) -> object:
        """Return exact selection detail or the explicit legacy sentinel."""

        return self.observability_field("context", "selection_items")

    @classmethod
    def from_payload(cls, payload: Mapping[str, object]) -> CodingQualificationRecordV1:
        """Read a historical V1 record without requiring newer fields."""

        if not isinstance(payload, Mapping):
            raise TypeError("qualification payload must be an object")
        allowed = {
            "schema_version",
            "record_type",
            "run_id",
            "result_state",
            "provider",
            "model",
            "provider_returned_model_id",
            "source_sha",
            "working_tree_identity",
            "provider_config_digest",
            "suite_id",
            "suite_version",
            "suite_digest",
            "scenario_id",
            "scenario_version",
            "scenario_digest",
            "fixture_digest",
            "prompt_digest",
            "system_prompt_digest",
            "tool_schema_digest",
            "policy_digest",
            "budgets",
            "timeout_seconds",
            "credential_ref",
            "reasoning_configuration",
            "metrics",
            "stages",
            "started_at",
            "finished_at",
            "observability_schema_version",
            "record_digest",
        }
        if set(payload) - allowed:
            raise ValueError("qualification payload contains unknown fields")
        if payload.get("schema_version") != 1 or payload.get("record_type") != "coding_qualification":
            raise ValueError("unsupported qualification record")
        try:
            result_state = CodingResultState(str(payload["result_state"]))
        except (KeyError, TypeError, ValueError) as exc:
            raise ValueError("qualification result_state is invalid") from exc
        stages = payload.get("stages", ())
        if not isinstance(stages, (list, tuple)):
            raise TypeError("qualification stages must be a list")
        if any(not isinstance(item, Mapping) for item in stages):
            raise ValueError("qualification stages contain an invalid item")
        budgets = payload.get("budgets")
        reasoning = payload.get("reasoning_configuration")
        metrics = payload.get("metrics")
        if not isinstance(budgets, Mapping) or not isinstance(reasoning, Mapping) or not isinstance(metrics, Mapping):
            raise TypeError("qualification payload mappings are invalid")
        timeout_seconds = payload.get("timeout_seconds")
        if type(timeout_seconds) not in {int, float}:
            raise ValueError("qualification timeout_seconds is invalid")
        numeric_timeout = cast(int | float, timeout_seconds)
        if not math.isfinite(float(numeric_timeout)):
            raise ValueError("qualification timeout_seconds is invalid")
        return cls(
            run_id=str(payload["run_id"]),
            result_state=result_state,
            provider=str(payload["provider"]),
            model=str(payload["model"]),
            provider_returned_model_id=(
                str(payload["provider_returned_model_id"])
                if payload.get("provider_returned_model_id") is not None
                else None
            ),
            source_sha=str(payload["source_sha"]),
            working_tree_identity=(
                str(payload["working_tree_identity"])
                if payload.get("working_tree_identity") is not None
                else None
            ),
            provider_config_digest=(
                str(payload["provider_config_digest"])
                if payload.get("provider_config_digest") is not None
                else None
            ),
            suite_id=str(payload["suite_id"]),
            suite_version=_required_payload_int(payload, "suite_version"),
            suite_digest=str(payload["suite_digest"]),
            scenario_id=str(payload["scenario_id"]),
            scenario_version=_required_payload_int(payload, "scenario_version"),
            scenario_digest=(
                str(payload["scenario_digest"])
                if payload.get("scenario_digest") is not None
                else None
            ),
            fixture_digest=(
                str(payload["fixture_digest"])
                if payload.get("fixture_digest") is not None
                else None
            ),
            prompt_digest=(
                str(payload["prompt_digest"])
                if payload.get("prompt_digest") is not None
                else None
            ),
            system_prompt_digest=(
                str(payload["system_prompt_digest"])
                if payload.get("system_prompt_digest") is not None
                else None
            ),
            tool_schema_digest=(
                str(payload["tool_schema_digest"])
                if payload.get("tool_schema_digest") is not None
                else None
            ),
            policy_digest=(
                str(payload["policy_digest"])
                if payload.get("policy_digest") is not None
                else None
            ),
            budgets=cast(Mapping[str, object], budgets),
            timeout_seconds=cast(float, timeout_seconds),
            credential_ref=(
                str(payload["credential_ref"])
                if payload.get("credential_ref") is not None
                else None
            ),
            reasoning_configuration=cast(Mapping[str, object], reasoning),
            metrics=cast(Mapping[str, object], metrics),
            stages=tuple(cast(Mapping[str, object], item) for item in stages),
            started_at=str(payload["started_at"]),
            finished_at=str(payload["finished_at"]),
            observability_schema_version=(
                _required_payload_int(payload, "observability_schema_version")
                if payload.get("observability_schema_version") is not None
                else None
            ),
            record_digest=str(payload.get("record_digest") or ""),
        )


def _required_payload_int(payload: Mapping[str, object], key: str) -> int:
    value = payload.get(key)
    if type(value) is not int:
        raise ValueError(f"qualification field {key} must be an integer")
    return value


def _observability_section_names(section: str) -> tuple[str, ...]:
    normalized = section.strip().casefold()
    if normalized in {"response", "response_observability"}:
        return ("response_observability",)
    if normalized in {"context", "context_observability"}:
        return ("context", "context_observability")
    if normalized in {"completion", "completion_observability"}:
        return ("completion", "completion_observability")
    if normalized in {"semantic_review", "semantic_review_observability"}:
        return ("semantic_review", "semantic_review_observability")
    return (section,)


class CodingQualificationJsonlWriter:
    """Crash-safe append-only writer for qualification records."""

    def __init__(
        self,
        path: Path,
        *,
        secret_redactor: SecretRedactor | None = None,
    ) -> None:
        self.path = path.expanduser().absolute()
        self._secret_redactor = secret_redactor
        if self.path.exists() and self.path.is_symlink():
            raise ValueError("qualification result path must not be a symlink")

    async def append(self, result: CodingQualificationRecordV1) -> None:
        if not isinstance(result, CodingQualificationRecordV1):
            raise TypeError("qualification result has an invalid type")
        payload = (
            result.to_sanitized_payload(self._secret_redactor)
            if self._secret_redactor is not None
            else result.to_payload()
        )
        line = canonical_json_bytes(payload) + b"\n"
        if len(line) > _MAX_RESULT_LINE_BYTES:
            raise ValueError("qualification result line exceeds its bound")
        await asyncio.to_thread(_append_result_line, self.path, line)


def _result_state(run: CodingEvaluationRun) -> CodingResultState:
    if run.verdict is CodingVerdict.PASS:
        return CodingResultState.SUCCESS
    if run.failure_reason is CodingFailureReason.PROVIDER_FAILURE:
        return CodingResultState.MODEL_ERROR
    if run.verdict is CodingVerdict.TIMEOUT:
        return CodingResultState.TIMEOUT
    if run.failure_reason is CodingFailureReason.TOOL_BUDGET_EXHAUSTED:
        return CodingResultState.TOOL_BUDGET_EXHAUSTED
    if run.verdict in {CodingVerdict.INVALID_FIXTURE, CodingVerdict.ORACLE_ERROR}:
        return CodingResultState.INFRASTRUCTURE_ERROR
    if run.verdict is CodingVerdict.INSUFFICIENT_EVIDENCE:
        return CodingResultState.PARTIAL
    return CodingResultState.FAILURE


def _failure_taxonomy(run: CodingEvaluationRun) -> CodingFailureTaxonomy | None:
    reason = run.failure_reason
    if reason is None or run.verdict is CodingVerdict.PASS:
        return None
    mapping = {
        CodingFailureReason.PROVIDER_FAILURE: CodingFailureTaxonomy.PROVIDER_FAILURE,
        CodingFailureReason.TOOL_BUDGET_EXHAUSTED: CodingFailureTaxonomy.RESOURCE_LIMIT,
        CodingFailureReason.TIMEOUT: CodingFailureTaxonomy.RESOURCE_LIMIT,
        CodingFailureReason.NO_PROGRESS: CodingFailureTaxonomy.NO_PROGRESS,
        CodingFailureReason.LOCALIZATION_FAILURE: CodingFailureTaxonomy.REPO_LOCALIZATION_FAILURE,
        CodingFailureReason.EDIT_FAILURE: CodingFailureTaxonomy.EDIT_FAILURE,
        CodingFailureReason.WRONG_FILES_CHANGED: CodingFailureTaxonomy.EDIT_SCOPE_FAILURE,
        CodingFailureReason.EXCESSIVE_DIFF: CodingFailureTaxonomy.EDIT_SCOPE_FAILURE,
        CodingFailureReason.REVIEW_MISSED_FINDING: CodingFailureTaxonomy.VERIFICATION_FAILURE,
        CodingFailureReason.REVIEW_FALSE_POSITIVE: CodingFailureTaxonomy.VERIFICATION_FAILURE,
        CodingFailureReason.OUTPUT_CONTRACT_FAILURE: CodingFailureTaxonomy.OUTPUT_CONTRACT_FAILURE,
        CodingFailureReason.SEMANTIC_REVIEW_FAILURE: CodingFailureTaxonomy.SEMANTIC_REVIEW_FAILURE,
        CodingFailureReason.TEST_FAILURE: CodingFailureTaxonomy.VERIFICATION_FAILURE,
        CodingFailureReason.BUILD_FAILURE: CodingFailureTaxonomy.VERIFICATION_FAILURE,
        CodingFailureReason.REGRESSION_FAILURE: CodingFailureTaxonomy.REPAIR_FAILURE,
        CodingFailureReason.ORACLE_ERROR: CodingFailureTaxonomy.ENVIRONMENT_FAILURE,
        CodingFailureReason.INVALID_FIXTURE: CodingFailureTaxonomy.ENVIRONMENT_FAILURE,
        CodingFailureReason.INSUFFICIENT_EVIDENCE: CodingFailureTaxonomy.VERIFICATION_FAILURE,
        CodingFailureReason.AGENT_ERROR: CodingFailureTaxonomy.TOOL_EXECUTION_FAILURE,
    }
    return mapping.get(reason, CodingFailureTaxonomy.ENVIRONMENT_FAILURE)


def infer_root_cause(
    run: CodingEvaluationRun,
    *,
    security_violation: bool = False,
    quarantined: bool = False,
) -> CodingRootCause | None:
    """Infer a conservative forensic root-cause bucket for one run.

    The evaluator owns observed failure taxonomy, while this separate bucket
    records the best evidence-bound explanation for report consumers.  An
    explicit caller-supplied root cause remains authoritative; this helper is
    only the safe default used when producing a benchmark artifact.  It never
    upgrades missing evidence into a Harness or model claim.
    """

    if not isinstance(run, CodingEvaluationRun):
        raise TypeError("root-cause inference requires a CodingEvaluationRun")
    if run.verdict is CodingVerdict.PASS and not security_violation and not quarantined:
        return None
    if security_violation:
        return CodingRootCause.HARNESS_DEFECT
    if quarantined:
        return CodingRootCause.UNKNOWN

    reason = run.failure_reason
    if reason is CodingFailureReason.PROVIDER_FAILURE:
        return CodingRootCause.PROVIDER_DEFECT
    if reason is CodingFailureReason.INVALID_FIXTURE:
        return CodingRootCause.BENCHMARK_DEFECT
    if reason in {
        CodingFailureReason.TOOL_BUDGET_EXHAUSTED,
        CodingFailureReason.NO_PROGRESS,
    }:
        return CodingRootCause.MODEL_TOOL_USE_LIMIT
    if reason in {
        CodingFailureReason.LOCALIZATION_FAILURE,
        CodingFailureReason.EDIT_FAILURE,
        CodingFailureReason.BUILD_FAILURE,
        CodingFailureReason.TEST_FAILURE,
        CodingFailureReason.REGRESSION_FAILURE,
        CodingFailureReason.TIMEOUT,
        CodingFailureReason.WRONG_FILES_CHANGED,
        CodingFailureReason.EXCESSIVE_DIFF,
        CodingFailureReason.REVIEW_MISSED_FINDING,
        CodingFailureReason.REVIEW_FALSE_POSITIVE,
        CodingFailureReason.OUTPUT_CONTRACT_FAILURE,
        CodingFailureReason.SEMANTIC_REVIEW_FAILURE,
    }:
        return CodingRootCause.MODEL_REASONING_LIMIT
    # Oracle errors, generic runtime errors, and insufficient evidence need
    # operator-level attribution: they may be benchmark, environment,
    # provider-adapter, or Harness failures.  Preserve that uncertainty.
    return CodingRootCause.UNKNOWN


@dataclass(frozen=True, slots=True)
class CodingBenchmarkResultV1:
    """One sanitized JSONL record for a real-provider or baseline run."""

    run_id: str
    result_state: CodingResultState
    scenario_id: str
    scenario_version: int
    scenario_digest: str
    scenario_kind: CodingScenarioKind
    difficulty: str
    languages: tuple[str, ...]
    repository_base_revision: str
    config: BenchmarkRunConfig
    started_at: str
    finished_at: str
    metrics: Mapping[str, object]
    failure_taxonomy: CodingFailureTaxonomy | None = None
    root_cause: CodingRootCause | None = None
    security_violation: bool = False
    quarantined: bool = False
    result_digest: str = ""

    def __post_init__(self) -> None:
        _bounded_text(self.run_id, "run_id")
        if not isinstance(self.result_state, CodingResultState):
            raise TypeError("result_state is invalid")
        _bounded_text(self.scenario_id, "scenario_id")
        if type(self.scenario_version) is not int or self.scenario_version <= 0:
            raise ValueError("scenario_version must be positive")
        _digest(self.scenario_digest, "scenario_digest")
        if not isinstance(self.scenario_kind, CodingScenarioKind):
            raise TypeError("scenario_kind is invalid")
        if self.difficulty not in {"easy", "medium", "hard", "long_horizon"}:
            raise ValueError("difficulty is invalid")
        if not self.languages or any(not isinstance(item, str) for item in self.languages):
            raise ValueError("languages are invalid")
        _bounded_text(self.repository_base_revision, "repository_base_revision")
        if not isinstance(self.config, BenchmarkRunConfig):
            raise TypeError("config is invalid")
        _bounded_text(self.started_at, "started_at")
        _bounded_text(self.finished_at, "finished_at")
        if not isinstance(self.metrics, Mapping):
            raise TypeError("metrics must be a mapping")
        if type(self.security_violation) is not bool or type(self.quarantined) is not bool:
            raise ValueError("security_violation and quarantined must be boolean")
        if self.root_cause is not None and not isinstance(self.root_cause, CodingRootCause):
            raise TypeError("root_cause is invalid")
        if self.result_state is CodingResultState.SUCCESS and self.root_cause is not None:
            raise ValueError("successful benchmark results cannot have a root cause")
        if self.result_state is not CodingResultState.SUCCESS and self.root_cause is None:
            object.__setattr__(self, "root_cause", CodingRootCause.UNKNOWN)
        object.__setattr__(self, "metrics", dict(self.metrics))
        expected = digest_payload(self._payload_without_digest())
        if self.result_digest and self.result_digest != expected:
            raise ValueError("benchmark result digest does not match payload")
        object.__setattr__(self, "result_digest", expected)

    @classmethod
    def from_run(
        cls,
        run: CodingEvaluationRun,
        scenario: CodingScenario,
        config: BenchmarkRunConfig,
        *,
        root_cause: CodingRootCause | None = None,
        security_violation: bool = False,
        quarantined: bool = False,
    ) -> CodingBenchmarkResultV1:
        if run.identity.scenario_id != scenario.scenario_id:
            raise ValueError("run and scenario identifiers disagree")
        if run.identity.scenario_version != scenario.version:
            raise ValueError("run and scenario versions disagree")
        if run.identity.scenario_digest != scenario.digest:
            raise ValueError("run and scenario digests disagree")
        if config.scenario_manifest_digest == "":
            raise ValueError("scenario manifest digest is required")
        state = (
            CodingResultState.SECURITY_FAILURE
            if security_violation
            else CodingResultState.QUARANTINED
            if quarantined
            else _result_state(run)
        )
        resolved_root_cause = root_cause
        if resolved_root_cause is None:
            resolved_root_cause = infer_root_cause(
                run,
                security_violation=security_violation,
                quarantined=quarantined,
            )
        return cls(
            run_id=run.identity.run_id,
            result_state=state,
            scenario_id=scenario.scenario_id,
            scenario_version=scenario.version,
            scenario_digest=scenario.digest,
            scenario_kind=scenario.kind,
            difficulty=scenario.difficulty,
            languages=scenario.languages,
            repository_base_revision=run.fixture_base_revision,
            config=config,
            started_at=run.started_at,
            finished_at=run.finished_at,
            metrics=run.metrics.to_payload(),
            failure_taxonomy=_failure_taxonomy(run),
            root_cause=resolved_root_cause,
            security_violation=security_violation,
            quarantined=quarantined,
        )

    def _payload_without_digest(self) -> dict[str, object]:
        return {
            "schema_version": 1,
            "run_id": self.run_id,
            "result_state": self.result_state.value,
            "scenario_id": self.scenario_id,
            "scenario_version": self.scenario_version,
            "scenario_digest": self.scenario_digest,
            "scenario_kind": self.scenario_kind.value,
            "difficulty": self.difficulty,
            "languages": list(self.languages),
            "repository_base_revision": self.repository_base_revision,
            "config": self.config.to_payload(),
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "metrics": dict(self.metrics),
            "failure_taxonomy": self.failure_taxonomy.value if self.failure_taxonomy else None,
            "root_cause": self.root_cause.value if self.root_cause else None,
            "security_violation": self.security_violation,
            "quarantined": self.quarantined,
        }

    def to_payload(self) -> dict[str, object]:
        return {**self._payload_without_digest(), "result_digest": self.result_digest}

    def to_sanitized_payload(self, redactor: SecretRedactor) -> dict[str, object]:
        """Redact durable fields and recompute the record digest."""
        candidate = redactor.redact_fail_closed(self._payload_without_digest())
        if not isinstance(candidate, Mapping):
            raise TypeError("benchmark result redaction did not preserve an object")
        payload = dict(candidate)
        payload["result_digest"] = digest_payload(payload)
        return payload


class CodingBenchmarkJsonlWriter:
    """Crash-safe, append-only writer for bounded benchmark result records."""

    def __init__(
        self,
        path: Path,
        *,
        secret_redactor: SecretRedactor | None = None,
    ) -> None:
        self.path = path.expanduser().absolute()
        self._secret_redactor = secret_redactor
        if self.path.exists() and self.path.is_symlink():
            raise ValueError("benchmark result path must not be a symlink")

    async def append(self, result: CodingBenchmarkResultV1) -> None:
        if not isinstance(result, CodingBenchmarkResultV1):
            raise TypeError("benchmark result must be CodingBenchmarkResultV1")
        payload = (
            result.to_sanitized_payload(self._secret_redactor)
            if self._secret_redactor is not None
            else result.to_payload()
        )
        line = canonical_json_bytes(payload) + b"\n"
        if len(line) > _MAX_RESULT_LINE_BYTES:
            raise ValueError("benchmark result line exceeds its bound")
        await asyncio.to_thread(_append_result_line, self.path, line)


def _append_result_line(path: Path, line: bytes) -> None:
    parent = path.parent
    if not parent.is_dir():
        raise OSError("benchmark result parent directory does not exist")
    with _APPEND_LOCK:
        if path.exists() and path.is_symlink():
            raise OSError("benchmark result path became a symlink")
        flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND | getattr(os, "O_BINARY", 0)
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(path, flags, 0o600)
        try:
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode):
                raise OSError("benchmark result path is not a regular file")
            if info.st_size + len(line) > _MAX_RESULT_FILE_BYTES:
                raise OSError("benchmark result file exceeds its bound")
            view = memoryview(line)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    raise OSError("benchmark result append made no progress")
                view = view[written:]
            os.fsync(descriptor)
        finally:
            os.close(descriptor)


def aggregate_benchmark_results(results: Iterable[CodingBenchmarkResultV1]) -> dict[str, object]:
    """Return bounded aggregate metrics without reading transcripts."""

    values = tuple(results)
    state_counts = Counter(item.result_state.value for item in values)
    category_counts: dict[str, dict[str, int]] = {}
    difficulty_counts: dict[str, dict[str, int]] = {}
    language_counts: dict[str, dict[str, int]] = {}
    for item in values:
        _increment_bucket(category_counts, item.scenario_kind.value, item.result_state.value)
        _increment_bucket(difficulty_counts, item.difficulty, item.result_state.value)
        for language in item.languages:
            _increment_bucket(language_counts, language, item.result_state.value)
    return {
        "schema_version": 1,
        "run_count": len(values),
        "state_counts": dict(sorted(state_counts.items())),
        "success_rate": (
            sum(item.result_state is CodingResultState.SUCCESS for item in values) / len(values)
            if values
            else None
        ),
        "security_failure_count": sum(item.security_violation for item in values),
        "quarantine_count": sum(item.quarantined for item in values),
        "wall_clock_ms": _percentiles(values, "wall_clock_ms"),
        "total_tokens": _percentiles(values, "total_tokens"),
        "tool_calls": _percentiles(values, "tool_calls"),
        "by_category": category_counts,
        "by_difficulty": difficulty_counts,
        "by_language": language_counts,
    }


def _increment_bucket(bucket: dict[str, dict[str, int]], key: str, state: str) -> None:
    counts = bucket.setdefault(key, {})
    counts[state] = counts.get(state, 0) + 1


def _percentiles(results: tuple[CodingBenchmarkResultV1, ...], metric: str) -> dict[str, float | None]:
    values: list[float] = []
    for item in results:
        raw_value = item.metrics.get(metric)
        if isinstance(raw_value, (int, float)) and not isinstance(raw_value, bool):
            values.append(float(raw_value))
    values.sort()
    return {
        "p50": _percentile(values, 0.50),
        "p75": _percentile(values, 0.75),
        "p90": _percentile(values, 0.90),
    }


def _percentile(values: list[float], fraction: float) -> float | None:
    if not values:
        return None
    if len(values) == 1:
        return values[0]
    position = (len(values) - 1) * fraction
    lower = int(position)
    upper = min(lower + 1, len(values) - 1)
    weight = position - lower
    return values[lower] + (values[upper] - values[lower]) * weight


__all__ = [
    "LEGACY_OBSERVABILITY_NOT_AVAILABLE",
    "BenchmarkRunConfig",
    "CodingBenchmarkJsonlWriter",
    "CodingBenchmarkResultV1",
    "CodingFailureTaxonomy",
    "CodingQualificationJsonlWriter",
    "CodingQualificationRecordV1",
    "CodingResultState",
    "CodingRootCause",
    "aggregate_benchmark_results",
    "capture_working_tree_identity",
    "infer_root_cause",
]
