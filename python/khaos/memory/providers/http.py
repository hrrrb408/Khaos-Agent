"""Generic, explicitly opt-in HTTP MemoryProvider adapter.

The adapter is intentionally protocol-oriented rather than vendor-specific.
It supports self-hosted Mem0/Graphiti-compatible deployments and custom
providers that expose the small Khaos JSON contract.  It never creates a
network client until the lifecycle registry has accepted a manifest with an
explicit network grant.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any

import httpx

from khaos.memory.core.contracts import (
    ForgetResult,
    MemoryCapabilities,
    MemoryForgetRequest,
    MemoryHit,
    MemorySearchRequest,
    MemoryStatus,
    MemoryWriteRequest,
    MemoryWriteResult,
    ProviderHealth,
    SourceType,
    enum_value,
)
from khaos.memory.providers.lifecycle import ProviderManifest


class MemoryHttpProvider:
    """Bounded HTTP provider using a Khaos-neutral JSON envelope."""

    trusted_canonical = False

    def __init__(
        self,
        manifest: ProviderManifest,
        *,
        api_key: str | None = None,
        timeout_seconds: float = 10.0,
        max_response_bytes: int = 4 * 1024 * 1024,
    ) -> None:
        if not manifest.network_required or not manifest.endpoint:
            raise ValueError("HTTP memory providers require an explicit network endpoint")
        if timeout_seconds <= 0 or timeout_seconds > 120:
            raise ValueError("memory provider timeout must be between 0 and 120 seconds")
        if max_response_bytes <= 0 or max_response_bytes > 64 * 1024 * 1024:
            raise ValueError("memory provider response budget is outside the bounded range")
        self.manifest = manifest
        self.provider_id = manifest.provider_id
        self._api_key = api_key
        self._timeout = timeout_seconds
        self._max_response_bytes = max_response_bytes
        self._client: httpx.AsyncClient | None = None

    def capabilities(self) -> MemoryCapabilities:
        """Return capabilities declared by the validated manifest."""

        return self.manifest.capabilities

    async def install(self) -> None:
        """No remote side effect is performed during install."""

    async def validate(self) -> None:
        """Validate endpoint shape before opening a client."""

        parsed = httpx.URL(self.manifest.endpoint or "")
        if parsed.scheme not in {"http", "https"} or not parsed.host:
            raise ValueError("memory provider endpoint must be an absolute HTTP(S) URL")

    async def mount(self) -> None:
        """Allocate no resources before the start phase."""

    async def start(self) -> None:
        if self._client is not None:
            return
        endpoint = self.manifest.endpoint
        if endpoint is None:
            raise RuntimeError("memory provider endpoint was not validated")
        headers = {"Accept": "application/json", "Content-Type": "application/json"}
        if self._api_key:
            headers["Authorization"] = f"Bearer {self._api_key}"
        self._client = httpx.AsyncClient(
            base_url=endpoint,
            headers=headers,
            timeout=self._timeout,
            follow_redirects=False,
            trust_env=False,
        )

    async def health(self) -> ProviderHealth:
        if self._client is None:
            return ProviderHealth(self.provider_id, False, "provider_not_started", "started")
        try:
            response = await self._client.get("/health")
            response.raise_for_status()
        except (httpx.HTTPError, ValueError) as exc:
            return ProviderHealth(self.provider_id, False, type(exc).__name__, "failed")
        return ProviderHealth(self.provider_id, True, "remote health check passed", "healthy")

    async def stop(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    async def unmount(self) -> None:
        """All client resources are closed by :meth:`stop`."""

    async def add(self, request: MemoryWriteRequest) -> MemoryWriteResult:
        payload = {
            "claim": request.candidate.claim,
            "memory_type": enum_value(request.candidate.memory_type),
            "key": request.candidate.key,
            "scope": request.candidate.scope,
            "namespace": request.candidate.namespace,
            "status": request.status.value,
            "authority": request.authority.value,
            "confidence": request.candidate.confidence,
            "source_event_ids": list(request.candidate.source_event_ids),
            "evidence_refs": [
                {
                    "source_type": enum_value(ref.source_type),
                    "source_ref": ref.source_ref,
                    "event_id": ref.event_id,
                    "verification_run_id": ref.verification_run_id,
                    "commit_sha": ref.commit_sha,
                }
                for ref in request.candidate.evidence_refs
            ],
            "runtime": {
                "principal_id": request.runtime.principal_id,
                "project_id": request.runtime.project_id,
                "session_id": request.runtime.session_id,
                "task_id": request.runtime.task_id,
                "workspace_id": request.runtime.workspace_id,
                "mode": request.runtime.mode,
                "environment_fingerprint": request.runtime.environment_fingerprint,
            },
        }
        data = await self._json_request("POST", "/memory/add", payload)
        memory_id = data.get("memory_id", data.get("id"))
        if not isinstance(memory_id, str) or not memory_id:
            raise ValueError("remote provider returned no memory_id")
        raw_status = str(data.get("status", request.status.value))
        try:
            status = MemoryStatus(raw_status)
        except ValueError:
            status = request.status
        superseded = data.get("superseded_memory_ids", ())
        if not isinstance(superseded, list | tuple):
            raise ValueError("remote provider returned malformed superseded ids")
        return MemoryWriteResult(
            memory_id=memory_id,
            status=status,
            superseded_memory_ids=tuple(str(value) for value in superseded),
            created=bool(data.get("created", True)),
        )

    async def search(self, request: MemorySearchRequest) -> list[MemoryHit]:
        data = await self._json_request(
            "POST",
            "/memory/search",
            {
                "query": request.query,
                "limit": request.limit,
                "include_historical": request.include_historical,
                "profile_id": request.profile_id,
                "filters": dict(request.filters),
                "runtime": {
                    "principal_id": request.runtime.principal_id,
                    "project_id": request.runtime.project_id,
                    "session_id": request.runtime.session_id,
                    "mode": request.runtime.mode,
                },
            },
        )
        raw_hits = data.get("hits", data.get("results", data))
        if not isinstance(raw_hits, list):
            raise ValueError("remote provider returned a non-list search result")
        hits: list[MemoryHit] = []
        for raw in raw_hits[: request.limit]:
            if not isinstance(raw, Mapping):
                raise ValueError("remote provider returned a malformed hit")
            hits.append(
                MemoryHit(
                    provider_id=self.provider_id,
                    external_id=_optional_string(raw.get("external_id", raw.get("id"))),
                    memory_id=_optional_string(raw.get("memory_id", raw.get("id"))),
                    content=str(raw.get("content", raw.get("value", ""))),
                    raw_score=_optional_float(raw.get("score")),
                    source_type=_optional_source(raw.get("source_type")),
                    source_ref=_optional_string(raw.get("source_ref")),
                    provider_metadata=dict(raw.get("metadata", {}))
                    if isinstance(raw.get("metadata", {}), Mapping)
                    else {},
                    authority_hint=_optional_string(raw.get("authority")),
                    confidence_hint=_optional_float(raw.get("confidence")),
                    memory_type=str(raw.get("memory_type", "PROJECT_FACT")),
                    status=str(raw.get("status", "ACTIVE")),
                    principal_id=str(raw.get("principal_id", request.runtime.principal_id)),
                    project_id=str(raw.get("project_id", request.runtime.project_id)),
                    namespace=str(raw.get("namespace", "private")),
                    scope=str(raw.get("scope", "global")),
                    session_id=_optional_string(raw.get("session_id")),
                    key=_optional_string(raw.get("key")),
                    event_ids=tuple(str(value) for value in raw.get("event_ids", ())),
                )
            )
        return hits

    async def forget(self, request: MemoryForgetRequest) -> ForgetResult:
        data = await self._json_request(
            "POST",
            "/memory/forget",
            {"memory_ids": list(request.memory_ids), "mode": request.mode},
        )
        forgotten = data.get("forgotten_ids", ())
        if not isinstance(forgotten, list | tuple):
            raise ValueError("remote provider returned malformed forgotten ids")
        return ForgetResult(tuple(str(value) for value in forgotten), request.mode)

    async def rebuild_from_events(self, events: list[Mapping[str, Any]]) -> int:
        """Import canonical event data through the remote provider contract."""

        if len(events) > 100_000:
            raise ValueError("remote memory rebuild event batch is oversized")
        data = await self._json_request("POST", "/memory/import", {"events": events})
        value = data.get("replayed", data.get("count", 0))
        try:
            count = int(value)
        except (TypeError, ValueError) as exc:
            raise ValueError("remote provider returned malformed rebuild count") from exc
        return max(0, count)

    async def rebuild_indexes(self) -> int:
        """Request rebuildable remote indexes after canonical import."""

        data = await self._json_request("POST", "/memory/rebuild", {})
        value = data.get("indexed", data.get("count", 0))
        try:
            count = int(value)
        except (TypeError, ValueError) as exc:
            raise ValueError("remote provider returned malformed index count") from exc
        return max(0, count)

    async def _json_request(self, method: str, path: str, payload: Mapping[str, Any]) -> dict[str, Any]:
        if self._client is None:
            raise RuntimeError("memory provider is not started")
        try:
            chunks: list[bytes] = []
            total = 0
            async with self._client.stream(method, path, json=dict(payload)) as response:
                response.raise_for_status()
                async for chunk in response.aiter_bytes(64 * 1024):
                    total += len(chunk)
                    if total > self._max_response_bytes:
                        raise ValueError("remote memory provider response is oversized")
                    chunks.append(chunk)
            data = json.loads(b"".join(chunks).decode("utf-8"))
        except (httpx.HTTPError, UnicodeDecodeError, ValueError, json.JSONDecodeError) as exc:
            raise RuntimeError(f"remote memory provider request failed: {type(exc).__name__}") from exc
        if not isinstance(data, dict):
            raise ValueError("remote memory provider response must be a JSON object")
        return data


def _optional_string(value: Any) -> str | None:
    return str(value) if isinstance(value, str) and value else None


def _optional_float(value: Any) -> float | None:
    if value is None:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _optional_source(value: Any) -> SourceType | str | None:
    if value is None:
        return None
    return str(value)


__all__ = ["MemoryHttpProvider"]
