"""Feature-flag configuration for optional LSP evidence fusion.

The flag ``enable_lsp_evidence_fusion`` defaults to ``False``. When disabled,
the fusion service returns repository-only results and never sends an LSP
request. Callers cannot toggle the flag per-tool-call — it is a server-side
runtime configuration.

When enabled, the following preconditions must ALL hold:
    - A managed ``LspClient`` is available and started.
    - An active ``TaskWorkspace`` exists.
    - An ``ExecutionService`` is bound.
    - A safe backend (network=none) is configured.
    - Trusted LSP server configuration is present.

No raw ``subprocess`` path is ever introduced — all LSP communication goes
through the existing ``LspClient`` → ``ExecutionService.start_managed_process``
gate.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class LspFusionConfig:
    """Server-side configuration for LSP evidence fusion.

    Defaults match ``config.yaml`` and are intentionally conservative.
    """

    enabled: bool = False
    request_timeout_seconds: float = 10.0
    restart_limit: int = 1
    cache_max_entries: int = 2048
    cache_ttl_seconds: float = 300.0
    cache_max_bytes: int = 16 * 1024 * 1024
    trusted_servers: tuple[str, ...] = field(default_factory=tuple)

    @classmethod
    def from_dict(cls, data: dict) -> "LspFusionConfig":
        """Build config from a parsed ``config.yaml`` fragment.

        Unknown keys are ignored. Missing keys fall back to defaults.
        """
        if not data:
            return cls()
        return cls(
            enabled=bool(data.get("enabled", False)),
            request_timeout_seconds=float(data.get("request_timeout_seconds", 10.0)),
            restart_limit=int(data.get("restart_limit", 1)),
            cache_max_entries=int(data.get("cache_max_entries", 2048)),
            cache_ttl_seconds=float(data.get("cache_ttl_seconds", 300.0)),
            cache_max_bytes=int(data.get("cache_max_bytes", 16 * 1024 * 1024)),
            trusted_servers=tuple(data.get("trusted_servers", ())),
        )

    def to_dict(self) -> dict:
        return {
            "enabled": self.enabled,
            "request_timeout_seconds": self.request_timeout_seconds,
            "restart_limit": self.restart_limit,
            "cache_max_entries": self.cache_max_entries,
            "cache_ttl_seconds": self.cache_ttl_seconds,
            "cache_max_bytes": self.cache_max_bytes,
            "trusted_servers": list(self.trusted_servers),
        }


DEFAULT_CONFIG = LspFusionConfig()
