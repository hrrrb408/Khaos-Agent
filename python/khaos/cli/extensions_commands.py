"""Read-only/explicit lifecycle commands for M8.7 extensions."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import yaml

from khaos.extensions.contracts import (
    ExtensionDescriptor,
    ExtensionProvenance,
    ExtensionSource,
    ExtensionType,
    McpTransportKind,
)
from khaos.extensions.service import ExtensionService


def build_extension_service(config_path: Path | str = "config.yaml") -> ExtensionService:
    """Load only declarative local config candidates into one extension service.

    Configuration creates candidates and validated metadata.  MCP handshake,
    process ownership, network authority, and availability remain explicit
    runtime operations; a config file cannot make a remote server executable
    merely by being discovered.
    """
    service = ExtensionService()
    path = Path(config_path)
    if not path.exists() or not path.is_file():
        return service
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except (OSError, UnicodeError, yaml.YAMLError):
        return service
    values = raw.get("extensions", []) if isinstance(raw, dict) else []
    if not isinstance(values, list):
        return service
    for entry in values[:128]:
        if not isinstance(entry, dict):
            continue
        try:
            extension_id = str(entry.get("extension_id", entry.get("id", "")))
            name = str(entry.get("name", extension_id))
            descriptor = ExtensionDescriptor(
                extension_id=extension_id,
                name=name,
                version=str(entry.get("version", "1")),
                extension_type=ExtensionType(str(entry.get("type", "MCP_SERVER"))),
                source=ExtensionSource(
                    locator=str(entry.get("source", entry.get("locator", extension_id))),
                    kind="CONFIG",
                    declared_by="config.yaml",
                ),
                provenance=ExtensionProvenance.LOCAL_TRUSTED_CONFIG,
                transport=McpTransportKind(str(entry.get("transport", "NONE"))),
                transport_identity=str(entry.get("transport_identity", entry.get("endpoint", ""))),
                artifact_digest=str(entry.get("artifact_digest", "")),
                config=entry.get("config", {}),
                metadata={"config_path": str(path)},
                enabled=bool(entry.get("enabled", True)),
            )
            service.registry.register(descriptor)
        except (TypeError, ValueError):
            continue
    return service


def render_extensions(service: ExtensionService, *, as_json: bool = False) -> str:
    """Render bounded extension metadata for CLI/API tests."""
    payload = list(service.list_payload())
    if as_json:
        return json.dumps(payload, ensure_ascii=False, sort_keys=True)
    if not payload:
        return "no extensions registered"
    lines = ["extensions:"]
    for record in payload:
        descriptor = record["descriptor"]
        lines.append(
            f"  {descriptor['extension_id']} "
            f"[{descriptor['extension_type']}/{record['state']}] "
            f"v{descriptor['version']} ({descriptor['provenance']})"
        )
    return "\n".join(lines)


def cmd_extensions(args: Any) -> int:
    """Handle ``khaos extensions`` without executing external code."""
    service = build_extension_service(getattr(args, "config", "config.yaml"))
    command = getattr(args, "extensions_command", None) or "list"
    as_json = bool(getattr(args, "as_json", False))
    try:
        if command == "list":
            print(render_extensions(service, as_json=as_json))
            return 0
        if command == "show":
            payload = service.show(args.extension_id)
            if as_json:
                print(json.dumps(payload, ensure_ascii=False, sort_keys=True))
            else:
                descriptor = payload["descriptor"]
                print(
                    f"{descriptor['extension_id']} "
                    f"[{descriptor['extension_type']}/{payload['state']}] "
                    f"v{descriptor['version']} ({descriptor['provenance']})"
                )
            return 0
        if command == "doctor":
            report = service.doctor()
            payload = {"healthy": report.healthy, "blockers": list(report.blockers), "records": list(report.records)}
            print(json.dumps(payload, ensure_ascii=False, sort_keys=True) if as_json else ("extensions healthy" if report.healthy else "\n".join(report.blockers)))
            return 0 if report.healthy else 1
        if command in {"enable", "disable"}:
            # Commands are explicit lifecycle intents.  A CLI process has no
            # running owner to drain, so the service applies only the
            # registry projection; a subsequent runtime must handshake again.
            import asyncio

            if command == "enable":
                record = asyncio.run(service.enable(args.extension_id))
            else:
                record = asyncio.run(service.disable(args.extension_id))
            print(json.dumps(record.to_payload(), ensure_ascii=False, sort_keys=True) if as_json else f"{args.extension_id}: {record.state.value}")
            return 0
    except (KeyError, RuntimeError, ValueError) as exc:
        print(f"extension command failed: {exc}")
        return 1
    print("usage: khaos extensions [list|show <id>|doctor|enable <id>|disable <id>]")
    return 2


__all__ = ["build_extension_service", "cmd_extensions", "render_extensions"]
