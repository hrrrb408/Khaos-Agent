#!/usr/bin/env python3
"""Generate browser kernel protocol types from the canonical JSON Schema."""

from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCHEMA = ROOT / "security" / "browser-kernel-protocol-v1.json"
PYTHON = ROOT / "python" / "khaos" / "security" / "browser_kernel_protocol_generated.py"
RUST = ROOT / "rust" / "khaos-core" / "src" / "browser_kernel_protocol_generated.rs"
GO = ROOT / "go" / "internal" / "platform" / "browser_kernel_protocol_generated.go"


def _load() -> dict[str, object]:
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    properties = schema["properties"]
    required = schema["required"]
    if set(properties) != set(required):
        raise SystemExit("browser protocol requires every request field")
    response = schema["x-khaos-response"]
    if set(response["properties"]) != set(response["required"]):
        raise SystemExit("browser protocol requires every response field")
    return schema


def _python(schema: dict[str, object]) -> str:
    properties = schema["properties"]
    operations = properties["op"]["enum"]
    fields = schema["required"]
    token_pattern = properties["sandbox_token"]["pattern"]
    response = schema["x-khaos-response"]
    response_fields = response["required"]
    error_codes = response["properties"]["error_code"]["oneOf"][1]["enum"]
    status = response["properties"]["status"]["oneOf"][1]
    return f'''"""Generated from security/browser-kernel-protocol-v1.json; do not edit."""

from typing import Final

PROTOCOL_VERSION: Final = {properties["protocol_version"]["const"]}
MAX_MESSAGE_BYTES: Final = {schema["x-khaos-max-message-bytes"]}
REQUEST_FIELDS: Final = frozenset({fields!r})
OPERATIONS: Final = frozenset({operations!r})
SANDBOX_TOKEN_PATTERN: Final = {token_pattern!r}
RESPONSE_FIELDS: Final = frozenset({response_fields!r})
ERROR_CODES: Final = frozenset({error_codes!r})
STATUS_FIELDS: Final = frozenset({status["required"]!r})
'''


def _rust(schema: dict[str, object]) -> str:
    properties = schema["properties"]
    operations = properties["op"]["enum"]
    variants = "\n".join(
        f'    #[serde(rename = "{operation}")]\n    {"".join(part.title() for part in operation.split("_"))},'
        for operation in operations
    )
    response = schema["x-khaos-response"]
    error_codes = response["properties"]["error_code"]["oneOf"][1]["enum"]
    error_variants = "\n".join(
        f'    #[serde(rename = "{code}")]\n    {"".join(part.title() for part in code.split("_"))},'
        for code in error_codes
    )
    return f'''//! Generated from security/browser-kernel-protocol-v1.json; do not edit.

use serde::{{Deserialize, Serialize}};

pub const PROTOCOL_VERSION: u16 = {properties["protocol_version"]["const"]};
pub const MAX_MESSAGE_BYTES: usize = {schema["x-khaos-max-message-bytes"]};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
pub enum BrowserKernelOperation {{
{variants}
}}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrowserKernelRequest {{
    pub protocol_version: u16,
    pub request_id: String,
    pub boot_id: String,
    pub client_pid: u32,
    pub client_start_time: u64,
    pub principal_id: String,
    pub project_id: String,
    pub runtime_id: String,
    pub task_id: String,
    pub sandbox_token: String,
    pub runtime_capability: Option<String>,
    pub op: BrowserKernelOperation,
    pub port: Option<u16>,
    pub target_pid: Option<u32>,
    pub target_start_time: Option<u64>,
}}

#[derive(Clone, Copy, Debug, Serialize, Eq, PartialEq)]
pub enum BrowserKernelErrorCode {{
{error_variants}
}}

#[derive(Clone, Default, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BrowserKernelIsolationStatus {{
    pub helper_authenticated: bool,
    pub network_namespace: bool,
    pub nft_default_deny: bool,
    pub cgroup_attached: bool,
    pub process_isolated: bool,
    pub resource_registry_verified: bool,
    pub quarantined: bool,
    pub proxy_host: String,
}}

#[derive(Debug, Serialize)]
pub struct BrowserKernelResponse<'a> {{
    pub protocol_version: u16,
    pub request_id: &'a str,
    pub ok: bool,
    pub error_code: Option<BrowserKernelErrorCode>,
    pub error: Option<String>,
    pub status: Option<BrowserKernelIsolationStatus>,
    pub runtime_capability: Option<String>,
}}
'''


def _go(schema: dict[str, object]) -> str:
    properties = schema["properties"]
    operations = properties["op"]["enum"]
    constants = "\n".join(
        f'\tBrowserKernelOperation{"".join(part.title() for part in operation.split("_"))} BrowserKernelOperation = "{operation}"'
        for operation in operations
    )
    response = schema["x-khaos-response"]
    error_codes = response["properties"]["error_code"]["oneOf"][1]["enum"]
    error_constants = "\n".join(
        f'\tBrowserKernelErrorCode{"".join(part.title() for part in code.split("_"))} BrowserKernelErrorCode = "{code}"'
        for code in error_codes
    )
    source = f'''// Code generated from security/browser-kernel-protocol-v1.json; DO NOT EDIT.
package platform

const BrowserKernelProtocolVersion uint16 = {properties["protocol_version"]["const"]}
const BrowserKernelMaxMessageBytes = {schema["x-khaos-max-message-bytes"]}

type BrowserKernelOperation string

const (
{constants}
)

type BrowserKernelRequest struct {{
\tProtocolVersion uint16 `json:"protocol_version"`
\tRequestID string `json:"request_id"`
\tBootID string `json:"boot_id"`
\tClientPID uint32 `json:"client_pid"`
\tClientStartTime uint64 `json:"client_start_time"`
\tPrincipalID string `json:"principal_id"`
\tProjectID string `json:"project_id"`
\tRuntimeID string `json:"runtime_id"`
\tTaskID string `json:"task_id"`
\tSandboxToken string `json:"sandbox_token"`
\tRuntimeCapability *string `json:"runtime_capability"`
\tOperation BrowserKernelOperation `json:"op"`
\tPort *uint16 `json:"port"`
\tTargetPID *uint32 `json:"target_pid"`
\tTargetStartTime *uint64 `json:"target_start_time"`
}}

type BrowserKernelErrorCode string

const (
{error_constants}
)

type BrowserKernelIsolationStatus struct {{
\tHelperAuthenticated bool `json:"helper_authenticated"`
\tNetworkNamespace bool `json:"network_namespace"`
\tNFTDefaultDeny bool `json:"nft_default_deny"`
\tCgroupAttached bool `json:"cgroup_attached"`
\tProcessIsolated bool `json:"process_isolated"`
\tResourceRegistryVerified bool `json:"resource_registry_verified"`
\tQuarantined bool `json:"quarantined"`
\tProxyHost string `json:"proxy_host"`
}}

type BrowserKernelResponse struct {{
\tProtocolVersion uint16 `json:"protocol_version"`
\tRequestID string `json:"request_id"`
\tOK bool `json:"ok"`
\tErrorCode *BrowserKernelErrorCode `json:"error_code"`
\tError *string `json:"error"`
\tStatus *BrowserKernelIsolationStatus `json:"status"`
\tRuntimeCapability *string `json:"runtime_capability"`
}}
'''
    formatted = subprocess.run(
        ("gofmt",), input=source, text=True, capture_output=True, check=True
    )
    return formatted.stdout


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    schema = _load()
    outputs = {PYTHON: _python(schema), RUST: _rust(schema), GO: _go(schema)}
    stale = [path for path, content in outputs.items() if not path.is_file() or path.read_text(encoding="utf-8") != content]
    if args.check:
        if stale:
            raise SystemExit("stale generated browser protocol: " + ", ".join(str(path.relative_to(ROOT)) for path in stale))
        return 0
    for path, content in outputs.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
