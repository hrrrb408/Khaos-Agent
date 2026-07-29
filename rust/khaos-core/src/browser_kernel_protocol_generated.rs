//! Generated from security/browser-kernel-protocol-v1.json; do not edit.

use serde::Deserialize;

pub const PROTOCOL_VERSION: u16 = 1;
pub const MAX_MESSAGE_BYTES: usize = 8192;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
pub enum BrowserKernelOperation {
    #[serde(rename = "authorize")]
    Authorize,
    #[serde(rename = "setup")]
    Setup,
    #[serde(rename = "allow_proxy")]
    AllowProxy,
    #[serde(rename = "revoke_proxy")]
    RevokeProxy,
    #[serde(rename = "attach_process")]
    AttachProcess,
    #[serde(rename = "join")]
    Join,
    #[serde(rename = "teardown")]
    Teardown,
    #[serde(rename = "status")]
    Status,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrowserKernelRequest {
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
}
