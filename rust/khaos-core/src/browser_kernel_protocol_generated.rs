//! Generated from security/browser-kernel-protocol-v1.json; do not edit.

use serde::{Deserialize, Serialize};

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

#[derive(Clone, Copy, Debug, Serialize, Eq, PartialEq)]
pub enum BrowserKernelErrorCode {
    #[serde(rename = "invalid_request")]
    InvalidRequest,
    #[serde(rename = "peer_authentication_failed")]
    PeerAuthenticationFailed,
    #[serde(rename = "authorization_denied")]
    AuthorizationDenied,
    #[serde(rename = "replay_detected")]
    ReplayDetected,
    #[serde(rename = "resource_not_found")]
    ResourceNotFound,
    #[serde(rename = "resource_conflict")]
    ResourceConflict,
    #[serde(rename = "resource_exhausted")]
    ResourceExhausted,
    #[serde(rename = "deadline_exceeded")]
    DeadlineExceeded,
    #[serde(rename = "tcb_integrity_failure")]
    TcbIntegrityFailure,
    #[serde(rename = "kernel_operation_failed")]
    KernelOperationFailed,
    #[serde(rename = "internal_error")]
    InternalError,
}

#[derive(Clone, Default, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BrowserKernelIsolationStatus {
    pub helper_authenticated: bool,
    pub network_namespace: bool,
    pub nft_default_deny: bool,
    pub cgroup_attached: bool,
    pub process_isolated: bool,
    pub resource_registry_verified: bool,
    pub quarantined: bool,
    pub proxy_host: String,
}

#[derive(Debug, Serialize)]
pub struct BrowserKernelResponse<'a> {
    pub protocol_version: u16,
    pub request_id: &'a str,
    pub ok: bool,
    pub error_code: Option<BrowserKernelErrorCode>,
    pub error: Option<String>,
    pub status: Option<BrowserKernelIsolationStatus>,
    pub runtime_capability: Option<String>,
}
