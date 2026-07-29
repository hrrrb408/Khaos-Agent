// Code generated from security/browser-kernel-protocol-v1.json; DO NOT EDIT.
package platform

const BrowserKernelProtocolVersion uint16 = 1
const BrowserKernelMaxMessageBytes = 8192

type BrowserKernelOperation string

const (
	BrowserKernelOperationAuthorize     BrowserKernelOperation = "authorize"
	BrowserKernelOperationSetup         BrowserKernelOperation = "setup"
	BrowserKernelOperationAllowProxy    BrowserKernelOperation = "allow_proxy"
	BrowserKernelOperationRevokeProxy   BrowserKernelOperation = "revoke_proxy"
	BrowserKernelOperationAttachProcess BrowserKernelOperation = "attach_process"
	BrowserKernelOperationJoin          BrowserKernelOperation = "join"
	BrowserKernelOperationTeardown      BrowserKernelOperation = "teardown"
	BrowserKernelOperationStatus        BrowserKernelOperation = "status"
)

type BrowserKernelRequest struct {
	ProtocolVersion   uint16                 `json:"protocol_version"`
	RequestID         string                 `json:"request_id"`
	BootID            string                 `json:"boot_id"`
	ClientPID         uint32                 `json:"client_pid"`
	ClientStartTime   uint64                 `json:"client_start_time"`
	PrincipalID       string                 `json:"principal_id"`
	ProjectID         string                 `json:"project_id"`
	RuntimeID         string                 `json:"runtime_id"`
	TaskID            string                 `json:"task_id"`
	SandboxToken      string                 `json:"sandbox_token"`
	RuntimeCapability *string                `json:"runtime_capability"`
	Operation         BrowserKernelOperation `json:"op"`
	Port              *uint16                `json:"port"`
	TargetPID         *uint32                `json:"target_pid"`
	TargetStartTime   *uint64                `json:"target_start_time"`
}

type BrowserKernelErrorCode string

const (
	BrowserKernelErrorCodeInvalidRequest           BrowserKernelErrorCode = "invalid_request"
	BrowserKernelErrorCodePeerAuthenticationFailed BrowserKernelErrorCode = "peer_authentication_failed"
	BrowserKernelErrorCodeAuthorizationDenied      BrowserKernelErrorCode = "authorization_denied"
	BrowserKernelErrorCodeReplayDetected           BrowserKernelErrorCode = "replay_detected"
	BrowserKernelErrorCodeResourceNotFound         BrowserKernelErrorCode = "resource_not_found"
	BrowserKernelErrorCodeResourceConflict         BrowserKernelErrorCode = "resource_conflict"
	BrowserKernelErrorCodeResourceExhausted        BrowserKernelErrorCode = "resource_exhausted"
	BrowserKernelErrorCodeDeadlineExceeded         BrowserKernelErrorCode = "deadline_exceeded"
	BrowserKernelErrorCodeTcbIntegrityFailure      BrowserKernelErrorCode = "tcb_integrity_failure"
	BrowserKernelErrorCodeKernelOperationFailed    BrowserKernelErrorCode = "kernel_operation_failed"
	BrowserKernelErrorCodeInternalError            BrowserKernelErrorCode = "internal_error"
)

type BrowserKernelIsolationStatus struct {
	HelperAuthenticated      bool   `json:"helper_authenticated"`
	NetworkNamespace         bool   `json:"network_namespace"`
	NFTDefaultDeny           bool   `json:"nft_default_deny"`
	CgroupAttached           bool   `json:"cgroup_attached"`
	ProcessIsolated          bool   `json:"process_isolated"`
	ResourceRegistryVerified bool   `json:"resource_registry_verified"`
	Quarantined              bool   `json:"quarantined"`
	ProxyHost                string `json:"proxy_host"`
}

type BrowserKernelResponse struct {
	ProtocolVersion   uint16                        `json:"protocol_version"`
	RequestID         string                        `json:"request_id"`
	OK                bool                          `json:"ok"`
	ErrorCode         *BrowserKernelErrorCode       `json:"error_code"`
	Error             *string                       `json:"error"`
	Status            *BrowserKernelIsolationStatus `json:"status"`
	RuntimeCapability *string                       `json:"runtime_capability"`
}
