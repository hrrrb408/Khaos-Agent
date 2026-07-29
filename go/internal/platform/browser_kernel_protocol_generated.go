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
