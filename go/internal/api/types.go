package api

import (
	"context"
	"encoding/json"
	"errors"
)

// ErrForbidden is returned by a Client method when the Python service
// rejects the call with ``status: "forbidden"`` (e.g. the caller is not
// in ``channel_admins`` for channel mutations).  The HTTP handler
// maps it to 403 so the REST caller can distinguish authorization
// failures from not-found / upstream errors.
//
// C-2-4 (HIGH 4): channel enable/disable via REST is now admin-gated
// on the Python side; without a distinguishable error type the handler
// would mask forbidden as 404 (the pre-C-2-4 behaviour).
var ErrForbidden = errors.New("forbidden")

// ChatRequest is the REST request body for POST /api/chat.
type ChatRequest struct {
	SessionID   string `json:"session_id"`
	Mode        string `json:"mode"`
	Message     string `json:"message"`
	PrincipalID string `json:"principal_id,omitempty"`
}

// ChatEvent is the gateway-neutral event shape streamed as SSE.
type ChatEvent struct {
	Event string         `json:"event"`
	Data  map[string]any `json:"data"`
}

// AgentClient is implemented by the Python gRPC client and by tests.
//
// C-1-1: every method that dispatches to Python must carry the
// authenticated principal so Python's RequestContext.principal_id
// (the sole identity authority) matches the Gateway's auth context.
// ``Chat`` and ``ConfirmPermission`` already took ``principalID``;
// ``SwitchMode`` now takes it too.
type AgentClient interface {
	Chat(ctx context.Context, req ChatRequest) (<-chan ChatEvent, error)
	ConfirmPermission(ctx context.Context, principalID string, sessionID string, toolCallID string, bindingDigest string, approved bool, remember bool) error
	SwitchMode(ctx context.Context, principalID string, sessionID string, targetMode string) (string, error)
}

// WebhookRequest preserves an external platform's original webhook data.
type WebhookRequest struct {
	Platform  string            `json:"platform"`
	ChannelID string            `json:"channel_id"`
	Headers   map[string]string `json:"headers"`
	Query     map[string]string `json:"query"`
	Body      json.RawMessage   `json:"body"`
}

// WebhookResponse is returned after an inbound webhook is processed.
type WebhookResponse struct {
	Status    string `json:"status"`
	MessageID string `json:"message_id,omitempty"`
	Error     string `json:"error,omitempty"`
}

// ChannelInfo reports one registered channel's state.
type ChannelInfo struct {
	ID      string `json:"id"`
	Type    string `json:"type"`
	Enabled bool   `json:"enabled"`
	Healthy bool   `json:"healthy"`
	Status  string `json:"status"`
}

// ChannelClient is the optional channel-management RPC surface.
//
// C-1-1: every method now carries the authenticated principal.
// ``HandleWebhook`` receives ``""`` for signature-authenticated
// webhook ingress (no API-key principal in that path); Python's
// ``AgentService.HandleWebhook`` treats empty principal as
// unauthenticated platform ingress.
type ChannelClient interface {
	HandleWebhook(ctx context.Context, principalID string, request WebhookRequest) (WebhookResponse, error)
	ListChannels(ctx context.Context, principalID string) ([]ChannelInfo, error)
	SetChannelEnabled(ctx context.Context, principalID string, channelID string, enabled bool) error
}

// TransitionResult identifies the outcome of a task lifecycle transition.
type TransitionResult string

const (
	TransitionUpdated   TransitionResult = "updated"
	TransitionUnchanged TransitionResult = "unchanged"
	TransitionNotFound  TransitionResult = "not_found"
	TransitionInvalid   TransitionResult = "invalid_transition"
	// TransitionLeaseInvalidationFailed signals that the TaskManager
	// refused to cancel the task because its workspace lease could not
	// be released (Batch 2.6 §4 fail-closed).  The task stays in its
	// pre-cancel state so the caller can retry.
	//
	// C-2-5 (HIGH 2): previously this outcome was silently swallowed
	// by the Python ``TaskService.cancel`` (returned ``{"ok": true}``)
	// and unmappable on the Go side (``taskAction`` collapsed it into
	// ``TransitionInvalid``).  The REST caller saw HTTP 200 while the
	// task was still active.  The handler now maps this to HTTP 503
	// (transient infrastructure failure — retry) rather than 409
	// (client-side state conflict).
	TransitionLeaseInvalidationFailed TransitionResult = "lease_invalidation_failed"
)

// TaskClient manages persistent coding tasks and their event streams.
//
// C-1-1: ``principalID`` is now the first argument of every method
// (after ``ctx``) so Python's TaskService can scope by
// ``ctx.principal_id`` instead of falling back to ``"gateway"``.
// ``ApproveTask`` / ``RejectTask`` already took ``principalID`` (in
// a different position) — their signatures are unchanged for
// backward compatibility with the approval binding flow.
type TaskClient interface {
	CreateTask(ctx context.Context, principalID string, goal string) (map[string]any, error)
	ListTasks(ctx context.Context, principalID string, activeOnly bool) ([]map[string]any, error)
	GetTask(ctx context.Context, principalID string, id string) (map[string]any, error)
	CancelTask(ctx context.Context, principalID string, id string) (TransitionResult, error)
	ApproveTask(ctx context.Context, id string, principalID string, sessionID string, bindingDigest string) (TransitionResult, error)
	RejectTask(ctx context.Context, id string, principalID string, sessionID string, bindingDigest string) (TransitionResult, error)
	TaskEvents(ctx context.Context, principalID string, id string) (<-chan map[string]any, error)
	TaskArtifacts(ctx context.Context, principalID string, id string) ([]map[string]any, error)
}

// SubagentClient forwards subagent lifecycle calls to the Python service.
type SubagentClient interface {
	Spawn(ctx context.Context, principalID string, goal string, context string, tools []string, timeout int) (map[string]any, error)
	CollectResults(ctx context.Context, principalID string) (map[string]any, error)
	Status(ctx context.Context, principalID string) (map[string]any, error)
}

// Memory represents one memory record.
type Memory struct {
	ID         int64  `json:"id"`
	Scope      string `json:"scope"`
	Key        string `json:"key"`
	Value      string `json:"value"`
	TTL        int    `json:"ttl"`
	Confidence int    `json:"confidence"`
	AccessFreq int    `json:"access_freq"`
	CreatedAt  string `json:"created_at"`
	UpdatedAt  string `json:"updated_at"`
}

// MemoryClient is implemented by the Python memory service and by tests.
//
// C-2-2 (HIGH 6): every method now carries ``principalID`` so the
// Python ``MemoryService`` can scope reads/writes to the authenticated
// caller.  Previously the Gateway called an in-process ``MemoryMap``
// with no principal — REST-saved memories never reached Python, were
// not principal-scoped, and were lost on Gateway restart.  The
// ``MemoryMap`` test double still exists but is no longer wired into
// the production Gateway binary.
type MemoryClient interface {
	Get(ctx context.Context, principalID string, scope string, key string) (Memory, error)
	Set(ctx context.Context, principalID string, memory Memory) (Memory, error)
	Delete(ctx context.Context, principalID string, id int64) error
	Search(ctx context.Context, principalID string, scope string, query string, topK int) ([]Memory, error)
}

// AuditEntry is one audit log record returned from the audit query endpoint.
type AuditEntry struct {
	ID        int64          `json:"id"`
	Action    string         `json:"action"`
	Target    string         `json:"target"`
	Result    string         `json:"result"`
	Detail    map[string]any `json:"detail"`
	SessionID string         `json:"session_id"`
	CreatedAt string         `json:"created_at"`
}

// AuditClient queries audit records from the Python audit service.
//
// C-1-1: ``Query`` now carries the authenticated principal so
// Python's AuditService can scope by ``ctx.principal_id`` instead
// of returning only ``"gateway"``-attributed entries.
type AuditClient interface {
	Query(ctx context.Context, principalID string, action, result, since, until string, limit int) ([]AuditEntry, error)
}

// ConfigStore abstracts runtime config persistence.
type ConfigStore interface {
	Get() map[string]any
	Set(map[string]any)
}
