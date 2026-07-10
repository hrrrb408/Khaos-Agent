package api

import (
	"context"
	"encoding/json"
)

// ChatRequest is the REST request body for POST /api/chat.
type ChatRequest struct {
	SessionID string `json:"session_id"`
	Mode      string `json:"mode"`
	Message   string `json:"message"`
}

// ChatEvent is the gateway-neutral event shape streamed as SSE.
type ChatEvent struct {
	Event string         `json:"event"`
	Data  map[string]any `json:"data"`
}

// AgentClient is implemented by the Python gRPC client and by tests.
type AgentClient interface {
	Chat(ctx context.Context, req ChatRequest) (<-chan ChatEvent, error)
	ConfirmPermission(ctx context.Context, sessionID string, toolCallID string, approved bool, remember bool) error
	SwitchMode(ctx context.Context, sessionID string, targetMode string) (string, error)
}

// WebhookRequest preserves an external platform's original webhook data.
type WebhookRequest struct {
	Platform  string            `json:"platform"`
	ChannelID string            `json:"channel_id"`
	Headers   map[string]string `json:"headers"`
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
type ChannelClient interface {
	HandleWebhook(ctx context.Context, request WebhookRequest) (WebhookResponse, error)
	ListChannels(ctx context.Context) ([]ChannelInfo, error)
	SetChannelEnabled(ctx context.Context, channelID string, enabled bool) error
}

// TaskClient manages persistent coding tasks and their event streams.
type TaskClient interface {
	CreateTask(ctx context.Context, goal string) (map[string]any, error)
	ListTasks(ctx context.Context, activeOnly bool) ([]map[string]any, error)
	GetTask(ctx context.Context, id string) (map[string]any, error)
	CancelTask(ctx context.Context, id string) error
	ApproveTask(ctx context.Context, id string) error
	RejectTask(ctx context.Context, id string) error
	TaskEvents(ctx context.Context, id string) (<-chan map[string]any, error)
	TaskArtifacts(ctx context.Context, id string) ([]map[string]any, error)
}

// SubagentClient forwards subagent lifecycle calls to the Python service.
type SubagentClient interface {
	Spawn(ctx context.Context, goal string, context string, tools []string, timeout int) (map[string]any, error)
	CollectResults(ctx context.Context) (map[string]any, error)
	Status(ctx context.Context) (map[string]any, error)
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
type MemoryClient interface {
	Get(ctx context.Context, scope string, key string) (Memory, error)
	Set(ctx context.Context, memory Memory) (Memory, error)
	Delete(ctx context.Context, id int64) error
	Search(ctx context.Context, scope string, query string, topK int) ([]Memory, error)
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
type AuditClient interface {
	Query(ctx context.Context, action, result, since, until string, limit int) ([]AuditEntry, error)
}

// ConfigStore abstracts runtime config persistence.
type ConfigStore interface {
	Get() map[string]any
	Set(map[string]any)
}
