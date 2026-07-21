package platform

import (
	"bufio"
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"path/filepath"
	"time"

	"khaos/go/internal/api"
)

// Compile-time assertions that PythonClient satisfies the gateway interfaces.
var (
	_ api.AgentClient    = PythonClient{}
	_ api.AuditClient    = PythonClient{}
	_ api.SubagentClient = PythonClient{}
	_ api.ChannelClient  = PythonClient{}
	_ api.TaskClient     = PythonClient{}
)

// CreateTask creates a persistent coding task.
//
// C-1-1: ``principalID`` is the authenticated principal from the
// Gateway's auth context.  It is written into the RPC auth envelope
// so Python's RequestContext.principal_id matches the caller.
func (c PythonClient) CreateTask(ctx context.Context, principalID string, goal string) (map[string]any, error) {
	return c.callMap(ctx, "TaskService.Create", map[string]any{"goal": goal}, principalID)
}
func (c PythonClient) ListTasks(ctx context.Context, principalID string, activeOnly bool) ([]map[string]any, error) {
	return c.callList(ctx, "TaskService.List", map[string]any{"active_only": activeOnly}, principalID)
}
func (c PythonClient) GetTask(ctx context.Context, principalID string, id string) (map[string]any, error) {
	return c.callMap(ctx, "TaskService.Get", map[string]any{"task_id": id}, principalID)
}
func (c PythonClient) CancelTask(ctx context.Context, principalID string, id string) (api.TransitionResult, error) {
	return c.taskAction(ctx, "TaskService.Cancel", principalID, id)
}
func (c PythonClient) ApproveTask(ctx context.Context, id string, principalID string, sessionID string, bindingDigest string) (api.TransitionResult, error) {
	return c.taskApprovalAction(ctx, "TaskService.Approve", id, principalID, sessionID, bindingDigest)
}
func (c PythonClient) RejectTask(ctx context.Context, id string, principalID string, sessionID string, bindingDigest string) (api.TransitionResult, error) {
	return c.taskApprovalAction(ctx, "TaskService.Reject", id, principalID, sessionID, bindingDigest)
}

func (c PythonClient) taskApprovalAction(ctx context.Context, method, id, principalID, sessionID, bindingDigest string) (api.TransitionResult, error) {
	response, err := c.callMap(ctx, method, map[string]any{
		"task_id": id, "principal_id": principalID, "session_id": sessionID,
		"binding_digest": bindingDigest,
	}, principalID)
	if err != nil {
		return "", err
	}
	if ok, _ := response["ok"].(bool); !ok {
		if stringValue(response["error"]) == "task not found" {
			return api.TransitionNotFound, nil
		}
		return api.TransitionInvalid, nil
	}
	return api.TransitionUpdated, nil
}
func (c PythonClient) TaskArtifacts(ctx context.Context, principalID string, id string) ([]map[string]any, error) {
	return c.callList(ctx, "TaskService.Artifacts", map[string]any{"task_id": id}, principalID)
}
func (c PythonClient) taskAction(ctx context.Context, method, principalID, id string) (api.TransitionResult, error) {
	response, err := c.callMap(ctx, method, map[string]any{"task_id": id}, principalID)
	if err != nil {
		return "", err
	}
	if ok, _ := response["ok"].(bool); !ok {
		message := stringValue(response["error"])
		if message == "task not found" {
			return api.TransitionNotFound, nil
		}
		return api.TransitionInvalid, nil
	}
	return api.TransitionUpdated, nil
}

func (c PythonClient) TaskEvents(ctx context.Context, principalID string, id string) (<-chan map[string]any, error) {
	conn, err := c.dial(ctx)
	if err != nil {
		return nil, err
	}
	stopCancelWatch := closeOnContextDone(ctx, conn)
	if err := c.writeRequest(conn, "TaskService.Events", map[string]any{"task_id": id}, principalID); err != nil {
		stopCancelWatch()
		conn.Close()
		return nil, err
	}
	ch := make(chan map[string]any)
	go func() {
		defer close(ch)
		defer conn.Close()
		defer stopCancelWatch()
		scanner := bufio.NewScanner(conn)
		for scanner.Scan() {
			var event map[string]any
			if json.Unmarshal(scanner.Bytes(), &event) == nil {
				select {
				case ch <- event:
				case <-ctx.Done():
					return
				}
			}
		}
	}()
	return ch, nil
}

// PythonClient talks to the Python AgentService JSON-line endpoint.
type PythonClient struct {
	Address    string
	Capability string
}

// writeRequest serializes and signs one JSON-line RPC request.
//
// C-1-1: ``principalID`` is the sole source of truth for the
// principal identity carried in the RPC auth envelope.  Previously
// this method extracted ``principal_id`` from the payload (defaulting
// to ``"gateway"``), which caused ~15 RPC methods to lose the
// caller's identity entirely.  Now every caller must pass the
// authenticated principal explicitly; Python's
// ``GatewayRPCAuthenticator`` still verifies that, if the payload
// contains ``principal_id``, it matches the envelope value (so
// Chat / ConfirmPermission / Spawn / ApproveTask / RejectTask —
// which embed ``principal_id`` in the payload for the Python service
// layer — remain transport-bound).
func (c PythonClient) writeRequest(conn net.Conn, method string, payload any, principalID string) error {
	if len(c.Capability) < 32 {
		return fmt.Errorf("Python AgentService capability is missing or too short")
	}
	raw, err := canonicalJSON(payload)
	if err != nil {
		return err
	}
	var normalized any
	if err := json.Unmarshal(raw, &normalized); err != nil {
		return err
	}
	canonical, err := canonicalJSON(normalized)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(canonical)
	nonceBytes := make([]byte, 16)
	if _, err := rand.Read(nonceBytes); err != nil {
		return err
	}
	nonce := hex.EncodeToString(nonceBytes)
	issuedAt := time.Now().Unix()
	payloadDigest := hex.EncodeToString(digest[:])
	signed := fmt.Sprintf("%s\n%s\n%d\n%s\n%s", method, nonce, issuedAt, principalID, payloadDigest)
	methodKey := hmac.New(sha256.New, []byte(c.Capability))
	_, _ = methodKey.Write([]byte("khaos-rpc-method-v1\n" + method))
	mac := hmac.New(sha256.New, methodKey.Sum(nil))
	_, _ = mac.Write([]byte(signed))
	return json.NewEncoder(conn).Encode(map[string]any{
		"method": method, "payload": normalized,
		"auth": map[string]any{
			"nonce": nonce, "issued_at": issuedAt, "principal_id": principalID,
			"payload_digest": payloadDigest, "mac": hex.EncodeToString(mac.Sum(nil)),
		},
	})
}

func canonicalJSON(value any) ([]byte, error) {
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buffer.Bytes(), []byte("\n")), nil
}

// HandleWebhook forwards an inbound webhook to Python without interpreting it.
//
// C-1-1: ``principalID`` is ``""`` for signature-authenticated webhook
// ingress (no API-key principal in that path); Python's
// ``AgentService.HandleWebhook`` treats the empty principal as
// unauthenticated platform ingress.
func (c PythonClient) HandleWebhook(ctx context.Context, principalID string, request api.WebhookRequest) (api.WebhookResponse, error) {
	response, err := c.callMap(ctx, "AgentService.HandleWebhook", map[string]any{
		"platform": request.Platform, "channel_id": request.ChannelID,
		"headers": request.Headers, "query": request.Query,
		"body": string(request.Body),
	}, principalID)
	if err != nil {
		return api.WebhookResponse{}, err
	}
	return api.WebhookResponse{Status: stringValue(response["status"]), MessageID: stringValue(response["message_id"]), Error: stringValue(response["error"])}, nil
}

// ListChannels returns all registered channels.
func (c PythonClient) ListChannels(ctx context.Context, principalID string) ([]api.ChannelInfo, error) {
	response, err := c.callMap(ctx, "ChannelService.List", map[string]any{}, principalID)
	if err != nil {
		return nil, err
	}
	raw, err := json.Marshal(response["channels"])
	if err != nil {
		return nil, err
	}
	var channels []api.ChannelInfo
	err = json.Unmarshal(raw, &channels)
	return channels, err
}

// SetChannelEnabled changes one registered channel's enabled state.
func (c PythonClient) SetChannelEnabled(ctx context.Context, principalID string, channelID string, enabled bool) error {
	method := "ChannelService.Disable"
	if enabled {
		method = "ChannelService.Enable"
	}
	response, err := c.callMap(ctx, method, map[string]any{"channel_id": channelID}, principalID)
	if err != nil {
		return err
	}
	if ok, _ := response["ok"].(bool); !ok {
		return fmt.Errorf("channel not found: %s", channelID)
	}
	return nil
}

func stringValue(value any) string {
	text, _ := value.(string)
	return text
}

// Chat starts a chat RPC and streams events.
func (c PythonClient) Chat(ctx context.Context, req api.ChatRequest) (<-chan api.ChatEvent, error) {
	conn, err := c.dial(ctx)
	if err != nil {
		return nil, err
	}
	stopCancelWatch := closeOnContextDone(ctx, conn)
	if err := c.writeRequest(conn, "AgentService.Chat", req, req.PrincipalID); err != nil {
		stopCancelWatch()
		conn.Close()
		return nil, err
	}
	ch := make(chan api.ChatEvent)
	go func() {
		defer close(ch)
		defer conn.Close()
		defer stopCancelWatch()
		scanner := bufio.NewScanner(conn)
		for scanner.Scan() {
			var event api.ChatEvent
			if json.Unmarshal(scanner.Bytes(), &event) == nil {
				select {
				case ch <- event:
				case <-ctx.Done():
					return
				}
			}
		}
	}()
	return ch, nil
}

// ConfirmPermission forwards a permission confirmation.
func (c PythonClient) ConfirmPermission(ctx context.Context, principalID string, sessionID string, toolCallID string, bindingDigest string, approved bool, remember bool) error {
	conn, err := c.dial(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	defer closeOnContextDone(ctx, conn)()
	return c.writeRequest(conn, "AgentService.ConfirmPermission", map[string]any{
		"session_id":     sessionID,
		"principal_id":   principalID,
		"tool_call_id":   toolCallID,
		"binding_digest": bindingDigest,
		"approved":       approved,
		"remember":       remember,
	}, principalID)
}

// SwitchMode switches mode through Python.
func (c PythonClient) SwitchMode(ctx context.Context, principalID string, sessionID string, targetMode string) (string, error) {
	conn, err := c.dial(ctx)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	defer closeOnContextDone(ctx, conn)()
	if err := c.writeRequest(conn, "AgentService.SwitchMode", map[string]any{
		"session_id": sessionID, "target_mode": targetMode,
	}, principalID); err != nil {
		return "", err
	}
	var response map[string]string
	if err := json.NewDecoder(conn).Decode(&response); err != nil {
		return "", err
	}
	return response["current_mode"], nil
}

// Query queries audit records through Python.
func (c PythonClient) Query(ctx context.Context, principalID string, action, result, since, until string, limit int) ([]api.AuditEntry, error) {
	conn, err := c.dial(ctx)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	defer closeOnContextDone(ctx, conn)()
	payload := map[string]any{
		"limit": limit,
	}
	if action != "" {
		payload["action"] = action
	}
	if result != "" {
		payload["result"] = result
	}
	if since != "" {
		payload["since"] = since
	}
	if until != "" {
		payload["until"] = until
	}
	if err := c.writeRequest(conn, "AuditService.Query", payload, principalID); err != nil {
		return nil, err
	}
	var entries []api.AuditEntry
	if err := json.NewDecoder(conn).Decode(&entries); err != nil {
		return nil, err
	}
	return entries, nil
}

// Spawn starts a subagent task through Python.
func (c PythonClient) Spawn(ctx context.Context, principalID string, goal string, taskContext string, tools []string, timeout int) (map[string]any, error) {
	return c.callMap(ctx, "SubAgentService.Spawn", map[string]any{
		"principal_id": principalID,
		"goal":         goal,
		"context":      taskContext,
		"tools":        tools,
		"timeout":      timeout,
	}, principalID)
}

// CollectResults collects completed subagent results through Python.
func (c PythonClient) CollectResults(ctx context.Context, principalID string) (map[string]any, error) {
	return c.callMap(ctx, "SubAgentService.Collect", map[string]any{
		"principal_id": principalID,
	}, principalID)
}

// Status returns subagent service status through Python.
func (c PythonClient) Status(ctx context.Context, principalID string) (map[string]any, error) {
	return c.callMap(ctx, "SubAgentService.Status", map[string]any{
		"principal_id": principalID,
	}, principalID)
}

func (c PythonClient) callMap(ctx context.Context, method string, payload map[string]any, principalID string) (map[string]any, error) {
	conn, err := c.dial(ctx)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	defer closeOnContextDone(ctx, conn)()
	if err := c.writeRequest(conn, method, payload, principalID); err != nil {
		return nil, err
	}
	var response map[string]any
	if err := json.NewDecoder(conn).Decode(&response); err != nil {
		return nil, err
	}
	return response, nil
}

func (c PythonClient) callList(ctx context.Context, method string, payload map[string]any, principalID string) ([]map[string]any, error) {
	conn, err := c.dial(ctx)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	defer closeOnContextDone(ctx, conn)()
	if err := c.writeRequest(conn, method, payload, principalID); err != nil {
		return nil, err
	}
	var response []map[string]any
	if err := json.NewDecoder(conn).Decode(&response); err != nil {
		return nil, err
	}
	return response, nil
}

func (c PythonClient) dial(ctx context.Context) (net.Conn, error) {
	if !filepath.IsAbs(c.Address) {
		return nil, fmt.Errorf("Python AgentService requires an absolute Unix socket path")
	}
	conn, err := (&net.Dialer{}).DialContext(ctx, "unix", c.Address)
	if err != nil {
		return nil, err
	}
	if deadline, ok := ctx.Deadline(); ok {
		if err := conn.SetDeadline(deadline); err != nil {
			conn.Close()
			return nil, err
		}
	}
	return conn, nil
}

func closeOnContextDone(ctx context.Context, conn net.Conn) func() {
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = conn.Close()
		case <-done:
		}
	}()
	return func() { close(done) }
}
