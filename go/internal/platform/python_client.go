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
	_ api.MemoryClient   = PythonClient{} // C-2-2 (HIGH 6): Gateway now proxies Python MemoryService.
)

// CreateTask creates a persistent coding task.
//
// C-1-1: “principalID“ is the authenticated principal from the
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
		// C-2-5: Python now returns an explicit ``status`` field for
		// ``LEASE_INVALIDATION_FAILED`` so the Go side can distinguish
		// a transient lease-hook failure (→ 503) from a genuine
		// invalid transition (→ 409).  Without this, both outcomes
		// collapsed into ``TransitionInvalid`` and the REST caller
		// could not tell whether to retry.
		if status, _ := response["status"].(string); status == string(api.TransitionLeaseInvalidationFailed) {
			return api.TransitionLeaseInvalidationFailed, nil
		}
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
//
// C-1-3: “ProjectID“ is the Gateway-level project identity
// (“sha256(realpath(project_root))[:32]“).  When non-empty it is
// injected into every RPC payload so Python's dispatcher (A-5-1b)
// can detect project drift (Gateway booted under project A routing
// to a Python server booted under project B).  Empty means the
// Gateway was not configured with a project root — Python accepts
// the empty claim for backward compatibility.
//
// C-1-4: “PolicyDigest“ is the Gateway-level policy identity
// (sha256 of the canonical EffectiveSecurityPolicy).  It is fetched
// once at startup via the Bootstrap.GetPolicyDigest RPC handshake —
// Python is the sole authority for policy_digest, Go never computes
// it independently.  When non-empty it is injected into every RPC
// payload so Python's dispatcher can detect policy drift (Gateway
// booted against a Python server with policy A, then routed to a
// Python server with policy B).  Empty means the bootstrap handshake
// failed or was skipped — Python accepts the empty claim for backward
// compatibility with older Gateways.
type PythonClient struct {
	Address      string
	Capability   string
	ProjectID    string
	PolicyDigest string
}

// writeRequest serializes and signs one JSON-line RPC request.
//
// C-1-1: “principalID“ is the sole source of truth for the
// principal identity carried in the RPC auth envelope.  Previously
// this method extracted “principal_id“ from the payload (defaulting
// to “"gateway"“), which caused ~15 RPC methods to lose the
// caller's identity entirely.  Now every caller must pass the
// authenticated principal explicitly; Python's
// “GatewayRPCAuthenticator“ still verifies that, if the payload
// contains “principal_id“, it matches the envelope value (so
// Chat / ConfirmPermission / Spawn / ApproveTask / RejectTask —
// which embed “principal_id“ in the payload for the Python service
// layer — remain transport-bound).
//
// C-1-3: “c.ProjectID“ (Gateway-level, not per-request) is injected
// into the payload before digest computation.  Python's dispatcher
// (A-5-1b) compares “payload["project_id"]“ against
// “agent._bound_project_id“; a mismatch is rejected as
// “project_drift“ (fail-closed).  An empty “ProjectID“ is
// accepted by Python (backward compat with older Gateways).  The
// injection happens before “canonicalJSON“ so “payload_digest“
// covers the injected value — Python's digest check passes.
//
// C-1-4: “c.PolicyDigest“ (Gateway-level, not per-request) is
// injected into the payload alongside “project_id“, before digest
// computation.  Python's dispatcher compares
// “payload["policy_digest"]“ against
// “agent._effective_policy.digest“; a mismatch is rejected as
// “policy_drift“ (fail-closed).  An empty “PolicyDigest“ is
// accepted by Python (backward compat with older Gateways or when
// the bootstrap handshake failed).  The injection happens before
// “canonicalJSON“ so “payload_digest“ covers the injected value.
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
	// C-1-3: inject project_id for drift detection.  project_id is
	// Gateway-level (all requests share the same project), so it
	// lives on PythonClient rather than in per-method args.  Only
	// inject when the payload is a map — streaming/webhook payloads
	// that are not maps skip injection (Python treats missing
	// project_id as an empty claim, which is accepted).
	if c.ProjectID != "" {
		if m, ok := normalized.(map[string]any); ok {
			m["project_id"] = c.ProjectID
		}
	}
	// C-1-4: inject policy_digest for drift detection — symmetric
	// to project_id injection above.  policy_digest is Gateway-level
	// (all requests share the same EffectiveSecurityPolicy), sourced
	// from the Bootstrap.GetPolicyDigest handshake at startup.  Only
	// inject when the payload is a map; non-map payloads skip
	// injection (Python treats missing policy_digest as an empty
	// claim, which is accepted).
	if c.PolicyDigest != "" {
		if m, ok := normalized.(map[string]any); ok {
			m["policy_digest"] = c.PolicyDigest
		}
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
// C-1-1: “principalID“ is “""“ for signature-authenticated webhook
// ingress (no API-key principal in that path); Python's
// “AgentService.HandleWebhook“ treats the empty principal as
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

// ListSessions proxies REST “GET /api/sessions“ to Python's
// “SessionService.List“ (C-2-3).
//
// The response is a principal-scoped list of session rows from the
// durable “sessions“ table.  Previously the Go handler served this
// from its in-memory “sessions“ + “sessionOwners“ maps, which were
// lost on restart and blind to sessions created directly against
// Python (CLI, subagents, webhooks).
func (c PythonClient) ListSessions(ctx context.Context, principalID string, limit, offset int) ([]api.SessionSummary, error) {
	response, err := c.callList(ctx, "SessionService.List", map[string]any{
		"limit":  limit,
		"offset": offset,
	}, principalID)
	if err != nil {
		return nil, err
	}
	raw, err := json.Marshal(response)
	if err != nil {
		return nil, err
	}
	var sessions []api.SessionSummary
	err = json.Unmarshal(raw, &sessions)
	return sessions, err
}

// GetSession proxies REST “GET /api/sessions/{id}“ to Python's
// “SessionService.Get“ (C-2-3).
//
// Cross-principal access is hidden by Python as
// “{"ok": false, "error": "session not found"}“ (symmetric to
// “TaskService.get“), so the Go handler can map a missing “ok“
// flag to HTTP 404 without leaking whether the session exists under
// another principal.
func (c PythonClient) GetSession(ctx context.Context, principalID string, sessionID string) (map[string]any, error) {
	return c.callMap(ctx, "SessionService.Get", map[string]any{
		"session_id": sessionID,
	}, principalID)
}

// SetChannelEnabled changes one registered channel's enabled state.
//
// C-2-4 (HIGH 4): Python now gates channel mutations on
// “channel_admins“; a non-admin caller receives
// “{"ok": false, "status": "forbidden", ...}“.  We translate that
// into :var:`api.ErrForbidden` so the REST handler can return 403
// instead of masking the authorization failure as 404.
func (c PythonClient) SetChannelEnabled(ctx context.Context, principalID string, channelID string, enabled bool) error {
	method := "ChannelService.Disable"
	if enabled {
		method = "ChannelService.Enable"
	}
	response, err := c.callMap(ctx, method, map[string]any{"channel_id": channelID}, principalID)
	if err != nil {
		return err
	}
	if status, _ := response["status"].(string); status == "forbidden" {
		msg, _ := response["error"].(string)
		if msg == "" {
			msg = "principal is not a channel admin"
		}
		return fmt.Errorf("%w: %s", api.ErrForbidden, msg)
	}
	if ok, _ := response["ok"].(bool); !ok {
		return fmt.Errorf("channel not found: %s", channelID)
	}
	return nil
}

// Get fetches one memory by scope+key from the Python MemoryService.
//
// C-2-2 (HIGH 6): the Gateway no longer keeps an in-process MemoryMap;
// every REST /api/memory call proxies to Python's per-principal
// MemoryService.  “principalID“ is the authenticated caller — Python
// scopes the read to the caller's own memories + project-shared rows.
func (c PythonClient) Get(ctx context.Context, principalID string, scope string, key string) (api.Memory, error) {
	response, err := c.callMap(ctx, "MemoryService.GetMemory", map[string]any{
		"scope": scope, "key": key,
	}, principalID)
	if err != nil {
		return api.Memory{}, err
	}
	return memoryFromMap(response), nil
}

// Set creates or updates a memory via the Python MemoryService.
func (c PythonClient) Set(ctx context.Context, principalID string, memory api.Memory) (api.Memory, error) {
	response, err := c.callMap(ctx, "MemoryService.SetMemory", map[string]any{
		"scope":      memory.Scope,
		"key":        memory.Key,
		"value":      memory.Value,
		"ttl":        memory.TTL,
		"confidence": memory.Confidence,
	}, principalID)
	if err != nil {
		return api.Memory{}, err
	}
	if ok, _ := response["ok"].(bool); !ok {
		return api.Memory{}, fmt.Errorf("MemoryService.SetMemory returned ok=false: %v", response)
	}
	// Python returns {"ok": true, "id": <int>}.  Refetch to get the
	// full record (created_at, updated_at, etc.) so the REST caller
	// sees the durable row, not just the input echo.
	id := int64FromAny(response["id"])
	if id == 0 {
		// Python didn't return a valid id — return the input memory
		// as-is (id=0 signals the caller that no durable row was
		// created).  In practice Python ``set_memory`` always returns
		// a non-zero DB id, so this branch is a defensive fallback.
		memory.ID = 0
		return memory, nil
	}
	// Refetch by (scope, key) — the MemoryService has no Get-by-id RPC.
	fetched, err := c.Get(ctx, principalID, memory.Scope, memory.Key)
	if err != nil {
		// Refetch failed; return the input with the id stamped.
		memory.ID = id
		return memory, nil
	}
	fetched.ID = id
	return fetched, nil
}

// Delete deletes a memory by id via the Python MemoryService.
//
// C-2-2: previously the Python dispatcher had no MemoryService.DeleteMemory
// route, so REST DELETE /api/memory/{id} only mutated the in-process
// MemoryMap and the durable row survived.  Python now exposes the
// DeleteMemory route and scopes deletion to “ctx.principal_id“.
func (c PythonClient) Delete(ctx context.Context, principalID string, id int64) error {
	response, err := c.callMap(ctx, "MemoryService.DeleteMemory", map[string]any{
		"memory_id": id,
	}, principalID)
	if err != nil {
		return err
	}
	if ok, _ := response["ok"].(bool); !ok {
		return fmt.Errorf("MemoryService.DeleteMemory returned ok=false: %v", response)
	}
	return nil
}

// Search performs a BM25 full-text search via the Python MemoryService.
func (c PythonClient) Search(ctx context.Context, principalID string, scope string, query string, topK int) ([]api.Memory, error) {
	response, err := c.callList(ctx, "MemoryService.SearchMemory", map[string]any{
		"query": query, "top_k": topK,
	}, principalID)
	if err != nil {
		return nil, err
	}
	results := make([]api.Memory, 0, len(response))
	for _, item := range response {
		results = append(results, memoryFromMap(item))
	}
	return results, nil
}

// memoryFromMap converts a Python MemoryService dict into an api.Memory.
// Missing fields default to zero values.  Numeric fields are coerced
// from any json.Number/float64/int payload.
func memoryFromMap(m map[string]any) api.Memory {
	return api.Memory{
		ID:         int64FromAny(m["id"]),
		Scope:      stringValue(m["scope"]),
		Key:        stringValue(m["key"]),
		Value:      stringValue(m["value"]),
		TTL:        intFromAny(m["ttl"]),
		Confidence: intFromAny(m["confidence"]),
		AccessFreq: intFromAny(m["access_freq"]),
		CreatedAt:  stringValue(m["created_at"]),
		UpdatedAt:  stringValue(m["updated_at"]),
	}
}

func int64FromAny(v any) int64 {
	switch n := v.(type) {
	case float64:
		return int64(n)
	case int64:
		return n
	case int:
		return int64(n)
	case json.Number:
		i, _ := n.Int64()
		return i
	}
	return 0
}

func intFromAny(v any) int {
	switch n := v.(type) {
	case float64:
		return int(n)
	case int64:
		return int(n)
	case int:
		return n
	case json.Number:
		i, _ := n.Int64()
		return int(i)
	}
	return 0
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

// ChatEvents replays and tails the durable Python-owned chat ledger.
func (c PythonClient) ChatEvents(ctx context.Context, principalID string, sessionID string, afterSequence uint64) (<-chan api.ChatEvent, error) {
	conn, err := c.dial(ctx)
	if err != nil {
		return nil, err
	}
	stopCancelWatch := closeOnContextDone(ctx, conn)
	if err := c.writeRequest(conn, "AgentService.ChatEvents", map[string]any{
		"session_id": sessionID, "after_sequence": afterSequence,
	}, principalID); err != nil {
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

// BootstrapPolicyDigest fetches the server-bound policy_digest via the
// Bootstrap.GetPolicyDigest RPC handshake.  Called once at Gateway
// startup to enable policy drift detection (C-1-4) on all subsequent
// RPCs.  Python is the sole authority for policy_digest — Go never
// computes it independently.  Uses an empty principal because this is
// a Gateway-level bootstrap call, not a user request.  The returned
// digest is stamped on PythonClient.PolicyDigest and injected into
// every subsequent writeRequest payload.
func (c PythonClient) BootstrapPolicyDigest(ctx context.Context) (string, error) {
	response, err := c.callMap(ctx, "Bootstrap.GetPolicyDigest", map[string]any{}, "")
	if err != nil {
		return "", err
	}
	digest, _ := response["policy_digest"].(string)
	return digest, nil
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
