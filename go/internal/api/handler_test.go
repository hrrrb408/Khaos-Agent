package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"khaos/go/internal/rate"
)

type mockAgent struct {
	confirmed bool
	mode      string
	principal string
	binding   string
}

func (m *mockAgent) Chat(ctx context.Context, req ChatRequest) (<-chan ChatEvent, error) {
	m.principal = req.PrincipalID
	ch := make(chan ChatEvent, 2)
	go func() {
		defer close(ch)
		ch <- ChatEvent{Event: "message", Data: map[string]any{"content": "hello"}}
		ch <- ChatEvent{Event: "done", Data: map[string]any{"total_tokens": 1}}
	}()
	return ch, nil
}

func (m *mockAgent) ConfirmPermission(ctx context.Context, principalID string, sessionID string, toolCallID string, bindingDigest string, approved bool, remember bool) error {
	m.confirmed = approved
	m.principal = principalID
	m.binding = bindingDigest
	return nil
}

func (m *mockAgent) SwitchMode(ctx context.Context, sessionID string, targetMode string) (string, error) {
	m.mode = targetMode
	return targetMode, nil
}

type mockSubagentClient struct {
	goal string
}

type mockChannelAgent struct {
	mockAgent
	webhook WebhookRequest
	enabled bool
}

type mockTaskClient struct{ activeOnly bool }

func (m *mockTaskClient) CreateTask(_ context.Context, goal string) (map[string]any, error) {
	return map[string]any{"id": "t1", "goal": goal}, nil
}
func (m *mockTaskClient) ListTasks(_ context.Context, active bool) ([]map[string]any, error) {
	m.activeOnly = active
	return []map[string]any{{"id": "t1"}}, nil
}
func (m *mockTaskClient) GetTask(_ context.Context, id string) (map[string]any, error) {
	if id == "missing" {
		return nil, errors.New("not found")
	}
	return map[string]any{"id": id}, nil
}
func (m *mockTaskClient) CancelTask(_ context.Context, id string) (TransitionResult, error) {
	return TransitionUpdated, nil
}
func (m *mockTaskClient) ApproveTask(_ context.Context, id string, principalID string, sessionID string, bindingDigest string) (TransitionResult, error) {
	return TransitionUpdated, nil
}
func (m *mockTaskClient) RejectTask(_ context.Context, id string, principalID string, sessionID string, bindingDigest string) (TransitionResult, error) {
	return TransitionUpdated, nil
}
func (m *mockTaskClient) TaskEvents(_ context.Context, id string) (<-chan map[string]any, error) {
	ch := make(chan map[string]any, 1)
	ch <- map[string]any{"event_id": "e1", "task_id": id, "sequence": 1, "type": "task.running", "timestamp": "now", "payload": map[string]any{}}
	close(ch)
	return ch, nil
}
func (m *mockTaskClient) TaskArtifacts(_ context.Context, id string) ([]map[string]any, error) {
	return []map[string]any{{"type": "file"}}, nil
}

func (m *mockChannelAgent) HandleWebhook(_ context.Context, request WebhookRequest) (WebhookResponse, error) {
	m.webhook = request
	return WebhookResponse{Status: "ok", MessageID: "m1"}, nil
}

func (m *mockChannelAgent) ListChannels(_ context.Context) ([]ChannelInfo, error) {
	return []ChannelInfo{{ID: "tg", Type: "telegram", Enabled: true, Healthy: true, Status: "enabled"}}, nil
}

func (m *mockChannelAgent) SetChannelEnabled(_ context.Context, _ string, enabled bool) error {
	m.enabled = enabled
	return nil
}

func (m *mockSubagentClient) Spawn(ctx context.Context, goal string, taskContext string, tools []string, timeout int) (map[string]any, error) {
	m.goal = goal
	return map[string]any{"id": "sub-1", "status": "running", "goal": goal}, nil
}

func (m *mockSubagentClient) CollectResults(ctx context.Context) (map[string]any, error) {
	return map[string]any{"results": []any{}}, nil
}

func (m *mockSubagentClient) Status(ctx context.Context) (map[string]any, error) {
	return map[string]any{"active": 0}, nil
}

func newTestHandler(apiKey string) (http.Handler, *mockAgent) {
	agent := &mockAgent{}
	handler := NewHandler(agent, NewMemoryMap(), NewMapConfig(map[string]any{"mode": "office"}), apiKey, rate.NewTokenBucket(1000, 100))
	return handler.Routes(), agent
}

func serve(handler http.Handler, method string, path string, body string, key string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, bytes.NewBufferString(body))
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if key != "" {
		req.Header.Set("X-Khaos-Key", key)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func TestChatAndStream(t *testing.T) {
	handler, _ := newTestHandler("")
	rec := serve(handler, http.MethodPost, "/api/chat", `{"session_id":"s1","message":"hello","mode":"office"}`, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	stream := serve(handler, http.MethodGet, "/api/chat/s1/stream", "", "")
	body := stream.Body.String()
	if !strings.Contains(body, "event: message") || !strings.Contains(body, "event: done") {
		t.Fatalf("unexpected stream: %s", body)
	}
}

func TestAuthRequired(t *testing.T) {
	handler, _ := newTestHandler("secret")
	if rec := serve(handler, http.MethodGet, "/api/health", "", ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d", rec.Code)
	}
	if rec := serve(handler, http.MethodGet, "/api/health", "", "secret"); rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if rec := serve(handler, http.MethodGet, "/api/health?key=secret", "", ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("query key status = %d", rec.Code)
	}
}

func TestConfirmAndMode(t *testing.T) {
	handler, agent := newTestHandler("secret")
	rec := serve(handler, http.MethodPost, "/api/chat/s1/confirm", `{"tool_call_id":"c1","binding_digest":"abc","approved":true}`, "secret")
	if rec.Code != http.StatusOK || !agent.confirmed {
		t.Fatalf("confirm status=%d confirmed=%v", rec.Code, agent.confirmed)
	}
	if !strings.HasPrefix(agent.principal, "api-key:") || agent.binding != "abc" {
		t.Fatalf("unbound confirmation principal=%q binding=%q", agent.principal, agent.binding)
	}
	rec = serve(handler, http.MethodPost, "/api/mode", `{"session_id":"s1","target_mode":"coding"}`, "secret")
	var payload map[string]string
	_ = json.NewDecoder(rec.Body).Decode(&payload)
	if payload["current_mode"] != "coding" || agent.mode != "coding" {
		t.Fatalf("mode payload=%v agent=%s", payload, agent.mode)
	}
}

func TestConfirmRequiresAuthenticatedPrincipalAndBinding(t *testing.T) {
	handler, _ := newTestHandler("")
	if rec := serve(handler, http.MethodPost, "/api/chat/s1/confirm", `{"tool_call_id":"c1","binding_digest":"abc","approved":true}`, ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated status=%d", rec.Code)
	}
	handler, _ = newTestHandler("secret")
	if rec := serve(handler, http.MethodPost, "/api/chat/s1/confirm", `{"tool_call_id":"c1","approved":true}`, "secret"); rec.Code != http.StatusBadRequest {
		t.Fatalf("missing binding status=%d", rec.Code)
	}
}

func TestMemoryEndpoints(t *testing.T) {
	handler, _ := newTestHandler("")
	if rec := serve(handler, http.MethodPost, "/api/memory", `{"scope":"global","key":"user","value":"Ruibang"}`, ""); rec.Code != http.StatusOK {
		t.Fatalf("set status = %d", rec.Code)
	}
	if rec := serve(handler, http.MethodGet, "/api/memory?scope=global&key=user", "", ""); rec.Code != http.StatusOK {
		t.Fatalf("get status = %d", rec.Code)
	}
	if rec := serve(handler, http.MethodDelete, "/api/memory/1", "", ""); rec.Code != http.StatusOK {
		t.Fatalf("delete status = %d", rec.Code)
	}
}

func TestConfigToolsSessionsHealth(t *testing.T) {
	handler, _ := newTestHandler("")
	paths := []string{"/api/config", "/api/tools?mode=coding", "/api/sessions", "/api/health"}
	for _, path := range paths {
		if rec := serve(handler, http.MethodGet, path, "", ""); rec.Code != http.StatusOK {
			t.Fatalf("%s status=%d", path, rec.Code)
		}
	}
	if rec := serve(handler, http.MethodPut, "/api/config", `{"mode":"coding"}`, ""); rec.Code != http.StatusOK {
		t.Fatalf("config put status=%d", rec.Code)
	}
}

func TestRateLimit(t *testing.T) {
	handler := NewHandler(&mockAgent{}, NewMemoryMap(), NewMapConfig(map[string]any{}), "", rate.NewTokenBucket(1, 1)).Routes()
	if rec := serve(handler, http.MethodGet, "/api/health", "", ""); rec.Code != http.StatusOK {
		t.Fatalf("first status=%d", rec.Code)
	}
	if rec := serve(handler, http.MethodGet, "/api/health", "", ""); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("second status=%d", rec.Code)
	}
}

func TestAPIKeyIsHeaderOnly(t *testing.T) {
	handler, _ := newTestHandler("gateway-key")
	if rec := serve(handler, http.MethodGet, "/api/health?key=gateway-key", "", ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("query credential status=%d", rec.Code)
	}
	if rec := serve(handler, http.MethodGet, "/api/health", "", "gateway-key"); rec.Code != http.StatusOK {
		t.Fatalf("header credential status=%d", rec.Code)
	}
}

func TestWebhookAndChannelEndpoints(t *testing.T) {
	agent := &mockChannelAgent{}
	handler := NewHandler(agent, NewMemoryMap(), NewMapConfig(nil), "gateway-key", rate.NewTokenBucket(100, 10)).Routes()
	rec := serve(handler, http.MethodPost, "/api/webhook/telegram?channel_id=tg", `{"message":{"message_id":1}}`, "")
	if rec.Code != http.StatusOK || agent.webhook.ChannelID != "tg" || agent.webhook.Platform != "telegram" {
		t.Fatalf("webhook status=%d request=%+v", rec.Code, agent.webhook)
	}
	if rec := serve(handler, http.MethodGet, "/api/channels", "", "gateway-key"); rec.Code != http.StatusOK {
		t.Fatalf("list status=%d", rec.Code)
	}
	if rec := serve(handler, http.MethodPost, "/api/channels/tg/enable", "", "gateway-key"); rec.Code != http.StatusOK || !agent.enabled {
		t.Fatalf("enable status=%d enabled=%v", rec.Code, agent.enabled)
	}
}

func TestTaskRESTAndEvents(t *testing.T) {
	tasks := &mockTaskClient{}
	handler := NewHandler(&mockAgent{}, NewMemoryMap(), NewMapConfig(nil), "", rate.NewTokenBucket(100, 10)).WithTasks(tasks).Routes()
	if rec := serve(handler, http.MethodPost, "/v1/tasks", `{"goal":"ship"}`, ""); rec.Code != http.StatusCreated {
		t.Fatalf("create=%d %s", rec.Code, rec.Body.String())
	}
	if rec := serve(handler, http.MethodPost, "/v1/tasks", `{"goal":""}`, ""); rec.Code != http.StatusBadRequest {
		t.Fatalf("empty=%d", rec.Code)
	}
	if rec := serve(handler, http.MethodGet, "/v1/tasks?active=true", "", ""); rec.Code != http.StatusOK || !tasks.activeOnly {
		t.Fatalf("list=%d active=%v", rec.Code, tasks.activeOnly)
	}
	if rec := serve(handler, http.MethodGet, "/v1/tasks/t1", "", ""); rec.Code != http.StatusOK {
		t.Fatalf("get=%d", rec.Code)
	}
	if rec := serve(handler, http.MethodPost, "/v1/tasks/t1/cancel", "", ""); rec.Code != http.StatusOK {
		t.Fatalf("cancel=%d", rec.Code)
	}
	rec := serve(handler, http.MethodGet, "/v1/tasks/t1/events", "", "")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"event_id":"e1"`) {
		t.Fatalf("events=%d %s", rec.Code, rec.Body.String())
	}
}

type mockAudit struct {
	entries  []AuditEntry
	action   string
	result   string
	limit    int
	failWith error
}

func (m *mockAudit) Query(ctx context.Context, action, result, since, until string, limit int) ([]AuditEntry, error) {
	m.action = action
	m.result = result
	m.limit = limit
	if m.failWith != nil {
		return nil, m.failWith
	}
	return m.entries, nil
}

func TestAuditEndpointReturnsEntries(t *testing.T) {
	audit := &mockAudit{entries: []AuditEntry{
		{ID: 1, Action: "write_file", Target: "/x", Result: "success"},
		{ID: 2, Action: "terminal", Target: "rm", Result: "denied"},
	}}
	handler := NewHandler(&mockAgent{}, NewMemoryMap(), NewMapConfig(map[string]any{}), "", rate.NewTokenBucket(1000, 100))
	handler = handler.WithAudit(audit)

	rec := serve(handler.Routes(), http.MethodGet, "/api/audit?result=denied&limit=5", "", "")

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if audit.result != "denied" {
		t.Fatalf("result filter not forwarded: %q", audit.result)
	}
	if audit.limit != 5 {
		t.Fatalf("limit not forwarded: %d", audit.limit)
	}
	var got []AuditEntry
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(got) != 2 || got[0].Action != "write_file" {
		t.Fatalf("unexpected entries: %+v", got)
	}
}

func TestAuditEndpointWithoutClientReturnsEmpty(t *testing.T) {
	handler := NewHandler(&mockAgent{}, NewMemoryMap(), NewMapConfig(map[string]any{}), "", rate.NewTokenBucket(1000, 100))
	// No WithAudit call -> audit client is nil.
	rec := serve(handler.Routes(), http.MethodGet, "/api/audit", "", "")

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d", rec.Code)
	}
	body := strings.TrimSpace(rec.Body.String())
	if body != "[]" {
		t.Fatalf("expected empty array, got %q", body)
	}
}

func TestAuditEndpointDefaultsLimit(t *testing.T) {
	audit := &mockAudit{}
	handler := NewHandler(&mockAgent{}, NewMemoryMap(), NewMapConfig(map[string]any{}), "", rate.NewTokenBucket(1000, 100)).WithAudit(audit)

	serve(handler.Routes(), http.MethodGet, "/api/audit", "", "")

	if audit.limit != 100 {
		t.Fatalf("default limit should be 100, got %d", audit.limit)
	}
}

func TestMetricsEndpoint(t *testing.T) {
	handler, _ := newTestHandler("")
	rec := serve(handler, http.MethodGet, "/api/metrics", "", "")

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var payload map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if _, ok := payload["total_requests"]; !ok {
		t.Fatalf("missing total_requests: %v", payload)
	}
	if _, ok := payload["requests_by_route"]; !ok {
		t.Fatalf("missing requests_by_route: %v", payload)
	}
}

func TestSubagentSpawn(t *testing.T) {
	subagents := &mockSubagentClient{}
	handler := NewHandler(&mockAgent{}, NewMemoryMap(), NewMapConfig(map[string]any{}), "", rate.NewTokenBucket(1000, 100)).WithSubagents(subagents)

	rec := serve(handler.Routes(), http.MethodPost, "/api/subagents/spawn", `{"goal":"inspect","context":"ctx","tools":["read_file"],"timeout":300}`, "")

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if subagents.goal != "inspect" {
		t.Fatalf("goal not forwarded: %q", subagents.goal)
	}
}

func TestSubagentStatusNotConfigured(t *testing.T) {
	handler, _ := newTestHandler("")
	rec := serve(handler, http.MethodGet, "/api/subagents/status", "", "")

	if rec.Code != http.StatusNotImplemented {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestNDJSONStream(t *testing.T) {
	handler, _ := newTestHandler("")
	rec := serve(handler, http.MethodPost, "/api/chat/s1/stream", `{"message":"hello","mode":"office"}`, "")

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if contentType := rec.Header().Get("Content-Type"); contentType != "application/x-ndjson" {
		t.Fatalf("content type=%q", contentType)
	}
	lines := strings.Split(strings.TrimSpace(rec.Body.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 ndjson lines, got %d: %q", len(lines), rec.Body.String())
	}
	for _, line := range lines {
		var event ChatEvent
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			t.Fatalf("invalid ndjson line %q: %v", line, err)
		}
	}
}
