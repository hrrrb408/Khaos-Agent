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
	"time"

	"khaos/go/internal/rate"
)

const testAPIKey = "test-gateway-key"

type mockAgent struct {
	confirmed bool
	mode      string
	principal string
	binding   string
}

type blockingAgent struct{ mockAgent }

func (m *blockingAgent) Chat(ctx context.Context, req ChatRequest) (<-chan ChatEvent, error) {
	return make(chan ChatEvent), nil
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
	if apiKey == "" {
		apiKey = testAPIKey
	}
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
	} else {
		req.Header.Set("X-Khaos-Key", testAPIKey)
	}
	req.Host = "127.0.0.1:8080"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func serveUnauthenticated(handler http.Handler, method string, path string, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, bytes.NewBufferString(body))
	req.Host = "127.0.0.1:8080"
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
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
	if rec := serveUnauthenticated(handler, http.MethodGet, "/api/health", ""); rec.Code != http.StatusOK {
		t.Fatalf("anonymous health status = %d", rec.Code)
	}
	if rec := serveUnauthenticated(handler, http.MethodPost, "/api/chat", `{"message":"hello"}`); rec.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous chat status = %d", rec.Code)
	}
	if rec := serveUnauthenticated(handler, http.MethodPost, "/api/chat?key=secret", `{"message":"hello"}`); rec.Code != http.StatusUnauthorized {
		t.Fatalf("query key status = %d", rec.Code)
	}
}

func TestConfirmAndMode(t *testing.T) {
	handler, agent := newTestHandler("secret")
	if rec := serve(handler, http.MethodPost, "/api/chat", `{"session_id":"s1","message":"hello","mode":"office"}`, "secret"); rec.Code != http.StatusOK {
		t.Fatalf("chat status=%d", rec.Code)
	}
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

func TestProtocolStrictJSONAndRequestLimit(t *testing.T) {
	handler, _ := newTestHandler("")
	unknown := serve(handler, http.MethodPost, "/api/chat", `{"message":"hello","unexpected":true}`, "")
	if unknown.Code != http.StatusBadRequest {
		t.Fatalf("unknown field status=%d", unknown.Code)
	}
	multiple := serve(handler, http.MethodPost, "/api/chat", `{"message":"hello"}{"message":"again"}`, "")
	if multiple.Code != http.StatusBadRequest {
		t.Fatalf("multiple JSON status=%d", multiple.Code)
	}
	oversized := `{"message":"` + strings.Repeat("x", int(maxRequestBodyBytes)) + `"}`
	large := serve(handler, http.MethodPost, "/api/chat", oversized, "")
	if large.Code != http.StatusBadRequest {
		t.Fatalf("oversized status=%d", large.Code)
	}
	health := serve(handler, http.MethodGet, "/api/health", "", "")
	if health.Header().Get("X-Khaos-Protocol-Version") != protocolVersion {
		t.Fatalf("protocol header=%q", health.Header().Get("X-Khaos-Protocol-Version"))
	}
}

func TestAuthenticatedSessionOwnershipIsFailClosed(t *testing.T) {
	apiHandler := NewHandler(&mockAgent{}, NewMemoryMap(), NewMapConfig(nil), "secret", rate.NewTokenBucket(100, 10))
	handler := apiHandler.Routes()
	if rec := serve(handler, http.MethodPost, "/api/chat", `{"session_id":"owned","message":"hello"}`, "secret"); rec.Code != http.StatusOK {
		t.Fatalf("create=%d", rec.Code)
	}
	apiHandler.mu.Lock()
	apiHandler.sessionOwners["owned"] = "api-key:another"
	apiHandler.mu.Unlock()
	if rec := serve(handler, http.MethodGet, "/api/chat/owned/stream", "", "secret"); rec.Code != http.StatusForbidden {
		t.Fatalf("cross-principal stream=%d", rec.Code)
	}
	if rec := serve(handler, http.MethodPost, "/api/chat/owned/confirm", `{"tool_call_id":"c1","binding_digest":"abc","approved":true}`, "secret"); rec.Code != http.StatusForbidden {
		t.Fatalf("cross-principal confirm=%d", rec.Code)
	}
}

func TestStreamDisconnectPropagatesCancellation(t *testing.T) {
	apiHandler := NewHandler(&blockingAgent{}, NewMemoryMap(), NewMapConfig(nil), testAPIKey, rate.NewTokenBucket(100, 10))
	handler := apiHandler.Routes()
	if rec := serve(handler, http.MethodPost, "/api/chat", `{"session_id":"blocking","message":"hello"}`, ""); rec.Code != http.StatusOK {
		t.Fatalf("create=%d", rec.Code)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	req := httptest.NewRequest(http.MethodGet, "/api/chat/blocking/stream", nil).WithContext(ctx)
	req.Host = "127.0.0.1:8080"
	req.Header.Set("X-Khaos-Key", testAPIKey)
	rec := httptest.NewRecorder()
	done := make(chan struct{})
	go func() { handler.ServeHTTP(rec, req); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("stream did not stop after request cancellation")
	}
}

func TestConfirmRequiresAuthenticatedPrincipalAndBinding(t *testing.T) {
	handler, _ := newTestHandler("")
	if rec := serveUnauthenticated(handler, http.MethodPost, "/api/chat/s1/confirm", `{"tool_call_id":"c1","binding_digest":"abc","approved":true}`); rec.Code != http.StatusUnauthorized {
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
	handler := NewHandler(&mockAgent{}, NewMemoryMap(), NewMapConfig(map[string]any{}), testAPIKey, rate.NewTokenBucket(1, 1)).Routes()
	if rec := serve(handler, http.MethodGet, "/api/health", "", ""); rec.Code != http.StatusOK {
		t.Fatalf("first status=%d", rec.Code)
	}
	if rec := serve(handler, http.MethodGet, "/api/health", "", ""); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("second status=%d", rec.Code)
	}
}

func TestAPIKeyIsHeaderOnly(t *testing.T) {
	handler, _ := newTestHandler("gateway-key")
	if rec := serveUnauthenticated(handler, http.MethodGet, "/api/config?key=gateway-key", ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("query credential status=%d", rec.Code)
	}
	if rec := serve(handler, http.MethodGet, "/api/config", "", "gateway-key"); rec.Code != http.StatusOK {
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
	if agent.webhook.Query["channel_id"] != "tg" {
		t.Fatalf("webhook query was not preserved: %+v", agent.webhook.Query)
	}
	if rec := serveUnauthenticated(handler, http.MethodPost, "/api/webhook/telegram?channel_id=tg", `{"message":{"message_id":2}}`); rec.Code != http.StatusOK {
		t.Fatalf("signed platform ingress should reach Python verifier: status=%d", rec.Code)
	}
	if rec := serveUnauthenticated(handler, http.MethodPost, "/api/webhook/generic?channel_id=generic", `{"message":"run"}`); rec.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous generic webhook status=%d", rec.Code)
	}
	if rec := serveUnauthenticated(handler, http.MethodPost, "/api/webhook/unknown?channel_id=unknown", `{}`); rec.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous unknown webhook status=%d", rec.Code)
	}
	if rec := serve(handler, http.MethodPost, "/api/webhook/generic?channel_id=generic", `{"message":"run"}`, "gateway-key"); rec.Code != http.StatusOK {
		t.Fatalf("authenticated generic webhook status=%d", rec.Code)
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
	handler := NewHandler(&mockAgent{}, NewMemoryMap(), NewMapConfig(nil), testAPIKey, rate.NewTokenBucket(100, 10)).WithTasks(tasks).Routes()
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

func TestTaskEventReplayCursorAndOwnership(t *testing.T) {
	tasks := &mockTaskClient{}
	apiHandler := NewHandler(&mockAgent{}, NewMemoryMap(), NewMapConfig(nil), "secret", rate.NewTokenBucket(100, 10)).WithTasks(tasks)
	handler := apiHandler.Routes()
	if rec := serve(handler, http.MethodPost, "/v1/tasks", `{"goal":"ship"}`, "secret"); rec.Code != http.StatusCreated {
		t.Fatalf("create=%d %s", rec.Code, rec.Body.String())
	}
	req := httptest.NewRequest(http.MethodGet, "/v1/tasks/t1/events", nil)
	req.Host = "127.0.0.1:8080"
	req.Header.Set("X-Khaos-Key", "secret")
	req.Header.Set("Last-Event-ID", "1")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || strings.Contains(rec.Body.String(), `"sequence":1`) {
		t.Fatalf("replay cursor status=%d body=%s", rec.Code, rec.Body.String())
	}
	apiHandler.mu.Lock()
	apiHandler.taskOwners["t1"] = "api-key:another"
	apiHandler.mu.Unlock()
	if rec := serve(handler, http.MethodGet, "/v1/tasks/t1", "", "secret"); rec.Code != http.StatusForbidden {
		t.Fatalf("cross-principal task=%d", rec.Code)
	}
}

func TestGatewayFailsClosedWithoutConfiguredAuthentication(t *testing.T) {
	handler := NewHandler(&mockAgent{}, NewMemoryMap(), NewMapConfig(nil), "", rate.NewTokenBucket(100, 10)).Routes()
	if rec := serveUnauthenticated(handler, http.MethodGet, "/api/health", ""); rec.Code != http.StatusOK {
		t.Fatalf("health status=%d", rec.Code)
	}
	if rec := serveUnauthenticated(handler, http.MethodPost, "/api/chat", `{"message":"drive-by"}`); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("empty-auth chat status=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestOriginAllowlistAndDNSRebindingDefense(t *testing.T) {
	handler := NewHandler(&mockAgent{}, NewMemoryMap(), NewMapConfig(nil), testAPIKey, rate.NewTokenBucket(100, 10)).
		WithAllowedOrigins("http://127.0.0.1:3000").Routes()

	malicious := httptest.NewRequest(http.MethodPost, "/api/chat/new/stream", strings.NewReader(`{"message":"steal files"}`))
	malicious.Host = "127.0.0.1:8080"
	malicious.Header.Set("Origin", "https://evil.example")
	malicious.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, malicious)
	if rec.Code != http.StatusForbidden || rec.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Fatalf("malicious origin status=%d cors=%q", rec.Code, rec.Header().Get("Access-Control-Allow-Origin"))
	}

	preflight := httptest.NewRequest(http.MethodOptions, "/api/chat", nil)
	preflight.Host = "127.0.0.1:8080"
	preflight.Header.Set("Origin", "http://127.0.0.1:3000")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, preflight)
	if rec.Code != http.StatusNoContent || rec.Header().Get("Access-Control-Allow-Origin") != "http://127.0.0.1:3000" {
		t.Fatalf("allowlisted preflight status=%d cors=%q", rec.Code, rec.Header().Get("Access-Control-Allow-Origin"))
	}

	rebinding := httptest.NewRequest(http.MethodGet, "/api/health", nil)
	rebinding.Host = "attacker.example"
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, rebinding)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("DNS rebinding Host status=%d", rec.Code)
	}

	defaultHandler := NewHandler(&mockAgent{}, NewMemoryMap(), NewMapConfig(nil), testAPIKey, rate.NewTokenBucket(100, 10)).Routes()
	plain := serve(defaultHandler, http.MethodGet, "/api/health", "", testAPIKey)
	if plain.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Fatalf("default CORS header=%q", plain.Header().Get("Access-Control-Allow-Origin"))
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
	handler := NewHandler(&mockAgent{}, NewMemoryMap(), NewMapConfig(map[string]any{}), testAPIKey, rate.NewTokenBucket(1000, 100))
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
	handler := NewHandler(&mockAgent{}, NewMemoryMap(), NewMapConfig(map[string]any{}), testAPIKey, rate.NewTokenBucket(1000, 100))
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
	handler := NewHandler(&mockAgent{}, NewMemoryMap(), NewMapConfig(map[string]any{}), testAPIKey, rate.NewTokenBucket(1000, 100)).WithAudit(audit)

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
	handler := NewHandler(&mockAgent{}, NewMemoryMap(), NewMapConfig(map[string]any{}), testAPIKey, rate.NewTokenBucket(1000, 100)).WithSubagents(subagents)

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
