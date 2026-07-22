package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
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

func (m *mockAgent) SwitchMode(ctx context.Context, principalID string, sessionID string, targetMode string) (string, error) {
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

func (m *mockTaskClient) CreateTask(_ context.Context, principalID string, goal string) (map[string]any, error) {
	return map[string]any{"id": "t1", "goal": goal}, nil
}
func (m *mockTaskClient) ListTasks(_ context.Context, principalID string, active bool) ([]map[string]any, error) {
	m.activeOnly = active
	return []map[string]any{{"id": "t1"}}, nil
}

func (m *mockTaskClient) GetTask(_ context.Context, principalID string, id string) (map[string]any, error) {
	if id == "missing" {
		return nil, errors.New("not found")
	}
	return map[string]any{"id": id}, nil
}

func (m *mockTaskClient) CancelTask(_ context.Context, principalID string, id string) (TransitionResult, error) {
	return TransitionUpdated, nil
}
func (m *mockTaskClient) ApproveTask(_ context.Context, id string, principalID string, sessionID string, bindingDigest string) (TransitionResult, error) {
	return TransitionUpdated, nil
}
func (m *mockTaskClient) RejectTask(_ context.Context, id string, principalID string, sessionID string, bindingDigest string) (TransitionResult, error) {
	return TransitionUpdated, nil
}
func (m *mockTaskClient) TaskEvents(_ context.Context, principalID string, id string) (<-chan map[string]any, error) {
	ch := make(chan map[string]any, 1)
	ch <- map[string]any{"event_id": "e1", "task_id": id, "sequence": 1, "type": "task.running", "timestamp": "now", "payload": map[string]any{}}
	close(ch)
	return ch, nil
}

func (m *mockTaskClient) TaskArtifacts(_ context.Context, principalID string, id string) ([]map[string]any, error) {
	return []map[string]any{{"type": "file"}}, nil
}

func (m *mockChannelAgent) HandleWebhook(_ context.Context, principalID string, request WebhookRequest) (WebhookResponse, error) {
	m.webhook = request
	return WebhookResponse{Status: "ok", MessageID: "m1"}, nil
}

func (m *mockChannelAgent) ListChannels(_ context.Context, principalID string) ([]ChannelInfo, error) {
	return []ChannelInfo{{ID: "tg", Type: "telegram", Enabled: true, Healthy: true, Status: "enabled"}}, nil
}

func (m *mockChannelAgent) SetChannelEnabled(_ context.Context, principalID string, _ string, enabled bool) error {
	m.enabled = enabled
	return nil
}

func (m *mockSubagentClient) Spawn(ctx context.Context, principalID string, goal string, taskContext string, tools []string, timeout int) (map[string]any, error) {
	m.goal = goal
	return map[string]any{"id": "sub-1", "status": "running", "goal": goal, "principal_id": principalID}, nil
}

func (m *mockSubagentClient) CollectResults(ctx context.Context, principalID string) (map[string]any, error) {
	return map[string]any{"results": []any{}, "principal_id": principalID}, nil
}

func (m *mockSubagentClient) Status(ctx context.Context, principalID string) (map[string]any, error) {
	return map[string]any{"active": 0, "principal_id": principalID}, nil
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
	// C-2-3: simulate a cross-principal collision by re-stamping the
	// in-memory session's PrincipalID to another principal.  The
	// deleted ``sessionOwners`` map would have done the same; now the
	// ownership check reads from ``sessions[id].PrincipalID``.
	apiHandler.mu.Lock()
	session := apiHandler.sessions["owned"]
	session.PrincipalID = "api-key:another"
	apiHandler.sessions["owned"] = session
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
	// C-2-3: ``/api/sessions`` is no longer in this list because it
	// now proxies to Python's SessionService and returns 503 when no
	// session client is wired (verified separately by
	// TestC_2_3_SessionsEndpointsProxyToPython).  The other endpoints
	// remain in-process Go-only.
	paths := []string{"/api/config", "/api/tools?mode=coding", "/api/health"}
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

func TestAnonymousWebhookCannotExhaustAuthenticatedOrHealthBuckets(t *testing.T) {
	agent := &mockChannelAgent{}
	handler := NewHandler(
		agent,
		NewMemoryMap(),
		NewMapConfig(map[string]any{}),
		testAPIKey,
		rate.NewTokenBucket(1, 1),
	).Routes()

	first := serveUnauthenticated(
		handler, http.MethodPost, "/api/webhook/slack?channel_id=slack-a", `{}`,
	)
	if first.Code != http.StatusOK {
		t.Fatalf("first webhook status=%d", first.Code)
	}
	second := serveUnauthenticated(
		handler, http.MethodPost, "/api/webhook/slack?channel_id=slack-a", `{}`,
	)
	if second.Code != http.StatusTooManyRequests {
		t.Fatalf("second webhook status=%d", second.Code)
	}
	if rec := serve(handler, http.MethodGet, "/api/config", "", testAPIKey); rec.Code != http.StatusOK {
		t.Fatalf("authenticated API bucket was exhausted by webhook: %d", rec.Code)
	}
	if rec := serveUnauthenticated(handler, http.MethodGet, "/api/health", ""); rec.Code != http.StatusOK {
		t.Fatalf("health bucket was exhausted by webhook: %d", rec.Code)
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

// TestC_2_4_ChannelEnableMapsForbiddenTo403 verifies the C-2-4 fix:
// when the Python service rejects a channel mutation with
// ``status: "forbidden"``, the Go handler MUST return 403 (not 404
// as it did pre-C-2-4), and an unauthenticated request MUST return
// 401 (fail-closed, previously the empty principal was silently
// forwarded to Python).
func TestC_2_4_ChannelEnableMapsForbiddenTo403(t *testing.T) {
	// mockForbiddenChannelAgent returns ErrForbidden for enable/disable,
	// simulating Python's ``{"ok": false, "status": "forbidden"}``.
	agent := &mockForbiddenChannelAgent{}
	handler := NewHandler(agent, NewMemoryMap(), NewMapConfig(nil), testAPIKey, rate.NewTokenBucket(100, 10)).Routes()

	// C-2-4: unauthenticated request → 401 (fail-closed).  Pre-C-2-4
	// the handler used ``principalID, _ := ...`` and forwarded an
	// empty string to Python, which then had no caller identity to
	// admin-check.
	rec := serveUnauthenticated(handler, http.MethodPost, "/api/channels/tg/enable", "")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated enable status=%d, want 401 (fail-closed)", rec.Code)
	}

	// C-2-4: Python returns forbidden → Go wraps as ErrForbidden →
	// handler maps to 403 (not 404 as pre-C-2-4).
	rec = serve(handler, http.MethodPost, "/api/channels/tg/disable", "", testAPIKey)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("forbidden disable status=%d, want 403 (not 404)", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "admin") {
		t.Fatalf("forbidden body should mention admin, got: %s", rec.Body.String())
	}
}

// mockForbiddenChannelAgent returns ErrForbidden for SetChannelEnabled.
type mockForbiddenChannelAgent struct{ mockChannelAgent }

func (m *mockForbiddenChannelAgent) SetChannelEnabled(_ context.Context, _ string, _ string, _ bool) error {
	return fmt.Errorf("%w: principal is not a channel admin", ErrForbidden)
}

// TestC_2_5_CancelMapsLeaseInvalidationFailedTo503 verifies the C-2-5
// fix: when the Python TaskService returns
// ``{"ok": false, "status": "lease_invalidation_failed"}``, the Go
// handler MUST return HTTP 503 (transient infrastructure failure —
// retry) rather than the pre-C-2-5 behaviour of HTTP 200 (silently
// swallowed as success by Python) or HTTP 409 (collapsed into
// ``TransitionInvalid`` by ``taskAction``).
//
// The 503 signals to the REST caller that the task is still active
// and the cancel can be retried (Batch 2.6 §4 fail-closed).
func TestC_2_5_CancelMapsLeaseInvalidationFailedTo503(t *testing.T) {
	tasks := &mockLeaseInvalidationTaskClient{}
	handler := NewHandler(&mockAgent{}, NewMemoryMap(), NewMapConfig(nil), testAPIKey, rate.NewTokenBucket(100, 10)).WithTasks(tasks).Routes()

	rec := serve(handler, http.MethodPost, "/v1/tasks/t1/cancel", "", testAPIKey)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("lease invalidation cancel status=%d, want 503 (not 200 or 409): %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "lease") {
		t.Fatalf("503 body should mention lease, got: %s", rec.Body.String())
	}
}

// mockLeaseInvalidationTaskClient returns
// TransitionLeaseInvalidationFailed for CancelTask, simulating
// Python's ``{"ok": false, "status": "lease_invalidation_failed"}``.
type mockLeaseInvalidationTaskClient struct{ mockTaskClient }

func (m *mockLeaseInvalidationTaskClient) CancelTask(_ context.Context, _ string, _ string) (TransitionResult, error) {
	return TransitionLeaseInvalidationFailed, nil
}

// --- C-2-3: REST /api/sessions proxies to Python SessionService ---

// mockSessionClient implements SessionClient for the C-2-3 acceptance
// tests.  It returns a deterministic list for one principal and a
// not-found response for unknown sessions / cross-principal callers.
type mockSessionClient struct {
	listErr      error
	getResponse  map[string]any
	getErr       error
	listCalled   bool
	listPrincipal string
}

func (m *mockSessionClient) ListSessions(_ context.Context, principalID string, _, _ int) ([]SessionSummary, error) {
	m.listCalled = true
	m.listPrincipal = principalID
	if m.listErr != nil {
		return nil, m.listErr
	}
	return []SessionSummary{
		{ID: "s1", Mode: "office", CreatedAt: "2026-07-22T00:00:00Z", MessageCount: 2, Preview: "hello"},
	}, nil
}

func (m *mockSessionClient) GetSession(_ context.Context, _ string, _ string) (map[string]any, error) {
	if m.getErr != nil {
		return nil, m.getErr
	}
	if m.getResponse == nil {
		return map[string]any{"ok": false, "error": "session not found"}, nil
	}
	return m.getResponse, nil
}

// TestC_2_3_SessionsEndpointsProxyToPython verifies the C-2-3 fix:
// GET /api/sessions and GET /api/sessions/{id} now proxy to Python's
// SessionService (via the SessionClient interface) instead of reading
// the Go in-memory ``sessions`` + ``sessionOwners`` maps.
//
// Coverage:
//   - unauthenticated request → 401 (fail-closed)
//   - no session client wired → 503 (graceful degradation, not a 5xx
//     crash or empty 200 that would mislead the caller)
//   - authenticated list → 200 + the principal-scoped list from the
//     mock, with the caller's principal forwarded to the client
//   - session detail not found → 404 (cross-principal hidden as 404)
//   - session detail found → 200 + the service response
func TestC_2_3_SessionsEndpointsProxyToPython(t *testing.T) {
	// 1. No session client wired → 503.
	bare := NewHandler(&mockAgent{}, NewMemoryMap(), NewMapConfig(nil), testAPIKey, rate.NewTokenBucket(100, 10)).Routes()
	if rec := serve(bare, http.MethodGet, "/api/sessions", "", testAPIKey); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("no-client list status=%d, want 503", rec.Code)
	}
	if rec := serve(bare, http.MethodGet, "/api/sessions/s1", "", testAPIKey); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("no-client detail status=%d, want 503", rec.Code)
	}

	// 2. Unauthenticated → 401.
	mock := &mockSessionClient{}
	authed := NewHandler(&mockAgent{}, NewMemoryMap(), NewMapConfig(nil), testAPIKey, rate.NewTokenBucket(100, 10)).WithSessions(mock).Routes()
	if rec := serveUnauthenticated(authed, http.MethodGet, "/api/sessions", ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated list status=%d, want 401", rec.Code)
	}
	if rec := serveUnauthenticated(authed, http.MethodGet, "/api/sessions/s1", ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated detail status=%d, want 401", rec.Code)
	}

	// 3. Authenticated list → 200 + principal forwarded.
	listRec := serve(authed, http.MethodGet, "/api/sessions", "", testAPIKey)
	if listRec.Code != http.StatusOK {
		t.Fatalf("authenticated list status=%d, want 200: %s", listRec.Code, listRec.Body.String())
	}
	if !mock.listCalled {
		t.Fatal("ListSessions was not called for /api/sessions")
	}
	if !strings.HasPrefix(mock.listPrincipal, "api-key:") {
		t.Fatalf("principal not forwarded to ListSessions: %q", mock.listPrincipal)
	}
	if !strings.Contains(listRec.Body.String(), "s1") {
		t.Fatalf("list body should contain s1, got: %s", listRec.Body.String())
	}

	// 4. Detail not found → 404.
	notFoundMock := &mockSessionClient{getResponse: nil} // returns ok:false
	notFoundHandler := NewHandler(&mockAgent{}, NewMemoryMap(), NewMapConfig(nil), testAPIKey, rate.NewTokenBucket(100, 10)).WithSessions(notFoundMock).Routes()
	if rec := serve(notFoundHandler, http.MethodGet, "/api/sessions/unknown", "", testAPIKey); rec.Code != http.StatusNotFound {
		t.Fatalf("not-found detail status=%d, want 404", rec.Code)
	}

	// 5. Detail found → 200 + service response.
	foundMock := &mockSessionClient{getResponse: map[string]any{
		"ok": true, "session_id": "s1",
		"session": map[string]any{"id": "s1", "mode": "office"},
		"messages": []any{},
	}}
	foundHandler := NewHandler(&mockAgent{}, NewMemoryMap(), NewMapConfig(nil), testAPIKey, rate.NewTokenBucket(100, 10)).WithSessions(foundMock).Routes()
	foundRec := serve(foundHandler, http.MethodGet, "/api/sessions/s1", "", testAPIKey)
	if foundRec.Code != http.StatusOK {
		t.Fatalf("found detail status=%d, want 200: %s", foundRec.Code, foundRec.Body.String())
	}
	if !strings.Contains(foundRec.Body.String(), "s1") {
		t.Fatalf("detail body should contain s1, got: %s", foundRec.Body.String())
	}
}

// TestC_2_3_SessionsEndpointBadGatewayOnUpstreamError verifies that
// when the SessionClient returns an error (e.g. Python unreachable),
// the handler maps it to 502 (not 200 with an empty body that would
// mislead the caller into thinking there are no sessions).
func TestC_2_3_SessionsEndpointBadGatewayOnUpstreamError(t *testing.T) {
	mock := &mockSessionClient{listErr: errors.New("python unreachable")}
	handler := NewHandler(&mockAgent{}, NewMemoryMap(), NewMapConfig(nil), testAPIKey, rate.NewTokenBucket(100, 10)).WithSessions(mock).Routes()
	if rec := serve(handler, http.MethodGet, "/api/sessions", "", testAPIKey); rec.Code != http.StatusBadGateway {
		t.Fatalf("upstream-error list status=%d, want 502", rec.Code)
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
	// C-1-2: Go no longer maintains an in-memory taskOwners map.
	// Cross-principal task access is enforced durably by Python's
	// TaskService (ctx.principal_id scoping hides foreign tasks as
	// "not found").  The Go layer only checks authentication — any
	// authenticated principal can reach the Python service, which
	// then scopes the response.  Verify the Go layer no longer 403s
	// on cross-principal access (the mock returns the task regardless
	// of principal; real Python would return "not found").
	if rec := serve(handler, http.MethodGet, "/v1/tasks/t1", "", "secret"); rec.Code != http.StatusOK {
		t.Fatalf("post-C-1-2 task access=%d (Go should not 403; Python scopes)", rec.Code)
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

func (m *mockAudit) Query(ctx context.Context, principalID string, action, result, since, until string, limit int) ([]AuditEntry, error) {
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
