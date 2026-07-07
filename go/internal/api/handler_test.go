package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"khaos/go/internal/rate"
)

type mockAgent struct {
	confirmed bool
	mode      string
}

func (m *mockAgent) Chat(ctx context.Context, req ChatRequest) (<-chan ChatEvent, error) {
	ch := make(chan ChatEvent, 2)
	go func() {
		defer close(ch)
		ch <- ChatEvent{Event: "message", Data: map[string]any{"content": "hello"}}
		ch <- ChatEvent{Event: "done", Data: map[string]any{"total_tokens": 1}}
	}()
	return ch, nil
}

func (m *mockAgent) ConfirmPermission(ctx context.Context, sessionID string, toolCallID string, approved bool, remember bool) error {
	m.confirmed = approved
	return nil
}

func (m *mockAgent) SwitchMode(ctx context.Context, sessionID string, targetMode string) (string, error) {
	m.mode = targetMode
	return targetMode, nil
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
	if rec := serve(handler, http.MethodGet, "/api/health?key=secret", "", ""); rec.Code != http.StatusOK {
		t.Fatalf("query key status = %d", rec.Code)
	}
}

func TestConfirmAndMode(t *testing.T) {
	handler, agent := newTestHandler("")
	rec := serve(handler, http.MethodPost, "/api/chat/s1/confirm", `{"tool_call_id":"c1","approved":true}`, "")
	if rec.Code != http.StatusOK || !agent.confirmed {
		t.Fatalf("confirm status=%d confirmed=%v", rec.Code, agent.confirmed)
	}
	rec = serve(handler, http.MethodPost, "/api/mode", `{"session_id":"s1","target_mode":"coding"}`, "")
	var payload map[string]string
	_ = json.NewDecoder(rec.Body).Decode(&payload)
	if payload["current_mode"] != "coding" || agent.mode != "coding" {
		t.Fatalf("mode payload=%v agent=%s", payload, agent.mode)
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
