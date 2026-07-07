package api

import (
	"bufio"
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

func newTestServer(apiKey string) (*httptest.Server, *mockAgent) {
	agent := &mockAgent{}
	handler := NewHandler(agent, NewMemoryMap(), NewMapConfig(map[string]any{"mode": "office"}), apiKey, rate.NewTokenBucket(1000, 100))
	return httptest.NewServer(handler.Routes()), agent
}

func TestChatAndStream(t *testing.T) {
	server, _ := newTestServer("")
	defer server.Close()
	body := bytes.NewBufferString(`{"session_id":"s1","message":"hello","mode":"office"}`)
	resp, err := http.Post(server.URL+"/api/chat", "application/json", body)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	stream, err := http.Get(server.URL + "/api/chat/s1/stream")
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Body.Close()
	scanner := bufio.NewScanner(stream.Body)
	var lines []string
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	joined := strings.Join(lines, "\n")
	if !strings.Contains(joined, "event: message") || !strings.Contains(joined, "event: done") {
		t.Fatalf("unexpected stream: %s", joined)
	}
}

func TestAuthRequired(t *testing.T) {
	server, _ := newTestServer("secret")
	defer server.Close()
	resp, err := http.Get(server.URL + "/api/health")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	req, _ := http.NewRequest(http.MethodGet, server.URL+"/api/health", nil)
	req.Header.Set("X-Khaos-Key", "secret")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
}

func TestConfirmAndMode(t *testing.T) {
	server, agent := newTestServer("")
	defer server.Close()
	resp, err := http.Post(server.URL+"/api/chat/s1/confirm", "application/json", bytes.NewBufferString(`{"tool_call_id":"c1","approved":true}`))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK || !agent.confirmed {
		t.Fatalf("confirm status=%d confirmed=%v", resp.StatusCode, agent.confirmed)
	}
	resp, err = http.Post(server.URL+"/api/mode", "application/json", bytes.NewBufferString(`{"session_id":"s1","target_mode":"coding"}`))
	if err != nil {
		t.Fatal(err)
	}
	var payload map[string]string
	_ = json.NewDecoder(resp.Body).Decode(&payload)
	if payload["current_mode"] != "coding" || agent.mode != "coding" {
		t.Fatalf("mode payload=%v agent=%s", payload, agent.mode)
	}
}

func TestMemoryEndpoints(t *testing.T) {
	server, _ := newTestServer("")
	defer server.Close()
	resp, err := http.Post(server.URL+"/api/memory", "application/json", bytes.NewBufferString(`{"scope":"global","key":"user","value":"Ruibang"}`))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("set status = %d", resp.StatusCode)
	}
	resp, err = http.Get(server.URL + "/api/memory?scope=global&key=user")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("get status = %d", resp.StatusCode)
	}
	req, _ := http.NewRequest(http.MethodDelete, server.URL+"/api/memory/1", nil)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("delete status = %d", resp.StatusCode)
	}
}

func TestConfigToolsSessionsHealth(t *testing.T) {
	server, _ := newTestServer("")
	defer server.Close()
	paths := []string{"/api/config", "/api/tools?mode=coding", "/api/sessions", "/api/health"}
	for _, path := range paths {
		resp, err := http.Get(server.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("%s status=%d", path, resp.StatusCode)
		}
	}
	req, _ := http.NewRequest(http.MethodPut, server.URL+"/api/config", bytes.NewBufferString(`{"mode":"coding"}`))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("config put status=%d", resp.StatusCode)
	}
}

func TestRateLimit(t *testing.T) {
	handler := NewHandler(&mockAgent{}, NewMemoryMap(), NewMapConfig(map[string]any{}), "", rate.NewTokenBucket(1, 1))
	server := httptest.NewServer(handler.Routes())
	defer server.Close()
	resp, err := http.Get(server.URL + "/api/health")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("first status=%d", resp.StatusCode)
	}
	resp, err = http.Get(server.URL + "/api/health")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("second status=%d", resp.StatusCode)
	}
}

