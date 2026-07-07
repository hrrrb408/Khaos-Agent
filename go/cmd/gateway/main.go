package main

import (
	"context"
	"flag"
	"log"
	"net/http"
	"os"
	"time"

	"khaos/go/internal/api"
	"khaos/go/internal/platform"
	"khaos/go/internal/rate"
)

type mockAgentClient struct{}

func (m mockAgentClient) Chat(ctx context.Context, req api.ChatRequest) (<-chan api.ChatEvent, error) {
	ch := make(chan api.ChatEvent, 4)
	go func() {
		defer close(ch)
		ch <- api.ChatEvent{Event: "message", Data: map[string]any{"role": "assistant", "content": "Khaos gateway mock response.", "token_count": 4}}
		ch <- api.ChatEvent{Event: "done", Data: map[string]any{"total_tokens": 4, "turns": 1, "duration_ms": 1}}
	}()
	return ch, nil
}

func (m mockAgentClient) ConfirmPermission(ctx context.Context, sessionID string, toolCallID string, approved bool, remember bool) error {
	return nil
}

func (m mockAgentClient) SwitchMode(ctx context.Context, sessionID string, targetMode string) (string, error) {
	return targetMode, nil
}

func main() {
	defaultAPIKey := os.Getenv("KHAOS_API_KEY")
	defaultPythonAgent := os.Getenv("KHAOS_PYTHON_AGENT")
	if defaultPythonAgent == "" {
		defaultPythonAgent = "127.0.0.1:50051"
	}
	addr := flag.String("addr", "127.0.0.1:8080", "listen address")
	apiKey := flag.String("api-key", defaultAPIKey, "X-Khaos-Key value")
	pythonAddr := flag.String("python-agent", defaultPythonAgent, "Python AgentService JSON-line address")
	mockAgent := flag.Bool("mock-agent", false, "use in-process mock agent")
	flag.Parse()
	var agent api.AgentClient = platform.PythonClient{Address: *pythonAddr}
	if *mockAgent {
		agent = mockAgentClient{}
	}

	handler := api.NewHandler(
		agent,
		api.NewMemoryMap(),
		api.NewMapConfig(map[string]any{"started_at": time.Now().Format(time.RFC3339)}),
		*apiKey,
		rate.NewTokenBucket(60, 10),
	)
	// When talking to a real Python agent, also forward audit queries. The mock
	// agent path leaves audit unconfigured (GET /api/audit returns []).
	if !*mockAgent {
		handler = handler.WithAudit(platform.PythonClient{Address: *pythonAddr})
	}
	log.Printf("Khaos gateway listening on %s", *addr)
	log.Fatal(http.ListenAndServe(*addr, handler.Routes()))
}
