package main

import (
	"context"
	"errors"
	"flag"
	"log"
	"net"
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

func (m mockAgentClient) ConfirmPermission(ctx context.Context, principalID string, sessionID string, toolCallID string, bindingDigest string, approved bool, remember bool) error {
	return nil
}

func (m mockAgentClient) SwitchMode(ctx context.Context, sessionID string, targetMode string) (string, error) {
	return targetMode, nil
}

func main() {
	defaultAPIKey := os.Getenv("KHAOS_API_KEY")
	defaultPythonAgent := os.Getenv("KHAOS_PYTHON_AGENT")
	if defaultPythonAgent == "" {
		defaultPythonAgent = "/tmp/khaos-agent.sock"
	}
	addr := flag.String("addr", "127.0.0.1:8080", "listen address")
	apiKey := flag.String("api-key", defaultAPIKey, "X-Khaos-Key value")
	pythonAddr := flag.String("python-agent", defaultPythonAgent, "Python AgentService Unix socket path")
	mockAgent := flag.Bool("mock-agent", false, "use in-process mock agent")
	enableSubagents := flag.Bool("subagents", false, "enable subagent proxy")
	flag.Parse()
	if err := validateListenConfig(*addr, *apiKey); err != nil {
		log.Fatal(err)
	}
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
		client := platform.PythonClient{Address: *pythonAddr}
		handler = handler.WithAudit(client)
		handler = handler.WithTasks(client)
		if *enableSubagents {
			handler = handler.WithSubagents(client)
		}
	}
	log.Printf("Khaos gateway listening on %s", *addr)
	if *enableSubagents {
		log.Printf("Subagent proxy enabled (Python agent: %s)", *pythonAddr)
	}
	server := &http.Server{
		Addr:              *addr,
		Handler:           handler.Routes(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      2 * time.Minute,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}
	log.Fatal(server.ListenAndServe())
}

func validateListenConfig(addr, apiKey string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return err
	}
	ip := net.ParseIP(host)
	isLoopback := host == "localhost" || (ip != nil && ip.IsLoopback())
	if !isLoopback && apiKey == "" {
		return errors.New("refusing non-loopback gateway listen without KHAOS_API_KEY")
	}
	return nil
}
