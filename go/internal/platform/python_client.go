package platform

import (
	"bufio"
	"context"
	"encoding/json"
	"net"

	"khaos/go/internal/api"
)

// PythonClient talks to the Python AgentService JSON-line endpoint.
type PythonClient struct {
	Address string
}

// Chat starts a chat RPC and streams events.
func (c PythonClient) Chat(ctx context.Context, req api.ChatRequest) (<-chan api.ChatEvent, error) {
	conn, err := net.Dial("tcp", c.Address)
	if err != nil {
		return nil, err
	}
	payload := map[string]any{"method": "AgentService.Chat", "payload": req}
	if err := json.NewEncoder(conn).Encode(payload); err != nil {
		conn.Close()
		return nil, err
	}
	ch := make(chan api.ChatEvent)
	go func() {
		defer close(ch)
		defer conn.Close()
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
func (c PythonClient) ConfirmPermission(ctx context.Context, sessionID string, toolCallID string, approved bool, remember bool) error {
	conn, err := net.Dial("tcp", c.Address)
	if err != nil {
		return err
	}
	defer conn.Close()
	return json.NewEncoder(conn).Encode(map[string]any{
		"method": "AgentService.ConfirmPermission",
		"payload": map[string]any{
			"session_id":   sessionID,
			"tool_call_id": toolCallID,
			"approved":     approved,
			"remember":     remember,
		},
	})
}

// SwitchMode switches mode through Python.
func (c PythonClient) SwitchMode(ctx context.Context, sessionID string, targetMode string) (string, error) {
	conn, err := net.Dial("tcp", c.Address)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	if err := json.NewEncoder(conn).Encode(map[string]any{
		"method":  "AgentService.SwitchMode",
		"payload": map[string]any{"session_id": sessionID, "target_mode": targetMode},
	}); err != nil {
		return "", err
	}
	var response map[string]string
	if err := json.NewDecoder(conn).Decode(&response); err != nil {
		return "", err
	}
	return response["current_mode"], nil
}
