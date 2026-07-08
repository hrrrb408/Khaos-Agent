package platform

import (
	"bufio"
	"context"
	"encoding/json"
	"net"

	"khaos/go/internal/api"
)

// Compile-time assertions that PythonClient satisfies the gateway interfaces.
var (
	_ api.AgentClient    = PythonClient{}
	_ api.AuditClient    = PythonClient{}
	_ api.SubagentClient = PythonClient{}
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

// Query queries audit records through Python.
func (c PythonClient) Query(ctx context.Context, action, result, since, until string, limit int) ([]api.AuditEntry, error) {
	conn, err := net.Dial("tcp", c.Address)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
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
	if err := json.NewEncoder(conn).Encode(map[string]any{
		"method":  "AuditService.Query",
		"payload": payload,
	}); err != nil {
		return nil, err
	}
	var entries []api.AuditEntry
	if err := json.NewDecoder(conn).Decode(&entries); err != nil {
		return nil, err
	}
	return entries, nil
}

// Spawn starts a subagent task through Python.
func (c PythonClient) Spawn(ctx context.Context, goal string, taskContext string, tools []string, timeout int) (map[string]any, error) {
	return c.callMap(ctx, "SubAgentService.Spawn", map[string]any{
		"goal":    goal,
		"context": taskContext,
		"tools":   tools,
		"timeout": timeout,
	})
}

// CollectResults collects completed subagent results through Python.
func (c PythonClient) CollectResults(ctx context.Context) (map[string]any, error) {
	return c.callMap(ctx, "SubAgentService.Collect", map[string]any{})
}

// Status returns subagent service status through Python.
func (c PythonClient) Status(ctx context.Context) (map[string]any, error) {
	return c.callMap(ctx, "SubAgentService.Status", map[string]any{})
}

func (c PythonClient) callMap(ctx context.Context, method string, payload map[string]any) (map[string]any, error) {
	conn, err := net.Dial("tcp", c.Address)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if err := json.NewEncoder(conn).Encode(map[string]any{
		"method":  method,
		"payload": payload,
	}); err != nil {
		return nil, err
	}
	var response map[string]any
	if err := json.NewDecoder(conn).Decode(&response); err != nil {
		return nil, err
	}
	return response, nil
}
