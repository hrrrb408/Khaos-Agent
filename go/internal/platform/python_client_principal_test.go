package platform

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"strings"
	"testing"

	"khaos/go/internal/api"
)

// TestC_1_1_MethodsPassPrincipalIDToWriteRequest verifies that every
// PythonClient method carries the caller-supplied principalID into
// the RPC auth envelope (regression coverage for the C-1-1 bug where
// ~15 RPC methods lost the caller's identity, defaulting to
// ``"gateway"``).
//
// The test stands up a fake Python AgentService on a Unix socket,
// calls each PythonClient method, and verifies the auth envelope's
// ``principal_id`` field matches the caller-supplied value.
func TestC_1_1_MethodsPassPrincipalIDToWriteRequest(t *testing.T) {
	const principal = "api-key:deadbeef-c-1-1"
	// macOS limits Unix socket paths to ~104 chars; t.TempDir() can
	// exceed that, so use a fixed short path under /tmp.
	sockPath := "/tmp/khaos-c-1-1-test.sock"
	defer os.Remove(sockPath)
	listener, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Skipf("cannot listen on unix socket: %v", err)
	}
	defer listener.Close()
	accepted := make(chan map[string]any, 16)
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				var request map[string]any
				if err := json.NewDecoder(conn).Decode(&request); err != nil {
					return
				}
				accepted <- request
				method, _ := request["method"].(string)
				// Each method expects a specific response shape;
				// return the minimal valid value so the client
				// call succeeds (or fails predictably) and the
				// request is captured for principal_id verification.
				switch {
				case method == "ChannelService.List":
					_, _ = conn.Write([]byte(`{"channels": []}` + "\n"))
				case method == "ChannelService.Enable",
					method == "ChannelService.Disable":
					_, _ = conn.Write([]byte(`{"ok": true}` + "\n"))
				case method == "AgentService.HandleWebhook":
					_, _ = conn.Write([]byte(`{"status": "ok"}` + "\n"))
				case method == "AuditService.Query",
					strings.Contains(method, "List"),
					strings.Contains(method, "Artifacts"),
					strings.Contains(method, "Events"):
					_, _ = conn.Write([]byte("[]\n"))
				default:
					_, _ = conn.Write([]byte("{}\n"))
				}
			}(conn)
		}
	}()

	client := PythonClient{Address: sockPath, Capability: "cccccccccccccccccccccccccccccccccccccccccccccccc"}
	ctx := context.Background()

	// Every method that previously lost the principal (default
	// ``"gateway"``) plus the methods that already had it (Spawn /
	// CollectResults / Status — verify no regression).
	cases := []struct {
		name string
		call func() error
		want string // expected auth.principal_id
	}{
		{"CreateTask", func() error { _, err := client.CreateTask(ctx, principal, "goal"); return err }, principal},
		{"ListTasks", func() error { _, err := client.ListTasks(ctx, principal, true); return err }, principal},
		{"GetTask", func() error { _, err := client.GetTask(ctx, principal, "t1"); return err }, principal},
		{"CancelTask", func() error { _, err := client.CancelTask(ctx, principal, "t1"); return err }, principal},
		{"TaskArtifacts", func() error { _, err := client.TaskArtifacts(ctx, principal, "t1"); return err }, principal},
		{"SwitchMode", func() error { _, err := client.SwitchMode(ctx, principal, "s1", "coding"); return err }, principal},
		{"Query", func() error { _, err := client.Query(ctx, principal, "", "", "", "", 10); return err }, principal},
		{"ListChannels", func() error { _, err := client.ListChannels(ctx, principal); return err }, principal},
		{"SetChannelEnabled", func() error { return client.SetChannelEnabled(ctx, principal, "tg", true) }, principal},
		// HandleWebhook passes "" because signature-authenticated
		// webhook ingress bypasses the API-key middleware (no
		// authenticated principal in that path).
		{"HandleWebhook", func() error {
			_, err := client.HandleWebhook(ctx, "", api.WebhookRequest{
				Platform: "telegram", Body: []byte("{}"),
			})
			return err
		}, ""},
		// Already had principalID pre-C-1-1 — verify no regression.
		{"Spawn", func() error { _, err := client.Spawn(ctx, principal, "g", "c", nil, 0); return err }, principal},
		{"CollectResults", func() error { _, err := client.CollectResults(ctx, principal); return err }, principal},
		{"Status", func() error { _, err := client.Status(ctx, principal); return err }, principal},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Drain any leftover requests from a previous failed
			// test case so we read the request THIS call produced.
			select {
			case <-accepted:
			default:
			}
			if err := tc.call(); err != nil {
				// Some methods (e.g. streaming) may return early
				// on EOF — that's fine, the request was sent.
				if !strings.Contains(err.Error(), "EOF") {
					t.Fatalf("call failed: %v", err)
				}
			}
			select {
			case request := <-accepted:
				auth, ok := request["auth"].(map[string]any)
				if !ok {
					t.Fatalf("missing auth envelope in request: %+v", request)
				}
				got, _ := auth["principal_id"].(string)
				if got != tc.want {
					t.Errorf("auth.principal_id = %q, want %q", got, tc.want)
				}
			default:
				t.Fatal("no request received on fake server")
			}
		})
	}
}
