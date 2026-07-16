package platform

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"testing"
)

func TestPythonClientRejectsTCPAddress(t *testing.T) {
	client := PythonClient{Address: "127.0.0.1:50051"}
	if _, err := client.dial(context.Background()); err == nil {
		t.Fatal("expected TCP-style Python RPC address to be rejected")
	}
}

func TestPythonClientSignsMethodPrincipalAndPayload(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()
	client := PythonClient{Capability: "cccccccccccccccccccccccccccccccccccccccccccccccc"}
	done := make(chan error, 1)
	go func() {
		done <- client.writeRequest(clientConn, "TaskService.Approve", map[string]any{
			"task_id": "task", "principal_id": "principal",
		})
	}()
	var request map[string]any
	if err := json.NewDecoder(serverConn).Decode(&request); err != nil {
		t.Fatal(err)
	}
	auth := request["auth"].(map[string]any)
	payload := request["payload"]
	canonical, _ := json.Marshal(payload)
	digest := sha256.Sum256(canonical)
	payloadDigest := hex.EncodeToString(digest[:])
	if auth["payload_digest"] != payloadDigest {
		t.Fatal("payload digest mismatch")
	}
	signed := fmt.Sprintf("%s\n%s\n%d\n%s\n%s", request["method"], auth["nonce"], int64(auth["issued_at"].(float64)), auth["principal_id"], payloadDigest)
	methodKey := hmac.New(sha256.New, []byte(client.Capability))
	_, _ = methodKey.Write([]byte("khaos-rpc-method-v1\nTaskService.Approve"))
	mac := hmac.New(sha256.New, methodKey.Sum(nil))
	_, _ = mac.Write([]byte(signed))
	if auth["mac"] != hex.EncodeToString(mac.Sum(nil)) {
		t.Fatal("method capability mismatch")
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestPythonClientRefusesMissingCapability(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()
	if err := (PythonClient{}).writeRequest(clientConn, "TaskService.List", map[string]any{}); err == nil {
		t.Fatal("expected missing capability to fail closed")
	}
}
