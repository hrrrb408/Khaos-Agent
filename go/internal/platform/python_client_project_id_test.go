package platform

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net"
	"testing"
)

// TestC_1_3_ProjectIDInjectedIntoPayload verifies that writeRequest
// injects PythonClient.ProjectID into the payload before digest
// computation, so Python's dispatcher (A-5-1b) can detect project
// drift.  The payload_digest must cover the injected project_id —
// Python's GatewayRPCAuthenticator recomputes the digest from the
// received payload and rejects mismatches.
func TestC_1_3_ProjectIDInjectedIntoPayload(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()
	const projectID = "abcdef0123456789abcdef0123456789"
	client := PythonClient{
		Capability: "cccccccccccccccccccccccccccccccccccccccccccccccc",
		ProjectID:  projectID,
	}
	done := make(chan error, 1)
	go func() {
		done <- client.writeRequest(clientConn, "TaskService.List", map[string]any{
			"active_only": true,
		}, "api-key:alice")
	}()
	var request map[string]any
	if err := json.NewDecoder(serverConn).Decode(&request); err != nil {
		t.Fatal(err)
	}
	payload := request["payload"].(map[string]any)
	// C-1-3: project_id must be present in the payload.
	if payload["project_id"] != projectID {
		t.Fatalf("payload project_id = %v, want %q", payload["project_id"], projectID)
	}
	// payload_digest must cover the injected project_id.  Recompute
	// the canonical JSON digest from the received payload and verify
	// it matches the auth.payload_digest — this proves the digest
	// was computed AFTER injection, not before.
	canonical, err := canonicalJSON(payload)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(canonical)
	wantDigest := hex.EncodeToString(digest[:])
	auth := request["auth"].(map[string]any)
	if auth["payload_digest"] != wantDigest {
		t.Fatalf("payload_digest mismatch: auth=%v want=%v (digest must cover injected project_id)",
			auth["payload_digest"], wantDigest)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

// TestC_1_3_EmptyProjectIDSkipsInjection verifies that an empty
// ProjectID (Gateway not configured with --project-root) does not
// inject project_id, maintaining backward compatibility with Python
// servers that accept empty claims.
func TestC_1_3_EmptyProjectIDSkipsInjection(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()
	client := PythonClient{
		Capability: "cccccccccccccccccccccccccccccccccccccccccccccccc",
		ProjectID:  "", // disabled
	}
	done := make(chan error, 1)
	go func() {
		done <- client.writeRequest(clientConn, "TaskService.List", map[string]any{
			"active_only": true,
		}, "api-key:alice")
	}()
	var request map[string]any
	if err := json.NewDecoder(serverConn).Decode(&request); err != nil {
		t.Fatal(err)
	}
	payload := request["payload"].(map[string]any)
	if _, present := payload["project_id"]; present {
		t.Fatalf("payload should not contain project_id when ProjectID is empty, got %v", payload["project_id"])
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

// TestC_1_3_ProjectIDNotInjectedIntoNonMapPayload verifies that
// project_id injection only happens for map payloads.  Non-map
// payloads (e.g. raw webhook bodies passed as arrays) skip injection
// — Python treats missing project_id as an empty claim, which is
// accepted for backward compatibility.
func TestC_1_3_ProjectIDNotInjectedIntoNonMapPayload(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()
	client := PythonClient{
		Capability: "cccccccccccccccccccccccccccccccccccccccccccccccc",
		ProjectID:  "abcdef0123456789abcdef0123456789",
	}
	done := make(chan error, 1)
	go func() {
		// raw JSON array payload (non-map)
		done <- client.writeRequest(clientConn, "ChannelService.Webhook", []any{"a", "b"}, "api-key:alice")
	}()
	var request map[string]any
	if err := json.NewDecoder(serverConn).Decode(&request); err != nil {
		t.Fatal(err)
	}
	payload := request["payload"]
	arr, ok := payload.([]any)
	if !ok {
		t.Fatalf("expected array payload, got %T", payload)
	}
	if len(arr) != 2 {
		t.Fatalf("array payload mutated: %v", arr)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

// TestC_1_3_ProjectIDOverridesExistingPayloadValue verifies
// that if the payload already contains a project_id (e.g. from a
// legacy caller), the PythonClient.ProjectID overwrites it — the
// Gateway's configured project is the sole authority, not the
// caller-asserted value.  Python's drift detection then compares
// this Gateway-asserted value against agent._bound_project_id.
func TestC_1_3_ProjectIDOverridesExistingPayloadValue(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()
	const gatewayProjectID = "gateway-project-id-12345678901234"
	client := PythonClient{
		Capability: "cccccccccccccccccccccccccccccccccccccccccccccccc",
		ProjectID:  gatewayProjectID,
	}
	done := make(chan error, 1)
	go func() {
		done <- client.writeRequest(clientConn, "TaskService.List", map[string]any{
			"project_id": "caller-asserted-should-be-overwritten",
		}, "api-key:alice")
	}()
	var request map[string]any
	if err := json.NewDecoder(serverConn).Decode(&request); err != nil {
		t.Fatal(err)
	}
	payload := request["payload"].(map[string]any)
	if payload["project_id"] != gatewayProjectID {
		t.Fatalf("payload project_id = %v, want Gateway's %q (Gateway is sole authority)",
			payload["project_id"], gatewayProjectID)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
