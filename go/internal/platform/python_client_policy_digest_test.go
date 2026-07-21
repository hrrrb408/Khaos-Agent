package platform

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net"
	"testing"
)

// TestC_1_4_PolicyDigestInjectedIntoPayload verifies that writeRequest
// injects PythonClient.PolicyDigest into the payload before digest
// computation, so Python's dispatcher (C-1-4) can detect policy drift.
// The payload_digest must cover the injected policy_digest — Python's
// GatewayRPCAuthenticator recomputes the digest from the received
// payload and rejects mismatches.
func TestC_1_4_PolicyDigestInjectedIntoPayload(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()
	const policyDigest = "fedcba9876543210fedcba9876543210"
	client := PythonClient{
		Capability:   "cccccccccccccccccccccccccccccccccccccccccccccccc",
		PolicyDigest: policyDigest,
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
	// C-1-4: policy_digest must be present in the payload.
	if payload["policy_digest"] != policyDigest {
		t.Fatalf("payload policy_digest = %v, want %q", payload["policy_digest"], policyDigest)
	}
	// payload_digest must cover the injected policy_digest.  Recompute
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
		t.Fatalf("payload_digest mismatch: auth=%v want=%v (digest must cover injected policy_digest)",
			auth["payload_digest"], wantDigest)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

// TestC_1_4_EmptyPolicyDigestSkipsInjection verifies that an empty
// PolicyDigest (bootstrap handshake failed or skipped) does not inject
// policy_digest, maintaining backward compatibility with Python servers
// that accept empty claims.
func TestC_1_4_EmptyPolicyDigestSkipsInjection(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()
	client := PythonClient{
		Capability:   "cccccccccccccccccccccccccccccccccccccccccccccccc",
		PolicyDigest: "", // disabled
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
	if _, present := payload["policy_digest"]; present {
		t.Fatalf("payload should not contain policy_digest when PolicyDigest is empty, got %v", payload["policy_digest"])
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

// TestC_1_4_PolicyDigestNotInjectedIntoNonMapPayload verifies that
// policy_digest injection only happens for map payloads.  Non-map
// payloads (e.g. raw webhook bodies passed as arrays) skip injection
// — Python treats missing policy_digest as an empty claim, which is
// accepted for backward compatibility.
func TestC_1_4_PolicyDigestNotInjectedIntoNonMapPayload(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()
	client := PythonClient{
		Capability:   "cccccccccccccccccccccccccccccccccccccccccccccccc",
		PolicyDigest: "fedcba9876543210fedcba9876543210",
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

// TestC_1_4_PolicyDigestOverridesExistingPayloadValue verifies
// that if the payload already contains a policy_digest (e.g. from a
// legacy caller), the PythonClient.PolicyDigest overwrites it — the
// Gateway's bootstrap-sourced digest is the sole authority, not the
// caller-asserted value.  Python's drift detection then compares
// this Gateway-asserted value against
// agent._effective_policy.digest.
func TestC_1_4_PolicyDigestOverridesExistingPayloadValue(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()
	const gatewayPolicyDigest = "gateway-policy-digest-12345678901234"
	client := PythonClient{
		Capability:   "cccccccccccccccccccccccccccccccccccccccccccccccc",
		PolicyDigest: gatewayPolicyDigest,
	}
	done := make(chan error, 1)
	go func() {
		done <- client.writeRequest(clientConn, "TaskService.List", map[string]any{
			"policy_digest": "caller-asserted-should-be-overwritten",
		}, "api-key:alice")
	}()
	var request map[string]any
	if err := json.NewDecoder(serverConn).Decode(&request); err != nil {
		t.Fatal(err)
	}
	payload := request["payload"].(map[string]any)
	if payload["policy_digest"] != gatewayPolicyDigest {
		t.Fatalf("payload policy_digest = %v, want Gateway's %q (Gateway is sole authority)",
			payload["policy_digest"], gatewayPolicyDigest)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
