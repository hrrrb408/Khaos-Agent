package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"khaos/go/internal/platform"
)

func TestValidateTLSConfig(t *testing.T) {
	for _, tc := range []struct {
		name, addr, cert, key string
		wantErr               bool
	}{
		{"loopback http", "127.0.0.1:8080", "", "", false},
		{"ipv6 loopback http", "[::1]:8080", "", "", false},
		{"public without tls", "0.0.0.0:8080", "", "", true},
		{"public tls", "0.0.0.0:8443", "cert.pem", "key.pem", false},
		{"partial tls", "127.0.0.1:8080", "cert.pem", "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := validateTLSConfig(tc.addr, tc.cert, tc.key)
			if (err != nil) != tc.wantErr {
				t.Fatalf("validateTLSConfig() error=%v wantErr=%v", err, tc.wantErr)
			}
		})
	}
}

func TestIsContainerSecretPath(t *testing.T) {
	for _, tc := range []struct {
		name string
		path string
		want bool
	}{
		{"direct secret", "/run/secrets/gateway-api-key", true},
		{"secret root", "/run/secrets", false},
		{"nested path", "/run/secrets/nested/gateway-api-key", false},
		{"path traversal", "/run/secrets/../gateway-api-key", false},
		{"lookalike root", "/run/secrets-extra/gateway-api-key", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := isContainerSecretPath(tc.path); got != tc.want {
				t.Fatalf("isContainerSecretPath(%q) = %v, want %v", tc.path, got, tc.want)
			}
		})
	}
}

func TestReadProtectedTokenContainerSecretAllowsReadOnlyGroupMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "gateway-api-key")
	if err := os.WriteFile(path, []byte("01234567890123456789012345678901\n"), 0o440); err != nil {
		t.Fatal(err)
	}
	if _, err := readProtectedToken(path, false); err == nil {
		t.Fatal("host token unexpectedly accepted group-readable permissions")
	}
	key, err := readProtectedToken(path, true)
	if err != nil {
		t.Fatalf("container secret token rejected: %v", err)
	}
	if key != "01234567890123456789012345678901" {
		t.Fatalf("key = %q, want trimmed secret", key)
	}
}

func TestProtectedFileModeForContainerSecretRejectsWritesOnly(t *testing.T) {
	for _, tc := range []struct {
		name string
		path string
		mode os.FileMode
		want bool
	}{
		{"host strict", "/tmp/tls-key.pem", 0o440, true},
		{"container read-only group", "/run/secrets/khaos_tls_key", 0o440, false},
		{"container read-only other", "/run/secrets/khaos_tls_key", 0o444, false},
		{"container group-write", "/run/secrets/khaos_tls_key", 0o460, true},
		{"container other-write", "/run/secrets/khaos_tls_key", 0o402, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := protectedFileModeUnsafe(tc.path, tc.mode); got != tc.want {
				t.Fatalf("protectedFileModeUnsafe(%q, %o) = %v, want %v", tc.path, tc.mode, got, tc.want)
			}
		})
	}
}

// TestC_2_1_ResolvePythonClient_RejectsEmptyProjectRoot verifies that
// production mode is fail-closed on empty --project-root.  C-2-1
// CRITICAL fix: drift detection cannot be silently disabled.
func TestC_2_1_ResolvePythonClient_RejectsEmptyProjectRoot(t *testing.T) {
	initial := platform.PythonClient{Address: "unused", Capability: "cap"}
	_, err := resolvePythonClient(initial, "", func(ctx context.Context) (string, error) {
		t.Fatal("bootstrap should not be called when project-root is empty")
		return "", nil
	})
	if err == nil {
		t.Fatal("expected error for empty project-root, got nil")
	}
	if !strings.Contains(err.Error(), "project-root is required") {
		t.Fatalf("expected 'project-root is required' error, got: %v", err)
	}
}

// TestC_2_1_ResolvePythonClient_RejectsWhitespaceProjectRoot verifies
// that whitespace-only project-root is also rejected.
func TestC_2_1_ResolvePythonClient_RejectsWhitespaceProjectRoot(t *testing.T) {
	initial := platform.PythonClient{Address: "unused", Capability: "cap"}
	_, err := resolvePythonClient(initial, "   \t  ", func(ctx context.Context) (string, error) {
		t.Fatal("bootstrap should not be called for whitespace project-root")
		return "", nil
	})
	if err == nil {
		t.Fatal("expected error for whitespace project-root, got nil")
	}
}

// TestC_2_1_ResolvePythonClient_RejectsBootstrapFailure verifies that
// policy_digest bootstrap failure rejects startup.  C-2-1 CRITICAL fix:
// the Python agent must be running before the gateway starts.
func TestC_2_1_ResolvePythonClient_RejectsBootstrapFailure(t *testing.T) {
	initial := platform.PythonClient{Address: "unused", Capability: "cap"}
	bootstrapErr := errors.New("connection refused")
	_, err := resolvePythonClient(initial, "/tmp/project", func(ctx context.Context) (string, error) {
		return "", bootstrapErr
	})
	if err == nil {
		t.Fatal("expected error for bootstrap failure, got nil")
	}
	if !strings.Contains(err.Error(), "bootstrap failed") {
		t.Fatalf("expected 'bootstrap failed' error, got: %v", err)
	}
	if !strings.Contains(err.Error(), "connection refused") {
		t.Fatalf("expected wrapped error to contain 'connection refused', got: %v", err)
	}
}

// TestC_2_1_ResolvePythonClient_RejectsEmptyDigest verifies that an
// empty digest (no error but empty string) rejects startup.
func TestC_2_1_ResolvePythonClient_RejectsEmptyDigest(t *testing.T) {
	initial := platform.PythonClient{Address: "unused", Capability: "cap"}
	_, err := resolvePythonClient(initial, "/tmp/project", func(ctx context.Context) (string, error) {
		return "", nil // no error but empty digest
	})
	if err == nil {
		t.Fatal("expected error for empty digest, got nil")
	}
	if !strings.Contains(err.Error(), "empty digest") {
		t.Fatalf("expected 'empty digest' error, got: %v", err)
	}
}

// TestC_2_1_ResolvePythonClient_SuccessStampsProjectIDAndDigest is the
// core CRITICAL-1 regression test: a successful bootstrap MUST produce
// a PythonClient with BOTH project_id AND policy_digest stamped, so
// every RPC interface (Chat/Confirm/SwitchMode/Audit/Tasks/Subagents)
// carries identical drift claims.
//
// Before C-2-1, NewHandler received a bare PythonClient and the later
// `agent = pc` only mutated the local variable — handler.agent kept the
// bootstrap-less copy, so /api/chat silently ran without drift claims.
func TestC_2_1_ResolvePythonClient_SuccessStampsProjectIDAndDigest(t *testing.T) {
	initial := platform.PythonClient{Address: "/tmp/sock", Capability: "cap123"}
	// C-2-1: use strings.Repeat + var because Go const cannot call functions
	// and does not support Python-style `"0" * 56` string repetition.
	wantDigest := "deadbeef" + strings.Repeat("0", 56) // 64-char hex
	client, err := resolvePythonClient(initial, "/tmp/project", func(ctx context.Context) (string, error) {
		return wantDigest, nil
	})
	if err != nil {
		t.Fatalf("expected success, got error: %v", err)
	}
	// C-2-1: project_id MUST be stamped (non-empty).
	if client.ProjectID == "" {
		t.Fatal("project_id is empty — drift detection on /api/chat would be silently disabled (CRITICAL 1 regression)")
	}
	// C-2-1: policy_digest MUST be stamped (non-empty, matches bootstrap).
	if client.PolicyDigest == "" {
		t.Fatal("policy_digest is empty — drift detection on /api/chat would be silently disabled (CRITICAL 1 regression)")
	}
	if client.PolicyDigest != wantDigest {
		t.Fatalf("policy_digest = %q, want %q", client.PolicyDigest, wantDigest)
	}
	// C-2-1: Address/Capability from initial MUST be preserved.
	if client.Address != "/tmp/sock" {
		t.Fatalf("Address = %q, want /tmp/sock (initial fields must be preserved)", client.Address)
	}
	if client.Capability != "cap123" {
		t.Fatalf("Capability = %q, want cap123 (initial fields must be preserved)", client.Capability)
	}
}

// TestC_2_1_ResolvePythonClient_ProjectIDIsStableForSameRoot verifies
// that the same project root always produces the same project_id (so
// Python's dispatcher sees a stable identity across restarts).
func TestC_2_1_ResolvePythonClient_ProjectIDIsStableForSameRoot(t *testing.T) {
	initial := platform.PythonClient{Address: "unused", Capability: "cap"}
	c1, err := resolvePythonClient(initial, "/tmp/project", func(ctx context.Context) (string, error) {
		return "d1", nil
	})
	if err != nil {
		t.Fatal(err)
	}
	c2, err := resolvePythonClient(initial, "/tmp/project", func(ctx context.Context) (string, error) {
		return "d2", nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if c1.ProjectID != c2.ProjectID {
		t.Fatalf("project_id not stable: %q vs %q", c1.ProjectID, c2.ProjectID)
	}
}

// TestC_2_1_ResolvePythonClient_ProjectIDDiffersForDifferentRoot ensures
// different project roots produce different project_ids (so two projects
// on the same gateway can't share drift identity).
func TestC_2_1_ResolvePythonClient_ProjectIDDiffersForDifferentRoot(t *testing.T) {
	initial := platform.PythonClient{Address: "unused", Capability: "cap"}
	c1, err := resolvePythonClient(initial, "/tmp/project-a", func(ctx context.Context) (string, error) {
		return "d", nil
	})
	if err != nil {
		t.Fatal(err)
	}
	c2, err := resolvePythonClient(initial, "/tmp/project-b", func(ctx context.Context) (string, error) {
		return "d", nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if c1.ProjectID == c2.ProjectID {
		t.Fatalf("project_id should differ for different roots, both = %q", c1.ProjectID)
	}
}
