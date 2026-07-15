package main

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestValidateListenConfigRequiresKeyOffLoopback(t *testing.T) {
	if err := validateListenConfig("0.0.0.0:8080", ""); err == nil {
		t.Fatal("expected non-loopback listen without key to be rejected")
	}
	strong := "0123456789abcdef0123456789abcdef"
	if err := validateListenConfig("0.0.0.0:8080", strong); err != nil {
		t.Fatalf("keyed non-loopback listen rejected: %v", err)
	}
	if err := validateListenConfig("127.0.0.1:8080", ""); err == nil {
		t.Fatal("loopback listen without key must be rejected")
	}
	if err := validateListenConfig("127.0.0.1:8080", strong); err != nil {
		t.Fatalf("authenticated loopback listen rejected: %v", err)
	}
}

func TestLoadOrCreateAPIKeyUsesProtectedHighEntropyFile(t *testing.T) {
	root := t.TempDir()
	if runtime.GOOS == "windows" {
		t.Setenv("AppData", root)
	}
	path := filepath.Join(root, "khaos", "gateway-token")
	first, storedAt, err := loadOrCreateAPIKey("", path)
	if err != nil {
		t.Fatal(err)
	}
	if storedAt != path || len(first) < 43 {
		t.Fatalf("path=%q token length=%d", storedAt, len(first))
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Fatalf("token mode=%#o", info.Mode().Perm())
	}
	second, _, err := loadOrCreateAPIKey("", path)
	if err != nil || second != first {
		t.Fatalf("token was not reused: err=%v equal=%v", err, second == first)
	}
}

func TestWindowsTokenPathCannotEscapeUserConfig(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows profile ACL boundary")
	}
	root := t.TempDir()
	t.Setenv("AppData", root)
	outside := filepath.Join(filepath.Dir(root), "shared", "gateway-token")
	if _, _, err := loadOrCreateAPIKey("", outside); err == nil {
		t.Fatal("token path outside the Windows user config directory was accepted")
	}
}

func TestLoadOrCreateAPIKeyRejectsWeakOrSymlinkTokenFile(t *testing.T) {
	dir := t.TempDir()
	weak := filepath.Join(dir, "weak")
	if err := os.WriteFile(weak, []byte("short\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := loadOrCreateAPIKey("", weak); err == nil {
		t.Fatal("weak persisted token accepted")
	}
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("0123456789abcdef0123456789abcdef\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if _, _, err := loadOrCreateAPIKey("", link); err == nil {
		t.Fatal("symlink token file accepted")
	}
}
