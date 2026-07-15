package main

import "testing"

func TestValidateListenConfigRequiresKeyOffLoopback(t *testing.T) {
	if err := validateListenConfig("0.0.0.0:8080", ""); err == nil {
		t.Fatal("expected non-loopback listen without key to be rejected")
	}
	if err := validateListenConfig("0.0.0.0:8080", "secret"); err != nil {
		t.Fatalf("keyed non-loopback listen rejected: %v", err)
	}
	if err := validateListenConfig("127.0.0.1:8080", ""); err != nil {
		t.Fatalf("loopback listen rejected: %v", err)
	}
}
