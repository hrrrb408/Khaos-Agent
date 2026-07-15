package platform

import (
	"context"
	"testing"
)

func TestPythonClientRejectsTCPAddress(t *testing.T) {
	client := PythonClient{Address: "127.0.0.1:50051"}
	if _, err := client.dial(context.Background()); err == nil {
		t.Fatal("expected TCP-style Python RPC address to be rejected")
	}
}
