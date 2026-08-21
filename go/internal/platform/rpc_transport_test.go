package platform

import (
	"context"
	"net"
	"testing"
	"time"
)

type rpcTransportFunc func(context.Context, string) (net.Conn, error)

func (f rpcTransportFunc) Dial(ctx context.Context, address string) (net.Conn, error) {
	return f(ctx, address)
}

func TestOpenRPCConnectionBindsCancellationToStream(t *testing.T) {
	clientSide, serverSide := net.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	conn, err := OpenRPCConnection(ctx, rpcTransportFunc(func(context.Context, string) (net.Conn, error) {
		return clientSide, nil
	}), "/memory/python.sock")
	if err != nil {
		t.Fatal(err)
	}
	defer serverSide.Close()

	cancel()
	_ = serverSide.SetReadDeadline(time.Now().Add(time.Second))
	var oneByte [1]byte
	_, err = serverSide.Read(oneByte[:])
	if err == nil {
		t.Fatal("context cancellation left the RPC stream open")
	}
	if err := conn.Close(); err != nil {
		t.Fatalf("idempotent close: %v", err)
	}
}

func TestPythonClientUsesInjectedTransport(t *testing.T) {
	clientSide, serverSide := net.Pipe()
	defer serverSide.Close()
	var gotAddress string
	client := PythonClient{
		Address: "in-memory/python.sock",
		Transport: rpcTransportFunc(func(_ context.Context, address string) (net.Conn, error) {
			gotAddress = address
			return clientSide, nil
		}),
	}
	conn, err := client.dial(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if gotAddress != client.Address {
		t.Fatalf("transport address = %q, want %q", gotAddress, client.Address)
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestUnixRPCTransportRejectsRelativeAddressBeforeDial(t *testing.T) {
	if _, err := (UnixRPCTransport{}).Dial(context.Background(), "relative.sock"); err == nil {
		t.Fatal("expected relative Unix socket path to fail closed")
	}
}
