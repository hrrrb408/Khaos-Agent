package ws

import (
	"sync"
	"testing"
	"time"

	"khaos/go/internal/api"
)

type mockConn struct {
	mu     sync.Mutex
	events []any
}

func (m *mockConn) WriteJSON(v any) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.events = append(m.events, v)
	return nil
}

func (m *mockConn) ReadJSON(v any) error {
	return nil
}

func (m *mockConn) Close() error {
	return nil
}

func (m *mockConn) count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.events)
}

func TestHubRegisterUnregister(t *testing.T) {
	hub := NewHub()
	go hub.Run()
	conn := &mockConn{}

	hub.Register(conn, "s1")
	waitFor(t, func() bool { return hub.HasClients("s1") })
	if hub.ClientCount() != 1 {
		t.Fatalf("client count=%d", hub.ClientCount())
	}

	hub.Unregister(conn, "s1")
	waitFor(t, func() bool { return !hub.HasClients("s1") })
	if hub.ClientCount() != 0 {
		t.Fatalf("client count=%d", hub.ClientCount())
	}
}

func TestHubBroadcast(t *testing.T) {
	hub := NewHub()
	go hub.Run()
	conn1 := &mockConn{}
	conn2 := &mockConn{}
	other := &mockConn{}

	hub.Register(conn1, "s1")
	hub.Register(conn2, "s1")
	hub.Register(other, "s2")
	waitFor(t, func() bool { return hub.ClientCount() == 3 })

	hub.Broadcast("s1", api.ChatEvent{Event: "message", Data: map[string]any{"content": "hello"}})
	waitFor(t, func() bool { return conn1.count() == 1 && conn2.count() == 1 })
	if other.count() != 0 {
		t.Fatalf("broadcast leaked to another session: %d", other.count())
	}
}

func TestHubClientCount(t *testing.T) {
	hub := NewHub()
	go hub.Run()
	conn1 := &mockConn{}
	conn2 := &mockConn{}

	hub.Register(conn1, "s1")
	hub.Register(conn2, "s2")
	waitFor(t, func() bool { return hub.ClientCount() == 2 })

	hub.Unregister(conn1, "s1")
	waitFor(t, func() bool { return hub.ClientCount() == 1 })
	if !hub.HasClients("s2") {
		t.Fatal("expected s2 to still have clients")
	}
}

func waitFor(t *testing.T, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("condition was not met before deadline")
}
