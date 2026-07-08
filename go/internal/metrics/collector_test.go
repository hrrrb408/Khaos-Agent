package metrics

import (
	"testing"
	"time"
)

func TestCollectorRecord(t *testing.T) {
	collector := NewCollector()

	collector.RecordRequest("/api/health", "GET", 10*time.Millisecond, nil)
	collector.RecordRequest("/api/health", "GET", 20*time.Millisecond, nil)
	collector.RecordRequest("/api/chat", "POST", 30*time.Millisecond, assertErr{})

	stats := collector.Snapshot()
	if stats.TotalRequests != 3 {
		t.Fatalf("total requests=%d", stats.TotalRequests)
	}
	if stats.TotalErrors != 1 {
		t.Fatalf("total errors=%d", stats.TotalErrors)
	}
	if stats.RequestsByRoute["/api/health"] != 2 {
		t.Fatalf("health route count=%d", stats.RequestsByRoute["/api/health"])
	}
	if stats.RequestsByMethod["GET"] != 2 || stats.RequestsByMethod["POST"] != 1 {
		t.Fatalf("method counts=%v", stats.RequestsByMethod)
	}
}

func TestCollectorAvgLatency(t *testing.T) {
	collector := NewCollector()

	collector.RecordRequest("/a", "GET", 10*time.Millisecond, nil)
	collector.RecordRequest("/a", "GET", 30*time.Millisecond, nil)

	stats := collector.Snapshot()
	if stats.AvgLatencyMs < 19.9 || stats.AvgLatencyMs > 20.1 {
		t.Fatalf("avg latency=%f", stats.AvgLatencyMs)
	}
}

func TestCollectorSnapshot(t *testing.T) {
	collector := NewCollector()
	collector.RecordRequest("/a", "GET", time.Millisecond, nil)

	snapshot := collector.Snapshot()
	snapshot.RequestsByRoute["/a"] = 99
	snapshot.RequestsByMethod["GET"] = 99

	next := collector.Snapshot()
	if next.RequestsByRoute["/a"] != 1 {
		t.Fatalf("route map was not deep copied: %v", next.RequestsByRoute)
	}
	if next.RequestsByMethod["GET"] != 1 {
		t.Fatalf("method map was not deep copied: %v", next.RequestsByMethod)
	}
}

type assertErr struct{}

func (assertErr) Error() string {
	return "assert error"
}
