// Package metrics collects gateway request statistics.
package metrics

import (
	"sync"
	"time"
)

const maxDurations = 1000

// Stats is a snapshot of request metrics.
type Stats struct {
	TotalRequests    int64            `json:"total_requests"`
	ActiveRequests   int64            `json:"active_requests"`
	TotalErrors      int64            `json:"total_errors"`
	RequestsByRoute  map[string]int64 `json:"requests_by_route"`
	RequestsByMethod map[string]int64 `json:"requests_by_method"`
	AvgLatencyMs     float64          `json:"avg_latency_ms"`
	StartedAt        time.Time        `json:"started_at"`
}

// Collector stores request metrics in memory.
type Collector struct {
	mu        sync.RWMutex
	stats     Stats
	durations []float64
}

// NewCollector creates a metrics collector.
func NewCollector() *Collector {
	return &Collector{
		stats: Stats{
			RequestsByRoute:  map[string]int64{},
			RequestsByMethod: map[string]int64{},
			StartedAt:        time.Now(),
		},
		durations: []float64{},
	}
}

// RecordRequest records one completed request.
func (c *Collector) RecordRequest(route, method string, duration time.Duration, err error) {
	if route == "" {
		route = "unknown"
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	c.stats.TotalRequests++
	if err != nil {
		c.stats.TotalErrors++
	}
	c.stats.RequestsByRoute[route]++
	c.stats.RequestsByMethod[method]++

	latencyMs := float64(duration.Microseconds()) / 1000.0
	c.durations = append(c.durations, latencyMs)
	if len(c.durations) > maxDurations {
		c.durations = c.durations[len(c.durations)-maxDurations:]
	}
	c.stats.AvgLatencyMs = average(c.durations)
}

// IncrActive increments the active request count.
func (c *Collector) IncrActive() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.stats.ActiveRequests++
}

// DecrActive decrements the active request count.
func (c *Collector) DecrActive() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.stats.ActiveRequests > 0 {
		c.stats.ActiveRequests--
	}
}

// Snapshot returns a deep copy of current metrics.
func (c *Collector) Snapshot() Stats {
	c.mu.RLock()
	defer c.mu.RUnlock()

	snapshot := c.stats
	snapshot.RequestsByRoute = map[string]int64{}
	for route, count := range c.stats.RequestsByRoute {
		snapshot.RequestsByRoute[route] = count
	}
	snapshot.RequestsByMethod = map[string]int64{}
	for method, count := range c.stats.RequestsByMethod {
		snapshot.RequestsByMethod[method] = count
	}
	return snapshot
}

func average(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}
	total := 0.0
	for _, value := range values {
		total += value
	}
	return total / float64(len(values))
}
