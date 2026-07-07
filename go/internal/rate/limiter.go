package rate

import (
	"sync"
	"time"
)

// TokenBucket is a small thread-safe token bucket limiter.
type TokenBucket struct {
	mu       sync.Mutex
	rate     float64
	burst    float64
	tokens   float64
	lastFill time.Time
}

// NewTokenBucket creates a token bucket with rate tokens per minute.
func NewTokenBucket(ratePerMinute int, burst int) *TokenBucket {
	if ratePerMinute <= 0 {
		ratePerMinute = 60
	}
	if burst <= 0 {
		burst = 10
	}
	return &TokenBucket{
		rate:     float64(ratePerMinute) / 60.0,
		burst:    float64(burst),
		tokens:   float64(burst),
		lastFill: time.Now(),
	}
}

// Allow consumes one token if available.
func (b *TokenBucket) Allow() bool {
	b.mu.Lock()
	defer b.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(b.lastFill).Seconds()
	b.tokens += elapsed * b.rate
	if b.tokens > b.burst {
		b.tokens = b.burst
	}
	b.lastFill = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}
