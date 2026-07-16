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

// Config returns the immutable rate and burst settings used by this bucket.
func (b *TokenBucket) Config() (int, int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return int(b.rate * 60), int(b.burst)
}

type keyedBucket struct {
	bucket   *TokenBucket
	lastSeen time.Time
}

// KeyedBuckets isolates token buckets by an authenticated or network identity.
// The bounded key table prevents a source-address spray from growing memory
// without limit.
type KeyedBuckets struct {
	mu      sync.Mutex
	rate    int
	burst   int
	maxKeys int
	idleTTL time.Duration
	buckets map[string]*keyedBucket
}

// NewKeyedBuckets creates a bounded collection of independent token buckets.
func NewKeyedBuckets(ratePerMinute int, burst int, maxKeys int, idleTTL time.Duration) *KeyedBuckets {
	if ratePerMinute <= 0 {
		ratePerMinute = 60
	}
	if burst <= 0 {
		burst = 10
	}
	if maxKeys <= 0 {
		maxKeys = 4096
	}
	if idleTTL <= 0 {
		idleTTL = 10 * time.Minute
	}
	return &KeyedBuckets{
		rate: ratePerMinute, burst: burst, maxKeys: maxKeys, idleTTL: idleTTL,
		buckets: make(map[string]*keyedBucket),
	}
}

// Allow consumes a token only from the bucket belonging to key.
func (b *KeyedBuckets) Allow(key string) bool {
	if key == "" {
		key = "unknown"
	}
	now := time.Now()
	b.mu.Lock()
	for existing, entry := range b.buckets {
		if now.Sub(entry.lastSeen) > b.idleTTL {
			delete(b.buckets, existing)
		}
	}
	entry := b.buckets[key]
	if entry == nil {
		if len(b.buckets) >= b.maxKeys {
			oldestKey := ""
			var oldest time.Time
			for existing, candidate := range b.buckets {
				if oldestKey == "" || candidate.lastSeen.Before(oldest) {
					oldestKey, oldest = existing, candidate.lastSeen
				}
			}
			delete(b.buckets, oldestKey)
		}
		entry = &keyedBucket{bucket: NewTokenBucket(b.rate, b.burst)}
		b.buckets[key] = entry
	}
	entry.lastSeen = now
	b.mu.Unlock()
	return entry.bucket.Allow()
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
