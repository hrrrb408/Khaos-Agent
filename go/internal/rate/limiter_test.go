package rate

import (
	"testing"
	"time"
)

func TestKeyedBucketsIsolateIdentities(t *testing.T) {
	limiter := NewKeyedBuckets(1, 1, 16, time.Minute)
	if !limiter.Allow("principal-a") {
		t.Fatal("first principal-a request was rejected")
	}
	if limiter.Allow("principal-a") {
		t.Fatal("principal-a bucket did not enforce its burst")
	}
	if !limiter.Allow("principal-b") {
		t.Fatal("principal-a exhausted principal-b bucket")
	}
}

func TestKeyedBucketsBoundIdentityTable(t *testing.T) {
	limiter := NewKeyedBuckets(60, 1, 2, time.Hour)
	if !limiter.Allow("one") || !limiter.Allow("two") || !limiter.Allow("three") {
		t.Fatal("new identities should receive an independent initial token")
	}
	if len(limiter.buckets) != 2 {
		t.Fatalf("identity table size=%d, want 2", len(limiter.buckets))
	}
}
