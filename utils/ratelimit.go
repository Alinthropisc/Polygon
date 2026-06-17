package utils

import (
	"sync"
	"time"
)

// TokenBucket is a classic token-bucket rate limiter.
// Take() blocks until a token is available.
type TokenBucket struct {
	mu       sync.Mutex
	tokens   float64
	capacity float64
	rate     float64 // tokens per second
	last     time.Time
}

// NewTokenBucket creates a bucket with the given capacity and refill rate (tokens/sec).
func NewTokenBucket(capacity, ratePerSec float64) *TokenBucket {
	return &TokenBucket{
		tokens:   capacity,
		capacity: capacity,
		rate:     ratePerSec,
		last:     time.Now(),
	}
}

// Take blocks until one token is available, then consumes it.
func (tb *TokenBucket) Take() {
	for {
		tb.mu.Lock()
		now := time.Now()
		elapsed := now.Sub(tb.last).Seconds()
		tb.tokens = min64(tb.capacity, tb.tokens+elapsed*tb.rate)
		tb.last = now
		if tb.tokens >= 1 {
			tb.tokens--
			tb.mu.Unlock()
			return
		}
		// Calculate exact sleep needed to get one token
		wait := time.Duration((1-tb.tokens)/tb.rate*1000) * time.Millisecond
		tb.mu.Unlock()
		time.Sleep(wait)
	}
}

// TryTake consumes a token and returns true, or returns false immediately if empty.
func (tb *TokenBucket) TryTake() bool {
	tb.mu.Lock()
	defer tb.mu.Unlock()
	now := time.Now()
	elapsed := now.Sub(tb.last).Seconds()
	tb.tokens = min64(tb.capacity, tb.tokens+elapsed*tb.rate)
	tb.last = now
	if tb.tokens >= 1 {
		tb.tokens--
		return true
	}
	return false
}

// Available returns the current token count (approximate, for display).
func (tb *TokenBucket) Available() float64 {
	tb.mu.Lock()
	defer tb.mu.Unlock()
	return tb.tokens
}

func min64(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}
