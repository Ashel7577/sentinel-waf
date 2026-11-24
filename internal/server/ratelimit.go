package server

import (
	"math"
	"sync"
	"time"
)

// RateLimiter is a per-key token bucket.
type RateLimiter struct {
	mu      sync.Mutex
	rate    float64 // tokens per second
	burst   float64
	buckets map[string]*bucket
}

type bucket struct {
	tokens float64
	last   time.Time
}

// NewRateLimiter allows `rate` requests/second per key with bursts of `burst`.
func NewRateLimiter(rate float64, burst int) *RateLimiter {
	if burst < 1 {
		burst = int(math.Max(1, rate))
	}
	l := &RateLimiter{rate: rate, burst: float64(burst), buckets: make(map[string]*bucket)}
	go l.janitor()
	return l
}

// Allow consumes one token for key.
func (l *RateLimiter) Allow(key string) bool {
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	b, ok := l.buckets[key]
	if !ok {
		b = &bucket{tokens: l.burst, last: now}
		l.buckets[key] = b
	}
	b.tokens = math.Min(l.burst, b.tokens+now.Sub(b.last).Seconds()*l.rate)
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

func (l *RateLimiter) janitor() {
	for range time.Tick(time.Minute) {
		cutoff := time.Now().Add(-5 * time.Minute)
		l.mu.Lock()
		for k, b := range l.buckets {
			if b.last.Before(cutoff) {
				delete(l.buckets, k)
			}
		}
		l.mu.Unlock()
	}
}
