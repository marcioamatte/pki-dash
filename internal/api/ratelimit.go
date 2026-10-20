package api

import (
	"net"
	"net/http"
	"sync"
	"time"
)

// limiter is a per-key token bucket. Memory is bounded: idle buckets are
// swept, and when the table is still full the request is refused.
type limiter struct {
	mu       sync.Mutex
	rate     float64 // tokens per second
	burst    float64
	max      int
	buckets  map[string]*bucket
	lastScan time.Time
	now      func() time.Time
}

type bucket struct {
	tokens float64
	last   time.Time
}

func newLimiter(perSecond float64, burst int, now func() time.Time) *limiter {
	return &limiter{rate: perSecond, burst: float64(burst), max: 100_000, buckets: map[string]*bucket{}, now: now}
}

func (l *limiter) allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	if now.Sub(l.lastScan) > time.Minute {
		l.sweep(now)
	}
	b, ok := l.buckets[key]
	if !ok {
		if len(l.buckets) >= l.max {
			return false
		}
		b = &bucket{tokens: l.burst, last: now}
		l.buckets[key] = b
	}
	b.tokens += now.Sub(b.last).Seconds() * l.rate
	if b.tokens > l.burst {
		b.tokens = l.burst
	}
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// sweep drops buckets that have refilled completely: they carry no state.
func (l *limiter) sweep(now time.Time) {
	l.lastScan = now
	for k, b := range l.buckets {
		if b.tokens+now.Sub(b.last).Seconds()*l.rate >= l.burst {
			delete(l.buckets, k)
		}
	}
}

// clientIP is the peer address. Forwarded headers are deliberately ignored:
// they are attacker-controlled unless a trusted proxy sets them, and there is
// no proxy support yet.
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
