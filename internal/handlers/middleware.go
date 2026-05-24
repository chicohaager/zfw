// Middleware helpers for the HTTP API. Kept stdlib-only so a single binary
// stays self-contained on a ZimaOS sysext.
package handlers

import (
	"net/http"
	"sync"
	"time"
)

// rateBucket is a single-process token bucket. Mutating endpoints
// (`apply`, `commit`, `revert`, `rules POST`, `rules/defaults`) share one
// instance so a stuck UI tab or a tight-loop script cannot pin the engine
// at 100 % CPU re-applying iptables. GET endpoints stay unlimited — they
// are cheap and the dashboard polls them on every refresh.
//
// Token model: `capacity` tokens at start, refilled at `rate` tokens per
// second up to capacity. `allow()` consumes one token, returns false when
// none are available.
type rateBucket struct {
	mu       sync.Mutex
	tokens   float64
	capacity float64
	rate     float64
	last     time.Time
}

// newRateBucket — capacity=burst, rate=sustained-tokens-per-second.
// ZFW defaults to burst 10, rate 1/s — a human clicking Safe-Apply ten
// times in a row passes, a runaway loop is throttled to one call/second.
func newRateBucket(rate, capacity float64) *rateBucket {
	return &rateBucket{
		tokens:   capacity,
		capacity: capacity,
		rate:     rate,
		last:     time.Now(),
	}
}

func (b *rateBucket) allow() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := time.Now()
	elapsed := now.Sub(b.last).Seconds()
	b.tokens += elapsed * b.rate
	if b.tokens > b.capacity {
		b.tokens = b.capacity
	}
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// rateLimited returns an http.HandlerFunc that drops non-GET requests when
// the shared mutateRL bucket is empty. GETs always pass — read traffic is
// not load-shedded so the dashboard never reports phantom errors.
//
// On 429 we set Retry-After: 1 so a naive client (no exponential back-off)
// at least waits a full bucket-refill before hammering us again — defeating
// the limiter's CPU-protection goal otherwise (security-review v0.2.20 L3).
func (s *Server) rateLimited(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && !s.mutateRL.allow() {
			w.Header().Set("Retry-After", "1")
			fail(w, http.StatusTooManyRequests,
				"rate limit exceeded — slow down (burst 10, 1/s sustained)")
			return
		}
		h(w, r)
	}
}

// rateLimitedGet caps expensive read endpoints (the ones that shell
// out to `ss`, `journalctl`, `docker`, `ssh -V`, or read /proc) with
// the dedicated readRL bucket — burst 60, sustained 5/s. Closes R3-5:
// an authenticated client can no longer flood these to CPU-pin the
// daemon. The same Retry-After/429 envelope as rateLimited so naive
// clients back off cleanly.
func (s *Server) rateLimitedGet(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.readRL.allow() {
			w.Header().Set("Retry-After", "1")
			fail(w, http.StatusTooManyRequests,
				"rate limit exceeded — slow down (burst 60, 5/s sustained on expensive reads)")
			return
		}
		h(w, r)
	}
}
