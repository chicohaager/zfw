// Middleware helpers for the HTTP API. Kept stdlib-only so a single binary
// stays self-contained on a ZimaOS sysext.
package handlers

import (
	"net"
	"net/http"
	"strings"
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

// maxTrackedClients caps the per-client bucket map so a flood of
// distinct client keys (e.g. spoofed X-Forwarded-For values) cannot
// grow it without bound. When the cap is hit the oldest-seen key is
// evicted. The aggregate bucket (see keyedLimiter) is the real
// anti-evasion control; this map is the fairness layer on top.
const maxTrackedClients = 4096

// keyedLimiter rate-limits per client key while keeping a global
// aggregate ceiling. A request is allowed only if BOTH the aggregate
// bucket and the client's own bucket have a token, so:
//
//   - one noisy client is throttled on its own bucket without 429-ing
//     other clients (fairness — closes the R3-6 per-IP residual), and
//   - an attacker rotating the client key (X-Forwarded-For is set by
//     the ZimaOS gateway and is not authenticated) still cannot exceed
//     the aggregate ceiling, which is evasion-proof because it is not
//     keyed. The aggregate is therefore never weaker than the old
//     single global bucket.
//
// Per-client params match the old global bucket; the aggregate is set
// a few × higher so a single legitimate client is bound by its own
// bucket, not the ceiling.
type keyedLimiter struct {
	mu        sync.Mutex
	clients   map[string]*clientBucket
	aggregate *rateBucket
	rate      float64
	capacity  float64
}

type clientBucket struct {
	bucket *rateBucket
	seen   time.Time
}

// newKeyedLimiter builds a limiter whose per-client buckets use
// (rate, capacity) and whose aggregate ceiling uses (aggRate, aggCap).
func newKeyedLimiter(rate, capacity, aggRate, aggCap float64) *keyedLimiter {
	return &keyedLimiter{
		clients:   make(map[string]*clientBucket),
		aggregate: newRateBucket(aggRate, aggCap),
		rate:      rate,
		capacity:  capacity,
	}
}

// allow consumes one token for key. It checks the per-client bucket
// first so a denied client never draws down the shared aggregate.
func (k *keyedLimiter) allow(key string) bool {
	k.mu.Lock()
	cb := k.clients[key]
	if cb == nil {
		if len(k.clients) >= maxTrackedClients {
			k.evictOldestLocked()
		}
		cb = &clientBucket{bucket: newRateBucket(k.rate, k.capacity)}
		k.clients[key] = cb
	}
	cb.seen = time.Now()
	k.mu.Unlock()

	if !cb.bucket.allow() {
		return false
	}
	return k.aggregate.allow()
}

// evictOldestLocked drops the least-recently-seen client. Caller holds k.mu.
func (k *keyedLimiter) evictOldestLocked() {
	var oldestKey string
	var oldest time.Time
	first := true
	for key, cb := range k.clients {
		if first || cb.seen.Before(oldest) {
			oldestKey, oldest, first = key, cb.seen, false
		}
	}
	if !first {
		delete(k.clients, oldestKey)
	}
}

// clientKey derives the rate-limit key for a request. The daemon binds
// loopback behind the ZimaOS gateway, so RemoteAddr is almost always
// 127.0.0.1; the gateway forwards the real LAN client in
// X-Forwarded-For. We key on the first XFF hop when present, falling
// back to RemoteAddr's host. XFF is gateway-set and not authenticated —
// an on-host process could spoof it, but that is out of scope (on-host
// code already has root-adjacent reach) and the aggregate ceiling caps
// any spoofing-based evasion regardless.
func clientKey(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if first, _, ok := strings.Cut(xff, ","); ok {
			xff = first
		}
		if v := strings.TrimSpace(xff); v != "" {
			return v
		}
	}
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
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
		if r.Method != http.MethodGet && !s.mutateRL.allow(clientKey(r)) {
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
		if !s.readRL.allow(clientKey(r)) {
			w.Header().Set("Retry-After", "1")
			fail(w, http.StatusTooManyRequests,
				"rate limit exceeded — slow down (burst 60, 5/s sustained on expensive reads)")
			return
		}
		h(w, r)
	}
}
