package handlers

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
)

// TestKeyedLimiterPerClientFairness pins the R3-6 fairness property: one
// client draining its own bucket must not 429 a different client. With
// per-client burst 5 and an aggregate ceiling of 100 (well clear), each
// key gets its own 5 tokens.
func TestKeyedLimiterPerClientFairness(t *testing.T) {
	k := newKeyedLimiter(1, 5, 50, 100)
	for i := 0; i < 5; i++ {
		if !k.allow("a") {
			t.Fatalf("client a request %d denied within its own burst", i)
		}
	}
	if k.allow("a") {
		t.Fatal("client a 6th request allowed past its per-client burst")
	}
	// A second client starts fresh — it must not inherit a's exhaustion.
	if !k.allow("b") {
		t.Fatal("client b denied even though it has its own bucket")
	}
}

// TestKeyedLimiterAggregateCeiling pins the evasion-proof backstop: an
// attacker rotating the client key (e.g. spoofed X-Forwarded-For) gets a
// fresh per-client bucket each time, but the aggregate ceiling caps total
// throughput so the flood cannot exceed it. Per-client burst 5, aggregate
// burst 10 → at most 10 allowed across distinct keys before the ceiling
// trips.
func TestKeyedLimiterAggregateCeiling(t *testing.T) {
	k := newKeyedLimiter(1, 5, 1, 10)
	allowed := 0
	for i := 0; i < 100; i++ {
		if k.allow("ip-" + strconv.Itoa(i)) { // unique key every call
			allowed++
		}
	}
	if allowed > 10 {
		t.Fatalf("key-rotating flood passed %d requests, aggregate ceiling is 10", allowed)
	}
	if allowed < 10 {
		t.Fatalf("aggregate ceiling under-counted: %d allowed, want 10", allowed)
	}
}

// TestKeyedLimiterEvictionBoundsMap guards the memory bound: pushing more
// than maxTrackedClients distinct keys must not grow the map past the cap.
func TestKeyedLimiterEvictionBoundsMap(t *testing.T) {
	k := newKeyedLimiter(1, 1, 1e9, 1e9) // aggregate effectively unlimited
	for i := 0; i < maxTrackedClients+500; i++ {
		k.allow("ip-" + strconv.Itoa(i))
	}
	k.mu.Lock()
	n := len(k.clients)
	k.mu.Unlock()
	if n > maxTrackedClients {
		t.Fatalf("client map grew to %d, cap is %d", n, maxTrackedClients)
	}
}

// TestClientKeyPrefersXForwardedFor pins the key-derivation contract: the
// gateway-set X-Forwarded-For first hop wins over the loopback RemoteAddr,
// and RemoteAddr's host is the fallback when no XFF is present.
func TestClientKeyPrefersXForwardedFor(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/api/status", nil)
	r.RemoteAddr = "127.0.0.1:54321"
	r.Header.Set("X-Forwarded-For", "192.168.50.50, 10.0.0.1")
	if got := clientKey(r); got != "192.168.50.50" {
		t.Errorf("clientKey with XFF = %q, want 192.168.50.50", got)
	}

	r2 := httptest.NewRequest(http.MethodGet, "/api/status", nil)
	r2.RemoteAddr = "192.168.50.77:40000"
	if got := clientKey(r2); got != "192.168.50.77" {
		t.Errorf("clientKey fallback = %q, want 192.168.50.77", got)
	}
}
