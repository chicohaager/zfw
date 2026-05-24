package notify

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// TestSendDisabledIsNoop guards the opt-out branch: an empty URL
// produces a nil *Hook and Send is a no-op (no I/O, no error).
func TestSendDisabledIsNoop(t *testing.T) {
	h := New("")
	if h != nil {
		t.Fatalf("New(\"\") = %v, want nil", h)
	}
	// Nil-receiver Send must not panic.
	if err := h.Send(context.Background(), Event{Type: "noop"}); err != nil {
		t.Errorf("nil-receiver Send returned err: %v", err)
	}
	h.SendAsync(Event{Type: "noop"}) // must not panic either
}

// TestSendDeliversJSONBody guards the canonical happy path: the
// configured URL receives a POST with a Content-Type header and a
// well-formed JSON body that matches the event we passed in.
func TestSendDeliversJSONBody(t *testing.T) {
	var seenCT, seenBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenCT = r.Header.Get("Content-Type")
		b, _ := io.ReadAll(r.Body)
		seenBody = string(b)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	h := New(srv.URL)
	ev := Event{
		Type:      "apply",
		Version:   "0.5.5",
		Timestamp: time.Date(2026, 5, 24, 12, 0, 0, 0, time.UTC),
		Details:   map[string]any{"safe": true},
	}
	if err := h.Send(context.Background(), ev); err != nil {
		t.Fatalf("Send failed: %v", err)
	}
	if seenCT != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", seenCT)
	}
	var got Event
	if err := json.Unmarshal([]byte(seenBody), &got); err != nil {
		t.Fatalf("body is not JSON: %v (body=%s)", err, seenBody)
	}
	if got.Type != "apply" || got.Version != "0.5.5" {
		t.Errorf("decoded event = %+v, want type=apply version=0.5.5", got)
	}
	if got.Details["safe"] != true {
		t.Errorf("Details lost the safe flag: %+v", got.Details)
	}
}

// TestSendReturnsHTTPError guards the failure path: a 4xx/5xx response
// surfaces as an error from Send. Tests rely on this to assert on
// webhook misconfiguration; production handlers fire-and-forget.
func TestSendReturnsHTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "denied", http.StatusUnauthorized)
	}))
	defer srv.Close()
	err := New(srv.URL).Send(context.Background(), Event{Type: "apply"})
	if err == nil {
		t.Fatal("Send accepted a 401 response without error")
	}
}

// TestSendAsyncFiresAndForgets guards the production happy path: the
// goroutine completes the POST without blocking the caller. We use a
// WaitGroup on the receiver side to confirm the body landed.
func TestSendAsyncFiresAndForgets(t *testing.T) {
	var wg sync.WaitGroup
	wg.Add(1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer wg.Done()
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	h := New(srv.URL)
	start := time.Now()
	h.SendAsync(Event{Type: "commit"})
	// SendAsync must return immediately — not wait for the HTTP round-trip.
	if d := time.Since(start); d > 50*time.Millisecond {
		t.Errorf("SendAsync blocked for %v, want <50ms", d)
	}
	// Confirm the request actually arrived (within a reasonable bound).
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("SendAsync did not deliver the request within 2s")
	}
}
