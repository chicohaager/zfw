// Package notify implements opt-in outbound webhooks that the daemon
// fires on rule changes, applies, commits and reverts. v0.5.5.
//
// Pattern follows internal/update: empty URL = disabled (no goroutines,
// no outbound HTTP), so a fresh install makes no calls until the
// operator sets ZFW_WEBHOOK_URL. Hook.Send returns the request error
// for tests but production callers do not block on it — webhook
// failures must never break the firewall flow itself.
package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// Event is the JSON body posted to the configured URL. Type is the
// short lifecycle name; Details carries free-form per-event data.
type Event struct {
	Type      string         `json:"type"`
	Version   string         `json:"version"`
	Timestamp time.Time      `json:"timestamp"`
	Details   map[string]any `json:"details,omitempty"`
}

// Hook is the configured webhook target. Send is safe for concurrent
// use. A nil *Hook (returned by New("")) is the disabled state — Send
// is a no-op on it.
type Hook struct {
	url    string
	client *http.Client
}

// New returns a *Hook configured against url. An empty url returns nil
// so callers can hold a *Hook field and call Send unconditionally —
// the nil receiver path is a no-op.
func New(url string) *Hook {
	if url == "" {
		return nil
	}
	return &Hook{
		url:    url,
		client: &http.Client{Timeout: 10 * time.Second},
	}
}

// Send posts the event JSON to the configured URL. Returns the request
// error so tests can assert on it; production callers should fire it
// in a goroutine and ignore the return value (the webhook is a
// best-effort signal, not a precondition for the firewall action).
// A nil *Hook (disabled) returns nil immediately without any I/O.
func (h *Hook) Send(ctx context.Context, ev Event) error {
	if h == nil {
		return nil
	}
	body, err := json.Marshal(ev)
	if err != nil {
		return fmt.Errorf("marshal event: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, h.url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "zfw/notify")
	resp, err := h.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("webhook HTTP %d", resp.StatusCode)
	}
	return nil
}

// SendAsync runs Send in a goroutine, swallowing any error. Used by
// handlers that must not block the response on webhook completion.
// The context is detached from the request so the webhook still
// flies after the HTTP response goes out.
func (h *Hook) SendAsync(ev Event) {
	if h == nil {
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		_ = h.Send(ctx, ev)
	}()
}
