// Package peers implements the opt-in multi-host rule-sync layer.
//
// One designated "leader" host pushes its rules.json to every configured
// follower. Followers expose a separate endpoint (/api/peers/receive) that
// is authenticated by a shared peer-token rather than the ZimaOS session
// JWT — so the leader doesn't need a follower's user session to push.
//
// The leader's peers list is loaded from a JSON file (defaults to
// /DATA/zfw/peers.json) so it is easy to keep in sync with the rest of
// the rules state. The list is opt-in: an empty file or missing file
// disables the push button in the UI and returns an empty Results from
// Push() — no network calls happen on a fresh install.
//
// Tokens are stored in the on-disk peers.json (file mode 0600 — the
// /DATA/zfw directory is already root-only, per the daemon's startup).
// The /api/peers GET endpoint strips tokens before serving so a
// compromised UI session cannot exfiltrate them.
package peers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"time"
)

// Peer is one configured follower.
type Peer struct {
	Name  string `json:"name"`
	URL   string `json:"url"`
	Token string `json:"token,omitempty"`
}

// Public is a Peer with Token redacted — what the UI sees.
type Public struct {
	Name string `json:"name"`
	URL  string `json:"url"`
}

// Result is the per-peer outcome of a Push call.
type Result struct {
	Name  string `json:"name"`
	URL   string `json:"url"`
	OK    bool   `json:"ok"`
	Code  int    `json:"code,omitempty"`
	Error string `json:"error,omitempty"`
}

// Load reads the peers file. An ENOENT or empty file returns an empty
// slice — peers is opt-in, so "no file" must be the same as "no peers".
func Load(path string) ([]Peer, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	if len(bytes.TrimSpace(b)) == 0 {
		return nil, nil
	}
	var ps []Peer
	if err := json.Unmarshal(b, &ps); err != nil {
		return nil, fmt.Errorf("peers.json parse: %w", err)
	}
	return ps, nil
}

// Sanitize returns a token-stripped view safe to ship over the UI API.
func Sanitize(ps []Peer) []Public {
	out := make([]Public, len(ps))
	for i, p := range ps {
		out[i] = Public{Name: p.Name, URL: p.URL}
	}
	return out
}

// Push POSTs the given JSON-encoded rules payload to every peer's
// /api/peers/receive endpoint. Each peer gets its own request with its
// own Bearer token. Results are returned in the same order as ps so the
// UI can render them alongside the names. A peer with empty URL or
// empty token is recorded as a failure rather than silently skipped.
func Push(ctx context.Context, client *http.Client, ps []Peer, body []byte) []Result {
	out := make([]Result, len(ps))
	for i, p := range ps {
		out[i] = pushOne(ctx, client, p, body)
	}
	return out
}

func pushOne(ctx context.Context, client *http.Client, p Peer, body []byte) Result {
	r := Result{Name: p.Name, URL: p.URL}
	if p.URL == "" {
		r.Error = "peer URL is empty"
		return r
	}
	if p.Token == "" {
		r.Error = "peer token is empty"
		return r
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.URL, bytes.NewReader(body))
	if err != nil {
		r.Error = err.Error()
		return r
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+p.Token)
	// R4-3: the follower's outer middleware runs a same-origin CSRF
	// check on every POST, including /api/peers/receive (which the
	// JWT middleware whitelists). Without an Origin header from the
	// leader, every push would 403 before the bearer check fires.
	// Set Origin to the URL's scheme+host so same-origin holds. The
	// shared bearer is still the load-bearing auth — Origin is
	// defence-in-depth, not the trust anchor.
	if u, perr := url.Parse(p.URL); perr == nil && u.Scheme != "" && u.Host != "" {
		req.Header.Set("Origin", u.Scheme+"://"+u.Host)
	}
	resp, err := client.Do(req)
	if err != nil {
		r.Error = err.Error()
		return r
	}
	defer resp.Body.Close()
	r.Code = resp.StatusCode
	if resp.StatusCode != http.StatusOK {
		r.Error = fmt.Sprintf("HTTP %d", resp.StatusCode)
		return r
	}
	r.OK = true
	return r
}

// DefaultClient returns an http.Client with a 30s timeout — long enough
// for a slow Recompile on the receiver, short enough that a hung peer
// doesn't pin the leader's push request indefinitely.
func DefaultClient() *http.Client {
	return &http.Client{Timeout: 30 * time.Second}
}
