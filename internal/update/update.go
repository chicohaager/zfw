// Package update polls a remote manifest URL for newer zfw releases and
// caches the result so the UI can surface a non-blocking "update available"
// badge on the Versions tab.
//
// The manifest is a tiny JSON document:
//
//	{ "version": "0.3.9", "notes": "second v0.5 batch" }
//
// Disabled by default (empty URL — opt-in via ZFW_UPDATE_URL) so a fresh
// install makes no outbound network calls before the user asks for them.
// Once a Mod-Store distribution channel exists in v0.5, the default URL
// can be wired in without code changes here.
package update

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/chicohaager/zfw/internal/httputil"
)

// Manifest is the on-network shape of a release manifest.
type Manifest struct {
	Version string `json:"version"`
	Notes   string `json:"notes,omitempty"`
}

// Status is the cached result of the last update check. Exposed via
// /api/update so the UI can render a "vX available" badge.
type Status struct {
	Current   string    `json:"current"`
	Latest    string    `json:"latest,omitempty"`
	Available bool      `json:"available"`
	Notes     string    `json:"notes,omitempty"`
	CheckedAt time.Time `json:"checked_at,omitempty"`
	// Error carries the last network/parse failure, if any. The badge is
	// hidden on error — silently degrade rather than confronting the user
	// with daemon-internal HTTP errors.
	Error string `json:"error,omitempty"`
}

// Checker holds the cached status and the daemon-owned configuration.
type Checker struct {
	mu      sync.RWMutex
	last    Status
	current string
	url     string
	client  *http.Client
}

// New returns a Checker. current is the daemon's own version (from
// buildinfo.Version). url is the manifest URL; an empty url disables
// the checker (Disabled() reports true, CheckOnce is a no-op).
//
// R4-7 (v1.0.2): the http.Client refuses cross-scheme downgrade and
// public→private/loopback redirects so an attacker who controls DNS for
// the operator-set URL cannot coerce the daemon into hitting a local
// service via a redirect chain.
func New(current, url string) *Checker {
	return &Checker{
		current: current,
		url:     url,
		client: &http.Client{
			Timeout:       10 * time.Second,
			CheckRedirect: httputil.SafeCheckRedirect(5),
		},
		last: Status{Current: current},
	}
}

// Disabled reports whether the checker has no URL configured.
func (c *Checker) Disabled() bool { return c.url == "" }

// Snapshot returns the most recent cached status. Safe for concurrent use.
func (c *Checker) Snapshot() Status {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.last
}

// CheckOnce fetches the manifest and updates the cache. Safe to call
// concurrently with Snapshot. On any failure the cache carries the
// previous Latest/Available values plus an Error string so the UI can
// distinguish "no update" from "couldn't reach the manifest URL".
func (c *Checker) CheckOnce(ctx context.Context) {
	if c.Disabled() {
		return
	}
	s := c.Snapshot()
	s.Current = c.current
	s.CheckedAt = time.Now()
	s.Error = ""

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.url, nil)
	if err != nil {
		s.Error = err.Error()
		c.set(s)
		return
	}
	resp, err := c.client.Do(req)
	if err != nil {
		s.Error = err.Error()
		c.set(s)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		s.Error = fmt.Sprintf("manifest HTTP %d", resp.StatusCode)
		c.set(s)
		return
	}
	var m Manifest
	if err := json.NewDecoder(resp.Body).Decode(&m); err != nil {
		s.Error = "manifest parse: " + err.Error()
		c.set(s)
		return
	}
	if m.Version == "" {
		s.Error = "manifest has no version field"
		c.set(s)
		return
	}
	s.Latest = m.Version
	s.Notes = m.Notes
	s.Available = Compare(c.current, m.Version) < 0
	c.set(s)
}

// Run kicks off a goroutine that calls CheckOnce immediately and then on
// every tick of interval. Stops when ctx is cancelled. A disabled checker
// (no URL) returns immediately without starting the goroutine.
func (c *Checker) Run(ctx context.Context, interval time.Duration) {
	if c.Disabled() {
		return
	}
	go func() {
		c.CheckOnce(ctx)
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				c.CheckOnce(ctx)
			}
		}
	}()
}

func (c *Checker) set(s Status) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.last = s
}

// Compare returns -1, 0 or +1 for semver-ish strings a vs b. It tolerates
// a leading "v" and trims any "-suffix" / "+suffix" (e.g. "-dev", "+build").
// Non-numeric components compare as 0. Missing trailing components are
// treated as 0 ("0.3" == "0.3.0").
//
// CQ-12 (documented v1.0.2): the suffix-stripping means
// Compare("1.2.3", "1.2.3-rc1") returns 0, NOT +1 — i.e. a -rc tag is
// treated as equal to its released form. Strictly this is wrong for
// semver pre-release ordering, but the release flow never ships -rc
// tags (the manifest only lists final releases) so the inaccuracy has
// no operational effect today. If a future release pipeline starts
// publishing -rc manifests, this function must be revisited so an
// installed -rc does not silently mark itself current vs the GA tag.
// TestCompareTreatsPreReleaseAsEqual pins the current behaviour.
func Compare(a, b string) int {
	pa := parts(a)
	pb := parts(b)
	n := len(pa)
	if len(pb) > n {
		n = len(pb)
	}
	for i := 0; i < n; i++ {
		var x, y int
		if i < len(pa) {
			x = pa[i]
		}
		if i < len(pb) {
			y = pb[i]
		}
		if x < y {
			return -1
		}
		if x > y {
			return +1
		}
	}
	return 0
}

func parts(v string) []int {
	v = strings.TrimPrefix(v, "v")
	if i := strings.IndexAny(v, "-+"); i >= 0 {
		v = v[:i]
	}
	raw := strings.Split(v, ".")
	out := make([]int, len(raw))
	for i, s := range raw {
		n, _ := strconv.Atoi(s)
		out[i] = n
	}
	return out
}
