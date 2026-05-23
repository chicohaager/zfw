// Package gateway registers this daemon's API route with the ZimaOS
// (CasaOS) gateway. The gateway is a Caddy-based reverse proxy on port 80;
// backend services bind to 127.0.0.1 and register a route so the Web UI
// reaches them same-origin via port 80 — the same pattern the zima_cron and
// zima_vm_extras modules use. This keeps the daemon off the LAN entirely.
package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// route is the JSON shape the gateway management API expects, confirmed
// against `GET /v1/gateway/routes` on ZimaOS 1.6.1.
type route struct {
	Path   string `json:"path"`
	Target string `json:"target"`
}

// Manager registers a single reverse-proxy route with the ZimaOS gateway.
type Manager struct {
	URLFile string // path to management.url, e.g. /var/run/casaos/management.url
	Path    string // route path to register, e.g. /v2/zfw
	Target  string // proxy destination, e.g. http://127.0.0.1:8489
	http    *http.Client
}

// New returns a Manager. urlFile holds the gateway management base URL.
func New(urlFile, path, target string) *Manager {
	return &Manager{
		URLFile: urlFile,
		Path:    path,
		Target:  target,
		http:    &http.Client{Timeout: 5 * time.Second},
	}
}

// mgmtURL reads and normalises the gateway management base URL.
func (m *Manager) mgmtURL() (string, error) {
	b, err := os.ReadFile(m.URLFile)
	if err != nil {
		return "", err
	}
	u := strings.TrimSpace(string(b))
	if u == "" {
		return "", fmt.Errorf("%s is empty", m.URLFile)
	}
	if !strings.HasPrefix(u, "http://") && !strings.HasPrefix(u, "https://") {
		u = "http://" + u
	}
	return strings.TrimRight(u, "/"), nil
}

// Register upserts the route. The gateway keys routes by path, so calling
// this repeatedly is safe and idempotent.
func (m *Manager) Register() error {
	base, err := m.mgmtURL()
	if err != nil {
		return err
	}
	body, _ := json.Marshal(route{Path: m.Path, Target: m.Target})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/v1/gateway/routes", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := m.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(resp.Body)
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("gateway register %s: HTTP %d: %s",
			m.Path, resp.StatusCode, strings.TrimSpace(string(rb)))
	}
	return nil
}

// LookupTarget returns the proxy target the gateway has registered for the
// given route path (e.g. "/.well-known/jwks.json"), so the daemon need not
// hard-code platform service ports.
func (m *Manager) LookupTarget(ctx context.Context, path string) (string, error) {
	base, err := m.mgmtURL()
	if err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/v1/gateway/routes", nil)
	if err != nil {
		return "", err
	}
	resp, err := m.http.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return "", fmt.Errorf("gateway routes: HTTP %d", resp.StatusCode)
	}
	var routes []route
	if err := json.NewDecoder(resp.Body).Decode(&routes); err != nil {
		return "", err
	}
	for _, rt := range routes {
		if rt.Path == path {
			return rt.Target, nil
		}
	}
	return "", fmt.Errorf("route %q not registered", path)
}

// RegisterWithRetry keeps trying Register until it succeeds or ctx is done,
// then re-registers every 5 minutes so the route survives a gateway restart
// (which drops all registered routes). Register() is idempotent.
func (m *Manager) RegisterWithRetry(ctx context.Context, logf func(string, ...any)) {
	delay := 2 * time.Second
	const maxDelay = 30 * time.Second
	for {
		if err := m.Register(); err == nil {
			if logf != nil {
				logf("gateway route registered: %s -> %s", m.Path, m.Target)
			}
			break
		} else if logf != nil {
			logf("gateway route registration failed (retry in %s): %v", delay, err)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(delay):
			if delay < maxDelay {
				delay *= 2
			}
		}
	}

	t := time.NewTicker(5 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := m.Register(); err != nil && logf != nil {
				logf("gateway route re-registration failed: %v", err)
			}
		}
	}
}
