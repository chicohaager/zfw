// Package geo manages per-country IP-range data for firewall geo-blocking.
// It fetches aggregated CIDR lists, caches them, and renders ipset-restore
// files the engine loads into hash:net sets.
package geo

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// ipdeny publishes free aggregated per-country zone files (one CIDR per line).
const sourceURL = "https://www.ipdeny.com/ipblocks/data/aggregated/%s-aggregated.zone"

// maxAge is how long a cached country file is considered fresh.
const maxAge = 30 * 24 * time.Hour

// Manager caches country IP data and renders ipset-restore files.
type Manager struct {
	dir string
	cli *http.Client
}

// New returns a Manager storing data under dir (e.g. /DATA/zfw/geo).
func New(dir string) *Manager {
	return &Manager{dir: dir, cli: &http.Client{Timeout: 30 * time.Second}}
}

// SetName is the ipset name for a country code.
func SetName(cc string) string { return "zfw-cc-" + strings.ToLower(strings.TrimSpace(cc)) }

func (m *Manager) zonePath(cc string) string {
	return filepath.Join(m.dir, strings.ToLower(cc)+".zone")
}
func (m *Manager) ipsetPath(cc string) string {
	return filepath.Join(m.dir, strings.ToLower(cc)+".ipset")
}

// IpsetPath is the ipset-restore file path for a country code.
func (m *Manager) IpsetPath(cc string) string { return m.ipsetPath(cc) }

// Ensure makes sure each country's data is cached and its ipset-restore file
// is current. A network error is tolerated when a cache already exists.
func (m *Manager) Ensure(ctx context.Context, codes []string, logf func(string, ...any)) error {
	if err := os.MkdirAll(m.dir, 0o700); err != nil {
		return err
	}
	for _, raw := range codes {
		cc := strings.ToLower(strings.TrimSpace(raw))
		if cc == "" {
			continue
		}
		zone := m.zonePath(cc)
		fresh := false
		if fi, err := os.Stat(zone); err == nil && time.Since(fi.ModTime()) < maxAge {
			fresh = true
		}
		if !fresh {
			if err := m.fetch(ctx, cc); err != nil {
				if _, statErr := os.Stat(zone); statErr != nil {
					return fmt.Errorf("Land %s: kein Cache und Download fehlgeschlagen: %w", cc, err)
				}
				if logf != nil {
					logf("geo: %s — Update fehlgeschlagen, nutze Cache: %v", cc, err)
				}
			}
		}
		if err := m.renderIpset(cc); err != nil {
			return fmt.Errorf("Land %s: %w", cc, err)
		}
	}
	return nil
}

func (m *Manager) fetch(ctx context.Context, cc string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf(sourceURL, cc), nil)
	if err != nil {
		return err
	}
	resp, err := m.cli.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return err
	}
	if len(body) == 0 {
		return fmt.Errorf("leere Antwort")
	}
	tmp := m.zonePath(cc) + ".tmp"
	if err := os.WriteFile(tmp, body, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, m.zonePath(cc))
}

// renderIpset turns the cached zone file into an ipset-restore script. Lines
// that are not valid CIDRs are skipped so a stray line cannot abort the load.
func (m *Manager) renderIpset(cc string) error {
	b, err := os.ReadFile(m.zonePath(cc))
	if err != nil {
		return err
	}
	set := SetName(cc)
	var sb strings.Builder
	fmt.Fprintf(&sb, "create %s hash:net family inet hashsize 4096 maxelem 262144 -exist\n", set)
	fmt.Fprintf(&sb, "flush %s\n", set)
	n := 0
	for _, ln := range strings.Split(string(b), "\n") {
		ln = strings.TrimSpace(ln)
		if ln == "" || strings.HasPrefix(ln, "#") {
			continue
		}
		if _, _, err := net.ParseCIDR(ln); err != nil {
			continue
		}
		fmt.Fprintf(&sb, "add %s %s\n", set, ln)
		n++
	}
	if n == 0 {
		return fmt.Errorf("keine gültigen CIDR-Einträge")
	}
	tmp := m.ipsetPath(cc) + ".tmp"
	if err := os.WriteFile(tmp, []byte(sb.String()), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, m.ipsetPath(cc))
}
