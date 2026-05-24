// Package geo manages per-country IP-range data for firewall geo-blocking.
// It fetches aggregated CIDR lists, caches them, and renders ipset-restore
// files the engine loads into hash:net sets.
//
// v0.4.5 added IP→country reverse lookup (Manager.Lookup) reusing the
// same on-disk .zone files. The index is built lazily on first call and
// rebuilt when any .zone file's mtime changes. Countries the user has
// not configured rules for are not in the index — Lookup returns "" for
// those IPs and the UI silently hides the flag. This is the
// fundamental trade-off vs. carrying a full GeoLite2 MMDB: the index
// is whatever the user's geo-block rules already pulled, no extra
// downloads, no extra deps.
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
	"sync"
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

	// Reverse-lookup index (v0.4.5). Built lazily on first Lookup;
	// rebuilt when the directory's fingerprint (file count + sum of
	// mtimes) changes. Fingerprint beats "newest mtime > built-at"
	// because filesystem mtime resolution is 1s on many setups —
	// adding a new .zone in the same second as the first build would
	// otherwise be missed.
	indexMu      sync.RWMutex
	indexEntries []indexEntry
	indexFP      string
}

// indexEntry is one CIDR/country pair in the reverse-lookup index.
type indexEntry struct {
	net *net.IPNet
	cc  string // lowercase ISO-3166 alpha-2
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
					return fmt.Errorf("country %s: no cache and download failed: %w", cc, err)
				}
				if logf != nil {
					logf("geo: %s — Update fehlgeschlagen, nutze Cache: %v", cc, err)
				}
			}
		}
		if err := m.renderIpset(cc); err != nil {
			return fmt.Errorf("country %s: %w", cc, err)
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
		return fmt.Errorf("empty response")
	}
	tmp := m.zonePath(cc) + ".tmp"
	if err := os.WriteFile(tmp, body, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, m.zonePath(cc))
}

// Lookup returns the lowercase ISO-3166 alpha-2 country code for ip, or
// "" when no cached .zone file claims it. Triggers a lazy index build
// on first call; subsequent calls reuse the index until any .zone
// mtime is newer than indexBuiltAt. Safe for concurrent use.
func (m *Manager) Lookup(ip net.IP) string {
	if ip == nil {
		return ""
	}
	m.ensureIndex()
	m.indexMu.RLock()
	defer m.indexMu.RUnlock()
	for _, e := range m.indexEntries {
		if e.net.Contains(ip) {
			return e.cc
		}
	}
	return ""
}

// LookupBatch resolves many IPs in one index pass. Strings that don't
// parse as IPs map to "" — callers can pass raw event sources without
// pre-filtering. The returned map always contains every input key so
// the UI can iterate it without nil checks.
func (m *Manager) LookupBatch(ips []string) map[string]string {
	out := make(map[string]string, len(ips))
	if len(ips) == 0 {
		return out
	}
	m.ensureIndex()
	m.indexMu.RLock()
	defer m.indexMu.RUnlock()
	for _, raw := range ips {
		out[raw] = "" // default; overridden below on a hit
		parsed := net.ParseIP(strings.TrimSpace(raw))
		if parsed == nil {
			continue
		}
		for _, e := range m.indexEntries {
			if e.net.Contains(parsed) {
				out[raw] = e.cc
				break
			}
		}
	}
	return out
}

// ensureIndex rebuilds the in-memory CIDR table when the directory
// fingerprint changes. Cheap (one ReadDir) on hits, O(total CIDR count)
// on a rebuild. Failure to open the directory or a file leaves the
// index empty rather than erroring — the UI just doesn't show flags,
// which is the right degradation on a fresh install with no geo
// rules configured yet.
func (m *Manager) ensureIndex() {
	fp := m.zoneFingerprint()
	m.indexMu.RLock()
	stale := fp != m.indexFP
	m.indexMu.RUnlock()
	if !stale {
		return
	}
	m.indexMu.Lock()
	defer m.indexMu.Unlock()
	// Double-check after the lock upgrade — another goroutine may have
	// rebuilt while we waited.
	if fp == m.indexFP {
		return
	}
	m.indexEntries = m.buildIndex()
	m.indexFP = fp
}

// zoneFingerprint returns a short string that changes whenever the set
// or mtime of .zone files changes. Empty string when there are no zone
// files (the same value the empty initial state carries, so the empty
// → still-empty transition does not trigger a rebuild).
func (m *Manager) zoneFingerprint() string {
	ents, err := os.ReadDir(m.dir)
	if err != nil {
		return ""
	}
	var parts []string
	for _, ent := range ents {
		if ent.IsDir() || !strings.HasSuffix(ent.Name(), ".zone") {
			continue
		}
		fi, err := ent.Info()
		if err != nil {
			continue
		}
		// name + size + mtime captures "file added, removed, modified
		// or grew/shrunk" without depending on sub-second mtime
		// resolution alone.
		parts = append(parts, fmt.Sprintf("%s:%d:%d",
			ent.Name(), fi.Size(), fi.ModTime().UnixNano()))
	}
	return strings.Join(parts, "|")
}

func (m *Manager) buildIndex() []indexEntry {
	ents, err := os.ReadDir(m.dir)
	if err != nil {
		return nil
	}
	var out []indexEntry
	for _, ent := range ents {
		if ent.IsDir() || !strings.HasSuffix(ent.Name(), ".zone") {
			continue
		}
		cc := strings.TrimSuffix(ent.Name(), ".zone")
		if len(cc) != 2 {
			continue
		}
		b, err := os.ReadFile(filepath.Join(m.dir, ent.Name()))
		if err != nil {
			continue
		}
		for _, ln := range strings.Split(string(b), "\n") {
			ln = strings.TrimSpace(ln)
			if ln == "" || strings.HasPrefix(ln, "#") {
				continue
			}
			_, n, err := net.ParseCIDR(ln)
			if err != nil {
				continue
			}
			out = append(out, indexEntry{net: n, cc: cc})
		}
	}
	return out
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
		return fmt.Errorf("no valid CIDR entries")
	}
	tmp := m.ipsetPath(cc) + ".tmp"
	if err := os.WriteFile(tmp, []byte(sb.String()), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, m.ipsetPath(cc))
}
