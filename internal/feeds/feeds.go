// Package feeds manages third-party IP blocklists ("feeds") the same way
// internal/geo manages country lists: fetch, cache, render an ipset-restore
// file the compiler loads, keep working from the cache when the network
// does not. A rule with source.type "feed" matches the resulting hash:net
// set, so one feed serves host, docker, inbound and outbound rules alike.
//
// Two properties are deliberate and load-bearing:
//
//   - The catalogue is fixed in code. There is no free URL field anywhere:
//     a feed decides what the firewall drops, and a URL the operator (or a
//     compromised session) can edit would turn that decision over to
//     whoever controls the far end.
//   - Special-use ranges are always removed before rendering, no option to
//     keep them. Measured on 2026-09-05: firehol_level1 ships "fullbogons",
//     i.e. 10/8, 172.16/12, 192.168/16, 100.64/10 (Tailscale's range),
//     127/8, 169.254/16, 224/3 and 0/8. Loaded verbatim as a src match on
//     ZFW-IN, that feed drops every LAN and every Tailscale packet — the
//     exact lockout ZFW exists to prevent.
package feeds

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Feed is one pinned blocklist source.
type Feed struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	URL     string `json:"url"`
	License string `json:"license"`
	// MinEntries / MaxEntries bound a fetched payload. Below the floor the
	// list is refused (a 200 with an error page, a truncated download);
	// above the ceiling it is refused too (a list that has grown into
	// something else, or a response that is not this list at all). The
	// cache survives either way.
	MinEntries int `json:"min_entries"`
	MaxEntries int `json:"max_entries"`
}

// Catalogue lists every feed ZFW knows. Bounds were set from the lists as
// measured on 2026-09-05 (firehol_level1: 4658 entries, spamhaus_drop:
// 1709) with generous headroom.
var Catalogue = []Feed{
	{
		ID: "firehol_level1", Name: "FireHOL Level 1",
		URL:        "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset",
		License:    "Compiled by FireHOL from public sources (Spamhaus DROP, DShield, Feodo, bogons); see iplists.firehol.org",
		MinEntries: 1000, MaxEntries: 50000,
	},
	{
		ID: "spamhaus_drop", Name: "Spamhaus DROP",
		URL:        "https://www.spamhaus.org/drop/drop.txt",
		License:    "The Spamhaus Project — free for non-commercial use, see spamhaus.org/drop",
		MinEntries: 200, MaxEntries: 20000,
	},
}

// Lookup returns the catalogue entry for id.
func Lookup(id string) (Feed, bool) {
	for _, f := range Catalogue {
		if f.ID == id {
			return f, true
		}
	}
	return Feed{}, false
}

// idRe is the shape of a feed id. It is also what makes an id safe to use
// in a file name and an ipset name: no separators, no dots, bounded.
var idRe = regexp.MustCompile(`^[a-z0-9_]{1,32}$`)

// IsValidID reports whether id is well-formed AND in the catalogue.
func IsValidID(id string) bool {
	if !idRe.MatchString(id) {
		return false
	}
	_, ok := Lookup(id)
	return ok
}

// SetName is the ipset name for a feed. ipset caps names at 31 bytes;
// "zfw-feed-" is 9, the id at most 32 — so the id is truncated to 22 here,
// which the catalogue ids never reach.
func SetName(id string) string {
	if len(id) > 22 {
		id = id[:22]
	}
	return "zfw-feed-" + id
}

// maxAge is how long a cached list is considered fresh by Ensure (the apply
// path). The periodic refresh has its own cadence.
const maxAge = 24 * time.Hour

// neverBlock lists the special-use ranges that are removed from every feed
// before it is rendered. Not configurable: an operator who wants to block
// their own LAN can write that rule explicitly; a feed must not be able to
// do it by accident. Entries are checked both ways — a feed entry that
// contains one of these (e.g. 0.0.0.0/0) or lies inside one (192.168.1.0/24)
// is dropped.
var neverBlock = mustCIDRs(
	"0.0.0.0/8",      // "this" network
	"10.0.0.0/8",     // RFC 1918
	"100.64.0.0/10",  // CGNAT, and Tailscale's address space
	"127.0.0.0/8",    // loopback
	"169.254.0.0/16", // link-local
	"172.16.0.0/12",  // RFC 1918
	"192.168.0.0/16", // RFC 1918
	"224.0.0.0/4",    // multicast
	"240.0.0.0/4",    // reserved, incl. broadcast
	"255.255.255.255/32",
)

func mustCIDRs(ss ...string) []*net.IPNet {
	out := make([]*net.IPNet, 0, len(ss))
	for _, s := range ss {
		_, n, err := net.ParseCIDR(s)
		if err != nil {
			panic(err)
		}
		out = append(out, n)
	}
	return out
}

// Manager caches feed data and renders ipset-restore files.
type Manager struct {
	dir string
	cli *http.Client
	// Source maps a catalogue entry to the URL fetched. Defaults to the
	// entry's own URL; tests point it at an httptest server.
	Source func(Feed) string

	mu        sync.Mutex
	protected []*net.IPNet            // host-specific never-block ranges, see Protect
	lastKept  map[string][]*net.IPNet // per feed, what the last render put in the set
}

// Protect sets the host-specific ranges that are removed from every feed on
// top of the built-in special-use list: the host's own LAN and address, and
// the peers it syncs rules with. A feed that happened to list the operator's
// own public /24 would otherwise lock the operator out with a green apply.
// Entries are CIDRs or bare IPs; anything else is ignored. The list is
// replaced, not merged, so a LAN that changed in rules.json does not keep
// its predecessor protected forever. Safe for concurrent use: the periodic
// refresh and a rules POST may render at the same time.
func (m *Manager) Protect(cidrs []string) {
	var nets []*net.IPNet
	for _, s := range cidrs {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if !strings.Contains(s, "/") {
			s += "/32"
		}
		if ip, n, err := net.ParseCIDR(s); err == nil && ip.To4() != nil {
			nets = append(nets, n)
		}
	}
	m.mu.Lock()
	m.protected = nets
	m.mu.Unlock()
}

func (m *Manager) protectedNets() []*net.IPNet {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]*net.IPNet(nil), m.protected...)
}

// New returns a Manager rooted at dir (created on first Ensure, mode 0700).
func New(dir string) *Manager {
	return &Manager{dir: dir, cli: &http.Client{
		Timeout: 60 * time.Second,
		// Feeds are fetched from pinned hosts; a redirect to somewhere
		// else is not something to follow silently.
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return fmt.Errorf("too many redirects")
			}
			if req.URL.Scheme != "https" {
				return fmt.Errorf("redirect to non-https %s refused", req.URL)
			}
			return nil
		},
	}, Source: func(f Feed) string { return f.URL }, lastKept: map[string][]*net.IPNet{}}
}

func (m *Manager) listPath(id string) string  { return filepath.Join(m.dir, id+".list") }
func (m *Manager) ipsetPath(id string) string { return filepath.Join(m.dir, id+".ipset") }
func (m *Manager) metaPath(id string) string  { return filepath.Join(m.dir, id+".meta.json") }

// IpsetPath is the ipset-restore file the compiler loads for a feed.
func (m *Manager) IpsetPath(id string) string { return m.ipsetPath(id) }

// Meta is what the last render recorded about a feed — the status card's
// source of truth, written next to the ipset file.
type Meta struct {
	ID       string    `json:"id"`
	Fetched  time.Time `json:"fetched"`  // mtime of the cached list
	Rendered time.Time `json:"rendered"` // when the ipset file was written
	Entries  int       `json:"entries"`  // networks in the set
	Dropped  int       `json:"dropped"`  // entries removed by the built-in special-use list
	// Protected counts entries removed because they overlap a host-specific
	// range set via Protect (own LAN, own address, peers).
	Protected int `json:"protected"`
}

// Ensure makes sure each feed's list is cached and its ipset-restore file is
// current. A network error is tolerated when a cache already exists, and an
// unknown or malformed id is an error before anything touches the network.
func (m *Manager) Ensure(ctx context.Context, ids []string, logf func(string, ...any)) error {
	if err := os.MkdirAll(m.dir, 0o700); err != nil {
		return err
	}
	for _, id := range ids {
		f, ok := Lookup(strings.TrimSpace(id))
		if !ok || !idRe.MatchString(f.ID) {
			return fmt.Errorf("feed %q: not in the catalogue", id)
		}
		list := m.listPath(f.ID)
		fresh := false
		if fi, err := os.Stat(list); err == nil && time.Since(fi.ModTime()) < maxAge {
			fresh = true
		}
		if !fresh {
			if err := m.fetch(ctx, f); err != nil {
				if _, statErr := os.Stat(list); statErr != nil {
					return fmt.Errorf("feed %s: no cache and download failed: %w", f.ID, err)
				}
				if logf != nil {
					logf("feeds: %s — update failed, using cache: %v", f.ID, err)
				}
			}
		}
		if _, err := m.render(f); err != nil {
			return fmt.Errorf("feed %s: %w", f.ID, err)
		}
	}
	return nil
}

// fetch downloads a feed into the cache. The payload must parse to a number
// of entries inside the feed's bounds before it may replace the cache.
func (m *Manager) fetch(ctx context.Context, f Feed) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, m.Source(f), nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "zfw-feeds/1 (+https://github.com/chicohaager/zfw)")
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
	n := len(parseEntries(body))
	if n < f.MinEntries || n > f.MaxEntries {
		return fmt.Errorf("response has %d entries, outside the feed's bounds [%d, %d] (%d bytes) — refusing to overwrite the cache with it",
			n, f.MinEntries, f.MaxEntries, len(body))
	}
	tmp, err := os.CreateTemp(m.dir, f.ID+".list.*.tmp")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(body); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(name, m.listPath(f.ID))
}

// parseEntries extracts the networks from a feed body. Both formats seen in
// the wild are handled: FireHOL ("#" comments, one CIDR per line, an
// occasional bare IP) and Spamhaus ("; comment" lines and "CIDR ; SBLnnn"
// trailers). Anything that does not parse is skipped, never fatal — the
// bounds check in fetch is what decides whether the file is usable.
func parseEntries(body []byte) []*net.IPNet {
	var out []*net.IPNet
	for _, ln := range strings.Split(string(body), "\n") {
		ln = strings.TrimSpace(ln)
		if ln == "" || ln[0] == '#' || ln[0] == ';' {
			continue
		}
		if i := strings.IndexAny(ln, ";#"); i >= 0 {
			ln = strings.TrimSpace(ln[:i])
		}
		if i := strings.IndexAny(ln, " \t"); i >= 0 {
			ln = ln[:i]
		}
		if !strings.Contains(ln, "/") {
			ln += "/32"
		}
		ip, n, err := net.ParseCIDR(ln)
		if err != nil || ip.To4() == nil {
			continue // IPv6 feeds are a separate list; this set is family inet
		}
		out = append(out, n)
	}
	return out
}

// overlaps reports whether a and b share any address.
func overlaps(a, b *net.IPNet) bool {
	return a.Contains(b.IP) || b.Contains(a.IP)
}

// filtered drops every entry that overlaps a neverBlock range (counted in
// dropped) or one of the extra host-specific ranges (counted in protected).
func filtered(nets []*net.IPNet, extra ...*net.IPNet) (kept []*net.IPNet, dropped, protected int) {
next:
	for _, n := range nets {
		for _, nb := range neverBlock {
			if overlaps(n, nb) {
				dropped++
				continue next
			}
		}
		for _, ex := range extra {
			if overlaps(n, ex) {
				protected++
				continue next
			}
		}
		kept = append(kept, n)
	}
	return kept, dropped, protected
}

// render turns the cached list into an ipset-restore file for the apply
// path (create, flush, add — the same shape geo uses) and writes the meta
// sidecar. Returns the meta for callers that want the counts.
func (m *Manager) render(f Feed) (Meta, error) {
	body, err := os.ReadFile(m.listPath(f.ID))
	if err != nil {
		return Meta{}, err
	}
	fi, _ := os.Stat(m.listPath(f.ID))
	kept, dropped, protected := filtered(parseEntries(body), m.protectedNets()...)
	if len(kept) == 0 {
		return Meta{}, fmt.Errorf("no usable entries after filtering")
	}
	sort.Slice(kept, func(i, j int) bool { return kept[i].String() < kept[j].String() })
	if err := writeAtomic(m.dir, f.ID+".ipset", m.ipsetPath(f.ID), []byte(restoreText(SetName(f.ID), kept))); err != nil {
		return Meta{}, err
	}
	m.mu.Lock()
	m.lastKept[f.ID] = kept
	m.mu.Unlock()
	meta := Meta{ID: f.ID, Rendered: time.Now(), Entries: len(kept), Dropped: dropped, Protected: protected}
	if fi != nil {
		meta.Fetched = fi.ModTime()
	}
	b, _ := json.Marshal(meta)
	if err := writeAtomic(m.dir, f.ID+".meta.json", m.metaPath(f.ID), b); err != nil {
		return Meta{}, err
	}
	return meta, nil
}

// restoreText is the ipset-restore document for set holding kept: create,
// flush, add. The apply path loads it with `ipset restore -exist`, where
// the flush+add window does not matter (an apply is a disruption anyway);
// the live refresh loads it under a temporary name and swaps, because a
// flush+add on the live set is not atomic — measured: 111 000 of 200 000
// entries present mid-restore.
func restoreText(set string, kept []*net.IPNet) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "create %s hash:net family inet hashsize 4096 maxelem 262144 -exist\n", set)
	fmt.Fprintf(&sb, "flush %s\n", set)
	for _, n := range kept {
		fmt.Fprintf(&sb, "add %s %s\n", set, n.String())
	}
	return sb.String()
}

// tmpSetName is the scratch set a live refresh loads into before the swap.
// ipset names are capped at 31 bytes; "zfw-tmp-" is 8, the id at most 22.
func tmpSetName(id string) string {
	if len(id) > 22 {
		id = id[:22]
	}
	return "zfw-tmp-" + id
}

// Runner executes one ipset invocation (args without the binary) and returns
// its combined output. Injected so tests can record the sequence instead
// of needing root and a kernel.
type Runner func(ctx context.Context, args ...string) (string, error)

// Refresh re-fetches each feed (tolerating a failure when a cache exists),
// re-renders its ipset file for the next apply, and — when the feed's set is
// live in the kernel — replaces the live content without touching a single
// iptables rule: load into a temporary set, swap, destroy the temporary
// one. Nothing here recompiles or applies; the firewall's rules are exactly
// what they were before. A feed whose set is not live (rules never applied)
// only gets its file updated.
func (m *Manager) Refresh(ctx context.Context, ids []string, run Runner, logf func(string, ...any)) error {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	if err := os.MkdirAll(m.dir, 0o700); err != nil {
		return err
	}
	var firstErr error
	note := func(err error) {
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}
	for _, id := range ids {
		f, ok := Lookup(strings.TrimSpace(id))
		if !ok {
			note(fmt.Errorf("feed %q: not in the catalogue", id))
			continue
		}
		if err := m.fetch(ctx, f); err != nil {
			if _, statErr := os.Stat(m.listPath(f.ID)); statErr != nil {
				note(fmt.Errorf("feed %s: no cache and download failed: %w", f.ID, err))
				continue
			}
			logf("feeds: %s — refresh download failed, keeping cache: %v", f.ID, err)
		}
		meta, err := m.render(f)
		if err != nil {
			note(fmt.Errorf("feed %s: %w", f.ID, err))
			continue
		}
		if err := m.swapLive(ctx, f.ID, run, logf); err != nil {
			note(fmt.Errorf("feed %s: %w", f.ID, err))
			continue
		}
		logf("feeds: %s refreshed — %d networks (%d special-use and %d host-specific entries removed)",
			f.ID, meta.Entries, meta.Dropped, meta.Protected)
	}
	return firstErr
}

// swapLive replaces the live set's content via a temporary set. Skips
// silently when the set is not loaded.
func (m *Manager) swapLive(ctx context.Context, id string, run Runner, logf func(string, ...any)) error {
	set, tmp := SetName(id), tmpSetName(id)
	if _, err := run(ctx, "-q", "list", "-n", set); err != nil {
		logf("feeds: %s — set %s not live, file updated for the next apply", id, set)
		return nil
	}
	m.mu.Lock()
	kept := m.lastKept[id]
	m.mu.Unlock()
	if len(kept) == 0 {
		return fmt.Errorf("nothing rendered to swap in")
	}
	doc, err := os.CreateTemp(m.dir, id+".swap.*.tmp")
	if err != nil {
		return err
	}
	docPath := doc.Name()
	defer os.Remove(docPath)
	if err := doc.Chmod(0o600); err != nil {
		doc.Close()
		return err
	}
	if _, err := doc.WriteString(restoreText(tmp, kept)); err != nil {
		doc.Close()
		return err
	}
	if err := doc.Close(); err != nil {
		return err
	}
	if out, err := run(ctx, "restore", "-exist", "-f", docPath); err != nil {
		_, _ = run(ctx, "-q", "destroy", tmp)
		return fmt.Errorf("load temporary set: %w (%s)", err, strings.TrimSpace(out))
	}
	if out, err := run(ctx, "swap", tmp, set); err != nil {
		_, _ = run(ctx, "-q", "destroy", tmp)
		return fmt.Errorf("swap: %w (%s)", err, strings.TrimSpace(out))
	}
	if out, err := run(ctx, "destroy", tmp); err != nil {
		// The swap already succeeded; the leftover set only holds the old
		// content. Say so rather than fail the refresh.
		logf("feeds: %s — temporary set %s not destroyed after swap: %v (%s)", id, tmp, err, strings.TrimSpace(out))
	}
	return nil
}

// writeAtomic publishes content at dst via a unique temp file and rename,
// so a concurrent reader never sees a torn file.
func writeAtomic(dir, prefix, dst string, content []byte) error {
	tmp, err := os.CreateTemp(dir, prefix+".*.tmp")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(content); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(name, dst)
}

// Info returns what the last render recorded for a feed, or ok=false when
// the feed has never been rendered on this host.
func (m *Manager) Info(id string) (Meta, bool) {
	b, err := os.ReadFile(m.metaPath(id))
	if err != nil {
		return Meta{}, false
	}
	var meta Meta
	if json.Unmarshal(b, &meta) != nil {
		return Meta{}, false
	}
	return meta, true
}

// LiveEntries asks the kernel how many networks the feed's set holds right
// now (ok=false when the set is not loaded). "Number of entries" is the
// line `ipset list -t` prints for every set type.
func LiveEntries(ctx context.Context, run Runner, id string) (int, bool) {
	out, err := run(ctx, "-q", "list", "-t", SetName(id))
	if err != nil {
		return 0, false
	}
	for _, ln := range strings.Split(out, "\n") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(ln), "Number of entries:"); ok {
			n, err := strconv.Atoi(strings.TrimSpace(v))
			return n, err == nil
		}
	}
	return 0, false
}
