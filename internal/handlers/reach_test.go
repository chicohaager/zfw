package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/chicohaager/zfw/internal/feeds"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/chicohaager/zfw/internal/firewall"
	"github.com/chicohaager/zfw/internal/rules"
	"github.com/chicohaager/zfw/internal/system"
)

// The Exposure and Audit tabs judge "is this port reachable" and must do so
// from rules.json — the file the firewall is compiled from. Until v1.0.25 they
// read the legacy allowlist.conf, which the UI stopped writing when the rules
// tab replaced it: on a v1.x install the file does not exist, LoadConfig
// fails, the empty config made every host socket "blocked" and every
// port-based audit finding "mitigated" as soon as the firewall was active,
// whatever the rules said. These tests build exactly that world — no
// allowlist.conf, a rule set that allows some ports — and assert that the
// verdicts follow the rules.

func reachRules() rules.RuleSet {
	return rules.RuleSet{
		DefaultPolicy: "deny",
		Rules: []rules.Rule{
			{ID: "r1", Order: 10, Enabled: true, Name: "ssh", Action: "allow",
				Source: rules.Source{Type: "any"}, Ports: rules.Ports{Type: "list", List: []int{22}},
				Protocol: "tcp", Zone: "host"},
			{ID: "r2", Order: 20, Enabled: true, Name: "jellyfin", Action: "allow",
				Source: rules.Source{Type: "any"}, Ports: rules.Ports{Type: "list", List: []int{8096}},
				Protocol: "tcp", Zone: "docker"},
			{ID: "r3", Order: 30, Enabled: false, Name: "disabled vnc", Action: "allow",
				Source: rules.Source{Type: "any"}, Ports: rules.Ports{Type: "list", List: []int{5900}},
				Protocol: "tcp", Zone: "host"},
		},
	}
}

func reachSockets() []system.Socket {
	return []system.Socket{
		{Port: 22, Bind: "0.0.0.0", Proc: "sshd", Scope: "all"},
		{Port: 5900, Bind: "0.0.0.0", Proc: "qemu", Scope: "all"},
		{Port: 8096, Bind: "0.0.0.0", Proc: "docker-proxy", Scope: "all"},
		{Port: 8888, Bind: "0.0.0.0", Proc: "docker-proxy", Scope: "all"},
		{Port: 8489, Bind: "127.0.0.1", Proc: "zfwd", Scope: "local"},
	}
}

func exposureReach(t *testing.T, s *Server) map[int]string {
	t.Helper()
	w := do(s, http.MethodGet, "/api/exposure", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("exposure: HTTP %d (body=%s)", w.Code, w.Body.String())
	}
	var got []struct {
		Port  int    `json:"port"`
		Reach string `json:"reach"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	out := map[int]string{}
	for _, e := range got {
		out[e.Port] = e.Reach
	}
	return out
}

func TestExposureJudgesReachFromRulesNotLegacyConfig(t *testing.T) {
	// No allowlist.conf: LoadConfig fails, exactly as on every v1.x install.
	fw := &fakeFirewall{status: firewall.Status{Active: true, Hooked: true},
		loadErr: errors.New("open allowlist.conf: no such file")}
	s, rulesPath := newTestServer(t, fw)
	if err := rules.Save(rulesPath, reachRules()); err != nil {
		t.Fatal(err)
	}
	s.listening = func(context.Context) ([]system.Socket, error) { return reachSockets(), nil }

	got := exposureReach(t, s)
	want := map[int]string{
		22:   "lan",     // allowed by r1
		5900: "blocked", // r3 is disabled; default deny
		8096: "lan",     // docker-proxy, allowed by r2
		8888: "blocked", // docker-proxy, no rule
		8489: "local",   // loopback is never "lan" or "blocked"
	}
	for port, w := range want {
		if got[port] != w {
			t.Errorf("port %d: reach=%q, want %q (rules must decide, not allowlist.conf)", port, got[port], w)
		}
	}
}

// With the firewall off nothing is blocked, whatever the rules say — the
// rules are not live.
func TestExposureInactiveFirewallBlocksNothing(t *testing.T) {
	fw := &fakeFirewall{loadErr: errors.New("no allowlist.conf")}
	s, rulesPath := newTestServer(t, fw)
	if err := rules.Save(rulesPath, reachRules()); err != nil {
		t.Fatal(err)
	}
	s.listening = func(context.Context) ([]system.Socket, error) { return reachSockets(), nil }
	for port, reach := range exposureReach(t, s) {
		if reach == "blocked" {
			t.Errorf("port %d reported blocked while the firewall is inactive", port)
		}
	}
}

// Default-policy allow flips the reading: everything is reachable unless a
// rule denies it.
func TestExposureAllowPolicyOnlyBlocksExplicitDenies(t *testing.T) {
	fw := &fakeFirewall{status: firewall.Status{Active: true, Hooked: true},
		loadErr: errors.New("no allowlist.conf")}
	s, rulesPath := newTestServer(t, fw)
	rs := rules.RuleSet{DefaultPolicy: "allow", Rules: []rules.Rule{
		{ID: "d1", Order: 10, Enabled: true, Name: "no vnc", Action: "deny",
			Source: rules.Source{Type: "any"}, Ports: rules.Ports{Type: "range", From: 5900, To: 5999},
			Protocol: "tcp", Zone: "host"},
	}}
	if err := rules.Save(rulesPath, rs); err != nil {
		t.Fatal(err)
	}
	s.listening = func(context.Context) ([]system.Socket, error) { return reachSockets(), nil }
	got := exposureReach(t, s)
	if got[5900] != "blocked" {
		t.Errorf("5900: reach=%q, want blocked (explicit deny under allow policy)", got[5900])
	}
	for _, p := range []int{22, 8096, 8888} {
		if got[p] != "lan" {
			t.Errorf("%d: reach=%q, want lan (allow policy, no deny rule)", p, got[p])
		}
	}
}

// A host that never migrated (allowlist.conf present, no rules.json) keeps
// the legacy reading rather than being judged deny-everything.
func TestExposureFallsBackToLegacyConfigWithoutRules(t *testing.T) {
	fw := &fakeFirewall{status: firewall.Status{Active: true, Hooked: true},
		conf: firewall.Config{HostTCPLAN: []string{"22"}, DockerDropLAN: []string{"8888"}}}
	s, _ := newTestServer(t, fw) // rules.json deliberately not written
	s.listening = func(context.Context) ([]system.Socket, error) { return reachSockets(), nil }
	got := exposureReach(t, s)
	want := map[int]string{22: "lan", 5900: "blocked", 8096: "lan", 8888: "blocked"}
	for port, w := range want {
		if got[port] != w {
			t.Errorf("legacy fallback port %d: reach=%q, want %q", port, got[port], w)
		}
	}
}

func auditStatus(t *testing.T, s *Server) map[string]string {
	t.Helper()
	w := do(s, http.MethodGet, "/api/audit", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("audit: HTTP %d (body=%s)", w.Code, w.Body.String())
	}
	var got []struct {
		ID     string `json:"id"`
		Status string `json:"status"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	out := map[string]string{}
	for _, f := range got {
		out[f.ID] = f.Status
	}
	return out
}

// The audit catalogue's port-based findings (H1 :8717 host, H3 :5900 host,
// H2 :15800 docker, M2 :8888 docker) must read the rules. The legacy path
// flipped all of them to "mitigated" the moment the firewall was active.
func TestAuditFindingsFollowRules(t *testing.T) {
	fw := &fakeFirewall{status: firewall.Status{Active: true, Hooked: true},
		loadErr: errors.New("no allowlist.conf")}
	s, rulesPath := newTestServer(t, fw)
	rs := rules.RuleSet{DefaultPolicy: "deny", Rules: []rules.Rule{
		{ID: "a1", Order: 10, Enabled: true, Name: "mcp open", Action: "allow",
			Source: rules.Source{Type: "any"}, Ports: rules.Ports{Type: "list", List: []int{8717}},
			Protocol: "tcp", Zone: "host"},
		{ID: "a2", Order: 20, Enabled: true, Name: "dozzle open", Action: "allow",
			Source: rules.Source{Type: "any"}, Ports: rules.Ports{Type: "list", List: []int{8888}},
			Protocol: "tcp", Zone: "docker"},
	}}
	if err := rules.Save(rulesPath, rs); err != nil {
		t.Fatal(err)
	}
	got := auditStatus(t, s)
	want := map[string]string{
		"H1": "open",      // 8717 explicitly allowed — still exposed
		"M2": "open",      // 8888 explicitly allowed (docker zone)
		"H3": "mitigated", // 5900: no rule, default deny
		"H2": "mitigated", // 15800: no rule, default deny
		"M1": "fixed",     // firewall active
	}
	for id, w := range want {
		if got[id] != w {
			t.Errorf("finding %s: status=%q, want %q", id, got[id], w)
		}
	}
}

// A rules POST with a feed source must fetch the feed (bounded, filtered),
// render its ipset file and reference it from compiled.sh — and /api/feeds
// must then report the feed as cached with the counts the render recorded.
func TestRulesPostWithFeedFetchesRendersAndCompiles(t *testing.T) {
	var body strings.Builder
	body.WriteString("# test feed\n10.0.0.0/8\n192.168.0.0/16\n100.64.0.0/10\n")
	for i := 0; i < 300; i++ {
		fmt.Fprintf(&body, "45.%d.%d.0/24\n", i/256, i%256)
	}
	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits++
		_, _ = w.Write([]byte(body.String()))
	}))
	defer srv.Close()
	s, _ := newTestServer(t, &fakeFirewall{})
	s.feeds.Source = func(f feeds.Feed) string { return srv.URL + "/" + f.ID }

	rs := rules.RuleSet{DefaultPolicy: "allow", Rules: []rules.Rule{{
		ID: "f1", Order: 10, Enabled: true, Name: "drop spamhaus", Action: "deny",
		Source: rules.Source{Type: "feed", Value: "spamhaus_drop"},
		Ports:  rules.Ports{Type: "all"}, Protocol: "both", Zone: "host"}}}
	if w := do(s, http.MethodPost, "/api/rules", rs); w.Code != http.StatusOK {
		t.Fatalf("rules POST: HTTP %d (body=%s)", w.Code, w.Body.String())
	}
	if hits != 1 {
		t.Fatalf("feed fetched %d times, want 1", hits)
	}
	compiled, err := os.ReadFile(s.compiledPath)
	if err != nil {
		t.Fatal(err)
	}
	ipsetPath := s.feeds.IpsetPath("spamhaus_drop")
	for _, want := range []string{`ipset restore -exist -f "` + ipsetPath + `"`, "--match-set zfw-feed-spamhaus_drop src -j DROP"} {
		if !strings.Contains(string(compiled), want) {
			t.Errorf("compiled.sh lacks %q", want)
		}
	}
	set, err := os.ReadFile(ipsetPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(set), "10.0.0.0/8") || strings.Contains(string(set), "192.168.0.0/16") || strings.Contains(string(set), "100.64.0.0/10") {
		t.Fatal("a special-use range from the feed reached the rendered set")
	}

	w := do(s, http.MethodGet, "/api/feeds", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("/api/feeds: HTTP %d", w.Code)
	}
	var list []struct {
		ID     string `json:"id"`
		Cached bool   `json:"cached"`
		Meta   *struct {
			Entries int `json:"entries"`
			Dropped int `json:"dropped"`
		} `json:"meta"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &list); err != nil {
		t.Fatal(err)
	}
	byID := map[string]int{}
	for i, e := range list {
		byID[e.ID] = i
	}
	sp := list[byID["spamhaus_drop"]]
	if !sp.Cached || sp.Meta == nil || sp.Meta.Entries != 300 || sp.Meta.Dropped != 3 {
		t.Fatalf("spamhaus_drop after POST: cached=%v meta=%+v, want cached with 300 entries / 3 dropped", sp.Cached, sp.Meta)
	}
	if fh := list[byID["firehol_level1"]]; fh.Cached {
		t.Fatal("firehol_level1 reported cached though never referenced")
	}
}

// An unknown feed id must be refused by validation before any fetch.
func TestRulesPostRejectsUnknownFeed(t *testing.T) {
	s, _ := newTestServer(t, &fakeFirewall{})
	called := false
	s.feeds.Source = func(f feeds.Feed) string { called = true; return "http://127.0.0.1:1/never" }
	rs := rules.RuleSet{DefaultPolicy: "allow", Rules: []rules.Rule{{
		ID: "f1", Order: 10, Enabled: true, Name: "bad", Action: "deny",
		Source: rules.Source{Type: "feed", Value: "https://example.invalid/list"},
		Ports:  rules.Ports{Type: "all"}, Protocol: "both", Zone: "host"}}}
	if w := do(s, http.MethodPost, "/api/rules", rs); w.Code != http.StatusBadRequest {
		t.Fatalf("HTTP %d, want 400", w.Code)
	}
	if called {
		t.Fatal("a fetch was attempted for a rejected feed id")
	}
}

// The host's own LAN and address from rules.json must never end up in a
// rendered feed set, even when a feed lists them.
func TestRulesPostProtectsOwnLANAndHostFromFeeds(t *testing.T) {
	var body strings.Builder
	body.WriteString("203.0.113.0/24\n198.51.100.7\n")
	for i := 0; i < 300; i++ {
		fmt.Fprintf(&body, "45.%d.%d.0/24\n", i/256, i%256)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(body.String()))
	}))
	defer srv.Close()
	s, _ := newTestServer(t, &fakeFirewall{})
	s.feeds.Source = func(f feeds.Feed) string { return srv.URL + "/" + f.ID }
	rs := rules.RuleSet{DefaultPolicy: "allow", LAN: "203.0.113.0/24", HostIP: "198.51.100.7",
		Rules: []rules.Rule{{
			ID: "f1", Order: 10, Enabled: true, Name: "feed", Action: "deny",
			Source: rules.Source{Type: "feed", Value: "spamhaus_drop"},
			Ports:  rules.Ports{Type: "all"}, Protocol: "both", Zone: "host"}}}
	if w := do(s, http.MethodPost, "/api/rules", rs); w.Code != http.StatusOK {
		t.Fatalf("rules POST: HTTP %d (body=%s)", w.Code, w.Body.String())
	}
	set, err := os.ReadFile(s.feeds.IpsetPath("spamhaus_drop"))
	if err != nil {
		t.Fatal(err)
	}
	for _, own := range []string{" 203.0.113.0/24\n", " 198.51.100.7/32\n"} {
		if strings.Contains(string(set), own) {
			t.Errorf("own range %q rendered into the feed set", strings.TrimSpace(own))
		}
	}
	if meta, ok := s.feeds.Info("spamhaus_drop"); !ok || meta.Protected != 2 {
		t.Fatalf("meta = %+v ok=%v, want protected=2", meta, ok)
	}
}

// RefreshFeeds swaps the live sets and leaves compiled.sh byte for byte as it
// was: the rules never move, only the set contents.
func TestRefreshFeedsSwapsLiveSetsAndNeverRecompiles(t *testing.T) {
	var body strings.Builder
	body.WriteString("203.0.113.0/24\n")
	for i := 0; i < 300; i++ {
		fmt.Fprintf(&body, "45.%d.%d.0/24\n", i/256, i%256)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(body.String()))
	}))
	defer srv.Close()
	s, _ := newTestServer(t, &fakeFirewall{})
	s.feeds.Source = func(f feeds.Feed) string { return srv.URL + "/" + f.ID }
	var calls [][]string
	s.ipsetRun = func(_ context.Context, args ...string) (string, error) {
		calls = append(calls, append([]string(nil), args...))
		return "", nil
	}
	rs := rules.RuleSet{DefaultPolicy: "allow", LAN: "203.0.113.0/24",
		Rules: []rules.Rule{{
			ID: "f1", Order: 10, Enabled: true, Name: "feed", Action: "deny",
			Source: rules.Source{Type: "feed", Value: "spamhaus_drop"},
			Ports:  rules.Ports{Type: "all"}, Protocol: "both", Zone: "host"}}}
	if w := do(s, http.MethodPost, "/api/rules", rs); w.Code != http.StatusOK {
		t.Fatalf("rules POST: HTTP %d", w.Code)
	}
	before, _ := os.ReadFile(s.compiledPath)
	if len(calls) != 0 {
		t.Fatalf("a rules POST must not touch live sets, got %v", calls)
	}

	if err := s.RefreshFeeds(context.Background()); err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(s.compiledPath)
	if string(before) != string(after) {
		t.Fatal("compiled.sh changed during a feed refresh")
	}
	var swapped bool
	for _, c := range calls {
		if c[0] == "swap" && c[2] == "zfw-feed-spamhaus_drop" {
			swapped = true
		}
	}
	if !swapped {
		t.Fatalf("live set not swapped; ipset calls: %v", calls)
	}
	// Protection from rules.json applies on refresh too, not only on POST.
	set, _ := os.ReadFile(s.feeds.IpsetPath("spamhaus_drop"))
	if strings.Contains(string(set), " 203.0.113.0/24\n") {
		t.Fatal("own LAN rendered into the set on refresh")
	}

	// The manual trigger returns the catalogue with fresh cache state.
	w := do(s, http.MethodPost, "/api/feeds/refresh", nil)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"cached":true`) {
		t.Fatalf("POST /api/feeds/refresh: HTTP %d body=%s", w.Code, w.Body.String())
	}
}

// Without a feed rule a refresh is a no-op: no download, no ipset call.
func TestRefreshFeedsNoopWithoutFeedRules(t *testing.T) {
	s, _ := newTestServer(t, &fakeFirewall{})
	fetched := false
	s.feeds.Source = func(f feeds.Feed) string { fetched = true; return "http://127.0.0.1:1/never" }
	called := false
	s.ipsetRun = func(_ context.Context, _ ...string) (string, error) { called = true; return "", nil }
	if err := s.RefreshFeeds(context.Background()); err != nil {
		t.Fatalf("no rules file: %v", err)
	}
	rs := rules.RuleSet{DefaultPolicy: "deny", Rules: []rules.Rule{{
		ID: "a1", Order: 10, Enabled: true, Name: "lan ssh", Action: "allow",
		Source: rules.Source{Type: "range", Value: "192.168.1.0/24"},
		Ports:  rules.Ports{Type: "list", List: []int{22}}, Protocol: "tcp", Zone: "host"}}}
	if w := do(s, http.MethodPost, "/api/rules", rs); w.Code != http.StatusOK {
		t.Fatalf("rules POST: HTTP %d", w.Code)
	}
	if err := s.RefreshFeeds(context.Background()); err != nil {
		t.Fatal(err)
	}
	if fetched || called {
		t.Fatalf("refresh without feed rules did work: fetched=%v ipset=%v", fetched, called)
	}
}

// /api/feeds tells the status card which rules use a feed, what the kernel
// holds and has counted against it, and when the next refresh is due.
func TestFeedsListReportsRulesLiveCountersAndNextRefresh(t *testing.T) {
	var body strings.Builder
	for i := 0; i < 300; i++ {
		fmt.Fprintf(&body, "45.%d.%d.0/24\n", i/256, i%256)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(body.String()))
	}))
	defer srv.Close()
	fw := &fakeFirewall{counters: map[string]firewall.Counters{"zfw-feed-spamhaus_drop": {Packets: 621, Bytes: 37260}}}
	s, _ := newTestServer(t, fw)
	s.feeds.Source = func(f feeds.Feed) string { return srv.URL + "/" + f.ID }
	s.ipsetRun = func(_ context.Context, args ...string) (string, error) {
		if strings.Contains(strings.Join(args, " "), "list -t zfw-feed-spamhaus_drop") {
			return "Number of entries: 300\n", nil
		}
		return "", fmt.Errorf("no such set")
	}
	atomic.StoreInt64(&s.feedsInterval, int64(12*time.Hour))
	rs := rules.RuleSet{DefaultPolicy: "allow", Rules: []rules.Rule{
		{ID: "f1", Order: 10, Enabled: true, Name: "Drop Spamhaus", Action: "deny",
			Source: rules.Source{Type: "feed", Value: "spamhaus_drop"}, Ports: rules.Ports{Type: "all"}, Protocol: "both", Zone: "host"},
		{ID: "f2", Order: 20, Enabled: true, Name: "No egress to Spamhaus", Action: "deny", Direction: "outbound",
			Source: rules.Source{Type: "feed", Value: "spamhaus_drop"}, Ports: rules.Ports{Type: "all"}, Protocol: "both", Zone: "host"}}}
	if w := do(s, http.MethodPost, "/api/rules", rs); w.Code != http.StatusOK {
		t.Fatalf("rules POST: HTTP %d", w.Code)
	}
	w := do(s, http.MethodGet, "/api/feeds", nil)
	var list []struct {
		ID    string   `json:"id"`
		Rules []string `json:"rules"`
		Live  *struct {
			Entries        int
			Packets, Bytes int64
		} `json:"live"`
		NextRefresh *string `json:"next_refresh"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &list); err != nil {
		t.Fatal(err)
	}
	var sp, fh int
	for i, e := range list {
		if e.ID == "spamhaus_drop" {
			sp = i
		}
		if e.ID == "firehol_level1" {
			fh = i
		}
	}
	e := list[sp]
	if len(e.Rules) != 2 || e.Rules[0] != "Drop Spamhaus" {
		t.Fatalf("rules = %v", e.Rules)
	}
	if e.Live == nil || e.Live.Entries != 300 || e.Live.Packets != 621 || e.Live.Bytes != 37260 {
		t.Fatalf("live = %+v", e.Live)
	}
	if e.NextRefresh == nil {
		t.Fatal("next_refresh missing with a 12h interval set")
	}
	if u := list[fh]; len(u.Rules) != 0 || u.Live != nil || u.NextRefresh != nil {
		t.Fatalf("unused feed reported state: %+v", u)
	}
}
