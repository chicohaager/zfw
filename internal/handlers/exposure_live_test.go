package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/chicohaager/zfw/internal/compiler"
	"github.com/chicohaager/zfw/internal/firewall"
	"github.com/chicohaager/zfw/internal/rules"
	"github.com/chicohaager/zfw/internal/system"
)

// markLive records rs (compiled against pp) as the ruleset the engine last
// applied — exactly what engine/zfw does after a successful apply: it copies
// the compiled script it ran to applied.sh next to compiled.sh.
func markLive(t *testing.T, s *Server, rs rules.RuleSet, pp system.PublishedPorts) {
	t.Helper()
	p := filepath.Join(filepath.Dir(s.compiledPath), "applied.sh")
	if err := os.WriteFile(p, []byte(compiler.Compile(rs, pp, nil)), 0o600); err != nil {
		t.Fatal(err)
	}
}

type exposureEntry struct {
	Port    int      `json:"port"`
	Reach   string   `json:"reach"`
	Pending string   `json:"pending"`
	Sources []string `json:"sources"`
}

func exposureEntries(t *testing.T, s *Server) map[int]exposureEntry {
	t.Helper()
	w := do(s, http.MethodGet, "/api/exposure", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("exposure: HTTP %d (body=%s)", w.Code, w.Body.String())
	}
	var got []exposureEntry
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	out := map[int]exposureEntry{}
	for _, e := range got {
		out[e.Port] = e
	}
	return out
}

func activeFW() *fakeFirewall {
	return &fakeFirewall{status: firewall.Status{Active: true, Hooked: true},
		loadErr: errors.New("no allowlist.conf")}
}

func liveTestRules() rules.RuleSet {
	return rules.RuleSet{
		LAN: "192.168.1.0/24", HostIP: "192.168.1.100", DefaultPolicy: "deny",
		Rules: []rules.Rule{
			{ID: "ssh", Order: 10, Enabled: true, Name: "ssh", Action: "allow",
				Source: rules.Source{Type: "range", Value: "192.168.1.0/24"},
				Ports:  rules.Ports{Type: "list", List: []int{22}}, Protocol: "tcp", Zone: "host"},
			{ID: "jf", Order: 20, Enabled: true, Name: "jellyfin", Action: "allow",
				Source: rules.Source{Type: "any"},
				Ports:  rules.Ports{Type: "list", List: []int{8096}}, Protocol: "tcp", Zone: "docker"},
		},
	}
}

func liveSockets() []system.Socket {
	return []system.Socket{
		{Port: 22, Bind: "0.0.0.0", Proc: "sshd", Scope: "all"},
		{Port: 8096, Bind: "0.0.0.0", Proc: "docker-proxy", Scope: "all"},
		{Port: 8888, Bind: "0.0.0.0", Proc: "docker-proxy", Scope: "all"},
	}
}

// Gap 1b: with no record of what the engine applied — every host upgraded
// from <= v1.0.26 until its next apply, whose live script also has no DNAT
// guard — Exposure must not vouch for "blocked". Before v1.0.27 it reported
// a container port published after the last apply as blocked while the live
// DOCKER-USER let it through.
func TestExposureWithoutLiveRecordNeverSaysBlocked(t *testing.T) {
	s, rulesPath := newTestServer(t, activeFW())
	if err := rules.Save(rulesPath, liveTestRules()); err != nil {
		t.Fatal(err)
	}
	s.listening = func(context.Context) ([]system.Socket, error) { return liveSockets(), nil }

	got := exposureEntries(t, s)
	if e := got[8888]; e.Reach == "blocked" {
		t.Errorf("8888 (no rule, live state unknown): reach=%q — Exposure vouches for a block it cannot see", e.Reach)
	}
	if e := got[8888]; e.Reach != "unverified" {
		t.Errorf("8888: reach=%q, want unverified", e.Reach)
	}
	if e := got[8096]; e.Reach != "lan" {
		t.Errorf("8096 (allowed from any): reach=%q, want lan — reporting exposure needs no proof", e.Reach)
	}
}

// Gap 1b with the guard live: a port published after the apply is blocked by
// the DNAT guard — and Exposure says why it is not in the compiled rules.
func TestExposurePortPublishedAfterApply(t *testing.T) {
	s, rulesPath := newTestServer(t, activeFW())
	rs := liveTestRules()
	if err := rules.Save(rulesPath, rs); err != nil {
		t.Fatal(err)
	}
	markLive(t, s, rs, system.PublishedPorts{TCP: map[int]bool{8096: true}, UDP: map[int]bool{}})
	s.listening = func(context.Context) ([]system.Socket, error) { return liveSockets(), nil }

	e := exposureEntries(t, s)[8888]
	if e.Reach != "blocked" || e.Pending != "published-after-apply" {
		t.Errorf("8888 published after the apply: reach=%q pending=%q, want blocked / published-after-apply", e.Reach, e.Pending)
	}
}

// A saved but unapplied change must not be shown as if it were live — in
// either direction.
func TestExposureReportsLiveStateAndFlagsUnappliedRules(t *testing.T) {
	s, rulesPath := newTestServer(t, activeFW())
	live := liveTestRules()
	markLive(t, s, live, system.PublishedPorts{TCP: map[int]bool{8096: true, 8888: true}, UDP: map[int]bool{}})

	saved := liveTestRules()
	saved.Rules[0].Action = "deny" // ssh: saved as deny, not applied
	saved.Rules = append(saved.Rules, rules.Rule{ID: "dz", Order: 30, Enabled: true, Name: "dozzle",
		Action: "allow", Source: rules.Source{Type: "any"},
		Ports: rules.Ports{Type: "list", List: []int{8888}}, Protocol: "tcp", Zone: "docker"})
	if err := rules.Save(rulesPath, saved); err != nil {
		t.Fatal(err)
	}
	s.listening = func(context.Context) ([]system.Socket, error) { return liveSockets(), nil }

	got := exposureEntries(t, s)
	if e := got[22]; e.Reach != "lan" || e.Pending != "rules-not-applied" {
		t.Errorf("22 (live allow, saved deny): reach=%q pending=%q, want lan / rules-not-applied", e.Reach, e.Pending)
	}
	if e := got[8888]; e.Reach != "blocked" || e.Pending != "rules-not-applied" {
		t.Errorf("8888 (live deny, saved allow): reach=%q pending=%q, want blocked / rules-not-applied", e.Reach, e.Pending)
	}
	if e := got[8096]; e.Pending != "" {
		t.Errorf("8096 unchanged: pending=%q, want none", e.Pending)
	}
}

// Gap 7: a port allowed only from one address is not LAN-wide open.
func TestExposureRestrictedSource(t *testing.T) {
	s, rulesPath := newTestServer(t, activeFW())
	rs := liveTestRules()
	rs.Rules[0].Source = rules.Source{Type: "ip", Value: "192.168.1.10"}
	rs.Rules[1].Source = rules.Source{Type: "range", Value: "192.168.1.16/28"}
	if err := rules.Save(rulesPath, rs); err != nil {
		t.Fatal(err)
	}
	markLive(t, s, rs, system.PublishedPorts{TCP: map[int]bool{8096: true}, UDP: map[int]bool{}})
	s.listening = func(context.Context) ([]system.Socket, error) { return liveSockets(), nil }

	got := exposureEntries(t, s)
	if e := got[22]; e.Reach != "restricted" || len(e.Sources) != 1 || e.Sources[0] != "192.168.1.10" {
		t.Errorf("22 allowed from one IP: reach=%q sources=%v, want restricted [192.168.1.10]", e.Reach, e.Sources)
	}
	if e := got[8096]; e.Reach != "restricted" || len(e.Sources) != 1 || e.Sources[0] != "192.168.1.16/28" {
		t.Errorf("8096 allowed from a /28: reach=%q sources=%v, want restricted [192.168.1.16/28]", e.Reach, e.Sources)
	}
}

// Gap 7, the other direction: the LAN itself, a country or "any" are not a
// restriction worth a quieter badge.
func TestExposureWideSourcesStayLAN(t *testing.T) {
	s, rulesPath := newTestServer(t, activeFW())
	rs := liveTestRules() // 22 from the LAN /24, 8096 from any
	if err := rules.Save(rulesPath, rs); err != nil {
		t.Fatal(err)
	}
	markLive(t, s, rs, system.PublishedPorts{TCP: map[int]bool{8096: true}, UDP: map[int]bool{}})
	s.listening = func(context.Context) ([]system.Socket, error) { return liveSockets(), nil }
	got := exposureEntries(t, s)
	for _, p := range []int{22, 8096} {
		if got[p].Reach != "lan" {
			t.Errorf("%d: reach=%q, want lan", p, got[p].Reach)
		}
	}
}

// The audit reads the same oracle and must not turn greener because of
// either change: a source-restricted port is still reachable (finding open),
// and a deny that is saved but not applied does not mitigate anything yet.
func TestAuditNotGreenerThanTheLiveState(t *testing.T) {
	s, rulesPath := newTestServer(t, activeFW())
	live := rules.RuleSet{LAN: "192.168.1.0/24", DefaultPolicy: "deny", Rules: []rules.Rule{
		{ID: "a1", Order: 10, Enabled: true, Name: "mcp from one host", Action: "allow",
			Source: rules.Source{Type: "ip", Value: "192.168.1.10"},
			Ports:  rules.Ports{Type: "list", List: []int{8717}}, Protocol: "tcp", Zone: "host"},
		{ID: "a2", Order: 20, Enabled: true, Name: "vnc", Action: "allow",
			Source: rules.Source{Type: "any"},
			Ports:  rules.Ports{Type: "list", List: []int{5900}}, Protocol: "tcp", Zone: "host"},
	}}
	markLive(t, s, live, system.PublishedPorts{TCP: map[int]bool{}, UDP: map[int]bool{}})
	saved := live
	saved.Rules = []rules.Rule{live.Rules[0], live.Rules[1]}
	saved.Rules[1].Action = "deny" // saved, not applied
	if err := rules.Save(rulesPath, saved); err != nil {
		t.Fatal(err)
	}
	got := auditStatus(t, s)
	if got["H1"] != "open" {
		t.Errorf("H1 (8717 allowed from one host): status=%q, want open — restricted is still reachable", got["H1"])
	}
	if got["H3"] != "open" {
		t.Errorf("H3 (5900 live allow, deny only saved): status=%q, want open until applied", got["H3"])
	}
}
