package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"

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

// auditDetail returns the detail text of one finding as the API serves it.
func auditDetail(t *testing.T, s *Server, id string) string {
	t.Helper()
	w := do(s, http.MethodGet, "/api/audit", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("audit: HTTP %d (body=%s)", w.Code, w.Body.String())
	}
	var got []struct {
		ID     string `json:"id"`
		Detail string `json:"detail"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	for _, f := range got {
		if f.ID == id {
			return f.Detail
		}
	}
	t.Fatalf("finding %s not in audit output", id)
	return ""
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

// M9: a chain inserted ahead of ZFW-IN runs before it. The finding must name
// the predecessors and flip to fixed the moment ZFW-IN is first again.
func TestAuditFlagsRulesAheadOfZFWIN(t *testing.T) {
	behind := &fakeFirewall{status: firewall.Status{Active: true, Hooked: true,
		InputPosition: 3, InputBefore: []string{"-j IPBLOCKLIST", "-j ts-input"}},
		loadErr: errors.New("no allowlist.conf")}
	s, _ := newTestServer(t, behind)
	got := auditStatus(t, s)
	if got["M9"] != "open" {
		t.Fatalf("M9 with ZFW-IN at position 3: status=%q, want open", got["M9"])
	}
	detail := auditDetail(t, s, "M9")
	for _, want := range []string{"#3", "IPBLOCKLIST", "ts-input"} {
		if !strings.Contains(detail, want) {
			t.Errorf("M9 detail %q does not name %q", detail, want)
		}
	}

	first := &fakeFirewall{status: firewall.Status{Active: true, Hooked: true, InputPosition: 1},
		loadErr: errors.New("no allowlist.conf")}
	s, _ = newTestServer(t, first)
	if got := auditStatus(t, s); got["M9"] != "fixed" {
		t.Fatalf("M9 with ZFW-IN first: status=%q, want fixed", got["M9"])
	}

	// Not hooked at all: nothing is "first", the finding stays open and
	// says so rather than reporting a comforting position.
	unhooked := &fakeFirewall{status: firewall.Status{Active: true, Hooked: false},
		loadErr: errors.New("no allowlist.conf")}
	s, _ = newTestServer(t, unhooked)
	if got := auditStatus(t, s); got["M9"] != "open" {
		t.Fatalf("M9 unhooked: status=%q, want open", got["M9"])
	}
}
