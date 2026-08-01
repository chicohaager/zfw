package handlers

import (
	"encoding/json"
	"net/http"
	"os"
	"testing"

	"github.com/chicohaager/zfw/internal/rules"
)

func getV6Audit(t *testing.T, s *Server) v6AuditResponse {
	t.Helper()
	w := do(s, http.MethodGet, "/api/rules/v6", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("GET /api/rules/v6 = %d, body %s", w.Code, w.Body.String())
	}
	var got v6AuditResponse
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v (body %s)", err, w.Body.String())
	}
	return got
}

func writeRules(t *testing.T, path string, rs rules.RuleSet) {
	t.Helper()
	b, err := json.Marshal(rs)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestRulesV6ReportsLANScopedRulesAsUncovered is the API half of the field
// report: the rule table shows "Allow 80,443" and the same rule reaches no
// IPv6 packet, because its source is an IPv4 CIDR. Every rule rules.Defaults
// seeds looks like this, so a default install is blind on IPv6 while every
// row reads green.
func TestRulesV6ReportsLANScopedRulesAsUncovered(t *testing.T) {
	s, rulesPath := newTestServer(t, &fakeFirewall{})
	writeRules(t, rulesPath, rules.RuleSet{
		DefaultPolicy: "deny",
		LAN:           "192.168.1.0/24",
		Rules: []rules.Rule{{
			ID: "web", Order: 10, Enabled: true, Name: "ZimaOS Web UI",
			Action: "allow", Source: rules.Source{Type: "range", Value: "192.168.1.0/24"},
			Ports:    rules.Ports{Type: "list", List: []int{80, 443}},
			Protocol: "tcp", Zone: "host",
		}},
	})

	got := getV6Audit(t, s)
	if len(got.Rules) != 1 {
		t.Fatalf("want 1 audited rule, got %+v", got.Rules)
	}
	if got.Rules[0].ID != "web" || got.Rules[0].Mirrored {
		t.Errorf("want rule web reported as not mirrored, got %+v", got.Rules[0])
	}
	if got.Rules[0].Reason != "ipv4-source" {
		t.Errorf("want reason ipv4-source, got %q", got.Rules[0].Reason)
	}
	if !got.Blind || got.InboundAllows != 0 {
		t.Errorf("want blind=true inbound_allows=0, got %+v", got.V6Audit)
	}
}

// TestRulesV6CoveredWhenSourceIsAny: the fix a user can actually apply —
// an any-source rule for the published port does reach ZFW-IN6.
func TestRulesV6CoveredWhenSourceIsAny(t *testing.T) {
	s, rulesPath := newTestServer(t, &fakeFirewall{})
	writeRules(t, rulesPath, rules.RuleSet{
		DefaultPolicy: "deny",
		Rules: []rules.Rule{{
			ID: "cms", Order: 10, Enabled: true, Name: "CMS",
			Action: "allow", Source: rules.Source{Type: "any"},
			Ports:    rules.Ports{Type: "list", List: []int{443}},
			Protocol: "tcp", Zone: "docker",
		}},
	})

	got := getV6Audit(t, s)
	if len(got.Rules) != 1 || !got.Rules[0].Mirrored {
		t.Fatalf("want the rule reported as mirrored, got %+v", got.Rules)
	}
	if got.Rules[0].Reason != "" {
		t.Errorf("a mirrored rule must carry no reason, got %q", got.Rules[0].Reason)
	}
	if got.Blind || got.InboundAllows != 1 {
		t.Errorf("want blind=false inbound_allows=1, got %+v", got.V6Audit)
	}
}

// TestRulesV6NoRulesFile: a fresh install has no rules.json. The endpoint
// must answer 200 with an empty audit rather than 500 — the UI calls this on
// every rules-tab load, including the very first one.
func TestRulesV6NoRulesFile(t *testing.T) {
	s, _ := newTestServer(t, &fakeFirewall{})
	got := getV6Audit(t, s)
	if len(got.Rules) != 0 {
		t.Errorf("want no audited rules on a fresh install, got %+v", got.Rules)
	}
	if !got.DefaultDeny {
		t.Error("a fresh install defaults to deny")
	}
}

// TestRulesV6RejectsWrite: read-only endpoint. It reports on the firewall,
// it must never be a way to change it.
func TestRulesV6RejectsWrite(t *testing.T) {
	s, _ := newTestServer(t, &fakeFirewall{})
	if w := do(s, http.MethodPost, "/api/rules/v6", map[string]string{}); w.Code == http.StatusOK {
		t.Errorf("POST /api/rules/v6 must not be accepted, got %d", w.Code)
	}
}
