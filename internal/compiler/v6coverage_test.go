package compiler

import (
	"strings"
	"testing"

	"github.com/chicohaager/zfw/internal/rules"
)

// zfwIn6Lines returns the ZFW-IN6 lines of a compiled script, with the
// "$IPT6 -A ZFW-IN6 " prefix stripped. Chain-scoped so an assertion cannot
// be satisfied by an identical-looking line in DOCKER-USER — the two chains
// sit on different packet paths and a rule in the wrong one is the bug this
// file is about.
func zfwIn6Lines(script string) []string {
	const pfx = "$IPT6 -A ZFW-IN6 "
	var out []string
	for _, ln := range strings.Split(script, "\n") {
		ln = strings.TrimSpace(ln)
		if strings.HasPrefix(ln, pfx) {
			out = append(out, strings.TrimPrefix(ln, pfx))
		}
	}
	return out
}

func hasLine(lines []string, want string) bool {
	for _, l := range lines {
		if l == want {
			return true
		}
	}
	return false
}

// TestV6MirrorsDockerPublishedPort is the regression test for the field
// report behind v1.0.22: a CMS container published on 443 was reachable on
// the LAN over IPv4 and dead from the internet, while the rule table said
// "Allow 443".
//
// Cause: with Docker's ip6tables support off (the ZimaOS default) an IPv6
// connection to a published port terminates on the host's docker-proxy
// listener and is filtered in INPUT — ZFW-IN6 — which carried no allow for
// the port because hostLines6 asked for the *host* half of the zone split.
// The v4 path was fine the whole time via DOCKER-USER, which is exactly why
// testing from inside the LAN could not see it.
func TestV6MirrorsDockerPublishedPort(t *testing.T) {
	for _, zone := range []string{"docker", "auto"} {
		t.Run(zone, func(t *testing.T) {
			rs := rules.RuleSet{
				DefaultPolicy: "deny",
				Rules: []rules.Rule{{
					ID: "cms", Order: 10, Enabled: true, Name: "CMS",
					Action: "allow", Source: rules.Source{Type: "any"},
					Ports:    rules.Ports{Type: "list", List: []int{443}},
					Protocol: "tcp", Zone: zone,
				}},
			}
			lines := zfwIn6Lines(Compile(rs, tcpOnly(map[int]bool{443: true}), nil))
			if !hasLine(lines, "-p tcp --dport 443 -j RETURN") {
				t.Errorf("zone %q: ZFW-IN6 carries no allow for the published port; "+
					"every IPv6 client hits the catch-all DROP.\nchain:\n  %s",
					zone, strings.Join(lines, "\n  "))
			}
		})
	}
}

// TestV6MirrorsDockerPortRange covers the range form of the same rule — a
// port range is the other shape portsForZone routed to the host chain only.
func TestV6MirrorsDockerPortRange(t *testing.T) {
	rs := rules.RuleSet{
		DefaultPolicy: "deny",
		Rules: []rules.Rule{{
			ID: "vnc", Order: 10, Enabled: true, Name: "VNC",
			Action: "allow", Source: rules.Source{Type: "any"},
			Ports:    rules.Ports{Type: "range", From: 5900, To: 5999},
			Protocol: "tcp", Zone: "docker",
		}},
	}
	lines := zfwIn6Lines(Compile(rs, tcpOnly(map[int]bool{5900: true}), nil))
	if !hasLine(lines, "-p tcp --dport 5900:5999 -j RETURN") {
		t.Errorf("ZFW-IN6 missing the mirrored range:\n  %s", strings.Join(lines, "\n  "))
	}
}

// TestV6DenyMirrored: a docker-zone deny must reach IPv6 too. Mirroring only
// the allows would turn a "block VNC" rule into "block VNC on IPv4", which
// reads as protection and is not.
func TestV6DenyMirrored(t *testing.T) {
	rs := rules.RuleSet{
		DefaultPolicy: "allow",
		Rules: []rules.Rule{{
			ID: "novnc", Order: 10, Enabled: true, Name: "Block VNC",
			Action: "deny", Source: rules.Source{Type: "any"},
			Ports:    rules.Ports{Type: "list", List: []int{5900}},
			Protocol: "tcp", Zone: "docker",
		}},
	}
	lines := zfwIn6Lines(Compile(rs, tcpOnly(map[int]bool{5900: true}), nil))
	if !hasLine(lines, "-p tcp --dport 5900 -j DROP") {
		t.Errorf("ZFW-IN6 missing the mirrored deny:\n  %s", strings.Join(lines, "\n  "))
	}
}

// TestV6DockerAllPortsNotWidened pins the one case portsForZone6 refuses to
// mirror. "Every port of my containers" must not become "every port of this
// host" on IPv6 — that would hand out SSH, Samba and the ZimaOS UI to any
// v6 source. The refusal has to be visible, so AuditV6 must name it.
func TestV6DockerAllPortsNotWidened(t *testing.T) {
	rs := rules.RuleSet{
		DefaultPolicy: "deny",
		Rules: []rules.Rule{{
			ID: "wide", Order: 10, Enabled: true, Name: "All container ports",
			Action: "allow", Source: rules.Source{Type: "any"},
			Ports:    rules.Ports{Type: "all"},
			Protocol: "tcp", Zone: "docker",
		}},
	}
	lines := zfwIn6Lines(Compile(rs, tcpOnly(map[int]bool{443: true}), nil))
	if hasLine(lines, "-p tcp -j RETURN") {
		t.Error("a docker-zone ports=all rule opened the whole IPv6 INPUT chain")
	}
	a := AuditV6(rs)
	if len(a.Rules) != 1 || a.Rules[0].Mirrored || a.Rules[0].Reason != "docker-all-ports" {
		t.Errorf("audit must name the refusal, got %+v", a.Rules)
	}
}

// TestV6HostAllPortsStillWidens: the host/auto ports=all rule kept its
// pre-v1.0.22 meaning. Pinned so the narrowing above cannot spread.
func TestV6HostAllPortsStillWidens(t *testing.T) {
	rs := rules.RuleSet{
		DefaultPolicy: "deny",
		Rules: []rules.Rule{{
			ID: "trust", Order: 10, Enabled: true, Name: "Trusted peer",
			Action: "allow", Source: rules.Source{Type: "ip", Value: "2001:db8::5"},
			Ports:    rules.Ports{Type: "all"},
			Protocol: "both", Zone: "host",
		}},
	}
	lines := zfwIn6Lines(Compile(rs, tcpOnly(map[int]bool{443: true}), nil))
	if !hasLine(lines, "-s 2001:db8::5 -j RETURN") {
		t.Errorf("host-zone ports=all no longer mirrors:\n  %s", strings.Join(lines, "\n  "))
	}
}

// TestAuditV6ReportsIPv4SourceSkip is fix (2): a rule whose source is an
// IPv4 CIDR cannot be expressed on ip6tables and is therefore skipped. That
// is correct and unavoidable — what was wrong is that it happened in
// silence. rules.Defaults seeds *every* starter rule with the LAN CIDR as
// source, so on a default install this is the whole rule table.
func TestAuditV6ReportsIPv4SourceSkip(t *testing.T) {
	rs := rules.RuleSet{
		DefaultPolicy: "deny",
		LAN:           "192.168.1.0/24",
		Rules: []rules.Rule{{
			ID: "lanweb", Order: 10, Enabled: true, Name: "ZimaOS Web UI",
			Action: "allow", Source: rules.Source{Type: "range", Value: "192.168.1.0/24"},
			Ports:    rules.Ports{Type: "list", List: []int{80, 443}},
			Protocol: "tcp", Zone: "host",
		}},
	}
	a := AuditV6(rs)
	if len(a.Rules) != 1 {
		t.Fatalf("want 1 audited rule, got %d", len(a.Rules))
	}
	if a.Rules[0].Mirrored || a.Rules[0].Reason != "ipv4-source" {
		t.Errorf("want skipped/ipv4-source, got %+v", a.Rules[0])
	}
	if a.InboundAllows != 0 || !a.Blind {
		t.Errorf("a deny-default set with no v6 allow must read as blind, got %+v", a)
	}
}

// TestAuditV6CountrySourceSkip: geo matching runs off IPv4-only ipsets.
func TestAuditV6CountrySourceSkip(t *testing.T) {
	rs := rules.RuleSet{
		DefaultPolicy: "deny",
		Rules: []rules.Rule{{
			ID: "geo", Order: 10, Enabled: true, Name: "Allow DE",
			Action: "allow", Source: rules.Source{Type: "country", Value: "de"},
			Ports:    rules.Ports{Type: "list", List: []int{443}},
			Protocol: "tcp", Zone: "host",
		}},
	}
	a := AuditV6(rs)
	if len(a.Rules) != 1 || a.Rules[0].Reason != "country-source" {
		t.Errorf("want country-source, got %+v", a.Rules)
	}
}

// TestAuditV6NotBlindWithAnySource: one any-source allow is enough to clear
// the warning — it does reach ZFW-IN6.
func TestAuditV6NotBlindWithAnySource(t *testing.T) {
	rs := rules.RuleSet{
		DefaultPolicy: "deny",
		Rules: []rules.Rule{{
			ID: "cms", Order: 10, Enabled: true, Name: "CMS",
			Action: "allow", Source: rules.Source{Type: "any"},
			Ports:    rules.Ports{Type: "list", List: []int{443}},
			Protocol: "tcp", Zone: "docker",
		}},
	}
	a := AuditV6(rs)
	if a.InboundAllows != 1 || a.Blind {
		t.Errorf("want one v6 allow and no warning, got %+v", a)
	}
}

// TestAuditV6AllowPolicyNeverBlind: with default_policy=allow the IPv6 chain
// ends in RETURN, so "no allow rules" is not a lockout.
func TestAuditV6AllowPolicyNeverBlind(t *testing.T) {
	a := AuditV6(rules.RuleSet{DefaultPolicy: "allow"})
	if a.DefaultDeny || a.Blind {
		t.Errorf("allow-policy set must never read as blind, got %+v", a)
	}
}

// TestAuditV6SkipsDisabledRules: a disabled rule emits nothing anywhere, so
// badging it with an IPv6 reason would be misinformation.
func TestAuditV6SkipsDisabledRules(t *testing.T) {
	rs := rules.RuleSet{
		DefaultPolicy: "deny",
		Rules: []rules.Rule{{
			ID: "off", Order: 10, Enabled: false, Name: "disabled",
			Action: "allow", Source: rules.Source{Type: "range", Value: "10.0.0.0/8"},
			Ports:    rules.Ports{Type: "list", List: []int{443}},
			Protocol: "tcp", Zone: "host",
		}},
	}
	if a := AuditV6(rs); len(a.Rules) != 0 {
		t.Errorf("disabled rule must not be audited, got %+v", a.Rules)
	}
}

// TestAuditV6DerivedFromEmitter is the anti-drift guard: for every rule the
// audit calls Mirrored, the compiled ZFW-IN6 chain must actually carry a
// line for it, and vice versa. A coverage report that drifts from the
// emitter is worse than none — it would state "covered" for a dropped port.
func TestAuditV6DerivedFromEmitter(t *testing.T) {
	cases := []rules.Rule{
		{ID: "a", Enabled: true, Action: "allow", Source: rules.Source{Type: "any"},
			Ports: rules.Ports{Type: "list", List: []int{443}}, Protocol: "tcp", Zone: "docker"},
		{ID: "b", Enabled: true, Action: "allow", Source: rules.Source{Type: "range", Value: "192.168.1.0/24"},
			Ports: rules.Ports{Type: "list", List: []int{22}}, Protocol: "tcp", Zone: "host"},
		{ID: "c", Enabled: true, Action: "allow", Source: rules.Source{Type: "any"},
			Ports: rules.Ports{Type: "all"}, Protocol: "tcp", Zone: "docker"},
		{ID: "d", Enabled: true, Action: "deny", Source: rules.Source{Type: "ip", Value: "2001:db8::9"},
			Ports: rules.Ports{Type: "list", List: []int{8080}}, Protocol: "tcp", Zone: "auto"},
	}
	for i := range cases {
		cases[i].Order = (i + 1) * 10
	}
	rs := rules.RuleSet{DefaultPolicy: "deny", Rules: cases}
	a := AuditV6(rs)
	for _, st := range a.Rules {
		emitted := len(hostLines6(ruleByID(rs, st.ID))) > 0
		if emitted != st.Mirrored {
			t.Errorf("rule %s: audit says mirrored=%v, emitter says %v",
				st.ID, st.Mirrored, emitted)
		}
	}
}

func ruleByID(rs rules.RuleSet, id string) rules.Rule {
	for _, r := range rs.Rules {
		if r.ID == id {
			return r
		}
	}
	return rules.Rule{}
}

func TestV6AuditNamesFeedSourceReason(t *testing.T) {
	a := AuditV6(rules.RuleSet{DefaultPolicy: "deny", Rules: []rules.Rule{{
		ID: "f", Order: 10, Enabled: true, Name: "feed", Action: "deny",
		Source: rules.Source{Type: "feed", Value: "spamhaus_drop"},
		Ports:  rules.Ports{Type: "all"}, Protocol: "both", Zone: "host"}}})
	if len(a.Rules) != 1 || a.Rules[0].Reason != "feed-source" {
		t.Errorf("want feed-source, got %+v", a.Rules)
	}
}
