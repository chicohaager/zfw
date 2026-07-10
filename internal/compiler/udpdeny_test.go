package compiler

import (
	"strings"
	"testing"

	"github.com/chicohaager/zfw/internal/rules"
	"github.com/chicohaager/zfw/internal/system"
)

// pp8181 mirrors the live inventory on a ZimaOS host that publishes 8181 on
// both protocols and 8086 on TCP only.
func pp8181() system.PublishedPorts {
	return system.PublishedPorts{
		TCP: map[int]bool{8086: true, 8181: true},
		UDP: map[int]bool{8181: true},
	}
}

// TestUDPPublishedPortGetsDefaultDeny is the regression guard for the TCP-only
// default-deny. Before v1.0.17 parseDockerPorts discarded UDP mappings, so a
// container publishing 8181/udp was exempt from DOCKER-USER entirely: no allow
// rule, no deny rule, reachable from any source.
func TestUDPPublishedPortGetsDefaultDeny(t *testing.T) {
	script := Compile(denyRuleSet(), pp8181(), nil)

	for _, want := range []string{
		`$IPT -A DOCKER-USER -p udp -m conntrack --ctorigdstport 8181 --ctstate NEW -j DROP`,
		`$IPT -A DOCKER-USER -p tcp -m conntrack --ctorigdstport 8181 --ctstate NEW -j DROP`,
		`$IPT6 -A DOCKER-USER -p udp -m conntrack --ctorigdstport 8181 --ctstate NEW -j DROP`,
	} {
		if !strings.Contains(script, want) {
			t.Errorf("missing default-deny line:\n  %s", want)
		}
	}
	// 8086 is TCP-only: inventing a UDP deny for it would drop traffic on a
	// port nothing listens on and muddy the Events tab.
	if strings.Contains(script, `-p udp -m conntrack --ctorigdstport 8086`) {
		t.Error("emitted a UDP deny for a TCP-only published port")
	}
}

// TestDenyLinesOrderIsDeterministic: the compiled script is written to disk and
// diffed across applies, so the rule order must not depend on map iteration.
func TestDenyLinesOrderIsDeterministic(t *testing.T) {
	first := denyLines(pp8181(), "ZFW-DOCK-DROP ")
	for range 20 {
		if got := denyLines(pp8181(), "ZFW-DOCK-DROP "); !equalStrings(got, first) {
			t.Fatalf("denyLines is not deterministic:\n  %v\n  %v", first, got)
		}
	}
	// Ports ascending; within a port, tcp before udp.
	want := []string{"8086/tcp", "8181/tcp", "8181/udp"}
	var got []string
	for _, l := range first {
		if !strings.Contains(l, "-j DROP") {
			continue
		}
		switch {
		case strings.Contains(l, "-p tcp") && strings.Contains(l, "8086"):
			got = append(got, "8086/tcp")
		case strings.Contains(l, "-p tcp") && strings.Contains(l, "8181"):
			got = append(got, "8181/tcp")
		case strings.Contains(l, "-p udp") && strings.Contains(l, "8181"):
			got = append(got, "8181/udp")
		}
	}
	if !equalStrings(got, want) {
		t.Errorf("deny order = %v, want %v", got, want)
	}
}

// TestDefaultsAllowsPublishedUDPPort guards against the lockout half of the
// fix: extending the deny to UDP without also generating the matching allow
// rule would make every published UDP port unreachable, LAN included.
func TestDefaultsAllowsPublishedUDPPort(t *testing.T) {
	rs := rules.Defaults("192.168.1.0/24", "192.168.1.143", pp8181())

	byPort := map[int]rules.Rule{}
	for _, r := range rs.Rules {
		if r.Zone == "docker" && len(r.Ports.List) == 1 {
			byPort[r.Ports.List[0]] = r
		}
	}
	if got, ok := byPort[8181]; !ok || got.Protocol != "both" {
		t.Errorf("port 8181 (tcp+udp) allow rule = %+v, want protocol \"both\"", got)
	}
	if got, ok := byPort[8086]; !ok || got.Protocol != "tcp" {
		t.Errorf("port 8086 (tcp only) allow rule = %+v, want protocol \"tcp\"", got)
	}

	// The allow must precede the deny: compile and check the emitted order.
	script := Compile(rs, pp8181(), nil)
	allow := strings.Index(script, `--ctorigdstport 8181 -j RETURN`)
	deny := strings.Index(script, `-p udp -m conntrack --ctorigdstport 8181 --ctstate NEW -j DROP`)
	if allow < 0 || deny < 0 || allow > deny {
		t.Errorf("allow rule for 8181 must be emitted before the deny (allow=%d deny=%d)", allow, deny)
	}
}

// TestUDPOnlyPortStillDenied: a container publishing only UDP must not fall
// through the chain just because it has no TCP sibling.
func TestUDPOnlyPortStillDenied(t *testing.T) {
	pp := system.PublishedPorts{TCP: map[int]bool{}, UDP: map[int]bool{51820: true}}
	script := Compile(denyRuleSet(), pp, nil)
	if !strings.Contains(script, `-p udp -m conntrack --ctorigdstport 51820 --ctstate NEW -j DROP`) {
		t.Error("UDP-only published port has no default-deny")
	}
	if strings.Contains(script, `-p tcp -m conntrack --ctorigdstport 51820`) {
		t.Error("invented a TCP deny for a UDP-only port")
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
