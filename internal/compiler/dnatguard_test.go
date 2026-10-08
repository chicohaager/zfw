package compiler

import (
	"strings"
	"testing"

	"github.com/chicohaager/zfw/internal/rules"
	"github.com/chicohaager/zfw/internal/system"
)

// The DNAT guard closes the window between "a container publishes a new port"
// and "the operator runs Safe-Apply again". The per-port default-deny is
// emitted once per port the inventory knew at compile time; dockerwatch
// recompiles on container events but deliberately does not apply, so a port
// published after the last apply had no DROP line in the live DOCKER-USER and
// fell through to the trailing RETURN — reachable from any source, while the
// Exposure view (judging rules.json) showed it as "blocked".
//
// The guard is a generic catch-all for inbound connections that Docker's
// port publishing DNATed towards a container (conntrack status DNAT, state
// NEW, leaving on a docker bridge), placed after every bypass, every user
// rule and every per-port deny, so it only ever sees what nothing above it
// decided.
var dnatGuard4 = []string{
	`-o docker0 -m conntrack --ctstate NEW -m conntrack --ctstate DNAT -j LOG --log-prefix "ZFW-DOCK-DROP " --log-level 6`,
	`-o docker0 -m conntrack --ctstate NEW -m conntrack --ctstate DNAT -j DROP`,
	`-o br-+ -m conntrack --ctstate NEW -m conntrack --ctstate DNAT -j LOG --log-prefix "ZFW-DOCK-DROP " --log-level 6`,
	`-o br-+ -m conntrack --ctstate NEW -m conntrack --ctstate DNAT -j DROP`,
}

var dnatGuard6 = []string{
	`-o docker0 -m conntrack --ctstate NEW -m conntrack --ctstate DNAT -j LOG --log-prefix "ZFW-DOCK6-DROP " --log-level 6`,
	`-o docker0 -m conntrack --ctstate NEW -m conntrack --ctstate DNAT -j DROP`,
	`-o br-+ -m conntrack --ctstate NEW -m conntrack --ctstate DNAT -j LOG --log-prefix "ZFW-DOCK6-DROP " --log-level 6`,
	`-o br-+ -m conntrack --ctstate NEW -m conntrack --ctstate DNAT -j DROP`,
}

func guardRuleSet() rules.RuleSet {
	rs := denyRuleSet()
	rs.LAN, rs.HostIP = "192.0.2.0/24", "192.0.2.100"
	rs.Rules = []rules.Rule{{
		ID: "r1", Order: 10, Enabled: true, Name: "app 8096 from LAN", Action: "allow",
		Source:   rules.Source{Type: "range", Value: "192.0.2.0/24"},
		Ports:    rules.Ports{Type: "list", List: []int{8096}},
		Protocol: "tcp", Zone: "docker",
	}}
	return rs
}

// assertGuardTail checks that the guard lines sit, in order, directly before
// the closing RETURN and after everything that must keep deciding first.
func assertGuardTail(t *testing.T, family string, lines, guard []string, mustPrecede []string) {
	t.Helper()
	if len(lines) < len(guard)+1 {
		t.Fatalf("%s DOCKER-USER too short for a guard:\n%s", family, strings.Join(lines, "\n"))
	}
	tail := lines[len(lines)-len(guard)-1:]
	for i, g := range guard {
		if tail[i] != g {
			t.Fatalf("%s DOCKER-USER: line %d before the closing RETURN = %q, want %q\nchain:\n%s",
				family, len(guard)-i, tail[i], g, strings.Join(lines, "\n"))
		}
	}
	if tail[len(tail)-1] != "-j RETURN" {
		t.Fatalf("%s DOCKER-USER must still close with -j RETURN, got %q", family, tail[len(tail)-1])
	}
	first := len(lines) - len(guard) - 1
	for _, sub := range mustPrecede {
		i := indexOfLine(lines, sub)
		if i < 0 {
			t.Errorf("%s DOCKER-USER lacks %q — cannot check it precedes the guard", family, sub)
			continue
		}
		if i >= first {
			t.Errorf("%s DOCKER-USER: %q (line %d) must precede the DNAT guard (line %d)", family, sub, i, first)
		}
	}
}

func TestDNATGuardClosesLaterPublishedPortsV4(t *testing.T) {
	rs := guardRuleSet()
	pp := tcpOnly(map[int]bool{8096: true, 8097: true})
	lines := dockerUserRules(rs, rs.Rules, pp, []string{"vpn+"})
	assertGuardTail(t, "IPv4", lines, dnatGuard4, []string{
		"-m conntrack --ctstate ESTABLISHED,RELATED -j RETURN",
		"-s 127.0.0.0/8 -j RETURN",
		"-s 192.0.2.100 -j RETURN",
		"-i tailscale0 -j RETURN",
		"-i zt+ -j RETURN",
		"-i wg+ -j RETURN",
		"-i tun0 -j RETURN",
		"-i vpn+ -j RETURN",
		"-i docker0 -j RETURN",
		"-i br-+ -j RETURN",
		"--ctorigdstport 8096 -j RETURN",             // the user's allow
		"--ctorigdstport 8097 --ctstate NEW -j DROP", // the known port's deny
		"--ctorigdstport 8097 --ctstate NEW -j LOG",  // and its log line
	})
}

func TestDNATGuardClosesLaterPublishedPortsV6(t *testing.T) {
	rs := denyRuleSet()
	rs.Rules = []rules.Rule{{
		ID: "r1", Order: 10, Enabled: true, Name: "app 8096", Action: "allow",
		Source:   rules.Source{Type: "any"},
		Ports:    rules.Ports{Type: "list", List: []int{8096}},
		Protocol: "tcp", Zone: "docker",
	}}
	pp := tcpOnly(map[int]bool{8096: true, 8097: true})
	lines := dockerUser6Rules(rs, rs.Rules, pp, []string{"vpn+"})
	assertGuardTail(t, "IPv6", lines, dnatGuard6, []string{
		"-m conntrack --ctstate ESTABLISHED,RELATED -j RETURN",
		"-i tailscale0 -j RETURN",
		"-i vpn+ -j RETURN",
		"-i docker0 -j RETURN",
		"-i br-+ -j RETURN",
		"--ctorigdstport 8096 -j RETURN",
		"--ctorigdstport 8097 --ctstate NEW -j DROP",
	})
}

// With nothing published at compile time the per-port deny is empty — and
// that is precisely the host on which the next `docker compose up` used to be
// wide open until the next apply.
func TestDNATGuardEmittedWithEmptyInventory(t *testing.T) {
	rs := denyRuleSet()
	assertGuardTail(t, "IPv4", dockerUserRules(rs, nil, system.PublishedPorts{}, nil), dnatGuard4, nil)
	assertGuardTail(t, "IPv6", dockerUser6Rules(rs, nil, system.PublishedPorts{}, nil), dnatGuard6, nil)
}

// default_policy=allow promises that unmatched traffic passes; the guard is
// part of the default-deny and must not appear there.
func TestDNATGuardAbsentUnderAllowPolicy(t *testing.T) {
	rs := denyRuleSet()
	rs.DefaultPolicy = "allow"
	pp := tcpOnly(map[int]bool{8096: true})
	for name, lines := range map[string][]string{
		"IPv4": dockerUserRules(rs, nil, pp, nil),
		"IPv6": dockerUser6Rules(rs, nil, pp, nil),
	} {
		if indexOfLine(lines, "--ctstate DNAT") >= 0 {
			t.Errorf("%s DOCKER-USER carries the DNAT guard under default_policy=allow:\n%s",
				name, strings.Join(lines, "\n"))
		}
	}
}

// Both emitters — the line-by-line bash script and the iptables-restore
// documents — must carry the guard on both families. Fixing one emitter only
// would leave the hole open on every host that runs the other.
func TestDNATGuardInBothEmitters(t *testing.T) {
	rs := guardRuleSet()
	pp := tcpOnly(map[int]bool{8096: true})

	script := Compile(rs, pp, nil)
	for _, g := range dnatGuard4 {
		mustContain(t, script, "  $IPT -A DOCKER-USER "+g+"\n")
	}
	for _, g := range dnatGuard6 {
		mustContain(t, script, "  $IPT6 -A DOCKER-USER "+g+"\n")
	}

	rest := CompileRestore(rs, pp)
	for _, g := range dnatGuard4 {
		mustContain(t, rest.V4, "-A DOCKER-USER "+g+"\n")
	}
	for _, g := range dnatGuard6 {
		mustContain(t, rest.V6, "-A DOCKER-USER "+g+"\n")
	}
	full := CompileRestoreScript(rs, pp, nil)
	mustContain(t, full, "-A DOCKER-USER "+dnatGuard4[1]+"\n")
	mustContain(t, full, "-A DOCKER-USER "+dnatGuard6[1]+"\n")
}
