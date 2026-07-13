package compiler

import (
	"strings"
	"testing"

	"github.com/chicohaager/zfw/internal/rules"
	"github.com/chicohaager/zfw/internal/system"
)

// indexOfLine returns the position of the first line containing sub, or -1.
func indexOfLine(lines []string, sub string) int {
	for i, l := range lines {
		if strings.Contains(l, sub) {
			return i
		}
	}
	return -1
}

// TestDockerBypassPrecedesUserRules pins the ordering that keeps a user's
// *inbound* deny rule from also severing container *egress*.
//
// DOCKER-USER hangs off FORWARD, and `--ctorigdstport` carries no direction:
// for a container's own outbound HTTPS the original destination port is 443.
// So a rule "deny any → 443, zone docker" — which the UI presents as an
// inbound rule, outbound having had its own Direction since v0.5.6 — matched
// the container's egress connection too and killed it. The docker-bridge
// RETURNs used to be appended *after* the rule loop (and only under a deny
// policy), so container-originated traffic reached the user rules first.
//
// Inbound filtering must stay intact: LAN traffic to a published port arrives
// on the physical interface, not on docker0/br-+, so it still falls through to
// the user rules and the per-port deny below.
func TestDockerBypassPrecedesUserRules(t *testing.T) {
	rs := rules.RuleSet{
		DefaultPolicy: "deny",
		Rules: []rules.Rule{{
			ID: "r1", Name: "block https to containers", Enabled: true,
			Action: "deny", Zone: "docker", Protocol: "tcp",
			Source: rules.Source{Type: "any"},
			Ports:  rules.Ports{Type: "list", List: []int{443}},
		}},
	}
	pp := system.PublishedPorts{TCP: map[int]bool{8096: true}, UDP: map[int]bool{}}

	lines := dockerUserRules(rs, rs.Rules, pp, nil)

	docker0 := indexOfLine(lines, "-i docker0 -j RETURN")
	bridges := indexOfLine(lines, "-i br-+ -j RETURN")
	userDeny := indexOfLine(lines, "--ctorigdstport 443")

	if docker0 < 0 || bridges < 0 {
		t.Fatalf("docker bridge bypasses missing from DOCKER-USER:\n%s", strings.Join(lines, "\n"))
	}
	if userDeny < 0 {
		t.Fatalf("user deny rule not emitted:\n%s", strings.Join(lines, "\n"))
	}
	if docker0 > userDeny || bridges > userDeny {
		t.Errorf("container-originated traffic reaches the user deny rule before the "+
			"docker0/br-+ RETURNs (docker0=%d br-+=%d deny=%d) — an inbound "+
			"\"deny port 443\" rule then also drops every container's outbound "+
			"HTTPS:\n%s", docker0, bridges, userDeny, strings.Join(lines, "\n"))
	}
}

// TestDockerBypassEmittedUnderAllowPolicy: the bridge RETURNs used to be
// emitted only inside the `default_policy == "deny"` branch, so on an
// allow-policy host a user deny rule cut container egress with nothing in
// front of it at all. The bypass protects container-originated traffic from
// the *user rules*, which exist under either policy.
func TestDockerBypassEmittedUnderAllowPolicy(t *testing.T) {
	rs := rules.RuleSet{
		DefaultPolicy: "allow",
		Rules: []rules.Rule{{
			ID: "r1", Name: "block https to containers", Enabled: true,
			Action: "deny", Zone: "docker", Protocol: "tcp",
			Source: rules.Source{Type: "any"},
			Ports:  rules.Ports{Type: "list", List: []int{443}},
		}},
	}
	pp := system.PublishedPorts{TCP: map[int]bool{8096: true}, UDP: map[int]bool{}}

	lines := dockerUserRules(rs, rs.Rules, pp, nil)

	docker0 := indexOfLine(lines, "-i docker0 -j RETURN")
	userDeny := indexOfLine(lines, "--ctorigdstport 443")
	if docker0 < 0 {
		t.Fatalf("docker0 bypass not emitted under default_policy=allow:\n%s",
			strings.Join(lines, "\n"))
	}
	if userDeny >= 0 && docker0 > userDeny {
		t.Errorf("docker0 bypass (%d) sits after the user deny rule (%d) under an "+
			"allow policy:\n%s", docker0, userDeny, strings.Join(lines, "\n"))
	}
}

// TestInboundDenyStillReachesPublishedPorts is the other half of the hoist:
// moving the bridge RETURNs up must not stop the per-port default-deny from
// being emitted. Inbound LAN traffic arrives on the physical NIC, so it never
// matches -i docker0 and still hits these lines.
func TestInboundDenyStillReachesPublishedPorts(t *testing.T) {
	rs := rules.RuleSet{DefaultPolicy: "deny"}
	pp := system.PublishedPorts{
		TCP: map[int]bool{8096: true},
		UDP: map[int]bool{1900: true},
	}

	joined := strings.Join(dockerUserRules(rs, nil, pp, nil), "\n")
	for _, want := range []string{
		"-p tcp -m conntrack --ctorigdstport 8096 --ctstate NEW -j DROP",
		"-p udp -m conntrack --ctorigdstport 1900 --ctstate NEW -j DROP",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("DOCKER-USER missing the per-port default-deny %q:\n%s", want, joined)
		}
	}
}
