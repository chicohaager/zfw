package compiler

import (
	"strings"
	"testing"

	"github.com/chicohaager/zfw/internal/system"

	"github.com/chicohaager/zfw/internal/rules"
)

func mustContain(t *testing.T, haystack, needle string) {
	t.Helper()
	if !strings.Contains(haystack, needle) {
		t.Errorf("compiled script missing:\n  %s", needle)
	}
}

func mustNotContain(t *testing.T, haystack, needle string) {
	t.Helper()
	if strings.Contains(haystack, needle) {
		t.Errorf("compiled script unexpectedly contains:\n  %s", needle)
	}
}

func TestEmptyDefaultDeny(t *testing.T) {
	out := Compile(rules.RuleSet{
		LAN: "192.168.1.0/24", HostIP: "192.168.1.100", DefaultPolicy: "deny",
	}, system.PublishedPorts{}, nil)
	mustContain(t, out, "$IPT -A ZFW-IN -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT")
	mustContain(t, out, "$IPT -A ZFW-IN -j DROP")
	mustContain(t, out, "$IPT -C INPUT -j ZFW-IN")
	mustContain(t, out, "$IPT -A DOCKER-USER -s 192.168.1.100 -j RETURN")
	// Default-deny is now scoped to published ports, not to the LAN source.
	// With no published ports there is nothing to drop, but container-egress
	// bridge RETURNs are still emitted, and the old source-scoped drop is gone.
	mustContain(t, out, "$IPT -A DOCKER-USER -i docker0 -j RETURN")
	mustNotContain(t, out, "$IPT -A DOCKER-USER -s 192.168.1.0/24 -j DROP")
}

// TestDockerPublishedPortDefaultDeny: a published port with no matching allow
// rule is dropped for NEW inbound regardless of source (closes the multi-homed
// trust-inversion where a non-LAN origin reached every container).
func TestDockerPublishedPortDefaultDeny(t *testing.T) {
	out := Compile(rules.RuleSet{
		LAN: "192.168.1.0/24", HostIP: "192.168.1.100", DefaultPolicy: "deny",
	}, tcpOnly(map[int]bool{3050: true}), nil)
	mustContain(t, out, `$IPT -A DOCKER-USER -p tcp -m conntrack --ctorigdstport 3050 --ctstate NEW -j DROP`)
	mustContain(t, out, "$IPT -A DOCKER-USER -i docker0 -j RETURN")
	mustContain(t, out, "$IPT -A DOCKER-USER -i br-+ -j RETURN")
	mustNotContain(t, out, "-s 192.168.1.0/24 -j DROP")
}

// TestDockerAllowPrecedesPortDrop: a declared LAN allow for a published port
// must appear before that port's default-deny DROP, so legitimate LAN access
// (and any source SNATed into the LAN) still returns.
func TestDockerAllowPrecedesPortDrop(t *testing.T) {
	out := Compile(rules.RuleSet{
		LAN: "192.168.1.0/24", DefaultPolicy: "deny",
		Rules: []rules.Rule{{
			Order: 10, Enabled: true, Name: "app 3050", Action: "allow",
			Source:   rules.Source{Type: "range", Value: "192.168.1.0/24"},
			Ports:    rules.Ports{Type: "list", List: []int{3050}},
			Protocol: "tcp", Zone: "docker",
		}},
	}, tcpOnly(map[int]bool{3050: true}), nil)
	allow := strings.Index(out, "-s 192.168.1.0/24 -p tcp -m conntrack --ctorigdstport 3050 -j RETURN")
	drop := strings.Index(out, "--ctorigdstport 3050 --ctstate NEW -j DROP")
	if allow < 0 || drop < 0 || allow > drop {
		t.Fatalf("allow (%d) must precede port drop (%d)", allow, drop)
	}
}

func TestHostAllowRule(t *testing.T) {
	out := Compile(rules.RuleSet{
		LAN: "192.168.1.0/24", DefaultPolicy: "deny",
		Rules: []rules.Rule{{
			Order: 10, Enabled: true, Name: "SSH", Action: "allow",
			Source:   rules.Source{Type: "range", Value: "192.168.1.0/24"},
			Ports:    rules.Ports{Type: "list", List: []int{22}},
			Protocol: "tcp", Zone: "host",
		}},
	}, system.PublishedPorts{}, nil)
	mustContain(t, out, "$IPT -A ZFW-IN -s 192.168.1.0/24 -p tcp --dport 22 -j ACCEPT")
}

func TestDockerDenyRule(t *testing.T) {
	out := Compile(rules.RuleSet{
		LAN: "192.168.1.0/24", DefaultPolicy: "deny",
		Rules: []rules.Rule{{
			Order: 10, Enabled: true, Name: "block dozzle", Action: "deny",
			Source:   rules.Source{Type: "any"},
			Ports:    rules.Ports{Type: "list", List: []int{8888}},
			Protocol: "tcp", Zone: "docker",
		}},
	}, system.PublishedPorts{}, nil)
	mustContain(t, out, "-m conntrack --ctorigdstport 8888 -j DROP")
}

func TestZoneAutoSplitsByDockerPorts(t *testing.T) {
	out := Compile(rules.RuleSet{
		LAN: "192.168.1.0/24", DefaultPolicy: "deny",
		Rules: []rules.Rule{{
			Order: 10, Enabled: true, Name: "mixed", Action: "allow",
			Source:   rules.Source{Type: "any"},
			Ports:    rules.Ports{Type: "list", List: []int{22, 8888}},
			Protocol: "tcp", Zone: "auto",
		}},
	}, tcpOnly(map[int]bool{8888: true}), nil)
	mustContain(t, out, "$IPT -A ZFW-IN -p tcp --dport 22 -j ACCEPT")
	mustContain(t, out, "--ctorigdstport 8888 -j RETURN")
}

func TestDisabledRuleSkipped(t *testing.T) {
	out := Compile(rules.RuleSet{
		LAN: "192.168.1.0/24", DefaultPolicy: "deny",
		Rules: []rules.Rule{{
			Order: 10, Enabled: false, Name: "off", Action: "allow",
			Source:   rules.Source{Type: "any"},
			Ports:    rules.Ports{Type: "list", List: []int{9999}},
			Protocol: "tcp", Zone: "host",
		}},
	}, system.PublishedPorts{}, nil)
	mustNotContain(t, out, "--dport 9999")
}

func TestDefaultAllowMode(t *testing.T) {
	out := Compile(rules.RuleSet{
		LAN: "192.168.1.0/24", DefaultPolicy: "allow",
	}, system.PublishedPorts{}, nil)
	mustContain(t, out, "$IPT -A ZFW-IN -j RETURN")
	mustNotContain(t, out, "$IPT -A ZFW-IN -j DROP\n")
	mustNotContain(t, out, "$IPT -A DOCKER-USER -s 192.168.1.0/24 -j DROP")
}

func TestV6Drop(t *testing.T) {
	out := Compile(rules.RuleSet{
		DefaultPolicy: "deny", V6Drop: []int{5900, 8717},
	}, system.PublishedPorts{}, nil)
	mustContain(t, out, "$IPT6 -A ZFW-IN6 -p tcp --dport 5900 -j DROP")
	mustContain(t, out, "$IPT6 -A ZFW-IN6 -p tcp --dport 8717 -j DROP")
}

func TestCountryRule(t *testing.T) {
	out := Compile(rules.RuleSet{
		LAN: "192.168.1.0/24", DefaultPolicy: "deny",
		Rules: []rules.Rule{{
			Order: 10, Enabled: true, Name: "nur DE", Action: "allow",
			Source:   rules.Source{Type: "country", Value: "DE"},
			Ports:    rules.Ports{Type: "list", List: []int{8096}},
			Protocol: "tcp", Zone: "host",
		}},
	}, system.PublishedPorts{}, map[string]string{"de": "/DATA/zfw/geo/de.ipset"})
	mustContain(t, out, "modprobe ip_set ip_set_hash_net xt_set")
	mustContain(t, out, "ipset restore -exist -f \"/DATA/zfw/geo/de.ipset\"")
	mustContain(t, out, "-m set --match-set zfw-cc-de src -p tcp --dport 8096 -j ACCEPT")
}

func TestCountryDenyMultiple(t *testing.T) {
	out := Compile(rules.RuleSet{
		LAN: "192.168.1.0/24", DefaultPolicy: "allow",
		Rules: []rules.Rule{{
			Order: 10, Enabled: true, Name: "block RU+CN", Action: "deny",
			Source:   rules.Source{Type: "country", Value: "RU, CN"},
			Ports:    rules.Ports{Type: "all"},
			Protocol: "both", Zone: "host",
		}},
	}, system.PublishedPorts{}, map[string]string{"ru": "/x/ru.ipset", "cn": "/x/cn.ipset"})
	mustContain(t, out, "-m set --match-set zfw-cc-ru src -j DROP")
	mustContain(t, out, "-m set --match-set zfw-cc-cn src -j DROP")
}

// TestHostPortRange locks in v0.2.16's port-range support: a rule with
// Ports.Type=="range" must emit a single iptables `--dport X:Y` line, not
// enumerate every port in between. Closes the "block VNC 5900-5999" use
// case without producing 100 multiport entries.
func TestHostPortRange(t *testing.T) {
	out := Compile(rules.RuleSet{
		LAN: "192.168.1.0/24", HostIP: "192.168.1.100", DefaultPolicy: "deny",
		Rules: []rules.Rule{{
			ID: "r1", Order: 10, Enabled: true,
			Name: "Block VNC range", Action: "deny",
			Source:   rules.Source{Type: "any"},
			Ports:    rules.Ports{Type: "range", From: 5900, To: 5999},
			Protocol: "tcp", Zone: "host",
		}},
	}, system.PublishedPorts{}, nil)
	mustContain(t, out, "$IPT -A ZFW-IN -p tcp --dport 5900:5999 -j DROP")
	mustNotContain(t, out, "multiport")
}

// TestDockerPortRange covers the docker-zone variant — published-port range
// must be expressed with conntrack's range syntax.
func TestDockerPortRange(t *testing.T) {
	out := Compile(rules.RuleSet{
		LAN: "192.168.1.0/24", HostIP: "192.168.1.100", DefaultPolicy: "deny",
		Rules: []rules.Rule{{
			ID: "r1", Order: 10, Enabled: true,
			Name: "Allow container range", Action: "allow",
			Source:   rules.Source{Type: "any"},
			Ports:    rules.Ports{Type: "range", From: 8000, To: 8100},
			Protocol: "tcp", Zone: "docker",
		}},
	}, system.PublishedPorts{}, nil)
	mustContain(t, out, "--ctorigdstport 8000:8100 -j RETURN")
}

// TestIPv6ChainAlwaysEmitted locks in the v0.2.15 IPv6 fix: ZFW-IN6 must be
// emitted on every build (not only when V6Drop is non-empty) so the SLAAC
// LAN gap stays closed by default.
func TestIPv6ChainAlwaysEmitted(t *testing.T) {
	out := Compile(rules.RuleSet{
		LAN: "192.168.1.0/24", HostIP: "192.168.1.100", DefaultPolicy: "deny",
	}, system.PublishedPorts{}, nil)
	mustContain(t, out, "$IPT6 -N ZFW-IN6")
	mustContain(t, out, "$IPT6 -A ZFW-IN6 -p ipv6-icmp -j RETURN")
	mustContain(t, out, "$IPT6 -A ZFW-IN6 -s fe80::/10 -j RETURN")
	mustContain(t, out, "ZFW-IN6-DROP")
	mustContain(t, out, "$IPT6 -A ZFW-IN6 -j DROP")
}

// TestDockerBridgeBypass locks in v0.2.13: docker0 and br-+ interfaces must
// bypass the catch-all DROP so container-to-host traffic isn't silently
// killed (mDNS / DNS / etc.).
func TestDockerBridgeBypass(t *testing.T) {
	out := Compile(rules.RuleSet{
		LAN: "192.168.1.0/24", HostIP: "192.168.1.100", DefaultPolicy: "deny",
	}, system.PublishedPorts{}, nil)
	mustContain(t, out, "$IPT -A ZFW-IN -i docker0 -j ACCEPT")
	mustContain(t, out, "$IPT -A ZFW-IN -i br-+ -j ACCEPT")
}

// TestIPv6SourceRoutesToIPv6Chain locks in v0.2.22: an IPv6 source (CIDR or
// single address) must emit ONLY on ip6tables, never on iptables. Pre-fix
// the IPv4 chain happily appended "-s 2001:db8::/64" which iptables-legacy
// rejects — with `set -eu` in the engine script this aborted every apply,
// turning an IPv6 rule into a silent show-stopper.
func TestIPv6SourceRoutesToIPv6Chain(t *testing.T) {
	out := Compile(rules.RuleSet{
		LAN: "192.168.1.0/24", HostIP: "192.168.1.100", DefaultPolicy: "deny",
		Rules: []rules.Rule{{
			Order: 10, Enabled: true, Name: "Allow SSH from SLAAC prefix",
			Action:   "allow",
			Source:   rules.Source{Type: "range", Value: "2001:db8::/64"},
			Ports:    rules.Ports{Type: "list", List: []int{22}},
			Protocol: "tcp", Zone: "host",
		}},
	}, system.PublishedPorts{}, nil)
	mustContain(t, out, "$IPT6 -A ZFW-IN6 -s 2001:db8::/64 -p tcp --dport 22 -j RETURN")
	mustNotContain(t, out, "$IPT -A ZFW-IN -s 2001:db8::/64")
	// DOCKER-USER must not see the IPv6 source either — DOCKER-USER is IPv4
	// only on ZimaOS and `iptables -s <ipv6>` would abort the engine.
	mustNotContain(t, out, "$IPT -A DOCKER-USER -s 2001:db8::/64")
}

// TestIPv6SingleSourceRoutesToIPv6Chain covers the `source.type=ip` variant
// (single address rather than CIDR). Same dispatch as the range case.
func TestIPv6SingleSourceRoutesToIPv6Chain(t *testing.T) {
	out := Compile(rules.RuleSet{
		LAN: "192.168.1.0/24", DefaultPolicy: "deny",
		Rules: []rules.Rule{{
			Order: 10, Enabled: true, Name: "Allow web from one host",
			Action:   "allow",
			Source:   rules.Source{Type: "ip", Value: "2001:db8::42"},
			Ports:    rules.Ports{Type: "list", List: []int{443}},
			Protocol: "tcp", Zone: "host",
		}},
	}, system.PublishedPorts{}, nil)
	mustContain(t, out, "$IPT6 -A ZFW-IN6 -s 2001:db8::42 -p tcp --dport 443 -j RETURN")
	mustNotContain(t, out, "$IPT -A ZFW-IN -s 2001:db8::42")
}

// TestIPv4SourceStillRoutesToIPv4Chain guards the inverse: the dispatch
// change for IPv6 must NOT have broken IPv4 routing. An IPv4-source rule
// still emits on iptables (with -s) and is NOT mirrored on ip6tables
// (source6Arg returns "skip" for IPv4 values, so the IPv6 mirror is dropped
// — an IPv4 source cannot legally match an IPv6 packet).
func TestIPv4SourceStillRoutesToIPv4Chain(t *testing.T) {
	out := Compile(rules.RuleSet{
		LAN: "192.168.1.0/24", DefaultPolicy: "deny",
		Rules: []rules.Rule{{
			Order: 10, Enabled: true, Name: "SSH from LAN", Action: "allow",
			Source:   rules.Source{Type: "range", Value: "192.168.1.0/24"},
			Ports:    rules.Ports{Type: "list", List: []int{22}},
			Protocol: "tcp", Zone: "host",
		}},
	}, system.PublishedPorts{}, nil)
	mustContain(t, out, "$IPT -A ZFW-IN -s 192.168.1.0/24 -p tcp --dport 22 -j ACCEPT")
	mustNotContain(t, out, "$IPT6 -A ZFW-IN6 -s 192.168.1.0/24")
}

// TestScheduledRuleEmitsTimeClause guards the v0.4.3 time-window
// rules: a rule with a Schedule must compile to a line carrying
// `-m time --timestart … --timestop … --weekdays … --kerneltz`
// between the port match and the -j target.
func TestScheduledRuleEmitsTimeClause(t *testing.T) {
	out := Compile(rules.RuleSet{
		LAN: "192.168.1.0/24", DefaultPolicy: "deny",
		Rules: []rules.Rule{{
			Order: 10, Enabled: true, Name: "SSH business hours", Action: "allow",
			Source:   rules.Source{Type: "range", Value: "192.168.1.0/24"},
			Ports:    rules.Ports{Type: "list", List: []int{22}},
			Protocol: "tcp", Zone: "host",
			Schedule: &rules.Schedule{From: "08:00", To: "18:00", Days: []string{"mon", "tue", "wed", "thu", "fri"}},
		}},
	}, system.PublishedPorts{}, nil)
	mustContain(t, out, "$IPT -A ZFW-IN -s 192.168.1.0/24 -p tcp --dport 22 -m time --timestart 08:00 --timestop 18:00 --kerneltz --weekdays Mon,Tue,Wed,Thu,Fri -j ACCEPT")
}

// TestScheduledRuleWithoutDaysOmitsWeekdays guards the every-day
// default: an empty Days slice must produce a -m time clause without
// the --weekdays flag, so the rule applies to all seven days.
func TestScheduledRuleWithoutDaysOmitsWeekdays(t *testing.T) {
	out := Compile(rules.RuleSet{
		LAN: "192.168.1.0/24", DefaultPolicy: "deny",
		Rules: []rules.Rule{{
			Order: 10, Enabled: true, Name: "Allow always 22-06", Action: "allow",
			Source:   rules.Source{Type: "range", Value: "192.168.1.0/24"},
			Ports:    rules.Ports{Type: "list", List: []int{22}},
			Protocol: "tcp", Zone: "host",
			Schedule: &rules.Schedule{From: "22:00", To: "06:00"},
		}},
	}, system.PublishedPorts{}, nil)
	mustContain(t, out, "-m time --timestart 22:00 --timestop 06:00 --kerneltz -j ACCEPT")
	mustNotContain(t, out, "--weekdays")
}

// TestRuleWithoutScheduleEmitsNoTimeClause guards that the time
// machinery does not leak into rules without Schedule — existing
// rules from a v1 rules.json must compile to identical iptables
// lines before and after v0.4.3.
func TestRuleWithoutScheduleEmitsNoTimeClause(t *testing.T) {
	out := Compile(rules.RuleSet{
		LAN: "192.168.1.0/24", DefaultPolicy: "deny",
		Rules: []rules.Rule{{
			Order: 10, Enabled: true, Name: "SSH", Action: "allow",
			Source:   rules.Source{Type: "range", Value: "192.168.1.0/24"},
			Ports:    rules.Ports{Type: "list", List: []int{22}},
			Protocol: "tcp", Zone: "host",
		}},
	}, system.PublishedPorts{}, nil)
	mustNotContain(t, out, "-m time")
}

// TestLogTrueEmitsLogLineBeforeAction guards the v0.4.4 per-rule
// LOG toggle: a rule with Log=true must emit a `-j LOG --log-prefix
// "ZFW-RULE-<id> "` line in front of the action line. The LOG
// target is non-terminating, so the action still fires.
func TestLogTrueEmitsLogLineBeforeAction(t *testing.T) {
	out := Compile(rules.RuleSet{
		LAN: "192.168.1.0/24", DefaultPolicy: "deny",
		Rules: []rules.Rule{{
			ID: "rabcd1234", Order: 10, Enabled: true,
			Name: "SSH (debug log)", Action: "allow",
			Source:   rules.Source{Type: "range", Value: "192.168.1.0/24"},
			Ports:    rules.Ports{Type: "list", List: []int{22}},
			Protocol: "tcp", Zone: "host",
			Log: true,
		}},
	}, system.PublishedPorts{}, nil)
	logLine := `$IPT -A ZFW-IN -s 192.168.1.0/24 -p tcp --dport 22 -j LOG --log-prefix "ZFW-RULE-rabcd1234 " --log-level 6`
	actLine := "$IPT -A ZFW-IN -s 192.168.1.0/24 -p tcp --dport 22 -j ACCEPT"
	mustContain(t, out, logLine)
	mustContain(t, out, actLine)
	li := strings.Index(out, logLine)
	ai := strings.Index(out, actLine)
	if li < 0 || ai < 0 || li > ai {
		t.Errorf("LOG line must precede ACCEPT line (li=%d ai=%d)", li, ai)
	}
}

// TestRateLimitEmitsRecentClause guards the v0.4.4 per-rule rate-
// limit: a rule with RateLimit{Conn,Seconds} must emit two
// `-m recent` lines (set + update --hitcount → DROP) in front of
// the action line, sharing the same match prefix.
func TestRateLimitEmitsRecentClause(t *testing.T) {
	out := Compile(rules.RuleSet{
		LAN: "192.168.1.0/24", DefaultPolicy: "deny",
		Rules: []rules.Rule{{
			ID: "rfeed", Order: 10, Enabled: true,
			Name: "SSH (3/s)", Action: "allow",
			Source:   rules.Source{Type: "range", Value: "192.168.1.0/24"},
			Ports:    rules.Ports{Type: "list", List: []int{22}},
			Protocol: "tcp", Zone: "host",
			RateLimit: &rules.RateLimit{Conn: 3, Seconds: 1},
		}},
	}, system.PublishedPorts{}, nil)
	mustContain(t, out, "$IPT -A ZFW-IN -s 192.168.1.0/24 -p tcp --dport 22 -m recent --set --name zrfeed")
	mustContain(t, out, "$IPT -A ZFW-IN -s 192.168.1.0/24 -p tcp --dport 22 -m recent --update --seconds 1 --hitcount 3 --name zrfeed -j DROP")
	mustContain(t, out, "$IPT -A ZFW-IN -s 192.168.1.0/24 -p tcp --dport 22 -j ACCEPT")
}

// TestOutboundHostRuleEmitsZFWOut guards the v0.5.6 outbound path:
// a Direction=outbound + zone=host + deny rule must emit on ZFW-OUT
// (hooked into OUTPUT) with -d (not -s) for the peer address, and
// must NOT emit on any inbound chain.
func TestOutboundHostRuleEmitsZFWOut(t *testing.T) {
	out := Compile(rules.RuleSet{
		LAN: "192.168.1.0/24", DefaultPolicy: "deny",
		Rules: []rules.Rule{{
			ID: "rout1", Order: 10, Enabled: true,
			Name: "Block egress to known bad C2", Action: "deny",
			Source:    rules.Source{Type: "ip", Value: "203.0.113.42"},
			Ports:     rules.Ports{Type: "all"},
			Protocol:  "both",
			Zone:      "host",
			Direction: "outbound",
		}},
	}, system.PublishedPorts{}, nil)
	mustContain(t, out, "$IPT -N ZFW-OUT")
	// R4-6 (v1.0.2): destination is emitted as a strconv.Quote'd literal
	// for shell-injection defence-in-depth, so the assertion matches the
	// quoted form. rules.Validate is still the load-bearing control —
	// only digits/dots/colons/slashes reach here today.
	mustContain(t, out, `$IPT -A ZFW-OUT -d "203.0.113.42" -j DROP`)
	mustContain(t, out, "$IPT -C OUTPUT -j ZFW-OUT 2>/dev/null || $IPT -I OUTPUT 1 -j ZFW-OUT")
	// Inbound chains must not carry the outbound rule.
	mustNotContain(t, out, "$IPT -A ZFW-IN -d 203.0.113.42")
	mustNotContain(t, out, "$IPT -A ZFW-IN -s 203.0.113.42")
}

// TestOutboundDockerRuleEmitsZFWFwdOut guards container-outbound
// emission: zone=docker → ZFW-FWD-OUT (FORWARD chain).
func TestOutboundDockerRuleEmitsZFWFwdOut(t *testing.T) {
	out := Compile(rules.RuleSet{
		LAN: "192.168.1.0/24", DefaultPolicy: "deny",
		Rules: []rules.Rule{{
			ID: "rfwd1", Order: 10, Enabled: true,
			Name: "Container cannot reach metadata service", Action: "deny",
			Source:    rules.Source{Type: "ip", Value: "169.254.169.254"},
			Ports:     rules.Ports{Type: "all"},
			Protocol:  "both",
			Zone:      "docker",
			Direction: "outbound",
		}},
	}, system.PublishedPorts{}, nil)
	mustContain(t, out, "$IPT -N ZFW-FWD-OUT")
	// R4-6: quoted destination — see TestOutboundHostRuleEmitsZFWOut.
	mustContain(t, out, `$IPT -A ZFW-FWD-OUT -d "169.254.169.254" -j DROP`)
	mustContain(t, out, "$IPT -C FORWARD -j ZFW-FWD-OUT 2>/dev/null || $IPT -I FORWARD 1 -j ZFW-FWD-OUT")
}

// TestNoOutboundRulesEmitsNoOutboundChains guards back-compat: a
// rule set with zero outbound rules must compile to a script that
// does NOT reference ZFW-OUT, ZFW-OUT6 or ZFW-FWD-OUT at all — old
// inbound-only deployments stay byte-identical to pre-v0.5.6.
func TestNoOutboundRulesEmitsNoOutboundChains(t *testing.T) {
	out := Compile(rules.RuleSet{
		LAN: "192.168.1.0/24", DefaultPolicy: "deny",
		Rules: []rules.Rule{{
			Order: 10, Enabled: true, Name: "SSH", Action: "allow",
			Source:   rules.Source{Type: "range", Value: "192.168.1.0/24"},
			Ports:    rules.Ports{Type: "list", List: []int{22}},
			Protocol: "tcp", Zone: "host",
		}},
	}, system.PublishedPorts{}, nil)
	mustNotContain(t, out, "ZFW-OUT")
	mustNotContain(t, out, "ZFW-FWD-OUT")
}

// TestOutboundChainTerminatesInReturn guards the safety contract for
// outbound: the chain MUST end in RETURN — never a catch-all DROP —
// because OUTPUT default-deny would brick the host's own DNS / NTP /
// container registry pulls. v0.5.6.
func TestOutboundChainTerminatesInReturn(t *testing.T) {
	out := Compile(rules.RuleSet{
		LAN: "192.168.1.0/24", DefaultPolicy: "deny",
		Rules: []rules.Rule{{
			ID: "rout2", Order: 10, Enabled: true,
			Name: "Block bad peer", Action: "deny",
			Source:   rules.Source{Type: "ip", Value: "203.0.113.99"},
			Ports:    rules.Ports{Type: "all"},
			Protocol: "both", Zone: "host",
			Direction: "outbound",
		}},
	}, system.PublishedPorts{}, nil)
	mustContain(t, out, "$IPT -A ZFW-OUT -j RETURN")
	// No DROP on the chain as catch-all (only the per-rule DROP above).
	mustNotContain(t, out, "$IPT -A ZFW-OUT -j DROP\n")
}

// TestWireGuardWildcardBypassed guards the v0.5.4 VPN-interface
// awareness: WireGuard (wg+) joins tailscale0/zt+ in the default
// bypass list for every chain. A peer reaching the host on wg0 /
// wg-clients / wg-mesh is pre-authenticated by the protocol, so
// default-deny should not catch them.
func TestWireGuardWildcardBypassed(t *testing.T) {
	out := Compile(rules.RuleSet{DefaultPolicy: "deny"}, system.PublishedPorts{}, nil)
	mustContain(t, out, "$IPT -A ZFW-IN -i wg+ -j ACCEPT")
	mustContain(t, out, "$IPT -A DOCKER-USER -i wg+ -j RETURN")
	mustContain(t, out, "$IPT6 -A ZFW-IN6 -i wg+ -j RETURN")
}

// TestZimaNetTunnelBypassed guards the tun0 entry added 2026-08-14.
//
// ZimaOS v1.7.1-beta1 ships its own mesh, "Zima Net" (`znet 0.2.0`, an
// embedded EasyTier), which owns tun0 — the same role zt+ has for
// ZeroTier. Without the bypass, a client that has built the tunnel is
// still cut off at the last hop: measured on a ZimaCube, 125 SYNs to
// 10.126.126.10:9527 went to ZFW-IN-DROP in a single connection attempt
// and the client hung on "connecting" indefinitely, while tun0's tx
// counter stayed at 668 bytes for days.
//
// All four emitters are asserted, not just ZFW-IN: the first fix
// applied by hand only covered that chain and was therefore incomplete.
func TestZimaNetTunnelBypassed(t *testing.T) {
	out := Compile(rules.RuleSet{DefaultPolicy: "deny"}, system.PublishedPorts{}, nil)
	mustContain(t, out, "$IPT -A ZFW-IN -i tun0 -j ACCEPT")
	mustContain(t, out, "$IPT -A DOCKER-USER -i tun0 -j RETURN")
	mustContain(t, out, "$IPT6 -A ZFW-IN6 -i tun0 -j RETURN")
}

// TestExtraBypassIfacesEmittedInAllChains guards the operator-
// configured extension to the bypass list: ZFW_EXTRA_BYPASS_IFACES
// names appear in ZFW-IN, ZFW-IN6 and DOCKER-USER so a custom-named
// VPN interface ("vpn0", "wg-priv+", …) does not require forking
// the daemon.
func TestExtraBypassIfacesEmittedInAllChains(t *testing.T) {
	out := Compile(rules.RuleSet{DefaultPolicy: "deny"}, system.PublishedPorts{}, nil, "vpn0", "mesh+")
	mustContain(t, out, "$IPT -A ZFW-IN -i vpn0 -j ACCEPT")
	mustContain(t, out, "$IPT -A ZFW-IN -i mesh+ -j ACCEPT")
	mustContain(t, out, "$IPT -A DOCKER-USER -i vpn0 -j RETURN")
	mustContain(t, out, "$IPT -A DOCKER-USER -i mesh+ -j RETURN")
	mustContain(t, out, "$IPT6 -A ZFW-IN6 -i vpn0 -j RETURN")
	mustContain(t, out, "$IPT6 -A ZFW-IN6 -i mesh+ -j RETURN")
}

// TestOutboundDestQuotedAsDefenseInDepth pins the R4-6 (v1.0.2) fix:
// outbound rules emit the destination via strconv.Quote so a future
// rules.Validate relaxation cannot quietly re-open a shell-injection
// vector into the root-run compiled.sh. Validate already chokes any
// non-canonical address today; the quoting is a second wall.
func TestOutboundDestQuotedAsDefenseInDepth(t *testing.T) {
	out := Compile(rules.RuleSet{
		LAN: "192.168.1.0/24", DefaultPolicy: "deny",
		Rules: []rules.Rule{
			{
				ID: "rout46v4", Order: 10, Enabled: true,
				Name: "ipv4 outbound", Action: "deny",
				Source:   rules.Source{Type: "ip", Value: "203.0.113.42"},
				Ports:    rules.Ports{Type: "all"},
				Protocol: "both", Zone: "host",
				Direction: "outbound",
			},
			{
				ID: "rout46v6", Order: 20, Enabled: true,
				Name: "ipv6 outbound", Action: "deny",
				Source:   rules.Source{Type: "ip", Value: "2001:db8::1"},
				Ports:    rules.Ports{Type: "all"},
				Protocol: "both", Zone: "host",
				Direction: "outbound",
			},
		},
	}, system.PublishedPorts{}, nil)
	mustContain(t, out, `$IPT -A ZFW-OUT -d "203.0.113.42" -j DROP`)
	mustContain(t, out, `$IPT6 -A ZFW-OUT6 -d "2001:db8::1" -j DROP`)
}

// TestNoLogNoRateLimitNoExtraLines guards that the v0.4.4 wrapEmit
// refactor did not leak extra lines into rules that didn't opt in —
// a rule without Log and without RateLimit must compile to exactly
// the same single iptables line as pre-v0.4.4.
func TestNoLogNoRateLimitNoExtraLines(t *testing.T) {
	out := Compile(rules.RuleSet{
		LAN: "192.168.1.0/24", DefaultPolicy: "deny",
		Rules: []rules.Rule{{
			ID: "rplain", Order: 10, Enabled: true,
			Name: "SSH", Action: "allow",
			Source:   rules.Source{Type: "range", Value: "192.168.1.0/24"},
			Ports:    rules.Ports{Type: "list", List: []int{22}},
			Protocol: "tcp", Zone: "host",
		}},
	}, system.PublishedPorts{}, nil)
	mustContain(t, out, "$IPT -A ZFW-IN -s 192.168.1.0/24 -p tcp --dport 22 -j ACCEPT")
	mustNotContain(t, out, "ZFW-RULE-rplain")
	mustNotContain(t, out, "--name zrplain")
}

// TestMultiportChunksAt15Ports guards the xt_multiport kernel limit:
// a list rule with more than 15 ports must be chunked into multiple
// multiport emits — a single over-long --dports line is rejected by
// iptables at apply time and, under set -eu, aborts the whole apply
// with the chains half-built. Reachable both via a hand-entered list
// (Validate allows up to 128) and via container-binding substitution
// (uncapped).
func TestMultiportChunksAt15Ports(t *testing.T) {
	ports := make([]int, 20)
	for i := range ports {
		ports[i] = 1000 + i
	}
	out := Compile(rules.RuleSet{
		LAN: "192.168.1.0/24", DefaultPolicy: "deny",
		Rules: []rules.Rule{{
			ID: "rmany", Order: 10, Enabled: true,
			Name: "many ports", Action: "allow",
			Source:   rules.Source{Type: "range", Value: "192.168.1.0/24"},
			Ports:    rules.Ports{Type: "list", List: ports},
			Protocol: "tcp", Zone: "host",
		}},
	}, system.PublishedPorts{}, nil)
	// First chunk: ports 1000-1014 (15), second chunk: 1015-1019 (5).
	mustContain(t, out, "--dports 1000,1001,1002,1003,1004,1005,1006,1007,1008,1009,1010,1011,1012,1013,1014 ")
	mustContain(t, out, "--dports 1015,1016,1017,1018,1019 ")
	for _, line := range strings.Split(out, "\n") {
		if i := strings.Index(line, "--dports "); i >= 0 {
			spec := strings.Fields(line[i+len("--dports "):])[0]
			if n := len(strings.Split(spec, ",")); n > 15 {
				t.Errorf("multiport emit with %d ports (max 15): %s", n, line)
			}
		}
	}
}

// TestMultiportChunkOfOneFallsBackToDport guards the chunk boundary:
// 16 ports must compile to one 15-port multiport plus a plain --dport
// for the lone remainder (multiport requires at least two ports).
func TestMultiportChunkOfOneFallsBackToDport(t *testing.T) {
	ports := make([]int, 16)
	for i := range ports {
		ports[i] = 2000 + i
	}
	out := Compile(rules.RuleSet{
		LAN: "192.168.1.0/24", DefaultPolicy: "deny",
		Rules: []rules.Rule{{
			ID: "rfence", Order: 10, Enabled: true,
			Name: "16 ports", Action: "allow",
			Source:   rules.Source{Type: "range", Value: "192.168.1.0/24"},
			Ports:    rules.Ports{Type: "list", List: ports},
			Protocol: "tcp", Zone: "host",
		}},
	}, system.PublishedPorts{}, nil)
	mustContain(t, out, "--dport 2015 ")
	mustNotContain(t, out, "--dports 2015")
}

// A feed source compiles exactly like a country source, against the feed's
// own ipset: src for inbound (host and docker zones), dst for outbound, and
// the set is loaded before the rules — on both the bash and the restore path.
func TestFeedRuleInboundOutboundAndRestoreParity(t *testing.T) {
	rs := rules.RuleSet{
		LAN: "192.168.1.0/24", DefaultPolicy: "allow",
		Rules: []rules.Rule{
			{ID: "fh", Order: 10, Enabled: true, Name: "host in", Action: "deny",
				Source: rules.Source{Type: "feed", Value: "spamhaus_drop"},
				Ports:  rules.Ports{Type: "all"}, Protocol: "both", Zone: "host"},
			{ID: "fd", Order: 20, Enabled: true, Name: "docker in", Action: "deny",
				Source: rules.Source{Type: "feed", Value: "firehol_level1"},
				Ports:  rules.Ports{Type: "list", List: []int{8096}}, Protocol: "tcp", Zone: "docker"},
			{ID: "fo", Order: 30, Enabled: true, Name: "egress", Action: "deny", Direction: "outbound",
				Source: rules.Source{Type: "feed", Value: "spamhaus_drop"},
				Ports:  rules.Ports{Type: "all"}, Protocol: "both", Zone: "host"},
		},
	}
	pp := system.PublishedPorts{TCP: map[int]bool{8096: true}}
	files := map[string]string{"feed:spamhaus_drop": "/DATA/zfw/feeds/spamhaus_drop.ipset", "feed:firehol_level1": "/DATA/zfw/feeds/firehol_level1.ipset"}
	out := Compile(rs, pp, files)
	mustContain(t, out, "modprobe ip_set ip_set_hash_net xt_set")
	mustContain(t, out, `ipset restore -exist -f "/DATA/zfw/feeds/spamhaus_drop.ipset"`)
	mustContain(t, out, `ipset restore -exist -f "/DATA/zfw/feeds/firehol_level1.ipset"`)
	mustContain(t, out, "$IPT -A ZFW-IN -m set --match-set zfw-feed-spamhaus_drop src -j DROP")
	mustContain(t, out, "-m set --match-set zfw-feed-firehol_level1 src")
	mustContain(t, out, "--match-set zfw-feed-spamhaus_drop dst")
	// The set must be loaded before any rule references it.
	if strings.Index(out, "ipset restore") > strings.Index(out, "--match-set zfw-feed-") {
		t.Fatal("feed ipset is loaded after the rule that references it")
	}
	// Restore path carries the same DOCKER-USER match.
	rest := CompileRestoreScript(rs, pp, files)
	mustContain(t, rest, `ipset restore -exist -f "/DATA/zfw/feeds/firehol_level1.ipset"`)
	mustContain(t, rest, "--match-set zfw-feed-firehol_level1 src")
}
