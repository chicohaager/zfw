package compiler

import (
	"strings"
	"testing"

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
		LAN: "192.168.1.0/24", HostIP: "192.168.50.23", DefaultPolicy: "deny",
	}, nil, nil)
	mustContain(t, out, "$IPT -A ZFW-IN -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT")
	mustContain(t, out, "$IPT -A ZFW-IN -j DROP")
	mustContain(t, out, "$IPT -C INPUT -j ZFW-IN")
	mustContain(t, out, "$IPT -A DOCKER-USER -s 192.168.50.23 -j RETURN")
	mustContain(t, out, "$IPT -A DOCKER-USER -s 192.168.1.0/24 -j DROP")
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
	}, nil, nil)
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
	}, nil, nil)
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
	}, map[int]bool{8888: true}, nil)
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
	}, nil, nil)
	mustNotContain(t, out, "--dport 9999")
}

func TestDefaultAllowMode(t *testing.T) {
	out := Compile(rules.RuleSet{
		LAN: "192.168.1.0/24", DefaultPolicy: "allow",
	}, nil, nil)
	mustContain(t, out, "$IPT -A ZFW-IN -j RETURN")
	mustNotContain(t, out, "$IPT -A ZFW-IN -j DROP\n")
	mustNotContain(t, out, "$IPT -A DOCKER-USER -s 192.168.1.0/24 -j DROP")
}

func TestV6Drop(t *testing.T) {
	out := Compile(rules.RuleSet{
		DefaultPolicy: "deny", V6Drop: []int{5900, 8717},
	}, nil, nil)
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
	}, nil, map[string]string{"de": "/DATA/zfw/geo/de.ipset"})
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
	}, nil, map[string]string{"ru": "/x/ru.ipset", "cn": "/x/cn.ipset"})
	mustContain(t, out, "-m set --match-set zfw-cc-ru src -j DROP")
	mustContain(t, out, "-m set --match-set zfw-cc-cn src -j DROP")
}

// TestHostPortRange locks in v0.2.16's port-range support: a rule with
// Ports.Type=="range" must emit a single iptables `--dport X:Y` line, not
// enumerate every port in between. Closes the "block VNC 5900-5999" use
// case without producing 100 multiport entries.
func TestHostPortRange(t *testing.T) {
	out := Compile(rules.RuleSet{
		LAN: "192.168.1.0/24", HostIP: "192.168.50.23", DefaultPolicy: "deny",
		Rules: []rules.Rule{{
			ID: "r1", Order: 10, Enabled: true,
			Name: "Block VNC range", Action: "deny",
			Source:   rules.Source{Type: "any"},
			Ports:    rules.Ports{Type: "range", From: 5900, To: 5999},
			Protocol: "tcp", Zone: "host",
		}},
	}, nil, nil)
	mustContain(t, out, "$IPT -A ZFW-IN -p tcp --dport 5900:5999 -j DROP")
	mustNotContain(t, out, "multiport")
}

// TestDockerPortRange covers the docker-zone variant — published-port range
// must be expressed with conntrack's range syntax.
func TestDockerPortRange(t *testing.T) {
	out := Compile(rules.RuleSet{
		LAN: "192.168.1.0/24", HostIP: "192.168.50.23", DefaultPolicy: "deny",
		Rules: []rules.Rule{{
			ID: "r1", Order: 10, Enabled: true,
			Name: "Allow container range", Action: "allow",
			Source:   rules.Source{Type: "any"},
			Ports:    rules.Ports{Type: "range", From: 8000, To: 8100},
			Protocol: "tcp", Zone: "docker",
		}},
	}, nil, nil)
	mustContain(t, out, "--ctorigdstport 8000:8100 -j RETURN")
}

// TestIPv6ChainAlwaysEmitted locks in the v0.2.15 IPv6 fix: ZFW-IN6 must be
// emitted on every build (not only when V6Drop is non-empty) so the SLAAC
// LAN gap stays closed by default.
func TestIPv6ChainAlwaysEmitted(t *testing.T) {
	out := Compile(rules.RuleSet{
		LAN: "192.168.1.0/24", HostIP: "192.168.50.23", DefaultPolicy: "deny",
	}, nil, nil)
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
		LAN: "192.168.1.0/24", HostIP: "192.168.50.23", DefaultPolicy: "deny",
	}, nil, nil)
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
		LAN: "192.168.1.0/24", HostIP: "192.168.50.23", DefaultPolicy: "deny",
		Rules: []rules.Rule{{
			Order: 10, Enabled: true, Name: "Allow SSH from SLAAC prefix",
			Action:   "allow",
			Source:   rules.Source{Type: "range", Value: "2001:db8::/64"},
			Ports:    rules.Ports{Type: "list", List: []int{22}},
			Protocol: "tcp", Zone: "host",
		}},
	}, nil, nil)
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
	}, nil, nil)
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
	}, nil, nil)
	mustContain(t, out, "$IPT -A ZFW-IN -s 192.168.1.0/24 -p tcp --dport 22 -j ACCEPT")
	mustNotContain(t, out, "$IPT6 -A ZFW-IN6 -s 192.168.1.0/24")
}
