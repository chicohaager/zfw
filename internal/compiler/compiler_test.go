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
