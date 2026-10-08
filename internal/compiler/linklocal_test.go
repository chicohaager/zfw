package compiler

import (
	"strings"
	"testing"

	"github.com/chicohaager/zfw/internal/rules"
)

// Until v1.0.26 ZFW-IN6 returned every packet from fe80::/10 to INPUT (policy
// ACCEPT) before a single user rule was consulted. Every device on the LAN
// could therefore reach every service listening on [::] — SSH, Samba, the
// ZimaOS UI, a docker-proxy port — through its link-local address, whatever
// the rules said, while the IPv4 path was filtered. The comment claimed ND,
// MLD and mDNSv6 needed it; ND and MLD are ICMPv6 and already pass on the
// ipv6-icmp line, only mDNS needs a link-local hole of its own.
//
// `-s ff00::/8` was dead code: a multicast address is never a valid source
// (RFC 4291 §2.7) and the kernel discards such packets before netfilter's
// filter table sees them in INPUT.
func TestV6LinkLocalNotBlanketAllowed(t *testing.T) {
	rs := rules.RuleSet{
		DefaultPolicy: "deny",
		Rules: []rules.Rule{{
			ID: "ssh", Order: 10, Enabled: true, Name: "SSH from LAN v4",
			Action: "allow", Source: rules.Source{Type: "range", Value: "192.168.1.0/24"},
			Ports:    rules.Ports{Type: "list", List: []int{22}},
			Protocol: "tcp", Zone: "host",
		}},
	}
	bash := zfwIn6Lines(Compile(rs, tcpOnly(nil), nil))
	restore := zfwIn6Rules(rs, rs.Rules, nil)

	for name, lines := range map[string][]string{"bash": bash, "restore": restore} {
		for _, l := range lines {
			if strings.Contains(l, "fe80::/10") && !strings.Contains(l, "--dport 5353") {
				t.Errorf("%s: ZFW-IN6 still lets link-local sources past the rules: %q", name, l)
			}
			if strings.Contains(l, "ff00::/8") {
				t.Errorf("%s: dead multicast-source line still emitted: %q", name, l)
			}
		}
		for _, want := range []string{
			"-p ipv6-icmp -j RETURN",                     // ND, MLD, PMTU
			"-p udp --dport 546 -j RETURN",               // DHCPv6 client
			"-s fe80::/10 -p udp --dport 5353 -j RETURN", // mDNS on the link
			"-m conntrack --ctstate NEW -j LOG --log-prefix \"ZFW-IN6-DROP \" --log-level 6",
			"-j DROP",
		} {
			if !hasLine(lines, want) {
				t.Errorf("%s: ZFW-IN6 lacks %q\n%s", name, want, strings.Join(lines, "\n"))
			}
		}
	}
}
