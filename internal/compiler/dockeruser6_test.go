package compiler

import (
	"strings"
	"testing"

	"github.com/chicohaager/zfw/internal/rules"
	"github.com/chicohaager/zfw/internal/system"
)

func denyRuleSet() rules.RuleSet {
	return rules.RuleSet{
		LAN:           "192.168.1.0/24",
		HostIP:        "192.168.1.100",
		DefaultPolicy: "deny",
	}
}

// TestDockerUser6GetsPortScopedDefaultDeny guards the second half of the
// v1.0.16 report: `ip6tables -S DOCKER-USER` returned only `-N DOCKER-USER`.
// Docker creates and jumps to that chain whenever its ip6tables support is on;
// leaving it empty means every published port is reachable over IPv6 once a
// user enables Docker IPv6.
func TestDockerUser6GetsPortScopedDefaultDeny(t *testing.T) {
	script := Compile(denyRuleSet(), tcpOnly(map[int]bool{8086: true}), nil)

	for _, want := range []string{
		`$IPT6 -A DOCKER-USER -p tcp -m conntrack --ctorigdstport 8086 --ctstate NEW -j DROP`,
		`$IPT6 -A DOCKER-USER -i docker0 -j RETURN`,
		`$IPT6 -A DOCKER-USER -j RETURN`,
	} {
		if !strings.Contains(script, want) {
			t.Errorf("compiled script missing IPv6 DOCKER-USER line:\n  %s", want)
		}
	}
	// Guarded: no ip6tables backend, or Docker's v6 DOCKER-USER absent.
	if !strings.Contains(script, `if [ -n "$IPT6" ] && $IPT6 -L DOCKER-USER -n >/dev/null 2>&1; then`) {
		t.Error("IPv6 DOCKER-USER block is not guarded on chain existence")
	}
	// v4 must keep its own prefix so Events can tell the families apart.
	if !strings.Contains(script, `ZFW-DOCK-DROP `) || !strings.Contains(script, `ZFW-DOCK6-DROP `) {
		t.Error("want distinct v4/v6 drop log prefixes")
	}
}

// TestDockerUser6EmptyPortsNoDeny: with no published ports there is nothing to
// scope a deny to. The chain must still terminate in RETURN rather than
// swallowing forwarded container traffic.
func TestDockerUser6EmptyPortsNoDeny(t *testing.T) {
	script := Compile(denyRuleSet(), system.PublishedPorts{}, nil)
	if strings.Contains(script, "ZFW-DOCK6-DROP") {
		t.Error("emitted an IPv6 deny with no published ports to scope it to")
	}
	if !strings.Contains(script, `$IPT6 -A DOCKER-USER -j RETURN`) {
		t.Error("IPv6 DOCKER-USER must terminate in RETURN")
	}
}

// TestBackendFamilyProbedNotNameMatched guards the shell side of the same bug
// fixed in firewall.v6For: `case "$IPT" in *nft*)` misreads the plain
// `iptables` alternatives symlink, which drives nf_tables on ZimaOS 1.6.2
// despite its name, and pins IPT6 to the legacy table.
func TestBackendFamilyProbedNotNameMatched(t *testing.T) {
	for _, script := range []string{
		Compile(denyRuleSet(), tcpOnly(map[int]bool{8086: true}), nil),
		CompileRestoreScript(denyRuleSet(), tcpOnly(map[int]bool{8086: true}), nil),
	} {
		if strings.Contains(script, `case "$IPT" in *nft*)`) {
			t.Error("backend family still inferred from the binary name")
		}
		if !strings.Contains(script, `_zfw_fam(){`) || !strings.Contains(script, `IPTFAM="$(_zfw_fam "$IPT")"`) {
			t.Error("backend family must be probed via `iptables -V`")
		}
	}
}

// TestRestoreV6DeclaresDockerUser: the atomic restore path is what production
// actually runs, so the v6 chain has to be in the restore document too.
func TestRestoreV6DeclaresDockerUser(t *testing.T) {
	rest := CompileRestore(denyRuleSet(), tcpOnly(map[int]bool{8086: true}))
	if !strings.Contains(rest.V6, ":DOCKER-USER - [0:0]") {
		t.Error("restore V6 document does not declare DOCKER-USER")
	}
	if !strings.Contains(rest.V6, "-A DOCKER-USER -p tcp -m conntrack --ctorigdstport 8086 --ctstate NEW -j DROP") {
		t.Error("restore V6 document lacks the port-scoped default-deny")
	}
}

// tcpOnly wraps a bare port set as a TCP-only published-port inventory, the
// shape every pre-v1.0.17 test assumed implicitly.
func tcpOnly(ports map[int]bool) system.PublishedPorts {
	return system.PublishedPorts{TCP: ports, UDP: map[int]bool{}}
}
