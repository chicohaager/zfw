package compiler

import (
	"fmt"
	"sort"
	"strings"

	"github.com/chicohaager/zfw/internal/rules"
)

// CompileRestore is the B4 (v1.1) atomic-apply path: instead of the
// line-by-line `iptables -A` bash script, it emits `iptables-restore`
// table documents so the whole ZFW ruleset for a table is swapped in one
// atomic operation. A malformed ruleset is then rejected wholesale (and
// can be pre-validated with `iptables-restore --test`) instead of
// aborting a bash script half-applied.
//
// Scope of this first cut (offline generator only — NOT wired into the
// engine yet):
//   - V4 carries the IPv4 ZFW chains: ZFW-IN, DOCKER-USER, and the
//     outbound ZFW-OUT / ZFW-FWD-OUT when outbound rules exist.
//   - V6 carries the IPv6 chains: ZFW-IN6 and ZFW-OUT6.
//
// The documents are meant to be applied with `iptables-restore --noflush`
// (and `ip6tables-restore --noflush` for V6): each `:CHAIN - [0:0]` line
// flushes-and-recreates ONLY that ZFW-owned chain, leaving INPUT,
// DOCKER-USER's Docker-managed neighbours, FORWARD and every other chain
// untouched — which is why a full `*filter` replace (that would wipe
// Docker's own chains) is deliberately NOT used.
//
// The chain-jump hooks (`-I INPUT 1 -j ZFW-IN`, etc.), the ipset restore
// and the modprobe preamble are intentionally NOT in these documents:
// they are idempotent / non-atomic shell steps that stay in the engine
// wrapper. The rule *content* here is produced from the same helpers the
// proven bash path uses (hostLines / dockerLines / hostLines6 /
// outboundLines / outboundLines6), and TestRestoreMatchesBashRules pins
// that the per-chain rule sequences are identical to Compile()'s output.
type RestoreScript struct {
	V4 string // iptables-restore --noflush input (filter table)
	V6 string // ip6tables-restore --noflush input (filter table)
}

// CompileRestore builds the restore documents for a rule set. dockerPorts
// resolves zone "auto"; extraBypass appends inbound-bypass interfaces
// (already validated by the caller, as for Compile).
func CompileRestore(rs rules.RuleSet, dockerPorts map[int]bool, extraBypass ...string) RestoreScript {
	rl := append([]rules.Rule(nil), rs.Rules...)
	sort.SliceStable(rl, func(i, j int) bool { return rl[i].Order < rl[j].Order })

	return RestoreScript{
		V4: restoreV4(rs, rl, dockerPorts, extraBypass),
		V6: restoreV6(rs, rl, dockerPorts, extraBypass),
	}
}

// restoreV4 emits the IPv4 filter table: ZFW-IN + DOCKER-USER, plus the
// outbound chains when present. Chain declarations precede all -A lines,
// as iptables-restore requires.
func restoreV4(rs rules.RuleSet, rl []rules.Rule, dockerPorts map[int]bool, extraBypass []string) string {
	hasHostOut, hasDockerOut := outboundZones(rl)

	chains := []string{"ZFW-IN", "DOCKER-USER"}
	if hasHostOut {
		chains = append(chains, "ZFW-OUT")
	}
	if hasDockerOut {
		chains = append(chains, "ZFW-FWD-OUT")
	}

	var b strings.Builder
	b.WriteString("*filter\n")
	for _, c := range chains {
		fmt.Fprintf(&b, ":%s - [0:0]\n", c)
	}
	writeChain(&b, "ZFW-IN", zfwInRules(rs, rl, dockerPorts, extraBypass))
	writeChain(&b, "DOCKER-USER", dockerUserRules(rs, rl, dockerPorts, extraBypass))
	if hasHostOut {
		writeChain(&b, "ZFW-OUT", zfwOutRules(rl))
	}
	if hasDockerOut {
		writeChain(&b, "ZFW-FWD-OUT", zfwFwdOutRules(rl))
	}
	b.WriteString("COMMIT\n")
	return b.String()
}

// restoreV6 emits the IPv6 filter table: ZFW-IN6, plus ZFW-OUT6 when host
// outbound rules exist (the engine wrapper runs this only when an
// ip6tables backend is present).
func restoreV6(rs rules.RuleSet, rl []rules.Rule, dockerPorts map[int]bool, extraBypass []string) string {
	hasHostOut, _ := outboundZones(rl)

	chains := []string{"ZFW-IN6"}
	if hasHostOut {
		chains = append(chains, "ZFW-OUT6")
	}

	var b strings.Builder
	b.WriteString("*filter\n")
	for _, c := range chains {
		fmt.Fprintf(&b, ":%s - [0:0]\n", c)
	}
	writeChain(&b, "ZFW-IN6", zfwIn6Rules(rs, rl, dockerPorts, extraBypass))
	if hasHostOut {
		writeChain(&b, "ZFW-OUT6", zfwOut6Rules(rl))
	}
	b.WriteString("COMMIT\n")
	return b.String()
}

func writeChain(b *strings.Builder, chain string, ruleArgs []string) {
	for _, a := range ruleArgs {
		fmt.Fprintf(b, "-A %s %s\n", chain, a)
	}
}

// outboundZones reports whether any enabled outbound rule targets the
// host (ZFW-OUT/ZFW-OUT6) and/or docker (ZFW-FWD-OUT) chains. Mirrors the
// gate in emitOutboundChains.
func outboundZones(rl []rules.Rule) (host, docker bool) {
	for _, r := range rl {
		if !r.Enabled || !r.IsOutbound() {
			continue
		}
		if r.Zone == "host" || r.Zone == "auto" {
			host = true
		}
		if r.Zone == "docker" || r.Zone == "auto" {
			docker = true
		}
	}
	return host, docker
}

// The following *Rules builders return the ordered rule arguments (the
// text after "-A <chain>") for each ZFW chain. They reproduce exactly the
// rule content emitted by the bash path in compiler.go; the static
// bypass/default lines are duplicated here deliberately and pinned
// identical by TestRestoreMatchesBashRules so the two paths cannot drift.

func zfwInRules(rs rules.RuleSet, rl []rules.Rule, dockerPorts map[int]bool, extraBypass []string) []string {
	out := []string{
		"-m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
		"-m conntrack --ctstate INVALID -j DROP",
		"-i lo -j ACCEPT",
		"-i docker0 -j ACCEPT",
		"-i br-+ -j ACCEPT",
		"-i virbr0 -j ACCEPT",
		"-i tailscale0 -j ACCEPT",
		"-i zt+ -j ACCEPT",
		"-i wg+ -j ACCEPT",
		"-p icmp -j ACCEPT",
		"-p udp --dport 68 -j ACCEPT",
		"-p udp --dport 41641 -j ACCEPT",
		"-p udp --dport 9993 -j ACCEPT",
	}
	for _, iface := range extraBypass {
		out = append(out, "-i "+iface+" -j ACCEPT")
	}
	for _, r := range rl {
		if !r.Enabled {
			continue
		}
		out = append(out, hostLines(r, dockerPorts)...)
	}
	if rs.DefaultPolicy == "allow" {
		out = append(out, "-j RETURN")
	} else {
		out = append(out,
			"-m conntrack --ctstate NEW -j LOG --log-prefix \"ZFW-IN-DROP \" --log-level 6",
			"-j DROP")
	}
	return out
}

func dockerUserRules(rs rules.RuleSet, rl []rules.Rule, dockerPorts map[int]bool, extraBypass []string) []string {
	out := []string{
		"-m conntrack --ctstate ESTABLISHED,RELATED -j RETURN",
		"-s 127.0.0.0/8 -j RETURN",
	}
	if rs.HostIP != "" {
		out = append(out, "-s "+rs.HostIP+" -j RETURN")
	}
	out = append(out,
		"-i tailscale0 -j RETURN",
		"-i zt+ -j RETURN",
		"-i wg+ -j RETURN")
	for _, iface := range extraBypass {
		out = append(out, "-i "+iface+" -j RETURN")
	}
	for _, r := range rl {
		if !r.Enabled {
			continue
		}
		out = append(out, dockerLines(r, dockerPorts)...)
	}
	if rs.DefaultPolicy == "deny" && rs.LAN != "" {
		out = append(out,
			"-s "+rs.LAN+" -m conntrack --ctstate NEW -j LOG --log-prefix \"ZFW-DOCK-DROP \" --log-level 6",
			"-s "+rs.LAN+" -j DROP")
	}
	out = append(out, "-j RETURN")
	return out
}

func zfwIn6Rules(rs rules.RuleSet, rl []rules.Rule, dockerPorts map[int]bool, extraBypass []string) []string {
	out := []string{
		"-m conntrack --ctstate ESTABLISHED,RELATED -j RETURN",
		"-m conntrack --ctstate INVALID -j DROP",
		"-i lo -j RETURN",
		"-i docker0 -j RETURN",
		"-i br-+ -j RETURN",
		"-i virbr0 -j RETURN",
		"-i tailscale0 -j RETURN",
		"-i zt+ -j RETURN",
		"-i wg+ -j RETURN",
	}
	for _, iface := range extraBypass {
		out = append(out, "-i "+iface+" -j RETURN")
	}
	out = append(out,
		"-p ipv6-icmp -j RETURN",
		"-p udp --dport 546 -j RETURN",
		"-s fe80::/10 -j RETURN",
		"-s ff00::/8 -j RETURN")
	for _, r := range rl {
		if !r.Enabled {
			continue
		}
		out = append(out, hostLines6(r, dockerPorts)...)
	}
	for _, p := range rs.V6Drop {
		out = append(out, fmt.Sprintf("-p tcp --dport %d -j DROP", p))
	}
	if rs.DefaultPolicy == "allow" {
		out = append(out, "-j RETURN")
	} else {
		out = append(out,
			"-m conntrack --ctstate NEW -j LOG --log-prefix \"ZFW-IN6-DROP \" --log-level 6",
			"-j DROP")
	}
	return out
}

func zfwOutRules(rl []rules.Rule) []string {
	out := []string{
		"-m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
		"-o lo -j ACCEPT",
	}
	for _, r := range rl {
		if !r.Enabled || !r.IsOutbound() {
			continue
		}
		if r.Zone != "host" && r.Zone != "auto" {
			continue
		}
		if isIPv6Source(r.Source) {
			continue
		}
		out = append(out, outboundLines(r)...)
	}
	out = append(out, "-j RETURN")
	return out
}

func zfwOut6Rules(rl []rules.Rule) []string {
	out := []string{
		"-m conntrack --ctstate ESTABLISHED,RELATED -j RETURN",
		"-o lo -j RETURN",
	}
	for _, r := range rl {
		if !r.Enabled || !r.IsOutbound() {
			continue
		}
		if r.Zone != "host" && r.Zone != "auto" {
			continue
		}
		out = append(out, outboundLines6(r)...)
	}
	out = append(out, "-j RETURN")
	return out
}

func zfwFwdOutRules(rl []rules.Rule) []string {
	out := []string{
		"-m conntrack --ctstate ESTABLISHED,RELATED -j RETURN",
	}
	for _, r := range rl {
		if !r.Enabled || !r.IsOutbound() {
			continue
		}
		if r.Zone != "docker" && r.Zone != "auto" {
			continue
		}
		if isIPv6Source(r.Source) {
			continue
		}
		out = append(out, outboundLines(r)...)
	}
	out = append(out, "-j RETURN")
	return out
}
