package rules

import (
	"net"
	"strings"
)

// Reach is the source-aware answer to "who can open a new connection to this
// port", as the dashboard's Exposure view needs it (v1.0.27).
//
// Disposition answers a narrower question — "does any rule let anything in" —
// and deliberately ignores sources, which is right for the conntrack flush and
// for the audit (both must err towards "reachable") but made Exposure show a
// port allowed from one single address exactly like a port open to the whole
// LAN. ReachOf keeps that conservative direction and adds one honest middle
// state:
//
//   - "open":       reachable from the LAN or wider (any source, the LAN range
//     itself, a country, a feed, a large range).
//   - "restricted": reachable only from the small sources listed in Sources —
//     single addresses, IPv4 ranges of /24 or narrower and IPv6 of /64 or
//     narrower that do not contain the whole LAN.
//   - "closed":     nothing reaches it.
//
// Conservative choices, all of them towards reporting more reach, never less:
//   - a deny rule only ends the walk when it is unconditional — source "any"
//     and no schedule. A deny for some sources, or for some hours, leaves
//     everyone else to the rules below it.
//   - a scheduled or rate-limited allow counts as an allow.
type Reach struct {
	Verdict string   // "open" | "restricted" | "closed"
	Sources []string // the restricting sources when Verdict == "restricted"
}

// ReachOf walks rs for an inbound packet to port/proto arriving in zone
// ("host" or "docker"). dockerKnown says whether, for zone "docker", the port
// was in the published-port inventory the ruleset was compiled against: the
// compiler only routes zone-"auto" port lists into DOCKER-USER for ports it
// knew to be Docker-published (portsForZone), so for a port published later
// only zone-"docker" rules exist in that chain.
func ReachOf(rs RuleSet, zone, proto string, port int, dockerKnown bool) Reach {
	var narrow []string
	stopped := false // the walk ended on an unconditional deny
	for _, r := range rs.Rules {
		if !inbound(r) || !protoMatch(r.Protocol, proto) || !portMatch(r.Ports, port) {
			continue
		}
		if !reachesChain(r, zone, dockerKnown) {
			continue
		}
		if r.Action == "deny" {
			if r.Source.Type == "any" && r.Schedule == nil {
				stopped = true
				break
			}
			continue
		}
		if !narrowSource(r.Source, rs.LAN) {
			return Reach{Verdict: "open"}
		}
		narrow = appendUnique(narrow, r.Source.Value)
	}
	if !stopped && rs.DefaultPolicy == "allow" {
		return Reach{Verdict: "open"}
	}
	if len(narrow) > 0 {
		return Reach{Verdict: "restricted", Sources: narrow}
	}
	return Reach{Verdict: "closed"}
}

// reachesChain mirrors the compiler's portsForZone split: which rules end up
// in the chain that filters this packet.
func reachesChain(r Rule, zone string, dockerKnown bool) bool {
	switch zone {
	case "host":
		return r.Zone == "host" || r.Zone == "auto"
	case "docker":
		if r.Zone == "docker" {
			return true
		}
		// auto + all / range go to the host chain only; auto + list reaches
		// DOCKER-USER only for ports known to be Docker-published.
		return r.Zone == "auto" && r.Ports.Type == "list" && dockerKnown
	}
	return r.Zone == "auto" || r.Zone == zone
}

// narrowSource reports whether a source is small enough to count as a
// restriction rather than as LAN-wide exposure. Unknown or unparsable values
// count as wide.
func narrowSource(s Source, lan string) bool {
	switch s.Type {
	case "ip":
		return net.ParseIP(s.Value) != nil
	case "range":
		_, n, err := net.ParseCIDR(s.Value)
		if err != nil {
			return false
		}
		ones, bits := n.Mask.Size()
		if bits == 32 && ones < 24 || bits == 128 && ones < 64 {
			return false
		}
		if _, ln, err := net.ParseCIDR(lan); err == nil {
			lOnes, lBits := ln.Mask.Size()
			if lBits == bits && ones <= lOnes && n.Contains(ln.IP) {
				return false // the source covers the whole LAN
			}
		}
		return true
	}
	return false // any, country, feed
}

func appendUnique(xs []string, v string) []string {
	v = strings.TrimSpace(v)
	for _, x := range xs {
		if x == v {
			return xs
		}
	}
	return append(xs, v)
}
