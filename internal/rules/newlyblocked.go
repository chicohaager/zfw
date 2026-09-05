package rules

// newlyblocked.go computes which inbound (proto, port) pairs transition from
// allowed to denied between two rule sets. The apply path feeds the result to
// conntrack.Flush so an already-established connection to a port the operator
// just blocked is torn down immediately, instead of surviving on the
// ESTABLISHED,RELATED fast-path until it closes on its own. Without this the
// UI's "Apply" looks like it did nothing to a live connection, and the only
// way to make the block bite was a full disable/enable cycle.
//
// The disposition here deliberately mirrors the compiler's inbound matching
// (first enabled rule whose protocol + port set covers the packet wins; no
// match falls through to DefaultPolicy) but ignores the rule's source
// narrowing. Ignoring `-s` can only ever flush MORE than strictly necessary,
// never less — a conservative direction: worst case an operator's own live
// connection to a still-source-allowed port is reset once and reconnects.
// Under-flushing, by contrast, would reproduce the exact bug this closes.

// PortProto is a protocol + destination port pair. Proto is "tcp" or "udp"
// (never "both" — callers expand "both" into the two concrete protocols).
type PortProto struct {
	Proto string
	Port  int
}

// maxRangeExpand caps how many ports a single "range" rule contributes to the
// candidate set. A pathological 1-65535 range would otherwise make the diff
// O(64k) per rule; real ranges (VNC 5900-5999 etc.) are tiny. Ports beyond the
// cap are simply not considered flush candidates — safe, never over-flushes.
const maxRangeExpand = 4096

// NewlyBlocked returns the inbound (proto, port) pairs that were allowed under
// oldRS and are denied under newRS. The result is deduplicated and only spans
// ports named explicitly in either rule set (type "list"/"range"); a rule with
// ports type "all" cannot be enumerated and so is not itself a candidate
// source — a limitation that only bites the rare "flip default policy to deny"
// case, which is out of scope for a targeted per-port flush.
func NewlyBlocked(oldRS, newRS RuleSet) []PortProto {
	cands := map[PortProto]struct{}{}
	collectCandidates(oldRS, cands)
	collectCandidates(newRS, cands)

	var out []PortProto
	for pp := range cands {
		if disposition(oldRS, pp) == "allow" && disposition(newRS, pp) == "deny" {
			out = append(out, pp)
		}
	}
	return out
}

// collectCandidates adds every concrete (proto, port) an inbound rule mentions
// to set. "both" expands to tcp+udp; "range" enumerates up to maxRangeExpand.
func collectCandidates(rs RuleSet, set map[PortProto]struct{}) {
	for _, r := range rs.Rules {
		if !inbound(r) {
			continue
		}
		for _, proto := range expandProto(r.Protocol) {
			switch r.Ports.Type {
			case "list":
				for _, p := range r.Ports.List {
					set[PortProto{proto, p}] = struct{}{}
				}
			case "range":
				n := 0
				for p := r.Ports.From; p <= r.Ports.To && n < maxRangeExpand; p, n = p+1, n+1 {
					set[PortProto{proto, p}] = struct{}{}
				}
			}
		}
	}
}

// disposition reports "allow" or "deny" for one inbound packet under rs,
// following the compiler's first-match-wins ordering and DefaultPolicy
// fallthrough. Source narrowing is intentionally not considered (see file doc).
func disposition(rs RuleSet, pp PortProto) string {
	return Disposition(rs, "", pp.Proto, pp.Port)
}

// Disposition reports "allow" or "deny" for an inbound packet to port/proto
// arriving in zone ("host" for a host-native listener, "docker" for a
// Docker-published port, "" for either), under the compiler's first-match-wins
// ordering with DefaultPolicy as the fallthrough. A rule takes part when its
// zone is "auto" or equals the packet's zone — the same split portsForZone
// makes when it decides which chain a rule lands in.
//
// It exists so the dashboard's Exposure and Audit views can answer "is this
// port reachable" from rules.json, the file the firewall is actually compiled
// from. Until v1.0.25 both views read the legacy allowlist.conf, which nothing
// has written since the rule model replaced it: on every install made since,
// an active firewall showed every host socket as "blocked" and every
// port-based audit finding as "mitigated", whatever the rules said.
//
// Source narrowing (-s) is ignored, as in NewlyBlocked: a port that any one
// source may reach counts as reachable, which errs towards reporting exposure
// rather than hiding it.
func Disposition(rs RuleSet, zone, proto string, port int) string {
	for _, r := range rs.Rules {
		if !inbound(r) {
			continue
		}
		if zone != "" && r.Zone != "auto" && r.Zone != zone {
			continue
		}
		if !protoMatch(r.Protocol, proto) {
			continue
		}
		if !portMatch(r.Ports, port) {
			continue
		}
		return r.Action // "allow" | "deny" — first match wins
	}
	if rs.DefaultPolicy == "allow" {
		return "allow"
	}
	return "deny"
}

// inbound reports whether a rule participates in inbound (INPUT/DOCKER-USER)
// filtering: it must be enabled and not an explicitly-outbound rule.
func inbound(r Rule) bool {
	return r.Enabled && r.Direction != "outbound"
}

func protoMatch(ruleProto, proto string) bool {
	return ruleProto == "both" || ruleProto == proto
}

func expandProto(ruleProto string) []string {
	if ruleProto == "both" {
		return []string{"tcp", "udp"}
	}
	return []string{ruleProto}
}

func portMatch(ports Ports, port int) bool {
	switch ports.Type {
	case "all":
		return true
	case "list":
		for _, p := range ports.List {
			if p == port {
				return true
			}
		}
		return false
	case "range":
		return port >= ports.From && port <= ports.To
	}
	return false
}
