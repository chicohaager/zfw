package compiler

import "github.com/chicohaager/zfw/internal/rules"

// V6RuleStatus is one rule's fate on the IPv6 side. Mirrored is false when
// the rule contributes no line at all to ZFW-IN6 / ZFW-OUT6, in which case
// Reason names why — the whole point of this type is that such a rule must
// not disappear in silence.
type V6RuleStatus struct {
	ID       string `json:"id"`
	Mirrored bool   `json:"mirrored"`
	Reason   string `json:"reason,omitempty"`
}

// V6Audit reports how a rule set lands on the IPv6 chains.
//
// Scope: ZFW-IN6 and ZFW-OUT6 — the chains that do the filtering on a stock
// ZimaOS, where Docker's ip6tables support is off and an inbound IPv6
// connection to a published port terminates on the host's docker-proxy
// listener (INPUT), never on FORWARD. The IPv6 DOCKER-USER chain is
// deliberately NOT counted here: it exists only once an operator turns
// Docker IPv6 on, and counting a rule as "covered" because of a chain that
// nothing jumps to is exactly the kind of substitute signal this audit
// exists to prevent.
type V6Audit struct {
	// Rules holds one entry per enabled rule, in rule order. Disabled
	// rules are omitted — they emit nothing on either family, so a badge
	// on them would say nothing about IPv6.
	Rules []V6RuleStatus `json:"rules"`
	// InboundAllows counts the enabled inbound allow rules that do reach
	// ZFW-IN6. Zero with DefaultDeny set means every inbound IPv6 packet
	// hits the catch-all DROP.
	InboundAllows int  `json:"inbound_allows"`
	DefaultDeny   bool `json:"default_deny"`
	// Blind is the condition worth warning about: a deny-by-default rule
	// set whose IPv6 chain carries not one allow. The host is then closed
	// to IPv6 no matter what the rule table appears to say.
	Blind bool `json:"blind"`
}

// AuditV6 derives the audit from the emitters themselves — hostLines6 and
// outboundLines6, the same functions Compile calls — rather than from a
// second reading of the rule model. A reimplementation here would be free
// to drift from what actually gets written into the chain, and a coverage
// report that drifts is worse than none: it would state "covered" for a
// port that is being dropped.
func AuditV6(rs rules.RuleSet) V6Audit {
	a := V6Audit{DefaultDeny: rs.DefaultPolicy != "allow"}
	for _, r := range rs.Rules {
		if !r.Enabled {
			continue
		}
		var lines []string
		if r.IsOutbound() {
			lines = outboundLines6(r)
		} else {
			lines = hostLines6(r)
		}
		st := V6RuleStatus{ID: r.ID, Mirrored: len(lines) > 0}
		if !st.Mirrored {
			st.Reason = v6SkipReason(r)
		} else if !r.IsOutbound() && r.Action != "deny" {
			a.InboundAllows++
		}
		a.Rules = append(a.Rules, st)
	}
	a.Blind = a.DefaultDeny && a.InboundAllows == 0
	return a
}

// v6SkipReason names why a rule emits nothing on IPv6. The order of the
// checks mirrors the order in which the emitters bail out, so the reason
// reported is the one that actually stopped the rule.
func v6SkipReason(r rules.Rule) string {
	switch source6Arg(r.Source) {
	case "skip":
		if r.Source.Type == "country" {
			// Geo matching runs off IPv4-only ipsets (geo.SetName sets are
			// built from IPv4 ranges); there is no v6 set to match against.
			return "country-source"
		}
		// An IPv4 address or CIDR cannot be expressed as an ip6tables
		// source match. This is the reason the LAN-scoped rules that
		// rules.Defaults seeds never reach IPv6 at all.
		return "ipv4-source"
	}
	if !r.IsOutbound() && r.Zone == "docker" && r.Ports.Type == "all" {
		// See portsForZone6: widening "every container port" into "every
		// host port" on IPv6 would switch off the default-deny for
		// host-native services, so it is refused rather than mirrored.
		return "docker-all-ports"
	}
	if r.Ports.Type == "list" && len(r.Ports.List) == 0 {
		return "no-ports"
	}
	return "not-mirrored"
}
