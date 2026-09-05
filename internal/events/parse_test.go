package events

import (
	"testing"
	"time"
)

// parseDropLine must recognise every prefix the compiler emits. Until
// v1.0.25 two of them were missing: the per-rule LOG ("ZFW-RULE-<id> ",
// behind the "Log when this rule fires" toggle that promises visibility in
// the Events tab) and the IPv6 DOCKER-USER drop ("ZFW-DOCK6-DROP "). Both
// were parsed as "not ours" and never reached the UI.
func TestParseDropLineRecognisesEveryCompilerPrefix(t *testing.T) {
	const tail = "IN=eth0 OUT= MAC=00 SRC=192.168.1.42 DST=192.168.1.100 LEN=60 PROTO=TCP SPT=51000 DPT=22 WINDOW=64240"
	cases := []struct {
		msg      string
		wantZone string
		wantRule string
	}{
		{"ZFW-IN-DROP " + tail, "host", ""},
		{"ZFW-IN6-DROP " + tail, "host6", ""},
		{"ZFW-DOCK-DROP " + tail, "docker", ""},
		{"ZFW-DOCK6-DROP " + tail, "docker6", ""},
		{"ZFW-RULE-rabcd1234 " + tail, "rule", "rabcd1234"},
		{"ZFW-RULE-my_rule-1 " + tail, "rule", "my_rule-1"},
	}
	for _, c := range cases {
		ev, ok := parseDropLine(c.msg, "1700000000000000")
		if !ok {
			t.Errorf("%q: not recognised as a ZFW line", c.msg[:16])
			continue
		}
		if ev.Zone != c.wantZone || ev.Rule != c.wantRule {
			t.Errorf("%q: zone=%q rule=%q, want zone=%q rule=%q", c.msg[:16], ev.Zone, ev.Rule, c.wantZone, c.wantRule)
		}
		if ev.Source != "192.168.1.42" || ev.Port != 22 || ev.Protocol != "tcp" {
			t.Errorf("%q: fields not parsed: %+v", c.msg[:16], ev)
		}
	}
	// Positive control for the negative branch: a kernel line that is not
	// ours must still be refused, or the switch is not a filter.
	if _, ok := parseDropLine("audit: type=1400 "+tail, "1"); ok {
		t.Error("non-ZFW kernel line was accepted")
	}
	if _, ok := parseDropLine("ZFW-RULES-are-not-a-prefix "+tail, "1"); ok {
		t.Error("near-miss prefix ZFW-RULES- was accepted")
	}
}

// A per-rule LOG line records a match, mostly on allow rules. A client that
// is allowed to reach many ports is not scanning them, so rule events must
// stay out of the drop-based classifiers — and must not shield a real scan
// from the same source either.
func TestClassifyIgnoresRuleMatchEvents(t *testing.T) {
	base := time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)
	var events []Event
	for i := 0; i < portScanPortThreshold; i++ {
		e := mkEvent(base.Add(time.Duration(i)*time.Second), "10.0.0.7", 1000+i)
		e.Zone, e.Rule = "rule", "r1"
		events = append(events, e)
	}
	Classify(events)
	for _, e := range events {
		if len(e.Threats) != 0 {
			t.Fatalf("allow-rule matches were classified as a threat: %+v", e)
		}
	}
	// The same source dropping on the host chain must still be flagged.
	var drops []Event
	for i := 0; i < portScanPortThreshold; i++ {
		drops = append(drops, mkEvent(base.Add(time.Duration(i)*time.Second), "10.0.0.7", 2000+i))
	}
	Classify(drops)
	if !hasThreat(drops[len(drops)-1], "port_scan") {
		t.Fatal("positive control failed: real drops from the same source were not flagged")
	}
}
