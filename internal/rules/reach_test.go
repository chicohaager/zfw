package rules

import (
	"reflect"
	"testing"
)

func reachRule(id, action, zone string, src Source, ports Ports) Rule {
	return Rule{ID: id, Enabled: true, Name: id, Action: action, Source: src, Ports: ports, Protocol: "tcp", Zone: zone}
}

var (
	anySrc = Source{Type: "any"}
	p22    = Ports{Type: "list", List: []int{22}}
)

func TestReachOf(t *testing.T) {
	lan := "192.0.2.0/24"
	cases := []struct {
		name  string
		rs    RuleSet
		zone  string
		known bool
		want  Reach
	}{
		{"no rule, deny policy", RuleSet{LAN: lan, DefaultPolicy: "deny"}, "host", true, Reach{Verdict: "closed"}},
		{"no rule, allow policy", RuleSet{LAN: lan, DefaultPolicy: "allow"}, "host", true, Reach{Verdict: "open"}},
		{"allow any", RuleSet{LAN: lan, DefaultPolicy: "deny", Rules: []Rule{reachRule("a", "allow", "host", anySrc, p22)}}, "host", true, Reach{Verdict: "open"}},
		{"allow LAN range", RuleSet{LAN: lan, DefaultPolicy: "deny", Rules: []Rule{reachRule("a", "allow", "host", Source{Type: "range", Value: lan}, p22)}}, "host", true, Reach{Verdict: "open"}},
		{"allow range wider than LAN", RuleSet{LAN: lan, DefaultPolicy: "deny", Rules: []Rule{reachRule("a", "allow", "host", Source{Type: "range", Value: "192.0.0.0/22"}, p22)}}, "host", true, Reach{Verdict: "open"}},
		{"allow country", RuleSet{LAN: lan, DefaultPolicy: "deny", Rules: []Rule{reachRule("a", "allow", "host", Source{Type: "country", Value: "DE"}, p22)}}, "host", true, Reach{Verdict: "open"}},
		{"allow one ip", RuleSet{LAN: lan, DefaultPolicy: "deny", Rules: []Rule{reachRule("a", "allow", "host", Source{Type: "ip", Value: "192.0.2.10"}, p22)}}, "host", true, Reach{Verdict: "restricted", Sources: []string{"192.0.2.10"}}},
		{"allow other /24 (VPN)", RuleSet{LAN: lan, DefaultPolicy: "deny", Rules: []Rule{reachRule("a", "allow", "host", Source{Type: "range", Value: "198.51.100.0/24"}, p22)}}, "host", true, Reach{Verdict: "restricted", Sources: []string{"198.51.100.0/24"}}},
		{"allow v6 /64", RuleSet{LAN: lan, DefaultPolicy: "deny", Rules: []Rule{reachRule("a", "allow", "host", Source{Type: "range", Value: "2001:db8::/64"}, p22)}}, "host", true, Reach{Verdict: "restricted", Sources: []string{"2001:db8::/64"}}},
		{"restricted then any", RuleSet{LAN: lan, DefaultPolicy: "deny", Rules: []Rule{
			reachRule("a", "allow", "host", Source{Type: "ip", Value: "192.0.2.10"}, p22),
			reachRule("b", "allow", "host", anySrc, p22)}}, "host", true, Reach{Verdict: "open"}},
		{"restricted then deny any", RuleSet{LAN: lan, DefaultPolicy: "allow", Rules: []Rule{
			reachRule("a", "allow", "host", Source{Type: "ip", Value: "192.0.2.10"}, p22),
			reachRule("b", "deny", "host", anySrc, p22)}}, "host", true, Reach{Verdict: "restricted", Sources: []string{"192.0.2.10"}}},
		// A deny for one source leaves everyone else to the default.
		{"partial deny under allow", RuleSet{LAN: lan, DefaultPolicy: "allow", Rules: []Rule{
			reachRule("a", "deny", "host", Source{Type: "ip", Value: "192.0.2.66"}, p22)}}, "host", true, Reach{Verdict: "open"}},
		// A deny that only holds at certain hours does not close the port.
		{"scheduled deny under allow", RuleSet{LAN: lan, DefaultPolicy: "allow", Rules: []Rule{func() Rule {
			r := reachRule("a", "deny", "host", anySrc, p22)
			r.Schedule = &Schedule{From: "22:00", To: "06:00"}
			return r
		}()}}, "host", true, Reach{Verdict: "open"}},
		// auto + list reaches DOCKER-USER only for ports known at compile time.
		{"auto list, docker port unknown", RuleSet{LAN: lan, DefaultPolicy: "deny", Rules: []Rule{reachRule("a", "allow", "auto", anySrc, p22)}}, "docker", false, Reach{Verdict: "closed"}},
		{"auto list, docker port known", RuleSet{LAN: lan, DefaultPolicy: "deny", Rules: []Rule{reachRule("a", "allow", "auto", anySrc, p22)}}, "docker", true, Reach{Verdict: "open"}},
		// auto + range never reaches DOCKER-USER (portsForZone).
		{"auto range on docker", RuleSet{LAN: lan, DefaultPolicy: "deny", Rules: []Rule{reachRule("a", "allow", "auto", anySrc, Ports{Type: "range", From: 1, To: 100})}}, "docker", true, Reach{Verdict: "closed"}},
	}
	for _, c := range cases {
		got := ReachOf(c.rs, c.zone, "tcp", 22, c.known)
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: got %+v, want %+v", c.name, got, c.want)
		}
	}
}
