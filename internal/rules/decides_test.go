package rules

import "testing"

// Decides is the new-app prompt's "somebody already chose for this port".
// A rule that names the port chose, whatever its action or source. A rule for
// all ports chose only when it speaks for the whole LAN: a country or feed
// deny, or an allow for one admin PC, says nothing about who else on the LAN
// may reach a new app — before this fix one such rule silenced the prompt for
// every port, and new container ports stayed closed by the DNAT guard without
// a word (review of v1.0.28, 2026-10-09).
func TestDecidesAllPortsOnlyWhenItSpeaksForTheLAN(t *testing.T) {
	lan := "192.0.2.0/24"
	all := Ports{Type: "all"}
	r := func(action string, src Source, ports Ports, zone string) Rule {
		return Rule{ID: "x", Enabled: true, Action: action, Source: src, Ports: ports, Protocol: "tcp", Zone: zone}
	}
	cases := []struct {
		name string
		rule Rule
		zone string
		want bool
	}{
		{"list names the port (deny)", r("deny", Source{Type: "any"}, Ports{Type: "list", List: []int{8080}}, "docker"), "docker", true},
		{"list names the port (allow one IP)", r("allow", Source{Type: "ip", Value: "192.0.2.5"}, Ports{Type: "list", List: []int{8080}}, "docker"), "docker", true},
		{"range contains the port", r("deny", Source{Type: "any"}, Ports{Type: "range", From: 8000, To: 8100}, "docker"), "docker", true},
		{"all ports, country deny", r("deny", Source{Type: "country", Value: "CN"}, all, "docker"), "docker", false},
		{"all ports, feed deny", r("deny", Source{Type: "feed", Value: "firehol_level1"}, all, "host"), "host", false},
		{"all ports, admin PC allow", r("allow", Source{Type: "ip", Value: "192.0.2.5"}, all, "host"), "host", false},
		{"all ports, small range", r("allow", Source{Type: "range", Value: "192.0.2.0/28"}, all, "host"), "host", false},
		{"all ports, any source allow", r("allow", Source{Type: "any"}, all, "docker"), "docker", true},
		{"all ports, any source deny", r("deny", Source{Type: "any"}, all, "host"), "host", true},
		{"all ports, range covering the LAN", r("allow", Source{Type: "range", Value: "192.0.0.0/16"}, all, "host"), "host", true},
		{"all ports, LAN-wide but scheduled", Rule{ID: "x", Enabled: true, Action: "allow", Source: Source{Type: "any"}, Ports: all,
			Protocol: "tcp", Zone: "host", Schedule: &Schedule{From: "08:00", To: "18:00"}}, "host", false},
	}
	for _, c := range cases {
		rs := RuleSet{LAN: lan, DefaultPolicy: "deny", Rules: []Rule{c.rule}}
		if got := Decides(rs, c.zone, "tcp", 8080); got != c.want {
			t.Errorf("%s: Decides = %v, want %v", c.name, got, c.want)
		}
	}
}
