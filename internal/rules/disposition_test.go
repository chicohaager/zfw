package rules

import "testing"

func dispRules(policy string) RuleSet {
	return RuleSet{DefaultPolicy: policy, Rules: []Rule{
		{ID: "h", Enabled: true, Name: "ssh host", Action: "allow", Source: Source{Type: "any"},
			Ports: Ports{Type: "list", List: []int{22}}, Protocol: "tcp", Zone: "host"},
		{ID: "d", Enabled: true, Name: "app docker", Action: "allow", Source: Source{Type: "any"},
			Ports: Ports{Type: "list", List: []int{8096}}, Protocol: "tcp", Zone: "docker"},
		{ID: "a", Enabled: true, Name: "either", Action: "allow", Source: Source{Type: "any"},
			Ports: Ports{Type: "range", From: 9000, To: 9010}, Protocol: "both", Zone: "auto"},
		{ID: "x", Enabled: true, Name: "deny first", Action: "deny", Source: Source{Type: "any"},
			Ports: Ports{Type: "list", List: []int{443}}, Protocol: "tcp", Zone: "host"},
		{ID: "y", Enabled: true, Name: "allow after deny", Action: "allow", Source: Source{Type: "any"},
			Ports: Ports{Type: "list", List: []int{443}}, Protocol: "tcp", Zone: "host"},
		{ID: "off", Enabled: false, Name: "disabled", Action: "allow", Source: Source{Type: "any"},
			Ports: Ports{Type: "list", List: []int{5900}}, Protocol: "tcp", Zone: "host"},
		{ID: "out", Enabled: true, Name: "outbound", Action: "allow", Source: Source{Type: "any"},
			Ports: Ports{Type: "list", List: []int{25}}, Protocol: "tcp", Zone: "host", Direction: "outbound"},
	}}
}

func TestDispositionHonoursZoneOrderAndPolicy(t *testing.T) {
	rs := dispRules("deny")
	cases := []struct {
		zone, proto string
		port        int
		want        string
	}{
		{"host", "tcp", 22, "allow"},     // host rule, host zone
		{"docker", "tcp", 22, "deny"},    // host rule does not cover docker zone
		{"docker", "tcp", 8096, "allow"}, // docker rule, docker zone
		{"host", "tcp", 8096, "deny"},    // docker rule does not cover host zone
		{"host", "udp", 9005, "allow"},   // auto + both covers either zone/proto
		{"docker", "tcp", 9010, "allow"},
		{"host", "tcp", 443, "deny"},   // first match wins: deny precedes allow
		{"host", "tcp", 5900, "deny"},  // disabled rule does not count
		{"host", "tcp", 25, "deny"},    // outbound rule does not count inbound
		{"host", "udp", 22, "deny"},    // protocol mismatch
		{"", "tcp", 8096, "allow"},     // zone "" = either
		{"host", "tcp", 12345, "deny"}, // fallthrough
	}
	for _, c := range cases {
		if got := Disposition(rs, c.zone, c.proto, c.port); got != c.want {
			t.Errorf("Disposition(%q,%q,%d)=%q, want %q", c.zone, c.proto, c.port, got, c.want)
		}
	}
	if got := Disposition(dispRules("allow"), "host", "tcp", 12345); got != "allow" {
		t.Errorf("allow policy fallthrough = %q, want allow", got)
	}
	if got := Disposition(dispRules("allow"), "host", "tcp", 443); got != "deny" {
		t.Errorf("explicit deny under allow policy = %q, want deny", got)
	}
}
