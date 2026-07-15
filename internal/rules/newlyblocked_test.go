package rules

import (
	"sort"
	"testing"
)

func rule(action, proto string, ports ...int) Rule {
	return Rule{
		Enabled:  true,
		Action:   action,
		Protocol: proto,
		Zone:     "host",
		Ports:    Ports{Type: "list", List: ports},
	}
}

func sortPP(pp []PortProto) []PortProto {
	sort.Slice(pp, func(i, j int) bool {
		if pp[i].Proto != pp[j].Proto {
			return pp[i].Proto < pp[j].Proto
		}
		return pp[i].Port < pp[j].Port
	})
	return pp
}

func TestNewlyBlocked(t *testing.T) {
	tests := []struct {
		name     string
		old, new RuleSet
		want     []PortProto
	}{
		{
			name: "add deny for a previously default-allowed port",
			old:  RuleSet{DefaultPolicy: "allow"},
			new:  RuleSet{DefaultPolicy: "allow", Rules: []Rule{rule("deny", "tcp", 8080)}},
			want: []PortProto{{"tcp", 8080}},
		},
		{
			name: "remove the allow rule under default-deny blocks the port",
			old:  RuleSet{DefaultPolicy: "deny", Rules: []Rule{rule("allow", "tcp", 8080)}},
			new:  RuleSet{DefaultPolicy: "deny"},
			want: []PortProto{{"tcp", 8080}},
		},
		{
			name: "flip an allow rule to deny",
			old:  RuleSet{DefaultPolicy: "deny", Rules: []Rule{rule("allow", "tcp", 7070)}},
			new:  RuleSet{DefaultPolicy: "deny", Rules: []Rule{rule("deny", "tcp", 7070)}},
			want: []PortProto{{"tcp", 7070}},
		},
		{
			name: "no change -> nothing flushed",
			old:  RuleSet{DefaultPolicy: "deny", Rules: []Rule{rule("allow", "tcp", 22)}},
			new:  RuleSet{DefaultPolicy: "deny", Rules: []Rule{rule("allow", "tcp", 22)}},
			want: nil,
		},
		{
			name: "newly ALLOWED port is not a flush target",
			old:  RuleSet{DefaultPolicy: "deny"},
			new:  RuleSet{DefaultPolicy: "deny", Rules: []Rule{rule("allow", "tcp", 9000)}},
			want: nil,
		},
		{
			name: "both-protocol deny expands to tcp and udp",
			old:  RuleSet{DefaultPolicy: "allow"},
			new:  RuleSet{DefaultPolicy: "allow", Rules: []Rule{rule("deny", "both", 5353)}},
			want: []PortProto{{"tcp", 5353}, {"udp", 5353}},
		},
		{
			name: "first-match-wins: an earlier allow shields a later deny",
			old:  RuleSet{DefaultPolicy: "deny", Rules: []Rule{rule("allow", "tcp", 80)}},
			new: RuleSet{DefaultPolicy: "deny", Rules: []Rule{
				rule("allow", "tcp", 80),
				rule("deny", "tcp", 80),
			}},
			want: nil, // still allowed by the first rule -> no transition
		},
		{
			name: "disabled deny rule does not block",
			old:  RuleSet{DefaultPolicy: "allow"},
			new: RuleSet{DefaultPolicy: "allow", Rules: []Rule{
				{Enabled: false, Action: "deny", Protocol: "tcp", Zone: "host", Ports: Ports{Type: "list", List: []int{8443}}},
			}},
			want: nil,
		},
		{
			name: "outbound deny rule is ignored for inbound conntrack",
			old:  RuleSet{DefaultPolicy: "allow"},
			new: RuleSet{DefaultPolicy: "allow", Rules: []Rule{
				{Enabled: true, Action: "deny", Protocol: "tcp", Zone: "host", Direction: "outbound", Ports: Ports{Type: "list", List: []int{443}}},
			}},
			want: nil,
		},
		{
			name: "range deny blocks each port in the span",
			old:  RuleSet{DefaultPolicy: "allow"},
			new: RuleSet{DefaultPolicy: "allow", Rules: []Rule{
				{Enabled: true, Action: "deny", Protocol: "tcp", Zone: "host", Ports: Ports{Type: "range", From: 5900, To: 5902}},
			}},
			want: []PortProto{{"tcp", 5900}, {"tcp", 5901}, {"tcp", 5902}},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := sortPP(NewlyBlocked(tc.old, tc.new))
			want := sortPP(tc.want)
			if len(got) != len(want) {
				t.Fatalf("got %v, want %v", got, want)
			}
			for i := range got {
				if got[i] != want[i] {
					t.Fatalf("got %v, want %v", got, want)
				}
			}
		})
	}
}
