package config

import (
	"reflect"
	"strings"
	"testing"
)

// TestIsSafeIfaceName pins the allowlist for ZFW_EXTRA_BYPASS_IFACES
// names. The compiler interpolates these into the root-run bash, so the
// allowlist is the load-bearing shell-injection control — anything that
// gets through here lands raw in compiled.sh.
func TestIsSafeIfaceName(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		// Valid.
		{"wg0", true},
		{"tailscale0", true},
		{"zt+", true}, // trailing wildcard ok
		{"wg+", true}, // trailing wildcard ok
		{"br-7bf3a1d4", true},
		{"eth0", true},
		{"a", true}, // single char ok
		{"A_b-1", true},

		// IFNAMSIZ - 1 = 15 chars max.
		{"abcdefghijklmno", true},   // 15 chars
		{"abcdefghijklmnop", false}, // 16 chars

		// Invalid: empty.
		{"", false},

		// Invalid: shell metacharacters.
		{"eth0; rm -rf /", false},
		{"eth0$(whoami)", false},
		{"eth0`id`", false},
		{"eth0|nc", false},
		{"eth0\n", false},
		{"eth0 spc", false},

		// Wildcard placement: only allowed at the very end, and never
		// alone — a bare "+" is iptables' match-ALL wildcard, which as
		// a bypass iface would silently neuter input filtering on every
		// interface.
		{"+", false},    // bare wildcard = "any iface" — rejected
		{"e+0", false},  // wildcard in the middle — rejected
		{"+wg", false},  // wildcard at the start — rejected
		{"wg++", false}, // double wildcard — rejected

		// Unicode is out.
		{"wgö", false},

		// Slash / dot — iptables iface names don't accept these.
		{"wg/0", false},
		{"wg.0", false},
	}
	for _, c := range cases {
		if got := isSafeIfaceName(c.in); got != c.want {
			t.Errorf("isSafeIfaceName(%q)=%v want %v", c.in, got, c.want)
		}
	}
}

// TestParseIfaceList covers the env-var split + filter: invalid entries
// are dropped silently (operator-supplied, do not fail loud) and the
// order of valid entries is preserved.
func TestParseIfaceList(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want []string
	}{
		{"empty", "", nil},
		{"single valid", "wg0", []string{"wg0"}},
		{"trailing wildcard", "wg+", []string{"wg+"}},
		{"two valid", "wg0,tailscale0", []string{"wg0", "tailscale0"}},
		{"whitespace stripped", " wg0 , tailscale0 ", []string{"wg0", "tailscale0"}},
		{"empty entries dropped", "wg0,,tailscale0", []string{"wg0", "tailscale0"}},
		{"invalid filtered out", "wg0,evil;rm,tailscale0", []string{"wg0", "tailscale0"}},
		{"all invalid", "evil;rm,$(id)", nil},
		{"injection attempt dropped", "; touch /tmp/x", nil},
		{"IFNAMSIZ-overrun dropped", "this-name-is-way-too-long-for-iface", nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := parseIfaceList(c.in)
			if !reflect.DeepEqual(got, c.want) {
				t.Errorf("parseIfaceList(%q)=%v want %v", c.in, got, c.want)
			}
		})
	}
}

// TestParseIfaceListNeverPanics is a belt-and-braces fuzz-shape probe:
// any operator-controlled input must produce a result without panicking
// and without leaking control characters.
func TestParseIfaceListNeverPanics(t *testing.T) {
	for _, in := range []string{
		"a,b,c", strings.Repeat(",", 200), strings.Repeat("a", 1024),
		"\x00", "\x01\x02", string(rune(0xFFFD)),
	} {
		_ = parseIfaceList(in)
	}
}
