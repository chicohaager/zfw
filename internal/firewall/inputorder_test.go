package firewall

import (
	"reflect"
	"strings"
	"testing"
)

// The dump a real ZimaOS host produced with a blocklist module and Tailscale
// installed: ZFW-IN had been pushed to position 3 without ZFW noticing.
const dumpBehindTwo = `-P INPUT ACCEPT
-A INPUT -j IPBLOCKLIST
-A INPUT -j ts-input
-A INPUT -j ZFW-IN
-A INPUT -j LIBVIRT_INP
`

func TestInputOrderReportsPositionAndPredecessors(t *testing.T) {
	pos, before := inputOrder(dumpBehindTwo, "ZFW-IN")
	if pos != 3 {
		t.Fatalf("position = %d, want 3", pos)
	}
	if want := []string{"-j IPBLOCKLIST", "-j ts-input"}; !reflect.DeepEqual(before, want) {
		t.Fatalf("before = %q, want %q", before, want)
	}
}

func TestInputOrderFirstIsCleanAndAbsentIsZero(t *testing.T) {
	pos, before := inputOrder("-P INPUT ACCEPT\n-A INPUT -j ZFW-IN\n-A INPUT -j DOCKER-USER\n", "ZFW-IN")
	if pos != 1 || len(before) != 0 {
		t.Fatalf("hooked first: pos=%d before=%q, want 1 and none", pos, before)
	}
	pos, before = inputOrder("-P INPUT ACCEPT\n-A INPUT -j ts-input\n", "ZFW-IN")
	if pos != 0 || before != nil {
		t.Fatalf("not hooked: pos=%d before=%v, want 0 and nil", pos, before)
	}
	// An empty dump (iptables failed / chain absent) must not panic or
	// invent a position.
	if pos, _ := inputOrder("", "ZFW-IN"); pos != 0 {
		t.Fatalf("empty dump: pos=%d, want 0", pos)
	}
}

func TestInputOrderKeepsMatchRulesAndIgnoresOtherChains(t *testing.T) {
	// A permissive rule with a match ahead of ZFW-IN is exactly the case
	// the field exists for; it must be reported verbatim, and a foreign
	// chain's lines that happen to name the target must not count.
	dump := "-P INPUT ACCEPT\n" +
		"-A INPUT -i lo -j ACCEPT\n" +
		"-A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT\n" +
		"-A FORWARD -j ZFW-IN\n" +
		"-A INPUT -j ZFW-IN\n"
	pos, before := inputOrder(dump, "ZFW-IN")
	if pos != 3 {
		t.Fatalf("position = %d, want 3 (the FORWARD line must not count)", pos)
	}
	if len(before) != 2 || before[1] != "-m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT" {
		t.Fatalf("before = %q", before)
	}
	// The v6 target is a different chain; a v4 dump must not match it.
	if pos, _ := inputOrder(dump, "ZFW-IN6"); pos != 0 {
		t.Fatalf("ZFW-IN6 in a v4 dump: pos=%d, want 0", pos)
	}
}

func TestInputOrderCapsPredecessorList(t *testing.T) {
	var sb strings.Builder
	sb.WriteString("-P INPUT ACCEPT\n")
	for i := 0; i < maxInputBefore+40; i++ {
		sb.WriteString("-A INPUT -s 203.0.113.1 -j DROP\n")
	}
	sb.WriteString("-A INPUT -j ZFW-IN\n")
	pos, before := inputOrder(sb.String(), "ZFW-IN")
	if pos != maxInputBefore+41 {
		t.Fatalf("position = %d, want %d (the cap must not alter the count)", pos, maxInputBefore+41)
	}
	if len(before) != maxInputBefore {
		t.Fatalf("before has %d entries, want cap %d", len(before), maxInputBefore)
	}
}
