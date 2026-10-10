package compiler

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/chicohaager/zfw/internal/system"
)

// Both emitters carry the zfw-live record, it round-trips, and the free-text
// fields stay out of the root-run script.
func TestLiveSnapshotInBothEmitters(t *testing.T) {
	rs := guardRuleSet()
	rs.Rules[0].Name = "evil $(reboot) `id`"
	rs.Rules[0].Notes = "note\nwith newline; touch /tmp/zfw-pwned"
	pp := system.PublishedPorts{TCP: map[int]bool{8096: true, 8097: true}, UDP: map[int]bool{1900: true}}

	for name, script := range map[string]string{
		"bash":    Compile(rs, pp, nil),
		"restore": CompileRestoreScript(rs, pp, nil),
	} {
		for _, leak := range []string{"reboot", "zfw-pwned", "`id`"} {
			if strings.Contains(script, leak) {
				t.Errorf("%s: free text %q reached the compiled script", name, leak)
			}
		}
		p := filepath.Join(t.TempDir(), "applied.sh")
		if err := os.WriteFile(p, []byte(script), 0o600); err != nil {
			t.Fatal(err)
		}
		snap, err := ReadLiveSnapshot(p)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if !snap.DNATGuard || snap.Rules.DefaultPolicy != "deny" || len(snap.Rules.Rules) != 1 ||
			snap.Rules.Rules[0].Ports.List[0] != 8096 || snap.Rules.Rules[0].Name != "" || snap.Rules.Rules[0].Notes != "" {
			t.Errorf("%s: snapshot = %+v", name, snap)
		}
		if !snap.Published(8097) || !snap.Published(1900) || snap.Published(8080) {
			t.Errorf("%s: published set wrong: tcp=%v udp=%v", name, snap.TCP, snap.UDP)
		}
	}
	allow := guardRuleSet()
	allow.DefaultPolicy = "allow"
	p := filepath.Join(t.TempDir(), "applied.sh")
	if err := os.WriteFile(p, []byte(Compile(allow, pp, nil)), 0o600); err != nil {
		t.Fatal(err)
	}
	if snap, err := ReadLiveSnapshot(p); err != nil || snap.DNATGuard {
		t.Errorf("allow policy: snapshot=%+v err=%v, want dnat_guard=false", snap, err)
	}
}

// A script from an older build has no record — "unknown", not an error that
// could be mistaken for "nothing is live".
func TestLiveSnapshotAbsent(t *testing.T) {
	p := filepath.Join(t.TempDir(), "applied.sh")
	if err := os.WriteFile(p, []byte("#!/bin/bash\nset -eu\n$IPT -F ZFW-IN\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadLiveSnapshot(p); !errors.Is(err, ErrNoLiveSnapshot) {
		t.Errorf("err = %v, want ErrNoLiveSnapshot", err)
	}
}
