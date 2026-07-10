package firewall

import (
	"os"
	"path/filepath"
	"testing"
)

// fakeIptables installs a stub binary on PATH that answers `-V` the way the
// real one does. name is the binary, ver is the parenthesised backend marker.
func fakeIptables(t *testing.T, dir, name, ver string) {
	t.Helper()
	script := "#!/bin/sh\ncase \"$1\" in -V) echo '" + name + " v1.8.11 (" + ver + ")';; *) exit 1;; esac\n"
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
}

// TestV6ForFollowsBackendNotBinaryName is the regression guard for the
// "IPv6 protection ✗ while ZFW-IN6 is live" bug reported on ZimaOS 1.6.2
// (v1.0.16). When the Docker-FORWARD probe finds nothing, New() falls back to
// the plain "iptables" alternatives symlink. That name has no "nft" in it, but
// on 1.6.2 it drives nf_tables. The old code keyed off the name and pinned
// IPv6 to ip6tables-legacy — an empty table — so Status reported ✗.
func TestV6ForFollowsBackendNotBinaryName(t *testing.T) {
	dir := t.TempDir()
	// The exact ZimaOS 1.6.2 layout: every binary exists, `iptables` is the
	// alternatives symlink pointing at the nft backend.
	fakeIptables(t, dir, "iptables", "nf_tables")
	fakeIptables(t, dir, "iptables-legacy", "legacy")
	fakeIptables(t, dir, "ip6tables", "nf_tables")
	fakeIptables(t, dir, "ip6tables-nft", "nf_tables")
	fakeIptables(t, dir, "ip6tables-legacy", "legacy")
	t.Setenv("PATH", dir)

	if got := familyOf("iptables"); got != "nft" {
		t.Fatalf("familyOf(iptables) = %q, want nft (the -V line says nf_tables)", got)
	}
	if got := v6For("iptables"); got != "ip6tables-nft" {
		t.Errorf("v6For(%q) = %q, want ip6tables-nft; a name-based check would "+
			"pick ip6tables-legacy and read an empty table", "iptables", got)
	}
}

// TestV6ForLegacyHost pins the ZimaOS<=1.6.1 side: a legacy v4 backend must
// not drag IPv6 onto nft.
func TestV6ForLegacyHost(t *testing.T) {
	dir := t.TempDir()
	fakeIptables(t, dir, "iptables", "legacy")
	fakeIptables(t, dir, "ip6tables", "legacy")
	fakeIptables(t, dir, "ip6tables-legacy", "legacy")
	fakeIptables(t, dir, "ip6tables-nft", "nf_tables")
	t.Setenv("PATH", dir)

	if got := v6For("iptables"); got != "ip6tables-legacy" {
		t.Errorf("v6For = %q, want ip6tables-legacy", got)
	}
}

// TestV6ForSkipsMismatchedCandidate covers the host where ip6tables-nft is
// absent and the generic ip6tables drives the wrong backend: we must not
// silently hand back a binary that writes to a table the kernel isn't using.
func TestV6ForSkipsMismatchedCandidate(t *testing.T) {
	dir := t.TempDir()
	fakeIptables(t, dir, "iptables", "nf_tables")
	fakeIptables(t, dir, "ip6tables", "legacy") // mismatched
	t.Setenv("PATH", dir)

	if got := v6For("iptables"); got != "ip6tables" {
		t.Errorf("v6For = %q; want the ip6tables fallback (nothing better exists)", got)
	}
	if familyOf("ip6tables") == "nft" {
		t.Error("fixture broken: ip6tables should report legacy")
	}
}

func TestFamilyOfMissingBinary(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	if got := familyOf("iptables-does-not-exist"); got != "" {
		t.Errorf("familyOf(missing) = %q, want \"\"", got)
	}
}
