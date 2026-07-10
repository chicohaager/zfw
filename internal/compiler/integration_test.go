// Integration tests that run the compiled iptables script inside an
// isolated Linux network namespace and assert the live chain state.
// These tests don't need sudo: `unshare -U -r -n` opens an unprivileged
// user+network namespace, and iptables-legacy runs against the netns as
// long as its lock file is redirected to a user-writable path
// (/run/xtables.lock is host-root-owned and refuses the userns user).
//
// Build tag keeps them out of the default `go test ./...` because:
//   - they spawn /usr/sbin/iptables-legacy (must be installed)
//   - they need unprivileged userns enabled (kernel.unprivileged_userns_clone=1)
//   - they're slower (~50-150 ms per test, vs. <5 ms for the pure unit tests)
//
// Run locally with:
//
//	go test -tags=netns_integration ./internal/compiler/...
//
//go:build netns_integration

package compiler

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/chicohaager/zfw/internal/rules"
)

// requireNetns skips the test when the host does not support the
// `unshare -U -r -n` invocation (older kernel, sysctl disabled, missing
// iptables-legacy). The goal is for the build tag to gate inclusion
// while the runtime skip gates execution — a developer who turns the
// tag on but lacks the capability still gets a clean SKIP, not a FAIL.
func requireNetns(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("iptables-legacy"); err != nil {
		t.Skipf("iptables-legacy not installed: %v", err)
	}
	if _, err := exec.LookPath("unshare"); err != nil {
		t.Skipf("unshare not installed: %v", err)
	}
	if err := exec.Command("unshare", "-U", "-r", "-n", "true").Run(); err != nil {
		t.Skipf("unprivileged netns unavailable: %v", err)
	}
}

// runInNetns writes the script to a temp file and executes it inside a
// fresh userns+netns with a per-test XTABLES_LOCKFILE. After the script
// runs it queries `iptables-legacy -S` on the relevant chain so the
// caller can assert the resulting rule state. Stderr is folded into the
// returned string only when the command exits non-zero, so a test
// failure shows both what was emitted and what iptables thought of it.
func runInNetns(t *testing.T, script, queryChain string) string {
	t.Helper()
	dir := t.TempDir()
	scriptPath := filepath.Join(dir, "compiled.sh")
	if err := os.WriteFile(scriptPath, []byte(script), 0o755); err != nil {
		t.Fatalf("write compiled.sh: %v", err)
	}
	lockPath := filepath.Join(dir, "xtables.lock")
	// Use a single inner bash so the compiled script and the iptables -S
	// query share the same netns / userns / mount view.
	inner := "export XTABLES_LOCKFILE=" + lockPath + "; " +
		"bash " + scriptPath + " >/tmp/out 2>&1 || { echo '--- compiled.sh failed ---'; cat /tmp/out >&2; exit 1; }; " +
		"iptables-legacy -S " + queryChain
	out, err := exec.Command("unshare", "-U", "-r", "-n", "bash", "-c", inner).CombinedOutput()
	if err != nil {
		t.Fatalf("netns exec failed: %v\n%s", err, out)
	}
	return string(out)
}

// TestEngineApplyAllowsExpectedHostPort drives a tiny rule set through
// compile + run-in-netns and asserts the resulting ZFW-IN chain
// contains the expected ACCEPT line. End-to-end: rule model → compiler
// → bash → live iptables-legacy. Without this test, every change in
// the v0.2.16+ batch (port-range, IPv6 dispatch, default-deny) had to
// be hand-verified on a real host.
func TestEngineApplyAllowsExpectedHostPort(t *testing.T) {
	requireNetns(t)
	rs := rules.RuleSet{
		LAN: "192.168.1.0/24", HostIP: "192.168.1.143", DefaultPolicy: "deny",
		Rules: []rules.Rule{{
			Order: 10, Enabled: true, Name: "SSH from LAN", Action: "allow",
			Source:   rules.Source{Type: "range", Value: "192.168.1.0/24"},
			Ports:    rules.Ports{Type: "list", List: []int{22}},
			Protocol: "tcp", Zone: "host",
		}},
	}
	out := runInNetns(t, Compile(rs, system.PublishedPorts{}, nil), "ZFW-IN")
	wantLines := []string{
		"-N ZFW-IN",
		"-A ZFW-IN -s 192.168.1.0/24",
		"--dport 22",
		"-j ACCEPT",
		"-j DROP", // default-deny catch-all
	}
	for _, w := range wantLines {
		if !strings.Contains(out, w) {
			t.Errorf("ZFW-IN missing %q\nfull output:\n%s", w, out)
		}
	}
}

// TestEngineApplyPortRangeEmitsContiguousRule covers v0.2.16: a port
// range compiles into one iptables line (`--dport 5900:5999`), not 100
// multiport entries. Run live to confirm iptables-legacy actually
// accepts the range syntax on the host's kernel.
func TestEngineApplyPortRangeEmitsContiguousRule(t *testing.T) {
	requireNetns(t)
	rs := rules.RuleSet{
		LAN: "192.168.1.0/24", DefaultPolicy: "deny",
		Rules: []rules.Rule{{
			Order: 10, Enabled: true, Name: "Block VNC", Action: "deny",
			Source:   rules.Source{Type: "any"},
			Ports:    rules.Ports{Type: "range", From: 5900, To: 5999},
			Protocol: "tcp", Zone: "host",
		}},
	}
	out := runInNetns(t, Compile(rs, system.PublishedPorts{}, nil), "ZFW-IN")
	if c := strings.Count(out, "--dport 5900:5999"); c != 1 {
		t.Errorf("expected exactly one '--dport 5900:5999' line, got %d\n%s", c, out)
	}
	// Sanity: the compiler must NOT have enumerated every port in the
	// range — e.g. `--dport 5901` would only appear if the range got
	// expanded into 100 individual entries.
	if strings.Contains(out, "--dport 5901") {
		t.Errorf("port range got enumerated instead of using --dport X:Y\n%s", out)
	}
}

// TestEngineApplyIPv6SourceDoesNotCrashIPv4 is the live counterpart to
// the v0.2.22 unit tests: feeding an IPv6 CIDR through the compiler
// must produce a script that *runs cleanly* under `set -eu` in a
// netns. Pre-fix the IPv4 chain emitted `-s 2001:db8::/64` and
// iptables-legacy aborted the apply.
func TestEngineApplyIPv6SourceDoesNotCrashIPv4(t *testing.T) {
	requireNetns(t)
	rs := rules.RuleSet{
		LAN: "192.168.1.0/24", DefaultPolicy: "deny",
		Rules: []rules.Rule{{
			Order: 10, Enabled: true, Name: "SSH from SLAAC", Action: "allow",
			Source:   rules.Source{Type: "range", Value: "2001:db8::/64"},
			Ports:    rules.Ports{Type: "list", List: []int{22}},
			Protocol: "tcp", Zone: "host",
		}},
	}
	out := runInNetns(t, Compile(rs, system.PublishedPorts{}, nil), "ZFW-IN")
	// Test passes if runInNetns did not Fatalf (no crash) and the IPv4
	// chain is present without an IPv6 source line.
	if !strings.Contains(out, "-N ZFW-IN") {
		t.Errorf("ZFW-IN was not created\nfull output:\n%s", out)
	}
	if strings.Contains(out, "2001:db8") {
		t.Errorf("IPv4 chain unexpectedly contains IPv6 source\nfull output:\n%s", out)
	}
}

// TestEngineRevertClearsAllChains walks the apply→revert flow that
// the engine's `revert` subcommand performs by hand (the engine script
// itself needs systemd and isn't reachable here). After revert, the
// ZFW-IN chain must be gone — iptables -S returns a non-zero exit and
// the recorded output mentions "No chain/target/match by that name".
func TestEngineRevertClearsAllChains(t *testing.T) {
	requireNetns(t)
	rs := rules.RuleSet{
		LAN: "192.168.1.0/24", DefaultPolicy: "deny",
	}
	revertScript := strings.Join([]string{
		`IPT="$(command -v iptables-legacy)"`,
		`$IPT -D INPUT -j ZFW-IN 2>/dev/null || true`,
		`$IPT -F ZFW-IN 2>/dev/null || true`,
		`$IPT -X ZFW-IN 2>/dev/null || true`,
		// Probe afterwards — iptables-legacy returns exit 1 + a
		// diagnostic when the chain is absent.
		`$IPT -S ZFW-IN 2>&1 || true`,
	}, "\n")
	combined := Compile(rs, system.PublishedPorts{}, nil) + "\n" + revertScript

	dir := t.TempDir()
	scriptPath := filepath.Join(dir, "compiled.sh")
	if err := os.WriteFile(scriptPath, []byte(combined), 0o755); err != nil {
		t.Fatalf("write compiled.sh: %v", err)
	}
	lockPath := filepath.Join(dir, "xtables.lock")
	out, err := exec.Command("unshare", "-U", "-r", "-n", "bash", "-c",
		"export XTABLES_LOCKFILE="+lockPath+"; bash "+scriptPath).CombinedOutput()
	if err != nil {
		t.Fatalf("netns exec failed: %v\n%s", err, out)
	}
	o := string(out)
	if !strings.Contains(o, "No chain/target/match by that name") {
		t.Errorf("revert did not remove ZFW-IN — `-S` should fail after `-X`\nfull output:\n%s", o)
	}
}
