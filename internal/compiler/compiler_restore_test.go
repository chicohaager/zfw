package compiler

import (
	"os/exec"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/chicohaager/zfw/internal/system"

	"github.com/chicohaager/zfw/internal/rules"
)

// zfwChains are the ZFW-owned chains both paths populate. The bash path
// also emits jump hooks on INPUT/OUTPUT/FORWARD (-C/-I) which are NOT
// rules and stay shell-only in the restore path; restricting the
// comparison to these chains excludes them cleanly.
var zfwChains = map[string]bool{
	"ZFW-IN": true, "DOCKER-USER": true, "ZFW-IN6": true,
	"ZFW-OUT": true, "ZFW-OUT6": true, "ZFW-FWD-OUT": true,
}

var bashRuleRE = regexp.MustCompile(`^\s*\$IPT6? -A (\S+) (.+)$`)
var restoreRuleRE = regexp.MustCompile(`^-A (\S+) (.+)$`)

func bashChainRules(script string) map[string][]string {
	out := map[string][]string{}
	for _, ln := range strings.Split(script, "\n") {
		m := bashRuleRE.FindStringSubmatch(ln)
		if m == nil || !zfwChains[m[1]] {
			continue
		}
		out[m[1]] = append(out[m[1]], m[2])
	}
	return out
}

func restoreChainRules(doc string) map[string][]string {
	out := map[string][]string{}
	for _, ln := range strings.Split(doc, "\n") {
		m := restoreRuleRE.FindStringSubmatch(ln)
		if m == nil {
			continue
		}
		out[m[1]] = append(out[m[1]], m[2])
	}
	return out
}

// comprehensiveRuleSet exercises every chain and rule shape: host list,
// docker, IPv6 source, country auto, outbound host + docker, disabled,
// scheduled + rate-limited, plus HostIP / LAN / V6Drop / extraBypass.
func comprehensiveRuleSet() rules.RuleSet {
	return rules.RuleSet{
		DefaultPolicy: "deny", LAN: "192.168.1.0/24", HostIP: "192.168.1.100",
		V6Drop: []int{5900, 23},
		Rules: []rules.Rule{
			{ID: "a", Order: 10, Enabled: true, Name: "SSH", Action: "allow", Source: rules.Source{Type: "range", Value: "192.168.1.0/24"}, Ports: rules.Ports{Type: "list", List: []int{22, 80, 443}}, Protocol: "tcp", Zone: "host", Log: true},
			{ID: "b", Order: 20, Enabled: true, Name: "web", Action: "allow", Source: rules.Source{Type: "any"}, Ports: rules.Ports{Type: "list", List: []int{8080}}, Protocol: "tcp", Zone: "docker"},
			{ID: "c", Order: 30, Enabled: true, Name: "v6", Action: "allow", Source: rules.Source{Type: "range", Value: "2001:db8::/64"}, Ports: rules.Ports{Type: "list", List: []int{443}}, Protocol: "tcp", Zone: "host"},
			{ID: "d", Order: 40, Enabled: true, Name: "cc", Action: "deny", Source: rules.Source{Type: "country", Value: "cn,ru"}, Ports: rules.Ports{Type: "all"}, Protocol: "both", Zone: "auto"},
			{ID: "e", Order: 50, Enabled: true, Name: "out", Action: "allow", Direction: "outbound", Source: rules.Source{Type: "ip", Value: "8.8.8.8"}, Ports: rules.Ports{Type: "list", List: []int{53}}, Protocol: "udp", Zone: "host"},
			{ID: "f", Order: 60, Enabled: true, Name: "dout", Action: "deny", Direction: "outbound", Source: rules.Source{Type: "any"}, Ports: rules.Ports{Type: "range", From: 6000, To: 6100}, Protocol: "tcp", Zone: "docker"},
			{ID: "g", Order: 70, Enabled: false, Name: "off", Action: "allow", Source: rules.Source{Type: "any"}, Ports: rules.Ports{Type: "all"}, Protocol: "tcp", Zone: "host"},
			{ID: "h", Order: 80, Enabled: true, Name: "sched", Action: "allow", Source: rules.Source{Type: "range", Value: "10.0.0.0/8"}, Ports: rules.Ports{Type: "list", List: []int{2222}}, Protocol: "tcp", Zone: "host", Schedule: &rules.Schedule{From: "08:00", To: "18:00", Days: []string{"mon", "fri"}}, RateLimit: &rules.RateLimit{Conn: 3, Seconds: 60}},
		},
	}
}

// TestRestoreMatchesBashRules is the correctness anchor for the B4
// restore path: for the same rule set, every per-chain rule sequence in
// the iptables-restore documents must be identical to the proven bash
// script's. This guards against the two paths drifting (the static
// bypass/default lines are duplicated between them on purpose).
func TestRestoreMatchesBashRules(t *testing.T) {
	rs := comprehensiveRuleSet()
	dp := tcpOnly(map[int]bool{8080: true})
	gf := map[string]string{"cn": "/DATA/zfw/geo/cn.ipset", "ru": "/DATA/zfw/geo/ru.ipset"}
	extra := []string{"wg+", "vpn0"}

	bash := Compile(rs, dp, gf, extra...)
	rest := CompileRestore(rs, dp, extra...)

	want := bashChainRules(bash)
	got := restoreChainRules(rest.V4 + "\n" + rest.V6)

	if !reflect.DeepEqual(got, want) {
		for chain := range zfwChains {
			if !reflect.DeepEqual(got[chain], want[chain]) {
				t.Errorf("chain %s differs:\n  bash:    %#v\n  restore: %#v", chain, want[chain], got[chain])
			}
		}
	}
}

// TestRestoreMatchesBashRulesAllowPolicy repeats the equivalence check
// with default_policy=allow so the RETURN-terminated chain branches are
// covered too.
func TestRestoreMatchesBashRulesAllowPolicy(t *testing.T) {
	rs := comprehensiveRuleSet()
	rs.DefaultPolicy = "allow"
	dp := tcpOnly(map[int]bool{8080: true})

	bash := Compile(rs, dp, nil)
	rest := CompileRestore(rs, dp)

	want := bashChainRules(bash)
	got := restoreChainRules(rest.V4 + "\n" + rest.V6)
	if !reflect.DeepEqual(got, want) {
		t.Errorf("allow-policy equivalence failed:\n  bash:    %#v\n  restore: %#v", want, got)
	}
}

// TestRestoreDocumentShape pins the iptables-restore envelope: each table
// opens with *filter, declares its ZFW chains with :CHAIN - [0:0] before
// any -A line, and ends with COMMIT.
func TestRestoreDocumentShape(t *testing.T) {
	rs := comprehensiveRuleSet()
	rest := CompileRestore(rs, tcpOnly(map[int]bool{8080: true}))

	for _, doc := range []string{rest.V4, rest.V6} {
		lines := strings.Split(strings.TrimRight(doc, "\n"), "\n")
		if lines[0] != "*filter" {
			t.Errorf("table does not open with *filter: %q", lines[0])
		}
		if lines[len(lines)-1] != "COMMIT" {
			t.Errorf("table does not end with COMMIT: %q", lines[len(lines)-1])
		}
		// Every :CHAIN declaration must precede the first -A line.
		seenAppend := false
		for _, ln := range lines {
			switch {
			case strings.HasPrefix(ln, "-A "):
				seenAppend = true
			case strings.HasPrefix(ln, ":"):
				if seenAppend {
					t.Errorf("chain declaration after an -A line: %q", ln)
				}
			}
		}
	}
	// V4 must declare the inbound chains; V6 must declare ZFW-IN6.
	if !strings.Contains(rest.V4, ":ZFW-IN - [0:0]") || !strings.Contains(rest.V4, ":DOCKER-USER - [0:0]") {
		t.Error("V4 missing ZFW-IN / DOCKER-USER chain declarations")
	}
	if !strings.Contains(rest.V6, ":ZFW-IN6 - [0:0]") {
		t.Error("V6 missing ZFW-IN6 chain declaration")
	}
}

// TestCompileRestoreScriptShape pins the engine-facing restore script:
// it must be valid bash (checked via `bash -n`), pre-validate each table
// with --test before applying, embed the V4/V6 docs from CompileRestore,
// and emit the idempotent jump hooks.
func TestCompileRestoreScriptShape(t *testing.T) {
	rs := comprehensiveRuleSet()
	dp := tcpOnly(map[int]bool{8080: true})
	gf := map[string]string{"cn": "/DATA/zfw/geo/cn.ipset", "ru": "/DATA/zfw/geo/ru.ipset"}
	script := CompileRestoreScript(rs, dp, gf, "wg+")

	for _, want := range []string{
		"#!/bin/bash",
		"set -eu",
		`"$IPTR" --test --noflush "$T4"`, // pre-validate v4 before apply
		`"$IPTR" --noflush "$T4"`,
		`"$IPT6R" --test --noflush "$T6"`,
		"<<'ZFW_RESTORE_V4'",
		"<<'ZFW_RESTORE_V6'",
		"$IPT -C INPUT -j ZFW-IN 2>/dev/null || $IPT -I INPUT 1 -j ZFW-IN",
		"$IPT -C OUTPUT -j ZFW-OUT ",      // outbound host hook present
		"$IPT -C FORWARD -j ZFW-FWD-OUT ", // outbound docker hook present
		"ipset restore -exist",            // geo preamble
	} {
		if !strings.Contains(script, want) {
			t.Errorf("restore script missing: %q", want)
		}
	}

	// The embedded V4/V6 docs must be exactly what CompileRestore emits.
	docs := CompileRestore(rs, dp, "wg+")
	if !strings.Contains(script, docs.V4) {
		t.Error("restore script does not embed the CompileRestore V4 document verbatim")
	}
	if !strings.Contains(script, docs.V6) {
		t.Error("restore script does not embed the CompileRestore V6 document verbatim")
	}

	// Must be syntactically valid bash.
	cmd := exec.Command("bash", "-n")
	cmd.Stdin = strings.NewReader(script)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("generated restore script failed `bash -n`: %v\n%s", err, out)
	}
}

// TestCompileRestoreScriptOmitsAbsentOutboundHooks pins that an
// inbound-only rule set produces no ZFW-OUT / ZFW-FWD-OUT jump hooks.
func TestCompileRestoreScriptOmitsAbsentOutboundHooks(t *testing.T) {
	rs := rules.RuleSet{
		DefaultPolicy: "deny", LAN: "192.168.1.0/24",
		Rules: []rules.Rule{{
			ID: "a", Order: 10, Enabled: true, Name: "ssh", Action: "allow",
			Source: rules.Source{Type: "range", Value: "192.168.1.0/24"},
			Ports:  rules.Ports{Type: "list", List: []int{22}}, Protocol: "tcp", Zone: "host",
		}},
	}
	script := CompileRestoreScript(rs, system.PublishedPorts{}, nil)
	if strings.Contains(script, "ZFW-OUT") || strings.Contains(script, "ZFW-FWD-OUT") {
		t.Error("inbound-only rule set emitted outbound chains/hooks")
	}
}
