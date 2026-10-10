package compiler

import (
	"regexp"
	"strings"
	"testing"

	"github.com/chicohaager/zfw/internal/apps"
	"github.com/chicohaager/zfw/internal/rules"
	"github.com/chicohaager/zfw/internal/system"
)

func appsTestSet(policy string) (rules.RuleSet, system.PublishedPorts) {
	rs := rules.RuleSet{LAN: "192.0.2.0/24", HostIP: "192.0.2.1", DefaultPolicy: policy, V6Drop: []int{23}, Rules: []rules.Rule{
		{ID: "d", Order: 10, Enabled: true, Action: "deny", Source: rules.Source{Type: "any"},
			Ports: rules.Ports{Type: "list", List: []int{8080}}, Protocol: "tcp", Zone: "docker"},
		{ID: "h", Order: 20, Enabled: true, Action: "allow", Source: rules.Source{Type: "range", Value: "192.0.2.0/24"},
			Ports: rules.Ports{Type: "list", List: []int{22}}, Protocol: "tcp", Zone: "host"},
	}}
	return rs, system.PublishedPorts{TCP: map[int]bool{8096: true}, UDP: map[int]bool{}}
}

func indexOf(lines []string, re string) int {
	r := regexp.MustCompile(re)
	for i, l := range lines {
		if r.MatchString(l) {
			return i
		}
	}
	return -1
}

// The jump sits after every user rule and before the catch-all, in every
// chain and in both emitters: a user deny wins, the default-deny does not.
func TestAppsJumpPlacement(t *testing.T) {
	rs, pp := appsTestSet("deny")
	rl := rs.Rules
	cases := []struct {
		name               string
		lines              []string
		jump, user, catchy string
	}{
		{"DOCKER-USER", dockerUserRules(rs, rl, pp, nil), "^-j ZFW-APPS$", "--ctorigdstport 8080 .*-j DROP", "ZFW-DOCK-DROP"},
		{"ZFW-IN", zfwInRules(rs, rl, pp.All(), nil), "^-j ZFW-APPS-IN$", "--dport 22 .*-j ACCEPT", "ZFW-IN-DROP"},
		{"ZFW-IN6", zfwIn6Rules(rs, rl, nil), "^-j ZFW-APPS-IN6$", "--dport 23 -j DROP", "ZFW-IN6-DROP"},
		// IPv6 DOCKER-USER (Docker's ip6tables support on): before 2026-10-09
		// it had no jump, so an "everyone" answer for a container port stayed
		// closed over IPv6 by the v6 DNAT guard.
		{"DOCKER-USER v6", dockerUser6Rules(rs, rl, pp, nil), "^-j ZFW-APPS6$", "--ctorigdstport 8080 .*-j DROP", "ZFW-DOCK6-DROP"},
	}
	for _, c := range cases {
		j, u, d := indexOf(c.lines, c.jump), indexOf(c.lines, c.user), indexOf(c.lines, c.catchy)
		if j < 0 || u < 0 || d < 0 {
			t.Errorf("%s: jump %d, user rule %d, catch-all %d — all must be present\n%s", c.name, j, u, d, strings.Join(c.lines, "\n"))
			continue
		}
		if u > j || j >= d {
			t.Errorf("%s: want user rule (%d) <= jump (%d) < catch-all (%d)", c.name, u, j, d)
		}
	}
	// The bash emitter carries the same jumps.
	bash := Compile(rs, pp, nil)
	for _, want := range []string{"-A ZFW-IN -j ZFW-APPS-IN", "$IPT -A DOCKER-USER -j ZFW-APPS\n", "-A ZFW-IN6 -j ZFW-APPS-IN6", "$IPT6 -A DOCKER-USER -j ZFW-APPS6"} {
		if !strings.Contains(bash, want) {
			t.Errorf("bash script lacks %q", want)
		}
	}
}

func TestAppsNoJumpUnderAllowPolicy(t *testing.T) {
	rs, pp := appsTestSet("allow")
	for name, s := range map[string]string{"bash": Compile(rs, pp, nil), "restore": CompileRestoreScript(rs, pp, nil)} {
		if strings.Contains(s, "-j ZFW-APPS") {
			t.Errorf("%s: default allow filters nothing — no app jump expected", name)
		}
	}
}

// An apply must never wipe the answers: no flush of an app chain anywhere in
// the apply scripts, no declaration in the restore documents (a declared
// chain is flushed by iptables-restore), and the chains created before the
// restore's --test needs them as jump targets.
func TestApplyNeverFlushesAppChains(t *testing.T) {
	rs, pp := appsTestSet("deny")
	flush := regexp.MustCompile(`-(F|X) ZFW-APPS`)
	bash := Compile(rs, pp, nil)
	restore := CompileRestoreScript(rs, pp, nil)
	for name, s := range map[string]string{"bash": bash, "restore": restore} {
		if flush.MatchString(s) {
			t.Errorf("%s apply script flushes or deletes an app chain", name)
		}
		for _, c := range []string{"ZFW-APPS", "ZFW-APPS-IN", "ZFW-APPS-IN6", "ZFW-APPS6"} {
			if !strings.Contains(s, " -N "+c+" 2>/dev/null || true") {
				t.Errorf("%s: %s is not created idempotently", name, c)
			}
		}
	}
	doc := CompileRestore(rs, pp)
	for _, d := range []string{doc.V4, doc.V6} {
		if regexp.MustCompile(`(?m)^:ZFW-APPS`).MatchString(d) {
			t.Error("a restore document declares an app chain — the restore would flush it")
		}
	}
	if strings.Index(restore, "-N ZFW-APPS ") > strings.Index(restore, "--test --noflush \"$T4\"") {
		t.Error("ZFW-APPS must exist before the v4 restore is tested")
	}
	if strings.Index(restore, "-N ZFW-APPS-IN6") > strings.Index(restore, "--test --noflush \"$T6\"") {
		t.Error("ZFW-APPS-IN6 must exist before the v6 restore is tested")
	}
	if i := strings.Index(restore, "-N ZFW-APPS6 "); i < 0 || i > strings.Index(restore, "--test --noflush \"$T6\"") {
		t.Error("ZFW-APPS6 must exist before the v6 restore is tested")
	}
}

func TestCompileAppsLines(t *testing.T) {
	active := []apps.Entry{
		{Zone: "docker", Proto: "tcp", Port: 8086, State: apps.LAN},
		{Zone: "docker", Proto: "udp", Port: 5000, State: apps.Pending}, // pending in lan mode → LAN
		{Zone: "host", Proto: "tcp", Port: 9100, State: apps.Any},
	}
	docker, host, host6, docker6 := AppLines(active, "192.0.2.0/24")
	wantD := []string{
		"-s 192.0.2.0/24 -p tcp -m conntrack --ctorigdstport 8086 -j ACCEPT",
		"-s 192.0.2.0/24 -p udp -m conntrack --ctorigdstport 5000 -j ACCEPT",
	}
	if strings.Join(docker, "\n") != strings.Join(wantD, "\n") {
		t.Errorf("docker lines:\n%s", strings.Join(docker, "\n"))
	}
	if len(host) != 1 || host[0] != "-p tcp --dport 9100 -j ACCEPT" {
		t.Errorf("host lines: %v", host)
	}
	if len(host6) != 1 || host6[0] != "-p tcp --dport 9100 -j ACCEPT" {
		t.Errorf("only an 'any' answer opens IPv6: %v", host6)
	}
	_, _, h6, d6 := AppLines([]apps.Entry{{Zone: "docker", Proto: "tcp", Port: 8086, State: apps.Any}}, "192.0.2.0/24")
	if len(d6) != 1 || d6[0] != "-p tcp -m conntrack --ctorigdstport 8086 -j ACCEPT" {
		t.Errorf("'any' for a container port opens the IPv6 DOCKER-USER path: %v", d6)
	}
	if len(h6) != 1 {
		t.Errorf("…and still the docker-proxy path in ZFW-IN6: %v", h6)
	}
	if len(docker6) != 0 {
		t.Errorf("a LAN answer never opens IPv6: %v", docker6)
	}
}

// Values that reach a root shell script are checked where they are used.
func TestCompileAppsRejectsUnsafeValues(t *testing.T) {
	active := []apps.Entry{
		{Zone: "docker", Proto: "tcp; reboot", Port: 80, State: apps.Any},
		{Zone: "docker", Proto: "tcp", Port: 70000, State: apps.Any},
		{Zone: "host", Proto: "tcp", Port: 0, State: apps.Any},
		{Zone: "elsewhere", Proto: "tcp", Port: 81, State: apps.Any},
		{Zone: "docker", Proto: "tcp", Port: 82, State: apps.LAN},
	}
	d, h, h6, d6 := AppLines(active, "192.0.2.0/24; reboot")
	if len(d)+len(h)+len(h6)+len(d6) != 0 {
		t.Errorf("unsafe values produced lines: %v %v %v %v", d, h, h6, d6)
	}
	script := CompileApps(active, "192.0.2.0/24; reboot")
	if strings.Contains(script, "reboot") || strings.Contains(script, "70000") {
		t.Errorf("unsafe value reached the script:\n%s", script)
	}
}

// The apps script touches the three app chains and nothing else.
func TestCompileAppsTouchesOnlyAppChains(t *testing.T) {
	script := CompileApps([]apps.Entry{
		{Zone: "docker", Proto: "tcp", Port: 8086, State: apps.Any},
		{Zone: "host", Proto: "tcp", Port: 9100, State: apps.LAN},
	}, "192.0.2.0/24")
	op := regexp.MustCompile(`\$IPT6? -(A|D|I|F|X|N|P|R|Z) (\S+)`)
	n := 0
	for _, m := range op.FindAllStringSubmatch(script, -1) {
		n++
		if !strings.HasPrefix(m[2], "ZFW-APPS") {
			t.Errorf("apps script modifies %s", m[2])
		}
	}
	if n < 8 { // 4 flushes + 4 appends at least
		t.Errorf("expected flush+fill of all three chains, found %d operations:\n%s", n, script)
	}
}
