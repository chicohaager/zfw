//go:build netns_integration

package compiler

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/chicohaager/zfw/internal/apps"
	"github.com/chicohaager/zfw/internal/rules"
	"github.com/chicohaager/zfw/internal/system"
)

// appsTopology extends dnatTopology with a source outside the LAN that no
// bypass covers (wan, 198.18.0.2 / fd00:3::2) and a network_mode: host app —
// a listener in the host namespace itself on :9100.
const appsTopology = `
ip netns add wan; ip netns exec wan ip link set lo up
ip link add eth-wan type veth peer name eth0 netns wan
ip addr add 198.18.0.1/24 dev eth-wan; ip addr add fd00:3::1/64 dev eth-wan nodad
ip link set eth-wan up
ip netns exec wan ip addr add 198.18.0.2/24 dev eth0
ip netns exec wan ip addr add fd00:3::2/64 dev eth0 nodad
ip netns exec wan ip link set eth0 up
ip netns exec wan ip route add default via 198.18.0.1
ip netns exec wan ip -6 route add default via fd00:3::1
python3 -c "$SRV" 9100 &
sleep 0.5
`

const appsProbes = `
CLI='import socket,sys
try:
    s=socket.create_connection((sys.argv[1],int(sys.argv[2])),timeout=1.5); print(sys.argv[3],"REACH" if s.recv(2)==b"ok" else "BLOCKED")
except Exception: print(sys.argv[3],"BLOCKED")'
probe(){ local ns="$1"; shift; ip netns exec "$ns" python3 -c "$CLI" "$@"; }
probe lan 192.0.2.1 8080 $P-docker-lan
probe wan 192.0.2.1 8080 $P-docker-wan
probe lan fd00:1::1 8080 $P-docker-lan-v6
probe lan 192.0.2.1 9100 $P-host-lan
probe wan 192.0.2.1 9100 $P-host-wan
probe wan fd00:1::1 9100 $P-host-wan-v6
probe lan 192.0.2.1 8096 $P-ruled-port
`

// TestAppChainsLive runs the new-app prompt's chains through real netfilter:
// a late-published container port answered "LAN only" and a host-network app
// answered "everyone", written by the apps script alone (no apply), then a
// normal apply on top — which must leave the answers in place.
func TestAppChainsLive(t *testing.T) {
	rs := rules.RuleSet{
		LAN: "192.0.2.0/24", HostIP: "192.0.2.1", DefaultPolicy: "deny",
		Rules: []rules.Rule{{
			ID: "r1", Order: 10, Enabled: true, Name: "app 8096", Action: "allow",
			Source: rules.Source{Type: "any"}, Ports: rules.Ports{Type: "list", List: []int{8096}},
			Protocol: "tcp", Zone: "docker",
		}},
	}
	// 8080 is published after the apply: not in the applied inventory.
	pp := system.PublishedPorts{TCP: map[int]bool{8096: true, 8097: true}, UDP: map[int]bool{}}
	active := []apps.Entry{
		{Key: "docker/tcp/8080/web", Zone: "docker", Proto: "tcp", Port: 8080, State: apps.LAN, Present: true},
		{Key: "host/tcp/9100/node", Zone: "host", Proto: "tcp", Port: 9100, State: apps.Any, Present: true},
	}
	want := map[string]string{
		// before: the default-deny answers for both
		"before-docker-lan": "BLOCKED", "before-docker-wan": "BLOCKED", "before-docker-lan-v6": "BLOCKED",
		"before-host-lan": "BLOCKED", "before-host-wan": "BLOCKED", "before-host-wan-v6": "BLOCKED",
		"before-ruled-port": "REACH",
		// after the apps script: LAN only for 8080, everyone for 9100
		"answered-docker-lan": "REACH", "answered-docker-wan": "BLOCKED", "answered-docker-lan-v6": "BLOCKED",
		"answered-host-lan": "REACH", "answered-host-wan": "REACH", "answered-host-wan-v6": "REACH",
		"answered-ruled-port": "REACH",
		// a normal apply afterwards must not wipe the answers
		"reapplied-docker-lan": "REACH", "reapplied-docker-wan": "BLOCKED", "reapplied-docker-lan-v6": "BLOCKED",
		"reapplied-host-lan": "REACH", "reapplied-host-wan": "REACH", "reapplied-host-wan-v6": "REACH",
		"reapplied-ruled-port": "REACH",
	}
	appsScript := CompileApps(active, rs.LAN)
	emitters := map[string]string{
		"bash":    Compile(rs, pp, nil),
		"restore": CompileRestoreScript(rs, pp, nil),
	}
	for _, backend := range []string{"nft", "legacy"} {
		for ename, script := range emitters {
			t.Run(backend+"/"+ename, func(t *testing.T) {
				requireNetnsMount(t, backend)
				dir := t.TempDir()
				sp, ap := filepath.Join(dir, "compiled.sh"), filepath.Join(dir, "apps.sh")
				if err := os.WriteFile(sp, []byte(script), 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(ap, []byte(appsScript), 0o600); err != nil {
					t.Fatal(err)
				}
				run := func(f string) string {
					return "bash " + f + " >> " + filepath.Join(dir, "log") + " 2>&1 || { echo RUN-FAILED " + f + "; cat " + filepath.Join(dir, "log") + "; exit 1; }\n"
				}
				full := "BACKEND=" + backend + "\n" + dnatTopology + appsTopology +
					// before the first apply the chains do not exist: the apps
					// script must change nothing and say so
					"bash " + ap + " | grep -c 'missing — apply once' | sed 's/^/premature-missing-lines /'\n" +
					run(sp) + "P=before\n" + appsProbes +
					run(ap) + "P=answered\n" + appsProbes +
					run(sp) + "P=reapplied\n" + appsProbes +
					"echo '--- ZFW-APPS'; $IPT -S ZFW-APPS; echo '--- ZFW-APPS-IN'; $IPT -S ZFW-APPS-IN; echo '--- ZFW-APPS-IN6'; $IPT6 -S ZFW-APPS-IN6\n" +
					// The engine's revert() alone (not its systemd half): afterwards
					// no ZFW chain may remain, the app chains included.
					"source <(sed -n '/^revert(){/,/^}/p' " + enginePath(t) + ")\nrevert\n" +
					"for c in ZFW-IN ZFW-APPS ZFW-APPS-IN; do $IPT -L $c -n >/dev/null 2>&1 && echo \"left-after-revert $c\"; done\n" +
					"$IPT6 -L ZFW-APPS-IN6 -n >/dev/null 2>&1 && echo 'left-after-revert ZFW-APPS-IN6'\n" +
					"echo revert-checked\n" +
					"kill $(jobs -p) 2>/dev/null || true\n"
				fp := filepath.Join(dir, "run.sh")
				if err := os.WriteFile(fp, []byte(full), 0o600); err != nil {
					t.Fatal(err)
				}
				out, err := exec.Command("unshare", "-U", "-r", "-n", "-m", "bash", fp).CombinedOutput()
				if err != nil {
					t.Fatalf("netns run failed: %v\n%s", err, out)
				}
				got := map[string]string{}
				for _, l := range strings.Split(string(out), "\n") {
					f := strings.Fields(l)
					if len(f) == 2 && (f[1] == "REACH" || f[1] == "BLOCKED") {
						got[f[0]] = f[1]
					}
				}
				for probe, w := range want {
					if got[probe] != w {
						t.Errorf("%s: got %q, want %s", probe, got[probe], w)
					}
				}
				if strings.Contains(string(out), "left-after-revert") || !strings.Contains(string(out), "revert-checked") {
					t.Errorf("engine revert left a ZFW chain behind (or did not run)")
				}
				if !strings.Contains(string(out), "premature-missing-lines 3") {
					t.Errorf("apps script before the first apply: want 3 'missing' notices")
				}
				if t.Failed() {
					t.Logf("full output:\n%s", out)
				}
			})
		}
	}
}

// TestAppChainsUserDenyWinsLive: an explicit deny for the port sits above the
// jump, so an answer in the app chain cannot override it.
func TestAppChainsUserDenyWinsLive(t *testing.T) {
	rs := rules.RuleSet{
		LAN: "192.0.2.0/24", HostIP: "192.0.2.1", DefaultPolicy: "deny",
		Rules: []rules.Rule{
			{ID: "d1", Order: 10, Enabled: true, Name: "no 8080", Action: "deny",
				Source: rules.Source{Type: "any"}, Ports: rules.Ports{Type: "list", List: []int{8080}},
				Protocol: "tcp", Zone: "docker"},
			{ID: "d2", Order: 20, Enabled: true, Name: "no 9100", Action: "deny",
				Source: rules.Source{Type: "any"}, Ports: rules.Ports{Type: "list", List: []int{9100}},
				Protocol: "tcp", Zone: "host"},
		},
	}
	pp := system.PublishedPorts{TCP: map[int]bool{8096: true}, UDP: map[int]bool{}}
	active := []apps.Entry{
		{Key: "a", Zone: "docker", Proto: "tcp", Port: 8080, State: apps.Any, Present: true},
		{Key: "b", Zone: "host", Proto: "tcp", Port: 9100, State: apps.Any, Present: true},
	}
	requireNetnsMount(t, "nft")
	dir := t.TempDir()
	sp, ap := filepath.Join(dir, "compiled.sh"), filepath.Join(dir, "apps.sh")
	os.WriteFile(sp, []byte(Compile(rs, pp, nil)), 0o600)
	os.WriteFile(ap, []byte(CompileApps(active, rs.LAN)), 0o600)
	full := "BACKEND=nft\n" + dnatTopology + appsTopology +
		"bash " + sp + " >/dev/null 2>&1\nbash " + ap + " >/dev/null 2>&1\nP=deny\n" + appsProbes +
		"kill $(jobs -p) 2>/dev/null || true\n"
	fp := filepath.Join(dir, "run.sh")
	os.WriteFile(fp, []byte(full), 0o600)
	out, err := exec.Command("unshare", "-U", "-r", "-n", "-m", "bash", fp).CombinedOutput()
	if err != nil {
		t.Fatalf("netns run failed: %v\n%s", err, out)
	}
	for _, p := range []string{"deny-docker-lan", "deny-docker-wan", "deny-host-lan", "deny-host-wan"} {
		if !strings.Contains(string(out), p+" BLOCKED") {
			t.Errorf("%s: want BLOCKED (user deny above the app chain)\n%s", p, out)
		}
	}
}

// enginePath locates engine/zfw from the package directory.
func enginePath(t *testing.T) string {
	t.Helper()
	p, err := filepath.Abs(filepath.Join("..", "..", "engine", "zfw"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(p); err != nil {
		t.Fatalf("engine script: %v", err)
	}
	return p
}
