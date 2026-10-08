//go:build netns_integration

package compiler

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/chicohaager/zfw/internal/rules"
	"github.com/chicohaager/zfw/internal/system"
)

// dnatTopology builds, inside an unprivileged user+net+mount namespace, the
// packet path a ZimaOS host puts in front of a published container port:
//
//	lan  (192.0.2.50, fd00:1::50) --eth-lan--> host (192.0.2.1, fd00:1::1)
//	ts   (100.64.0.2)            --tailscale0--> host            (mesh bypass)
//	host --br-test--> ctr  (198.51.100.2, fd00:2::2)  listens on :80 :81 :82
//	host --br-two---> ctr2 (203.0.113.2)                          (2nd compose network)
//
// with Docker's own plumbing reproduced by hand: an empty DOCKER-USER that
// FORWARD jumps to first, and DNAT in nat PREROUTING + OUTPUT for
// 8080->:80, 8096->:81, 8097->:82 (IPv4 and IPv6). The firewall under test is
// then the compiled script, run exactly as the engine runs it.
//
// $BACKEND selects which iptables flavour plays "Docker's backend"; the
// compiled script's own probe has to find it.
const dnatTopology = `set -eu
mount -t tmpfs none /run
mkdir -p /run/netns
export XTABLES_LOCKFILE=/run/xtables.lock
IPT=iptables-$BACKEND; IPT6=ip6tables-$BACKEND
ip link set lo up
for n in lan ctr ctr2 ts; do ip netns add $n; ip netns exec $n ip link set lo up; done
sysctl -qw net.ipv4.ip_forward=1
sysctl -qw net.ipv6.conf.all.forwarding=1

ip link add br-test type bridge; ip link set br-test up
ip addr add 198.51.100.1/24 dev br-test; ip addr add fd00:2::1/64 dev br-test nodad
ip link add v-ctr type veth peer name eth0 netns ctr
ip link set v-ctr master br-test up
ip netns exec ctr ip addr add 198.51.100.2/24 dev eth0
ip netns exec ctr ip addr add fd00:2::2/64 dev eth0 nodad
ip netns exec ctr ip link set eth0 up
ip netns exec ctr ip route add default via 198.51.100.1
ip netns exec ctr ip -6 route add default via fd00:2::1

ip link add br-two type bridge; ip link set br-two up
ip addr add 203.0.113.1/24 dev br-two
ip link add v-ctr2 type veth peer name eth0 netns ctr2
ip link set v-ctr2 master br-two up
ip netns exec ctr2 ip addr add 203.0.113.2/24 dev eth0
ip netns exec ctr2 ip link set eth0 up
ip netns exec ctr2 ip route add default via 203.0.113.1

ip link add eth-lan type veth peer name eth0 netns lan
ip addr add 192.0.2.1/24 dev eth-lan; ip addr add fd00:1::1/64 dev eth-lan nodad
ip link set eth-lan up
ip netns exec lan ip addr add 192.0.2.50/24 dev eth0
ip netns exec lan ip addr add fd00:1::50/64 dev eth0 nodad
ip netns exec lan ip link set eth0 up
ip netns exec lan ip route add default via 192.0.2.1
ip netns exec lan ip -6 route add default via fd00:1::1

ip link add tailscale0 type veth peer name eth0 netns ts
ip addr add 100.64.0.1/24 dev tailscale0; ip link set tailscale0 up
ip netns exec ts ip addr add 100.64.0.2/24 dev eth0
ip netns exec ts ip link set eth0 up
ip netns exec ts ip route add default via 100.64.0.1

for X in "$IPT" "$IPT6"; do
  $X -N DOCKER-USER; $X -A DOCKER-USER -j RETURN; $X -A FORWARD -j DOCKER-USER
done
for pair in 8080:80 8096:81 8097:82; do
  p=${pair%%:*}; c=${pair##*:}
  for ch in PREROUTING OUTPUT; do
    $IPT  -t nat -A $ch -p tcp -d 192.0.2.1 --dport $p -j DNAT --to-destination 198.51.100.2:$c
    $IPT6 -t nat -A $ch -p tcp -d fd00:1::1 --dport $p -j DNAT --to-destination "[fd00:2::2]:$c"
  done
done
# Masquerade the container's egress, as Docker does.
$IPT -t nat -A POSTROUTING -s 198.51.100.0/24 ! -o br-test -j MASQUERADE

SRV='import socket,sys,threading
def serve(p):
    s=socket.socket(socket.AF_INET6); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
    s.setsockopt(socket.IPPROTO_IPV6,socket.IPV6_V6ONLY,0); s.bind(("::",p)); s.listen(8)
    while True:
        c,_=s.accept(); c.sendall(b"ok"); c.close()
for p in map(int,sys.argv[1:]): threading.Thread(target=serve,args=(p,),daemon=True).start()
threading.Event().wait()'
ip netns exec ctr python3 -c "$SRV" 80 81 82 &
ip netns exec lan python3 -c "$SRV" 9000 &
sleep 0.7
`

// dnatProbes run after the firewall is applied. Each prints "<name> REACH" or
// "<name> BLOCKED".
const dnatProbes = `
CLI='import socket,sys
try:
    s=socket.create_connection((sys.argv[1],int(sys.argv[2])),timeout=1.5); print(sys.argv[3],"REACH" if s.recv(2)==b"ok" else "BLOCKED")
except Exception: print(sys.argv[3],"BLOCKED")'
probe(){ local ns="$1"; shift; if [ "$ns" = host ]; then python3 -c "$CLI" "$@"; else ip netns exec "$ns" python3 -c "$CLI" "$@"; fi; }
probe lan  192.0.2.1  8080 new-port-from-lan
probe lan  fd00:1::1  8080 new-port-from-lan-v6
probe lan  192.0.2.1  8096 allowed-port-from-lan
probe lan  fd00:1::1  8096 allowed-port-from-lan-v6
probe lan  192.0.2.1  8097 known-denied-port-from-lan
probe ctr  192.0.2.50 9000 container-egress
probe host 192.0.2.1  8080 host-process-to-new-port
probe ctr2 192.0.2.1  8080 other-network-container-to-new-port
probe ts   192.0.2.1  8080 tailscale-peer-to-new-port
echo "--- DOCKER-USER v4 ---"; $IPT -S DOCKER-USER
echo "--- DOCKER-USER v6 ---"; $IPT6 -S DOCKER-USER
kill $(jobs -p) 2>/dev/null || true
`

func requireNetnsMount(t *testing.T, backend string) {
	t.Helper()
	requireNetns(t)
	for _, b := range []string{"iptables-" + backend, "ip6tables-" + backend, "ip", "python3"} {
		if _, err := exec.LookPath(b); err != nil {
			t.Skipf("%s not installed: %v", b, err)
		}
	}
	probe := "mount -t tmpfs none /run && export XTABLES_LOCKFILE=/run/x.lock && " +
		"iptables-" + backend + " -t nat -L -n >/dev/null && ip6tables-" + backend + " -t nat -L -n >/dev/null"
	if out, err := exec.Command("unshare", "-U", "-r", "-n", "-m", "bash", "-c", probe).CombinedOutput(); err != nil {
		t.Skipf("%s nat table unavailable in an unprivileged netns: %v\n%s", backend, err, out)
	}
}

// TestDNATGuardLive drives the compiled script through real netfilter, on
// both backends and through both emitters, and checks every path the guard
// could have broken next to the one it must close.
func TestDNATGuardLive(t *testing.T) {
	rs := rules.RuleSet{
		LAN: "192.0.2.0/24", HostIP: "192.0.2.1", DefaultPolicy: "deny",
		Rules: []rules.Rule{{
			ID: "r1", Order: 10, Enabled: true, Name: "app 8096", Action: "allow",
			Source:   rules.Source{Type: "any"},
			Ports:    rules.Ports{Type: "list", List: []int{8096}},
			Protocol: "tcp", Zone: "docker",
		}},
	}
	// The inventory at compile time: 8080 is NOT in it — it stands for the
	// app installed after the last apply.
	pp := system.PublishedPorts{TCP: map[int]bool{8096: true, 8097: true}, UDP: map[int]bool{}}

	want := map[string]string{
		"new-port-from-lan":                   "BLOCKED", // the hole this closes
		"new-port-from-lan-v6":                "BLOCKED",
		"allowed-port-from-lan":               "REACH",
		"allowed-port-from-lan-v6":            "REACH",
		"known-denied-port-from-lan":          "BLOCKED",
		"container-egress":                    "REACH",
		"host-process-to-new-port":            "REACH", // network_mode: host apps (Newt) — OUTPUT path
		"other-network-container-to-new-port": "REACH", // container -> published port on another bridge
		"tailscale-peer-to-new-port":          "REACH", // mesh bypass
	}

	emitters := map[string]string{
		"bash":    Compile(rs, pp, nil),
		"restore": CompileRestoreScript(rs, pp, nil),
	}
	for _, backend := range []string{"nft", "legacy"} {
		for ename, script := range emitters {
			t.Run(backend+"/"+ename, func(t *testing.T) {
				requireNetnsMount(t, backend)
				dir := t.TempDir()
				sp := filepath.Join(dir, "compiled.sh")
				if err := os.WriteFile(sp, []byte(script), 0o600); err != nil {
					t.Fatal(err)
				}
				full := "BACKEND=" + backend + "\n" + dnatTopology +
					"bash " + sp + " > " + filepath.Join(dir, "apply.log") + " 2>&1 || { echo APPLY-FAILED; cat " + filepath.Join(dir, "apply.log") + "; exit 1; }\n" +
					dnatProbes
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
				if t.Failed() {
					t.Logf("full output:\n%s", out)
				}
			})
		}
	}
}

// linkLocalTopology: host and one LAN neighbour on a veth, IPv6 only. The
// host serves :2222 (no rule) and :2223 (allowed from any source) on [::].
const linkLocalTopology = `set -eu
mount -t tmpfs none /run
mkdir -p /run/netns
export XTABLES_LOCKFILE=/run/xtables.lock
ip link set lo up
sysctl -qw net.ipv6.conf.default.accept_dad=0 net.ipv6.conf.all.accept_dad=0
ip netns add lan
ip netns exec lan sysctl -qw net.ipv6.conf.default.accept_dad=0 net.ipv6.conf.all.accept_dad=0
ip netns exec lan ip link set lo up
ip link add eth-lan type veth peer name eth0 netns lan
ip addr add fd00:1::1/64 dev eth-lan nodad
ip link set eth-lan up
ip netns exec lan ip addr add fd00:1::50/64 dev eth0 nodad
ip netns exec lan ip link set eth0 up
# Link-local addresses still run DAD-less but need the link to settle before
# the kernel uses them as a source; wait until both ends report them usable.
for i in $(seq 1 50); do
  if ! ip -6 addr show dev eth-lan | grep -q tentative && \
     ! ip netns exec lan ip -6 addr show dev eth0 | grep -q tentative && \
     ip netns exec lan ip -6 addr show dev eth0 scope link | grep -q fe80; then break; fi
  sleep 0.1
done
sleep 1
LL="$(ip -6 -o addr show dev eth-lan scope link | awk '{print $4}' | cut -d/ -f1)"
[ -n "$LL" ] || { echo "no link-local address on eth-lan"; exit 1; }
SRV='import socket,sys,threading
def serve(p):
    s=socket.socket(socket.AF_INET6); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
    s.bind(("::",p)); s.listen(8)
    while True:
        c,_=s.accept(); c.sendall(b"ok"); c.close()
for p in map(int,sys.argv[1:]): threading.Thread(target=serve,args=(p,),daemon=True).start()
threading.Event().wait()'
python3 -c "$SRV" 2222 2223 &
sleep 0.5
`

const linkLocalProbes = `
CLI='import socket,sys
try:
    s=socket.create_connection((sys.argv[1],int(sys.argv[2])),timeout=1.5); print(sys.argv[3],"REACH" if s.recv(2)==b"ok" else "BLOCKED")
except Exception: print(sys.argv[3],"BLOCKED")'
# Positive control first: it also settles neighbour discovery on the link,
# so a BLOCKED below cannot be an unresolved neighbour in disguise.
ip netns exec lan python3 -c "$CLI" "$LL%eth0" 2223 allowed-port-via-link-local
ip netns exec lan python3 -c "$CLI" "$LL%eth0" 2222 unruled-port-via-link-local
ip netns exec lan python3 -c "$CLI" fd00:1::1   2222 unruled-port-via-ula
[ -n "${ZFW_DEBUG:-}" ] && { ip6tables-nft -L ZFW-IN6 -v -n; ip6tables-nft -S INPUT; ip netns exec lan ip -6 addr; ip -6 addr; }
kill $(jobs -p) 2>/dev/null || true
`

// TestLinkLocalFilteredLive: a LAN neighbour must not reach an un-ruled
// service through the host's fe80:: address. The allowed port doubles as the
// positive control that neighbour discovery (ICMPv6) still works with the
// blanket link-local RETURN gone.
func TestLinkLocalFilteredLive(t *testing.T) {
	rs := rules.RuleSet{
		DefaultPolicy: "deny",
		Rules: []rules.Rule{{
			ID: "r1", Order: 10, Enabled: true, Name: "svc 2223", Action: "allow",
			Source:   rules.Source{Type: "any"},
			Ports:    rules.Ports{Type: "list", List: []int{2223}},
			Protocol: "tcp", Zone: "host",
		}},
	}
	want := map[string]string{
		"unruled-port-via-link-local": "BLOCKED",
		"unruled-port-via-ula":        "BLOCKED",
		"allowed-port-via-link-local": "REACH",
	}
	for ename, script := range map[string]string{
		"bash":    Compile(rs, system.PublishedPorts{}, nil),
		"restore": CompileRestoreScript(rs, system.PublishedPorts{}, nil),
	} {
		t.Run(ename, func(t *testing.T) {
			requireNetnsMount(t, "nft")
			dir := t.TempDir()
			sp := filepath.Join(dir, "compiled.sh")
			if err := os.WriteFile(sp, []byte(script), 0o600); err != nil {
				t.Fatal(err)
			}
			full := linkLocalTopology +
				"bash " + sp + " > " + filepath.Join(dir, "apply.log") + " 2>&1 || { echo APPLY-FAILED; cat " + filepath.Join(dir, "apply.log") + "; exit 1; }\n" +
				linkLocalProbes
			fp := filepath.Join(dir, "run.sh")
			if err := os.WriteFile(fp, []byte(full), 0o600); err != nil {
				t.Fatal(err)
			}
			out, err := exec.Command("unshare", "-U", "-r", "-n", "-m", "bash", fp).CombinedOutput()
			if err != nil {
				t.Fatalf("netns run failed: %v\n%s", err, out)
			}
			t.Logf("probe output:\n%s", out)
			for probe, w := range want {
				if !strings.Contains(string(out), probe+" "+w) {
					t.Errorf("%s: want %s\nfull output:\n%s", probe, w, out)
				}
			}
		})
	}
}
