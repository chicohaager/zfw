// Package system inspects the host: listening TCP sockets and component
// versions with known-CVE annotations.
package system

import (
	"bufio"
	"context"
	"net"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// DetectLAN6 guesses the primary SLAAC prefix and host IPv6 address by asking
// the kernel which source IPv6 it would pick to reach an arbitrary public
// IPv6 address. Like DetectLAN this does not send any packets — the UDP dial
// only resolves the default-route source. Both return values are empty when
// the host has no IPv6 connectivity (no global default route, ULA-only, or
// IPv6 disabled), so callers must treat the empty case as "no IPv6 known"
// and not as a validation error.
//
// The returned prefix is whatever CIDR the interface advertises for the
// chosen source address — typically /64 from SLAAC, occasionally /128 for
// a privacy address whose lease registers only the host. Either is correct
// input for a per-rule IPv6 source picker; the caller decides how much of
// it to surface.
func DetectLAN6() (lan6CIDR, hostIP6 string) {
	conn, err := net.Dial("udp", "[2001:4860:4860::8888]:80")
	if err != nil {
		return
	}
	defer conn.Close()
	local, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok || local.IP.To4() != nil {
		return
	}
	hostIP6 = local.IP.String()
	ifs, err := net.Interfaces()
	if err != nil {
		return
	}
	for _, iface := range ifs {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			ipnet, ok := addr.(*net.IPNet)
			if !ok || !ipnet.IP.Equal(local.IP) {
				continue
			}
			if _, network, err := net.ParseCIDR(ipnet.String()); err == nil {
				lan6CIDR = network.String()
			}
			return
		}
	}
	return
}

// DetectLAN guesses the primary LAN CIDR and host IP by asking the kernel
// which source IP it would pick to reach an arbitrary public address — no
// packets are sent, the UDP dial only resolves the default-route source.
// Both return values fall back to safe placeholders when detection fails so
// the caller never has to handle errors.
//
// CQ-14 (v1.0.2): the result is cached for lanTTL to mirror Versions()'s
// caching policy. A repeated dashboard refresh that hits both /api/versions
// and any handler reaching DetectLAN was otherwise inconsistent — one
// payed the kernel-route-resolution cost, the other did not.
func DetectLAN() (lanCIDR, hostIP string) {
	lanMu.Lock()
	defer lanMu.Unlock()
	if !lanCached.IsZero() && time.Since(lanCached) < lanTTL {
		return lanCacheLAN, lanCacheIP
	}
	lan, ip := detectLANUncached()
	lanCacheLAN, lanCacheIP, lanCached = lan, ip, time.Now()
	return lan, ip
}

func detectLANUncached() (lanCIDR, hostIP string) {
	lanCIDR = "192.168.1.0/24"
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return
	}
	defer conn.Close()
	local, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok {
		return
	}
	hostIP = local.IP.String()
	ifs, err := net.Interfaces()
	if err != nil {
		return
	}
	for _, iface := range ifs {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			ipnet, ok := addr.(*net.IPNet)
			if !ok || !ipnet.IP.Equal(local.IP) {
				continue
			}
			if _, network, err := net.ParseCIDR(ipnet.String()); err == nil {
				lanCIDR = network.String()
			}
			return
		}
	}
	return
}

// LAN detection cache — same TTL shape as Versions(). Mutex-guarded so a
// concurrent dashboard refresh from multiple browser tabs cannot race
// the cache fields.
var (
	lanMu       sync.Mutex
	lanCached   time.Time
	lanCacheLAN string
	lanCacheIP  string
)

const lanTTL = 60 * time.Second

func run(ctx context.Context, name string, args ...string) string {
	cctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	out, _ := exec.CommandContext(cctx, name, args...).CombinedOutput()
	return string(out)
}

// Socket is one listening TCP port.
type Socket struct {
	Port  int    `json:"port"`
	Bind  string `json:"bind"`
	Proc  string `json:"proc"`
	Scope string `json:"scope"` // "local" (loopback) or "all" (LAN-facing)
}

// Listening returns deduplicated listening TCP sockets, sorted by port.
func Listening(ctx context.Context) ([]Socket, error) {
	cctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	out, err := exec.CommandContext(cctx, "ss", "-tlnHp").CombinedOutput()
	if err != nil {
		return nil, err
	}
	seen := map[int]Socket{}
	sc := bufio.NewScanner(strings.NewReader(string(out)))
	for sc.Scan() {
		line := sc.Text()
		f := strings.Fields(line)
		if len(f) < 4 {
			continue
		}
		local := f[3]
		i := strings.LastIndex(local, ":")
		if i < 0 {
			continue
		}
		host := strings.Trim(local[:i], "[]")
		port, err := strconv.Atoi(local[i+1:])
		if err != nil {
			continue
		}
		scope := "all"
		if host == "127.0.0.1" || host == "::1" {
			scope = "local"
		}
		proc := ""
		if j := strings.Index(line, `users:(("`); j >= 0 {
			rest := line[j+9:]
			if k := strings.IndexByte(rest, '"'); k >= 0 {
				proc = rest[:k]
			}
		}
		if ex, ok := seen[port]; ok {
			if ex.Scope == "all" {
				scope = "all" // a LAN-facing bind dominates a loopback one
			}
			if proc == "" {
				proc = ex.Proc
			}
		}
		seen[port] = Socket{Port: port, Bind: host, Proc: proc, Scope: scope}
	}
	res := make([]Socket, 0, len(seen))
	for _, s := range seen {
		res = append(res, s)
	}
	sort.Slice(res, func(i, j int) bool { return res[i].Port < res[j].Port })
	return res, nil
}

// DockerContainer is one live container with its host-published TCP ports.
// v0.5.7 — drives per-container rule binding: the daemon resolves
// Rule.ContainerID at compile time and substitutes the container's
// current published-port list into the rule, so a Docker app's rule
// follows its ports across restarts and remaps.
type DockerContainer struct {
	ID    string `json:"id"`    // short 12-char container ID
	Name  string `json:"name"`  // container name (handier for the UI than the ID)
	Image string `json:"image"` // image:tag the container is running
	Ports []int  `json:"ports"` // host-published TCP ports, sorted+deduped
}

// DockerContainers returns the live container inventory. Empty slice on
// error (test envs without docker, daemon down, etc.) — the daemon
// degrades to using saved Rule.Ports for bound rules.
func DockerContainers(ctx context.Context) []DockerContainer {
	out := run(ctx, "docker", "ps",
		"--format", "{{.ID}}\t{{.Names}}\t{{.Image}}\t{{.Ports}}")
	var cs []DockerContainer
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, "\t", 4)
		if len(parts) < 3 {
			continue
		}
		portsField := ""
		if len(parts) == 4 {
			portsField = parts[3]
		}
		cs = append(cs, DockerContainer{
			ID:    parts[0],
			Name:  parts[1],
			Image: parts[2],
			Ports: parseDockerPorts(portsField),
		})
	}
	return cs
}

// parseDockerPorts extracts host-side TCP port numbers from the
// docker-ps Ports column. Format examples:
//
//	"0.0.0.0:8096->8096/tcp, :::8096->8096/tcp"
//	"0.0.0.0:32400->32400/tcp, :::32400->32400/tcp, 32400/udp"
//
// Container-only ports (no `->host` mapping) are skipped because they
// are not LAN-reachable. UDP-mapped ports are dropped because the rule
// engine emits TCP rules by default; the user can add UDP rules
// explicitly.
func parseDockerPorts(s string) []int {
	seen := map[int]bool{}
	var ports []int
	for _, p := range strings.Split(s, ",") {
		p = strings.TrimSpace(p)
		// Only host-mapped TCP entries carry "host:port->container/tcp".
		if !strings.Contains(p, "->") || !strings.HasSuffix(p, "/tcp") {
			continue
		}
		arrow := strings.Index(p, "->")
		before := p[:arrow]
		colon := strings.LastIndex(before, ":")
		if colon < 0 {
			continue
		}
		n, err := strconv.Atoi(before[colon+1:])
		if err != nil || n < 1 || n > 65535 {
			continue
		}
		if !seen[n] {
			seen[n] = true
			ports = append(ports, n)
		}
	}
	sort.Ints(ports)
	return ports
}

// DockerPorts returns the set of TCP ports published by Docker (recognised by
// the docker-proxy process). Used to resolve firewall rule zone "auto".
func DockerPorts(ctx context.Context) map[int]bool {
	m := map[int]bool{}
	socks, err := Listening(ctx)
	if err != nil {
		return m
	}
	for _, s := range socks {
		if s.Proc == "docker-proxy" {
			m[s.Port] = true
		}
	}
	return m
}

// Component is one software component with a version and a risk note.
type Component struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Note    string `json:"note"`
	Level   string `json:"level"` // "ok" | "warn" | "crit"
}

// versions are cached briefly: each call spawns several subprocesses, so an
// authenticated client cannot use /api/versions to amplify host load (ZFW-S9).
var (
	verMu     sync.Mutex
	verCache  []Component
	verCached time.Time
)

const verTTL = 60 * time.Second

// Versions reports key host component versions with known-CVE annotations.
func Versions(ctx context.Context) []Component {
	verMu.Lock()
	defer verMu.Unlock()
	if verCache != nil && time.Since(verCached) < verTTL {
		return verCache
	}
	var cs []Component

	cs = append(cs, Component{
		Name: "ZimaOS", Version: orDash(osRelease("VERSION")),
		Note: "All app-layer CVEs ≤1.5.3 are fixed", Level: "ok",
	})

	kern := firstLine(run(ctx, "uname", "-r"))
	kc := Component{Name: "Linux kernel", Version: orDash(kern), Note: "up to date", Level: "ok"}
	if kernelVulnerable(kern) {
		kc.Note = "CVE-2026-31431 (Copy Fail) — local root; fix only in ~6.12.86, firmware update only"
		kc.Level = "warn"
	}
	cs = append(cs, kc)

	docker := extractVersion(run(ctx, "docker", "--version"))
	cs = append(cs, Component{
		Name: "Docker Engine", Version: orDash(docker),
		Note: "docker cp escapes < 29.3.1 (conditional)", Level: levelIf(dockerOld(docker)),
	})

	ssh := opensshVersion(run(ctx, "ssh", "-V"))
	cs = append(cs, Component{
		Name: "OpenSSH", Version: orDash(ssh),
		Note: "regreSSHion (CVE-2024-6387) not affected from 9.8p1 onward", Level: "ok",
	})

	ipt := extractVersion(run(ctx, "iptables-legacy", "--version"))
	if ipt == "" {
		ipt = extractVersion(run(ctx, "iptables", "--version"))
	}
	cs = append(cs, Component{
		Name: "iptables", Version: orDash(ipt),
		Note: "Backend: iptables-legacy (Docker-compatible)", Level: "ok",
	})
	verCache, verCached = cs, time.Now()
	return cs
}

func osRelease(key string) string {
	f, err := os.Open("/etc/os-release")
	if err != nil {
		return ""
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), "=")
		if ok && k == key {
			return strings.Trim(strings.TrimSpace(v), `"`)
		}
	}
	return ""
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	return strings.TrimSpace(s)
}

// extractVersion pulls the first dotted-number token out of a tool's
// "--version" banner (e.g. "Docker version 27.5.1, build ..." -> "27.5.1",
// "iptables v1.8.10 (legacy)" -> "1.8.10").
func extractVersion(s string) string {
	for _, tok := range strings.FieldsFunc(s, func(r rune) bool {
		return r == ' ' || r == ',' || r == '\n' || r == '\t' || r == '('
	}) {
		t := strings.TrimLeft(tok, "vV")
		if len(t) > 0 && t[0] >= '0' && t[0] <= '9' && strings.Contains(t, ".") {
			return strings.TrimRight(t, ".,)")
		}
	}
	return ""
}

// opensshVersion extracts e.g. "9.9p2" from `ssh -V`
// ("OpenSSH_9.9p2, OpenSSL 3.4.3 ...").
func opensshVersion(s string) string {
	s = firstLine(s)
	if i := strings.Index(s, "OpenSSH_"); i >= 0 {
		s = s[i+len("OpenSSH_"):]
	}
	if i := strings.IndexAny(s, ", "); i >= 0 {
		s = s[:i]
	}
	return strings.TrimSpace(s)
}

func orDash(s string) string {
	if s == "" {
		return "—"
	}
	return s
}

func levelIf(warn bool) string {
	if warn {
		return "warn"
	}
	return "ok"
}

// kernelVulnerable reports whether a 6.12.x kernel predates the Copy-Fail fix.
func kernelVulnerable(kern string) bool {
	maj, min, patch := parseKernel(kern)
	return maj == 6 && min == 12 && patch > 0 && patch < 86
}

func dockerOld(ver string) bool {
	maj, _, _ := parseKernel(ver) // reuse the major.minor.patch splitter
	return maj > 0 && maj < 29
}

func parseKernel(s string) (maj, min, patch int) {
	parts := strings.SplitN(s, ".", 3)
	get := func(i int) int {
		if i >= len(parts) {
			return 0
		}
		num := ""
		for _, r := range parts[i] {
			if r < '0' || r > '9' {
				break
			}
			num += string(r)
		}
		n, _ := strconv.Atoi(num)
		return n
	}
	return get(0), get(1), get(2)
}
