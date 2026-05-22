// Package system inspects the host: listening TCP sockets and component
// versions with known-CVE annotations.
package system

import (
	"bufio"
	"context"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

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
		Note: "App-Layer-CVEs alle ≤1.5.3 gefixt", Level: "ok",
	})

	kern := firstLine(run(ctx, "uname", "-r"))
	kc := Component{Name: "Linux-Kernel", Version: orDash(kern), Note: "aktuell", Level: "ok"}
	if kernelVulnerable(kern) {
		kc.Note = "CVE-2026-31431 (Copy Fail) — lokaler Root; Fix erst ~6.12.86, nur per Firmware-Update"
		kc.Level = "warn"
	}
	cs = append(cs, kc)

	docker := extractVersion(run(ctx, "docker", "--version"))
	cs = append(cs, Component{
		Name: "Docker Engine", Version: orDash(docker),
		Note: "docker cp-Escapes < 29.3.1 (konditionell)", Level: levelIf(dockerOld(docker)),
	})

	ssh := opensshVersion(run(ctx, "ssh", "-V"))
	cs = append(cs, Component{
		Name: "OpenSSH", Version: orDash(ssh),
		Note: "regreSSHion (CVE-2024-6387) nicht betroffen ab 9.8p1", Level: "ok",
	})

	ipt := extractVersion(run(ctx, "iptables-legacy", "--version"))
	if ipt == "" {
		ipt = extractVersion(run(ctx, "iptables", "--version"))
	}
	cs = append(cs, Component{
		Name: "iptables", Version: orDash(ipt),
		Note: "Backend: iptables-legacy (Docker-kompatibel)", Level: "ok",
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
