package system

import (
	"bufio"
	"context"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// AppPort is one port a running container offers to the network (v1.0.28,
// the new-app prompt). Zone is "docker" for a published port (DNAT through
// DOCKER-USER) and "host" for a network_mode: host container's own listener
// (filtered by ZFW-IN).
type AppPort struct {
	Container string
	AppID     string // io.zimaos.app.id — set by the ZimaOS app store and custom apps
	Project   string // com.docker.compose.project
	Zone      string
	Proto     string
	Port      int
	Started   time.Time // host zone only
}

// AppPorts lists the network-facing ports of every running container.
// Loopback-only publishings (127.0.0.1:8080->80) are left out: nothing on the
// LAN can reach them, so there is nothing to ask.
func AppPorts(ctx context.Context) ([]AppPort, error) {
	out, err := runErr(ctx, "docker", "ps", "--no-trunc", "--format",
		`{{.ID}}	{{.Names}}	{{.Ports}}	{{.Networks}}	{{.Label "io.zimaos.app.id"}}	{{.Label "com.docker.compose.project"}}`)
	if err != nil {
		return nil, err
	}
	var res []AppPort
	var hostNet []hostNetContainer
	for _, line := range strings.Split(out, "\n") {
		f := strings.Split(strings.TrimRight(line, "\r"), "\t")
		if len(f) < 6 || f[0] == "" {
			continue
		}
		id, name, ports, nets, appID, project := f[0], f[1], f[2], f[3], f[4], f[5]
		if nets == "host" {
			hostNet = append(hostNet, hostNetContainer{id: id, name: name, appID: appID, project: project})
			continue
		}
		for _, p := range parsePublished(ports) {
			res = append(res, AppPort{Container: name, AppID: appID, Project: project,
				Zone: "docker", Proto: p.proto, Port: p.port})
		}
	}
	if len(hostNet) > 0 {
		res = append(res, hostNetPorts(ctx, hostNet)...)
	}
	return res, nil
}

type published struct {
	proto string
	port  int
}

// parsePublished reads docker ps' Ports column ("0.0.0.0:8086->80/tcp,
// :::8086->80/tcp, 127.0.0.1:9000->9000/tcp") and returns each host port that
// is bound to at least one non-loopback address, once per protocol.
func parsePublished(s string) []published {
	seen := map[published]bool{}
	var out []published
	for _, p := range strings.Split(s, ",") {
		p = strings.TrimSpace(p)
		before, after, ok := strings.Cut(p, "->")
		if !ok {
			continue
		}
		proto := ""
		switch {
		case strings.HasSuffix(after, "/tcp"):
			proto = "tcp"
		case strings.HasSuffix(after, "/udp"):
			proto = "udp"
		default:
			continue
		}
		colon := strings.LastIndex(before, ":")
		if colon < 0 {
			continue
		}
		host := strings.Trim(before[:colon], "[]")
		if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
			continue
		}
		// A range publishing (0.0.0.0:8000-8010->…) is skipped: one question per
		// port of a range would be noise, and ranges are rare in app manifests.
		n, err := strconv.Atoi(before[colon+1:])
		if err != nil || n < 1 || n > 65535 {
			continue
		}
		k := published{proto, n}
		if !seen[k] {
			seen[k] = true
			out = append(out, k)
		}
	}
	return out
}

type hostNetContainer struct{ id, name, appID, project string }

var ssPID = regexp.MustCompile(`pid=(\d+)`)

// hostNetPorts finds what network_mode: host containers listen on. Their
// sockets live in the host's namespace, so `ss` shows them with the owning
// pid; a pid belongs to a container when its cgroup path carries the
// container's full ID (cgroup v1 and v2, docker and systemd drivers).
func hostNetPorts(ctx context.Context, cs []hostNetContainer) []AppPort {
	started := map[string]time.Time{}
	for _, c := range cs {
		if o, err := runErr(ctx, "docker", "inspect", "-f", "{{.State.StartedAt}}", c.id); err == nil {
			if t, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(o)); err == nil {
				started[c.id] = t
			}
		}
	}
	var res []AppPort
	for _, proto := range []string{"tcp", "udp"} {
		flag := "-tlnHp"
		if proto == "udp" {
			flag = "-ulnHp"
		}
		out, err := runErr(ctx, "ss", flag)
		if err != nil {
			continue
		}
		seen := map[string]bool{}
		sc := bufio.NewScanner(strings.NewReader(out))
		for sc.Scan() {
			line := sc.Text()
			fs := strings.Fields(line)
			if len(fs) < 4 {
				continue
			}
			local := fs[3]
			i := strings.LastIndex(local, ":")
			if i < 0 {
				continue
			}
			host := strings.Trim(local[:i], "[]")
			if pct := strings.Index(host, "%"); pct >= 0 {
				host = host[:pct] // 0.0.0.0%eth0 — bound to a device
			}
			if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
				continue
			}
			port, err := strconv.Atoi(local[i+1:])
			if err != nil {
				continue
			}
			for _, m := range ssPID.FindAllStringSubmatch(line, -1) {
				c, ok := containerOfPID(m[1], cs)
				if !ok {
					continue
				}
				key := c.id + "/" + strconv.Itoa(port)
				if seen[key] {
					break
				}
				seen[key] = true
				res = append(res, AppPort{Container: c.name, AppID: c.appID, Project: c.project,
					Zone: "host", Proto: proto, Port: port, Started: started[c.id]})
				break
			}
		}
	}
	return res
}

func containerOfPID(pid string, cs []hostNetContainer) (hostNetContainer, bool) {
	b, err := os.ReadFile("/proc/" + pid + "/cgroup")
	if err != nil {
		return hostNetContainer{}, false
	}
	cg := string(b)
	for _, c := range cs {
		if len(c.id) >= 12 && strings.Contains(cg, c.id) {
			return c, true
		}
	}
	return hostNetContainer{}, false
}

// CasaOSAppsDir is where ZimaOS keeps each app's compose file, one directory
// per compose project (measured on 1.8.0-beta2, KB §75).
const CasaOSAppsDir = "/var/lib/casaos/apps"

// AppTitle returns an app's display title from the x-casaos block of its
// compose file, "" when there is none. ZimaOS writes either
//
//	x-casaos:
//	  title:
//	    en_us: CasaDrop
//
// or, for a custom app, `custom: Pangolin Site` under title. A hand-rolled
// scan rather than a YAML dependency: one key is needed, and the file is
// written by ZimaOS in this one shape.
func AppTitle(dir, project string) string {
	if project == "" || strings.ContainsAny(project, `/\`) || project == "." || project == ".." {
		return ""
	}
	f, err := os.Open(filepath.Join(dir, project, "docker-compose.yml"))
	if err != nil {
		return ""
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	inX, inTitle := false, false
	titleIndent := 0
	found := map[string]string{}
	for sc.Scan() {
		raw := strings.TrimRight(sc.Text(), " \t\r")
		trimmed := strings.TrimLeft(raw, " ")
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		indent := len(raw) - len(trimmed)
		if indent == 0 {
			inX, inTitle = trimmed == "x-casaos:", false
			continue
		}
		if !inX {
			continue
		}
		key, val, _ := strings.Cut(trimmed, ":")
		val = unquote(strings.TrimSpace(val))
		if inTitle && indent > titleIndent {
			found[strings.ToLower(strings.TrimSpace(key))] = val
			continue
		}
		inTitle = false
		if strings.TrimSpace(key) == "title" {
			if val != "" {
				return val
			}
			inTitle, titleIndent = true, indent
		}
	}
	for _, k := range []string{"en_us", "custom"} {
		if v := found[k]; v != "" {
			return v
		}
	}
	for _, v := range found {
		if v != "" {
			return v
		}
	}
	return ""
}

func unquote(s string) string {
	if len(s) >= 2 && (s[0] == '"' && s[len(s)-1] == '"' || s[0] == '\'' && s[len(s)-1] == '\'') {
		return s[1 : len(s)-1]
	}
	return s
}
