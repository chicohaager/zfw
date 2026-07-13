// Package firewall wraps the ZFW firewall engine (the /DATA/zfw/zfw script
// plus its allowlist.conf) and reads live iptables/systemd state. The daemon
// is the control plane; the script stays the engine.
package firewall

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Config mirrors allowlist.conf.
type Config struct {
	LAN           string   `json:"lan"`
	HostIP        string   `json:"host_ip"`
	HostTCPLAN    []string `json:"host_tcp_lan"`
	HostUDPLAN    []string `json:"host_udp_lan"`
	DockerDropLAN []string `json:"docker_drop_lan"`
	V6Drop        []string `json:"v6_drop"`
}

// Status is the live firewall state read from iptables and systemd.
type Status struct {
	Active         bool `json:"active"` // ZFW-IN chain exists
	Hooked         bool `json:"hooked"` // INPUT jumps to ZFW-IN
	InputRules     int  `json:"input_rules"`
	DockerDrops    int  `json:"docker_drops"`
	IPv6Active     bool `json:"ipv6_active"`
	Deadman        bool `json:"deadman"`         // a safe-apply rollback is armed
	ServiceEnabled bool `json:"service_enabled"` // zfw.service enabled at boot
}

// Manager wraps the firewall engine.
type Manager struct {
	Bin    string // path to the zfw engine script
	Conf   string // path to allowlist.conf
	iptBin string
	ipt6   string
}

// familyOf reports the backend an iptables binary drives: "nft" or "legacy".
// Both `iptables` and `ip6tables` are alternatives symlinks whose target
// varies per distro release (ZimaOS 1.6.2 points them at nf_tables), so the
// binary *name* says nothing about the table it writes. `-V` does:
//
//	iptables v1.8.11 (nf_tables)
//	iptables v1.8.11 (legacy)
//
// Returns "" when the binary is missing or prints neither marker.
func familyOf(bin string) string {
	out, err := exec.Command(bin, "-V").CombinedOutput()
	if err != nil {
		return ""
	}
	switch s := string(out); {
	case strings.Contains(s, "nf_tables"):
		return "nft"
	case strings.Contains(s, "legacy"):
		return "legacy"
	}
	return ""
}

// v6For returns the ip6tables binary that drives the same backend as the
// given IPv4 binary. Deriving it from the v4 binary's *name* (the pre-v1.0.17
// `strings.Contains(iptBin, "nft")` test) breaks on the fallback path: when
// the Docker-FORWARD probe finds nothing — e.g. zfwd starts before dockerd has
// installed its chains — iptBin is the plain "iptables" alternatives symlink,
// which contains no "nft" substring even though it drives nf_tables. IPv6 then
// gets pinned to ip6tables-legacy, reads an empty table, and Status reports
// "IPv6 protection ✗" while ZFW-IN6 is live in the nft table. Ask each
// candidate what it actually drives instead of pattern-matching its name.
func v6For(iptBin string) string {
	fam := familyOf(iptBin)
	if fam == "" {
		fam = "nft" // modern default; still verified against each candidate below
	}
	for _, c := range []string{"ip6tables-" + fam, "ip6tables"} {
		if _, err := exec.LookPath(c); err != nil {
			continue
		}
		if familyOf(c) == fam {
			return c
		}
	}
	return "ip6tables"
}

// New returns a Manager whose iptables backend matches whichever backend
// Docker actually uses — legacy on ZimaOS<=1.6.1, nft on >=1.6.2. Picking a
// fixed backend silently writes to an unused table after the 1.6.2 nft switch,
// so probe which backend owns Docker's FORWARD jumps and match it.
func New(bin, conf string) *Manager {
	dockerBackend := func() string {
		for _, c := range []string{"iptables-nft", "iptables-legacy"} {
			if _, err := exec.LookPath(c); err != nil {
				continue
			}
			out, _ := exec.Command(c, "-S", "FORWARD").CombinedOutput()
			if strings.Contains(string(out), "DOCKER-USER") || strings.Contains(string(out), "DOCKER-FORWARD") {
				return c
			}
		}
		if _, err := exec.LookPath("iptables"); err == nil {
			return "iptables"
		}
		return "iptables-legacy"
	}
	iptBin := dockerBackend()
	return &Manager{
		Bin:    bin,
		Conf:   conf,
		iptBin: iptBin,
		ipt6:   v6For(iptBin),
	}
}

// run executes a short-lived probe (iptables -S, systemctl is-active, …). The
// 25 s cap is a backstop against a wedged binary; these all answer in
// milliseconds. Engine invocations do NOT go through here — see runEngine.
func run(ctx context.Context, name string, args ...string) (string, error) {
	cctx, cancel := context.WithTimeout(ctx, 25*time.Second)
	defer cancel()
	out, err := exec.CommandContext(cctx, name, args...).CombinedOutput()
	return string(out), err
}

// runEngine executes the privileged engine script. It differs from run in two
// ways that matter, both learned from the apply path:
//
// First, it honours the caller's deadline instead of imposing its own 25 s.
// An apply is not a probe: it modprobes, restores several country ipsets and
// inserts hundreds of rules, which on a slow ARM host can exceed 25 s. The
// handler already bounds it (90 s), and the daemon's startup recompile bounds
// its own — a second, tighter, invisible cap only turned a slow apply into a
// reported failure.
//
// Second, it runs the engine in its own process group and kills the whole group
// on cancellation. exec.CommandContext kills just the process it started, so a
// timeout used to leave the engine's `bash compiled.sh` child running: it kept
// mutating iptables while the handler reported the apply had failed, the
// engine's own revert-on-failure never ran, and in safe mode the still-armed
// dead-man later tore down a firewall the operator had been told did not apply.
// State and report have to agree.
func runEngine(ctx context.Context, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		// Negative pid = the whole process group: the engine and every child it
		// spawned (bash compiled.sh, iptables, ipset).
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
	// Give the group a moment to die before we stop waiting on its output pipes,
	// so a child that ignores the signal cannot pin this goroutine forever.
	cmd.WaitDelay = 5 * time.Second
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// Status reads the live firewall state from iptables and systemd.
func (m *Manager) Status(ctx context.Context) Status {
	var s Status
	if out, err := run(ctx, m.iptBin, "-S", "ZFW-IN"); err == nil {
		s.Active = true
		for _, ln := range strings.Split(out, "\n") {
			if strings.HasPrefix(ln, "-A ZFW-IN") {
				s.InputRules++
			}
		}
	}
	if out, err := run(ctx, m.iptBin, "-S", "INPUT"); err == nil {
		s.Hooked = strings.Contains(out, "-j ZFW-IN")
	}
	if out, err := run(ctx, m.iptBin, "-S", "DOCKER-USER"); err == nil {
		for _, ln := range strings.Split(out, "\n") {
			if strings.Contains(ln, "ctorigdstport") {
				s.DockerDrops++
			}
		}
	}
	s.IPv6Active = m.ipv6Active(ctx)
	if out, _ := run(ctx, "systemctl", "is-active", "zfw-deadman.timer"); strings.TrimSpace(out) == "active" {
		s.Deadman = true
	}
	if out, _ := run(ctx, "systemctl", "is-enabled", "zfw.service"); strings.TrimSpace(out) == "enabled" {
		s.ServiceEnabled = true
	}
	return s
}

// ipv6Active reports whether ZFW-IN6 is both populated and hooked into INPUT.
// Checking only that the chain has rules would call a stranded chain
// "protection"; a chain nothing jumps to filters nothing.
//
// The Manager's ip6tables binary is resolved once at start, but a host can
// carry rules in *both* backends (ZimaOS 1.6.2 leaves the legacy tables in
// place after switching Docker to nft) and the kernel traverses whichever
// table holds rules. So if the primary binary comes up empty, ask the other
// family before reporting ✗ — a false "IPv6 protection ✗" on a host that is
// in fact protected is the exact bug reported against v1.0.16.
func (m *Manager) ipv6Active(ctx context.Context) bool {
	seen := map[string]bool{}
	for _, bin := range []string{m.ipt6, "ip6tables-nft", "ip6tables-legacy"} {
		if bin == "" || seen[bin] {
			continue
		}
		seen[bin] = true
		out, err := run(ctx, bin, "-S", "ZFW-IN6")
		if err != nil || !strings.Contains(out, "-A ZFW-IN6") {
			continue
		}
		if hook, err := run(ctx, bin, "-S", "INPUT"); err == nil && strings.Contains(hook, "-j ZFW-IN6") {
			return true
		}
	}
	return false
}

// LoadConfig parses allowlist.conf.
func (m *Manager) LoadConfig() (Config, error) {
	f, err := os.Open(m.Conf)
	if err != nil {
		return Config{}, err
	}
	defer f.Close()
	var c Config
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch strings.TrimSpace(k) {
		case "LAN":
			c.LAN = strings.TrimSpace(v)
		case "HOST_IP":
			c.HostIP = strings.TrimSpace(v)
		case "HOST_TCP_LAN":
			c.HostTCPLAN = splitPorts(v)
		case "HOST_UDP_LAN":
			c.HostUDPLAN = splitPorts(v)
		case "DOCKER_DROP_LAN":
			c.DockerDropLAN = splitPorts(v)
		case "V6_DROP":
			c.V6Drop = splitPorts(v)
		}
	}
	return c, sc.Err()
}

func splitPorts(v string) []string {
	out := []string{}
	for _, p := range strings.Split(v, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// SaveConfig validates and atomically writes allowlist.conf.
func (m *Manager) SaveConfig(c Config) error {
	if err := validate(c); err != nil {
		return err
	}
	var b strings.Builder
	b.WriteString("# ZFW Allowlist — managed by the zfw module UI.\n")
	b.WriteString("# Hand edits are fine; the UI rewrites this file on save.\n\n")
	fmt.Fprintf(&b, "LAN=%s\n", c.LAN)
	fmt.Fprintf(&b, "HOST_IP=%s\n", c.HostIP)
	fmt.Fprintf(&b, "HOST_TCP_LAN=%s\n", strings.Join(c.HostTCPLAN, ","))
	fmt.Fprintf(&b, "HOST_UDP_LAN=%s\n", strings.Join(c.HostUDPLAN, ","))
	fmt.Fprintf(&b, "DOCKER_DROP_LAN=%s\n", strings.Join(c.DockerDropLAN, ","))
	fmt.Fprintf(&b, "V6_DROP=%s\n", strings.Join(c.V6Drop, ","))
	tmp := m.Conf + ".tmp"
	if err := os.WriteFile(tmp, []byte(b.String()), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, m.Conf)
}

// validate rejects anything that could corrupt the conf or the iptables rules.
func validate(c Config) error {
	// Both values land in IPv4-only iptables chains — an IPv6 value
	// would abort the apply mid-script (set -eu). Require IPv4.
	_, ipnet, err := net.ParseCIDR(c.LAN)
	if err != nil || ipnet.IP.To4() == nil {
		return fmt.Errorf("LAN must be an IPv4 CIDR (e.g. 192.168.1.0/24)")
	}
	if ip := net.ParseIP(c.HostIP); ip == nil || ip.To4() == nil {
		return fmt.Errorf("HOST_IP must be an IPv4 address")
	}
	for _, set := range [][]string{c.HostTCPLAN, c.HostUDPLAN, c.DockerDropLAN, c.V6Drop} {
		for _, p := range set {
			n, err := strconv.Atoi(p)
			if err != nil || n < 1 || n > 65535 {
				return fmt.Errorf("invalid port %q (1-65535 allowed)", p)
			}
		}
	}
	return nil
}

// engine runs the engine script with the given verb after re-checking that it
// is still safe to execute as root. Every exec of m.Bin goes through here:
// the ZFW-S8 guard is a property of running that file as root, not of the
// "apply" verb, and Commit/Revert exec exactly the same file with exactly the
// same privileges. Checking only in Apply left the guard trivially bypassable
// — an actor able to write under /DATA (a container with the usual /DATA bind
// mount) could swap the engine for their own script, watch Apply refuse it,
// and have it run as root the moment the operator clicked Confirm or Revert.
func (m *Manager) engine(ctx context.Context, args ...string) (string, error) {
	if err := secureRootFile(m.Bin); err != nil {
		return "", fmt.Errorf("engine script unsafe: %w", err)
	}
	return runEngine(ctx, m.Bin, args...)
}

// Apply runs the engine. When safe is true a 120s dead-man auto-revert is armed.
func (m *Manager) Apply(ctx context.Context, safe bool) (string, error) {
	args := []string{"apply"}
	if safe {
		args = append(args, "--safe")
	}
	return m.engine(ctx, args...)
}

// secureRootFile verifies path is owned by root and not group/world-writable
// before it is executed with root privileges.
func secureRootFile(path string) error {
	fi, err := os.Stat(path)
	if err != nil {
		return err
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok && st.Uid != 0 {
		return fmt.Errorf("%s is not root-owned (uid=%d)", path, st.Uid)
	}
	if fi.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("%s is group/world-writable (%#o)", path, fi.Mode().Perm())
	}
	return nil
}

// Commit cancels an armed dead-man timer so the rules persist.
func (m *Manager) Commit(ctx context.Context) (string, error) {
	return m.engine(ctx, "commit")
}

// Revert removes all ZFW rules and restores the stock state.
func (m *Manager) Revert(ctx context.Context) (string, error) {
	return m.engine(ctx, "revert")
}
