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

// New returns a Manager, preferring the iptables-legacy backend if present
// (Docker/libvirt/Tailscale all use legacy on ZimaOS).
func New(bin, conf string) *Manager {
	pick := func(legacy, std string) string {
		if _, err := exec.LookPath(legacy); err == nil {
			return legacy
		}
		return std
	}
	return &Manager{
		Bin:    bin,
		Conf:   conf,
		iptBin: pick("iptables-legacy", "iptables"),
		ipt6:   pick("ip6tables-legacy", "ip6tables"),
	}
}

func run(ctx context.Context, name string, args ...string) (string, error) {
	cctx, cancel := context.WithTimeout(ctx, 25*time.Second)
	defer cancel()
	out, err := exec.CommandContext(cctx, name, args...).CombinedOutput()
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
	if out, err := run(ctx, m.ipt6, "-S", "ZFW-IN6"); err == nil && strings.Contains(out, "-A ZFW-IN6") {
		s.IPv6Active = true
	}
	if out, _ := run(ctx, "systemctl", "is-active", "zfw-deadman.timer"); strings.TrimSpace(out) == "active" {
		s.Deadman = true
	}
	if out, _ := run(ctx, "systemctl", "is-enabled", "zfw.service"); strings.TrimSpace(out) == "enabled" {
		s.ServiceEnabled = true
	}
	return s
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

// Apply runs the engine. When safe is true a 120s dead-man auto-revert is armed.
func (m *Manager) Apply(ctx context.Context, safe bool) (string, error) {
	// The engine script is executed as root — refuse to run it unless it is
	// owned by root and not group/world-writable (ZFW-S8).
	if err := secureRootFile(m.Bin); err != nil {
		return "", fmt.Errorf("engine script unsafe: %w", err)
	}
	args := []string{"apply"}
	if safe {
		args = append(args, "--safe")
	}
	return run(ctx, m.Bin, args...)
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
	return run(ctx, m.Bin, "commit")
}

// Revert removes all ZFW rules and restores the stock state.
func (m *Manager) Revert(ctx context.Context) (string, error) {
	return run(ctx, m.Bin, "revert")
}
