// Package audit exposes the findings of the 2026-05-21 security audit as a
// live traffic-light: each finding's status is recomputed against the
// current firewall configuration.
package audit

import (
	"strconv"

	"github.com/chicohaager/zfw/internal/firewall"
)

// Finding is one audit item with a live status.
type Finding struct {
	ID     string `json:"id"`
	Sev    string `json:"sev"` // HIGH | MED | LOW
	Title  string `json:"title"`
	Detail string `json:"detail"`
	Status string `json:"status"` // open | mitigated | fixed
}

func contains(set []string, port string) bool {
	for _, p := range set {
		if p == port {
			return true
		}
	}
	return false
}

// PortPolicy answers whether a TCP port is reachable from the LAN once the
// firewall is active. The rule model (rules.json) is the production
// implementation; the legacy allowlist.conf adapter below is kept for the
// migration path and for tests that build a Config by hand.
type PortPolicy interface {
	HostOpen(port int) bool   // a host-native listener on port is reachable
	DockerOpen(port int) bool // a Docker-published port is reachable
}

// configPolicy adapts the legacy v0.1 tier config: host ports are open only
// when listed, docker ports are closed only when listed.
type configPolicy struct{ cfg firewall.Config }

func (p configPolicy) HostOpen(port int) bool {
	return contains(p.cfg.HostTCPLAN, strconv.Itoa(port))
}

func (p configPolicy) DockerOpen(port int) bool {
	return !contains(p.cfg.DockerDropLAN, strconv.Itoa(port))
}

// Findings recomputes the catalog against the current firewall state, judged
// by the legacy allowlist.conf tiers. Production callers use FindingsWith
// and a rules.json-backed policy — see PortPolicy.
func Findings(st firewall.Status, cfg firewall.Config) []Finding {
	return FindingsWith(st, configPolicy{cfg})
}

// FindingsWith recomputes the catalog against the current firewall state.
// "mitigated" = the LAN path is closed but the underlying config still
// needs hardening; "fixed" = fully resolved; "open" = untouched.
func FindingsWith(st firewall.Status, pol PortPolicy) []Finding {
	// A host-native port is LAN-blocked when the firewall is active and no
	// rule lets it through (default-drop closes it).
	hostBlocked := func(port string) string {
		if n, err := strconv.Atoi(port); err == nil && st.Active && !pol.HostOpen(n) {
			return "mitigated"
		}
		return "open"
	}
	// A Docker-published port is LAN-blocked when the rules deny it.
	dockerBlocked := func(port string) string {
		if n, err := strconv.Atoi(port); err == nil && st.Active && !pol.DockerOpen(n) {
			return "mitigated"
		}
		return "open"
	}
	m1 := "open"
	if st.Active {
		m1 = "fixed"
	}

	return []Finding{
		{"M1", "MED", "No host firewall", "ZimaOS ships without a packet filter — resolved by ZFW.", m1},
		{"H1", "HIGH", "zimaos-mcp: privileged & no auth", "MCP API :8717, container privileged+host-net+docker.sock → LAN path to host root.", hostBlocked("8717")},
		{"H2", "HIGH", "xpkg-desktop: remote desktop without auth", "noVNC :15800/:15900, WEB_AUTHENTICATION=0, empty VNC password.", dockerBlocked("15800")},
		{"H3", "HIGH", "ZVM VNC without password", "qemu console :5900/:5700 with no passwd — IceWhale disclosure in progress.", hostBlocked("5900")},
		{"H4", "HIGH", "SSH root login open", "PermitRootLogin yes + password auth + root has a password. sshd_config fix required.", "open"},
		{"M2", "MED", "dozzle without authentication", ":8888 no auth + docker.sock → all container logs readable LAN-wide.", dockerBlocked("8888")},
		{"M3", "MED", "Docker apps bypass the gateway", "~12 apps publish directly on 0.0.0.0 instead of via the gateway route.", "open"},
		{"M4", "MED", "Outdated container images", "postgres:14.2 (~4y, EOL); many :latest tags.", "open"},
		{"M5", "MED", "Kernel CVE 2026-31431", "Kernel 6.12.25 — local root; patchable only via a ZimaOS firmware update.", "open"},
		{"M6", "MED", "NFS/RPC LAN-exposed", "nfsd :2049 + rpcbind :111 open, but no exports configured.", hostBlocked("2049")},
		{"M7", "MED", "Docker Engine 27.5.1", "< 29.3.1 → docker cp host-root escapes conditionally applicable.", "open"},
		{"M8", "MED", "SSH password auth + full sudo", "PasswordAuthentication yes; the admin user holds full sudo (ALL:ALL) → SSH password = root.", "open"},
		{"L1", "LOW", "ttyd web terminal LAN-open", ":7681 login-gated but brute-forceable, no rate limit.", hostBlocked("7681")},
		{"L2", "LOW", "zima-cron-watchdog failed", "Watchdog looks for zima-cron.service (does not exist; unit is named cron.service).", "open"},
		{"L3", "LOW", "/DATA shares 0777", "AppData/Backup/Documents and others are world-writable.", "open"},
		{"L4", "LOW", "rclone rcd --rc-no-auth", "Unix socket only, not LAN-exposed — low risk.", "open"},
		{"L5", "LOW", "/var/run/casaos world-readable", "Caddyfile + message-bus.db mode 644 — minor info leak.", "open"},
	}
}
