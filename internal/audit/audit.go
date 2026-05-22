// Package audit exposes the findings of the 2026-05-21 security audit as a
// live traffic-light: each finding's status is recomputed against the
// current firewall configuration.
package audit

import "github.com/chicohaager/zfw/internal/firewall"

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

// Findings recomputes the catalog against the current firewall state.
// "mitigated" = the LAN path is closed but the underlying config still
// needs hardening; "fixed" = fully resolved; "open" = untouched.
func Findings(st firewall.Status, cfg firewall.Config) []Finding {
	// A host-native port is LAN-blocked when the firewall is active and the
	// port is not on the host allowlist (default-drop closes it).
	hostBlocked := func(port string) string {
		if st.Active && !contains(cfg.HostTCPLAN, port) {
			return "mitigated"
		}
		return "open"
	}
	// A Docker-published port is LAN-blocked when it is on the drop list.
	dockerBlocked := func(port string) string {
		if st.Active && contains(cfg.DockerDropLAN, port) {
			return "mitigated"
		}
		return "open"
	}
	m1 := "open"
	if st.Active {
		m1 = "fixed"
	}

	return []Finding{
		{"M1", "MED", "Keine Host-Firewall", "ZimaOS bringt keinen Paketfilter mit — behoben durch ZFW.", m1},
		{"H1", "HIGH", "zimaos-mcp: privilegiert & auth-los", "MCP-API :8717, Container privileged+host-net+docker.sock → LAN-Pfad zu Host-Root.", hostBlocked("8717")},
		{"H2", "HIGH", "xpkg-desktop: Remote-Desktop ohne Auth", "noVNC :15800/:15900, WEB_AUTHENTICATION=0, VNC-Passwort leer.", dockerBlocked("15800")},
		{"H3", "HIGH", "ZVM-VNC ohne Passwort", "qemu-Konsole :5900/:5700 ohne passwd — IceWhale-Disclosure läuft.", hostBlocked("5900")},
		{"H4", "HIGH", "SSH-Root-Login offen", "PermitRootLogin yes + Passwort-Auth + root hat Passwort. sshd_config-Fix nötig.", "open"},
		{"M2", "MED", "dozzle ohne Authentifizierung", ":8888 ohne Auth + docker.sock → alle Container-Logs LAN-weit lesbar.", dockerBlocked("8888")},
		{"M3", "MED", "Docker-Apps umgehen das Gateway", "~12 Apps publishen direkt auf 0.0.0.0 statt über die Gateway-Route.", "open"},
		{"M4", "MED", "Veraltete Container-Images", "postgres:14.2 (~4 J, EOL); viele :latest-Tags.", "open"},
		{"M5", "MED", "Kernel-CVE 2026-31431", "Kernel 6.12.25 — lokaler Root; nur per ZimaOS-Firmware-Update patchbar.", "open"},
		{"M6", "MED", "NFS/RPC LAN-exponiert", "nfsd :2049 + rpcbind :111 offen, aber ohne Exports.", hostBlocked("2049")},
		{"M7", "MED", "Docker Engine 27.5.1", "< 29.3.1 → docker cp-Host-Root-Escapes konditionell anwendbar.", "open"},
		{"M8", "MED", "SSH-Passwort-Auth + Vollzugriff-sudo", "PasswordAuthentication yes; Maintainer (ALL:ALL) ALL → SSH-PW = Root.", "open"},
		{"L1", "LOW", "ttyd-Web-Terminal LAN-offen", ":7681 login-gated, aber brute-forcebar, kein Rate-Limit.", hostBlocked("7681")},
		{"L2", "LOW", "zima-cron-watchdog failed", "Watchdog sucht zima-cron.service (existiert nicht; Unit heißt cron.service).", "open"},
		{"L3", "LOW", "/DATA-Shares 0777", "AppData/Backup/Documents u. a. world-writable.", "open"},
		{"L4", "LOW", "rclone rcd --rc-no-auth", "Nur Unix-Socket, nicht LAN-exponiert — Risiko niedrig.", "open"},
		{"L5", "LOW", "/var/run/casaos world-readable", "Caddyfile + message-bus.db mode 644 — kleiner Info-Leak.", "open"},
	}
}
