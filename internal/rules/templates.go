package rules

// Template is a pre-built rule (or rule group) the user can drop into
// their rule set with one click. The catalog is curated, not editable;
// the daemon serves it under /api/rules/templates and the frontend
// renders it as a picker. Click "Add" → the embedded rules get appended
// to the local rule list (the user still has to Save + Safe-Apply).
//
// The Template.ID is a stable slug for the picker; the rules inside each
// Template get fresh NewID()s every time Templates(lan) is called, so a
// user adding the same template twice ends up with two independent rules
// — not two rules that collide on the same id during local edits.
type Template struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Category    string `json:"category"` // "security" or "service"
	Rules       []Rule `json:"rules"`
}

// lanSource resolves a template's "from the LAN" source against the
// host's current LAN CIDR. With no detected LAN it falls back to "any"
// — applyable but broader than intended; the user should narrow it
// before Safe-Apply.
func lanSource(lan string) Source {
	if lan == "" {
		return Source{Type: "any"}
	}
	return Source{Type: "range", Value: lan}
}

// Templates returns the catalog with lan substituted into rules that
// target the local network. The order of templates within the slice
// is the order the UI renders them — security wins first, convenience
// services after.
//
// Service-template port defaults follow the upstream image's docker-
// compose conventions (Mod-Store apps mostly publish on a fixed port
// per app — the user can edit ports after adding if they remap). Zone
// is "auto" for every Mod-Store app so the compiler can route the
// rule to ZFW-IN or DOCKER-USER live based on what's actually
// published, rather than asking the user to know which chain handles
// their container's port.
func Templates(lan string) []Template {
	// allow constructs an "allow from LAN" rule with fresh ID. Cuts the
	// boilerplate of the 8-field literal that otherwise dominates each
	// template body.
	allow := func(name, proto string, ports ...int) Rule {
		return Rule{
			ID:       NewID(),
			Enabled:  true,
			Name:     name,
			Action:   "allow",
			Source:   lanSource(lan),
			Ports:    Ports{Type: "list", List: ports},
			Protocol: proto,
			Zone:     "auto",
		}
	}
	return []Template{
		{
			ID:          "block-vnc-consoles",
			Name:        "Block VNC consoles (5900-5999)",
			Description: "Deny the full VNC TCP port range. ZimaOS VM consoles ship passwordless on 0.0.0.0 by default — this template closes that footgun on the LAN without enumerating 100 individual ports.",
			Category:    "security",
			Rules: []Rule{{
				ID:       NewID(),
				Enabled:  true,
				Name:     "Block VNC consoles",
				Action:   "deny",
				Source:   Source{Type: "any"},
				Ports:    Ports{Type: "range", From: 5900, To: 5999},
				Protocol: "tcp",
				Zone:     "host",
			}},
		},
		{
			ID:          "block-nfs-rpc",
			Name:        "Block NFS / rpcbind (111, 2049, 20048)",
			Description: "Deny the NFS + rpcbind stack on both TCP and UDP. NFS exposes file shares without authentication and rpcbind on port 111 is a well-known reflection/amplification vector and information-disclosure source.",
			Category:    "security",
			Rules: []Rule{
				{
					ID:       NewID(),
					Enabled:  true,
					Name:     "Block NFS / rpcbind (TCP)",
					Action:   "deny",
					Source:   Source{Type: "any"},
					Ports:    Ports{Type: "list", List: []int{111, 2049, 20048}},
					Protocol: "tcp",
					Zone:     "host",
				},
				{
					ID:       NewID(),
					Enabled:  true,
					Name:     "Block NFS / rpcbind (UDP)",
					Action:   "deny",
					Source:   Source{Type: "any"},
					Ports:    Ports{Type: "list", List: []int{111, 2049, 20048}},
					Protocol: "udp",
					Zone:     "host",
				},
			},
		},
		{
			ID:          "allow-plex",
			Name:        "Allow Plex Media Server (32400)",
			Description: "Allow Plex's TCP port from the LAN. Useful when Plex runs as a Docker app and the auto-detected starter set has not picked it up — e.g. because the container was stopped at install time.",
			Category:    "service",
			Rules:       []Rule{allow("Allow Plex", "tcp", 32400)},
		},
		{
			ID:          "allow-termina",
			Name:        "Allow Termina / ttyd (7681)",
			Description: "Allow the ZimaOS Termina web-terminal app (ttyd) on its default port. ZimaOS ships this as a stock Mod-Store entry; the rule opens it from the LAN so the dashboard tile is reachable from your other devices.",
			Category:    "service",
			Rules:       []Rule{allow("Allow Termina / ttyd", "tcp", 7681)},
		},
		{
			ID:          "allow-portainer",
			Name:        "Allow Portainer (9000, 9443)",
			Description: "Allow the Portainer container-management UI on both the HTTP (9000) and HTTPS (9443) defaults. Standard ZimaOS Mod-Store entry — drop this template in if you want to reach Portainer from anywhere on the LAN.",
			Category:    "service",
			Rules:       []Rule{allow("Allow Portainer", "tcp", 9000, 9443)},
		},
		{
			ID:          "allow-jellyfin",
			Name:        "Allow Jellyfin (8096, 8920, 7359/udp, 1900/udp)",
			Description: "Allow Jellyfin Media Server's HTTP (8096), HTTPS (8920), client auto-discovery (7359/udp) and DLNA (1900/udp) ports from the LAN. Covers both a stock Docker install and the ZimaOS Mod-Store entry.",
			Category:    "service",
			Rules: []Rule{
				allow("Allow Jellyfin (HTTP/HTTPS)", "tcp", 8096, 8920),
				allow("Allow Jellyfin (discovery)", "udp", 7359, 1900),
			},
		},
		{
			ID:          "allow-immich",
			Name:        "Allow Immich (2283)",
			Description: "Allow the Immich self-hosted photo & video backup app on its default web port. Stock ZimaOS Mod-Store entry — pair with Immich's mobile-app backup if you want LAN devices to reach it without a tunnel.",
			Category:    "service",
			Rules:       []Rule{allow("Allow Immich", "tcp", 2283)},
		},
		{
			ID:          "allow-home-assistant",
			Name:        "Allow Home Assistant (8123)",
			Description: "Allow Home Assistant's web UI on its default port from the LAN. Mod-Store staple — opens the dashboard to your phone / tablet on the same network without needing the HA Companion app via a tunnel.",
			Category:    "service",
			Rules:       []Rule{allow("Allow Home Assistant", "tcp", 8123)},
		},
		{
			ID:          "allow-adguard-home",
			Name:        "Allow AdGuard Home (3000 + 53)",
			Description: "Allow AdGuard Home's initial-setup port (3000) and DNS (53 TCP+UDP) from the LAN so client devices can resolve through it. Skip port 80 — that conflicts with the ZimaOS gateway by default. Keep AdGuard's admin on 3000 or pick a different port and edit the rule.",
			Category:    "service",
			Rules: []Rule{
				allow("Allow AdGuard (admin + DNS/TCP)", "tcp", 3000, 53),
				allow("Allow AdGuard (DNS/UDP)", "udp", 53),
			},
		},
		{
			ID:          "allow-vaultwarden",
			Name:        "Allow Vaultwarden (8222)",
			Description: "Allow the Vaultwarden self-hosted Bitwarden-compatible password manager on its conventional Docker-Compose port (8222). If you remapped the container, edit the rule's port list after adding.",
			Category:    "service",
			Rules:       []Rule{allow("Allow Vaultwarden", "tcp", 8222)},
		},
		{
			ID:          "allow-syncthing",
			Name:        "Allow Syncthing (8384 + 22000 + 21027/udp)",
			Description: "Allow Syncthing's web UI (8384), peer-sync TCP (22000), QUIC (22000/udp) and discovery broadcasts (21027/udp). Required for both LAN-pairing and ongoing peer sync.",
			Category:    "service",
			Rules: []Rule{
				allow("Allow Syncthing (UI + sync TCP)", "tcp", 8384, 22000),
				allow("Allow Syncthing (QUIC + discovery)", "udp", 22000, 21027),
			},
		},
		{
			ID:          "allow-nextcloud",
			Name:        "Allow Nextcloud (8080)",
			Description: "Allow Nextcloud's web UI on the Docker-AIO default port (8080). If your install uses a different port (Apache image on 80, custom remap, etc.), edit the rule's port list after adding.",
			Category:    "service",
			Rules:       []Rule{allow("Allow Nextcloud", "tcp", 8080)},
		},
		{
			ID:          "allow-photoprism",
			Name:        "Allow PhotoPrism (2342)",
			Description: "Allow the PhotoPrism AI-powered photo library on its default web port. Common ZimaOS Mod-Store entry.",
			Category:    "service",
			Rules:       []Rule{allow("Allow PhotoPrism", "tcp", 2342)},
		},
		{
			ID:          "allow-arr-suite",
			Name:        "Allow *arr suite (Sonarr / Radarr / Bazarr / Prowlarr)",
			Description: "Allow the four canonical media-management *arr apps on their default ports: Sonarr 8989, Radarr 7878, Bazarr 6767, Prowlarr 9696. One template add covers a typical homelab automation stack.",
			Category:    "service",
			Rules:       []Rule{allow("Allow *arr suite", "tcp", 8989, 7878, 6767, 9696)},
		},
		{
			ID:          "allow-qbittorrent",
			Name:        "Allow qBittorrent (8080)",
			Description: "Allow the qBittorrent web UI on its canonical default port. NOTE: 8080 also defaults for Nextcloud AIO — if both apps run on the same host you'll need to remap one (qBittorrent supports `-c` or env-var override).",
			Category:    "service",
			Rules:       []Rule{allow("Allow qBittorrent", "tcp", 8080)},
		},
	}
}
