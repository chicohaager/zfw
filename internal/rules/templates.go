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
func Templates(lan string) []Template {
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
			Rules: []Rule{{
				ID:       NewID(),
				Enabled:  true,
				Name:     "Allow Plex",
				Action:   "allow",
				Source:   lanSource(lan),
				Ports:    Ports{Type: "list", List: []int{32400}},
				Protocol: "tcp",
				Zone:     "auto",
			}},
		},
	}
}
