package rules

import "github.com/chicohaager/zfw/internal/firewall"

// FromTiers builds a RuleSet equivalent to the legacy v0.1 allowlist.conf, so
// upgrading to the rule model never changes the live firewall behaviour.
//
// dockerListening is the set of currently Docker-published TCP ports. The
// migration creates an allow rule for all of them except those on the legacy
// drop list — so no app the user relies on loses LAN reachability when the
// default policy flips to deny.
func FromTiers(cfg firewall.Config, dockerListening []int) RuleSet {
	rs := RuleSet{
		LAN:           cfg.LAN,
		HostIP:        cfg.HostIP,
		DefaultPolicy: "deny",
		V6Drop:        atoiList(cfg.V6Drop),
	}

	drop := map[int]bool{}
	for _, p := range atoiList(cfg.DockerDropLAN) {
		drop[p] = true
	}
	var dockerAllow []int
	for _, p := range dockerListening {
		if !drop[p] {
			dockerAllow = append(dockerAllow, p)
		}
	}

	src := Source{Type: "any"}
	if cfg.LAN != "" {
		src = Source{Type: "range", Value: cfg.LAN}
	}
	order := 10
	add := func(name, proto, zone string, ports []int) {
		if len(ports) == 0 {
			return
		}
		rs.Rules = append(rs.Rules, Rule{
			ID: NewID(), Order: order, Enabled: true, Name: name, Action: "allow",
			Source:   src,
			Ports:    Ports{Type: "list", List: ports},
			Protocol: proto, Zone: zone,
		})
		order += 10
	}
	add("Host TCP ports (migrated)", "tcp", "host", atoiList(cfg.HostTCPLAN))
	add("Host UDP ports (migrated)", "udp", "host", atoiList(cfg.HostUDPLAN))
	add("Docker apps (migrated)", "tcp", "docker", dockerAllow)
	return rs
}

func atoiList(ss []string) []int {
	var out []int
	for _, s := range ss {
		n, ok := 0, len(s) > 0
		for _, c := range s {
			if c < '0' || c > '9' {
				ok = false
				break
			}
			n = n*10 + int(c-'0')
		}
		if ok {
			out = append(out, n)
		}
	}
	return out
}
