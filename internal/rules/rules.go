// Package rules defines the zfw firewall rule model and its persistence.
// A RuleSet is the single source of truth (rules.json); the compiler turns
// it into the iptables script the engine applies.
package rules

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
)

// Source is a rule's traffic source.
type Source struct {
	Type  string `json:"type"`  // any | ip | range
	Value string `json:"value"` // ip address, or CIDR for range
}

// Ports is a rule's destination port set.
//
// Type semantics:
//   - "all":   every port (compiler emits no --dport clause)
//   - "list":  the ports in List (compiler emits -m multiport --dports …)
//   - "range": the half-open span [From,To] inclusive (compiler emits
//     --dport From:To). Useful for VNC 5900-5999 etc. without
//     enumerating 100 individual entries.
type Ports struct {
	Type string `json:"type"`
	List []int  `json:"list"`
	From int    `json:"from,omitempty"`
	To   int    `json:"to,omitempty"`
}

// Rule is one ordered firewall rule.
type Rule struct {
	ID       string `json:"id"`
	Order    int    `json:"order"`
	Enabled  bool   `json:"enabled"`
	Name     string `json:"name"`
	Action   string `json:"action"` // allow | deny
	Source   Source `json:"source"`
	Ports    Ports  `json:"ports"`
	Protocol string `json:"protocol"` // tcp | udp | both
	Zone     string `json:"zone"`     // auto | host | docker
}

// RuleSet is the whole firewall configuration.
type RuleSet struct {
	LAN           string `json:"lan"`
	HostIP        string `json:"host_ip"`
	DefaultPolicy string `json:"default_policy"` // deny | allow
	V6Drop        []int  `json:"v6_drop"`
	Rules         []Rule `json:"rules"`
}

// NewID returns a short random rule id.
func NewID() string {
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		return "r00000000"
	}
	return fmt.Sprintf("r%x", b)
}

// Defaults returns a starter rule set built from a live system inventory.
// The hard-coded baseline covers ZimaOS host infrastructure the user almost
// certainly needs reachable on the LAN (web UI, SSH, Samba shares, mDNS
// discovery). One additional allow-rule is generated per live
// Docker-published port so containers the user is already running are not
// silently killed when the defaults are applied. The default-deny policy
// blocks everything else — closing the LAN footguns flagged by the audit
// (VM VNC without password, NFS/RPC, ttyd, etc.) by construction.
//
// dockerPorts may be nil; in that case only the baseline is returned. The
// caller passes the result of system.DockerPorts(ctx) — the inventory must
// be live, not cached, so a stopped container does not leave a stale rule
// pinned in the starter set.
func Defaults(lan, hostIP string, dockerPorts map[int]bool) RuleSet {
	src := Source{Type: "range", Value: lan}
	mk := func(order int, name, action, proto, zone string, ports ...int) Rule {
		return Rule{
			ID:       NewID(),
			Order:    order,
			Enabled:  true,
			Name:     name,
			Action:   action,
			Source:   src,
			Ports:    Ports{Type: "list", List: ports},
			Protocol: proto,
			Zone:     zone,
		}
	}
	rs := []Rule{
		mk(10, "ZimaOS Web UI", "allow", "tcp", "host", 80, 443),
		mk(20, "SSH (admin)", "allow", "tcp", "host", 22),
		mk(30, "Samba file sharing (TCP)", "allow", "tcp", "host", 139, 445),
		mk(40, "Samba file sharing (UDP)", "allow", "udp", "host", 137, 138),
		mk(50, "mDNS discovery", "allow", "udp", "host", 5353),
	}
	// Live Docker-published ports — sorted so the rule list is deterministic.
	ports := make([]int, 0, len(dockerPorts))
	for p := range dockerPorts {
		ports = append(ports, p)
	}
	sort.Ints(ports)
	order := 60
	for _, p := range ports {
		rs = append(rs, mk(order, fmt.Sprintf("Docker app on :%d", p), "allow", "tcp", "docker", p))
		order += 10
	}
	return RuleSet{
		LAN:           lan,
		HostIP:        hostIP,
		DefaultPolicy: "deny",
		Rules:         rs,
	}
}

// Load reads and parses rules.json.
func Load(path string) (RuleSet, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return RuleSet{}, err
	}
	var rs RuleSet
	if err := json.Unmarshal(b, &rs); err != nil {
		return RuleSet{}, err
	}
	return rs, nil
}

// Save validates nothing but assigns missing ids and writes rules.json atomically.
func Save(path string, rs RuleSet) error {
	for i := range rs.Rules {
		if rs.Rules[i].ID == "" {
			rs.Rules[i].ID = NewID()
		}
	}
	b, err := json.MarshalIndent(rs, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// Size caps keep a crafted rules.json from compiling into an oversized
// root-run script or fanning out into excessive geo downloads (ZFW-S4).
const (
	maxRules         = 256
	maxPortsPerRule  = 128
	maxV6DropPorts   = 128
	maxRuleCountries = 32
)

// Validate rejects anything that could corrupt the compiled ruleset.
func Validate(rs RuleSet) error {
	if rs.DefaultPolicy != "deny" && rs.DefaultPolicy != "allow" {
		return fmt.Errorf("default_policy must be deny or allow")
	}
	if len(rs.Rules) > maxRules {
		return fmt.Errorf("too many rules: %d (max %d)", len(rs.Rules), maxRules)
	}
	if len(rs.V6Drop) > maxV6DropPorts {
		return fmt.Errorf("too many v6_drop ports: %d (max %d)", len(rs.V6Drop), maxV6DropPorts)
	}
	if rs.LAN != "" {
		if _, _, err := net.ParseCIDR(rs.LAN); err != nil {
			return fmt.Errorf("lan must be a CIDR (e.g. 192.168.1.0/24)")
		}
	}
	if rs.HostIP != "" && net.ParseIP(rs.HostIP) == nil {
		return fmt.Errorf("host_ip must be an IP address")
	}
	for _, p := range rs.V6Drop {
		if p < 1 || p > 65535 {
			return fmt.Errorf("v6_drop: invalid port %d", p)
		}
	}
	for _, r := range rs.Rules {
		if err := validateRule(r); err != nil {
			return fmt.Errorf("rule %q: %w", r.Name, err)
		}
	}
	return nil
}

// SplitCountries parses a comma-separated ISO-3166 country-code list.
func SplitCountries(v string) []string {
	var out []string
	for _, c := range strings.Split(v, ",") {
		if c = strings.TrimSpace(c); c != "" {
			out = append(out, c)
		}
	}
	return out
}

func isAlpha(s string) bool {
	for _, r := range s {
		if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') {
			return false
		}
	}
	return s != ""
}

func validateRule(r Rule) error {
	if r.Name == "" {
		return fmt.Errorf("name is required")
	}
	if r.Action != "allow" && r.Action != "deny" {
		return fmt.Errorf("action must be allow or deny")
	}
	switch r.Source.Type {
	case "any":
	case "ip":
		if net.ParseIP(r.Source.Value) == nil {
			return fmt.Errorf("source IP is invalid")
		}
	case "range":
		if _, _, err := net.ParseCIDR(r.Source.Value); err != nil {
			return fmt.Errorf("source range must be a CIDR")
		}
	case "country":
		codes := SplitCountries(r.Source.Value)
		if len(codes) == 0 {
			return fmt.Errorf("no country specified")
		}
		if len(codes) > maxRuleCountries {
			return fmt.Errorf("too many countries: %d (max %d)", len(codes), maxRuleCountries)
		}
		for _, c := range codes {
			if len(c) != 2 || !isAlpha(c) {
				return fmt.Errorf("country code %q is invalid (ISO-3166 alpha-2, e.g. DE)", c)
			}
		}
	default:
		return fmt.Errorf("source.type is invalid")
	}
	switch r.Ports.Type {
	case "all":
	case "list":
		if len(r.Ports.List) == 0 {
			return fmt.Errorf("ports list is empty")
		}
		if len(r.Ports.List) > maxPortsPerRule {
			return fmt.Errorf("too many ports: %d (max %d)", len(r.Ports.List), maxPortsPerRule)
		}
		for _, p := range r.Ports.List {
			if p < 1 || p > 65535 {
				return fmt.Errorf("invalid port %d", p)
			}
		}
	case "range":
		if r.Ports.From < 1 || r.Ports.From > 65535 {
			return fmt.Errorf("port range: from %d out of 1-65535", r.Ports.From)
		}
		if r.Ports.To < 1 || r.Ports.To > 65535 {
			return fmt.Errorf("port range: to %d out of 1-65535", r.Ports.To)
		}
		if r.Ports.From > r.Ports.To {
			return fmt.Errorf("port range: from (%d) > to (%d)", r.Ports.From, r.Ports.To)
		}
	default:
		return fmt.Errorf("ports.type is invalid")
	}
	if r.Protocol != "tcp" && r.Protocol != "udp" && r.Protocol != "both" {
		return fmt.Errorf("protocol must be tcp, udp or both")
	}
	if r.Zone != "auto" && r.Zone != "host" && r.Zone != "docker" {
		return fmt.Errorf("zone must be auto, host or docker")
	}
	return nil
}
