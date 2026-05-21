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
	"strings"
)

// Source is a rule's traffic source.
type Source struct {
	Type  string `json:"type"`  // any | ip | range
	Value string `json:"value"` // ip address, or CIDR for range
}

// Ports is a rule's destination port set.
type Ports struct {
	Type string `json:"type"` // all | list
	List []int  `json:"list"`
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
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// Validate rejects anything that could corrupt the compiled ruleset.
func Validate(rs RuleSet) error {
	if rs.DefaultPolicy != "deny" && rs.DefaultPolicy != "allow" {
		return fmt.Errorf("default_policy muss deny oder allow sein")
	}
	if rs.LAN != "" {
		if _, _, err := net.ParseCIDR(rs.LAN); err != nil {
			return fmt.Errorf("lan muss ein CIDR sein (z. B. 192.168.1.0/24)")
		}
	}
	if rs.HostIP != "" && net.ParseIP(rs.HostIP) == nil {
		return fmt.Errorf("host_ip muss eine IP-Adresse sein")
	}
	for _, p := range rs.V6Drop {
		if p < 1 || p > 65535 {
			return fmt.Errorf("v6_drop: ungültiger Port %d", p)
		}
	}
	for _, r := range rs.Rules {
		if err := validateRule(r); err != nil {
			return fmt.Errorf("Regel %q: %w", r.Name, err)
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
		return fmt.Errorf("Name fehlt")
	}
	if r.Action != "allow" && r.Action != "deny" {
		return fmt.Errorf("action muss allow oder deny sein")
	}
	switch r.Source.Type {
	case "any":
	case "ip":
		if net.ParseIP(r.Source.Value) == nil {
			return fmt.Errorf("source-IP ungültig")
		}
	case "range":
		if _, _, err := net.ParseCIDR(r.Source.Value); err != nil {
			return fmt.Errorf("source-range muss ein CIDR sein")
		}
	case "country":
		codes := SplitCountries(r.Source.Value)
		if len(codes) == 0 {
			return fmt.Errorf("kein Land angegeben")
		}
		for _, c := range codes {
			if len(c) != 2 || !isAlpha(c) {
				return fmt.Errorf("Ländercode %q ungültig (ISO-3166 alpha-2, z. B. DE)", c)
			}
		}
	default:
		return fmt.Errorf("source.type ungültig")
	}
	switch r.Ports.Type {
	case "all":
	case "list":
		if len(r.Ports.List) == 0 {
			return fmt.Errorf("Ports-Liste ist leer")
		}
		for _, p := range r.Ports.List {
			if p < 1 || p > 65535 {
				return fmt.Errorf("ungültiger Port %d", p)
			}
		}
	default:
		return fmt.Errorf("ports.type ungültig")
	}
	if r.Protocol != "tcp" && r.Protocol != "udp" && r.Protocol != "both" {
		return fmt.Errorf("protocol muss tcp, udp oder both sein")
	}
	if r.Zone != "auto" && r.Zone != "host" && r.Zone != "docker" {
		return fmt.Errorf("zone muss auto, host oder docker sein")
	}
	return nil
}
