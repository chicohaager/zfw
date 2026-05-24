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
	"strconv"
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
	// Notes is free-text the user writes to explain why this rule exists
	// ("M.s_PC, allow temporarily for testing"). Persisted in rules.json,
	// rendered as a tooltip + below-row caption in the UI, never read by
	// the compiler. Length-capped by Validate so an oversize note can't
	// bloat rules.json or the embedded UI payload.
	Notes string `json:"notes,omitempty"`
	// Schedule restricts when the rule is active. Pointer + omitempty
	// so an unscoped rule stays compact on the wire — nil means
	// "always-on", which is the historical default. The compiler emits
	// an `-m time --timestart … --timestop … --weekdays … --kerneltz`
	// clause when a Schedule is present. Introduced in schema v2.
	Schedule *Schedule `json:"schedule,omitempty"`
	// Log toggles per-rule iptables LOG emission so the user can
	// sanity-check a specific rule by watching its hits in the Events
	// tab. Compiler emits a non-terminating `-j LOG --log-prefix
	// "ZFW-RULE-<id> "` line in front of the rule's action line; the
	// match still falls through to the action. omitempty so the
	// default (no per-rule logging) stays compact on the wire.
	// Field-additive; no schema bump.
	Log bool `json:"log,omitempty"`
	// RateLimit caps how many new connections the rule will pass from
	// a given source within a sliding window. Compiler emits two
	// `-m recent` lines (one to set, one to drop above threshold) in
	// front of the action line. Off when nil. Field-additive; no
	// schema bump.
	RateLimit *RateLimit `json:"rate_limit,omitempty"`
	// Direction routes the rule to the OUTPUT/FORWARD side (outbound)
	// instead of INPUT/DOCKER-USER (inbound, the historical default).
	// Empty / "inbound" → emit on ZFW-IN, ZFW-IN6, DOCKER-USER.
	// "outbound" → emit on ZFW-OUT (zone host|auto) and/or
	// ZFW-FWD-OUT (zone docker|auto), plus ZFW-OUT6 for IPv6
	// sources. The Source field's semantic flips: in outbound rules
	// it is the *peer* (remote host the container/process tries to
	// reach) and the compiler emits `-d` instead of `-s`. Introduced
	// in schema v3.
	Direction string `json:"direction,omitempty"`
	// ContainerID (v0.5.7) optionally binds the rule to a Docker
	// container by its short ID or name. At Recompile time the daemon
	// looks up the container in the live inventory and substitutes
	// its current host-published ports into the rule, so a rule
	// follows its container across restarts and port remaps. Empty
	// disables binding (the rule's Ports field is used directly).
	// Field-additive; no schema bump.
	ContainerID string `json:"container_id,omitempty"`
}

// RateLimit is the per-rule connection-rate cap. At most Conn new
// connections from one source within Seconds seconds are allowed; the
// rest hit a DROP. Implemented via iptables `-m recent` (xt_recent —
// available on stock kernels; the engine modprobes it before apply).
type RateLimit struct {
	Conn    int `json:"conn"`    // max connections in window
	Seconds int `json:"seconds"` // window length
}

// Schedule restricts when a rule is active. From and To are wall-clock
// HH:MM in the host's kernel time zone. Days lists the lowercase
// 3-letter weekday names the rule fires on; an empty Days slice means
// every day. From > To is allowed and wraps midnight (e.g. 22:00 → 06:00
// for an overnight window).
type Schedule struct {
	From string   `json:"from"`           // HH:MM
	To   string   `json:"to"`             // HH:MM
	Days []string `json:"days,omitempty"` // mon, tue, wed, thu, fri, sat, sun
}

// RuleSet is the whole firewall configuration.
//
// Schema versioning: Version is the on-disk schema. Save() always stamps
// it to CurrentSchema; Load() runs migrate() on read. A rules.json with
// no version field parses to Version=0 and is upgraded transparently.
// A rules.json from a *newer* daemon (Version > CurrentSchema) is
// refused with a clear error rather than silently dropping fields. The
// migration plumbing is in place even though the schema has not yet
// changed — keeping future bumps a backwards-compatible single-line
// add ("case 1: rs.Version = 2; rs.X = default").
type RuleSet struct {
	Version       int    `json:"version,omitempty"`
	LAN           string `json:"lan"`
	HostIP        string `json:"host_ip"`
	DefaultPolicy string `json:"default_policy"` // deny | allow
	V6Drop        []int  `json:"v6_drop"`
	Rules         []Rule `json:"rules"`
}

// CurrentSchema is the rules.json schema version this build emits.
//
//	v1 — initial explicit-version schema (v0.3.8 — field-compatible
//	     rename from the unversioned format).
//	v2 — adds optional Rule.Schedule for time-window rules (v0.4.3 —
//	     first real use of the migrate() plumbing).
//	v3 — adds optional Rule.Direction for outbound rules on OUTPUT /
//	     FORWARD chains (v0.5.6 — second use of the migrate plumbing,
//	     still field-additive so v2 files round-trip with only the
//	     version stamp updated).
const CurrentSchema = 3

// migrate brings an on-disk RuleSet up to CurrentSchema, one step at a time.
// Returns (migrated, changed, err). A nil error with changed=false means the
// input was already current; a non-nil error means the input was from a
// future schema or hit an unknown step. The chain is intentionally a
// switch-on-source-version (not a table) so each migration step lives next
// to the schema change it accompanies.
func migrate(rs RuleSet) (RuleSet, bool, error) {
	if rs.Version > CurrentSchema {
		return rs, false, fmt.Errorf("rules.json schema v%d is newer than this daemon (max v%d) — refusing to load to avoid silent field loss", rs.Version, CurrentSchema)
	}
	if rs.Version == CurrentSchema {
		return rs, false, nil
	}
	for rs.Version < CurrentSchema {
		switch rs.Version {
		case 0:
			// Legacy / unversioned rules.json (everything shipped before
			// v0.3.8). v0 → v1 is a field-compatible rename: no struct
			// changes, just stamp the version so future bumps land cleanly.
			rs.Version = 1
		case 1:
			// v1 → v2 (v0.4.3): adds optional Rule.Schedule for time-
			// window rules. The new field is omitempty + pointer, so a
			// v1 rules.json with no schedule field reads back identical
			// — only the version stamp changes. The .bak.v1 file Load()
			// preserves still loads cleanly in this build via the same
			// migration path.
			rs.Version = 2
		case 2:
			// v2 → v3 (v0.5.6): adds optional Rule.Direction for
			// outbound rules on OUTPUT / FORWARD. Field-additive
			// (omitempty string defaulting to "inbound"), so v2 files
			// round-trip with only the version stamp updated.
			rs.Version = 3
		default:
			return rs, false, fmt.Errorf("no migration from rules.json schema v%d", rs.Version)
		}
	}
	return rs, true, nil
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

// Load reads and parses rules.json, migrating the schema in place if the
// file is from an older daemon. When a migration runs, the pre-migration
// bytes are preserved as <path>.bak.v<sourceVersion> before the upgraded
// form is written back — so a user always has a path back even if a future
// migration step turns out to be wrong.
func Load(path string) (RuleSet, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return RuleSet{}, err
	}
	var rs RuleSet
	if err := json.Unmarshal(b, &rs); err != nil {
		return RuleSet{}, err
	}
	sourceVersion := rs.Version
	migrated, changed, err := migrate(rs)
	if err != nil {
		return RuleSet{}, err
	}
	if changed {
		bak := fmt.Sprintf("%s.bak.v%d", path, sourceVersion)
		if err := os.WriteFile(bak, b, 0o600); err != nil {
			return RuleSet{}, fmt.Errorf("rules.json migration backup failed: %w", err)
		}
		if err := writeAtomic(path, migrated); err != nil {
			return RuleSet{}, fmt.Errorf("rules.json migration write failed: %w", err)
		}
	}
	return migrated, nil
}

// Save validates nothing but assigns missing ids, stamps the current schema
// version and writes rules.json atomically.
func Save(path string, rs RuleSet) error {
	rs.Version = CurrentSchema
	for i := range rs.Rules {
		if rs.Rules[i].ID == "" {
			rs.Rules[i].ID = NewID()
		}
	}
	return writeAtomic(path, rs)
}

func writeAtomic(path string, rs RuleSet) error {
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
	// maxNoteLen caps free-text rule notes. 256 chars is comfortable for
	// "M.s_PC, allow temporarily for testing — remove after 2026-06-01"
	// without letting a crafted rules.json balloon: 256 rules × 256 chars
	// = 64 KB of notes, bounded.
	maxNoteLen = 256
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
	// Round-4 (R4-5): reject duplicate rule IDs. xt_recent --name and
	// the LOG --log-prefix line both key on Rule.ID; collisions silently
	// share an xt_recent hashtable bucket which makes rate-limit
	// semantics surprising. Same-id rules are almost always a mistake
	// (copy-paste, restore-after-edit), not an intentional pattern.
	seenID := make(map[string]bool, len(rs.Rules))
	for _, r := range rs.Rules {
		if err := validateRule(r); err != nil {
			return fmt.Errorf("rule %q: %w", r.Name, err)
		}
		if r.ID != "" {
			if seenID[r.ID] {
				return fmt.Errorf("rule %q: duplicate id %q", r.Name, r.ID)
			}
			seenID[r.ID] = true
		}
	}
	return nil
}

// isSafeContainerID matches Docker's container-name regex
// (alphanumeric + dot + dash + underscore), capped at 64 chars
// — Docker's own limit. Empty is accepted (no binding).
func isSafeContainerID(s string) bool {
	if len(s) > 64 {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z',
			r >= 'A' && r <= 'Z',
			r >= '0' && r <= '9',
			r == '-', r == '_', r == '.':
			// ok
		default:
			return false
		}
	}
	return true
}

// isSafeRuleID guards against shell-injection through Rule.ID. The
// compiler interpolates the value into the generated bash script's
// xt_recent `--name z<ID>` clause and into the per-rule LOG prefix
// `"ZFW-RULE-<ID> "`. Round-4 R4-1 PoC: an ID containing `;` lands two
// commands in the root-run compiled.sh because the inner `--log-prefix
// "ZFW-RULE-<ID> "` quoting is bash-fragile under set -eu. Locking the
// character set + length here closes that path before it ever reaches
// the compiler. Empty IDs are accepted because Save() fills them in;
// Validate is called both before Save (rules POST) and after (engine
// recompile) and the compiler tolerates the empty-id wrapEmit path
// (it just emits no LOG/recent line for that rule).
func isSafeRuleID(s string) bool {
	if s == "" {
		return true
	}
	if len(s) > 16 {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z',
			r >= 'A' && r <= 'Z',
			r >= '0' && r <= '9',
			r == '-', r == '_':
			// ok
		default:
			return false
		}
	}
	return true
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
	// Round-4 R4-1: id must be empty (Save fills it) or pass the
	// strict allowlist — Rule.ID lands raw in the compiled bash via
	// xt_recent --name and the LOG --log-prefix; without this guard a
	// crafted id of `ok"; rm -rf / #` becomes root code execution.
	if !isSafeRuleID(r.ID) {
		return fmt.Errorf("id %q invalid (expected empty or 1..16 chars of [A-Za-z0-9_-])", r.ID)
	}
	// Round-4 R4-4: container_id is used as a Go map key today and
	// not interpolated into bash, but the field is free-form and
	// persisted — locking the char-set keeps future emit paths from
	// inheriting injection risk by default.
	if r.ContainerID != "" && !isSafeContainerID(r.ContainerID) {
		return fmt.Errorf("container_id %q invalid (expected 1..64 chars of [A-Za-z0-9_.-])", r.ContainerID)
	}
	if r.Name == "" {
		return fmt.Errorf("name is required")
	}
	if r.Action != "allow" && r.Action != "deny" {
		return fmt.Errorf("action must be allow or deny")
	}
	if len(r.Notes) > maxNoteLen {
		return fmt.Errorf("notes too long: %d chars (max %d)", len(r.Notes), maxNoteLen)
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
	if r.Schedule != nil {
		if err := validateSchedule(*r.Schedule); err != nil {
			return fmt.Errorf("schedule: %w", err)
		}
	}
	if r.RateLimit != nil {
		if err := validateRateLimit(*r.RateLimit); err != nil {
			return fmt.Errorf("rate_limit: %w", err)
		}
	}
	if r.Direction != "" && r.Direction != "inbound" && r.Direction != "outbound" {
		return fmt.Errorf("direction must be inbound, outbound or empty (got %q)", r.Direction)
	}
	return nil
}

// IsOutbound reports whether this rule targets the OUTPUT/FORWARD
// chains instead of the historical INPUT/DOCKER-USER ones. Empty
// Direction is treated as inbound, matching the v0.5.6 migration
// invariant that v2 rules.json files round-trip semantically
// unchanged.
func (r Rule) IsOutbound() bool { return r.Direction == "outbound" }

// validateRateLimit caps Conn/Seconds inside ranges that produce a
// useful iptables clause without letting a crafted rules.json emit a
// silly value (e.g. negative seconds, or hitcount in the millions that
// hash-table-bloats xt_recent).
func validateRateLimit(rl RateLimit) error {
	if rl.Conn < 1 || rl.Conn > 1000 {
		return fmt.Errorf("conn must be 1..1000 (got %d)", rl.Conn)
	}
	if rl.Seconds < 1 || rl.Seconds > 3600 {
		return fmt.Errorf("seconds must be 1..3600 (got %d)", rl.Seconds)
	}
	return nil
}

// scheduleDays is the set of accepted lowercase weekday names. The
// compiler maps these to iptables-legacy's Mon/Tue/… form before
// emitting -m time --weekdays.
var scheduleDays = map[string]bool{
	"mon": true, "tue": true, "wed": true, "thu": true,
	"fri": true, "sat": true, "sun": true,
}

func validateSchedule(s Schedule) error {
	if !isHHMM(s.From) {
		return fmt.Errorf("from must be HH:MM (got %q)", s.From)
	}
	if !isHHMM(s.To) {
		return fmt.Errorf("to must be HH:MM (got %q)", s.To)
	}
	// Empty Days = every day (the compiler then emits no --weekdays).
	// Duplicates are accepted but useless; we cap the count so a
	// crafted rules.json cannot produce an oversized iptables line.
	if len(s.Days) > 7 {
		return fmt.Errorf("days: at most 7 entries")
	}
	for _, d := range s.Days {
		if !scheduleDays[strings.ToLower(d)] {
			return fmt.Errorf("days: %q is not a valid weekday (mon|tue|wed|thu|fri|sat|sun)", d)
		}
	}
	return nil
}

// isHHMM reports whether s is a "HH:MM" string in 24-hour wall-clock form.
func isHHMM(s string) bool {
	if len(s) != 5 || s[2] != ':' {
		return false
	}
	h, err1 := strconv.Atoi(s[:2])
	m, err2 := strconv.Atoi(s[3:])
	return err1 == nil && err2 == nil && h >= 0 && h <= 23 && m >= 0 && m <= 59
}
