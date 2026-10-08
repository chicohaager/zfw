// Package apps answers "who may reach the port this new app just opened?"
// (v1.0.28).
//
// Under default-deny a container port published after the last apply is
// dropped by the DNAT guard (v1.0.27), and a network_mode: host app by the
// ZFW-IN catch-all — safe, but to the person who just installed an app from
// the ZimaOS store the app simply looks broken. This package tracks every
// such port as an Entry, asks the operator (ZFW UI, ZimaOS dashboard card)
// whether it should be reachable from the LAN, from everywhere, or not at
// all, and until the answer arrives keeps it reachable from the LAN — or
// closed, if the operator chose that mode.
//
// What it deliberately does NOT do is apply the rule set: an apply replays
// every saved-but-untested edit too, without the dead-man, which is the hole
// v1.0.27 closed at boot. The answer lands in dedicated chains (ZFW-APPS in
// DOCKER-USER, ZFW-APPS-IN in ZFW-IN, ZFW-APPS-IN6 in ZFW-IN6) that a normal
// apply creates and jumps to but never flushes; only `zfw apps` rewrites
// their content. Adding one ACCEPT for one port cannot lock anyone out.
//
// "New" is narrow on purpose, so an upgrade never opens a port the operator
// had left closed:
//   - docker zone: the port is not in the inventory of the applied rule set
//     (it was published after the last apply — exactly what the Exposure tab
//     calls "new since apply");
//   - host zone (network_mode: host): the container started after this
//     package first ran on the host (Baseline);
//   - and in both cases no live rule mentions the port (rules.Decides).
package apps

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/chicohaager/zfw/internal/rules"
)

// State is the operator's answer for one port, or Pending while there is none.
type State string

const (
	Pending State = "pending"
	LAN     State = "lan"   // reachable from the configured LAN
	Any     State = "any"   // reachable from every source
	Block   State = "block" // closed
)

// Mode decides what a Pending port does until it is answered.
const (
	ModeLAN   = "lan"   // reachable from the LAN (default, decided 2026-10-08)
	ModeBlock = "block" // stays closed, as in v1.0.27
)

// Entry is one container port that appeared without a rule deciding it.
type Entry struct {
	Key       string    `json:"key"`       // zone/proto/port/container — see KeyOf
	Container string    `json:"container"` // container name
	AppID     string    `json:"app_id,omitempty"`
	Title     string    `json:"title"` // ZimaOS app title, else the container name
	Zone      string    `json:"zone"`  // docker | host
	Proto     string    `json:"proto"` // tcp | udp
	Port      int       `json:"port"`
	State     State     `json:"state"`
	RuleID    string    `json:"rule_id,omitempty"` // the rule the answer was saved as
	Since     time.Time `json:"since"`             // first seen
	LastSeen  time.Time `json:"last_seen"`         // last seen published/listening
	Present   bool      `json:"present"`           // published/listening right now
}

// Candidate is a port a running container offers to the network right now.
type Candidate struct {
	Container string
	AppID     string // io.zimaos.app.id label, empty for a hand-started container
	Title     string
	Zone      string // docker | host
	Proto     string
	Port      int
	Started   time.Time // only used for the host zone (Baseline comparison)
}

// KeyOf identifies a port across restarts and recreations of its container.
func KeyOf(zone, proto string, port int, container string) string {
	return fmt.Sprintf("%s/%s/%d/%s", zone, proto, port, container)
}

// File is the persisted state, /DATA/zfw/apps.json (root-only directory).
type File struct {
	V        int       `json:"v"`
	Mode     string    `json:"mode"`     // ModeLAN | ModeBlock
	Baseline time.Time `json:"baseline"` // host-zone containers started before this are not "new"
	Entries  []Entry   `json:"entries"`
}

// Load reads the state file. A missing file is a first run: the baseline is
// set to now so that host-network apps already running are not treated as new.
func Load(path string, now time.Time) (File, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return File{V: 1, Mode: ModeLAN, Baseline: now}, nil
	}
	if err != nil {
		return File{}, err
	}
	var f File
	if err := json.Unmarshal(b, &f); err != nil {
		return File{}, fmt.Errorf("apps state %s: %w", path, err)
	}
	if f.Mode != ModeBlock {
		f.Mode = ModeLAN
	}
	if f.Baseline.IsZero() {
		f.Baseline = now
	}
	return f, nil
}

// Save writes the state atomically with mode 0600.
func Save(path string, f File) error {
	f.V = 1
	b, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".apps-*.json")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// How long an entry is kept after its container stopped offering the port.
// A pending one goes after an hour (the app was removed before anyone
// answered); an answered one is kept for a month, so that recreating the
// container — every app update does — does not ask the same question again.
const (
	pendingTTL = time.Hour
	answerTTL  = 30 * 24 * time.Hour
)

// Live is what the applied rule set says, as far as Detect needs it.
type Live struct {
	Rules     rules.RuleSet
	Published func(port int) bool // the applied inventory (LiveSnapshot.Published)
}

// Detect merges the running candidates into the stored entries.
//
// live is nil when ZFW has no record of what it applied (firewall off, never
// applied by v1.0.27+, or reverted): nothing is filtered by ZFW then, or ZFW
// cannot tell, so no new entry is created — only presence is refreshed.
func Detect(f File, cands []Candidate, live *Live, now time.Time) File {
	byKey := make(map[string]int, len(f.Entries))
	for i := range f.Entries {
		byKey[f.Entries[i].Key] = i
		f.Entries[i].Present = false
	}
	deny := live != nil && live.Rules.DefaultPolicy == "deny"
	for _, c := range cands {
		key := KeyOf(c.Zone, c.Proto, c.Port, c.Container)
		if i, ok := byKey[key]; ok {
			e := &f.Entries[i]
			e.Present, e.LastSeen = true, now
			if c.Title != "" {
				e.Title = c.Title
			}
			if c.AppID != "" {
				e.AppID = c.AppID
			}
			continue
		}
		if !deny || rules.Decides(live.Rules, c.Zone, c.Proto, c.Port) {
			continue
		}
		switch c.Zone {
		case "docker":
			if live.Published != nil && live.Published(c.Port) {
				continue // in the applied inventory: left closed on purpose
			}
		case "host":
			if c.Started.IsZero() || !c.Started.After(f.Baseline) {
				continue // already running before ZFW started asking
			}
		default:
			continue
		}
		title := c.Title
		if title == "" {
			title = c.Container
		}
		f.Entries = append(f.Entries, Entry{
			Key: key, Container: c.Container, AppID: c.AppID, Title: title,
			Zone: c.Zone, Proto: c.Proto, Port: c.Port, State: Pending,
			Since: now, LastSeen: now, Present: true,
		})
		byKey[key] = len(f.Entries) - 1
	}
	kept := f.Entries[:0]
	for _, e := range f.Entries {
		// A pending question a live rule has since answered (the operator wrote
		// the rule by hand and applied it) is no question any more.
		if e.State == Pending && live != nil && rules.Decides(live.Rules, e.Zone, e.Proto, e.Port) {
			continue
		}
		if !e.Present {
			ttl := answerTTL
			if e.State == Pending {
				ttl = pendingTTL
			}
			if now.Sub(e.LastSeen) > ttl {
				continue
			}
		}
		kept = append(kept, e)
	}
	f.Entries = kept
	sort.SliceStable(f.Entries, func(i, j int) bool { return f.Entries[i].Since.Before(f.Entries[j].Since) })
	return f
}

// Active returns the entries that need an ACCEPT in the app chains right now:
// present, open by answer or by the pending mode, and not yet carried by the
// applied rule set itself (after the next apply the saved rule takes over and
// the app chain entry would only hide a later edit of that rule).
func Active(f File, live *Live) []Entry {
	applied := map[string]bool{}
	if live != nil {
		for _, r := range live.Rules.Rules {
			applied[r.ID] = true
		}
	}
	var out []Entry
	for _, e := range f.Entries {
		if !e.Present || (e.RuleID != "" && applied[e.RuleID]) {
			continue
		}
		switch e.State {
		case LAN, Any:
			out = append(out, e)
		case Pending:
			if f.Mode == ModeLAN {
				out = append(out, e)
			}
		}
	}
	return out
}

// Open reports the source an active entry admits: "lan" or "any".
func (e Entry) Open() string {
	if e.State == Any {
		return "any"
	}
	return "lan"
}

// Find returns the index of the entry with key, or -1.
func (f File) Find(key string) int {
	for i := range f.Entries {
		if f.Entries[i].Key == key {
			return i
		}
	}
	return -1
}

// RuleFor turns an answer into an ordinary rule, so that it shows in the Rules
// tab, survives in rules.json and takes over from the app chain at the next
// apply. It names the one port the app opened — not the container — so a
// later port change of the app asks again instead of inheriting the answer.
func RuleFor(e Entry, answer State, lan, id string, order int, now time.Time) (rules.Rule, error) {
	r := rules.Rule{
		ID:       id,
		Order:    order,
		Enabled:  true,
		Name:     fmt.Sprintf("%s (port %d)", e.Title, e.Port),
		Ports:    rules.Ports{Type: "list", List: []int{e.Port}},
		Protocol: e.Proto,
		Zone:     e.Zone,
		Notes:    "New-app prompt, answered " + now.Format("2006-01-02") + ": " + string(answer),
	}
	switch answer {
	case LAN:
		if lan == "" {
			return rules.Rule{}, errors.New("no LAN configured — set it on the Firewall tab first")
		}
		r.Action, r.Source = "allow", rules.Source{Type: "range", Value: lan}
	case Any:
		r.Action, r.Source = "allow", rules.Source{Type: "any"}
	case Block:
		r.Action, r.Source = "deny", rules.Source{Type: "any"}
	default:
		return rules.Rule{}, fmt.Errorf("unknown answer %q (lan, any or block)", answer)
	}
	return r, nil
}
