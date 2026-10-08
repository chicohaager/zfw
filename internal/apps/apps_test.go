package apps

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/chicohaager/zfw/internal/rules"
)

var t0 = time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)

func liveDeny(published []int, rl ...rules.Rule) *Live {
	pub := map[int]bool{}
	for _, p := range published {
		pub[p] = true
	}
	return &Live{
		Rules:     rules.RuleSet{LAN: "192.0.2.0/24", DefaultPolicy: "deny", Rules: rl},
		Published: func(p int) bool { return pub[p] },
	}
}

func rule(id, action, zone string, port int) rules.Rule {
	return rules.Rule{ID: id, Enabled: true, Action: action, Zone: zone, Protocol: "tcp",
		Source: rules.Source{Type: "any"}, Ports: rules.Ports{Type: "list", List: []int{port}}}
}

func docker(name string, port int) Candidate {
	return Candidate{Container: name, Zone: "docker", Proto: "tcp", Port: port}
}

func keys(f File) []string {
	var out []string
	for _, e := range f.Entries {
		out = append(out, e.Key)
	}
	return out
}

func TestDetectNewDockerPort(t *testing.T) {
	f := File{Mode: ModeLAN, Baseline: t0.Add(-time.Hour)}
	f = Detect(f, []Candidate{docker("web", 8080)}, liveDeny(nil), t0)
	if len(f.Entries) != 1 || f.Entries[0].State != Pending || !f.Entries[0].Present {
		t.Fatalf("want one present pending entry, got %+v", f.Entries)
	}
	if f.Entries[0].Title != "web" {
		t.Errorf("title falls back to the container name, got %q", f.Entries[0].Title)
	}
}

// The upgrade guard: a port that was in the applied inventory was left
// closed by the operator at that apply — it is not new and must not open.
func TestDetectSkipsPortsOfTheAppliedInventory(t *testing.T) {
	f := Detect(File{Mode: ModeLAN}, []Candidate{docker("old", 8000)}, liveDeny([]int{8000}), t0)
	if len(f.Entries) != 0 {
		t.Fatalf("inventory port became an entry: %+v", f.Entries)
	}
}

func TestDetectSkipsPortsARuleDecides(t *testing.T) {
	for _, action := range []string{"allow", "deny"} {
		f := Detect(File{Mode: ModeLAN}, []Candidate{docker("web", 8080)},
			liveDeny(nil, rule("r", action, "docker", 8080)), t0)
		if len(f.Entries) != 0 {
			t.Errorf("%s rule for the port: no question expected, got %+v", action, f.Entries)
		}
	}
}

func TestDetectNeedsDenyAndARecord(t *testing.T) {
	if f := Detect(File{}, []Candidate{docker("web", 8080)}, nil, t0); len(f.Entries) != 0 {
		t.Errorf("no record of what is live: no new entry, got %+v", f.Entries)
	}
	allow := liveDeny(nil)
	allow.Rules.DefaultPolicy = "allow"
	if f := Detect(File{}, []Candidate{docker("web", 8080)}, allow, t0); len(f.Entries) != 0 {
		t.Errorf("default allow filters nothing: no new entry, got %+v", f.Entries)
	}
}

func TestDetectHostZoneUsesBaseline(t *testing.T) {
	base := t0.Add(-time.Hour)
	old := Candidate{Container: "node-old", Zone: "host", Proto: "tcp", Port: 9100, Started: base.Add(-time.Minute)}
	fresh := Candidate{Container: "node-new", Zone: "host", Proto: "tcp", Port: 9101, Started: base.Add(time.Minute)}
	unknown := Candidate{Container: "node-x", Zone: "host", Proto: "tcp", Port: 9102}
	f := Detect(File{Mode: ModeLAN, Baseline: base}, []Candidate{old, fresh, unknown}, liveDeny(nil), t0)
	if got := keys(f); len(got) != 1 || !strings.Contains(got[0], "9101") {
		t.Fatalf("only the container started after the baseline is new, got %v", got)
	}
}

func TestDetectDropsAPendingQuestionALiveRuleAnswered(t *testing.T) {
	f := Detect(File{Mode: ModeLAN}, []Candidate{docker("web", 8080)}, liveDeny(nil), t0)
	f = Detect(f, []Candidate{docker("web", 8080)}, liveDeny(nil, rule("r", "allow", "docker", 8080)), t0.Add(time.Minute))
	if len(f.Entries) != 0 {
		t.Fatalf("a hand-written, applied rule answers the question: %+v", f.Entries)
	}
}

func TestDetectKeepsAnswersAcrossRecreation(t *testing.T) {
	f := Detect(File{Mode: ModeLAN}, []Candidate{docker("web", 8080)}, liveDeny(nil), t0)
	f.Entries[0].State = LAN
	// the container is recreated by an app update: gone for a while…
	f = Detect(f, nil, liveDeny(nil), t0.Add(2*time.Hour))
	if len(f.Entries) != 1 || f.Entries[0].Present {
		t.Fatalf("an answered entry survives its container's absence: %+v", f.Entries)
	}
	// …and back: same key, same answer, no new question
	f = Detect(f, []Candidate{docker("web", 8080)}, liveDeny(nil), t0.Add(3*time.Hour))
	if len(f.Entries) != 1 || f.Entries[0].State != LAN || !f.Entries[0].Present {
		t.Fatalf("answer lost across recreation: %+v", f.Entries)
	}
}

func TestDetectPrunesAbandonedEntries(t *testing.T) {
	f := Detect(File{Mode: ModeLAN}, []Candidate{docker("a", 8080), docker("b", 8081)}, liveDeny(nil), t0)
	f.Entries[1].State = Block
	f = Detect(f, nil, liveDeny(nil), t0.Add(2*time.Hour))
	if got := keys(f); len(got) != 1 || !strings.Contains(got[0], "8081") {
		t.Fatalf("pending gone after 1 h, answered kept: %v", got)
	}
	f = Detect(f, nil, liveDeny(nil), t0.Add(31*24*time.Hour))
	if len(f.Entries) != 0 {
		t.Fatalf("answered entries go after 30 days: %+v", f.Entries)
	}
}

func TestActive(t *testing.T) {
	mk := func(port int, st State, present bool, ruleID string) Entry {
		return Entry{Key: KeyOf("docker", "tcp", port, "c"), Zone: "docker", Proto: "tcp", Port: port, State: st, Present: present, RuleID: ruleID}
	}
	f := File{Mode: ModeLAN, Entries: []Entry{
		mk(1, Pending, true, ""),
		mk(2, LAN, true, "r2"),
		mk(3, Any, true, "r3"),
		mk(4, Block, true, "r4"),
		mk(5, LAN, false, "r5"),     // container gone
		mk(6, LAN, true, "applied"), // carried by the applied rules now
	}}
	live := liveDeny(nil, rule("applied", "allow", "docker", 6))
	ports := func() string {
		var got []int
		for _, e := range Active(f, live) {
			got = append(got, e.Port)
		}
		return fmt.Sprint(got)
	}
	if got := ports(); got != "[1 2 3]" {
		t.Errorf("lan mode: want [1 2 3] active, got %s", got)
	}
	f.Mode = ModeBlock
	if got := ports(); got != "[2 3]" {
		t.Errorf("block mode: a pending port stays closed, want [2 3], got %s", got)
	}
}

func TestRuleFor(t *testing.T) {
	e := Entry{Title: "CasaDrop", Zone: "docker", Proto: "tcp", Port: 8086}
	lan, err := RuleFor(e, LAN, "192.0.2.0/24", "rx", 70, t0)
	if err != nil || lan.Action != "allow" || lan.Source != (rules.Source{Type: "range", Value: "192.0.2.0/24"}) {
		t.Fatalf("lan answer: %+v %v", lan, err)
	}
	if lan.Name != "CasaDrop (port 8086)" || lan.Zone != "docker" || lan.Ports.List[0] != 8086 || !lan.Enabled {
		t.Errorf("rule shape: %+v", lan)
	}
	if r, _ := RuleFor(e, Any, "192.0.2.0/24", "rx", 70, t0); r.Action != "allow" || r.Source.Type != "any" {
		t.Errorf("any answer: %+v", r)
	}
	if r, _ := RuleFor(e, Block, "192.0.2.0/24", "rx", 70, t0); r.Action != "deny" || r.Source.Type != "any" {
		t.Errorf("block answer: %+v", r)
	}
	if _, err := RuleFor(e, LAN, "", "rx", 70, t0); err == nil {
		t.Error("lan answer without a LAN must be refused, not saved as an open rule")
	}
	if _, err := RuleFor(e, Pending, "192.0.2.0/24", "rx", 70, t0); err == nil {
		t.Error("pending is not an answer")
	}
	rs := rules.RuleSet{LAN: "192.0.2.0/24", DefaultPolicy: "deny", Rules: []rules.Rule{lan}}
	if err := rules.Validate(rs); err != nil {
		t.Errorf("the generated rule must pass the rule validator: %v", err)
	}
}

func TestLoadFirstRunSetsBaseline(t *testing.T) {
	p := filepath.Join(t.TempDir(), "apps.json")
	f, err := Load(p, t0)
	if err != nil || f.Mode != ModeLAN || !f.Baseline.Equal(t0) {
		t.Fatalf("first run: %+v %v", f, err)
	}
	f.Mode = ModeBlock
	f.Entries = []Entry{{Key: "k", Port: 1, State: Any}}
	if err := Save(p, f); err != nil {
		t.Fatal(err)
	}
	g, err := Load(p, t0.Add(time.Hour))
	if err != nil || g.Mode != ModeBlock || !g.Baseline.Equal(t0) || len(g.Entries) != 1 {
		t.Fatalf("round trip: %+v %v", g, err)
	}
}

func TestCardText(t *testing.T) {
	e := Entry{Title: "CasaDrop", Port: 8086, Proto: "tcp", Key: "docker/tcp/8086/casadrop"}
	if s := CardText(e, ModeLAN); !strings.Contains(s, "CasaDrop opened port 8086/tcp") || !strings.Contains(s, "LAN only") {
		t.Errorf("lan mode text: %q", s)
	}
	if s := CardText(e, ModeBlock); !strings.Contains(s, "keeps it closed") {
		t.Errorf("block mode text: %q", s)
	}
	if CardID(e) != "zfw:app:docker/tcp/8086/casadrop" {
		t.Errorf("card id must be stable per entry: %q", CardID(e))
	}
}
