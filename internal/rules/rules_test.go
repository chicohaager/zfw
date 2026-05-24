package rules

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// minimalRule is a complete, valid Rule for tests that want to flip
// exactly one field. Validate accepts it as-is.
func minimalRule() Rule {
	return Rule{
		ID:       "r12345678",
		Name:     "test rule",
		Action:   "allow",
		Source:   Source{Type: "any"},
		Ports:    Ports{Type: "list", List: []int{22}},
		Protocol: "tcp",
		Zone:     "host",
	}
}

// TestValidateAcceptsNotes guards the v0.3.2 notes field: a rule with a
// reasonable free-text note must pass Validate so the new UI input
// works end-to-end.
func TestValidateAcceptsNotes(t *testing.T) {
	r := minimalRule()
	r.Notes = "Allow temporarily for M.s_PC testing — remove 2026-06-01"
	rs := RuleSet{DefaultPolicy: "deny", Rules: []Rule{r}}
	if err := Validate(rs); err != nil {
		t.Fatalf("Validate rejected a rule with valid notes: %v", err)
	}
}

// TestValidateRejectsOversizeNotes guards the maxNoteLen cap so a
// crafted rules.json cannot balloon: a note above the limit must be
// refused before it lands on disk.
func TestValidateRejectsOversizeNotes(t *testing.T) {
	r := minimalRule()
	r.Notes = strings.Repeat("x", maxNoteLen+1)
	rs := RuleSet{DefaultPolicy: "deny", Rules: []Rule{r}}
	err := Validate(rs)
	if err == nil {
		t.Fatal("Validate accepted a note above maxNoteLen — want error")
	}
	if !strings.Contains(err.Error(), "notes too long") {
		t.Errorf("error message did not mention notes: %v", err)
	}
}

// TestLoadMissingVersionMigratesAndBacksUp guards the v0.3.8 migration
// plumbing: an old rules.json with no "version" field must be loaded
// transparently, written back stamped with CurrentSchema, and a
// .bak.v0 file must contain the original bytes verbatim.
func TestLoadMissingVersionMigratesAndBacksUp(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rules.json")
	original := []byte(`{"lan":"192.168.1.0/24","default_policy":"deny","rules":[]}`)
	if err := os.WriteFile(path, original, 0o600); err != nil {
		t.Fatal(err)
	}
	rs, err := Load(path)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if rs.Version != CurrentSchema {
		t.Errorf("loaded RuleSet version = %d, want %d", rs.Version, CurrentSchema)
	}
	bak := path + ".bak.v0"
	got, err := os.ReadFile(bak)
	if err != nil {
		t.Fatalf("expected backup at %s: %v", bak, err)
	}
	if string(got) != string(original) {
		t.Errorf("backup bytes differ from original\n got: %s\nwant: %s", got, original)
	}
	// And the on-disk file must now carry the stamped version.
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var parsed RuleSet
	if err := json.Unmarshal(after, &parsed); err != nil {
		t.Fatal(err)
	}
	if parsed.Version != CurrentSchema {
		t.Errorf("post-migration on-disk version = %d, want %d", parsed.Version, CurrentSchema)
	}
}

// TestLoadCurrentVersionIsNoOp guards that a rules.json already at
// CurrentSchema produces no .bak file and leaves the bytes untouched.
// The seed version interpolates CurrentSchema so this test stays
// honest across future schema bumps (the v1→v2 bump in v0.4.3 broke
// the hard-coded version=1 seed).
func TestLoadCurrentVersionIsNoOp(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rules.json")
	original := []byte(fmt.Sprintf(`{"version":%d,"lan":"192.168.1.0/24","default_policy":"deny","rules":[]}`, CurrentSchema))
	if err := os.WriteFile(path, original, 0o600); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	bak := fmt.Sprintf("%s.bak.v%d", path, CurrentSchema)
	if _, err := os.Stat(bak); !os.IsNotExist(err) {
		t.Errorf("unexpected backup file written for current-version rules.json")
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Errorf("Load mutated a current-version rules.json on disk")
	}
}

// TestLoadFutureVersionRefuses guards that a rules.json from a future
// daemon refuses to load — so we never silently drop fields the newer
// schema added.
func TestLoadFutureVersionRefuses(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rules.json")
	original := []byte(`{"version":99,"default_policy":"deny","rules":[]}`)
	if err := os.WriteFile(path, original, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := Load(path)
	if err == nil {
		t.Fatal("Load accepted a future-version rules.json — want error")
	}
	if !strings.Contains(err.Error(), "newer than this daemon") {
		t.Errorf("error message did not flag the version mismatch: %v", err)
	}
	// The file must be left untouched (no .bak written, no overwrite).
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(original) {
		t.Errorf("Load mutated a refused future-version rules.json on disk")
	}
	if _, err := os.Stat(path + ".bak.v99"); !os.IsNotExist(err) {
		t.Errorf("unexpected backup file written for refused future-version rules.json")
	}
}

// TestLoadV1MigratesToV2 guards the v0.4.3 schema bump — the first
// real use of the v0.3.8 migrate() plumbing. A rules.json carrying
// version: 1 (the schema before v0.4.3) must be upgraded to
// CurrentSchema (=2) and the pre-migration bytes preserved as
// .bak.v1, so a user always has a way back if a future migration
// step turns out to be wrong.
func TestLoadV1MigratesToV2(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rules.json")
	original := []byte(`{"version":1,"lan":"192.168.1.0/24","default_policy":"deny","rules":[]}`)
	if err := os.WriteFile(path, original, 0o600); err != nil {
		t.Fatal(err)
	}
	rs, err := Load(path)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if rs.Version != CurrentSchema {
		t.Errorf("post-migration Version = %d, want %d", rs.Version, CurrentSchema)
	}
	bak := path + ".bak.v1"
	got, err := os.ReadFile(bak)
	if err != nil {
		t.Fatalf("expected backup at %s: %v", bak, err)
	}
	if string(got) != string(original) {
		t.Errorf("backup bytes differ from original\n got: %s\nwant: %s", got, original)
	}
}

// TestValidateAcceptsSchedule guards the v0.4.3 Schedule field: a
// rule with a sane "Allow SSH 08:00-18:00, weekdays" Schedule must
// pass Validate so the UI's editor works end-to-end.
func TestValidateAcceptsSchedule(t *testing.T) {
	r := minimalRule()
	r.Schedule = &Schedule{From: "08:00", To: "18:00", Days: []string{"mon", "tue", "wed", "thu", "fri"}}
	rs := RuleSet{DefaultPolicy: "deny", Rules: []Rule{r}}
	if err := Validate(rs); err != nil {
		t.Fatalf("Validate rejected a sane Schedule: %v", err)
	}
}

// TestValidateRejectsBadScheduleTime guards that an HH:MM that does
// not parse is refused with a clear error — a typo'd "8:00" must not
// silently land in rules.json where it would crash the compiler's
// iptables-line emit.
func TestValidateRejectsBadScheduleTime(t *testing.T) {
	r := minimalRule()
	r.Schedule = &Schedule{From: "8:00", To: "18:00"}
	rs := RuleSet{DefaultPolicy: "deny", Rules: []Rule{r}}
	err := Validate(rs)
	if err == nil {
		t.Fatal("Validate accepted Schedule with bad From time")
	}
	if !strings.Contains(err.Error(), "from must be HH:MM") {
		t.Errorf("error message did not flag the bad time: %v", err)
	}
}

// TestValidateRejectsBadScheduleDay guards the day-name allow-list:
// only mon/tue/wed/thu/fri/sat/sun pass. Anything else (typos,
// crafted JSON, locale variants) must be refused.
func TestValidateRejectsBadScheduleDay(t *testing.T) {
	r := minimalRule()
	r.Schedule = &Schedule{From: "08:00", To: "18:00", Days: []string{"funday"}}
	rs := RuleSet{DefaultPolicy: "deny", Rules: []Rule{r}}
	err := Validate(rs)
	if err == nil {
		t.Fatal("Validate accepted Schedule with bad day")
	}
	if !strings.Contains(err.Error(), "weekday") {
		t.Errorf("error message did not flag the bad day: %v", err)
	}
}

// TestScheduleRoundTripsThroughJSON guards that omitempty does the
// right thing: a rule without a Schedule produces JSON without a
// "schedule" key (so existing rules.json files stay compact); a rule
// WITH a Schedule round-trips byte-perfect.
func TestScheduleRoundTripsThroughJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rules.json")
	rs := RuleSet{
		LAN:           "192.168.1.0/24",
		DefaultPolicy: "deny",
		Rules: []Rule{
			minimalRule(),
			func() Rule {
				r := minimalRule()
				r.ID = "rscheduled"
				r.Schedule = &Schedule{From: "22:00", To: "06:00", Days: []string{"sat", "sun"}}
				return r
			}(),
		},
	}
	if err := Save(path, rs); err != nil {
		t.Fatalf("Save: %v", err)
	}
	loaded, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if loaded.Rules[0].Schedule != nil {
		t.Errorf("rule without schedule round-tripped with a non-nil Schedule: %+v", loaded.Rules[0].Schedule)
	}
	if loaded.Rules[1].Schedule == nil {
		t.Fatalf("rule with schedule round-tripped with nil Schedule")
	}
	got := loaded.Rules[1].Schedule
	if got.From != "22:00" || got.To != "06:00" || len(got.Days) != 2 {
		t.Errorf("Schedule round-trip mismatch: %+v", got)
	}
}

// TestValidateAcceptsLogAndRateLimit guards the v0.4.4 fields: a rule
// with Log=true and a sane RateLimit must pass Validate so the new UI
// inputs work end-to-end.
func TestValidateAcceptsLogAndRateLimit(t *testing.T) {
	r := minimalRule()
	r.Log = true
	r.RateLimit = &RateLimit{Conn: 3, Seconds: 1}
	rs := RuleSet{DefaultPolicy: "deny", Rules: []Rule{r}}
	if err := Validate(rs); err != nil {
		t.Fatalf("Validate rejected log + rate_limit: %v", err)
	}
}

// TestValidateRejectsInjectionID (Round-4 R4-1 regression lock): a
// rule whose ID contains shell metacharacters MUST be rejected by
// Validate before the compiler interpolates it into the root-run
// bash. Without this guard the LOG --log-prefix line at
// compiler.go:wrapEmit becomes `LOG --log-prefix "ZFW-RULE-ok"; rm
// -rf /; #"` and bash runs the second command as root.
func TestValidateRejectsInjectionID(t *testing.T) {
	for _, badID := range []string{
		`ok"; touch /tmp/pwn; #`,
		`ok\nrm -rf /`,
		`ok rm`,
		`abcdefghijklmnopqr`, // 18 chars — over the 16-char cap
		"ok\x00null",         // embedded NUL
	} {
		r := minimalRule()
		r.ID = badID
		rs := RuleSet{DefaultPolicy: "deny", Rules: []Rule{r}}
		if err := Validate(rs); err == nil {
			t.Errorf("Validate accepted unsafe id %q — R4-1 regression", badID)
		}
	}
}

// TestValidateAcceptsCleanID guards the inverse: a normal random id
// shape (NewID produces 9-char r-prefixed hex) MUST be accepted, and
// an empty id MUST be accepted (Save fills it in).
func TestValidateAcceptsCleanID(t *testing.T) {
	for _, goodID := range []string{"", "r12345678", "r-abc", "ABC_def-09"} {
		r := minimalRule()
		r.ID = goodID
		rs := RuleSet{DefaultPolicy: "deny", Rules: []Rule{r}}
		if err := Validate(rs); err != nil {
			t.Errorf("Validate rejected clean id %q: %v", goodID, err)
		}
	}
}

// TestValidateRejectsDuplicateID (R4-5): two rules sharing the same
// non-empty ID must be refused so xt_recent --name collisions don't
// silently corrupt rate-limit semantics.
func TestValidateRejectsDuplicateID(t *testing.T) {
	a := minimalRule()
	a.ID = "rdupAAAA"
	a.Name = "rule-a"
	b := minimalRule()
	b.ID = "rdupAAAA"
	b.Name = "rule-b"
	rs := RuleSet{DefaultPolicy: "deny", Rules: []Rule{a, b}}
	err := Validate(rs)
	if err == nil {
		t.Fatal("Validate accepted duplicate Rule.ID — R4-5 regression")
	}
	if !strings.Contains(err.Error(), "duplicate id") {
		t.Errorf("error did not mention duplicate id: %v", err)
	}
}

// TestValidateRejectsBadContainerID (R4-4): ContainerID is reserved
// for Docker-style identifiers; reject anything outside Docker's
// own container-name char-set so a future emit path can't inherit
// injection risk.
func TestValidateRejectsBadContainerID(t *testing.T) {
	for _, bad := range []string{
		`name with space`,
		`name;rm`,
		`/etc/passwd`,
		strings.Repeat("a", 65),
	} {
		r := minimalRule()
		r.ContainerID = bad
		rs := RuleSet{DefaultPolicy: "deny", Rules: []Rule{r}}
		if err := Validate(rs); err == nil {
			t.Errorf("Validate accepted unsafe container_id %q", bad)
		}
	}
}

// TestValidateRejectsBadRateLimit guards the value caps: Conn=0 or
// negative Seconds must be refused before the compiler ever sees them.
func TestValidateRejectsBadRateLimit(t *testing.T) {
	for _, tc := range []struct {
		name string
		rl   RateLimit
		want string
	}{
		{"zero conn", RateLimit{Conn: 0, Seconds: 1}, "conn must be 1..1000"},
		{"negative seconds", RateLimit{Conn: 3, Seconds: -1}, "seconds must be 1..3600"},
		{"conn too big", RateLimit{Conn: 9999, Seconds: 1}, "conn must be 1..1000"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := minimalRule()
			rl := tc.rl
			r.RateLimit = &rl
			rs := RuleSet{DefaultPolicy: "deny", Rules: []Rule{r}}
			err := Validate(rs)
			if err == nil {
				t.Fatalf("Validate accepted RateLimit %+v, want error", tc.rl)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not mention %q", err.Error(), tc.want)
			}
		})
	}
}

// TestSaveStampsCurrentVersion guards that every Save() writes
// version=CurrentSchema regardless of what the caller passed in — the
// version field is daemon-owned, not user-owned.
func TestSaveStampsCurrentVersion(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rules.json")
	rs := RuleSet{Version: 0, LAN: "192.168.1.0/24", DefaultPolicy: "deny"}
	if err := Save(path, rs); err != nil {
		t.Fatalf("Save failed: %v", err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var parsed RuleSet
	if err := json.Unmarshal(b, &parsed); err != nil {
		t.Fatal(err)
	}
	if parsed.Version != CurrentSchema {
		t.Errorf("Save wrote version=%d, want %d", parsed.Version, CurrentSchema)
	}
}
