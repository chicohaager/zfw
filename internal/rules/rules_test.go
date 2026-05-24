package rules

import (
	"encoding/json"
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
func TestLoadCurrentVersionIsNoOp(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rules.json")
	original := []byte(`{"version":1,"lan":"192.168.1.0/24","default_policy":"deny","rules":[]}`)
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
	if _, err := os.Stat(path + ".bak.v1"); !os.IsNotExist(err) {
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
