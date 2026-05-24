package rules

import (
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
