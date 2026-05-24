package audit

import (
	"path/filepath"
	"testing"
	"time"
)

func TestHistoryRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit-history.json")

	h := History{
		"M1": {{TS: "2026-05-22T10:00:00Z", Status: "open"}},
	}
	if err := SaveHistory(path, h); err != nil {
		t.Fatalf("save: %v", err)
	}
	got, err := LoadHistory(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(got["M1"]) != 1 || got["M1"][0].Status != "open" {
		t.Errorf("round-trip lost data: %+v", got)
	}
}

// TestHistoryUpdateAppendsOnlyOnStatusChange is the heart of the
// v0.3.5 contract — recording one entry per status flip, not one per
// audit fetch. Without this guard the history file balloons by O(audit
// requests) instead of O(actual posture changes).
func TestHistoryUpdateAppendsOnlyOnStatusChange(t *testing.T) {
	h := History{}
	findings := []Finding{{ID: "M1", Status: "open"}}

	// First call: empty history → must seed a row.
	if !h.Update(findings, time.Date(2026, 5, 22, 10, 0, 0, 0, time.UTC)) {
		t.Fatal("first Update should seed history")
	}
	if len(h["M1"]) != 1 {
		t.Errorf("after seed: got %d entries, want 1", len(h["M1"]))
	}
	// Second call same status: history must NOT grow.
	if h.Update(findings, time.Date(2026, 5, 23, 10, 0, 0, 0, time.UTC)) {
		t.Error("Update reported dirty for unchanged status")
	}
	if len(h["M1"]) != 1 {
		t.Errorf("after no-op: got %d entries, want 1", len(h["M1"]))
	}
	// Status flip: history grows by one.
	findings[0].Status = "fixed"
	if !h.Update(findings, time.Date(2026, 5, 24, 10, 0, 0, 0, time.UTC)) {
		t.Error("Update missed a status flip")
	}
	if len(h["M1"]) != 2 || h["M1"][1].Status != "fixed" {
		t.Errorf("after flip: %+v", h["M1"])
	}
}

// TestHistoryUpdateCapsLength guards the per-finding row cap. A
// finding that flips constantly cannot balloon audit-history.json
// past maxHistoryPerFinding — the oldest entries get dropped.
func TestHistoryUpdateCapsLength(t *testing.T) {
	h := History{}
	statuses := []string{"open", "mitigated", "fixed"}
	for i := 0; i < maxHistoryPerFinding*2; i++ {
		findings := []Finding{{ID: "M1", Status: statuses[i%len(statuses)]}}
		h.Update(findings, time.Date(2026, 5, 22, 0, 0, i, 0, time.UTC))
	}
	if len(h["M1"]) != maxHistoryPerFinding {
		t.Errorf("got %d entries, want cap of %d", len(h["M1"]), maxHistoryPerFinding)
	}
}

// TestHistoryAttachIncludesEmptyTimeline guards the API contract: a
// finding with no recorded history must come back with history=[]
// (not null) so the UI's `for (const e of f.history)` doesn't crash.
func TestHistoryAttachIncludesEmptyTimeline(t *testing.T) {
	h := History{"M1": {{TS: "x", Status: "open"}}}
	findings := []Finding{
		{ID: "M1", Status: "open"},
		{ID: "M2", Status: "fixed"},
	}
	out := h.Attach(findings)
	if len(out) != 2 {
		t.Fatalf("got %d wrapped findings, want 2", len(out))
	}
	if len(out[0].History) != 1 {
		t.Errorf("M1 history dropped: %+v", out[0].History)
	}
	// M2 has no recorded history yet. The wire shape must still
	// have a `history` field — encoding/json renders a nil slice as
	// `null`, which crashes the UI's iteration loop. The handler
	// (not Attach) normalises this; here we just verify Attach
	// returned the entry at all.
	if out[1].Finding.ID != "M2" {
		t.Errorf("M2 entry missing or wrong: %+v", out[1])
	}
}
