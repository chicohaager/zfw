package audit

import (
	"encoding/json"
	"os"
	"time"
)

// HistoryEntry is one transition in a finding's posture over time —
// "open → fixed at 2026-05-22T10:00:00Z". Recorded only when the live
// status differs from the previous entry, so a finding that stays
// fixed for weeks keeps a short timeline rather than one row per audit
// fetch.
type HistoryEntry struct {
	TS     string `json:"ts"`     // RFC 3339 in UTC
	Status string `json:"status"` // open | mitigated | fixed
}

// History is the on-disk timeline keyed by finding ID.
type History map[string][]HistoryEntry

// maxHistoryPerFinding bounds the timeline so a finding that flips
// repeatedly cannot balloon audit-history.json. The newest entry is
// always kept; older ones are dropped from the front.
const maxHistoryPerFinding = 20

// LoadHistory reads the persisted timeline. A missing file is not an
// error — it means we have no history yet, so the caller starts with
// an empty map and Update will seed it on the first call.
func LoadHistory(path string) (History, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return History{}, nil
		}
		return nil, err
	}
	var h History
	if err := json.Unmarshal(b, &h); err != nil {
		return nil, err
	}
	if h == nil {
		h = History{}
	}
	return h, nil
}

// SaveHistory writes the timeline atomically: temp file on the same
// filesystem, fsync via os.Rename. Mirrors the rules.Save pattern so a
// concurrent reader never observes a half-written file.
func SaveHistory(path string, h History) error {
	b, err := json.MarshalIndent(h, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// Update walks the current findings, appends a new HistoryEntry to each
// finding whose live status differs from the latest recorded entry, and
// returns whether anything changed (so the caller knows whether to save
// to disk). The timestamp uses a single instant for the whole batch so
// rows that flip together share an exact ts.
func (h History) Update(findings []Finding, now time.Time) bool {
	ts := now.UTC().Format(time.RFC3339)
	dirty := false
	for _, f := range findings {
		entries := h[f.ID]
		if len(entries) > 0 && entries[len(entries)-1].Status == f.Status {
			continue // unchanged — no new row
		}
		entries = append(entries, HistoryEntry{TS: ts, Status: f.Status})
		if len(entries) > maxHistoryPerFinding {
			entries = entries[len(entries)-maxHistoryPerFinding:]
		}
		h[f.ID] = entries
		dirty = true
	}
	return dirty
}

// Attach copies each finding's history slice into the returned slice
// of FindingWithHistory — the on-the-wire shape the API returns. The
// original Findings slice is left unmodified.
type FindingWithHistory struct {
	Finding
	History []HistoryEntry `json:"history"`
}

func (h History) Attach(findings []Finding) []FindingWithHistory {
	out := make([]FindingWithHistory, len(findings))
	for i, f := range findings {
		out[i] = FindingWithHistory{Finding: f, History: h[f.ID]}
	}
	return out
}
