package handlers

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/chicohaager/zfw/internal/apps"
	"github.com/chicohaager/zfw/internal/conntrack"
	"github.com/chicohaager/zfw/internal/rules"
	"github.com/chicohaager/zfw/internal/system"
)

// Gaps in the v1.0.28 new-app prompt found in review (2026-10-09).

func decide(t *testing.T, s *Server, key, answer string) {
	t.Helper()
	if w := do(s, http.MethodPost, "/api/apps/decide", map[string]string{"key": key, "answer": answer}); w.Code != http.StatusOK {
		t.Fatalf("decide %s: HTTP %d %s", answer, w.Code, w.Body.String())
	}
}

func dropRule(t *testing.T, s *Server, id string) rules.RuleSet {
	t.Helper()
	rs, err := rules.Load(s.rulesPath)
	if err != nil {
		t.Fatal(err)
	}
	kept := rs.Rules[:0]
	for _, r := range rs.Rules {
		if r.ID != id {
			kept = append(kept, r)
		}
	}
	rs.Rules = kept
	if err := rules.Save(s.rulesPath, rs); err != nil {
		t.Fatal(err)
	}
	return rs
}

// Deleting the rule an answer became, then applying: the port was in that
// apply's inventory, so it is no longer new — the default-deny decides and the
// app chain must not keep it open. Before the fix the entry stayed "lan" in
// apps.json and Active re-admitted it because its rule was no longer live.
func TestDeletedAnswerRuleAndApplyClosesThePort(t *testing.T) {
	s, _, _ := appsFixture(t)
	_ = s.SyncApps(context.Background())
	key := appsState(t, s).Entries[0].Key
	decide(t, s, key, "lan")
	rs := dropRule(t, s, appsState(t, s).Entries[0].RuleID)
	markLive(t, s, rs, system.PublishedPorts{TCP: map[int]bool{8096: true, 8080: true}, UDP: map[int]bool{}})
	if err := s.SyncApps(context.Background()); err != nil {
		t.Fatal(err)
	}
	if script := appsScriptOf(t, s); strings.Contains(script, "--ctorigdstport 8080") {
		t.Errorf("answer rule deleted and applied, but the app chain still opens 8080:\n%s", script)
	}
	if f := appsState(t, s); f.Find(key) >= 0 {
		t.Errorf("withdrawn answer still recorded: %+v", f.Entries)
	}
	if row := exposureRow(t, s, 8080); row.Reach != "blocked" {
		t.Errorf("exposure after deleting the answer rule: %+v", row)
	}
}

// Deleting the answer rule and only saving: nothing was applied since the app
// appeared, so the port is still new — the question comes back (in LAN mode
// reachable from the LAN until answered again), it is not silently kept open
// under the old answer.
func TestDeletedAnswerRuleAsksAgain(t *testing.T) {
	s, _, _ := appsFixture(t)
	_ = s.SyncApps(context.Background())
	key := appsState(t, s).Entries[0].Key
	decide(t, s, key, "any")
	dropRule(t, s, appsState(t, s).Entries[0].RuleID)
	if err := s.SyncApps(context.Background()); err != nil {
		t.Fatal(err)
	}
	f := appsState(t, s)
	i := f.Find(key)
	if i < 0 || f.Entries[i].State != apps.Pending || f.Entries[i].RuleID != "" {
		t.Fatalf("want the question back as pending, got %+v", f.Entries)
	}
	if script := appsScriptOf(t, s); !strings.Contains(script, lan8080) {
		t.Errorf("pending in LAN mode: LAN line expected, not the old 'everyone':\n%s", script)
	}
}

// Narrowing an answer must end connections the old answer let in: the app
// chain only judges new connections, ESTABLISHED ones pass ahead of it.
func TestNarrowingAnAnswerFlushesConntrack(t *testing.T) {
	s, _, _ := appsFixture(t)
	var flushed [][]conntrack.PortKey
	s.flushConntrack = func(_ context.Context, k []conntrack.PortKey) (int, error) {
		flushed = append(flushed, k)
		return len(k), nil
	}
	_ = s.SyncApps(context.Background()) // pending, LAN mode: open to the LAN
	key := appsState(t, s).Entries[0].Key
	decide(t, s, key, "any") // widening: nothing to tear down
	if len(flushed) != 0 {
		t.Fatalf("widening flushed connections: %v", flushed)
	}
	decide(t, s, key, "lan") // any → LAN: connections from outside the LAN must go
	decide(t, s, key, "block")
	want := conntrack.PortKey{Proto: "tcp", Port: 8080}
	if len(flushed) != 2 || len(flushed[0]) != 1 || flushed[0][0] != want || len(flushed[1]) != 1 || flushed[1][0] != want {
		t.Errorf("want two flushes of tcp/8080 (any→lan, lan→block), got %v", flushed)
	}
}

func TestModeBlockFlushesPendingConnections(t *testing.T) {
	s, _, _ := appsFixture(t)
	var flushed []conntrack.PortKey
	s.flushConntrack = func(_ context.Context, k []conntrack.PortKey) (int, error) {
		flushed = append(flushed, k...)
		return len(k), nil
	}
	_ = s.SyncApps(context.Background())
	if w := do(s, http.MethodPost, "/api/apps", map[string]string{"mode": "block"}); w.Code != http.StatusOK {
		t.Fatalf("mode: %d %s", w.Code, w.Body.String())
	}
	if len(flushed) != 1 || flushed[0] != (conntrack.PortKey{Proto: "tcp", Port: 8080}) {
		t.Errorf("switching to block mode closes the pending port: want its connections flushed, got %v", flushed)
	}
}
