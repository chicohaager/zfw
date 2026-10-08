package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/chicohaager/zfw/internal/apps"
	"github.com/chicohaager/zfw/internal/rules"
	"github.com/chicohaager/zfw/internal/system"
)

// appsFixture: deny policy, LAN 192.0.2.0/24, applied with 8096 in the
// inventory; a container "web" (ZimaOS app "Web App") then publishes 8080.
func appsFixture(t *testing.T) (*Server, *fakeFirewall, rules.RuleSet) {
	t.Helper()
	fw := activeFW()
	s, rulesPath := newTestServer(t, fw)
	rs := rules.RuleSet{LAN: "192.0.2.0/24", HostIP: "192.0.2.1", DefaultPolicy: "deny", Rules: []rules.Rule{}}
	if err := rules.Save(rulesPath, rs); err != nil {
		t.Fatal(err)
	}
	markLive(t, s, rs, system.PublishedPorts{TCP: map[int]bool{8096: true}, UDP: map[int]bool{}})
	s.appPorts = func(context.Context) ([]system.AppPort, error) {
		return []system.AppPort{{Container: "web", Project: "web", AppID: "web", Zone: "docker", Proto: "tcp", Port: 8080}}, nil
	}
	s.appTitle = func(p string) string {
		if p == "web" {
			return "Web App"
		}
		return ""
	}
	s.listening = func(context.Context) ([]system.Socket, error) {
		return []system.Socket{{Port: 8080, Bind: "*", Proc: "docker-proxy", Scope: "all"}}, nil
	}
	return s, fw, rs
}

func appsScriptOf(t *testing.T, s *Server) string {
	t.Helper()
	b, err := os.ReadFile(s.appsScriptPath())
	if err != nil {
		t.Fatalf("apps.sh: %v", err)
	}
	return string(b)
}

func appsState(t *testing.T, s *Server) apps.File {
	t.Helper()
	f, err := apps.Load(s.appsStatePath(), s.clock())
	if err != nil {
		t.Fatal(err)
	}
	return f
}

type exposureAppRow struct {
	Port    int    `json:"port"`
	Reach   string `json:"reach"`
	Pending string `json:"pending"`
	App     *struct {
		Key, Title, State, Mode string
		Open                    bool
	} `json:"app"`
}

func exposureRow(t *testing.T, s *Server, port int) exposureAppRow {
	t.Helper()
	w := do(s, http.MethodGet, "/api/exposure", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("exposure: HTTP %d %s", w.Code, w.Body.String())
	}
	var rows []exposureAppRow
	if err := json.Unmarshal(w.Body.Bytes(), &rows); err != nil {
		t.Fatal(err)
	}
	for _, r := range rows {
		if r.Port == port {
			return r
		}
	}
	t.Fatalf("port %d not in exposure", port)
	return exposureAppRow{}
}

const lan8080 = "-s 192.0.2.0/24 -p tcp -m conntrack --ctorigdstport 8080 -j ACCEPT"

func TestSyncAppsOpensANewPortToTheLAN(t *testing.T) {
	s, fw, _ := appsFixture(t)
	if err := s.SyncApps(context.Background()); err != nil {
		t.Fatal(err)
	}
	f := appsState(t, s)
	if len(f.Entries) != 1 || f.Entries[0].State != apps.Pending || f.Entries[0].Title != "Web App" {
		t.Fatalf("want one pending entry titled Web App, got %+v", f.Entries)
	}
	if !strings.Contains(appsScriptOf(t, s), lan8080) {
		t.Errorf("apps.sh lacks the LAN line:\n%s", appsScriptOf(t, s))
	}
	if fw.appsCalls != 1 {
		t.Errorf("engine apps runs: %d, want 1", fw.appsCalls)
	}
	// Nothing changed: the engine is not run again.
	if err := s.SyncApps(context.Background()); err != nil {
		t.Fatal(err)
	}
	if fw.appsCalls != 1 {
		t.Errorf("unchanged state re-ran the engine: %d calls", fw.appsCalls)
	}
	row := exposureRow(t, s, 8080)
	if row.Reach != "lan" || row.Pending != "app-decision" || row.App == nil || row.App.Title != "Web App" || !row.App.Open {
		t.Errorf("exposure row: %+v app=%+v", row, row.App)
	}
}

func TestDecideAnswersBecomeRules(t *testing.T) {
	s, _, _ := appsFixture(t)
	if err := s.SyncApps(context.Background()); err != nil {
		t.Fatal(err)
	}
	key := appsState(t, s).Entries[0].Key

	for _, tc := range []struct {
		answer, action, source string
		line                   bool
	}{
		{"lan", "allow", "range", true},
		{"any", "allow", "any", true},
		{"block", "deny", "any", false},
	} {
		w := do(s, http.MethodPost, "/api/apps/decide", map[string]string{"key": key, "answer": tc.answer})
		if w.Code != http.StatusOK {
			t.Fatalf("%s: HTTP %d %s", tc.answer, w.Code, w.Body.String())
		}
		rs, err := rules.Load(s.rulesPath)
		if err != nil {
			t.Fatal(err)
		}
		var mine []rules.Rule
		for _, r := range rs.Rules {
			if r.Name == "Web App (port 8080)" {
				mine = append(mine, r)
			}
		}
		if len(mine) != 1 {
			t.Fatalf("%s: want exactly one rule for the port (answers replace), got %d", tc.answer, len(mine))
		}
		if mine[0].Action != tc.action || mine[0].Source.Type != tc.source || mine[0].Zone != "docker" {
			t.Errorf("%s: rule %+v", tc.answer, mine[0])
		}
		e := appsState(t, s).Entries[0]
		if string(e.State) != tc.answer || e.RuleID != mine[0].ID {
			t.Errorf("%s: entry %+v", tc.answer, e)
		}
		script := appsScriptOf(t, s)
		if has := strings.Contains(script, "--ctorigdstport 8080"); has != tc.line {
			t.Errorf("%s: app chain line present=%v, want %v\n%s", tc.answer, has, tc.line, script)
		}
		row := exposureRow(t, s, 8080)
		if row.Pending == "app-decision" {
			t.Errorf("%s: answered port still shows as awaiting a decision", tc.answer)
		}
	}
}

// Once the next apply carries the answer as a rule, the app chain lets go of
// it — otherwise a later edit of that rule would be hidden by the chain.
func TestAnsweredPortLeavesTheAppChainAfterApply(t *testing.T) {
	s, _, rs := appsFixture(t)
	_ = s.SyncApps(context.Background())
	key := appsState(t, s).Entries[0].Key
	if w := do(s, http.MethodPost, "/api/apps/decide", map[string]string{"key": key, "answer": "lan"}); w.Code != http.StatusOK {
		t.Fatalf("decide: %d %s", w.Code, w.Body.String())
	}
	saved, _ := rules.Load(s.rulesPath)
	markLive(t, s, saved, system.PublishedPorts{TCP: map[int]bool{8096: true, 8080: true}, UDP: map[int]bool{}})
	if err := s.SyncApps(context.Background()); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(appsScriptOf(t, s), "--ctorigdstport 8080") {
		t.Error("the applied rule carries the answer now; the app chain must drop it")
	}
	if row := exposureRow(t, s, 8080); row.Reach != "lan" {
		t.Errorf("still reachable from the LAN through the applied rule, got %+v", row)
	}
	_ = rs
}

func TestModeBlockKeepsPendingPortsClosed(t *testing.T) {
	s, _, _ := appsFixture(t)
	if w := do(s, http.MethodPost, "/api/apps", map[string]string{"mode": "block"}); w.Code != http.StatusOK {
		t.Fatalf("mode: %d %s", w.Code, w.Body.String())
	}
	if err := s.SyncApps(context.Background()); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(appsScriptOf(t, s), "--ctorigdstport 8080") {
		t.Error("block mode opened a pending port")
	}
	row := exposureRow(t, s, 8080)
	if row.Reach != "blocked" || row.Pending != "app-decision" || row.App == nil || row.App.Open {
		t.Errorf("block mode exposure row: %+v app=%+v", row, row.App)
	}
	w := do(s, http.MethodGet, "/api/apps", nil)
	if !strings.Contains(w.Body.String(), `"mode":"block"`) {
		t.Errorf("GET /api/apps: %s", w.Body.String())
	}
}

func TestAppsAPIRejectsBadInput(t *testing.T) {
	s, _, _ := appsFixture(t)
	_ = s.SyncApps(context.Background())
	key := appsState(t, s).Entries[0].Key
	cases := []struct {
		path string
		body any
		want int
	}{
		{"/api/apps/decide", map[string]string{"key": "nope", "answer": "lan"}, http.StatusNotFound},
		{"/api/apps/decide", map[string]string{"key": key, "answer": "pending"}, http.StatusBadRequest},
		{"/api/apps/decide", map[string]string{"key": key, "answer": "everyone"}, http.StatusBadRequest},
		{"/api/apps", map[string]string{"mode": "open"}, http.StatusBadRequest},
	}
	for _, c := range cases {
		if w := do(s, http.MethodPost, c.path, c.body); w.Code != c.want {
			t.Errorf("%s %v: HTTP %d, want %d (%s)", c.path, c.body, w.Code, c.want, w.Body.String())
		}
	}
	// a LAN answer without a configured LAN is refused, not saved as open
	rs, _ := rules.Load(s.rulesPath)
	rs.LAN = ""
	_ = rules.Save(s.rulesPath, rs)
	if w := do(s, http.MethodPost, "/api/apps/decide", map[string]string{"key": key, "answer": "lan"}); w.Code != http.StatusBadRequest {
		t.Errorf("lan answer without LAN: HTTP %d, want 400", w.Code)
	}
}

func TestAuditCountsAnAppChainPortAsOpen(t *testing.T) {
	s, _, rs := appsFixture(t)
	_ = s.SyncApps(context.Background())
	snap := s.liveSnapshot()
	pol := auditPolicy{saved: rulesPolicy{rs: rs}, live: snap, apps: s.appsOverlay(snap)}
	if !pol.DockerOpen(8080) {
		t.Error("a port the app chain admits is reachable — the audit must count it")
	}
	if pol.DockerOpen(8081) {
		t.Error("an unrelated port must stay closed")
	}
}

// An apply recreates the app chains empty (after a revert, or on the first
// apply of this version): the next sync must rewrite their content even
// though apps.sh did not change. And an engine run that found the chains
// missing must not count as done.
func TestAppChainsRewrittenAfterApplyAndWhenMissing(t *testing.T) {
	s, fw, _ := appsFixture(t)
	fw.appsOut = "[zfw] ZFW-APPS missing — apply once to create it"
	if err := s.SyncApps(context.Background()); err != nil {
		t.Fatal(err)
	}
	fw.appsOut = "[zfw] ZFW-APPS: 1"
	if err := s.SyncApps(context.Background()); err != nil {
		t.Fatal(err)
	}
	if fw.appsCalls != 2 {
		t.Fatalf("chains were missing on the first run: want a second engine run, got %d", fw.appsCalls)
	}
	if err := s.SyncApps(context.Background()); err != nil {
		t.Fatal(err)
	}
	if fw.appsCalls != 2 {
		t.Fatalf("nothing changed: want no third run, got %d", fw.appsCalls)
	}
	if w := do(s, http.MethodPost, "/api/apply", map[string]bool{"safe": true}); w.Code != http.StatusOK {
		t.Fatalf("apply: %d %s", w.Code, w.Body.String())
	}
	if err := s.SyncApps(context.Background()); err != nil {
		t.Fatal(err)
	}
	if fw.appsCalls != 3 {
		t.Fatalf("after an apply the chains must be rewritten, engine runs: %d", fw.appsCalls)
	}
}
