// Package handlers serves the zfw module HTTP API.
package handlers

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/chicohaager/zfw/internal/audit"
	"github.com/chicohaager/zfw/internal/buildinfo"
	"github.com/chicohaager/zfw/internal/compiler"
	"github.com/chicohaager/zfw/internal/conntrack"
	"github.com/chicohaager/zfw/internal/events"
	"github.com/chicohaager/zfw/internal/firewall"
	"github.com/chicohaager/zfw/internal/geo"
	"github.com/chicohaager/zfw/internal/peers"
	"github.com/chicohaager/zfw/internal/rules"
	"github.com/chicohaager/zfw/internal/system"
	"github.com/chicohaager/zfw/internal/update"
)

// maxGeoCountries caps how many distinct country geo-sets one rule set may
// reference — each triggers a synchronous download during recompile (ZFW-S4).
const maxGeoCountries = 40

// Firewall is the subset of *firewall.Manager that the HTTP handlers depend
// on. Defined here (the consumer side) so tests can pass a fake without
// needing real systemd / iptables, and so the rest of the firewall package
// stays free of test-only abstractions.
type Firewall interface {
	Status(ctx context.Context) firewall.Status
	LoadConfig() (firewall.Config, error)
	SaveConfig(firewall.Config) error
	Apply(ctx context.Context, safe bool) (string, error)
	Commit(ctx context.Context) (string, error)
	Revert(ctx context.Context) (string, error)
}

// Server holds the dependencies for the HTTP API.
type Server struct {
	mu           sync.Mutex // serialises apply/commit/revert/recompile
	auditMu      sync.Mutex // serialises audit-history reads/writes
	fw           Firewall
	rulesPath    string
	compiledPath string
	historyPath  string
	peersPath    string
	peerToken    string // shared secret for inbound /api/peers/receive; empty = disabled
	geo          *geo.Manager
	upd          *update.Checker // nil = self-update polling disabled
	httpClient   *http.Client    // reusable client for outbound peer pushes
	mutateRL     *rateBucket     // shared by all non-GET endpoints
}

// NewServer returns a Server. fw may be *firewall.Manager in production or
// any Firewall implementation in tests. historyPath may be "" to disable
// audit-finding history persistence. upd may be nil to disable
// self-update polling. peersPath may be "" to disable the leader-side
// /api/peers list+push endpoints; peerToken may be "" to disable the
// follower-side /api/peers/receive endpoint. The two are independent —
// a host can be a leader, a follower, both, or neither.
func NewServer(fw Firewall, rulesPath, compiledPath, geoDir, historyPath string, upd *update.Checker, peersPath, peerToken string) *Server {
	return &Server{
		fw:           fw,
		rulesPath:    rulesPath,
		compiledPath: compiledPath,
		historyPath:  historyPath,
		peersPath:    peersPath,
		peerToken:    peerToken,
		geo:          geo.New(geoDir),
		upd:          upd,
		httpClient:   peers.DefaultClient(),
		// Burst 10, sustained 1/s — a user clicking Safe-Apply repeatedly
		// passes the burst; a runaway script is throttled to one call/sec.
		mutateRL: newRateBucket(1, 10),
	}
}

// Recompile loads the rule set, ensures geo data for any country rules,
// resolves zones against live Docker ports and writes the engine's compiled
// ruleset script.
func (s *Server) Recompile(ctx context.Context) error {
	rs, err := rules.Load(s.rulesPath)
	if err != nil {
		return err
	}
	// Never compile unvalidated rules: the result is run as root by the engine.
	if err := rules.Validate(rs); err != nil {
		return fmt.Errorf("rule set invalid: %w", err)
	}
	ccSet := map[string]bool{}
	for _, r := range rs.Rules {
		if r.Source.Type == "country" {
			for _, cc := range rules.SplitCountries(r.Source.Value) {
				ccSet[strings.ToLower(cc)] = true
			}
		}
	}
	if len(ccSet) > maxGeoCountries {
		return fmt.Errorf("too many countries (%d) — at most %d geo sets", len(ccSet), maxGeoCountries)
	}
	geoFiles := map[string]string{}
	if len(ccSet) > 0 {
		codes := make([]string, 0, len(ccSet))
		for cc := range ccSet {
			codes = append(codes, cc)
		}
		if err := s.geo.Ensure(ctx, codes, nil); err != nil {
			return err
		}
		for cc := range ccSet {
			geoFiles[cc] = s.geo.IpsetPath(cc)
		}
	}
	script := compiler.Compile(rs, system.DockerPorts(ctx), geoFiles)
	// 0600: the compiled script is executed as root — keep it owner-only.
	return os.WriteFile(s.compiledPath, []byte(script), 0o600)
}

// Routes returns the API mux.
func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/health", s.health)
	mux.HandleFunc("/api/status", s.status)
	mux.HandleFunc("/api/config", s.config)
	mux.HandleFunc("/api/rules", s.rateLimited(s.rules))
	mux.HandleFunc("/api/rules/defaults", s.rateLimited(s.rulesDefaults))
	mux.HandleFunc("/api/rules/templates", s.rulesTemplates)
	mux.HandleFunc("/api/apply", s.rateLimited(s.apply))
	mux.HandleFunc("/api/commit", s.rateLimited(s.commit))
	mux.HandleFunc("/api/revert", s.rateLimited(s.revert))
	mux.HandleFunc("/api/exposure", s.exposure)
	mux.HandleFunc("/api/audit", s.auditHandler)
	mux.HandleFunc("/api/versions", s.versions)
	mux.HandleFunc("/api/update", s.updateStatus)
	mux.HandleFunc("/api/peers", s.peersList)
	mux.HandleFunc("/api/peers/push", s.rateLimited(s.peersPush))
	mux.HandleFunc("/api/peers/receive", s.peersReceive)
	mux.HandleFunc("/api/geo/lookup", s.geoLookup)
	mux.HandleFunc("/api/events", s.events)
	mux.HandleFunc("/api/conntrack", s.conntrack)
	mux.HandleFunc("/api/openapi.json", s.openapi)
	mux.HandleFunc("/api/openapi.yaml", s.openapi)
	return mux
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func fail(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

func reqCtx() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 90*time.Second)
}

func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "version": buildinfo.Version})
}

// openapiSpec is embedded at compile time so the daemon serves its own
// OpenAPI 3.0 contract under /api/openapi.{json,yaml} without depending on
// a file shipped next to the binary. Source: docs/openapi.yaml in the repo.
//
//go:embed openapi.yaml
var openapiSpec []byte

// openapi serves the embedded spec. Both /api/openapi.json and
// /api/openapi.yaml return the same bytes (the file is YAML; OpenAPI tools
// accept the JSON URL because YAML is a JSON superset for the relevant
// constructs).
func (s *Server) openapi(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		fail(w, http.StatusMethodNotAllowed, "GET required")
		return
	}
	w.Header().Set("Content-Type", "application/yaml; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(openapiSpec)
}

func (s *Server) status(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := reqCtx()
	defer cancel()
	st := s.fw.Status(ctx)
	cfg, err := s.fw.LoadConfig()
	if err != nil {
		cfg = firewall.Config{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"version":  buildinfo.Version,
		"firewall": st,
		"config":   cfg,
	})
}

// config is the legacy v0.1 tier endpoint, kept until the UI moves to rules.
func (s *Server) config(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		fail(w, http.StatusMethodNotAllowed, "POST required")
		return
	}
	var c firewall.Config
	if err := json.NewDecoder(r.Body).Decode(&c); err != nil {
		fail(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	if err := s.fw.SaveConfig(c); err != nil {
		fail(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "saved"})
}

// rules is the v0.2 rule-model endpoint: GET returns the rule set, POST
// validates, saves and recompiles it.
func (s *Server) rules(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		rs, err := rules.Load(s.rulesPath)
		if err != nil {
			// A fresh install has no rules.json yet — surface that as an
			// empty deny-default set so the UI renders "No rules yet"
			// instead of a red 500 error.
			if os.IsNotExist(err) {
				writeJSON(w, http.StatusOK, rules.RuleSet{DefaultPolicy: "deny"})
				return
			}
			fail(w, http.StatusInternalServerError, "load rules: "+err.Error())
			return
		}
		writeJSON(w, http.StatusOK, rs)
	case http.MethodPost:
		var rs rules.RuleSet
		if err := json.NewDecoder(r.Body).Decode(&rs); err != nil {
			fail(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
			return
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		if err := rules.Validate(rs); err != nil {
			fail(w, http.StatusBadRequest, err.Error())
			return
		}
		if err := rules.Save(s.rulesPath, rs); err != nil {
			fail(w, http.StatusInternalServerError, "save: "+err.Error())
			return
		}
		ctx, cancel := reqCtx()
		defer cancel()
		if err := s.Recompile(ctx); err != nil {
			fail(w, http.StatusInternalServerError, "compile: "+err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "saved"})
	default:
		fail(w, http.StatusMethodNotAllowed, "GET or POST")
	}
}

// rulesDefaults regenerates and persists the recommended starter rule set
// (auto-detected LAN, deny-default plus the five allow rules from
// rules.Defaults). Drives the UI's "Apply recommended defaults" button —
// the user must still click Safe-Apply on the Firewall tab to deploy them,
// so the 120 s dead-man timer remains the last line of defence.
func (s *Server) rulesDefaults(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		fail(w, http.StatusMethodNotAllowed, "POST required")
		return
	}
	ctx, cancel := reqCtx()
	defer cancel()
	lan, hostIP := system.DetectLAN()
	dp := system.DockerPorts(ctx)
	rs := rules.Defaults(lan, hostIP, dp)
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := rules.Save(s.rulesPath, rs); err != nil {
		fail(w, http.StatusInternalServerError, "save: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, rs)
}

// rulesTemplates serves the curated rule-template catalog. Read-only
// and idempotent, so it sits outside the mutate rate-limit. The LAN
// substituted into each template comes from rules.json's current `lan`
// field, falling back to system.DetectLAN() so a fresh install still
// produces useful template rules instead of empty placeholders.
func (s *Server) rulesTemplates(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		fail(w, http.StatusMethodNotAllowed, "GET required")
		return
	}
	lan := ""
	if rs, err := rules.Load(s.rulesPath); err == nil {
		lan = rs.LAN
	}
	if lan == "" {
		lan, _ = system.DetectLAN()
	}
	writeJSON(w, http.StatusOK, rules.Templates(lan))
}

func (s *Server) apply(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		fail(w, http.StatusMethodNotAllowed, "POST required")
		return
	}
	var body struct {
		Safe bool `json:"safe"`
	}
	// A malformed body must not silently fall back to safe=false — that would
	// apply rules without the 120s dead-man (ZFW-S3). An empty body (EOF) is
	// allowed and keeps the default.
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil && err != io.EOF {
		fail(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	ctx, cancel := reqCtx()
	defer cancel()
	// Recompile so the engine applies the current rule set.
	if err := s.Recompile(ctx); err != nil {
		if os.IsNotExist(err) {
			// Fresh install: rules.json does not exist yet. Don't surface
			// the raw file-not-found error — tell the user what to do.
			fail(w, http.StatusBadRequest, "no rules saved yet — open the Rules tab, add a rule and click Save")
			return
		}
		fail(w, http.StatusInternalServerError, "compile: "+err.Error())
		return
	}
	out, err := s.fw.Apply(ctx, body.Safe)
	if err != nil {
		fail(w, http.StatusInternalServerError, "apply: "+err.Error()+"\n"+out)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "applied", "output": out})
}

func (s *Server) commit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		fail(w, http.StatusMethodNotAllowed, "POST required")
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	ctx, cancel := reqCtx()
	defer cancel()
	out, err := s.fw.Commit(ctx)
	if err != nil {
		fail(w, http.StatusInternalServerError, "commit: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "committed", "output": out})
}

func (s *Server) revert(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		fail(w, http.StatusMethodNotAllowed, "POST required")
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	ctx, cancel := reqCtx()
	defer cancel()
	out, err := s.fw.Revert(ctx)
	if err != nil {
		fail(w, http.StatusInternalServerError, "revert: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "reverted", "output": out})
}

// events returns the recent firewall DROP events parsed from the kernel
// log. Defaults: last hour, up to 200 entries, newest-first. Query
// parameters `since` (unix seconds) and `limit` override these.
func (s *Server) events(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		fail(w, http.StatusMethodNotAllowed, "GET required")
		return
	}
	since := time.Now().Add(-1 * time.Hour)
	if v := r.URL.Query().Get("since"); v != "" {
		if ts, err := strconv.ParseInt(v, 10, 64); err == nil {
			since = time.Unix(ts, 0)
		}
	}
	limit := 200
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 5000 {
			limit = n
		}
	}
	ctx, cancel := reqCtx()
	defer cancel()
	evs, err := events.Read(ctx, since, limit)
	if err != nil {
		fail(w, http.StatusInternalServerError, "events: "+err.Error())
		return
	}
	if evs == nil {
		evs = []events.Event{}
	}
	writeJSON(w, http.StatusOK, evs)
}

func (s *Server) exposure(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := reqCtx()
	defer cancel()
	socks, err := system.Listening(ctx)
	if err != nil {
		fail(w, http.StatusInternalServerError, "ss: "+err.Error())
		return
	}
	st := s.fw.Status(ctx)
	cfg, _ := s.fw.LoadConfig()
	tcpAllow := toSet(cfg.HostTCPLAN)
	dockerDrop := toSet(cfg.DockerDropLAN)

	type entry struct {
		system.Socket
		Reach string `json:"reach"`
	}
	out := make([]entry, 0, len(socks))
	for _, sk := range socks {
		reach := "lan"
		switch {
		case sk.Scope == "local":
			reach = "local"
		case st.Active && sk.Proc == "docker-proxy":
			if dockerDrop[strconv.Itoa(sk.Port)] {
				reach = "blocked"
			}
		case st.Active:
			if !tcpAllow[strconv.Itoa(sk.Port)] {
				reach = "blocked"
			}
		}
		out = append(out, entry{Socket: sk, Reach: reach})
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) auditHandler(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := reqCtx()
	defer cancel()
	st := s.fw.Status(ctx)
	cfg, _ := s.fw.LoadConfig()
	findings := audit.Findings(st, cfg)

	// Load + update the audit-finding history under a dedicated mutex
	// so concurrent /api/audit requests don't race the file. When
	// historyPath is empty (tests pass ""), skip persistence — the
	// response still carries an empty history slice per finding so
	// the UI's iteration code never crashes on a missing field.
	var hist audit.History
	if s.historyPath != "" {
		s.auditMu.Lock()
		defer s.auditMu.Unlock()
		loaded, err := audit.LoadHistory(s.historyPath)
		if err != nil {
			fail(w, http.StatusInternalServerError, "load history: "+err.Error())
			return
		}
		hist = loaded
		if hist.Update(findings, time.Now()) {
			if err := audit.SaveHistory(s.historyPath, hist); err != nil {
				fail(w, http.StatusInternalServerError, "save history: "+err.Error())
				return
			}
		}
	} else {
		hist = audit.History{}
	}

	// Normalise nil history slices to empty arrays so the UI's
	// `for (const e of f.history)` never iterates `null`.
	out := hist.Attach(findings)
	for i := range out {
		if out[i].History == nil {
			out[i].History = []audit.HistoryEntry{}
		}
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) versions(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := reqCtx()
	defer cancel()
	writeJSON(w, http.StatusOK, system.Versions(ctx))
}

// conntrack returns a snapshot of the kernel's live connection-
// tracking table (v0.5.0). Cap at 500 entries — a busy host can hold
// 100k+ active flows and the UI table doesn't render that many usefully
// anyway. Returns 200 with an empty array when the kernel module is
// absent or `/proc/net/nf_conntrack` is unreadable; the conntrack
// package returns an error in that case, but the UI's "no
// connections" branch already handles an empty array, so swallowing
// the error keeps the tab quiet on hosts without conntrack support.
func (s *Server) conntrack(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		fail(w, http.StatusMethodNotAllowed, "GET required")
		return
	}
	ctx, cancel := reqCtx()
	defer cancel()
	entries, err := conntrack.Read(ctx, 500)
	if err != nil || entries == nil {
		entries = []conntrack.Entry{}
	}
	writeJSON(w, http.StatusOK, entries)
}

// peersList returns the configured peer list with tokens stripped so a
// compromised UI session cannot exfiltrate them. Empty list (or
// missing peers.json) is the normal opt-out state — the UI hides
// the push button when the array is empty.
func (s *Server) peersList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		fail(w, http.StatusMethodNotAllowed, "GET required")
		return
	}
	if s.peersPath == "" {
		writeJSON(w, http.StatusOK, []peers.Public{})
		return
	}
	ps, err := peers.Load(s.peersPath)
	if err != nil {
		fail(w, http.StatusInternalServerError, "load peers: "+err.Error())
		return
	}
	out := peers.Sanitize(ps)
	if out == nil {
		out = []peers.Public{}
	}
	writeJSON(w, http.StatusOK, out)
}

// peersPush sends the current saved rules.json to every configured peer
// via its /api/peers/receive endpoint. Returns one Result per peer (in
// the same order as peers.json) so the UI can render successes and
// failures side by side. Reads rules.json off disk — pushes what is
// saved, not whatever the caller posts, so a peer can never end up
// with a different rule set than the local one.
func (s *Server) peersPush(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		fail(w, http.StatusMethodNotAllowed, "POST required")
		return
	}
	if s.peersPath == "" {
		writeJSON(w, http.StatusOK, []peers.Result{})
		return
	}
	ps, err := peers.Load(s.peersPath)
	if err != nil {
		fail(w, http.StatusInternalServerError, "load peers: "+err.Error())
		return
	}
	if len(ps) == 0 {
		writeJSON(w, http.StatusOK, []peers.Result{})
		return
	}
	rs, err := rules.Load(s.rulesPath)
	if err != nil {
		fail(w, http.StatusBadRequest, "no rules saved yet — open the Rules tab, add a rule and click Save")
		return
	}
	body, err := json.Marshal(rs)
	if err != nil {
		fail(w, http.StatusInternalServerError, "marshal rules: "+err.Error())
		return
	}
	ctx, cancel := reqCtx()
	defer cancel()
	results := peers.Push(ctx, s.httpClient, ps, body)
	writeJSON(w, http.StatusOK, results)
}

// peersReceive accepts an inbound rule push from a leader. Authentication
// is a shared bearer (s.peerToken); ZimaOS-session JWT is bypassed for
// this route in main.go's middleware wiring. When peerToken is empty,
// the endpoint is disabled — the host is not configured to act as a
// follower and returns 403 unconditionally.
func (s *Server) peersReceive(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		fail(w, http.StatusMethodNotAllowed, "POST required")
		return
	}
	if s.peerToken == "" {
		fail(w, http.StatusForbidden, "peer-receive disabled (ZFW_PEER_TOKEN unset)")
		return
	}
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") || auth[len("Bearer "):] != s.peerToken {
		fail(w, http.StatusUnauthorized, "invalid peer token")
		return
	}
	var rs rules.RuleSet
	if err := json.NewDecoder(r.Body).Decode(&rs); err != nil {
		fail(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	if err := rules.Validate(rs); err != nil {
		fail(w, http.StatusBadRequest, err.Error())
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := rules.Save(s.rulesPath, rs); err != nil {
		fail(w, http.StatusInternalServerError, "save: "+err.Error())
		return
	}
	ctx, cancel := reqCtx()
	defer cancel()
	if err := s.Recompile(ctx); err != nil {
		fail(w, http.StatusInternalServerError, "compile: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "received", "rules": fmt.Sprintf("%d", len(rs.Rules))})
}

// geoLookup turns a comma-separated `ips` query parameter into a
// {ip: country} map. Reuses the geo manager's cached .zone files —
// no extra network calls, no extra deps. An IP outside every cached
// CIDR maps to "" (the UI then silently hides its flag). Empty query
// returns {}. GET-only and read-only so it sits outside the mutate
// rate-limit. v0.4.5.
func (s *Server) geoLookup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		fail(w, http.StatusMethodNotAllowed, "GET required")
		return
	}
	raw := r.URL.Query().Get("ips")
	if raw == "" {
		writeJSON(w, http.StatusOK, map[string]string{})
		return
	}
	// Cap the input fan-out to keep the linear-scan lookup cheap. A
	// typical Events tab refresh has <100 unique source IPs; 500 is
	// comfortable headroom and bounds a crafted query.
	ips := strings.Split(raw, ",")
	if len(ips) > 500 {
		ips = ips[:500]
	}
	writeJSON(w, http.StatusOK, s.geo.LookupBatch(ips))
}

// updateStatus returns the cached self-update check result so the UI can
// render a "vX available" badge without doing its own HTTP. A nil
// checker (disabled) still returns 200 — the response just carries
// only the current version so the UI code path is the same.
func (s *Server) updateStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		fail(w, http.StatusMethodNotAllowed, "GET required")
		return
	}
	if s.upd == nil {
		writeJSON(w, http.StatusOK, update.Status{Current: buildinfo.Version})
		return
	}
	writeJSON(w, http.StatusOK, s.upd.Snapshot())
}

func toSet(xs []string) map[string]bool {
	m := make(map[string]bool, len(xs))
	for _, x := range xs {
		m[x] = true
	}
	return m
}
