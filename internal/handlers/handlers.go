// Package handlers serves the zfw module HTTP API.
package handlers

import (
	"context"
	"crypto/subtle"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
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
	"github.com/chicohaager/zfw/internal/notify"
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
	peerToken    string   // shared secret for inbound /api/peers/receive; empty = disabled
	extraBypass  []string // v0.5.4 — extra inbound-bypass iface names appended to every chain
	geo          *geo.Manager
	upd          *update.Checker // nil = self-update polling disabled
	hook         *notify.Hook    // v0.5.5 — nil = webhook disabled
	httpClient   *http.Client    // reusable client for outbound peer pushes
	mutateRL     *rateBucket     // shared by all non-GET endpoints
	// readRL caps expensive GET endpoints (exposure, events, conntrack,
	// versions) that shell out to ss / journalctl / docker / sshd. An
	// authenticated user could otherwise flood them and CPU-pin the
	// daemon (R3-5). Burst 60 / sustained 5/s comfortably covers
	// normal browser refresh + dashboard polling on a multi-tab UI
	// session while capping abusive flooding. /api/health stays
	// uncapped (liveness probe).
	readRL *rateBucket
}

// NewServer returns a Server. fw may be *firewall.Manager in production or
// any Firewall implementation in tests. historyPath may be "" to disable
// audit-finding history persistence. upd may be nil to disable
// self-update polling. peersPath may be "" to disable the leader-side
// /api/peers list+push endpoints; peerToken may be "" to disable the
// follower-side /api/peers/receive endpoint. The two are independent —
// a host can be a leader, a follower, both, or neither.
func NewServer(fw Firewall, rulesPath, compiledPath, geoDir, historyPath string, upd *update.Checker, peersPath, peerToken string, extraBypass []string, hook *notify.Hook) *Server {
	return &Server{
		fw:           fw,
		rulesPath:    rulesPath,
		compiledPath: compiledPath,
		historyPath:  historyPath,
		peersPath:    peersPath,
		peerToken:    peerToken,
		extraBypass:  extraBypass,
		geo:          geo.New(geoDir),
		upd:          upd,
		hook:         hook,
		httpClient:   peers.DefaultClient(),
		// Burst 10, sustained 1/s — a user clicking Safe-Apply repeatedly
		// passes the burst; a runaway script is throttled to one call/sec.
		mutateRL: newRateBucket(1, 10),
		// Burst 60, sustained 5/s — see Server.readRL field doc above.
		readRL: newRateBucket(5, 60),
	}
}

// emitEvent fires a webhook with the given type + details. Fire-and-
// forget — the daemon must not block on or fail because of webhook
// delivery (config option, best-effort signal). v0.5.5.
func (s *Server) emitEvent(typ string, details map[string]any) {
	s.hook.SendAsync(notify.Event{
		Type:      typ,
		Version:   buildinfo.Version,
		Timestamp: time.Now().UTC(),
		Details:   details,
	})
}

// Recompile loads the rule set, ensures geo data for any country rules,
// resolves zones against live Docker ports and writes the engine's compiled
// ruleset script.
//
// CQ-9 (v1.0.2): the slow external IO (DockerContainers, DockerPorts,
// geo.Ensure downloads) runs BEFORE the per-server mutex is acquired so
// concurrent callers no longer block one another for the full 20-minute
// worst-case of a 40-country geo refresh. Recompile takes s.mu itself
// for the rules.Load + Validate + compile + write step. Callers must
// NOT hold s.mu when calling Recompile (the lock is non-reentrant —
// re-acquiring s.mu would deadlock). Mutating handlers that already
// hold s.mu do the prefetch themselves via prefetchForCompile, then
// call recompileLocked under their existing lock.
func (s *Server) Recompile(ctx context.Context) error {
	containers, dockerPorts, err := s.prefetchForCompile(ctx, nil)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.recompileLocked(containers, dockerPorts)
}

// prefetchForCompile does the slow external IO that recompile needs
// (Docker container inventory, host-published port map, geo downloads
// for any country sources in the current rule set). Safe to call
// without s.mu — it talks to docker / ss / disk-cached geo files only.
// Returns the prefetched containers + dockerPorts so the caller can
// hand them to recompileLocked without re-querying. The optional
// rsHint lets a caller pass a not-yet-saved rule set so the geo
// prefetch covers the about-to-be-saved country codes; passing nil
// reads the current rules.json from disk for the geo plan.
func (s *Server) prefetchForCompile(ctx context.Context, rsHint *rules.RuleSet) ([]system.DockerContainer, map[int]bool, error) {
	containers := system.DockerContainers(ctx)
	dockerPorts := system.DockerPorts(ctx)

	var rs rules.RuleSet
	if rsHint != nil {
		rs = *rsHint
	} else {
		// A fresh install has no rules.json yet — geo prefetch in that
		// case is empty, which is fine. Surface any other read error so
		// the caller can fail loud.
		loaded, err := rules.Load(s.rulesPath)
		if err != nil && !os.IsNotExist(err) {
			return nil, nil, err
		}
		rs = loaded
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
		return nil, nil, fmt.Errorf("too many countries (%d) — at most %d geo sets", len(ccSet), maxGeoCountries)
	}
	if len(ccSet) > 0 {
		codes := make([]string, 0, len(ccSet))
		for cc := range ccSet {
			codes = append(codes, cc)
		}
		if err := s.geo.Ensure(ctx, codes, nil); err != nil {
			return nil, nil, err
		}
	}
	return containers, dockerPorts, nil
}

// recompileLocked does the fast lock-protected portion of Recompile:
// load rules.json, validate, substitute container-bound ports, run the
// compiler, write compiled.sh. Caller must already hold s.mu. Slow IO
// (Docker, geo downloads) is the caller's responsibility — pass live
// containers + dockerPorts maps and pre-warm s.geo if any country
// sources are in play. Used by both the unlocked-entry Recompile and
// by mutate handlers that hold s.mu across save+recompile.
func (s *Server) recompileLocked(containers []system.DockerContainer, dockerPorts map[int]bool) error {
	rs, err := rules.Load(s.rulesPath)
	if err != nil {
		return err
	}
	// Never compile unvalidated rules: the result is run as root by the engine.
	if err := rules.Validate(rs); err != nil {
		return fmt.Errorf("rule set invalid: %w", err)
	}
	// Per-container binding resolution (v0.5.7) — see Recompile doc.
	if len(containers) > 0 {
		byID := make(map[string][]int, len(containers))
		byName := make(map[string][]int, len(containers))
		for _, c := range containers {
			if c.ID != "" {
				byID[c.ID] = c.Ports
			}
			if c.Name != "" {
				byName[c.Name] = c.Ports
			}
		}
		// CQ-3: warn if a name doubles as some other container's ID
		// and the two would resolve to different ports.
		for _, c := range containers {
			if c.Name == "" {
				continue
			}
			if idPorts, ok := byID[c.Name]; ok && !portsEqual(idPorts, c.Ports) {
				slog.Warn("docker name collides with another container's ID",
					"name", c.Name, "id_ports", idPorts, "name_ports", c.Ports)
			}
		}
		for i := range rs.Rules {
			cid := rs.Rules[i].ContainerID
			if cid == "" {
				continue
			}
			ports, ok := byID[cid]
			if !ok {
				ports, ok = byName[cid]
			}
			if !ok || len(ports) == 0 {
				continue
			}
			rs.Rules[i].Ports = rules.Ports{Type: "list", List: ports}
		}
	}
	geoFiles := map[string]string{}
	for _, r := range rs.Rules {
		if r.Source.Type == "country" {
			for _, cc := range rules.SplitCountries(r.Source.Value) {
				lc := strings.ToLower(cc)
				geoFiles[lc] = s.geo.IpsetPath(lc)
			}
		}
	}
	script := compiler.Compile(rs, dockerPorts, geoFiles, s.extraBypass...)
	// 0600: the compiled script is executed as root — keep it owner-only.
	return os.WriteFile(s.compiledPath, []byte(script), 0o600)
}

// Routes returns the API mux.
func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/health", s.health)
	// status and audit both call fw.Status, which forks iptables /
	// ip6tables / systemctl subprocesses per call — same flood surface
	// as the R3-5 endpoints below, so they share the read limiter.
	mux.HandleFunc("/api/status", s.rateLimitedGet(s.status))
	mux.HandleFunc("/api/config", s.rateLimited(s.config))
	mux.HandleFunc("/api/rules", s.rateLimited(s.rules))
	mux.HandleFunc("/api/rules/defaults", s.rateLimited(s.rulesDefaults))
	mux.HandleFunc("/api/rules/templates", s.rulesTemplates)
	mux.HandleFunc("/api/apply", s.rateLimited(s.apply))
	mux.HandleFunc("/api/commit", s.rateLimited(s.commit))
	mux.HandleFunc("/api/revert", s.rateLimited(s.revert))
	// R3-5 (closed v1.0.2): endpoints that shell out to ss / journalctl /
	// docker / sshd / iptables, or do per-request linear scans, are
	// wrapped in the read-side rate limiter so an authenticated user
	// cannot flood them and CPU-pin the daemon. Cheap reads (peers
	// list, openapi, update snapshot, rules GET, templates) stay
	// uncapped — they hit memory + a small JSON encode at worst.
	mux.HandleFunc("/api/exposure", s.rateLimitedGet(s.exposure))
	mux.HandleFunc("/api/audit", s.rateLimitedGet(s.auditHandler))
	mux.HandleFunc("/api/versions", s.rateLimitedGet(s.versions))
	mux.HandleFunc("/api/update", s.updateStatus)
	mux.HandleFunc("/api/peers", s.peersList)
	mux.HandleFunc("/api/peers/push", s.rateLimited(s.peersPush))
	// peers/receive is JWT-exempt (peer-token auth) — the mutate
	// limiter also throttles online brute-forcing of ZFW_PEER_TOKEN.
	mux.HandleFunc("/api/peers/receive", s.rateLimited(s.peersReceive))
	mux.HandleFunc("/api/geo/lookup", s.rateLimitedGet(s.geoLookup))
	mux.HandleFunc("/api/events", s.rateLimitedGet(s.events))
	mux.HandleFunc("/api/conntrack", s.rateLimitedGet(s.conntrack))
	mux.HandleFunc("/api/system/containers", s.systemContainers)
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
		if err := rules.Validate(rs); err != nil {
			fail(w, http.StatusBadRequest, err.Error())
			return
		}
		ctx, cancel := reqCtx()
		defer cancel()
		// CQ-9: slow IO (docker inventory, geo downloads) happens
		// outside s.mu so a concurrent commit/revert is not blocked
		// behind a country-list refresh.
		containers, dockerPorts, err := s.prefetchForCompile(ctx, &rs)
		if err != nil {
			fail(w, http.StatusInternalServerError, "prepare: "+err.Error())
			return
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		if err := rules.Save(s.rulesPath, rs); err != nil {
			fail(w, http.StatusInternalServerError, "save: "+err.Error())
			return
		}
		if err := s.recompileLocked(containers, dockerPorts); err != nil {
			fail(w, http.StatusInternalServerError, "compile: "+err.Error())
			return
		}
		s.emitEvent("rules.saved", map[string]any{"rules": len(rs.Rules)})
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
	// R3-9 (v1.0.2): this endpoint overwrites the saved rule set with
	// the recommended defaults. The UI's JS confirms first, but a
	// direct curl/script call had no such gate. Require an explicit
	// `?confirm=1` query parameter so an automation written against
	// the API has to opt into the destructive behaviour rather than
	// stumble into it. The UI sends ?confirm=1.
	if r.URL.Query().Get("confirm") != "1" {
		fail(w, http.StatusBadRequest,
			"this overwrites your saved rules; pass ?confirm=1 to acknowledge")
		return
	}
	ctx, cancel := reqCtx()
	defer cancel()
	// CQ-8: prefer the user's saved LAN over a fresh DetectLAN —
	// multi-homed hosts where the kernel's default-route IP isn't the
	// LAN the operator cares about would otherwise have their
	// custom LAN overwritten by the "Recommended defaults" button.
	lan, hostIP := "", ""
	if existing, err := rules.Load(s.rulesPath); err == nil && existing.LAN != "" {
		lan, hostIP = existing.LAN, existing.HostIP
	} else {
		lan, hostIP = system.DetectLAN()
	}
	dp := system.DockerPorts(ctx)
	rs := rules.Defaults(lan, hostIP, dp)
	// CQ-2: mirror the rules POST contract — Validate before Save,
	// Recompile after, fire the webhook.
	if err := rules.Validate(rs); err != nil {
		fail(w, http.StatusInternalServerError, "defaults invalid: "+err.Error())
		return
	}
	// CQ-9: pre-resolve slow IO outside s.mu.
	containers, dockerPorts, err := s.prefetchForCompile(ctx, &rs)
	if err != nil {
		fail(w, http.StatusInternalServerError, "prepare: "+err.Error())
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := rules.Save(s.rulesPath, rs); err != nil {
		fail(w, http.StatusInternalServerError, "save: "+err.Error())
		return
	}
	if err := s.recompileLocked(containers, dockerPorts); err != nil {
		fail(w, http.StatusInternalServerError, "compile: "+err.Error())
		return
	}
	s.emitEvent("rules.defaulted", map[string]any{"rules": len(rs.Rules)})
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
	ctx, cancel := reqCtx()
	defer cancel()
	// CQ-9: slow IO outside s.mu so a concurrent operator click on
	// commit/revert is not blocked behind docker ps + geo Ensure.
	containers, dockerPorts, err := s.prefetchForCompile(ctx, nil)
	if err != nil {
		if os.IsNotExist(err) {
			fail(w, http.StatusBadRequest, "no rules saved yet — open the Rules tab, add a rule and click Save")
			return
		}
		fail(w, http.StatusInternalServerError, "prepare: "+err.Error())
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	// Recompile so the engine applies the current rule set.
	if err := s.recompileLocked(containers, dockerPorts); err != nil {
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
	s.emitEvent("firewall.applied", map[string]any{"safe": body.Safe})
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
	s.emitEvent("firewall.committed", nil)
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
	s.emitEvent("firewall.reverted", nil)
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
	// Floor the window: ?since=0 would otherwise make events.Read parse
	// the entire retained kernel journal into RAM before `limit` applies.
	if floor := time.Now().Add(-7 * 24 * time.Hour); since.Before(floor) {
		since = floor
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

// systemContainers returns the live Docker container inventory used
// by the rule editor's container-binding picker (v0.5.7). Empty list
// on hosts without docker or in test envs — UI handles the empty
// case (the container picker shows "no containers detected").
func (s *Server) systemContainers(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		fail(w, http.StatusMethodNotAllowed, "GET required")
		return
	}
	ctx, cancel := reqCtx()
	defer cancel()
	cs := system.DockerContainers(ctx)
	if cs == nil {
		cs = []system.DockerContainer{}
	}
	writeJSON(w, http.StatusOK, cs)
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
	// CQ-6 (closed v1.0.2): peersPush was the only lifecycle handler
	// that did not fire a webhook on completion. Operators wiring n8n /
	// Home Assistant to ZFW events otherwise had no signal that a
	// rule-set distribution had happened — and crucially no signal when
	// some followers failed (ok=false). The event carries the totals so
	// the receiver does not need to walk the Results array.
	okN, failN := 0, 0
	for _, r := range results {
		if r.OK {
			okN++
		} else {
			failN++
		}
	}
	s.emitEvent("peers.pushed", map[string]any{
		"peers": len(ps),
		"ok":    okN,
		"fail":  failN,
	})
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
	// R4-2: constant-time compare against the shared bearer token —
	// non-constant `!=` short-circuits on the first byte mismatch and
	// leaks token length / common-prefix length by timing. Length
	// match check happens first (cheap and not timing-sensitive
	// because token length is operator-set and not secret-by-itself).
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") {
		fail(w, http.StatusUnauthorized, "invalid peer token")
		return
	}
	provided := auth[len("Bearer "):]
	if len(provided) != len(s.peerToken) ||
		subtle.ConstantTimeCompare([]byte(provided), []byte(s.peerToken)) != 1 {
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
	ctx, cancel := reqCtx()
	defer cancel()
	// CQ-9: pre-resolve slow IO before taking the lock.
	containers, dockerPorts, err := s.prefetchForCompile(ctx, &rs)
	if err != nil {
		fail(w, http.StatusInternalServerError, "prepare: "+err.Error())
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := rules.Save(s.rulesPath, rs); err != nil {
		fail(w, http.StatusInternalServerError, "save: "+err.Error())
		return
	}
	if err := s.recompileLocked(containers, dockerPorts); err != nil {
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

// portsEqual reports whether two int slices represent the same set of
// host-published ports. Both inputs come from system.DockerContainers,
// which already sorts and de-duplicates them, so a straight element-
// wise compare is sufficient (no sort needed). Used by Recompile to
// gate the name/ID collision warning (CQ-3).
func portsEqual(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
