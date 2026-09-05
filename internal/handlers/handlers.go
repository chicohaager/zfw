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
	"path/filepath"
	"sort"
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
	mutateRL     *keyedLimiter   // shared by all non-GET endpoints
	// readRL caps expensive GET endpoints (exposure, events, conntrack,
	// versions) that shell out to ss / journalctl / docker / sshd. An
	// authenticated user could otherwise flood them and CPU-pin the
	// daemon (R3-5). Burst 60 / sustained 5/s comfortably covers
	// normal browser refresh + dashboard polling on a multi-tab UI
	// session while capping abusive flooding. /api/health stays
	// uncapped (liveness probe). Both limiters key per client (R3-6)
	// with a global aggregate ceiling as the evasion-proof backstop.
	readRL *keyedLimiter
	// logLevel, when set via SetLogLevel, lets /api/debug flip the
	// daemon's slog level at runtime so an operator can surface the
	// slog.Debug diagnostics (e.g. journalctl failures in events.Read)
	// without restarting the daemon. nil = the endpoint reports the
	// feature unavailable. v1.0.13.
	logLevel *slog.LevelVar
	// dockerPorts / dockerContainers are the live-inventory probes, injected
	// so the compile guards can be tested against an unreachable docker daemon
	// without one (and so the suite never depends on the build host's docker).
	// Default to the real system probes in NewServer.
	dockerPorts      func(context.Context) (system.PublishedPorts, error)
	dockerContainers func(context.Context) ([]system.DockerContainer, error)
	// listening is the host socket probe behind /api/exposure, injected for
	// the same reason: the reach verdicts can then be tested against a fixed
	// socket list instead of whatever the build host happens to listen on.
	listening func(context.Context) ([]system.Socket, error)

	// lastCompiled is the (binding-resolved) rule set the most recent
	// recompileLocked produced; lastApplied is the one the last successful
	// apply pushed live. Their diff (rules.NewlyBlocked) drives the post-apply
	// conntrack flush, so a port the operator just switched from allow to deny
	// has its established connections torn down at once instead of surviving on
	// the ESTABLISHED,RELATED fast-path. Both are guarded by mu. v1.0.21.
	lastCompiled rules.RuleSet
	lastApplied  rules.RuleSet
}

// SetLogLevel wires the daemon's runtime log-level control into the
// /api/debug endpoint. Call once after NewServer with the same
// *slog.LevelVar the slog handler was built with.
func (s *Server) SetLogLevel(lv *slog.LevelVar) { s.logLevel = lv }

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
		// Per client: burst 10, sustained 1/s — a user clicking
		// Safe-Apply repeatedly passes the burst; a runaway script is
		// throttled to one call/sec. Aggregate ceiling burst 30, 3/s
		// covers a few simultaneous clients but caps total throughput
		// so a key-rotating flood cannot evade the limit.
		mutateRL: newKeyedLimiter(1, 10, 3, 30),
		// Per client burst 60 / 5/s (see readRL field doc); aggregate
		// burst 180 / 15/s as the shared ceiling.
		readRL:           newKeyedLimiter(5, 60, 15, 180),
		dockerPorts:      system.DockerPorts,
		dockerContainers: system.DockerContainers,
		listening:        system.Listening,
	}
}

// rulesPolicy answers the Exposure/Audit reachability questions from the rule
// model — the file the firewall is compiled from. See rules.Disposition for
// the matching semantics and for why the legacy allowlist.conf was the wrong
// oracle.
type rulesPolicy struct{ rs rules.RuleSet }

func (p rulesPolicy) HostOpen(port int) bool {
	return rules.Disposition(p.rs, "host", "tcp", port) == "allow"
}

func (p rulesPolicy) DockerOpen(port int) bool {
	return rules.Disposition(p.rs, "docker", "tcp", port) == "allow"
}

// portPolicy returns the reachability oracle for the dashboard views.
// rules.json wins whenever it exists; a host that still only has the legacy
// allowlist.conf (pre-migration) falls back to it, and a host with neither
// gets an empty rule set — deny-default, which is also what such a host would
// compile to.
func (s *Server) portPolicy() audit.PortPolicy {
	rs, err := rules.Load(s.rulesPath)
	if err == nil {
		return rulesPolicy{rs}
	}
	if !os.IsNotExist(err) {
		slog.Warn("dashboard reach verdicts: rules.json unreadable, falling back to allowlist.conf", "err", err)
	}
	if cfg, cerr := s.fw.LoadConfig(); cerr == nil {
		return legacyPolicy{cfg}
	}
	return rulesPolicy{rules.RuleSet{DefaultPolicy: "deny"}}
}

// legacyPolicy is the allowlist.conf reading, kept only for hosts that have
// not migrated to rules.json yet.
type legacyPolicy struct{ cfg firewall.Config }

func (p legacyPolicy) HostOpen(port int) bool {
	return toSet(p.cfg.HostTCPLAN)[strconv.Itoa(port)]
}

func (p legacyPolicy) DockerOpen(port int) bool {
	return !toSet(p.cfg.DockerDropLAN)[strconv.Itoa(port)]
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
func (s *Server) prefetchForCompile(ctx context.Context, rsHint *rules.RuleSet) ([]system.DockerContainer, system.PublishedPorts, error) {
	// An unreadable docker inventory is carried through as
	// PublishedPorts.SourceErr rather than swallowed into an empty port set:
	// recompileLocked refuses to scope a default-deny by a port set it does not
	// actually know. It is not fatal here, because a host with no Docker at all
	// must still be able to compile its host rules.
	containers, cErr := s.dockerContainers(ctx)
	if cErr != nil {
		slog.Warn("docker container inventory unreadable — container-bound rules fall back to their saved ports", "err", cErr)
	}
	dockerPorts, ppErr := s.dockerPorts(ctx)
	if ppErr != nil {
		slog.Error("docker published-port inventory unreadable", "err", ppErr)
	}

	var rs rules.RuleSet
	if rsHint != nil {
		rs = *rsHint
	} else {
		// A fresh install has no rules.json yet — geo prefetch in that
		// case is empty, which is fine. Surface any other read error so
		// the caller can fail loud.
		loaded, err := rules.Load(s.rulesPath)
		if err != nil && !os.IsNotExist(err) {
			return nil, system.PublishedPorts{}, err
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
		return nil, system.PublishedPorts{}, fmt.Errorf("too many countries (%d) — at most %d geo sets", len(ccSet), maxGeoCountries)
	}
	if len(ccSet) > 0 {
		codes := make([]string, 0, len(ccSet))
		for cc := range ccSet {
			codes = append(codes, cc)
		}
		if err := s.geo.Ensure(ctx, codes, nil); err != nil {
			return nil, system.PublishedPorts{}, err
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
func (s *Server) recompileLocked(containers []system.DockerContainer, dockerPorts system.PublishedPorts) error {
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
			// Both protocols: the substituted port list must cover everything
			// the container actually publishes. Keyed on c.Ports alone (TCP),
			// a rule bound to a container publishing e.g. 8181/tcp + 5514/udp
			// had its ports rewritten to just [8181] — so the UDP port lost its
			// allow rule and was silently dropped by the default-deny, on a rule
			// the UI promises "follows its container". Same UDP blind spot that
			// v1.0.17 closed in the port inventory, one layer up.
			ports := containerPorts(c)
			if c.ID != "" {
				byID[c.ID] = ports
			}
			if c.Name != "" {
				byName[c.Name] = ports
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
	// The DOCKER-USER default-deny is emitted once per published port, so an
	// unknown port inventory silently degrades "deny" to "allow everything that
	// reaches a container": no per-port deny rule is emitted, the chain is left
	// with nothing but its bypasses and a trailing RETURN, and the dashboard
	// still goes green. Refuse the compile instead — a firewall that cannot see
	// what it must protect has to say so, not guess "nothing".
	//
	// The predicate is "inventory unreadable", NOT "inventory empty". Those are
	// different hosts: `docker ps` succeeding with zero published ports is a
	// legitimate, fully-protected state (nothing to deny), while `docker ps`
	// failing means the port set is unknown. Until v1.0.20 this guard read
	// `!dockerPorts.Any() && len(containers) > 0` and only logged — so it stayed
	// silent in the one case that matters (a broken docker CLI returns *no*
	// containers, so `len(containers) > 0` was false), fired spuriously on hosts
	// whose containers publish no ports, and let the apply report success either
	// way. That is the "0 ctorigdstport in DOCKER-USER while the apply is green"
	// report from the field.
	if rs.DefaultPolicy == "deny" && dockerPorts.SourceErr != nil {
		return fmt.Errorf("docker published-port inventory unreadable — refusing to compile a "+
			"deny policy that would leave DOCKER-USER unscoped (every published container port "+
			"would stay reachable from any source): %w", dockerPorts.SourceErr)
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
	if err := writeScriptAtomic(s.compiledPath, script); err != nil {
		return err
	}
	// Also write the atomic-apply variant (B4) alongside compiled.sh so
	// switching the engine to ZFW_APPLY_MODE=restore needs no recompile.
	// Dormant until the engine opts in; a write failure here must not
	// fail the apply since the default bash path already succeeded.
	restoreScript := compiler.CompileRestoreScript(rs, dockerPorts, geoFiles, s.extraBypass...)
	if err := writeScriptAtomic(restorePathFor(s.compiledPath), restoreScript); err != nil {
		slog.Warn("write compiled.restore.sh (non-fatal — bash path is default)", "err", err)
	}
	// Record the binding-resolved rule set that backs the script just written,
	// so a subsequent apply can diff it against what is currently live and flush
	// conntrack for the ports that transitioned to denied (v1.0.21).
	s.lastCompiled = rs
	return nil
}

// writeScriptAtomic publishes a compiled script via tmp+rename so a reader
// never observes a half-written file. s.mu serialises the daemon's own
// compiles, but not the engine: zfw.service is PartOf=docker.service, so it
// re-runs `bash compiled.sh` on every dockerd restart — at the same moment
// dockerwatch sees that docker event and recompiles. A plain os.WriteFile
// truncates the very inode bash is reading, and a mid-line truncation is a
// syntax error: under `set -eu` the engine aborts, reverts, and the host is
// left with no firewall after a routine docker restart. rename(2) is atomic
// within a filesystem, so the engine sees either the old script or the new one.
//
// The tmp file is created 0600 (the script is executed as root, so it must
// never be group/world-writable — the engine's own secure_file check would
// refuse it, and rightly so) and lives in the same directory as the target so
// the rename stays within one filesystem.
func writeScriptAtomic(path, content string) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, filepath.Base(path)+".tmp*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp) // no-op once the rename below succeeded
	if err := f.Chmod(0o600); err != nil {
		f.Close()
		return err
	}
	if _, err := f.WriteString(content); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// restorePathFor derives the atomic-apply script path that sits next to
// compiled.sh (e.g. /DATA/zfw/compiled.sh -> /DATA/zfw/compiled.restore.sh).
func restorePathFor(compiledPath string) string {
	dir := filepath.Dir(compiledPath)
	base := filepath.Base(compiledPath)
	if ext := filepath.Ext(base); ext != "" {
		base = strings.TrimSuffix(base, ext) + ".restore" + ext
	} else {
		base += ".restore"
	}
	return filepath.Join(dir, base)
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
	mux.HandleFunc("/api/rules/v6", s.rateLimitedGet(s.rulesV6))
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
	mux.HandleFunc("/api/debug", s.rateLimited(s.debugLevel))
	// system/containers forks `docker ps` per call — same flood surface as the
	// R3-5 endpoints above, and the only shell-out GET that was missing the
	// read limiter. Uncapped, an authenticated session could loop it and fork
	// a docker CLI process per request until the daemon is CPU-pinned.
	mux.HandleFunc("/api/system/containers", s.rateLimitedGet(s.systemContainers))
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

// v6AuditResponse is the /api/rules/v6 payload: the compiler's own view of
// what the saved rule set does on IPv6, plus whether this host has an
// internet-routable IPv6 address at all.
//
// GlobalIPv6 is what keeps the UI warning honest in both directions. On an
// IPv4-only host a blind IPv6 chain is harmless and the banner would be
// noise; on a host with a global address it is the difference between "my
// rules say allow" and "every v6 client is being dropped".
type v6AuditResponse struct {
	compiler.V6Audit
	GlobalIPv6 bool `json:"global_ipv6"`
}

// rulesV6 reports IPv6 coverage for the saved rule set (v1.0.22). Read-only;
// it never touches the live firewall.
//
// It exists because the rule table cannot show this on its own: a rule reads
// "Allow 443" whether or not it reaches ip6tables, and until v1.0.22 the
// rules that did not reach it failed silently. The two ways a rule drops out
// are an IPv4 source (which has no ip6tables equivalent) and — before the
// portsForZone6 fix in this same release — a Docker-zone port.
func (s *Server) rulesV6(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		fail(w, http.StatusMethodNotAllowed, "GET required")
		return
	}
	rs, err := rules.Load(s.rulesPath)
	if err != nil {
		if !os.IsNotExist(err) {
			fail(w, http.StatusInternalServerError, "load rules: "+err.Error())
			return
		}
		// Fresh install: no rules.json yet. An empty deny-default set is
		// genuinely blind on IPv6, but there is nothing for the user to
		// act on yet, so report it as-is and let the UI stay quiet until
		// rules exist.
		rs = rules.RuleSet{DefaultPolicy: "deny"}
	}
	writeJSON(w, http.StatusOK, v6AuditResponse{
		V6Audit:    compiler.AuditV6(rs),
		GlobalIPv6: system.HasGlobalIPv6(),
	})
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
	// "Recommended defaults" derives its per-port docker rules from the live
	// inventory, so a half-read inventory would silently produce a half-covered
	// rule set. Fail rather than hand the operator defaults that miss ports.
	dp, err := s.dockerPorts(ctx)
	if err != nil {
		fail(w, http.StatusInternalServerError, "docker published-port inventory: "+err.Error())
		return
	}
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

	// v1.0.21: tear down conntrack for the ports this apply switched from
	// allowed to denied. Without it, a connection already established to such a
	// port survives on the ESTABLISHED,RELATED fast-path until it closes on its
	// own, so "Apply" looks like it did nothing to a live connection and the
	// operator had to disable/enable the whole firewall to make the block bite.
	// Best-effort: the rules are already live, so a flush failure is logged, not
	// surfaced as an apply failure. First apply after boot has an empty
	// lastApplied and so flushes nothing (every port reads as already-denied).
	if targets := blockedPortKeys(rules.NewlyBlocked(s.lastApplied, s.lastCompiled)); len(targets) > 0 {
		if n, ferr := conntrack.Flush(ctx, targets); ferr != nil {
			slog.Warn("conntrack flush after apply (non-fatal)", "err", ferr, "ports", len(targets))
		} else if n > 0 {
			slog.Info("flushed conntrack for newly-blocked ports", "deleted", n, "ports", len(targets))
		}
	}
	s.lastApplied = s.lastCompiled

	writeJSON(w, http.StatusOK, map[string]string{"status": "applied", "output": out})
}

// blockedPortKeys adapts the rules-layer diff to the conntrack flush API.
func blockedPortKeys(pps []rules.PortProto) []conntrack.PortKey {
	if len(pps) == 0 {
		return nil
	}
	out := make([]conntrack.PortKey, len(pps))
	for i, pp := range pps {
		out[i] = conntrack.PortKey{Proto: pp.Proto, Port: pp.Port}
	}
	return out
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
	socks, err := s.listening(ctx)
	if err != nil {
		fail(w, http.StatusInternalServerError, "ss: "+err.Error())
		return
	}
	st := s.fw.Status(ctx)
	// Reach is judged by the rule model, not the legacy allowlist.conf: the
	// UI has not written that file since the rules tab replaced it, so on a
	// v1.x install it is absent, the old code read an empty config, and every
	// LAN-facing socket rendered "blocked" the moment the firewall was active
	// — including the ones the rules explicitly allow.
	pol := s.portPolicy()

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
			if !pol.DockerOpen(sk.Port) {
				reach = "blocked"
			}
		case st.Active:
			if !pol.HostOpen(sk.Port) {
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
	// Same oracle as /api/exposure — see portPolicy. With the legacy config
	// read here, every port-based finding flipped to "mitigated" as soon as
	// the firewall was active, regardless of the rules.
	findings := audit.FindingsWith(st, s.portPolicy())

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
	cs, err := s.dockerContainers(ctx)
	if err != nil {
		// An unreachable docker daemon is not an empty container list: showing
		// "no containers detected" here would invite the operator to bind rules
		// to nothing. Say what actually broke.
		fail(w, http.StatusInternalServerError, "docker inventory: "+err.Error())
		return
	}
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
	if err != nil {
		// Never answer 200 [] here. An unreadable connection table is not
		// an empty one, and conflating them sent issue #1's reporter
		// chasing a kernel module that was in fact tracking hundreds of
		// flows. Say what failed, with a status the UI cannot mistake.
		slog.Error("conntrack read failed", "err", err)
		fail(w, http.StatusServiceUnavailable, "connection table unreadable: "+err.Error())
		return
	}
	if entries == nil {
		entries = []conntrack.Entry{} // genuinely idle host: [], not null
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

// debugLevel reports (GET) or sets (POST {"enabled":bool}) the daemon's
// runtime log level. POST true switches slog to Debug so an operator can
// surface the diagnostic logs without a restart; false returns to Info.
func (s *Server) debugLevel(w http.ResponseWriter, r *http.Request) {
	if s.logLevel == nil {
		fail(w, http.StatusServiceUnavailable, "runtime log-level control not wired")
		return
	}
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, map[string]bool{"debug": s.logLevel.Level() == slog.LevelDebug})
	case http.MethodPost:
		var body struct {
			Enabled bool `json:"enabled"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			fail(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
			return
		}
		if body.Enabled {
			s.logLevel.Set(slog.LevelDebug)
		} else {
			s.logLevel.Set(slog.LevelInfo)
		}
		s.emitEvent("debug.toggled", map[string]any{"enabled": body.Enabled})
		slog.Info("runtime log level changed", "debug", body.Enabled)
		writeJSON(w, http.StatusOK, map[string]bool{"debug": body.Enabled})
	default:
		fail(w, http.StatusMethodNotAllowed, "GET or POST")
	}
}

func toSet(xs []string) map[string]bool {
	m := make(map[string]bool, len(xs))
	for _, x := range xs {
		m[x] = true
	}
	return m
}

// containerPorts is the full published-port set of one container: TCP and UDP
// unioned, sorted and de-duplicated. A rule bound to a container is rewritten
// to this list, so it has to be everything the container publishes — a
// TCP-only list silently strips the container's UDP ports out of its own allow
// rule. The rule's Protocol field decides which protocols the ports are
// emitted for; this is the port *set*, not a protocol decision.
func containerPorts(c system.DockerContainer) []int {
	if len(c.PortsUDP) == 0 {
		return c.Ports // already sorted + de-duplicated by system.DockerContainers
	}
	seen := make(map[int]bool, len(c.Ports)+len(c.PortsUDP))
	out := make([]int, 0, len(c.Ports)+len(c.PortsUDP))
	for _, p := range c.Ports {
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	for _, p := range c.PortsUDP {
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	sort.Ints(out)
	return out
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
