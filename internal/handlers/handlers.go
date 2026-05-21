// Package handlers serves the zfw module HTTP API.
package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/chicohaager/zfw/internal/audit"
	"github.com/chicohaager/zfw/internal/buildinfo"
	"github.com/chicohaager/zfw/internal/compiler"
	"github.com/chicohaager/zfw/internal/firewall"
	"github.com/chicohaager/zfw/internal/geo"
	"github.com/chicohaager/zfw/internal/rules"
	"github.com/chicohaager/zfw/internal/system"
)

// Server holds the dependencies for the HTTP API.
type Server struct {
	fw           *firewall.Manager
	rulesPath    string
	compiledPath string
	geo          *geo.Manager
}

// NewServer returns a Server.
func NewServer(fw *firewall.Manager, rulesPath, compiledPath, geoDir string) *Server {
	return &Server{
		fw:           fw,
		rulesPath:    rulesPath,
		compiledPath: compiledPath,
		geo:          geo.New(geoDir),
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
	ccSet := map[string]bool{}
	for _, r := range rs.Rules {
		if r.Source.Type == "country" {
			for _, cc := range rules.SplitCountries(r.Source.Value) {
				ccSet[strings.ToLower(cc)] = true
			}
		}
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
	return os.WriteFile(s.compiledPath, []byte(script), 0o755)
}

// Routes returns the API mux.
func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/health", s.health)
	mux.HandleFunc("/api/status", s.status)
	mux.HandleFunc("/api/config", s.config)
	mux.HandleFunc("/api/rules", s.rules)
	mux.HandleFunc("/api/apply", s.apply)
	mux.HandleFunc("/api/commit", s.commit)
	mux.HandleFunc("/api/revert", s.revert)
	mux.HandleFunc("/api/exposure", s.exposure)
	mux.HandleFunc("/api/audit", s.auditHandler)
	mux.HandleFunc("/api/versions", s.versions)
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
		fail(w, http.StatusMethodNotAllowed, "POST erforderlich")
		return
	}
	var c firewall.Config
	if err := json.NewDecoder(r.Body).Decode(&c); err != nil {
		fail(w, http.StatusBadRequest, "ungültiges JSON: "+err.Error())
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
			fail(w, http.StatusInternalServerError, "Regeln laden: "+err.Error())
			return
		}
		writeJSON(w, http.StatusOK, rs)
	case http.MethodPost:
		var rs rules.RuleSet
		if err := json.NewDecoder(r.Body).Decode(&rs); err != nil {
			fail(w, http.StatusBadRequest, "ungültiges JSON: "+err.Error())
			return
		}
		if err := rules.Validate(rs); err != nil {
			fail(w, http.StatusBadRequest, err.Error())
			return
		}
		if err := rules.Save(s.rulesPath, rs); err != nil {
			fail(w, http.StatusInternalServerError, "speichern: "+err.Error())
			return
		}
		ctx, cancel := reqCtx()
		defer cancel()
		if err := s.Recompile(ctx); err != nil {
			fail(w, http.StatusInternalServerError, "kompilieren: "+err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "saved"})
	default:
		fail(w, http.StatusMethodNotAllowed, "GET oder POST")
	}
}

func (s *Server) apply(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		fail(w, http.StatusMethodNotAllowed, "POST erforderlich")
		return
	}
	var body struct {
		Safe bool `json:"safe"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	ctx, cancel := reqCtx()
	defer cancel()
	// Recompile so the engine applies the current rule set.
	if err := s.Recompile(ctx); err != nil {
		fail(w, http.StatusInternalServerError, "kompilieren: "+err.Error())
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
		fail(w, http.StatusMethodNotAllowed, "POST erforderlich")
		return
	}
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
		fail(w, http.StatusMethodNotAllowed, "POST erforderlich")
		return
	}
	ctx, cancel := reqCtx()
	defer cancel()
	out, err := s.fw.Revert(ctx)
	if err != nil {
		fail(w, http.StatusInternalServerError, "revert: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "reverted", "output": out})
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
	writeJSON(w, http.StatusOK, audit.Findings(st, cfg))
}

func (s *Server) versions(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := reqCtx()
	defer cancel()
	writeJSON(w, http.StatusOK, system.Versions(ctx))
}

func toSet(xs []string) map[string]bool {
	m := make(map[string]bool, len(xs))
	for _, x := range xs {
		m[x] = true
	}
	return m
}
