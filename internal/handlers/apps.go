package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/chicohaager/zfw/internal/apps"
	"github.com/chicohaager/zfw/internal/compiler"
	"github.com/chicohaager/zfw/internal/rules"
	"github.com/chicohaager/zfw/internal/system"
)

// The new-app prompt (v1.0.28) — see package apps for the design. The
// daemon side: a background loop (RunApps) that keeps apps.json and the app
// chains in step with the running containers and the dashboard cards in step
// with the open questions, and the API the UI answers through.

func (s *Server) appsStatePath() string {
	return filepath.Join(filepath.Dir(s.compiledPath), "apps.json")
}

func (s *Server) appsScriptPath() string {
	return filepath.Join(filepath.Dir(s.compiledPath), "apps.sh")
}

// appsLive is the applied rule set as package apps needs it; nil when there
// is no record of what was applied.
func appsLive(snap *compiler.LiveSnapshot) *apps.Live {
	if snap == nil {
		return nil
	}
	return &apps.Live{Rules: snap.Rules, Published: snap.Published}
}

// KickApps asks the background loop for a sync now (after an apply, a
// confirm, a container event). Non-blocking: the channel holds one queued
// request, further kicks before it is taken are the same request. Without a
// running loop (the handler tests) the request simply stays queued.
func (s *Server) KickApps() {
	s.kickApps(false)
}

// kickAppsRewrite is KickApps after the firewall itself changed (apply,
// confirm, revert): the app chains are rewritten even if their content did not.
func (s *Server) kickAppsRewrite() { s.kickApps(true) }

func (s *Server) kickApps(rewrite bool) {
	if rewrite {
		s.appsForce.Store(true)
	}
	select {
	case s.appsKick <- struct{}{}:
	default: // a sync is already queued
	}
}

// RunApps is the background loop. Every minute is also the cadence at which
// the dashboard card of an unanswered port is re-sent: ZimaOS does not store
// cards (KB §75), so a dashboard opened later would otherwise never see it.
func (s *Server) RunApps(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		if err := s.SyncApps(ctx); err != nil {
			slog.Warn("new-app sync (retried)", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-s.appsKick:
		}
	}
}

// SyncApps merges the running containers into apps.json, rewrites the app
// chains when their content changed and shows/withdraws dashboard cards.
func (s *Server) SyncApps(ctx context.Context) error {
	s.appsMu.Lock()
	defer s.appsMu.Unlock()
	return s.syncAppsLocked(ctx, nil)
}

func (s *Server) syncAppsLocked(ctx context.Context, withdraw []apps.Entry) error {
	now := s.clock()
	f, err := apps.Load(s.appsStatePath(), now)
	if err != nil {
		return err
	}
	ports, err := s.appPorts(ctx)
	if err != nil {
		// Without an inventory every entry would look absent; keep the state.
		return err
	}
	cands := make([]apps.Candidate, 0, len(ports))
	titles := map[string]string{}
	for _, p := range ports {
		title, ok := titles[p.Project]
		if !ok {
			title = s.appTitle(p.Project)
			titles[p.Project] = title
		}
		cands = append(cands, apps.Candidate{Container: p.Container, AppID: p.AppID, Title: title,
			Zone: p.Zone, Proto: p.Proto, Port: p.Port, Started: p.Started})
	}
	before := map[string]bool{}
	for _, e := range f.Entries {
		if e.State == apps.Pending && e.Present {
			before[e.Key] = true
		}
	}
	live := appsLive(s.liveSnapshot())
	f = apps.Detect(f, cands, live, now)
	if err := apps.Save(s.appsStatePath(), f); err != nil {
		return err
	}
	for _, e := range f.Entries {
		if e.State == apps.Pending && e.Present && !before[e.Key] {
			slog.Info("new app port", "app", e.Title, "container", e.Container, "port", e.Port, "proto", e.Proto, "zone", e.Zone, "mode", f.Mode)
			s.emitEvent("apps.new", map[string]any{"app": e.Title, "container": e.Container, "port": e.Port, "proto": e.Proto, "zone": e.Zone})
		}
	}
	lan := ""
	if live != nil {
		lan = live.Rules.LAN
	}
	script := compiler.CompileApps(apps.Active(f, live), lan)
	// Rewrite when the content changed, and after every apply/confirm/revert:
	// an apply (re)creates the chains empty when they did not exist — the
	// first apply of this version, or any apply after a revert or a dead-man
	// rollback — and the content would otherwise stay missing.
	if script != s.appsScript || s.appsForce.Swap(false) {
		if err := writeScriptAtomic(s.appsScriptPath(), script); err != nil {
			return err
		}
		out, err := s.fw.Apps(ctx)
		if err != nil {
			return errors.New("zfw apps: " + err.Error() + " " + out)
		}
		slog.Info("app chains updated", "output", out)
		if strings.Contains(out, "missing") {
			// Nothing was written; the next apply creates the chains and forces
			// a rewrite. Never remember this run as done.
			s.appsScript = ""
		} else {
			s.appsScript = script
		}
	}
	// Cards: re-send every open question (they are not stored by ZimaOS),
	// withdraw the ones that were open before and are not any more.
	open := map[string]bool{}
	for _, e := range f.Entries {
		if e.State == apps.Pending && e.Present {
			open[e.Key] = true
			if err := s.notifier.Show(ctx, e, f.Mode); err != nil {
				slog.Debug("dashboard card (non-fatal)", "err", err)
			}
		}
	}
	for k := range before {
		if !open[k] {
			if err := s.notifier.Withdraw(ctx, apps.Entry{Key: k}); err != nil {
				slog.Debug("withdraw dashboard card (non-fatal)", "err", err)
			}
		}
	}
	for _, e := range withdraw {
		if !open[e.Key] {
			_ = s.notifier.Withdraw(ctx, e)
		}
	}
	return nil
}

// appOverlay is one present TCP app port as the Exposure and Audit views
// need it (TCP is what both judge): the entry and whether an app chain
// admits it right now.
type appOverlay struct {
	apps.Entry
	Active bool
	Mode   string
}

func overlayKey(zone string, port int) string { return zone + "/" + strconv.Itoa(port) }

// appsOverlay maps zone/port to the app entry for that port.
func (s *Server) appsOverlay(snap *compiler.LiveSnapshot) map[string]appOverlay {
	f, err := apps.Load(s.appsStatePath(), s.clock())
	if err != nil {
		slog.Warn("apps state unreadable", "err", err)
		return nil
	}
	active := map[string]bool{}
	for _, e := range apps.Active(f, appsLive(snap)) {
		active[e.Key] = true
	}
	ov := map[string]appOverlay{}
	for _, e := range f.Entries {
		if e.Present && e.Proto == "tcp" {
			ov[overlayKey(e.Zone, e.Port)] = appOverlay{Entry: e, Active: active[e.Key], Mode: f.Mode}
		}
	}
	return ov
}

func (s *Server) appsHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.appsMu.Lock()
		f, err := apps.Load(s.appsStatePath(), s.clock())
		s.appsMu.Unlock()
		if err != nil {
			fail(w, http.StatusInternalServerError, err.Error())
			return
		}
		active := map[string]bool{}
		for _, e := range apps.Active(f, appsLive(s.liveSnapshot())) {
			active[e.Key] = true
		}
		type out struct {
			apps.Entry
			Open bool `json:"open"` // an app chain admits it right now
		}
		list := make([]out, 0, len(f.Entries))
		for _, e := range f.Entries {
			list = append(list, out{Entry: e, Open: active[e.Key]})
		}
		writeJSON(w, http.StatusOK, map[string]any{"mode": f.Mode, "entries": list})
	case http.MethodPost:
		var body struct {
			Mode string `json:"mode"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			fail(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
			return
		}
		if body.Mode != apps.ModeLAN && body.Mode != apps.ModeBlock {
			fail(w, http.StatusBadRequest, `mode must be "lan" or "block"`)
			return
		}
		ctx, cancel := reqCtx()
		defer cancel()
		s.appsMu.Lock()
		defer s.appsMu.Unlock()
		f, err := apps.Load(s.appsStatePath(), s.clock())
		if err != nil {
			fail(w, http.StatusInternalServerError, err.Error())
			return
		}
		f.Mode = body.Mode
		if err := apps.Save(s.appsStatePath(), f); err != nil {
			fail(w, http.StatusInternalServerError, err.Error())
			return
		}
		if err := s.syncAppsLocked(ctx, nil); err != nil {
			fail(w, http.StatusInternalServerError, "saved, but updating the app chains failed: "+err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "saved", "mode": f.Mode})
	default:
		fail(w, http.StatusMethodNotAllowed, "GET or POST required")
	}
}

// appsDecide records an answer: as a rule in rules.json (saved, not applied —
// it takes over at the next apply) and, until then, in the app chains.
func (s *Server) appsDecide(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		fail(w, http.StatusMethodNotAllowed, "POST required")
		return
	}
	var body struct {
		Key    string `json:"key"`
		Answer string `json:"answer"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		fail(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	answer := apps.State(body.Answer)
	if answer != apps.LAN && answer != apps.Any && answer != apps.Block {
		fail(w, http.StatusBadRequest, `answer must be "lan", "any" or "block"`)
		return
	}
	ctx, cancel := reqCtx()
	defer cancel()
	s.appsMu.Lock()
	defer s.appsMu.Unlock()
	now := s.clock()
	f, err := apps.Load(s.appsStatePath(), now)
	if err != nil {
		fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	i := f.Find(body.Key)
	if i < 0 {
		fail(w, http.StatusNotFound, "no such app port — it may have been removed")
		return
	}
	e := f.Entries[i]
	rs, err := rules.Load(s.rulesPath)
	if err != nil {
		fail(w, http.StatusInternalServerError, "load rules: "+err.Error())
		return
	}
	order := 0
	for _, x := range rs.Rules {
		if x.Order > order {
			order = x.Order
		}
	}
	// An earlier answer for the same port is replaced, not stacked.
	if e.RuleID != "" {
		kept := rs.Rules[:0]
		for _, x := range rs.Rules {
			if x.ID != e.RuleID {
				kept = append(kept, x)
			}
		}
		rs.Rules = kept
	}
	rule, err := apps.RuleFor(e, answer, rs.LAN, rules.NewID(), order+10, now)
	if err != nil {
		fail(w, http.StatusBadRequest, err.Error())
		return
	}
	rs.Rules = append(rs.Rules, rule)
	if err := rules.Validate(rs); err != nil {
		fail(w, http.StatusBadRequest, "rule: "+err.Error())
		return
	}
	containers, dockerPorts, err := s.prefetchForCompile(ctx, &rs)
	if err != nil {
		fail(w, http.StatusInternalServerError, "prepare: "+err.Error())
		return
	}
	s.mu.Lock()
	err = rules.Save(s.rulesPath, rs)
	if err == nil {
		err = s.recompileLocked(containers, dockerPorts)
	}
	s.mu.Unlock()
	if err != nil {
		fail(w, http.StatusInternalServerError, "save rule: "+err.Error())
		return
	}
	f.Entries[i].State, f.Entries[i].RuleID = answer, rule.ID
	if err := apps.Save(s.appsStatePath(), f); err != nil {
		fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.emitEvent("apps.answered", map[string]any{"app": e.Title, "port": e.Port, "proto": e.Proto, "answer": string(answer), "rule": rule.ID})
	if err := s.syncAppsLocked(ctx, []apps.Entry{e}); err != nil {
		fail(w, http.StatusInternalServerError, "rule saved, but updating the app chains failed: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "answered", "rule": rule})
}

// defaults wired by NewServer; replaced in tests.
func defaultAppTitle(project string) string { return system.AppTitle(system.CasaOSAppsDir, project) }
