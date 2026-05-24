// zfwd: the zfw module daemon — a ZimaOS web UI and HTTP API for the ZFW
// host firewall, plus a live security dashboard (exposure, audit, versions).
//
// The daemon binds 127.0.0.1 only and registers a reverse-proxy route with
// the ZimaOS gateway, so the UI is reachable same-origin via port 80. The
// gateway does not authenticate proxied module routes, so the daemon verifies
// a ZimaOS session token (ES256 JWT) on every API request; an Origin-header
// CSRF check guards state-changing requests as a second layer.
package main

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/chicohaager/zfw/internal/auth"
	"github.com/chicohaager/zfw/internal/buildinfo"
	"github.com/chicohaager/zfw/internal/config"
	"github.com/chicohaager/zfw/internal/firewall"
	"github.com/chicohaager/zfw/internal/gateway"
	"github.com/chicohaager/zfw/internal/handlers"
	"github.com/chicohaager/zfw/internal/notify"
	"github.com/chicohaager/zfw/internal/rules"
	"github.com/chicohaager/zfw/internal/system"
	"github.com/chicohaager/zfw/internal/update"
	"github.com/chicohaager/zfw/internal/watchdog"
)

// slogf adapts a printf-style logger call to slog.Info. Used as a callback
// argument for library code (gateway.RegisterWithRetry, watchdog.EnsureInstalled)
// that still takes the legacy `func(string, ...any)` signature so those
// packages stay slog-agnostic.
func slogf(format string, args ...any) {
	slog.Info(fmt.Sprintf(format, args...))
}

func main() {
	// Use the text handler — key=value lines stay readable in journalctl
	// without a JSON pipeline, and slog adds source location automatically
	// when AddSource is enabled.
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr,
		&slog.HandlerOptions{AddSource: true})))

	cfg := config.Load()
	slog.Info("zfwd starting",
		"bind", cfg.BindAddr+":"+cfg.Port,
		"route", cfg.RoutePath,
		"engine", cfg.ZfwBin)

	if err := os.MkdirAll(cfg.DataDir, 0o755); err != nil {
		slog.Warn("mkdir data_dir (non-fatal)", "err", err, "dir", cfg.DataDir)
	}

	// The engine, allowlist.conf and the compiled ruleset live here and run
	// as root — keep the directory root-only so no other user or container on
	// the writable /DATA partition can plant a script (ZFW-3).
	zfwDir := filepath.Dir(cfg.RulesFile)
	if err := os.MkdirAll(zfwDir, 0o700); err != nil {
		slog.Warn("mkdir zfw dir (non-fatal)", "err", err, "dir", zfwDir)
	} else if err := os.Chmod(zfwDir, 0o700); err != nil {
		slog.Warn("chmod zfw dir (non-fatal)", "err", err, "dir", zfwDir)
	}

	fw := firewall.New(cfg.ZfwBin, cfg.ZfwConf)
	// Optional self-update poller — empty ZFW_UPDATE_URL leaves it disabled
	// (no outbound HTTP from a fresh install). Run loop starts after main's
	// signal-aware context is constructed below.
	upd := update.New(buildinfo.Version, cfg.UpdateURL)
	hook := notify.New(cfg.WebhookURL)
	srv := handlers.NewServer(fw, cfg.RulesFile, cfg.CompiledFile, cfg.GeoDir, cfg.HistoryFile, upd, cfg.PeersFile, cfg.PeerToken, cfg.ExtraBypassIfaces, hook)

	// v0.2 rule model: migrate the legacy allowlist.conf on first run; on a
	// truly fresh host (no allowlist either) seed a recommended starter
	// rule set so the UI opens onto something usable instead of an empty
	// page that locks the user out the moment they hit Safe-Apply.
	if _, err := os.Stat(cfg.RulesFile); os.IsNotExist(err) {
		if tier, lerr := fw.LoadConfig(); lerr == nil {
			mctx, mcancel := context.WithTimeout(context.Background(), 20*time.Second)
			dp := system.DockerPorts(mctx)
			mcancel()
			ports := make([]int, 0, len(dp))
			for p := range dp {
				ports = append(ports, p)
			}
			rs := rules.FromTiers(tier, ports)
			if serr := rules.Save(cfg.RulesFile, rs); serr != nil {
				slog.Warn("rule migration (non-fatal)", "err", serr)
			} else {
				slog.Info("migrated allowlist.conf -> rules.json", "rules", len(rs.Rules))
			}
		} else {
			lan, hostIP := system.DetectLAN()
			dctx, dcancel := context.WithTimeout(context.Background(), 10*time.Second)
			dp := system.DockerPorts(dctx)
			dcancel()
			rs := rules.Defaults(lan, hostIP, dp)
			if serr := rules.Save(cfg.RulesFile, rs); serr != nil {
				slog.Warn("default rule seed (non-fatal)", "err", serr)
			} else {
				slog.Info("seeded default rules.json — not applied; user must Safe-Apply",
					"lan", lan, "host", hostIP,
					"rules", len(rs.Rules), "docker_ports", len(dp))
			}
		}
	}
	{
		rctx, rcancel := context.WithTimeout(context.Background(), 20*time.Second)
		if err := srv.Recompile(rctx); err != nil {
			slog.Warn("initial recompile (non-fatal)", "err", err)
		}
		rcancel()
	}

	// The gateway client: the UI reaches this daemon through its /v2/zfw route.
	gw := gateway.New(cfg.GatewayURLFile, cfg.RoutePath, "http://127.0.0.1:"+cfg.Port)

	// The ZimaOS gateway proxies /v2/zfw LAN-wide without authenticating it,
	// so the daemon verifies the ZimaOS session token itself. Discover the
	// JWKS endpoint via the gateway (port-agnostic); fall back to the default.
	jwksURL := cfg.JWKSURL
	{
		dctx, dcancel := context.WithTimeout(context.Background(), 5*time.Second)
		if target, err := gw.LookupTarget(dctx, "/.well-known/jwks.json"); err == nil {
			cand := strings.TrimRight(target, "/") + "/.well-known/jwks.json"
			// The gateway routes table is mutable, so the discovered JWKS
			// target is trusted only when it points at loopback — otherwise
			// the auth trust anchor could be redirected off-host (ZFW-S1).
			if isLoopbackURL(cand) {
				jwksURL = cand
			} else {
				slog.Warn("discovered JWKS target not loopback — keeping pinned default",
					"target", target, "default", jwksURL)
			}
		} else {
			slog.Warn("JWKS discovery failed, using default",
				"default", jwksURL, "err", err)
		}
		dcancel()
	}
	if !isLoopbackURL(jwksURL) {
		slog.Warn("JWKS URL is not loopback — session-auth trust anchor is off-host",
			"jwks_url", jwksURL)
	}
	verifier := auth.NewVerifier(jwksURL)
	{
		wctx, wcancel := context.WithTimeout(context.Background(), 5*time.Second)
		if err := verifier.Warm(wctx); err != nil {
			slog.Warn("JWKS warm-up failed (retried lazily)", "err", err)
		}
		wcancel()
	}
	slog.Info("session auth enabled", "jwks_url", jwksURL)

	mux := http.NewServeMux()
	// Every API call needs a valid ZimaOS session token; /api/health stays
	// open so liveness probes still work, and /api/peers/receive uses its
	// own shared-token auth (it's invoked by a leader host, not a
	// browser session) so it bypasses the JWT middleware.
	mux.Handle("/api/", verifier.Middleware(srv.Routes(), func(p string) bool {
		return p == "/api/health" || p == "/api/peers/receive"
	}))

	// Static UI fallback for direct localhost access. The gateway also serves
	// these files directly under /modules/zfw/.
	fs := http.FileServer(http.Dir(cfg.StaticDir))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "..") {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		fs.ServeHTTP(w, r)
	})

	// The gateway proxies the registered route prefix verbatim
	// (e.g. /v2/zfw/api/status). Strip it so internal routing stays
	// prefix-agnostic and direct localhost access (/api/...) keeps working.
	root := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20)

		// CSRF: a state-changing request must prove it is same-origin.
		// Browsers always attach Origin to POST/PUT/DELETE fetches; a request
		// with neither Origin nor a matching Referer is a non-browser or a
		// forged caller, so it is rejected rather than waved through (ZFW-4).
		if r.Method == http.MethodPost || r.Method == http.MethodPut || r.Method == http.MethodDelete {
			if !sameOrigin(r) {
				http.Error(w, "cross-origin request rejected", http.StatusForbidden)
				return
			}
		}

		if cfg.RoutePath != "" {
			if r.URL.Path == cfg.RoutePath {
				r.URL.Path = "/"
			} else if strings.HasPrefix(r.URL.Path, cfg.RoutePath+"/") {
				r.URL.Path = r.URL.Path[len(cfg.RoutePath):]
			}
		}
		mux.ServeHTTP(w, r)
	})

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Keep the reverse-proxy route registered so the UI reaches this daemon.
	go gw.RegisterWithRetry(ctx, slogf)

	// Poll for upstream releases once per week. A disabled checker
	// (empty ZFW_UPDATE_URL) returns immediately without starting the
	// goroutine, so no outbound calls happen on a fresh install.
	upd.Run(ctx, 7*24*time.Hour)

	// Install the boot watchdog on the persistent root (ZimaOS sysext units
	// can lose the multi-user.target race — see KB §18.9).
	go func() {
		if err := watchdog.EnsureInstalled(slogf); err != nil {
			slog.Warn("watchdog setup (non-fatal)", "err", err)
		}
	}()

	httpSrv := &http.Server{
		Addr:              cfg.BindAddr + ":" + cfg.Port,
		Handler:           root,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      120 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	go func() {
		slog.Info("listening", "addr", httpSrv.Addr)
		if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("listen failed", "err", err)
			os.Exit(1)
		}
	}()

	<-ctx.Done()
	slog.Info("shutdown signal received, stopping")
	shutCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := httpSrv.Shutdown(shutCtx); err != nil {
		slog.Warn("graceful shutdown error", "err", err)
	}
}

// sameOrigin reports whether a state-changing request carries proof that it
// originates from the daemon's own origin. Origin is checked first, then
// Referer as a fallback; a request with neither header fails the check.
func sameOrigin(r *http.Request) bool {
	if o := r.Header.Get("Origin"); o != "" {
		u, err := url.Parse(o)
		return err == nil && u.Host == r.Host
	}
	if ref := r.Header.Get("Referer"); ref != "" {
		u, err := url.Parse(ref)
		return err == nil && u.Host == r.Host
	}
	return false
}

// isLoopbackURL reports whether u is an http/https URL whose host is a
// loopback address. The JWKS trust anchor must stay on-host.
func isLoopbackURL(u string) bool {
	p, err := url.Parse(u)
	if err != nil || (p.Scheme != "http" && p.Scheme != "https") {
		return false
	}
	host := p.Hostname()
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
