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
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/chicohaager/zfw/internal/auth"
	"github.com/chicohaager/zfw/internal/config"
	"github.com/chicohaager/zfw/internal/firewall"
	"github.com/chicohaager/zfw/internal/gateway"
	"github.com/chicohaager/zfw/internal/handlers"
	"github.com/chicohaager/zfw/internal/rules"
	"github.com/chicohaager/zfw/internal/system"
	"github.com/chicohaager/zfw/internal/watchdog"
)

func main() {
	cfg := config.Load()
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	log.Printf("zfwd starting: bind=%s:%s route=%s engine=%s",
		cfg.BindAddr, cfg.Port, cfg.RoutePath, cfg.ZfwBin)

	if err := os.MkdirAll(cfg.DataDir, 0o755); err != nil {
		log.Printf("mkdir data_dir (non-fatal): %v", err)
	}

	// The engine, allowlist.conf and the compiled ruleset live here and run
	// as root — keep the directory root-only so no other user or container on
	// the writable /DATA partition can plant a script (ZFW-3).
	zfwDir := filepath.Dir(cfg.RulesFile)
	if err := os.MkdirAll(zfwDir, 0o700); err != nil {
		log.Printf("mkdir zfw dir (non-fatal): %v", err)
	} else if err := os.Chmod(zfwDir, 0o700); err != nil {
		log.Printf("chmod zfw dir (non-fatal): %v", err)
	}

	fw := firewall.New(cfg.ZfwBin, cfg.ZfwConf)
	srv := handlers.NewServer(fw, cfg.RulesFile, cfg.CompiledFile, cfg.GeoDir)

	// v0.2 rule model: migrate the legacy allowlist.conf on first run, then
	// compile the rule set into the script the engine applies.
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
				log.Printf("rule migration (non-fatal): %v", serr)
			} else {
				log.Printf("migrated allowlist.conf -> rules.json (%d rules)", len(rs.Rules))
			}
		}
	}
	{
		rctx, rcancel := context.WithTimeout(context.Background(), 20*time.Second)
		if err := srv.Recompile(rctx); err != nil {
			log.Printf("initial recompile (non-fatal): %v", err)
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
			jwksURL = strings.TrimRight(target, "/") + "/.well-known/jwks.json"
		} else {
			log.Printf("JWKS discovery failed, using default (%s): %v", jwksURL, err)
		}
		dcancel()
	}
	verifier := auth.NewVerifier(jwksURL)
	{
		wctx, wcancel := context.WithTimeout(context.Background(), 5*time.Second)
		if err := verifier.Warm(wctx); err != nil {
			log.Printf("JWKS warm-up failed (retried lazily): %v", err)
		}
		wcancel()
	}
	log.Printf("session auth enabled (JWKS=%s)", jwksURL)

	mux := http.NewServeMux()
	// Every API call needs a valid ZimaOS session token; /api/health stays
	// open so liveness probes still work.
	mux.Handle("/api/", verifier.Middleware(srv.Routes(), func(p string) bool {
		return p == "/api/health"
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
	go gw.RegisterWithRetry(ctx, log.Printf)

	// Install the boot watchdog on the persistent root (ZimaOS sysext units
	// can lose the multi-user.target race — see KB §18.9).
	go func() {
		if err := watchdog.EnsureInstalled(log.Printf); err != nil {
			log.Printf("watchdog setup (non-fatal): %v", err)
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
		log.Printf("listening on %s", httpSrv.Addr)
		if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("listen: %v", err)
		}
	}()

	<-ctx.Done()
	log.Printf("shutdown signal received, stopping")
	shutCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := httpSrv.Shutdown(shutCtx); err != nil {
		log.Printf("graceful shutdown error: %v", err)
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
