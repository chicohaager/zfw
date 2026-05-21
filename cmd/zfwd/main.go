// zfwd: the zfw module daemon — a ZimaOS web UI and HTTP API for the ZFW
// host firewall, plus a live security dashboard (exposure, audit, versions).
//
// The daemon binds 127.0.0.1 only and registers a reverse-proxy route with
// the ZimaOS gateway, so the UI is reachable same-origin via port 80 without
// ever opening a new LAN port. State-changing requests are guarded by an
// Origin-header CSRF check.
package main

import (
	"context"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

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

	mux := http.NewServeMux()
	mux.Handle("/api/", srv.Routes())

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

		// CSRF: reject cross-origin state-changing requests.
		if r.Method == http.MethodPost || r.Method == http.MethodPut || r.Method == http.MethodDelete {
			if o := r.Header.Get("Origin"); o != "" {
				if u, err := url.Parse(o); err != nil || u.Host != r.Host {
					http.Error(w, "cross-origin request rejected", http.StatusForbidden)
					return
				}
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

	// Register the reverse-proxy route so the UI reaches this daemon via port 80.
	gw := gateway.New(cfg.GatewayURLFile, cfg.RoutePath, "http://127.0.0.1:"+cfg.Port)
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
