// Package config loads the daemon configuration from the environment.
// All values have defaults so `go run ./cmd/zfwd` works without a unit file.
package config

import "os"

// Config holds the resolved daemon settings.
type Config struct {
	BindAddr       string // loopback only — never expose the daemon directly
	Port           string
	RoutePath      string // gateway route prefix, e.g. /v2/zfw
	GatewayURLFile string // file holding the gateway management base URL
	StaticDir      string // directory served as the web UI
	ZfwBin         string // the firewall engine script (/DATA/zfw/zfw)
	ZfwConf        string // legacy v0.1 tier allowlist (/DATA/zfw/allowlist.conf)
	RulesFile      string // v0.2 rule model — source of truth (/DATA/zfw/rules.json)
	CompiledFile   string // daemon-compiled ruleset the engine applies
	GeoDir         string // per-country IP data + ipset files (/DATA/zfw/geo)
	HistoryFile    string // audit-finding status timeline (/DATA/zfw/audit-history.json)
	DataDir        string // module state directory
	JWKSURL        string // ZimaOS JWKS endpoint for session-token validation
	UpdateURL      string // optional manifest URL polled for new releases; empty disables the check
	PeersFile      string // opt-in peers list for multi-host rule sync (leader-side)
	PeerToken      string // shared bearer accepted by /api/peers/receive (follower-side); empty disables inbound receive
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// Load resolves the configuration from environment variables.
func Load() Config {
	return Config{
		BindAddr:       env("BIND_ADDR", "127.0.0.1"),
		Port:           env("PORT", "8489"),
		RoutePath:      env("ROUTE_PATH", "/v2/zfw"),
		GatewayURLFile: env("GATEWAY_URL_FILE", "/var/run/casaos/management.url"),
		StaticDir:      env("STATIC_DIR", "/usr/share/casaos/www/modules/zfw"),
		ZfwBin:         env("ZFW_BIN", "/DATA/zfw/zfw"),
		ZfwConf:        env("ZFW_CONF", "/DATA/zfw/allowlist.conf"),
		RulesFile:      env("ZFW_RULES", "/DATA/zfw/rules.json"),
		CompiledFile:   env("ZFW_COMPILED", "/DATA/zfw/compiled.sh"),
		GeoDir:         env("ZFW_GEO", "/DATA/zfw/geo"),
		HistoryFile:    env("ZFW_HISTORY", "/DATA/zfw/audit-history.json"),
		DataDir:        env("DATA_DIR", "/DATA/AppData/zfw"),
		JWKSURL:        env("ZFW_JWKS_URL", "http://127.0.0.1:37815/.well-known/jwks.json"),
		UpdateURL:      env("ZFW_UPDATE_URL", ""),
		PeersFile:      env("ZFW_PEERS", "/DATA/zfw/peers.json"),
		PeerToken:      env("ZFW_PEER_TOKEN", ""),
	}
}
