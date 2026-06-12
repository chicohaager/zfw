// Package config loads the daemon configuration from the environment.
// All values have defaults so `go run ./cmd/zfwd` works without a unit file.
package config

import (
	"os"
	"strings"
)

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
	// ExtraBypassIfaces (v0.5.4) — additional inbound-bypass interface
	// names appended to every chain on top of the built-in list
	// (lo / docker0 / br-+ / tailscale0 / zt+ / wg+). Strings may use
	// iptables' "+" wildcard suffix; comma-separated via ZFW_EXTRA_BYPASS_IFACES.
	// Invalid names are filtered out by the daemon before compile so a
	// crafted env var cannot inject shell payload into compiled.sh.
	ExtraBypassIfaces []string
	// WebhookURL (v0.5.5) — opt-in outbound webhook fired on rule
	// changes, applies, commits and reverts. Empty disables; daemon
	// makes no outbound HTTP from a fresh install.
	WebhookURL string
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
		BindAddr:          env("BIND_ADDR", "127.0.0.1"),
		Port:              env("PORT", "8489"),
		RoutePath:         env("ROUTE_PATH", "/v2/zfw"),
		GatewayURLFile:    env("GATEWAY_URL_FILE", "/var/run/casaos/management.url"),
		StaticDir:         env("STATIC_DIR", "/usr/share/casaos/www/modules/zfw"),
		ZfwBin:            env("ZFW_BIN", "/DATA/zfw/zfw"),
		ZfwConf:           env("ZFW_CONF", "/DATA/zfw/allowlist.conf"),
		RulesFile:         env("ZFW_RULES", "/DATA/zfw/rules.json"),
		CompiledFile:      env("ZFW_COMPILED", "/DATA/zfw/compiled.sh"),
		GeoDir:            env("ZFW_GEO", "/DATA/zfw/geo"),
		HistoryFile:       env("ZFW_HISTORY", "/DATA/zfw/audit-history.json"),
		DataDir:           env("DATA_DIR", "/DATA/AppData/zfw"),
		JWKSURL:           env("ZFW_JWKS_URL", "http://127.0.0.1:37815/.well-known/jwks.json"),
		UpdateURL:         env("ZFW_UPDATE_URL", ""),
		PeersFile:         env("ZFW_PEERS", "/DATA/zfw/peers.json"),
		PeerToken:         env("ZFW_PEER_TOKEN", ""),
		ExtraBypassIfaces: parseIfaceList(env("ZFW_EXTRA_BYPASS_IFACES", "")),
		WebhookURL:        env("ZFW_WEBHOOK_URL", ""),
	}
}

// parseIfaceList splits a comma-separated env var into iface names and
// filters out anything that does not match the safe iface-name pattern
// (alphanumeric, dash, underscore, trailing "+" wildcard). Anything
// rejected is dropped silently — the env var is operator-supplied so
// a typo should not break the daemon, just be ignored.
func parseIfaceList(raw string) []string {
	if raw == "" {
		return nil
	}
	var out []string
	for _, p := range strings.Split(raw, ",") {
		p = strings.TrimSpace(p)
		if p == "" || !isSafeIfaceName(p) {
			continue
		}
		out = append(out, p)
	}
	return out
}

// isSafeIfaceName guards against shell-injection through the compiled
// engine script. iptables iface names are POSIX-ish; we accept only
// the documented character set plus the wildcard suffix.
func isSafeIfaceName(s string) bool {
	if s == "" || len(s) > 15 {
		return false // IFNAMSIZ - 1
	}
	// A bare "+" is iptables' match-ALL-interfaces wildcard — as a
	// bypass iface it would silently neuter input filtering on every
	// interface. Require at least one real character before a trailing
	// wildcard.
	if s == "+" {
		return false
	}
	for i, r := range s {
		switch {
		case r >= 'a' && r <= 'z',
			r >= 'A' && r <= 'Z',
			r >= '0' && r <= '9',
			r == '-', r == '_':
			// ok
		case r == '+' && i == len(s)-1:
			// trailing wildcard only
		default:
			return false
		}
	}
	return true
}
