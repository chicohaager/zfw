# ZFW Security Report

| | |
|---|---|
| **Module** | ZFW — host firewall for ZimaOS |
| **Version reviewed** | 0.2.6 |
| **Date** | 2026-05-22 |
| **Author** | Holger Kuehn aka Lintuxer |

---

## Executive summary

ZFW is a systemd-sysext module that adds a host firewall to ZimaOS: a Go
daemon (`zfwd`) running as **root**, a web UI served through the ZimaOS
gateway, and a privileged shell engine that applies the iptables ruleset.
Because the component runs as root and its API is reachable across the LAN,
it was security-reviewed in **two rounds** before release for testing.

**Result: 17 findings, all remediated.** No Critical or High issue remains
open. The most dangerous class for a tool of this shape — shell-command
injection into the root-executed ruleset — was examined specifically and
found **not exploitable**. Version 0.2.6 is considered fit for a testing
handoff.

| Severity | Found | Remediated | Open |
|----------|-------|------------|------|
| Critical | 1 | 1 | 0 |
| High | 1 | 1 | 0 |
| Medium | 7 | 7 | 0 |
| Low | 8 | 8 | 0 |
| **Total** | **17** | **17** | **0** |

---

## Scope

Reviewed in full:

- the Go codebase — `cmd/zfwd` and every package under `internal/`
  (auth, audit, compiler, config, firewall, gateway, geo, handlers, rules,
  system, watchdog);
- the privileged engine script `engine/zfw` and the daemon-generated
  ruleset (`compiled.sh`);
- the build pipeline `build.sh` and the `zfw-ui.service` systemd unit;
- file and directory permissions on the runtime state under `/DATA/zfw`.

Out of scope: the ZimaOS platform itself, the gateway, and the host kernel.

---

## Threat model

The daemon binds `127.0.0.1` only, but the ZimaOS gateway proxies its
`/v2/zfw` route **LAN-wide on port 80 without authenticating it**. The
adversaries considered:

1. an **unauthenticated device** on the local network;
2. an **authenticated but malicious** ZimaOS user;
3. a **malicious or compromised container** with loopback or `/DATA` access.

The daemon runs as root and compiles a bash script that is executed as root,
so any input-handling or trust-boundary flaw is potentially a path to host
root. The review weighted findings on that basis.

---

## Methodology

**Round 1 — functional security review** (during development). Identified
the auth, validation and privilege-boundary gaps inherent in the initial
design (findings ZFW-1 … ZFW-8).

**Round 2 — pre-handoff review** of v0.2.5. Two independent in-depth reviews
were run in parallel — one for code quality, one adversarial — supported by a
manual review of the two highest-risk components: the hand-written ES256 JWT
verifier and the ruleset compiler (findings S1 … S9).

Every finding was cross-checked against the source before being accepted,
fixed, rebuilt (`gofmt` + `go vet` + unit tests) and — for the externally
observable controls — verified live on a ZimaOS 1.6.1 host.

---

## Findings — Round 1 (ZFW-1 … ZFW-8)

| ID | Sev | Finding | Remediation |
|----|-----|---------|-------------|
| ZFW-1 | Critical | Control API reachable LAN-wide with no authentication — the gateway proxies `/v2/zfw` without a token check | ES256 JWT verifier (`internal/auth`) validates the ZimaOS session token on every API call |
| ZFW-2 | Medium | `rules.json` compiled into the root-run `compiled.sh` without validation | `rules.Validate` enforced before every compile |
| ZFW-3 | Medium | Privileged engine + `compiled.sh` in writable `/DATA`, world-readable | `/DATA/zfw` is `root:root 0700`; generated files `0600` |
| ZFW-4 | Low | CSRF check skipped when the `Origin` header was absent | State-changing requests must prove same-origin via `Origin` or `Referer`, else `403` |
| ZFW-5 | Low | `zfw-ui.service` ran without sandboxing | 11 systemd hardening directives added (filesystem/namespace) |
| ZFW-6 | Low | `build.sh` swallowed test failures; unformatted source | `go test` is now blocking; a `gofmt` gate was added |
| ZFW-7 | Low | The generated `compiled.sh` ran without `set -e` | Generated script runs under `set -eu` |
| ZFW-8 | Medium | Engine armed the dead-man *after* applying — a failed apply left partial rules with no auto-revert | Dead-man armed *before* apply; partial state reverted on failure |

## Findings — Round 2 (S1 … S9, pre-handoff)

| ID | Sev | Finding | Remediation |
|----|-----|---------|-------------|
| S1 | High | JWKS URL discovered from the *mutable* gateway routes table — the auth trust anchor could be redirected off-host | Discovered target accepted only when it is a loopback address; pinned default otherwise |
| S2 | Medium | JWT verification did not require `exp`, ignored `nbf`, and the JWKS client followed redirects | `exp` mandatory, `nbf` honoured with clock skew, redirects refused |
| S3 | Medium | A malformed `POST /api/apply` body silently fell back to an unsafe apply (no dead-man) | A malformed body is rejected with `400` |
| S4 | Medium | `rules.Validate` had no size limits — a crafted rule set could exhaust resources / fan out geo downloads | Caps on rule, port, v6-drop and country counts |
| S5 | Medium | apply / commit / revert / recompile were not serialised | Serialised behind a mutex |
| S6 | Low | Cached JWKS keys were served indefinitely on refresh failure; `kid` was ignored | Stale keys dropped after a bound; `kid` selects the verification key |
| S7 | Low | The dead-man transient unit could run with a minimal `PATH` | Engine pins a deterministic `PATH` |
| S8 | Low | No integrity check before executing the engine / `compiled.sh` as root | Both are refused unless root-owned and not group/world-writable |
| S9 | Low | `/api/versions` spawned subprocesses uncached; geo files were world-readable | Versions cached 60 s; geo files `0600` in a `0700` directory |

All 17 findings are fixed on `master` across commits `5fad73d`, `95dee93`,
`ee27995` and `bf15dcf`.

---

## Notable findings in detail

**ZFW-1 — unauthenticated control API (Critical).** The ZimaOS gateway
proxies a module's route to the LAN without enforcing the session token;
verified by `curl` that `GET` and `POST` to `/v2/zfw/api/*` reached the
backend unauthenticated. ZFW now verifies the ZimaOS ES256 session JWT
itself, using only the Go standard library (no third-party crypto), against
the platform JWKS.

**S1 — auth trust anchor (High).** The daemon resolved the JWKS endpoint
from the gateway routes table, which any loopback caller can modify. A
poisoned route would let an attacker serve their own signing key and mint
accepted tokens. The discovered target is now trusted only when it is a
loopback address; anything else falls back to the pinned default.

**Command injection — examined, not present.** Because the daemon generates
a bash script executed as root, injection was the focus of the adversarial
review. It is **not exploitable**: `rules.Validate` runs before every
compile and is the sole path into the compiler; IP, CIDR, port and country
inputs are parsed/bounded (`net.ParseIP`, `net.ParseCIDR`, integer ranges,
`[A-Za-z]{2}`), and the free-text rule *name* is never interpolated into the
script.

---

## Residual risk & known limitations

- **ZFW is a packet filter, not an application firewall.** It controls who
  can reach a port, not what they may do once connected. It is one layer of
  defence in depth — application authentication and patching remain
  necessary.
- **The trust anchor is the loopback JWKS endpoint.** Auth is only as sound
  as the ZimaOS platform key service it pins to.
- **The `.raw` image is not byte-reproducible** — `mksquashfs` embeds
  timestamps, so each build yields a different checksum. `install.sh`
  verifies the module against the `.sha256` shipped in the same package, so
  every release package is internally consistent.
- The Exposure and Audit dashboards derive reachability from the legacy
  `allowlist.conf`; on an install that never had one the reachability
  column can read conservatively. This is a display limitation, not a
  filtering one — the firewall itself always compiles from `rules.json`.

---

## Verification

- **Build:** `gofmt` gate, `go vet` and the unit tests (the ES256 verifier
  and the ruleset compiler) all pass.
- **Live:** v0.2.6 was deployed to a ZimaOS 1.6.1 host. The control API
  returns `401` without a valid session token, `403` for a cross-origin
  state-changing request, and `200` only on the public `/api/health`
  endpoint. The hardened `zfw-ui.service` starts the daemon cleanly with no
  sandbox error, and the engine integrity checks accept the correctly
  installed engine and `compiled.sh`.

---

## Conclusion

All 17 findings from both review rounds are remediated. No Critical or High
severity issue is open. The injection class that matters most for a
root-privileged ruleset generator was specifically examined and found
closed. **ZFW v0.2.6 is assessed as fit for a testing handoff**, with the
residual risks above understood and accepted.

---

*© 2026 Virtual Services*
