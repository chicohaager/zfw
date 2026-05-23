# ZFW Security Report

| | |
|---|---|
| **Module** | ZFW — host firewall for ZimaOS |
| **Version reviewed** | 0.2.6 (round 1+2) + 0.2.7–0.2.19 (round 3) |
| **Latest review date** | 2026-05-23 (round 3 incremental) |
| **Author** | Holger Kuehn aka Lintuxer |

---

## Executive summary

ZFW is a systemd-sysext module that adds a host firewall to ZimaOS: a Go
daemon (`zfwd`) running as **root**, a web UI served through the ZimaOS
gateway, and a privileged shell engine that applies the iptables ruleset.
Because the component runs as root and its API is reachable across the LAN,
it was security-reviewed in **three rounds**: round 1+2 before the initial
testing handoff at v0.2.6, and **round 3** (incremental) covering the
v0.2.7–v0.2.19 change set after the next-tester feedback cycle drove
defaults seeding, reboot-persistence, the Events tab, IPv6 protection, and
the v0.3-foundation work (handler tests, slog, rate-limit, OpenAPI,
reproducible builds).

**Cumulative result: 27 findings, 22 remediated, 5 accepted residuals.**
No Critical or High issue is open. The injection class examined in round 2
was re-tested against the new code paths (port-range, IPv6 source mirror,
events parser, defaults seeding) and remains **not exploitable** — every
caller-supplied value crosses `rules.Validate` (`net.ParseIP`,
`net.ParseCIDR`, `[A-Za-z]{2}` for country codes, integer bounds for
ports), and the kernel-log strings the events parser reads are
script-display-only, never re-executed.

| Severity | Found | Remediated | Accepted residual |
|----------|-------|------------|---|
| Critical | 1 | 1 | 0 |
| High | 1 | 1 | 0 |
| Medium | 12 | 9 | 3 |
| Low | 13 | 11 | 2 |
| **Total** | **27** | **22** | **5** |

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

## Findings — Round 3 (R3-1 … R3-10, v0.2.7–v0.2.19 incremental review)

Scope for round 3: every change between v0.2.6 (the round-2 handoff
release) and v0.2.19 (current). New attack surface:

- defaults seeding (`rules.Defaults`, `system.DetectLAN`, `DockerPorts`);
- the reboot-persistence systemd unit installed/removed by `engine commit`
  / `revert` (new `/etc/systemd/system/zfw.service`);
- the kernel-log events parser (`internal/events`, new endpoint
  `GET /api/events`);
- the IPv6 INPUT chain with mirrored allow-rules (`compiler.hostLines6`);
- the port-range rule type (`Ports.Type == "range"`);
- the token-bucket rate-limit middleware (`internal/handlers/middleware.go`);
- the embedded OpenAPI 3.0 spec (`GET /api/openapi.{yaml,json}`);
- the reproducible build pipeline and optional SBOM step in `build.sh`.

The review was conducted in two parallel passes — one inside this session
(file-by-file, with adversarial framing for every new caller-controlled
value) and one delegated to a focused subagent for the highest-risk pair
(`engine/zfw` boot-persistence + `middleware.go` rate-limit).

| ID | Sev | Finding | Status |
|----|-----|---------|--------|
| R3-1 | Medium | `engine commit` did not re-verify `compiled.sh` (`secure_file`) before installing the boot-persistence unit — the boot-time `apply` would catch tampering, but only on next boot | **Fixed in v0.2.20:** `commit` now runs the same `secure_file` check as `apply` before writing the unit |
| R3-2 | Medium | `write_persist_unit` truncated `/etc/systemd/system/zfw.service` then wrote, leaving a window where a concurrent `daemon-reload` could observe an empty unit | **Fixed in v0.2.20:** unit is staged in `.tmp` on the same fs, `chmod` while hidden, then atomic `mv -f` |
| R3-3 | Low | `systemctl enable zfw.service \|\| true` swallowed failures — the operator saw "boot-persistence enabled" even when the enable had silently failed (read-only `/etc`, masked unit, sysext quirk) | **Fixed in v0.2.20:** failure surfaces as `exit 1` with a clear error |
| R3-4 | Low | HTTP 429 responses lacked a `Retry-After` header — a naive client could hot-loop and defeat the limiter's CPU-protection goal | **Fixed in v0.2.20:** `Retry-After: 1` set on every rate-limit response |
| R3-5 | Medium | GET endpoints are not rate-limited — an authenticated user (one valid ZimaOS session token) can flood expensive reads (`GET /api/exposure` shells out to `ss`, `GET /api/events` to `journalctl`) and CPU-pin the daemon | **Accepted residual** for the single-admin appliance use case; tracked for the v0.4 "per-IP rate-limit + dashboard polling debounce" item |
| R3-6 | Medium | One global rate-limit bucket shared across all clients — a runaway browser tab or a poll loop in one UI session can lock the legitimate operator out of `commit` / `revert` during an incident, exactly when responsiveness matters most | **Accepted residual** with the same v0.4 plan |
| R3-7 | Medium | `zfw.service` hardcodes `/DATA/zfw/zfw` and `/DATA/zfw/compiled.sh` regardless of dev paths or `ZFW_COMPILED` override; `ConditionPathExists` makes a non-standard install silently no-op at boot | **Accepted residual** — production install path is fixed and the daemon refuses to start outside it; flagged in `BEST-PRACTICES.md` |
| R3-8 | Low | `internal/events.Read` silently discards `cmd.Wait()` and does not capture journalctl's stderr — an operator wouldn't know if journalctl errored partway through | **Accepted residual** — fail-soft was deliberate so a journald hiccup doesn't blank the UI, but a debug log line is on the v0.4 polish list |
| R3-9 | Low | `POST /api/rules/defaults` silently overwrites the saved rule set; the UI confirms but the API does not require a `?confirm=1` parameter | **Accepted residual** — `mutateRL` rate-limit + same-origin CSRF + Bearer token make the unintended-overwrite scenario require either UI use (where the JS confirm dialog runs) or a deliberate authenticated curl |
| R3-10 | Info | Injection re-tested across the new compiler paths (port-range emits `--dport X:Y` only when `Validate` accepted `From/To` integers, IPv6 source mirror passes through `net.ParseCIDR`-validated values, events parser reads from journald not from user input) | **Not exploitable** — validation gates hold across every new path |

### Build pipeline & supply chain

The v0.2.19 reproducible-build hardening was reviewed as a supply-chain
control rather than a runtime control:

- `build.sh` runs `-buildvcs=false`, `-trimpath`, `SOURCE_DATE_EPOCH` from
  the last git commit, GNU-tar with `--sort=name --owner=0 --group=0
  --mtime --pax-option=delete=atime,delete=ctime`, mksquashfs with
  `SOURCE_DATE_EPOCH`-driven timestamps. Two clean builds of the same tree
  produce byte-identical `zfw-<v>.tar.gz` and `.raw` (verified live —
  same `sha256` twice in a row).
- Optional CycloneDX SBOM (`cyclonedx-gomod`) is fetched at build-time
  via `go install ...@latest`. **This is the one new supply-chain trust
  link** — pinning to a specific tag (e.g. `@v1.7.0`) is recommended once
  CI lands on a real GitHub remote.
- The CI workflow file (`.github/workflows/ci.yml`) is committed but
  inactive while the repo has no remote — it asserts reproducibility on
  every build (two builds, SHA compare) and includes an arm64 smoke
  cross-compile.

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
- **GET endpoints are not rate-limited and the mutation bucket is global
  (R3-5, R3-6).** On a single-admin appliance this is acceptable — the
  legitimate operator is the only token-holder — but a misbehaving UI tab
  can momentarily lock its own user out of `commit`/`revert`. v0.4 will
  introduce per-source-IP buckets and a separate (higher) read bucket.
- **The boot-persistence unit hardcodes `/DATA/zfw/*` paths (R3-7).**
  Production installs use exactly those paths; dev checkouts that override
  `ZFW_COMPILED` will not survive a reboot. Not a security flaw — a
  product-policy choice — but worth flagging.
- **`build.sh` fetches `cyclonedx-gomod` via `go install …@latest`** when
  the SBOM step runs. Pinning to a tagged version is recommended once CI
  is live; today the SBOM step is opt-in (build succeeds without it).
- The Exposure and Audit dashboards derive reachability from the legacy
  `allowlist.conf`; on an install that never had one the reachability
  column can read conservatively. This is a display limitation, not a
  filtering one — the firewall itself always compiles from `rules.json`.

---

## Verification

- **Build (round 1+2):** `gofmt` gate, `go vet` and the unit tests for the
  ES256 verifier and the ruleset compiler all pass.
- **Build (round 3):** the suite now has **17 unit tests** — five locking
  in v0.2.7–v0.2.13 regressions in `internal/handlers` (Health, fresh-
  install GET /rules, dead-man lifecycle, friendly fresh-install Safe-Apply
  error, CSRF documentation), the rate-limit burst/sustained test from
  v0.2.17, the OpenAPI-served test from v0.2.18, and five new compiler
  tests (port-range host + docker, IPv6 chain always-emitted, docker-
  bridge bypass, plus the original empty-deny test). All green; `gofmt
  -l .` clean; `go test ./... -race -count=1` passes.
- **Live (round 1+2):** v0.2.6 deployed to a ZimaOS 1.6.1 host — control
  API returns `401` without a valid session token, `403` for a
  cross-origin state-changing request, `200` only on `/api/health`.
- **Live (round 3):** v0.2.19 deployed to the same host and exercised
  end-to-end:
  - dead-man lifecycle proven (Safe-Apply → `deadman:true`, Confirm →
    `false`, 120 s timeout → `false` with `[zfw] DEADMAN FIRED — reverting
    firewall` in the journal);
  - reboot-persistence proven (real `systemctl reboot`, host returns,
    `zfw.service` auto-started, 17 ZFW-IN rules + INPUT hook + 1
    DOCKER-USER drop all restored);
  - IPv6 chain emitted by default (`ip6tables-legacy -S ZFW-IN6` shows the
    14-rule chain ending in `ZFW-IN6-DROP` LOG + `DROP`);
  - port-range round-trip (POST a `{"type":"range","from":5900,"to":5999}`
    rule → `iptables-legacy -S ZFW-IN` shows `--dport 5900:5999 -j DROP`,
    no multiport entries);
  - reproducible builds proven (two clean builds → identical `tar.gz` and
    `.raw` SHA-256);
  - OpenAPI 3.0 spec served at `/api/openapi.{yaml,json}` and parseable.

---

## Conclusion

Across three review rounds, 22 of 27 findings are remediated and 5 are
accepted residuals (all Medium/Low, all documented). No Critical or High
severity issue is open. The injection class that matters most for a
root-privileged ruleset generator was re-examined against every new
caller-controlled path introduced in v0.2.7–v0.2.19 (port-range, IPv6
source mirror, events parser, defaults seeding) and remains closed.

**ZFW v0.2.20 is assessed as fit for continued testing**, with the
single-admin-appliance threat model explicit in the residual list and
clear v0.4 work-items (per-IP rate-limit, GET-throttle, journalctl error
logging) to close the remaining Medium gaps.

---

*© 2026 Virtual Services*
