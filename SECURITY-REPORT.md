# ZFW Security Report

| | |
|---|---|
| **Module** | ZFW — host firewall for ZimaOS |
| **Version reviewed** | 0.2.6 (round 1+2) + 0.2.7–0.2.19 (round 3) + 1.0.0 (round 4) + 1.0.10 (round 5) |
| **Latest review date** | 2026-06-12 (round 5 QA + bug-hunt) |
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

**Cumulative result across five rounds: 50 findings, 45 remediated,
5 accepted residuals.** v1.0.2 closed the three Round-4 Info-grade
residuals (R4-6 / R4-7 / R4-8) plus three older Round-3 residuals
(R3-5 / R3-8 / R3-9). **Round 5** (v1.0.10 full-codebase QA pass,
fixed in v1.0.11) added 15 findings — no Critical/High; the Mediums
cluster around apply atomicity and resource exhaustion, see the
Round-5 section. No Critical or High issue is open. The injection
class is closed across every caller-controlled path (Round-1
`rules.Validate` chokepoint extended in Round-4 via `isSafeRuleID`
and `isSafeContainerID` for the daemon-supplied fields that turned
out to be attacker-controlled on the wire).

| Severity | Found | Remediated | Accepted residual |
|----------|-------|------------|---|
| Critical | 1 | 1 | 0 |
| High | 1 | 1 | 0 |
| Medium | 19 | 17 | 2 |
| Low | 25 | 23 | 2 |
| Info | 4 | 4 | 0 |
| **Total** | **50** | **45** | **5** |

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
| R3-5 | Medium | GET endpoints are not rate-limited — an authenticated user (one valid ZimaOS session token) can flood expensive reads (`GET /api/exposure` shells out to `ss`, `GET /api/events` to `journalctl`) and CPU-pin the daemon | **Fixed in v1.0.2:** new read-side `rateBucket` (burst 60, sustained 5/s) wraps `/api/exposure`, `/api/events`, `/api/conntrack`, `/api/versions` via `rateLimitedGet`. `/api/health` stays uncapped (liveness probe). Same `Retry-After: 1` envelope as the mutate bucket. |
| R3-6 | Medium | One global rate-limit bucket shared across all clients — a runaway browser tab or a poll loop in one UI session can lock the legitimate operator out of `commit` / `revert` during an incident, exactly when responsiveness matters most | **Accepted residual** with the same v0.4 plan |
| R3-7 | Medium | `zfw.service` hardcodes `/DATA/zfw/zfw` and `/DATA/zfw/compiled.sh` regardless of dev paths or `ZFW_COMPILED` override; `ConditionPathExists` makes a non-standard install silently no-op at boot | **Accepted residual** — production install path is fixed and the daemon refuses to start outside it; flagged in `BEST-PRACTICES.md` |
| R3-8 | Low | `internal/events.Read` silently discards `cmd.Wait()` and does not capture journalctl's stderr — an operator wouldn't know if journalctl errored partway through | **Fixed in v1.0.2:** stderr captured, `cmd.Wait()` non-zero + stderr logged at `slog.Debug`. UX preserved (events tab still empties soft on transient hiccups). |
| R3-9 | Low | `POST /api/rules/defaults` silently overwrites the saved rule set; the UI confirms but the API does not require a `?confirm=1` parameter | **Fixed in v1.0.2:** `?confirm=1` query parameter required; 400 with a clear error otherwise. UI sends `?confirm=1`. OpenAPI spec updated. Regression-locked by `TestRulesDefaultsRequiresConfirm`. |
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

## Conclusion of Rounds 1–3

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

## Findings — Round 4 (R4-1 … R4-8, v1.0.0 GA review)

Round 4 covers every code path that landed between v0.2.21 and v1.0.0
(~25 releases / six phases). Methodology: file-by-file adversarial
read driven by the v1.0.0 `THREAT-MODEL.md` adversaries (A1–A7), with
PoC verification for any injection-class candidate.

| ID | Severity | Where | Status |
|---|---|---|---|
| **R4-1** | **Critical** | `Rule.ID` interpolated raw into `compiled.sh` at `compiler.go:423` (`--name z<ID>`) and `:435` (`--log-prefix "ZFW-RULE-<ID> "`); `validateRule` at `rules.go:371` never touches `r.ID`. An authenticated POST `/api/rules` (or `/api/peers/receive` with a valid peer token) with an id like `"ok\"; touch /tmp/zfw-pwned; #"` lands two commands in the root-run bash; the first is a valid LOG line that succeeds under `set -eu`, the second runs as root. Confirmed local PoC by the review agent. | **Fixed in v1.0.1:** new `isSafeRuleID(s)` (rules.go) accepts only `[A-Za-z0-9_-]{1,16}`; `validateRule` calls it before every other check. New test `TestValidateRejectsInjectionID` pins a representative injection string. Compiler at `compiler.go:435` switches to `strconv.Quote("ZFW-RULE-"+r.ID+" ")` as defence-in-depth so a future Validate relaxation can't quietly re-open this path. |
| **R4-2** | Low | `internal/handlers/handlers.go:675` peer-bearer compare uses Go `!=`, which short-circuits and leaks length-information by timing. Globally rate-limited (10/burst, 1/s) so a remote attacker can only run ~60 probes/min. Token space is operator-set with typical high entropy. | **Fixed in v1.0.1:** switched to `crypto/subtle.ConstantTimeCompare` after a length-matched check. |
| **R4-3** | Medium | `sameOrigin` (`cmd/zfwd/main.go:193`) runs on every POST/PUT/DELETE — including `/api/peers/receive` — even though the JWT middleware whitelists the route. `peers.pushOne` never sets `Origin` / `Referer`. Multi-host push fails 403 in any real two-host deployment. The risk is that a maintainer "fixes" the operational bug by removing the same-origin check entirely and silently downgrades defence-in-depth. | **Fixed in v1.0.1:** `peers.pushOne` sets a synthetic `Origin: <follower-base>` header derived from the peer URL so the same-origin invariant is preserved on the receiver side. |
| **R4-4** | Low | `Rule.ContainerID` (`rules.go:92`) has no character or length validation; not currently interpolated into bash but used as a Go map key. Future code that emits it into a command line or log message would inherit injection risk by default. | **Fixed in v1.0.1:** validate against `[A-Za-z0-9_.-]{1,64}` (Docker container-name regex). |
| **R4-5** | Low | Compiler comment at `compiler.go:421` claims "Validate rejects duplicates upstream" — false. Two rules with identical IDs share the same `xt_recent` hashtable bucket, so a rate-limit on rule A burns rule B's window. Operator confusion / firewall-semantics drift, not a privilege boundary loss. | **Fixed in v1.0.1:** `Validate` builds a `seen[id]bool` and rejects duplicate IDs. Compiler comment updated. |
| **R4-6** | Info | Outbound rule `Source.Value` reaches `-d <addr>` unquoted at `compiler.go:343`. `Validate` already canonicalises via `net.ParseIP` / `net.ParseCIDR`, so only `0-9a-fA-F:./` bytes reach the compiler. Not exploitable today; flagged so a future Validate relaxation doesn't quietly open the path. | **Fixed in v1.0.2:** outbound `-d <addr>` is now emitted via `strconv.Quote` as defence-in-depth (mirrors the v1.0.1 R4-1 LOG `--log-prefix` quoting). `rules.Validate`'s `net.Parse*` chokepoint is still the load-bearing control. Regression-locked by `TestOutboundDestQuotedAsDefenseInDepth`. |
| **R4-7** | Info | `update.Checker` (`update.go:62`) and `notify.Hook` (`notify.go:46`) instantiate `&http.Client{Timeout: 10s}` with the default `CheckRedirect` — up to 10 redirects, scheme-agnostic. An attacker controlling DNS for the operator-set URL can coerce a fetch to a private/loopback address and read the HTTP status (response body is not echoed back). Operator-set URL means this is opt-in by configuration, but the S1 / S2 spirit is "trust anchor stays loopback". | **Fixed in v1.0.2:** new shared `internal/httputil.SafeCheckRedirect` callback wired into both clients refuses https→http downgrade, refuses public→private/loopback redirects (DNS-based SSRF chains caught at first hop), caps hop count at 5. Tests with `httptest` cover all four shapes. |
| **R4-8** | Info | Migration `.bak.v<old>` write at `rules.go:269` is a single ≤16KB `os.WriteFile` call — atomic in practice on Linux but not guaranteed by the kernel API. The migration write itself is `tmp + rename` (atomic), but two concurrent `Load` calls on a v0 file both run migration and both write the same `.tmp`. End-state consistent thanks to `rename(2)`. | **Fixed in v1.0.2:** package-level `migrateMu` serialises the migrate+save block. After acquiring the lock, Load re-reads the on-disk schema so a second concurrent caller skips the redundant `.bak` write entirely. |

### Cross-checks ("not-a-finding" surface)

Review agent verified the following paths and found no vulnerability:

- **Frontend XSS** — every `${...}` interpolation in `app.js` that handles
  user/API data passes through `esc()`; unescaped interpolations are
  fixed enum lookups, daemon-controlled integers, or `toFixed()` numerics.
- **Compiler input validation** — country codes, IP/CIDR, port-int, schedule
  HH:MM, weekday names, rate-limit Conn/Seconds, interface names
  (`ZFW_EXTRA_BYPASS_IFACES`) all pass through strict allowlists in
  `rules.Validate` or `config.isSafeIfaceName` before reaching the
  compiler.
- **Schema migration** — future-version refusal path is correct; crafted
  version fields can't poison the round-trip because `Save` always
  overwrites `Version` to `CurrentSchema`.
- **`/api/conntrack`** — JWT-gated; matches the single-admin appliance model.
  Cap of 500 entries; `/proc` parser handles malformed lines safely.
- **`/api/audit` history** — file `0600` in `0700` directory; per-finding cap
  of 20; concurrent reads/writes serialised by `s.auditMu`.
- **Webhook (`internal/notify`)** — fire-and-forget, 15s detached timeout,
  never blocks the firewall flow, response body never reaches a UI client.
- **GeoIP lookup** — `/api/geo/lookup?ips=` capped at 500 entries before
  `LookupBatch`; fingerprint-based staleness detection correct.
- **Docker inventory** — names/images used as map keys (no compile-time
  interpolation); ports `strconv.Atoi`-validated. Safe through to Recompile.

---

## Conclusion of Round 4

Round 4 found **one Critical** (R4-1, authenticated root RCE via
`Rule.ID` injection), **one Medium** (R4-3, peer-push CSRF-rejection
making the multi-host feature operationally broken in a security-
relevant way), three Low (R4-2 / R4-4 / R4-5) and three Info
(R4-6 / R4-7 / R4-8). All five with-fix findings are remediated in
**v1.0.1**; the three Info-grade items were initially tracked as
accepted residuals and are now **all closed in v1.0.2** alongside
three older Round-3 residuals (R3-5 / R3-8 / R3-9).

Cumulative tally across four rounds: **35 findings, 30 remediated,
5 accepted residuals**. The critical finding (R4-1) is the only one of
its kind across all four rounds and re-confirms the injection-class
discipline established in Rounds 1–3 — once `validateRule` covered
every caller-supplied field, the class closed again. The pattern to
watch for in future bumps: any new `Rule.*` field that looks
"daemon-supplied" (because `Save` fills it on empty) but is in fact
attacker-controlled on the wire.

The remaining accepted residuals — R3-6 (per-IP rate-limit), R3-7
(boot-persistence unit path hardcoded), and R3-10 (info-grade
injection re-test, not exploitable) — are architectural / product-
policy items deferred to v1.1 with explicit tracking.

---

## Findings — Round 5 (R5-1 … R5-15, v1.0.10 QA + bug-hunt review)

Round 5 is a full-codebase QA pass over v1.0.10: four parallel
adversarial review agents (API/auth, rule compiler, backend services,
frontend), every candidate finding re-verified by hand against the
source before being accepted. Scanner-grade complexity metrics were
excluded; everything below demonstrably misbehaves.

| ID | Severity | Where | Status |
|---|---|---|---|
| **R5-1** | **Medium** | `compiler.multiport` emitted every port of a list rule into a single `-m multiport --dports` clause. The kernel `xt_multiport` match caps at 15 ports — a 16+-port rule compiled into a line iptables rejects, and under the script's `set -eu` that aborts the whole apply mid-stream with `ZFW-IN` already hooked default-deny and `DOCKER-USER` half-built. Reachable by hand (`Validate` allows 128 ports) and via container-binding substitution (uncapped, see R5-12). | **Fixed in v1.0.11:** `multiport` chunks into ≤15-port emits, one iptables line per chunk. Boundary case (chunk of one → plain `--dport`) covered. Tests `TestMultiportChunksAt15Ports`, `TestMultiportChunkOfOneFallsBackToDport`. |
| **R5-2** | **Medium** | Top-level `lan` / `host_ip` accepted any `net.ParseCIDR`/`ParseIP` value, including IPv6, but are emitted unconditionally into the IPv4-only `DOCKER-USER` chain — same mid-script abort class as R5-1 (host hardened, containers left without their DROP). Rule *sources* had this guard since v0.2.22; the top-level fields did not. Same gap in `firewall.validate` for the legacy conf. | **Fixed in v1.0.11:** both validators require IPv4 (`To4() != nil`). Test `TestValidateRejectsIPv6LANAndHostIP`. |
| **R5-3** | Medium | `/api/status` and `/api/audit` were exempt from the R3-5 read limiter on the premise they "hit memory at worst" — factually wrong: both call `fw.Status`, which forks six subprocesses (`iptables-legacy -S` ×3, `ip6tables-legacy -S`, `systemctl` ×2) per request. An authenticated session could fork-bomb the host through the exact vector R3-5 was meant to close. | **Fixed in v1.0.11:** both wrapped in `rateLimitedGet`; route comment corrected. |
| **R5-4** | Medium | `/api/peers/receive` (JWT-exempt, shared-token auth) had no rate limiter — constant-time compare prevents timing leakage but not full-speed online brute-forcing of `ZFW_PEER_TOKEN` against a root-privileged, rule-overwriting endpoint. | **Fixed in v1.0.11:** wrapped in the mutate limiter (burst 10, 1/s sustained). |
| **R5-5** | Low | `/api/config` (disk-writing POST) and `/api/geo/lookup` (O(ips × CIDRs) linear scan, tens of millions of `Contains` calls with large country zones) were unthrottled. | **Fixed in v1.0.11:** `config` → mutate limiter, `geo/lookup` → read limiter. |
| **R5-6** | Medium | `/api/events?since=0` made the daemon run `journalctl -k --since 1970…` and accumulate the entire retained kernel journal in RAM before `limit` was applied — `limit` bounded the response, not the work. | **Fixed in v1.0.11:** handler floors the window at 7 days; `events.Read` additionally ring-caps raw accumulation at 50k events (oldest half dropped, newest always survive). |
| **R5-7** | Low | `update.CheckOnce` decoded the manifest body with no size limit — a malicious/MITM'd manifest server could stream hundreds of MB into one allocation (URL is operator-set and not forced to HTTPS). Inconsistent with `geo.fetch`'s 16 MB cap. | **Fixed in v1.0.11:** `io.LimitReader(body, 1 MB)`. |
| **R5-8** | Low | The geo HTTP client lacked the `SafeCheckRedirect` hardening that update/notify got in R4-7 — a compromised or redirecting zone source could bounce the root daemon at a private/loopback endpoint. | **Fixed in v1.0.11:** same `httputil.SafeCheckRedirect(5)` wired in. |
| **R5-9** | Low | `SafeCheckRedirect` failed **open** when the redirect target's host didn't resolve: a DNS-rebinding answer that NXDOMAINs at check time and flips to a private A record at dial time walked straight past the public→private guard. | **Fixed in v1.0.11:** fails closed — a public original may only redirect to a hop that provably resolves public. Test `TestSafeCheckRedirectRefusesPublicToUnresolvable`. |
| **R5-10** | Low | `isSafeIfaceName` accepted a bare `+` — iptables' match-ALL-interfaces wildcard. As a `ZFW_EXTRA_BYPASS_IFACES` entry it would silently neuter input filtering on every interface (single-character footgun, operator-controlled). | **Fixed in v1.0.11:** bare `+` rejected; trailing wildcards (`wg+`) still allowed. THREAT-MODEL §8 updated. |
| **R5-11** | Low | `conntrack.Read` parsed the full table (100k+ entries on a busy host) into memory before applying the 500-entry cap. | **Fixed in v1.0.11:** `parseStream` stops at `limit`; the `conntrack -L` fallback kills the subprocess on early stop. |
| **R5-12** | Low | Container-binding port substitution in `recompileLocked` ran *after* `rules.Validate` with no re-validation — a container publishing 16+ host ports bypassed `maxPortsPerRule` and triggered R5-1 even though the stored rule was valid. | **Fixed in v1.0.11:** subsumed by the R5-1 chunking (port values are Docker-sourced integers; only the count was the issue). |
| **R5-13** | Low | The templates-modal renderer was the **only** `innerHTML` sink in `app.js` bypassing `esc()` — name/category/description plus an attribute context, and the error path interpolated `e.message` raw. Not attacker-reachable today (catalog is compile-time constant) but exactly the class R1–R4 closed everywhere else; any future template field sourced from rules.json or a remote catalog would have become stored XSS with no further code change. | **Fixed in v1.0.11:** all five interpolations escaped. |
| **R5-14** | Low | Frontend correctness batch: (a) editing any field of a container-bound rule silently stripped `container_id` when the inventory fetch was slow, failed, or the container was stopped — permanently changing firewall semantics; (b) the Refresh button wiped unsaved rule edits without confirmation; (c) a failed stats refresh after apply/commit/revert overrode the success status with "Error", which during Safe-Apply could stop the user from confirming before the 120 s dead-man reverts. | **Fixed in v1.0.11:** bound container inserted synchronously as a pre-selected option; rules reload skipped while dirty; post-action refresh failures reported separately from the action result. |
| **R5-15** | Info | `geo.Ensure` trusted its callers for country-code shape; `cc` lands in a filepath and the download URL. All current callers validate upstream (`rules.Validate`), so not exploitable — flagged so a future caller can't reintroduce a traversal/SSRF vector. | **Fixed in v1.0.11:** package-local `isValidCC` guard (two ASCII letters). Test `TestEnsureRejectsMalformedCountryCode`. |

### Open recommendation (tracked, not fixed in v1.0.11)

- **JWT claim scoping** — `auth.Verify` validates signature, `exp` and
  `nbf` only. Any ES256 token signed by a key in the ZimaOS JWKS is
  accepted as a firewall-admin session regardless of its type or
  audience. Fixing this requires inspecting the claims real ZimaOS
  session tokens carry (blind pinning would break auth); scheduled for
  v1.0.12 together with the R3-6 per-IP rate-limit residual.

---

## Conclusion of Round 5

Round 5 found **no Critical** and **no High**: the injection class
stayed closed (every candidate was refuted against `rules.Validate` /
`isSafeRuleID` / `isSafeIfaceName`), and the JWT/CSRF perimeter held.
The five Medium findings cluster around two themes the earlier rounds
under-weighted: **apply atomicity** (R5-1/R5-2 — validation gaps whose
blast radius is a half-built ruleset, because the compiled script is
line-by-line `set -eu` rather than an atomic restore) and **resource
exhaustion on authenticated endpoints** (R5-3/R5-4/R5-6 — the R3-5
limiter premise was not re-checked as endpoints grew costlier).

Cumulative tally across five rounds: **50 findings, 45 remediated, 5
accepted residuals** from earlier rounds, plus one newly tracked
recommendation (JWT claim scoping). Scheduled: JWT claim scoping and
the R3-6 per-IP rate-limit → v1.0.12; apply atomicity via
`iptables-restore` → v1.1.

**ZFW v1.0.2 is assessed as fit for the v1.0 General-Availability
release** — the same Round-3 single-admin-appliance threat-model
constraints apply, now extended with the v1.0.0 `THREAT-MODEL.md`
adversary catalogue and `BUG-BOUNTY.md` disclosure process. v1.0.2
closes every Round-4 finding and tightens three Round-3 residuals
that the single-admin model had previously made acceptable.

---

*© 2026 Virtual Services*
