# ZFW Code-Quality Review — v1.0.0

> Companion document to [SECURITY-REPORT.md](SECURITY-REPORT.md) (vulns)
> and [THREAT-MODEL.md](THREAT-MODEL.md) (assets/adversaries). This
> doc covers **engineering quality**: architecture, patterns, smells,
> test-coverage gaps, documentation drift. Findings here are
> maintenance hazards — not vulnerabilities.

The review was conducted by a second-pass Engineer agent against the
v1.0.0 GA codebase (~25 releases of growth since SECURITY-REPORT.md
Round 3 at v0.2.20). Severity is engineering-impact, not security.

---

## Overall assessment

ZFW is a genuinely well-built Go codebase that punches above its
weight for a single-maintainer project: 15 internal packages with
clear boundaries, structured logging through `slog`, context plumbed
to the syscall boundary, and an extremely defensible
compiler↔engine separation. Test coverage is solid at the unit +
contract layer (>130 Go tests across 13 `_test.go` files).

The biggest engineering weakness is the **`internal/handlers`
package**, which has accreted nineteen handler funcs (~750 LoC)
without ever extracting the recurring `lock → validate → save →
recompile → emit` sequence. The four lifecycle endpoints (`rules`
POST, `apply`, `commit`, `revert`) re-implement the same plumbing
four slightly different ways. **CQ-2 (now fixed in v1.0.1)** was the
worst instance — `rulesDefaults` silently skipped Validate,
Recompile and emitEvent. The remaining duplication (CQ-1) is on the
v1.x refactor list.

Five packages shipped without any tests at v1.0.0: `config`, `firewall`,
`gateway`, `system`, `watchdog`. v1.0.2 adds tests for `config` and
`system` (the two pure-function packages); `firewall`, `gateway`,
`watchdog` still need real systemd / iptables / HTTP test infrastructure
and stay on the v1.1 list. The added tests lock in the parsers that are
most exposed to external-tool format drift —
`system.parseDockerPorts`, `extractVersion`, `parseKernel`,
`opensshVersion`, `kernelVulnerable`, `dockerOld`, plus
`config.parseIfaceList` / `isSafeIfaceName`.

---

## Highlights (well-engineered)

- **Compiler ↔ engine separation.** `internal/compiler/compiler.go`
  produces a deterministic bash script; `engine/zfw` *executes* it
  and owns the dead-man machinery. This is the spine of every
  security claim and the right line to defend against future "let's
  move it into Go" refactors. The `wrapEmit(match, r, target)`
  helper at `compiler.go:416` is exemplary — LOG/rate-limit emit
  shape stays byte-identical across host/IPv6/docker chains.
- **Schema-versioned migration**, additive by construction. The
  v0→v1→v2→v3 chain in `rules.migrate` lives next to `CurrentSchema`
  with one switch arm per bump and a `.bak.v<old>` safety net.
  Future bumps land cleanly.
- **Auth posture** in `internal/auth/auth.go`: ES256-only, mandatory
  `exp`, kid-pinned key rotation, redirect-refusing HTTP client,
  JWKS max-stale window, loopback-trust-anchor enforced in
  `main.go:isLoopbackURL`.
- **Atomic file writes** everywhere that matters (`writeAtomic` in
  rules, `SaveHistory` in audit, `write_persist_unit` in engine,
  `renderIpset` + `fetch` in geo). Consistent `tmp + rename` pattern.
- **JSON `omitempty` discipline** on the v2/v3/v0.4.x additive
  fields (`Schedule`, `RateLimit`, `Notes`, `Direction`,
  `ContainerID`, `Log`, `Ports.From/To`) is correct — a v1 file with
  no schedule, or a v2 file with no direction, round-trips
  byte-equal after a Save. Many projects get this wrong on the
  third bump.
- **Same-origin CSRF + JWT + rate-limit triplet** in `main.go` is
  layered cleanly with each control in its own helper.
- **Test-suite shape.** `handlers_test.go` uses a small hand-written
  `fakeFirewall` instead of a mocking library — the right call for
  a small daemon, keeps the regression-lock-in tests readable.
- **Engine bash uses `set -u` with surgical `|| true`** exactly on
  the lines that must tolerate "rule not present yet" (revert path)
  — the disciplined version of `|| true`, not the lazy version.

---

## Findings — engineering quality

Severity is engineering impact (High = next-maintainer trip-wire;
Medium = will bite during a refactor; Low = nice-to-have; Nit =
cosmetic).

### CQ-1 — Four lifecycle handlers duplicate lock/save/recompile/emit — **High**
**Where:** `internal/handlers/handlers.go` rules-POST, apply, commit, revert; also peersReceive.
**Status:** Open — flagged for v1.x. Partial mitigation in v1.0.1 (CQ-2 fix aligns rulesDefaults with the rest).
**Smell:** The same idiom `s.mu.Lock(); defer Unlock(); validate → save → reqCtx → Recompile → emitEvent` appears at four call sites in three subtly different shapes. A reader trying to answer "what runs when a rule changes?" has to diff four code blocks to spot which steps are missing in which path.
**Fix sketch:** Extract `(s *Server) mutateRules(ctx, mutate func(*rules.RuleSet) error, event string) error`. Each handler becomes a 5-line wrapper.

### CQ-2 — `rulesDefaults` silently skipped Validate + Recompile + emitEvent — **High**
**Status:** ✅ **Fixed in v1.0.1**.
**What changed:** `rulesDefaults` now validates, saves, recompiles and emits `rules.defaulted` — matching the rules-POST contract. Also fixed CQ-8 in the same patch: prefer the user's saved LAN over a fresh `DetectLAN()`.

### CQ-3 — Container-binding name/ID map collides silently — **Medium**
**Where:** `internal/handlers/handlers.go:124-128`.
**Status:** ✅ **Fixed in v1.0.2.**
**What changed:** Split into two maps — `byID` (canonical, looked up first) and `byName` (fallback). A genuine name/ID collision between *different* containers now emits a `slog.Warn` so the operator can rename one; the byID/byName split keeps the lookup semantics deterministic (ID wins).

### CQ-4 — Remaining German strings in user-facing paths — **Medium**
**Status:** ✅ **Fixed in v1.0.1**.
**What changed:** `firewall.go:216` "ist" → "is"; `geo.go:96` German log message → English; `migrate.go:48-50` rule names (migriert) → (migrated). The "english-only" project policy now holds across user-visible Go strings. (UI/HTML/docs are already English.)

### CQ-5 — Five packages have zero tests — **Medium**
**Where:** `internal/config`, `internal/firewall`, `internal/gateway`, `internal/system`, `internal/watchdog`.
**Status:** ✅ **Fixed in v1.0.2 (partial — config + system).** firewall, gateway and watchdog still lack tests (they need real systemd / iptables / HTTP test infrastructure) and remain on the v1.1 list.
**What changed:** New `internal/config/config_test.go` covers `parseIfaceList` + `isSafeIfaceName` with a strict-allowlist + injection-attempt table. New `internal/system/system_test.go` covers `parseDockerPorts` (three documented input shapes), `extractVersion`, `opensshVersion`, `parseKernel`, `kernelVulnerable`, `dockerOld`.

### CQ-6 — `peersPush` is the only lifecycle handler without webhook emit — **Low**
**Where:** `internal/handlers/handlers.go` peersPush.
**Status:** ✅ **Fixed in v1.0.2.**
**What changed:** `peersPush` now emits `peers.pushed` with `{peers, ok, fail}` totals after `peers.Push` returns. n8n / Home Assistant integrations get the multi-host sync signal that other lifecycle events have always had.

### CQ-7 — `RuleSet.V6Drop` lacks `omitempty` — marshals as `null` — **Low**
**Where:** `internal/rules/rules.go` RuleSet struct.
**Status:** ✅ **Fixed in v1.0.2.**
**What changed:** `Save()` initialises `V6Drop` to `[]int{}` when nil so the wire shape is always `"v6_drop": []`. Chosen over `,omitempty` so the OpenAPI required-fields list does not change. Pinned by `TestSaveInitialisesV6DropToEmpty`.

### CQ-8 — `rulesDefaults` re-detected LAN, overwriting user-set value — **Low**
**Status:** ✅ **Fixed in v1.0.1** alongside CQ-2.

### CQ-9 — `Recompile` holds the lock through `docker ps` + geo downloads — **Low**
**Where:** `internal/handlers/handlers.go` Recompile.
**Status:** ✅ **Fixed in v1.0.2.**
**What changed:** Split into `prefetchForCompile` (slow IO — `DockerContainers`, `DockerPorts`, `geo.Ensure` — outside any lock) and `recompileLocked` (fast in-memory + `os.WriteFile` under `s.mu`). The public `Recompile` chains both. Every mutate handler (`rules` POST, `apply`, `rulesDefaults`, `peersReceive`) now runs the slow prefetch *before* taking `s.mu` so a concurrent commit/revert no longer queues behind a 40-country geo refresh.

### CQ-10 — Engine `commit` chains five steps but only checks one — **Low**
**Where:** `engine/zfw` commit case.
**Status:** ✅ **Fixed in v1.0.2.**
**What changed:** New `apply_or_die "$@"` helper at the top of the engine. `write_persist_unit`, `systemctl daemon-reload` and `systemctl enable zfw.service` are each wrapped — a silent failure in any step now aborts commit with a clear `[zfw] ERROR: <cmd> failed` instead of letting the operator believe boot-persistence is active when it isn't.

### CQ-11 — `app.js saveRuleFromEditor` is 120 lines of inline validation — **Low**
**Where:** `raw/usr/share/casaos/www/modules/zfw/app.js` saveRuleFromEditor.
**Status:** Open — flagged for v1.x.
**Smell:** Reads 19 DOM inputs and re-implements every server-side validation rule. When schema v4 lands, eleven `modalError(...)` calls have to mirror the backend change.
**Fix sketch:** Extract `validateRulePartial(fields) → errorString | null` as a pure JS function. The single-file vanilla-JS design intent stays — the refactor is *inside* that decision.

### CQ-12..CQ-15 — Nits — **Nit** — all ✅ Fixed in v1.0.2
- **CQ-12** `update.Compare("1.2.3", "1.2.3-rc1")` returns 0 (suffix stripped). v1.0.2: documented in the Compare doc-comment + pinned by `TestCompareTreatsPreReleaseAsEqual` so a future maintainer considering -rc publishing knows to revisit.
- **CQ-13** `gateway`/`watchdog` took legacy `func(string, ...any)` loggers via the `slogf` bridge. v1.0.2: both now accept `*slog.Logger` directly (nil logger discards via `io.Discard`); `slogf` adapter removed from `main.go`.
- **CQ-14** `Versions` was cached, `DetectLAN` was not. v1.0.2: `DetectLAN` cached behind `lanMu` with the same 60s TTL (`lanTTL`).
- **CQ-15** `events.parseDropLine` used `strings.Cut` which truncates values containing further `=`. v1.0.2: switched to `strings.SplitN(_, "=", 2)`; regression-locked by `TestParseDropLinePreservesEqualsInValue`.

---

## Summary table

| ID | Severity | Title | Effort | Status |
|---|---|---|---|---|
| CQ-1 | High | Four lifecycle handlers duplicate plumbing | M | Open (v1.1) |
| CQ-2 | High | rulesDefaults skipped Validate + Recompile + emit | S | ✅ Fixed v1.0.1 |
| CQ-3 | Medium | Container-binding map collision | S | ✅ Fixed v1.0.2 |
| CQ-4 | Medium | German strings in user-facing paths | S | ✅ Fixed v1.0.1 |
| CQ-5 | Medium | 5 packages with zero tests | M | ✅ Fixed v1.0.2 (config + system; firewall/gateway/watchdog deferred to v1.1) |
| CQ-6 | Low | peersPush has no webhook emit | S | ✅ Fixed v1.0.2 |
| CQ-7 | Low | RuleSet.V6Drop marshals as null | S | ✅ Fixed v1.0.2 |
| CQ-8 | Low | rulesDefaults overwrote saved LAN | S | ✅ Fixed v1.0.1 |
| CQ-9 | Low | Recompile holds mutex through subprocess/HTTP | M | ✅ Fixed v1.0.2 |
| CQ-10 | Low | Engine commit only checks last step | S | ✅ Fixed v1.0.2 |
| CQ-11 | Low | app.js saveRuleFromEditor monolith | M | Open (v1.1) |
| CQ-12 | Nit | update.Compare ignores -rc suffix | S | ✅ Fixed v1.0.2 (documented + test) |
| CQ-13 | Nit | gateway/watchdog use printf-shape logger | S | ✅ Fixed v1.0.2 |
| CQ-14 | Nit | DetectLAN not cached like Versions | S | ✅ Fixed v1.0.2 |
| CQ-15 | Nit | events.parseDropLine truncates '=' values | S | ✅ Fixed v1.0.2 |

---

## Test-coverage gaps (ordered by risk)

- **`internal/system` — 0 tests, highest risk.** `parseDockerPorts`,
  `extractVersion`, `opensshVersion`, `parseKernel`, `kernelVulnerable`,
  `dockerOld` are pure parsers over external-tool output. Format
  change in `docker --version` or `ssh -V` between distros would
  silently degrade the Versions tab and /api/system/containers.
- **`internal/firewall` — 0 tests.** `secureRootFile` permission gate
  is security-critical; `LoadConfig`/`SaveConfig` round-trip; `splitPorts`
  parser. `fakeFirewall` in handler tests bypasses the real Manager.
- **`internal/gateway` — 0 tests.** `mgmtURL` URL normalisation,
  `Register` idempotency, `RegisterWithRetry` exponential backoff loop.
- **`internal/watchdog` — 0 tests.** Writes `/etc` files and shells
  `systemctl daemon-reload`; the "rewrite-if-different" check is a
  one-liner with regression potential.
- **`internal/config` — 0 tests.** `parseIfaceList` + `isSafeIfaceName`
  are strict-allowlist parsers — exactly the place where a future
  "let's also accept colons" change should fail a test.
- **`internal/handlers` — well-tested but gaps.** No test for the
  apply→Recompile error path branch (`handlers.go:382-387`), no test
  for the container-binding port-substitution path (`handlers.go:122-140`
  — `TestSystemContainersReturnsArray` only checks the endpoint shape).
- **`internal/compiler` — strongest coverage** (28+ tests). Gap: no
  test for `scheduleArg` with mixed-case day names (allow set vs.
  accept set).
- **`internal/rules` — solid** (13+3+v1.0.1 R4 tests). Gap: no test
  for `FromTiers` v0→rule-model migration shape.

---

## Documentation drift

Spot drift (low priority but worth a cleanup pass before any external
publication):

- **README §Architecture** lists 6 internal packages — actual count
  is 18 (the original 6 plus auth, buildinfo, compiler, config,
  conntrack, events, geo, handlers, notify, peers, rules, update).
- **README mentions** `lo`/`tailscale0`/`zt+` as always-allowed bypass
  interfaces but **omits `wg+`** which has been built-in since v0.5.4.
  THREAT-MODEL §5.4 mentions it correctly; README does not.
- **README §Configuration** documents only the legacy `allowlist.conf`
  keys. The actual v0.2+ source of truth is `rules.json`, edited from
  the UI. The legacy file is migration-only.
- **ROADMAP.md is enormous** (~70KB) — stream-of-consciousness append-log
  rather than a roadmap. The phase-recap table in README is much more
  useful. Consider promoting it to ROADMAP as the canonical reference.
- **No user-facing mention of the `maxGeoCountries = 40` cap.** A user
  who pastes a 50-country list gets a confusing save error.
- **OpenAPI spec** (`docs/openapi.yaml`) — not reviewed file-by-file
  against handler signatures, especially the v0.5.x additions.
  Worth a separate sweep.

---

## What this document is not

- **Not a vulnerability list.** Security findings are in
  `SECURITY-REPORT.md` Round 4.
- **Not a refactor PR.** It's a punch list for the next maintainer
  (or a future you).
- **Not exhaustive.** Two passes by two agents will find more.
  Treat this as the v1.0.0 baseline — every future review should
  add or close items, not start from scratch.
