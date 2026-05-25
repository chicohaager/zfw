# ZFW Threat Model

> Author: Holger Kuehn (Lintux)
> Companion document to [SECURITY-REPORT.md](SECURITY-REPORT.md).
> Target audience: IceWhale's security team, Mod-Store reviewers,
> downstream pen-testers. Reading time: ~15 minutes.

This document declares **what ZFW protects, against whom, with which
controls, and where the residual risk lives**. Every mitigation
references a numbered finding in `SECURITY-REPORT.md` so the reader
can trace claim → finding → code change → test.

---

## 1. System summary

ZFW is a host firewall for ZimaOS. It runs as a systemd-sysext
module that ships:

- **`zfwd`** — a Go daemon bound to `127.0.0.1:8489`, reverse-proxied
  by the ZimaOS gateway at `/v2/zfw` so the UI is reachable
  same-origin via port 80.
- **`/DATA/zfw/zfw`** — a bash engine script run as root, in charge
  of applying / committing / reverting iptables rules and arming the
  120-second dead-man timer.
- **Static web UI** — HTML+CSS+JS served from
  `/usr/share/casaos/www/modules/zfw/`, rendered as a ZimaOS
  dashboard tile.

The daemon's job is to be a *control plane*. It never touches the
kernel directly: it writes a compiled bash script (`/DATA/zfw/
compiled.sh`) which the engine executes. This separation is the
spine of every mitigation below — the daemon's privileges stop at
"can write a file the root engine will run", which is exactly the
boundary the security review pressed against.

---

## 2. Assets

In rough order of value to the operator:

1. **Confidentiality + integrity of `rules.json`** — the source of
   truth for what the firewall does. Tampering = adversary writes
   their own allow rules.
2. **Integrity of `compiled.sh`** — runs as root. Tampering =
   arbitrary command execution as root on next apply.
3. **Integrity of the engine script** (`/DATA/zfw/zfw`) — same
   blast radius as compiled.sh.
4. **Availability of the firewall** — losing the firewall exposes
   every service the host runs. Losing apply/revert atomicity
   strands the host in a half-applied state.
5. **Confidentiality of audit / events data** — surfaces what is
   reachable from the LAN; useful reconnaissance for any next-hop
   attacker.
6. **Persistent boot enablement** — `zfw.service` ensures the
   firewall comes up at boot. Losing it = silent regression at
   the next reboot.
7. **Shared peer-token for multi-host sync** — if disclosed,
   a leader can be impersonated against followers.

---

## 3. Trust boundaries

```
                    ┌─────────────────────────────────────┐
                    │  ZimaOS host (single trust domain)  │
                    │                                     │
   LAN ────────┐    │  ┌──────────┐   ┌──────────────┐   │
   (untrusted) │    │  │  zfwd    │──▶│ /DATA/zfw/   │   │
   ────────────┤────┼─▶│ (127.0.0 │   │ rules.json   │   │
                ┃   │  │ .1 only) │   │ compiled.sh  │   │
   ZimaOS GW ━━┛   │  └─────┬────┘   │ zfw (engine) │   │
   (/v2/zfw,         │       │         └─────┬────────┘   │
   forwards          │       │ writes        │ runs as    │
   without auth)     │       ▼               ▼ root       │
                    │  ┌──────────┐   ┌──────────────┐   │
                    │  │ rules    │──▶│ iptables-    │   │
                    │  │ compiler │   │ legacy       │   │
                    │  └──────────┘   └──────────────┘   │
                    └─────────────────────────────────────┘
```

Boundaries crossed by traffic:

- **LAN → daemon** — every API request crosses here. Gateway
  *does not authenticate*; the daemon enforces JWT auth itself.
- **Daemon → engine** — the daemon writes `compiled.sh`; the
  engine reads it. Adversary in the daemon's user could inject root
  code if compiled.sh is writable to them. Mitigated.
- **Daemon → peer (multi-host sync)** — outbound HTTP to a
  follower's `/api/peers/receive`. Bearer-authenticated, opt-in,
  off by default.
- **Engine → kernel** — engine runs as root; the bash → iptables
  call is the bottom of the stack.

---

## 4. Adversaries

| # | Adversary | Where they sit | Goal |
|---|---|---|---|
| **A1** | LAN-network attacker | Same subnet, can send packets to host IP | Take over the firewall and/or any host service |
| **A2** | Compromised LAN device (IoT, smart TV, guest phone, neighbour) | Trusted-network peer with bidirectional reachability | Pivot to NAS data, scan internal services |
| **A3** | Compromised container | Local on the host, runs as the container's user | Escape the firewall sandbox; pivot to host or other containers |
| **A4** | Malicious app from the ZimaOS Mod-Store | Installed by the user, root inside its container, unprivileged on host | Persist a backdoor through the firewall; phone home |
| **A5** | Network-local MITM | Active on the L2 segment (rogue AP, ARP spoofing) | Hijack the daemon's outbound calls (updates, webhooks, peer-sync) |
| **A6** | Authenticated UI user with a stolen session token | Holds a valid ZimaOS JWT (e.g. token leak via XSS in another module) | Reconfigure or disable the firewall remotely |
| **A7** | Local non-root user on the host | Shell access as a non-root user | Tamper with rules.json or `compiled.sh` for root-code execution |

Out of scope as ZFW threats (but documented because they neighbour
the model):

- **The kernel itself** — kernel CVEs are tracked on the Versions
  tab (see `internal/system.versions`) but ZFW does not patch the
  kernel.
- **The ZimaOS gateway / web server** — out-of-band vulnerabilities
  in the gateway proxy are IceWhale's responsibility; ZFW
  defends *at the daemon layer* against the gateway forwarding an
  unauthenticated request.
- **Side-channels** — timing attacks on the rate limiter, etc.,
  are not modelled. The bucket is best-effort CPU-protection,
  not a cryptographic constant-time primitive.

---

## 5. Mitigations (claim → finding → code)

This section is the connective tissue: every adversary above is
contained by a finite set of controls, each one cross-referenced
to a finding in `SECURITY-REPORT.md`.

### 5.1 LAN-attacker / unauthenticated access (A1, A2, A6)

| Control | Finding | Code |
|---|---|---|
| ZimaOS session JWT verified on every API call | ZFW-1, S1, S2, S6 | `internal/auth` |
| Daemon binds 127.0.0.1 only — never directly LAN-reachable | (architectural) | `cmd/zfwd/main.go` bind addr |
| JWKS trust anchor pinned to loopback; mutable-gateway routes refused | S1 | `cmd/zfwd/main.go` `isLoopbackURL` |
| Same-origin CSRF check on every state-changing request | ZFW-4 | `cmd/zfwd/main.go` `sameOrigin` |
| Token-bucket rate limit on every non-GET endpoint (burst 10, 1/s sustained) | (v0.2.17) | `internal/handlers` `rateBucket` |
| `Retry-After: 1` on 429 so naive clients don't hot-loop | R3-4 | `internal/handlers/ratelimit.go` |

### 5.2 Rule-set integrity / privileged-command injection (A1, A6, A7)

| Control | Finding | Code |
|---|---|---|
| `rules.Validate` is the only path between JSON and the compiler | ZFW-2 | `internal/rules.Validate` |
| Caps on every list field — rules, ports, country, schedule days, notes, rate-limit | S4 | `internal/rules/rules.go` |
| Interface names for `ZFW_EXTRA_BYPASS_IFACES` validated against a strict char-set before reaching the compiler | (v0.5.4) | `internal/config.isSafeIfaceName` |
| `/DATA/zfw` is `root:root 0700`; `compiled.sh` is `0600` | ZFW-3, S9 | `cmd/zfwd/main.go` startup `Chmod` |
| Engine refuses to execute `compiled.sh` or itself if root is not the owner OR if anyone but root has write | S8 | `engine/zfw` `secure_file` |
| `commit` re-runs `secure_file` before installing the boot-persistence unit so tampering caught at apply isn't bypassed by a stale unit | R3-1 | `engine/zfw` |
| Engine runs under `set -eu` so a partial-apply aborts loudly instead of silently | ZFW-7 | `internal/compiler/compiler.go` |
| Schema-versioned `rules.json` migration with `.bak.v<old>` backup | (v0.3.8 + v0.4.3 + v0.5.6) | `internal/rules.migrate` |

### 5.3 Firewall availability (A1 attack on safety)

| Control | Finding | Code |
|---|---|---|
| Safe-Apply armed *before* `compiled.sh` runs; partial-apply triggers immediate revert | ZFW-8 | `engine/zfw` |
| `apply` / `commit` / `revert` serialised behind a mutex | S5 | `internal/handlers.Server.mu` |
| Boot-persistence unit written atomically (`.tmp` → `mv`) | R3-2 | `engine/zfw` `write_persist_unit` |
| `systemctl enable zfw.service` failure surfaces with `exit 1` | R3-3 | `engine/zfw` |
| Dead-man timer transient unit pins a deterministic `PATH` | S7 | `engine/zfw` `apply --safe` |
| Outbound chains (v0.5.6 — ZFW-OUT, ZFW-FWD-OUT, ZFW-OUT6) **never default-deny** so a blanket OUTPUT/FORWARD policy cannot brick the host's own DNS / NTP / Docker pulls | (v0.5.6 design invariant) | `internal/compiler/compiler.go`; test `TestOutboundChainTerminatesInReturn` |

### 5.4 Container escape / docker-bypass (A3, A4)

| Control | Finding | Code |
|---|---|---|
| Docker-published ports filtered at `DOCKER-USER`, not INPUT — published ports bypass INPUT via DNAT and would otherwise be ungated | (architectural) | `internal/compiler.dockerLines` |
| Container-bound rules resolve to the *current* host-published ports at every Recompile — a container that swaps ports does not silently lose its rule | (v0.5.7) | `internal/handlers.Server.Recompile` |
| Outbound rules for `Zone=docker|auto` emit on a `ZFW-FWD-OUT` chain hooked into FORWARD — a compromised container's egress can be blocked at the host level without the container needing to cooperate | (v0.5.6) | `internal/compiler/compiler.go` |
| Container bypass list (lo, docker0, br-+, virbr0, tailscale0, zt+, wg+) does not include the LAN — a container that wants to phone home outbound still hits ZFW-FWD-OUT user rules | (v0.5.4) | `internal/compiler/compiler.go` |

### 5.5 Multi-host & outbound trust (A5)

| Control | Finding | Code |
|---|---|---|
| `/api/peers/receive` requires a shared bearer token; ZimaOS JWT middleware is bypassed for this route alone | (v0.3.10) | `internal/handlers.peersReceive` |
| Disabled by default — empty `ZFW_PEER_TOKEN` returns 403 unconditionally | (v0.3.10) | same |
| Peers list is token-stripped before serving via `/api/peers` so a compromised UI session cannot exfiltrate the shared secret | (v0.3.10) | `internal/peers.Sanitize` |
| Outbound peer-push uses a 30s-timeout HTTP client; per-peer results returned without short-circuit so one slow follower doesn't pin the leader | (v0.3.10) | `internal/peers.Push` |
| Self-update (`ZFW_UPDATE_URL`) and webhook (`ZFW_WEBHOOK_URL`) both opt-in with empty defaults — no outbound HTTP from a fresh install | (v0.3.9, v0.5.5) | `internal/update.New`, `internal/notify.New` |

### 5.6 Hardening / defence-in-depth

| Control | Finding | Code |
|---|---|---|
| `zfw-ui.service` runs with 11 systemd hardening directives (filesystem, namespace, capability) | ZFW-5 | `raw/usr/lib/systemd/system/zfw-ui.service` |
| Structured logging via `slog` — every event is `key=value` with source location | (v0.2.17) | `cmd/zfwd/main.go` |
| Reproducible builds — two clean builds of the same source produce byte-identical tarballs | (v0.2.19) | `build.sh` SOURCE_DATE_EPOCH path |
| CI gate — `go test` blocking, `gofmt` blocking, reproducibility-verify | ZFW-6, R3-10 | `.github/workflows/ci.yml`, `build.sh` |
| OpenAPI 3.0 spec served from `/api/openapi.{json,yaml}` — third-party tools (n8n, Home Assistant) don't have to read Go to integrate | (v0.2.18) | `docs/openapi.yaml`, `internal/handlers.openapi` |

---

## 6. Accepted residual risks

These are the trade-offs ZFW *deliberately* makes. The reviewer
should treat each as a known limit, not a missing control.

| Residual | Finding | Rationale |
|---|---|---|
| GET endpoints are not rate-limited | R3-5 | Single-admin appliance use case; expensive-read endpoints (`/api/exposure`, `/api/events`) are short and bounded. Per-IP throttling is on the v1.x backlog. |
| Single global rate-limit bucket | R3-6 | A runaway browser tab in one session can briefly delay other sessions' POSTs. Per-session buckets need session-ID tracking the daemon does not currently keep. |
| Unit-file path hardcoded (`/DATA/zfw`) | R3-7 | The production install path is fixed; the boot-persistence unit's `ConditionPathExists` makes a non-standard install no-op safely. Documented in `BEST-PRACTICES.md`. |
| `journalctl` errors swallowed by `internal/events.Read` | R3-8 | Fail-soft: a journald hiccup must not blank the Events tab. Debug logging is a v1.x polish. |
| `POST /api/rules/defaults` overwrites without `?confirm=1` | R3-9 | The UI confirms via JS dialog; the API only surfaces this path with a valid JWT + same-origin + rate-limit gate, making unintentional CLI invocation a deliberate authenticated curl. |
| `/proc/net/nf_conntrack` only populated after first Safe-Apply | (v0.5.0 + tester report) | The conntrack kernel module loads on first ZFW iptables `-m conntrack` rule. The Connections tab shows an explanatory empty state until then. |
| GeoIP flags require ≥1 country `.zone` file cached | (v0.4.5) | The geo manager downloads only countries that user-configured rules reference. Tester-observed: a host behind NAT with no country rules sees no flags. Documented in `THREAT-MODEL.md` itself (this very row) and on the Events tab. |
| Outbound rules cannot default-deny | (v0.5.6 design invariant) | A blanket OUTPUT/FORWARD policy of DROP would brick the host's own DNS / NTP / Docker registry pulls and the gateway forwarding. Outbound is per-rule only — by construction. |
| No watcher for live Docker port changes | (v0.5.7) | Container rule binding is resolved at Recompile; user re-runs Safe-Apply after a container port remap. A `docker events` watcher is a v1.x polish (auto-apply would skip the dead-man, which the design refuses). |
| Mod-Store submission on hold | (v0.4.0) | Daemon-side complete; the PR against `IceWhaleTech/Mod-Store` is a manual operator action. Documented in `MOD-STORE.md`. |

---

## 7. Verification map

For each adversary, the test that proves the corresponding control
holds:

| Adversary | Control | Test |
|---|---|---|
| A1 LAN attacker | JWT auth on every API call | `internal/auth/*_test.go` |
| A1 | Loopback-only JWKS trust anchor | (manual + S1 finding in SECURITY-REPORT) |
| A1, A6 | CSRF same-origin | (manual + ZFW-4 finding) |
| A1, A6 | Rate-limit on mutate endpoints | `TestMutateRateLimitTrips` |
| A6 | `/api/health` is the only auth-bypass route | `cmd/zfwd/main.go` middleware whitelist |
| A6 | `/api/peers/receive` requires its own bearer, not JWT | `TestPeersReceiveDisabledReturns403`, `TestPeersReceiveRejectsWrongToken` |
| A1, A6 | Bad JSON / missing body bounces with 400, not unsafe-default | `TestApplyRejectsMalformedJSON` |
| A1, A6 | Validate rejects oversized rule sets | `TestValidateRejects*` family |
| A3 | DOCKER-USER filters published container ports | `TestDockerDenyRule`, `TestDockerPortRange` |
| A4 | Container egress can be blocked at FORWARD | `TestOutboundDockerRuleEmitsZFWFwdOut` |
| A4 | Container-bound rule follows container's port changes | (live behaviour — covered by `internal/handlers.Server.Recompile` resolution path; no automated docker-events test in v0.5.7) |
| A1 | Engine refuses world-writable `compiled.sh` | `engine/zfw secure_file` (manual + S8 finding) |
| A1 | Safe-Apply auto-reverts on failure | `TestApplyHappyPath`, `TestApplyEngineErrorBubblesUp`, integration test in `internal/compiler` netns suite |
| A5 | Webhook / update / peers all opt-in by URL | `TestSendDisabledIsNoop`, `TestCheckOnceDisabledIsNoop` |
| A5 | Peer push uses bounded timeout | `internal/peers.DefaultClient` (30s) |
| A5 | Update manifest URL TLS validated through standard `http.Client` | (no per-test; relies on Go stdlib TLS defaults) |

---

## 8. What this document is not

- **Not a substitute for an external pen-test.** The
  `SECURITY-REPORT.md` is three rounds of internal review; the
  v1.0 spec calls for at least one external party. Bug-bounty
  contact / scope is in `BUG-BOUNTY.md` (shipping with v1.0.0).
- **Not a guarantee that all attack paths are listed.** New
  features in v1.x+ will land their own findings — the trail is
  the per-version section of `SECURITY-REPORT.md`, not this
  document.
- **Not a guarantee against kernel exploits.** ZFW assumes the
  Linux kernel and iptables stack behave as documented. The
  Versions tab flags known-CVE versions; remediation is upstream.
- **Not a guarantee against operator misconfiguration.** The
  Safe-Apply / dead-man machinery is designed to make
  lock-yourself-out impossible *for the firewall itself*; an
  operator who configures `ZFW_EXTRA_BYPASS_IFACES=*` (a wildcard
  that matches every interface) bypasses ZFW entirely. Validate
  catches the obvious cases; the operator owns intent.

---

## 9. Reading further

- `SECURITY-REPORT.md` — three-round internal security review,
  27 findings, 22 remediated, 5 accepted residuals
- `BEST-PRACTICES.md` — operator-facing safety guide
- `BUG-BOUNTY.md` — contact + scope for external researchers
  (v1.0.0)
- `docs/openapi.yaml` — every endpoint, every parameter, every
  failure code
