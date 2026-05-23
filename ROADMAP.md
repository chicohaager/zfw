# ZFW Roadmap

> Author: Holger Kühn (Lintux)
> Status: v0.2.20 — live on a ZimaOS 1.6.1 host, security-reviewed (three rounds), English UI,
> intelligent default-set with live Docker inventory, reboot-persistent,
> with a working Events / IDS-MVP tab (host + host6 + docker zones),
> Docker-bridge bypass, the Donezo-style light-theme UI, default-deny IPv6
> INPUT chain, port-range rule support and the first batch of v0.3 handler
> tests (deadman-lifecycle regression lock-in).

This document lays out where ZFW goes from "working tool" to "professional
ZimaOS module that an IceWhale moderator would recommend without caveats."

The goal of each release is small and concrete. No feature is in a phase
because it *might* be useful — every entry has a user pain it removes or a
quality bar it raises.

---

## Delivered in v0.2.7 – v0.2.13

The current v0.2 line addressed every regression and gap surfaced by the
first external test cycle (Gelbuilding / IceWhale forum). All items below
ship in v0.2.13.

| Version | What shipped | Why it mattered |
|---|---|---|
| **v0.2.7** | `/api/rules` returns an empty deny-default set on a fresh install instead of HTTP 500; all backend error strings translated from German to English; all Audit-tab findings and Versions-tab notes translated. | First-install UX was broken — UI opened with a red banner. The bug also made the localization gap visible. |
| **v0.2.8** | Safe-Apply on an empty rule set returns a clear *"no rules saved yet — open the Rules tab, add a rule and click Save"* (HTTP 400) instead of a raw file-not-found error. | The "nothing to apply" state was bewildering and looked like a daemon bug. |
| **v0.2.9** | Fresh install seeds a recommended starter rule set with the LAN auto-detected from the default route. New "Recommended defaults" button on the Rules tab. The 5 baseline allow-rules keep the ZimaOS web UI, SSH, Samba shares and mDNS reachable; default policy is deny. | Empty-state Apply was a foot-gun — it would have locked the user out of every service. |
| **v0.2.10** | Default seed is now built from a live system inventory: one extra allow-rule per Docker-published port discovered on the host (e.g. `:8085 moviestation`, `:15800 xpkg-desktop`). So the user's running containers stay reachable when they Safe-Apply. | A static baseline would silently kill whatever Docker apps the user already had running. |
| **v0.2.11** | Engine `commit` now installs and enables `/etc/systemd/system/zfw.service` (Type=oneshot, After=docker.service); `revert` removes it. The committed firewall genuinely survives a reboot. Verified end-to-end on a test ZimaCube. | The UI's "Boot-persistent" indicator was a UX promise the code had never kept. |
| **v0.2.12** | New **Events** tab: iptables LOG targets emit drop events to journald, the daemon parses them via `journalctl -k -o json`, the UI shows a live table (time / source IP / dest port / proto / zone). New "Drops (1h)" stat in the header. Volume control uses `-m conntrack --ctstate NEW` so a port scan can't flood the journal (ZimaOS doesn't ship `xt_limit`). | Users could not see what their firewall was actually doing — no observability, no IDS-style visibility. |
| **v0.2.13** | `docker0` and `br-+` added to the ZFW-IN bypass list — container-to-host traffic (mDNS, DNS, etc.) no longer hits the catch-all DROP. Verified by zero new docker-bridge events after a 60 s observation window on a host running 5+ containers. | A regression of v0.2.12: the new Events tab made it visible that container traffic was being silently dropped, which had presumably been broken in earlier versions but invisible. |
| **v0.2.14** | Light-theme UI overhaul inspired by the Donezo dashboard: warm off-white page background, white cards with soft shadows and 18 px corners, forest-green primary accent, pill-shaped status badges, Fira Sans / Fira Code typography, KPI-style status bar. Design system derived from the ui-ux-pro-max skill (Bento Grids + Executive Dashboard patterns). No JS or backend change. | The dark default looked generic and read "developer tool"; users expect their NAS dashboard to look as polished as the rest of ZimaOS. |
| **v0.2.15** | IPv6 INPUT default-deny — `ZFW-IN6` is now emitted on every build (not only when `V6Drop` is non-empty). Bypass list mirrors ZFW-IN: `lo` / `docker0` / `br-+` / `virbr0` / `tailscale0` / `zt+`, plus ICMPv6 (ND, MTU, MLD), DHCPv6 client (UDP 546), link-local `fe80::/10` and multicast `ff00::/8`. Host-zone allow-rules are mirrored to ip6tables (IPv6 sources passed through, IPv4 sources skipped). Catch-all is `LOG --log-prefix "ZFW-IN6-DROP "` then `DROP`. Events tab carries the new `host6` zone. | ZimaOS enables SLAAC by default, so a stock host is reachable on IPv6 the moment a router announces a prefix. The IPv4 deny-default did nothing for that path — this was the single biggest remaining gap in ZFW's coverage. |
| **v0.2.16** | First v0.3 batch: port-range support in the rule model (`Ports.Type = "range"` with `From`/`To`, compiler emits a single `--dport X:Y` line — VNC 5900-5999 is now one rule instead of 100 multiport entries); rule-editor modal gets a "Port range" option; new handler test package (`fakeFirewall`-driven, no systemd/iptables needed) locks in five regressions including the **dead-man timer lifecycle** verified live on 2026-05-23 (Safe-Apply → `deadman:true`, Confirm → `false`, 120 s timeout → `false`); four new compiler tests cover port-range, IPv6 chain emission and docker-bridge bypass. | Without these tests, the v0.2.7–0.2.15 fixes have no automated guard — and the port-range gap was forcing users to enumerate 100 entries for a single VNC block. |
| **v0.2.17** | Second v0.3 batch: structured logging via `log/slog` (text handler with key=value pairs and source location; gateway + watchdog stay legacy-printf via a thin `slogf` adapter) and a stdlib-only token-bucket rate-limit middleware on every non-GET endpoint (`/api/apply`, `/api/commit`, `/api/revert`, `/api/rules` POST, `/api/rules/defaults`). Burst 10, sustained 1/s — a user clicking Safe-Apply repeatedly passes; a stuck UI tab or runaway script gets HTTP 429 instead of pinning the engine. GET endpoints stay unlimited so the dashboard never sees phantom errors. New `TestMutateRateLimitTrips` locks in the bucket behaviour. | journalctl filtering is now structured (`zfw_event=…` style queries possible); the engine is protected from accidental loops without affecting normal use. |
| **v0.2.18** | OpenAPI 3.0 spec — hand-curated `docs/openapi.yaml` covering all 13 endpoints with Bearer-JWT security scheme, request/response schemas (RuleSet, FirewallStatus, Event, Finding, Component, etc.) and the rate-limit `429` documented per endpoint. `build.sh` copies the spec into `internal/handlers/` so it ships via `//go:embed`; the daemon serves it at `/api/openapi.{json,yaml}` so third-party tools (n8n flows, Home Assistant custom integrations, OpenAPI generators) can discover the API without reading Go source. New `TestOpenAPISpecServed` locks in both routes + presence of key endpoints in the spec. | An undocumented HTTP API limits adoption to people willing to read source code — that excludes the IceWhale-community integration ecosystem this module is meant to live in. |
| **v0.2.19** | Final v0.3 batch: **reproducible builds** (`-buildvcs=false`, `SOURCE_DATE_EPOCH` from the last git commit, GNU-tar `--sort=name --owner=0 --group=0 --mtime --pax-option=delete=atime,delete=ctime`, mksquashfs with the env-var time lock, `touch -d` on every payload file). Two clean builds of the same source produce byte-identical `zfw-<v>.tar.gz` — verified by hand (`7c743441…58c7d4` twice in a row). New `dist/<pkg>.tar.gz.sha256` artifact for downstream verification. Optional CycloneDX SBOM via `cyclonedx-gomod` — included when the tool is installed, skipped with a hint otherwise. **GitHub-Actions CI** (`.github/workflows/ci.yml`): gofmt + vet + race-test, then build twice and assert reproducibility, plus an arm64 cross-compile smoke job. Workflow is committed but inactive until the repo gets a GitHub remote. | Reproducibility is the prerequisite for the Mod-Store submission planned in v0.5 (IceWhale requires verifiable artifacts) and for any external security audit beyond the initial review. |
| **v0.2.20** | **Round-3 security review** of the v0.2.7–v0.2.19 delta. New section in `SECURITY-REPORT.md`: 10 findings (R3-1…R3-10), 4 fixed in this release, 5 accepted residuals, 1 informational ("injection re-tested, not exploitable"). Fixes: `engine commit` now re-runs `secure_file` on `compiled.sh` before installing the boot-persistence unit (R3-1); `write_persist_unit` writes to `.tmp` and atomically renames so a concurrent `daemon-reload` cannot observe a half-written unit (R3-2); `systemctl enable zfw.service` failure surfaces as a clear `exit 1` instead of being silently swallowed (R3-3); `Retry-After: 1` header on every HTTP 429 (R3-4). Accepted residuals (GET-bypass on rate-limiter, global bucket, unit path hardcoding, journalctl error-swallow, defaults-overwrite without API confirm) are tracked for v0.4 with a clear "per-IP rate-limit + dashboard polling debounce" work-item. Cumulative tally: 27 findings, 22 remediated, 5 accepted. | A second security pass after the v0.2.6 handoff was overdue — every release since has added new attack surface (defaults seeding, boot-persistence unit, events parser, IPv6 chain, rate-limit, OpenAPI). |

---

## v0.3 — Professionalization & IPv6 (foundation)

Make the codebase boring to maintain and hard to break. **IPv6 first-class
moved up from v1.0** — on a ZimaOS host with SLAAC enabled by default, an
ungated IPv6 INPUT chain is the single biggest remaining gap in ZFW's
coverage (the IPv4 deny-default does nothing for traffic that arrives over
IPv6).

| Item | Why |
|---|---|
| **IPv6 first-class** *(was v1.0, pulled forward)* | Today `ZFW-IN6` is only emitted when `rs.V6Drop` is non-empty and ends in `RETURN`, not `DROP` — a blacklist, not protection. v0.3 makes it match `ZFW-IN`: always emitted, full bypass list (`lo` / `docker0` / `br-+` / ICMPv6 / DHCPv6 / link-local fe80::/10 / multicast ff00::/8), host-zone rules mirrored to ip6tables, default-deny with `ZFW-IN6-DROP ` LOG target. Events tab picks up `host6` zone. v0.2.15 ships the MVP. |
| **Per-rule IPv6 source support** | Rule source `range` accepts IPv6 CIDR; SLAAC prefix auto-detected analogous to `DetectLAN()`. Today rules silently ignore IPv6 sources. |
| **Handler tests** | `internal/handlers` has zero test coverage today. A regression in `s.apply` or `s.rules` is the most user-visible failure mode; needs golden tests covering ENOENT, malformed input, valid POSTs, CSRF rejection. Concrete first case to lock in: **dead-man timer lifecycle** — Safe-Apply ⇒ `deadman:true`, Commit ⇒ `deadman:false`, 120 s timeout ⇒ `deadman:false`. Verified by hand on 2026-05-23 (all three transitions clean); test prevents future regression. |
| **Rules engine integration tests** | Compile + apply + revert against a netns sandbox. Currently only `compiler.Compile` is unit-tested; the integration is verified by hand. |
| **Port-range support in the rule model** | `ports: { type: "range", from: 5900, to: 5999 }` — without this, blocking VM VNC means 100 list entries. The compiler already understands ranges via `iptables --dport 5900:5999`; only the rule model and UI need it. |
| **Structured logging (`slog`)** | Today: `log.Printf` everywhere. Switch to slog with key=value fields so journalctl filtering works (`zfw_event=rule_apply rule_id=r12345`). |
| **API rate-limit middleware** | Token-bucket per session on `/api/apply` and `/api/rules` POST. Prevents accidental rapid-fire from a stuck UI session and slows down a foothold attacker. |
| **OpenAPI spec for `/api`** | Generated from handler annotations or maintained by hand. Lets third-party tools (Home Assistant, n8n) call the API without code-reading. |
| **Reproducible builds + SBOM** | `go build -trimpath` already; add `-buildvcs=false`, embed a CycloneDX SBOM in the release tarball, sign with cosign. |
| **CI on GitHub Actions** | Matrix: gofmt, vet, test, build amd64 + arm64, sysext-pack, attach release artifact, sign with sigstore. |

**Exit criterion:** every endpoint has at least one test; CI green on push;
release tarball is reproducible byte-for-byte from a tagged commit.

---

## v0.4 — UX polish (rule authoring)

Make the Rules tab feel like a tool that respects the user's time.

| Item | Why |
|---|---|
| **Rule templates library** | One-click "Block all VNC (5900–5999)", "Allow LAN web", "Block all UDP from WAN". Drops the cognitive load for new users; teaches the threat model. |
| **Rule notes / comments field** | Free-text per rule ("M.s_PC, allow temporarily for testing"). Persisted in rules.json. UI shows as tooltip + below-row caption. |
| **Backup / restore rules.json** | UI button: download current rules.json as a timestamped JSON, drop one in to restore. Survives reinstalls and human error. |
| **Diff view: unsaved vs applied** | When `rulesDirty=true`, show side-by-side what will change. Currently the user just gets a "dirty" badge. |
| **Inline frontend i18n (DE / EN)** | Toggle in the header. All labels in a single dict file — no AJAX. The strings are short enough that a 2-language switch is < 200 lines. |
| **Audit findings: history** | "M2 dozzle: fixed 2026-05-22, regressed 2026-06-01." Persist the status timeline so the user sees their own posture drift. |
| **Quick-action from Exposure tab** | Each listening port already has `+ Rule`. Add `→ Deny` next to it for one-click block. |

**Exit criterion:** a new ZFW user can produce a clean rule set without
reading docs.

---

## v0.5 — Distribution & multi-host

Stop being a tarball-on-Maintainers-Github tool. Become discoverable, updatable,
multi-platform.

| Item | Why |
|---|---|
| **arm64 build** | ZimaBoard 216/432/832 (N3350/N3450) and ZimaBoard 2 (N100) are all amd64, but third-party Lattepanda/Pi-class hosts run arm64. Cheap win — already `CGO_ENABLED=0`. |
| **Mod-Store submission** | PR to `IceWhaleTech/Mod-Store` → ZFW appears in the ZimaOS web UI's Module Store, 1-click install. The official distribution channel. |
| **`zpkg` self-update** | After Mod-Store entry exists, daemon checks for new versions weekly and shows a non-blocking "v0.3 available" badge on the Versions tab. |
| **Migration helper** | When v0.2 rules.json is read by v0.3+ daemon, auto-migrate to the new schema with a backup. Today, schema is stable; designing the migration plumbing now keeps future bumps painless. |
| **Multi-host rule sync (opt-in)** | Maintainer has 5 ZimaOS hosts. One designated "leader" pushes rules.json to its followers via the existing API. Off by default; explicit configuration. |

**Exit criterion:** a Gelbuilding-class user can `zpkg install zfw` and never
see Github at all.

---

## v0.6 — Intrusion detection & state

Move from "static allow / deny" to a firewall that understands when, what,
and from whom. Builds on the v0.2.12 Events foundation (kernel-LOG capture
+ `/api/events` + Events tab).

| Item | Why |
|---|---|
| **Top sources / top ports widgets** | Aggregations over the last 1h/24h on top of the Events stream. "Top 10 source IPs", "Top 10 targeted ports". Turns the raw log into a posture overview. |
| **GeoIP source flags** | Reuse the geo ipset data already loaded for outbound country rules — color the source IPs on the Events tab by country. "47% of blocks from RU" reads in seconds. |
| **Last-24h sparkline** | Lightweight inline-SVG, 144 buckets × 10min, drops-per-bucket. Lives in the status bar. |
| **Port-scan detection** | 1-minute window: same source IP → ≥10 distinct dest ports → flag the event with `port_scan`. UI shows a banner on the Events tab when one fires. |
| **Brute-force detection** | Same source → same port (22/445/3389/8888) → ≥20 hits in 60s → flag `brute_force`. |
| **Time-window rules** | "Allow SSH from LAN 08:00–18:00, deny otherwise." Schema gets an optional `schedule: { from: "08:00", to: "18:00", days: ["mon", "tue", ...] }`. |
| **Connection-state visibility** | Live conntrack table with rule-match annotations. Tells the user "this rule is what blocked that 192.168.50.42:33124 → :5900 attempt 2 minutes ago." |
| **Per-rule logging toggle** | Per-rule `log: true` so the user can sanity-check a specific deny rule by watching its hits in the Events tab before relying on it. |
| **Rate-limit per source** | A rule action `rate-limit` (3 conn/s, then drop). Built into iptables `recent` module — no extra deps. |

**Exit criterion:** firewall posture answers "what happened" and "what will
happen at 2 AM," not just "what's the current ruleset."

---

## v1.0 — General Availability

Everything below is required for a 1.0 stamp.

| Item | Why |
|---|---|
| **Outbound rules (`OUTPUT` + `FORWARD`)** | Today: only `INPUT`. v1.0: rules can target outbound traffic so the user can block a compromised container from phoning home. |
| **Per-container rule binding** | Bind a rule to a Docker container ID, not just a port. When the container restarts on a new port, the rule follows. Auto-detects via `docker events`. |
| **VPN-interface awareness** | Detect `tailscale0` / `wg0` and exempt them from default-deny by default. Otherwise installing ZFW kills Tailscale silently. |
| **Notification hooks** | On rule change / apply / revert / dead-man timeout: POST to a configurable URL (n8n, Slack, Telegram bot). Stateless, opt-in, plain webhook. |
| **Threat model document** | Published `THREAT-MODEL.md` listing every assumed adversary, every mitigation, every accepted risk. The bar IceWhale's security team should be able to read in 15 minutes. |
| **External pen-test** | At least one external reviewer beyond the security-review already in `SECURITY-REPORT.md`. Bug-bounty announcement on the IceWhale forum. |

**Exit criterion:** an enterprise admin would install ZFW on a small office
ZimaCube and not lose sleep.

---

## Out of scope (explicitly)

To keep focus, these are **not** in any roadmap phase:

- **Replacing the ZimaOS gateway.** ZFW is a host firewall, not a reverse
  proxy. Web auth, TLS termination, route management stay with
  `zimaos-gateway`.
- **Pluggable rule engines.** iptables-legacy is what ZimaOS ships;
  nftables/eBPF backends are too much surface for one maintainer.
- **GUI rule builder beyond the modal.** The 2026 UI trend toward
  drag-and-drop rule canvases burns weeks for marginal usability gain on a
  rule set that rarely exceeds 30 entries.
- **Cloud-managed control plane.** ZFW stays fully local. No phone-home,
  no SaaS dashboard, no required external account.

---

## How to read this

Numbers are **versions**, not deadlines. Each phase ships when its exit
criterion is met, not on a calendar.

Items inside a phase are **negotiable** — feedback from Gelbuilding and the
IceWhale forum may reorder them. The phases themselves are the
non-negotiable spine: foundation → polish → distribution → semantics → GA.

If a feature request lands that doesn't fit the spine, it goes into a
"v1.x — future" section (which currently does not exist; first request
creates it).
