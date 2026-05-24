# ZFW Roadmap

> Author: Holger Kuehn (Lintux)
> Status: **v0.3.4 — fourth v0.4 (*UX polish*) item shipped.** New
> Diff button on the Rules tab opens a modal listing every change
> Save would push (added / removed / changed + default-policy flips,
> with one-line semantic summaries). v0.3.3 shipped backup/restore;
> v0.3.2 per-rule notes; v0.3.1 the rule-templates library. The v0.3
> phase itself closed with v0.3.0 (netns integration tests + every
> v0.3 roadmap item shipped across v0.2.15–v0.3.0). v0.3.0 builds on
> v0.2.21's external sign-off — **Gelbuilding's 2026-05-24 ZimaBoard
> validation of v0.2.20** — and on v0.2.20's three-round security
> review. Next v0.4 items: audit-history, Exposure-tab quick-action.
> (Frontend i18n was dropped — ZFW stays English-only.)
> English UI, intelligent default-set with live Docker inventory, reboot-persistent,
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

## Delivered in v0.2.7 – v0.3.4

The v0.2 line addressed every regression and gap surfaced by the first
external test cycle (Gelbuilding / IceWhale forum). v0.3.0 closed the
*Professionalization & IPv6 (foundation)* phase with netns integration
tests as the final piece — every v0.3 roadmap item has shipped. v0.3.1
opened the v0.4 *UX polish* phase with the rule-templates library;
v0.3.2 adds per-rule notes. The
release history below records what each release added and why it
mattered; the per-version entries are the source of truth for what
changed when.

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
| **v0.2.21** | **External tester sign-off baked into the release.** README + ROADMAP carry Gelbuilding's 2026-05-24 ZimaBoard validation of v0.2.20: install, dashboard tile, Safe-Apply, Confirm, custom-port rule-edit (SSH 22 → 2222 for ttydBridge) and full reboot-persistence cycle all confirmed by an external party. Binary code identical to v0.2.20; cache-buster bumped (`?v=0.2.21` on `styles.css` / `app.js`) so the UI doesn't serve stale assets after install; `openapi.yaml` info-version bumped to match. v0.2.20 is preserved as the canonical reproducibility anchor (its tarball SHA stays the reference for the security-reviewed binary). | The first external "works as advertised on hardware I don't control" sign-off since the tester-feedback cycle began. Putting it inside the release tarball — not just in a forum reply — turns word-of-mouth into an artifact a downstream user can inspect before installing. |
| **v0.2.22** | **Per-rule IPv6 source support** — closes the second-to-last v0.3 item. Compiler dispatches by source family: an IPv6 CIDR or single IPv6 address (`source.type` of `range` or `ip`, value `2001:db8::/64` or `2001:db8::42`) now routes to `ZFW-IN6` only and is skipped on the IPv4 chain. Pre-fix `iptables-legacy -s 2001:db8::/64` returned `Bad argument` and `set -eu` aborted the whole engine apply — an IPv6 source rule was a silent show-stopper. New `system.DetectLAN6()` resolves the host's SLAAC prefix and global IPv6 the same way `DetectLAN()` resolves IPv4 (UDP-dial trick; empty return on no-IPv6 connectivity). Three new compiler tests: `TestIPv6SourceRoutesToIPv6Chain` (range), `TestIPv6SingleSourceRoutesToIPv6Chain` (single address), `TestIPv4SourceStillRoutesToIPv4Chain` (inverse guard so the IPv6 dispatch didn't break the v4 path). Comment in `Compile()` clarified — the previous "destination-port-only mirror" wording described behaviour that did not match the code. | ZimaOS hosts get a SLAAC global address the moment a router advertises a prefix, so any user trying to scope a rule to "from my LAN" on IPv6 hit a blank wall. Closing this gap turns the IPv6 default-deny chain (v0.2.15) into something the user can actually customise per rule. |
| **v0.3.0** | **v0.3 phase closed — netns integration tests.** New `internal/compiler/integration_test.go` (build tag `netns_integration`) drives `Compile() → bash → live iptables-legacy` inside `unshare -U -r -n` (unprivileged user+network namespace, no sudo needed). Four tests: `TestEngineApplyAllowsExpectedHostPort` (compile a host allow rule, verify the ACCEPT line lands), `TestEngineApplyPortRangeEmitsContiguousRule` (VNC 5900-5999 is one `--dport 5900:5999` line, not 100 entries), `TestEngineApplyIPv6SourceDoesNotCrashIPv4` (live counterpart to v0.2.22's unit tests — IPv6 source under `set -eu` no longer aborts the apply), `TestEngineRevertClearsAllChains` (apply→revert cycle leaves no ZFW chain behind). `requireNetns(t)` skips cleanly when iptables-legacy / unshare / unprivileged userns are absent. With this, the v0.3 exit criterion ("every endpoint has at least one test; CI green on push; release tarball reproducible byte-for-byte") is fully met. | Pre-v0.3.0 the integration was "verified by hand" on a real ZimaCube — a class of regression no unit test could catch (e.g. iptables-legacy's actual syntax for port ranges on the host kernel). Locking these down means the next refactor across compiler / engine / handlers can be reviewed by reading the diff, not by reproducing a manual ZimaCube run. |
| **v0.3.4** | **Diff view, unsaved vs applied — fourth v0.4 item.** Adds a *Diff* button to the Rules-tab action row, enabled only when `rulesDirty` is true. Click opens a modal that fetches `/api/rules` (the saved snapshot) and compares it against the in-memory `ruleSet`. Each change is one row: added (green `+`, left-border green), removed (red `−`), changed (amber `~`, with before-and-after one-line summaries), plus a leading row when the default policy flipped. The summaries use the same shape across all three cases (`Allow tcp 22 from 192.168.1.0/24 [Host]`) so the user can spot a typo or zone mistake in seconds. Matching is by rule id; rules with empty `id` (added via the editor or templates, not yet saved) are always treated as additions. No new endpoint, no engine change. New helpers `ruleSignature()` (semantic equality test that excludes id/order — both legitimately differ across save cycles) and `ruleSummary()` (the one-line human form). | A "rulesDirty" badge is honest but unhelpful: a user comes back from a five-minute interruption and has no idea what they changed. Diff turns Save rules from "trust me" into "here's exactly what hits the daemon", which matters most for users who only Safe-Apply once a week and need to remember the in-flight edits. |
| **v0.3.3** | **Backup / restore rules.json — third v0.4 item.** Two new buttons in the Rules-tab action row. *Backup* fetches `/api/rules` and offers it as a timestamped download (`zfw-rules-YYYY-MM-DD_HH-MM-SS.json`); the file is the raw `RuleSet` exactly as the daemon serves it, so a backup file is also a restore file with no transformation. *Restore* opens a file picker, parses the JSON, sanity-checks the shape (`default_policy` in {deny, allow}, `rules` is an array), asks the user to confirm the rule-count swap, then POSTs to `/api/rules` — the server-side Validate gate runs again, so a tampered file still gets rejected with a clear error. The firewall is **not** re-applied automatically: the user has to click Safe-Apply on the Firewall tab afterwards, keeping the 120-second dead-man as the last line of defence. No new endpoint, no engine change. | A user who breaks their rule set has no path back today other than "Recommended defaults" — which destroys hand-tuned configuration. Backup turns "I'll just try this rule" from a foot-gun into a reversible action. Restore also survives reinstalls without manual `/DATA/zfw/rules.json` archaeology. |
| **v0.3.2** | **Per-rule notes / comments — second v0.4 item.** New optional `notes` string field on every `Rule` (up to 256 chars, capped by `Validate`). UI: a textarea in the rule editor modal and a "note" pill next to the rule's name in the table that surfaces the full text on hover (`title=` attribute, XSS-escaped via the existing `esc()` helper). Compiler does not read the field — metadata only. JSON tag is `omitempty` so existing rules.json files round-trip cleanly and the API output stays compact for rules without notes. New backend tests: `TestValidateAcceptsNotes` (a reasonable note passes) and `TestValidateRejectsOversizeNotes` (a note above the cap is refused with a clear error). OpenAPI Rule schema documents the new field with `maxLength: 256`. | Without notes, a user who comes back to their rule list two weeks later has no way to remember why rule 17 exists — and a temporary allow-rule that should have been removed turns into a permanent gap. Notes are the cheapest possible posture-hygiene primitive (no new endpoint, no engine change, no migration). |
| **v0.3.1** | **Rule-templates library — first v0.4 (*UX polish*) item.** New curated catalog under `internal/rules/templates.go`: three templates in this release, *Block VNC consoles (5900-5999)* (security), *Block NFS / rpcbind* (security, TCP+UDP for 111/2049/20048), *Allow Plex Media Server* (service, 32400 from LAN). New endpoint `GET /api/rules/templates` returns the catalog with the host's LAN substituted into "from the LAN" rules — picked up from rules.json's `lan` field, falling back to live `system.DetectLAN()` so a fresh install still produces meaningful templates. Rules tab grows a `Templates` button next to *+ New rule*; the picker modal lists each template with name, category badge (security/service), description and rule count, and an *Add* button that appends the rules to the local set with fresh order numbers (the user still has to Save + Safe-Apply). New tests: three in `internal/rules` (`TestTemplatesAllValid`, `TestTemplatesFreshIDs`, `TestTemplatesSubstituteLAN`) and two in `internal/handlers` (`TestRulesTemplatesReturnsCatalog`, `TestRulesTemplatesSubstitutesPersistedLAN`). OpenAPI 3.0 spec documents the new endpoint. | The first v0.4 exit-criterion lever ("a new user can produce a clean rule set without reading docs"). Templates teach the threat model by example — clicking *Block VNC* once is faster than reading the audit catalogue and figuring out which deny rules to draft. Frontend i18n was deliberately dropped from v0.4 — ZFW stays English-only. |

---

## v0.3 — Professionalization & IPv6 (foundation) — DELIVERED in v0.3.0

Made the codebase boring to maintain and hard to break. **IPv6 first-class
moved up from v1.0** — on a ZimaOS host with SLAAC enabled by default, an
ungated IPv6 INPUT chain was the single biggest remaining gap in ZFW's
coverage (the IPv4 deny-default does nothing for traffic that arrives over
IPv6). Every item below shipped across v0.2.15 → v0.3.0.

| Item | Why |
|---|---|
| **IPv6 first-class** *(shipped v0.2.15, pulled forward from v1.0)* | Pre-v0.2.15 `ZFW-IN6` was only emitted when `rs.V6Drop` was non-empty and ended in `RETURN`, not `DROP` — a blacklist, not protection. Now ZFW-IN6 matches ZFW-IN: always emitted, full bypass list (`lo` / `docker0` / `br-+` / ICMPv6 / DHCPv6 / link-local fe80::/10 / multicast ff00::/8), host-zone rules mirrored to ip6tables, default-deny with `ZFW-IN6-DROP` LOG target. Events tab picks up the `host6` zone. |
| **Per-rule IPv6 source support** *(shipped v0.2.22)* | Rule source `range` accepts IPv6 CIDR; SLAAC prefix auto-detected analogous to `DetectLAN()`. Pre-fix the IPv4 chain crashed on a `-s <ipv6>` arg, silently aborting every apply that referenced an IPv6 source — now `isIPv6Source()` routes those rules to ZFW-IN6 only. |
| **Handler tests** *(shipped v0.2.16 + v0.2.22)* | `internal/handlers` was zero-coverage at start of v0.3; v0.2.16 landed the dead-man-timer-lifecycle batch (Safe-Apply ⇒ `deadman:true`, Commit ⇒ `deadman:false`, 120 s timeout ⇒ `deadman:false` — verified live 2026-05-23), v0.2.22 added 15 more tests so all 14 API endpoints have at least one regression guard (ENOENT, malformed input, valid POSTs, CSRF rejection, engine-error bubbling). |
| **Rules engine integration tests** *(shipped v0.3.0)* | Four netns tests under build tag `netns_integration` run `Compile() → bash → live iptables-legacy` in an unprivileged user+net namespace (`unshare -U -r -n`, no sudo). They lock in port-range emission, IPv6/IPv4 dispatch, host-allow apply and revert. The pure unit tests stay in the default `go test ./...` run; the integration suite gates on `requireNetns(t)` and skips cleanly when the kernel / iptables-legacy / userns are unavailable. |
| **Port-range support in the rule model** *(shipped v0.2.16)* | `ports: { type: "range", from: 5900, to: 5999 }` — without this, blocking VM VNC meant 100 list entries. Compiler emits a single `--dport 5900:5999`. The rule-editor modal got a "Port range" option in the same release. |
| **Structured logging (`slog`)** *(shipped v0.2.17)* | `log.Printf` replaced with `log/slog` text handler emitting key=value pairs plus source location. Gateway + watchdog stay legacy-printf via a thin `slogf` adapter to keep their call sites trivial. journalctl now supports `zfw_event=…` style filters. |
| **API rate-limit middleware** *(shipped v0.2.17)* | Stdlib-only token-bucket on every non-GET endpoint (`/api/apply`, `/api/commit`, `/api/revert`, `/api/rules` POST, `/api/rules/defaults`). Burst 10, sustained 1/s. GET endpoints stay unlimited. `TestMutateRateLimitTrips` locks the bucket behaviour in. |
| **OpenAPI spec for `/api`** *(shipped v0.2.18)* | Hand-curated `docs/openapi.yaml` covering all 13 endpoints, embedded via `//go:embed` and served at `/api/openapi.{json,yaml}`. `TestOpenAPISpecServed` keeps the routes alive. |
| **Reproducible builds + SBOM** *(shipped v0.2.19)* | `-buildvcs=false`, `SOURCE_DATE_EPOCH` from the last git commit, GNU-tar `--sort=name --owner=0 --group=0 --mtime --pax-option=delete=atime,delete=ctime`, mksquashfs with the env-var time lock. Two clean builds of the same source produce byte-identical `zfw-<v>.tar.gz`. Optional CycloneDX SBOM via `cyclonedx-gomod`. Cosign-signing is deferred to v0.5 (Mod-Store distribution). |
| **CI on GitHub Actions** *(workflow shipped v0.2.19, inactive)* | `.github/workflows/ci.yml` runs gofmt + vet + race-test, then builds twice and asserts reproducibility, plus an arm64 cross-compile smoke job. The workflow is committed and turns active automatically the moment the repo gets a GitHub remote — no further code change needed. |

**Exit criterion (met in v0.3.0):** every endpoint has at least one test
(22 handler tests + 17 compiler tests + 4 netns integration tests); the
release tarball is reproducible byte-for-byte from a tagged commit (since
v0.2.19); the GitHub-Actions CI workflow is committed but stays inactive
until the repo gets a remote — once published it goes green on push by
construction.

---

## v0.4 — UX polish (rule authoring)

Make the Rules tab feel like a tool that respects the user's time.

| Item | Why |
|---|---|
| **Rule templates library** *(shipped v0.3.1)* | Three templates so far — *Block VNC consoles* (5900-5999), *Block NFS / rpcbind* (111/2049/20048 TCP+UDP), *Allow Plex Media Server* (32400 from LAN). New endpoint `GET /api/rules/templates` with LAN-substitution; Rules-tab modal renders the catalogue. More templates can ship as future patches without endpoint churn. |
| **Rule notes / comments field** *(shipped v0.3.2)* | Optional free-text `notes` per Rule (max 256 chars). Textarea in the editor, "note" pill with hover-tooltip in the rule table. Validate caps the length; OpenAPI Rule schema documents it. |
| **Backup / restore rules.json** *(shipped v0.3.3)* | Backup button downloads `zfw-rules-<ts>.json` (raw RuleSet, no custom wrapper); Restore reads a JSON file, sanity-checks the shape, confirms the overwrite count, then POSTs to `/api/rules` so server-side Validate runs again. Firewall not auto-re-applied — user still has to Safe-Apply. |
| **Diff view: unsaved vs applied** *(shipped v0.3.4)* | Diff button on the Rules tab (enabled only when `rulesDirty`) opens a modal listing every change Save would push — added / removed / changed rules plus default-policy flips, each with a one-line semantic summary. Pure client-side; fetches `/api/rules` for the saved snapshot. |
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
- **UI / docs translation.** ZFW is **English-only** by design. The
  IceWhale community lives in English (forum, Mod-Store, GitHub
  issues), and the v0.2.7 backend translation already removed the
  earlier German leakage. A DE/EN toggle was considered for v0.4 and
  deliberately dropped.

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
