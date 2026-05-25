# ZFW Roadmap

> Author: Holger Kuehn (Lintux)
> Status: **v1.0.10 — GA + post-launch hardening, polish, brand,
> logo-iteration, appicon alignment. Tested + approved live on lan-host
> (HolgisNAS); next step is the external-tester handoff to
> Gelbuilding.** Shipped across ten point releases after v1.0.0:
>
>   v1.0.1  Round-4 security review hotfix — Critical RCE closed
>           (R4-1: `Rule.ID` shell-injection), plus R4-2..R4-5
>           hardening and three code-quality wins (CQ-2/4/8).
>   v1.0.2  Round-4 residual closeout + code-quality batch — closes
>           R4-6/R4-7/R4-8 plus R3-5/R3-8/R3-9 and ten CQ items;
>           cumulative tally now 35/30/5.
>   v1.0.3  Brand refresh — real ZFW wordmark in the header,
>           forest-green shield favicon + dashboard tile.
>   v1.0.4  Release-engineering polish — tarball doc bundle extended
>           (THREAT-MODEL + BUG-BOUNTY + CODE-REVIEW now ship inside
>           the .tar.gz so external testers get the full reading
>           list without a GitHub round-trip); mod-store/zfw.yaml
>           refreshed to v1.0.x with live sha256 anchors.
>   v1.0.5..v1.0.9  Logo polish iteration — five point-releases of
>           visual fine-tuning. v1.0.5 alpha-cleaned the source
>           PNG (cream backdrop → transparent, 1448×1086 → 1114×267,
>           852KB → 99KB) and doubled the CSS .logo height
>           (48px → 96px). v1.0.6 tripled to 144px ("doppelt reicht
>           nicht, min 3fach"). v1.0.7 returned to 96px ("doch zu
>           groß"). v1.0.8 dropped the version pill from
>           align-items: center to flex-end. v1.0.9 lifted the pill
>           24px so it sits on the "Firewall" baseline, not the
>           container floor. Final state: 96px logo with
>           transparent backdrop; v-pill flex-end + 24px margin.
>   v1.0.10 Appicon alignment — the ZimaOS dashboard tile redrawn
>           in the wordmark's language: brick-wall shield with a
>           single central orange hub radiating three lines to
>           warm off-white endpoint dots (was: five-node circuit
>           motif from v1.0.3). Tile + wordmark now read as one
>           mark.
>
> All six roadmap
> phases shipped: v0.2 (tester foundation, v0.2.7–v0.2.21), v0.3
> (professionalization + IPv6, v0.2.15–v0.3.0), v0.4 (UX polish,
> v0.3.1–v0.3.6), v0.5 (distribution + multi-host, v0.3.7–v0.4.0),
> v0.6 (intrusion detection + state, v0.4.1–v0.5.0), v1.0 (GA,
> v0.5.4–v1.0.0). Capstone deliverables in v1.0.0: **THREAT-
> MODEL.md** (assets/adversaries/mitigations/accepted-residuals,
> cross-referenced to every SECURITY-REPORT.md finding) and **BUG-
> BOUNTY.md** (external-researcher contract with scope, process,
> safe harbour). External pen-test remains an operator action —
> contact and scope live in BUG-BOUNTY.md. With v1.0.0 the exit
> criterion is met: "an enterprise admin would install ZFW on a
> small office ZimaCube and not lose sleep." Future-version
> backlog is tracked in `## v1.x — future` (currently captures
> deferred polish: docker-events watcher for live container
> re-bind, per-IP rate-limit, journalctl debug logging).
>
> *Earlier-phase status block:* **v0.5.0 — the v0.6 (*Intrusion
> detection & state*) phase is complete.** Final piece: **connection-state
> visibility** — new `internal/conntrack` package reads
> `/proc/net/nf_conntrack` (with `conntrack -L` fallback); new
> `GET /api/conntrack` returns up to 500 active entries; new
> *Connections* tab renders them with state-coloured pills. The
> v0.6 line shipped across v0.4.1 → v0.5.0 (analytics, threat
> detection, time-window rules with first real schema bump,
> per-rule logging + rate-limit, GeoIP source flags, conntrack
> visibility). v0.5 shipped across v0.3.7 → v0.4.0
> (Distribution & multi-host: arm64, migration helper,
> self-update, peers sync, Mod-Store prep — submission itself on
> hold pending IceWhale outreach). v0.4 *UX polish* closed in
> v0.3.6; v0.3 *Professionalization & IPv6* closed in v0.3.0.
> Next phase: **v1.0 — General Availability** (outbound rules,
> per-container binding, VPN-interface awareness, notification
> hooks, threat-model doc, external pen-test). `geo.Manager` gains `Lookup(ip)` + `LookupBatch`
> reusing the cached per-country `.zone` files already on disk; no
> extra download, no extra deps. New endpoint
> `GET /api/geo/lookup?ips=...` returns `{ip: cc}`. UI shows a
> flag-emoji + ISO-code pill next to each source IP on the Events
> tab. v0.4.4 shipped per-rule logging toggle + rate-limit per
> source. Only one v0.6 item left: connection-state visibility
> (live conntrack) — that lands as v0.5.0 and closes the phase. `Rule.Log` (bool) and
> `Rule.RateLimit{Conn, Seconds}` shipped together because both
> are field-additive (no schema bump) and share a single compiler
> refactor — `wrapEmit(match, r, target)` extracted so the
> LOG/rate-limit emit shape is identical across host/IPv6/docker
> chains. UI: log checkbox + rate-limit fieldset in the rule
> editor. v0.4.3 shipped time-window rules (first real use of
> v0.3.8's migration plumbing — schema v1→v2). First real use of v0.3.8's rules.json
> migration plumbing — schema bumps v1 → v2 as a single switch-case
> in `migrate()`. Each Rule gains an optional `Schedule { from, to,
> days }`; the compiler emits `-m time --timestart … --timestop …
> --weekdays … --kerneltz`. UI: collapsible fieldset in the rule
> editor + HH:MM–HH:MM pill on the rule row. v0.4.2 shipped
> threat detection (port-scan + brute-force classifier on
> /api/events); v0.4.1 shipped Events tab analytics (top-10
> sources/ports + 24h sparkline). Three roadmap items merged into one
> frontend-only release: top-10 source IPs + top-10 dest ports
> (last 1h) as side-by-side cards, plus a 24h × 10-minute inline-
> SVG sparkline above the status bar. One `/api/events?since=24h`
> fetch drives sparkline, cards, and the existing 1h table. The
> v0.5 *Distribution & multi-host* phase shipped in full across
> v0.3.7 → v0.4.0 (arm64, rules.json migration, self-update check,
> multi-host sync, Mod-Store submission prep). Mod-Store PR itself
> is on hold pending IceWhale outreach. The v0.4 *UX polish* phase
> closed in v0.3.6; the v0.3 *Professionalization & IPv6* phase
> closed in v0.3.0. v0.3.0 builds on v0.2.21's external sign-off
> — **Gelbuilding's 2026-05-24 ZimaBoard validation of v0.2.20** —
> and on v0.2.20's three-round security review. Remaining v0.6
> items: threat detection (port-scan + brute-force), time-window
> rules (first real schema bump), per-rule logging + rate-limit,
> GeoIP source flags, conntrack visibility.
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

## Delivered in v0.2.7 – v0.5.0

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
| **v0.5.0** | **Connection-state visibility — seventh v0.6 item; closes v0.6.** New `internal/conntrack` package reads the kernel's live conntrack table. Primary source is `/proc/net/nf_conntrack` (always available when the conntrack kernel module is loaded — which it is on every ZimaOS host because ZFW already uses conntrack matches in the compiled iptables script); fall-through is `conntrack -L -o extended` when /proc is unreadable. The parser handles both shapes transparently — the `ipv4 2` L3 prefix in /proc output is stripped so downstream field indexing is identical to the conntrack(8) shape. Each `Entry` carries protocol, state (omitempty so stateless protocols stay compact), original-direction src/dst IP + port (reply direction is dropped — the UI cares about "who initiated what"), and the kernel's timeout countdown in seconds (bigger = more recent — TCP ESTABLISHED defaults to ~5 days, UDP to seconds). State extraction uses an all-caps no-`=` heuristic so flag tokens (`ASSURED`, `UNREPLIED`) appearing after the state name never overwrite the first state-shaped token seen. Lines without `src=`/`dst=` (kernel emits these transiently during connection setup for some L4 protos) are silently dropped. New endpoint `GET /api/conntrack` caps the response at 500 entries — a busy host can hold 100k+ active flows and the UI table doesn't render that many usefully anyway. On a host without conntrack support the endpoint returns `[]` rather than 500, so the new *Connections* tab degrades gracefully to "no active connections". UI: state-coloured pill (`ESTABLISHED` green, `SYN_*` accent, `CLOSE_WAIT` amber, `TIME_WAIT` muted) keeps the table scannable. Seven new tests in `internal/conntrack`: `/proc` shape (L3 prefix stripped), conntrack(8) shape, UDP stateless (state stays empty), malformed line without src/dst dropped, flag tokens never overwrite state, garbage lines in a stream are silently skipped, the limit cap is honoured. One new handler test asserts `/api/conntrack` returns a JSON array (never null) even when the kernel module is absent (which is the test environment). OpenAPI documents the endpoint and the `Connection` schema. With this, every v0.6 roadmap item has shipped — exit criterion ("firewall posture answers 'what happened' and 'what will happen at 2 AM,' not just 'what's the current ruleset'") is met. | The remaining piece of the v0.6 thesis: events (v0.4.1/v0.4.2) tell the user what was DROPPED, conntrack tells the user what was ACCEPTED. Without it the dashboard shows the half of the story that's already triggered the firewall and none of the half that's living through it. The conntrack-via-/proc decision means zero new dependency on the `conntrack` userland tool (which ZimaOS may or may not ship) — every working ZFW install can serve this endpoint because the same kernel module that powers `-m conntrack --ctstate ESTABLISHED,RELATED` in the compiled script also fills /proc/net/nf_conntrack. |
| **v0.4.5** | **GeoIP source flags on the Events tab — sixth v0.6 item.** Reuses the cached per-country `.zone` files the `internal/geo` package already downloads for outbound geo-block rules — no extra MMDB download, no extra deps. New `geo.Manager.Lookup(ip)` + `LookupBatch(ips)` build an in-memory CIDR→country index lazily on first call and rebuild when the directory **fingerprint** changes — composed from `name + size + mtime-nano` per `.zone` file. Fingerprint beats mtime-only staleness because filesystem mtime resolution is 1s on many setups; adding a new `.zone` in the same second as the first build would otherwise be missed by a naive mtime check. New endpoint `GET /api/geo/lookup?ips=ip1,ip2,...` returns `{ip: lowercase-cc}` (every input IP is present in the response; unknowns map to `""` so the UI's iteration is nil-safe). The UI batches all unique source IPs from the visible 1h Events slice into one call rather than fan-out per row. Cap of 500 IPs per query bounds the linear-scan lookup (typical Events tab has <100 unique source IPs; 500 is comfortable headroom). UI: country flag emoji rendered as a regional-indicator-pair pill (`🇷🇺 RU`) next to the source IP, hidden when the lookup returned `""` so the column stays clean for sources in countries the user has not configured rules for. The fundamental limitation disclosed when this was split off in v0.4.1 stands: only countries with cached `.zone` files appear in the index, so a fresh install with no geo rules sees no flags — but the common use-case (user blocks RU/CN and wants flagged events for those countries) works exactly because the geo manager already cached those zones for the outbound rule. Five new tests in `internal/geo`: empty manager returns `""`; cached zone hits resolve to the file's country code; miss outside every cached CIDR returns `""`; `LookupBatch` always contains every input key (so the UI doesn't crash on a missing entry); rebuild-on-new-zone (fingerprint catches the add even within sub-second filesystem resolution). Two new handler tests: `/api/geo/lookup` with empty query returns `{}` (no 400 / 404), `/api/geo/lookup` against a fresh-install Manager with no `.zone` data returns the empty-string value for every input IP. OpenAPI documents the new endpoint. | Without a country signal on the Events tab, a user looking at a screen full of `198.51.100.x` entries has to copy-paste each one into whois.com to find out where they came from. The flag pill compresses that to a glance. Reusing the existing `.zone` cache instead of pulling a MaxMind MMDB means: zero new bytes on disk for users who don't have geo rules, full coverage for the countries they care enough to block. The cost is honest under-coverage for everyone else, which the UI surfaces by silently hiding the flag rather than painting a fake "unknown" placeholder. |
| **v0.4.4** | **Per-rule logging toggle + rate-limit per source — fourth + fifth v0.6 items in one release.** Two field-additive Rule extensions shipped together because both have the same compiler-emit shape (extra match lines that share the rule's match prefix), so factoring them through a single `wrapEmit(match, r, target)` helper used by `hostLines`, `hostLines6` and `dockerLines` keeps the LOG/rate-limit shape consistent across the host, IPv6 and docker chains. **`Rule.Log` (bool)** — the compiler emits a non-terminating `-j LOG --log-prefix "ZFW-RULE-<id> " --log-level 6` line in front of the rule's action; the packet still falls through to the action, so the LOG is a transparent observer (the user can sanity-check a specific rule by watching its hits in the Events tab before relying on it). **`Rule.RateLimit{Conn, Seconds}`** — two `-m recent` lines (a `--set --name z<id>` to track, then `--update --seconds N --hitcount C --name z<id> -j DROP` to drop over threshold) in front of the action. The per-rule `--name z<id>` keeps each rule's tracking table isolated; the `z` prefix preserves the xt_recent 32-char name cap with headroom. Engine preamble `modprobe`s `xt_recent` and `xt_time` (v0.4.3) alongside the pre-existing `xt_LOG` so all three modules are loaded before any rule references them. Both fields are omitempty (Log bool, RateLimit pointer) so a rule that does not opt in round-trips byte-equal to a pre-v0.4.4 v2 rules.json — no schema bump needed. Validate caps RateLimit Conn 1..1000 and Seconds 1..3600 so a crafted rules.json can't bloat the xt_recent hash table or produce nonsensical iptables clauses. UI: two new controls in the rule editor — a `Log when this rule fires` checkbox and a `Rate-limit per source` collapsible fieldset with conn/seconds number inputs. `ruleSignature()` picks up both new fields so a save where only the log toggle flipped still shows up in the unsaved-changes diff view. Five new tests: two in `internal/rules` (validate accepts log + rate_limit; rejects bad conn=0, negative seconds, conn>1000), three in `internal/compiler` (`TestLogTrueEmitsLogLineBeforeAction` asserts the LOG line lands before the ACCEPT line and has the correct `ZFW-RULE-<id>` prefix; `TestRateLimitEmitsRecentClause` asserts both `-m recent` lines emit with `--name z<id>` and the configured `--seconds`/`--hitcount`; `TestNoLogNoRateLimitNoExtraLines` proves the wrapEmit refactor did not leak extra lines into rules that didn't opt in — a plain rule emits a single line unchanged from pre-v0.4.4). | These two are the lowest-cost levers in the v0.6 plan: per-rule LOG turns the Events tab from a global drop log into a per-rule diagnostic ("did my deny actually catch the thing I thought it caught?") and per-source rate-limit is the canonical SSH-brute-force defence pattern (`-m recent --hitcount 3 --seconds 1 -j DROP` is the four-line iptables idiom every homelab guide cites). Shipping them in one release saved a duplicate compiler refactor — the second time a field would have been bolted onto each of three chain emitters was the moment to extract `wrapEmit`. |
| **v0.4.3** | **Time-window rules — third v0.6 item; first real use of v0.3.8's migration plumbing.** Each `Rule` gains an optional `Schedule { From, To, Days }` (pointer + omitempty so unscoped rules stay compact). `From` and `To` are HH:MM wall-clock; `Days` is the lowercase 3-letter weekday names allow-list `mon|tue|wed|thu|fri|sat|sun`. Compiler emits `-m time --timestart HH:MM --timestop HH:MM --weekdays Mon,Tue,... --kerneltz` between the port match and `-j <target>`; `--kerneltz` uses the host's local time zone rather than UTC (what the user expects when they type "08:00"). Empty `Days` means every day (compiler omits `--weekdays`); `From > To` wraps midnight for overnight windows (e.g. 22:00–06:00). **Schema bump v1 → v2** lands as a single switch-case in `migrate()`: an on-disk v1 rules.json auto-migrates on `Load` with `.bak.v1` preserved before the rewrite, exactly as v0.3.8's tests promised. The bump is field-additive — an existing v1 file round-trips byte-equal except for the stamped `"version": 2`. Validate rejects bad HH:MM and non-allow-list day names with clear error messages so a crafted rules.json never crashes the compiler's iptables-line emit. UI: new collapsible *Time-window rule* fieldset in the rule editor (`<input type="time">` × 2 + 7 day checkboxes); a `HH:MM–HH:MM` pill next to the rule name on the Rules table surfaces the schedule at a glance; the existing diff view + `ruleSignature` both pick up the new field so a schedule-only change shows up in the unsaved-changes diff. Five new tests in `internal/rules`: validate accepts a sane schedule, rejects bad From-time, rejects bad day, schedule round-trips through JSON (`omitempty` keeps unscoped rules compact while scheduled rules deserialise byte-for-byte), v1 → v2 migration writes `.bak.v1` with original bytes preserved. Three new compiler tests: scheduled rule emits the full `-m time --timestart … --timestop … --kerneltz --weekdays …` clause in the right position, empty `Days` omits `--weekdays`, an unscheduled rule emits no `-m time` at all (proving the time machinery doesn't leak into rules that never opted in). Existing `TestLoadCurrentVersionIsNoOp` re-parameterised to interpolate `CurrentSchema` so future schema bumps don't break it. OpenAPI `Rule.schedule` documented with HH:MM regex + weekday enum; `RuleSet.version` example bumps to 2. | The single most-requested ZFW capability that had no story before: "allow SSH from LAN 08:00–18:00, deny otherwise" is the canonical home-network policy users actually want. Beyond the feature itself, v0.4.3 is the **proof** that v0.3.8's migration plumbing works end-to-end on a real schema bump. The two-line `case 1: rs.Version = 2` change in `migrate()` and the field-additive design together mean every future schema change in this codebase costs one switch-case + one default-value assignment, not a release-blocking migration design. |
| **v0.4.2** | **Threat detection (port-scan + brute-force) — second v0.6 item.** New `events.Classify()` walks the time-ascending event series before `Read()` reverses for the UI. Per-source sliding 60s window flags `port_scan` when a source has crossed ≥ 10 distinct dest ports, and `brute_force` when a source has hit the same auth-relevant dest port (22 SSH / 445 SMB / 3389 RDP / 8888 admin) ≥ 20 times. The two classifiers share a single window-shrink loop since both use the same 60s window. Both thresholds are package-level consts so the test suite locks in the exact numbers documented in the README/ROADMAP — drift between code and docs would be a silent regression. The brute-force target list is a tiny map (high-risk credential-attack ports only) so a 20-hit UDP burst against an ephemeral port stays quiet — otherwise the banner would light up on every misbehaving client. The `Event` JSON gains a `Threats []string \`json:"threats,omitempty"\`` field; unflagged events stay compact on the wire. UI: single amber threat banner above the events table summarising counts (`N sources flagged for port-scan · M sources flagged for brute-force`); per-row, inline `scan` / `brute` pill next to the source IP marks the threshold-crossing events, the row tinted warm-white. Seven new tests in `internal/events`: threshold-cross detection (port_scan + brute_force), slow-scan non-detection (10 ports over 100 minutes), sub-threshold off-by-one (9 ports stays quiet), non-target-port non-detection (port 54321 hammered at brute-force volume stays quiet), cross-source separation (two sources × 5 ports each does not collapse into one synthetic scan), empty-input safety. OpenAPI `Event` schema documents the new field with the enum constraint on tag values. | The raw drop log + the v0.4.1 top-sources card together tell the user "this source hit my host a lot," but not "this source was doing reconnaissance against your perimeter." The classifier turns volume into a shape — port-scan vs. credential-guess — that maps to a different response (geo-block vs. fail2ban-style temporary lockout). Volume-only metrics confuse busy clients with attackers; this is the first signal in the project that distinguishes them. |
| **v0.4.1** | **Events tab analytics — first v0.6 (*Intrusion detection & state*) item.** Three roadmap entries merged into one frontend-only release on top of the existing `/api/events` stream — no new endpoint, no backend change. **Top 10 source IPs** and **top 10 targeted ports** render as side-by-side cards above the Events table; each row is a key + horizontal bar + count, the bar scaled relative to the top entry so the visual carries information density beyond the count alone. **24h sparkline**: 144 buckets × 10 minutes, inline SVG drawn from the same `/api/events?since=24h&limit=5000` fetch the rest of the tab uses (one round-trip per refresh, not three). The 1h slice driving the cards + table is a client-side filter on the same payload. Three new JS helpers: `topN(events, pick, n)` with deterministic lex tie-breaking so the cards do not flicker between refreshes when two entries tie, `bucketByTime(events, start, end, bucketMs)` returns count-per-bucket and silently drops out-of-range events, `renderSparkline(buckets)` emits viewBox-scaled SVG so the host element controls layout. The analytics block hides itself when the 1h slice is empty, keeping a quiet host's Events tab as clean as before v0.4.1. The 4th roadmap analytics item — **GeoIP source flags** — was split off into v0.4.5 because it needs an IP→country reverse-lookup index that does not exist in `internal/geo` today (which only maintains country→CIDR data for outbound rules). | The raw events table is honest but not actionable: a user looking at 200 rows can't see "47% of blocks come from one source" at a glance. The aggregations turn the same data into a posture overview without changing the underlying event stream — and the sparkline above the status bar gives a 24h volume signal that does not require switching tabs. |
| **v0.4.0** | **Mod-Store submission prep — fifth v0.5 item; closes v0.5.** New `mod-store/zfw.yaml` is the source-of-truth submission manifest (`id`, `title`, `tagline`, `description`, `category: Network`, `tags`, `icon`, `author`, `maintainer`, `license: ISC`, `repository`/`homepage`/`issues` URLs, per-arch artifact pointers + `sha256: TBD` placeholders for release-cut time, `ui.entry`/`formality` mirror of the in-module `casaos/modules/zfw.json`, screenshot list with captions, hardware compatibility — `os_min: 1.6.0`, `architectures: [amd64, arm64]`, `kernel_min: 6.12` — and informational required-permissions list). New `MOD-STORE.md` is the operator runbook: (1) one-time GitHub-remote setup with `gh repo create` (the committed CI workflow goes green on first push by construction), (2) the per-release tag + `gh release create` step that uploads both arch tarballs + their `.sha256` + the SBOM, (3) the `gh repo fork IceWhaleTech/Mod-Store && gh pr create` flow with a ready-made PR body explaining the stock-ZimaOS firewall gap, (4) the post-submission step that wires `ZFW_UPDATE_URL` so v0.3.9's update banner starts firing across every host, (5) the per-release sanity checklist that mirrors the project's `pre-tarball-checklist` memory. No daemon code change in this release: the submission is gated on a manual operator step (the repo needs a GitHub remote and a maintainer to file the PR), so the daemon could not legitimately automate it without exceeding its scope. The phase exit criterion — "a Gelbuilding-class user can `zpkg install zfw` and never see Github at all" — becomes met the moment Maintainer walks through MOD-STORE.md once. | Without the submission-prep step, every individual v0.5 piece (arm64 binary, self-update plumbing, multi-host sync) would be plumbing without a destination — the canonical-distribution promise the phase was named for. Capturing the submission steps as a runbook turns a one-time operator task into something a future Claude session can also walk through if Maintainer loops back later, and locks in the contract (which fields the manifest needs, which arches matter, what the PR body should say) at the same point in history as the code that justifies it. |
| **v0.3.10** | **Multi-host rule sync (opt-in) — fourth v0.5 item.** New `internal/peers` package: each follower host is configured in a JSON file at `/DATA/zfw/peers.json` (override via `ZFW_PEERS`) with `{name, url, token}`. The leader's `POST /api/peers/push` reads the currently saved `rules.json` off disk and fans it out to every peer's `/api/peers/receive` endpoint, returning per-peer `Result` entries (`{name, url, ok, code, error}`) in the same order as peers.json so the UI can render successes and failures side by side. Authentication on the follower side is a shared bearer (`ZFW_PEER_TOKEN` env, empty by default — opt-in) checked directly inside the handler; the ZimaOS-session JWT middleware is bypassed for `/api/peers/receive` because the leader has no user session on the follower. Both sides are independent — a host can be a leader (peers.json configured), a follower (`ZFW_PEER_TOKEN` set), both, or neither. `GET /api/peers` returns a token-stripped view (`peers.Public`) so a compromised UI session cannot exfiltrate the shared secrets. Outbound HTTP uses a 30 s-timeout client — long enough for a slow Recompile on the receiver, short enough that a hung peer doesn't pin the leader's push request indefinitely. The Rules-tab action row grows a *Push to peers* button that stays hidden when `/api/peers` returns an empty list; clicking it surfaces a confirm dialog listing every peer by name+URL, then routes through `/api/peers/push` and reports per-peer ok/fail to the status bar. Followers must still click Safe-Apply themselves after a push — the 120 s dead-man timer remains the last line of defence. New tests: seven in `internal/peers` (Load on missing/empty/valid file, Sanitize strips tokens, Push wire shape, Push per-peer error fanout, empty-token short-circuit) plus six handler tests (list strips tokens, list empty when unconfigured, push empty without peers, receive disabled 403, receive wrong token 401, receive happy-path saves rules.json + recompiles). New config fields `PeersFile` (`ZFW_PEERS`, default `/DATA/zfw/peers.json`) and `PeerToken` (`ZFW_PEER_TOKEN`, default empty). OpenAPI 3.0 spec documents the three new endpoints and the `Peer` / `PeerResult` schemas. | A homelab user with multiple ZimaOS hosts had to copy rules.json by hand (scp, then Safe-Apply on each one) — the entire point of having an HTTP API was lost when scaling past one host. Push closes that gap with a JWT-free fast path (the only sane authentication when the leader doesn't sit in the follower's session table) while keeping both sides opt-in: no peers.json on the leader = no push button; no `ZFW_PEER_TOKEN` on the follower = 403 on every receive. A misconfiguration on either end is silently safe by default. |
| **v0.3.9** | **`zpkg` self-update check — third v0.5 item.** New `internal/update` package polls a configurable manifest URL (`ZFW_UPDATE_URL`, opt-in via env — empty by default so a fresh install makes no outbound HTTP) once per week and caches the result in process memory. The manifest is a tiny JSON document — `{"version":"0.4.0","notes":"closes v0.5"}` — so it can be hosted on any static URL (raw GitHub, S3, Mod-Store CDN). New endpoint `GET /api/update` returns the cached `{current, latest, available, notes, checked_at, error}` snapshot; a daemon with no URL still responds 200 with only `current` populated, so the UI's fetch never sees a phantom 404. `update.Run(ctx, 7*24h)` starts the polling goroutine; ctx-cancellation on shutdown stops it cleanly. Semver-ish `Compare(a, b)` handles `0.3.10 > 0.3.9` correctly (lexicographic ordering would not) and tolerates `v0.3.7` / `0.3.7-dev` / `0.3.7+build`. The Versions tab now renders a non-blocking green "Update available: vX.Y.Z" banner above the component list when `available=true` — silently hidden on network/parse errors so a flaky check never confronts the user with an HTTP trace. Seven new unit tests in `internal/update` cover Compare ordering, happy-path manifest parse, same-version no-badge, HTTP 500, non-JSON body, disabled-checker no-op, context cancellation. Two new handler tests: `TestUpdateEndpointDisabledStillReturns200` and `TestUpdateEndpointReturnsCheckerSnapshot`. New config field `UpdateURL` (`ZFW_UPDATE_URL`, default `""`). OpenAPI 3.0 spec documents `/api/update` and the new `UpdateStatus` schema. | Pre-v0.3.9 a user on v0.3.6 had no in-product signal that v0.3.7 (arm64) and v0.3.8 (migration) had shipped — they had to follow the GitHub repo by hand. The check is opt-in (empty URL by default) so the privacy story stays "no outbound calls until you ask" while the Mod-Store entry from a later v0.5 release will be able to wire in a canonical URL with zero code change here. |
| **v0.3.8** | **rules.json migration helper — second v0.5 item.** `RuleSet` gains an explicit `version` field (current schema = 1). `Load(path)` runs `migrate()` on read: an older rules.json (no `version` field, or `version < CurrentSchema`) is upgraded transparently and the pre-migration bytes are preserved as `<path>.bak.v<sourceVersion>` before the upgraded form is written back. A rules.json from a *future* daemon (`version > CurrentSchema`) is refused with `rules.json schema vN is newer than this daemon` rather than loaded with silently-dropped fields. `Save(path, rs)` always stamps `rs.Version = CurrentSchema` regardless of what the caller passed — the version field is daemon-owned, never user-owned. The schema is stable today (`v0 → v1` is a field-compatible rename), so this release does not migrate any real-world data — the value is the plumbing. Adding a new field in a future schema bump becomes a single switch-case (`case 1: rs.Version = 2; rs.X = default`) instead of a from-scratch migration design. Four new tests in `internal/rules`: missing-version load migrates + writes `.bak.v0` with byte-identical original; current-version load is a no-op (no .bak written, on-disk bytes unchanged); future-version load refuses (file left untouched, no .bak); `Save` stamps `CurrentSchema` regardless of the input `Version` field. OpenAPI `RuleSet` schema documents the new field with a daemon-owned annotation. | Schema bumps in a deployed product without migration plumbing become user-hostile decisions ("upgrade and lose your rules" vs. "stay on the old version forever"). Designing the plumbing while the schema is still stable means the next bump — adding outbound-rule fields (v1.0), schedule fields (v0.6), or per-rule logging toggle (v0.6) — costs one switch-case and a backup file, not a release-blocking migration design. The .bak file is the cheapest possible safety net: a user who hits a buggy migration can `mv rules.json.bak.v0 rules.json` and downgrade. |
| **v0.3.7** | **arm64 build — first v0.5 (*Distribution & multi-host*) item.** `build.sh` now loops over the `ARCHES` env var (default `amd64 arm64`) and produces one reproducible tarball per arch — `dist/zfw-<v>-amd64.tar.gz` (ZimaBoard 1/2, ZimaCube; N3350/N3450/N100) and `dist/zfw-<v>-arm64.tar.gz` (Lattepanda/Pi-class hosts). The host's arch is auto-detected in `install.sh` via `uname -m` (`x86_64`→`amd64`, `aarch64`→`arm64`) so a source-repo install picks the right `dist/zfw-<arch>.raw` without extra flags; the in-tarball payload stays `zfw.raw` (generic name) so `install.sh` itself does not need to know about arches. Cross-compile is free — the daemon is pure Go (`CGO_ENABLED=0`, `-trimpath -buildvcs=false`) so the existing amd64 build host produces both binaries in one pass. Reproducibility holds per-arch: two clean builds of the same source produce byte-identical tarballs for each arch independently (verified locally — amd64 `0eb75059…`, arm64 `a3ededee…`, both identical across two consecutive runs). Verified binary types via `file(1)` against the unsquashfs'd raw: amd64 → `ELF 64-bit LSB executable, x86-64, statically linked`; arm64 → `ELF 64-bit LSB executable, ARM aarch64, statically linked`. The CI workflow's pre-existing arm64 cross-compile smoke job becomes redundant with this — it will be removed when the repo gets its GitHub remote and the main build path runs in CI. | First v0.5 lever. ZimaBoard 216/432/832 (N3350/N3450) and ZimaBoard 2 (N100) are all amd64 — those users were covered. But third-party hosts running ZimaOS on Lattepanda/Pi-class hardware are arm64, and previously had to compile from source. With `CGO_ENABLED=0` already set, multi-arch was a five-line refactor of `build.sh`; not shipping it was the user-hostile choice. |
| **v0.3.6** | **Exposure → Deny quick-action — sixth v0.4 item; closes v0.4.** Each listening-port row in the Exposure tab grows a second button (`→ Deny`) next to the existing `+ Rule`. Click opens the rule editor pre-filled for a flat block of that port (`action: deny`, `source.type: any`, `ports.list: [<port>]`, `zone: auto`, name `Block port <port>`). The user still has to Save rules + Safe-Apply — the prefill just collapses a seven-field setup into two clicks. New helper `openDenyEditorForPort(port)` mirrors the existing `openRuleEditorForPort`; `renderExposure` renders both buttons with `.exp-actions` keeping them inline. New CSS for `.exp-deny` (red border on hover) signals the destructive direction. No backend change. | The Exposure tab is where a user actually *sees* an open port they did not expect — making "click → block" the same two-click loop as "click → permit" turns the tab from a read-only scoreboard into the natural place to harden posture. With this, every v0.4 roadmap item has shipped (modulo the deliberately-dropped i18n). |
| **v0.3.5** | **Audit-findings status history — fifth v0.4 item.** New `internal/audit/history.go` adds a `History` map keyed by finding ID, with `Load` / `Save` / `Update(findings, now)` / `Attach(findings)` helpers. The handler at `/api/audit` now loads the on-disk timeline, recomputes findings against the live firewall state, appends a new `{ts, status}` row to any finding whose status differs from the previous entry, persists the file if anything changed and returns each finding wrapped in a `FindingWithHistory` with `history` always normalised to `[]` (never null — the UI iterates the slice). Per-finding cap of 20 entries prevents a flapping posture from ballooning the file. New config field `HistoryFile` (`/DATA/zfw/audit-history.json` by default), new env var `ZFW_HISTORY`. `auditMu` serialises concurrent /api/audit reads so the file write is race-free. UI renders an inline `History: open → fixed → open (since YYYY-MM-DD)` below each finding card, hidden when the posture has never flipped. Four new unit tests cover round-trip, append-on-change-only, the length cap and the attach shape; the existing `TestAuditReturnsArray` is upgraded to assert `history` is always present and non-null. | Without a timeline, the audit tab is a snapshot — the user can't tell whether "M2 dozzle: fixed" has been stable for a week or just flipped this morning. The history field is the cheapest possible posture-drift signal that does not require an external metrics store. |
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

## v0.4 — UX polish (rule authoring) — DELIVERED in v0.3.6

Made the Rules tab feel like a tool that respects the user's time.
Every item below shipped across v0.3.1 → v0.3.6, except the
deliberately-dropped i18n entry.

| Item | Why |
|---|---|
| **Rule templates library** *(shipped v0.3.1)* | Three templates so far — *Block VNC consoles* (5900-5999), *Block NFS / rpcbind* (111/2049/20048 TCP+UDP), *Allow Plex Media Server* (32400 from LAN). New endpoint `GET /api/rules/templates` with LAN-substitution; Rules-tab modal renders the catalogue. More templates can ship as future patches without endpoint churn. |
| **Rule notes / comments field** *(shipped v0.3.2)* | Optional free-text `notes` per Rule (max 256 chars). Textarea in the editor, "note" pill with hover-tooltip in the rule table. Validate caps the length; OpenAPI Rule schema documents it. |
| **Backup / restore rules.json** *(shipped v0.3.3)* | Backup button downloads `zfw-rules-<ts>.json` (raw RuleSet, no custom wrapper); Restore reads a JSON file, sanity-checks the shape, confirms the overwrite count, then POSTs to `/api/rules` so server-side Validate runs again. Firewall not auto-re-applied — user still has to Safe-Apply. |
| **Diff view: unsaved vs applied** *(shipped v0.3.4)* | Diff button on the Rules tab (enabled only when `rulesDirty`) opens a modal listing every change Save would push — added / removed / changed rules plus default-policy flips, each with a one-line semantic summary. Pure client-side; fetches `/api/rules` for the saved snapshot. |
| **Audit findings: history** *(shipped v0.3.5)* | Persistent per-finding status timeline in `/DATA/zfw/audit-history.json`. One entry per posture flip, capped at 20 per finding. Audit-tab renders an inline chain ("History: open → fixed → open *(since 2026-05-22)*") below each finding once it has flipped at least once. |
| **Quick-action from Exposure tab** *(shipped v0.3.6)* | `→ Deny` button alongside the existing `+ Rule` on every listening-port row. Opens the rule editor pre-filled for a flat block; user still has to Save + Safe-Apply. No backend change. |

**Exit criterion (met in v0.3.6):** a new ZFW user can produce a
clean rule set without reading docs. Templates (v0.3.1) provide
one-click presets, defaults (v0.2.9) auto-detect LAN+Docker, the
Exposure→Deny quick-action (v0.3.6) blocks an unexpected open port in
two clicks, backup/restore (v0.3.3) and the diff view (v0.3.4) make
edits reversible, notes (v0.3.2) and audit history (v0.3.5) keep the
posture self-documenting.

---

## v0.5 — Distribution & multi-host — DELIVERED in v0.4.0

Stop being a tarball-on-Maintainers-Github tool. Become discoverable, updatable,
multi-platform.

| Item | Why |
|---|---|
| **arm64 build** *(shipped v0.3.7)* | `build.sh` loops over `ARCHES` (default `amd64 arm64`) and produces one reproducible tarball per arch; `install.sh` picks the right `dist/zfw-<arch>.raw` from `uname -m`. ZimaBoard 1/2 and ZimaCube stay amd64; third-party Lattepanda/Pi-class hosts can install without compiling from source. |
| **Mod-Store submission** *(prep shipped v0.4.0)* | `mod-store/zfw.yaml` is the source-of-truth submission manifest; `MOD-STORE.md` is the operator runbook for the manual GitHub-remote setup and the per-release `gh pr create` flow against `IceWhaleTech/Mod-Store`. Submission itself remains a one-shot operator step (needs the GitHub remote first); the prep file + runbook stay in the repo so the contract does not have to be re-derived per release. |
| **`zpkg` self-update** *(shipped v0.3.9)* | `internal/update` polls a configurable manifest URL (`ZFW_UPDATE_URL`, opt-in) once per week and caches the result; `GET /api/update` exposes the snapshot; the Versions tab renders a non-blocking "Update available: vX" banner when `available=true`. The manifest URL stays empty until a Mod-Store entry exists, so no outbound HTTP on a fresh install. |
| **Migration helper** *(shipped v0.3.8)* | `RuleSet` carries explicit `version`; `Load` migrates older files transparently with a `.bak.v<old>` backup; a future-schema rules.json is refused rather than silently truncated. Schema is stable today — the plumbing is in place for the next bump. |
| **Multi-host rule sync (opt-in)** *(shipped v0.3.10)* | `internal/peers` package + three handlers (`GET /api/peers`, `POST /api/peers/push`, `POST /api/peers/receive`). Leader-side: peers.json with `{name, url, token}` per follower. Follower-side: shared `ZFW_PEER_TOKEN` env, JWT-bypassed handler. Off by default on both sides. UI grows a *Push to peers* button on the Rules tab; the receiver still has to Safe-Apply. |

**Exit criterion (met in v0.4.0, gated on the manual Mod-Store PR):** a
Gelbuilding-class user can `zpkg install zfw` and never see Github at
all. The five-release v0.5 line — v0.3.7 (arm64), v0.3.8 (migration),
v0.3.9 (self-update), v0.3.10 (multi-host sync), v0.4.0 (Mod-Store
prep) — landed everything the daemon side needs; the only remaining
step is the operator walking through MOD-STORE.md once.

---

## v0.6 — Intrusion detection & state — DELIVERED in v0.5.0

Move from "static allow / deny" to a firewall that understands when, what,
and from whom. Builds on the v0.2.12 Events foundation (kernel-LOG capture
+ `/api/events` + Events tab).

| Item | Why |
|---|---|
| **Top sources / top ports widgets** *(shipped v0.4.1)* | Side-by-side cards above the Events table with the top-10 source IPs and top-10 targeted ports of the last hour, each row a key + horizontal bar + count. Client-side aggregation over the existing /api/events stream — no new endpoint. |
| **GeoIP source flags** *(shipped v0.4.5)* | `geo.Manager.Lookup(ip)` + `LookupBatch(ips)` build an in-memory CIDR→country index from the cached `.zone` files on disk (no extra MMDB). New `GET /api/geo/lookup?ips=…` endpoint; UI renders a flag-emoji + ISO-code pill next to each source IP on the Events tab. |
| **Last-24h sparkline** *(shipped v0.4.1)* | 144 buckets × 10min inline-SVG above the status bar. Same /api/events fetch as the cards above. |
| **Port-scan detection** *(shipped v0.4.2)* | `events.Classify()` per-source sliding 60s window, `port_scan` flag when ≥10 distinct dest ports. UI threat banner + inline `scan` pill. |
| **Brute-force detection** *(shipped v0.4.2)* | Same window, `brute_force` flag when ≥20 hits against an auth-relevant port (22/445/3389/8888). UI threat banner + inline `brute` pill. |
| **Time-window rules** *(shipped v0.4.3)* | `Rule.Schedule { From, To, Days }` (schema v2 — first real use of v0.3.8's migration plumbing). Compiler emits `-m time --timestart … --timestop … --weekdays … --kerneltz`. Empty Days = every day; From > To wraps midnight. UI fieldset + on-row pill. |
| **Connection-state visibility** *(shipped v0.5.0)* | `internal/conntrack` reads `/proc/net/nf_conntrack` with `conntrack -L` fallback; `GET /api/conntrack` returns up to 500 active entries (original direction only); new *Connections* tab renders them with state-coloured pills. The rule-match annotation mentioned in the original spec is deferred to v1.0 — the conntrack table itself is the v0.6 deliverable. |
| **Per-rule logging toggle** *(shipped v0.4.4)* | `Rule.Log` (bool). Compiler emits non-terminating `-j LOG --log-prefix "ZFW-RULE-<id> "` in front of the action; matching packets appear in the Events tab without changing the rule's effect. |
| **Rate-limit per source** *(shipped v0.4.4)* | `Rule.RateLimit{Conn, Seconds}`. Compiler emits two `-m recent` lines (set + update --hitcount → DROP) sharing the rule's match prefix; per-rule `--name z<id>` keeps each rule's tracking table isolated. |

**Exit criterion (met in v0.5.0):** firewall posture answers "what
happened" and "what will happen at 2 AM," not just "what's the
current ruleset." Seven releases shipped across v0.4.1 → v0.5.0:
analytics (v0.4.1), threat detection (v0.4.2), time-window rules +
first real schema bump (v0.4.3), per-rule logging + rate-limit
(v0.4.4), GeoIP source flags (v0.4.5), conntrack visibility
(v0.5.0).

---

## v1.0 — General Availability — DELIVERED in v1.0.0

Six items, shipped across five releases:

| Item | Status |
|---|---|
| **Outbound rules (`OUTPUT` + `FORWARD`)** *(shipped v0.5.6)* | Schema v2 → v3. New chains ZFW-OUT (OUTPUT), ZFW-OUT6 (ip6tables OUTPUT), ZFW-FWD-OUT (FORWARD). Outbound never default-denies (would brick host DNS / NTP / Docker pulls). Source field flips semantically to "destination peer", compiler emits `-d` instead of `-s`. |
| **Per-container rule binding** *(shipped v0.5.7)* | Optional `Rule.ContainerID` binds a rule by short ID or name; daemon resolves the live container's host-published ports at every Recompile and substitutes them into the rule. Missing container falls back to saved ports. New `/api/system/containers` endpoint feeds the rule-editor's binding picker. Auto-recompile via `docker events` deferred to v1.x — current behaviour is "user re-runs Safe-Apply after a container port remap." |
| **VPN-interface awareness** *(shipped v0.5.4)* | `wg+` (WireGuard wildcard) joins `lo / docker0 / br-+ / virbr0 / tailscale0 / zt+` as a built-in default-bypass on every chain. Operator-supplied extras via `ZFW_EXTRA_BYPASS_IFACES` env (comma-separated, strict char-set validation). |
| **Notification hooks** *(shipped v0.5.5)* | New `internal/notify` package + `ZFW_WEBHOOK_URL` env. Fire-and-forget JSON POST on `rules.saved` / `firewall.applied` / `firewall.committed` / `firewall.reverted`. Best-effort, never blocks the firewall flow. Opt-in (empty URL = no outbound HTTP). |
| **Threat model document** *(shipped v1.0.0)* | `THREAT-MODEL.md` — 15-min read for IceWhale reviewers: assets, adversaries (A1 LAN-attacker, A2 compromised LAN device, A3 container, A4 malicious app, A5 MITM, A6 stolen session token, A7 local non-root), trust boundaries, mitigations cross-referenced to every finding in SECURITY-REPORT.md, accepted residuals with rationale, per-adversary test map. |
| **External pen-test prep** *(shipped v1.0.0)* | `BUG-BOUNTY.md` — in-scope / out-of-scope, process, severity → fix-window matrix, safe-harbour clause, hall of fame. External pen-test itself stays operator-driven (forum outreach), same gating as the Mod-Store-PR in v0.4.0. |

**Exit criterion (met in v1.0.0):** an enterprise admin would
install ZFW on a small office ZimaCube and not lose sleep. The
v1.0 phase shipped four code releases (v0.5.4–v0.5.7) and one
capstone (v1.0.0) carrying THREAT-MODEL.md + BUG-BOUNTY.md.

---

## v1.x — future

This section did not exist before v1.0.0; future feature requests
that don't fit the GA spine land here.

- **Docker-events watcher** — currently the user runs Safe-Apply
  after a container port remap. A `docker events` subscriber that
  triggers Recompile (not auto-apply — dead-man invariant) is the
  natural follow-up to v0.5.7 per-container binding.
- **Per-IP rate-limit + dashboard polling debounce** — accepted
  residual R3-5 / R3-6. Needs session-ID tracking the daemon
  currently doesn't keep.
- **Debug-log path for journalctl errors** — accepted residual R3-8.
  Currently `internal/events.Read` swallows journalctl errors to
  keep the Events tab non-blank on a journald hiccup; a debug-log
  line would help operators diagnose persistent failures.
- **GeoIP source flags for hosts behind NAT** — flagged limitation
  during v0.5.0 testing: a host with only RFC1918 source-IP drops
  sees no flags. A small UI banner "all sources in this window are
  private" would set the expectation without claiming the feature
  is broken.
- **Live conntrack rule-match annotation** — original v0.6
  ROADMAP spec for conntrack was "live conntrack with rule-match
  annotations." v0.5.0 shipped the table; the annotation ("this
  rule is what blocked X") needs a richer rule-evaluation log
  inside the engine.

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
