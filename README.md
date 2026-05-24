# ZFW — a host firewall for ZimaOS

> **Current release:** v0.5.6 — see [Status](#status) for the build line.

ZFW is a standalone ZimaOS module that adds the one thing ZimaOS does not ship:
a **host firewall** — with a web UI and a live security dashboard.

## Why ZimaOS needs a firewall

ZimaOS ships with **no host firewall at all**. On a stock install every `iptables`
chain — `INPUT`, `FORWARD`, `OUTPUT` — has a default policy of `ACCEPT` and carries
no filtering rules, and there is no `nftables` ruleset either. This is not one host
misconfigured; it is the out-of-the-box state of the operating system.

The direct consequence: **every service listening on `0.0.0.0` is reachable from the
entire local network, and nothing in the OS can stop it.** That already covers
services ZimaOS itself ships and enables by default:

- **Samba/SMB** (445/139) and the **NFS + rpcbind** stack (2049/111) — file-sharing
  daemons open to the whole subnet. `rpcbind` on port 111 is a well-known
  reflection/amplification and information-disclosure vector.
- **Discovery services** — mDNS, WS-Discovery, SSDP/UPnP, LLMNR — broadcast services
  enabled by default.
- **The built-in VM console.** Virtual machines created through ZimaOS's built-in
  virtualization module expose their VNC console (port 5900 and up) **with no
  password**, bound to all interfaces. Any device on the LAN can point a VNC viewer
  at it and take full keyboard/mouse/screen control of the running VM. This is a
  shipped default — it affects every ZimaOS user who runs a VM.
- **The ZimaOS web UI** on port 80.

Then there is the app store. ZimaOS is built around one-click Docker apps, and a
published container port goes straight onto `0.0.0.0` — Docker's port mapping
bypasses the host entirely and is LAN-wide the instant the app starts. Many
widely-used self-hosted images **default to no authentication**: log viewers,
metrics dashboards, browser-desktop / noVNC images, admin panels. With no host
firewall, each such app is an open door on the network the moment it is installed —
and a ZimaOS user is *expected* to install apps freely; that is the product.

Finally, the LAN itself is no longer a trust boundary. A normal home network carries
smart TVs, IoT gadgets, a games console, guests' phones — any one of which can be
compromised and is then a direct peer of the NAS that holds all your data.

ZimaOS is marketed as a plug-and-play homelab/NAS appliance for people who are
explicitly *not* network engineers. Expecting every owner to hand-audit service
bindings is unrealistic. A firewall is the single systemic control that closes this
entire class of exposure at once. That is what ZFW provides.

> ZFW grew out of a hands-on security audit. That audit ran on a heavily customised
> host with many self-installed apps — those host-specific findings are deliberately
> **not** the argument here. The argument is the stock ZimaOS baseline described
> above, which is identical on every install.

## What ZFW does

A standalone ZimaOS module — a tile in the ZimaOS dashboard — with five sections:

- **Firewall** — live status; **Safe-Apply** with a 120-second dead-man switch that
  auto-reverts the rules if you do not confirm in time, so a bad rule can never lock
  you out; Commit; Revert.
- **Allowlist** — edit which ports are reachable from the LAN by clicking — no SSH,
  no file editing.
- **Exposure** — every listening TCP port, live, classified: reachable from the LAN /
  blocked by ZFW / loopback-only.
- **Audit** — a catalogue of security findings, each re-evaluated live against the
  current firewall configuration (open / LAN-blocked / fixed).
- **Versions** — the host's key components with their known-CVE status.

## How it works

ZFW filters at **two hook points**, because traffic on ZimaOS takes two separate paths:

| Hook | Filters | Mode |
|------|---------|------|
| `INPUT` (chain `ZFW-IN`) | host-native daemons (SSH, web UI, SMB, NFS, …) | default-drop allowlist |
| `DOCKER-USER` | published Docker container ports | blocklist |

A plain `INPUT` firewall is not enough: **Docker-published ports never traverse
`INPUT`** — they are DNAT'd and routed through `FORWARD`. `DOCKER-USER` is Docker's
official, guaranteed-untouched user hook, so ZFW filters container ports there.

`localhost`, the host's own IP and the `tailscale0` / ZeroTier interfaces are always
allowed — so VPN access and tunnel clients (e.g. Pangolin/Newt) are never affected.
ZFW governs the **LAN** boundary only.

## Architecture

ZFW is two layers:

- **Engine** — `/DATA/zfw/zfw`, a shell script plus `allowlist.conf`. It applies the
  `iptables` rules, runs as root from a systemd unit, and supports a dead-man
  `--safe` mode.
- **Module** (this repository) — a Go daemon (`zfwd`) and the web UI. The daemon
  binds **`127.0.0.1` only**; the ZimaOS gateway proxies the route `/v2/zfw` so the
  UI is reachable same-origin via port 80. Because the gateway forwards module
  routes **without authenticating them**, the daemon verifies a valid ZimaOS session
  token (an ES256 JWT, checked against the platform JWKS) on every API request — the
  firewall's own control panel must not be an unauthenticated hole in the firewall.

```
cmd/zfwd            daemon entry point
internal/firewall   control plane: wraps the engine + allowlist.conf, reads live state
internal/system     listening-port scan, component versions
internal/audit      finding catalogue, scored live against the firewall config
internal/gateway    ZimaOS gateway route registration
internal/watchdog   boot watchdog (ZimaOS sysext units can lose the boot race)
raw/                the sysext file tree (binary, systemd unit, manifest, static UI)
```

## Build

```sh
sh build.sh        # -> dist/zfw-<version>-<arch>.tar.gz  (per arch)
```

Default arches: `amd64` (ZimaBoard 1/2, ZimaCube) and `arm64` (Lattepanda/Pi-class
hosts). Override with `ARCHES="amd64" sh build.sh` to build a single arch.
Requires `go` 1.22+ and `squashfs-tools` (`mksquashfs`). The image is packed with
gzip — the ZimaOS kernel is built without zstd/xz squashfs support.

## Deploy

`build.sh` writes one release package per arch — `dist/zfw-<version>-<arch>.tar.gz`
contains the `zfw.raw` module, the `zfw` engine script, `install.sh` and the docs.
Copy the matching arch to the ZimaOS host and run the installer as root:

```sh
scp dist/zfw-<version>-amd64.tar.gz root@<host>:/tmp/   # ZimaBoard / ZimaCube
ssh root@<host> 'cd /tmp && tar xzf zfw-<version>-amd64.tar.gz && cd zfw-* && sh install.sh'
```

`install.sh` places the sysext module in `/var/lib/extensions/`, installs the
engine script to `/DATA/zfw/zfw` (`root:root`, `0700`), verifies the module
checksum, merges the sysext and (re)starts `zfw-ui.service`. Re-run it any
time to update an install in place.

Open it from the ZimaOS dashboard (tile **ZFW Firewall**), or directly at
`http://<host>/modules/zfw/index.html`.

## Configuration

The allowlist is edited from the UI, or directly in `/DATA/zfw/allowlist.conf`:

| Key | Meaning |
|-----|---------|
| `LAN` | the local subnet, e.g. `192.168.1.0/24` |
| `HOST_IP` | the host's LAN IP |
| `HOST_TCP_LAN` / `HOST_UDP_LAN` | host-native ports left reachable from the LAN; everything else is dropped (still reachable via Tailscale / loopback) |
| `DOCKER_DROP_LAN` | published container ports to block from the LAN |
| `V6_DROP` | ports to block on IPv6 |

After any change, run **Safe-Apply** from the Firewall tab (or `zfw apply` on the host).

## Safety

Applying firewall rules over the network is risky — one wrong rule can lock you out.
ZFW's **Safe-Apply** applies the rules and arms a 120-second timer; unless you click
**Confirm** (or run `zfw commit`) within that window, the rules are reverted
automatically. The current SSH session is never dropped — established connections are
accepted first.

For a full operating guide — staying reachable, rule ordering, geo-blocking
limits and recovery — see **[BEST-PRACTICES.md](BEST-PRACTICES.md)**.

## Status

**v0.5.6** — third v1.0 item: **outbound rules (OUTPUT + FORWARD)**.
The largest v1.0 lift: rules can now target traffic leaving the host
or containers, not just traffic arriving. Schema bumps **v2 → v3**
(second real use of v0.3.8's migrate() plumbing) to add the
field-additive `Rule.Direction` (empty / `inbound` = historical
default; `outbound` = new). The compiler emits up to three new
iptables chains when at least one outbound rule exists:

  * `ZFW-OUT`     — host-initiated outbound, hooked into OUTPUT
  * `ZFW-OUT6`    — IPv6 mirror, hooked into ip6tables OUTPUT
  * `ZFW-FWD-OUT` — container-initiated outbound, hooked into FORWARD

Zone routing reuses the existing `Rule.Zone`: `host|auto` → ZFW-OUT,
`docker|auto` → ZFW-FWD-OUT. **The outbound chains never
default-deny** — they always terminate in RETURN — because a blanket
OUTPUT/FORWARD denial would break the host's own DNS / NTP / Docker
registry pulls and the gateway forwarding. Outbound is per-rule
allow/deny, never policy-wide. For outbound rules the `Source` field
flips semantically: it is the destination peer (compiler emits `-d`
instead of `-s`); the UI's source label changes to "Destination /
peer" when the user picks outbound. A rule set with zero outbound
rules compiles to a byte-identical script vs. pre-v0.5.6, so
existing deployments are unaffected. Engine `revert` extends to
flush + detach + delete the new chains; engine `status` lists them
too. Four new compiler tests cover the emit shape, the back-compat
absence-of-outbound, and the safety invariant that ZFW-OUT
terminates in RETURN not DROP. UI: new Direction select in the rule
editor + a yellow `→` pill on the rule-table row for outbound rules.
`ruleSignature` picks up the new field so a direction-only edit
shows up in the diff. OpenAPI Rule.direction documented with the
enum. Deployed and verified live on lan-host — installation includes
the engine-revert update.

**v0.5.5** — second v1.0 item: **notification hooks (webhook)**. New
`internal/notify` package: opt-in outbound webhook fired on every
firewall lifecycle event. Config `ZFW_WEBHOOK_URL` (empty default,
no outbound HTTP from a fresh install). Fire points: `rules.saved`
(after a successful POST /api/rules + recompile), `firewall.applied`
(after Safe-Apply/Apply succeeds, with `safe: true|false` detail),
`firewall.committed` (after Confirm/Commit), `firewall.reverted`
(after Revert — both explicit user revert and dead-man auto-revert
look identical from the daemon's perspective). JSON body: `{type,
version, timestamp, details}`. `Hook.SendAsync` fires the request in
a goroutine with a detached 15s context so the firewall response
goes out without waiting for webhook delivery — best-effort signal,
must never block the firewall flow. A nil-receiver Send is a no-op,
so `s.hook.SendAsync(...)` is safe even when the operator has not
configured a URL. Four new tests cover the contract (disabled =
noop, JSON body matches, HTTP error returns error, async fires
without blocking). New `notify.Hook` field on Server, plumbed
through NewServer (10th param now). v1.0 progress: 2 of 6 shipped
(VPN-bypass v0.5.4, webhook v0.5.5).

**v0.5.4** — first **v1.0 (*GA*)** item: **VPN-interface awareness**.
WireGuard wildcard `wg+` joins the built-in default-bypass list
(lo / docker0 / br-+ / virbr0 / tailscale0 / zt+) on all three
chains — ZFW-IN, ZFW-IN6, DOCKER-USER. A peer arriving on `wg0` /
`wg-clients` / `wg-mesh` is by definition pre-authenticated by
WireGuard's static-key handshake, so default-deny no longer breaks
WireGuard's reach to host services or container ports out of the
box. Operator-supplied extra interface names via the new
`ZFW_EXTRA_BYPASS_IFACES` env var (comma-separated) get appended to
the same lists — useful for custom VPN setups (Mullvad's mullvad0,
Innernet's iface name, etc.) without forking the daemon. Names are
validated against a strict char-set (alnum, dash, underscore, `+`
trailing wildcard, ≤15 chars per IFNAMSIZ) so a crafted env var
cannot inject shell payload into the compiled engine script — that
defence is in `config.isSafeIfaceName`. Two new compiler tests
(`TestWireGuardWildcardBypassed`, `TestExtraBypassIfacesEmittedInAllChains`)
lock the contract. No schema change, no UI change — pure
infrastructure widening.

**v0.5.3** — second template-catalog expansion (Maintainer pick #2).
Catalog now **21 entries**. Added: *Paperless-NGX* (8000), *Mealie*
(9000), *Dozzle* (8080), *n8n* (5678), *OpenWebUI* (3000). The
existing `allow-arr-suite` renamed to `allow-arr-stack` and
expanded to the full six-app *arr family: Sonarr 8989, Radarr 7878,
**Lidarr 8686**, **Readarr 8787**, Bazarr 6767, Prowlarr 9696. Port-
conflict notes refreshed: 8080 now collides on Nextcloud AIO /
qBittorrent / Dozzle / OpenWebUI (latter normally maps host:3000 →
container:8080), 9000 on Portainer + Mealie. Same `allow()`
constructor pattern — each new template stays a one-liner.

**v0.5.2** — pre-v1.0 template catalog expansion. Templates picker
now ships **16 entries** (up from 3): the existing two security
templates (block VNC consoles, block NFS/rpcbind) and "Allow Plex"
stay, plus **13 new "Allow"-from-LAN templates for the typical
ZimaOS Mod-Store app catalog**: *Termina / ttyd* (7681), *Portainer*
(9000+9443), *Jellyfin* (8096+8920+7359/udp+1900/udp), *Immich*
(2283), *Home Assistant* (8123), *AdGuard Home* (3000+53 TCP+UDP),
*Vaultwarden* (8222), *Syncthing* (8384+22000+21027/udp), *Nextcloud*
(8080), *PhotoPrism* (2342), ***arr suite* (Sonarr 8989, Radarr 7878,
Bazarr 6767, Prowlarr 9696 in one template — a typical homelab adds
all four together), *qBittorrent* (8080). Every new template has
zone `auto` so the compiler routes the rule to `ZFW-IN` or
`DOCKER-USER` live based on what is actually published; source is
LAN (auto-substituted via the existing `lanSource(lan)` helper, with
"any" fallback when no LAN is detected). All template
implementations go through a single internal `allow(name, proto,
ports...)` constructor so adding the next Mod-Store entry is a
one-line literal. No schema bump, no compiler change, no UI change —
the picker just gets longer. Existing tests (`TestTemplatesAllValid`,
`TestTemplatesFreshIDs`, `TestTemplatesSubstituteLAN`) cover the
expanded catalog without modification.

**v0.5.1** — hotfix on top of v0.5.0. Two robustness fixes after a
live-test report from lan-host that the **Events**, **Connections** and
**Versions** tabs stuck on "Loading…" with nothing in the console.
Root cause: a single failure anywhere in the tab-load chain threw
to `refreshAll()`'s outer `try/catch`, which surfaced the error in
the status bar but skipped every subsequent tab — and on a host
where one new endpoint returned an unexpected shape (null / {} /
non-array), the per-tab renderers tried `.filter` / `.map` /
`.length` on it and tripped a silent TypeError. Two fixes: (1) new
`runTab(name, fn)` helper wraps each load in its own `try/catch`
plus `console.error` so a faulty tab no longer cascades — every
other tab renders normally and the failing tab name surfaces in
the status bar and DevTools console. (2) defensive
`Array.isArray()` coerce in `loadEvents` / `loadConntrack` /
`loadVersions` so a malformed endpoint response degrades to "no
data" rather than throwing. The `/api/geo/lookup` consumer also
coerces non-object responses to `{}`. No backend change — the
underlying handlers already emit `[]` for empty data; this just
hardens the client against the possibility.

**v0.5.0** — the **v0.6 (*Intrusion detection & state*) phase is
complete**. Final piece: **connection-state visibility** — a live
view of the kernel's conntrack table on a new *Connections* tab.
New `internal/conntrack` package reads `/proc/net/nf_conntrack` as
the primary source (always available when the kernel module is
loaded, which it is on every ZimaOS host because ZFW already
depends on conntrack matches) and falls back to `conntrack -L -o
extended` when /proc is unreadable. Parser handles both shapes
transparently — the `ipv4 2` L3 prefix in /proc output is stripped
so downstream indexing into the field list is identical either
way. Each `Entry` carries protocol, state (omitempty for stateless
protocols), original-direction src/dst IP + port, and the kernel's
timeout countdown (bigger = more recent — TCP ESTABLISHED defaults
to ~5 days, UDP to seconds). New endpoint `GET /api/conntrack`
returns up to 500 entries; UI renders a table with a colour-coded
state pill (`ESTABLISHED` green, `SYN_*` accent, `CLOSE_WAIT`
amber, `TIME_WAIT` muted). On a host without conntrack support the
endpoint returns `[]` and the UI shows a graceful "no active
connections" message rather than erroring. Seven new unit tests in
`internal/conntrack` lock in the parser: `/proc` shape (L3 prefix
stripped), conntrack(8) shape, UDP stateless (state stays empty),
malformed line without src/dst dropped, flag tokens never overwrite
the state name, garbage lines in a stream are silently skipped, the
limit cap is honoured. One new handler test asserts `/api/conntrack`
returns a JSON array (never null). OpenAPI documents the endpoint
and the `Connection` schema. With v0.5.0 in the can, the full v0.6
line has shipped: events analytics (v0.4.1), threat detection
(v0.4.2), time-window rules (v0.4.3), per-rule logging + rate-limit
(v0.4.4), GeoIP source flags (v0.4.5), conntrack visibility (this
release). Exit criterion ("firewall posture answers 'what
happened' and 'what will happen at 2 AM,' not just 'what's the
current ruleset'") is met.

**v0.4.5** — sixth v0.6 item: **GeoIP source flags on the Events
tab**. Reuses the cached per-country `.zone` files the
`internal/geo` package already downloads for outbound geo-block
rules — no extra MMDB download, no extra deps. New
`geo.Manager.Lookup(ip)` + `LookupBatch(ips)` build an in-memory
CIDR→country index lazily on first call and rebuild when the
directory fingerprint (file name + size + mtime nano per `.zone`
file) changes — staleness-by-fingerprint beats staleness-by-mtime
because filesystem mtime resolution is 1s on many setups, so adding
a new `.zone` in the same second as the first build would
otherwise be missed. New endpoint `GET /api/geo/lookup?ips=
ip1,ip2,...` returns `{ip: lowercase-cc}` (every input key
present; unknowns map to `""`) — the UI batches all unique source
IPs from the visible 1h Events slice into one call. Cap of 500 IPs
per query bounds the linear-scan lookup. UI: country flag emoji
(`🇷🇺 RU` regional-indicator pair) + ISO code render as a small
pill next to the source IP on the Events tab, hidden when the
lookup returns `""`. The "fundamental limitation" disclosed when
this was split off in v0.4.1 stands: only countries the user
configured rules for are in the index, so a fresh install with no
geo rules sees no flags — but the common case (blocking RU/CN and
wanting to see RU/CN sources flagged) works exactly. Five new
tests in `internal/geo`: empty manager returns `""`, cached zone
hits, miss outside CIDR returns `""`, LookupBatch contract (every
input key present), rebuild-on-new-zone (fingerprint detects the
add even within sub-second resolution). Two new handler tests:
`/api/geo/lookup` empty query returns `{}`, no-data lookup returns
empty-string values for every input IP. OpenAPI documents the new
endpoint.

**v0.4.4** — fourth + fifth v0.6 items: **per-rule logging toggle**
and **rate-limit per source**, shipped together because both are
field-additive Rule extensions with the same compiler-emit shape
(extra match lines that share the rule's match prefix).
`Rule.Log` (bool): the compiler emits a non-terminating `-j LOG
--log-prefix "ZFW-RULE-<id> " --log-level 6` line in front of the
rule's action line so matching packets appear in the Events tab
without changing the rule's effect. `Rule.RateLimit{Conn, Seconds}`:
two `-m recent` lines (set + update --hitcount → DROP) in front of
the action, using a per-rule `--name z<id>` so each rule's tracking
table is isolated. The engine preamble `modprobe`s `xt_recent` +
`xt_time` (v0.4.3) alongside the pre-existing `xt_LOG` so all three
modules are loaded before any rule references them. Both fields are
omitempty pointers / bools so a rule that does not opt in
round-trips byte-equal to a pre-v0.4.4 v2 rules.json — no schema
bump needed. The compiler refactor extracts a `wrapEmit(match, r,
target)` helper used by all three chain emitters (hostLines,
hostLines6, dockerLines) so the LOG/rate-limit emit shape stays
consistent across host/IPv6/docker zones. Five new tests: two in
`internal/rules` (validate accepts log + rate_limit; rejects bad
conn=0, negative seconds, conn>1000), three in `internal/compiler`
(LOG line emitted before action with correct prefix; recent --set
+ --update lines emitted with `--name z<id>`; no leak — rules
without log/rate-limit emit a single line unchanged). UI: two new
controls in the rule editor — a `Log when this rule fires`
checkbox and a `Rate-limit per source` collapsible fieldset with
conn/seconds inputs. Both round-trip through `ruleSignature` so the
diff view surfaces changes correctly.

**v0.4.3** — third v0.6 item: **time-window rules** — and the
**first real use** of v0.3.8's rules.json migration plumbing. Each
`Rule` gains an optional `Schedule { from, to, days }`. When set,
the compiler emits `-m time --timestart HH:MM --timestop HH:MM
--weekdays Mon,Tue,... --kerneltz` so the rule only matches during
the configured wall-clock window (the `--kerneltz` flag uses the
host's local time, not UTC). Empty `days` means every day; `from`
> `to` wraps midnight (22:00 → 06:00 for an overnight window).
**Schema bump v1 → v2** lands as a single switch-case in
`migrate()` — a v1 rules.json on disk auto-migrates on Load with a
`.bak.v1` preserved before the rewrite, exactly as v0.3.8's tests
promised. The bump is field-additive: an old `rules.json` round-
trips byte-equal except for the stamped `"version": 2`. UI: a new
collapsible *Time-window rule* fieldset in the rule editor with two
`<input type="time">` pickers and a 7-day checkbox row; a small
`HH:MM–HH:MM` pill next to the rule name on the Rules table
surfaces the schedule at a glance; the diff view + ruleSignature
both pick up the new field so saving a schedule-only change shows
up in the diff. Five new tests in `internal/rules` (validate
accepts schedule, rejects bad HH:MM, rejects bad day, schedule
round-trips through JSON omitempty, v1→v2 migrates with .bak.v1
preserved); three new compiler tests (scheduled rule emits the
`-m time …` clause, empty days omits `--weekdays`, unscheduled rule
emits no time clause). OpenAPI Rule schema documents the new
`schedule` field with HH:MM regex + weekday enum; the `version`
field example bumps to 2.

**v0.4.2** — second v0.6 item: **threat detection (port-scan +
brute-force)**. New `events.Classify()` runs on every `/api/events`
response: a sliding 60s window per source IP flags `port_scan` when a
source has hit ≥ 10 distinct dest ports, and `brute_force` when a
source has hit the same auth-relevant dest port (22 / 445 / 3389 /
8888) ≥ 20 times. Thresholds are package-level consts so the test
suite asserts the same numbers documented in the README/ROADMAP —
drift between code and docs would be a silent regression. The
`Event` JSON gains a `threats []string` field (`omitempty`, so
unflagged events stay compact). UI: Events tab carries a single
amber banner above the table when at least one source was flagged
(`N sources flagged for port-scan · M sources flagged for
brute-force`); per-row, an inline `scan` / `brute` pill next to the
source IP marks the threshold-crossing events, with the entire row
tinted warm-white for at-a-glance visibility. Seven new tests cover
both classifiers: threshold-cross detection, slow-scan
non-detection, sub-threshold off-by-one, non-target-port
non-detection (54321 hammered at brute-force volume stays quiet),
cross-source separation (two sources × 5 ports each does not
collapse into one synthetic scan), empty-input safety. OpenAPI
`Event` schema documents the new field.

**v0.4.1** — first **v0.6 (*Intrusion detection & state*)** item:
**Events tab analytics**. Three v0.6 roadmap items merged into one
frontend-only release on top of the existing `/api/events` stream
— no new endpoint, no backend change. (1) **Top 10 source IPs** and
(2) **Top 10 targeted ports** rendered as side-by-side cards above
the Events table, each row a key + horizontal bar + count, scaled
to the top entry. (3) **24h sparkline** above the status bar: 144
buckets × 10 minutes, inline SVG drawn from one `/api/events?since=
24h&limit=5000` fetch — the same payload drives the 1h slice used
by the cards and table, so it is a single round-trip per refresh.
New `topN(events, pick, n)` aggregator with deterministic
tie-breaking (lex on key, so the cards don't flicker between
refreshes). New `bucketByTime(events, start, end, bucketMs)` helper
returns count-per-bucket; events outside the range are silently
dropped. `renderSparkline(buckets)` emits viewBox-scaled SVG so the
host element controls layout. **GeoIP source flags** (4th v0.6
analytics item) was split off into v0.4.5 — it needs an
IP→country reverse-lookup index that does not exist today.

**v0.4.0** — the **v0.5 (*Distribution & multi-host*) phase is
complete**. Final piece: **Mod-Store submission prep**. New
`mod-store/zfw.yaml` is the submission-manifest source-of-truth (id,
title, tagline, description, category=Network, per-arch artifact
URLs + sha256 stubs, screenshot list, hardware compatibility,
required permissions). New `MOD-STORE.md` is the operator runbook:
one-time setup (create the GitHub remote, cut the first
`gh release`, fill in SHAs, capture screenshots), per-release PR
flow against `IceWhaleTech/Mod-Store` (`gh repo fork && gh pr
create` with a ready-made PR body), the post-submission
`ZFW_UPDATE_URL` wiring step that turns v0.3.9's update banner on
across every host, and the per-release sanity checklist that
mirrors the project's `pre-tarball-checklist` memory. No daemon
code change in this release — the submission is gated on a manual
operator step (the repo needs a GitHub remote and a maintainer
willing to file the PR) so the daemon could not legitimately
automate it. With v0.4.0 in the can, the full v0.5 phase has
shipped: arm64 build (v0.3.7), rules.json migration helper
(v0.3.8), `zpkg` self-update check (v0.3.9), multi-host rule sync
(v0.3.10), Mod-Store prep (v0.4.0). The exit criterion ("a
Gelbuilding-class user can `zpkg install zfw` and never see Github
at all") is met as soon as Maintainer runs the steps in `MOD-STORE.md`.

**v0.3.10** — fourth v0.5 item: **multi-host rule sync (opt-in)**.
New `internal/peers` package: each follower host is configured in a
JSON file (`/DATA/zfw/peers.json` by default, override via
`ZFW_PEERS`) with `{name, url, token}`; the leader's `POST
/api/peers/push` reads the currently saved `rules.json` off disk and
fans it out to every peer's `/api/peers/receive`. Per-peer results
(`{name, url, ok, code, error}`) are returned in input order so the UI
can render successes and failures side by side. Authentication on
the follower side is a shared bearer (`ZFW_PEER_TOKEN` env, empty by
default — opt-in) checked inside the handler; the ZimaOS-session JWT
middleware is bypassed for `/api/peers/receive` because a leader has
no user session on the follower. Both sides are independent — a host
can be a leader (peers.json configured), a follower
(`ZFW_PEER_TOKEN` set), both, or neither. `GET /api/peers` returns
the peer list with tokens stripped so a compromised UI session
cannot exfiltrate them. The Rules tab grows a *Push to peers* button
that stays hidden when no peers are configured. Followers must
still click Safe-Apply themselves after a push — the 120 s dead-man
remains the last line of defence. New tests: seven in
`internal/peers` (Load missing/empty/json, Sanitize strips tokens,
Push wire shape + Bearer + per-peer error + empty-token failure) +
six handler tests (list strips tokens, list empty when unconfigured,
push empty without peers, receive disabled 403, receive wrong token
401, receive happy-path applies to disk). OpenAPI documents the
three endpoints and the `Peer` / `PeerResult` schemas.

**v0.3.9** — third v0.5 item: **`zpkg` self-update check**. New
`internal/update` package polls a configurable manifest URL
(`ZFW_UPDATE_URL`, opt-in — empty by default so a fresh install makes
no outbound HTTP) once per week and caches the result. New endpoint
`GET /api/update` returns the cached `{current, latest, available,
notes, checked_at, error}` snapshot; a disabled checker still
responds 200 with only `current` set so the UI never sees a phantom
404. The Versions tab now renders a non-blocking green
"Update available: vX.Y.Z" banner above the component list when
`available=true` — silently hidden on network/parse errors. Semver
comparison handles `0.3.10 > 0.3.9` correctly (lexicographic ordering
would get this wrong) and tolerates a leading `v` plus trailing
`-dev` / `+build` suffixes. Seven unit tests in `internal/update`
cover ordering, happy-path parse, same-version no-badge, HTTP error,
non-JSON body, disabled no-op, and context cancellation. Two new
handler tests cover the disabled-200 branch and the wired-checker
snapshot pass-through. OpenAPI documents the new endpoint and the
`UpdateStatus` schema.

**v0.3.8** — second v0.5 item: **rules.json migration helper**. The
`RuleSet` JSON now carries an explicit `version` field (current schema
= `1`). `Load(path)` runs `migrate()` on read: an older rules.json
(no `version` field, or `version < 1`) is upgraded transparently and
the pre-migration bytes are preserved as `<path>.bak.v<old>` before
the upgraded form is written back. A rules.json from a **future**
daemon (`version > 1`) is refused with a clear error rather than
loaded with silently-dropped fields. `Save(path, rs)` always stamps
`rs.Version = CurrentSchema` regardless of what the caller passed —
the version field is daemon-owned. Today the schema is stable, so the
v0 → v1 step is a field-compatible rename; the plumbing exists so
future schema bumps land as a single switch-case alongside the field
change. Four new tests in `internal/rules`: missing-version migrates
+ writes `.bak.v0` with byte-identical original; current-version
load is a no-op (no .bak, on-disk bytes unchanged); future-version
refuses (file untouched, no .bak); `Save` stamps `CurrentSchema`
regardless of input. OpenAPI `RuleSet` schema documents the new
field.

**v0.3.7** — first **v0.5 (*Distribution & multi-host*)** item:
**arm64 build**. `build.sh` now loops over the `ARCHES` env var
(default `amd64 arm64`) and produces one reproducible tarball per
arch — `dist/zfw-<v>-amd64.tar.gz` (ZimaBoard 1/2, ZimaCube;
N3350/N3450/N100) and `dist/zfw-<v>-arm64.tar.gz` (Lattepanda/Pi-class
hosts). `install.sh` auto-detects the host arch via `uname -m` so a
source-repo install picks the right `dist/zfw-<arch>.raw` without
extra flags. Both archs are pure Go (`CGO_ENABLED=0`,
`-trimpath -buildvcs=false`) so cross-compile costs nothing on the
existing amd64 build host. Reproducibility holds per-arch — two clean
builds produce byte-identical tarballs (verified locally for the
v0.3.6 → v0.3.7 cut: amd64 `0eb75059…`, arm64 `a3ededee…`, both
identical across two runs). The arm64 binary is `ELF 64-bit ARM
aarch64, statically linked` (verified via `file(1)` against
unsquashfs'd `dist/zfw-arm64.raw`); the amd64 binary stays `ELF 64-bit
x86-64, statically linked`. The CI workflow's pre-existing arm64
cross-compile smoke job is now redundant with the main build path and
will be removed when the repo gets its GitHub remote.

**v0.3.6** — sixth (and final) v0.4 item: **Exposure-tab → Deny
quick-action**. Each listening-port row now carries a second button
next to *+ Rule*: *→ Deny* opens the rule editor pre-filled with
`action: deny`, `source: any`, `ports: [<that port>]`, `zone: auto`
and a default name (`Block port <port>`). The user still has to Save
rules + Safe-Apply — the prefill just turns "block this exposed port
from the LAN" from a seven-field setup into two clicks. The v0.4 *UX
polish* phase is now complete; every roadmap item shipped except
frontend i18n (deliberately dropped — ZFW stays English-only).

**v0.3.5** — fifth v0.4 item: **audit-findings status history**. Each
finding's posture now carries a persistent timeline — every time the
live status flips (open → mitigated → fixed and back), a new
timestamped entry is appended to `/DATA/zfw/audit-history.json`. Up
to 20 entries per finding are kept; identical-status checks are
suppressed, so a finding that stays *fixed* for weeks keeps a short
history. The Audit tab renders the chain inline below each finding
("History: open → fixed → open *(since 2026-05-22)*"), hidden when
the posture has never changed. New `internal/audit/history.go`
(Load/Save + Update + Attach), four new unit tests covering
round-trip / append-on-change / length cap / attach contract, and a
handler test that asserts `history` is never null in the response.

**v0.3.4** — fourth v0.4 item: **diff view, unsaved vs applied**. A
new *Diff* button on the Rules tab (only enabled when there are
unsaved changes) opens a modal listing every change *Save rules*
would push: rules added (green `+`), removed (red `−`), changed
(amber `~`, with the before/after summary), and default-policy
flips. Each row carries a one-line semantic summary
(`Allow tcp 22 from 192.168.1.0/24 [Host]`) so the user can spot a
typo in seconds. Pure client-side: fetches the saved snapshot via
`/api/rules` and compares against the in-memory `ruleSet` by rule
id, treating new rules with empty `id` as additions. No new endpoint
and no engine change.

**v0.3.3** — third v0.4 item: **backup / restore rules.json**. Two
new buttons on the Rules tab. *Backup* downloads the currently saved
rule set as `zfw-rules-YYYY-MM-DD_HH-MM-SS.json` (the file is the raw
RuleSet, so restoring is a single POST — no custom format to parse).
*Restore* opens a file picker, parses the JSON, sanity-checks the
shape (`default_policy` + `rules` array) client-side, asks the user
to confirm the overwrite count, then POSTs to `/api/rules` where the
existing Validate gate runs again. No new endpoint and no engine
change; the firewall is NOT re-applied automatically — the user still
has to Safe-Apply afterwards.

**v0.3.2** — second v0.4 item: **per-rule notes / comments**. Each
rule gets an optional free-text `notes` field (up to 256 chars). The
rule editor modal carries a new textarea; the rule table shows a
"note" pill next to the name when notes are present, with the full
text on hover. Compiler ignores the field — it is metadata only.
`Validate` caps the length so a crafted rules.json can't balloon. New
backend tests `TestValidateAcceptsNotes` and
`TestValidateRejectsOversizeNotes` lock in the contract; OpenAPI
schema is updated. The field is `omitempty` so existing rules.json
files on disk keep round-tripping cleanly.

**v0.3.1** — first v0.4 (*UX polish*) item shipped: **rule-templates
library**. The Rules tab now carries a `Templates` button that opens a
picker over the curated catalog (`GET /api/rules/templates`). Three
templates in this release: Block VNC consoles (5900-5999, security),
Block NFS / rpcbind (111/2049/20048, security), Allow Plex Media
Server (32400 from LAN, service). Adding a template appends its rules
to the current set with fresh IDs and stable order spacing; the user
still has to click Save rules + Safe-Apply. The LAN value substituted
into "from the LAN" rules comes from the saved rules.json, falling
back to live `system.DetectLAN()` detection on a fresh install. New
backend tests: `TestTemplatesAllValid`, `TestTemplatesFreshIDs`,
`TestTemplatesSubstituteLAN` (rules package) plus
`TestRulesTemplatesReturnsCatalog` and
`TestRulesTemplatesSubstitutesPersistedLAN` (handlers package).

**v0.3.0** — the v0.3 *Professionalization & IPv6 (foundation)* phase
is complete. Every roadmap item under v0.3 has shipped:

- IPv6 first-class (default-deny ZFW-IN6 with full bypass list, v0.2.15)
  and per-rule IPv6 source support (v0.2.22)
- Handler tests: all 14 API endpoints carry at least one regression
  guard (22 tests total — v0.2.16 deadman-lifecycle batch + v0.2.22
  endpoint coverage expansion)
- **Rules engine integration tests** (this release): four netns tests
  run the compiled bash through a real iptables-legacy under
  `unshare -U -r -n` (no sudo) and assert the live chain state —
  port-range emits one `--dport 5900:5999` line, IPv6 sources never
  reach the IPv4 chain, revert clears every ZFW chain
- Port-range support in the rule model (v0.2.16), structured logging
  via `slog` (v0.2.17), API rate-limit middleware (v0.2.17), OpenAPI
  3.0 spec served from `/api/openapi.{json,yaml}` (v0.2.18),
  reproducible builds + optional CycloneDX SBOM (v0.2.19), and a
  GitHub-Actions CI workflow committed-but-inactive until the repo
  gets a remote

v0.3.0 builds on v0.2.21's external sign-off: **Gelbuilding's 2026-05-24
ZimaBoard validation of v0.2.20** — install, dashboard tile, Safe-Apply,
Confirm, custom-port rule-edit (SSH 22 → 2222 for ttydBridge) and full
reboot-persistence cycle all independently confirmed.

Underlying platform: built, deployed and browser-verified on a ZimaOS
1.6.1 host, with ZimaOS session authentication, CSRF protection and
systemd sandboxing in place; the codebase has passed a [code and
security review](SECURITY-REPORT.md) across three rounds (27 findings,
22 remediated, 5 accepted residuals tracked for v0.4); all user-facing
messages are English, and a fresh install seeds a recommended starter
rule set: deny-default plus baseline allow-rules for the ZimaOS web UI,
SSH, Samba shares and mDNS discovery (LAN auto-detected from the
default route), and one additional allow-rule per Docker-published port
discovered live on the host so running containers stay reachable.

Next phase: **v1.0 — General Availability** (outbound rules,
per-container rule binding, VPN-interface awareness, notification
hooks, threat-model doc, external pen-test). The v0.6 — *Intrusion
detection & state* — phase shipped in full across v0.4.1 → v0.5.0
(events analytics, threat detection, time-window rules with first
real schema bump v1→v2, per-rule logging + rate-limit, GeoIP source
flags, live conntrack). The v0.5 — *Distribution & multi-host* —
phase shipped across v0.3.7 → v0.4.0.
