# ZFW — a host firewall for ZimaOS

> **Current release:** v0.3.8 — see [Status](#status) for the build line.

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

Next phase work (v0.5 — *Distribution & multi-host*): arm64 build
(shipped v0.3.7), rules.json migration helper, `zpkg` self-update
check, multi-host rule sync (opt-in), Mod-Store submission prep.
