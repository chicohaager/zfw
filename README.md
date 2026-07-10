<p align="center">
  <img src="docs/screenshots/wordmark.png" alt="ZFW Firewall — host firewall &amp; security dashboard for ZimaOS" />
</p>

# ZFW — a host firewall for ZimaOS

> **Current release:** v1.0.19 — the Connections tab finally works on ZimaOS ([#1](https://github.com/chicohaager/zfw/issues/1)). ZFW read the connection table from `/proc/net/nf_conntrack` and, failing that, from `conntrack(8)`. A stock ZimaOS kernel builds with `# CONFIG_NF_CONNTRACK_PROCFS is not set` and the image ships no `conntrack` binary, so both sources were unavailable and the tab was permanently empty — on a host that was tracking hundreds of flows. ZFW now reads **ctnetlink** (`CONFIG_NF_CT_NETLINK=y`), the kernel's netlink interface, in pure Go with no new dependency. Second, `/api/conntrack` no longer answers `200 []` when the table cannot be read: an unreadable table is a `503` naming the source that failed, and the UI shows that reason instead of wrongly blaming a missing kernel module.
>
> **Previous release:** v1.0.18 — follow-up to v1.0.17. `revert` (and therefore the Safe-Apply dead-man) never emptied the **IPv6** `DOCKER-USER` chain, which v1.0.17 started filling — so a "reverted" firewall kept silently dropping IPv6 traffic to published container ports while every status surface reported it was off. `revert` now restores that chain's stock `-j RETURN`, and `zfw status` shows it. The engine script also carried the same name-based backend guess fixed elsewhere in v1.0.17 (`case "$IPT" in *nft*)`), so on ZimaOS 1.6.2 its `revert`/`status` operated on the wrong IPv6 table. Finally, the UI, README and engine logs now say plainly that the dead-man **removes the firewall entirely** rather than restoring the previous rules.
>
> **Previous release:** v1.0.17 — two ZimaOS 1.6.2 fixes. **(1)** The iptables backend is now identified by asking the binary (`iptables -V` → `nf_tables`/`legacy`) instead of pattern-matching its name. On 1.6.2 the plain `iptables` symlink drives nf_tables despite having no `nft` in its name, so whenever the Docker-FORWARD probe missed — e.g. `zfwd` starting before `dockerd` — IPv6 was pinned to the empty legacy table and the dashboard reported "IPv6 protection ✗" while `ZFW-IN6` was live. **(2)** The published-port inventory that scopes the `DOCKER-USER` default-deny now unions docker-proxy sockets with `docker ps`. With `"userland-proxy": false` there is no docker-proxy, the inventory came up empty, and the per-port default-deny was silently not emitted at all — the firewall failed open behind a green tile. **(3)** The inventory is now protocol-aware: `parseDockerPorts` used to discard UDP mappings outright, so a container publishing e.g. `8181/udp` got neither an allow rule nor a deny rule and stayed reachable from any source while its TCP sibling was filtered. Published UDP ports now get both. Also new: the IPv6 `DOCKER-USER` chain is populated (it matters the moment Docker IPv6 is enabled), and an empty inventory under `default_policy=deny` is now logged as an error instead of passing silently.

ZFW is a standalone ZimaOS module that adds the one thing ZimaOS does not ship:
a **host firewall** — with a web UI and a live security dashboard.

![ZFW Firewall dashboard on a live ZimaOS host — Rules tab showing 12 default rules (ZimaOS Web UI, SSH, Samba TCP/UDP, mDNS, Docker apps) plus the live status bar: firewall active, 18 exposed services, 24 blocked, 0 drops in the last hour, 10 open findings.](docs/screenshots/dashboard.png)

![ZFW Firewall dashboard, Events tab — top source and destination IPs in the last hour rendered as bar charts, plus the rolling drop log with timestamp, source, destination, port, protocol and zone for every blocked packet.](docs/screenshots/events.png)

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

- **Firewall** — live status; **Safe-Apply** with a 120-second dead-man switch: if you do
  not Confirm in time, ZFW **removes the firewall entirely** (all ZFW rules dropped, host
  back to its unprotected stock state — *not* a restore of the previously committed rules).
  A bad rule can never lock you out, but an unattended Safe-Apply leaves the host
  unprotected; Commit; Revert.
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
