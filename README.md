# ZFW — a host firewall for ZimaOS

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
sh build.sh        # -> dist/zfw.raw  (+ .sha256)
```

Requires `go` 1.22+ and `squashfs-tools` (`mksquashfs`). The image is packed with
gzip — the ZimaOS kernel is built without zstd/xz squashfs support.

## Deploy

`build.sh` writes a self-contained install bundle to `dist/` — the `zfw.raw`
module, the `zfw` engine script and `install.sh`. Copy that directory to the
ZimaOS host and run the installer as root:

```sh
scp -r dist root@<host>:/tmp/
ssh root@<host> 'cd /tmp/dist && sh install.sh'
```

`install.sh` places the sysext module in `/var/lib/extensions/`, installs the
engine script to `/DATA/zfw/zfw` (`root:root`, `0700`), merges the sysext and
(re)starts `zfw-ui.service`. Re-run it any time to update an install in place.

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

## Status

**v0.1.0** — built, deployed and browser-verified on a ZimaOS 1.6.1 host.
