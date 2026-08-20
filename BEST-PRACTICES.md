# ZFW Best Practices

A field guide to running the ZFW host firewall on ZimaOS — how to lock the
host down **without locking yourself out**, and without leaving gaps. Read it
once before you switch the firewall to default-deny.

---

## The model in 60 seconds

ZFW filters inbound traffic in **two** kernel chains, because ZimaOS needs
both:

| Chain | Covers | Why a single chain is not enough |
|-------|--------|----------------------------------|
| `ZFW-IN` | Host-native services — SSH, Samba, NFS, the ZimaOS UI, the VM VNC console, … | Hooks the kernel `INPUT` chain |
| `DOCKER-USER` | Ports **published by Docker containers** | Docker's published ports are DNAT-forwarded and bypass `INPUT` entirely — a host-only firewall never sees them |

Every rule you create targets one or both chains. Leave a rule's **Zone** on
`auto` and ZFW decides per port: a port a Docker container published goes to
`DOCKER-USER`, every other port goes to `ZFW-IN`. Use an explicit zone only
when `auto` guesses wrong.

A rule set has a **default policy**:

- **`deny` (allowlist) — recommended.** Anything not explicitly allowed is
  dropped from the LAN. This is the posture that actually protects the host.
- **`allow` (blocklist).** Everything passes except what you block. Use this
  only as a stop-gap while you inventory a busy host.

---

## 1. Always use Safe-Apply

Applying firewall rules over the network is the single most dangerous thing
you can do on a remote box. **Always use Safe-Apply, never plain Apply, for
remote changes.**

Safe-Apply installs the rules and arms a **120-second dead-man timer**. If you
do not click **Confirm** within that window, ZFW reverts the rules
automatically. The workflow:

1. Click **Safe-Apply**.
2. *Within 120 seconds*, prove you still have access — open a **new** SSH
   session and reload the ZFW UI in a **new** browser tab. Do not trust the
   tab you already have open; established connections are accepted regardless.
3. Only once a fresh connection succeeds, click **Confirm**.
4. If anything is wrong, do nothing — the firewall rolls back on its own.

Plain **Apply** (no dead-man) is for the physical console only.

---

## 2. Keep your management paths open

Before you switch to `deny`, make sure the rule set explicitly allows every
way you reach the host. In `deny` mode, *anything* you forget is dropped.

- **SSH (TCP 22)** — allow it from your admin host or admin subnet.
- **TCP 80** — this is not optional. The ZimaOS dashboard **and the ZFW UI
  itself** are served on port 80 through the gateway. Block 80 from your
  admin network and you lock yourself out of ZFW. Allow it from the subnet
  you administer from.
- **Tailscale** — see below; it is allowed automatically and is your most
  reliable lifeline. Set it up *before* you harden.

Scope these rules to the **smallest source** that works — a single admin IP
or a management subnet, not `any`.

---

## 3. Know what ZFW always allows

You never need rules for these — the engine allows them on every apply, so a
tunnelled or host-local client cannot be cut off:

| Always allowed | Purpose |
|----------------|---------|
| Loopback (`lo`) | Host-local traffic |
| Established / related connections | Your current session is never dropped |
| `tailscale0` interface + UDP 41641 | Tailscale mesh — out-of-band access |
| `zt+` interfaces + UDP 9993 | ZeroTier mesh |
| `tun0` interface | znet / Zima Net — ZimaOS' own mesh, shipped and preset-enabled since at least v1.7.0 |
| `virbr0` | libvirt / ZimaOS VM networking |
| ICMP | ping / path-MTU |
| UDP 68 | DHCP client |

In `DOCKER-USER`, loopback, the host's own LAN IP and the mesh interfaces are
also always returned to Docker's accept path — so a `network_mode: host`
tunnel client (Newt / Pangolin) that reaches a container via the host IP
keeps working.

**Practical takeaway:** install Tailscale on the host before you go
default-deny. Even a rule set that locks out SSH and port 80 still leaves you
a way in over the tailnet.

---

## 4. Rule order matters — first match wins

Rules are evaluated **top to bottom**; the first matching rule decides the
verdict. Put **specific rules above general ones**:

```
1. allow  22/tcp   from 192.168.1.10      (your admin host)
2. deny   22/tcp   from 192.168.1.0/24    (everyone else on the LAN)
```

Reverse those two and the deny matches first — your admin host is blocked.
Reorder with the ▲ / ▼ controls in the Rules tab.

---

## 5. Work the Exposure tab

The Exposure tab lists every TCP port currently **listening**, live, with how
far each one reaches:

- **`LAN`** — reachable from the whole network. Treat every `LAN` row as a
  question: *does this need to be open?*
- **`blocked`** — ZFW is dropping it from the LAN. Good.
- **`localhost`** — bound to loopback only; not your problem.

Prioritise services that ship with **no authentication** — log viewers,
metrics dashboards, noVNC / browser-desktop images, admin panels, and the
ZimaOS VM VNC console (port 5900+, no password by default). Use the
**+ Rule** shortcut on a row to pre-fill a rule for that port.

---

## 6. Work the Audit tab

The Audit tab is a live traffic-light of the host security findings. Each
finding is re-scored on every apply:

- **open** — not addressed.
- **LAN-blocked** — ZFW now closes the LAN path; the underlying service is
  still misconfigured but no longer exposed.
- **fixed** — fully resolved.

Drive findings from *open* towards *fixed*. ZFW can move many of them to
*LAN-blocked* with a rule; the rest (SSH root login, EOL container images,
kernel CVEs) need a fix on the host itself.

---

## 7. Geo-blocking: know the limit

Country rules (ipset-backed) only work for traffic whose **real source IP
arrives at the host** — i.e. a direct port-forward from your router.

They do **not** work behind a reverse tunnel (Pangolin, Cloudflare Tunnel,
`cloudflared`, …): there the connection reaches the host from the tunnel
client, so every packet carries the tunnel's IP, not the visitor's. Filter by
country **at the VPS / tunnel edge** in that case, not on the ZimaOS host.

---

## 8. Do not forget IPv6

ZimaOS is dual-stacked. A rule that closes a port on IPv4 does nothing for
IPv6. Use the **V6-Drop** list to block sensitive ports on IPv6 as well —
especially anything you have just locked down on IPv4.

**The other direction bites harder, and it is easy to miss (v1.0.22).** A rule
whose source is an IPv4 address or range — which is what every rule in the
*Recommended defaults* set is, scoped to your LAN — **cannot apply to IPv6 at
all**. There is no way to express `192.168.1.0/24` as an ip6tables source
match. With the default policy on Deny, that means the IPv6 input chain
(`ZFW-IN6`) carries no allow rule and drops every inbound IPv6 connection,
while the rule table shows nothing but green "Allow" rows.

You will not notice this from the LAN. Testing at home almost always goes over
IPv4, and IPv4 is fine. It shows up the first time someone reaches the host
**from the internet by domain name**: if the name has an `AAAA` record, the
client connects over IPv6 and is dropped — the service looks dead from outside
and healthy from inside.

Since v1.0.22 the Rules tab marks such rules **IPv4 only**, and warns with a
banner when a deny-by-default set has no IPv6 coverage at all on a host that
really does have a public IPv6 address. What to do about it:

- For a service that must be reachable **from the internet**, give it a rule
  with source **Any** (or an explicit IPv6 range). One such rule for the port
  is enough; keep the LAN-scoped rule alongside it if you like.
- For a service that must **not** be reachable from the internet, leave it
  LAN-scoped — the IPv6 drop is then doing exactly what you want, and the
  badge is telling you so rather than hiding it.
- To see what is actually being dropped, look for the log prefix
  `ZFW-IN6-DROP` in the Events tab or in `journalctl -k`.

Note also that a host reachable only through Tailscale or ZeroTier does not
count as having public IPv6 — those hand out ULA addresses (`fd…`), which ZFW
bypasses by interface anyway, and the banner deliberately stays quiet for them.

---

## 9. First-time setup walkthrough

A safe order for a fresh install:

1. **Install Tailscale on the host first** — your guaranteed lifeline.
2. Open the **ZFW Firewall** tile in the ZimaOS dashboard.
3. **Exposure tab:** read what is currently listening. Note what must stay
   reachable.
4. **Rules tab:** create your allow rules — at minimum SSH (22) and TCP 80
   from your admin subnet. Add rules for the services you actually use.
5. Set the **default policy to `deny`**.
6. **Safe-Apply.** Then, within 120 s, open a fresh SSH session and reload
   the UI in a new tab.
7. Access confirmed? Click **Confirm**. Not confirmed? Wait — it reverts.
8. Re-check the Exposure tab: the rows you did not allow should now read
   `blocked`.

---

## 10. Updating ZFW

Re-run the installer — it is idempotent and updates in place:

```sh
sh install.sh        # on the host, as root
```

Your rule set lives in `/DATA/zfw/rules.json` and is **not** touched by an
update. The currently applied iptables rules also stay in place across a
module update; re-run **Safe-Apply** only if you want the new build to
recompile and re-apply them.

---

## 11. Recovery — if you lock yourself out

In order of preference:

1. **Wait.** If you used Safe-Apply and did not Confirm, the dead-man reverts
   the firewall after 120 seconds. Do nothing and you are back.
2. **Tailscale.** SSH in over the tailnet — it is allowed even by a
   default-deny rule set.
3. **Physical console.** Keyboard + monitor on the ZimaOS box.
4. **Revert from a shell** (console, or SSH if still reachable), as root:

   ```sh
   /DATA/zfw/zfw revert
   ```

   This removes every ZFW chain and restores the stock (unfiltered) state.
   `/DATA/zfw/zfw commit` cancels an armed dead-man; `/DATA/zfw/zfw status`
   shows the live chains.

---

## 12. What ZFW is — and is not

**ZFW is** a host packet filter (iptables) for ZimaOS, with a UI, that closes
the gap of ZimaOS shipping no firewall at all.

**ZFW is not** a replacement for authentication. It controls *who can reach a
port*, not *what they can do once connected*. It does not inspect payloads,
it is not a WAF or an IDS. Keep authentication on your apps, keep images
patched, keep SSH hardened — ZFW is one layer of defence in depth, not the
only one.

---

## Hardening checklist

- [ ] Tailscale installed on the host before going default-deny
- [ ] SSH (22) allowed from the admin subnet only
- [ ] TCP 80 allowed from the admin subnet (ZimaOS UI **and** ZFW UI)
- [ ] `LAN` subnet and `HOST_IP` configured correctly
- [ ] Default policy set to `deny`
- [ ] Every `LAN` row in the Exposure tab reviewed and justified
- [ ] No-auth services (dashboards, noVNC, VM VNC console) blocked or secured
- [ ] IPv6 ports closed via V6-Drop where the IPv4 port is closed
- [ ] No **IPv4 only** badge on a rule for a service that must be reachable
      from the internet (§8) — and no IPv6 coverage banner on the Rules tab
- [ ] Change applied with **Safe-Apply**, verified on a fresh connection,
      then **Confirm**ed
- [ ] Audit-tab findings driven towards *fixed*

---

*Author: Holger Kuehn aka Lintuxer · © 2026 Virtual Services*
