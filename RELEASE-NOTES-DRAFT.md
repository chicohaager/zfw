# Release notes — DRAFT for the next release (version not chosen)

> Draft written on branch `fix/gaps-2026-10-08`. Version number, the README
> "Current release" block and the image tag are the maintainer's decision; this
> file is the proposed text only. Nothing here has been measured on a ZimaOS
> host — see "Not measured" at the end.

**Proposed headline:** *Closes four ways the firewall was more open than it
looked: container ports published after the last apply, IPv6 link-local
access, untested rules at boot, and a dashboard that showed saved rules as if
they were live.*

## Security fixes

- **Container ports published after the last apply were open to everyone.**
  Under the Deny default, `DOCKER-USER` only dropped the published ports the
  inventory held when the rules were compiled, then returned. The container
  watcher recompiles on `docker` events but deliberately never applies, so an
  app installed after the last Safe-Apply was reachable from any source until
  the next apply — while the Exposure tab showed it as *blocked*.
  **Fixed:** both `DOCKER-USER` chains (IPv4 and IPv6, line-by-line and
  `iptables-restore` emitters) now end in a guard that logs and drops any new
  connection Docker DNATs towards `docker0`/`br-+` that no rule decided
  (`-m conntrack --ctstate NEW -m conntrack --ctstate DNAT`). It sits after
  every bypass, user rule and per-port deny. Reproduced and verified on real
  netfilter (nf_tables) in a network namespace: the late port went from
  reachable to blocked; allowed ports, container egress, container-to-container
  over a published port on another network, a host-network process connecting
  to the host IP (Newt/Pangolin path) and a Tailscale peer are unchanged.
  **Behaviour change:** a zone-*auto* allow rule that names a port no
  container published at compile time does not reach `DOCKER-USER` for that
  port; a container that publishes it later is now closed until the next apply
  (before: open to everyone). Apply after installing an app.

- **IPv6 link-local was a way around every rule.** `ZFW-IN6` returned every
  packet from `fe80::/10` before the rules, so any LAN device reached any
  service listening on `[::]` (SSH, Samba, the ZimaOS UI) through the host's
  link-local address. **Fixed:** link-local sources are filtered like any
  other; ICMPv6 (neighbour discovery, MLD), the DHCPv6 client port and mDNS
  (UDP 5353) from the link still pass. The dead `-s ff00::/8` line is gone (a
  multicast address is never a valid source). **Behaviour change:** LLMNR
  (5355), WS-Discovery (3702) and any LAN-scoped (IPv4-source) service are no
  longer reachable over `fe80::`; clients fall back to IPv4 (assumption, not
  measured).

- **Boot replayed rules that were never confirmed.** `zfw.service` replayed
  the current `compiled.sh`, which the daemon rewrites on every rule save and
  container event — after a reboot or dockerd restart a saved-but-never-applied
  ruleset went live without the dead-man. **Fixed:** the engine records what an
  apply ran (`applied.sh`), Confirm promotes exactly that to `committed.sh`
  (root-only, atomic, checked by `secure_file`), a plain Apply writes it
  directly, and the unit now runs `zfw boot`, which replays only
  `committed.sh`. Revert and the dead-man remove both copies. **Upgrade:**
  `install.sh` runs `zfw _migrate-persist`, which rewrites an existing unit and
  seeds `committed.sh` from the `compiled.sh` present at upgrade time; hosts
  that never confirmed are left alone. A Confirm without a recorded apply is
  refused ("run Safe-Apply first") — e.g. a Safe-Apply started by the old
  engine and confirmed after the upgrade.

## Dashboard

- **Exposure judges from what is live.** Every compiled script carries a
  one-line `# zfw-live:` record (rules without names/notes, published-port
  inventory, guard on/off); the engine's `applied.sh` copy is therefore a
  record of the live state. Exposure reads it instead of `rules.json`:
  - `restricted` — new badge: reachable only from single addresses or small
    ranges (IPv4 /24 or narrower, IPv6 /64 or narrower, not covering the LAN);
    the tooltip lists them. Counted as exposed.
  - `unverified` — the firewall is active but there is no record of what it
    applied (first start after this update until the next apply/boot). A
    block is never claimed without the record.
  - tag *not yet applied* — saved rules answer differently; tag *new since
    apply* — container port not in the applied inventory (closed by the guard).
  - API: `/api/exposure` entries gain `sources` and `pending`; `reach` gains
    `restricted` and `unverified` (see `docs/openapi.yaml`).
- **Audit is never greener than the live state:** a port counts as reachable
  when the saved rules *or* the live record say so; source restrictions never
  mitigate a finding.

## Docs

- The README and the Events tab promised "Logging is rate-limited to 60/min
  per chain". No such limit exists (`xt_limit` is not shipped on the ZimaOS
  kernel); the text now says what happens: one log line per new connection
  that reaches a final DROP, no fixed cap. A test pins it.
- Host commands now carry `sudo` (`sudo docker run … chicohaager/zfw`,
  `sudo sh install.sh`, `sudo /DATA/zfw/zfw revert|commit|status`): on a stock
  ZimaOS the login user is not in the `docker` group. A test pins it.
- Feed cache directory: `/DATA/zfw/feeds` (daemon default, `ZFW_FEEDS`); a
  test now pins docs, default and unit together.
- Test tooling: the `netns_integration` suite compiled again (missing import)
  and queries the iptables backend the script actually picked.

## Not measured on a ZimaOS host (to do before release)

- DNAT guard and link-local change on ZimaOS kernels (6.12.25 legacy backend,
  6.18.9 / 1.6.2+ nf_tables backend). Local evidence: kernel 7.0 /
  iptables 1.8.10 nf_tables in a network namespace; the legacy-backend runs
  were skipped locally (no `ip6_tables` legacy module loadable without root).
  `xt_conntrack` is built in on ZimaOS 6.12.25 (measured 2026-05-23), and the
  existing `--ctorigdstport` rules already depend on it.
- Engine `boot` / `_migrate-persist` under real systemd (tested with the real
  script, systemctl stubbed).
- Exposure UI rendered in headless Chromium against a mock API, not against a
  running daemon.
