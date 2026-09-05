# ZFW Security Disclosure & Bug-Bounty Programme

> **Status:** open as of v1.0.0 (GA). Researchers are welcome.
> **Maintainer:** Holger Kuehn (Lintux) — `holger.kuehn@virtual-services.info`
> **Companion docs:** [SECURITY-REPORT.md](SECURITY-REPORT.md) (three rounds of internal review), [THREAT-MODEL.md](THREAT-MODEL.md) (assets, adversaries, mitigations).

ZFW is a host firewall for ZimaOS that ships as a sysext module +
small Go daemon + bash engine running as root. Its blast radius
makes it a worthwhile target — and a worthwhile contribution
when a researcher finds something. This document is the contract.

---

## 1. Scope

### In scope

- The `zfwd` daemon and all packages under `internal/` of this repository
- The `engine/zfw` shell script (runs as root)
- The compiled-bash output path (`internal/compiler` + `/DATA/zfw/compiled.sh`)
- The web UI under `raw/usr/share/casaos/www/modules/zfw/`
- The HTTP API surface documented in `docs/openapi.yaml`
- Build / release pipeline: `build.sh`, `.github/workflows/ci.yml`,
  reproducibility of `dist/zfw-<v>-<arch>.tar.gz`
- Multi-host sync endpoints (`/api/peers/*`)
- Webhook / self-update / GeoIP-lookup outbound HTTP paths
- The systemd unit `zfw-ui.service` and its hardening directives

### Out of scope

- **The Linux kernel and iptables-legacy** — upstream
- **The ZimaOS gateway / web server** — IceWhale's product
- **Third-party Mod-Store apps installed alongside ZFW** — those
  apps' own security, not ZFW's. ZFW *does* claim to limit blast
  radius via per-rule + per-container binding; an escape that
  works against the Mod-Store app is in scope only when it
  bypasses ZFW's containment.
- **Denial-of-service via legitimate request volume** below the
  rate limiter — single-admin appliance, the bucket is sized for
  human use; cf. `R3-5` in SECURITY-REPORT.md
- **Issues that require pre-existing root on the host**
- **Self-XSS, missing CSP on a page that has no JS-exposed
  sensitive state, etc.** — best-effort fixed but not awarded
- **Theoretical attacks without a working PoC**
- **Reports about features the operator has explicitly opted
  into** (`ZFW_EXTRA_BYPASS_IFACES=*`, `ZFW_PEER_TOKEN` set to
  `password`, etc.) — operator owns intent

### Specifically welcome

- Bypasses of the JWT verifier (`internal/auth`)
- CSRF / same-origin gaps on state-changing endpoints
- Shell injection through `compiled.sh` (any path from rules.json
  to the compiler that escapes the iface-name / port-int / CIDR
  validation)
- Privilege escalation from non-root local user to root via the
  daemon, the engine or `compiled.sh`
- Race conditions between `apply` / `commit` / `revert` / `recompile`
- Rules.json migration that loses or corrupts data
- Multi-host sync: forgery of a peer-push without the token; replay
  attacks; man-in-the-middle on the receive endpoint
- IPv6 chain gaps — anything that reaches the host on IPv6 that the
  ZFW-IN6 default-deny is supposed to catch
- Anything that lets a container reach the host or sibling
  containers in a way DOCKER-USER should have blocked
- Anything that breaks the Safe-Apply dead-man invariant

---

## 2. Process

1. **Report**: email `holger.kuehn@virtual-services.info` with subject
   line starting `[ZFW]`. PGP key on request.
2. **Acknowledge**: within **3 working days**.
3. **Triage**: within **7 working days**, including severity
   classification (Critical / High / Medium / Low / Info).
4. **Fix**: target windows by severity:
   - Critical: 7 days
   - High: 14 days
   - Medium: 30 days
   - Low: next minor release
5. **Coordinated disclosure**: 90 days from report unless a fix
   ships sooner; researcher may opt for shorter. Public credit in
   `SECURITY-REPORT.md` and the relevant release notes (unless
   the researcher prefers anonymity).
6. **Bounty**: ZFW is single-maintainer open-source; there is no
   monetary programme. Public acknowledgement + hall-of-fame entry
   is offered. Researchers willing to take Bitcoin tips: include a
   payout address in your report.

---

## 3. Reporting checklist

A useful report contains:

- **Affected version** (`cat VERSION` from a deployed install or the
  release tarball SHA from `dist/*.tar.gz.sha256`)
- **Reproduction steps** — exact commands, exact rules.json, exact
  request, exact response
- **Impact assessment** — what an attacker achieves at the bottom of
  the kill chain
- **Suggested fix** if you have one (welcome but not required)
- **Disclosure timeline** if your default is shorter than the 90
  days above

A PoC against a host you own is fine. A PoC against a host you do
not own — the maintainer's test ZimaCube included — requires
explicit prior agreement; without it, that's testing in production.
Agreement is requested by e-mail, at the same address as reports.
This document publishes no host address of the maintainer's.

---

## 4. Safe harbour

The maintainer commits to:

- **Not pursue legal action** against researchers acting in good
  faith and within this scope
- **Not contact employers, hosting providers or law enforcement**
  about a researcher who follows the process above
- **Treat the researcher as a collaborator**: share fix drafts,
  ask for retest before public release, name them in the credit
  line

The researcher commits to:

- **Stay within scope** (Section 1)
- **Stay within process** (Section 2)
- **Not exfiltrate, modify or destroy data** beyond the minimum
  needed to demonstrate the vulnerability
- **Not run sustained DoS** — a PoC that briefly hangs the daemon
  to demonstrate a parser bug is fine; a multi-hour resource
  exhaustion isn't
- **Not test against hosts they do not own**
- **Not disclose publicly** before the coordinated window closes

---

## 5. Hall of fame

Researchers credited in `SECURITY-REPORT.md`:

- Five rounds of internal review by Holger Kuehn / Claude — see
  `SECURITY-REPORT.md` Rounds 1–5 (50 findings, 45 remediated,
  5 accepted residuals).
- External validation: **Gelbuilding (IceWhale forum)** — v0.2.20
  / v0.2.21 ZimaBoard validation (install, dashboard tile, Safe-
  Apply, Confirm, custom-port rule-edit for SSH → ttydBridge,
  full reboot-persistence cycle). Not a vulnerability report but
  the first external sign-off and the proof-point for the
  reproducible-build pipeline.

The hall of fame extends every time a researcher reports a
verified finding that lands a fix or a documented accepted-risk.
