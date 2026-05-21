# zfw — UGREEN-Parität: Umsetzungsplan (Roadmap v0.2.0)

> Arbeitsdokument, erstellt 2026-05-21. Ziel: die UGREEN-UGOS-Firewall — Funktion
> **und** Bedien-Erlebnis — in `zfw` nachbilden.

## 1. Ziel

`zfw` v0.1 nutzt ein **Tier-Allowlist**-Modell: vier feste Port-Listen
(`HOST_TCP_LAN`, `HOST_UDP_LAN`, `DOCKER_DROP_LAN`, `V6_DROP`). Funktional, aber grob —
man kann nicht „Quelle A darf Port X, Quelle B nicht" ausdrücken.

UGREEN nutzt das klassische NAS-Firewall-Modell: eine **geordnete Regelliste** mit
einem Assistenten. Maintainer will dieses Modell **und** dessen UI in `zfw`.

**Ergebnis v0.2.0:** `zfw` = UGREEN-artige Regel-Firewall **+** das bestehende
Security-Dashboard. Die Tabs Exposition / Audit / Versionen bleiben unverändert —
nur der Tab „Allowlist" wird zu „Regeln".

## 2. Was die UGREEN-Firewall bietet (recherchiert)

Quelle: UGREEN NAS Firewall-Setup-Guide (nas.ugreen.com).

- **Regelbasiert** — „+ Neue Regel"-Button öffnet einen „Firewall-Regel hinzufügen"-Assistenten.
- Pro Regel: **Name**, **Berechtigung** (Allow / Deny), **Netzwerk-Verbindung** (Interface),
  **Port** (alle / spezifisch), **Quell-IP** (Einzel-IP oder Bereich, z. B. `192.168.50.1–192.168.50.100`).
- **Globale Default-Aktion** für ungematchten Verkehr: Deny (Allowlist-Modus) / Allow (Blocklist-Modus).
- **Enable-Checkbox** pro Regel, **Apply-Button**.
- Separat: Brute-Force-Lockout (Login-Sicherheit, nicht Teil der Regel-Engine).
- Nicht belegt im UI: Zeitplan, Protokoll-Auswahl, Regel-Priorität/Reorder, Geo-Sperren.

## 3. Gap-Analyse — zfw heute vs. UGREEN

| Aspekt | zfw v0.1 | UGREEN | Aufgabe |
|---|---|---|---|
| Modell | 4 Tier-Portlisten | geordnete Regelliste | → Regelliste |
| Regel-Granularität | nur Port | Name + Aktion + Quelle + Port + Interface | → volle Regel-Struktur |
| Default-Policy | implizit (Host=drop, Docker=allow) | explizit, umschaltbar | → explizite Einstellung |
| UI | Chip-Editor pro Tier | Regel-Tabelle + Assistent | → Tabelle + Modal-Assistent |
| Engine | 4 Variablen → feste Regeln | Regelliste → kompilierte Kette | → Regel-Compiler |
| Vorteil zfw | Exposition/Audit/Versionen, Safe-Apply-Totmann | — | bleibt erhalten |

## 4. Ziel-Regelmodell

`rules.json` ersetzt `allowlist.conf` — eine geordnete Liste:

```json
{
  "default_policy": "deny",
  "rules": [
    {
      "id": "r1", "order": 10, "enabled": true,
      "name": "SSH vom LAN",
      "action": "allow",
      "source":   { "type": "range", "value": "192.168.1.0/24" },
      "ports":    { "type": "list",  "value": [22] },
      "protocol": "tcp",
      "zone":     "auto"
    }
  ]
}
```

- `source.type`: `any` | `ip` | `range` (CIDR) — später `region`
- `ports.type`: `all` | `list`
- `protocol`: `tcp` | `udp` | `both`
- `zone`: `auto` | `host` | `docker`
- `default_policy`: was mit ungematchtem LAN-Verkehr passiert

**Der Clou — `zone: auto`:** Der Nutzer sagt nur „Port 8888 sperren". Der Daemon
erkennt über den Exposure-Scan (Prozess = `docker-proxy`?), ob der Port host-nativ
oder Docker-publiziert ist, und kompiliert in die richtige Chain (`ZFW-IN` bzw.
`DOCKER-USER`). UGREEN-Einfachheit nach außen, zfw-Zwei-Hook-Korrektheit nach innen —
der Nutzer muss `INPUT` vs. `DOCKER-USER` nie kennen.

## 5. Architektur-Entscheidungen

- **Regel-Compiler im Go-Daemon**, nicht im Shell-Skript. Der Daemon liest
  `rules.json`, löst `zone:auto` gegen den Live-Scan auf, erzeugt die iptables-Sequenz.
- **Engine-Skript bleibt der privilegierte Ausführer** mit Safe-Apply/Totmann —
  bekommt das generierte Regelwerk gefüttert. Das Dead-man-Verfahren bleibt
  unverändert wertvoll und wird nicht angefasst.
- **Migration:** beim ersten v0.2-Start `allowlist.conf` automatisch in äquivalente
  Regeln übersetzen (4 Tiers → N Regeln + Default-Policy). Kein Bruch, kein Datenverlust.
- **UI-Stil:** UGREEN-*Interaktionsmuster* übernehmen (Regel-Tabelle + Modal-Assistent,
  klare Schritt-für-Schritt-Felder), aber ZimaOS-kohärent **dunkel** halten — kein
  Voll-Reskin. Es geht um das Bedien-Erlebnis, nicht die Farbpalette.

## 6. Umsetzungswellen

### Welle 1 — Datenmodell & Regel-Compiler (Backend)
- `internal/rules` — Regel-Schema, Laden/Speichern `rules.json`, Validierung.
- `internal/compiler` — Regelliste → iptables (`ZFW-IN` + `DOCKER-USER`),
  `zone:auto`-Auflösung über den Exposure-Scan.
- Migration `allowlist.conf` → `rules.json` (einmalig, automatisch).
- Engine-Skript nimmt das generierte Regelwerk entgegen.
- API: `GET/POST /api/rules`, `POST /api/rules/reorder`, `GET/POST /api/default-policy`.

### Welle 2 — Regel-Tabelle (UI)
- Tab „Allowlist" → „Regeln".
- Tabelle: Reihenfolge (Drag-Handle), Name, Aktion (Allow/Deny-Badge), Quelle, Ports,
  Enable-Toggle, Bearbeiten/Löschen.
- „+ Neue Regel"-Button; Default-Policy-Umschalter oben.

### Welle 3 — Regel-Editor-Assistent (UI)
- Modal-Dialog im UGREEN-Stil: Name → Aktion (Allow/Deny) → Quelle (Any / IP /
  Bereich, mit Validierung) → Ports (Alle / Liste) → Protokoll → Zone (Auto/Host/Docker,
  Default Auto).
- Speichern schreibt eine Regel; danach Hinweis „Safe-Apply".

### Welle 4 — Politur & Extras
- **„Regel aus Port erstellen"** — Shortcut aus dem Exposition-Tab: Klick auf einen
  offenen Port öffnet den Regel-Editor vorausgefüllt. Das ist *besser* als UGREEN.
- Optional: Zeitplan pro Regel; Brute-Force-IP-Auto-Block (verknüpft mit dem Audit-Tab).

## 7. Nicht im Scope / später

- **Geo-/Region-Sperren** — braucht einen IP-zu-Land-Datensatz (Größe, Update-Pflege).
  Erst nach v0.2, wenn gewünscht.
- **Outbound-Filterung** — UGREEN filtert primär Inbound; zfw bleibt zunächst dabei.

## 8. Risiken & Gegenmaßnahmen

- **Regel-Reihenfolge über zwei Chains.** Eine geordnete Nutzer-Regelliste wird auf
  `ZFW-IN` und `DOCKER-USER` verteilt — die Reihenfolge muss *innerhalb* jeder Chain
  stimmen. Lösung: pro Chain die betreffenden Regeln in Nutzer-Reihenfolge emittieren;
  `zone:auto`-Regeln, die beide betreffen, in beide.
- **Migration darf die laufende Firewall nicht brechen.** `zone:auto`-Erkennung gegen
  den Live-Scan testen; Migration immer mit Safe-Apply (Totmann) ausrollen.
- **Drag-Reorder.** Nach jedem Reorder Safe-Apply anbieten — keine stille Anwendung.

## 9. Aufwandseinschätzung

Welle 1 ist der Brocken (neues Modell + Compiler + Migration). Wellen 2–3 sind
überschaubar (UI auf bestehender Daemon-/Tab-Struktur). Welle 4 ist inkrementell.
Reihenfolge strikt 1 → 2 → 3 → 4.

---

## 10. Welle 4 — Ländersperre (Geo) + „Regel aus Port"

> Ersetzt die §7-Einordnung „Geo später": Geo ist als **wichtig** eingestuft — ZimaOS-
> Nutzer exponieren Jellyfin/Immich/Nextcloud ins Internet und wollen den Zugriff aufs
> eigene Land beschränken bzw. Hochrisiko-Länder sperren.

### 10.1 Feasibility — bestätigt (Live-Check nas-main, 2026-05-21)

`ipset` v7.16 vorhanden (`/usr/sbin/ipset`); Kernel: `CONFIG_IP_SET=m`,
**`CONFIG_IP_SET_HASH_NET=m`** (CIDR-Sets), `CONFIG_NETFILTER_XT_SET=m`, Modul `xt_set.ko`.
→ **Ländersperre via ipset voll umsetzbar.** (`nft` fehlt — wird nicht gebraucht.)

### 10.2 Wo Geo wirkt — und wo NICHT

Geo-Matching braucht die **echte Client-IP** am NAS:
- **Router-Port-Forward** → echte Internet-IP kommt am NAS an → **Geo wirkt.** Häufigster
  Weg, wie ZimaOS-Nutzer Jellyfin/Immich freigeben.
- **Pangolin / Cloudflare-Tunnel** → NAS sieht die Tunnel-IP, nicht den Besucher → **Geo
  am NAS wirkt NICHT**, muss am VPS (Pangolin/Traefik/CrowdSec) sitzen.

→ Die UI zeigt das bei Geo-Regeln ehrlich an. zfw blockt, was es sieht.

### 10.3 Mechanik

- Pro Land ein ipset `hash:net` namens `zfw-cc-<cc>` (z. B. `zfw-cc-de`).
- Match: `iptables -A <chain> -m set --match-set zfw-cc-de src -j <target>`.
- Der Daemon erzeugt pro genutztem Land eine `ipset restore`-Datei aus den CIDR-Daten;
  `compiled.sh` lädt sie via `ipset restore -exist -f …` (schnell, kein Zeilen-Spam) und
  macht vorab `modprobe ip_set ip_set_hash_net xt_set`.

### 10.4 Datenquelle & Updates

- **Quelle:** ipdeny.com aggregierte Zonen (`…/ipblocks/data/aggregated/<cc>-aggregated.zone`)
  bzw. GitHub `country-ip-blocks` — frei, CIDR-Listen pro Land.
- **Pipeline:** Daemon lädt nur die *tatsächlich in Regeln verwendeten* Länder, cached
  unter `/DATA/zfw/geo/<cc>.zone`, refresht monatlich. Offline-tauglich (letzter Cache).
- Lizenz im Modul dokumentieren.

### 10.5 Regelmodell-Erweiterung

Neuer `source.type`: **`country`**, `source.value` = ISO-Code(s) (`DE`, `RU,CN`).
Fügt sich nahtlos in die Regelliste (Welle 1-3) — kein Sondersystem. Compiler:
`source.type=country` → `-m set --match-set zfw-cc-<cc> src`.

### 10.6 UI

- Regel-Editor: Quelle-Dropdown bekommt Option **„Land"** → Länder-Mehrfachauswahl mit
  Suchfilter.
- Geo-Regel zeigt Inline-Hinweis „Wirkt nur bei Port-Forward, nicht hinter Tunnel".
- Anzeige: Stand der Geo-Daten (letztes Update).

### 10.7 Welle-4-Umfang

1. **Ländersperre** (10.1–10.6) — der Brocken.
2. **„Regel aus Port"** — Klick auf einen Port im Exposition-Tab öffnet den Regel-Editor
   vorausgefüllt.
3. Optional/später: Zeitplan pro Regel, Brute-Force-IP-Auto-Block.
